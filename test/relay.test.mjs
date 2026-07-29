import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  acceptKey, encodeTextFrame, encodeControlFrame, decodeFrames, Rooms,
} from '../niceassos-relay.mjs';

// Build a MASKED client→server text frame (what a browser actually sends),
// so decodeFrames is exercised on real input.
function maskClientFrame(str, mask = [0x37, 0xfa, 0x21, 0x3d]) {
  const payload = Buffer.from(str, 'utf8');
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x81, 0x80 | len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81; header[1] = 0x80 | 126; header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81; header[1] = 0x80 | 127; header.writeBigUInt64BE(BigInt(len), 2);
  }
  const m = Buffer.from(mask);
  const masked = Buffer.alloc(len);
  for (let i = 0; i < len; i++) masked[i] = payload[i] ^ m[i & 3];
  return Buffer.concat([header, m, masked]);
}

// ─── acceptKey (RFC 6455 §1.3 worked example) ───────────────────────────────
test('acceptKey matches the RFC 6455 example vector', () => {
  assert.equal(acceptKey('dGhlIHNhbXBsZSBub25jZQ=='), 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
});
test('acceptKey is input-sensitive', () => {
  assert.notEqual(acceptKey('aaaa'), acceptKey('aaab'));
});

// ─── encodeTextFrame ────────────────────────────────────────────────────────
test('encodeTextFrame writes an unmasked FIN text frame with 7-bit length', () => {
  const f = encodeTextFrame('hi');
  assert.equal(f[0], 0x81);           // FIN + text opcode
  assert.equal(f[1], 0x02);           // unmasked, len 2
  assert.equal(f.subarray(2).toString('utf8'), 'hi');
});
test('encodeTextFrame uses 16-bit length at the 126 boundary', () => {
  const s = 'x'.repeat(200);
  const f = encodeTextFrame(s);
  assert.equal(f[1], 126);            // extended-16 marker
  assert.equal(f.readUInt16BE(2), 200);
  assert.equal(f.subarray(4).toString('utf8'), s);
});
test('encodeTextFrame stays 7-bit at exactly 125 bytes', () => {
  const f = encodeTextFrame('y'.repeat(125));
  assert.equal(f[1], 125);            // still 7-bit, not the 126 marker
});
test('encodeTextFrame round-trips at the 126 boundary (7-bit would corrupt it)', () => {
  const s = 'p'.repeat(126);          // 126 as a 7-bit length IS the extend marker → must use 16-bit
  assert.deepEqual(decodeFrames(encodeTextFrame(s)).messages, [s]);
});
test('encodeTextFrame round-trips at the 65536 boundary (16-bit would overflow it)', () => {
  const s = 'q'.repeat(65536);        // 65536 overflows a 16-bit length → must use 64-bit
  assert.deepEqual(decodeFrames(encodeTextFrame(s)).messages, [s]);
});

// ─── decodeFrames ───────────────────────────────────────────────────────────
test('decodeFrames unmasks a client text frame', () => {
  const { messages, rest, close } = decodeFrames(maskClientFrame('{"k":1}'));
  assert.deepEqual(messages, ['{"k":1}']);
  assert.equal(rest.length, 0);
  assert.equal(close, false);
});
test('decodeFrames parses two frames in one buffer', () => {
  const buf = Buffer.concat([maskClientFrame('a'), maskClientFrame('bb')]);
  const { messages } = decodeFrames(buf);
  assert.deepEqual(messages, ['a', 'bb']);
});
test('decodeFrames returns an incomplete trailing frame as rest', () => {
  const whole = maskClientFrame('hello');
  const partial = whole.subarray(0, whole.length - 2); // chop the last 2 payload bytes
  const { messages, rest } = decodeFrames(partial);
  assert.deepEqual(messages, []);
  assert.equal(rest.length, partial.length); // nothing consumed — wait for more
});
test('decodeFrames carries the completed frame after a split', () => {
  const whole = maskClientFrame('hello');
  const a = whole.subarray(0, 4), b = whole.subarray(4);
  let { rest } = decodeFrames(a);            // incomplete
  const joined = Buffer.concat([rest, b]);
  const out = decodeFrames(joined);
  assert.deepEqual(out.messages, ['hello']);
});
test('decodeFrames flags a close frame', () => {
  const closeFrame = Buffer.from([0x88, 0x80, 0, 0, 0, 0]); // masked, empty close
  const { close } = decodeFrames(closeFrame);
  assert.equal(close, true);
});
test('decodeFrames consumes a 2-byte unmasked empty text frame (loop-bound boundary)', () => {
  // exactly fills the buffer: off+2 === buf.length must still process the frame
  const { messages, rest } = decodeFrames(Buffer.from([0x81, 0x00]));
  assert.deepEqual(messages, ['']);
  assert.equal(rest.length, 0);
});
test('decodeFrames handles the 16-bit length path', () => {
  const s = 'z'.repeat(300);
  const { messages } = decodeFrames(maskClientFrame(s));
  assert.deepEqual(messages, [s]);
});
test('decodeFrames flags an over-cap declared length (DoS defense) instead of buffering', () => {
  // 64-bit length declaring 2^40 bytes with a tiny cap → tooBig, no messages
  const hdr = Buffer.alloc(14);
  hdr[0] = 0x81; hdr[1] = 0x80 | 127; hdr.writeBigUInt64BE(BigInt(2 ** 40), 2);
  const { messages, tooBig } = decodeFrames(hdr, { maxPayload: 1 << 20 });
  assert.equal(tooBig, true);
  assert.deepEqual(messages, []);
});
test('decodeFrames does not flag a frame within the cap', () => {
  const { tooBig } = decodeFrames(maskClientFrame('ok'), { maxPayload: 1 << 20 });
  assert.equal(tooBig, false);
});
test('decodeFrames tooBig boundary: len === maxPayload passes, len > maxPayload fails', () => {
  const hdr = Buffer.from([0x81, 126, 0x00, 0xC8]); // declares 200-byte payload (header only)
  assert.equal(decodeFrames(hdr, { maxPayload: 200 }).tooBig, false); // exactly at cap → allowed
  assert.equal(decodeFrames(hdr, { maxPayload: 199 }).tooBig, true);  // one over → flagged
});
test('decodeFrames processes a 16-bit-length frame whose length bytes exactly fill the buffer', () => {
  // [text, len16 marker, 0x0000] — the 2 length bytes are the last bytes; the
  // read-guard must accept (p+2 == length), not break. Pins `>` not `>=`.
  const { messages } = decodeFrames(Buffer.from([0x81, 126, 0x00, 0x00]));
  assert.deepEqual(messages, ['']);
});
test('decodeFrames processes a 64-bit-length frame whose length bytes exactly fill the buffer', () => {
  const { messages } = decodeFrames(Buffer.from([0x81, 127, 0, 0, 0, 0, 0, 0, 0, 0]));
  assert.deepEqual(messages, ['']);
});

// ─── encodeControlFrame ─────────────────────────────────────────────────────
test('encodeControlFrame builds a FIN close/pong frame', () => {
  const f = encodeControlFrame(0x8);
  assert.equal(f[0], 0x88);
  assert.equal(f[1], 0);
});

// ─── Rooms (fan-out) ────────────────────────────────────────────────────────
test('Rooms carries to room-mates but never the sender', () => {
  const r = new Rooms();
  r.join('fed', 'A'); r.join('fed', 'B'); r.join('fed', 'C');
  assert.deepEqual(r.targets('A').sort(), ['B', 'C']);
  assert.equal(r.targets('A').includes('A'), false);
});
test('Rooms isolates distinct rooms', () => {
  const r = new Rooms();
  r.join('fed', 'A'); r.join('other', 'B');
  assert.deepEqual(r.targets('A'), []);   // B is in a different room
  assert.equal(r.roomOf('B'), 'other');
});
test('Rooms leave removes a member and cleans up empty rooms', () => {
  const r = new Rooms();
  r.join('fed', 'A');
  assert.equal(r.leave('A'), true);
  assert.equal(r.size, 0);
  assert.equal(r.byRoom.has('fed'), false); // empty room dropped
  assert.equal(r.leave('ghost'), false);    // unknown id
});
test('Rooms targets of an unknown id is empty', () => {
  const r = new Rooms();
  assert.deepEqual(r.targets('nobody'), []);
});
