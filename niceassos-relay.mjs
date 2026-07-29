/* niceassos-relay.mjs
 * ◊·κ=1 · the cross-machine carrier — PURE protocol (§6).
 * Architecture: Thomas Frumkin · Implementation: Simon Gant
 *
 * A relay federates two boxes' meshes by carrying signed envelopes between them.
 * It is a DUMB, UNTRUSTED carrier: it cannot forge (envelopes are Ed25519-signed
 * and prev_hash-chained — the kernel verifies on receipt), it can only carry or
 * drop. So the relay needs no keys and holds no trust; its whole job is
 * WebSocket framing + room fan-out, both of which are pure and gated here.
 *
 * This module is Node-only server infrastructure (uses Buffer / node:crypto).
 * The browser side needs none of it — browsers speak WebSocket natively. The
 * socket glue that wires these functions to real TCP lives in
 * scripts/relay-server.mjs (I/O, not witnessed).
 */
import { createHash } from 'node:crypto';

// RFC 6455 handshake: Sec-WebSocket-Accept = base64(sha1(key + GUID))
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
export function acceptKey(secWebSocketKey) {
  return createHash('sha1').update(secWebSocketKey + WS_GUID).digest('base64');
}

// Encode a server→client TEXT frame. Server frames are NEVER masked (RFC 6455).
export function encodeTextFrame(str) {
  const payload = Buffer.from(str, 'utf8');
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x81, len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81; header[1] = 126; header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81; header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

// Encode a control frame (close 0x8 / pong 0xA), unmasked, empty or short payload.
export function encodeControlFrame(opcode, payload = Buffer.alloc(0)) {
  const len = payload.length; // control payloads stay under 126 bytes by spec
  return Buffer.concat([Buffer.from([0x80 | (opcode & 0x0f), len]), payload]);
}

// Decode as many complete client→server frames as `buf` holds. Client frames
// are ALWAYS masked (RFC 6455). Returns the decoded text messages, any leftover
// bytes (an incomplete trailing frame), and control signals (close / ping /
// tooBig). `maxPayload` caps a single frame's declared length: a frame that
// declares more is a DoS attempt (buffer it forever) — we flag tooBig so the
// caller closes the connection instead of accumulating unbounded bytes.
// Message-level fragmentation (FIN=0 continuation) is not used for the small
// JSON envelopes this relay carries; continuation/pong opcodes are ignored.
export function decodeFrames(buf, { maxPayload = 1 << 20 } = {}) {
  const messages = [];
  let close = false;
  let ping = null;
  let tooBig = false;
  let off = 0;
  while (off + 2 <= buf.length) {
    const b0 = buf[off];
    const b1 = buf[off + 1];
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let p = off + 2;
    if (len === 126) {
      if (p + 2 > buf.length) break;
      len = buf.readUInt16BE(p); p += 2;
    } else if (len === 127) {
      if (p + 8 > buf.length) break;
      len = Number(buf.readBigUInt64BE(p)); p += 8;
    }
    if (len > maxPayload) { tooBig = true; break; } // hostile declared length → caller must close
    let mask = null;
    if (masked) {
      if (p + 4 > buf.length) break;
      mask = buf.subarray(p, p + 4); p += 4;
    }
    if (p + len > buf.length) break; // payload not fully arrived yet
    let payload = buf.subarray(p, p + len);
    if (masked) {
      const out = Buffer.alloc(len);
      for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i & 3];
      payload = out;
    }
    off = p + len;
    if (opcode === 0x8) { close = true; break; }          // close
    else if (opcode === 0x9) { ping = payload; }           // ping → caller pongs
    else if (opcode === 0x1) { messages.push(payload.toString('utf8')); } // text
    // 0x0 continuation / 0xA pong → ignored
  }
  return { messages, rest: buf.subarray(off), close, ping, tooBig };
}

// Rooms — the pure fan-out map. Each connection joins a named federation room;
// a message is carried to every OTHER member of the sender's room. The relay
// never inspects payloads — only membership.
export class Rooms {
  constructor() {
    this.byRoom = new Map(); // room -> Set(id)
    this.byId = new Map();   // id -> room
  }
  join(room, id) {
    if (!this.byRoom.has(room)) this.byRoom.set(room, new Set());
    this.byRoom.get(room).add(id);
    this.byId.set(id, room);
    return this.byRoom.get(room).size;
  }
  leave(id) {
    const room = this.byId.get(id);
    if (room === undefined) return false;
    this.byId.delete(id);
    const set = this.byRoom.get(room);
    if (set) { set.delete(id); if (set.size === 0) this.byRoom.delete(room); }
    return true;
  }
  // everyone in the sender's room except the sender
  targets(id) {
    const room = this.byId.get(id);
    if (room === undefined) return [];
    const set = this.byRoom.get(room);
    if (!set) return [];
    const out = [];
    for (const m of set) if (m !== id) out.push(m);
    return out;
  }
  roomOf(id) { return this.byId.get(id); }
  get size() { return this.byId.size; }
}

export default { acceptKey, encodeTextFrame, encodeControlFrame, decodeFrames, Rooms };
