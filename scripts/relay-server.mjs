/* scripts/relay-server.mjs
 * ◊·κ=1 · the cross-machine relay — SOCKET GLUE (I/O; not witnessed).
 * Wires the pure protocol (../niceassos-relay.mjs) to real TCP. A dumb,
 * untrusted carrier: it re-frames and fans out signed envelopes to room-mates,
 * never inspecting or trusting a payload. Every node verifies on receipt.
 *
 *   node scripts/relay-server.mjs                 # ws://localhost:17346/  ?room=fed
 *   RELAY_PORT=9000 node scripts/relay-server.mjs
 *
 * Run one of these on any box two machines can both reach (a cheap VPS, a
 * laptop with a forwarded port, a tailscale node). Point each machine's OS at
 * it (?room=<shared-secret-ish-name>) and their meshes federate.
 */
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import {
  acceptKey, encodeTextFrame, encodeControlFrame, decodeFrames, Rooms,
} from '../niceassos-relay.mjs';

export function createRelay(opts = {}) {
  const MAX_CONN = opts.maxConn || 512;         // total sockets on this relay
  const MAX_BUF = opts.maxBuf || (2 << 20);     // per-socket accumulated bytes (2 MiB)
  const MAX_PAYLOAD = opts.maxPayload || (1 << 20); // per-frame declared length (1 MiB)
  const IDLE_MS = opts.idleMs || 120000;        // drop a silent socket after 2 min

  const rooms = new Rooms();
  const sockets = new Map(); // id -> socket

  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(`niceassos-relay · ${rooms.size} connected · ${rooms.byRoom.size} room(s)\n`);
  });

  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    if (!key) { socket.destroy(); return; }          // invalid handshake
    if (sockets.size >= MAX_CONN) { socket.destroy(); return; } // connection cap
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`,
    );
    let room = 'fed';
    try { room = new URL(req.url, 'http://localhost').searchParams.get('room') || 'fed'; } catch (_) {}
    const id = randomUUID();
    sockets.set(id, socket);
    rooms.join(room, id);

    let buf = Buffer.alloc(0);
    let dead = false;
    const drop = () => { if (dead) return; dead = true; rooms.leave(id); sockets.delete(id); try { socket.destroy(); } catch (_) {} };

    socket.setTimeout(IDLE_MS, drop); // slowloris / idle defense

    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > MAX_BUF) { drop(); return; }   // never let one socket buffer without bound
      const { messages, rest, close, ping, tooBig } = decodeFrames(buf, { maxPayload: MAX_PAYLOAD });
      if (tooBig) { drop(); return; }                 // hostile declared frame length
      buf = rest;
      if (ping) { try { socket.write(encodeControlFrame(0xA, ping)); } catch (_) {} }
      for (const msg of messages) {
        // carry verbatim to every room-mate (re-framed unmasked); no inspection
        for (const tid of rooms.targets(id)) {
          const s = sockets.get(tid);
          if (s && !s.destroyed) { try { s.write(encodeTextFrame(msg)); } catch (_) {} }
        }
      }
      if (close) { try { socket.end(encodeControlFrame(0x8)); } catch (_) {} drop(); }
    });
    socket.on('close', drop);
    socket.on('error', drop);
  });

  return { server, rooms, sockets };
}

export function start(port = process.env.RELAY_PORT || 17346) {
  const relay = createRelay();
  return new Promise((resolve) => {
    relay.server.listen(port, () => {
      const addr = relay.server.address();
      resolve({ ...relay, port: addr.port, url: `ws://localhost:${addr.port}/` });
    });
  });
}

// run standalone
const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop());
if (isMain) {
  start().then(({ url }) => console.log(`niceassos-relay · ${url}  (federation rooms via ?room=…)`));
}
