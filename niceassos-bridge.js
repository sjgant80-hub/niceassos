/* niceassos-bridge.js
 * ◊·κ=1 · the browser adapter that lands the PURE kernel onto real hardware.
 * Architecture: Thomas Frumkin · Implementation: Simon Gant
 *
 * The kernel (niceassos-kernel.mjs) decides; this bridge does the I/O the kernel
 * refuses to touch: Ed25519 signing (Web Crypto), the niceassos-mesh
 * BroadcastChannel, SHA-256 for the hash chain, and IndexedDB identity.
 *
 * This is the seam where fallos.html stops being a private postMessage desktop
 * and becomes a first-class SIGNED NODE on niceassos-mesh — the merge, made real.
 *
 *   import { installOS } from './niceassos-bridge.js';
 *   const os = await installOS({ manifest: { name:'niceassos-ground', ring:0, ... } });
 *   os.emit('organ_event', { from:'crm', event:'deal.closed', data:{...} });
 *   os.onEnvelope(env => { ... });               // every signed envelope on the bus
 *   os.requestAI({ prompt, tokens }, onToken);   // cascade: local-first, remote fallback
 */
import {
  VERSION, SIGNAL_VERSION, MeshLog, canonicalJSON, fnv1a, admit, route, cascade, ringGlyph, organEvent,
  verifyEnvelope, FederationLedger, SeenCache, fingerprint, shouldFederate, validSignal, politePeer,
} from './niceassos-kernel.mjs';

const FRESHNESS_MS = 300000; // reject relayed envelopes whose ts is >5 min off — bounds reconnect-replay

const DB_NAME = 'niceassos-seed-v1';
const DB_STORE = 'identity';
const FALLBACK_STORE = 'niceassos-organ-v1';
const MESH = 'niceassos-mesh';
const LEGACY = 'fall-signal';

const enc = new TextEncoder();
const hex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = (s) => { const a = new Uint8Array(s.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(s.substr(i * 2, 2), 16); return a; };
const sha256hex = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));

// Verify a remote envelope's Ed25519 signature against its own fork_pub. The
// relay is untrusted; this is what makes a forged/tampered envelope unusable.
async function verifyRemoteSig(env) {
  if (!env || typeof env.signature !== 'string' || typeof env.fork_pub !== 'string') return false;
  try {
    const pub = await crypto.subtle.importKey('raw', unhex(env.fork_pub), { name: 'Ed25519' }, false, ['verify']);
    const { signature, ...rest } = env; // sign was over the envelope MINUS signature
    return await crypto.subtle.verify({ name: 'Ed25519' }, pub, unhex(signature), enc.encode(canonicalJSON(rest)));
  } catch (_) { return false; }
}

// ─── IndexedDB (identity persistence, shared with organ-graft) ───────────────
function openDB(name, store) {
  return new Promise((res, rej) => {
    const req = indexedDB.open(name, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(store)) db.createObjectStore(store);
    };
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}
async function dbGet(name, store, key) {
  const db = await openDB(name, store);
  return new Promise((res, rej) => {
    const tx = db.transaction(store, 'readonly').objectStore(store).get(key);
    tx.onsuccess = () => res(tx.result);
    tx.onerror = () => rej(tx.error);
  });
}
async function dbPut(name, store, key, val) {
  const db = await openDB(name, store);
  return new Promise((res, rej) => {
    const tx = db.transaction(store, 'readwrite').objectStore(store).put(val, key);
    tx.onsuccess = () => res();
    tx.onerror = () => rej(tx.error);
  });
}

// ─── identity: reuse the niceassos-seed fork key if present, else mint ───────
async function loadOrMintIdentity() {
  try {
    const seed = await dbGet(DB_NAME, DB_STORE, 'fork');
    if (seed && seed.konomi_pub && seed.konomi_priv) {
      return { pubHex: seed.konomi_pub, privKey: seed.konomi_priv, source: 'niceassos-seed' };
    }
  } catch (_) { /* no seed */ }
  try {
    const existing = await dbGet(FALLBACK_STORE, FALLBACK_STORE, 'os-identity');
    if (existing && existing.pubHex && existing.privKey) return existing;
  } catch (_) {}
  try {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
    const rec = { pubHex: hex(raw), privKey: pair.privateKey, source: 'os-local-ed25519' };
    await dbPut(FALLBACK_STORE, FALLBACK_STORE, 'os-identity', rec);
    return rec;
  } catch (e) {
    const r = crypto.getRandomValues(new Uint8Array(32));
    return { pubHex: hex(r), privKey: null, source: 'fallback-random' };
  }
}

async function signCanonical(privKey, envMinusSig) {
  if (!privKey) return null;
  try {
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, privKey, enc.encode(canonicalJSON(envMinusSig)));
    return hex(sig);
  } catch (_) { return null; }
}

// ─── the local-AI tier: fallrelay WS bridge (own GPU / WebLLM), best-effort ──
// Returns a probe you can call to check availability, and a completer.
function makeLocalWorker(relayURL) {
  const url = relayURL || 'ws://localhost:17345/relay';
  let ws = null, ready = false;
  const pending = new Map();
  function connect() {
    try {
      ws = new WebSocket(url);
      ws.onopen = () => { ready = true; };
      ws.onclose = () => { ready = false; };
      ws.onerror = () => { ready = false; };
      ws.onmessage = (ev) => {
        let m; try { m = JSON.parse(ev.data); } catch (_) { return; }
        const cb = pending.get(m.id);
        if (cb) { cb(m); if (m.done) pending.delete(m.id); }
      };
    } catch (_) { ready = false; }
  }
  connect();
  return {
    available: () => ready,
    complete: (prompt, id, onChunk) => {
      if (!ready) return false;
      pending.set(id, (m) => onChunk(m.text || '', !!m.done));
      try { ws.send(JSON.stringify({ type: 'complete', id, prompt })); return true; }
      catch (_) { return false; }
    },
  };
}

// ─── installOS: the OS grafts itself as a signed node, returns the mesh API ──
export async function installOS(opts = {}) {
  const manifest = opts.manifest || {
    name: 'niceassos-ground', ring: 0, glyph: ringGlyph(0),
    purpose: 'the OS ground · window manager + signed mesh kernel',
    publishes: ['fork_join', 'beacon', 'organ_event'],
    listens: ['organ_event', 'beacon', 'bloom_pulse'],
  };
  const identity = await loadOrMintIdentity();
  const log = new MeshLog({ forkPub: identity.pubHex, hasher: (s) => s }); // seq only; real hash below
  let prevHash = null;
  let seq = 0;

  let mesh = null, legacy = null;
  try { mesh = new BroadcastChannel(MESH); } catch (_) {}
  try { legacy = new BroadcastChannel(LEGACY); } catch (_) {}

  const envListeners = new Set();
  const local = makeLocalWorker(opts.relayURL);

  // ── federation: carry this box's mesh to another box ─────────────────────────
  // Transport-agnostic. Envelopes are self-authenticating (Ed25519 + prev_hash
  // chain), so a CARRIER — a WebSocket relay OR a peer-to-peer WebRTC data
  // channel — only carries. On receipt every envelope is structurally checked,
  // signature-verified against its fork_pub, replay/chain-checked (FederationLedger),
  // deduped (SeenCache), then injected onto the local mesh. Forwarding uses
  // shouldFederate to keep one coherent chain across sibling tabs.
  let fed = null;

  // per-room federation state, shared by every carrier
  function makeFedContext(room, extra) {
    const ledgerKey = 'ledger:' + room, hwKey = 'fedhw:' + room;
    let ledger = new FederationLedger();
    const hydrated = (async () => {
      try {
        const snap = await dbGet(FALLBACK_STORE, FALLBACK_STORE, ledgerKey);
        if (snap && typeof snap === 'object') ledger = new FederationLedger({ initial: snap });
      } catch (_) {}
    })();
    let persistTimer = null;
    const persist = () => {
      if (persistTimer) return;
      persistTimer = setTimeout(() => { persistTimer = null; dbPut(FALLBACK_STORE, FALLBACK_STORE, ledgerKey, ledger.snapshot()).catch(() => {}); }, 500);
    };
    const hw = { seq: -1, key: hwKey };
    let hwTimer = null;
    const persistHw = () => {
      if (hwTimer) return;
      hwTimer = setTimeout(() => { hwTimer = null; dbPut(FALLBACK_STORE, FALLBACK_STORE, hwKey, { seq: hw.seq }).catch(() => {}); }, 500);
    };
    const stat = Object.assign({ connected: false, sent: 0, recv: 0, rejected: 0, room }, extra || {});
    return { room, get ledger() { return ledger; }, hydrated, persist, hw, persistHw, seen: new SeenCache(4096), stat };
  }

  // resume our fork's seq strictly above the persisted high-water (a gap, so the
  // remote ledger accepts rather than chain-breaking) — no regression on failover
  // or reconnect. Shared by every carrier before it starts forwarding.
  async function resumeSeqAboveHighWater(ctx) {
    try {
      const rec = await dbGet(FALLBACK_STORE, FALLBACK_STORE, ctx.hw.key);
      if (rec && Number.isInteger(rec.seq)) { ctx.hw.seq = rec.seq; if (seq <= ctx.hw.seq) seq = ctx.hw.seq + 2; }
    } catch (_) {}
  }

  // the four-check receive path — identical for every carrier
  async function fedReceive(data, ctx) {
    let env; try { env = JSON.parse(data); } catch (_) { return; }
    await ctx.hydrated; // ledger loaded before we judge replay
    if (!verifyEnvelope(env, { requireSig: true, maxSkewMs: FRESHNESS_MS, now: Date.now() }).ok) { ctx.stat.rejected++; return; }
    if (!(await verifyRemoteSig(env))) { ctx.stat.rejected++; return; }  // a carrier can't forge
    const h = await sha256hex(canonicalJSON(env));
    if (!ctx.ledger.accept(env, h).ok) { ctx.stat.rejected++; return; }  // replay / chain break
    if (!ctx.seen.add(h)) return;                                        // already handled → no loop
    ctx.persist(); ctx.stat.recv++;
    try { mesh && mesh.postMessage(env); } catch (_) {}                  // inject onto local mesh (all tabs see it)
    envListeners.forEach(fn => { try { fn(env); } catch (_) {} });
    try { window.dispatchEvent(new CustomEvent('niceassos:fed-recv', { detail: env })); } catch (_) {}
  }

  // SERIALIZE receive per context: carriers deliver envelopes in order (TCP/SCTP
  // ordered), but fedReceive is async — two close-together envelopes could
  // interleave and hit the ledger out of order, making it reject the earlier
  // (now "stale") one. Chain them so the ledger sees them in arrival order.
  function fedReceiveOrdered(data, ctx) {
    ctx.recvTail = (ctx.recvTail || Promise.resolve()).then(() => fedReceive(data, ctx)).catch(() => {});
    return ctx.recvTail;
  }

  // the forward path — identical for every carrier; `send(str)→bool` is the wire
  async function fedForward(env, fromEmit, ctx, send) {
    if (!ctx.stat.connected) return;
    if (!shouldFederate(env, identity.pubHex, !!fromEmit)) return;
    const h = await sha256hex(canonicalJSON(env));
    if (ctx.seen.has(h)) return;              // came from the carrier, or already sent → don't echo
    if (!send(JSON.stringify(env))) return;   // send failed → do NOT mark seen; stays retryable (no chain gap)
    ctx.seen.add(h);                          // record only after a confirmed send
    ctx.stat.sent++;
    if (env.fork_pub === identity.pubHex && Number.isInteger(env.seq) && env.seq > ctx.hw.seq) { ctx.hw.seq = env.seq; ctx.persistHw(); }
  }

  // ── carrier 1: WebSocket relay (with Web Locks leader election) ──────────────
  function connectFederation(url, room) {
    if (fed && fed.stop) { try { fed.stop(); } catch (_) {} } // one active carrier per machine
    room = room || 'fed';
    const wsurl = url + (url.includes('?') ? '&' : '?') + 'room=' + encodeURIComponent(room);
    const ctx = makeFedContext(room, { leader: false, transport: 'ws', url: wsurl });
    let ws = null;
    let releaseLock = null; // resolves the held Web Lock so a queued tab can take over
    function openSocket() {
      try { ws = new WebSocket(wsurl); } catch (_) { return; }
      ws.onopen = () => { ctx.stat.connected = true; try { window.dispatchEvent(new CustomEvent('niceassos:fed-open', { detail: { ...ctx.stat } })); } catch (_) {} };
      ws.onclose = () => { ctx.stat.connected = false; if (ctx.stat.leader && fed) setTimeout(() => { if (ctx.stat.leader && fed) openSocket(); }, 2000); };
      ws.onerror = () => { ctx.stat.connected = false; };
      ws.onmessage = (ev) => fedReceiveOrdered(ev.data, ctx);
    }
    async function becomeLeader() {
      ctx.stat.leader = true;
      await resumeSeqAboveHighWater(ctx);
      openSocket();
    }
    // LEADER ELECTION (Web Locks): whichever tab holds the exclusive lock is the
    // machine's federation gateway — the only tab with a relay socket and the only
    // forwarder. The lock releases on tab close OR on stop() (via releaseLock), so
    // a queued tab takes over on failover, carrier-switch, or re-federate.
    const lockName = 'niceassos-fed:' + room;
    if (typeof navigator !== 'undefined' && navigator.locks && navigator.locks.request) {
      navigator.locks.request(lockName, { mode: 'exclusive' }, () => new Promise((resolve) => { releaseLock = resolve; becomeLeader(); })).catch(() => {});
    } else {
      becomeLeader(); // no Web Locks → behave as the sole tab
    }
    const send = (s) => { try { if (ws && ws.readyState === 1) { ws.send(s); return true; } } catch (_) {} return false; };
    fed = {
      status: () => ({ ...ctx.stat }),
      forward: (env, fromEmit) => fedForward(env, fromEmit, ctx, send),
      stop: () => {
        ctx.stat.leader = false;
        try { ws && ws.close(); } catch (_) {}
        if (releaseLock) { try { releaseLock(); } catch (_) {} releaseLock = null; } // free the lock → queued tab takes over
        fed = null;
      },
    };
    return fed;
  }

  // Sign a signal blob so it is TAMPER-EVIDENT: Ed25519 over
  // (v,type,room,from,to,ts,sha256(sdp)). `to` and `ts` are INSIDE the signed
  // body so a relay cannot redirect a signed offer or replay a stale one. A peer
  // verifies against the blob's own `from`. NOTE: full MITM protection also
  // requires confirming the peer's `from` fork_pub out-of-band.
  const signalBody = async (sig) => ({
    v: sig.v, type: sig.type, room: sig.room, from: sig.from,
    to: sig.to ?? null, ts: sig.ts ?? null, sdpHash: await sha256hex(sig.sdp || ''),
  });
  async function signSignal(sig) {
    return Object.assign({}, sig, { sig: await signCanonical(identity.privKey, await signalBody(sig)) });
  }
  // opts.maxSkewMs (auto-signaling) rejects a signal whose ts is stale/future →
  // replay defense. Manual copy-paste passes no maxSkewMs (a blob may be pasted
  // minutes later), so ts is signed but not freshness-checked there.
  async function verifySignalSig(sig, opts = {}) {
    if (!sig || typeof sig.sig !== 'string' || typeof sig.from !== 'string') return false;
    if (opts.maxSkewMs) {
      if (typeof sig.ts !== 'number' || Math.abs(Date.now() - sig.ts) > opts.maxSkewMs) return false;
    }
    try {
      const pub = await crypto.subtle.importKey('raw', unhex(sig.from), { name: 'Ed25519' }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'Ed25519' }, pub, unhex(sig.sig), enc.encode(canonicalJSON(await signalBody(sig))));
    } catch (_) { return false; }
  }

  // ── carrier 2: WebRTC data channel — a RELAY-FREE, peer-to-peer transport ────
  // Non-trickle ICE: gather all candidates, then hand back ONE offer/answer blob
  // for out-of-band exchange (copy-paste / QR / any shared channel). No signaling
  // server, no relay in the data path. `iceServers` (STUN) only needed for
  // internet NAT traversal; default = host candidates (same machine / LAN), zero
  // external dependency.
  const RTC_BACKPRESSURE = 4 << 20; // 4 MiB buffered → treat send as failed (retryable)
  function makeRTCCarrier({ iceServers, room }) {
    const openCbs = [], closeCbs = [], msgCbs = [], drainCbs = [];
    const pc = new RTCPeerConnection({ iceServers: iceServers || [] });
    let dc = null;
    function wire(channel) {
      dc = channel;
      try { dc.bufferedAmountLowThreshold = RTC_BACKPRESSURE >> 1; } catch (_) {}
      dc.onopen = () => openCbs.forEach(f => { try { f(); } catch (_) {} });
      dc.onclose = () => closeCbs.forEach(f => { try { f(); } catch (_) {} });
      dc.onmessage = (e) => msgCbs.forEach(f => { try { f(e.data); } catch (_) {} });
      dc.onbufferedamountlow = () => drainCbs.forEach(f => { try { f(); } catch (_) {} }); // congestion cleared → flush queues
    }
    pc.ondatachannel = (e) => wire(e.channel); // the answerer receives the channel
    // wait for ICE gathering to finish (or a 3s cap) — with full listener/timer cleanup
    function gathered() {
      return new Promise((resolve) => {
        if (pc.iceGatheringState === 'complete') return resolve();
        let done = false;
        let timer = null;
        const finish = () => { if (done) return; done = true; clearTimeout(timer); pc.removeEventListener('icegatheringstatechange', check); resolve(); };
        const check = () => { if (pc.iceGatheringState === 'complete') finish(); };
        pc.addEventListener('icegatheringstatechange', check);
        timer = setTimeout(finish, 3000); // fall back to partial candidates
      });
    }
    return {
      kind: 'rtc',
      onOpen: (f) => openCbs.push(f), onClose: (f) => closeCbs.push(f), onMessage: (f) => msgCbs.push(f), onDrain: (f) => drainCbs.push(f),
      // backpressure: if the channel is congested, report a (retryable) failure
      // instead of dropping — fedForward won't mark it seen, so it isn't lost.
      send: (s) => { try { if (dc && dc.readyState === 'open' && dc.bufferedAmount < RTC_BACKPRESSURE) { dc.send(s); return true; } } catch (_) {} return false; },
      isOpen: () => !!dc && dc.readyState === 'open',
      close: () => { try { dc && dc.close(); } catch (_) {} try { pc.close(); } catch (_) {} },
      // extra = { to, ts } folded into the signed signal; verifyOpts = { maxSkewMs }
      createOffer: async (selfPub, extra) => {
        wire(pc.createDataChannel('niceassos-fed'));
        await pc.setLocalDescription(await pc.createOffer());
        await gathered();
        return signSignal(Object.assign({ v: SIGNAL_VERSION, type: 'offer', from: selfPub, room, sdp: pc.localDescription.sdp }, extra || {}));
      },
      acceptOffer: async (offerSignal, selfPub, extra, verifyOpts) => {
        const chk = validSignal(offerSignal);
        if (!chk.ok || offerSignal.type !== 'offer') throw new Error('bad offer signal: ' + chk.reason);
        if (!(await verifySignalSig(offerSignal, verifyOpts))) throw new Error('offer signature invalid (tampered, unsigned, or stale)');
        await pc.setRemoteDescription({ type: 'offer', sdp: offerSignal.sdp });
        await pc.setLocalDescription(await pc.createAnswer());
        await gathered();
        return signSignal(Object.assign({ v: SIGNAL_VERSION, type: 'answer', from: selfPub, room, sdp: pc.localDescription.sdp }, extra || {}));
      },
      acceptAnswer: async (answerSignal, verifyOpts) => {
        const chk = validSignal(answerSignal);
        if (!chk.ok || answerSignal.type !== 'answer') throw new Error('bad answer signal: ' + chk.reason);
        if (!(await verifySignalSig(answerSignal, verifyOpts))) throw new Error('answer signature invalid (tampered, unsigned, or stale)');
        await pc.setRemoteDescription({ type: 'answer', sdp: answerSignal.sdp });
      },
    };
  }

  function connectFederationRTC(opts) {
    opts = opts || {};
    const room = opts.room || 'fed';
    if (fed && fed.stop) { try { fed.stop(); } catch (_) {} } // one active carrier per machine
    const ctx = makeFedContext(room, { leader: true, transport: 'rtc', role: null });
    const carrier = makeRTCCarrier({ iceServers: opts.iceServers, room });
    // resume seq above the high-water BEFORE the channel is marked connected, so
    // no envelope is forwarded until the seq is guaranteed non-regressing.
    carrier.onOpen(async () => {
      await resumeSeqAboveHighWater(ctx);
      ctx.stat.connected = true;
      try { window.dispatchEvent(new CustomEvent('niceassos:fed-open', { detail: { ...ctx.stat } })); } catch (_) {}
    });
    carrier.onClose(() => { ctx.stat.connected = false; });
    carrier.onMessage((data) => fedReceiveOrdered(data, ctx));
    fed = {
      status: () => ({ ...ctx.stat }),
      forward: (env, fromEmit) => fedForward(env, fromEmit, ctx, carrier.send),
      stop: () => { try { carrier.close(); } catch (_) {} fed = null; },
      // manual (relay-free) signaling — exchange these blobs out-of-band:
      //   initiator: const offer = await fed.createOffer();  → send offer to peer
      //   answerer:  const answer = await fed.acceptOffer(offer); → send answer back
      //   initiator: await fed.acceptAnswer(answer);  → data channel opens
      createOffer: () => { ctx.stat.role = 'initiator'; return carrier.createOffer(identity.pubHex); },
      acceptOffer: (offerSignal) => { ctx.stat.role = 'answerer'; return carrier.acceptOffer(offerSignal, identity.pubHex); },
      acceptAnswer: (answerSignal) => carrier.acceptAnswer(answerSignal),
    };
    return fed;
  }

  // ── carrier 3: WebRTC AUTO-signaling — N-PEER FULL MESH ──────────────────────
  // Every machine in the signaling room holds a direct WebRTC link to every other
  // machine (K machines → K−1 links each). The relay brokers ONLY the handshake;
  // envelopes go peer-to-peer over the mesh. Discovery: signed `hello`; each PAIR
  // negotiates independently and politePeer picks that pair's offerer. Each link
  // self-heals (per-link negotiation timeout tears down + re-announces). Forwarding
  // broadcasts to every open link; the shared FederationLedger/SeenCache dedup
  // across links. Web Locks elects one gateway tab per machine. opts.peers (array)
  // pins an allow-list; MAX_PEERS bounds the mesh. Note: FULL mesh (no relay-through
  // gossip) — two machines that cannot form a direct link do not exchange.
  const SIGNAL_SKEW_MS = 60000;  // reject signals whose ts is >1 min off (replay defense)
  const NEGO_TIMEOUT_MS = 12000; // no open data channel within this → tear down + restart
  const MAX_PEERS = 16;          // total links (memory bound)
  const MAX_PENDING = 6;         // half-open (negotiating) links — sybil / churn bound
  const OUTBOX_MAX = 512;        // per-link backlog bound
  function connectFederationRTCAuto(opts) {
    opts = opts || {};
    const room = opts.room || 'fed';
    if (!opts.url) throw new Error('federateRTCAuto needs { url } (a relay for signaling)');
    if (fed && fed.stop) { try { fed.stop(); } catch (_) {} } // one active carrier per machine
    const allow = Array.isArray(opts.peers) ? new Set(opts.peers) : (typeof opts.peer === 'string' ? new Set([opts.peer]) : null);
    const sigRoom = 'rtcsig:' + room; // isolate signaling from any WS-carrier envelope room
    const wsurl = opts.url + (opts.url.includes('?') ? '&' : '?') + 'room=' + encodeURIComponent(sigRoom);
    const ctx = makeFedContext(room, { leader: false, transport: 'rtc-auto', peers: 0, connectedPeers: 0 });
    const links = new Map(); // peerPub -> { pub, carrier, role, negoTimer, connected, outbox[], delivered }
    const sigSeen = new SeenCache(2048); // signal-level replay cache (within the freshness window)
    let sigWs = null, releaseLock = null, stopped = false;

    function sigSend(obj) { try { if (sigWs && sigWs.readyState === 1) sigWs.send(JSON.stringify(obj)); } catch (_) {} }
    async function hello(to) {
      const h = { v: SIGNAL_VERSION, type: 'hello', from: identity.pubHex, room, ts: Date.now() };
      if (to) h.to = to;
      sigSend(await signSignal(h));
    }
    function pendingCount() { let n = 0; for (const l of links.values()) if (!l.connected) n++; return n; }
    // reject a NEW peer if the total or half-open budget is exhausted (sybil bound)
    function overBudget(from) { return !links.has(from) && (links.size >= MAX_PEERS || pendingCount() >= MAX_PENDING); }
    function refreshStats() {
      ctx.stat.peers = links.size;
      ctx.stat.connectedPeers = [...links.values()].filter(l => l.connected).length;
      ctx.stat.connected = ctx.stat.connectedPeers > 0;
    }
    function link(pub) {
      let l = links.get(pub);
      if (!l) { l = { pub, carrier: null, role: null, negoTimer: null, connected: false, outbox: [], delivered: new SeenCache(4096) }; links.set(pub, l); refreshStats(); }
      return l;
    }
    function clearNego(l) { if (l.negoTimer) { clearTimeout(l.negoTimer); l.negoTimer = null; } }
    function dropLink(l, reannounce) {
      clearNego(l);
      try { l.carrier && l.carrier.close(); } catch (_) {}
      links.delete(l.pub); refreshStats();
      if (reannounce && !stopped) hello(l.pub); // DIRECTIONAL re-invite (not a room-wide broadcast)
    }
    function armNego(l) {
      clearNego(l);
      l.negoTimer = setTimeout(() => { if (!stopped && (!l.carrier || !l.carrier.isOpen())) dropLink(l, true); }, NEGO_TIMEOUT_MS);
    }
    // PER-LINK delivery: each link drains its own outbox, so a slow/late/congested
    // link never loses an envelope a faster link already got (the N-peer fix).
    function flushLink(l) {
      if (!l.carrier || !l.carrier.isOpen()) return;
      while (l.outbox.length) {
        const item = l.outbox[0];
        if (l.carrier.send(item.s)) { l.outbox.shift(); l.delivered.add(item.k); }
        else break; // congested → wait for onDrain / next flush
      }
    }
    function wireCarrier(l) {
      l.carrier.onOpen(async () => { clearNego(l); l.connected = true; await resumeSeqAboveHighWater(ctx); refreshStats(); flushLink(l); try { window.dispatchEvent(new CustomEvent('niceassos:fed-open', { detail: { ...ctx.stat, peer: l.pub } })); } catch (_) {} });
      l.carrier.onClose(() => { if (!stopped) dropLink(l, true); }); // dropped link → tear down + re-invite
      l.carrier.onDrain(() => flushLink(l));                          // congestion cleared → drain backlog
      l.carrier.onMessage((data) => fedReceiveOrdered(data, ctx));           // shared ctx → ledger/seen dedup across links
    }
    async function startOffer(l) {
      if (l.carrier) return;
      l.role = 'offerer';
      l.carrier = makeRTCCarrier({ iceServers: opts.iceServers, room });
      wireCarrier(l); armNego(l);
      const offer = await l.carrier.createOffer(identity.pubHex, { to: l.pub, ts: Date.now() });
      sigSend(offer);
    }
    async function onSignal(msg) {
      if (!validSignal(msg).ok) return;
      if (msg.from === identity.pubHex) return;         // our own echo (or same-identity tab)
      if (msg.to && msg.to !== identity.pubHex) return; // directed at another peer
      if (allow && !allow.has(msg.from)) return;        // allow-list (opts.peers)
      if (!(await verifySignalSig(msg, { maxSkewMs: SIGNAL_SKEW_MS }))) return; // tampered / unsigned / stale
      if (typeof msg.sig === 'string' && !sigSeen.add(msg.sig)) return; // exact replay of a signed signal → drop
      if (msg.type === 'hello') {
        const existing = links.get(msg.from);
        if (existing && existing.carrier) return;       // already negotiating/connected with this peer
        if (overBudget(msg.from)) return;               // sybil / capacity bound (re-checked post-verify)
        await hello(msg.from);                          // reply so this peer learns us
        const l = link(msg.from);
        if (!politePeer(identity.pubHex, msg.from)) await startOffer(l); // impolite → we offer
        else armNego(l);                                // polite → wait for their offer, but bounded
        return;
      }
      if (msg.type === 'offer') {
        if (overBudget(msg.from)) return;
        const l = link(msg.from);
        if (l.carrier && l.carrier.isOpen()) return;    // already connected with this peer
        if (l.carrier) { clearNego(l); try { l.carrier.close(); } catch (_) {} l.carrier = null; } // rebuild for this offer
        l.role = 'answerer';
        l.carrier = makeRTCCarrier({ iceServers: opts.iceServers, room });
        wireCarrier(l); armNego(l);
        const answer = await l.carrier.acceptOffer(msg, identity.pubHex, { to: msg.from, ts: Date.now() }, { maxSkewMs: SIGNAL_SKEW_MS });
        sigSend(answer);
        return;
      }
      if (msg.type === 'answer') {
        const l = links.get(msg.from);
        if (!l || !l.carrier || l.role !== 'offerer') return;
        try { await l.carrier.acceptAnswer(msg, { maxSkewMs: SIGNAL_SKEW_MS }); } catch (_) {}
      }
    }
    function openSignaling() {
      try { sigWs = new WebSocket(wsurl); } catch (_) { return; }
      sigWs.onopen = () => { hello(); };                // announce presence to the whole room (once)
      sigWs.onmessage = (ev) => { let m; try { m = JSON.parse(ev.data); } catch (_) { return; } if (m && m.v === SIGNAL_VERSION) onSignal(m); };
      sigWs.onclose = () => { if (!stopped && ctx.stat.leader && fed) setTimeout(() => { if (!stopped && ctx.stat.leader && fed) openSignaling(); }, 2000); };
      sigWs.onerror = () => {};
    }
    function becomeLeader() { ctx.stat.leader = true; openSignaling(); }
    const lockName = 'niceassos-fed:' + room; // shared with the WS carrier → one gateway tab/machine
    if (typeof navigator !== 'undefined' && navigator.locks && navigator.locks.request) {
      navigator.locks.request(lockName, { mode: 'exclusive' }, () => new Promise((resolve) => { releaseLock = resolve; becomeLeader(); })).catch(() => {});
    } else { becomeLeader(); }
    fed = {
      status: () => ({ ...ctx.stat }),
      // enqueue to EVERY link that hasn't already been delivered this envelope, then
      // flush. Per-link outboxes + onOpen/onDrain flushing mean a slow or late link
      // gets the backlog — no envelope is lost just because a faster link took it.
      forward: (env, fromEmit) => fedForward(env, fromEmit, ctx, (s) => {
        const k = fnv1a(s);
        let queued = false;
        for (const l of links.values()) {
          if (l.delivered.has(k)) continue;
          l.outbox.push({ s, k });
          while (l.outbox.length > OUTBOX_MAX) l.outbox.shift(); // bound the backlog
          flushLink(l);
          queued = true;
        }
        return queued || links.size === 0; // handled → ctx.seen dedups our own re-forward
      }),
      stop: () => {
        stopped = true; ctx.stat.leader = false;
        for (const l of links.values()) { clearNego(l); try { l.carrier && l.carrier.close(); } catch (_) {} }
        links.clear();
        try { sigWs && sigWs.close(); } catch (_) {}
        if (releaseLock) { try { releaseLock(); } catch (_) {} releaseLock = null; }
        fed = null;
      },
    };
    return fed;
  }

  // emit: build (kernel) → SHA-256 chain (bridge) → Ed25519 sign (bridge) → post.
  // SERIALIZED through emitTail: seq++ and the async sha256 chain must advance
  // atomically, or two overlapping emits interleave and scramble prev_hash.
  let emitTail = Promise.resolve();
  async function doEmit(kind, payload) {
    const envMinusSig = {
      version: VERSION, kind, fork_pub: identity.pubHex,
      ts: new Date().toISOString(), seq: seq++, prev_hash: prevHash, payload,
    };
    const signature = await signCanonical(identity.privKey, envMinusSig);
    const env = Object.assign({}, envMinusSig, { signature });
    prevHash = await sha256hex(canonicalJSON(env));
    try { mesh && mesh.postMessage(env); } catch (_) {}
    try { legacy && legacy.postMessage(env); } catch (_) {}
    if (fed) fed.forward(env, true);   // our own emit → always carry to the other box
    try { window.dispatchEvent(new CustomEvent('niceassos:sent', { detail: env })); } catch (_) {}
    return env;
  }
  function emit(kind, payload) {
    const p = emitTail.then(() => doEmit(kind, payload));
    emitTail = p.catch(() => {}); // chain regardless of a prior failure
    return p;
  }

  // dedup local ingress: an envelope may arrive on BOTH the mesh and legacy
  // channels; deliver it to listeners once.
  const localSeen = new SeenCache(4096);
  function onMesh(ev) {
    const env = ev.data || {};
    if (!localSeen.add(fingerprint(env))) return; // same envelope on mesh+legacy → once
    if (fed) fed.forward(env, false);   // other local emitter → forward only if a different fork
    envListeners.forEach(fn => { try { fn(env); } catch (_) {} });
    try { window.dispatchEvent(new CustomEvent('niceassos:recv', { detail: env })); } catch (_) {}
  }
  mesh && (mesh.onmessage = onMesh);
  legacy && (legacy.onmessage = onMesh);

  // graft: fork_join announces the OS on the bus
  await emit('fork_join', {
    handle: manifest.name, vertical: manifest.purpose, seeded_at: new Date().toISOString(),
    organ: { name: manifest.name, ring: manifest.ring, glyph: manifest.glyph,
             publishes: manifest.publishes, listens: manifest.listens },
  });
  // heartbeat
  const beacon = setInterval(() => emit('beacon', { handle: manifest.name, ring: manifest.ring, glyph: manifest.glyph }),
    opts.beaconInterval || 60000);

  const api = {
    identity: () => ({ pub: identity.pubHex, source: identity.source }),
    emit,
    onEnvelope: (fn) => { envListeners.add(fn); return () => envListeners.delete(fn); },

    // admission: proof-of-play gate — pure kernel decides, bridge enforces
    admit: (m, status) => admit(m, status),

    // route an app domain-event across the mounted organ graph (pure kernel)
    // AND put a signed organ_event on the mesh. Returns the target organ names.
    fireOrganEvent: (from, event, data, mountedOrgans) => {
      const env = { kind: 'organ_event', payload: organEvent(from, event, data) };
      const targets = route(env, mountedOrgans);
      emit('organ_event', env.payload); // signed, on the bus
      return targets;
    },

    // brain: cascade decides the tier, then serve it. Streams via onToken(text, done).
    requestAI: (task, onToken) => {
      const caps = { local: local.available(), remote: !!opts.remote };
      const pick = cascade(task || {}, caps);
      const id = 'ai-' + seq + '-' + Math.floor(performance.now());
      if (pick.tier === 'local') {
        const ok = local.complete(task.prompt || '', id, (text, done) => onToken(text, done, pick));
        if (ok) return pick;
        // local said available but send failed → degrade
      }
      // no live worker wired in-browser yet for 'remote'/'none' → honest signal
      onToken(`[cascade:${pick.tier}] ${pick.reason}. `
        + (pick.tier === 'local'
          ? 'Local worker dropped — start fallrelay (ws://localhost:17345/relay).'
          : pick.tier === 'remote'
            ? 'Remote tier not wired in this build — use the si-didy-agent cockpit.'
            : 'Load a local worker (fallrelay / didi) to give the OS a brain.'),
        true, pick);
      return pick;
    },

    // federation: join another box's mesh over a relay. Returns a handle whose
    // .status() reports { connected, sent, recv, rejected }.
    federate: (url, room) => connectFederation(url, room),               // WebSocket relay carrier
    federateRTC: (opts) => connectFederationRTC(opts || {}),             // relay-free WebRTC (manual signaling)
    federateRTCAuto: (opts) => connectFederationRTCAuto(opts || {}),     // WebRTC, relay brokers only the handshake
    federation: () => (fed ? fed.status() : { connected: false, leader: false, sent: 0, recv: 0, rejected: 0 }),

    manifest: () => Object.assign({}, manifest),
    stop: () => { clearInterval(beacon); if (fed) fed.stop(); try { mesh.close(); } catch (_) {} try { legacy.close(); } catch (_) {} },
    KAPPA: (Math.sqrt(5) - 1) / 2,
  };
  // auto-connect federation if the caller supplied a relay
  if (opts.federate) {
    const f = typeof opts.federate === 'string' ? { url: opts.federate } : opts.federate;
    if (f && f.url) connectFederation(f.url, f.room);
  }
  try { window.dispatchEvent(new CustomEvent('niceassos:installed', { detail: { name: manifest.name, pub: identity.pubHex } })); } catch (_) {}
  return api;
}

export default { installOS };
