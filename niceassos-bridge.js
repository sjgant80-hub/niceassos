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
  VERSION, MeshLog, canonicalJSON, admit, route, cascade, ringGlyph, organEvent,
  verifyEnvelope, FederationLedger, SeenCache, fingerprint, shouldFederate,
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

  // ── federation: carry this box's mesh to another box over an untrusted relay ─
  // Envelopes are self-authenticating (Ed25519 + prev_hash chain); the relay
  // only carries. On receipt every envelope is: structurally checked, signature-
  // verified against its fork_pub, replay/chain-checked by the FederationLedger,
  // and deduped (SeenCache) so echoes can't loop. Only then is it injected onto
  // the local mesh so this box's tabs see the remote organ.
  let fed = null;
  function connectFederation(url, room) {
    room = room || 'fed';
    const wsurl = url + (url.includes('?') ? '&' : '?') + 'room=' + encodeURIComponent(room);
    const seen = new SeenCache(4096);
    const ledgerKey = 'ledger:' + room;
    const hwKey = 'fedhw:' + room;
    // hydrate the per-fork high-water from IndexedDB so a reload/reconnect can't
    // be tricked by the untrusted relay into re-accepting a fork's old history.
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
    // our fork's highest FORWARDED seq — persisted so a NEW leader (after this
    // tab closes) resumes above it and the remote never sees a seq regression.
    let hwSeq = -1;
    let hwTimer = null;
    const persistHw = () => {
      if (hwTimer) return;
      hwTimer = setTimeout(() => { hwTimer = null; dbPut(FALLBACK_STORE, FALLBACK_STORE, hwKey, { seq: hwSeq }).catch(() => {}); }, 500);
    };

    const stat = { connected: false, leader: false, sent: 0, recv: 0, rejected: 0, url: wsurl, room };
    let ws = null;

    function openSocket() {
      try { ws = new WebSocket(wsurl); } catch (_) { return; }
      ws.onopen = () => { stat.connected = true; try { window.dispatchEvent(new CustomEvent('niceassos:fed-open', { detail: { ...stat } })); } catch (_) {} };
      ws.onclose = () => { stat.connected = false; if (stat.leader && fed) setTimeout(() => { if (stat.leader && fed) openSocket(); }, 2000); };
      ws.onerror = () => { stat.connected = false; };
      ws.onmessage = async (ev) => {
        let env; try { env = JSON.parse(ev.data); } catch (_) { return; }
        await hydrated; // ledger loaded before we judge replay
        if (!verifyEnvelope(env, { requireSig: true, maxSkewMs: FRESHNESS_MS, now: Date.now() }).ok) { stat.rejected++; return; }
        if (!(await verifyRemoteSig(env))) { stat.rejected++; return; }  // relay can't forge
        const h = await sha256hex(canonicalJSON(env));
        if (!ledger.accept(env, h).ok) { stat.rejected++; return; }      // replay / chain break
        if (!seen.add(h)) return;                                         // already handled → no loop
        persist();                                                        // durably advance the high-water
        stat.recv++;
        try { mesh && mesh.postMessage(env); } catch (_) {}               // inject onto local mesh (all tabs see it)
        envListeners.forEach(fn => { try { fn(env); } catch (_) {} });
        try { window.dispatchEvent(new CustomEvent('niceassos:fed-recv', { detail: env })); } catch (_) {}
      };
    }

    async function becomeLeader() {
      stat.leader = true;
      // failover / reboot continuity: resume our fork's seq strictly above the
      // last forwarded seq (a gap, so the remote ledger accepts rather than
      // chain-breaking) — no regression, no stall.
      try {
        const rec = await dbGet(FALLBACK_STORE, FALLBACK_STORE, hwKey);
        if (rec && Number.isInteger(rec.seq)) { hwSeq = rec.seq; if (seq <= hwSeq) seq = hwSeq + 2; }
      } catch (_) {}
      openSocket();
    }

    // LEADER ELECTION (Web Locks): whichever tab holds the exclusive lock is the
    // machine's federation gateway — the only tab with a relay socket and the
    // only forwarder. Other tabs queue on the lock; when the leader tab closes,
    // the lock releases on unload and a queued tab becomes leader automatically.
    const lockName = 'niceassos-fed:' + room;
    if (typeof navigator !== 'undefined' && navigator.locks && navigator.locks.request) {
      navigator.locks.request(lockName, { mode: 'exclusive' }, () => new Promise(() => { becomeLeader(); })).catch(() => {});
    } else {
      becomeLeader(); // no Web Locks → behave as the sole tab
    }

    fed = {
      status: () => ({ ...stat }),
      // forward a locally-originated envelope out to the relay. Only the leader
      // has a socket; shouldFederate keeps the forwarded stream a single coherent
      // chain (own emits + genuine other-fork organs, never a sibling tab's
      // same-fork envelopes).
      forward: async (env, fromEmit) => {
        if (!stat.connected || !ws) return;
        if (!shouldFederate(env, identity.pubHex, !!fromEmit)) return;
        const h = await sha256hex(canonicalJSON(env));
        if (!seen.add(h)) return;   // came from the relay, or already sent → don't echo
        try { ws.send(JSON.stringify(env)); stat.sent++; } catch (_) { return; }
        if (env.fork_pub === identity.pubHex && Number.isInteger(env.seq) && env.seq > hwSeq) { hwSeq = env.seq; persistHw(); }
      },
      stop: () => { stat.leader = false; try { ws && ws.close(); } catch (_) {} fed = null; },
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
    federate: (url, room) => connectFederation(url, room),
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
