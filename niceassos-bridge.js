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
} from './niceassos-kernel.mjs';

const DB_NAME = 'niceassos-seed-v1';
const DB_STORE = 'identity';
const FALLBACK_STORE = 'niceassos-organ-v1';
const MESH = 'niceassos-mesh';
const LEGACY = 'fall-signal';

const enc = new TextEncoder();
const hex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
const sha256hex = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));

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

  // emit: build (kernel) → SHA-256 chain (bridge) → Ed25519 sign (bridge) → post
  async function emit(kind, payload) {
    const envMinusSig = {
      version: VERSION, kind, fork_pub: identity.pubHex,
      ts: new Date().toISOString(), seq: seq++, prev_hash: prevHash, payload,
    };
    const signature = await signCanonical(identity.privKey, envMinusSig);
    const env = Object.assign({}, envMinusSig, { signature });
    prevHash = await sha256hex(canonicalJSON(env));
    try { mesh && mesh.postMessage(env); } catch (_) {}
    try { legacy && legacy.postMessage(env); } catch (_) {}
    try { window.dispatchEvent(new CustomEvent('niceassos:sent', { detail: env })); } catch (_) {}
    return env;
  }

  function onMesh(ev) {
    const env = ev.data || {};
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

    manifest: () => Object.assign({}, manifest),
    stop: () => { clearInterval(beacon); try { mesh.close(); } catch (_) {} try { legacy.close(); } catch (_) {} },
    KAPPA: (Math.sqrt(5) - 1) / 2,
  };
  try { window.dispatchEvent(new CustomEvent('niceassos:installed', { detail: { name: manifest.name, pub: identity.pubHex } })); } catch (_) {}
  return api;
}

export default { installOS };
