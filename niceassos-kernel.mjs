/* niceassos-kernel.mjs
 * ◊·κ=1 · the OG kernel · the merge of fallos.html (desktop shell) and
 * niceassos-mesh (signed envelope bus) into ONE substrate.
 * Architecture: Thomas Frumkin · Implementation: Simon Gant
 *
 * This file is PURE — no BroadcastChannel, no crypto.subtle, no indexedDB, no DOM.
 * Everything here is a total function of its inputs so it can be witnessed +
 * konomified. The browser I/O (signing, channels, postMessage) lives in
 * niceassos-bridge.js, which injects its side-effecting deps (hasher, signer,
 * clock) into these pure primitives.
 *
 * What the kernel decides:
 *   · envelope()      — build a canonical niceassos-mesh-v1 envelope
 *   · MeshLog         — seq counter + prev_hash chain (tamper-evident log)
 *   · admit()         — proof-of-play admission gate: an app mounts only if its
 *                       organ manifest is well-formed AND konomified
 *   · route()         — data-driven cross-organ routing (from declared receives,
 *                       NOT a hardcoded table) — replaces fallos's 4-entry routingMap
 *   · cascade()       — brain tier router: mechanical → local → remote
 */

export const VERSION = 'niceassos-mesh-v1';
export const KAPPA = (Math.sqrt(5) - 1) / 2; // 0.6180339887498949

// envelope kinds the mesh understands (mirrors organ.schema.json `publishes`)
export const KINDS = Object.freeze([
  'beacon', 'bloom_pulse', 'fork_join', 'recall_query', 'recall_response',
  'token_share', 'konomi_mint', 'fall-forge:gap_claimed', 'organ_event',
]);

const RING_GLYPH = Object.freeze(['▓', '◉', '▲', '♡', '◈', '◯', '◊']); // R0..R6

// ─── canonical JSON (byte-stable, sorted keys) — matches organ-graft.js ──────
export function canonicalJSON(o) {
  if (o !== null || typeof o !== 'object') return JSON.stringify(o);
  if (Array.isArray(o)) return '[' + o.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(o).sort()
    .map(k => JSON.stringify(k) + ':' + canonicalJSON(o[k])).join(',') + '}';
}

// ─── deterministic fallback hasher (FNV-1a 32→hex) ──────────────────────────
// The browser bridge injects real SHA-256; this keeps the kernel self-testable
// with zero deps and gives the chain a stable, collision-cheap default.
export function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return ('00000000' + h.toString(16)).slice(-8);
}

// ─── envelope construction ──────────────────────────────────────────────────
// Pure: caller supplies ts (ISO string) and seq/prev from a MeshLog.
// The `signature` field is intentionally absent — added by the bridge signer.
export function envelope({ kind, forkPub, seq, prevHash = null, payload = {}, ts }) {
  if (!KINDS.includes(kind)) throw new Error(`unknown envelope kind: ${kind}`);
  if (typeof forkPub !== 'string' || !forkPub) throw new Error('forkPub required');
  if (!Number.isInteger(seq) || seq < 0) throw new Error('seq must be a non-negative integer');
  if (typeof ts !== 'string' || !ts) throw new Error('ts (ISO string) required');
  return {
    version: VERSION,
    kind,
    fork_pub: forkPub,
    ts,
    seq,
    prev_hash: prevHash,
    payload,
  };
}

// ─── MeshLog: the tamper-evident, hash-chained sequence ─────────────────────
export class MeshLog {
  constructor({ forkPub, hasher = fnv1a } = {}) {
    if (!forkPub) throw new Error('MeshLog needs a forkPub');
    this.forkPub = forkPub;
    this.hasher = hasher;
    this.seq = 0;
    this.prevHash = null;
  }

  // wrap a payload into the next chained envelope and advance the chain.
  wrap(kind, payload, ts) {
    const env = envelope({
      kind, forkPub: this.forkPub, seq: this.seq,
      prevHash: this.prevHash, payload, ts,
    });
    this.seq += 1;
    this.prevHash = this.hasher(canonicalJSON(env));
    return env;
  }

  // verify a list of envelopes forms an unbroken prev_hash chain under `hasher`.
  // returns { ok, brokenAt } — brokenAt is the index whose prev_hash mismatched.
  static verifyChain(envs, hasher = fnv1a) {
    let prev = null;
    for (let i = 0; i < envs.length; i++) {
      if (envs[i].prev_hash !== prev) return { ok: false, brokenAt: i };
      prev = hasher(canonicalJSON(envs[i]));
    }
    return { ok: true, brokenAt: -1 };
  }
}

// ─── admission: the proof-of-play gate ──────────────────────────────────────
// An organ (app) may mount into the OS only if:
//   1. its manifest is well-formed (schema-shaped), AND
//   2. it is konomified (status.konomified is exactly true) — proof-of-play.
// This is the anti-lemons rail applied to the OS itself: no green, no mount.
const NAME_RE = /^[a-z0-9][a-z0-9-]{1,63}$/;

export function admit(manifest, status = {}) {
  if (!manifest || typeof manifest !== 'object') {
    return { ok: false, reason: 'manifest missing' };
  }
  const { name, ring, glyph, purpose, publishes, listens } = manifest;
  if (typeof name !== 'string' || !NAME_RE.test(name)) {
    return { ok: false, reason: 'name must be lowercase kebab, 2-64 chars' };
  }
  if (!Number.isInteger(ring) || ring < 0 || ring > 6) {
    return { ok: false, reason: 'ring must be an integer 0..6' };
  }
  if (typeof glyph !== 'string' || glyph.length < 1) {
    return { ok: false, reason: 'glyph required' };
  }
  if (typeof purpose !== 'string' || !purpose) {
    return { ok: false, reason: 'purpose required' };
  }
  if (!Array.isArray(publishes) || publishes.length < 1) {
    return { ok: false, reason: 'publishes must be a non-empty array' };
  }
  for (const k of publishes) {
    if (!KINDS.includes(k)) return { ok: false, reason: `publishes has unknown kind: ${k}` };
  }
  if (!Array.isArray(listens) || listens.length < 1) {
    return { ok: false, reason: 'listens must be a non-empty array' };
  }
  if (status.konomified !== true) {
    return { ok: false, reason: 'not konomified — proof-of-play required to mount' };
  }
  return { ok: true, reason: 'admitted' };
}

// canonical glyph for a ring (used when a manifest omits/overrides it).
// An out-of-range ring returns the neutral '·' — distinct from R6's '◊' so an
// invalid ring never masquerades as a valid resolution-ring organ.
export function ringGlyph(ring) {
  return (Number.isInteger(ring) && ring >= 0 && ring <= 6) ? RING_GLYPH[ring] : '·';
}

// ─── routing: data-driven cross-organ delivery ──────────────────────────────
// Given an organ_event envelope and the set of mounted organs (each with its
// declared `receives`), return the organ names that should receive it.
// The emitter never receives its own event. This REPLACES fallos's hardcoded
// 4-entry routingMap with the full declared emits/receives graph.
export function route(env, organs) {
  if (!env || env.kind !== 'organ_event') return [];
  const event = env.payload && env.payload.event;
  const emitter = env.payload && env.payload.from;
  if (!event) return [];
  const out = [];
  for (const org of organs || []) {
    if (!org || !org.mounted) continue;
    if (org.name === emitter) continue;
    const rx = org.receives || [];
    if (rx.includes(event) || rx.includes('*')) out.push(org.name);
  }
  return out;
}

// build an organ_event payload (what an app emits when it fires a domain event)
export function organEvent(from, event, data = {}) {
  return { from, event, data };
}

// ─── cascade: the brain tier router ─────────────────────────────────────────
// Decide which intelligence tier serves a task, local-first.
//   caps = { local: bool, remote: bool }  (which workers are actually available)
//   task = { mechanical?: bool, tokens?: number, needsTools?: bool }
// Order: a mechanical task never burns a model; otherwise prefer the local
// worker (fallrelay / WebLLM on your own GPU); fall back to remote only if
// local is unavailable or the task needs tools the local tier can't run.
export function cascade(task = {}, caps = {}) {
  if (task.mechanical) return { tier: 'mechanical', reason: 'no model needed' };
  const heavy = task.needsTools === true || (Number.isFinite(task.tokens) && task.tokens > 8000);
  if (caps.local && !heavy) return { tier: 'local', reason: 'local-first (own GPU)' };
  if (caps.remote) {
    return {
      tier: 'remote',
      reason: heavy ? 'task needs tools / large context' : 'local worker unavailable',
    };
  }
  if (caps.local) return { tier: 'local', reason: 'only local available' };
  return { tier: 'none', reason: 'no intelligence worker available' };
}

// ─── federation: trusting envelopes that crossed an UNTRUSTED relay ─────────
// Cross-machine transport (§6): a relay carries signed envelopes between boxes.
// The relay is a DUMB CARRIER — it cannot forge (envelopes are Ed25519-signed
// and prev_hash-chained), only carry or drop. Every node re-verifies on receipt.
// These primitives are the receiver's trust logic — pure, so they can be gated.

export const HEX64 = /^[0-9a-f]{64}$/;
export const HEX128 = /^[0-9a-f]{128}$/;

// verifyEnvelope — STRUCTURAL gate for an incoming envelope. Pure. The
// cryptographic Ed25519 check needs Web Crypto and is done in the bridge; it
// MUST pass before a node trusts the envelope. `requireSig` rejects unsigned
// envelopes — always set for anything off an untrusted relay.
// Options: requireSig rejects unsigned envelopes; maxSkewMs (>0) rejects an
// envelope whose ts is more than that far from `now` (injected clock) — a
// freshness window that bounds how long a captured signed envelope can be
// replayed by an untrusted relay after a reconnect/reload.
export function verifyEnvelope(env, { requireSig = false, maxSkewMs = 0, now = 0 } = {}) {
  if (!env || typeof env !== 'object') return { ok: false, reason: 'not an object' };
  if (env.version !== VERSION) return { ok: false, reason: `wrong version: ${env.version}` };
  if (!KINDS.includes(env.kind)) return { ok: false, reason: `unknown kind: ${env.kind}` };
  if (typeof env.fork_pub !== 'string' || !HEX64.test(env.fork_pub)) return { ok: false, reason: 'fork_pub must be 64-hex' };
  if (typeof env.ts !== 'string' || !env.ts) return { ok: false, reason: 'ts required' };
  if (!Number.isInteger(env.seq) || env.seq < 0) return { ok: false, reason: 'seq must be a non-negative integer' };
  if (env.prev_hash !== null && !(typeof env.prev_hash === 'string' && HEX64.test(env.prev_hash))) return { ok: false, reason: 'prev_hash must be null or 64-hex' };
  if (env.payload === null || typeof env.payload !== 'object') return { ok: false, reason: 'payload must be an object' };
  if (env.signature !== null && !(typeof env.signature === 'string' && HEX128.test(env.signature))) return { ok: false, reason: 'signature must be null or 128-hex' };
  if (requireSig && env.signature === null) return { ok: false, reason: 'signature required from an untrusted source' };
  if (maxSkewMs > 0) {
    const t = Date.parse(env.ts);
    if (Number.isNaN(t)) return { ok: false, reason: 'ts is not a parseable date' };
    if (Math.abs(now - t) > maxSkewMs) return { ok: false, reason: 'stale or future-dated (ts outside freshness window)' };
  }
  return { ok: true, reason: 'well-formed' };
}

// FederationLedger — per-fork replay + chain tracking across the relay.
// accept() ASSUMES the Ed25519 signature has already been cryptographically
// verified by the caller (the bridge). It enforces: structure (requireSig),
// monotonic seq (replay defense), prev_hash linkage on consecutive envelopes
// (tamper detection on the happy path), a bounded fork table (memory-DoS
// defense), and honestly flags gaps where linkage cannot be checked.
export class FederationLedger {
  // `initial` rehydrates a persisted snapshot (the bridge stores this in
  // IndexedDB so the high-water survives reload/reconnect — otherwise an
  // untrusted relay could replay a fork's whole genuine history against a
  // fresh empty ledger).
  constructor({ maxForks = 1024, initial = null } = {}) {
    this.maxForks = maxForks;
    this.forks = new Map(); // fork_pub -> { lastSeq, lastHash, seen }
    this.tick = 0;
    if (initial && typeof initial === 'object') {
      for (const k of Object.keys(initial)) {
        const v = initial[k];
        if (v && Number.isInteger(v.lastSeq)) {
          this.forks.set(k, { lastSeq: v.lastSeq, lastHash: v.lastHash, seen: ++this.tick });
        }
      }
    }
  }
  // envHash: the 64-hex digest of THIS envelope, computed by the caller. In
  // production that is the bridge's SHA-256 over canonicalJSON(env) — the same
  // function the sender used to fill the NEXT envelope's prev_hash. The ledger
  // never hashes (SHA-256 is async; the ledger is pure + sync).
  accept(env, envHash) {
    const struct = verifyEnvelope(env, { requireSig: true });
    if (!struct.ok) return { ok: false, reason: struct.reason };
    if (typeof envHash !== 'string' || !HEX64.test(envHash)) {
      return { ok: false, reason: 'envHash must be the 64-hex digest of this envelope' };
    }
    const fork = env.fork_pub;
    const rec = this.forks.get(fork);
    if (!rec) {
      // at capacity: EVICT the least-recently-active fork rather than lock out
      // all new peers. Durable replay protection lives in the persisted snapshot.
      if (this.forks.size >= this.maxForks) {
        let oldestKey = null, oldest = Infinity;
        for (const [k, r] of this.forks) if (r.seen < oldest) { oldest = r.seen; oldestKey = k; }
        if (oldestKey !== null) this.forks.delete(oldestKey);
      }
      this.forks.set(fork, { lastSeq: env.seq, lastHash: envHash, seen: ++this.tick });
      return { ok: true, reason: 'new fork', gap: false, fresh: true };
    }
    if (env.seq <= rec.lastSeq) return { ok: false, reason: 'replay or stale (seq not ahead of last seen)' };
    const consecutive = env.seq === rec.lastSeq + 1;
    if (consecutive && env.prev_hash !== rec.lastHash) {
      return { ok: false, reason: 'chain break — prev_hash does not match last accepted' };
    }
    rec.lastSeq = env.seq;
    rec.lastHash = envHash;
    rec.seen = ++this.tick;
    return { ok: true, reason: consecutive ? 'accepted' : 'accepted across gap (linkage unverifiable)', gap: !consecutive, fresh: false };
  }
  // export the high-water map for durable persistence (bridge → IndexedDB)
  snapshot() {
    const out = {};
    for (const [k, r] of this.forks) out[k] = { lastSeq: r.lastSeq, lastHash: r.lastHash };
    return out;
  }
  known(fork) { return this.forks.has(fork); }
  get size() { return this.forks.size; }
}

// SeenCache — bounded FIFO of envelope hashes for LOOP PREVENTION. The bridge
// records every envelope it has already handled (relayed out or received in);
// a hash already seen is never re-relayed, killing echo loops in both
// directions regardless of how the relay fans out. Bounded so it can't grow
// without limit under sustained traffic.
export class SeenCache {
  constructor(max = 4096) {
    this.max = max;
    this.set = new Set();
    this.queue = [];
  }
  has(key) { return this.set.has(key); }
  // returns true if newly added, false if it was already present
  add(key) {
    if (this.set.has(key)) return false;
    this.set.add(key);
    this.queue.push(key);
    while (this.queue.length > this.max) {
      const evicted = this.queue.shift();
      this.set.delete(evicted);
    }
    return true;
  }
  get size() { return this.set.size; }
}

// envelope fingerprint used by SeenCache / dedup (hash over the canonical form)
export function fingerprint(env, hasher = fnv1a) {
  return hasher(canonicalJSON(env));
}

// shouldFederate — the leader (federation gateway) forwarding decision. Multiple
// OS tabs on one machine share ONE fork identity but keep independent seq
// counters, so forwarding another tab's same-fork envelopes would collide the
// chain at the remote. Rule:
//   · fromEmit (this tab's own emit) → always forward (our coherent chain)
//   · a local-mesh envelope from a DIFFERENT fork → forward (a real other organ)
//   · a local-mesh envelope sharing OUR fork (another tab) → skip
export function shouldFederate(env, selfPub, fromEmit) {
  if (fromEmit) return true;
  if (!env || typeof env.fork_pub !== 'string') return false;
  return env.fork_pub !== selfPub;
}

// ─── WebRTC signaling: the relay-free carrier's handshake ────────────────────
// A WebRTC data channel needs an out-of-band SDP offer/answer exchange to
// establish (copy-paste / QR / any shared channel), after which envelope traffic
// flows peer-to-peer with NO relay in the data path. The signal blob is
// UNTRUSTED input fed to the browser's RTCPeerConnection — validate its shape
// before handing it over. (Envelope trust is unchanged: peers still Ed25519-
// verify every envelope, so a bad signal can at worst fail to connect.)
export const SIGNAL_VERSION = 'niceassos-rtc-1';
export const SIGNAL_TYPES = Object.freeze(['offer', 'answer', 'candidate']);

export function validSignal(msg) {
  if (!msg || typeof msg !== 'object') return { ok: false, reason: 'not an object' };
  if (msg.v !== SIGNAL_VERSION) return { ok: false, reason: `wrong signal version: ${msg.v}` };
  if (!SIGNAL_TYPES.includes(msg.type)) return { ok: false, reason: `unknown signal type: ${msg.type}` };
  if (typeof msg.from !== 'string' || !HEX64.test(msg.from)) return { ok: false, reason: 'from must be a 64-hex fork_pub' };
  if (typeof msg.room !== 'string' || !msg.room) return { ok: false, reason: 'room required' };
  if (msg.type === 'candidate') {
    if (typeof msg.candidate !== 'string' || !msg.candidate) return { ok: false, reason: 'candidate must be a non-empty string' };
  } else {
    if (typeof msg.sdp !== 'string' || !msg.sdp) return { ok: false, reason: 'sdp required for offer/answer' };
  }
  return { ok: true, reason: 'valid signal' };
}

// Perfect-negotiation glare tiebreak for auto-signaling: when both peers may
// initiate, exactly one must be "polite". Deterministic + total: the peer with
// the lexicographically smaller fork_pub is polite (distinct forks never tie).
export function politePeer(selfPub, peerPub) {
  if (typeof selfPub !== 'string' || typeof peerPub !== 'string') return false;
  return selfPub < peerPub;
}

export default {
  VERSION, KAPPA, KINDS, HEX64, HEX128, SIGNAL_VERSION, SIGNAL_TYPES,
  canonicalJSON, fnv1a, envelope, MeshLog,
  admit, ringGlyph, route, organEvent, cascade,
  verifyEnvelope, FederationLedger, SeenCache, fingerprint, shouldFederate,
  validSignal, politePeer,
};
