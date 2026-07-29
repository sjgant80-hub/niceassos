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
  if (o === null || typeof o !== 'object') return JSON.stringify(o);
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

export default {
  VERSION, KAPPA, KINDS,
  canonicalJSON, fnv1a, envelope, MeshLog,
  admit, ringGlyph, route, organEvent, cascade,
};
