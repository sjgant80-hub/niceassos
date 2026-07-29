import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  VERSION, KAPPA, KINDS, canonicalJSON, fnv1a, envelope, MeshLog,
  admit, ringGlyph, route, organEvent, cascade,
  verifyEnvelope, FederationLedger, SeenCache, fingerprint, shouldFederate,
} from '../niceassos-kernel.mjs';

test('KAPPA is (√5−1)/2 ≈ 0.618, not φ', () => {
  assert.ok(Math.abs(KAPPA - 0.6180339887498949) < 1e-12);
  assert.ok(KAPPA < 1); // guards the `- 1` in the definition (φ = +1 would be > 1)
});

const TS = '2026-07-29T00:00:00.000Z';
const PUB = 'a'.repeat(64);

const goodManifest = () => ({
  name: 'fall-remember',
  ring: 3,
  glyph: '♡',
  purpose: 'dodecahedral memory',
  publishes: ['recall_response', 'beacon'],
  listens: ['recall_query'],
});

// ─── canonicalJSON ──────────────────────────────────────────────────────────
test('canonicalJSON sorts keys stably', () => {
  assert.equal(canonicalJSON({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalJSON({ a: 2, b: 1 }), '{"a":2,"b":1}');
  assert.equal(canonicalJSON([3, { y: 1, x: 2 }]), '[3,{"x":2,"y":1}]');
  assert.equal(canonicalJSON(null), 'null');
  assert.equal(canonicalJSON('s'), '"s"');
});

// ─── fnv1a ──────────────────────────────────────────────────────────────────
test('fnv1a is deterministic 8-hex and input-sensitive', () => {
  assert.equal(fnv1a('abc'), fnv1a('abc'));
  assert.notEqual(fnv1a('abc'), fnv1a('abd'));
  assert.match(fnv1a('anything'), /^[0-9a-f]{8}$/);
  // exact offset-basis pin: empty input never enters the loop → the FNV seed.
  // (guards the loop bound: an off-by-one `<=` would mix one NaN round here.)
  assert.equal(fnv1a(''), '811c9dc5');
});

// ─── envelope ───────────────────────────────────────────────────────────────
test('envelope builds a well-formed niceassos-mesh-v1 record', () => {
  const e = envelope({ kind: 'beacon', forkPub: PUB, seq: 0, ts: TS, payload: { x: 1 } });
  assert.equal(e.version, VERSION);
  assert.equal(e.kind, 'beacon');
  assert.equal(e.fork_pub, PUB);
  assert.equal(e.seq, 0);
  assert.equal(e.prev_hash, null);
  assert.deepEqual(e.payload, { x: 1 });
  assert.equal('signature' in e, false); // sig is added by the bridge, never here
});

test('envelope rejects unknown kind', () => {
  assert.throws(() => envelope({ kind: 'nope', forkPub: PUB, seq: 0, ts: TS }), /unknown envelope kind/);
});
test('envelope rejects missing forkPub', () => {
  assert.throws(() => envelope({ kind: 'beacon', forkPub: '', seq: 0, ts: TS }), /forkPub required/);
});
test('envelope rejects negative / non-integer seq', () => {
  assert.throws(() => envelope({ kind: 'beacon', forkPub: PUB, seq: -1, ts: TS }), /seq/);
  assert.throws(() => envelope({ kind: 'beacon', forkPub: PUB, seq: 1.5, ts: TS }), /seq/);
});
test('envelope rejects missing ts', () => {
  assert.throws(() => envelope({ kind: 'beacon', forkPub: PUB, seq: 0 }), /ts/);
});
test('envelope rejects an empty-string ts (guards the || in the ts check)', () => {
  assert.throws(() => envelope({ kind: 'beacon', forkPub: PUB, seq: 0, ts: '' }), /ts/);
});
test('KINDS includes organ_event and the mesh natives', () => {
  for (const k of ['beacon', 'fork_join', 'organ_event', 'recall_query']) {
    assert.ok(KINDS.includes(k), `${k} should be a known kind`);
  }
});

// ─── MeshLog chain ──────────────────────────────────────────────────────────
test('MeshLog advances seq and chains prev_hash', () => {
  const log = new MeshLog({ forkPub: PUB });
  const e0 = log.wrap('beacon', { n: 0 }, TS);
  const e1 = log.wrap('beacon', { n: 1 }, TS);
  assert.equal(e0.seq, 0);
  assert.equal(e1.seq, 1);
  assert.equal(e0.prev_hash, null);
  assert.equal(e1.prev_hash, fnv1a(canonicalJSON(e0)));
  assert.equal(log.seq, 2);
});

test('MeshLog requires a forkPub', () => {
  assert.throws(() => new MeshLog({}), /forkPub/);
});

test('verifyChain accepts an intact chain and locates a break', () => {
  const log = new MeshLog({ forkPub: PUB });
  const envs = [log.wrap('beacon', { n: 0 }, TS), log.wrap('beacon', { n: 1 }, TS), log.wrap('beacon', { n: 2 }, TS)];
  assert.deepEqual(MeshLog.verifyChain(envs), { ok: true, brokenAt: -1 });
  // tamper with the middle payload → its hash changes → index 2's prev_hash no longer matches
  const tampered = envs.map(e => ({ ...e }));
  tampered[1].payload = { n: 99 };
  const res = MeshLog.verifyChain(tampered);
  assert.equal(res.ok, false);
  assert.equal(res.brokenAt, 2);
});

// ─── admit (proof-of-play gate) ─────────────────────────────────────────────
test('admit passes a well-formed, konomified organ', () => {
  assert.deepEqual(admit(goodManifest(), { konomified: true }), { ok: true, reason: 'admitted' });
});
test('admit blocks a non-konomified organ (proof-of-play)', () => {
  const r = admit(goodManifest(), { konomified: false });
  assert.equal(r.ok, false);
  assert.match(r.reason, /proof-of-play/);
});
test('admit blocks konomified missing entirely', () => {
  assert.equal(admit(goodManifest()).ok, false);
});
test('admit ring boundaries: -1 and 7 reject, 0 and 6 pass', () => {
  assert.equal(admit({ ...goodManifest(), ring: -1 }, { konomified: true }).ok, false);
  assert.equal(admit({ ...goodManifest(), ring: 7 }, { konomified: true }).ok, false);
  assert.equal(admit({ ...goodManifest(), ring: 0 }, { konomified: true }).ok, true);
  assert.equal(admit({ ...goodManifest(), ring: 6 }, { konomified: true }).ok, true);
});
test('admit rejects bad names and empty arrays', () => {
  assert.equal(admit({ ...goodManifest(), name: 'X' }, { konomified: true }).ok, false); // uppercase
  assert.equal(admit({ ...goodManifest(), name: 'a' }, { konomified: true }).ok, false);  // too short (needs 2+)
  assert.equal(admit({ ...goodManifest(), publishes: [] }, { konomified: true }).ok, false);
  assert.equal(admit({ ...goodManifest(), listens: [] }, { konomified: true }).ok, false);
});
test('admit rejects an empty glyph (guards the || in the glyph check)', () => {
  const r = admit({ ...goodManifest(), glyph: '' }, { konomified: true });
  assert.equal(r.ok, false);
  assert.match(r.reason, /glyph/);
});
test('admit rejects an empty purpose (guards the || in the purpose check)', () => {
  const r = admit({ ...goodManifest(), purpose: '' }, { konomified: true });
  assert.equal(r.ok, false);
  assert.match(r.reason, /purpose/);
});
test('admit rejects an unknown publishes kind', () => {
  const r = admit({ ...goodManifest(), publishes: ['made_up'] }, { konomified: true });
  assert.equal(r.ok, false);
  assert.match(r.reason, /unknown kind/);
});
test('admit rejects a missing manifest', () => {
  assert.equal(admit(null, { konomified: true }).ok, false);
});

// ─── ringGlyph ──────────────────────────────────────────────────────────────
test('ringGlyph maps 0..6 and falls back to a neutral · for out-of-range', () => {
  assert.equal(ringGlyph(0), '▓');
  assert.equal(ringGlyph(3), '♡');
  assert.equal(ringGlyph(6), '◊');        // R6 is the resolution glyph
  assert.equal(ringGlyph(7), '·');        // out of range → neutral, NOT ◊
  assert.equal(ringGlyph(-1), '·');
  assert.notEqual(ringGlyph(6), ringGlyph(7)); // R6 must be distinguishable from invalid
});

// ─── route (data-driven cross-organ delivery) ───────────────────────────────
const organs = () => ([
  { name: 'crm', mounted: true, receives: ['invoice.created', 'meeting.scheduled'] },
  { name: 'account', mounted: true, receives: ['deal.closed', 'contact.updated'] },
  { name: 'meet', mounted: true, receives: ['contact.updated'] },
  { name: 'audit', mounted: true, receives: ['*'] },
  { name: 'sleeping', mounted: false, receives: ['deal.closed'] },
]);

const orgEnv = (from, event) => ({ kind: 'organ_event', payload: organEvent(from, event) });

test('route delivers an event only to organs that declare receiving it', () => {
  const targets = route(orgEnv('crm', 'deal.closed'), organs());
  assert.deepEqual(targets.sort(), ['account', 'audit']); // account receives it; audit wildcards
});
test('route excludes the emitter even if it would match', () => {
  const orgs = organs();
  orgs[0].receives.push('deal.closed'); // crm now also "receives" it
  const targets = route(orgEnv('crm', 'deal.closed'), orgs);
  assert.equal(targets.includes('crm'), false);
});
test('route excludes unmounted organs', () => {
  const targets = route(orgEnv('crm', 'deal.closed'), organs());
  assert.equal(targets.includes('sleeping'), false);
});
test('route ignores non-organ_event envelopes and empty events', () => {
  assert.deepEqual(route({ kind: 'beacon', payload: {} }, organs()), []);
  assert.deepEqual(route(orgEnv('crm', ''), organs()), []);
});
test('route handles a null envelope without throwing (guards the || short-circuit)', () => {
  assert.deepEqual(route(null, organs()), []);
});
test('route fan-out: contact.updated reaches account + meet + audit', () => {
  const targets = route(orgEnv('crm', 'contact.updated'), organs());
  assert.deepEqual(targets.sort(), ['account', 'audit', 'meet']);
});

// ─── cascade (brain tier router) ────────────────────────────────────────────
test('cascade: mechanical task burns no model', () => {
  assert.deepEqual(cascade({ mechanical: true }, { local: true, remote: true }),
    { tier: 'mechanical', reason: 'no model needed' });
});
test('cascade: prefers local when available and task is light', () => {
  assert.equal(cascade({ tokens: 100 }, { local: true, remote: true }).tier, 'local');
});
test('cascade: heavy task (tools) goes remote even if local is up', () => {
  assert.equal(cascade({ needsTools: true }, { local: true, remote: true }).tier, 'remote');
});
test('cascade: large context goes remote', () => {
  assert.equal(cascade({ tokens: 9000 }, { local: true, remote: true }).tier, 'remote');
});
test('cascade: no local → remote', () => {
  assert.equal(cascade({ tokens: 100 }, { local: false, remote: true }).tier, 'remote');
});
test('cascade: heavy but only local available → falls to local', () => {
  assert.equal(cascade({ needsTools: true }, { local: true, remote: false }).tier, 'local');
});
test('cascade: nothing available → none', () => {
  assert.deepEqual(cascade({ tokens: 100 }, {}),
    { tier: 'none', reason: 'no intelligence worker available' });
});
test('cascade: 8000 tokens is the boundary — not heavy', () => {
  assert.equal(cascade({ tokens: 8000 }, { local: true, remote: true }).tier, 'local');
  assert.equal(cascade({ tokens: 8001 }, { local: true, remote: true }).tier, 'remote');
});

// ─── federation: verifyEnvelope ─────────────────────────────────────────────
const SIG = 'b'.repeat(128);
const signedEnv = (over = {}) => ({
  version: VERSION, kind: 'beacon', fork_pub: 'c'.repeat(64), ts: TS,
  seq: 0, prev_hash: null, payload: {}, signature: SIG, ...over,
});

test('verifyEnvelope accepts a well-formed signed envelope', () => {
  assert.equal(verifyEnvelope(signedEnv()).ok, true);
});
test('verifyEnvelope rejects a null / non-object', () => {
  assert.equal(verifyEnvelope(null).ok, false);
  assert.equal(verifyEnvelope(42).ok, false);
});
test('verifyEnvelope rejects a wrong version', () => {
  const r = verifyEnvelope(signedEnv({ version: 'nope-v9' }));
  assert.equal(r.ok, false); assert.match(r.reason, /version/);
});
test('verifyEnvelope rejects an unknown kind', () => {
  assert.equal(verifyEnvelope(signedEnv({ kind: 'made_up' })).ok, false);
});
test('verifyEnvelope rejects a non-64-hex fork_pub', () => {
  assert.equal(verifyEnvelope(signedEnv({ fork_pub: 'xyz' })).ok, false);
  assert.equal(verifyEnvelope(signedEnv({ fork_pub: 'c'.repeat(63) })).ok, false); // one short
});
test('verifyEnvelope rejects missing ts and bad seq', () => {
  assert.equal(verifyEnvelope(signedEnv({ ts: '' })).ok, false);
  assert.equal(verifyEnvelope(signedEnv({ seq: -1 })).ok, false);
  assert.equal(verifyEnvelope(signedEnv({ seq: 1.5 })).ok, false);
});
test('verifyEnvelope allows null prev_hash but rejects a non-64-hex one', () => {
  assert.equal(verifyEnvelope(signedEnv({ prev_hash: null })).ok, true);
  assert.equal(verifyEnvelope(signedEnv({ prev_hash: 'a'.repeat(64) })).ok, true);
  assert.equal(verifyEnvelope(signedEnv({ prev_hash: 'short' })).ok, false);
});
test('verifyEnvelope rejects a non-object payload', () => {
  assert.equal(verifyEnvelope(signedEnv({ payload: null })).ok, false);
  assert.equal(verifyEnvelope(signedEnv({ payload: 'x' })).ok, false);
});
test('verifyEnvelope rejects a non-128-hex signature', () => {
  assert.equal(verifyEnvelope(signedEnv({ signature: 'a'.repeat(127) })).ok, false);
  assert.equal(verifyEnvelope(signedEnv({ signature: 'zz' })).ok, false);
});
test('verifyEnvelope requireSig rejects an unsigned envelope, allows it otherwise', () => {
  assert.equal(verifyEnvelope(signedEnv({ signature: null })).ok, true);            // default: allowed
  const r = verifyEnvelope(signedEnv({ signature: null }), { requireSig: true });
  assert.equal(r.ok, false); assert.match(r.reason, /signature required/);
});
test('verifyEnvelope freshness window rejects stale and future-dated envelopes', () => {
  const now = Date.parse('2026-07-29T12:00:00.000Z');
  const at = (iso) => verifyEnvelope(signedEnv({ ts: iso }), { maxSkewMs: 120000, now });
  assert.equal(at('2026-07-29T12:00:30.000Z').ok, true);   // 30s → inside 2-min window
  assert.equal(at('2026-07-29T11:57:00.000Z').ok, false);  // 3 min old → stale
  assert.equal(at('2026-07-29T12:03:00.000Z').ok, false);  // 3 min future → rejected
  assert.equal(at(new Date(now - 120000).toISOString()).ok, true); // exactly at the edge → accepted (pins > not >=)
  const r = verifyEnvelope(signedEnv({ ts: 'not-a-date' }), { maxSkewMs: 1, now });
  assert.equal(r.ok, false); assert.match(r.reason, /parseable/);
});
test('verifyEnvelope skips freshness when maxSkewMs is 0 (default)', () => {
  assert.equal(verifyEnvelope(signedEnv({ ts: '1999-01-01T00:00:00.000Z' })).ok, true);
});

// ─── federation: FederationLedger ───────────────────────────────────────────
// The bridge passes a 64-hex SHA-256 digest per envelope; these tests use
// fixed 64-hex stand-ins and chain prev_hash → the previous envelope's digest,
// exactly as production does.
const FORK = 'd'.repeat(64);
const H0 = '0'.repeat(64), H1 = '1'.repeat(64), H5 = '5'.repeat(64);
const e0 = () => signedEnv({ fork_pub: FORK, seq: 0, prev_hash: null, payload: { n: 0 } });
const e1 = () => signedEnv({ fork_pub: FORK, seq: 1, prev_hash: H0, payload: { n: 1 } }); // points at e0's digest

test('ledger accepts a new fork, then a consecutive well-chained envelope', () => {
  const L = new FederationLedger();
  const r0 = L.accept(e0(), H0);
  assert.equal(r0.ok, true); assert.equal(r0.fresh, true);
  const r1 = L.accept(e1(), H1);   // consecutive; e1.prev_hash === H0 (e0's digest)
  assert.equal(r1.ok, true); assert.equal(r1.gap, false);
  assert.equal(L.size, 1);
});
test('ledger rejects a replay / stale seq', () => {
  const L = new FederationLedger();
  L.accept(e0(), H0); L.accept(e1(), H1);
  const r = L.accept(e1(), H1);    // seq 1 again
  assert.equal(r.ok, false); assert.match(r.reason, /replay|stale/);
});
test('ledger rejects a chain break on consecutive seq', () => {
  const L = new FederationLedger();
  L.accept(e0(), H0);
  const forged = signedEnv({ fork_pub: FORK, seq: 1, prev_hash: 'f'.repeat(64), payload: { n: 9 } });
  const r = L.accept(forged, H1); // prev_hash 'fff…' !== H0 (e0's digest)
  assert.equal(r.ok, false); assert.match(r.reason, /chain break/);
});
test('ledger accepts across a gap but flags linkage as unverifiable', () => {
  const L = new FederationLedger();
  L.accept(e0(), H0);
  const far = signedEnv({ fork_pub: FORK, seq: 5, prev_hash: 'e'.repeat(64), payload: { n: 5 } });
  const r = L.accept(far, H5);     // seq jumps 0 -> 5: linkage can't be checked
  assert.equal(r.ok, true); assert.equal(r.gap, true);
});
test('ledger requires a 64-hex envHash', () => {
  const L = new FederationLedger();
  assert.equal(L.accept(e0(), 'short').ok, false);
  assert.equal(L.accept(e0(), undefined).ok, false);
});
test('ledger bounds the fork table and LRU-evicts (no lockout DoS)', () => {
  const L = new FederationLedger({ maxForks: 2 });
  const mk = (c) => signedEnv({ fork_pub: c.repeat(64), seq: 0 });
  assert.equal(L.accept(mk('1'), H0).ok, true);
  assert.equal(L.accept(mk('2'), H0).ok, true);
  const r = L.accept(mk('3'), H0);   // over cap → evict LRU (fork '1'), accept '3'
  assert.equal(r.ok, true);
  assert.equal(L.size, 2);
  assert.equal(L.known('1'.repeat(64)), false); // least-recently-seen evicted
  assert.equal(L.known('3'.repeat(64)), true);
});
test('ledger snapshot round-trips high-water and blocks replay after restore', () => {
  const L = new FederationLedger();
  L.accept(e0(), H0); L.accept(e1(), H1);          // fork advanced to seq 1
  const snap = L.snapshot();
  assert.equal(snap[FORK].lastSeq, 1);
  // a reloaded ledger restored from the snapshot must reject the old seq-1 replay
  const L2 = new FederationLedger({ initial: snap });
  assert.equal(L2.accept(e1(), H1).ok, false);     // replay after "reload" → rejected
  assert.equal(L2.known(FORK), true);
});
test('ledger restore skips malformed snapshot entries (truthy but no integer lastSeq)', () => {
  const L = new FederationLedger({ initial: { [FORK]: { lastSeq: 'nope' } } });
  assert.equal(L.known(FORK), false); // invalid entry not restored (guards the && in validation)
  assert.equal(L.size, 0);
});
test('ledger rejects a structurally-invalid or unsigned envelope', () => {
  const L = new FederationLedger();
  assert.equal(L.accept(signedEnv({ signature: null }), H0).ok, false); // unsigned off the relay
  assert.equal(L.accept(signedEnv({ fork_pub: 'bad' }), H0).ok, false);
});

// ─── federation: SeenCache (loop prevention) ────────────────────────────────
test('SeenCache add returns true once, false on repeat', () => {
  const s = new SeenCache(8);
  assert.equal(s.add('k'), true);
  assert.equal(s.add('k'), false);
  assert.equal(s.has('k'), true);
});
test('SeenCache evicts oldest past its bound', () => {
  const s = new SeenCache(2);
  s.add('a'); s.add('b'); s.add('c');   // 'a' evicted
  assert.equal(s.has('a'), false);
  assert.equal(s.has('b'), true);
  assert.equal(s.has('c'), true);
  assert.equal(s.size, 2);
});
test('fingerprint is a stable hash of the canonical envelope', () => {
  const e = signedEnv();
  assert.equal(fingerprint(e), fnv1a(canonicalJSON(e)));
  assert.equal(fingerprint(e), fingerprint({ ...e }));   // order-independent
});

// ─── federation: shouldFederate (leader forwarding decision) ────────────────
test('shouldFederate forwards own emits, forwards foreign forks, skips same-fork tabs', () => {
  const me = 'a'.repeat(64), other = 'b'.repeat(64);
  assert.equal(shouldFederate({ fork_pub: me }, me, true), true);    // my own emit → always
  assert.equal(shouldFederate({ fork_pub: me }, me, false), false);  // another tab, same fork → skip
  assert.equal(shouldFederate({ fork_pub: other }, me, false), true); // a real other organ → forward
  assert.equal(shouldFederate(null, me, false), false);              // junk → skip
  assert.equal(shouldFederate({}, me, false), false);                // no fork_pub → skip
});
