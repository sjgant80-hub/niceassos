/* integration/gossip.mjs
 * Deterministic simulation of the mesh GOSSIP (relay-through) algorithm using the
 * real kernel primitives (FederationLedger + SeenCache + verifyEnvelope). No
 * WebRTC — the transport is proven elsewhere; this pins the flooding logic:
 * relay-through reachability in a PARTIAL mesh, loop-freedom in a cyclic mesh,
 * and no-bounce-to-source. Run: `node integration/gossip.mjs`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { VERSION, canonicalJSON, verifyEnvelope, FederationLedger, SeenCache, fingerprint } from '../niceassos-kernel.mjs';

const sha = (s) => createHash('sha256').update(s).digest('hex');
const SIG = 'a'.repeat(128);

// a fork that emits a chained, (structurally) signed stream
function fork(pub) {
  let seq = 0, prev = null;
  return {
    pub,
    make(payload) {
      const env = { version: VERSION, kind: 'organ_event', fork_pub: pub, ts: new Date().toISOString(), seq: seq++, prev_hash: prev, payload, signature: SIG };
      prev = sha(canonicalJSON(env));
      return env;
    },
  };
}

// a machine: verifies + ledger/seen dedup on receive, injects, then GOSSIPS to
// every peer except the one it came from (exactly the bridge's meshReceive).
function machine(pub, net) {
  const ledger = new FederationLedger();
  const seen = new SeenCache();
  const delivered = new Map(); // peerPub -> SeenCache (per-link, like the bridge)
  const link = (p) => { if (!delivered.has(p)) delivered.set(p, new SeenCache()); return delivered.get(p); };
  const m = {
    pub, peers: new Set(), injected: [], sends: 0,
    connect(peer) { m.peers.add(peer); },
    receive(env, fromPub) {
      if (env.fork_pub === pub) return;                          // our own echo
      if (!verifyEnvelope(env, { requireSig: true }).ok) return; // structure (crypto proven elsewhere)
      if (!ledger.accept(env, sha(canonicalJSON(env))).ok) return; // replay / chain → stops loops
      if (!seen.add(fingerprint(env))) return;
      m.injected.push(env);
      if (fromPub) link(fromPub).add(fingerprint(env));          // don't bounce back to the source
      m.broadcast(env);                                          // gossip onward
    },
    broadcast(env) {
      const k = fingerprint(env);
      for (const peer of m.peers) {
        if (link(peer).has(k)) continue;                        // already sent to this peer
        link(peer).add(k);
        m.sends++;
        net.deliver(peer, env, pub);
      }
    },
  };
  return m;
}

function network() {
  const machines = new Map();
  const q = [];
  return {
    add(m) { machines.set(m.pub, m); },
    link(a, b) { machines.get(a).connect(b); machines.get(b).connect(a); },
    deliver(to, env, from) { q.push({ to, env, from }); },
    run() { let n = 0; while (q.length) { const { to, env, from } = q.shift(); machines.get(to).receive(env, from); if (++n > 100000) throw new Error('gossip did not terminate (loop!)'); } return n; },
  };
}

test('gossip relays B↔C through a common peer A (partial mesh, no direct B-C link)', () => {
  const net = network();
  const A = machine('a'.repeat(64), net), B = machine('b'.repeat(64), net), C = machine('c'.repeat(64), net);
  [A, B, C].forEach(m => net.add(m));
  net.link(A.pub, B.pub); net.link(A.pub, C.pub); // B and C are NOT directly linked
  const fb = fork(B.pub);
  B.broadcast(fb.make({ from: 'B', n: 0 })); // B emits to its peers (A only)
  net.run();
  // C received B's envelope even though B and C have no direct link
  assert.equal(C.injected.length, 1, 'C got B\'s envelope via A (relay-through)');
  assert.equal(C.injected[0].fork_pub, B.pub);
  assert.equal(A.injected.length, 1, 'A relayed exactly one');
});

test('gossip does not loop in a fully cyclic mesh (triangle)', () => {
  const net = network();
  const A = machine('a'.repeat(64), net), B = machine('b'.repeat(64), net), C = machine('c'.repeat(64), net);
  [A, B, C].forEach(m => net.add(m));
  net.link(A.pub, B.pub); net.link(B.pub, C.pub); net.link(A.pub, C.pub); // full triangle (cyclic)
  const fa = fork(A.pub);
  A.broadcast(fa.make({ from: 'A', n: 0 }));
  const steps = net.run(); // throws if it loops forever
  // every other machine received A's envelope exactly once
  assert.equal(B.injected.length, 1);
  assert.equal(C.injected.length, 1);
  assert.ok(steps < 100000, 'terminated');
});

test('gossip never bounces an envelope back to its source', () => {
  const net = network();
  const A = machine('a'.repeat(64), net), B = machine('b'.repeat(64), net), C = machine('c'.repeat(64), net);
  [A, B, C].forEach(m => net.add(m));
  net.link(A.pub, B.pub); net.link(A.pub, C.pub);
  const fb = fork(B.pub);
  B.broadcast(fb.make({ from: 'B', n: 0 }));
  net.run();
  // B emitted its own fork; the echo (via A→...) is ignored, so B injects nothing of its own
  assert.equal(B.injected.length, 0, 'B does not re-inject its own gossiped envelope');
});

test('gossip floods a line topology end to end (A-B-C-D)', () => {
  const net = network();
  const M = ['a', 'b', 'c', 'd'].map(x => machine(x.repeat(64), net));
  M.forEach(m => net.add(m));
  net.link(M[0].pub, M[1].pub); net.link(M[1].pub, M[2].pub); net.link(M[2].pub, M[3].pub); // a line
  const fa = fork(M[0].pub);
  M[0].broadcast(fa.make({ from: 'A', n: 0 }));
  net.run();
  assert.equal(M[3].injected.length, 1, 'D (two hops away) received A\'s envelope via B then C');
});
