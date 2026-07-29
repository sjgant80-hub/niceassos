/* integration/federation.mjs
 * End-to-end proof that two boxes federate through the relay.
 * Real relay server + two native WebSocket clients + real Ed25519 signing +
 * the kernel's verify/ledger. NOT a unit test (needs sockets + a server), so it
 * lives outside test/ and is run explicitly: `node integration/federation.mjs`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { start } from '../scripts/relay-server.mjs';
import { VERSION, canonicalJSON, verifyEnvelope, FederationLedger } from '../niceassos-kernel.mjs';

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = (s) => { const a = new Uint8Array(s.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(s.substr(i * 2, 2), 16); return a; };
const sha256hex = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));

// a "machine": an Ed25519 fork that emits chained, signed envelopes
async function machine() {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = hex(await crypto.subtle.exportKey('raw', kp.publicKey));
  let seq = 0, prev = null;
  async function make(kind, payload) {
    const ems = { version: VERSION, kind, fork_pub: pub, ts: new Date().toISOString(), seq: seq++, prev_hash: prev, payload };
    const sig = hex(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, enc.encode(canonicalJSON(ems))));
    const env = { ...ems, signature: sig };
    prev = await sha256hex(canonicalJSON(env));
    return env;
  }
  return { pub, make };
}

// the receiver's trust check (exactly what the bridge does on receipt)
async function verifyRemoteSig(env) {
  try {
    const pub = await crypto.subtle.importKey('raw', unhex(env.fork_pub), { name: 'Ed25519' }, false, ['verify']);
    const { signature, ...rest } = env;
    return await crypto.subtle.verify({ name: 'Ed25519' }, pub, unhex(signature), enc.encode(canonicalJSON(rest)));
  } catch (_) { return false; }
}

function connect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.onopen = () => resolve(ws);
    ws.onerror = (e) => reject(new Error('ws error'));
    setTimeout(() => reject(new Error('connect timeout')), 3000);
  });
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('two boxes federate over the untrusted relay', async () => {
  const relay = await start(0); // ephemeral port
  const base = `ws://localhost:${relay.port}/?room=fed`;
  const A = await machine();
  const B = await machine();

  // B is the receiver: verify sig + ledger on every relayed envelope
  const ledgerB = new FederationLedger();
  const acceptedByB = [];
  const rejectedByB = [];
  const wsA = await connect(base);
  const wsB = await connect(base);
  wsB.onmessage = async (ev) => {
    const env = JSON.parse(ev.data);
    if (!verifyEnvelope(env, { requireSig: true }).ok) return rejectedByB.push('structure');
    if (!(await verifyRemoteSig(env))) return rejectedByB.push('forged-sig');
    const h = await sha256hex(canonicalJSON(env));
    const r = ledgerB.accept(env, h);
    if (!r.ok) return rejectedByB.push(r.reason);
    acceptedByB.push(env);
  };
  await wait(150); // let both joins settle

  try {
    // 1) A emits two chained signed envelopes → B should accept both
    const e0 = await A.make('beacon', { n: 0 });
    const e1 = await A.make('organ_event', { from: 'crm', event: 'deal.closed', data: { amount: 5000 } });
    wsA.send(JSON.stringify(e0));
    wsA.send(JSON.stringify(e1));
    await wait(250);
    assert.equal(acceptedByB.length, 2, 'B accepts both of A\'s signed envelopes');
    assert.equal(acceptedByB[1].payload.event, 'deal.closed', 'payload crossed the machine boundary intact');

    // 2) FORGERY: relay carries a tampered envelope → B rejects (relay cannot forge)
    const forged = { ...e0, payload: { n: 999 } }; // signature no longer matches payload
    wsA.send(JSON.stringify(forged));
    await wait(200);
    assert.ok(rejectedByB.includes('forged-sig'), 'B rejects a tampered payload (sig fails)');

    // 3) REPLAY: A re-sends e0 (seq 0, already seen) → ledger rejects as stale
    wsA.send(JSON.stringify(e0));
    await wait(200);
    assert.ok(rejectedByB.some(r => /replay|stale/.test(r)), 'B rejects a replayed envelope');
    assert.equal(acceptedByB.length, 2, 'no new acceptance from forgery or replay');

    // 4) BIDIRECTIONAL: B emits, A receives + verifies
    const acceptedByA = [];
    wsA.onmessage = async (ev) => {
      const env = JSON.parse(ev.data);
      if (verifyEnvelope(env, { requireSig: true }).ok && await verifyRemoteSig(env)) acceptedByA.push(env);
    };
    const b0 = await B.make('beacon', { hello: 'from B' });
    wsB.send(JSON.stringify(b0));
    await wait(250);
    assert.equal(acceptedByA.length, 1, 'A receives B\'s envelope — federation is bidirectional');
    assert.equal(acceptedByA[0].fork_pub, B.pub, 'A sees B\'s real fork identity');
  } finally {
    try { wsA.close(); } catch (_) {}
    try { wsB.close(); } catch (_) {}
    await new Promise((r) => relay.server.close(r));
  }
});
