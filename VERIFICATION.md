# Verification

What was proven, and how. Two layers: the pure kernel (deterministic gates) and
the live browser wiring (observed in a running OS).

## Kernel — deterministic

```
node --test                                          → 37 pass / 0 fail
node ../witness/witness.mjs mutate niceassos-kernel.mjs → 49/49 killed · clean · 1.0
node ../konomify/konomify.mjs .                       → konomified · core 9/9 · witness 1.0
```

## Browser — live, observed in a booted OS (`http://localhost/`)

Inspected via the console against `window.NICEASSOS` after boot:

| Claim | Evidence |
|---|---|
| OS grafts onto the mesh on boot | `window.NICEASSOS` present; `identity.source = os-local-ed25519`, 64-hex pub |
| Envelopes are Ed25519-signed | emitted `beacon` had `signature` length 128 (64-byte sig) |
| Hash chain is intact | `prev_hash` a 64-hex SHA-256; second emit's `prev_hash` chained the first |
| Independent subscribers receive signed traffic | a fresh `BroadcastChannel('niceassos-mesh')` captured 2/2 signed envelopes |
| Data-driven routing (not the hardcoded table) | `fireOrganEvent('crm','deal.closed',…)` → `['account','audit']`; emitter `crm` excluded |
| App mounts as a real file | launching FallMesh created `frame-mesh` as an `IFRAME` (not the NOT-FOUND placeholder) |
| Mounting announces a signed organ | a `fork_join` with `handle: 'mesh'` appeared on the bus |
| Cascade brain routes local-first | `requestAI({tokens:10})` → tier `local`, reason "local-first (own GPU)" |

These are functional observations against the running merge, not assertions about
the source. Re-run: `node scripts/serve.mjs`, open the served OS, repeat the
console checks in [`CLAUDE.md`](./CLAUDE.md).

## Cross-machine federation — proven two ways

**Deterministic** — `node integration/federation.mjs` (real relay + two native
WebSocket clients + real Ed25519):

| Claim | Evidence |
|---|---|
| Two machines federate | A's two signed envelopes reach B; payload intact across the boundary |
| The relay cannot forge | a tampered payload's signature fails B's verify → rejected |
| Replays are rejected | a re-sent envelope is caught by the `FederationLedger` |
| Bidirectional | B→A works; A sees B's real fork identity |

**Live browser** — the actual `fallos` OS with `?relay=ws://localhost:17346/&room=fed`,
against a real relay and a separate node "machine" listening on the same room:

| Claim | Evidence |
|---|---|
| The OS federates | `os.federation()` → `{connected:true}` |
| It forwards its own signed envelopes | after two emits, `sent: 2` |
| The remote machine receives + verifies them | listener logged `beacon seq=1` and `organ_event seq=2` from the OS's fork, both `struct=true sig=true` (Ed25519 verified) |

The relay held no keys and inspected no payloads — it only carried; the far side
did all the trusting.

## Adversarial review + hardening

A 5-lens adversary workflow (attack → adversarially verify each finding) drove
these tested fixes:

| Fix | Proof |
|---|---|
| `emit()` serialized (no chain race) | 15 concurrent emits in-browser → unique+contiguous seqs, SHA-256 `prev_hash` linkage intact (`brokeAt: -1`) |
| Relay over-cap frame → `tooBig` (DoS) | `decodeFrames` unit test: a 2⁴⁰-declared frame flags `tooBig`, buffers nothing |
| Ledger persistence blocks reconnect-replay | kernel test: restore from `snapshot()` rejects the replayed seq |
| Freshness window (±5 min) | kernel test: stale + future-dated envelopes rejected at the boundary |
| Fork-table LRU (no lockout) | kernel test: over-cap evicts the least-recently-seen fork, accepts the new one |
| Federation intact after hardening | remote machine verified all forwarded envelopes (`sig=true`) through the hardened relay + bridge |
