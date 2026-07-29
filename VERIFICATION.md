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

## Multi-tab leader election

Two OS tabs opened on one machine, both with `?relay=…&room=fed`:

| Claim | Evidence |
|---|---|
| Only the leader connects | relay reported **1 connection** with two federating tabs open |
| Roles are exclusive | tab 1 → `{leader:true, connected:true}`; tab 2 → `{leader:false, connected:false}` |
| Automatic failover | navigating the leader tab away → tab 2 auto-promoted to `{leader:true, connected:true}`; relay still 1 connection |
| Coherent forwarding | `shouldFederate` unit-tested: forwards own emits + foreign forks, skips a sibling tab's same-fork envelopes |
| No seq regression on failover | new leader resumes above the persisted `fedhw` high-water (ledger snapshot/restore unit-tested) |

## WebRTC carrier — relay-free, peer-to-peer

Two OS tabs, connected via `os.federateRTC()` with the offer/answer blobs
exchanged out-of-band (copy-paste), **no relay running in the data path**:

| Claim | Evidence |
|---|---|
| Direct data channel establishes | both tabs → `{connected:true, transport:'rtc'}` (roles initiator/answerer) via host candidates, no STUN |
| Envelopes flow peer-to-peer | initiator `sent:2`; answerer `recv:3` (incl. a boot beacon), bidirectional |
| Four-check verification over RTC | `rejected:0` on both — every envelope passed structure + Ed25519 + ledger + dedup |
| No relay in the data path | relay reported **0 connections** during the entire RTC exchange |
| Signaling is validated | `validSignal` unit-tested (offer/answer/candidate shape, bad version/from/room rejected) |
| WS path unregressed by the refactor | tab was `{connected:true, leader:true, transport:'ws'}` before switching carriers |

## WebRTC auto-signaling — relay brokers only the handshake

Two **different-origin** tabs (`localhost` vs `127.0.0.1` → distinct identities,
separate BroadcastChannel scopes — a genuine two-machine simulation), each opened
with `?rtc=ws://localhost:17346/&room=autotest`:

| Claim | Evidence |
|---|---|
| Auto-discovery + role split | A → `{transport:'rtc-auto', role:'offerer'}`, B → `{role:'answerer'}`; `politePeer` picked the offerer deterministically |
| Distinct identities | A pub `c7b4acadbe`, B pub `8522d2fb6e`; each sees the other as `peer` |
| P2P channel auto-established | both `{connected:true}` with only the relay handshake between them |
| Envelopes flow P2P, verified | A `sent:1/recv:1`, B `sent:2/recv:2`, both `rejected:0` |
| Relay-free data path | envelopes go `carrier.send` (data channel); the signaling socket carries only `hello`/`offer`/`answer` |
| hello signal validated | `validSignal` unit-tested for the `hello` type (no sdp required; bad from/room rejected) |

## N-peer full mesh

**Three** different-origin tabs (`localhost`, `127.0.0.1`, `127.0.0.2` → three
distinct identities), each `?rtc=ws://localhost:17346/&room=mesh3`:

| Claim | Evidence |
|---|---|
| Full mesh auto-forms | all three machines reached `connectedPeers: 2` (each linked to the other two — 3 pairwise links) |
| Distinct identities | pubs `d74b4b42`, `8f168eb6`, `1684bc89`; relay showed 3 signaling connections |
| Envelopes flow across all links | every machine `sent`/`recv` > 0, all `rejected: 0` (four-check verified) |
| Broadcast forwarding | `forward` sends to every open link; shared ledger/SeenCache dedup across links |
| Bounded | `MAX_PEERS` (16) caps the mesh; `opts.peers` optional allow-list |

## Relay-through gossip

**Deterministic** — `node integration/gossip.mjs` (real kernel primitives, simulated topology): relay-through in a partial mesh (B↔C via A), loop-freedom in a cyclic triangle, no-bounce-to-source, and multi-hop line flooding (A→B→C→D). 4/4.

**Live** — a forced partial mesh: A opened plain; B and C opened with `?peers=<A's pub>` so they link **only to A**, never each other:

| Claim | Evidence |
|---|---|
| Partial mesh formed | A `connectedPeers: 2`; B `connectedPeers: 1` (A only) |
| Gossip relays through A | B (no direct C link) received a **third fork** `c7cf531e88` = C's, relayed by A — `gossipProven: true` |
