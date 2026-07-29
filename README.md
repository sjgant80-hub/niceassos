# niceassos

**The OG sovereign browser OS.** One substrate: the `fallos` desktop shell
(blob-iframe app sandbox + shared IndexedDB) merged onto the signed
`niceassos-mesh` (Ed25519 envelopes, hash-chained) — with proof-of-play
admission, data-driven cross-organ routing, and a local-first brain.

Architecture: Thomas Frumkin · Implementation: Simon Gant · ◊·κ=1

---

## What this is

Before this repo there were two half-operating-systems that never touched:

- **`fallos.html`** — a real desktop shell: boots, docks apps, sandboxes any
  HTML tool in a blob-iframe with a `postMessage` + shared-IndexedDB bridge. But
  its cross-app bus was a hardcoded 4-entry table, its AI was a stub, and it knew
  nothing about the mesh.
- **`niceassos-mesh`** — a real signed bus: every tab a node, every envelope
  Ed25519-signed and `prev_hash`-chained. But nothing mounted onto it.

`niceassos` is the **merge**. The shell is now a first-class signed node on the
mesh; apps launched in the desktop announce themselves as signed organs; the
cross-app bus is the mesh; the brain is a local-first cascade.

## The pieces

| File | Role | Gated |
|---|---|---|
| `niceassos-kernel.mjs` | **Pure** merge logic — envelope build, hash-chain (`MeshLog`), proof-of-play admission (`admit`), data-driven routing (`route`), brain tier router (`cascade`). Zero browser deps. | witness **49/49 · 1.0** |
| `niceassos-bridge.js` | Browser adapter — lands the kernel on real hardware: Ed25519 signing (Web Crypto), the `niceassos-mesh` BroadcastChannel, SHA-256 chain, IndexedDB identity, the fallrelay local-AI worker. | in-browser verified |
| `fallos.html` | The merged OS shell — grafts onto the mesh on boot, routes app events through the kernel, serves AI through the cascade, signs a `fork_join` per mounted app. | in-browser verified |
| `apps/fallmesh.html` | The OS's own bus inspector — a real first app: live signed-envelope monitor. | mounts as a real organ |
| `organ.schema.json` | The L3 organ manifest schema every app declares itself with. | — |

## Why a pure kernel

The load-bearing decisions — *is this envelope well-formed, does this app get to
mount, who receives this event, which brain tier serves this task* — live in
`niceassos-kernel.mjs` as **total functions of their inputs**. No
`BroadcastChannel`, no `crypto`, no DOM. That is what makes the OS's core
**witnessable and konomifiable**: 49 mutants, all killed, score 1.0. The browser
I/O that *can't* be pure (signing, channels) is quarantined in the bridge.

## Proof-of-play admission

An app mounts into the OS only if `admit(manifest, {konomified})` passes: the
manifest is schema-shaped **and** the tool is konomified. The anti-lemons rail,
applied to the OS itself — no green, no mount.

## Local-first brain

`cascade(task, caps)` routes intelligence: a mechanical task burns no model;
otherwise the local worker (fallrelay / WebLLM on your own GPU) serves it; remote
is the fallback, taken only when local is down or the task needs tools it can't
run. The OS is local-first by construction, not by policy.

## Run it

```bash
node scripts/serve.mjs            # dev static server → http://localhost:8231
# open http://localhost:8231/ — the OS boots and grafts onto the mesh
```

On boot the HUD logs `niceassos-mesh · GROUND grafted · fork <pub>…`. Launch
**FallMesh** from the dock to watch signed envelopes fly. Open a second tab to
see the two nodes federate over the shared bus.

## Test the kernel

```bash
node --test               # 37 tests
node ../witness/witness.mjs mutate niceassos-kernel.mjs   # 49/49 killed · clean
```

## Cross-machine federation

Two boxes' meshes federate over an **untrusted WebSocket relay**
(`scripts/relay-server.mjs`, zero-dep protocol in `niceassos-relay.mjs`). The
relay only carries; every node re-verifies on receipt — structure, **Ed25519
signature**, `FederationLedger` replay/chain, `SeenCache` loop dedup. A forged or
replayed envelope is rejected; only verified envelopes reach the local mesh.

```bash
node scripts/relay-server.mjs                 # ws://localhost:17346/  (on a box both can reach)
node integration/federation.mjs               # end-to-end proof: 2 machines, forgery + replay rejected
```

Enable it in the OS by opening `fallos.html?relay=ws://host:port/&room=fed` on
each machine, or `installOS({ federate: { url, room } })`. See [`SPEC.md`](./SPEC.md) §6.

**Or go relay-free** with the **WebRTC carrier** — a direct peer-to-peer data
channel, no relay in the data path. Signaling is out-of-band (copy-paste one
offer/answer blob), so no signaling server either:

```js
// machine A (initiator)          // machine B (answerer)
const f = os.federateRTC();       const f = os.federateRTC();
const offer  = await f.createOffer();      // → send offer to B
                                  const answer = await f.acceptOffer(offer); // → send answer back
await f.acceptAnswer(answer);     // channel opens → envelopes flow P2P
```

Same four-check verification, same coherence guarantees — only the wire differs.
See [`SPEC.md`](./SPEC.md) §6b.

**Turnkey WebRTC** with **auto-signaling** — the relay brokers only the handshake,
then the data path is peer-to-peer. Point every machine at the same relay+room and
they discover each other and form a **full mesh** (N machines, each linked to every
other) automatically:

```js
os.federateRTCAuto({ url: 'ws://host:port/', room: 'fed' });
// or open fallos.html?rtc=ws://host:port/&room=fed on each machine
```

`politePeer` (pure kernel) splits the role for each pair so there's never a glare
collision; the relay never touches envelope data. See [`SPEC.md`](./SPEC.md) §6c.

## What's real vs what's next

**Real and verified:** the signed mesh, the blob-iframe sandbox, the hash chain,
data-driven routing, proof-of-play admission, the cascade tiering, the
launch→signed-`fork_join` loop, and **cross-machine federation** (relay carrier +
sign/chain/replay verification on receipt).

Two machines that can't form a *direct* WebRTC link still exchange via **relay-through
gossip** — any machine re-forwards a received envelope to its other peers (loops
stopped by the ledger + dedup). On by default; `opts.gossip:false` for a pure mesh.

**Next:** the full estate app set mounted as gated organs; the remote AI tier wired
in-browser (today it's the si-didy-agent cockpit); a spanning-tree gossip overlay to
cut the flood's redundant sends on large meshes.

## License

MIT — see [`LICENSE`](./LICENSE). Sovereign code. The math is the math.
