# niceassos-spec/1.0 · the OG merge

The architecture of the merged OS. Sections map to the build phases.

## §0 · Substrate

One bus, one shell. The signed `niceassos-mesh` is the kernel bus; `fallos.html`
is the window/view onto it. Everything is an **organ** — the OS ground itself
(ring 0), and every app mounted into it (its declared ring).

Envelope (`niceassos-mesh-v1`), produced by `niceassos-kernel.mjs`:

```json
{
  "version": "niceassos-mesh-v1",
  "kind": "fork_join | beacon | bloom_pulse | organ_event | recall_query | ...",
  "fork_pub": "<64-hex Ed25519 public key>",
  "ts": "<ISO8601>",
  "seq": 0,
  "prev_hash": "<sha256 of the previous canonical envelope, or null>",
  "payload": { },
  "signature": "<128-hex Ed25519 signature over the canonical envelope-minus-sig>"
}
```

`prev_hash` links every envelope from a fork into a tamper-evident chain
(`MeshLog.verifyChain` locates the first break). `signature` is added by the
bridge; the kernel never signs and never sees a private key.

## §1 · Kernel (pure)

`niceassos-kernel.mjs` — total functions, node-testable, witness-clean:

- `canonicalJSON(o)` — byte-stable sorted-key stringify (signing/hashing basis).
- `envelope({kind,forkPub,seq,prevHash,payload,ts})` — validated construction.
- `MeshLog` — seq counter + `prev_hash` chain; `wrap(kind,payload,ts)` and static
  `verifyChain(envs, hasher)`.
- `admit(manifest, status)` — §2 admission.
- `route(env, organs)` — §3 routing.
- `cascade(task, caps)` — §4 brain tiering.
- `ringGlyph(ring)` — R0..R6 glyphs; out-of-range → neutral `·`.
- `verifyEnvelope(env, {requireSig})`, `FederationLedger`, `SeenCache`,
  `fingerprint` — §6 federation trust primitives (receiver-side, pure).

The bridge injects the real `sha256` hasher and Ed25519 signer; the kernel's
default `fnv1a` hasher exists only so the core is self-testable with zero deps.

## §2 · Admission — proof-of-play

`admit(manifest, {konomified})` returns `{ok, reason}`. Passes iff:

1. `name` matches `^[a-z0-9][a-z0-9-]{1,63}$`
2. `ring` is an integer 0..6
3. `glyph`, `purpose` are non-empty
4. `publishes` is a non-empty subset of the known envelope kinds
5. `listens` is non-empty
6. **`status.konomified === true`** — the proof-of-play gate

No green, no mount. This is the estate's anti-lemons rail turned inward on the
OS. The shell calls `admit` on launch; hard-blocking (vs logging) is a
deployment switch.

## §3 · Routing — data-driven

`route(organ_event, organs)` returns the organ names that should receive an app
domain-event, derived from each organ's **declared `receives`** (plus a `*`
wildcard), never a hardcoded table. The emitter never receives its own event;
unmounted organs are skipped. This replaces `fallos`'s original 4-entry
`routingMap` with the full emits/receives graph the app manifests already carry.

## §4 · Brain — local-first cascade

`cascade(task, caps)` with `caps = {local, remote}`:

- `task.mechanical` → `mechanical` (no model burned)
- else `local` when a local worker is up and the task is light
- else `remote` when local is down, or the task `needsTools` / exceeds 8000 tokens
- else `local` if only local exists; else `none`

The bridge's local tier is the `fallrelay` WebSocket worker
(`ws://localhost:17345/relay`) — your own GPU / WebLLM. Remote is a declared seam
(si-didy-agent / Claude), not wired in-browser in this build.

## §5 · Shell wiring (`fallos.html`)

- **boot** → `initMesh()` → `installOS()` grafts ring-0 `niceassos-ground`, emits
  a signed `fork_join`, beacons every 60s, mirrors bus traffic into the HUD.
- **launch** → on real mount, emits a signed `fork_join` for the app organ.
- **`handleModuleEvent`** → builds the mounted-organ view and routes via the
  kernel, emitting a signed `organ_event` on the bus.
- **`handleAIRequest`** → serves through `cascade`; honest degrade, never a fake
  "processing" placeholder.

## §6 · Cross-machine federation (BUILT)

Two boxes' meshes federate over an **untrusted WebSocket relay**. The relay
(`scripts/relay-server.mjs`, protocol in `niceassos-relay.mjs`) is a dumb carrier
— it re-frames and fans signed envelopes to room-mates and holds no keys and no
trust. Every node re-verifies on receipt, in the bridge's `connectFederation`:

1. **structure** — `verifyEnvelope(env, {requireSig:true})` (pure kernel).
2. **signature** — Ed25519 verify against the envelope's own `fork_pub`, over
   `canonicalJSON(env-minus-signature)`. A tampered payload fails here → the
   relay cannot forge.
3. **replay / chain** — `FederationLedger.accept(env, sha256)`: monotonic seq per
   fork (replay defense), `prev_hash` linkage on consecutive envelopes (tamper
   detection), a bounded fork table (memory-DoS defense), honest gap flagging.
4. **loop dedup** — `SeenCache` on the envelope digest, applied to both the
   receive path and the forward path, so an echo can never loop.

Only after all four does a remote envelope get injected onto the local mesh. A
box enables federation with `installOS({ federate: { url, room } })`, or the OS
shell reads `?relay=ws://host:port/&room=fed`.

**Transport model.** Envelopes are transport-agnostic and self-authenticating,
so the relay adds a carrier, not a trust model. A WebRTC carrier (browser-to-
browser via `fallswarm`) is a drop-in alternative once built — same envelopes,
same four checks.

**Proven** (see [`VERIFICATION.md`](./VERIFICATION.md)): `node integration/federation.mjs`
— two Ed25519 machines federate, a forged payload is rejected, a replay is
rejected, bidirectional; and live browser→relay→remote with signature
verification on the far side.

## §6a · Federation hardening (adversarial-review outcomes)

An adversarial review of the trust boundary drove these fixes, all tested:

- **emit() serialized** — overlapping async emits no longer interleave; `seq` and
  `prev_hash` advance atomically (proven under 15 concurrent emits, chain intact).
- **Relay DoS caps** — `decodeFrames` flags an over-cap declared length
  (`tooBig`); the server enforces a per-frame cap, a per-socket buffer cap, a
  connection cap, and an idle/slowloris timeout.
- **Reconnect-replay closed** — the `FederationLedger` high-water is persisted to
  IndexedDB per room and rehydrated on connect, and `verifyEnvelope` enforces a
  `±5 min` freshness window, so a relay cannot replay a fork's old signed history
  against a fresh ledger.
- **Fork-table LRU** — capacity is enforced by evicting the least-recently-active
  fork, not by locking out all new peers.
- **Local ingress dedup** — an envelope arriving on both the mesh and legacy
  channels is delivered to listeners once.

**Known limitations (documented, not yet fixed):**
- **One federating tab per machine.** Multiple tabs share one fork identity but
  keep independent chains; run the OS in a single tab, or add leader election
  (Web Locks) so one tab owns the relay socket and the chain.
- **RFC 6455 completeness.** The codec assumes the small, single-frame, masked
  JSON messages real browser/Node clients send; it does not enforce client
  masking or reassemble fragmented (FIN=0) messages. The relay never trusts a
  payload, so these are robustness items, not trust holes.

## §7 · Non-goals for this build

- WebRTC (browser-to-browser) carrier — the relay carrier is built; WebRTC is a
  drop-in alternative transport, same envelopes and same four checks.
- Remote AI tier in-browser (use the si-didy-agent cockpit).
- Hard-blocking admission (logged, switchable).
- The full estate app set mounted (FallMesh is the reference organ; the rest
  mount the same way once each ships an `organ.json` + konomify pass).
