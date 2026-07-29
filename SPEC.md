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

## §6 · Cross-machine (next)

The mesh is same-machine cross-tab (BroadcastChannel). The bridge carries a
`fallrelay` WebSocket seam already. Federation of two boxes' meshes:

1. **relay path (achievable now):** a dumb WS relay rebroadcasts signed envelopes
   between machines; signatures + `prev_hash` chains make the relay untrusted —
   it cannot forge, only carry. Per-fork chains are verified on receipt.
2. **WebRTC path (stretch):** browser-to-browser via the existing `fallswarm`
   transport once built.

Envelopes are already transport-agnostic and self-authenticating, so §6 adds a
carrier, not a trust model.

## §7 · Non-goals for this build

- Remote AI tier in-browser (use the si-didy-agent cockpit).
- Hard-blocking admission (logged, switchable).
- The full estate app set mounted (FallMesh is the reference organ; the rest
  mount the same way once each ships an `organ.json` + konomify pass).
