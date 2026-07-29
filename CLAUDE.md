# CLAUDE.md — niceassos build notes

Context for anyone (human or Claude) working on this repo.

## What it is

The merge of `fallos.html` (desktop shell) and `niceassos-mesh` (signed bus) into
one sovereign browser OS. See [`README.md`](./README.md) and [`SPEC.md`](./SPEC.md).

## Layout

- `niceassos-kernel.mjs` — **pure** merge logic. Edit here for admission/routing/
  cascade/envelope behaviour. Every function is a total function of its inputs —
  keep it that way (no `Date.now`, `crypto`, `BroadcastChannel`, DOM). Injected
  deps only.
- `niceassos-bridge.js` — browser I/O. The only place `crypto.subtle`,
  `BroadcastChannel`, `indexedDB`, `WebSocket` live. ES module.
- `fallos.html` — the shell. The merge touches four spots: `initMesh()`,
  `launchModule`'s `iframe.onload`, `handleModuleEvent`, `handleAIRequest`.
- `apps/*.html` — mounted organs. `fallmesh.html` is the reference.
- `test/kernel.test.mjs` — node test suite for the kernel.
- `serve.mjs` — dev static server (not shipped as part of the OS).

## Invariants

- **The kernel stays pure.** If a change needs I/O, it goes in the bridge and the
  kernel gets a new pure function the bridge calls.
- **Signatures are added only in the bridge.** The kernel builds envelope-minus-
  signature; the `signature` key must never appear in kernel output.
- **The chain is canonical-JSON + SHA-256** in the bridge; `fnv1a` in the kernel
  is the zero-dep self-test hasher only.
- **Admission is proof-of-play.** Don't loosen `admit` to mount un-konomified
  organs; if you need a dev bypass, gate it behind an explicit flag, logged.

## Federation (§6)

- `niceassos-relay.mjs` — **pure** WS protocol (frame codec + `Rooms` fan-out).
  Witnessed. One reviewed-equivalent baselined in `witness.baseline.json`.
- `scripts/relay-server.mjs` — socket glue (I/O, not witnessed). `start(port)`
  is importable so `integration/federation.mjs` can spin it up.
- Bridge federation is **transport-agnostic**: `makeFedContext` (per-room state) +
  `fedReceive` (the four checks) + `fedForward` (`shouldFederate` + dedup) are
  shared by both carriers. `connectFederation` = WS relay carrier (+ Web Locks
  leader election); `connectFederationRTC` + `makeRTCCarrier` = WebRTC carrier.
  When editing the receive/forward path, edit the shared helper — never one
  carrier only — so both stay in lockstep.
- WebRTC (relay-free): `os.federateRTC({room, iceServers?})` → `createOffer` /
  `acceptOffer` / `acceptAnswer` (out-of-band blob exchange). `validSignal`
  (kernel) guards the blob; envelopes are still Ed25519-verified, so signaling
  carries no trust. Default `iceServers: []` = host candidates (LAN); add STUN
  only for internet NAT.
- Run a relay: `node scripts/relay-server.mjs`. Federate the OS:
  `fallos.html?relay=ws://host:port/&room=fed`.

## Gates

```bash
node --test                                           # unit tests (kernel + relay), fast/pure
node integration/federation.mjs                       # end-to-end federation proof (real sockets)
node ../witness/witness.mjs mutate niceassos-kernel.mjs  # kernel: must stay clean
node ../witness/witness.mjs mutate niceassos-relay.mjs   # relay: 20/21 + 1 baselined equivalent
node ../konomify/konomify.mjs .                        # repo gate (non-masking: witnesses every root .mjs)
```

Note `node --test` deliberately does NOT run `integration/` (it's outside the
test glob) so the mutation gate stays fast and pure.

After any kernel edit: re-run witness. A surviving mutant means a new line is
unguarded — add the boundary test, don't baseline unless it's a genuine reviewed
equivalent.

## Verifying the browser wiring

Serve, open `http://localhost:8231/`, wait for boot, then in the console:

```js
window.NICEASSOS.identity();                 // { pub, source: 'os-local-ed25519' }
await window.NICEASSOS.emit('beacon', {x:1}); // signed (sigLen 128), chained
```

Launch **FallMesh** to see live signed traffic; a second tab federates.

## Provenance

Architecture: Thomas Frumkin · Implementation: Simon Gant. Part of the sjgant80-hub
estate. The private cosmology (v23-seed, κ/θ/Ψ internals) is not required to read
or extend this repo — the mechanisms here are standard web primitives with a
clean seam.
