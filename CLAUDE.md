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

## Gates

```bash
node --test                                           # 37 kernel tests
node ../witness/witness.mjs mutate niceassos-kernel.mjs  # must stay 49/49 · clean
node ../konomify/konomify.mjs .                        # repo gate
```

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
