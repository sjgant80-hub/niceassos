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
