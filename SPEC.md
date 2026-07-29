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

Two boxes' meshes federate over a **carrier**. Carriers are interchangeable — the
envelopes are self-authenticating, so a carrier only carries. The receive path
(the four checks below), the `shouldFederate` forwarding, the `FederationLedger`,
persistence and dedup are **transport-agnostic** (`makeFedContext` / `fedReceive` /
`fedForward` in the bridge); each carrier just supplies a wire.

- **Carrier 1 — WebSocket relay** (`connectFederation`): a dumb, untrusted relay
  (`scripts/relay-server.mjs`, protocol in `niceassos-relay.mjs`) fans signed
  envelopes to room-mates. Web Locks leader election (§6a).
- **Carrier 2 — WebRTC data channel** (`connectFederationRTC`): peer-to-peer, **no
  relay in the data path** (§6b).

Every node re-verifies on receipt, whichever carrier delivered the envelope:

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
- **Leader election (multi-tab).** Multiple OS tabs on one machine now federate
  cleanly: a **Web Locks** exclusive lock (`niceassos-fed:<room>`) elects one
  tab as the machine's federation gateway — the only tab with a relay socket and
  the only forwarder. `shouldFederate` keeps its forwarded stream a single
  coherent chain (own emits + genuine other-fork organs, never a sibling tab's
  same-fork envelopes). When the leader tab closes the lock releases and a queued
  tab takes over automatically; the new leader resumes its fork's `seq` strictly
  above the persisted high-water (`fedhw:<room>`), so the remote sees a gap, never
  a regression. Followers still see all remote traffic — the leader injects it
  onto the shared local mesh. *Verified: two tabs → one relay connection; on
  leader close the follower auto-promotes and connects.*

**Known limitations (documented, not yet fixed):**
- **RFC 6455 completeness.** The codec assumes the small, single-frame, masked
  JSON messages real browser/Node clients send; it does not enforce client
  masking or reassemble fragmented (FIN=0) messages. The relay never trusts a
  payload, so these are robustness items, not trust holes.

## §6b · WebRTC carrier — relay-free, peer-to-peer (BUILT)

`connectFederationRTC` federates two boxes over an **RTCDataChannel with no relay
in the data path**. It reuses the exact same engine as the WS carrier
(`fedReceive` / `fedForward` / the four checks / `shouldFederate`); only the wire
differs. `makeRTCCarrier` wires an `RTCPeerConnection` + a `niceassos-fed` data
channel.

- **Signaling is out-of-band.** Non-trickle ICE: the carrier gathers all
  candidates, then hands back **one** offer/answer blob for exchange by any means
  (copy-paste, QR, a file) — so a connection needs **no signaling server**. The
  blob is untrusted input: `validSignal` (pure kernel) checks its shape before it
  reaches `setRemoteDescription`. Flow: initiator `createOffer()` → peer
  `acceptOffer(offer)` → initiator `acceptAnswer(answer)` → the channel opens.
- **Signals are signed + verified.** Each blob is Ed25519-signed over
  `(v,type,room,from,sha256(sdp))` and the peer verifies it against the blob's own
  `from` before `setRemoteDescription` — so a signal tampered in transit is
  rejected. This is tamper-evidence, not full MITM immunity: because `from` rides
  in the blob, a transparent MITM over an *untrusted* signaling channel could
  substitute its own key-pair. For MITM protection, **confirm the peer's `from`
  fork_pub out-of-band** (compare the short prefix), or exchange the blob over a
  channel you already trust (in person, an authenticated messenger). Envelope
  trust is separate and always holds: every envelope is Ed25519-verified on
  receipt, so signaling compromise can censor/observe but never *inject* data.
- **Zero external dependency by default.** `iceServers` is empty → host candidates
  (same machine / LAN). A STUN server is only needed for internet NAT traversal
  (it reflects your IP; it never carries data). No TURN — that would reintroduce a
  relay.
- **Same engine, same guarantees.** Ledger persistence, `fedhw` seq continuity,
  `SeenCache` dedup, and `shouldFederate` coherence all apply over WebRTC.

Enable it: `installOS(...)` then `os.federateRTC({ room, iceServers? })` and drive
the offer/answer exchange. *Verified: two tabs established a direct data channel
via copy-paste signaling; envelopes flowed bidirectionally, all four-check
verified (`rejected: 0`), with the relay at **0 connections** — genuinely
relay-free.*

## §6c · WebRTC auto-signaling — N-PEER full mesh (BUILT)

`connectFederationRTCAuto` makes the WebRTC carrier turnkey and scales to K
machines: the relay brokers only the handshakes, then every machine holds a
direct P2P link to every other machine (a **full mesh**, K−1 links each).

- **Discovery.** Every machine joins a signaling-only relay room (`rtcsig:<room>`)
  and announces a signed `hello`. Seeing an unknown peer, a node replies with its
  own `hello`, so the mesh fills in regardless of join order — a late joiner is
  discovered by, and discovers, every existing member.
- **Per-pair role split (no glare).** Each pair negotiates independently; for any
  pair `politePeer(self, peer)` (pure kernel, total + antisymmetric) makes exactly
  one side the offerer. No offer collision, across the whole mesh.
- **Per-link state.** A `Map<peerPub, link>` holds one carrier + role + self-heal
  timer per peer. A dropped or failed link tears down and re-announces on its own,
  independent of the other links.
- **Broadcast forwarding.** An envelope is sent to every open link; the single
  shared `FederationLedger` + `SeenCache` dedup across links (an envelope arriving
  from two peers is processed once).
- **Signed handshake, relay-free data.** `hello`/`offer`/`answer` are Ed25519-
  signed (`to`+`ts` in the signed body) and verified before touching
  `RTCPeerConnection`; envelopes go over the data channels, never the relay.
- **Per-link delivery.** Each link has its own outbox + delivered-set; an envelope
  is queued to every link and flushed on open / `bufferedamountlow`, so a slow,
  congested, or late-joining link never loses an envelope a faster link already
  took. Receive is serialized per context so the ledger sees envelopes in order.
- **Self-heal + bounds.** Per-link 12s negotiation timeout tears down and
  re-invites (directional); a dropped connected link recovers via WebRTC's own
  connection-state detection. `MAX_PEERS` (16) + `MAX_PENDING` (6 half-open) bound
  the mesh; signals carry a replay cache. Shares the WS carrier's Web Lock — one
  gateway tab per machine.
- **Trust model.** The relay room is the admission boundary. On an *untrusted*
  relay, a room member can Sybil-churn half-open slots (bounded by `MAX_PENDING`)
  or flood the shared ledger (bounded by its LRU); it can **never forge** an
  envelope (Ed25519). For untrusted networks, pass `opts.peers` (allow-list) or use
  a secret room name.
- **Limitation.** Full mesh, no relay-through gossip: two machines that cannot form
  a *direct* link (e.g. symmetric NAT without a STUN/TURN server) do not exchange,
  even if both can reach a third.

Enable it: `os.federateRTCAuto({ url, room, iceServers?, peers? })`, or open
`fallos.html?rtc=ws://host:port/&room=fed` on each machine. *Verified: three
different-origin tabs (distinct identities) auto-formed a full mesh — each machine
`connectedPeers: 2` — and envelopes flowed across all links, all four-check
verified (`rejected: 0`).*

## §7 · Non-goals for this build

- Relay-through gossip (partial-mesh relay of a peer's envelopes) — the full mesh
  is built; gossip would let non-directly-connectable machines still exchange.
- Remote AI tier in-browser (use the si-didy-agent cockpit).
- Hard-blocking admission (logged, switchable).
- The full estate app set mounted (FallMesh is the reference organ; the rest
  mount the same way once each ships an `organ.json` + konomify pass).
