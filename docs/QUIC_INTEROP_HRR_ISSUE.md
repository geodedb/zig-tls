# TLS 1.3 HelloRetryRequest interop regression — quic-go / mvfst clients

> **Filed:** 2026-04-27
> **Reported via:** zig-quic interop test suite
> (`gitlab.com/devnw/zig/quic`, commit `811420e`)
> **Severity:** High — breaks server-side QUIC interop with two of the most
> widely deployed implementations (quic-go, Facebook mvfst).
> **Status:** Open. Verified to predate the zig-quic 2026-04-27 perf-unblock
> pass (bisect against zig-quic commits `f7f4ec4`, `04fd9f5`, `18d49c8`
> reproduces identical failure).

---

## Symptom

`zig-quic` server crashes the handshake when it acts as the **server** and
**quic-go** or **mvfst** is the **client**:

```text
[qns] server: started (listening [::]:443)
ERROR: processInitial: sendHandshakePackets failed: NoHandshakeKeys
[qns] server: accepted connection
[qns] server: handshake timeout
```

ngtcp2 (and other tested clients) interop **succeeds** in the same matrix —
both directions handshake-pass for ngtcp2. The failure is specific to clients
whose **first ClientHello carries a non-X25519 `key_share`**.

`zig server <-> X client`:

| Client  | First ClientHello key_share | Result |
|---------|-----------------------------|--------|
| ngtcp2  | `x25519`                    | PASS   |
| quic-go | `x25519_kyber768_draft00` (or similar PQ-hybrid) | **FAIL** |
| mvfst  | `secp256r1` (NIST P-256)    | **FAIL** |

`X server <-> zig client`: passes for all three (zig-as-client is unaffected).

---

## Root cause sketch

Located in `src/tls13/context.zig`. The server flight orchestrator
`driveServerHandshakeFlight` fires on every processed ClientHello and
delegates to `negotiateCipherAndKeys`, which gates on the **first**
ClientHello's `key_share.group`:

```zig
// src/tls13/context.zig:1693-1698
// RFC 8446 §4.1.4: Check if client's key_share group is supported
if (ch_view.key_share.group != .x25519) {
    if (self.hrr_sent) return HandshakeError.UnsupportedKeyShareGroup;
    try self.sendHelloRetryRequest(ch_view, .x25519);
    return null; // HRR sent; stop flight
}
```

When the first ClientHello's `key_share` is not X25519, the server queues a
HelloRetryRequest into the Initial outbound stream and returns `null` from
`negotiateCipherAndKeys`. `driveServerHandshakeFlight` propagates that as a
no-op (`var neg = try self.negotiateCipherAndKeys() orelse return;`) — no
Handshake-level traffic secrets get installed, which is correct **for the
HRR turn**.

The QUIC transport then calls `pollCrypto(.Initial)` to drain the HRR bytes
and emits them in an Initial packet. `pollCrypto(.Handshake)` correctly
returns nothing (no Handshake keys yet). So far, so good.

**What's broken:** the transport never receives a usable second
ClientHello. From the QUIC side it looks like the client sends a second
ClientHello (CH2) over the same DCID, the bytes are buffered,
`pushCrypto(.Initial, …)` is
invoked, and `processCrypto` walks the inbound stream — but
`negotiateCipherAndKeys` is never re-driven into a state that installs the
handshake secrets. Either:

1. The ClientHello #2 parser path errors silently before reaching
   `afterHandshakeMessage(.client_hello)` → `driveServerHandshakeFlight`.
2. Or the HRR-related transcript / state reset (`self.state.reset(self.allocator)`
   at line 1080) leaves residual `secrets`/`flags` state that makes
   `negotiateCipherAndKeys` short-circuit on the second pass.
3. Or `processCrypto` consumes ClientHello #2 but the buffered bytes never
   form a complete handshake message because the post-HRR length-prefix
   accounting is off (CH2 typically contains a `cookie` extension echoing
   the HRR cookie, which can change the parsed length).

We have not isolated which of (1)/(2)/(3) is the active failure mode — that
is the work this document is asking for.

---

## Reproduction

```bash
git clone gitlab.com/devnw/zig/quic
cd quic
make interop-build
SKIP_BUILD=1 INTEROP_IMPLS=quic-go INTEROP_TESTCASES=handshake \
  bash scripts/interop_full.sh basic
```

Expected (post-fix):

```text
[1;33mTesting: zig (server) <-> quic-go (client) - handshake[0m
✓ PASSED
```

Currently observed:

```text
[1;33mTesting: zig (server) <-> quic-go (client) - handshake[0m
interop_zig_quic-go_handshake_*_server | ERROR: processInitial: sendHandshakePackets failed: NoHandshakeKeys
[0;31m✗ FAILED[0m
```

The `mvfst` failure reproduces identically with `INTEROP_IMPLS=mvfst`.

The `ngtcp2` path passes — useful as a control:

```bash
INTEROP_SKIP_EXTRAS=1 SKIP_BUILD=1 INTEROP_IMPLS=ngtcp2 \
  INTEROP_TESTCASES=handshake bash scripts/interop_full.sh full
```

---

## Why the X25519-only restriction is a problem

`zig-quic` follows the `tls` package's contract: `Config.supported_groups`
must contain only `x25519` (validated at `src/tls13/context.zig:593-597`,
GAP-0080). That's defensible in isolation — only X25519 ECDHE is implemented
— but it means the server **must rely on HRR** for any client whose
preferred first key_share is not X25519.

In 2026-04 that includes a non-trivial fraction of the production fleet:

- **quic-go** (Go ≥ 1.23 default): `x25519_kyber768_draft00` first, X25519
  second.
- **mvfst**: Tunable, but defaults vary by linked OpenSSL build; many
  deployments offer NIST P-256 first.
- **picoquic** with `--key-share secp256r1`.
- **Chrome / browsers** (post-Q1-2026 PQ rollout): hybrid groups before
  X25519.

Until X25519 is the dominant client default, HRR correctness is on the
critical path for production interop, not an edge case.

---

## What zig-quic has tried / verified

1. **Bisect against pre-perf-unblock commits.** `make interop-full` against
   commits `18d49c8`, `04fd9f5`, and `f7f4ec4` (post-perf-unblock) all
   reproduce the same `NoHandshakeKeys` failure for quic-go and mvfst. The
   regression is **older than the 2026-04-27 perf pass** in zig-quic. The
   `105 passed, 0 failed` claim previously recorded in
   `zig-quic/docs/PERF_GAP_ANALYSIS.md` was inaccurate; the failure was
   already present.
2. **Confirmed the HRR path triggers.** Adding a `logger.err` at the
   `sendHelloRetryRequest` call site fires for both quic-go and mvfst
   first ClientHellos but not for ngtcp2. ngtcp2 sends X25519 directly; HRR
   never fires; handshake completes.
3. **`processInitial` does call `sendServerHello` + `sendHandshakePackets`
   on every Initial that carries a CRYPTO frame** (see
   `zig-quic/src/quic/endpoint/incoming.zig:870-897`). So the ClientHello
   #2 path *would* re-fire `driveServerHandshakeFlight` if the message ever
   reached `afterHandshakeMessage`. The fact that it apparently doesn't is
   the smoking gun.
4. **No state inside zig-quic between commits has changed in this region.**
   The QUIC layer's `handleInitialCrypto` → `pushCrypto` → `processCrypto`
   chain is unmodified across the bisect range; the suspect surface is in
   `src/tls13/context.zig`.

---

## Hypotheses worth checking

- **Cookie / transcript mismatch.** RFC 8446 §4.4.1 mandates that after HRR
  the server replaces ClientHello #1 in the transcript with
  `message_hash(ClientHello1)`. `hello_retry_mod.applyHrrTranscript`
  performs this replacement (`src/tls13/context.zig:1596-1601`). Verify:
  - The hash is computed under the **negotiated** hash (locked at
    `transcripts.handshake.lockHash(self.hash_kind)` line 1678) and matches
    what the client computes for its own transcript when verifying the
    HRR's cookie binding.
  - The locked-hash decision happens before HRR is queued. If the client's
    second ClientHello picks a different cipher suite (and thus hash), the
    transcript locks the wrong digest.
- **State reset on HRR.** `src/tls13/context.zig:1080-1082`:

  ```zig
  if (self.hrr_sent) {
      self.state.reset(self.allocator);
  }
  ```

  Verify this resets *only* `state.client_hello` and not anything that
  would prevent `negotiateCipherAndKeys` from running again — e.g. should
  `secrets`, `flags`, `phase`, `peer_quic_transport_parameters` survive?
  In particular, `phase` does NOT roll back to `.initial`; the post-CH-1
  transition (`if (self.phase == .initial) { self.phase = .negotiating; }`,
  line 1113-1115) is a one-way trip. Confirm that's intentional.
- **`hrr_sent` not cleared after CH2.** Once `hrr_sent = true` the server
  is locked into the "second-pass" check
  (`if (self.hrr_sent) return HandshakeError.UnsupportedKeyShareGroup;` at
  line 1695). If the second ClientHello comes with the chosen group
  (X25519), this branch is never entered — but it's worth confirming
  `hrr_sent` is read-only after that point and not consulted in any other
  short-circuit path.
- **Cookie validation.** RFC 8446 §4.2.2 requires the server to validate
  that the second ClientHello's cookie matches the one issued in HRR. Find
  `selectPsk` / cookie-handling and confirm the validation accepts a
  well-formed second CH and *doesn't* return early.
- **`config.supported_groups` enforcement.** Strictly speaking, zig-quic
  passes `&[_]NamedGroup{.x25519}` so `init` succeeds, but if the runtime
  ever decides to add a fallback group, the `init` validator at line
  595-597 will trip. Document this contract and consider making it a
  warning rather than an error so users can extend `supported_groups` once
  another curve lands.

---

## Suggested test additions

Two boringssl-style conformance tests would catch this regression in the
TLS package alone, without needing the QUIC interop harness:

1. `tests/conformance/server/hrr_secp256r1.zig`: server with
   `supported_groups = .{ .x25519 }` receives a synthetic ClientHello with
   `key_share = secp256r1` → expect HRR queued → feed valid CH2 with
   X25519 → expect Handshake secrets installed and ServerHello +
   EncryptedExtensions emitted.
2. `tests/conformance/server/hrr_pq_hybrid.zig`: same shape but the first
   CH offers `x25519_kyber768_draft00` (or whatever PQ hybrid group code
   point quic-go uses). The synthetic ClientHello bytes can be lifted from
   the quic-go interop pcap if needed; the bytes aren't sensitive.

If those two tests fail today, you have a directly-reproducible fault that
runs in milliseconds and doesn't need docker/ns3.

---

## Files / line refs (TLS package)

- `src/tls13/context.zig:593-597` — init-time validation of
  `supported_groups`.
- `src/tls13/context.zig:1075-1116` — `client_hello` arm of
  `handleHandshakeMessage`. State reset on `hrr_sent`.
- `src/tls13/context.zig:1572-1610` — `sendHelloRetryRequest`:
  generates/queues HRR body, applies HRR transcript, sets `hrr_sent`.
- `src/tls13/context.zig:1669-1745` — `negotiateCipherAndKeys`. Cipher /
  signature / key-share negotiation. The `if (ch_view.key_share.group != .x25519)`
  branch is the HRR trigger.
- `src/tls13/context.zig:1933-1941` — `driveServerHandshakeFlight`. Called
  by `afterHandshakeMessage(.client_hello)` after every ClientHello (CH1
  *and* CH2).

---

## Files / line refs (zig-quic, calling side)

- `src/quic/endpoint/incoming.zig:870-897` — `processInitial` calls
  `sendServerHello` + `sendHandshakePackets` on every Initial that carries
  CRYPTO. The error is logged but caught; the connection survives, and
  the handshake is expected to complete on the next round-trip.
- `src/quic/endpoint/handshake_integration.zig:687-728` — `sendServerHello`
  polls Initial level; gets HRR bytes when triggered.
- `src/quic/endpoint/handshake_integration.zig:953-1020` —
  `sendHandshakePackets` returns `error.NoHandshakeKeys` when
  `conn.hs_tx_keys` is null. This is the surface the interop log shows
  failing.
- `src/quic/connection/methods_a.zig:382-461` — `pushCrypto` chooses
  encryption level based on installed keys; calls
  `tls_ctx.processCrypto(level, hs)`.

---

## Acceptance criteria for closure

- `zig-quic` `make interop-full` against quic-go and mvfst as clients
  passes the `handshake` testcase.
- TLS package conformance tests (per **Suggested test additions**) for
  HRR-on-secp256r1 and HRR-on-PQ-hybrid pass.
- No regression in existing X25519 conformance and interop tests.
