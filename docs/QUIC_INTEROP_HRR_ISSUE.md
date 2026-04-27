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

---

## 2026-04-27 follow-up — verification after parent fix + cookie/sentinel pass

After bumping zig-quic to tls `e1d6a5d` (covers `4d2d69e` parent fix +
`db073a3` cookie/sentinel follow-ups + `e1d6a5d` GAP-tracker update), the
interop matrix has shifted but is **not fully green**:

| Client  | Pre-bump signature                                | Post-bump signature                          | Result   |
|---------|---------------------------------------------------|----------------------------------------------|----------|
| ngtcp2  | clean handshake                                   | clean handshake                              | PASS     |
| mvfst  | `sendHandshakePackets failed: NoHandshakeKeys` + timeout | `accepted connection` then handshake timeout (no NoHandshakeKeys error) | **PARTIAL** |
| quic-go | `sendHandshakePackets failed: NoHandshakeKeys` + timeout | identical — still `NoHandshakeKeys` + timeout | FAIL     |

What this tells us about each remaining failure:

- **mvfst (improved, not green).** The `NoHandshakeKeys` log is gone,
  meaning either (a) HRR no longer fires for mvfst's first ClientHello, or
  (b) HRR fires and the post-HRR ServerHello + Handshake flight reaches
  the wire — but the handshake still doesn't complete from the server's
  point of view (`server: handshake timeout`). Plausible causes:
  - The new cookie wire format (SEC-087) is encoded correctly server-side
    but mvfst's TLS stack rejects the Handshake flight downstream
    (signature scheme mismatch? transport-params mismatch?).
  - Server emits Handshake-level CRYPTO but the QUIC layer's
    `pushCrypto` / `pollCrypto(.Handshake)` round trip drops it.
- **quic-go (unchanged failure shape).** Suggests the TLS-side fixes did
  not change the server's behaviour on quic-go's first ClientHello at all.
  Two possibilities:
  - quic-go's first key_share is already X25519 — then the
    `NoHandshakeKeys` we observed pre-fix was *not* HRR-driven and the
    TLS fix is irrelevant. The error has a different upstream cause.
  - quic-go's key_share parses to a group that the new
    `parseKeyShare` (`messages/client_hello_handlers.zig:217-281`)
    classifies as "no entry recorded" rather than "first non-X25519
    sentinel". Worth printing the parsed `key_share.raw_group_code` and
    `key_share.group` for the failing handshake to see exactly which
    branch fired.

### What zig-quic verified

```bash
# Control: passes pre and post bump
INTEROP_SKIP_EXTRAS=1 SKIP_BUILD=1 INTEROP_IMPLS=ngtcp2 \
  INTEROP_TESTCASES=handshake bash scripts/interop_full.sh full
# → both directions PASS

# mvfst: behavioural change, not yet green
INTEROP_SKIP_EXTRAS=1 SKIP_BUILD=1 INTEROP_IMPLS=mvfst \
  INTEROP_TESTCASES=handshake bash scripts/interop_full.sh full
# → zig-server <-> mvfst-client: NoHandshakeKeys gone, handshake timeout

# quic-go: unchanged
SKIP_BUILD=1 INTEROP_IMPLS=quic-go INTEROP_TESTCASES=handshake \
  bash scripts/interop_full.sh basic
# → zig-server <-> quic-go-client: NoHandshakeKeys + handshake timeout
```

### Suggested next steps in the TLS package

1. **Capture the actual ClientHello bytes** that quic-go and mvfst send.
   The simplest way is to add a one-shot `logger.err` dump in
   `parseKeyShare` (or its caller) that emits `key_share.raw_group_code`,
   `key_share.group`, and the offered `supported_groups` extension. Run
   the interop matrix once with that logging enabled. The output will
   distinguish between "client offered X25519" (TLS fix is unrelated) and
   "client offered group X, parser classified as Y".
2. **Add a stand-alone TLS-only repro** in
   `tests/conformance/server/`: feed the captured quic-go / mvfst
   ClientHello bytes to a Context with a real X25519-only config and
   assert one of (HRR queued, HRR queued+CH2-cookie-verifies+secrets
   installed, parse error). That isolates the bug to the TLS layer
   without needing docker / quic-go runtime.
3. **Verify cookie wire-format on the wire** for mvfst. SEC-087 fixed the
   inner-prefix encoding; if mvfst's ClientHello #2 cookie matches our
   server's HMAC over `(client_random, ch1_transcript_hash, selected_group)`
   the verifyCookie path should succeed. If we're returning
   `HandshakeError.InvalidCookie`, surface it via `logger.err` so the
   interop log distinguishes "cookie mismatch" from "handshake just timed
   out".

   **Status:** landed in `src/tls13/context.zig:1714-1771`. Each of the
   three failure branches now emits a tagged `logger.err`:

   - `[TLS-HRR] post-HRR ClientHello#2 still offers non-X25519 key_share
     (raw_group_code=0xNNNN, group=…)` — client ignored HRR and re-offered
     a wrong group on CH2 (post-HRR `UnsupportedKeyShareGroup`).
   - `[TLS-HRR] post-HRR cookie verify failed: server lost CH1 transcript
     hash before CH2 arrived` — internal state inconsistency
     (`ch1_transcript_hash == null` on the second pass).
   - `[TLS-HRR] post-HRR cookie verify failed: ClientHello#2 missing
     cookie extension (RFC 8446 §4.2.2)` — CH2 omitted the cookie.
   - `[TLS-HRR] post-HRR cookie verify failed: HMAC mismatch or stale
     cookie (cookie_len=N, ch1_hash_len=M, max_age_s=10)` — cookie was
     present but its HMAC didn't validate.

   Existing regression tests
   `tests/context_hrr_server_tests.zig` ("CH2 with a forged cookie is
   rejected", "CH2 without a cookie ext is rejected") continue to assert
   `HandshakeError.InvalidCookie` and now exercise the logged paths.

   What this gives the next interop run: when mvfst (or quic-go, if it
   ever takes the HRR path) hangs at the handshake-timeout stage, the
   server stderr will say *which* of the four post-HRR failure modes
   actually fired — instead of looking like a silent QUIC timeout.

Steps 1 (one-shot `parseKeyShare` dump) and 2 (stand-alone TLS-only repro
under `tests/conformance/server/`) are still open as recommended next
investigation steps and are deliberately not landed in this commit; they
require a captured ClientHello byte sequence from the failing interop run.

---

## 2026-04-27 verification — tls bump to `307b100` (zig-quic commit `c749107`)

After bumping the zig-quic `build.zig.zon` to tls `307b10031217164024c6bf652547c9df455f7a61`
and re-running the interop suite, **the new `[TLS-HRR]` post-HRR
diagnostics did NOT fire for either failing client**. That is a strong
signal in itself: it rules out *all four* of the post-HRR cookie-verify
failure modes for both mvfst and quic-go.

### Test results (zig-quic commit `c749107`, tls dep `307b100`)

```text
zig (server) <-> ngtcp2  (client) — handshake — PASS  (control)
ngtcp2  (server) <-> zig (client) — handshake — PASS  (control)
zig (server) <-> mvfst   (client) — handshake — FAIL: server: accepted connection -> handshake timeout
                                                       (no NoHandshakeKeys, no [TLS-HRR] line)
mvfst   (server) <-> zig (client) — handshake — PASS
zig (server) <-> quic-go (client) — handshake — FAIL: ERROR processInitial: sendHandshakePackets failed: NoHandshakeKeys
                                                       -> handshake timeout
                                                       (no [TLS-HRR] line)
quic-go (server) <-> zig (client) — handshake — PASS
```

Stripped to one observation per client:

| Client  | NoHandshakeKeys log  | `[TLS-HRR]` log | Diagnosis                                                                 |
|---------|----------------------|-----------------|---------------------------------------------------------------------------|
| ngtcp2  | no                   | no              | clean — X25519 first; HRR never fires; everything passes.                  |
| mvfst  | **no** (vs pre-fix)  | **no**          | HRR-emit path is fine. CH2 never reaches `negotiateCipherAndKeys`.        |
| quic-go | **yes** (unchanged)  | **no**          | HRR may not even fire on CH1. `NoHandshakeKeys` has a different upstream cause. |

### What this tells us

The cookie-verify code path is **fully bypassed** in the failing interop
runs. None of the four failure modes (non-X25519 CH2, lost
ch1_transcript_hash, missing cookie ext, HMAC mismatch) is the active
fault for either client. This means:

1. **mvfst** — CH2 never reaches the TLS Context's
   `handleHandshakeMessage(.client_hello)` path on the second pass.
   `[TLS-HRR]` would necessarily have fired on at least *one* of the
   four branches if CH2 had reached `negotiateCipherAndKeys`, even on
   the success path the lack of a log just means we returned without
   error — but the `server: handshake timeout` outcome means we never
   completed the handshake at all. The fault is between
   `pushCrypto(.Initial, …)` and `negotiateCipherAndKeys` — most likely
   in the QUIC layer's CRYPTO-frame reassembly or in the TLS layer's
   `parseHandshakeOne` / `handleHandshakeMessage` ClientHello gate.
2. **quic-go** — `NoHandshakeKeys` fires once, on what looks like CH1
   processing, *not* on a post-HRR retry. Combined with the absence of
   any `[TLS-HRR]` line, this strongly suggests **HRR is not firing at
   all** on quic-go's first ClientHello, but the server still fails to
   install Handshake-level keys. Two candidates:

   - quic-go's first ClientHello already carries an X25519 key_share, so
     `negotiateCipherAndKeys` proceeds past the HRR gate, but a
     downstream check (signature scheme negotiation? PSK selection?
     transport-params validation?) fails silently and the function
     returns without installing secrets.
   - quic-go's CH1 has *no* X25519 key_share but the new
     `parseKeyShare` (`messages/client_hello_handlers.zig:217-281`)
     classifies the offered group in a way that leaves
     `ch.key_share = null`, which then trips `ClientHelloInfo.parse`'s
     `MissingKeyShare` and `handleInitialCrypto` errors silently before
     ever reaching `afterHandshakeMessage` → `driveServerHandshakeFlight`.

Both candidates are testable by capturing the actual CH1 byte sequence
quic-go sends (Step 1 above). Neither is reachable through the cookie-
verify diagnostics that 307b100 added — those only catch *post-HRR*
faults, and quic-go's failure is plausibly *pre-HRR*.

### Suggested next step (revised)

Given the two new data points, the highest-leverage instrumentation is
upstream of the cookie verifier — at the boundary between QUIC CRYPTO
delivery and TLS message parsing. Concretely, one of:

- One-shot `logger.err` at the top of `parseKeyShare` printing the raw
  ClientHello bytes (or just the key_share extension bytes) for the
  first 2 ClientHellos seen after Context init. This isolates whether
  CH2 is even reaching the TLS layer for mvfst, and reveals the actual
  key_share group quic-go offers in CH1.
- One-shot `logger.err` at every early-return path in
  `negotiateCipherAndKeys` (NoCipherSuite, NoSignatureScheme,
  MissingKeyShare-via-`ClientHelloInfo.parse`) so a quic-go-style
  silent failure surfaces in the interop log instead of looking like a
  generic `NoHandshakeKeys`.
- Capture the failing CH1 bytes from a `tcpdump -i any port 443` run
  during the interop test, decode them with `openssl s_client -msg`
  or `boringssl bssl client`, and turn the bytes into a stand-alone
  `tests/conformance/server/{quic_go_ch1,mvfst_ch2}.zig` repro.

The cookie-verify logging in `307b100` remains valuable as a contract
check — it just doesn't apply to the failure modes the current interop
run hits.

---

## 2026-04-27 follow-up — upstream `[TLS-HRR]` diagnostics landed

The first two recommended instrumentation steps from the previous
section are now wired into `src/tls13/context.zig`. The third step
(captured `tcpdump` repro under `tests/conformance/server/`) remains
open and requires a real interop run.

### What landed

1. **CH1/CH2 parse-state snapshot** (`dispatchHandshake.client_hello`,
   `context.zig:1086-1209`).
   - Wraps `state.setClientHello` so any RFC 8446 §4.2.x parse failure
     emits a tagged line *before* `failAlert` re-raises:

     ```text
     [TLS-HRR] ClientHello parse failed at level=Initial: MissingKeyShare (body_len=NN, hrr_sent=false)
     ```

   - On parse success, dumps a one-line snapshot of the parsed CH so
     interop logs distinguish "client offered X25519" from "client
     offered group X classified as Y":

     ```text
     [TLS-HRR] ClientHello#1 parsed at level=Initial: key_share.group=secp256r1, raw_group_code=0x0017, key_len=65, cipher_suites=1, has_cookie=false
     ```

     The CH index is `1` for the first ClientHello and `2` for any
     post-HRR ClientHello (read from `self.hrr_sent`). The
     `raw_group_code` field is the original wire codepoint preserved by
     `parseKeyShare` (QUAL-369), so PQ-hybrid `0x6399` and any other
     unknown group surfaces verbatim.

2. **`negotiateCipherAndKeys` early-return diagnostics**
   (`context.zig:1812-1932`). Every silent early-return now carries a
   `[TLS-HRR] negotiate <variant> (<reason>)` line:

   - `NoCipherSuite (no_overlap)` — client suites and server suites do
     not intersect (after the `ClientHelloInfo.parse` TLS 1.3 prefilter).
   - `NoSignatureScheme (server_config_empty)` —
     `Config.supported_signature_schemes` is empty.
   - `NoSignatureScheme (peer_list_missing)` — ClientHello had no
     `signature_algorithms` extension.
   - `NoSignatureScheme (no_overlap)` — both sides have lists, no
     intersection.
   - `UnsupportedKeyShareGroup (x25519_short_key)` — client offered
     `group=x25519` but the key_exchange field is not 32 bytes
     (RFC 7748 §6.1).
   - `UnexpectedMessage` for the impossible-by-design "negotiate
     entered without a parsed ClientHello" case.

3. **Test sink in `quic_logger`** (`src/quic_logger.zig`). The library's
   logger is no-op by default in this repo; the embedding QUIC stack
   replaces `log()` for production. Tests now opt in via
   `setTestSink(...)` to capture emitted lines so the diagnostics can
   be regression-tested without rebuilding for a debug pass. Production
   behaviour is unchanged when the sink is null.

4. **Regression coverage** —
   `tests/security/quic_interop_hrr_diagnostics.zig` (9 tests). Each
   test installs the sink, drives a synthetic ClientHello through the
   server context, asserts the corresponding error variant, and asserts
   that the expected `[TLS-HRR]` line landed. The tests fail without
   the diagnostics and pass with them — proof that the wiring is
   correct on every branch.

### What zig-quic should see in the next interop run

When mvfst hangs at the handshake-timeout stage, the server stderr will
now show one of:

- `[TLS-HRR] ClientHello#1 parsed ...` followed by HRR emission, then
  silence — meaning CH2 *truly* never reaches the TLS layer (transport
  bug between `pushCrypto(.Initial)` and the TLS Context's
  `processCrypto`).
- `[TLS-HRR] ClientHello#1 parsed ...` followed by
  `[TLS-HRR] ClientHello#2 parsed ...` and then either a successful
  flight or one of the four post-HRR cookie-verify errors from
  `307b100`.

When quic-go fails with `NoHandshakeKeys`, the server stderr will now
show one of:

- `[TLS-HRR] ClientHello#1 parsed at level=Initial: key_share.group=x25519, raw_group_code=0x001d, key_len=32, ...` —
  X25519 already first; HRR never fires; the failure is downstream of
  the X25519 gate. The `[TLS-HRR] negotiate ...` line that follows
  pinpoints whether NoSignatureScheme, NoCipherSuite, or another
  early-return is the actual cause.
- `[TLS-HRR] ClientHello parse failed at level=Initial: MissingKeyShare ...` —
  the new `parseKeyShare` "no recorded entry" path was hit (CH1 had
  *zero* key_share entries the parser could record, including no
  unsupported sentinel).
- `[TLS-HRR] ClientHello#1 parsed ... raw_group_code=0xNNNN ...` for a
  non-X25519 first key_share, followed by HRR emission — same shape as
  the mvfst path.

### Open follow-ups

- **CH1 byte capture and stand-alone TLS repro.** Still requires a
  `tcpdump -i any port 443` snapshot from a failing interop run to
  decode quic-go's actual CH1 wire bytes. With the bytes in hand, a
  test under `tests/conformance/server/quic_go_ch1.zig` would feed
  them straight into `processCrypto(.Initial, ...)` and assert
  whichever branch the diagnostic identified — closing the
  reproduction loop without docker.
- **Re-run interop matrix against this commit.** The expected outcome
  is that the next failing run will name the actual fault in the
  server stderr, replacing the silent `NoHandshakeKeys` /
  `handshake timeout` shape with a tagged `[TLS-HRR]` line that points
  at one specific branch.
