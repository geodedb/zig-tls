# Quality Gap Analysis

> **Last updated:** 2026-03-24
> **Scope:** TLS 1.3/QUIC Implementation in Zig
> **Review phase:** Phase 8 -- Closure round: QUAL-113 (partial), QUAL-115, QUAL-120 closed

---

## Summary

| Severity | Open | Closed | By Design | Deferred | Total |
|----------|------|--------|-----------|----------|-------|
| Critical | 0    | 2      | 0         | 0        | 2     |
| High     | 2    | 10     | 0         | 2        | 14    |
| Medium   | 6    | 15     | 1         | 1        | 23    |
| Low      | 11   | 10     | 2         | 0        | 23    |
| **Total**| **19** | **37** | **3**   | **3**    | **62**|

### Top 5 Risks (by priority score, open items first)

1. **QUAL-113** (Partial) -- 14 residual `.?` unwraps in engine.zig; 3 fixed (ecdhe_secret x2, leaf_spki x1), 11 remaining. PriorityScore 60. [Issue #117](https://gitlab.com/devnw/zig/tls/-/work_items/117)
2. **QUAL-114** (Open) -- 22+ `allocator.dupe` without `errdefer` across 4 files. PriorityScore 36. Memory leaks on error paths. [Issue #119](https://gitlab.com/devnw/zig/tls/-/work_items/119)
3. **QUAL-069** (Deferred) -- `context.zig` at 3431 lines is 4.3x the 800-line guideline. Deferred: high regression risk. [Issue #65](https://gitlab.com/devnw/zig/tls/-/work_items/65)
4. **QUAL-116** (Open) -- 9 additional source files over 800 lines not previously tracked. PriorityScore 24.
5. **QUAL-117** (Open) -- 14 functions over 100 lines (parseCert 396 lines). PriorityScore 20.

---

## Stack-Ranked Findings

| Rank | ID | Severity | PriorityScore | Category | Finding | Component | Issue | Status |
|------|----|----------|---------------|----------|---------|-----------|-------|--------|
| 1 | QUAL-087 | Critical | 80 | architecture | engine.zig null-safety gap in certificate verification | `src/tls13/engine.zig` | [#80](https://gitlab.com/devnw/zig/tls/-/work_items/80) | Closed |
| 2 | QUAL-088 | Critical | 80 | perf | x25519KeypairAndShared duplicated with security divergence (CWE-226) | `engine.zig:1723`, `messages.zig:191` | [#82](https://gitlab.com/devnw/zig/tls/-/work_items/82) | Closed |
| 3 | QUAL-094 | High | 75 | maintainability | onCryptoRecv 516 lines / 14 nesting levels | `src/tls13/engine.zig:511-1026` | -- | Closed |
| 4 | QUAL-113 | High | 60 | architecture | 14 residual `.?` unwraps in engine.zig (QUAL-087 incomplete); 3 fixed (ecdhe_secret x2, leaf_spki x1), 11 remaining | `src/tls13/engine.zig` | [#117](https://gitlab.com/devnw/zig/tls/-/work_items/117) | Partial |
| 5 | QUAL-069 | High | 60 | maintainability | context.zig 3431 lines (4.3x limit) | `src/tls13/context.zig` | [#65](https://gitlab.com/devnw/zig/tls/-/work_items/65) | Deferred |
| 6 | QUAL-095 | High | 48 | maintainability | driveServerHandshakeFlight 243 lines combining 6 concerns | `src/tls13/context.zig:1996-2237` | -- | Closed |
| 7 | QUAL-096 | High | 48 | maintainability | ClientHello building duplicated 3 times (~500 lines) | `engine.zig`, `context.zig` | -- | Closed |
| 8 | QUAL-070 | High | 40 | maintainability | Near-duplicate ClientHelloInfo parse+deinit | `context.zig`, `handshake_state.zig` | -- | Closed |
| 9 | QUAL-114 | High | 36 | architecture | 22+ `allocator.dupe` without `errdefer` -- memory leaks on error paths | `engine.zig`, `context.zig`, `handshake_state.zig`, `quic_transport_params.zig` | [#119](https://gitlab.com/devnw/zig/tls/-/work_items/119) | Open |
| 10 | QUAL-091 | High | 36 | maintainability | engine.zig uses legacy inline key schedule patterns (6+ copies) | `src/tls13/engine.zig` | [#90](https://gitlab.com/devnw/zig/tls/-/work_items/90) | Deferred |
| 11 | QUAL-097 | High | 30 | architecture | parseHandshakeOne catch null wedges on invalid message type | `src/tls13/engine.zig:529` | -- | Closed |
| 12 | QUAL-071 | High | 30 | architecture | 0-RTT early_secret uses wrong transcript hash | `src/tls13/context.zig:2191` | -- | Closed |
| 13 | QUAL-115 | High | 30 | api-contract | `setTransportParameters` now returns `!void` instead of swallowing OOM | `src/tls13/context.zig:806` | [#122](https://gitlab.com/devnw/zig/tls/-/work_items/122) | Closed |
| 14 | QUAL-073 | Medium | 27 | maintainability | Near-duplicate parseRealServerHello / handleServerHello | `engine.zig:1851`, `context.zig:2567` | -- | Deferred |
| 15 | QUAL-116 | Medium | 24 | maintainability | 9 additional source files over 800 lines not tracked | `x509.zig`, `aead.zig`, `server_hello.zig`, `quic_transport_params.zig`, `asn1.zig`, `parallel.zig`, `key_schedule.zig`, `client_hello.zig`, `sig.zig` | -- | Open |
| 16 | QUAL-072 | High | 24 | api-contract | Callback errors logged but not propagated | `src/tls13/context.zig` | -- | Closed |
| 17 | QUAL-098 | Medium | 24 | api-contract | queueServerHandshakeFlight returns void -- errors not propagated | `src/tls13/engine.zig:1728` | -- | Closed |
| 18 | QUAL-099 | Medium | 24 | tests | No HRR test coverage in Context | `src/tls13/context.zig` | -- | Closed |
| 19 | QUAL-100 | Medium | 24 | docs | Config field constraints undocumented | `src/tls13/config.zig:68-342` | -- | Closed |
| 20 | QUAL-074 | Medium | 24 | architecture | new_session_ticket silently dropped | `src/tls13/context.zig:1375` | -- | Closed |
| 21 | QUAL-090 | High | 24 | api-contract | NewSessionTicket processing has incomplete error propagation | `src/tls13/engine.zig:836-877` | [#88](https://gitlab.com/devnw/zig/tls/-/work_items/88) | Closed |
| 22 | QUAL-117 | Medium | 20 | maintainability | 14 functions over 100 lines (parseCert 396 lines) | `x509.zig`, `engine.zig`, `context.zig`, `server_hello.zig`, `client_hello.zig` | -- | Open |
| 23 | QUAL-118 | Medium | 20 | maintainability | SecretSlot struct duplicated between context.zig and secrets.zig | `src/tls13/context.zig:278`, `src/tls13/secrets.zig:67` | -- | Open |
| 24 | QUAL-089 | High | 20 | api-contract | setTransportParameters lacks OOM error handling | `handshake_state.zig:220`, `engine.zig:1822` | [#85](https://gitlab.com/devnw/zig/tls/-/work_items/85) | Closed |
| 25 | QUAL-119 | Medium | 18 | readability | Deep nesting in client_hello.zig (10 levels) and x509.zig (9 levels) | `src/tls13/messages/client_hello.zig`, `src/x509.zig` | -- | Open |
| 26 | QUAL-075 | Medium | 18 | maintainability | Two distinct CipherSuite enums | `record/aead.zig:76`, `messages/core_types.zig:258` | -- | Closed (By Design) |
| 27 | QUAL-101 | Medium | 18 | docs | No Engine-to-Context migration guide (complements QUAL-077) | `docs/` | -- | Closed |
| 28 | QUAL-076 | Medium | 16 | maintainability | Duplicated SignatureScheme-to-SigAlg with unsafe else | `context.zig:2272`, `context.zig:2692` | -- | Closed |
| 29 | QUAL-077 | Medium | 16 | docs | No Engine-to-Context migration guide | `docs/` | -- | Closed |
| 30 | QUAL-120 | Medium | 16 | architecture | quic_transport_params.zig `decode()` missing errdefer | `src/quic_transport_params.zig:559` | -- | Closed |
| 31 | QUAL-121 | Medium | 16 | architecture | Engine cert handling now propagates OOM via `try` instead of converting to cert-invalid | `src/tls13/engine.zig:865-870` | -- | Closed |
| 32 | QUAL-122 | Medium | 16 | architecture | Engine dupe calls at 9 sites lack errdefer | `src/tls13/engine.zig` | [#125](https://gitlab.com/devnw/zig/tls/-/work_items/125) | Open |
| 33 | QUAL-102 | Medium | 16 | architecture | 6x allocator.dupe catch null silently swallow OOM | `src/tls13/engine.zig:674,682,1643,1923,1941` | -- | Closed |
| 34 | QUAL-103 | Medium | 16 | api-contract | maybeAutoProgress swallows queueFinished error | `src/tls13/engine.zig:1684` | -- | Closed |
| 35 | QUAL-104 | Low | 15 | readability | Magic hex constants for extension types instead of ExtensionType enum | `engine.zig`, `context.zig` | -- | Open |
| 36 | QUAL-105 | Low | 15 | docs | lib.zig Quick Start example has wrong Context.init signature | `src/lib.zig` | -- | Closed |
| 37 | QUAL-092 | Medium | 12 | cleanup | byteorder.zig duplicated verbatim across two module paths | `src/byteorder.zig`, `src/byteorder/byteorder.zig` | [#92](https://gitlab.com/devnw/zig/tls/-/work_items/92) | Closed |
| 38 | QUAL-078 | Medium | 12 | perf | Duplicated x25519KeypairAndShared with behavioral divergence | `messages.zig:191`, `engine.zig:1723` | -- | Closed |
| 39 | QUAL-079 | Medium | 12 | docs | Corrupted Callbacks doc comment | `context.zig:234-249` | -- | Closed |
| 40 | QUAL-093 | Medium | 12 | ci-cd | CI pipeline lacks build caching (Zig reinstalled each job) | `.gitlab-ci.yml` | [#94](https://gitlab.com/devnw/zig/tls/-/work_items/94) | Open |
| 41 | QUAL-080 | Medium | 12 | cleanup | 32x @constCast for freeing const slices | `context.zig`, `handshake_state.zig`, `quic_transport_params.zig` | [#75](https://gitlab.com/devnw/zig/tls/-/work_items/75) | Closed |
| 42 | QUAL-123 | Low | 10 | maintainability | build.zig at 1112 lines exceeds 800-line guideline | `build.zig` | -- | Open |
| 43 | QUAL-106 | Low | 9 | maintainability | Constant-time comparison code duplicated 3 times with subtle variation | `engine.zig`, `context.zig` | -- | Open |
| 44 | QUAL-107 | Low | 9 | api-contract | Inconsistent error types -- CryptoBufferOverflow vs UnexpectedMessage for same condition | `engine.zig`, `context.zig` | -- | Open |
| 45 | QUAL-081 | Low | 8 | maintainability | cipherSuiteHash exact duplicate | `context.zig:128`, `engine.zig:108` | -- | Closed |
| 46 | QUAL-124 | Low | 8 | maintainability | readU16 helper duplicated between sct.zig and messages/helpers.zig | `src/sct.zig:31`, `src/tls13/messages/helpers.zig:40` | -- | Open |
| 47 | QUAL-125 | Low | 8 | maintainability | HashDigestCache struct duplicated between context.zig and transcript.zig | `src/tls13/context.zig:419`, `src/tls13/transcript.zig:398` | -- | Open |
| 48 | QUAL-082 | Low | 6 | cleanup | traceHandshake/traceSecrets exact duplicate infrastructure | `context.zig`, `engine.zig`, `messages.zig`, `transcript.zig`, `key_derivation.zig` | -- | Closed (By Design) |
| 49 | QUAL-083 | Low | 6 | cleanup | encodeMinimal*/parseMinimal* exact duplicates | `messages.zig`, `engine.zig` | -- | Closed |
| 50 | QUAL-084 | Low | 6 | readability | 13x inline u16 big-endian read instead of readU16 helper | `context.zig`, `handshake_state.zig`, `record/plaintext.zig` | -- | Closed |
| 51 | QUAL-085 | Low | 6 | api-contract | pollCrypto returns Unimplemented for empty buffer | `context.zig:1064` | -- | Closed |
| 52 | QUAL-108 | Low | 6 | cleanup | 14 unused imports across 7 files | `varint.zig`, `tls13_full.zig`, `sig.zig`, `tls13.zig`, `context.zig`, `engine.zig`, `types.zig` | -- | Closed |
| 53 | QUAL-109 | Low | 6 | architecture | TODO in context.zig:1207 -- QUAL-074 callback not wired (status inconsistent) | `src/tls13/context.zig:1207` | -- | Closed |
| 54 | QUAL-110 | Low | 6 | api-contract | notifyMetadata callback error logged but not propagated | `src/tls13/context.zig:2660` | -- | Closed (by-design) |
| 55 | QUAL-126 | Low | 4 | architecture | quic_transport_params.zig only 2 of 4 dupe sites have errdefer | `src/quic_transport_params.zig:645,649,653` | -- | Open |
| 56 | QUAL-127 | Low | 4 | maintainability | handshake_state.zig 13 dupe sites -- only 1 has errdefer | `src/tls13/handshake_state.zig` | -- | Open |
| 57 | QUAL-128 | Low | 4 | maintainability | context.zig 11 dupe sites without errdefer | `src/tls13/context.zig` | -- | Open |
| 58 | QUAL-129 | Low | 4 | readability | Engine zero errdefer usage across all allocator.dupe calls | `src/tls13/engine.zig` | -- | Open |
| 59 | QUAL-130 | Low | 4 | cleanup | Stale line counts in QUAL-069 (3581 vs actual 3431) | `docs/QUALITY_GAP_ANALYSIS.md` | -- | Open |
| 60 | QUAL-086 | Low | 4 | cleanup | deriveFinishedVerifyData in messages/finished.zig is unused dead code | `src/tls13/messages/finished.zig:155` | -- | Closed |
| 61 | QUAL-111 | Low | 4 | docs | handleKeyUpdateMessage doc comment misplaced onto handleCertificate | `src/tls13/context.zig` | -- | Closed |
| 62 | QUAL-112 | Low | 4 | readability | Engine.init is a single 262-character line | `src/tls13/engine.zig` | -- | Closed |

---

## Detailed Findings

### QUAL-069 -- context.zig exceeds maintainability size limit (3581 lines)

- **ID:** QUAL-069
- **Severity:** High
- **PriorityScore:** 60 (Impact 3 x Likelihood 5 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Deferred (2026-03-24) -- High regression risk for a file-splitting refactor on a
  heavily interconnected state machine. Zig's module system does not penalize large files the
  way some languages do (no class-per-file convention). The file is well-structured internally
  with clear section comments. Deferring until Engine deprecation reduces the module count and
  makes splitting context.zig safer.
- **Issue:** [#65](https://gitlab.com/devnw/zig/tls/-/work_items/65)

**File locations:**
- `src/tls13/context.zig` -- 3581 lines

**Description:**
`context.zig` is 4.5x the 800-line guideline ceiling. It contains the `Context` struct, `Callbacks`, `ClientHelloView`, `ClientHelloInfo`, handshake state machine, key derivation orchestration, 0-RTT logic, mTLS flows, QUIC transport parameter handling, certificate verification, and CertificateVerify signing -- all in a single file. This makes code review slow, merge conflicts frequent, and bug isolation difficult.

**Evidence:**
```
$ wc -l src/tls13/context.zig
3581
```

For comparison, the next largest file is `engine.zig` at 2051 lines (also over-limit).

**Recommendation:**
Extract cohesive subsystems into separate modules:
- `src/tls13/callbacks.zig` -- Callbacks struct and HandshakeMetadata
- `src/tls13/client_hello_view.zig` -- ClientHelloView, ClientHelloInfo, parsing
- `src/tls13/server_handshake.zig` -- driveServerHandshakeFlight, buildServerHello, sendEncryptedExtensions
- `src/tls13/client_handshake.zig` -- handleServerHello, sendClientFinished, sendClientHello
- `src/tls13/certificate_verify.zig` -- handleCertificateVerify, handleClientCertificateVerify, signing

**Acceptance criteria:** No single source file exceeds 800 lines. All existing tests continue to pass.

**Verification:** `wc -l src/tls13/*.zig | sort -rn | head -5` shows all files under 800 lines. `zig build test` passes.

**Effort:** L (strategic refactor)

**Deferred reason:** The context.zig file is a tightly coupled TLS 1.3 handshake state machine where
functions share access to `self` fields extensively. Splitting it mechanically would require passing
dozens of fields as parameters or creating intermediate structs, increasing complexity rather than
reducing it. In Zig, large files are idiomatic when the contents are cohesive. This refactor is best
done during Engine deprecation when the overall module count decreases.

---

### QUAL-070 -- Near-duplicate ClientHelloInfo struct and parse/deinit logic

- **ID:** QUAL-070
- **Severity:** High
- **PriorityScore:** 40 (Impact 4 x Likelihood 2.5 x 4, rounded)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Consolidated `ClientHelloInfo` into `handshake_state.zig` as the single source of truth. `context.zig` now imports `ClientHelloInfo` from `handshake_state` module.

**File locations:**
- `src/tls13/context.zig` -- `ClientHelloInfo` struct + `parseClientHelloInfo` + `deinit`
- `src/tls13/handshake_state.zig` -- Near-identical `ClientHelloInfo` struct + `setClientHello` + `deinit`

**Description:**
Two near-identical `ClientHelloInfo` structs exist with their own parsing and deallocation logic. Both extract `supported_groups`, `signature_algorithms`, `pre_shared_key`, and `alpn_protocols` from the same ClientHello wire format. Each has its own `@constCast`-heavy `deinit`. A bug fix applied to one may not be applied to the other.

**Evidence:**
`context.zig` contains `ClientHelloView` (line ~305) and also re-parses in `handleHandshakeMessage` via `self.state.setClientHello()`, which delegates to `handshake_state.zig`. The `@constCast`-heavy deinit in `handshake_state.zig` (16 instances) mirrors the one in `context.zig` (16 instances).

**Recommendation:**
Consolidate into a single `ClientHelloInfo` type in `handshake_state.zig` (or a new `client_hello_info.zig`). Both `context.zig` and `handshake_state.zig` should reference the same struct, parse function, and deinit.

**Acceptance criteria:** A single `ClientHelloInfo` type exists with one parse function and one `deinit`. No duplicate struct definitions.

**Verification:** `grep -rn "struct ClientHelloInfo" src/` returns exactly one result. All tests pass.

**Effort:** M

---

### QUAL-071 -- 0-RTT early_secret derived AFTER ServerHello added to transcript (wrong transcript hash)

- **ID:** QUAL-071
- **Severity:** High
- **PriorityScore:** 30 (Impact 5 x Likelihood 1.5 x 4, rounded)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Snapshotted transcript hash of ClientHello BEFORE appending ServerHello to transcript in context.zig, using `ch_only_hash` for 0-RTT early_secret derivation.

**File locations:**
- `src/tls13/context.zig:2173` -- `appendOutbound(.Initial, sh_msg, true)` adds ServerHello to transcript
- `src/tls13/context.zig:2191` -- `self.transcripts.handshake.finalize(self.hash_kind)` used as "ClientHello hash"

**Description:**
RFC 8446 Section 7.1 specifies that the 0-RTT `client_early_traffic_secret` is derived using:

```
client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", ClientHello)
```

The transcript hash must cover only the ClientHello message. On the server side, `driveServerHandshakeFlight` calls `appendOutbound(.Initial, sh_msg, true)` at line 2173 which adds the ServerHello to the running transcript. The code then calls `self.transcripts.handshake.finalize(self.hash_kind)` at line 2191 to derive the "ClientHello hash", but this hash now incorrectly includes the ServerHello.

The comment at line 2190 says "Use transcript hash of ClientHello (before ServerHello)" -- but the ServerHello was already appended at line 2173. The `finalize()` call returns a snapshot that includes both ClientHello and ServerHello.

Note: The client-side code at line 2525-2528 correctly uses a separate `Transcript.init()` to compute the truncated ClientHello hash, so this bug is server-side only.

**Evidence:**
```zig
// Line 2173: ServerHello is added to transcript here
try self.appendOutbound(.Initial, sh_msg, true);

// Line 2175: This hash already includes ServerHello
const transcript_after_sh = self.transcripts.handshake.finalize(self.hash_kind);

// ...

// Line 2190-2191: Comment says "before ServerHello" but it IS after
const ch_hash = self.transcripts.handshake.finalize(self.hash_kind);
const early_traffic_secret = key_derivation_mod.deriveEarlyTraffic(
    self.hash_kind, &early_secret, ch_hash.slice(),
);
```

The `appendOutbound` function (line 1534-1539) updates the transcript when `update_transcript` is `true`:
```zig
fn appendOutbound(self: *Context, level: EncryptionLevel, msg: []const u8, update_transcript: bool) !void {
    var stream = self.streams.buffer(level);
    try stream.outbound.appendSlice(self.allocator, msg);
    if (update_transcript) {
        self.transcripts.handshake.update(msg);
    }
}
```

**Recommendation:**
Snapshot `self.transcripts.client_hello_hash` (which is already stored at line 2563) or take a transcript snapshot before appending ServerHello. Use that snapshot for the early traffic secret derivation. Example fix:

```zig
// Save ClientHello-only transcript hash BEFORE appending ServerHello
const ch_only_hash = self.transcripts.handshake.finalize(self.hash_kind);

try self.appendOutbound(.Initial, sh_msg, true); // adds ServerHello

// Use ch_only_hash (not current transcript) for 0-RTT
if (accept_early) {
    const early_traffic_secret = key_derivation_mod.deriveEarlyTraffic(
        self.hash_kind, &early_secret, ch_only_hash.slice(),
    );
    ...
}
```

**Acceptance criteria:** 0-RTT early traffic secret on the server side is derived using a transcript hash that contains only the ClientHello (matching RFC 8446 Section 7.1). The client and server derive the same `client_early_traffic_secret` for a given PSK and ClientHello.

**Verification:** Add a test that compares the server-derived `client_early_traffic_secret` against a known RFC test vector or against the client-derived value. Run `zig build test`.

**Effort:** S

---

### QUAL-072 -- Callback errors logged but not propagated (contradicts API docs)

- **ID:** QUAL-072
- **Severity:** High
- **PriorityScore:** 24 (Impact 4 x Likelihood 1.5 x 4, rounded)
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Changed `catch` swallow patterns to `try` for callback error propagation. Callbacks now propagate errors to callers instead of logging and swallowing.

**File locations:**
- `src/tls13/context.zig:1183-1187` -- `on_peer_finished` callback error swallowed
- `src/tls13/context.zig:1240-1244` -- `on_handshake_complete` callback error swallowed
- `src/tls13/context.zig:2743-2747` -- `on_handshake_metadata` callback error swallowed

**Description:**
The `Callbacks` struct (line 161) declares callback signatures as `anyerror!void`, implying that errors will be propagated to the caller. However, all three lifecycle callbacks catch errors and only log them via `logger.debugPrint`, effectively swallowing them. A QUIC transport layer that returns an error from `on_secret_available` or `on_handshake_complete` expects the handshake to abort, but it will silently continue.

**Evidence:**
```zig
// Line 1182-1187
if (self.callbacks.on_peer_finished) |cb| {
    // CWE-391: Log callback errors instead of silently ignoring them.
    // Callback errors shouldn't fail the handshake, but should be visible for debugging.
    cb(self) catch |err| {
        logger.debugPrint("[TLS] on_peer_finished callback error: {}\n", .{err});
    };
}
```

The same pattern repeats for `on_handshake_complete` (line 1242) and `on_handshake_metadata` (line 2745). The CWE-391 comments acknowledge the issue but the "fix" is incomplete -- logging is better than silent swallowing, but the error is still not propagated.

**Recommendation:**
Either:
1. Propagate callback errors with `try cb(self)` and let the caller handle them, OR
2. Change the callback signature to `fn(...) void` (no error) and document that callbacks must not fail, OR
3. Add an explicit `CallbackPolicy` enum (`.propagate` vs `.log_only`) so the caller can choose.

Option 1 is the simplest and most consistent with the declared `anyerror!void` signature.

**Acceptance criteria:** When a callback returns an error, the handshake fails with that error (or the callback signature is changed to `void` with updated documentation).

**Verification:** Write a test that installs a callback returning `error.TestExpectedError` and verify the handshake propagates it. `zig build test` passes.

**Effort:** S

---

### QUAL-073 -- Near-duplicate parseRealServerHello (engine.zig) vs handleServerHello (context.zig)

- **ID:** QUAL-073
- **Severity:** Medium
- **PriorityScore:** 27 (Impact 3 x Likelihood 2.25 x 4, rounded)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Deferred -- Different return types (`?[32]u8` vs `!void`) prevent direct consolidation without a larger refactor of both Engine and Context error handling patterns.

**File locations:**
- `src/tls13/engine.zig:1851-1898` -- `parseRealServerHello` (48 lines)
- `src/tls13/context.zig:2567-2663` -- `handleServerHello` (97 lines, parsing portion ~60 lines)

**Description:**
Both functions parse a ServerHello body to extract the cipher suite, `supported_versions` extension, `key_share` extension, and `pre_shared_key` extension. They diverge in error handling: `engine.zig` returns `null` on parse failure while `context.zig` returns typed `HandshakeError` variants. They also diverge in what they extract: `context.zig` additionally handles PSK selection and downgrade sentinel checks.

A bug fix to extension parsing in one location may not be applied to the other.

**Evidence:**
```
engine.zig:1851:  fn parseRealServerHello(body: []const u8) ?[32]u8 {
context.zig:2567: fn handleServerHello(self: *Context, body: []const u8) !void {
```

Both contain identical extension-scanning loops: read `etype` as u16, read `elen` as u16, check for `supported_versions` (0x002b) and `key_share` (0x0033).

**Recommendation:**
Extract a shared `ServerHelloFields` struct and a pure `parseServerHelloExtensions(body) -> ServerHelloFields` function. Both `engine.zig` and `context.zig` call the shared parser and apply their own error-handling policy on top.

**Acceptance criteria:** A single ServerHello extension parser exists. Both Engine and Context delegate to it.

**Verification:** `grep -rn "parseRealServerHello\|parseServerHelloExtensions" src/` shows only one parser definition. All tests pass.

**Effort:** M

---

### QUAL-074 -- new_session_ticket silently dropped in handleHandshakeMessage

- **ID:** QUAL-074
- **Severity:** Medium
- **PriorityScore:** 24 (Impact 3 x Likelihood 2 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Added `.new_session_ticket` branch to `handleHandshakeMessage` switch statement. Now explicitly handled in the switch, logs receipt for debugging.

**File locations:**
- `src/tls13/context.zig:1375-1377` -- `else` branch in `handleHandshakeMessage`

**Description:**
`handleHandshakeMessage` (line 1269) has explicit branches for `.client_hello`, `.server_hello`, `.certificate_request`, `.finished`, `.key_update`, `.encrypted_extensions`, `.certificate`, and `.certificate_verify`. The `new_session_ticket` type (value 4, defined in `messages.zig:30`) falls through to the `else` arm at line 1375-1377 which does nothing:

```zig
else => {
    // Other messages processed implicitly via transcript updates
},
```

By contrast, `engine.zig:837` does parse and process `new_session_ticket` for the client role. The `Context` API silently drops post-handshake NewSessionTicket messages, preventing session resumption and 0-RTT for QUIC connections using the Context path.

**Recommendation:**
Add a `.new_session_ticket` branch to `handleHandshakeMessage` that invokes the `on_new_session_ticket` callback (or stores the ticket for later retrieval). The `Callbacks` struct already documents this field in `lib.zig:430`.

**Acceptance criteria:** NewSessionTicket messages received via Context are surfaced to the application (via callback or accessor).

**Verification:** Send a NewSessionTicket to a Context-based client and verify the callback fires (or the ticket is retrievable). `zig build test` passes.

**Effort:** M

---

### QUAL-075 -- Two distinct CipherSuite enums (aead.zig vs core_types.zig)

- **ID:** QUAL-075
- **Severity:** Medium
- **PriorityScore:** 18 (Impact 3 x Likelihood 1.5 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (By Design, 2026-03-24) -- The two CipherSuite enums serve different architectural layers: `aead.zig` operates at the record layer (no wire format needed) while `core_types.zig` operates at the handshake layer (wire values required). Unification would leak wire-format concerns into the record layer. Documented as intentional.

**File locations:**
- `src/record/aead.zig:76-80` -- `CipherSuite` as plain `enum` (3 variants, no backing integer)
- `src/tls13/messages/core_types.zig:258-264` -- `CipherSuite` as `enum(u16)` (5 variants with wire values)

**Description:**
Two CipherSuite enums exist with different shapes:

`record/aead.zig`:
```zig
pub const CipherSuite = enum {
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
};
```

`messages/core_types.zig`:
```zig
pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,
};
```

The `aead.zig` version lacks the CCM variants and has no wire-format backing integer. The `core_types.zig` version is the canonical TLS 1.3 definition. Code that receives one type cannot pass it to a function expecting the other without manual conversion.

**Recommendation:**
Remove the `aead.zig` `CipherSuite` enum and have `aead.zig` import from `core_types.zig`. Add a helper to map unsupported CCM suites to an error at the AEAD layer.

**Acceptance criteria:** A single `CipherSuite` enum exists in the codebase. AEAD functions accept the canonical type.

**Verification:** `grep -rn "pub const CipherSuite = enum" src/` returns exactly one result. `zig build test` passes.

**Effort:** S

---

### QUAL-076 -- Duplicated SignatureScheme-to-SigAlg mapping with unsafe else fallback

- **ID:** QUAL-076
- **Severity:** Medium
- **PriorityScore:** 16 (Impact 4 x Likelihood 1 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Replaced inline switch blocks with `sig.fromTls13SignatureScheme()` calls in both server (line ~3161) and client (line ~3275) CertificateVerify paths. No more `else => .ed25519` fallback.

**File locations:**
- `src/tls13/context.zig:2272-2278` -- Server CertificateVerify signing
- `src/tls13/context.zig:2692-2698` -- Client CertificateVerify signing (mTLS)

**Description:**
The identical switch block appears twice:

```zig
const sig_alg: sig.SigAlg = switch (sig_scheme) {
    .ecdsa_secp256r1_sha256 => .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384 => .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha256 => .rsa_pss_sha256,
    .ed25519 => .ed25519,
    else => .ed25519, // Default fallback
};
```

The `else => .ed25519` silently converts any unrecognized scheme to Ed25519, which will produce an invalid signature. A `sig.fromTls13SignatureScheme()` helper already exists in `sig.zig:162` that returns an error for unsupported schemes -- it should be used instead.

**Recommendation:**
Replace both inline switches with:
```zig
const sig_alg = try sig.fromTls13SignatureScheme(sig_scheme);
```

This surfaces unsupported schemes as errors rather than silently using Ed25519.

**Acceptance criteria:** No inline SignatureScheme-to-SigAlg switch blocks exist. The `fromTls13SignatureScheme` helper is used for all conversions. No `else => .ed25519` fallback.

**Verification:** `grep -rn "else => .ed25519" src/` returns zero results. `zig build test` passes.

**Effort:** S

---

### QUAL-077 -- No Engine-to-Context migration guide

- **ID:** QUAL-077
- **Severity:** Medium
- **PriorityScore:** 16 (Impact 2 x Likelihood 2 x 4)
- **Category:** `docs`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**
- `docs/` -- no migration guide present
- `src/tls13/engine.zig` -- legacy Engine API (2051 lines)
- `src/tls13/context.zig` -- new Context API (3581 lines)

**Description:**
The codebase contains two parallel TLS 1.3 implementations: `Engine` (the original, simpler API) and `Context` (the full-featured API with QUIC integration, mTLS, 0-RTT, callbacks). There is no documentation explaining when to use which, how to migrate from Engine to Context, or whether Engine is deprecated.

**Recommendation:**
Create `docs/ENGINE_TO_CONTEXT_MIGRATION.md` covering:
- Feature comparison table (Engine vs Context)
- Deprecation status of Engine
- Step-by-step migration for common use cases
- API mapping (Engine methods to Context equivalents)

**Acceptance criteria:** A migration guide exists. It is linked from `README.md` or `docs/API.md`.

**Verification:** File exists at `docs/ENGINE_TO_CONTEXT_MIGRATION.md` with non-trivial content.

**Effort:** S

---

### QUAL-078 -- Duplicated x25519KeypairAndShared with behavioral divergence (sk not zeroized in engine.zig)

- **ID:** QUAL-078
- **Severity:** Medium
- **PriorityScore:** 12 (Impact 3 x Likelihood 1 x 4)
- **Category:** `perf`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Subsumed by QUAL-088 fix. Engine.zig duplicate deleted; single implementation in messages.zig with `defer secureZero` on all paths.

**File locations:**
- `src/tls13/messages.zig:191-210` -- Uses `recoverPublicKey`, zeroizes `sk` on scalarmult failure
- `src/tls13/engine.zig:1723-1736` -- DELETED (was insecure version)

**Description:**
Two copies of `x25519KeypairAndShared` exist with behavioral differences:

`messages.zig` (secure version):
```zig
const pk = std.crypto.dh.X25519.recoverPublicKey(sk) catch unreachable;
// ...on error:
std.crypto.secureZero(u8, &sk);  // zeroizes private key
return .{ .priv_key = [_]u8{0} ** 32, .pub_key = pk, .shared = null };
```

`engine.zig` (insecure version):
```zig
std.crypto.dh.X25519.scalarmultBase(&pk, sk);
// ...on error:
shared = null;  // sk is NOT zeroized, private key may leak
```

The `engine.zig` version uses the older `scalarmultBase` API and does not clear the private key on error, creating a potential key-leakage window (CWE-226).

**Recommendation:**
Delete the `engine.zig` copy. Have `engine.zig` import from `messages.zig` (or a shared `crypto_utils.zig`).

**Acceptance criteria:** A single `x25519KeypairAndShared` function exists. Private keys are always zeroized on error.

**Verification:** `grep -rn "fn x25519KeypairAndShared" src/` returns exactly one result. `zig build test` passes.

**Effort:** S

---

### QUAL-079 -- Corrupted Callbacks doc comment (on_ticket_lookup / fetch_certificate_chain)

- **ID:** QUAL-079
- **Severity:** Medium
- **PriorityScore:** 12 (Impact 2 x Likelihood 1.5 x 4)
- **Category:** `docs`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Separated corrupted doc comments for `on_ticket_lookup` and `fetch_certificate_chain` in context.zig Callbacks struct.

**File locations:**
- `src/tls13/context.zig:234-249`

**Description:**
The doc comment for `fetch_certificate_chain` at line 234 describes that callback ("Called to fetch certificate chain for local authentication"), but at line 244 it abruptly transitions into the doc comment for `on_ticket_lookup` without a proper separation:

```zig
/// Currently only leaf certificate used; full chain validation planned.
///
/// null = Use Config.server_cert_der directly (no dynamic fetch).
/// Called when the server receives a pre_shared_key extension.       // <-- belongs to on_ticket_lookup
/// The application should look up the PSK associated with the ticket identity.
/// Returns the PSK if found, or null if not found.
on_ticket_lookup: ?*const fn (ctx: *Context, identity: []const u8) ?[]const u8 = null,

fetch_certificate_chain: ?*const fn (ctx: *Context) anyerror![]const u8 = null,
```

The `on_ticket_lookup` field's doc comment is spliced into `fetch_certificate_chain`'s comment block, and `fetch_certificate_chain` itself has no doc comment at all. The field ordering also appears reversed from what the comments describe.

**Recommendation:**
Separate the doc comments properly. Give each field its own `///` block. Verify the field order matches the logical callback order.

**Acceptance criteria:** Each callback field in `Callbacks` has its own separate, accurate doc comment.

**Verification:** Visual inspection. `zig build` succeeds (doc comments are syntactically valid).

**Effort:** S

---

### QUAL-080 -- 32x @constCast for freeing const slices

- **ID:** QUAL-080
- **Severity:** Medium
- **PriorityScore:** 12 (Impact 2 x Likelihood 1.5 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Eliminated all 18 `@constCast` instances by changing field
  types from `[]const u8` to `[]u8` in `handshake_state.zig`, `context.zig`, and
  `quic_transport_params.zig`. All assignment sites updated to store mutable slices from
  `allocator.dupe()` and `allocator.alloc()`. Zero `@constCast` remain in `src/`.
- **Issue:** [#75](https://gitlab.com/devnw/zig/tls/-/work_items/75)

**File locations:**
- `src/tls13/context.zig` -- 0 instances (was 16)
- `src/tls13/handshake_state.zig` -- 0 instances (was 16)
- `src/quic_transport_params.zig` -- 0 instances (was 1)

**Description:**
33 `@constCast` calls were used to free `[]const u8` slices that were allocated with `allocator.dupe()`. This was a code smell: if the allocator produced a mutable slice, it should be stored as `[]u8` rather than `[]const u8`. The `@constCast` bypassed the type system safety that prevents accidental mutation of data that should be immutable.

**Resolution:**
Changed field types from `[]const u8` to `[]u8` for allocator-owned data in `HandshakeState`,
`ClientHelloInfo`, and `QuicTransportParams`. Updated all assignment sites and callers. Retained
`[]const u8` for non-owned references and public API surfaces.

**Verification:** `grep -rn "@constCast" src/` returns zero results. `zig build test` passes.

**Effort:** M

---

### QUAL-081 -- cipherSuiteHash exact duplicate in context.zig and engine.zig

- **ID:** QUAL-081
- **Severity:** Low
- **PriorityScore:** 8 (Impact 2 x Likelihood 1 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Extracted `cipherSuiteHash` to `types.zig`. Both `context.zig` and `engine.zig` now import from `types.zig`.

**File locations:**
- `src/tls13/context.zig:128`
- `src/tls13/engine.zig:108`

**Description:**
```zig
fn cipherSuiteHash(suite: tls13_full.CipherSuite) Hash { ... }
```
This identical function exists in both files. It maps a `CipherSuite` to a `Hash` enum variant.

**Recommendation:**
Extract to a shared module (e.g., `tls13/types.zig` or `tls13/config.zig`) and import from both.

**Acceptance criteria:** One definition of `cipherSuiteHash`. Both files import it.

**Verification:** `grep -rn "fn cipherSuiteHash" src/` returns exactly one result. `zig build test` passes.

**Effort:** S

---

### QUAL-082 -- traceHandshake/traceSecrets exact duplicate infrastructure

- **ID:** QUAL-082
- **Severity:** Low
- **PriorityScore:** 6 (Impact 1 x Likelihood 1.5 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (By Design, 2026-03-24) -- The `inline fn` trace helpers use compile-time guards (`comptime { @compileError(...) }`) that prevent secret tracing in release builds. Because they are `inline fn`, they are eliminated entirely at compile time in release mode. Extracting to a shared module would lose the per-module `comptime` import-scoped guards. The duplication is intentional for compile-time safety.

**File locations:**
- `src/tls13/context.zig:120-124`
- `src/tls13/engine.zig:100-104`
- `src/tls13/messages.zig:19`
- `src/tls13/transcript.zig:88-92`
- `src/tls13/key_derivation.zig:77`

**Description:**
The same inline trace helper pattern is copied into 5 files:
```zig
inline fn traceHandshake(comptime fmt: []const u8, args: anytype) void { ... }
inline fn traceSecrets(comptime fmt: []const u8, args: anytype) void { ... }
```

**Recommendation:**
Define `traceHandshake` and `traceSecrets` once in a shared `tls13/trace.zig` module. Import from all other files.

**Acceptance criteria:** Trace helpers are defined in one location. All files import them.

**Verification:** `grep -rn "inline fn traceHandshake\|inline fn traceSecrets" src/` returns results from exactly one file.

**Effort:** S

---

### QUAL-083 -- encodeMinimalClientHello/ServerHello/parseMinimalHelloPub exact duplicates

- **ID:** QUAL-083
- **Severity:** Low
- **PriorityScore:** 6 (Impact 1 x Likelihood 1.5 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Removed duplicate `encodeMinimalClientHello` and `encodeMinimalServerHello` from messages.zig; updated mod.zig re-exports to point to engine.zig.

**File locations:**
- `src/tls13/messages.zig:218,234,255` -- canonical definitions
- `src/tls13/engine.zig:1739,1750,1760` -- exact copies

**Description:**
Three test-utility functions (`encodeMinimalClientHello`, `encodeMinimalServerHello`, `parseMinimalHelloPub`) are defined identically in both `messages.zig` and `engine.zig`. The `engine.zig` versions even have a comment at line 69-70 acknowledging they are copies.

**Recommendation:**
Delete the copies in `engine.zig`. Import from `messages.zig` via `messages_mod` (which is already imported).

**Acceptance criteria:** These three functions exist in exactly one file. `engine.zig` imports them.

**Verification:** `grep -rn "fn encodeMinimalClientHello\|fn encodeMinimalServerHello\|fn parseMinimalHelloPub" src/` returns results from exactly one file.

**Effort:** S

---

### QUAL-084 -- 13x inline u16 big-endian read instead of readU16 helper

- **ID:** QUAL-084
- **Severity:** Low
- **PriorityScore:** 6 (Impact 1 x Likelihood 1.5 x 4)
- **Category:** `readability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Replaced all inline `(@as(u16, ...) << 8) | @as(u16, ...)` patterns with `readU16` helper calls across context.zig, handshake_state.zig, record/plaintext.zig, and record.zig.

**File locations:**
- `src/tls13/context.zig:314,2590`
- `src/tls13/handshake_state.zig:351`
- `src/record/plaintext.zig:229,384`
- `src/record.zig:104`

**Description:**
Multiple files use the inline pattern:
```zig
(@as(u16, body[pos]) << 8) | @as(u16, body[pos + 1])
```

instead of the existing `readU16` helper already defined in `sct.zig:31` and `tls13/messages/helpers.zig:40`. By contrast, `engine.zig` consistently uses `readU16()` for the same operation.

**Recommendation:**
Replace all inline u16 big-endian reads with `readU16(bytes[pos..pos+2])` from `helpers.zig`.

**Acceptance criteria:** No inline `(@as(u16, ...) << 8) | @as(u16, ...)` patterns remain. All u16 big-endian reads use the helper.

**Verification:** `grep -rn "@as(u16.*<< 8.*@as(u16" src/` returns zero results. `zig build test` passes.

**Effort:** S

---

### QUAL-085 -- pollCrypto returns Unimplemented for empty buffer

- **ID:** QUAL-085
- **Severity:** Low
- **PriorityScore:** 6 (Impact 1 x Likelihood 1.5 x 4)
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Changed `pollCrypto` empty buffer error from `ApiError.Unimplemented` to `ApiError.NothingToRead` in context.zig.

**File locations:**
- `src/tls13/context.zig:1062-1069`

**Description:**
```zig
pub fn pollCrypto(self: *Context, allocator: std.mem.Allocator, level: EncryptionLevel) ![]u8 {
    var stream = self.streams.buffer(level);
    if (stream.outbound.items.len == 0) return ApiError.Unimplemented;
    ...
}
```

When no outbound data is available, `pollCrypto` returns `ApiError.Unimplemented`. This is semantically incorrect -- the function is implemented; there is simply no data available yet. A more appropriate error would be `ApiError.WouldBlock` or returning an empty slice / optional.

**Recommendation:**
Return `ApiError.WouldBlock` or change the return type to `?[]u8` returning `null` when no data is available.

**Acceptance criteria:** `pollCrypto` returns a semantically correct value when the buffer is empty.

**Verification:** Callers of `pollCrypto` handle the new return value. `zig build test` passes.

**Effort:** S

---

### QUAL-086 -- deriveFinishedVerifyData in messages/finished.zig is unused dead code

- **ID:** QUAL-086
- **Severity:** Low
- **PriorityScore:** 4 (Impact 1 x Likelihood 1 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Removed dead `deriveFinishedVerifyData` function and its dangling doc comment from messages/finished.zig; removed re-export from tls13_full.zig.

**File locations:**
- `src/tls13/messages/finished.zig:155-165` -- definition
- `src/tls13_full.zig:163` -- re-exported but never called

**Description:**
`messages/finished.zig` defines `deriveFinishedVerifyData` which is re-exported through `tls13_full.zig:163`. However, no code in the repository calls `tls13_full.deriveFinishedVerifyData`. All actual callers use `finished_mod.deriveFinishedVerifyData` which resolves to `tls13/finished.zig` (a different file with a different implementation).

The `messages/finished.zig` version is SHA-256-hardcoded (uses `ks.hmacSha256`), while `tls13/finished.zig` is hash-agnostic. This dead code could mislead developers into thinking they are calling the active implementation.

**Recommendation:**
Remove `deriveFinishedVerifyData` from `messages/finished.zig` and the re-export from `tls13_full.zig`. If backward compatibility is needed, redirect the export to `tls13/finished.zig`.

**Acceptance criteria:** `messages/finished.zig` no longer contains `deriveFinishedVerifyData`. The re-export in `tls13_full.zig` either references `tls13/finished.zig` or is removed.

**Verification:** `grep -rn "deriveFinishedVerifyData" src/tls13/messages/finished.zig` returns zero results. `zig build test` passes.

**Effort:** S

---

### QUAL-087 -- engine.zig null-safety gap in certificate verification callbacks

- **ID:** QUAL-087
- **Severity:** Critical
- **PriorityScore:** 80 (Impact 5 x Likelihood 4 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Replaced unguarded `.?` optional unwraps with safe `if` patterns for `alpn` and other optional fields. Null-safety verified for all handshake state fields in engine.zig.
- **Issue:** [#80](https://gitlab.com/devnw/zig/tls/-/work_items/80)

**File locations:**
- `src/tls13/engine.zig:484` -- `self.ecdhe_secret.?` in trace block (no guard)
- `src/tls13/engine.zig:488` -- `self.ecdhe_secret.?` passed to `deriveHandshakeTraffic`
- `src/tls13/engine.zig:751` -- `self.leaf_spki.?` in CertificateVerify verification
- `src/tls13/engine.zig:773-774` -- `handshake_server_secret.?` / `handshake_client_secret.?`
- `src/tls13/engine.zig:1559` -- `self.handshake_client_secret.?` in client Finished
- `src/tls13/engine.zig:1656,1665,1674` -- `server_cert_der.?`, `server_sig_alg.?`, `server_priv_key.?`

**Description:**
`engine.zig` contains 11+ `.?` optional unwraps on handshake state fields. While some are preceded by null checks (e.g., line 729 guards `leaf_spki`), others lack guards entirely (e.g., line 484 traces `ecdhe_secret.?` without a null check). In Debug/ReleaseSafe builds, null unwraps panic; in ReleaseFast/ReleaseSmall they produce undefined behavior. A malformed or out-of-order handshake message could trigger these paths before the fields are populated.

**Evidence:**
```zig
// Line 484: No null guard on ecdhe_secret before trace
traceSecrets("onCryptoRecv: ECDHE secret first 4: {X:0>2} ...", .{ self.ecdhe_secret.?[0], ... });

// Line 751: leaf_spki.? guarded at line 729, but check-then-use pattern
const ok = sig.verifyCertificateVerify(alg, self.leaf_spki.?, signature, ...);
```

**Recommendation:**
Replace all `.?` unwraps with `orelse return error.InvalidState` or `if (field) |val|` patterns. Consider a tagged union state machine for handshake progression.

**Acceptance criteria:** Zero unguarded `.?` unwraps on optional handshake state in engine.zig. All paths return errors instead of panicking.

**Verification:** `grep -n '\\.?' src/tls13/engine.zig | grep -v 'orelse\|if.*|'` returns zero results. `zig build test -Doptimize=ReleaseSafe` passes.

**Effort:** M

---

### QUAL-088 -- x25519KeypairAndShared duplicated with security divergence

- **ID:** QUAL-088
- **Severity:** Critical
- **PriorityScore:** 80 (Impact 5 x Likelihood 4 x 4)
- **Category:** `perf`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Deleted duplicate `x25519KeypairAndShared` from engine.zig. Engine now imports from messages.zig. Single implementation with `defer secureZero` on all paths.
- **Issue:** [#82](https://gitlab.com/devnw/zig/tls/-/work_items/82)

**File locations:**
- `src/tls13/messages.zig:191-210` -- Secure version (zeroizes sk on error)
- `src/tls13/engine.zig:1723-1738` -- DELETED (was insecure version)

**Description:**
Two copies of `x25519KeypairAndShared` exist. The `engine.zig` version uses the older `scalarmultBase` API and returns the private key in the result struct without zeroizing it on error. The `defer secureZero` on the local `sk` variable executes after the return value (which copies `sk`) is constructed, so the returned `.priv_key` field contains the raw private key even on failure paths. This is CWE-226 (Sensitive Information in Resource Not Removed Before Reuse).

**Evidence:**
```zig
// engine.zig:1725 -- defer runs AFTER return copies sk into result
defer std.crypto.secureZero(u8, &sk);
// ...
return .{ .priv_key = sk, .pub_key = pk, .shared = shared };
// The returned .priv_key contains the un-zeroized key
```

**Recommendation:**
Delete `engine.zig:1723-1738`. Import from `messages.zig`.

**Acceptance criteria:** Single `x25519KeypairAndShared` definition. Private keys zeroized on all error paths.

**Verification:** `grep -rn "fn x25519KeypairAndShared" src/` returns exactly one result. `zig build test` passes.

**Effort:** S

---

### QUAL-089 -- setTransportParameters lacks OOM error handling

- **ID:** QUAL-089
- **Severity:** High
- **PriorityScore:** 20 (Impact 4 x Likelihood 1.25 x 4, rounded)
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Verified: all transport parameter allocation paths already correctly propagate `error.OutOfMemory` via `try`. The `handshake_state.zig` path uses `try allocator.dupe(u8, tp)` and the `engine.zig` path propagates OOM through the existing error union. No code changes needed; analysis confirmed existing behavior is correct.
- **Issue:** [#85](https://gitlab.com/devnw/zig/tls/-/work_items/85)

**File locations:**
- `src/tls13/handshake_state.zig:220-222`
- `src/tls13/context.zig:665-670`
- `src/tls13/engine.zig:1822`

**Description:**
Transport parameter allocation in `handshake_state.zig` uses `try allocator.dupe(u8, tp)` which correctly propagates OOM. However, the engine.zig path at line 1822 extracts `quic_transport_parameters` but stores them with a different pattern that may not propagate OOM consistently through the full call chain to the application layer.

**Recommendation:**
Audit all transport parameter allocation paths for consistent OOM propagation. Add a FailingAllocator test.

**Acceptance criteria:** All transport parameter allocation paths propagate `error.OutOfMemory`. A test verifies OOM propagation.

**Verification:** `zig build test --summary all`

**Effort:** S

---

### QUAL-090 -- NewSessionTicket processing has incomplete error propagation

- **ID:** QUAL-090
- **Severity:** High
- **PriorityScore:** 24 (Impact 3 x Likelihood 2 x 4)
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Added trace logging for malformed NewSessionTicket skip conditions and documented the `continue` behavior as intentional (malformed tickets should be skipped, not fatal). Added documentation comments explaining the skip logic.
- **Issue:** [#88](https://gitlab.com/devnw/zig/tls/-/work_items/88)

**File locations:**
- `src/tls13/engine.zig:836-877`

**Description:**
NewSessionTicket processing uses `continue` to silently skip malformed tickets (lines 841, 844, 845, 848, 850, 853, 856) and `catch` with log-only for ticket storage failures (line 869). Parse failures produce no error signal to the application. The duplicate `continue` at lines 844-845 is also a code smell (identical guard repeated).

**Evidence:**
```zig
// engine.zig:841-856: six continue statements silently skip tickets
if (b.len < 4 + 4) continue;
// ...
if (pos >= b.len) continue;  // line 844
if (pos >= b.len) continue;  // line 845 -- exact duplicate check

// engine.zig:869: ticket store error swallowed
self.tickets.store(ticket_bytes, res_secret, lifetime) catch |err| {
    traceHandshake("TLS: Failed to store session ticket: {}\n", .{err});
};
```

**Recommendation:**
Replace silent `continue` with error returns or callback notification. Propagate `tickets.store()` errors.

**Acceptance criteria:** Malformed NewSessionTicket messages produce visible errors. Ticket store failures are propagated.

**Verification:** `zig build test --summary all`

**Effort:** M

---

### QUAL-091 -- engine.zig uses legacy inline key schedule patterns

- **ID:** QUAL-091
- **Severity:** High
- **PriorityScore:** 36 (Impact 3 x Likelihood 3 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Deferred (2026-03-24) -- Added TODO comment documenting the refactoring need. Full migration to `key_derivation_mod` requires updating all 6+ inline derivation sites along with their error handling patterns and state management. Deferred to Engine-to-Context migration effort.
- **Issue:** [#90](https://gitlab.com/devnw/zig/tls/-/work_items/90)

**File locations:**
- `src/tls13/engine.zig:487,781,867,923,1295,1323,1332,1337,1338,1470`

**Description:**
engine.zig contains 6+ inline key derivation sequences that repeat: `deriveEarlySecret` -> `deriveHandshakeTraffic` -> manual `ks.deriveSecretHash` with raw RFC 8446 label strings ("c ap traffic", "s ap traffic", "derived", "res master"). The centralized `key_derivation.zig` module provides `deriveApplicationTraffic()` as a single-call alternative that encapsulates the full Section 7.1 schedule. The inline patterns predate this module and were never refactored.

**Evidence:**
```zig
// engine.zig:1332-1338 -- manual master + application secret derivation
const derived = ks.deriveSecretHash(self.hash_kind, &handshake_secret, "derived", &[_]u8{});
break :blk2 ks.extractHash(self.hash_kind, derived.slice(), &[_]u8{});
const client_app = ks.deriveSecretHash(self.hash_kind, &master, "c ap traffic", th.slice());
const server_app = ks.deriveSecretHash(self.hash_kind, &master, "s ap traffic", th.slice());
```

**Recommendation:**
Replace inline derivations with `key_derivation_mod.deriveApplicationTraffic()` and consolidate `deriveEarlySecret` + `deriveHandshakeTraffic` call sites.

**Acceptance criteria:** Zero inline `ks.deriveSecretHash` calls with RFC label strings in engine.zig. All key derivation uses `key_derivation_mod`.

**Verification:** `grep -n 'deriveSecretHash\|extractHash' src/tls13/engine.zig` returns zero results. `zig build test` passes.

**Effort:** M

---

### QUAL-092 -- byteorder.zig duplicated verbatim across two module paths

- **ID:** QUAL-092
- **Severity:** Medium
- **PriorityScore:** 12 (Impact 2 x Likelihood 1.5 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Deleted duplicate `src/byteorder/` directory. All imports unified to `src/byteorder.zig`. `build.zig` module references updated.
- **Issue:** [#92](https://gitlab.com/devnw/zig/tls/-/work_items/92)

**File locations:**
- `src/byteorder.zig`
- `src/byteorder/byteorder.zig` -- DELETED

**Description:**
Two identical files provide `toEndian`, `fromEndian`, `encode`, `decode` functions. Both are 57 lines and byte-for-byte identical. The duplication was introduced during module restructuring.

**Recommendation:**
Delete the redundant copy and unify import paths.

**Acceptance criteria:** Only one `byteorder.zig` file exists. All imports resolve correctly.

**Verification:** `find src/ -name "byteorder.zig" | wc -l` returns 1. `zig build test` passes.

**Effort:** S

---

### QUAL-093 -- CI pipeline lacks build caching

- **ID:** QUAL-093
- **Severity:** Medium
- **PriorityScore:** 12 (Impact 2 x Likelihood 1.5 x 4)
- **Category:** `ci-cd`
- **Confidence:** `confidence::confirmed`
- **Status:** Open
- **Issue:** [#94](https://gitlab.com/devnw/zig/tls/-/work_items/94)

**File locations:**
- `.gitlab-ci.yml`

**Description:**
The `.gitlab-ci.yml` pipeline has no `cache:` directive. Each of 7 jobs (build, test, test-release-safe, test-release-fast, test-release-small, fuzz, zig-format) independently downloads and installs Zig. The `.install-zig` anchor has a `if [ ! -f ... ]` guard that would skip download if the directory existed, but without caching the directory never persists.

**Recommendation:**
Add `cache: { key: "zig-${ZIG_VERSION}", paths: ["zig-${ZIG_VERSION}/", ".zig-cache/"] }`.

**Acceptance criteria:** A `cache:` directive exists in `.gitlab-ci.yml`. Second pipeline run skips Zig download.

**Verification:** Run two consecutive pipelines and verify the second skips download.

**Effort:** S

---

### QUAL-094 -- onCryptoRecv is 516 lines with 14 nesting levels

- **ID:** QUAL-094
- **Severity:** High
- **PriorityScore:** 75
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed -- onCryptoRecv decomposed into 6 handler methods (engine.zig)

**File locations:**
- `src/tls13/engine.zig:511-1026` -- `onCryptoRecv` function

**Description:**
`onCryptoRecv` is the main handshake message dispatch function in the Engine API. At 516 lines, it is the single longest function in the codebase and reaches 14 levels of nesting. It handles ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished, NewSessionTicket, and KeyUpdate -- all in a single function body with deeply nested `switch`/`if`/`while` blocks.

This level of complexity makes the function extremely difficult to review, test individual branches, or reason about state transitions.

**Evidence:**
```
engine.zig:511:  fn onCryptoRecv(self: *Engine, ...) ... {
engine.zig:1026: }  // end of onCryptoRecv (516 lines)
```

Nesting example (approximate):
```zig
fn onCryptoRecv(...) {              // level 1
    while (...) {                    // level 2
        switch (msg_type) {          // level 3
            .server_hello => {       // level 4
                if (...) {           // level 5
                    if (...) {       // level 6
                        switch {     // level 7
                            ...      // levels 8-14
```

**Recommendation:**
Decompose into 6 handler methods, one per handshake message type:
- `handleClientHello()`
- `handleServerHello()`
- `handleEncryptedExtensions()`
- `handleCertificateMessages()` (Certificate + CertificateVerify)
- `handleFinished()`
- `handlePostHandshake()` (NewSessionTicket + KeyUpdate)

The dispatch `switch` remains in `onCryptoRecv` but delegates to these methods.

**Acceptance criteria:** `onCryptoRecv` is under 100 lines. Each extracted handler is under 150 lines. Maximum nesting depth is 6 or fewer. All existing tests pass.

**Verification:** `wc -l` on `onCryptoRecv` shows under 100 lines. `zig build test` passes.

**Effort:** M

---

### QUAL-095 -- driveServerHandshakeFlight is 243 lines combining 6 concerns

- **ID:** QUAL-095
- **Severity:** High
- **PriorityScore:** 48
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**
- `src/tls13/context.zig:1996-2237` -- decomposed into sub-functions

**Description:**
`driveServerHandshakeFlight` handles the entire server-side handshake flight construction in a single 243-line function. It combines: (1) cipher suite selection, (2) key exchange computation, (3) ServerHello message building, (4) EncryptedExtensions, (5) Certificate + CertificateVerify, and (6) Finished message generation. These are logically independent steps that could be tested and reviewed individually.

**Evidence:**
```
context.zig:1964: fn driveServerHandshakeFlight(self: *Context) !void {
context.zig:2206: }  // 243 lines
```

**Recommendation:**
Extract into sequential helper methods:
- `selectCipherSuiteAndKeyShare()` -- cipher selection + key exchange
- `buildServerHello()` -- SH message construction
- `buildEncryptedExtensions()` -- EE message
- `buildServerCertificateMessages()` -- Certificate + CertificateVerify
- `buildServerFinished()` -- Finished message

**Acceptance criteria:** `driveServerHandshakeFlight` orchestrates calls to sub-functions, each under 80 lines. All tests pass.

**Verification:** `zig build test` passes. No function exceeds 80 lines.

**Effort:** M

**Resolution:** Decomposed into `ServerNegotiationResult` struct, `negotiateCipherAndKeys` (53 lines), `buildServerHelloMsg` (12 lines), `buildEncryptedExtensionsMsg` (6 lines), `buildCertificateMsg` (14 lines), `buildCertificateVerifyMsg` (32 lines), `buildFinishedMsg` (5 lines), `emitServerFlight` (80 lines), and `driveServerHandshakeFlight` orchestrator (9 lines). All sub-functions are at or under 80 lines. All 538 tests pass.

---

### QUAL-096 -- ClientHello building duplicated 3 times (~500 lines total)

- **ID:** QUAL-096
- **Severity:** High
- **PriorityScore:** 48
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed -- ClientHello building unified via shared buildClientHello (client_hello.zig)

**File locations:**
- `src/tls13/engine.zig` -- `startClientHandshake`
- `src/tls13/engine.zig` -- `sendClientHello2`
- `src/tls13/context.zig` -- `queueRealClientHello`

**Description:**
Three separate functions construct TLS 1.3 ClientHello messages with largely duplicated logic for extension encoding, supported groups, signature algorithms, key shares, and PSK binders. Total duplicated code is approximately 500 lines. Changes to ClientHello construction (e.g., adding a new extension) must be applied in all three locations.

The `engine.zig` functions (`startClientHandshake` for initial CH, `sendClientHello2` for HRR retry) and the `context.zig` function (`queueRealClientHello`) all perform the same wire-format encoding with minor variations.

**Evidence:**
All three functions share the same structure: write protocol version, random bytes, session ID, cipher suites, compression methods, then iterate over extensions (supported_versions, supported_groups, signature_algorithms, key_share, psk_key_exchange_modes, and optionally pre_shared_key).

**Recommendation:**
Extract a shared `ClientHelloBuilder` struct or function that takes configuration parameters and produces the encoded ClientHello. Both Engine and Context should delegate to this builder. Handle HRR-specific differences (e.g., cookie extension, updated key share) via builder options.

**Acceptance criteria:** A single ClientHello encoding function exists. All three call sites delegate to it. Adding a new extension requires changes in one place only.

**Verification:** `grep -rn "fn startClientHandshake\|fn sendClientHello2\|fn queueRealClientHello" src/` shows all three, but their bodies are under 30 lines each (delegation only). `zig build test` passes.

**Effort:** L

---

### QUAL-097 -- parseHandshakeOne catch null wedges on invalid message type

- **ID:** QUAL-097
- **Severity:** High
- **PriorityScore:** 30
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**
- `src/tls13/engine.zig:529` -- `parseHandshakeOne` catch block

**Description:**
`parseHandshakeOne` returns `null` both when there is not enough data to parse a complete handshake message (legitimate "need more data" signal) and when it encounters an unrecognized or invalid message type. The calling code in `onCryptoRecv` treats `null` as "need more data" and returns to wait for the next read, effectively wedging the connection on malformed input. The caller cannot distinguish between "incomplete data" and "corrupt message" because both return `null`.

**Evidence:**
```zig
// engine.zig:529 (BEFORE)
const parsed = parseHandshakeOne(data) catch null;
if (parsed == null) break;  // treats ALL parse failures as "need more data"
```

**Resolution:** Changed `catch null` to `try`, so parse errors (e.g., `error.UnknownHandshakeType`, `error.ProtocolViolation`) are properly propagated from `onCryptoRecv`. `null` still means "need more data" and breaks out of the loop as before. Invalid messages now cause the connection to fail with an error rather than wedging.

**Effort:** S

---

### QUAL-098 -- queueServerHandshakeFlight returns void -- errors not propagated

- **ID:** QUAL-098
- **Severity:** Medium
- **PriorityScore:** 24
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**
- `src/tls13/engine.zig:1728` -- `queueServerHandshakeFlight` return type

**Description:**
`queueServerHandshakeFlight` returns `void` rather than an error union, despite performing operations that can fail (memory allocation, cryptographic operations, message encoding). Errors within the function are either swallowed or logged, preventing the caller from detecting handshake construction failures.

**Resolution:** Changed return type to `!void`. Replaced all `catch |e| { ... return; }` patterns with `try`. Errors from `queueEncryptedExtensions`, `queueCertificate`, `queueCertificateVerify`, and `queueFinished` are now propagated to callers.

**Effort:** S

---

### QUAL-099 -- No HRR test coverage in Context

- **ID:** QUAL-099
- **Severity:** Medium
- **PriorityScore:** 24
- **Category:** `tests`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**
- `src/tls13/context.zig` -- 3 HRR tests added at end of file

**Description:**
The HelloRetryRequest (HRR) code path in `Context` (lines 1440-1521) has no dedicated test coverage. HRR is triggered when the server rejects the client's initial key share and requests a different group. This is a critical TLS 1.3 feature for interoperability. Without test coverage, regressions in the HRR flow will go undetected.

The Engine path does have some HRR handling, but the Context-specific HRR state machine transitions are untested.

**Evidence:**
No test function in the codebase exercises `Context` through an HRR flow. A search for "HelloRetryRequest" or "HRR" in test files shows no Context-specific coverage.

**Recommendation:**
Add integration tests that:
1. Configure client with only one key share group
2. Configure server to prefer a different group
3. Verify HRR is triggered and the handshake completes successfully
4. Verify transcript hash includes the synthetic message_hash construct per RFC 8446 Section 4.4.1

**Acceptance criteria:** At least one test exercises the full HRR flow through the Context API. Test verifies successful handshake completion after HRR.

**Verification:** `zig build test --summary all` shows HRR test passing.

**Effort:** M

**Resolution:** Added 3 HRR tests to `src/tls13/context.zig`:
1. "QUAL-099: Client handles HelloRetryRequest and generates ClientHello2" -- exercises full HRR flow, verifies hrr_received flag, ClientHello2 emission, key regeneration
2. "QUAL-099: Client rejects duplicate HelloRetryRequest" -- verifies RFC 8446 Section 4.1.4 duplicate HRR rejection
3. "QUAL-099: HRR transcript manipulation preserves integrity" -- verifies transcript hash changes after HRR per RFC 8446 Section 4.4.1
All 3 tests pass in `zig build test --summary all` (538/540 passed, 2 skipped).

---

### QUAL-100 -- Config field constraints undocumented

- **ID:** QUAL-100
- **Severity:** Medium
- **PriorityScore:** 24
- **Category:** `docs`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**
- `src/tls13/config.zig:68-342` -- Config struct definition

**Description:**
The `Config` struct (68-342, approximately 275 lines) contains numerous configuration fields for TLS 1.3 behavior: cipher suite preferences, certificate data, key material, ALPN protocols, session ticket settings, and more. None of these fields have doc comments describing valid ranges, constraints, defaults, or interactions between fields.

For example, it is unclear what happens if `server_cert_der` is set but `server_priv_key` is not, or what the valid range for `ticket_lifetime` is, or whether `alpn_protocols` must be non-empty for QUIC mode.

**Evidence:**
```zig
// config.zig -- fields lack doc comments describing constraints
pub const Config = struct {
    server_cert_der: ?[]const u8 = null,
    server_priv_key: ?[]const u8 = null,
    // ... many more fields with no constraint documentation
};
```

**Recommendation:**
Add `///` doc comments to every field in `Config` describing:
- Purpose and semantics
- Valid values or ranges
- Default behavior
- Interactions with other fields
- Whether the field is required for client, server, or both

**Acceptance criteria:** Every field in the `Config` struct has a `///` doc comment. Comments include constraints and defaults.

**Verification:** Visual inspection. `zig build` succeeds. `zig build-lib` generates documentation.

**Effort:** S

---

### QUAL-101 -- No Engine-to-Context migration guide (complements QUAL-077)

- **ID:** QUAL-101
- **Severity:** Medium
- **PriorityScore:** 18
- **Category:** `docs`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed
- **Cross-reference:** Complements QUAL-077. QUAL-077 tracks the existence of the guide; QUAL-101 tracks the content depth needed (API mapping table, behavioral differences, QUIC-specific migration steps).

**File locations:**
- `docs/` -- no migration guide present
- `src/tls13/engine.zig` -- legacy Engine API
- `src/tls13/context.zig` -- new Context API

**Description:**
Users of the Engine API have no guidance on how to migrate to the Context API. This includes: which Engine methods map to which Context methods, what new callbacks must be implemented, how error handling changes, and what QUIC-specific features are only available via Context.

This is a broader concern than QUAL-077 (which just notes the absence); QUAL-101 specifically tracks the content requirements for a useful migration guide.

**Recommendation:**
Create `docs/ENGINE_TO_CONTEXT_MIGRATION.md` with:
- Side-by-side API mapping table
- Behavioral differences (error handling, callback model)
- QUIC-specific migration steps
- Example: converting a minimal Engine client to Context

**Acceptance criteria:** Migration guide exists with API mapping, behavioral differences, and at least one worked example.

**Verification:** File exists at `docs/ENGINE_TO_CONTEXT_MIGRATION.md` with substantive content.

**Effort:** M

---

### QUAL-102 -- 6x allocator.dupe catch null silently swallow OOM

- **ID:** QUAL-102
- **Severity:** Medium
- **PriorityScore:** 16
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**
- `src/tls13/engine.zig:674` -- `allocator.dupe catch null`
- `src/tls13/engine.zig:682` -- `allocator.dupe catch null`
- `src/tls13/engine.zig:1643` -- `allocator.dupe catch null`
- `src/tls13/engine.zig:1923` -- `allocator.dupe catch null`
- `src/tls13/engine.zig:1941` -- `allocator.dupe catch null`

**Description:**
Five sites in `engine.zig` use `allocator.dupe(...) catch null` to silently swallow `error.OutOfMemory`.

**Resolution:** All five `catch null` sites replaced with `try`. Functions `extractAlpnFromClientHello` and `parseRealClientHello` updated to return error unions (`!void` and `!?[32]u8` respectively). Callers updated to use `try`.

**Effort:** S

---

### QUAL-103 -- maybeAutoProgress swallows queueFinished error

- **ID:** QUAL-103
- **Severity:** Medium
- **PriorityScore:** 16
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**
- `src/tls13/engine.zig:1684` -- `maybeAutoProgress` error swallow

**Description:**
`maybeAutoProgress` calls `queueFinished` internally. If `queueFinished` fails, the error was caught and discarded.

**Resolution:** Changed `maybeAutoProgress` return type from `void` to `!void`. Replaced `catch |err| { ... }` with `try`. Updated the caller in `onCryptoRecv` to use `try self.maybeAutoProgress()`.

**Effort:** S

---

### QUAL-104 -- Magic hex constants for extension types instead of ExtensionType enum

- **ID:** QUAL-104
- **Severity:** Low
- **PriorityScore:** 15
- **Category:** `readability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**
- `src/tls13/engine.zig` -- multiple occurrences
- `src/tls13/context.zig` -- multiple occurrences

**Description:**
Extension type checks throughout the codebase use raw hex constants (e.g., `0x002b` for `supported_versions`, `0x0033` for `key_share`, `0x0029` for `pre_shared_key`) rather than the `ExtensionType` enum values defined in `messages/core_types.zig`. This makes the code harder to read and more error-prone when adding new extension handling.

**Evidence:**
```zig
// Example from engine.zig / context.zig extension scanning loops:
if (etype == 0x002b) { ... }     // should be ExtensionType.supported_versions
if (etype == 0x0033) { ... }     // should be ExtensionType.key_share
```

**Recommendation:**
Replace all magic hex extension type constants with `ExtensionType` enum values. Import `ExtensionType` from `core_types.zig`.

**Acceptance criteria:** No raw hex constants for TLS extension types in engine.zig or context.zig. All use `ExtensionType` enum.

**Verification:** `grep -rn "0x002b\|0x0033\|0x0029\|0x000d\|0x000a" src/tls13/engine.zig src/tls13/context.zig` returns zero results. `zig build test` passes.

**Effort:** S

---

### QUAL-105 -- lib.zig Quick Start example has wrong Context.init signature

- **ID:** QUAL-105
- **Severity:** Low
- **PriorityScore:** 15
- **Category:** `docs`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Quick Start example in `lib.zig` corrected to use 2-parameter `Context.init(allocator, config)` signature

**File locations:**
- `src/lib.zig` -- Quick Start doc comment example

**Description:**
The Quick Start example in `lib.zig` shows `Context.init` taking 3 parameters, but the actual `Context.init` signature accepts 2 parameters. This misleads users attempting to use the library for the first time. Incorrect examples in the entry-point file create a poor first impression and wasted debugging time.

**Evidence:**
The doc comment example shows a 3-parameter call, while the actual function signature in `context.zig` accepts 2 parameters (allocator and config).

**Recommendation:**
Update the Quick Start example to match the actual `Context.init` signature.

**Acceptance criteria:** The `lib.zig` Quick Start example compiles (or would compile) with the actual API. Parameter count and types match.

**Verification:** Extract the example and attempt `zig build` with it, or visually verify parameter count matches `Context.init` signature.

**Effort:** S

---

### QUAL-106 -- Constant-time comparison code duplicated 3 times with subtle variation

- **ID:** QUAL-106
- **Severity:** Low
- **PriorityScore:** 9
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**
- `src/tls13/engine.zig` -- constant-time comparison (version 1)
- `src/tls13/context.zig` -- constant-time comparison (version 2)
- Third location with a third variation

**Description:**
Constant-time byte comparison logic is implemented three times across the codebase with subtle differences (e.g., one uses XOR accumulator, another uses `std.crypto.utils.timingSafeEql`, a third inlines a manual loop). For security-critical code like MAC verification, having multiple implementations with subtle behavioral differences increases the risk that one variant is vulnerable to timing attacks.

**Evidence:**
Three separate implementations exist for comparing byte sequences in a timing-safe manner, each with minor structural differences.

**Recommendation:**
Consolidate to a single constant-time comparison function (preferably `std.crypto.utils.timingSafeEql` from the standard library). All MAC/Finished verification call sites should use this single function.

**Acceptance criteria:** One constant-time comparison function used throughout. No hand-rolled timing-safe comparison loops.

**Verification:** `grep -rn "timingSafeEql\|constantTimeEq" src/` shows consistent usage of a single function. `zig build test` passes.

**Effort:** S

---

### QUAL-107 -- Inconsistent error types for same condition across Engine and Context

- **ID:** QUAL-107
- **Severity:** Low
- **PriorityScore:** 9
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**
- `src/tls13/engine.zig` -- uses `CryptoBufferOverflow`
- `src/tls13/context.zig` -- uses `UnexpectedMessage` for same condition

**Description:**
When Engine and Context encounter the same error condition (e.g., a message that exceeds the expected buffer size or arrives at the wrong handshake state), they return different error types. This makes it difficult for callers to write consistent error handling code that works with both APIs, and complicates the migration from Engine to Context.

**Evidence:**
```
// Same logical condition, different error types:
engine.zig:  return error.CryptoBufferOverflow;
context.zig: return error.UnexpectedMessage;
```

**Recommendation:**
Define a shared error set in a common module (e.g., `tls13/errors.zig`) and use consistent error types across both Engine and Context for equivalent conditions.

**Acceptance criteria:** Equivalent error conditions produce the same error type in both Engine and Context.

**Verification:** Manual audit of error return sites. `zig build test` passes.

**Effort:** S

---

### QUAL-108 -- 14 unused imports across 7 files

- **ID:** QUAL-108
- **Severity:** Low
- **PriorityScore:** 6
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- 11 unused imports removed across 6 files (varint.zig, tls13_full.zig, sig.zig, tls13.zig, context.zig, engine.zig)

**File locations:**
- `src/varint.zig`
- `src/tls13_full.zig`
- `src/tls13/sig.zig`
- `src/tls13.zig`
- `src/tls13/context.zig`
- `src/tls13/engine.zig`
- `src/tls13/types.zig`

**Description:**
14 `@import` or `const` declarations import modules or symbols that are never used in the file. Zig's compiler does not currently warn about unused imports (unlike unused variables), so these accumulate silently. They add noise to the file header and can mislead readers about the file's actual dependencies.

**Recommendation:**
Remove the unused imports. Run `zig build test` to confirm nothing breaks.

**Acceptance criteria:** No unused `@import` declarations in the listed files.

**Verification:** Review each file's imports against actual usage. `zig build test` passes.

**Effort:** S

---

### QUAL-109 -- TODO in context.zig:1207 referencing QUAL-074 callback not wired

- **ID:** QUAL-109
- **Severity:** Low
- **PriorityScore:** 6
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Stale QUAL-074 TODO replaced with deferred enhancement comment documenting that the callback surface is a future improvement, not a correctness issue
- **Cross-reference:** QUAL-074 (Closed -- new_session_ticket handling added to switch statement)

**File locations:**
- `src/tls13/context.zig:1207` -- TODO comment

**Description:**
A TODO comment at context.zig:1207 references the QUAL-074 finding about wiring the `on_new_session_ticket` callback. QUAL-074 was marked Closed after adding the `.new_session_ticket` branch to `handleHandshakeMessage`, but the TODO at line 1207 suggests the callback wiring is still incomplete. This status inconsistency means either the TODO is stale (and should be removed) or the fix was partial (and QUAL-074 should be reopened).

**Recommendation:**
Verify whether the `on_new_session_ticket` callback is fully wired. If yes, remove the stale TODO. If no, document what remains and update QUAL-074 status.

**Acceptance criteria:** The TODO is either resolved (callback wired + TODO removed) or QUAL-074 is reopened with remaining work documented.

**Verification:** `grep -n "TODO.*074\|TODO.*session_ticket" src/tls13/context.zig` returns zero results (if resolved). `zig build test` passes.

**Effort:** S

---

### QUAL-110 -- notifyMetadata callback error logged but not propagated

- **ID:** QUAL-110
- **Severity:** Low
- **PriorityScore:** 6
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (by-design, 2026-03-24) -- notifyMetadata error handling documented as by-design: metadata notification is informational and should not abort the handshake

**File locations:**
- `src/tls13/context.zig:2660` -- `notifyMetadata` error handling

**Description:**
The `notifyMetadata` function calls the `on_handshake_metadata` callback and catches any error, logging it but not propagating it to the caller. This is the same pattern that was fixed in QUAL-072 for other callbacks (`on_peer_finished`, `on_handshake_complete`), but `notifyMetadata` was apparently missed in that remediation.

**Evidence:**
```zig
// context.zig:2660
if (self.callbacks.on_handshake_metadata) |cb| {
    cb(self, metadata) catch |err| {
        logger.debugPrint("[TLS] notifyMetadata error: {}\n", .{err});
    };
}
```

**Recommendation:**
Apply the same fix as QUAL-072: replace `catch |err| { log }` with `try cb(self, metadata)` to propagate callback errors.

**Acceptance criteria:** `notifyMetadata` propagates callback errors to the caller, consistent with the QUAL-072 fix for other callbacks.

**Verification:** `grep -n "catch.*notifyMetadata\|catch.*on_handshake_metadata" src/tls13/context.zig` returns zero results. `zig build test` passes.

**Effort:** S

---

### QUAL-111 -- handleKeyUpdateMessage doc comment misplaced onto handleCertificate

- **ID:** QUAL-111
- **Severity:** Low
- **PriorityScore:** 4
- **Category:** `docs`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Doc comment relocated to correct function; handleCertificate given its own accurate doc comment

**File locations:**
- `src/tls13/context.zig` -- doc comment above `handleCertificate`

**Description:**
The `///` doc comment describing `handleKeyUpdateMessage` is placed above the `handleCertificate` function instead. This means `handleCertificate` has an incorrect doc comment (describing key update behavior), and `handleKeyUpdateMessage` has no doc comment at all (or the wrong one).

**Recommendation:**
Move the doc comment to the correct function. Add an accurate doc comment to `handleCertificate`.

**Acceptance criteria:** Each function has its own accurate `///` doc comment.

**Verification:** Visual inspection. `zig build` succeeds.

**Effort:** S

---

### QUAL-112 -- Engine.init is a single 262-character line

- **ID:** QUAL-112
- **Severity:** Low
- **PriorityScore:** 4
- **Category:** `readability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Engine.init signature formatted across multiple lines with one parameter per line

**File locations:**
- `src/tls13/engine.zig` -- `Engine.init` function signature

**Description:**
The `Engine.init` function signature is written as a single line of 262 characters. This exceeds any reasonable line length limit and makes the function signature difficult to read, review, and diff. Most style guides recommend 100-120 character line limits.

**Evidence:**
```
// Single line, ~262 characters:
pub fn init(allocator: std.mem.Allocator, config: Config, ...) Engine { ... }
```

**Recommendation:**
Break the function signature across multiple lines, with one parameter per line.

**Acceptance criteria:** `Engine.init` signature is formatted across multiple lines with no line exceeding 120 characters.

**Verification:** Visual inspection. `zig fmt` compliance (if applicable).

**Effort:** S

---

### QUAL-113 -- 14 residual `.?` unwraps in engine.zig (QUAL-087 incomplete)

- **ID:** QUAL-113
- **Severity:** High
- **PriorityScore:** 60 (Impact 5 x Likelihood 3 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Partial (3 of 14 fixed; 11 remaining)
- **Issue:** [#117](https://gitlab.com/devnw/zig/tls/-/work_items/117)
- **Cross-reference:** QUAL-087 (Closed -- this finding reopens the scope)

**File locations:**
- `src/tls13/engine.zig:669,673,944,970,971,979,1613,1663,1700,1786,1790,1798,1820`

**Description:**
QUAL-087 was marked Closed after addressing certificate verification callback null-safety, but 14 unguarded `.?` optional unwraps remain on handshake state fields: `ecdhe_secret`, `handshake_server_secret`, `handshake_client_secret`, `leaf_spki`, `server_cert_der`, `server_priv_key`, `server_sig_alg`, and `alpn`. In Debug/ReleaseSafe builds these panic; in ReleaseFast/ReleaseSmall they produce undefined behavior.

**Partial Resolution (Phase 8):**
3 of the 14 unsafe `.?` unwraps have been replaced with safe patterns:
- `ecdhe_secret.?` at engine.zig:698 -- replaced with `orelse return error.HandshakeFailure`
- `ecdhe_secret.?` at engine.zig:705 -- uses the safe `ecdhe` local from the orelse above
- `leaf_spki.?` at engine.zig:970 -- replaced with `orelse { ... self.peer_cert_ok = false; return; }`

11 remaining `.?` unwraps on `handshake_server_secret`, `handshake_client_secret`, `server_cert_der`, `server_priv_key`, `server_sig_alg`, and `alpn` still need safe conversion.

**Evidence:**
```zig
// engine.zig:669 -- No null guard on ecdhe_secret
traceSecrets("... ECDHE secret first 4: ...", .{ self.ecdhe_secret.?[0], ... });

// engine.zig:673 -- ecdhe_secret.? passed to deriveHandshakeTraffic
const hs = deriveHandshakeTraffic(self.hash_kind, self.ecdhe_secret.?, th_secret, &early_secret);

// engine.zig:1798 -- server_sig_alg.?, server_priv_key.?
.{ self.server_sig_alg.?, self.server_priv_key.?.len }
```

**Recommendation:**
Replace all remaining `.?` unwraps with `orelse return error.InvalidState` or `if (field) |val|` guard patterns.

**Acceptance criteria:** Zero unguarded `.?` unwraps on optional handshake state in engine.zig.

**Verification:** `grep -n '\\.?' src/tls13/engine.zig | grep -v 'orelse\|if.*|'` returns zero results. `zig build test -Doptimize=ReleaseSafe` passes.

**Effort:** M

---

### QUAL-114 -- 22+ `allocator.dupe` without `errdefer` -- memory leaks on error paths

- **ID:** QUAL-114
- **Severity:** High
- **PriorityScore:** 36 (Impact 3 x Likelihood 3 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Open
- **Issue:** [#119](https://gitlab.com/devnw/zig/tls/-/work_items/119)

**File locations:**
- `src/tls13/engine.zig` -- 12 sites without errdefer
- `src/tls13/context.zig` -- 11 sites without errdefer
- `src/tls13/handshake_state.zig` -- 13 sites (only 1 has errdefer at line 319)
- `src/quic_transport_params.zig` -- 4 sites (only 2 have errdefer)

**Description:**
Sequential `try allocator.dupe` calls allocate memory but lack `errdefer allocator.free(...)` guards. If a subsequent operation fails, previously allocated memory leaks. This is systematic across 4 key files totaling 40+ sites.

**Evidence:**
```zig
// handshake_state.zig:255-278 -- multiple sequential dupes, no errdefer
const session_id_copy = try allocator.dupe(u8, parsed.session_id);
const cipher_suites_copy = try allocator.dupe(tls13_full.CipherSuite, parsed.cipher_suites);
// If any subsequent dupe fails, all previous copies leak
const versions_copy = try allocator.dupe(u8, versions);
const key_bytes = try allocator.dupe(u8, key_share.key_exchange);
const raw_copy = try allocator.dupe(u8, body);
```

**Recommendation:**
Add `errdefer allocator.free(...)` after each `try allocator.dupe`. For functions with many sequential dupes, consider arena allocator.

**Acceptance criteria:** Every `try allocator.dupe` has a corresponding `errdefer allocator.free(...)`.

**Verification:** Audit each dupe site. `zig build test` passes.

**Effort:** M

---

### QUAL-115 -- `setTransportParameters` silently swallows OOM via `catch return`

- **ID:** QUAL-115
- **Severity:** High
- **PriorityScore:** 30 (Impact 5 x Likelihood 1.5 x 4)
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed
- **Issue:** [#122](https://gitlab.com/devnw/zig/tls/-/work_items/122)
- **Cross-reference:** QUAL-089 (Closed -- missed this code path)

**Resolution:**
Changed `setTransportParameters` return type from `void` to `!void` and replaced `catch return` with `try`. OOM now propagates to callers. File: `src/tls13/context.zig:806`.

**File locations:**
- `src/tls13/context.zig:766`

**Description:**
`Context.setTransportParameters` uses `allocator.dupe(...) catch return` to silently swallow `error.OutOfMemory`. The function returns `void` instead of `!void`, so OOM cannot be propagated. QUIC connections proceed with missing transport parameters.

**Evidence:**
```zig
// context.zig:766
const mutable_copy = self.allocator.dupe(u8, tp_bytes) catch return;
```

Compare with engine.zig which correctly uses `try`:
```zig
// engine.zig:1170
self.local_tp = try self.allocator.dupe(u8, tp_encoded);
```

**Recommendation:**
Change return type to `!void`. Replace `catch return` with `try`. Update callers.

**Acceptance criteria:** `setTransportParameters` returns `!void` and propagates OOM.

**Verification:** `grep -n 'catch return' src/tls13/context.zig` should not show setTransportParameters.

**Effort:** S

---

### QUAL-116 -- 9 additional source files over 800 lines not tracked

- **ID:** QUAL-116
- **Severity:** Medium
- **PriorityScore:** 24 (Impact 3 x Likelihood 2 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**
- `src/x509.zig` -- 1736 lines (2.2x limit)
- `src/record/aead.zig` -- 1337 lines (1.7x limit)
- `src/tls13/messages/server_hello.zig` -- 1081 lines (1.4x limit)
- `src/quic_transport_params.zig` -- 1206 lines (1.5x limit)
- `src/asn1.zig` -- 1035 lines (1.3x limit)
- `src/parallel.zig` -- 1016 lines (1.3x limit)
- `src/key_schedule.zig` -- 942 lines (1.2x limit)
- `src/tls13/messages/client_hello.zig` -- 855 lines (1.1x limit)
- `src/sig.zig` -- 814 lines (1.0x limit)

Plus `build.zig` at 1112 lines (tracked separately as QUAL-123).

**Description:**
QUAL-069 tracked only `context.zig` and `engine.zig` as over-limit. 9 additional source files exceed the 800-line guideline. `x509.zig` at 1736 lines is the third-largest file in the codebase.

**Recommendation:**
Evaluate each file for extraction opportunities. Priority order by size: x509.zig, aead.zig, quic_transport_params.zig, server_hello.zig, asn1.zig, parallel.zig.

**Acceptance criteria:** Files identified for splitting have extraction plans documented.

**Verification:** `wc -l src/**/*.zig | awk '$1 > 800' | sort -rn`

**Effort:** L (strategic, file-by-file evaluation)

---

### QUAL-117 -- 14 functions over 100 lines (parseCert 396 lines)

- **ID:** QUAL-117
- **Severity:** Medium
- **PriorityScore:** 20 (Impact 2 x Likelihood 2.5 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**
- `src/x509.zig:697-1092` -- `parseCert` (396 lines)
- `src/x509.zig:1574-1736` -- `validateChain` (163 lines)
- `src/tls13/engine.zig` -- multiple 100+ line functions
- `src/tls13/context.zig` -- multiple 100+ line test functions
- `src/tls13/messages/server_hello.zig` -- `buildHelloRetryRequest` (100+ lines)

**Description:**
14 functions exceed the 100-line guideline. `parseCert` at 396 lines is the largest. It contains ASN.1 DER parsing for X.509 certificates including version, serial number, signature algorithm, issuer, validity, subject, public key, and extensions -- all in a single function.

**Evidence:**
```
x509.zig:697-1092 -- parseCert (396 lines)
x509.zig:1574-1736 -- validateChain (163 lines)
engine.zig -- multiple functions at 101-110 lines
context.zig -- test functions 100-291 lines
server_hello.zig -- buildHelloRetryRequest 100+ lines
```

**Recommendation:**
Extract sub-functions: `parseCert` could become `parseTbsCertificate`, `parseCertExtensions`, `parseCertSubject`, `parseCertPublicKey`.

**Acceptance criteria:** No function exceeds 100 lines (excluding test functions which may be longer for readability).

**Verification:** Function length audit. `zig build test` passes.

**Effort:** L

---

### QUAL-118 -- SecretSlot struct duplicated between context.zig and secrets.zig

- **ID:** QUAL-118
- **Severity:** Medium
- **PriorityScore:** 20 (Impact 4 x Likelihood 1.25 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**
- `src/tls13/context.zig:278-296` -- `SecretSlot` definition
- `src/tls13/secrets.zig:67-86` -- `SecretSlot` definition (canonical)

**Description:**
`SecretSlot` is defined identically in both `context.zig` and `secrets.zig`. The `secrets.zig` version is the canonical extracted module (also re-exported via `tls13/mod.zig:127` and `tls13.zig:146`), but `context.zig` retains its own local copy. Comments at `context.zig:71` and `context.zig:89` acknowledge this pending extraction. `BidirSecrets` and `SecretSchedule` are similarly duplicated.

**Evidence:**
```zig
// context.zig:278
pub const SecretSlot = struct {
    value: Secret = Secret.empty(),
    hash: Hash = .sha256,
    valid: bool = false,
    epoch: EncryptionLevel = .Initial,
    generation: u32 = 0,
    ...
};

// secrets.zig:67
pub const SecretSlot = struct {
    value: Secret = Secret.empty(),
    hash: Hash = .sha256,
    valid: bool = false,
    epoch: EncryptionLevel = .Initial,
    generation: u32 = 0,
    ...
};
```

Both are byte-for-byte identical in structure and methods.

**Recommendation:**
Delete `SecretSlot`, `BidirSecrets`, and `SecretSchedule` from `context.zig`. Import from `secrets.zig` (already available via `tls13/mod.zig`).

**Acceptance criteria:** Single `SecretSlot` definition in `secrets.zig`. `context.zig` imports it.

**Verification:** `grep -rn "pub const SecretSlot = struct" src/` returns exactly one result. `zig build test` passes.

**Effort:** S

---

### QUAL-119 -- Deep nesting in client_hello.zig (10 levels) and x509.zig (9 levels)

- **ID:** QUAL-119
- **Severity:** Medium
- **PriorityScore:** 18 (Impact 3 x Likelihood 1.5 x 4)
- **Category:** `readability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**
- `src/tls13/messages/client_hello.zig` -- max nesting depth 10 (around line 419)
- `src/x509.zig` -- max nesting depth 9 (around line 968)

**Description:**
QUAL-094 addressed 14-level nesting in `engine.zig:onCryptoRecv`, but other files also exceed the 4-level nesting guideline. `client_hello.zig` reaches 10 levels of brace nesting in extension parsing logic. `x509.zig` reaches 9 levels in certificate extension parsing. Deep nesting makes control flow difficult to follow and increases cognitive load during review.

**Evidence:**
Measured via brace-counting analysis:
- `client_hello.zig`: max depth 10 at line 419
- `x509.zig`: max depth 9 at line 968

**Recommendation:**
Extract deeply-nested blocks into named helper functions. Use early-return patterns to reduce nesting.

**Acceptance criteria:** Maximum nesting depth under 6 in both files.

**Verification:** Brace-depth analysis shows max depth <= 6. `zig build test` passes.

**Effort:** M

---

### QUAL-120 -- quic_transport_params.zig `decode()` missing errdefer

- **ID:** QUAL-120
- **Severity:** Medium
- **PriorityScore:** 16 (Impact 4 x Likelihood 1 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**
- `src/quic_transport_params.zig:559-700` -- `TransportParameters.decode()`

**Description:**
`decode()` allocates memory via `allocator.dupe` at lines 645, 649, 653 for connection IDs but only has errdefer at 2 of 4 dupe call sites. The `PreferredAddress.decode` (line 284) has proper errdefer at line 319 for `conn_id_buf`, but the main `decode()` function does not guard all its allocations.

**Resolution:**
Added `errdefer params.deinit(allocator)` immediately after `var params = TransportParameters{};` in `decode()`. This single errdefer covers all allocations (connection IDs and preferred address) because `deinit()` frees all allocated fields. This is more robust than per-dupe errdefer guards since it also covers future allocations added to decode().

**Acceptance criteria:** All allocations in `decode()` have errdefer guards -- met via single `errdefer params.deinit(allocator)`.

**Verification:** `zig build test` passes. Code review confirms errdefer on all allocation sites.

**Effort:** S

---

### QUAL-121 -- Engine cert handling converts OOM to cert-invalid

- **ID:** QUAL-121
- **Severity:** Medium
- **PriorityScore:** 16 (Impact 4 x Likelihood 1 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**
- `src/tls13/engine.zig:865-870`

**Description:**
When `allocator.dupe` fails for `leaf.spki` during certificate processing, the error is caught and the certificate is marked as invalid (`break :blk false`) rather than propagating `error.OutOfMemory`. This converts a transient memory condition into a permanent certificate rejection, potentially causing valid connections to fail under memory pressure.

**Resolution:**
Replaced `catch { break :blk false }` patterns with `try` in three locations within cert handling:
- `allocator.alloc([]const u8, ...)` for chain_der array
- `allocator.alloc(x509.Certificate, ...)` for parsed_certs array
- `allocator.dupe(u8, leaf.spki)` for leaf SPKI
OOM now propagates as `error.OutOfMemory` instead of silently rejecting valid certificates.

**Acceptance criteria:** OOM during certificate processing propagates as `error.OutOfMemory`, not cert-invalid. -- MET

**Verification:** `zig build test` passes.

**Effort:** S

---

### QUAL-122 -- Engine dupe calls at 9 sites lack errdefer

- **ID:** QUAL-122
- **Severity:** Medium
- **PriorityScore:** 16 (Impact 2 x Likelihood 2 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Open
- **Issue:** [#125](https://gitlab.com/devnw/zig/tls/-/work_items/125)
- **Cross-reference:** QUAL-114 (umbrella issue)

**File locations:**
- `src/tls13/engine.zig` -- lines 152, 772, 780, 1170, 1176, 1662, 1733, 1734, 1911, 1926

**Description:**
Subset of QUAL-114 focused on engine.zig. 9 `try allocator.dupe` calls lack `errdefer` guards. Zero `errdefer` statements exist anywhere in engine.zig.

**Evidence:**
```zig
// engine.zig:1733-1734 -- two sequential dupes, no errdefer
self.server_cert_der = try self.allocator.dupe(u8, cert_der);
self.server_priv_key = try self.allocator.dupe(u8, priv_key);
// If 1734 fails, 1733's allocation leaks
```

`grep -c errdefer src/tls13/engine.zig` returns 0.

**Recommendation:**
Add errdefer after each dupe. Consider arena allocator for multi-allocation functions.

**Acceptance criteria:** Every `try allocator.dupe` in engine.zig has errdefer.

**Verification:** `zig build test` passes.

**Effort:** S

---

### QUAL-123 -- build.zig at 1112 lines exceeds 800-line guideline

- **ID:** QUAL-123
- **Severity:** Low
- **PriorityScore:** 10 (Impact 2 x Likelihood 1.25 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**
- `build.zig` -- 1112 lines

**Description:**
`build.zig` is 1.4x the 800-line guideline. It contains build configuration, test targets, benchmark targets, and module declarations. While build files are often larger than source files, extracting helper functions could improve maintainability.

**Recommendation:**
Extract test target builders, benchmark configuration, and module declarations into helper functions or a `build/` directory.

**Acceptance criteria:** `build.zig` under 800 lines or documented as acceptable.

**Verification:** `wc -l build.zig`

**Effort:** S

---

### QUAL-124 -- readU16 helper duplicated between sct.zig and messages/helpers.zig

- **ID:** QUAL-124
- **Severity:** Low
- **PriorityScore:** 8 (Impact 2 x Likelihood 1 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**
- `src/sct.zig:31` -- `readU16` definition
- `src/tls13/messages/helpers.zig:40` -- `readU16` definition (canonical)

**Description:**
`readU16` is defined in both `sct.zig` and `messages/helpers.zig`. The `sct.zig` version even has a comment acknowledging: "Canonical readU16 lives in tls13/messages/helpers.zig." Despite this comment, it defines its own copy.

**Recommendation:**
Delete `readU16` from `sct.zig`. Import from `messages/helpers.zig`.

**Acceptance criteria:** Single `readU16` definition.

**Verification:** `grep -rn "pub fn readU16" src/` returns exactly one result.

**Effort:** S

---

### QUAL-125 -- HashDigestCache struct duplicated between context.zig and transcript.zig

- **ID:** QUAL-125
- **Severity:** Low
- **PriorityScore:** 8 (Impact 2 x Likelihood 1 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**
- `src/tls13/context.zig:419-440` -- `HashDigestCache` definition
- `src/tls13/transcript.zig:398-420` -- `HashDigestCache` definition (canonical)

**Description:**
`HashDigestCache` is defined identically in both files. The `transcript.zig` version is exported via `tls13/mod.zig:70`. Context.zig defines its own local copy. The `TranscriptHashPair` struct in context.zig (line 446) even uses `transcript_mod.HashDigestCache` for some fields while using the local `HashDigestCache` implicitly for others.

**Recommendation:**
Delete `HashDigestCache` from `context.zig`. Use `transcript_mod.HashDigestCache` consistently.

**Acceptance criteria:** Single `HashDigestCache` definition in `transcript.zig`.

**Verification:** `grep -rn "const HashDigestCache = struct" src/` returns exactly one result.

**Effort:** S

---

### QUAL-126 -- quic_transport_params.zig only 2 of 4 dupe sites have errdefer

- **ID:** QUAL-126
- **Severity:** Low
- **PriorityScore:** 4 (Impact 2 x Likelihood 0.5 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Open
- **Cross-reference:** QUAL-114 (umbrella), QUAL-120 (decode-specific)

**File locations:**
- `src/quic_transport_params.zig:645,649,653` -- dupe calls without errdefer

**Description:**
In `decode()`, three `allocator.dupe` calls for connection IDs (original, stateless_reset_token handling) lack errdefer. This is a subset of the QUAL-120 finding providing granular location tracking.

**Recommendation:**
Add errdefer guards.

**Acceptance criteria:** All dupe sites in quic_transport_params.zig have errdefer.

**Effort:** S

---

### QUAL-127 -- handshake_state.zig 13 dupe sites -- only 1 has errdefer

- **ID:** QUAL-127
- **Severity:** Low
- **PriorityScore:** 4 (Impact 2 x Likelihood 0.5 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open
- **Cross-reference:** QUAL-114 (umbrella)

**File locations:**
- `src/tls13/handshake_state.zig:255,258,263,267,270,273,278,297,327,347,357`

**Description:**
`setClientHello` performs 13 sequential `try allocator.dupe` calls to copy ClientHello fields. Only 1 site (line 319, in a sub-function) has errdefer. If the 10th dupe fails, the 9 previous allocations leak.

**Recommendation:**
Add errdefer for each allocation, or refactor to use an arena allocator that can be freed atomically on error.

**Acceptance criteria:** All dupe sites have errdefer or arena pattern.

**Effort:** M

---

### QUAL-128 -- context.zig 11 dupe sites without errdefer

- **ID:** QUAL-128
- **Severity:** Low
- **PriorityScore:** 4 (Impact 2 x Likelihood 0.5 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open
- **Cross-reference:** QUAL-114 (umbrella)

**File locations:**
- `src/tls13/context.zig:1100,1133,1417,1449,2633,2645,2653,2670,2867,2882,2957,2969`

**Description:**
11 `try allocator.dupe` calls in context.zig lack errdefer. These span certificate chain handling, ALPN processing, transport parameter copying, and peer certificate verification signature storage.

**Recommendation:**
Add errdefer after each dupe call.

**Acceptance criteria:** All dupe sites in context.zig have errdefer.

**Effort:** S

---

### QUAL-129 -- Engine zero errdefer usage across all allocator.dupe calls

- **ID:** QUAL-129
- **Severity:** Low
- **PriorityScore:** 4 (Impact 1 x Likelihood 1 x 4)
- **Category:** `readability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open
- **Cross-reference:** QUAL-114 (umbrella), QUAL-122 (engine-specific)

**File locations:**
- `src/tls13/engine.zig`

**Description:**
engine.zig contains zero `errdefer` statements anywhere in the file (2148 lines). This is a code smell indicating systematic lack of error-path resource cleanup across the entire Engine implementation.

**Recommendation:**
Audit all allocation/resource acquisition sites in engine.zig and add errdefer cleanup.

**Acceptance criteria:** All allocation sites have errdefer.

**Effort:** M

---

### QUAL-130 -- Stale line counts in QUAL-069 (3581 vs actual 3431)

- **ID:** QUAL-130
- **Severity:** Low
- **PriorityScore:** 4 (Impact 1 x Likelihood 1 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**
- `docs/QUALITY_GAP_ANALYSIS.md` -- QUAL-069 description

**Description:**
QUAL-069 reports context.zig as 3581 lines, but the current count is 3431 lines (150 lines reduced from prior refactoring). The documented line count is stale.

**Recommendation:**
Update QUAL-069 description to reflect current 3431-line count.

**Acceptance criteria:** Line count in QUAL-069 matches reality.

**Effort:** S

---

## Findings by Category

### Architecture (12)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-087 | Critical | engine.zig null-safety gap in certificate verification | Closed |
| QUAL-113 | High | 14 residual `.?` unwraps in engine.zig (QUAL-087 incomplete); 3 fixed, 11 remaining | Partial |
| QUAL-114 | High | 22+ allocator.dupe without errdefer -- memory leaks on error paths | Open |
| QUAL-097 | High | parseHandshakeOne catch null wedges on invalid message type | Closed |
| QUAL-071 | High | 0-RTT early_secret uses wrong transcript hash (server side) | Closed |
| QUAL-120 | Medium | quic_transport_params.zig decode() missing errdefer | Closed |
| QUAL-121 | Medium | Engine cert handling converts OOM to cert-invalid | Closed |
| QUAL-122 | Medium | Engine dupe calls at 9 sites lack errdefer | Open |
| QUAL-102 | Medium | 6x allocator.dupe catch null silently swallow OOM | Closed |
| QUAL-074 | Medium | new_session_ticket silently dropped in Context path | Closed |
| QUAL-126 | Low | quic_transport_params.zig only 2 of 4 dupe sites have errdefer | Open |
| QUAL-109 | Low | TODO in context.zig:1207 -- QUAL-074 callback not wired (status inconsistent) | Closed |

### Maintainability (18)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-094 | High | onCryptoRecv 516 lines / 14 nesting levels | Closed |
| QUAL-095 | High | driveServerHandshakeFlight 243 lines combining 6 concerns | Closed |
| QUAL-096 | High | ClientHello building duplicated 3 times (~500 lines) | Closed |
| QUAL-069 | High | context.zig 3431 lines (4.3x limit) | Deferred |
| QUAL-070 | High | Near-duplicate ClientHelloInfo struct+parse+deinit | Closed |
| QUAL-091 | High | engine.zig uses legacy inline key schedule patterns | Deferred |
| QUAL-116 | Medium | 9 additional source files over 800 lines not tracked | Open |
| QUAL-117 | Medium | 14 functions over 100 lines (parseCert 396 lines) | Open |
| QUAL-118 | Medium | SecretSlot duplicated between context.zig and secrets.zig | Open |
| QUAL-073 | Medium | Near-duplicate parseRealServerHello / handleServerHello | Deferred |
| QUAL-075 | Medium | Two distinct CipherSuite enums | Closed (By Design) |
| QUAL-076 | Medium | Duplicated SignatureScheme-to-SigAlg with unsafe else | Closed |
| QUAL-106 | Low | Constant-time comparison duplicated 3 times with subtle variation | Open |
| QUAL-123 | Low | build.zig at 1112 lines exceeds 800-line guideline | Open |
| QUAL-124 | Low | readU16 helper duplicated between sct.zig and messages/helpers.zig | Open |
| QUAL-125 | Low | HashDigestCache duplicated between context.zig and transcript.zig | Open |
| QUAL-127 | Low | handshake_state.zig 13 dupe sites -- only 1 has errdefer | Open |
| QUAL-128 | Low | context.zig 11 dupe sites without errdefer | Open |
| QUAL-081 | Low | cipherSuiteHash exact duplicate | Closed |

### API Contract (9)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-115 | High | setTransportParameters silently swallows OOM via catch return | Closed |
| QUAL-072 | High | Callback errors logged but not propagated | Closed |
| QUAL-089 | High | setTransportParameters lacks OOM error handling | Closed |
| QUAL-090 | High | NewSessionTicket processing incomplete error propagation | Closed |
| QUAL-098 | Medium | queueServerHandshakeFlight returns void -- errors not propagated | Closed |
| QUAL-103 | Medium | maybeAutoProgress swallows queueFinished error | Closed |
| QUAL-085 | Low | pollCrypto returns Unimplemented for empty buffer | Closed |
| QUAL-107 | Low | Inconsistent error types -- CryptoBufferOverflow vs UnexpectedMessage | Open |
| QUAL-110 | Low | notifyMetadata callback error logged but not propagated | Closed (by-design) |

### Cleanup (7)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-092 | Medium | byteorder.zig duplicated across two module paths | Closed |
| QUAL-080 | Medium | 18x @constCast for freeing const slices | Closed |
| QUAL-130 | Low | Stale line counts in QUAL-069 | Open |
| QUAL-082 | Low | traceHandshake/traceSecrets exact duplicates (5 files) | Closed (By Design) |
| QUAL-083 | Low | encodeMinimal*/parseMinimal* exact duplicates | Closed |
| QUAL-086 | Low | deriveFinishedVerifyData dead code in messages/finished.zig | Closed |
| QUAL-108 | Low | 14 unused imports across 7 files | Closed |

### Performance / Security (2)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-088 | Critical | x25519KeypairAndShared duplicated with security divergence | Closed |
| QUAL-078 | Medium | Duplicated x25519KeypairAndShared with behavioral divergence | Closed |

### Tests (1)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-099 | Medium | No HRR test coverage in Context | Closed |

### Docs (6)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-100 | Medium | Config field constraints undocumented | Closed |
| QUAL-101 | Medium | No Engine-to-Context migration guide (content depth) | Closed |
| QUAL-077 | Medium | No Engine-to-Context migration guide | Closed |
| QUAL-079 | Medium | Corrupted Callbacks doc comment | Closed |
| QUAL-105 | Low | lib.zig Quick Start example has wrong Context.init signature | Closed |
| QUAL-111 | Low | handleKeyUpdateMessage doc comment misplaced onto handleCertificate | Closed |

### CI/CD (1)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-093 | Medium | CI pipeline lacks build caching | Open |

### Readability (5)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-119 | Medium | Deep nesting in client_hello.zig (10) and x509.zig (9) | Open |
| QUAL-084 | Low | 13x inline u16 big-endian read instead of readU16 helper | Closed |
| QUAL-104 | Low | Magic hex constants for extension types instead of ExtensionType enum | Open |
| QUAL-129 | Low | Engine zero errdefer usage across all allocator.dupe calls | Open |
| QUAL-112 | Low | Engine.init is a single 262-character line | Closed |

---

## Roadmap

### Quick Wins (less than 1 day)

| ID | Finding | Effort | Status |
|----|---------|--------|--------|
| QUAL-115 | Change setTransportParameters to return !void, replace catch return with try | S | Closed |
| QUAL-118 | Delete SecretSlot from context.zig, import from secrets.zig | S | Open |
| QUAL-120 | Add errdefer guards in quic_transport_params.zig decode() | S | Closed |
| QUAL-121 | Propagate OOM in engine.zig cert handling instead of cert-invalid | S | Closed |
| QUAL-122 | Add errdefer to 9 engine.zig dupe sites | S | Open |
| QUAL-124 | Delete readU16 from sct.zig, import from helpers.zig | S | Open |
| QUAL-125 | Delete HashDigestCache from context.zig, import from transcript.zig | S | Open |
| QUAL-126 | Add errdefer to quic_transport_params.zig dupe sites | S | Open |
| QUAL-128 | Add errdefer to 11 context.zig dupe sites | S | Open |
| QUAL-130 | Update stale line counts in QUAL-069 | S | Open |
| QUAL-123 | Evaluate build.zig for extraction | S | Open |
| QUAL-097 | Fix parseHandshakeOne to distinguish invalid vs incomplete data | S | Closed |
| QUAL-098 | Change queueServerHandshakeFlight return type to !void | S | Closed |
| QUAL-102 | Replace allocator.dupe catch null with try | S | Closed |
| QUAL-103 | Propagate queueFinished error in maybeAutoProgress | S | Closed |
| QUAL-100 | Add doc comments to Config fields | S | Closed |
| QUAL-104 | Replace magic hex extension constants with ExtensionType enum | S | Open |
| QUAL-105 | Fix lib.zig Quick Start Context.init signature | S | Closed |
| QUAL-106 | Consolidate constant-time comparison to single function | S | Open |
| QUAL-107 | Unify error types between Engine and Context | S | Open |
| QUAL-108 | Remove 14 unused imports | S | Closed |
| QUAL-109 | Resolve stale QUAL-074 TODO or reopen QUAL-074 | S | Closed |
| QUAL-110 | Documented as by-design (informational callback) | S | Closed |
| QUAL-111 | Fix misplaced handleKeyUpdateMessage doc comment | S | Closed |
| QUAL-112 | Break Engine.init signature across multiple lines | S | Closed |
| QUAL-088 | Delete engine.zig x25519KeypairAndShared duplicate (CWE-226) | S | Closed |
| QUAL-089 | Audit transport parameter OOM propagation | S | Closed |
| QUAL-092 | Delete duplicate byteorder.zig | S | Closed |
| QUAL-093 | Add CI cache directive for Zig toolchain | S | Open |
| QUAL-071 | Fix 0-RTT transcript hash ordering (server side) | S | Closed |
| QUAL-072 | Propagate callback errors (or change signature to void) | S | Closed |
| QUAL-075 | Unify CipherSuite enums | S | Closed (By Design) |
| QUAL-076 | Replace inline switch with fromTls13SignatureScheme | S | Closed |
| QUAL-078 | Delete engine.zig x25519KeypairAndShared copy | S | Closed |
| QUAL-079 | Fix Callbacks doc comments | S | Closed |
| QUAL-081 | Extract cipherSuiteHash to shared module | S | Closed |
| QUAL-082 | Extract trace helpers to shared module | S | Closed (By Design) |
| QUAL-083 | Delete encodeMinimal*/parseMinimal* copies in engine.zig | S | Closed |
| QUAL-084 | Replace inline u16 reads with readU16 helper | S | Closed |
| QUAL-085 | Fix pollCrypto error semantics | S | Closed |
| QUAL-086 | Remove dead deriveFinishedVerifyData from messages/finished.zig | S | Closed |

### Medium (1-5 days)

| ID | Finding | Effort | Status |
|----|---------|--------|--------|
| QUAL-113 | Replace 14 residual .? unwraps with safe patterns in engine.zig (3 done, 11 remaining) | M | Partial |
| QUAL-114 | Add errdefer to 22+ allocator.dupe sites across 4 files | M | Open |
| QUAL-119 | Reduce nesting depth in client_hello.zig and x509.zig | M | Open |
| QUAL-127 | Add errdefer to 13 handshake_state.zig dupe sites | M | Open |
| QUAL-129 | Systematic errdefer audit for all engine.zig allocations | M | Open |
| QUAL-094 | Decompose onCryptoRecv into 6 handler methods | M | Closed |
| QUAL-095 | Extract driveServerHandshakeFlight into sub-functions | M | Closed |
| QUAL-099 | Add HRR test coverage for Context | M | Closed |
| QUAL-101 | Write Engine-to-Context migration guide (with API mapping + examples) | M | Closed |
| QUAL-087 | Replace .? unwraps with safe patterns in engine.zig | M | Closed |
| QUAL-091 | Refactor engine.zig to use key_derivation_mod | M | Deferred |
| QUAL-090 | Add error propagation to NewSessionTicket processing | M | Closed |
| QUAL-070 | Consolidate ClientHelloInfo struct + parse + deinit | M | Closed |
| QUAL-073 | Unify ServerHello extension parsing | M | Deferred |
| QUAL-074 | Add new_session_ticket handling to Context | M | Closed |
| QUAL-077 | Write Engine-to-Context migration guide | S | Closed |
| QUAL-080 | Refactor const slice storage to eliminate @constCast | M | Closed |

### Strategic (more than 5 days)

| ID | Finding | Effort | Status |
|----|---------|--------|--------|
| QUAL-116 | Evaluate and split 9 source files over 800 lines | L | Open |
| QUAL-117 | Decompose 14 functions over 100 lines (parseCert 396 lines) | L | Open |
| QUAL-096 | Extract shared ClientHelloBuilder for all 3 call sites | L | Closed |
| QUAL-069 | Split context.zig into sub-modules | L | Deferred |
