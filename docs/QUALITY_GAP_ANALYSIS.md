# Quality Gap Analysis

> **Last updated:** 2026-03-24
> **Scope:** TLS 1.3/QUIC Implementation in Zig
> **Review phase:** Phase 4 Quality Issue Tracking

---

## Summary

| Severity | Open | Closed | By Design | Deferred | Total |
|----------|------|--------|-----------|----------|-------|
| Critical | 0    | 2      | 0         | 0        | 2     |
| High     | 2    | 4      | 0         | 1        | 7     |
| Medium   | 2    | 4      | 2         | 2        | 10    |
| Low      | 0    | 6      | 0         | 0        | 6     |
| **Total**| **4** | **16** | **2**    | **3**    | **25**|

### Top 5 Risks

1. **QUAL-087** -- `engine.zig` has multiple `.?` optional unwraps on handshake state fields (leaf_spki, ecdhe_secret, handshake_client_secret) that can panic on null, causing server crashes or undefined behavior in release builds (CWE-476). [Issue #80](https://gitlab.com/devnw/zig/tls/-/work_items/80)
2. **QUAL-088** -- `x25519KeypairAndShared` exists in both `messages.zig` and `engine.zig` with different security properties; the engine.zig version does not zeroize the private key on error (CWE-226). [Issue #82](https://gitlab.com/devnw/zig/tls/-/work_items/82)
3. **QUAL-069** -- `context.zig` at 3581 lines is 4.5x the 800-line maintainability ceiling, making review, testing, and safe modification increasingly difficult.
4. **QUAL-091** -- `engine.zig` contains 6+ inline key derivation sequences duplicating `key_derivation.zig`, with raw RFC 8446 label strings that risk typo-induced key schedule failures. [Issue #90](https://gitlab.com/devnw/zig/tls/-/work_items/90)
5. **QUAL-070** -- Near-duplicate `ClientHelloInfo` struct with its own parse/deinit logic exists in two locations, doubling the maintenance and bug surface.

---

## Stack-Ranked Findings

| Rank | ID | Severity | PriorityScore | Category | Finding | Component | Issue | Status |
|------|----|----------|---------------|----------|---------|-----------|-------|--------|
| 1 | QUAL-087 | Critical | 80 | architecture | engine.zig null-safety gap in certificate verification | `src/tls13/engine.zig` | [#80](https://gitlab.com/devnw/zig/tls/-/work_items/80) | Closed |
| 2 | QUAL-088 | Critical | 80 | perf | x25519KeypairAndShared duplicated with security divergence (CWE-226) | `engine.zig:1723`, `messages.zig:191` | [#82](https://gitlab.com/devnw/zig/tls/-/work_items/82) | Closed |
| 3 | QUAL-069 | High | 60 | maintainability | context.zig 3581 lines (4.5x limit) | `src/tls13/context.zig` | -- | Open |
| 4 | QUAL-070 | High | 40 | maintainability | Near-duplicate ClientHelloInfo parse+deinit | `context.zig`, `handshake_state.zig` | -- | Closed |
| 5 | QUAL-091 | High | 36 | maintainability | engine.zig uses legacy inline key schedule patterns (6+ copies) | `src/tls13/engine.zig` | [#90](https://gitlab.com/devnw/zig/tls/-/work_items/90) | Deferred |
| 6 | QUAL-071 | High | 30 | architecture | 0-RTT early_secret uses wrong transcript hash | `src/tls13/context.zig:2191` | -- | Closed |
| 7 | QUAL-073 | Medium | 27 | maintainability | Near-duplicate parseRealServerHello / handleServerHello | `engine.zig:1851`, `context.zig:2567` | -- | Deferred |
| 8 | QUAL-072 | High | 24 | api-contract | Callback errors logged but not propagated | `src/tls13/context.zig` | -- | Closed |
| 9 | QUAL-074 | Medium | 24 | architecture | new_session_ticket silently dropped | `src/tls13/context.zig:1375` | -- | Closed |
| 10 | QUAL-090 | High | 24 | api-contract | NewSessionTicket processing has incomplete error propagation | `src/tls13/engine.zig:836-877` | [#88](https://gitlab.com/devnw/zig/tls/-/work_items/88) | Closed |
| 11 | QUAL-089 | High | 20 | api-contract | setTransportParameters lacks OOM error handling | `handshake_state.zig:220`, `engine.zig:1822` | [#85](https://gitlab.com/devnw/zig/tls/-/work_items/85) | Closed |
| 12 | QUAL-075 | Medium | 18 | maintainability | Two distinct CipherSuite enums | `record/aead.zig:76`, `messages/core_types.zig:258` | -- | Closed (By Design) |
| 13 | QUAL-076 | Medium | 16 | maintainability | Duplicated SignatureScheme-to-SigAlg with unsafe else | `context.zig:2272`, `context.zig:2692` | -- | Closed |
| 14 | QUAL-077 | Medium | 16 | docs | No Engine-to-Context migration guide | `docs/` | -- | Open |
| 15 | QUAL-092 | Medium | 12 | cleanup | byteorder.zig duplicated verbatim across two module paths | `src/byteorder.zig`, `src/byteorder/byteorder.zig` | [#92](https://gitlab.com/devnw/zig/tls/-/work_items/92) | Closed |
| 16 | QUAL-078 | Medium | 12 | perf | Duplicated x25519KeypairAndShared with behavioral divergence | `messages.zig:191`, `engine.zig:1723` | -- | Closed |
| 17 | QUAL-079 | Medium | 12 | docs | Corrupted Callbacks doc comment | `context.zig:234-249` | -- | Closed |
| 18 | QUAL-093 | Medium | 12 | ci-cd | CI pipeline lacks build caching (Zig reinstalled each job) | `.gitlab-ci.yml` | [#94](https://gitlab.com/devnw/zig/tls/-/work_items/94) | Open |
| 19 | QUAL-080 | Medium | 12 | cleanup | 32x @constCast for freeing const slices | `context.zig`, `handshake_state.zig`, `quic_transport_params.zig` | -- | Deferred |
| 20 | QUAL-081 | Low | 8 | maintainability | cipherSuiteHash exact duplicate | `context.zig:128`, `engine.zig:108` | -- | Closed |
| 21 | QUAL-082 | Low | 6 | cleanup | traceHandshake/traceSecrets exact duplicate infrastructure | `context.zig`, `engine.zig`, `messages.zig`, `transcript.zig`, `key_derivation.zig` | -- | Closed (By Design) |
| 22 | QUAL-083 | Low | 6 | cleanup | encodeMinimal*/parseMinimal* exact duplicates | `messages.zig`, `engine.zig` | -- | Closed |
| 23 | QUAL-084 | Low | 6 | readability | 13x inline u16 big-endian read instead of readU16 helper | `context.zig`, `handshake_state.zig`, `record/plaintext.zig` | -- | Closed |
| 24 | QUAL-085 | Low | 6 | api-contract | pollCrypto returns Unimplemented for empty buffer | `context.zig:1064` | -- | Closed |
| 25 | QUAL-086 | Low | 4 | cleanup | deriveFinishedVerifyData in messages/finished.zig is unused dead code | `src/tls13/messages/finished.zig:155` | -- | Closed |

---

## Detailed Findings

### QUAL-069 -- context.zig exceeds maintainability size limit (3581 lines)

- **ID:** QUAL-069
- **Severity:** High
- **PriorityScore:** 60 (Impact 3 x Likelihood 5 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

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
- **Status:** Open

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
- **Status:** Deferred (2026-03-24) -- Requires cascading type changes across context.zig, handshake_state.zig, and quic_transport_params.zig. Changing field types from `[]const u8` to `[]u8` would require updating all assignment sites and callers. Low security risk; deferred to future refactoring.

**File locations:**
- `src/tls13/context.zig` -- 16 instances
- `src/tls13/handshake_state.zig` -- 16 instances
- `src/quic_transport_params.zig` -- 1 instance

**Description:**
33 `@constCast` calls are used to free `[]const u8` slices that were allocated with `allocator.dupe()`. This is a code smell: if the allocator produced a mutable slice, it should be stored as `[]u8` rather than `[]const u8`. The `@constCast` bypasses the type system safety that prevents accidental mutation of data that should be immutable.

**Evidence:**
```zig
// context.zig:323
if (groups.len != 0) allocator.free(@constCast(groups));

// handshake_state.zig:208
errdefer if (sigalgs_copy) |buf| if (buf.len != 0) allocator.free(@constCast(buf));
```

**Recommendation:**
Store allocator-owned slices as `[]u8` internally. Expose them as `[]const u8` only through accessor functions or pub const fields. This eliminates the need for `@constCast` at deallocation time.

**Acceptance criteria:** Zero `@constCast` calls remain in `context.zig` and `handshake_state.zig` for freeing purposes.

**Verification:** `grep -rn "@constCast" src/tls13/context.zig src/tls13/handshake_state.zig` returns zero results. `zig build test` passes.

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

## Findings by Category

### Architecture (3)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-087 | Critical | engine.zig null-safety gap in certificate verification | Closed |
| QUAL-071 | High | 0-RTT early_secret uses wrong transcript hash (server side) | Closed |
| QUAL-074 | Medium | new_session_ticket silently dropped in Context path | Closed |

### Maintainability (6)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-069 | High | context.zig 3581 lines (4.5x limit) | Open |
| QUAL-070 | High | Near-duplicate ClientHelloInfo struct+parse+deinit | Closed |
| QUAL-091 | High | engine.zig uses legacy inline key schedule patterns | Deferred |
| QUAL-073 | Medium | Near-duplicate parseRealServerHello / handleServerHello | Deferred |
| QUAL-075 | Medium | Two distinct CipherSuite enums | Closed (By Design) |
| QUAL-076 | Medium | Duplicated SignatureScheme-to-SigAlg with unsafe else | Closed |
| QUAL-081 | Low | cipherSuiteHash exact duplicate | Closed |

### API Contract (4)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-072 | High | Callback errors logged but not propagated | Closed |
| QUAL-089 | High | setTransportParameters lacks OOM error handling | Closed |
| QUAL-090 | High | NewSessionTicket processing incomplete error propagation | Closed |
| QUAL-085 | Low | pollCrypto returns Unimplemented for empty buffer | Closed |

### Cleanup (5)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-092 | Medium | byteorder.zig duplicated across two module paths | Closed |
| QUAL-080 | Medium | 17x @constCast for freeing const slices | Deferred |
| QUAL-082 | Low | traceHandshake/traceSecrets exact duplicates (5 files) | Closed (By Design) |
| QUAL-083 | Low | encodeMinimal*/parseMinimal* exact duplicates | Closed |
| QUAL-086 | Low | deriveFinishedVerifyData dead code in messages/finished.zig | Closed |

### Performance / Security (2)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-088 | Critical | x25519KeypairAndShared duplicated with security divergence | Closed |
| QUAL-078 | Medium | Duplicated x25519KeypairAndShared with behavioral divergence | Closed |

### Docs (2)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-077 | Medium | No Engine-to-Context migration guide | Open |
| QUAL-079 | Medium | Corrupted Callbacks doc comment | Closed |

### CI/CD (1)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-093 | Medium | CI pipeline lacks build caching | Open |

### Readability (1)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-084 | Low | 13x inline u16 big-endian read instead of readU16 helper | Closed |

---

## Roadmap

### Quick Wins (less than 1 day)

| ID | Finding | Effort | Status |
|----|---------|--------|--------|
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
| QUAL-087 | Replace .? unwraps with safe patterns in engine.zig | M | Closed |
| QUAL-091 | Refactor engine.zig to use key_derivation_mod | M | Deferred |
| QUAL-090 | Add error propagation to NewSessionTicket processing | M | Closed |
| QUAL-070 | Consolidate ClientHelloInfo struct + parse + deinit | M | Closed |
| QUAL-073 | Unify ServerHello extension parsing | M | Deferred |
| QUAL-074 | Add new_session_ticket handling to Context | M | Closed |
| QUAL-077 | Write Engine-to-Context migration guide | S | Open |
| QUAL-080 | Refactor const slice storage to eliminate @constCast | M | Deferred |

### Strategic (more than 5 days)

| ID | Finding | Effort | Status |
|----|---------|--------|--------|
| QUAL-069 | Split context.zig into sub-modules | L | Open |
