# Quality Gap Analysis

> **Last updated:** 2026-03-24
> **Scope:** TLS 1.3/QUIC Implementation in Zig
> **Review phase:** Phase 3 Quality Review

---

## Summary

| Severity | Open | Closed | Total |
|----------|------|--------|-------|
| Critical | 0    | 0      | 0     |
| High     | 3    | 1      | 4     |
| Medium   | 7    | 1      | 8     |
| Low      | 3    | 3      | 6     |
| **Total**| **13** | **5** | **18**|

### Top 5 Risks

1. **QUAL-069** -- `context.zig` at 3581 lines is 4.5x the 800-line maintainability ceiling, making review, testing, and safe modification increasingly difficult.
2. **QUAL-071** -- 0-RTT `early_secret` is derived using a transcript hash that already includes the ServerHello, violating RFC 8446 Section 7.1 (server side only).
3. **QUAL-070** -- Near-duplicate `ClientHelloInfo` struct with its own parse/deinit logic exists in two locations, doubling the maintenance and bug surface.
4. **QUAL-072** -- Callback errors from `on_peer_finished`, `on_handshake_complete`, and `on_handshake_metadata` are caught, logged, and swallowed, contradicting the API documentation which declares them as `anyerror!void`.
5. **QUAL-073** -- `parseRealServerHello` in `engine.zig` and `handleServerHello` in `context.zig` implement the same ServerHello extension-parsing logic independently with divergent error handling.

---

## Stack-Ranked Findings

| Rank | ID | Severity | PriorityScore | Category | Finding | Component | Status |
|------|----|----------|---------------|----------|---------|-----------|--------|
| 1 | QUAL-069 | High | 60 | maintainability | context.zig 3581 lines (4.5x limit) | `src/tls13/context.zig` | Open |
| 2 | QUAL-070 | High | 40 | maintainability | Near-duplicate ClientHelloInfo parse+deinit | `context.zig`, `handshake_state.zig` | Open |
| 3 | QUAL-071 | High | 30 | architecture | 0-RTT early_secret uses wrong transcript hash | `src/tls13/context.zig:2191` | Closed |
| 4 | QUAL-073 | Medium | 27 | maintainability | Near-duplicate parseRealServerHello / handleServerHello | `engine.zig:1851`, `context.zig:2567` | Open |
| 5 | QUAL-072 | High | 24 | api-contract | Callback errors logged but not propagated | `src/tls13/context.zig` | Open |
| 6 | QUAL-074 | Medium | 24 | architecture | new_session_ticket silently dropped | `src/tls13/context.zig:1375` | Open |
| 7 | QUAL-075 | Medium | 18 | maintainability | Two distinct CipherSuite enums | `record/aead.zig:76`, `messages/core_types.zig:258` | Open |
| 8 | QUAL-076 | Medium | 16 | maintainability | Duplicated SignatureScheme-to-SigAlg with unsafe else | `context.zig:2272`, `context.zig:2692` | Open |
| 9 | QUAL-077 | Medium | 16 | docs | No Engine-to-Context migration guide | `docs/` | Open |
| 10 | QUAL-078 | Medium | 12 | perf | Duplicated x25519KeypairAndShared with behavioral divergence | `messages.zig:191`, `engine.zig:1723` | Open |
| 11 | QUAL-079 | Medium | 12 | docs | Corrupted Callbacks doc comment | `context.zig:234-249` | Closed |
| 12 | QUAL-080 | Medium | 12 | cleanup | 32x @constCast for freeing const slices | `context.zig`, `handshake_state.zig`, `quic_transport_params.zig` | Open |
| 13 | QUAL-081 | Low | 8 | maintainability | cipherSuiteHash exact duplicate | `context.zig:128`, `engine.zig:108` | Open |
| 14 | QUAL-082 | Low | 6 | cleanup | traceHandshake/traceSecrets exact duplicate infrastructure | `context.zig`, `engine.zig`, `messages.zig`, `transcript.zig`, `key_derivation.zig` | Open |
| 15 | QUAL-083 | Low | 6 | cleanup | encodeMinimal*/parseMinimal* exact duplicates | `messages.zig`, `engine.zig` | Closed |
| 16 | QUAL-084 | Low | 6 | readability | 13x inline u16 big-endian read instead of readU16 helper | `context.zig`, `handshake_state.zig`, `record/plaintext.zig` | Open |
| 17 | QUAL-085 | Low | 6 | api-contract | pollCrypto returns Unimplemented for empty buffer | `context.zig:1064` | Closed |
| 18 | QUAL-086 | Low | 4 | cleanup | deriveFinishedVerifyData in messages/finished.zig is unused dead code | `src/tls13/messages/finished.zig:155` | Closed |

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
- **Status:** Open

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
- **Status:** Open

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
- **Status:** Open

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
- **Status:** Open

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
- **Status:** Open

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
- **Status:** Open

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
- **Status:** Open

**File locations:**
- `src/tls13/messages.zig:191-210` -- Uses `recoverPublicKey`, zeroizes `sk` on scalarmult failure
- `src/tls13/engine.zig:1723-1736` -- Uses `scalarmultBase`, does NOT zeroize `sk` on failure

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
- **Status:** Open

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
- **Status:** Open

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
- **Status:** Open

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
- **Status:** Open

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

## Findings by Category

### Architecture (2)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-071 | High | 0-RTT early_secret uses wrong transcript hash (server side) | Closed |
| QUAL-074 | Medium | new_session_ticket silently dropped in Context path | Open |

### Maintainability (5)
| ID | Severity | Finding |
|----|----------|---------|
| QUAL-069 | High | context.zig 3581 lines (4.5x limit) |
| QUAL-070 | High | Near-duplicate ClientHelloInfo struct+parse+deinit |
| QUAL-073 | Medium | Near-duplicate parseRealServerHello / handleServerHello |
| QUAL-075 | Medium | Two distinct CipherSuite enums |
| QUAL-081 | Low | cipherSuiteHash exact duplicate |

### API Contract (2)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-072 | High | Callback errors logged but not propagated | Open |
| QUAL-085 | Low | pollCrypto returns Unimplemented for empty buffer | Closed |

### Cleanup (4)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-080 | Medium | 32x @constCast for freeing const slices | Open |
| QUAL-082 | Low | traceHandshake/traceSecrets exact duplicates (5 files) | Open |
| QUAL-083 | Low | encodeMinimal*/parseMinimal* exact duplicates | Closed |
| QUAL-086 | Low | deriveFinishedVerifyData dead code in messages/finished.zig | Closed |

### Docs (2)
| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-077 | Medium | No Engine-to-Context migration guide | Open |
| QUAL-079 | Medium | Corrupted Callbacks doc comment | Closed |

### Performance / Security (1)
| ID | Severity | Finding |
|----|----------|---------|
| QUAL-078 | Medium | Duplicated x25519KeypairAndShared with behavioral divergence |

### Readability (1)
| ID | Severity | Finding |
|----|----------|---------|
| QUAL-084 | Low | 13x inline u16 big-endian read instead of readU16 helper |

### Other (1)
| ID | Severity | Finding |
|----|----------|---------|
| QUAL-076 | Medium | Duplicated SignatureScheme-to-SigAlg with unsafe else fallback |

---

## Roadmap

### Quick Wins (less than 1 day)

| ID | Finding | Effort | Status |
|----|---------|--------|--------|
| QUAL-071 | Fix 0-RTT transcript hash ordering (server side) | S | Closed |
| QUAL-072 | Propagate callback errors (or change signature to void) | S | Open |
| QUAL-075 | Unify CipherSuite enums | S | Open |
| QUAL-076 | Replace inline switch with fromTls13SignatureScheme | S | Open |
| QUAL-078 | Delete engine.zig x25519KeypairAndShared copy | S | Open |
| QUAL-079 | Fix Callbacks doc comments | S | Closed |
| QUAL-081 | Extract cipherSuiteHash to shared module | S | Open |
| QUAL-082 | Extract trace helpers to shared module | S | Open |
| QUAL-083 | Delete encodeMinimal*/parseMinimal* copies in engine.zig | S | Closed |
| QUAL-084 | Replace inline u16 reads with readU16 helper | S | Open |
| QUAL-085 | Fix pollCrypto error semantics | S | Closed |
| QUAL-086 | Remove dead deriveFinishedVerifyData from messages/finished.zig | S | Closed |

### Medium (1-5 days)

| ID | Finding | Effort |
|----|---------|--------|
| QUAL-070 | Consolidate ClientHelloInfo struct + parse + deinit | M |
| QUAL-073 | Unify ServerHello extension parsing | M |
| QUAL-074 | Add new_session_ticket handling to Context | M |
| QUAL-077 | Write Engine-to-Context migration guide | S |
| QUAL-080 | Refactor const slice storage to eliminate @constCast | M |

### Strategic (more than 5 days)

| ID | Finding | Effort |
|----|---------|--------|
| QUAL-069 | Split context.zig into sub-modules | L |
