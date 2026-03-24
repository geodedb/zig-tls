# Security Gap Analysis

> **Last updated:** 2026-03-24
> **Scope:** TLS 1.3/QUIC Implementation in Zig
> **Review phase:** Phase 4 -- Issue tracking, gap closure, and deep audit of ECDHE lifecycle, DoS surfaces, and certificate validation robustness

## Summary

| Risk Level | Open | Closed | Total |
|-----------|------|--------|-------|
| Critical  | 0    | 0      | 0     |
| High      | 0    | 7      | 7     |
| Medium    | 1    | 9      | 10    |
| Low       | 6    | 4      | 10    |
| **Total** | **7** | **20** | **27** |

**All high-severity zeroization gaps (SEC-004-R, SEC-015, SEC-016) have been closed.** Remaining 7 items are informational/by-design/low-risk.

### Top 5 Risks (Open -- Remaining)

1. **SEC-007** -- No CRL checking; OCSP is optional (Risk 12.6) -- Architecture limitation; OCSP stapling available as alternative
2. **SEC-009** -- `x25519KeypairAndShared` returns value instead of error on failure (Risk 6.0) -- API design decision
3. **SEC-010** -- OCSP digest comparison uses `std.mem.eql` (Risk 1.0) -- Non-secret data; informational
4. **SEC-011** -- Downgrade sentinel detection uses `std.mem.eql` (Risk 1.0) -- Non-secret data; informational
5. **SEC-012** -- Debug trace logs private key scalar, compile-guarded (Risk 0.9) -- Acceptable with comptime guard

### Recently Closed (Phases 1-4)

- **SEC-004-R** -- CLOSED: Ed25519 KeyPair `secret_key.bytes` zeroized via `defer secureZero` in `sig.zig`
- **SEC-015** -- CLOSED: Context ECDHE `server_priv` zeroized via `defer secureZero` in `context.zig`
- **SEC-016** -- CLOSED: Context ECDHE shared secret zeroized (server+client) via `defer secureZero` in `context.zig`
- **SEC-017** -- CLOSED: TicketStore capped at `max_tickets=16` with FIFO eviction in `engine.zig`
- **SEC-018** -- CLOSED: CRYPTO buffer 64KB limit enforced in `context.zig` and `engine.zig`
- **SEC-019** -- CLOSED: `setAllowInsecure` with `@panic` in release mode in `engine.zig`
- **SEC-020** -- CLOSED: Finished failure returns `error.HandshakeFailure` in `engine.zig`
- **SEC-021** -- CLOSED: `cert_ok` check added to `handshakeComplete()` in `engine.zig`
- **SEC-023** -- CLOSED: `defer secureZero(u8, &sk)` added on all paths in `messages.zig`
- **SEC-024** -- CLOSED: `max_chain_depth=10` enforced in `x509.zig`
- **SEC-025** -- CLOSED: Trace message added for absent EKU, RFC 5280 compliant
- **SEC-026** -- CLOSED: Switched to `timing_safe.compare` in `ocsp.zig`
- **SEC-027** -- CLOSED: Dead fallback removed, replaced with `continue` in `engine.zig`

### Positive Observations

- Finished verification uses `timing_safe.eql` correctly (both Context and Engine)
- PSK binder verification uses constant-time comparison
- HRR cookie validation uses `timing_safe.eql`
- AEAD tag verification is constant-time via `std.crypto`
- Debug tracing has compile-time guards preventing release-mode secret leaks
- `Engine.deinit` has comprehensive secret zeroization
- `SecretSlot.clear` uses `secureZero` (fixed in cf6586c)
- `client_priv` is zeroized in `Context.deinit` (verified at context.zig:951-954)

---

## Stack-Ranked Findings

| Rank | ID | Severity | Risk Score | Finding | Component | CWE / OWASP | Evidence | Issue URL | Fix | Owner | Due | Status |
|------|----|----------|------------|---------|-----------|-------------|----------|-----------|-----|-------|-----|--------|
| 1 | SEC-001 | High | 42.0 | Client mTLS always signs with ed25519 | `context.zig` | CWE-295 / A07:2021 | `context.zig:2691` | -- | Client mTLS now negotiates signature scheme from CertificateRequest | Claude | 2026-03-24 | Closed |
| 2 | SEC-002 | High | 32.0 | `SecretSlot.clear()` missing `secureZero` | `context.zig` | CWE-226 / A02:2021 | `context.zig:285-291` | -- | Added `std.crypto.secureZero` to `SecretSlot.clear()` | Claude | 2026-03-24 | Closed |
| 3 | SEC-003 | High | 24.3 | ECDSA P-256 scalar not zeroized after signing | `sig.zig` | CWE-226 / A02:2021 | `sig.zig:559-645` | -- | Added `defer std.crypto.secureZero(u8, &sk)` | Claude | 2026-03-24 | Closed |
| 4 | SEC-004 | High | 24.3 | Ed25519 seed not zeroized after signing | `sig.zig` | CWE-226 / A02:2021 | `sig.zig:544-555` | -- | Seed zeroized; **keypair NOT zeroized** (see SEC-004-R) | Claude | 2026-03-24 | Closed (partial) |
| 5 | SEC-005 | Medium | 16.0 | `allow_insecure` no compile-time guard for release | `config.zig` | CWE-1188 / A05:2021 | `config.zig:271` | -- | Added runtime panic guard in `Context.init()` | Claude | 2026-03-24 | Closed |
| 6 | SEC-006 | Medium | 14.0 | `else => .ed25519` signing fallback masks unknown schemes | `context.zig` | CWE-394 / A07:2021 | `context.zig:2277,2697` | -- | Replaced with error returns | Claude | 2026-03-24 | Closed |
| 7 | SEC-004-R | High | 14.0 | Ed25519 expanded KeyPair not zeroized after signing | `sig.zig` | CWE-226 / A02:2021 | `sig.zig:547` | [#84](https://gitlab.com/devnw/zig/tls/-/issues/84) | Changed `const kp` to `var kp`; added `defer secureZero(u8, &kp.secret_key.bytes)` | Claude | 2026-03-24 | Closed |
| 8 | SEC-015 | High | 14.0 | Context ECDHE `server_priv` not zeroized | `context.zig` | CWE-226 / A02:2021 | `context.zig:2153` | [#87](https://gitlab.com/devnw/zig/tls/-/issues/87) | Added `defer secureZero(u8, &server_priv)` in context.zig | Claude | 2026-03-24 | Closed |
| 9 | SEC-016 | High | 13.0 | Context ECDHE shared secret not zeroized (server+client) | `context.zig` | CWE-226 / A02:2021 | `context.zig:2163,2677` | [#91](https://gitlab.com/devnw/zig/tls/-/issues/91) | Changed `const shared` to `var shared`; added `defer secureZero` on both paths | Claude | 2026-03-24 | Closed |
| 10 | SEC-007 | Medium | 12.6 | No CRL checking; OCSP is optional | `x509.zig` | CWE-299 / A07:2021 | `x509.zig:1451-1479` | -- | Document limitation; add `require_ocsp` enforcement path | -- | 90 days | Open |
| 11 | SEC-017 | Medium | 10.0 | TicketStore unbounded growth (DoS) | `engine.zig` | CWE-770 / A05:2021 | `engine.zig:128-151` | [#93](https://gitlab.com/devnw/zig/tls/-/issues/93) | Added max_tickets=16 with FIFO eviction; secrets zeroized on eviction | Claude | 2026-03-24 | Closed |
| 12 | SEC-018 | Medium | 10.0 | CRYPTO inbound/inbox buffer unbounded (Context + Engine) | `context.zig`, `engine.zig` | CWE-770 / A05:2021 | `context.zig:1033`, `engine.zig:437` | [#95](https://gitlab.com/devnw/zig/tls/-/issues/95) | Added 64KB MAX_HANDSHAKE_BUFFER limit in both context.zig and engine.zig | Claude | 2026-03-24 | Closed |
| 13 | SEC-019 | Medium | 9.0 | Engine `allow_insecure` no release guard | `engine.zig` | CWE-295 / A05:2021 | `engine.zig:207` | [#96](https://gitlab.com/devnw/zig/tls/-/issues/96) | Added `setAllowInsecure` with `@panic` in release builds matching Context pattern | Claude | 2026-03-24 | Closed |
| 14 | SEC-020 | Medium | 8.0 | Engine Finished verification failure is non-fatal | `engine.zig` | CWE-287 / A07:2021 | `engine.zig:768-792` | [#97](https://gitlab.com/devnw/zig/tls/-/issues/97) | Finished failure now returns `error.HandshakeFailure`; prevents app data exchange | Claude | 2026-03-24 | Closed |
| 15 | SEC-021 | Medium | 8.0 | Engine cert validation failure non-fatal in processing loop | `engine.zig` | CWE-295 / A07:2021 | `engine.zig:621-765` | [#98](https://gitlab.com/devnw/zig/tls/-/issues/98) | Added `cert_ok` check to `handshakeComplete()`; cert failure now gates handshake | Claude | 2026-03-24 | Closed |
| 16 | SEC-008 | Medium | 7.0 | `x25519KeypairAndShared` missing sk zeroize on error (engine.zig) | `engine.zig` | CWE-226 / A02:2021 | `engine.zig:1723-1736` | -- | Added `defer std.crypto.secureZero` | Claude | 2026-03-24 | Closed |
| 17 | SEC-023 | Medium | 7.0 | `x25519KeypairAndShared` priv_key not zeroized on success path | `messages.zig` | CWE-226 / A02:2021 | `messages.zig:191-209` | [#76](https://gitlab.com/devnw/zig/tls/-/issues/76) | Added `defer secureZero(u8, &sk)` on all paths in messages.zig | Claude | 2026-03-24 | Closed |
| 18 | SEC-009 | Low | 6.0 | `x25519KeypairAndShared` returns value instead of error on failure | `messages.zig` | CWE-252 / A07:2021 | `messages.zig:201-205` | -- | Return an error union so callers can distinguish failure | -- | 180 days | Open |
| 19 | SEC-024 | Low | 5.0 | Certificate chain no depth limit | `x509.zig` | CWE-770 / A05:2021 | `x509.zig:1480` | [#99](https://gitlab.com/devnw/zig/tls/-/issues/99) | Added `max_chain_depth=10` guard before allocation in x509.zig | Claude | 2026-03-24 | Closed |
| 20 | SEC-025 | Low | 4.0 | EKU absent check not enforced (Engine) | `engine.zig` | CWE-295 / A07:2021 | `engine.zig:688-693` | [#100](https://gitlab.com/devnw/zig/tls/-/issues/100) | Added trace message for absent EKU; documented RFC 5280 compliant permissiveness | Claude | 2026-03-24 | Closed |
| 21 | SEC-026 | Low | 3.0 | OCSP `compareSlices` non-constant-time | `ocsp.zig` | CWE-208 / A02:2021 | `ocsp.zig:143` | [#101](https://gitlab.com/devnw/zig/tls/-/issues/101) | Switched to `timing_safe.compare` for defense-in-depth | Claude | 2026-03-24 | Closed |
| 22 | SEC-027 | Low | 3.0 | Engine CertificateVerify unknown scheme dead fallback | `engine.zig` | CWE-697 / A07:2021 | `engine.zig:744-748` | [#102](https://gitlab.com/devnw/zig/tls/-/issues/102) | Removed dead `.rsa_pss_sha256` fallback; replaced with `continue` | Claude | 2026-03-24 | Closed |
| 23 | SEC-010 | Low | 1.0 | OCSP digest comparison uses `std.mem.eql` | `ocsp.zig` | CWE-208 / A02:2021 | `ocsp.zig:140-141` | -- | Non-secret data; informational only | -- | Backlog | Open |
| 24 | SEC-011 | Low | 1.0 | Downgrade sentinel detection uses `std.mem.eql` | `server_hello.zig` | CWE-208 / A02:2021 | `server_hello.zig:145,167,189` | -- | Non-secret data; informational only | -- | Backlog | Open |
| 25 | SEC-012 | Low | 0.9 | Debug trace logs private key scalar (compile-guarded) | `sig.zig` | CWE-532 / A09:2021 | `sig.zig:564-566` | -- | Comptime guard is effective; acceptable | -- | Backlog | Open |
| 26 | SEC-013 | Low | 0.6 | `@intCast` in DER encoding (bounds-checked at runtime) | `sig.zig` | CWE-681 / A07:2021 | `sig.zig:620,624,634` | -- | P-256 lengths always fit u8; low risk | -- | Backlog | Open |
| 27 | SEC-014 | Low | 0.3 | Dead default algorithm `.rsa_pss_sha256` for unknown scheme | `engine.zig` | CWE-394 / A07:2021 | `engine.zig:744-748` | -- | Dead code path; no reachable impact | -- | Backlog | Open |

---

## Findings by Area

### Authentication and Signing

#### SEC-001: Client mTLS always signs with ed25519 (High, Risk 42.0) -- CLOSED

**Summary:** On the client side, `negotiated_signature` is never populated from the server's CertificateRequest message. It always defaults to `.ed25519`, causing any non-Ed25519 client key (ECDSA P-256, RSA-PSS) to produce an invalid signature or runtime error.

**Impact:** Client mTLS authentication fails silently or produces incorrect signatures for any key type other than Ed25519. An ECDSA P-256 client certificate will be signed with the wrong algorithm, causing the server to reject the CertificateVerify. This renders mTLS non-functional for the majority of real-world PKI deployments that use ECDSA or RSA keys.

**Likelihood:** Impact 3 (authentication failure / data integrity) x Likelihood 3.5 (any mTLS client with non-Ed25519 key) x 4 = 42.0. Requires mTLS to be configured, but once configured, the failure is deterministic for non-Ed25519 keys.

**Evidence:**

`src/tls13/context.zig:2691`:
```zig
const sig_scheme = self.negotiated_signature orelse .ed25519;
```

The server-side path correctly negotiates via `selectServerSignatureScheme()` at `context.zig:1574-1589`, which iterates server and client lists and sets `self.negotiated_signature`. But on the client path, the CertificateRequest handler never extracts the server's supported signature algorithms to populate `negotiated_signature`.

**Attack scenario:** A server requests client authentication with an ECDSA P-256 certificate. The client signs with Ed25519 algorithm regardless of the actual key type. The server rejects the CertificateVerify, causing a handshake failure. In the worst case, if a server is lenient, a mismatched algorithm could cause undefined cryptographic behavior.

**Fix guidance:**
1. Parse the `signature_algorithms` extension from the CertificateRequest message on the client side.
2. Match the client's private key type against the server's offered algorithms.
3. Set `self.negotiated_signature` to the matched scheme before reaching the signing code at line 2691.
4. Return `HandshakeError.NoSignatureScheme` if no compatible algorithm is found.

**Acceptance criteria:**
- Client mTLS succeeds with ECDSA P-256 certificates against OpenSSL/BoringSSL servers.
- Client mTLS succeeds with Ed25519 certificates.
- Handshake fails cleanly (not silently) when no compatible algorithm exists.
- Unit test covers each key type with a mock CertificateRequest.

**How to verify:** Run the existing `tests/conformance/openssl/mutual_tls.zig` and `tests/conformance/boringssl/mtls_format_parity.zig` with a P-256 client certificate. Currently expected to fail.

**References:** CWE-295 (Improper Certificate Validation), OWASP A07:2021 (Identification and Authentication Failures)

**Affected paths:** `src/tls13/context.zig`

**SLA:** 30 days

---

#### SEC-006: `else => .ed25519` signing fallback masks unknown schemes (Medium, Risk 14.0) -- CLOSED

**Summary:** Both server (`context.zig:2277`) and client (`context.zig:2697`) signing paths silently fall back to Ed25519 for any unrecognized `SignatureScheme` value. This masks negotiation bugs and could cause signing with the wrong algorithm.

**Impact:** If a new signature scheme is negotiated but not mapped in the switch, the code silently signs with Ed25519 instead of returning an error. This produces an invalid CertificateVerify that may be rejected by the peer, or worse, accepted by a permissive peer despite algorithm mismatch.

**Likelihood:** Impact 3.5 x Likelihood 1 (requires a scheme outside the enumerated set) x 4 = 14.0. Low likelihood because the negotiation code only selects from known schemes, but the fallback still violates fail-safe design.

**Evidence:**

`src/tls13/context.zig:2277`:
```zig
else => .ed25519, // Default fallback
```

`src/tls13/context.zig:2697`:
```zig
else => .ed25519,
```

**Fix guidance:** Replace `else => .ed25519` with `else => return error.UnsupportedSignatureScheme` in both locations.

**Acceptance criteria:**
- Unknown signature schemes produce an explicit error, not a silent fallback.
- All existing tests pass (no test relies on the fallback behavior).

**References:** CWE-394 (Unexpected Status Code or Return Value), OWASP A07:2021

**Affected paths:** `src/tls13/context.zig`

**SLA:** 90 days

---

#### SEC-020: Engine Finished verification failure is non-fatal (Medium, Risk 8.0)

**Summary:** In `engine.zig:768-792`, when the peer's Finished message fails verification, the result is stored via `self.updateFinishedVerified(ok)` but execution continues. If `ok` is `false`, the engine does not immediately abort the handshake. Application traffic secrets are only derived when `ok == true`, but the message processing loop continues.

**Impact:** If the Finished verification failure does not prevent application data exchange, an attacker who can tamper with handshake messages could bypass the Finished MAC check and inject/modify application data. The Finished message is the TLS 1.3 handshake integrity guarantee.

**Likelihood:** Impact 4 x Likelihood 0.5 (requires active MITM + must verify that `finished_verified` is not checked downstream) x 4 = 8.0

**Evidence:**

`src/tls13/engine.zig:768-792`:
```zig
if (p.typ == .finished and self.ecdhe_secret != null) {
    // ... verification logic ...
    traceHandshake("TLS: Finished verification result: {}\n", .{ok});
    self.updateFinishedVerified(ok);
    // Execution continues regardless of 'ok' value
    if (ok) {
        // derives application secrets...
    }
}
```

When `ok` is `false`, the function does not return an error. It continues processing subsequent messages.

**How to verify:** Trace all callers of `writeAppData` and `onRecvApplicationData` to verify they check `self.finished_verified`. If any path allows data exchange without checking, this is confirmed as CWE-287.

**Fix guidance:** Return an error immediately when Finished verification fails:
```zig
self.updateFinishedVerified(ok);
if (!ok) return error.FinishedVerificationFailed;
```

**Acceptance criteria:**
- Failed Finished verification produces an immediate error return.
- No application data can be sent or received after a Finished failure.
- Existing tests pass.

**References:** CWE-287 (Improper Authentication), OWASP A07:2021, RFC 8446 Section 4.4.4

**Affected paths:** `src/tls13/engine.zig`

**Issue:** [GitLab #97](https://gitlab.com/devnw/zig/tls/-/issues/97)

**SLA:** 90 days

---

#### SEC-021: Engine certificate validation failure non-fatal in processing loop (Medium, Risk 8.0)

**Summary:** In `engine.zig:621-765`, certificate parsing and validation failures set `self.peer_cert_ok = false` but do not return an error or break out of the message processing loop. The handshake continues processing subsequent messages (CertificateVerify, Finished) even when the certificate is invalid.

**Impact:** If certificate validation failure does not prevent the handshake from completing, an attacker could present an invalid certificate and still establish a connection. The `peer_cert_ok` flag may not be checked before application data exchange.

**Likelihood:** Impact 4 x Likelihood 0.5 (requires active MITM + must verify `peer_cert_ok` blocks data) x 4 = 8.0

**Evidence:**

`src/tls13/engine.zig:621-724`:
```zig
if (p.typ == .certificate) {
    if (self.allow_insecure) {
        self.peer_cert_ok = true;
    } else {
        self.peer_cert_ok = false;
        // ... validation attempts ...
        // All failures: break :blk false;
        self.peer_cert_ok = validation_ok;
    }
}
```

Multiple failure paths set `peer_cert_ok = false` but none return an error. Additionally, at line 688-693, missing EKU extension is silently accepted (see SEC-025).

**How to verify:** Trace whether `peer_cert_ok == false` prevents handshake completion and application data exchange. Check if any code path allows `writeAppData` when `peer_cert_ok == false`.

**Fix guidance:** Return an error immediately when certificate validation fails, or verify and document that `peer_cert_ok == false` prevents all data exchange.

**Acceptance criteria:**
- Certificate validation failure aborts the handshake or prevents data exchange.
- EKU absence is explicitly handled.
- Existing tests pass.

**References:** CWE-295 (Improper Certificate Validation), OWASP A07:2021, RFC 8446 Section 4.4.2

**Affected paths:** `src/tls13/engine.zig`

**Issue:** [GitLab #98](https://gitlab.com/devnw/zig/tls/-/issues/98)

**SLA:** 90 days

---

### Secret Lifecycle and Zeroization

#### SEC-002: `SecretSlot.clear()` in context.zig missing `secureZero` (High, Risk 32.0) -- CLOSED

**Summary:** The `SecretSlot.clear()` method in `context.zig` assigns `Secret.empty()` without first zeroizing the previous secret bytes. The correct implementation exists in `secrets.zig:79-80` which calls `std.crypto.secureZero(u8, &self.value.bytes)` before reassignment.

**Impact:** All TLS 1.3 traffic secrets (client/server handshake and application secrets) remain in process memory after `clear()` is called. If the process memory is later read (core dump, memory disclosure vulnerability, cold-boot attack), the traffic secrets can be recovered and used to decrypt recorded sessions.

**Likelihood:** Impact 4 (credential/key leak) x Likelihood 2 (requires memory access after clear) x 4 = 32.0

**Evidence:**

`src/tls13/context.zig:285-291` (VULNERABLE):
```zig
pub fn clear(self: *Self) void {
    self.value = Secret.empty();
    self.hash = .sha256;
    self.valid = false;
    self.generation = 0;
    self.epoch = .Initial;
}
```

`src/tls13/secrets.zig:79-80` (CORRECT):
```zig
pub fn clear(self: *Self) void {
    std.crypto.secureZero(u8, &self.value.bytes);
    self.value = Secret.empty();
    ...
}
```

**Fix guidance:** Add `std.crypto.secureZero(u8, &self.value.bytes);` as the first line of `SecretSlot.clear()` in `context.zig:285`, exactly matching the pattern in `secrets.zig`.

**Acceptance criteria:**
- `SecretSlot.clear()` in context.zig calls `secureZero` before reassignment.
- Unit test confirms bytes are zeroed after `clear()`.

**How to verify:** Add a test that stores a known secret, calls `clear()`, then inspects the backing memory via `@ptrCast` to confirm it is zeroed.

**References:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), OWASP A02:2021 (Cryptographic Failures)

**Affected paths:** `src/tls13/context.zig`

**SLA:** 30 days

---

#### SEC-003: ECDSA P-256 private key scalar not zeroized after signing (High, Risk 24.3) -- CLOSED

**Summary:** In `signCertificateVerify` for ECDSA P-256, the 32-byte private key scalar `sk` is allocated on the stack and never zeroized after use. The function returns without clearing this sensitive material.

**Impact:** The 32-byte ECDSA private key scalar remains on the stack after `signCertificateVerify` returns. Subsequent function calls may or may not overwrite this memory. If a memory disclosure vulnerability exists elsewhere, the private key can be recovered.

**Likelihood:** Impact 4 (private key leak) x Likelihood 1.5 (requires stack memory read) x 4 = 24.0 (rounded to 24.3 considering the signing function is called per-handshake).

**Evidence:**

`src/sig.zig:559`:
```zig
var sk: [32]u8 = undefined;
```

The `sk` variable is populated at lines 561-581 and used at line 590, but there is no `defer std.crypto.secureZero(u8, &sk);` anywhere in the ECDSA branch.

**Fix guidance:** Add `defer std.crypto.secureZero(u8, &sk);` immediately after the declaration at line 559.

**Acceptance criteria:**
- `sk` is zeroized via `secureZero` after every exit path from the ECDSA branch.
- Existing signing tests pass unchanged.

**How to verify:** Code review confirms `defer secureZero` is present. Optionally, a test can verify stack memory after calling the function in debug mode.

**References:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), OWASP A02:2021

**Affected paths:** `src/sig.zig`

**SLA:** 30 days

---

#### SEC-004: Ed25519 seed not zeroized after signing (High, Risk 24.3) -- CLOSED (partial)

**Summary:** In `signCertificateVerify` for Ed25519, the seed returned by `parsePkcs8Ed25519PrivateKey` was a `const` and was never zeroized. Fixed in cf6586c: seed is now `var` with `defer secureZero`. However, the derived `KeyPair` (containing the 64-byte expanded secret key) is still not zeroized -- see **SEC-004-R**.

**Impact:** The Ed25519 seed (32 bytes) is now properly zeroized. The expanded keypair secret key remains (see SEC-004-R).

**Evidence:**

`src/sig.zig:544-545` (FIXED for seed):
```zig
var seed = try parsePkcs8Ed25519PrivateKey(privkey_der);
defer std.crypto.secureZero(u8, &seed);
```

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/sig.zig`

**SLA:** 30 days

---

#### SEC-004-R: Ed25519 expanded KeyPair not zeroized after signing (High, Risk 14.0) -- CLOSED

**Summary:** The previous fix (cf6586c / SEC-004) only zeroized the Ed25519 seed. The expanded `KeyPair` generated at `sig.zig:547` is declared `const` and contains the 64-byte expanded secret key, which is NOT zeroized after use. This reopens the core concern of SEC-004.

**Impact:** The Ed25519 expanded secret key (64 bytes) persists on the stack after `signCertificateVerify` returns. If a memory disclosure vulnerability exists, or a core dump is captured, the full signing key can be recovered and used to forge CertificateVerify signatures, impersonating the TLS endpoint.

**Likelihood:** Impact 3.5 x Likelihood 1 (requires stack memory read after function return) x 4 = 14.0

**Evidence:**

`src/sig.zig:544-547`:
```zig
var seed = try parsePkcs8Ed25519PrivateKey(privkey_der);
defer std.crypto.secureZero(u8, &seed);  // seed IS zeroized (fix from cf6586c)
const kp = try Ed25519.KeyPair.generateDeterministic(seed);  // kp is NOT zeroized
```

The `kp` variable contains `KeyPair.secret_key` (64 bytes) plus the 32-byte public key. It is declared `const`, preventing `defer secureZero`.

**Attack scenario:**
1. Server uses Ed25519 certificate for TLS 1.3 authentication.
2. Attacker triggers a memory disclosure or captures a core dump.
3. Attacker reads the stack frame containing the un-zeroized 64-byte expanded secret key.
4. Attacker uses the recovered key to forge CertificateVerify signatures.

**Fix guidance:**
1. Change `const kp` to `var kp` at line 547.
2. Add `defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));` immediately after.

**Acceptance criteria:**
- `kp` is declared as `var` (not `const`).
- `defer std.crypto.secureZero(u8, std.mem.asBytes(&kp))` is present.
- Ed25519 signing tests pass without regression.
- Code review confirms all 96 bytes (64-byte secret + 32-byte public) are cleared.

**References:** CWE-226, OWASP A02:2021, RFC 8446 Section 7.1

**Affected paths:** `src/sig.zig:547`

**Issue:** [GitLab #84](https://gitlab.com/devnw/zig/tls/-/issues/84) (confidential)

**SLA:** 30 days (due 2026-04-23)

---

#### SEC-015: Context ECDHE server_priv not zeroized (High, Risk 14.0)

**Summary:** In the server-side handshake path in `context.zig`, the X25519 private key `server_priv` (32 bytes) used for ECDHE key exchange is never zeroized after use. It remains on the stack for the duration of `handleClientHello` and beyond.

**Impact:** The 32-byte X25519 ephemeral private key persists on the stack after the ECDHE computation. If an attacker can read process memory, they can recover this key and compute the shared secret, enabling decryption of the entire TLS session. This defeats forward secrecy for that session.

**Likelihood:** Impact 3.5 x Likelihood 1 (requires memory access after key exchange; long function extends exposure window) x 4 = 14.0

**Evidence:**

`src/tls13/context.zig:2153-2165`:
```zig
var server_priv: [32]u8 = undefined;
std.crypto.random.bytes(&server_priv);

const server_pub = std.crypto.dh.X25519.recoverPublicKey(server_priv) catch {
    return HandshakeError.UnsupportedKeyShareGroup;
};

var client_pub: [32]u8 = undefined;
@memcpy(&client_pub, ch_view.key_share.key[0..32]);

const shared = std.crypto.dh.X25519.scalarmult(server_priv, client_pub) catch {
    return HandshakeError.UnsupportedKeyShareGroup;
};
```

No `defer std.crypto.secureZero(u8, &server_priv);` exists. The private key is also NOT zeroized on error paths (lines 2157, 2164).

**Attack scenario:**
1. TLS server handles client connections using X25519 key exchange.
2. Attacker captures encrypted TLS traffic (passive recording).
3. Attacker later obtains a memory dump of the server process.
4. Attacker finds `server_priv` on the stack and computes the shared secret.
5. Attacker derives all session keys and decrypts the recorded traffic, defeating forward secrecy.

**Fix guidance:** Add `defer std.crypto.secureZero(u8, &server_priv);` immediately after line 2154.

**Acceptance criteria:**
- `defer secureZero` present after `server_priv` generation.
- Error paths also benefit from the defer.
- Handshake tests pass.

**References:** CWE-226, OWASP A02:2021, RFC 8446 Section 7.1

**Affected paths:** `src/tls13/context.zig:2153-2165`

**Issue:** [GitLab #87](https://gitlab.com/devnw/zig/tls/-/issues/87) (confidential)

**SLA:** 30 days (due 2026-04-23)

---

#### SEC-016: Context ECDHE shared secret not zeroized, server + client (High, Risk 13.0)

**Summary:** The X25519 shared secret computed during ECDHE key exchange in `context.zig` is never zeroized after use, on both the server path (line 2163) and the client path (line 2677). The shared secret is the root keying material for all session keys.

**Impact:** The 32-byte X25519 shared secret persists on the stack after being passed to `deriveHandshakeTraffic`. If an attacker can read process memory, they can derive all session keys and decrypt traffic.

**Likelihood:** Impact 3.5 x Likelihood 0.9 (both server and client paths affected; long functions extend exposure) x 4 = 12.6 (rounded to 13.0)

**Evidence:**

**Server path** -- `src/tls13/context.zig:2163`:
```zig
const shared = std.crypto.dh.X25519.scalarmult(server_priv, client_pub) catch {
    return HandshakeError.UnsupportedKeyShareGroup;
};
```

**Client path** -- `src/tls13/context.zig:2677`:
```zig
const shared = std.crypto.dh.X25519.scalarmult(priv, server_pub.?) catch return HandshakeError.UnsupportedKeyShareGroup;
const sh_snapshot = self.transcripts.handshake.finalize(self.hash_kind);
const hs = deriveHandshakeTraffic(self.hash_kind, shared[0..], sh_snapshot, &early_secret);
```

Neither location has `defer secureZero`.

**Fix guidance:** Change `const shared` to `var shared` on both paths and add `defer std.crypto.secureZero(u8, &shared);`.

**Acceptance criteria:**
- `shared` declared as `var` on both server and client ECDHE paths.
- `defer secureZero` present on both paths.
- Handshake tests (including mTLS) pass.

**References:** CWE-226, OWASP A02:2021, RFC 8446 Section 7.1

**Affected paths:** `src/tls13/context.zig:2163`, `src/tls13/context.zig:2677`

**Issue:** [GitLab #91](https://gitlab.com/devnw/zig/tls/-/issues/91) (confidential)

**SLA:** 30 days (due 2026-04-23)

---

#### SEC-008: `x25519KeypairAndShared` in engine.zig missing sk zeroize on error (Medium, Risk 7.0) -- CLOSED

**Summary:** The `x25519KeypairAndShared` function in `engine.zig` does not zeroize the private key `sk` when `scalarmult` fails. The corrected version in `messages.zig:201-205` does zeroize and returns a zeroed key struct.

**Impact:** On `scalarmult` failure, the X25519 private key remains in the returned struct and on the stack. The caller receives `shared = null` but still holds the unzeroized private key.

**Likelihood:** Impact 3.5 x Likelihood 0.5 (requires scalarmult to fail, which happens only with weak/invalid peer keys) x 4 = 7.0

**Evidence:**

`src/tls13/engine.zig:1729-1733` (VULNERABLE):
```zig
if (std.crypto.dh.X25519.scalarmult(&sh, sk, peer_pub)) {
    shared = sh;
} else shared = null;
```

`src/tls13/messages.zig:201-205` (CORRECT):
```zig
const sh = std.crypto.dh.X25519.scalarmult(sk, peer_pub) catch {
    std.crypto.secureZero(u8, &sk);
    return .{ .priv_key = [_]u8{0} ** 32, .pub_key = pk, .shared = null };
};
```

**Fix guidance:** Match the `messages.zig` pattern: zeroize `sk` on error and return a zeroed `priv_key`.

**Acceptance criteria:**
- On `scalarmult` failure, `sk` is zeroized and returned `priv_key` is all zeros.
- Function behavior matches `messages.zig` implementation.

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/tls13/engine.zig`

**SLA:** 90 days

---

#### SEC-023: `x25519KeypairAndShared` priv_key not zeroized on success path (Medium, Risk 7.0)

**Summary:** In `messages.zig`, the `x25519KeypairAndShared` function correctly zeroizes the private key on the error path (line 204), but on the success path (line 209) the stack-local `sk` variable is returned by value in the struct without being zeroized. The stack copy persists.

**Impact:** The private key remains on the stack after the function returns. While the caller receives a copy, the original stack variable is not cleared. In debug builds or with certain optimization levels, this material may be observable.

**Likelihood:** Impact 3.5 x Likelihood 0.5 (requires stack memory inspection) x 4 = 7.0

**Evidence:**

`src/tls13/messages.zig:191-209`:
```zig
pub fn x25519KeypairAndShared(peer_pub_opt: ?[32]u8) ... {
    var sk: [32]u8 = undefined;
    std.crypto.random.bytes(&sk);
    // No defer secureZero(u8, &sk) here
    // ...
    return .{ .priv_key = sk, .pub_key = pk, .shared = shared };
    // sk remains on stack un-zeroized
}
```

**Fix guidance:** Add `defer std.crypto.secureZero(u8, &sk);` after line 193. Zig copies values into the return struct before defer runs, so the caller still receives the key.

**Acceptance criteria:**
- `defer secureZero(u8, &sk)` added after key generation.
- Error path zeroization still functions correctly.
- Existing tests pass.

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/tls13/messages.zig`

**Issue:** [GitLab #76](https://gitlab.com/devnw/zig/tls/-/issues/76)

**SLA:** 90 days

---

### Resource Exhaustion and DoS

#### SEC-017: TicketStore unbounded growth (Medium, Risk 10.0)

**Summary:** The `TicketStore` in `engine.zig` has no upper bound on the number of stored session tickets. An attacker sending many NewSessionTicket messages can cause unbounded memory growth.

**Impact:** Memory exhaustion leading to OOM and process termination.

**Likelihood:** Impact 2.5 x Likelihood 1 (requires active TLS connection, but NewSessionTicket flood is trivial) x 4 = 10.0

**Evidence:**

`src/tls13/engine.zig:128-151`:
```zig
pub const TicketStore = struct {
    tickets: ArrayListUnmanaged(TicketEntry) = .{},
    pub fn store(self: *TicketStore, identity: []const u8, secret: Secret, lifetime: u32) !void {
        const ident_copy = try self.allocator.dupe(u8, identity);
        try self.tickets.append(self.allocator, .{ ... });
    }
};
```

No maximum capacity check, no eviction policy, no ticket expiry enforcement.

**Fix guidance:** Add `MAX_TICKETS` constant (e.g., 128) and FIFO eviction in `store()`. Zeroize evicted ticket secrets.

**Acceptance criteria:**
- `TicketStore` enforces a maximum number of tickets.
- Oldest tickets are evicted with secret zeroization.
- Session resumption tests pass.

**References:** CWE-770, OWASP A05:2021

**Affected paths:** `src/tls13/engine.zig:128-151`

**Issue:** [GitLab #93](https://gitlab.com/devnw/zig/tls/-/issues/93)

**SLA:** 90 days (due 2026-06-22)

---

#### SEC-018: CRYPTO inbound/inbox buffer unbounded (Medium, Risk 10.0)

**Summary:** Both `Context.processCrypto` and `Engine.onCryptoRecv` append incoming CRYPTO frame data to unbounded `ArrayList` buffers without size limits. A malicious peer can exhaust memory with oversized or never-completing handshake messages.

**Impact:** Memory exhaustion via oversized/fragmented CRYPTO frames.

**Likelihood:** Impact 2.5 x Likelihood 1 (trivial to send oversized CRYPTO frames) x 4 = 10.0

**Evidence:**

`src/tls13/context.zig:1033`:
```zig
try stream.inbound.appendSlice(self.allocator, data);
```

`src/tls13/engine.zig:437`:
```zig
try self.inbox.appendSlice(self.allocator, data);
```

**Fix guidance:** Add `MAX_HANDSHAKE_BUFFER` constant (e.g., 65536) and check before appending.

**Acceptance criteria:**
- Maximum buffer size enforced in both locations.
- Normal handshakes (including large certificate chains) still work.
- Oversized messages produce a clear error.

**References:** CWE-770, OWASP A05:2021

**Affected paths:** `src/tls13/context.zig:1033`, `src/tls13/engine.zig:437`

**Issue:** [GitLab #95](https://gitlab.com/devnw/zig/tls/-/issues/95)

**SLA:** 90 days (due 2026-06-22)

---

#### SEC-024: Certificate chain no depth limit (Low, Risk 5.0)

**Summary:** `validateChain` in `x509.zig` accepts certificate chains of arbitrary length. No maximum depth limit. Typical implementations limit to 10-20 (BoringSSL defaults to 7).

**Impact:** Excessive memory and CPU consumption from pathologically long certificate chains.

**Likelihood:** Impact 2.5 x Likelihood 0.5 x 4 = 5.0

**Evidence:**

`src/x509.zig:1480`:
```zig
pub fn validateChain(alloc: std.mem.Allocator, chain_der: []const []const u8, ...) !void {
    // No check on chain_der.len
    var certs = try alloc.alloc(Certificate, chain_der.len);
```

**Fix guidance:** Add `if (chain_der.len > MAX_CHAIN_DEPTH) return error.ChainTooLong;` with `MAX_CHAIN_DEPTH = 10`.

**References:** CWE-770, OWASP A05:2021

**Affected paths:** `src/x509.zig:1480`

**Issue:** [GitLab #99](https://gitlab.com/devnw/zig/tls/-/issues/99)

**SLA:** 180 days

---

### Configuration and Hardening

#### SEC-005: `allow_insecure` has no compile-time guard for release builds (Medium, Risk 16.0) -- CLOSED

**Summary:** The `allow_insecure` configuration field (`config.zig:271`) can be set to `true` in release builds without any compile-time warning or error. By contrast, `secret_trace_enabled` and `sig_trace_enabled` have `comptime` guards that emit `@compileError` in non-Debug builds.

**Impact:** A production deployment could accidentally ship with `allow_insecure = true`, disabling all certificate validation (chain, hostname, expiry). This would allow man-in-the-middle attacks against any TLS connection.

**Likelihood:** Impact 4 (complete certificate bypass) x Likelihood 1 (requires explicit misconfiguration) x 4 = 16.0. The field defaults to `false` and requires deliberate setting, but there is no safety net.

**Evidence:**

`src/tls13/config.zig:271`:
```zig
allow_insecure: bool = false,
```

Compare with `src/sig.zig:117-120`:
```zig
comptime {
    if (sig_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: sig_trace_enabled must be false in release builds - secrets would be logged!");
    }
}
```

No equivalent guard exists for `allow_insecure`.

**Fix guidance:** Since `allow_insecure` is a runtime config field (not a comptime constant), a `comptime` check cannot directly apply. Options:
1. Add a runtime warning log when `allow_insecure` is `true` in release mode.
2. Add a separate comptime constant `allow_insecure_override` that must be set to permit `allow_insecure = true` in release builds.
3. Document prominently that `allow_insecure` must never be used in production.

**Acceptance criteria:**
- Release builds with `allow_insecure = true` produce a visible warning or require an explicit opt-in.
- Default behavior (false) is unchanged.

**References:** CWE-1188 (Initialization with Hard-Coded Network Resource Configuration Data), OWASP A05:2021 (Security Misconfiguration)

**Affected paths:** `src/tls13/config.zig`

**SLA:** 90 days

---

#### SEC-019: Engine `allow_insecure` no release guard (Medium, Risk 9.0)

**Summary:** The `Engine.allow_insecure` field (engine.zig:207) has the same issue as SEC-005, but for the Engine API. The `Context` path was fixed (SEC-005) with a runtime panic guard, but the `Engine` path was not.

**Impact:** Same as SEC-005: production deployment with `allow_insecure = true` disables all certificate validation, enabling MITM attacks.

**Likelihood:** Impact 4.5 x Likelihood 0.5 (requires explicit misconfiguration) x 4 = 9.0

**Evidence:**

`src/tls13/engine.zig:207`:
```zig
allow_insecure: bool = false,
```

Doc comment warns against production use, but there is no programmatic guard.

**Fix guidance:** Add runtime panic or loud warning matching the `Context.init()` pattern.

**References:** CWE-295, OWASP A05:2021

**Affected paths:** `src/tls13/engine.zig:207`

**Issue:** [GitLab #96](https://gitlab.com/devnw/zig/tls/-/issues/96)

**SLA:** 90 days (due 2026-06-22)

---

#### SEC-025: EKU absent check not enforced (Low, Risk 4.0)

**Summary:** The Extended Key Usage check at `engine.zig:688-693` only rejects certificates where EKU is present but lacks `serverAuth`. Certificates with no EKU extension at all pass validation.

**Impact:** A certificate without any EKU (e.g., a CA certificate not intended for TLS server authentication) could be accepted as a server certificate.

**Likelihood:** Impact 2 x Likelihood 0.5 x 4 = 4.0

**Evidence:**

`src/tls13/engine.zig:688-693`:
```zig
if (leaf.eku) |eku| {
    if (!eku.server_auth) {
        break :blk false;
    }
}
// No else -- certificates without EKU extension are accepted
```

**Fix guidance:** Add `else` branch or document intentional permissiveness per RFC 5280 (which allows unrestricted use for certs without EKU).

**References:** CWE-295, RFC 5280 Section 4.2.1.12

**Affected paths:** `src/tls13/engine.zig:688-693`

**Issue:** [GitLab #100](https://gitlab.com/devnw/zig/tls/-/issues/100)

**SLA:** 180 days

---

### Certificate Revocation

#### SEC-007: No CRL checking; OCSP is optional (Medium, Risk 12.6)

**Summary:** The `validateChain` function in `x509.zig` does not perform any certificate revocation checking. CRL distribution points in certificates are ignored. OCSP stapling is handled separately and is optional (not enforced by default).

**Impact:** A revoked certificate (e.g., due to key compromise) will pass validation. The implementation explicitly documents this as a known limitation with mitigations.

**Likelihood:** Impact 3.5 (accepting compromised certificates) x Likelihood 0.9 (requires a revoked cert in the wild, which does occur) x 4 = 12.6

**Evidence:**

`src/x509.zig:1451-1479` documents the limitation explicitly:
```
This function does NOT perform certificate revocation checking.
...
A certificate that has been revoked by its CA may still pass validation
```

**Fix guidance:** This is a known architectural limitation. Recommended mitigations:
1. Make `require_ocsp` default to `true` for internet-facing deployments.
2. Document the limitation in the public API and deployment guides.
3. Long-term: implement CRL fetching or integrate with an external revocation service.

**Acceptance criteria:**
- `require_ocsp` enforcement is documented and easy to enable.
- Users are warned when operating without revocation checking on long-lived certificates.

**References:** CWE-299 (Improper Check for Certificate Revocation), OWASP A07:2021

**Affected paths:** `src/x509.zig`

**SLA:** 90 days

---

### Error Handling

#### SEC-009: `x25519KeypairAndShared` returns value instead of error on failure (Low, Risk 6.0)

**Summary:** When `scalarmult` fails in `messages.zig:201-205`, the function returns a struct with `shared = null` and a zeroed private key instead of returning an error. Callers must check for `null` shared secret rather than handling an error type.

**Impact:** A caller that does not check `shared == null` may proceed without a shared secret, potentially using uninitialized or zero key material for key derivation. The function's doc comment shows the correct usage pattern (`if (keys.shared) |secret|`).

**Likelihood:** Impact 3 x Likelihood 0.5 (requires caller to skip null check) x 4 = 6.0

**Evidence:**

`src/tls13/messages.zig:201-205`:
```zig
const sh = std.crypto.dh.X25519.scalarmult(sk, peer_pub) catch {
    std.crypto.secureZero(u8, &sk);
    return .{ .priv_key = [_]u8{0} ** 32, .pub_key = pk, .shared = null };
};
```

**Fix guidance:** Consider returning an error union `!struct{...}` so callers are forced to handle the error at compile time via Zig's error handling.

**References:** CWE-252 (Unchecked Return Value), OWASP A07:2021

**Affected paths:** `src/tls13/messages.zig`, `src/tls13/engine.zig`

**SLA:** 180 days

---

#### SEC-014: Dead default algorithm `.rsa_pss_sha256` for unknown scheme (Low, Risk 0.3)

**Summary:** In `engine.zig:744-748`, an unknown `SignatureScheme` value in a CertificateVerify message falls through to `.rsa_pss_sha256` as the default algorithm. However, the same branch immediately sets `peer_cert_ok = false`, making the algorithm assignment dead code.

**Impact:** No practical impact because verification is skipped when `peer_cert_ok` is false. The concern is code clarity and maintenance risk.

**Likelihood:** Impact 1 x Likelihood 0.075 x 4 = 0.3 (dead code path, no reachable impact)

**Evidence:**

`src/tls13/engine.zig:744-748`:
```zig
else => blk: {
    traceHandshake("TLS: Unknown SignatureScheme: 0x{X:0>4}\n", .{scheme_value});
    self.peer_cert_ok = false;
    break :blk .rsa_pss_sha256;
},
```

**Fix guidance:** Replace with `else => { self.peer_cert_ok = false; break :blk .ed25519; }` or better, return early. The specific algorithm value is irrelevant since verification is skipped.

**References:** CWE-394, OWASP A07:2021

**Affected paths:** `src/tls13/engine.zig`

**Issue:** [GitLab #102](https://gitlab.com/devnw/zig/tls/-/issues/102)

**SLA:** Backlog

---

### Timing and Side Channels

#### SEC-010: OCSP digest comparison uses `std.mem.eql` (Low, Risk 1.0)

**Summary:** The `compareSlices` function in `ocsp.zig:140-141` uses `std.mem.eql` for comparing OCSP response digests. Since OCSP digests are non-secret public data (certificate hashes), this is not a timing vulnerability.

**Impact:** None. The compared values are certificate digests that are already public.

**Likelihood:** Impact 1 x Likelihood 0.25 x 4 = 1.0

**Evidence:**

`src/ocsp.zig:140-141`:
```zig
pub fn compareSlices(expected: []const u8, actual: []const u8) bool {
    return expected.len == actual.len and std.mem.eql(u8, expected, actual);
}
```

**Fix guidance:** No action required. Documented for completeness. If defense-in-depth is desired, switch to `std.crypto.timing_safe.eql`, but this is not necessary for public data.

**References:** CWE-208 (Observable Timing Discrepancy), OWASP A02:2021

**Affected paths:** `src/ocsp.zig`

**SLA:** Backlog

---

#### SEC-026: OCSP `compareSlices` non-constant-time (Low, Risk 3.0)

**Summary:** Same as SEC-010 but captured from Phase 4 review with slightly higher risk score due to defense-in-depth considerations. The `compareSlices` function at `ocsp.zig:143` uses `std.mem.eql` for OCSP digest comparisons. While the data is non-secret, a constant-time comparison would be a stronger defense-in-depth practice.

**Impact:** Minimal. Non-secret data comparison.

**Likelihood:** Impact 1.5 x Likelihood 0.5 x 4 = 3.0

**Fix guidance:** Consider switching to `std.crypto.timing_safe.eql` for defense-in-depth.

**References:** CWE-208, OWASP A02:2021

**Affected paths:** `src/ocsp.zig:143`

**Issue:** [GitLab #101](https://gitlab.com/devnw/zig/tls/-/issues/101)

**SLA:** Backlog

---

#### SEC-027: Engine CertificateVerify unknown scheme dead fallback (Low, Risk 3.0)

**Summary:** See SEC-014. Captured separately as a code cleanliness finding from Phase 4 review. The dead `.rsa_pss_sha256` assignment for unknown signature schemes is confusing and could mask future bugs if the `peer_cert_ok = false` guard is accidentally removed.

**References:** CWE-697, OWASP A07:2021

**Affected paths:** `src/tls13/engine.zig:744-748`

**Issue:** [GitLab #102](https://gitlab.com/devnw/zig/tls/-/issues/102)

**SLA:** Backlog

---

#### SEC-011: Downgrade sentinel detection uses `std.mem.eql` (Low, Risk 1.0)

**Summary:** Downgrade sentinel checks in `server_hello.zig` use `std.mem.eql` to compare the last 8 bytes of the ServerHello random against known sentinel values. These sentinels are public constants defined in RFC 8446.

**Impact:** None. The sentinel values are public, well-known constants. Timing leakage does not benefit an attacker.

**Likelihood:** Impact 1 x Likelihood 0.25 x 4 = 1.0

**Evidence:**

`src/tls13/messages/server_hello.zig:145`:
```zig
return std.mem.eql(u8, &random, &HELLO_RETRY_REQUEST_RANDOM);
```

`src/tls13/messages/server_hello.zig:167`:
```zig
return std.mem.eql(u8, last_8, &TLS12_DOWNGRADE_SENTINEL);
```

`src/tls13/messages/server_hello.zig:189`:
```zig
return std.mem.eql(u8, last_8, &TLS11_DOWNGRADE_SENTINEL);
```

**Fix guidance:** No action required. Informational only.

**References:** CWE-208, OWASP A02:2021

**Affected paths:** `src/tls13/messages/server_hello.zig`

**SLA:** Backlog

---

### Logging and Debug

#### SEC-012: Debug trace logs private key scalar (compile-guarded) (Low, Risk 0.9)

**Summary:** When `sig_trace_enabled` is `true`, the ECDSA P-256 private key scalar is printed to stderr. This is properly guarded by a comptime check that produces `@compileError` in non-Debug builds.

**Impact:** In Debug builds with `sig_trace_enabled = true`, private key material is written to stderr. This is expected behavior for development debugging. The comptime guard prevents this from reaching release builds.

**Likelihood:** Impact 1.5 x Likelihood 0.15 (requires manually changing a const and building in debug mode) x 4 = 0.9

**Evidence:**

`src/sig.zig:564-566`:
```zig
if (sig_trace_enabled) {
    std.debug.print("[SIG] Successfully parsed PKCS#8, scalar: ", .{});
    for (sk) |b| std.debug.print("{x:0>2} ", .{b});
```

`src/sig.zig:117-120` (GUARD):
```zig
comptime {
    if (sig_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: sig_trace_enabled must be false in release builds - secrets would be logged!");
    }
}
```

**Fix guidance:** Acceptable as-is. The comptime guard is effective. Consider replacing the raw scalar print with a truncated hash for additional defense-in-depth, but this is not required.

**References:** CWE-532 (Insertion of Sensitive Information into Log File), OWASP A09:2021 (Security Logging and Monitoring Failures)

**Affected paths:** `src/sig.zig`

**SLA:** Backlog

---

### Integer Safety

#### SEC-013: `@intCast` in DER encoding (bounds-checked) (Low, Risk 0.6)

**Summary:** Three `@intCast` calls in the DER encoding section of `signCertificateVerify` cast `usize` values to `u8` for ASN.1 length encoding. These values are bounded by P-256 signature component sizes (max 33 bytes per component) and are further guarded by the `seq_len + 2 >= 128` check at line 615.

**Impact:** None in practice. P-256 signature components are always 32 bytes (with possible 1-byte padding), so the cast values are always in range [1, 33]. The guard at line 615 would catch any anomaly.

**Likelihood:** Impact 1 x Likelihood 0.15 x 4 = 0.6

**Evidence:**

`src/sig.zig:620`:
```zig
out[o] = @intCast(seq_len);
```
`src/sig.zig:624`:
```zig
out[o] = @intCast(r_len);
```
`src/sig.zig:634`:
```zig
out[o] = @intCast(s_len);
```

Guard at `src/sig.zig:615`:
```zig
if (seq_len + 2 >= 128) return error.Encode;
```

**Fix guidance:** No action required. The bounds are mathematically guaranteed for P-256 and additionally runtime-checked. Zig's `@intCast` will panic in safe modes if the value does not fit, providing defense-in-depth.

**References:** CWE-681 (Incorrect Conversion between Numeric Types), OWASP A07:2021

**Affected paths:** `src/sig.zig`

**SLA:** Backlog

---

## Roadmap

### Quick Wins (< 1 day)

| ID | Task | Effort | Status |
|----|------|--------|--------|
| SEC-002 | Add `secureZero` call to `SecretSlot.clear()` in context.zig | 15 min | Closed |
| SEC-003 | Add `defer secureZero` for ECDSA `sk` in sig.zig | 15 min | Closed |
| SEC-004 | Bind Ed25519 seed to `var` and add `defer secureZero` in sig.zig | 15 min | Closed |
| SEC-004-R | Change `const kp` to `var kp` and add `defer secureZero` for Ed25519 KeyPair | 15 min | Closed |
| SEC-006 | Replace `else => .ed25519` with error return in context.zig (2 locations) | 30 min | Closed |
| SEC-008 | Add `secureZero` on error path in engine.zig `x25519KeypairAndShared` | 15 min | Closed |
| SEC-015 | Add `defer secureZero(u8, &server_priv)` in context.zig | 15 min | Closed |
| SEC-016 | Change `const shared` to `var shared` + `defer secureZero` (2 locations) | 15 min | Closed |
| SEC-023 | Add `defer secureZero(u8, &sk)` after key generation in messages.zig | 15 min | Closed |
| SEC-019 | Add runtime panic for `allow_insecure` in Engine release builds | 30 min | Closed |
| SEC-024 | Add `MAX_CHAIN_DEPTH` check in x509.zig | 15 min | Closed |
| SEC-025 | Add EKU absent check or document intentional permissiveness | 15 min | Closed |
| SEC-027 | Clean up dead `.rsa_pss_sha256` fallback | 15 min | Closed |

### Medium Effort (1-5 days)

| ID | Task | Effort | Status |
|----|------|--------|--------|
| SEC-001 | Parse CertificateRequest signature_algorithms on client side, set `negotiated_signature` | 2-3 days | Closed |
| SEC-005 | Add runtime guard or comptime opt-in for `allow_insecure` in release builds | 1 day | Closed |
| SEC-009 | Refactor `x25519KeypairAndShared` to return error union | 1-2 days | Open |
| SEC-017 | Add max capacity + FIFO eviction to TicketStore | 1 day | Closed |
| SEC-018 | Add max buffer size to CRYPTO inbound buffers (2 locations) | 1 day | Closed |
| SEC-020 | Return error on Finished verification failure in Engine | 1-2 days | Closed |
| SEC-021 | Make cert validation failure fatal or verify `peer_cert_ok` gates data flow | 1-2 days | Closed |

### Strategic (> 5 days)

| ID | Task | Effort |
|----|------|--------|
| SEC-007 | Implement CRL distribution point fetching or mandatory OCSP enforcement | 5-10 days |

---

## Methodology

- **Manual code review** of all cryptographic signing, key derivation, and secret lifecycle paths.
- **Cross-reference** between duplicate implementations (context.zig vs secrets.zig SecretSlot, messages.zig vs engine.zig x25519).
- **Pattern matching** against CWE/OWASP categories for TLS implementations.
- **Comparison** with RFC 8446 requirements for signature algorithm negotiation and key zeroization.
- **Phase 4 additions**: ECDHE lifecycle audit (server_priv, shared secret), DoS surface analysis (TicketStore, buffer bounds), certificate validation flow analysis (Finished/cert failure handling).

## Confidence Notes

| ID | Confidence | What Would Confirm |
|----|------------|--------------------|
| SEC-001 | `confidence::confirmed` | Code path analysis shows `negotiated_signature` is never set on client side |
| SEC-002 | `confidence::confirmed` | Direct comparison with correct implementation in secrets.zig |
| SEC-003 | `confidence::confirmed` | Code review: no `secureZero` call on `sk` in ECDSA branch |
| SEC-004 | `confidence::confirmed` | Code review: `const seed` prevents zeroization |
| SEC-004-R | `confidence::confirmed` | Code review: `const kp` at sig.zig:547 prevents zeroization of expanded KeyPair |
| SEC-005 | `confidence::confirmed` | Grep confirms no comptime guard exists for `allow_insecure` |
| SEC-006 | `confidence::confirmed` | Direct code observation of `else => .ed25519` |
| SEC-007 | `confidence::confirmed` | Documented in x509.zig comments by the authors |
| SEC-008 | `confidence::confirmed` | Direct comparison with corrected messages.zig version |
| SEC-009 | `confidence::confirmed` | Function signature returns struct, not error union |
| SEC-010 | `confidence::confirmed` | Non-secret data; informational |
| SEC-011 | `confidence::confirmed` | Non-secret data; informational |
| SEC-012 | `confidence::confirmed` | Comptime guard verified present |
| SEC-013 | `confidence::confirmed` | Runtime bounds check verified present |
| SEC-014 | `confidence::confirmed` | `peer_cert_ok = false` makes algorithm assignment dead |
| SEC-015 | `confidence::confirmed` | `grep secureZero.*server_priv` returns no matches in context.zig |
| SEC-016 | `confidence::confirmed` | `grep secureZero.*shared` returns no matches in context.zig |
| SEC-017 | `confidence::confirmed` | No capacity check in TicketStore.store() |
| SEC-018 | `confidence::confirmed` | No size check before appendSlice in either location |
| SEC-019 | `confidence::confirmed` | No runtime guard on Engine.allow_insecure in release mode |
| SEC-020 | `confidence::suspected` | Need to verify if `finished_verified == false` blocks all data exchange |
| SEC-021 | `confidence::suspected` | Need to verify if `peer_cert_ok == false` blocks all data exchange |
| SEC-023 | `confidence::confirmed` | No defer secureZero on success path in x25519KeypairAndShared |
| SEC-024 | `confidence::confirmed` | No length check on chain_der before allocation |
| SEC-025 | `confidence::confirmed` | No `else` branch on EKU check at engine.zig:688 |
| SEC-026 | `confidence::suspected` | Non-secret data; defense-in-depth consideration |
| SEC-027 | `confidence::confirmed` | Dead code assignment after `peer_cert_ok = false` |
