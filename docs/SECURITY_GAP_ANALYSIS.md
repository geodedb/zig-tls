# Security Gap Analysis

> **Last updated:** 2026-03-24
> **Scope:** TLS 1.3/QUIC Implementation in Zig
> **Review phase:** Phase 3 -- Deep code audit of cryptographic operations, secret lifecycle, and signing paths

## Summary

| Risk Level | Open | Closed | Total |
|-----------|------|--------|-------|
| Critical  | 0    | 0      | 0     |
| High      | 0    | 4      | 4     |
| Medium    | 1    | 3      | 4     |
| Low       | 6    | 0      | 6     |
| **Total** | **7** | **7** | **14** |

**Immediate actions required:** 0 (all High-priority items closed)

### Top 5 Risks

1. ~~**SEC-001** -- Client mTLS always signs with ed25519 regardless of key type (Risk 42.0)~~ **CLOSED**
2. ~~**SEC-002** -- `SecretSlot.clear()` in context.zig does not zeroize old secret bytes (Risk 32.0)~~ **CLOSED**
3. ~~**SEC-003** -- ECDSA P-256 private key scalar not zeroized after signing (Risk 24.3)~~ **CLOSED**
4. ~~**SEC-004** -- Ed25519 seed not zeroized after signing (Risk 24.3)~~ **CLOSED**
5. ~~**SEC-005** -- `allow_insecure` has no compile-time guard for release builds (Risk 16.0)~~ **CLOSED**

---

## Stack-Ranked Findings

| Rank | ID | Severity | Risk Score | Finding | Component | CWE / OWASP | Evidence | Fix | Owner | Due | Status |
|------|----|----------|------------|---------|-----------|-------------|----------|-----|-------|-----|--------|
| 1 | SEC-001 | High | 42.0 | Client mTLS always signs with ed25519 | `context.zig` | CWE-295 / A07:2021 | `context.zig:2691` | Client mTLS now negotiates signature scheme from CertificateRequest; added scheme selection in client-side processing | Claude | 2026-03-24 | Closed |
| 2 | SEC-002 | High | 32.0 | `SecretSlot.clear()` missing `secureZero` | `context.zig` | CWE-226 / A02:2021 | `context.zig:285-291` | Added `std.crypto.secureZero` to `SecretSlot.clear()` matching secrets.zig pattern | Claude | 2026-03-24 | Closed |
| 3 | SEC-003 | High | 24.3 | ECDSA P-256 scalar not zeroized after signing | `sig.zig` | CWE-226 / A02:2021 | `sig.zig:559-645` | Added `defer std.crypto.secureZero(u8, &sk)` for P-256 private key | Claude | 2026-03-24 | Closed |
| 4 | SEC-004 | High | 24.3 | Ed25519 seed not zeroized after signing | `sig.zig` | CWE-226 / A02:2021 | `sig.zig:544-555` | Changed `const seed` to `var seed`; added `defer std.crypto.secureZero(u8, &seed)` | Claude | 2026-03-24 | Closed |
| 5 | SEC-005 | Medium | 16.0 | `allow_insecure` has no compile-time guard for release | `config.zig` | CWE-1188 / A05:2021 | `config.zig:271` | Added runtime panic guard in `Context.init()` preventing `allow_insecure=true` in non-Debug builds | Claude | 2026-03-24 | Closed |
| 6 | SEC-006 | Medium | 14.0 | `else => .ed25519` signing fallback masks unknown schemes | `context.zig` | CWE-394 / A07:2021 | `context.zig:2277,2697` | Replaced `else => .ed25519` with error returns in both paths; added client-side scheme negotiation from CertificateRequest | Claude | 2026-03-24 | Closed |
| 7 | SEC-007 | Medium | 12.6 | No CRL checking; OCSP is optional | `x509.zig` | CWE-299 / A07:2021 | `x509.zig:1451-1479` | Document limitation; add `require_ocsp` enforcement path | -- | 90 days | Open |
| 8 | SEC-008 | Medium | 7.0 | `x25519KeypairAndShared` missing sk zeroize on error (engine.zig) | `engine.zig` | CWE-226 / A02:2021 | `engine.zig:1723-1736` | Added `defer std.crypto.secureZero` for both `sk` and `sh` variables | Claude | 2026-03-24 | Closed |
| 9 | SEC-009 | Low | 6.0 | `x25519KeypairAndShared` returns value instead of error on failure | `messages.zig` | CWE-252 / A07:2021 | `messages.zig:201-205` | Return an error union so callers can distinguish failure | -- | 180 days | Open |
| 10 | SEC-010 | Low | 1.0 | OCSP digest comparison uses `std.mem.eql` | `ocsp.zig` | CWE-208 / A02:2021 | `ocsp.zig:140-141` | Non-secret data; constant-time not required. Informational only. | -- | Backlog | Open |
| 11 | SEC-011 | Low | 1.0 | Downgrade sentinel detection uses `std.mem.eql` | `server_hello.zig` | CWE-208 / A02:2021 | `server_hello.zig:145,167,189` | Non-secret data; constant-time not required. Informational only. | -- | Backlog | Open |
| 12 | SEC-012 | Low | 0.9 | Debug trace logs private key scalar (compile-guarded) | `sig.zig` | CWE-532 / A09:2021 | `sig.zig:564-566` | Already guarded by `sig_trace_enabled` comptime check. Acceptable. | -- | Backlog | Open |
| 13 | SEC-013 | Low | 0.6 | `@intCast` in DER encoding (bounds-checked at runtime) | `sig.zig` | CWE-681 / A07:2021 | `sig.zig:620,624,634` | P-256 lengths always fit u8; pre-checked by `seq_len + 2 >= 128` guard. Low risk. | -- | Backlog | Open |
| 14 | SEC-014 | Low | 0.3 | Dead default algorithm `.rsa_pss_sha256` for unknown scheme | `engine.zig` | CWE-394 / A07:2021 | `engine.zig:744-748` | Unknown scheme already sets `peer_cert_ok = false`. Dead code path. | -- | Backlog | Open |

---

## Findings by Area

### Authentication and Signing

#### SEC-001: Client mTLS always signs with ed25519 (High, Risk 42.0)

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

#### SEC-006: `else => .ed25519` signing fallback masks unknown schemes (Medium, Risk 14.0)

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

### Secret Lifecycle and Zeroization

#### SEC-002: `SecretSlot.clear()` in context.zig missing `secureZero` (High, Risk 32.0)

**Summary:** The `SecretSlot.clear()` method in `context.zig` assigns `Secret.empty()` without first zeroizing the previous secret bytes. This leaves traffic secret material in memory. The correct implementation exists in `secrets.zig:79-80` which calls `std.crypto.secureZero(u8, &self.value.bytes)` before reassignment.

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

#### SEC-003: ECDSA P-256 private key scalar not zeroized after signing (High, Risk 24.3)

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

#### SEC-004: Ed25519 seed not zeroized after signing (High, Risk 24.3)

**Summary:** In `signCertificateVerify` for Ed25519, the seed returned by `parsePkcs8Ed25519PrivateKey` is a `const` (returned by value) and is never zeroized. The derived `KeyPair` also contains the secret key and is not zeroized.

**Impact:** The Ed25519 seed (32 bytes) and derived keypair secret key remain on the stack after signing. Same memory disclosure risk as SEC-003.

**Likelihood:** Impact 4 x Likelihood 1.5 x 4 = 24.0 (rounded to 24.3).

**Evidence:**

`src/sig.zig:544-546`:
```zig
const seed = try parsePkcs8Ed25519PrivateKey(privkey_der);
const kp = try Ed25519.KeyPair.generateDeterministic(seed);
```

Neither `seed` nor `kp` is zeroized. The `seed` is declared as `const`, preventing a simple `defer secureZero` without first binding it to a mutable variable.

**Fix guidance:**
1. Change `const seed` to `var seed` so it can be zeroized.
2. Add `defer std.crypto.secureZero(u8, &seed);`.
3. Bind `kp` to `var` and add `defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));`.

**Acceptance criteria:**
- Both seed and keypair are zeroized on all exit paths.
- Ed25519 signing tests pass unchanged.

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/sig.zig`

**SLA:** 30 days

---

#### SEC-008: `x25519KeypairAndShared` in engine.zig missing sk zeroize on error (Medium, Risk 7.0)

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

### Configuration and Hardening

#### SEC-005: `allow_insecure` has no compile-time guard for release builds (Medium, Risk 16.0)

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
| SEC-006 | Replace `else => .ed25519` with error return in context.zig (2 locations) | 30 min | Closed |
| SEC-008 | Add `secureZero` on error path in engine.zig `x25519KeypairAndShared` | 15 min | Closed |

### Medium Effort (1-5 days)

| ID | Task | Effort | Status |
|----|------|--------|--------|
| SEC-001 | Parse CertificateRequest signature_algorithms on client side, set `negotiated_signature` | 2-3 days | Closed |
| SEC-005 | Add runtime guard or comptime opt-in for `allow_insecure` in release builds | 1 day | Closed |
| SEC-009 | Refactor `x25519KeypairAndShared` to return error union | 1-2 days | Open |

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

## Confidence Notes

| ID | Confidence | What Would Confirm |
|----|------------|--------------------|
| SEC-001 | `confidence::confirmed` | Code path analysis shows `negotiated_signature` is never set on client side |
| SEC-002 | `confidence::confirmed` | Direct comparison with correct implementation in secrets.zig |
| SEC-003 | `confidence::confirmed` | Code review: no `secureZero` call on `sk` in ECDSA branch |
| SEC-004 | `confidence::confirmed` | Code review: `const seed` prevents zeroization |
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
