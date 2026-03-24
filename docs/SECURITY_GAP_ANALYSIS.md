# Security Gap Analysis

> **Last updated:** 2026-03-24
> **Scope:** TLS 1.3/QUIC Implementation in Zig
> **Review phase:** Phase 8 -- Closure round: SEC-040, SEC-046, SEC-047, SEC-048 closed

## Summary

| Risk Level | Open | Closed | Total |
|-----------|------|--------|-------|
| Critical  | 0    | 0      | 0     |
| High      | 0    | 10     | 10    |
| Medium    | 0    | 15     | 15    |
| Low       | 5    | 14     | 19    |
| Info      | 3    | 1      | 4     |
| **Total** | **8** | **40** | **48** |

**Phase 8** closed the remaining HIGH finding (SEC-047) and 3 Low findings (SEC-040, SEC-046, SEC-048). All Phase 6-7 closures remain valid. Zero HIGH/Critical items remain open.

### Top 5 Risks (Open -- Remaining)

1. **SEC-038** -- Global mutable TrustStore creates theoretical TOCTOU window (Risk 12, Info) -- Benign; Zig lacks dynamic library unloading
2. **SEC-039** -- Handshake trace may leak error details in production (Risk 8, Info) -- Add compileError guard matching secret trace pattern
3. **SEC-009** -- x25519KeypairAndShared returns value instead of error on failure (Risk 6, Low) -- Return an error union
4. **SEC-045** -- `@ptrCast` on PSK binder/identity bypasses type safety (Risk 2, Info) -- Replace with explicit field-by-field conversion
5. **SEC-010** -- OCSP digest comparison uses std.mem.eql (Risk 1, Info) -- Non-secret data; informational only

### Phase 8 Closures

- **SEC-047** -- **CLOSED** (HIGH): Engine `computeApplicationSecrets` now uses `emptyHash()` for context and `zeroSecret()` for IKM per RFC 8446 Section 7.1. Fixed at `engine.zig:1510-1516`.
- **SEC-040** -- **CLOSED** (Low): `startClientHandshake` now has explicit X25519 clamping at `context.zig:2181-2187`. [Issue #126](https://gitlab.com/devnw/zig/tls/-/issues/126)
- **SEC-048** -- **CLOSED** (Low): Server `negotiateCipherAndKeys` now has explicit X25519 clamping at `context.zig:1959-1965`. [Issue #127](https://gitlab.com/devnw/zig/tls/-/issues/127)
- **SEC-046** -- **CLOSED** (Low): PSK identity comparison now uses `timing_safe.compare` at `context.zig:1825`.

### Phase 7 Closures (Security Reviewer)

- **SEC-042** -- **CLOSED**: `deriveHandshakeTraffic` intermediates now zeroized via `defer std.crypto.secureZero` on `derived.bytes`
- **SEC-043** -- **CLOSED**: `deriveApplicationTraffic` intermediates now zeroized via `defer std.crypto.secureZero` on `derived.bytes` and `master.bytes`
- **SEC-041** -- **CLOSED**: `expandLabelHash` PRK copy now zeroized via `defer std.crypto.secureZero` on `arr` in both sha256/sha384 branches
- **SEC-044** -- **CLOSED**: `expandLabelHash` fbb buffer now zeroized via `defer std.crypto.secureZero` on `fbb`
- **SEC-045** -- OPEN (Info): `@ptrCast` on PSK binder/identity bypasses type safety at `context.zig:506,512,514`

### Recently Closed (Phase 6 -- Round 3)

- **SEC-028** -- CLOSED: Client validates server-selected cipher suite against offered list in `context.zig:2511-2522`
- **SEC-029** -- CLOSED: `MissingServerName` error returned when `server_name` is null in `context.zig:2955`, `types.zig`, `alert.zig`
- **SEC-030** -- CLOSED: Self-signed cert now gets hostname and EKU validation in `x509.zig:1567-1572`
- **SEC-031** -- CLOSED: mTLS client cert validated for `clientAuth` EKU via `EkuPurpose` enum in `x509.zig:321-332`, `context.zig:3172`, `engine.zig`, `parallel.zig`
- **SEC-032** -- CLOSED: `validateTimeFields` validates month/day/hour/min/sec ranges in `x509.zig:603-612`
- **SEC-033** -- CLOSED: `matchesNameConstraint` uses `toLowerAscii` case-insensitive comparison in `x509.zig:1131-1151`
- **SEC-034** -- CLOSED: Dependency pinned to commit SHA `bbf106dc8131` in `build.zig.zon:38`
- **SEC-035** -- CLOSED: HRR `session_id` bounds-checked: `if (pos + 1 + sid_len > body.len)` in `context.zig:1456`
- **SEC-036** -- CLOSED: Old `client_priv` zeroized via `secureZero` before HRR rekey in `context.zig:1534-1538`
- **SEC-037** -- CLOSED: Explicit X25519 clamping (`priv[0] &= 248; priv[31] &= 127; priv[31] |= 64`) in `context.zig:1543-1549`

### Previously Closed (Phases 1-5)

- **SEC-014** -- CLOSED (Phase 5): Duplicate of SEC-027. Dead `.rsa_pss_sha256` fallback already removed; `engine.zig:836-840` now uses `continue`. Resolved by SEC-027 closure.
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
| 1 | SEC-029 | High | 80 | Hostname validation silently skipped when server_name is null | `context.zig`, `x509.zig` | CWE-295 / A07:2021 | `context.zig:2955`, `types.zig:218` | -- | Fail-closed: MissingServerName error when server_name is null | Claude | 2026-03-24 | Closed |
| 2 | SEC-028 | High | 64 | Client does not validate server-selected cipher suite was in offered list | `context.zig` | CWE-757 / A02:2021 | `context.zig:2511-2522` | -- | Cipher suite validated against offered list per RFC 8446 Section 4.1.3 | Claude | 2026-03-24 | Closed |
| 3 | SEC-030 | Medium | 48 | Self-signed cert bypasses EKU, hostname, and KeyUsage checks | `x509.zig` | CWE-295, CWE-863 / A07:2021 | `x509.zig:1567-1572` | -- | Hostname and EKU checks now applied to self-signed certs | Claude | 2026-03-24 | Closed |
| 4 | SEC-032 | Medium | 48 | parseDerTime accepts invalid month/day values | `x509.zig` | CWE-1284, CWE-125 / A07:2021 | `x509.zig:603-612` | -- | validateTimeFields validates month/day/hour/min/sec ranges | Claude | 2026-03-24 | Closed |
| 5 | SEC-033 | Medium | 48 | matchesNameConstraint uses case-sensitive comparison | `x509.zig` | CWE-178 / A07:2021 | `x509.zig:1131-1151` | -- | Uses toLowerAscii case-insensitive comparison per RFC 5280 Section 4.2.1.10 | Claude | 2026-03-24 | Closed |
| 6 | SEC-001 | High | 42.0 | Client mTLS always signs with ed25519 | `context.zig` | CWE-295 / A07:2021 | `context.zig:2691` | -- | Client mTLS now negotiates signature scheme from CertificateRequest | Claude | 2026-03-24 | Closed |
| 7 | SEC-047 | High | 36 | Engine computeApplicationSecrets uses wrong context hash and IKM for master secret | `engine.zig` | CWE-327 / A02:2021 | `engine.zig:1510-1516` | [#123](https://gitlab.com/devnw/zig/tls/-/issues/123) (confidential) | Uses `emptyHash()` for context and `zeroSecret()` for IKM per RFC 8446 S7.1 | Claude | 2026-03-24 | Closed |
| 8 | SEC-031 | Medium | 36 | mTLS client cert validation skips clientAuth EKU check | `context.zig`, `x509.zig` | CWE-295 / A07:2021 | `x509.zig:321-332`, `context.zig:3172` | -- | EkuPurpose enum added; validateChain passes .client_auth for mTLS | Claude | 2026-03-24 | Closed |
| 9 | SEC-034 | Medium | 32 | Dependency fetched from mutable main branch URL | `build.zig.zon` | CWE-829 / A08:2021 | `build.zig.zon:38` | -- | Dependency pinned to commit SHA bbf106dc8131 | Claude | 2026-03-24 | Closed |
| 10 | SEC-002 | High | 32.0 | `SecretSlot.clear()` missing `secureZero` | `context.zig` | CWE-226 / A02:2021 | `context.zig:285-291` | -- | Added `std.crypto.secureZero` to `SecretSlot.clear()` | Claude | 2026-03-24 | Closed |
| 11 | SEC-003 | High | 24.3 | ECDSA P-256 scalar not zeroized after signing | `sig.zig` | CWE-226 / A02:2021 | `sig.zig:559-645` | -- | Added `defer std.crypto.secureZero(u8, &sk)` | Claude | 2026-03-24 | Closed |
| 12 | SEC-004 | High | 24.3 | Ed25519 seed not zeroized after signing | `sig.zig` | CWE-226 / A02:2021 | `sig.zig:544-555` | -- | Seed zeroized; **keypair NOT zeroized** (see SEC-004-R) | Claude | 2026-03-24 | Closed (partial) |
| 13 | SEC-035 | Low | 24 | HRR session_id length not bounds-checked against body.len | `context.zig` | CWE-120 / A07:2021 | `context.zig:1456` | -- | Bounds check added: `if (pos + 1 + sid_len > body.len)` | Claude | 2026-03-24 | Closed |
| 14 | SEC-005 | Medium | 16.0 | `allow_insecure` no compile-time guard for release | `config.zig` | CWE-1188 / A05:2021 | `config.zig:271` | -- | Added runtime panic guard in `Context.init()` | Claude | 2026-03-24 | Closed |
| 15 | SEC-036 | Low | 16 | Client private key not zeroized on HRR rekey path | `context.zig` | CWE-226 / A02:2021 | `context.zig:1534-1538` | -- | Old client_priv secureZero'd before HRR rekey overwrite | Claude | 2026-03-24 | Closed |
| 16 | SEC-006 | Medium | 14.0 | `else => .ed25519` signing fallback masks unknown schemes | `context.zig` | CWE-394 / A07:2021 | `context.zig:2277,2697` | -- | Replaced with error returns | Claude | 2026-03-24 | Closed |
| 17 | SEC-004-R | High | 14.0 | Ed25519 expanded KeyPair not zeroized after signing | `sig.zig` | CWE-226 / A02:2021 | `sig.zig:547` | [#84](https://gitlab.com/devnw/zig/tls/-/issues/84) | Changed `const kp` to `var kp`; added `defer secureZero(u8, &kp.secret_key.bytes)` | Claude | 2026-03-24 | Closed |
| 18 | SEC-015 | High | 14.0 | Context ECDHE `server_priv` not zeroized | `context.zig` | CWE-226 / A02:2021 | `context.zig:2153` | [#87](https://gitlab.com/devnw/zig/tls/-/issues/87) | Added `defer secureZero(u8, &server_priv)` in context.zig | Claude | 2026-03-24 | Closed |
| 19 | SEC-016 | High | 13.0 | Context ECDHE shared secret not zeroized (server+client) | `context.zig` | CWE-226 / A02:2021 | `context.zig:2163,2677` | [#91](https://gitlab.com/devnw/zig/tls/-/issues/91) | Changed `const shared` to `var shared`; added `defer secureZero` on both paths | Claude | 2026-03-24 | Closed |
| 20 | SEC-007 | Medium | 12.6 | No CRL checking; OCSP is optional | `x509.zig` | CWE-299 / A07:2021 | `x509.zig:1451-1479` | -- | Document limitation; add `require_ocsp` enforcement path | -- | 90 days | Closed |
| 21 | SEC-037 | Low | 12 | sendClientHello2 does not explicitly clamp X25519 private key | `context.zig` | CWE-326 / A02:2021 | `context.zig:1543-1549` | -- | Explicit X25519 clamping added (priv[0]&=248, priv[31]&=127|=64) | Claude | 2026-03-24 | Closed |
| 22 | SEC-038 | Info | 12 | Global mutable TrustStore creates theoretical TOCTOU window | `x509.zig` | CWE-367 / A04:2021 | `x509.zig:134-155` | -- | Benign; Zig lacks dynamic library unloading | -- | Backlog | Open |
| 23 | SEC-017 | Medium | 10.0 | TicketStore unbounded growth (DoS) | `engine.zig` | CWE-770 / A05:2021 | `engine.zig:128-151` | [#93](https://gitlab.com/devnw/zig/tls/-/issues/93) | Added max_tickets=16 with FIFO eviction; secrets zeroized on eviction | Claude | 2026-03-24 | Closed |
| 24 | SEC-018 | Medium | 10.0 | CRYPTO inbound/inbox buffer unbounded (Context + Engine) | `context.zig`, `engine.zig` | CWE-770 / A05:2021 | `context.zig:1033`, `engine.zig:437` | [#95](https://gitlab.com/devnw/zig/tls/-/issues/95) | Added 64KB MAX_HANDSHAKE_BUFFER limit in both context.zig and engine.zig | Claude | 2026-03-24 | Closed |
| 25 | SEC-019 | Medium | 9.0 | Engine `allow_insecure` no release guard | `engine.zig` | CWE-295 / A05:2021 | `engine.zig:207` | [#96](https://gitlab.com/devnw/zig/tls/-/issues/96) | Added `setAllowInsecure` with `@panic` in release builds matching Context pattern | Claude | 2026-03-24 | Closed |
| 26 | SEC-040 | Low | 8 | `startClientHandshake` missing X25519 clamping | `context.zig` | CWE-326 / A02:2021 | `context.zig:2181-2187` | [#126](https://gitlab.com/devnw/zig/tls/-/issues/126) | Explicit X25519 clamping added (priv[0]&=248, priv[31]&=127|=64) | Claude | 2026-03-24 | Closed |
| 27 | SEC-039 | Info | 8 | Handshake trace may leak error details in production | `context.zig` | CWE-209 / A09:2021 | `context.zig:2950,3146` | -- | Add `@compileError` guard matching secret trace pattern | -- | Backlog | Open |
| 28 | SEC-020 | Medium | 8.0 | Engine Finished verification failure is non-fatal | `engine.zig` | CWE-287 / A07:2021 | `engine.zig:768-792` | [#97](https://gitlab.com/devnw/zig/tls/-/issues/97) | Finished failure now returns `error.HandshakeFailure`; prevents app data exchange | Claude | 2026-03-24 | Closed |
| 29 | SEC-021 | Medium | 8.0 | Engine cert validation failure non-fatal in processing loop | `engine.zig` | CWE-295 / A07:2021 | `engine.zig:621-765` | [#98](https://gitlab.com/devnw/zig/tls/-/issues/98) | Added `cert_ok` check to `handshakeComplete()`; cert failure now gates handshake | Claude | 2026-03-24 | Closed |
| 30 | SEC-008 | Medium | 7.0 | `x25519KeypairAndShared` missing sk zeroize on error (engine.zig) | `engine.zig` | CWE-226 / A02:2021 | `engine.zig:1723-1736` | -- | Added `defer std.crypto.secureZero` | Claude | 2026-03-24 | Closed |
| 31 | SEC-023 | Medium | 7.0 | `x25519KeypairAndShared` priv_key not zeroized on success path | `messages.zig` | CWE-226 / A02:2021 | `messages.zig:191-209` | [#76](https://gitlab.com/devnw/zig/tls/-/issues/76) | Added `defer secureZero(u8, &sk)` on all paths in messages.zig | Claude | 2026-03-24 | Closed |
| 32 | SEC-046 | Low | 6 | PSK identity comparison non-constant-time | `context.zig` | CWE-208 / A02:2021 | `context.zig:1825` | -- | Replaced `std.mem.eql` with `timing_safe.compare` for PSK identity lookup | Claude | 2026-03-24 | Closed |
| 33 | SEC-048 | Low | 6 | Server `negotiateCipherAndKeys` missing X25519 clamping | `context.zig` | CWE-326 / A02:2021 | `context.zig:1959-1965` | [#127](https://gitlab.com/devnw/zig/tls/-/issues/127) | Explicit X25519 clamping added (priv[0]&=248, priv[31]&=127|=64) | Claude | 2026-03-24 | Closed |
| 34 | SEC-009 | Low | 6.0 | `x25519KeypairAndShared` returns value instead of error on failure | `messages.zig` | CWE-252 / A07:2021 | `messages.zig:201-205` | -- | Return an error union so callers can distinguish failure | -- | 180 days | Open |
| 35 | SEC-024 | Low | 5.0 | Certificate chain no depth limit | `x509.zig` | CWE-770 / A05:2021 | `x509.zig:1480` | [#99](https://gitlab.com/devnw/zig/tls/-/issues/99) | Added `max_chain_depth=10` guard before allocation in x509.zig | Claude | 2026-03-24 | Closed |
| 36 | SEC-042 | Low | 4 | `deriveHandshakeTraffic` intermediates not zeroized | `key_derivation.zig` | CWE-226 / A02:2021 | `key_derivation.zig:218-222` | -- | Added `defer std.crypto.secureZero(u8, &derived.bytes)` | Claude | 2026-03-24 | **Closed** |
| 37 | SEC-043 | Low | 4 | `deriveApplicationTraffic` intermediates not zeroized | `key_derivation.zig` | CWE-226 / A02:2021 | `key_derivation.zig:340-351` | -- | Added `defer std.crypto.secureZero` on `derived.bytes` and `master.bytes` | Claude | 2026-03-24 | **Closed** |
| 38 | SEC-025 | Low | 4.0 | EKU absent check not enforced (Engine) | `engine.zig` | CWE-295 / A07:2021 | `engine.zig:688-693` | [#100](https://gitlab.com/devnw/zig/tls/-/issues/100) | Added trace message for absent EKU; documented RFC 5280 compliant permissiveness | Claude | 2026-03-24 | Closed |
| 39 | SEC-041 | Low | 3 | `expandLabelHash` PRK copy not zeroized | `key_schedule.zig` | CWE-226 / A02:2021 | `key_schedule.zig:143-150` | -- | Added `defer std.crypto.secureZero(u8, &arr)` in both sha256/sha384 branches | Claude | 2026-03-24 | **Closed** |
| 40 | SEC-026 | Low | 3.0 | OCSP `compareSlices` non-constant-time | `ocsp.zig` | CWE-208 / A02:2021 | `ocsp.zig:143` | [#101](https://gitlab.com/devnw/zig/tls/-/issues/101) | Switched to `timing_safe.compare` for defense-in-depth | Claude | 2026-03-24 | Closed |
| 41 | SEC-027 | Low | 3.0 | Engine CertificateVerify unknown scheme dead fallback | `engine.zig` | CWE-697 / A07:2021 | `engine.zig:744-748` | [#102](https://gitlab.com/devnw/zig/tls/-/issues/102) | Removed dead `.rsa_pss_sha256` fallback; replaced with `continue` | Claude | 2026-03-24 | Closed |
| 42 | SEC-045 | Info | 2 | `@ptrCast` on PSK binder/identity bypasses type safety | `context.zig` | CWE-843 / A07:2021 | `context.zig:506,512,514` | -- | Replace `@ptrCast` with explicit field-by-field conversion | -- | Backlog | **Open** |
| 43 | SEC-010 | Low | 1.0 | OCSP digest comparison uses `std.mem.eql` | `ocsp.zig` | CWE-208 / A02:2021 | `ocsp.zig:140-141` | -- | Non-secret data; informational only | -- | Backlog | Open |
| 44 | SEC-044 | Info | 1 | `expandLabelHash` fbb buffer not zeroized | `key_schedule.zig` | CWE-226 / A02:2021 | `key_schedule.zig:134` | -- | Added `defer std.crypto.secureZero(u8, &fbb)` | Claude | 2026-03-24 | **Closed** |
| 45 | SEC-011 | Low | 1.0 | Downgrade sentinel detection uses `std.mem.eql` | `server_hello.zig` | CWE-208 / A02:2021 | `server_hello.zig:145,167,189` | -- | Non-secret data; informational only | -- | Backlog | Open |
| 46 | SEC-012 | Low | 0.9 | Debug trace logs private key scalar (compile-guarded) | `sig.zig` | CWE-532 / A09:2021 | `sig.zig:564-566` | -- | Comptime guard is effective; acceptable | -- | Backlog | Open |
| 47 | SEC-013 | Low | 0.6 | `@intCast` in DER encoding (bounds-checked at runtime) | `sig.zig` | CWE-681 / A07:2021 | `sig.zig:620,624,634` | -- | P-256 lengths always fit u8; low risk | -- | Backlog | Open |
| 48 | SEC-014 | Low | 0.3 | Dead default algorithm `.rsa_pss_sha256` for unknown scheme | `engine.zig` | CWE-394 / A07:2021 | `engine.zig:744-748` | [#102](https://gitlab.com/devnw/zig/tls/-/issues/102) | Duplicate of SEC-027; resolved by SEC-027 closure | -- | -- | Closed |

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

#### SEC-007: No CRL checking; OCSP is optional (Medium, Risk 12.6) -- **Status: Closed**

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

**Resolution:** CRL limitation documented in 3 locations:
1. `src/x509.zig:1533-1564` -- comprehensive CRL limitation documentation with workarounds (already present)
2. `src/tls13/config.zig:252,267` -- `require_ocsp` field with documentation (already present)
3. `src/lib.zig` -- CRL limitation added to "Known Limitations" section and x509 module doc comment with SEC-007 reference, pointing users to `require_ocsp = true` mitigation

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

#### SEC-014: Dead default algorithm `.rsa_pss_sha256` for unknown scheme (Low, Risk 0.3) -- CLOSED

**Summary:** In `engine.zig:744-748`, an unknown `SignatureScheme` value in a CertificateVerify message falls through to `.rsa_pss_sha256` as the default algorithm. However, the same branch immediately sets `peer_cert_ok = false`, making the algorithm assignment dead code.

**Status:** Closed. Duplicate of SEC-027. The dead `.rsa_pss_sha256` fallback has been removed as part of SEC-027 remediation. `engine.zig:836-840` now uses `continue` to skip verification for unknown schemes, eliminating both the dead assignment and the confusing fallback.

**References:** CWE-394, OWASP A07:2021

**Affected paths:** `src/tls13/engine.zig`

**Issue:** [GitLab #102](https://gitlab.com/devnw/zig/tls/-/issues/102)

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

### Handshake Negotiation (Phase 5)

#### SEC-028: Client does not validate server-selected cipher suite was in offered list (High, Risk 64)

**Summary:** When the client receives a ServerHello, it accepts whatever cipher suite the server selected without verifying it was in the client's offered list. RFC 8446 Section 4.1.3 requires: "A client which receives a cipher suite that was not offered MUST abort the handshake with an 'illegal_parameter' alert."

**Impact:** A malicious server (or MITM attacker) can force the client to use any cipher suite, including potentially weaker ones that the client intentionally excluded. This undermines the client's security policy for cipher suite selection. Impact 4 (authentication/crypto bypass) x Likelihood 4 (remote, any TLS connection to rogue server) x 4 = 64.

**Likelihood:** Any client connecting to a malicious server is vulnerable. No authentication required. The attack surface is internet-facing.

**Evidence:**

`src/tls13/context.zig:2492-2494`:
```zig
const suite_value: u16 = readU16(body[pos .. pos + 2]);
const cipher_suite = std.meta.intToEnum(tls13_full.CipherSuite, suite_value) catch return HandshakeError.NoCipherSuite;
self.negotiated_cipher_suite = cipher_suite;
```

The code only checks that the value is a valid `CipherSuite` enum variant. It does not verify that this suite was in the list offered in the ClientHello.

**Attack scenario:**
1. Client offers only AES-256-GCM cipher suites in its ClientHello.
2. Malicious server responds with AES-128-GCM (weaker but still a valid enum value).
3. Client accepts the downgraded cipher suite without complaint.
4. All session traffic uses the weaker algorithm the client intended to exclude.

**Fix guidance:**
1. Store the list of cipher suites offered in the ClientHello (or reference the config).
2. After parsing `cipher_suite` from ServerHello, verify it appears in the offered list.
3. If not found, return `HandshakeError.IllegalParameter` and send an `illegal_parameter` alert.

**Acceptance criteria:**
- Client rejects ServerHello containing a cipher suite not in the offered list.
- Test: configure client with restricted cipher suite list, mock server responds with excluded suite, verify handshake fails with `IllegalParameter`.
- Normal handshakes with valid suite selection still succeed.

**How to verify:** Add test case in `tests/rfc8446/section_4_1_3_server_hello.zig` with a server that selects a non-offered suite.

**References:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation), OWASP A02:2021 (Cryptographic Failures), RFC 8446 Section 4.1.3

**Affected paths:** `src/tls13/context.zig`

**SLA:** 30 days

**Status: Closed** (2026-03-24) -- Added cipher suite validation against offered list at `context.zig:2511-2522`. After parsing the server-selected cipher suite, the code iterates `self.config.supported_cipher_suites` and returns `HandshakeError.NoCipherSuite` if the suite is not found.

---

#### SEC-029: Hostname validation silently skipped when server_name is null (High, Risk 80)

**Summary:** When the client's `config.server_name` is null, the code passes an empty string to `validateChain`. Inside `validateChain`, `matchDnsName` is only called when `server_name.len != 0`, meaning hostname validation is entirely skipped. Any valid certificate from any CA is accepted regardless of its subject. This is a fail-open design that enables MITM attacks.

**Impact:** An attacker with any valid certificate (e.g., obtained for a domain they control) can MITM connections from clients that have not set `server_name`. This is particularly dangerous because `server_name` defaults to null in the config, making unvalidated connections the default behavior. Impact 5 (complete authentication bypass / MITM) x Likelihood 4 (remote, requires client config omission) x 4 = 80.

**Likelihood:** Any client that does not explicitly set `server_name` is vulnerable. Internet-facing. The default configuration is the vulnerable state.

**Evidence:**

`src/tls13/context.zig:2934`:
```zig
const server_name = if (self.config.server_name) |sni| sni else "";
```

`src/x509.zig:1511`:
```zig
if (server_name.len != 0 and !matchDnsName(&certs[0], server_name)) return error.NameMismatch;
```

When `server_name` is `""`, the `server_name.len != 0` check is false, so `matchDnsName` is never called. Any certificate with a valid chain passes validation regardless of its subject/SAN.

**Attack scenario:**
1. Application creates TLS context without setting `server_name` (using default null).
2. Attacker obtains a valid certificate for `evil.com` from a public CA.
3. Attacker performs MITM on the connection, presenting the `evil.com` certificate.
4. Client validates the chain (it chains to a trusted CA) but never checks the hostname.
5. Connection succeeds; attacker can read and modify all traffic.

**Fix guidance:**
1. When `server_name` is null and `allow_insecure` is false, return an error from the client handshake path. Hostname validation must be mandatory for secure connections.
2. Alternatively, require `server_name` to be non-null in `Context.init()` when operating in secure mode.
3. Document that `server_name` is security-critical and must always be set.

**Acceptance criteria:**
- Client handshake with null `server_name` and `allow_insecure = false` produces a clear error.
- Client handshake with a valid `server_name` continues to work correctly.
- `allow_insecure = true` still allows null `server_name` for testing.

**How to verify:** Test that `Context.init()` or `processServerHello()` returns an error when `server_name` is null and `allow_insecure` is false.

**References:** CWE-295 (Improper Certificate Validation), OWASP A07:2021 (Identification and Authentication Failures), RFC 6125 Section 6

**Affected paths:** `src/tls13/context.zig`, `src/x509.zig`

**SLA:** 30 days

**Status: Closed** (2026-03-24) -- Added `MissingServerName` error variant to `types.zig:218` and alert mapping in `alert.zig:128`. When `server_name` is null and `allow_insecure` is false, `context.zig:2955` returns `HandshakeError.MissingServerName` instead of passing an empty string.

---

### Certificate Validation (Phase 5)

#### SEC-030: Self-signed cert bypasses EKU, hostname, and KeyUsage checks (Medium, Risk 48)

**Summary:** When `validateChain` encounters a single self-signed certificate (chain length 1, subject equals issuer), it skips hostname validation, EKU checking, and KeyUsage checking. Only validity period and the CA basic constraint are verified. This means a self-signed certificate for `evil.com` would be accepted when connecting to `example.com`.

**Impact:** Any self-signed trust anchor bypasses critical security checks. If a self-signed certificate is in the trust store, it is accepted regardless of hostname mismatch or inappropriate key usage. Impact 4 (authentication bypass for trust anchor scenario) x Likelihood 3 (requires self-signed cert in trust path; common in internal PKI) x 4 = 48.

**Likelihood:** Common in internal PKI deployments, development environments, and any scenario where self-signed certificates are used as trust anchors.

**Evidence:**

`src/x509.zig:1503-1526`:
```zig
const is_single_self_signed = chain_der.len == 1 and
    std.mem.eql(u8, certs[0].subject_der, certs[0].issuer_der);

// Leaf checks (skip for single self-signed certs which are trust anchors)
try checkValidity(now_unix, &certs[0]);

if (!is_single_self_signed) {
    if (server_name.len != 0 and !matchDnsName(&certs[0], server_name)) return error.NameMismatch;
    if (certs[0].eku) |eku| if (!eku.server_auth) return error.EkuNotAllowed;
    if (certs[0].ku) |ku| {
        if (!keyUsageHas(ku, key_usage_digital_signature)) return error.KuNotAllowed;
    }
    // ...
} else {
    // For self-signed roots, verify CA flag is set
    if (certs[0].basic) |b| {
        if (!b.ca) return error.BasicConstraints;
    }
}
```

The `if (!is_single_self_signed)` branch contains all hostname, EKU, and KeyUsage checks. The `else` branch only checks `CA=true`.

**Fix guidance:**
1. Apply hostname validation to self-signed certificates (remove the `is_single_self_signed` exemption for `matchDnsName`).
2. Consider applying EKU checks as well, or document the intentional exemption with a clear security rationale.
3. At minimum, hostname validation should never be skipped for any certificate type.

**Acceptance criteria:**
- Self-signed certificates are validated against `server_name`.
- Self-signed certificate with wrong hostname returns `NameMismatch`.
- Existing self-signed trust anchor tests updated to use matching hostnames.

**References:** CWE-295 (Improper Certificate Validation), CWE-863 (Incorrect Authorization), OWASP A07:2021, RFC 6125

**Affected paths:** `src/x509.zig`

**SLA:** 90 days

**Status: Closed** (2026-03-24) -- Moved hostname and EKU validation outside the `is_single_self_signed` guard at `x509.zig:1567-1572`. Self-signed certs now undergo hostname validation via `matchDnsName` and EKU checking via `checkEkuPurpose`. Only the chain-walk logic (intermediate CA checks, pathLen constraints) is skipped for single self-signed certs.

---

#### SEC-031: mTLS client cert validation skips clientAuth EKU check (Medium, Risk 36)

**Summary:** When the server validates client certificates during mTLS, it calls `validateChain` with an empty hostname (correct, since client certs have no hostname). However, `validateChain` only checks for `server_auth` EKU (line 1512). The mTLS path at `context.zig:3135-3148` does not add a separate `clientAuth` EKU check. A certificate with `serverAuth` EKU but without `clientAuth` EKU would pass validation as a client certificate.

**Impact:** Certificates not authorized for client authentication could be accepted. For example, a server certificate (with only `serverAuth` EKU) could be misused as a client certificate. Impact 3 (authorization bypass) x Likelihood 3 (requires mTLS deployment + cert with wrong EKU) x 4 = 36.

**Likelihood:** Requires mTLS to be configured. The impact depends on whether the environment has certificates with only `serverAuth` that could be presented as client certs.

**Evidence:**

`src/tls13/context.zig:3135-3148`:
```zig
if (!self.config.allow_insecure) {
    // RFC 5280 Section 6: Validate client certificate chain
    // Skip hostname validation for client certs (no SNI to match against)
    const now_unix = std.time.timestamp();
    x509.validateChain(
        self.allocator,
        chain,
        now_unix,
        "", // No hostname validation for client certs
        false, // Don't skip validation
    ) catch |err| {
        traceHandshake("Server: Client certificate chain validation failed: {}\n", .{err});
        return HandshakeError.CertificateValidationFailed;
    };
```

Inside `validateChain`, line 1512 checks `eku.server_auth`:
```zig
if (certs[0].eku) |eku| if (!eku.server_auth) return error.EkuNotAllowed;
```

No `clientAuth` EKU check is performed anywhere in the mTLS validation path.

**Fix guidance:**
1. Add an `eku_mode` parameter to `validateChain` (or a separate `validateClientChain` function) that checks `eku.client_auth` instead of `eku.server_auth` for client certificates.
2. Alternatively, add the `clientAuth` EKU check in the mTLS handler after `validateChain` returns.

**Acceptance criteria:**
- Client certificates with `clientAuth` EKU pass mTLS validation.
- Client certificates with only `serverAuth` EKU (no `clientAuth`) are rejected.
- Client certificates without any EKU still pass (per RFC 5280 permissiveness).

**References:** CWE-295 (Improper Certificate Validation), OWASP A07:2021, RFC 5280 Section 4.2.1.12

**Affected paths:** `src/tls13/context.zig`, `src/x509.zig`

**SLA:** 90 days

**Status: Closed** (2026-03-24) -- Added `EkuPurpose` enum (`server_auth`, `client_auth`) at `x509.zig:321-332` with `checkEkuPurpose` helper at `x509.zig:329-332`. `validateChain` now accepts an `eku_purpose` parameter. Server-side mTLS path at `context.zig:3172` passes `.client_auth`. Client-side path passes `.server_auth`. The `engine.zig` and `parallel.zig` call sites also updated.

---

### X.509 Parsing (Phase 5)

#### SEC-032: parseDerTime accepts invalid month/day values (Medium, Risk 48)

**Summary:** The `parseDerTime` function in `x509.zig` parses ASN.1 DER time values but does not validate that month and day values are within legal ranges. A month value of 14 or higher causes an out-of-bounds array access in `daysBeforeMonth`, where `mdays[m-1]` is accessed with `m=13` (index 12) on a 12-element array. In safe (debug) builds, this triggers a panic. In release builds (`ReleaseFast`/`ReleaseSmall`), this is undefined behavior.

**Impact:** Malformed certificates with invalid date fields can trigger UB in release builds or panics in debug builds. An attacker could craft a certificate with month=14 to crash the TLS handshake process. Impact 4 (denial of service / potential memory corruption in release) x Likelihood 3 (requires malformed cert to reach parser; pre-auth for server-presented certs) x 4 = 48.

**Likelihood:** Any TLS client that parses a malicious server certificate is exposed. The certificate does not need to be signed by a trusted CA to trigger the parsing code (parsing happens before chain validation).

**Evidence:**

`src/x509.zig:552-573` (no range check on month/day):
```zig
const month = try std.fmt.parseInt(u8, bytes[2..4], 10);
const day = try std.fmt.parseInt(u8, bytes[4..6], 10);
// ... no validation that month is in [1,12] or day is in [1,31]
return unixSecondsFromYMDHMS(year, month, day, hh, mm, ss);
```

`src/x509.zig:532-539` (OOB access path):
```zig
fn daysBeforeMonth(year: u16, month: u8) i64 {
    const mdays = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var d: i64 = 0;
    var m: u8 = 1;
    while (m < month) : (m += 1) {
        if (m == 2 and isLeap(year)) d += 29 else d += mdays[m - 1];
    }
    return d;
}
```

When `month >= 14`, the loop variable `m` reaches 13, and `mdays[13 - 1] = mdays[12]` is out of bounds (array has indices 0-11).

**Fix guidance:** Add validation at the start of `parseDerTime` or `unixSecondsFromYMDHMS`:
```zig
if (month < 1 or month > 12) return error.InvalidTime;
if (day < 1 or day > 31) return error.InvalidTime;
if (hh > 23 or mm > 59 or ss > 59) return error.InvalidTime;
```

**Acceptance criteria:**
- `parseDerTime` returns an error for month=0, month=13, day=0, day=32.
- Valid DER time strings continue to parse correctly.
- Test with boundary values: month=1, month=12, day=1, day=31.

**References:** CWE-1284 (Improper Validation of Specified Quantity in Input), CWE-125 (Out-of-bounds Read), OWASP A07:2021

**Affected paths:** `src/x509.zig`

**SLA:** 90 days

**Status: Closed** (2026-03-24) -- Added `validateTimeFields` function at `x509.zig:603-612` that validates month (1-12), day (1-31), hour (0-23), minute (0-59), second (0-59). Called from `parseDerTime` before `unixSecondsFromYMDHMS`. Returns `error.UnsupportedTimeFormat` for out-of-range values.

---

### Name Constraints (Phase 5)

#### SEC-033: matchesNameConstraint uses case-sensitive comparison (Medium, Risk 48)

**Summary:** The `matchesNameConstraint` function in `x509.zig` uses `std.mem.eql` for both exact match and suffix match comparisons. RFC 5280 Section 4.2.1.10 requires case-insensitive matching for DNS name constraints. A name constraint for `.Example.COM` would fail to match `www.example.com` despite being semantically equivalent.

**Impact:** Name constraints can be bypassed by using different letter casing in certificate DNS names. An attacker who obtains a certificate for `WWW.EXAMPLE.COM` could bypass a name constraint that only permits `.example.com`. Impact 4 (constraint bypass / authorization failure) x Likelihood 3 (requires mixed-case names in constrained PKI) x 4 = 48.

**Likelihood:** Likely in environments with name constraints (enterprise PKI, constrained CA hierarchies). Mixed-case DNS names are uncommon but valid per DNS standards.

**Evidence:**

`src/x509.zig:1152-1162`:
```zig
pub fn matchesNameConstraint(name: []const u8, constraint: []const u8) bool {
    if (constraint.len > 0 and constraint[0] == '.') {
        if (name.len < constraint.len) return false;
        const suffix = name[name.len - constraint.len ..];
        return std.mem.eql(u8, suffix, constraint);  // case-sensitive
    } else {
        return std.mem.eql(u8, name, constraint);  // case-sensitive
    }
}
```

Both comparisons use `std.mem.eql` which is byte-exact.

**Fix guidance:** Replace `std.mem.eql(u8, ...)` with `std.ascii.eqlIgnoreCase(...)` in both comparison paths. DNS names are ASCII and case-insensitive per RFC 4343.

**Acceptance criteria:**
- `matchesNameConstraint("www.Example.COM", ".example.com")` returns true.
- `matchesNameConstraint("EXAMPLE.COM", "example.com")` returns true.
- Existing name constraint tests updated with mixed-case scenarios.

**How to verify:** Add test cases in `tests/conformance/openssl/name_constraints.zig` with mixed-case DNS names.

**References:** CWE-178 (Improper Handling of Case Sensitivity), OWASP A07:2021, RFC 5280 Section 4.2.1.10, RFC 4343

**Affected paths:** `src/x509.zig`

**SLA:** 90 days

**Status: Closed** (2026-03-24) -- Replaced `std.mem.eql` with `toLowerAscii`-based case-insensitive comparison at `x509.zig:1131-1151`. Both exact match and suffix match paths now use per-byte `toLowerAscii` comparison per RFC 5280 Section 4.2.1.10 and RFC 4343.

---

### Supply Chain (Phase 5)

#### SEC-034: Dependency fetched from mutable main branch URL (Medium, Risk 32)

**Summary:** The `spice` dependency in `build.zig.zon` is fetched from a mutable URL that references the `main` branch (`spice-main.tar.gz`). While a hash is specified, the URL points to a moving target. If the hash is ever updated without reviewing the new content, a compromised upstream could inject malicious code.

**Impact:** Supply chain compromise if the dependency hash is updated without proper review. The hash provides integrity checking for the current fetch, but the mutable URL means the "expected" content changes over time. Impact 4 (potential code injection) x Likelihood 2 (requires hash update without review; hash currently provides protection) x 4 = 32.

**Likelihood:** Low in practice because the Zig build system enforces hash verification. The risk materializes only when the hash is updated (e.g., via `zig fetch --save`). Requires the upstream `main` branch to be compromised at that moment.

**Evidence:**

`build.zig.zon:37`:
```zig
.spice = .{
    .url = "https://gitlab.com/devnw/zig/spice/-/archive/main/spice-main.tar.gz",
    .hash = "spice-0.0.0-HnDb58jJAACojBd1dquGT-Ngc6TORlC6izlAKf0f4Rno",
},
```

The URL contains `/main/` indicating it tracks the mutable default branch.

**Fix guidance:** Pin the dependency to a specific commit SHA or tagged release:
```zig
.url = "https://gitlab.com/devnw/zig/spice/-/archive/<commit-sha>/spice-<commit-sha>.tar.gz",
```

**Acceptance criteria:**
- Dependency URL references a specific immutable commit SHA or tag, not a branch name.
- Build still succeeds with the pinned version.
- Document the update process for the pinned dependency.

**References:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), OWASP A08:2021 (Software and Data Integrity Failures)

**Affected paths:** `build.zig.zon`

**SLA:** 90 days

**Status: Closed** (2026-03-24) -- Dependency URL pinned to commit SHA `bbf106dc8131a514a4d1687cc2173f124f5c8181` at `build.zig.zon:38`. URL now references immutable archive path instead of mutable `/main/` branch.

---

### HRR and Rekey Paths (Phase 5)

#### SEC-035: HRR session_id length not bounds-checked against body.len (Low, Risk 24)

**Summary:** In the HelloRetryRequest handler at `context.zig:1454-1455`, `sid_len` is read from `body[pos]` and then `pos` is advanced by `1 + sid_len` without first checking that `pos + 1 + sid_len <= body.len`. If a malicious server sends a truncated HRR with a large `sid_len`, this could cause an integer overflow in the `pos` addition in release builds, or a panic in debug builds.

**Impact:** Denial of service via crafted HRR message. In release builds, the overflow could cause out-of-bounds reads. Impact 3 (DoS / potential OOB read) x Likelihood 2 (requires malicious server + HRR negotiation) x 4 = 24.

**Likelihood:** Requires the server to trigger HelloRetryRequest, which is an uncommon handshake path. The attacker must be the server or a MITM.

**Evidence:**

`src/tls13/context.zig:1454-1455`:
```zig
const sid_len: usize = body[pos];
pos += 1 + sid_len;
```

The next check at line 1458 (`if (pos + 2 + 1 > body.len)`) would catch the overflow in many cases, but if `1 + sid_len` wraps `pos` past `body.len` such that the subsequent check passes (possible with large `sid_len`), memory safety is violated.

**Fix guidance:** Add explicit bounds check: `if (pos + 1 + sid_len > body.len) return HandshakeError.UnexpectedMessage;` immediately after reading `sid_len`.

**Acceptance criteria:**
- HRR with `sid_len` exceeding remaining body length returns `UnexpectedMessage`.
- Valid HRR messages still parse correctly.

**References:** CWE-120 (Buffer Copy without Checking Size of Input), OWASP A07:2021

**Affected paths:** `src/tls13/context.zig`

**SLA:** 180 days

**Status: Closed** (2026-03-24) -- Added bounds check `if (pos + 1 + sid_len > body.len) return HandshakeError.UnexpectedMessage;` at `context.zig:1456`, immediately after reading `sid_len`.

---

#### SEC-036: Client private key not zeroized on HRR rekey path (Low, Risk 16)

**Summary:** In `sendClientHello2` at `context.zig:1532-1538`, when a HelloRetryRequest triggers re-keying, a new X25519 private key is generated and written to `self.client_priv`. The previous value of `client_priv` is overwritten without being zeroized first. The old key material remains in memory until the field happens to be reused or freed.

**Impact:** The original X25519 private key persists in the `client_priv` field's previous memory location (if the field is stack-allocated or inline). While `self.client_priv = priv` performs a value copy, the old value in `self.client_priv` is simply overwritten, not securely erased. Impact 2 (ephemeral key leak, limited window) x Likelihood 2 (requires HRR + memory read at precise time) x 4 = 16.

**Likelihood:** Requires HRR to be triggered (uncommon), plus memory inspection between key generation events. Low practical risk.

**Evidence:**

`src/tls13/context.zig:1532-1538`:
```zig
var priv: [32]u8 = undefined;
std.crypto.random.bytes(&priv);
const pub_key = std.crypto.dh.X25519.recoverPublicKey(priv) catch {
    return HandshakeError.UnsupportedKeyShareGroup;
};

self.client_priv = priv;  // Old client_priv overwritten without secureZero
self.client_pub = pub_key;
```

**Fix guidance:** Add `std.crypto.secureZero(u8, &self.client_priv);` before `self.client_priv = priv;` to clear the old key. Also add `defer std.crypto.secureZero(u8, &priv);` to clear the stack copy.

**Acceptance criteria:**
- Old `client_priv` is securely zeroed before being overwritten on the HRR path.
- Stack-local `priv` is zeroed after copy to `self.client_priv`.
- HRR handshake tests pass.

**References:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), OWASP A02:2021

**Affected paths:** `src/tls13/context.zig`

**SLA:** 180 days

**Status: Closed** (2026-03-24) -- Added `secureZero` on old `client_priv` before overwrite at `context.zig:1534-1538`. When `self.client_priv` is non-null, the old key is zeroized and set to null before generating the new key.

---

#### SEC-037: sendClientHello2 does not explicitly clamp X25519 private key (Low, Risk 12)

**Summary:** In `sendClientHello2` at `context.zig:1532-1534`, the X25519 private key is generated from random bytes without explicit clamping (clearing the low 3 bits and setting bit 254). Zig's `std.crypto.dh.X25519.recoverPublicKey` and `scalarmult` perform internal clamping during computation, so the DH output is correct. However, the Engine's equivalent code performs explicit clamping, creating an inconsistency.

**Impact:** No cryptographic impact. Zig's X25519 implementation internally clamps the scalar during computation, so the DH result is correct regardless. The concern is code consistency and defense-in-depth. Impact 3 (code quality / defense-in-depth) x Likelihood 1 (theoretical; no practical exploit) x 4 = 12.

**Likelihood:** Purely theoretical. Would only matter if the X25519 implementation changed to not internally clamp, which would break the public API contract.

**Evidence:**

`src/tls13/context.zig:1532-1534`:
```zig
var priv: [32]u8 = undefined;
std.crypto.random.bytes(&priv);
const pub_key = std.crypto.dh.X25519.recoverPublicKey(priv) catch { ... };
```

No explicit clamping step (`priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;`) before use.

**Fix guidance:** Add explicit clamping after `random.bytes` for consistency with other code paths and defense-in-depth. This makes the code self-documenting about X25519 key requirements.

**Acceptance criteria:**
- Explicit clamping applied to the private key before use.
- Handshake tests pass.
- Comment documents why clamping is applied (defense-in-depth).

**References:** CWE-326 (Inadequate Encryption Strength), OWASP A02:2021, RFC 7748 Section 5

**Affected paths:** `src/tls13/context.zig`

**SLA:** Backlog

**Status: Closed** (2026-03-24) -- Added explicit X25519 clamping at `context.zig:1543-1549`: `priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;` with comment referencing RFC 7748 Section 5 and consistency with `engine.zig`'s `ensureKeypair()`.

---

### Runtime Safety (Phase 5)

#### SEC-038: Global mutable TrustStore creates theoretical TOCTOU window (Info, Risk 12)

**Summary:** The global `TrustStoreState` at `x509.zig:134-155` is a `var` with a read-write lock. The lock protects individual reads and writes, but there is a theoretical TOCTOU (time-of-check-to-time-of-use) window: a trust store could be modified between the time it is read by `validateChain` and the time validation completes. In practice, this is benign because: (1) Zig does not support dynamic library unloading, so the trust store function pointer remains valid; (2) trust store changes during active handshakes are an administrative operation.

**Impact:** Theoretical only. If the trust store is changed mid-validation, a certificate could be validated against the wrong trust store. Impact 3 (validation inconsistency) x Likelihood 1 (requires precise timing + administrative action during handshake) x 4 = 12.

**Likelihood:** Extremely unlikely in practice. Requires simultaneous trust store modification and active handshake validation.

**Evidence:**

`src/x509.zig:134-155`:
```zig
const TrustStoreState = struct {
    store: ?TrustStore = null,
    lock: std.Thread.RwLock = .{},

    fn get(self: *TrustStoreState) ?TrustStore {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.store;
    }

    fn set(self: *TrustStoreState, ts: ?TrustStore) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.store = ts;
    }
};

var g_trust_store_state: TrustStoreState = .{};
```

**Fix guidance:** No action required. Document the design decision. If stronger guarantees are needed in the future, consider using an epoch-based reclamation scheme or holding the read lock for the duration of validation.

**References:** CWE-367 (Time-of-check Time-of-use Race Condition), OWASP A04:2021 (Insecure Design)

**Affected paths:** `src/x509.zig`

**SLA:** Backlog

---

### Logging and Debug (Phase 5)

#### SEC-039: Handshake trace may leak error details in production (Info, Risk 8)

**Summary:** The `traceHandshake` calls at `context.zig:2950` and `context.zig:3146` log certificate validation error details. Unlike the secret-trace functions (`sig_trace_enabled`, `secret_trace_enabled`), the handshake trace does not have a `@compileError` guard that prevents it from being active in release builds. If handshake tracing is enabled in production, error messages could leak information about the server's certificate validation logic.

**Impact:** Information disclosure about validation failures. The leaked information (error type, failure point) could help an attacker craft certificates that bypass specific checks. Impact 1 (information leak, limited) x Likelihood 2 (requires trace enabled in production) x 4 = 8.

**Likelihood:** Requires handshake tracing to be explicitly enabled in a production build. Low probability but worth noting for consistency.

**Evidence:**

`src/tls13/context.zig:2950`:
```zig
traceHandshake("Client: Certificate chain validation failed: {}\\n", .{err});
```

`src/tls13/context.zig:3146`:
```zig
traceHandshake("Server: Client certificate chain validation failed: {}\n", .{err});
```

Compare with the secret trace guard pattern in `src/sig.zig:117-120`:
```zig
comptime {
    if (sig_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: sig_trace_enabled must be false in release builds");
    }
}
```

No equivalent guard exists for `handshake_trace_enabled`.

**Fix guidance:** Add a `@compileError` guard for `handshake_trace_enabled` matching the pattern used for `sig_trace_enabled`, or ensure trace output does not include error details (only generic "validation failed" without the error enum).

**Acceptance criteria:**
- Handshake trace in release builds either (a) produces a compile error or (b) omits error-specific details.
- Debug builds retain full error tracing.

**References:** CWE-209 (Generation of Error Message Containing Sensitive Information), OWASP A09:2021 (Security Logging and Monitoring Failures)

**Affected paths:** `src/tls13/context.zig`

**SLA:** Backlog

---

### Key Schedule and Master Secret Derivation (Phase 7)

#### SEC-047: Engine computeApplicationSecrets uses wrong context hash and IKM for master secret (High, Risk 36) -- CLOSED

**Status:** Closed (Phase 8)

**Summary:** In `engine.zig:1474-1475`, `computeApplicationSecrets` derived the master secret with two incorrect inputs: (1) an empty slice `&[_]u8{}` as the context hash for `Derive-Secret`, instead of `Hash("")` (the hash of the empty string); and (2) an empty slice `&[_]u8{}` as the IKM for `HKDF-Extract`, instead of `HashLen` zeros. This produced a master secret that did not match RFC 8446 Section 7.1.

**Resolution:** Added `emptyHash()` and `zeroSecret()` helper functions mirroring the key_derivation.zig pattern. `computeApplicationSecrets` at engine.zig:1510-1516 now uses `emptyHash(self.hash_kind)` for context and `zeroSecret(self.hash_kind)` for IKM.

**Impact:** The Engine API produces incorrect application traffic secrets. Any standards-compliant TLS 1.3 peer (OpenSSL, BoringSSL, etc.) will derive different keys, causing AEAD decryption failure on the first application data record. If both sides use this library's Engine API, the connection works but uses non-standard key material that has not been analyzed for security properties.

**Likelihood:** Impact 3 (interoperability failure, non-standard crypto) x Likelihood 3 (deterministic on every Engine handshake, internet-facing) x 4 = 36

**Evidence:**

**VULNERABLE** -- `src/tls13/engine.zig:1473-1476`:
```zig
const master = blk2: {
    const derived = ks.deriveSecretHash(self.hash_kind, &handshake_secret, "derived", &[_]u8{});
    break :blk2 ks.extractHash(self.hash_kind, derived.slice(), &[_]u8{});
};
```

Two errors:
1. Line 1474: `&[_]u8{}` (length 0) passed as context hash. RFC 8446 requires `Hash("")` -- a 32-byte (SHA-256) or 48-byte (SHA-384) digest of the empty string.
2. Line 1475: `&[_]u8{}` (length 0) passed as IKM. RFC 8446 requires `0^HashLen` -- 32 or 48 zero bytes.

**CORRECT** -- `src/tls13/key_derivation.zig:340-348`:
```zig
const eh = emptyHash(hash);
const derived = ks.deriveSecretHash(hash, handshake_secret, "derived", eh.slice());
const zero_ikm = ks.zeroSecret(hash);
const master = ks.extractHash(hash, derived.slice(), zero_ikm.slice());
```

**Attack scenario:**
1. Application uses the Engine API for TLS 1.3.
2. Handshake traffic keys derive correctly (via `deriveHandshakeTraffic`).
3. `computeApplicationSecrets` at line 1473-1476 derives the master secret with wrong inputs.
4. Application traffic secrets differ from what any RFC-compliant peer would compute.
5. First application data record fails AEAD decryption; connection terminates.

**How to verify:** Compare Engine `computeApplicationSecrets` output against RFC 8448 test vectors or against Context `deriveApplicationTraffic` output for identical handshake transcripts and shared secrets.

**Fix guidance:** Replace the inline derivation with the correct pattern:
```zig
const master = blk2: {
    const eh = key_derivation_mod.emptyHash(self.hash_kind);
    const derived = ks.deriveSecretHash(self.hash_kind, &handshake_secret, "derived", eh.slice());
    const zero_ikm = ks.zeroSecret(self.hash_kind);
    break :blk2 ks.extractHash(self.hash_kind, derived.slice(), zero_ikm.slice());
};
```
Or call `key_derivation_mod.deriveApplicationTraffic()` directly.

**Acceptance criteria:**
- `computeApplicationSecrets` uses `Hash("")` (emptyHash) as context for Derive-Secret
- `computeApplicationSecrets` uses `HashLen` zeros (zeroSecret) as IKM for HKDF-Extract
- Engine produces the same application traffic secrets as the Context path for identical inputs
- Interop test: Engine connects to OpenSSL/BoringSSL and exchanges application data
- Unit test compares output against RFC 8448 test vectors

**References:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), OWASP A02:2021 (Cryptographic Failures), RFC 8446 Section 7.1, RFC 8448

**Affected paths:** `src/tls13/engine.zig:1473-1476`

**Issue:** [GitLab #123](https://gitlab.com/devnw/zig/tls/-/issues/123) (confidential)

**SLA:** 30 days (due 2026-04-23)

---

### ECDHE Key Generation (Phase 7)

#### SEC-040: startClientHandshake missing X25519 clamping (Low, Risk 8) -- CLOSED

**Status:** Closed (Phase 8)

**Summary:** `startClientHandshake` at `context.zig:2122-2126` generated an X25519 private key from random bytes without explicit clamping. Zig's `std.crypto.dh.X25519` internally clamps during computation, so the DH output was correct. However, `sendClientHello2` (fixed in SEC-037) and the Engine's `ensureKeypair` both apply explicit clamping, creating an inconsistency.

**Resolution:** Added explicit clamping (`priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;`) at `context.zig:2181-2187` with RFC 7748 S5 comment. All X25519 key generation paths now consistently clamp.

**Impact:** No cryptographic impact. Defense-in-depth concern only.

**Likelihood:** Impact 2 x Likelihood 1 (theoretical) x 4 = 8

**Evidence:**

`src/tls13/context.zig:2122-2126`:
```zig
var priv: [32]u8 = undefined;
std.crypto.random.bytes(&priv);
const client_pubkey = std.crypto.dh.X25519.recoverPublicKey(priv) catch return HandshakeError.UnsupportedKeyShareGroup;
self.client_priv = priv;
```

No explicit clamping (`priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;`) before use.

**Fix guidance:** Add explicit X25519 clamping after `random.bytes`, matching the SEC-037 pattern at `context.zig:1543-1549`.

**Acceptance criteria:**
- Explicit clamping applied before `recoverPublicKey`
- Comment references RFC 7748 Section 5
- All X25519 key generation paths consistently clamp

**References:** CWE-326 (Inadequate Encryption Strength), OWASP A02:2021, RFC 7748 Section 5

**Affected paths:** `src/tls13/context.zig:2122-2126`

**Issue:** [GitLab #126](https://gitlab.com/devnw/zig/tls/-/issues/126)

**SLA:** 180 days (due 2026-09-20)

---

#### SEC-048: Server negotiateCipherAndKeys missing X25519 clamping (Low, Risk 6) -- CLOSED

**Status:** Closed (Phase 8)

**Summary:** Server-side `negotiateCipherAndKeys` at `context.zig:1907-1909` generated an X25519 private key without explicit clamping. The key already had `defer secureZero` (line 1908), showing security awareness, but lacked the explicit clamping that other paths apply.

**Resolution:** Added explicit clamping at `context.zig:1959-1965` with RFC 7748 S5 comment, matching all other X25519 key generation paths.

**Impact:** No cryptographic impact. Defense-in-depth inconsistency.

**Likelihood:** Impact 2 x Likelihood 0.75 (theoretical) x 4 = 6

**Evidence:**

`src/tls13/context.zig:1907-1909`:
```zig
var server_priv: [32]u8 = undefined;
defer std.crypto.secureZero(u8, &server_priv);
std.crypto.random.bytes(&server_priv);
```

No explicit clamping step before `recoverPublicKey` at line 1911.

**Fix guidance:** Add explicit clamping after `random.bytes`, matching the SEC-037 pattern.

**Acceptance criteria:**
- Explicit clamping applied before `recoverPublicKey`
- Server handshake tests pass

**References:** CWE-326, OWASP A02:2021, RFC 7748 Section 5

**Affected paths:** `src/tls13/context.zig:1907-1909`

**Issue:** [GitLab #127](https://gitlab.com/devnw/zig/tls/-/issues/127)

**SLA:** 180 days (due 2026-09-20)

---

### Timing and Side Channels (Phase 7)

#### SEC-046: PSK identity comparison non-constant-time (Low, Risk 6) -- CLOSED

**Status:** Closed (Phase 8)

**Summary:** At `context.zig:1776`, external PSK identity matching used `std.mem.eql(u8, ident.identity, self.config.external_psk_identity.?)`. PSK identities are not secret (they are sent in cleartext in the ClientHello), but timing differences in the comparison could theoretically reveal whether a partial prefix of the identity matched.

**Resolution:** Replaced with length check followed by `std.crypto.timing_safe.compare` at `context.zig:1825`. Length check is non-secret (lengths visible in cleartext ClientHello), constant-time comparison prevents prefix timing leaks.

**Impact:** Minimal. PSK identities are transmitted in plaintext in the ClientHello per RFC 8446 Section 4.2.11. An attacker already knows the identity being offered. However, for server-side PSK lookup across multiple configured identities, timing could reveal which identity the server recognizes.

**Likelihood:** Impact 2 (limited info disclosure) x Likelihood 0.75 (requires multiple PSK identities + timing measurement) x 4 = 6

**Evidence:**

`src/tls13/context.zig:1776`:
```zig
std.mem.eql(u8, ident.identity, self.config.external_psk_identity.?)
```

**Fix guidance:** Replace with `std.crypto.timing_safe.eql` after verifying length equality. This is defense-in-depth; the data is not secret.

**Acceptance criteria:**
- PSK identity comparison uses constant-time comparison
- PSK handshake tests pass

**References:** CWE-208 (Observable Timing Discrepancy), OWASP A02:2021, RFC 8446 Section 4.2.11

**Affected paths:** `src/tls13/context.zig:1776`

**SLA:** 180 days (due 2026-09-20)

---

### Secret Lifecycle and Zeroization (Phase 7)

#### SEC-042: deriveHandshakeTraffic intermediates not zeroized (Low, Risk 4)

**Summary:** In `key_derivation.zig:218-222`, `deriveHandshakeTraffic` computes `derived`, `handshake_secret`, `client_hs`, and `server_hs` as local `const` values that are returned or discarded. The intermediate `derived` value and the returned secrets persist on the stack without zeroization after the function returns.

**Impact:** Intermediate key derivation values remain on the stack. If a memory disclosure occurs after the function returns, an attacker could recover the handshake secret and derive all session keys.

**Likelihood:** Impact 2 (intermediate key material, not the final secret) x Likelihood 0.5 (requires stack memory read after function return) x 4 = 4

**Evidence:**

`src/tls13/key_derivation.zig:218-222`:
```zig
const derived = ks.deriveSecretHash(hash, early_secret, "derived", eh.slice());
const handshake_secret = ks.extractHash(hash, derived.slice(), ecdhe_secret);
const client_hs = ks.deriveSecretHash(hash, &handshake_secret, "c hs traffic", transcript_hash.slice());
const server_hs = ks.deriveSecretHash(hash, &handshake_secret, "s hs traffic", transcript_hash.slice());
```

All are `const`; no `defer secureZero` is possible without changing to `var`.

**Fix guidance:** Change `const` to `var` for intermediate values and add `defer` zeroization. The return value will be copied before defer runs.

**Acceptance criteria:**
- `derived` and `handshake_secret` intermediates are zeroized after use
- Handshake tests pass

**References:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), OWASP A02:2021

**Affected paths:** `src/tls13/key_derivation.zig:218-222`

**SLA:** 180 days (due 2026-09-20)

---

#### SEC-043: deriveApplicationTraffic intermediates not zeroized (Low, Risk 4)

**Summary:** In `key_derivation.zig:340-351`, `deriveApplicationTraffic` computes `derived`, `zero_ikm`, `master`, `client_app`, `server_app`, and `exporter_master` as local `const` values. The intermediate values (`derived`, `zero_ikm`, `master`) are not zeroized after the function returns.

**Impact:** Same as SEC-042 -- intermediate key material persists on the stack.

**Likelihood:** Impact 2 x Likelihood 0.5 x 4 = 4

**Evidence:**

`src/tls13/key_derivation.zig:340-351`:
```zig
const eh = emptyHash(hash);
const derived = ks.deriveSecretHash(hash, handshake_secret, "derived", eh.slice());
const zero_ikm = ks.zeroSecret(hash);
const master = ks.extractHash(hash, derived.slice(), zero_ikm.slice());
const client_app = ks.deriveSecretHash(hash, &master, "c ap traffic", transcript_hash.slice());
const server_app = ks.deriveSecretHash(hash, &master, "s ap traffic", transcript_hash.slice());
const exporter_master = ks.deriveSecretHash(hash, &master, "exp master", transcript_hash.slice());
```

**Fix guidance:** Change `derived`, `zero_ikm`, and `master` to `var` and add `defer secureZero`.

**Acceptance criteria:**
- `derived`, `zero_ikm`, and `master` intermediates zeroized after use
- Application traffic derivation tests pass

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/tls13/key_derivation.zig:340-351`

**SLA:** 180 days (due 2026-09-20)

---

#### SEC-041: expandLabelHash PRK copy not zeroized (Low, Risk 3)

**Summary:** In `key_schedule.zig:143-150`, `expandLabelHash` copies the PRK into a fixed-size array `arr` for HKDF-Expand. The `arr` variable is not zeroized after use. It contains the raw PRK (pseudorandom key), which is intermediate key material.

**Impact:** PRK copy persists on the stack after the function returns. The PRK is also available via the caller's Secret struct, so this is a secondary exposure.

**Likelihood:** Impact 1.5 (secondary copy of already-held key material) x Likelihood 0.5 x 4 = 3

**Evidence:**

`src/key_schedule.zig:143-150`:
```zig
.sha256 => {
    var arr: [Sha256.digest_length]u8 = undefined;
    @memcpy(arr[0..], prk_slice);
    HkdfSha256.expand(out, info, arr);
},
.sha384 => {
    var arr: [Sha384.digest_length]u8 = undefined;
    @memcpy(arr[0..], prk_slice);
    HkdfSha384.expand(out, info, arr);
},
```

No `defer secureZero(u8, &arr)` after the expand call.

**Fix guidance:** Add `defer std.crypto.secureZero(u8, &arr);` after `@memcpy` in both branches.

**Acceptance criteria:**
- `arr` is zeroized after HKDF-Expand completes
- Key schedule tests pass

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/key_schedule.zig:143-150`

**SLA:** 180 days (due 2026-09-20)

---

### Type Safety (Phase 7)

#### SEC-045: @ptrCast on PSK binder/identity bypasses type safety (Info, Risk 2)

**Summary:** At `context.zig:506,512,514`, `@ptrCast` is used to convert between owned and view types for PSK identities, binders, and ALPN lists. While the memory layouts are documented as equivalent, `@ptrCast` bypasses Zig's type system and could cause undefined behavior if the layouts ever diverge.

**Impact:** Theoretical type confusion. The casts are documented with inline comments explaining the layout equivalence. In practice, the types are defined adjacently and reviewed together, making layout divergence unlikely.

**Likelihood:** Impact 1 (theoretical UB) x Likelihood 0.5 (requires type definition changes) x 4 = 2

**Evidence:**

`src/tls13/context.zig:506`:
```zig
.alpn_list = if (info.alpn_list) |list| @as([]const []const u8, @ptrCast(list)) else null,
```

`src/tls13/context.zig:512`:
```zig
.identities = @as([]const ClientHelloPskIdentityView, @ptrCast(psk.identities)),
```

`src/tls13/context.zig:514`:
```zig
.binders = @as([]const []const u8, @ptrCast(psk.binders)),
```

**Fix guidance:** Replace `@ptrCast` with explicit field-by-field construction of the view types, or add comptime assertions verifying layout equivalence:
```zig
comptime {
    std.debug.assert(@sizeOf(OwnedPskIdentity) == @sizeOf(ClientHelloPskIdentityView));
    std.debug.assert(@alignOf(OwnedPskIdentity) == @alignOf(ClientHelloPskIdentityView));
}
```

**Acceptance criteria:**
- Either `@ptrCast` is replaced with safe conversions, or comptime layout assertions are added
- PSK handshake tests pass

**References:** CWE-843 (Access of Resource Using Incompatible Type), OWASP A07:2021

**Affected paths:** `src/tls13/context.zig:506,512,514`

**SLA:** Backlog

---

### Buffer Zeroization (Phase 7)

#### SEC-044: expandLabelHash fbb buffer not zeroized (Info, Risk 1)

**Summary:** In `key_schedule.zig:134`, the `fbb` stack buffer (256 bytes) used by `expandLabelHash` to construct the HKDF label is not zeroized after use. The buffer contains the HKDF label bytes (label string + context hash), which are non-secret (they encode public label names and transcript hashes).

**Impact:** None. The fbb buffer contains only HKDF label encoding, which consists of public label strings ("c hs traffic", etc.) and transcript hashes. These are not secret.

**Likelihood:** Impact 1 (non-secret data) x Likelihood 0.25 x 4 = 1

**Evidence:**

`src/key_schedule.zig:134`:
```zig
var fbb: [256]u8 = undefined;
var fba = std.heap.FixedBufferAllocator.init(&fbb);
```

No zeroing after use. The allocated info is freed via `defer alloc.free(info)` but the backing buffer is not zeroized.

**Fix guidance:** Add `defer @memset(&fbb, 0);` for defense-in-depth. Low priority since the data is non-secret.

**Acceptance criteria:**
- `fbb` buffer is zeroized after use (defense-in-depth)

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/key_schedule.zig:134`

**SLA:** Backlog

---

## Roadmap

### Quick Wins (< 1 day)

| ID | Task | Effort | Status |
|----|------|--------|--------|
| SEC-040 | Add explicit X25519 clamping in `startClientHandshake` | 15 min | Closed |
| SEC-048 | Add explicit X25519 clamping in `negotiateCipherAndKeys` | 15 min | Closed |
| SEC-046 | Replace `std.mem.eql` with `timing_safe` for PSK identity comparison | 15 min | Closed |
| SEC-041 | Add `defer secureZero` on PRK copy `arr` in `expandLabelHash` (2 branches) | 15 min | Closed |
| SEC-042 | Add `defer secureZero` on intermediates in `deriveHandshakeTraffic` | 30 min | Closed |
| SEC-043 | Add `defer secureZero` on intermediates in `deriveApplicationTraffic` | 30 min | Closed |
| SEC-044 | Add `defer secureZero` on fbb buffer in `expandLabelHash` | 5 min | Closed |
| SEC-045 | Add comptime layout assertions for `@ptrCast` PSK types | 15 min | Open |
| SEC-032 | Add month/day range validation in `parseDerTime` | 15 min | Closed |
| SEC-033 | Replace `std.mem.eql` with `toLowerAscii` in `matchesNameConstraint` | 15 min | Closed |
| SEC-035 | Add bounds check for `sid_len` in HRR handler | 15 min | Closed |
| SEC-036 | Add `secureZero` on old `client_priv` before HRR rekey overwrite | 15 min | Closed |
| SEC-037 | Add explicit X25519 clamping in `sendClientHello2` | 15 min | Closed |
| SEC-034 | Pin spice dependency to commit SHA in `build.zig.zon` | 15 min | Closed |
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
| SEC-047 | Fix Engine master secret derivation: use `emptyHash()` + `zeroSecret()` in `computeApplicationSecrets` | 1-2 days | Closed |
| SEC-029 | Fail-closed hostname validation: require server_name or error | 1-2 days | Closed |
| SEC-028 | Validate server-selected cipher suite against offered list | 1-2 days | Closed |
| SEC-030 | Apply hostname/EKU/KU checks to self-signed certs | 1-2 days | Closed |
| SEC-031 | Add clientAuth EKU check in mTLS validation path | 1-2 days | Closed |
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
| SEC-007 | Implement CRL distribution point fetching or mandatory OCSP enforcement -- **Closed** (limitation documented in lib.zig + x509.zig) | 5-10 days |

---

## Methodology

- **Manual code review** of all cryptographic signing, key derivation, and secret lifecycle paths.
- **Cross-reference** between duplicate implementations (context.zig vs secrets.zig SecretSlot, messages.zig vs engine.zig x25519).
- **Pattern matching** against CWE/OWASP categories for TLS implementations.
- **Comparison** with RFC 8446 requirements for signature algorithm negotiation and key zeroization.
- **Phase 4 additions**: ECDHE lifecycle audit (server_priv, shared secret), DoS surface analysis (TicketStore, buffer bounds), certificate validation flow analysis (Finished/cert failure handling).
- **Phase 5 additions**: Cipher suite negotiation RFC compliance, hostname validation fail-open analysis, X.509 self-signed bypass, DER time parsing safety, name constraint case sensitivity, mTLS EKU validation, supply chain dependency pinning, HRR rekey path audit.
- **Phase 7 additions**: Engine key schedule correctness audit (emptyHash vs empty slice, zeroSecret vs empty IKM), X25519 clamping consistency across all key generation paths, PSK identity timing analysis, key derivation intermediate zeroization audit, `@ptrCast` type safety review.

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
| SEC-014 | `confidence::confirmed` | Duplicate of SEC-027; dead fallback removed (verified at engine.zig:836-840) |
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
| SEC-028 | `confidence::confirmed` | Code at context.zig:2492-2494 accepts any valid enum value without checking offered list |
| SEC-029 | `confidence::confirmed` | Null server_name produces empty string; x509.zig:1511 skips matchDnsName when len==0 |
| SEC-030 | `confidence::confirmed` | `is_single_self_signed` guard at x509.zig:1510 bypasses hostname/EKU/KU checks |
| SEC-031 | `confidence::confirmed` | validateChain checks `server_auth` EKU (x509.zig:1512); no `client_auth` check exists anywhere |
| SEC-032 | `confidence::confirmed` | No range validation on month/day in parseDerTime; month>=14 causes OOB in daysBeforeMonth |
| SEC-033 | `confidence::confirmed` | `std.mem.eql` at x509.zig:1159,1162 is byte-exact; RFC 5280 requires case-insensitive |
| SEC-034 | `confidence::confirmed` | URL contains `/main/` branch reference at build.zig.zon:37 |
| SEC-035 | `confidence::suspected` | `sid_len` at context.zig:1454 not bounds-checked; confirm exploitability with crafted HRR |
| SEC-036 | `confidence::confirmed` | No secureZero on old client_priv before overwrite at context.zig:1538 |
| SEC-037 | `confidence::confirmed` | No explicit clamping; Zig's X25519 internally clamps (verified in std.crypto source) |
| SEC-038 | `confidence::confirmed` | Global mutable var at x509.zig:155; benign due to Zig's lack of dynamic unloading |
| SEC-039 | `confidence::suspected` | Verify whether handshake_trace_enabled has a comptime release guard |
| SEC-040 | `confidence::confirmed` | No explicit clamping at context.zig:2122-2126; SEC-037 pattern not applied to this path |
| SEC-041 | `confidence::confirmed` | No `defer secureZero` on `arr` in either sha256/sha384 branch at key_schedule.zig:143-150 |
| SEC-042 | `confidence::confirmed` | All intermediates are `const` with no zeroization at key_derivation.zig:218-222 |
| SEC-043 | `confidence::confirmed` | All intermediates are `const` with no zeroization at key_derivation.zig:340-351 |
| SEC-044 | `confidence::confirmed` | `fbb` buffer at key_schedule.zig:134 has no zeroing; contains non-secret HKDF label data |
| SEC-045 | `confidence::confirmed` | Direct `@ptrCast` at context.zig:506,512,514 with no comptime layout assertions |
| SEC-046 | `confidence::confirmed` | `std.mem.eql` at context.zig:1776; PSK identities are cleartext but timing could reveal server state |
| SEC-047 | `confidence::confirmed` | engine.zig:1474 passes `&[_]u8{}` vs key_derivation.zig:340-341 uses `emptyHash()` and `zeroSecret()` |
| SEC-048 | `confidence::confirmed` | No explicit clamping at context.zig:1907-1909; SEC-037 pattern not applied to server path |
