# Security Code Review Notes

## Orientation & Tool Readiness

- **Repository:** `devnw/zig/tls` (A TLS 1.3/QUIC implementation in Zig)
- **Target:** Full codebase, pipeline (`.gitlab-ci.yml`), and configuration.
- **Tooling:**
  - `semgrep` is available and configured locally.
  - `checkov`, `trivy`, `osv-scanner`, `gitleaks`, `trufflehog`, and `syft` were verified as missing from the environment. Graceful fallback to manual inspection was used where tooling lacked coverage.
- **Constraints:** Network constraints and environment limits restricted the use of `auto` config on `semgrep`; executed successfully via offline `p/default`.

## Security Sweeps

### 1. Static Analysis (Semgrep)

- **Command:** `semgrep scan --config p/default --json > /tmp/semgrep.json`
- **Results:** Identified 8 findings related to hardcoded private keys.
  - 7 findings in `tests/test_certs/*.pem` (Known test fixtures, documented via `tests/test_certs/README.md`). Tracked historically in #47.
  - 1 finding in `tests/rfc9001/appendix_a_initial_secrets.zig` (Known RFC 9001 Appendix A test vectors, benign hex strings).
- **Action:** Validated findings as non-production test fixtures. Explicit `gitleaks` allowlist entries exist; risk is negligible due to context but rotation/storage warnings remain valid.

### 2. Manual Deep Dive: Core TLS Handshake Parsers

- Investigated parsing boundaries for duplicate extension processing (`RFC 8446 §4.2`).
- Originally flagged an architectural bypass in duplicate extension handling in
  `client_hello.zig`, `encrypted_extensions.zig`, and `certificate_request.zig`.
  - **Mechanism (historical):** The parsers used `std.EnumSet(core_types.ExtensionType)` to
    track seen extensions. Because the raw `u16` type was mapped to the
    `core_types.ExtensionType` enum *before* registration, unknown extensions
    (`std.enums.fromInt` returns `null`) were never registered, so identical *unknown*
    extensions (e.g. `[0x1234, 0x1234]`) evaded the duplicate-extension gate, violating
    RFC 8446 §4.2.
  - **Status: RESOLVED.** This is already fixed in the current tree. Commit `b2e58ac`
    ("feat: introduce handshake scratch arena and address GAP-0135/SEC-092", landing
    GAP-0145) replaced the bypassable `EnumSet` with a fixed-size raw-`u16` seen-list that
    rejects duplicates *before* enum mapping, so unknown duplicates are now rejected with
    `error.DuplicateExtension`. Verified at:
    - `src/tls13/messages/client_hello.zig:359-384` (raw-`u16` `seen_extensions`, dup check at `:377-379`).
    - `src/tls13/messages/encrypted_extensions.zig:222-245` (dup check at `:239-241`).
    - `src/tls13/messages/certificate_request.zig:202-219` (dup check at `:213-215`).
    - `src/tls13/messages/certificate.zig:217-234` (per Certificate-entry, dup check at `:228-230`).
    - The HelloRetryRequest extension loop is likewise gated (GAP-0144): `src/tls13/context/hello_retry.zig:109-126`, tested in `tests/security/gap0144_hrr_dup_ext.zig`.
- **Action (doc reconciliation, 2026-06-10):** Marked RESOLVED with the citations above.
  - **ID collision note:** The "SEC-101 (#350)" identifier recorded for this finding collides
    with the already-assigned **SEC-101 (#347)** in `docs/SECURITY_GAP_ANALYSIS.md` (the
    `parseExtSan` dNSName SAN-truncation drift item, still Open). When re-filing, allocate a
    distinct unused SEC-* ID (e.g. the next free number) instead of reusing SEC-101.

### 3. CI/CD & Pipeline Review

- Inspected `.gitlab-ci.yml`.
- Validated that the pipeline leverages heavily pinned external dependencies (`security-sast@41983cfbddfe06a5e6e3c126a7f16404d36c7ef9`).
- Zig toolchain download uses strict SHA256 validation.
- No new delivery pipeline vulnerabilities discovered.

## Conclusion

The repository maintains a very strong security posture with deep coverage of known TLS 1.3 protocol flaws (e.g., timing oracles, HRR downgrade attacks, key exhaustion). The unknown-extension duplicate-bypass that was originally the primary finding of this review has since been **RESOLVED** in the current tree by commit `b2e58ac` (GAP-0145), which rejects duplicate extension types — known or unknown — before enum mapping in all four handshake parsers and in the HelloRetryRequest loop. No open code-level findings remain from this review; the only outstanding item is the documentation hygiene note on the SEC-101 ID collision above.
