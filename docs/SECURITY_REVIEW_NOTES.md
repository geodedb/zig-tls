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
- Discovered an architectural bypass in duplicate extension handling in `client_hello.zig`, `encrypted_extensions.zig`, and `certificate_request.zig`.
  - **Mechanism:** The codebase utilizes `std.EnumSet(core_types.ExtensionType)` to track seen extensions. However, before registering an extension, the parser attempts to map the `u16` raw type to the `core_types.ExtensionType` enum. For unknown extensions, `std.enums.fromInt` returns `null`, and the parsers skip registering the extension type altogether.
  - **Result:** An attacker can inject arbitrary identical *unknown* extensions (e.g., `[0x1234, 0x1234]`) to completely evade the duplicate-extension gates. This violates RFC 8446 §4.2.
- **Action:** Created GitLab issue **SEC-101 (#350)**.

### 3. CI/CD & Pipeline Review

- Inspected `.gitlab-ci.yml`.
- Validated that the pipeline leverages heavily pinned external dependencies (`security-sast@41983cfbddfe06a5e6e3c126a7f16404d36c7ef9`).
- Zig toolchain download uses strict SHA256 validation.
- No new delivery pipeline vulnerabilities discovered.

## Conclusion

The repository maintains a very strong security posture with deep coverage of known TLS 1.3 protocol flaws (e.g., timing oracles, HRR downgrade attacks, key exhaustion). The primary finding of this review is a novel RFC compliance and protocol state flaw in the handling of unknown extension types.
