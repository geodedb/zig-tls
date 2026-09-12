# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.21] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5 (GAP-0838 diamond sync).

## [0.2.0] - 2026-04-27

### Removed (BREAKING)
- `src/parallel.zig` and the `pub const parallel = @import("parallel")` re-export on the `ztls` root module are gone. The thread-pool-backed batch helpers (`parallelCertificateValidate`, `parallelSignatureVerify`, `parallelAeadSeal`, `parallelKeyDerive`, plus `getPool` / `deinitPool`) are no longer part of the public API. Callers that need parallelism should drive batches against the per-op primitives in `sig`, `x509`, and `record`. The upstream `thread_pool` package remains available; only the `parallel` wrapper is removed (PERF-237b, GAP-0131).
- `tests/fuzz/rsa_pss_verify.zig` differential against `parallel.verifyRsaPssWithHash` is now a self-comparison against `sig.rsaPssVerifyGeneric`. Output is functionally equivalent (the prior wrapper delegated to the same generic helper) but the public hook is gone.
- `build.zig` no longer registers the `parallel` module; the `bench-threadpool` step still works because it depends only on the upstream `thread_pool` package.

### Migration
- Replace `ztls.parallel.verifyRsaPssWithHash(Sha256, in, alloc)` with `ztls.sig.rsaPssVerifyGeneric(Sha256, spki, msg, sig, alloc)` (single-shot) or hand-roll a thread pool driver around the same call.
- Replace `ztls.parallel.parallelCertificateValidate` with serial `ztls.x509.validateChain` calls or your own pool driver.
- `getPool` / `deinitPool` callers should remove the calls; there is no global pool to free anymore.

## [0.1.1] - 2026-04-27

### Security
- RNG fail-closed via new `src/entropy.zig` helper using `std.Io.randomSecure` + panic on `error.EntropyUnavailable`; 9 `std.os.linux.getrandom` sites in `src/tls13/context.zig` migrated. Also eliminates the Linux-only `getrandom` hardwiring (SEC-074, SEC-081).
- X.509 unknown critical extensions now rejected per RFC 5280 §4.2 — `parseExtensionsBlock` parses the BOOLEAN criticality flag and returns `error.UnknownCriticalExtension` on critical+unknown OIDs (SEC-075).
- OID matching canonicalized across OCSP and ECDSA/RSA SPKI parsers — new `asn1.oidEqual` helper replaces 11 suffix-match sites that previously accepted prefix-attack encodings (SEC-076).
- `x509.validateChainEx` / `validateChainReturnParsed` / `Config.allow_insecure` replaced raw `bool` with `x509.InsecureValidation` sentinel enum; the insecure variant requires `-Dtls-insecure-testing=true` build flag and panics otherwise (SEC-077).
- `Config.persistent_anti_replay_store` wired into 0-RTT accept path with fail-closed semantics (backend errors fall back to 1-RTT). Closes cross-connection and cross-restart replay windows for multi-server deployments (SEC-065/085).

### Added
- `Context.deliverAlert(level, payload)` decodes inbound TLS alert bytes, populates `HandshakeFlags.alert`, invokes the new `Callbacks.on_alert` hook, and terminates on fatal alerts (GAP-0133).
- `Context.sendCloseNotify()`, `Context.sendFatalAlert(desc)`, `sendInternalError()`, `sendHandshakeFailure()` write 2-byte alert payloads to the outbound stream at the current encryption level and transition the Context to `.terminated` (GAP-0134).
- New `HandshakePhase.terminated` variant for post-alert lifecycle.
- CI job `test-insecure-flag` exercises `zig build test -Dtls-insecure-testing=true` to cover both flag states.
- CI job `no-raw-getrandom` regression guard greps `src/` for re-introduction of raw `std.os.linux.getrandom` (SEC-074 structural guard).

### Changed
- `src/tls13.zig` 239-LOC compat shim removed; `build.zig` module `tls13` now roots at `src/tls13/mod.zig`. `cookie_mod` re-export ported to the canonical barrel (QUAL-358).
- `handleCertificateVerify` decomposed from 163 LOC monolith into a ~50-LOC orchestrator plus 3 per-concern validators in `src/tls13/context/cert_handlers.zig` (`validateChainAndLeaf`, `validateOcspStaple`, `validateSctList`); semantic behavior unchanged (oracle test byte-identical) (QUAL-357).
- Minimum supported Zig version raised to 0.16.0 (stdlib APIs used by the bench harness were removed after 0.15.x).
- Removed the `flake.nix` / `flake.lock` Nix derivation (it referenced a `nix/quic.nix` that was never committed; consumers build via `zig build` directly).

### Documented
- ADR-0002 — ECDSA-P256 performance strategy. `nistz256` port deferred; FFI to libcrypto rejected as zero-deps violation; guidance-first approach for P-256 workloads. `docs/RUNBOOK.md` §Performance and `README.md` performance note updated to flag the P-256 2-3 ms range vs the <2 ms Ed25519/RSA-2048 SLO (PERF-229).
- `docs/RUNBOOK.md` §0-RTT deployment (SEC-065): multi-server / load-balanced deployments MUST configure `Config.persistent_anti_replay_store`.
- `docs/API.md` §Alert protocol: inbound dispatch and outbound API usage (GAP-0133/0134).

## [0.1.0] - 2026-01-24

This release marks the initial open source release of ztls under the Apache-2.0 license.

### Added
- Merge request template for contributions
- Issue templates for bug reports, features, and questions

#### Core TLS 1.3 Implementation
- Complete TLS 1.3 handshake state machine (RFC 8446)
- HKDF-based key schedule implementation (RFC 8446 Section 7, RFC 9001 Section 5.1)
- AEAD record protection with AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305
- Alert protocol implementation
- 0-RTT anti-replay support

#### QUIC Integration
- Native QUIC-TLS support (RFC 9001)
- QUIC transport parameter handling
- Server transport parameter extraction from ClientHello
- QUIC extension interfaces

#### Certificate Handling
- X.509 certificate parsing and validation
- ASN.1 DER decoder
- SNI matching and validity checks
- Signature verification for ECDSA (P-256, P-384), RSA-PSS, and Ed25519

#### Testing Infrastructure
- 262 unit tests with RFC subsection references
- 148 RFC compliance tests (TLS 1.3, QUIC-TLS, X.509)
- 13 official RFC test vectors from RFC 8446 and RFC 9001 appendices
- 430 conformance tests for BoringSSL and OpenSSL parity
- Performance benchmarks (latency <2ms, memory <100KB)
- Security testing including fuzzing and input validation

#### Build System
- Makefile with convenient targets (build, test, dev, clean)
- build.zig for native Zig builds
- Support for Zig 0.15.1

#### CI/CD
- GitLab CI configuration with DevNW CI/CD Catalog
- Multi-platform builds (Linux, macOS, Windows)
- Security scanning (SAST, Dependency Scanning, Secret Detection)
- SBOM generation
- OpenSSL conformance test stage

#### Documentation
- Comprehensive README with usage examples
- BUILD_SYSTEM.md for build system documentation
- CONFORMANCE_TESTS.md for compatibility test documentation
- CLAUDE.md for AI assistance context
- RFC section citations throughout the codebase

### Fixed
- Updated gitleaks allowlist for false positives
- TLS 1.3 early secret derivation (RFC 8446 Section 7.1)
- Master secret derivation using empty slice instead of zero bytes
- Use Hash("") instead of empty slice for 'derived' secret context
- Crypto buffer data preservation when consuming
- Various memory leaks in OpenSSL conformance tests
- Windows CI compatibility issues
- Zig formatting compliance

### Changed
- Updated CI catalog components to v1.7.1
- Removed 'zig' prefix from library name (now `ztls`)
- Prepared repository for open source release
- Migrated to more stdlib implementations where possible

---

## Version History Summary

The project evolved through several development phases:

1. **Initial Implementation** - Core TLS 1.3 state machine and key schedule
2. **QUIC Extensions** - Native QUIC transport integration
3. **Conformance Testing** - BoringSSL and OpenSSL compatibility
4. **Modularization** - Code restructuring across 5 phases
5. **RFC Compliance** - Gap analysis and full RFC 8446/9001 coverage
6. **Open Source Release** - Apache-2.0 licensing and public documentation

[Unreleased]: https://gitlab.com/devnw/zig/tls/-/compare/main...HEAD
[0.1.0]: https://gitlab.com/devnw/zig/tls/-/releases/v0.1.0
