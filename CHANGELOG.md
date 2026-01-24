# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
