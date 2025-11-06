# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **TLS 1.3 implementation for QUIC** written in Zig 0.15.1, strictly adhering to RFC 8446 (TLS 1.3) and RFC 9001 (QUIC-TLS). The implementation is QUIC-focused and uses only Zig standard library primitives with no external dependencies.

Key characteristics:
- QUIC-native: No traditional record layer, integrates directly with QUIC's CRYPTO frames
- Interop-first design: Auto-detects and supports standard TLS 1.3 formats for compatibility with real-world QUIC implementations (quic-go, quinn, msquic)
- RFC-compliant: Every implementation block includes RFC section citations
- Zero external dependencies: Uses only `std.crypto`, `std.mem`, etc.

## Development Commands

### Running Tests

The project uses both Make and `build.zig` for flexibility:

```bash
# Recommended: Use Make for comprehensive test suites
make                      # Build + run all tests (unit + vectors + conformance)
make test                 # Run unit tests + RFC vectors
make test-unit            # Run only unit tests
make test-vectors         # Run RFC 8446/9001 test vectors
make test-conformance     # Run BoringSSL/OpenSSL conformance (requires libssl-dev)

# Alternative: Use zig build directly
zig build test            # Run all unit tests
zig build test-vectors    # Run RFC test vectors
zig build test-conformance # Run conformance tests (requires OpenSSL)

# Run tests for a single module
zig test src/alert.zig
zig test src/tls13.zig
zig test src/record.zig
```

### Development Workflow

```bash
# Quick development iteration (format + check + test)
make dev

# Format code
make fmt
# or
zig fmt src/ tests/

# Check syntax
make check
# or
zig ast-check src/tls13.zig

# Clean build artifacts
make clean
```

### Installing Dependencies

For conformance tests, you need OpenSSL development libraries:

```bash
# Auto-install for your OS
make install-deps

# Or manually:
# Ubuntu/Debian: sudo apt-get install libssl-dev pkg-config
# Fedora/RHEL: sudo dnf install openssl-devel pkg-config
# Arch: sudo pacman -S openssl pkg-config
# macOS: brew install openssl pkg-config
```

## Architecture

### Core Design Principles

1. **INTEROP FIRST** (defined in `src/tls13.zig`):
   - Always attempt to parse standard TLS 1.3 formats BEFORE falling back to minimal/test formats
   - Auto-detection preferred over configuration flags
   - Ensures compatibility with real-world QUIC implementations out-of-the-box

2. **RFC-Driven Development**:
   - Every implementation block cites the relevant RFC 8446 or RFC 9001 section
   - Example: `// RFC 8446 §5.1` for record framing

3. **Zig Stdlib Migration Path**:
   - Key schedule already uses `std.crypto.kdf.hkdf.Hkdf`
   - ASN.1/X.509 parsing currently custom but migration to stdlib planned (tracked in implementation plan)
   - AEAD operations use `std.crypto.aead` (AES-GCM, ChaCha20-Poly1305)

### Module Structure

```
src/
├── tls13.zig           # Main TLS 1.3 context & handshake state machine
│                       # Provides Config, Callbacks, Context types
│                       # Manages transcript hashing, secret derivation, CRYPTO frame processing
│
├── tls13_full.zig      # Full TLS 1.3 message parsing (ClientHello, ServerHello, extensions)
│                       # Defines ExtensionType, NamedGroup, SignatureScheme, CipherSuite
│                       # Handles real-world TLS format parsing for interop
│
├── record.zig          # TLS 1.3 record layer primitives (RFC 8446 §5)
│                       # TLSPlaintext/TLSInnerPlaintext framing
│                       # AEAD protection (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
│                       # Nonce derivation and usage limit tracking
│
├── key_schedule.zig    # HKDF-based key derivation (RFC 8446 §7, RFC 9001 §5.1)
│                       # Uses std.crypto.kdf.hkdf.Hkdf
│                       # Provides initial secrets, traffic secrets, key updates
│
├── x509.zig            # X.509 certificate parsing and validation (RFC 5280 subset)
│                       # Subject Alternative Names, Basic Constraints, Key Usage
│                       # Certificate validity checking, SNI matching
│
├── sig.zig             # Signature scheme handling (RFC 8446 §4.2.3, §4.4.3)
│                       # ECDSA (P-256, P-384), RSA-PSS, Ed25519
│                       # SubjectPublicKeyInfo parsing and signature verification
│
├── asn1.zig            # Minimal ASN.1 DER decoder for X.509
│                       # TLV parsing, SEQUENCE, INTEGER, BIT STRING, OID, etc.
│
├── alert.zig           # TLS alert protocol (RFC 8446 §6)
│                       # Alert descriptions, levels, QUIC error code mapping (RFC 9001 §4.8)
│
└── zero_rtt.zig        # 0-RTT ticket tracking and anti-replay (RFC 8446 §8)
                        # AntiReplayWindow, TicketState, FIFO eviction
```

### Key Data Flow

1. **Handshake Flow** (Client/Server):
   - QUIC receives CRYPTO frame data → `Context.processCrypto()`
   - Parse ClientHello/ServerHello → extract extensions (ALPN, key_share, transport params)
   - Update transcript hash → derive secrets via `key_schedule.zig`
   - Install traffic secrets → callback to QUIC layer (`on_secret_available`)
   - Emit Finished message → verify peer Finished
   - Transition to application data ready

2. **Secret Derivation**:
   - HKDF-Extract + HKDF-Expand with "tls13 " labels
   - Early Secret → Handshake Secret → Application Secret
   - Per-role (client/server) traffic secrets for send/receive
   - Key updates rotate secrets without full handshake

3. **Certificate Validation**:
   - Parse DER-encoded cert via `asn1.zig` → `x509.zig`
   - Check validity period, Extended Key Usage (serverAuth), SNI match
   - Extract SPKI → verify CertificateVerify signature via `sig.zig`
   - Trust anchor validation (optional TrustStore callback)

### Important Context for AI

- **Build system**: Uses both Makefile (recommended) and `build.zig`. The build system manages module dependencies and test orchestration. See `build.zig` for module import structure.
- **QUIC integration context**: This is not a standalone TLS library - it's designed to be embedded in a QUIC stack where CRYPTO frames replace traditional TLS records
- **Transcript management**: The TLS handshake messages are hashed incrementally; the transcript hash is critical for Finished message verification and must be updated in the exact order messages are processed
- **Secret callbacks**: When new encryption levels become available, the TLS layer calls back to QUIC (`on_secret_available`) so it can install keys for packet protection
- **Transport parameters**: QUIC-specific transport parameters are carried in TLS extension 0x0039 (quic_transport_parameters) in EncryptedExtensions
- **Cipher suite support**: Primary focus on TLS_AES_128_GCM_SHA256 (0x1301), with support for AES-256-GCM-SHA384 and ChaCha20-Poly1305
- **Version constraint**: Implementation targets Zig 0.15.1 specifically - stdlib APIs differ across Zig versions
- **Module organization**: Library is organized as interdependent Zig modules - see `src/lib.zig` for the public API surface and module re-exports

### RFC References

Key RFCs implemented (cited throughout code):
- **RFC 8446**: TLS 1.3 core protocol
- **RFC 9001**: QUIC transport TLS integration
- **RFC 9369**: QUIC v2 (label updates)
- **RFC 5280**: X.509 certificate format
- **RFC 7301**: ALPN extension

### Testing Strategy

The project has comprehensive test coverage across multiple levels:

- **Unit tests** (94 tests): Per-module tests with RFC subsection references (embedded in source files)
  - Run with: `make test-unit` or `zig build test`
  - Each module includes its own test suite

- **RFC test vectors** (13 tests): Validates compliance with RFC 8446 & RFC 9001
  - Run with: `make test-vectors` or `zig build test-vectors`
  - Located in: `tests/rfc8446_vectors.zig`
  - Tests HKDF key derivation, QUIC initial secrets, traffic secret expansion

- **Conformance tests** (67 tests): BoringSSL and OpenSSL parity testing
  - Run with: `make test-conformance` or `zig build test-conformance`
  - Located in: `tests/boringssl_conformance.zig` and `tests/openssl_conformance.zig`
  - Requires OpenSSL development libraries (`libssl-dev`)
  - Tests AEAD operations, HKDF compatibility, alert code mapping, transport parameters

**Total test count**: 174 tests across all suites

### Known Limitations and Future Work

**Implemented with full test coverage:**
- X.509 parsing - 26 unit tests (x509_unit_tests.zig) + 31 OpenSSL conformance tests
- ASN.1 DER decoder - 15 unit tests in asn1.zig
- Signature verification - 10 unit tests (sig_unit_tests.zig)
- Certificate chain validation (RFC 5280) - Fully tested via x509_unit_tests.zig and conformance tests
- KeyUsage extension parsing - Fixed and fully tested with OpenSSL conformance

**Implemented but with limited test coverage:**
- OCSP stapling (RFC 6960) - Fully implemented but lacks dedicated unit tests
- SCT parsing (RFC 6962) - Fully implemented with conformance tests only

**Implemented:**
- Advanced X.509 features: Name constraints (RFC 5280 §4.2.1.10), policy mapping (RFC 5280 §4.2.1.5), policy constraints (RFC 5280 §4.2.1.11)
- ChaCha20-Poly1305 OpenSSL conformance tests (enabled with runtime availability detection)

**Not yet implemented:**
- AES-128-CCM cipher suite variants (RFC 6655) - **Blocked**: Zig 0.15.1 stdlib does not include `std.crypto.aead.aes_ccm`. Implementation would require custom AES-CCM from scratch, which is complex and requires extensive cryptographic validation. AES-CCM is less common in modern QUIC deployments (most use AES-GCM or ChaCha20-Poly1305).

**Intentionally not supported:**
- Post-handshake authentication - Forbidden by RFC 9001 §4.4 for QUIC (client auth must occur during initial handshake)

### Code Style and Conventions

- RFC citations are MANDATORY for protocol logic: `// RFC 8446 §5.3`
- Error handling uses explicit Zig error unions, not panics
- Zeroization of secrets after use (see `record.zig` AEAD key handling)
- Allocator must be passed explicitly - no global allocators
- Buffer ownership clearly defined (caller-owned vs. callee-owned)
- Field naming: snake_case for struct fields, camelCase for function names (mixed in codebase)

### Security Considerations

- Constant-time operations for secret comparison (use `std.crypto.utils.timingSafeEql`)
- AEAD usage limits enforced per RFC 8446 §5.5
- Anti-replay window for 0-RTT (RFC 8446 §8.1)
- Transcript hash integrity critical - tampering must cause handshake failure
- Certificate validation includes validity period, EKU, and SNI matching
- Downgrade protection via random sentinel in ServerHello

### Debugging Tips

- Transcript hash mismatches: Enable logging in `key_schedule.zig` (has debug statements)
- Extension parsing issues: Check `tls13_full.zig` for format assumptions
- Secret derivation: Compare against RFC 8446 Appendix A test vectors
- Certificate errors: Verify DER encoding with `openssl x509 -inform DER -in cert.der -text`
- Test failures: Run `make clean` to clear Zig cache if tests fail unexpectedly after code changes

### Common Development Scenarios

**Adding a new cipher suite:**
1. Add enum variant to `CipherSuite` in `src/tls13_full.zig`
2. Update cipher suite mapping in `src/record.zig` for AEAD operations
3. Add HKDF variant in `src/key_schedule.zig` if needed (e.g., SHA-384 vs SHA-256)
4. Add test vectors in `tests/rfc8446_vectors.zig`
5. Add conformance tests in `tests/boringssl_conformance.zig` and `tests/openssl_conformance.zig`

**Adding a new signature scheme:**
1. Add enum variant to `SignatureScheme` in `src/tls13_full.zig`
2. Implement verification in `src/sig.zig` using `std.crypto.sign`
3. Add test certificates and signatures in test files
4. Update signature scheme negotiation in `src/tls13.zig`

**Modifying handshake flow:**
1. Update state machine in `src/tls13.zig` (see HandshakePhase enum)
2. Ensure transcript hash is updated in correct order
3. Update secret installation callbacks if encryption level changes
4. Add tests for new flow in `src/tls13.zig` test section

**Working with conformance tests:**
- These tests link against system OpenSSL/BoringSSL libraries
- If tests fail, check hex string lengths match buffer sizes (common issue)
- Use `hexToBytes()` utility function for test data conversion
- Conformance tests validate that ztls produces identical outputs to industry-standard implementations
