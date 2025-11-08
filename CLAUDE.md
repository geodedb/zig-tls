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

# Run tests for specific modules
zig test src/alert.zig
zig test src/tls13/context.zig
zig test src/tls13/transcript.zig
zig test src/tls13/messages/client_hello.zig
zig test src/record/protection.zig
zig test src/quic_transport_params.zig
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
zig ast-check src/tls13/context.zig

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

### Module Structure (Modularization Phases 1-5 Complete)

The codebase is **fully modularized** into focused, single-responsibility modules:

```
src/
├── tls13/                      # Core TLS 1.3 modules (~4,000 lines total)
│   ├── config.zig              # Configuration (SNI, ALPN, certs, trust store)
│   ├── context.zig             # Main TLS driver, CRYPTO frame processing (~1,697 lines)
│   ├── engine.zig              # Legacy minimal driver (~1,759 lines)
│   ├── key_derivation.zig      # Traffic secret derivation (RFC 8446 §7.1)
│   ├── secret_manager.zig      # Secret lifecycle & installation
│   ├── state.zig               # Handshake state machine (RFC 8446 §4)
│   ├── transcript.zig          # Transcript hash management (RFC 8446 §4.4.1)
│   ├── callbacks.zig           # QUIC integration callbacks
│   ├── crypto_processor.zig    # CRYPTO frame buffering & parsing
│   └── handshake_flow.zig      # Message flow orchestration
│
├── tls13/messages/             # TLS 1.3 message parsing (~2,300 lines total)
│   ├── client_hello.zig        # ClientHello parsing (RFC 8446 §4.1.2)
│   ├── server_hello.zig        # ServerHello parsing (RFC 8446 §4.1.3)
│   ├── core_types.zig          # ExtensionType, NamedGroup, SignatureScheme, CipherSuite
│   ├── encrypted_extensions.zig # EncryptedExtensions (RFC 8446 §4.3.1)
│   ├── certificate.zig         # Certificate message (RFC 8446 §4.4.2)
│   ├── certificate_verify.zig  # CertificateVerify (RFC 8446 §4.4.3)
│   ├── finished.zig            # Finished message (RFC 8446 §4.4.4)
│   └── new_session_ticket.zig  # NewSessionTicket (RFC 8446 §4.6.1)
│
├── record/                     # TLS 1.3 record layer (RFC 8446 §5)
│   ├── types.zig               # TLSPlaintext, TLSInnerPlaintext, ContentType
│   ├── protection.zig          # AEAD protection (AES-GCM, ChaCha20-Poly1305)
│   └── limits.zig              # AEAD usage limits (RFC 8446 §5.5)
│
├── key_schedule.zig            # HKDF-based key derivation (RFC 8446 §7, RFC 9001 §5)
│                               # Uses std.crypto.kdf.hkdf.Hkdf
│
├── x509.zig                    # X.509 certificate parsing (RFC 5280)
│                               # SANs, Basic Constraints, Key Usage, SNI matching
│
├── sig.zig                     # Signature verification (RFC 8446 §4.2.3)
│                               # ECDSA (P-256, P-384), RSA-PSS, Ed25519
│
├── asn1.zig                    # ASN.1 DER decoder for X.509
│
├── ocsp.zig                    # OCSP stapling (RFC 6960)
│
├── sct.zig                     # SCT parsing (RFC 6962)
│
├── alert.zig                   # TLS alerts (RFC 8446 §6)
│
├── zero_rtt.zig                # 0-RTT anti-replay (RFC 8446 §8)
│
└── quic_transport_params.zig   # QUIC transport parameters (RFC 9001 §8.2, RFC 9000 §18)
```

**RFC Section to Module Mapping:**
- **RFC 8446 §4.1.2** ClientHello → `src/tls13/messages/client_hello.zig`
- **RFC 8446 §4.1.3** ServerHello → `src/tls13/messages/server_hello.zig`
- **RFC 8446 §4.2** Extensions → `src/tls13/messages/core_types.zig`, `encrypted_extensions.zig`
- **RFC 8446 §4.4.1** Transcript Hash → `src/tls13/transcript.zig`
- **RFC 8446 §4.4.4** Finished → `src/tls13/messages/finished.zig`
- **RFC 8446 §5** Record Layer → `src/record/protection.zig`, `src/record/types.zig`
- **RFC 8446 §7** Key Schedule → `src/key_schedule.zig`, `src/tls13/key_derivation.zig`
- **RFC 9001 §4** CRYPTO Frames → `src/tls13/context.zig` (processCrypto)
- **RFC 9001 §8.2** Transport Parameters → `src/quic_transport_params.zig`
- **RFC 5280** Certificates → `src/x509.zig`

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
- **Modular architecture**: Codebase is **fully modularized** (Phases 1-5 complete) with 21+ focused modules:
  - Core TLS 1.3: `src/tls13/` (10 modules for state, config, transcript, secrets, callbacks, etc.)
  - Message parsing: `src/tls13/messages/` (8 modules for ClientHello, ServerHello, extensions, etc.)
  - Record layer: `src/record/` (3 modules for types, protection, limits)
  - Supporting: key_schedule.zig, x509.zig, sig.zig, asn1.zig, quic_transport_params.zig, etc.
- **QUIC integration context**: This is not a standalone TLS library - it's designed to be embedded in a QUIC stack where CRYPTO frames replace traditional TLS records
  - CRYPTO frame processing: `src/tls13/crypto_processor.zig` and `src/tls13/context.zig`
  - Transport parameters: `src/quic_transport_params.zig` (RFC 9001 §8.2, RFC 9000 §18)
  - Encryption level callbacks: `src/tls13/callbacks.zig` and `src/tls13/secret_manager.zig`
- **Transcript management**: The TLS handshake messages are hashed incrementally via `src/tls13/transcript.zig`; the transcript hash is critical for Finished message verification and must be updated in the exact order messages are processed
- **Secret callbacks**: When new encryption levels become available, the TLS layer calls back to QUIC (`on_secret_available`) via `src/tls13/callbacks.zig` so it can install keys for packet protection
- **Transport parameters**: QUIC-specific transport parameters are carried in TLS extension 0x0039 (quic_transport_parameters) in EncryptedExtensions
- **Cipher suite support**: Primary focus on TLS_AES_128_GCM_SHA256 (0x1301), with support for AES-256-GCM-SHA384 and ChaCha20-Poly1305
- **Version constraint**: Implementation targets Zig 0.15.1 specifically - stdlib APIs differ across Zig versions
- **Module organization**: Library is organized as interdependent Zig modules - see `src/lib.zig` for the public API surface and module re-exports. Each module maps to specific RFC sections for traceability.

### RFC References

Key RFCs implemented (cited throughout code):
- **RFC 8446**: TLS 1.3 core protocol
- **RFC 9001**: QUIC transport TLS integration
- **RFC 9369**: QUIC v2 (label updates)
- **RFC 5280**: X.509 certificate format
- **RFC 7301**: ALPN extension

### Testing Strategy

The project has comprehensive test coverage across multiple levels:

- **Unit tests** (262 tests): Per-module tests with RFC subsection references (embedded in source files)
  - Run with: `make test-unit` or `zig build test`
  - Each module includes its own test suite
  - Covers all 21+ modules in the modular architecture

- **RFC compliance tests** (148 tests): Validates strict adherence to RFC specifications
  - Run with: `make test` (included in default test suite)
  - **RFC 8446** (79 tests): TLS 1.3 protocol tests organized by section
    - `tests/rfc8446/section_4_1_2_client_hello.zig` (16 tests)
    - `tests/rfc8446/section_4_1_3_server_hello.zig` (11 tests)
    - `tests/rfc8446/section_4_2_extensions.zig` (13 tests)
    - `tests/rfc8446/section_4_4_finished.zig` (10 tests)
    - And more covering all TLS 1.3 protocol aspects
  - **RFC 9001** (52 tests): QUIC-TLS integration tests
    - `tests/rfc9001/section_4_crypto_frames.zig` (23 tests)
    - `tests/rfc9001/section_8_2_transport_params.zig` (18 tests)
    - `tests/rfc9001/section_5_key_schedule.zig` (11 tests)
  - **RFC 5280** (17 tests): X.509 certificate structure tests
    - `tests/rfc5280/section_4_certificate_structure.zig`

- **RFC test vectors** (13 tests): Official test vectors from RFC appendices
  - Run with: `make test-vectors` or `zig build test-vectors`
  - Located in: `tests/rfc8446_vectors.zig`
  - Tests HKDF key derivation, QUIC initial secrets, traffic secret expansion

- **Conformance tests** (430 tests): BoringSSL and OpenSSL parity testing
  - Run with: `make test-conformance` or `zig build test-conformance`
  - Requires OpenSSL development libraries (`libssl-dev`)
  - **BoringSSL conformance** (123 tests):
    - Core: `tests/conformance/boringssl.zig` (34 tests)
    - Performance: `tests/conformance/boringssl/performance.zig` (12 tests)
    - Memory: `tests/conformance/boringssl/memory_optimization.zig` (15 tests)
    - Post-Quantum: `tests/conformance/boringssl/post_quantum_readiness.zig` (12 tests)
    - Fuzzing: `tests/conformance/boringssl/fuzzing.zig` (20 tests)
    - Key Update: `tests/conformance/boringssl/key_update.zig` (8 tests)
    - Client Auth: `tests/conformance/boringssl/client_auth.zig` (10 tests)
    - P-256/P-384: `tests/conformance/boringssl/p256_ecdhe.zig` (12 tests)
  - **OpenSSL conformance** (279 tests):
    - Core: `tests/conformance/openssl.zig` (90 tests)
    - Chain Validation: `tests/conformance/openssl/chain_validation.zig` (26 tests)
    - OCSP: `tests/conformance/openssl/ocsp_validation.zig` (13 tests)
    - CRL: `tests/conformance/openssl/crl_validation.zig` (31 tests)
    - AIA: `tests/conformance/openssl/aia_validation.zig` (34 tests)
    - Advanced X.509: `tests/conformance/openssl/advanced_x509.zig` (13 tests)
    - Name Constraints: `tests/conformance/openssl/name_constraints.zig` (10 tests)
    - Policy Validation: `tests/conformance/openssl/policy_validation.zig` (12 tests)
    - Crypto Suites: `tests/conformance/openssl/cipher_suites.zig` (16 tests)
    - FFDHE: `tests/conformance/openssl/ffdhe.zig` (8 tests)
    - SCT/CT: `tests/conformance/openssl/sct_validation.zig` (8 tests)
    - Hello Retry Request: `tests/conformance/openssl/hello_retry_request.zig` (8 tests)
    - Zero-RTT: `tests/conformance/openssl/zero_rtt.zig` (10 tests)
  - **RFC 8446 conformance** (28 tests):
    - Extensions: `tests/conformance/rfc8446/extensions.zig` (15 tests)
    - PSK Modes: `tests/conformance/rfc8446/psk_modes.zig` (13 tests)
  - Tests AEAD operations, HKDF compatibility, alert code mapping, transport parameters, X.509 validation, cryptographic algorithm parity, performance characteristics, memory safety, fuzzing robustness, and post-quantum readiness

**Total test count**: 853 tests across all suites (262 unit + 148 RFC compliance + 13 vectors + 430 conformance)

All tests include RFC section citations for traceability and are organized to match the specification structure.

### Known Limitations and Future Work

**Implemented with full test coverage:**
- X.509 parsing - 26 unit tests (x509_unit_tests.zig) + 31 OpenSSL conformance tests
- ASN.1 DER decoder - 15 unit tests in asn1.zig
- Signature verification - 10 unit tests (sig_unit_tests.zig)
- Certificate chain validation (RFC 5280) - Fully tested via x509_unit_tests.zig and conformance tests
- KeyUsage extension parsing - Fixed and fully tested with OpenSSL conformance
- Advanced X.509 extensions (RFC 5280):
  - Name Constraints (§4.2.1.10) - Permitted/excluded DNS name subtrees
  - Policy Mappings (§4.2.1.5) - Cross-domain policy equivalence
  - Policy Constraints (§4.2.1.11) - Policy validation constraints
- ChaCha20-Poly1305 conformance - 1 OpenSSL test with runtime availability detection

**Implemented but with limited test coverage:**
- OCSP stapling (RFC 6960) - Fully implemented, 28 unit tests + 13 OpenSSL conformance tests
- SCT parsing (RFC 6962) - Fully implemented, 18 unit tests + 8 OpenSSL conformance tests

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

- **Transcript hash mismatches**: Enable logging in `src/tls13/transcript.zig` and `src/key_schedule.zig` (have debug statements)
- **Extension parsing issues**: Check `src/tls13/messages/core_types.zig` and specific message parsers for format assumptions
- **ClientHello/ServerHello issues**: See `src/tls13/messages/client_hello.zig` and `src/tls13/messages/server_hello.zig`
- **Handshake state errors**: Check `src/tls13/state.zig` for state machine transitions and `src/tls13/handshake_flow.zig` for message flow
- **CRYPTO frame processing**: Debug `src/tls13/crypto_processor.zig` for buffering and `src/tls13/context.zig` for processCrypto logic
- **Secret derivation**: Compare against RFC 8446 Appendix A test vectors; check `src/tls13/key_derivation.zig` and `src/key_schedule.zig`
- **AEAD protection errors**: See `src/record/protection.zig` for encryption/decryption and `src/record/limits.zig` for usage limits
- **Certificate errors**: Verify DER encoding with `openssl x509 -inform DER -in cert.der -text`; check `src/x509.zig` and `src/asn1.zig`
- **Transport parameters**: Debug `src/quic_transport_params.zig` for encoding/decoding issues
- **Test failures**: Run `make clean` to clear Zig cache if tests fail unexpectedly after code changes

### Common Development Scenarios

**Adding a new cipher suite:**
1. Add enum variant to `CipherSuite` in `src/tls13/messages/core_types.zig`
2. Update cipher suite mapping in `src/record/protection.zig` for AEAD operations
3. Add HKDF variant in `src/key_schedule.zig` if needed (e.g., SHA-384 vs SHA-256)
4. Update cipher suite negotiation in `src/tls13/context.zig` or `src/tls13/handshake_flow.zig`
5. Add test vectors in `tests/rfc8446_vectors.zig`
6. Add conformance tests in `tests/boringssl_conformance.zig` and `tests/openssl_conformance.zig`
7. Add RFC compliance tests in `tests/rfc8446/section_4_1_3_server_hello.zig` (cipher suite negotiation)

**Adding a new signature scheme:**
1. Add enum variant to `SignatureScheme` in `src/tls13/messages/core_types.zig`
2. Implement verification in `src/sig.zig` using `std.crypto.sign`
3. Add test certificates and signatures in test files
4. Update signature scheme negotiation in `src/tls13/messages/certificate_verify.zig`
5. Add tests to `tests/rfc8446/section_4_2_extensions.zig` (signature_algorithms extension)

**Modifying handshake flow:**
1. Update state machine in `src/tls13/state.zig` (HandshakePhase enum)
2. Update message processing in `src/tls13/handshake_flow.zig`
3. Ensure transcript hash is updated in correct order via `src/tls13/transcript.zig`
4. Update secret installation callbacks in `src/tls13/secret_manager.zig` if encryption level changes
5. Add tests for new flow in relevant `tests/rfc8446/section_*.zig` files

**Working with TLS 1.3 messages:**
- **Parsing ClientHello**: See `src/tls13/messages/client_hello.zig` + `tests/rfc8446/section_4_1_2_client_hello.zig`
- **Parsing ServerHello**: See `src/tls13/messages/server_hello.zig` + `tests/rfc8446/section_4_1_3_server_hello.zig`
- **Extension handling**: See `src/tls13/messages/core_types.zig` + `tests/rfc8446/section_4_2_extensions.zig`
- **Finished message**: See `src/tls13/messages/finished.zig` + `tests/rfc8446/section_4_4_finished.zig`

**Working with QUIC integration:**
- **CRYPTO frame processing**: See `src/tls13/crypto_processor.zig` and `src/tls13/context.zig` (processCrypto method)
- **Transport parameters**: See `src/quic_transport_params.zig` + `tests/rfc9001/section_8_2_transport_params.zig`
- **Encryption level transitions**: See `src/tls13/secret_manager.zig` and callbacks in `src/tls13/callbacks.zig`

**Working with conformance tests:**
- These tests link against system OpenSSL/BoringSSL libraries
- If tests fail, check hex string lengths match buffer sizes (common issue)
- Use `hexToBytes()` utility function for test data conversion
- Conformance tests validate that ztls produces identical outputs to industry-standard implementations
- Test categories organized by verification focus:
  - **Cryptographic parity**: HKDF, AEAD, signatures, key exchange (BoringSSL/OpenSSL)
  - **X.509 validation**: Certificate parsing, chain validation, extensions, revocation (OpenSSL)
  - **Protocol compliance**: TLS 1.3 extensions, handshake flows, state machine (RFC 8446)
  - **Performance**: Handshake latency, memory usage, hot path optimization (BoringSSL)
  - **Security**: Fuzzing robustness, input validation, error handling (BoringSSL)
  - **Future compatibility**: Post-quantum algorithm parsing (BoringSSL)
- Module-specific conformance coverage:
  - HKDF/key schedule: `src/key_schedule.zig` (BoringSSL vectors)
  - AEAD operations: `src/record/protection.zig` (BoringSSL/OpenSSL parity)
  - Transport parameters: `src/quic_transport_params.zig` (BoringSSL/OpenSSL)
  - X.509 parsing: `src/x509.zig` (OpenSSL parity + advanced extensions)
  - Certificate chain validation: `src/x509.zig` (OpenSSL multi-level chains)
  - OCSP/CRL: `src/ocsp.zig`, `src/crl.zig` (OpenSSL validation)
  - Signature verification: `src/sig.zig` (BoringSSL/OpenSSL schemes)
  - State machine: `src/tls13/state.zig` (RFC 8446 transitions)
