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

Tests are embedded in source files using Zig's built-in test framework:

```bash
# Run all tests in a specific file
zig test src/alert.zig
zig test src/tls13.zig
zig test src/record.zig

# Run tests for all modules
find src -name "*.zig" -exec zig test {} \;
```

Note: There is no `build.zig` file yet - tests are run directly via `zig test`.

### Checking Syntax

```bash
# Check syntax without running
zig ast-check src/tls13.zig
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

- **No build system yet**: Tests run via `zig test <file>` directly
- **QUIC integration context**: This is not a standalone TLS library - it's designed to be embedded in a QUIC stack where CRYPTO frames replace traditional TLS records
- **Transcript management**: The TLS handshake messages are hashed incrementally; the transcript hash is critical for Finished message verification and must be updated in the exact order messages are processed
- **Secret callbacks**: When new encryption levels become available, the TLS layer calls back to QUIC (`on_secret_available`) so it can install keys for packet protection
- **Transport parameters**: QUIC-specific transport parameters are carried in TLS extension 0x0039 (quic_transport_parameters) in EncryptedExtensions
- **Cipher suite limitation**: Currently focused on TLS_AES_128_GCM_SHA256 (0x1301) as the primary suite
- **Version constraint**: Implementation targets Zig 0.15.1 specifically - stdlib APIs differ across Zig versions

### RFC References

Key RFCs implemented (cited throughout code):
- **RFC 8446**: TLS 1.3 core protocol
- **RFC 9001**: QUIC transport TLS integration
- **RFC 9369**: QUIC v2 (label updates)
- **RFC 5280**: X.509 certificate format
- **RFC 7301**: ALPN extension

### Testing Strategy

- **Unit tests**: Per-module tests with RFC subsection references (embedded in source files)
- **Integration tests**: Planned in `tests/` directory for full handshake flows
- **Fuzz targets**: Harnesses for message parsing, certificate handling
- **Property tests**: HKDF vector validation, transcript hash invariants

### Known Gaps and Future Work

- OCSP stapling and SCT (Signed Certificate Timestamp) support - placeholders exist
- Full certificate chain validation - currently validates leaf only
- Additional cipher suites (AES-256-GCM-SHA384, AES-128-CCM variants)
- Post-handshake authentication and key updates (partial implementation exists)

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
