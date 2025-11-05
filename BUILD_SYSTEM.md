# zig-tls Build System

This document describes the build system setup for the zig-tls TLS 1.3 implementation.

## Overview

The project now includes a comprehensive `build.zig` that provides:

1. **Module System**: All TLS components are exposed as Zig modules
2. **Unit Tests**: Individual tests for each module
3. **Integration Tests**: RFC 8446 test vector validation
4. **Conformance Tests**: BoringSSL and OpenSSL parity testing

## Building

```bash
# Build the library
zig build

# Run all unit tests (default)
zig build test

# Run RFC 8446 test vectors
zig build test-vectors

# Run conformance tests (requires libssl-dev installed)
zig build test-conformance
```

## Project Structure

### Library Modules

The following modules are exposed and can be imported:

- `zig-tls` - Main library entry point (re-exports everything)
- `tls13` - TLS 1.3 handshake state machine
- `quic_tls` - Key schedule (HKDF-based key derivation)
- `record` - TLS 1.3 record layer and AEAD operations
- `x509` - X.509 certificate parsing and validation
- `sig` - Signature scheme handling
- `asn1` - ASN.1 DER decoder
- `alert` - TLS alert protocol
- `zero_rtt` - 0-RTT ticket tracking and anti-replay
- `tls13_full` - Full TLS 1.3 message parsing
- `quic_logger` - Logging interface (placeholder)
- `quic_transport_params` - QUIC transport parameters (placeholder)

### Source Files

```
src/
├── lib.zig                    # Main library entrypoint
├── tls13.zig                  # TLS 1.3 context & handshake
├── tls13_full.zig             # Full message parsing
├── key_schedule.zig           # HKDF key derivation
├── record.zig                 # Record layer & AEAD
├── x509.zig                   # Certificate parsing
├── sig.zig                    # Signature verification
├── asn1.zig                   # ASN.1 decoder
├── alert.zig                  # Alert protocol
├── zero_rtt.zig               # 0-RTT support
├── quic_logger.zig            # Logging (placeholder)
└── quic_transport_params.zig  # Transport params (placeholder)
```

### Test Files

```
tests/
├── rfc8446_vectors.zig        # RFC 8446 & 9001 test vectors
├── boringssl_conformance.zig  # BoringSSL parity tests
└── openssl_conformance.zig    # OpenSSL parity tests
```

## Test Coverage

### Unit Tests (77 tests total)

All source modules include embedded tests that validate:
- Core functionality of each module
- RFC compliance at the module level
- Edge cases and error conditions

Run with: `zig build test`

### RFC Test Vectors (13 tests)

Validates compliance with:
- **RFC 9001 Appendix A**: QUIC-TLS initial secret derivation
- **RFC 8446 Appendix A**: TLS 1.3 key schedule test vectors

Tests include:
- QUIC initial secret derivation (v1 and v2)
- HKDF-Extract and HKDF-Expand operations
- Traffic key expansion
- Key update procedures
- Exporter and resumption secret derivation

Run with: `zig build test-vectors`

### Conformance Tests

#### BoringSSL Conformance

Validates that our implementation produces identical cryptographic outputs to BoringSSL for:
- HKDF-Extract and HKDF-Expand
- QUIC initial secret derivation
- Client/server traffic secret derivation
- AES-128-GCM AEAD operations
- Alert code compatibility
- SHA-256 transcript hashing

#### OpenSSL 3.x Conformance

Validates compatibility with OpenSSL 3.x using the EVP API:
- HKDF using EVP_PKEY_derive
- AES-128-GCM and AES-256-GCM
- ChaCha20-Poly1305 availability
- SHA-256/384/512 hash functions
- Key update procedures
- Exporter secret derivation

Run with: `zig build test-conformance`

**Note**: Conformance tests require OpenSSL development libraries:
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# macOS (via Homebrew)
brew install openssl
```

## Implementation Notes

### HKDF-Expand-Label

The current implementation uses Zig stdlib's `std.crypto.kdf.hkdf.Hkdf` for basic HKDF operations. The TLS 1.3 `HKDF-Expand-Label` format (RFC 8446 §7.1) needs to be implemented as a wrapper that:

1. Constructs the HkdfLabel structure:
   ```
   struct {
       uint16 length = Length;
       opaque label<7..255> = "tls13 " + Label;
       opaque context<0..255> = Context;
   } HkdfLabel;
   ```

2. Calls `HkdfSha256.expand(output, HkdfLabel, prk)`

This is tracked as a TODO in `tests/rfc8446_vectors.zig`.

### Placeholder Modules

Two modules are currently placeholders:
- `quic_logger.zig` - Provides a no-op logging interface
- `quic_transport_params.zig` - Basic structure definitions

These will be replaced by actual QUIC stack implementations when integrated.

## Zig Version

This project targets **Zig 0.15.1** specifically. The build.zig uses the new module API introduced in Zig 0.15:
- `b.addModule()` for public modules
- `b.createModule()` for test-only modules
- `.imports` field for dependency resolution

## Integration Guide

To use this library in your QUIC implementation:

```zig
const std = @import("std");
const tls = @import("zig-tls");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // Configure TLS context
    const config = tls.Config{
        .allocator = gpa.allocator(),
        .role = .client,
        .supported_cipher_suites = &.{.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .alpn_protocols = &.{"h3"},
    };

    // Create callbacks
    const callbacks = tls.Callbacks{
        .on_secret_available = mySecretCallback,
        .on_handshake_complete = myHandshakeCompleteCallback,
    };

    // Initialize context
    var ctx = try tls.Context.init(config, callbacks);
    defer ctx.deinit();

    // Process incoming CRYPTO frames
    try ctx.processCrypto(crypto_data);
}
```

See `src/lib.zig` for the complete public API.

## Contributing

When adding new features:

1. Add module to `build.zig` with proper dependencies
2. Include unit tests in the source file
3. Update integration tests if RFC compliance is affected
4. Add conformance tests if affecting cryptographic operations
5. Document in `CLAUDE.md` for AI assistance context

## Testing Best Practices

- **Unit tests**: Test individual functions and edge cases
- **Integration tests**: Validate RFC compliance with real test vectors
- **Conformance tests**: Ensure interoperability with OpenSSL/BoringSSL
- **Fuzz tests**: (Future) Add fuzz harnesses for parsing logic

## Performance

The build system supports multiple optimization levels:

```bash
# Debug build (default)
zig build -Doptimize=Debug

# Release with safety checks
zig build -Doptimize=ReleaseSafe

# Release optimized for speed
zig build -Doptimize=ReleaseFast

# Release optimized for size
zig build -Doptimize=ReleaseSmall
```

## License

See main project LICENSE file.
