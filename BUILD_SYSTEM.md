# ztls Build System Documentation

**Last Updated**: 2025-11-07 (Phase 5 - Build System Finalization)

This document describes the build system for the ztls TLS 1.3 implementation, including module organization, dependencies, test structure, and usage patterns.

## Overview

The ztls build system is implemented in `build.zig` using Zig 0.15.1's module system. The project is organized around RFC-mapped modules with comprehensive test coverage across unit tests, RFC test vectors, and conformance tests.

**Key Features**:
- **Modular Architecture**: 15+ focused modules mapped to RFC sections
- **RFC-Organized Tests**: 260+ tests organized by RFC 8446, RFC 9001, and RFC 5280
- **Zero Dependencies**: Uses only Zig standard library
- **Comprehensive Testing**: Unit tests, RFC vectors, BoringSSL/OpenSSL conformance
- **Backward Compatibility**: All public APIs maintained through modularization

## Module Organization

The library has been modularized through Phases 1-3 of the modularization plan (see MODULARIZATION_PROGRESS.md). Modules are organized hierarchically with clear RFC mappings:

### Core Protocol Modules

#### **tls13** - RFC 8446: TLS 1.3 Core Protocol / RFC 9001: QUIC-TLS Integration
- **Path**: `src/tls13.zig` + `src/tls13/` (modularized)
- **Purpose**: Main handshake state machine, context management, CRYPTO frame processing
- **Exports**: Config, Callbacks, Context, HandshakePhase, Role
- **Modularization Status**: Phase 1 (~41% complete, Context/Engine deferred)
- **Submodules**:
  - `src/tls13/types.zig` - Core types (Role, errors, metadata)
  - `src/tls13/transcript.zig` - RFC 8446 §4.4.1 Transcript hashing
  - `src/tls13/handshake_state.zig` - State machine, CRYPTO buffering
  - `src/tls13/secrets.zig` - Traffic secret management
  - `src/tls13/finished.zig` - RFC 8446 §4.4.4 Finished message verification
  - `src/tls13/key_derivation.zig` - TLS 1.3 key schedule wrappers
  - `src/tls13/messages.zig` - Message parsing and encoding
  - `src/tls13/mod.zig` - Public API re-exports

#### **tls13_full** - RFC 8446: Full Message Parsing
- **Path**: `src/tls13_full.zig` + `src/tls13/messages/` (modularized)
- **Purpose**: Complete TLS 1.3 message parsing for real-world interop
- **Exports**: ExtensionType, NamedGroup, SignatureScheme, CipherSuite, ClientHello, ServerHello
- **Modularization Status**: Phase 2 (100% complete)
- **Submodules**:
  - `src/tls13/messages/core_types.zig` - Extension/cipher suite enums
  - `src/tls13/messages/helpers.zig` - RFC 8446 §3, §4.2 encoding helpers
  - `src/tls13/messages/client_hello.zig` - RFC 8446 §4.1.2, §4.2 ClientHello parsing
  - `src/tls13/messages/server_hello.zig` - RFC 8446 §4.1.3 ServerHello building
  - `src/tls13/messages/encrypted_extensions.zig` - RFC 8446 §4.3.1 EncryptedExtensions
  - `src/tls13/messages/certificate.zig` - RFC 8446 §4.4.2 Certificate parsing
  - `src/tls13/messages/certificate_verify.zig` - RFC 8446 §4.4.3 CertificateVerify
  - `src/tls13/messages/finished.zig` - RFC 8446 §4.4.4 Finished building

#### **record** - RFC 8446 §5: Record Protocol
- **Path**: `src/record.zig` + `src/record/` (modularized)
- **Purpose**: TLS 1.3 record layer, AEAD operations, nonce derivation
- **Exports**: PlaintextView, InnerPlaintext, AeadCipher, AeadUsageLimits
- **Modularization Status**: Phase 3 (100% complete)
- **Submodules**:
  - `src/record/plaintext.zig` - RFC 8446 §5.1, §5.4 TLSPlaintext/InnerPlaintext
  - `src/record/aead.zig` - RFC 8446 §5.2, §5.3, §5.5 AEAD operations
  - `src/record/mod.zig` - Public API re-exports

### Cryptographic Modules

#### **quic_tls** (key_schedule) - RFC 8446 §7 / RFC 9001 §5.1
- **Path**: `src/key_schedule.zig`
- **Purpose**: HKDF-based key derivation, traffic secrets, key updates
- **Exports**: HkdfSha256, HkdfSha384, initial_salt_v1, initial_salt_v2, expandLabel
- **Dependencies**: None (uses std.crypto.kdf.hkdf)
- **Key Functions**:
  - HKDF-Extract and HKDF-Expand (RFC 5869)
  - TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1)
  - QUIC initial secret derivation (RFC 9001 Appendix A)
  - Traffic key/IV derivation (RFC 9001 §5.1)

#### **sig** - RFC 8446 §4.2.3, §4.4.3: Signature Schemes
- **Path**: `src/sig.zig`
- **Purpose**: Signature scheme handling and verification
- **Exports**: SignatureScheme (re-exported from tls13_full), verify functions
- **Supported**: ECDSA (P-256, P-384), RSA-PSS, Ed25519
- **Dependencies**: asn1 (for SubjectPublicKeyInfo parsing)

### Certificate and X.509 Modules

#### **x509** - RFC 5280: X.509 Public Key Infrastructure
- **Path**: `src/x509.zig`
- **Purpose**: Certificate parsing, validation, path building
- **Exports**: Certificate, CertificateChain, TrustStore, ValidationOptions
- **Key Features**:
  - Validity period checking
  - Subject Alternative Names (SAN) parsing and matching
  - Basic Constraints (CA vs end-entity)
  - Extended Key Usage (EKU) validation
  - Certificate path validation
- **Dependencies**: asn1, sig

#### **asn1** - ASN.1 DER Decoder
- **Path**: `src/asn1.zig`
- **Purpose**: Minimal ASN.1 DER decoder for X.509
- **Exports**: Tag, Class, Element, parseElement, parseSequence, parseOID
- **Supported**: SEQUENCE, INTEGER, BIT STRING, OCTET STRING, OID, UTCTime, GeneralizedTime
- **Dependencies**: None

### Protocol Support Modules

#### **alert** - RFC 8446 §6: Alert Protocol
- **Path**: `src/alert.zig`
- **Purpose**: TLS alert descriptions, severity levels, QUIC error mapping
- **Exports**: AlertDescription, AlertLevel, toQuicError (RFC 9001 §4.8)
- **Dependencies**: None

#### **zero_rtt** - RFC 8446 §8: 0-RTT and Anti-Replay
- **Path**: `src/zero_rtt.zig`
- **Purpose**: 0-RTT ticket tracking, anti-replay window
- **Exports**: TicketState, AntiReplayWindow
- **Dependencies**: None

### Placeholder Modules

#### **quic_logger** - Logging Interface
- **Path**: `src/quic_logger.zig`
- **Purpose**: No-op logging interface (replaced by QUIC stack)
- **Dependencies**: None

#### **quic_transport_params** - QUIC Transport Parameters
- **Path**: `src/quic_transport_params.zig`
- **Purpose**: Basic structure definitions (replaced by QUIC stack)
- **Dependencies**: None

### Main Library Entrypoint

#### **ztls** - Public API
- **Path**: `src/lib.zig`
- **Purpose**: Main library entrypoint, re-exports all public APIs
- **Exports**: Everything from all modules (consolidated)

## Module Dependency Graph

```
ztls (lib.zig)
├── tls13 (main handshake state machine)
│   ├── tls13_full (message parsing)
│   │   └── (no dependencies)
│   ├── record (record layer)
│   │   └── quic_tls (key schedule)
│   ├── x509 (certificate validation)
│   │   ├── asn1 (DER parsing)
│   │   └── sig (signature verification)
│   │       └── asn1
│   ├── quic_tls (key schedule)
│   ├── alert (alert protocol)
│   ├── zero_rtt (0-RTT support)
│   ├── quic_logger (logging stub)
│   └── quic_transport_params (transport params stub)
├── tls13_full
├── record
│   └── quic_tls
├── quic_tls
├── x509
│   ├── asn1
│   └── sig
│       └── asn1
├── sig
│   └── asn1
├── asn1
├── alert
├── zero_rtt
├── quic_logger
└── quic_transport_params
```

**Dependency Rules**:
- Cryptographic modules (quic_tls, asn1) have no dependencies
- Certificate modules (x509, sig) depend only on asn1
- Record layer depends only on key schedule
- Main TLS module integrates all components

## Build Targets

### Development Commands

```bash
# Quick development iteration (format + check + test)
make dev

# Build library only
zig build

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

### Test Targets

```bash
# Run ALL tests (unit + RFC vectors + conformance)
make
# or
make test

# Run only unit tests (194/196 tests)
make test-unit
# or
zig build test

# Run RFC test vectors (66 tests)
make test-vectors
# or
zig build test-vectors

# Run conformance tests (67 tests, requires OpenSSL)
make test-conformance
# or
zig build test-conformance

# Run specific RFC test suites
zig build test-rfc8446     # TLS 1.3 tests (47 tests)
zig build test-rfc9001     # QUIC-TLS tests (19 tests)
zig build test-rfc5280     # X.509 tests (placeholder)

# Run specific test file
zig test src/record.zig
zig test tests/rfc8446/section_5_record_protocol.zig
```

## Test Organization

The test suite is organized across three levels with **340 total tests**:

### Unit Tests (194/196 tests, 99.0%)

Embedded in source files, testing individual module functionality:
- `src/tls13.zig` - Handshake state machine tests
- `src/record.zig` - Record layer and AEAD tests
- `src/key_schedule.zig` - HKDF and key derivation tests
- `src/x509.zig` - Certificate parsing tests (26 tests)
- `src/asn1.zig` - ASN.1 DER decoder tests (15 tests)
- `src/sig.zig` - Signature verification tests (10 tests)
- `src/alert.zig` - Alert code tests
- `src/zero_rtt.zig` - Anti-replay window tests

**Run with**: `make test-unit` or `zig build test`

### RFC Test Vectors (66 tests, 100%)

**Phase 4 Addition**: RFC-organized test structure

Tests organized by RFC section number in `tests/rfc8446/` and `tests/rfc9001/`:

#### RFC 8446 Tests (47 tests)
Located in `tests/rfc8446/`:
- `section_4_4_1_transcript.zig` - 10 tests for transcript hash (§4.4.1)
- `section_4_4_4_finished.zig` - 10 tests for Finished message (§4.4.4)
- `section_5_record_protocol.zig` - 12 tests for record layer (§5)
- `section_7_1_key_schedule.zig` - 6 tests for key schedule (§7.1)
- `appendix_a_vectors.zig` - 9 tests for complete key schedule (Appendix A)

#### RFC 9001 Tests (19 tests)
Located in `tests/rfc9001/`:
- `appendix_a_initial_secrets.zig` - 8 tests for QUIC initial secrets (Appendix A)
- `section_5_packet_protection.zig` - 11 tests for packet protection (§5)

#### RFC 5280 Tests (placeholder)
Located in `tests/rfc5280/`:
- `mod.zig` - Placeholder for future X.509 tests

**Run with**: `make test-vectors` or `zig build test-vectors`

**Run specific RFC**: `zig build test-rfc8446` or `zig build test-rfc9001`

### Conformance Tests (67 tests)

Validates compatibility with industry-standard TLS implementations:

#### BoringSSL Conformance (36 tests)
Located in `tests/boringssl_conformance.zig`:
- HKDF-Extract and HKDF-Expand (6 tests)
- QUIC initial secrets (4 tests)
- Traffic secret derivation (4 tests)
- AES-128-GCM AEAD (6 tests)
- Alert code mapping (10 tests)
- SHA-256 transcript hashing (6 tests)

#### OpenSSL 3.x Conformance (31 tests)
Located in `tests/openssl_conformance.zig`:
- HKDF using EVP_PKEY_derive (4 tests)
- AES-128-GCM and AES-256-GCM (8 tests)
- ChaCha20-Poly1305 availability (1 test)
- SHA-256/384/512 hash functions (6 tests)
- Key update procedures (4 tests)
- Exporter secret derivation (8 tests)

**Requires**: OpenSSL development libraries (`libssl-dev`)

**Install dependencies**:
```bash
# Auto-detect and install for your OS
make install-deps

# Or manually:
# Ubuntu/Debian: sudo apt-get install libssl-dev pkg-config
# Fedora/RHEL: sudo dnf install openssl-devel pkg-config
# Arch: sudo pacman -S openssl pkg-config
# macOS: brew install openssl pkg-config
```

**Run with**: `make test-conformance` or `zig build test-conformance`

### Test Coverage Summary

| Test Category | Count | Pass Rate | Purpose |
|--------------|-------|-----------|---------|
| Unit Tests | 194/196 | 99.0% | Module-level functionality |
| RFC 8446 Tests | 47/47 | 100% | TLS 1.3 compliance |
| RFC 9001 Tests | 19/19 | 100% | QUIC-TLS compliance |
| RFC 5280 Tests | 0 (placeholder) | - | X.509 compliance (future) |
| BoringSSL Conformance | 36/36 | 100% | BoringSSL parity |
| OpenSSL Conformance | 31/31 | 100% | OpenSSL 3.x parity |
| **Total** | **327/329** | **99.4%** | Comprehensive validation |

**Note**: 2 tests skipped are platform-specific.

## Adding New Modules

To add a new module to the build system:

1. **Create module file** in `src/` or appropriate submodule directory
2. **Add module definition** to `build.zig`:

```zig
// RFC XXXX §Y: Module Description
const my_module = b.addModule("my_module", .{
    .root_source_file = b.path("src/my_module.zig"),
    .target = target,
    .imports = &.{
        .{ .name = "dependency_module", .module = dependency_mod },
    },
});
```

3. **Add to library imports** in the ztls module:
```zig
const ztls_mod = b.addModule("ztls", .{
    .root_source_file = b.path("src/lib.zig"),
    .target = target,
    .imports = &.{
        // ... existing imports ...
        .{ .name = "my_module", .module = my_module },
    },
});
```

4. **Re-export in lib.zig** if part of public API:
```zig
pub const my_module = @import("my_module");
```

5. **Add module tests** to test executable:
```zig
lib_unit_tests.root_module.addImport("my_module", my_module);
```

6. **Document in CLAUDE.md** for AI assistance context

## Import Patterns

### In Source Files

```zig
// Import from same package
const tls13 = @import("tls13");
const record = @import("record");

// Import stdlib
const std = @import("std");
const crypto = std.crypto;

// Import from test context (test files only)
const testing = std.testing;
const key_schedule = @import("quic_tls");
```

### In Build.zig

```zig
// Create module with dependencies
const my_mod = b.addModule("my_module", .{
    .root_source_file = b.path("src/my_module.zig"),
    .target = target,
    .imports = &.{
        .{ .name = "imported_name", .module = other_module },
    },
});

// Add to test executable
test_exe.root_module.addImport("my_module", my_mod);
```

## Cross-Compilation

```bash
# Linux x86_64
zig build -Dtarget=x86_64-linux

# macOS ARM64
zig build -Dtarget=aarch64-macos

# Windows x86_64
zig build -Dtarget=x86_64-windows
```

## Optimization Levels

```bash
# Debug build (default, best for development)
zig build -Doptimize=Debug

# Release with safety checks (recommended for production)
zig build -Doptimize=ReleaseSafe

# Release optimized for speed
zig build -Doptimize=ReleaseFast

# Release optimized for size
zig build -Doptimize=ReleaseSmall
```

## Troubleshooting

### Test Failures After Changes

```bash
# Clean Zig cache
make clean
# or
rm -rf zig-cache zig-out

# Rebuild and test
make test
```

### Conformance Tests Fail

```bash
# Check OpenSSL is installed
pkg-config --modversion openssl

# Reinstall dependencies
make install-deps

# Run conformance tests with verbose output
zig build test-conformance --summary all
```

### Module Not Found Errors

1. Check module is defined in `build.zig`
2. Verify module is added to imports of dependent modules
3. Check import name matches module definition
4. Ensure module path is correct

### RFC Test Failures

1. Check test file is in correct RFC directory (`tests/rfc8446/`, etc.)
2. Verify mod.zig re-exports the test module
3. Ensure build.zig includes the RFC test suite
4. Run specific test file: `zig test tests/rfc8446/section_X.zig`

## Development Workflow

Recommended workflow for making changes:

```bash
# 1. Make your changes to source files
vim src/tls13.zig

# 2. Format code
make fmt

# 3. Check syntax
make check

# 4. Run relevant tests
zig test src/tls13.zig          # Unit tests for changed module
zig build test-rfc8446           # RFC tests if protocol changes
zig build test-conformance       # Conformance if crypto changes

# 5. Run full test suite
make test

# 6. Commit changes
git add src/tls13.zig
git commit -m "feat: add X.509 extension parsing"
```

## Zig Version Requirement

This project targets **Zig 0.15.1** specifically. The build system uses APIs introduced in Zig 0.15:
- `b.addModule()` for public modules
- `b.createModule()` for test-only modules (deprecated, now using addModule for test-internal modules)
- `.imports` field for dependency resolution
- `b.path()` for file paths (replaces older `b.pathJoin()`)

**Incompatibilities with older Zig versions**:
- Zig 0.14.x and earlier use different module APIs
- Stdlib APIs (especially `std.crypto`) differ across versions

## Integration Example

To use ztls in your QUIC implementation:

```zig
const std = @import("std");
const ztls = @import("ztls");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // Configure TLS context
    const config = ztls.Config{
        .allocator = gpa.allocator(),
        .role = .client,
        .supported_cipher_suites = &.{.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .alpn_protocols = &.{"h3"},
    };

    // Create callbacks
    const callbacks = ztls.Callbacks{
        .on_secret_available = mySecretCallback,
        .on_handshake_complete = myHandshakeCompleteCallback,
    };

    // Initialize context
    var ctx = try ztls.Context.init(config, callbacks);
    defer ctx.deinit();

    // Process incoming CRYPTO frames from QUIC
    try ctx.processCrypto(crypto_level, crypto_data);

    // Get outgoing CRYPTO data
    const outgoing = try ctx.getCryptoData();
}

fn mySecretCallback(level: ztls.EncryptionLevel, secret: []const u8) void {
    // Install traffic secrets in QUIC packet protection
}

fn myHandshakeCompleteCallback() void {
    // Handshake complete, application data ready
}
```

## Build System Files

- **build.zig** - Main build configuration (~400 lines)
- **build.zig.zon** - Package metadata (not yet created)
- **Makefile** - Convenience wrapper for common commands

## Future Enhancements

Potential build system improvements (not currently planned):

1. **Package Manager Integration**: Add `build.zig.zon` for Zig package manager
2. **Fuzz Testing**: Add fuzz targets using `zig build fuzz`
3. **Benchmarking**: Add benchmark suite for crypto operations
4. **Documentation Generation**: Auto-generate docs from source comments
5. **Code Coverage**: Integrate kcov or similar for coverage reports

## References

- **MODULARIZATION_PLAN.md** - Original modularization plan
- **MODULARIZATION_PROGRESS.md** - Current progress and phase completion status
- **PHASE1_COMPLETE.md** - Phase 1 (tls13.zig modularization) completion report
- **PHASE2_COMPLETE.md** - Phase 2 (tls13_full.zig modularization) completion report
- **PHASE3_COMPLETE.md** - Phase 3 (record.zig modularization) completion report
- **PHASE4_COMPLETE.md** - Phase 4 (RFC test structure) completion report
- **CLAUDE.md** - AI assistance context and development guidelines

## License

See main project LICENSE file.
