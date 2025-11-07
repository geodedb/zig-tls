# Modularization Plan: RFC-Specific Code Organization

## Executive Summary

This document outlines a plan to split the large monolithic files (`tls13.zig` - 4033 lines, `tls13_full.zig` - 1499 lines) into smaller, RFC-specific modules with dedicated unit tests.

**Goals:**
1. Improve code navigability and maintainability
2. Isolate RFC-specific logic for easier verification
3. Create focused unit tests matching RFC sections
4. Reduce compilation times through better modularity
5. Enable parallel development on different protocol areas

## Current File Analysis

### Large Files Requiring Modularization

| File | Lines | Primary RFCs | Responsibilities |
|------|-------|--------------|------------------|
| `tls13.zig` | 4033 | RFC 8446, 9001, 9369 | Handshake state machine, key schedule, Engine API |
| `tls13_full.zig` | 1499 | RFC 8446 §4, §4.2 | Message parsing/building, extensions |
| `record.zig` | 1381 | RFC 8446 §5 | TLS record layer, AEAD operations |
| `x509.zig` | 1310 | RFC 5280 | Certificate parsing and validation |
| `quic_transport_params.zig` | 1182 | RFC 9000, 9001 §8.2 | QUIC transport parameter encoding |
| `asn1.zig` | 1032 | ITU-T X.690 | ASN.1 DER encoding/decoding |

### Files Already Well-Modularized (Keep As-Is)

| File | Lines | Status | Rationale |
|------|-------|--------|-----------|
| `key_schedule.zig` | 889 | ✅ Keep | Single RFC focus (8446 §7), well-tested |
| `sig.zig` | 957 | ✅ Keep | Focused on signature operations (8446 §4.4.3) |
| `alert.zig` | 296 | ✅ Keep | Small, single-purpose (8446 §6) |
| `zero_rtt.zig` | 403 | ✅ Keep | Focused on 0-RTT logic (8446 §8) |
| `ocsp.zig` | 312 | ✅ Keep | Single RFC focus (6960) |
| `sct.zig` | 97 | ✅ Keep | Single RFC focus (6962) |

---

## Phase 1: Split `tls13.zig` (4033 lines)

### Target Module Structure

```
src/tls13/
├── mod.zig                      # Public API re-exports (200 lines)
├── handshake_state.zig          # HandshakePhase, state transitions (300 lines)
│   └── RFC 8446 §4: Handshake Protocol
├── context.zig                  # Context struct, main driver (800 lines)
│   └── RFC 8446 §4: Full handshake flow
├── engine.zig                   # Engine struct, legacy API (1200 lines)
│   └── RFC 9001 §4: QUIC-TLS integration
├── transcript.zig               # Transcript hash management (200 lines)
│   └── RFC 8446 §4.4.1: Transcript-Hash
├── finished.zig                 # Finished message logic (300 lines)
│   └── RFC 8446 §4.4.4: Finished
├── certificate_verify.zig       # CertificateVerify handling (400 lines)
│   └── RFC 8446 §4.4.3: CertificateVerify
└── key_derivation.zig           # Public key derivation helpers (300 lines)
    └── RFC 8446 §7.1: Key Schedule (wrappers for key_schedule.zig)
```

### Module Responsibilities

#### `mod.zig` - Public API Surface
```zig
//! TLS 1.3 for QUIC - Main Module
//!
//! RFC References:
//! - RFC 8446: Transport Layer Security (TLS) Version 1.3
//! - RFC 9001: Using TLS to Secure QUIC
//! - RFC 9369: QUIC Version 2

pub const Context = @import("context.zig").Context;
pub const Engine = @import("engine.zig").Engine;
pub const Config = @import("context.zig").Config;
pub const Callbacks = @import("context.zig").Callbacks;
// ... re-export public API
```

#### `handshake_state.zig` - State Machine (300 lines)
```zig
//! Handshake State Machine
//!
//! RFC 8446 §4: Handshake Protocol
//! RFC 9001 §4: TLS Handshake

/// RFC 8446 §4: Handshake protocol phases
pub const HandshakePhase = enum {
    initial,              // RFC 8446 §4: Before any messages
    negotiating,          // RFC 8446 §4.1.2: After ClientHello received
    keys_installed,       // RFC 9001 §5: After handshake secrets installed
    application_ready,    // RFC 8446 §4.4.4: After both Finished messages
};

pub const HandshakeState = struct {
    phase: HandshakePhase,
    flags: HandshakeFlags,
    
    pub fn init() HandshakeState { ... }
    pub fn canSendFinished(self: *const HandshakeState) bool { ... }
    pub fn markFinishedSent(self: *HandshakeState) void { ... }
};
```

**Unit Tests:**
- `tests/tls13/handshake_state_test.zig` (RFC 8446 §4 test vectors)

#### `transcript.zig` - Transcript Hash (200 lines)
```zig
//! Transcript Hash Management
//!
//! RFC 8446 §4.4.1: Transcript-Hash
//! 
//! The transcript hash is computed as:
//!   Hash(Handshake Context) = Hash(Messages)
//! where Messages is the concatenation of all Handshake messages.

pub const Transcript = struct {
    sha256: std.crypto.hash.sha2.Sha256,
    sha384: std.crypto.hash.sha2.Sha384,
    
    /// Initialize empty transcript.
    /// RFC 8446 §4.4.1: Transcript hash begins empty
    pub fn init() Transcript { ... }
    
    /// Update transcript with handshake message.
    /// RFC 8446 §4.4.1: Messages MUST be included in order sent/received
    pub fn update(self: *Transcript, msg: []const u8) void { ... }
    
    /// Finalize transcript for given hash algorithm.
    /// RFC 8446 §4.4.1: Returns Hash(Messages)
    pub fn finalize(self: *Transcript, hash: Hash) Secret { ... }
};
```

**Unit Tests:**
- `tests/tls13/transcript_test.zig` (RFC 8446 §4.4.1 test vectors)
- Verify hash matches RFC 8446 Appendix C.1 traces

---

## Phase 2: Split `tls13_full.zig` (1499 lines)

### Target Module Structure

```
src/tls13/messages/
├── mod.zig                      # Message type re-exports (100 lines)
├── client_hello.zig             # ClientHello parsing/building (400 lines)
│   └── RFC 8446 §4.1.2: ClientHello
├── server_hello.zig             # ServerHello parsing/building (300 lines)
│   └── RFC 8446 §4.1.3: ServerHello
├── encrypted_extensions.zig    # EncryptedExtensions (200 lines)
│   └── RFC 8446 §4.3.1: EncryptedExtensions
├── certificate.zig              # Certificate message (300 lines)
│   └── RFC 8446 §4.4.2: Certificate
├── extensions/
│   ├── mod.zig                  # Extension registry (100 lines)
│   ├── key_share.zig            # key_share extension (200 lines)
│   │   └── RFC 8446 §4.2.8: Key Share
│   ├── supported_versions.zig  # supported_versions (100 lines)
│   │   └── RFC 8446 §4.2.1: Supported Versions
│   ├── signature_algorithms.zig # signature_algorithms (150 lines)
│   │   └── RFC 8446 §4.2.3: Signature Algorithms
│   ├── alpn.zig                 # ALPN extension (150 lines)
│   │   └── RFC 7301: ALPN
│   └── quic_transport_params.zig # quic_transport_parameters (100 lines)
       └── RFC 9001 §8.2: QUIC Transport Parameters Extension
```

### Module Responsibilities

#### `messages/client_hello.zig` (400 lines)
```zig
//! ClientHello Message
//!
//! RFC 8446 §4.1.2: ClientHello
//!
//! Structure:
//!   uint16 ProtocolVersion;
//!   opaque Random[32];
//!   opaque legacy_session_id<0..32>;
//!   CipherSuite cipher_suites<2..2^16-2>;
//!   opaque legacy_compression_methods<1..2^8-1>;
//!   Extension extensions<8..2^16-1>;

pub const ClientHello = struct {
    legacy_version: u16,        // RFC 8446 §4.1.2: MUST be 0x0303
    random: [32]u8,             // RFC 8446 §4.1.2: Client random
    session_id: []const u8,     // RFC 8446 §4.1.2: Legacy field (middlebox compat)
    cipher_suites: []const CipherSuite, // RFC 8446 §4.1.2: Offered ciphers
    extensions: Extensions,     // RFC 8446 §4.2: Extension block
};

/// Parse ClientHello from wire format.
/// RFC 8446 §4.1.2: Validates structure and extensions
pub fn parse(allocator: std.mem.Allocator, data: []const u8) !ClientHello { ... }

/// Build ClientHello for transmission.
/// RFC 8446 §4.1.2: Constructs valid ClientHello with required extensions
pub fn build(allocator: std.mem.Allocator, params: ClientHelloParams) ![]u8 { ... }
```

**Unit Tests:**
- `tests/tls13/messages/client_hello_test.zig`
- Test vectors from RFC 8446 Appendix C.1
- Malformed ClientHello rejection tests

#### `extensions/key_share.zig` (200 lines)
```zig
//! Key Share Extension
//!
//! RFC 8446 §4.2.8: Key Share
//!
//! The "key_share" extension contains the endpoint's cryptographic parameters
//! for ECDHE key agreement.

pub const KeyShareEntry = struct {
    group: NamedGroup,          // RFC 8446 §4.2.7: Named group identifier
    key_exchange: []const u8,   // RFC 8446 §4.2.8: Public key bytes
};

pub const KeyShareClientHello = struct {
    client_shares: []const KeyShareEntry, // RFC 8446 §4.2.8: Client offers
};

pub const KeyShareServerHello = struct {
    server_share: KeyShareEntry, // RFC 8446 §4.2.8: Server selects one
};

/// Parse key_share extension from ClientHello.
/// RFC 8446 §4.2.8: Validates group and key lengths
pub fn parseClientShare(data: []const u8) !KeyShareClientHello { ... }

/// Parse key_share extension from ServerHello.
/// RFC 8446 §4.2.8: Single selected group
pub fn parseServerShare(data: []const u8) !KeyShareServerHello { ... }
```

**Unit Tests:**
- `tests/tls13/extensions/key_share_test.zig`
- X25519 key share parsing (RFC 8446 §4.2.8.2)
- Invalid key length rejection

---

## Phase 3: Modularize `record.zig` (1381 lines)

### Target Module Structure

```
src/record/
├── mod.zig                      # Public API (100 lines)
├── plaintext.zig                # TLSPlaintext/TLSInnerPlaintext (300 lines)
│   └── RFC 8446 §5.1, §5.2: Record Protocol
├── aead.zig                     # AEAD cipher operations (500 lines)
│   └── RFC 8446 §5.3: Per-Record Nonce, §5.2: Record Payload Protection
├── cipher_suites.zig            # Cipher suite definitions (200 lines)
│   └── RFC 8446 §B.4: Cipher Suites
└── nonce.zig                    # Nonce derivation and limits (300 lines)
    └── RFC 8446 §5.3: Per-Record Nonce, §5.5: Limits on Key Usage
```

#### `record/aead.zig` (500 lines)
```zig
//! AEAD Operations
//!
//! RFC 8446 §5.2: Record Payload Protection
//! RFC 8446 §5.3: Per-Record Nonce

pub const AeadCipher = struct {
    cipher_suite: CipherSuite,
    key: []u8,
    iv: []u8,
    
    /// Initialize AEAD cipher with traffic secret.
    /// RFC 8446 §5.2: AEAD keys derived from traffic secret via HKDF-Expand-Label
    pub fn init(suite: CipherSuite, key: []const u8, iv: []const u8) !AeadCipher { ... }
    
    /// Seal plaintext into ciphertext with AEAD.
    /// RFC 8446 §5.2: AEAD(key, nonce, additional_data, plaintext)
    pub fn seal(self: *AeadCipher, alloc: std.mem.Allocator, seq: u64, 
                ad: []const u8, pt: []const u8) ![]u8 { ... }
    
    /// Open ciphertext into plaintext with AEAD.
    /// RFC 8446 §5.2: Verify authentication tag before returning plaintext
    pub fn open(self: *AeadCipher, alloc: std.mem.Allocator, seq: u64,
                ad: []const u8, ct: []const u8) ![]u8 { ... }
};
```

**Unit Tests:**
- `tests/record/aead_test.zig`
- RFC 8446 Appendix C.2 AEAD test vectors
- OpenSSL/BoringSSL conformance (existing tests remain)

---

## Phase 4: Create RFC-Specific Test Structure

### Test Organization

```
tests/
├── rfc8446/
│   ├── section_4_1_2_client_hello_test.zig      # ClientHello tests
│   ├── section_4_1_3_server_hello_test.zig      # ServerHello tests
│   ├── section_4_2_8_key_share_test.zig         # Key Share extension
│   ├── section_4_4_1_transcript_hash_test.zig   # Transcript tests
│   ├── section_4_4_4_finished_test.zig          # Finished message
│   ├── section_5_2_aead_test.zig                # AEAD operations
│   ├── section_7_1_key_schedule_test.zig        # Key derivation
│   └── appendix_c_test_vectors.zig              # Full RFC test vectors
├── rfc9001/
│   ├── section_4_quic_tls_test.zig              # QUIC-TLS handshake
│   ├── section_5_1_packet_protection_test.zig   # Packet protection keys
│   ├── section_8_2_transport_params_test.zig    # Transport parameters
│   └── initial_secrets_test.zig                 # Initial secret derivation
├── rfc5280/
│   ├── section_4_2_certificate_test.zig         # Certificate structure
│   ├── section_6_path_validation_test.zig       # Path validation
│   └── extension_tests.zig                      # X.509 extensions
└── conformance/
    ├── boringssl_hkdf_test.zig                  # Existing conformance
    ├── openssl_aead_test.zig
    └── ...
```

### Test Template

```zig
//! RFC 8446 §4.1.2: ClientHello Tests
//!
//! Validates ClientHello message structure and parsing per RFC 8446 §4.1.2.

const std = @import("std");
const testing = std.testing;
const ClientHello = @import("tls13").messages.ClientHello;

/// RFC 8446 §4.1.2: ClientHello MUST include legacy_version = 0x0303
test "ClientHello legacy_version must be 0x0303" {
    const data = // ... test vector from RFC 8446 Appendix C.1
    const ch = try ClientHello.parse(testing.allocator, data);
    defer ch.deinit(testing.allocator);
    
    try testing.expectEqual(@as(u16, 0x0303), ch.legacy_version);
}

/// RFC 8446 §4.1.2: Random MUST be 32 bytes
test "ClientHello random field is 32 bytes" {
    const data = // ... test vector
    const ch = try ClientHello.parse(testing.allocator, data);
    defer ch.deinit(testing.allocator);
    
    try testing.expectEqual(@as(usize, 32), ch.random.len);
}

/// RFC 8446 §4.2: ClientHello MUST contain supported_versions extension
test "ClientHello requires supported_versions extension" {
    const data_without_sv = // ... malformed test vector
    const result = ClientHello.parse(testing.allocator, data_without_sv);
    
    try testing.expectError(error.MissingSupportedVersions, result);
}
```

---

## Phase 5: Build System Updates

### New `build.zig` Structure

```zig
// Module tree with explicit RFC documentation
const tls13_mod = b.addModule("tls13", .{
    .root_source_file = b.path("src/tls13/mod.zig"),
    .imports = &.{
        .{ .name = "key_schedule", .module = key_schedule_mod },
        .{ .name = "x509", .module = x509_mod },
        .{ .name = "sig", .module = sig_mod },
    },
});

const tls13_messages_mod = b.addModule("tls13_messages", .{
    .root_source_file = b.path("src/tls13/messages/mod.zig"),
    .imports = &.{
        .{ .name = "extensions", .module = extensions_mod },
    },
});

// RFC-specific test suites
const rfc8446_tests = b.addTest(.{
    .name = "rfc8446-compliance",
    .root_source_file = b.path("tests/rfc8446/mod.zig"),
    .target = target,
    .optimize = optimize,
});
rfc8446_tests.root_module.addImport("tls13", tls13_mod);

const rfc9001_tests = b.addTest(.{
    .name = "rfc9001-compliance",
    .root_source_file = b.path("tests/rfc9001/mod.zig"),
    .target = target,
    .optimize = optimize,
});
```

---

## Implementation Timeline

### Week 1: Analysis & Preparation
- [ ] Complete detailed code mapping for tls13.zig
- [ ] Identify all inter-module dependencies
- [ ] Create stub module structure
- [ ] Set up test infrastructure

### Week 2: Split `tls13.zig`
- [ ] Extract `transcript.zig` (200 lines, minimal deps)
- [ ] Extract `handshake_state.zig` (300 lines)
- [ ] Create unit tests for above modules
- [ ] Extract `finished.zig` (300 lines)
- [ ] Verify all existing tests still pass

### Week 3: Split `tls13_full.zig`
- [ ] Extract `client_hello.zig`, `server_hello.zig`
- [ ] Extract extension modules
- [ ] Create RFC 8446 §4.2.x tests
- [ ] Verify conformance tests pass

### Week 4: Split `record.zig` & Polish
- [ ] Extract AEAD operations
- [ ] Extract nonce management
- [ ] Create RFC 8446 §5.x tests
- [ ] Final integration testing
- [ ] Documentation updates

---

## Migration Strategy

### Backward Compatibility

Maintain existing API through `src/lib.zig` re-exports:

```zig
// src/lib.zig - Stable public API
pub const tls13 = @import("tls13/mod.zig");
pub const Context = tls13.Context;  // Re-export for compatibility
pub const Engine = tls13.Engine;
// ... existing exports unchanged
```

### Incremental Migration

1. **Phase 1:** Create new modules alongside existing code
2. **Phase 2:** Update internal imports to use new modules
3. **Phase 3:** Move code from old files to new modules
4. **Phase 4:** Delete old monolithic files
5. **Phase 5:** Update external consumers (if any)

### Testing at Each Step

```bash
# After each module extraction:
make test              # Unit tests
make test-vectors      # RFC test vectors
make test-conformance  # OpenSSL/BoringSSL parity
```

**Rule:** Never commit code that breaks existing tests.

---

## Benefits

### Immediate

1. **Easier Navigation** - Find RFC 8446 §4.2.8 code in `extensions/key_share.zig`
2. **Faster Compilation** - Only recompile changed modules
3. **Clearer Testing** - Test vectors match module structure
4. **Better Documentation** - Each module documents its RFC section

### Long-Term

1. **Parallel Development** - Multiple developers can work on different RFC sections
2. **Easier Auditing** - Security review per RFC section
3. **Protocol Evolution** - Add TLS 1.4 features in new modules
4. **Code Reuse** - Use transcript.zig in other TLS implementations

---

## Risk Mitigation

### Risks

1. **Regression Introduction** - Breaking existing functionality
2. **Incomplete Migration** - Leaving code in inconsistent state
3. **Performance Impact** - Additional module boundaries
4. **API Instability** - Breaking downstream consumers

### Mitigation

1. **Comprehensive Testing**
   - Run full test suite after each change
   - Add regression tests for found issues
   - Maintain >=99% test pass rate

2. **Incremental Approach**
   - Complete one module at a time
   - Verify tests pass before next module
   - Can pause/resume at any point

3. **Performance Monitoring**
   - Benchmark key operations before/after
   - Use `inline` hints for hot paths
   - Zig optimizer eliminates module boundaries

4. **API Stability**
   - Maintain `src/lib.zig` re-exports
   - Use semantic versioning
   - Document breaking changes

---

## Success Metrics

### Quantitative

- ✅ Reduce largest file from 4033 to <1000 lines
- ✅ Achieve >95% test coverage per module
- ✅ Maintain 99.4% test pass rate (326/328 tests)
- ✅ Compilation time ≤ current baseline
- ✅ Zero breaking changes to public API

### Qualitative

- ✅ RFC section → code file mapping is intuitive
- ✅ New contributor can find relevant code in <5 minutes
- ✅ Security auditor can verify RFC compliance per module
- ✅ Code reviews focus on single RFC section
- ✅ Module documentation matches RFC structure

---

## Next Steps

1. **Approve Plan** - Review and approve this modularization approach
2. **Create Branches** - Set up feature branches for each phase
3. **Begin Phase 1** - Start with `transcript.zig` (smallest, fewest deps)
4. **Continuous Integration** - Ensure CI runs all tests on each commit
5. **Iterate** - Adjust plan based on findings during implementation

---

**Document Version:** 1.0  
**Created:** 2025-11-07  
**Status:** Proposed (Pending Approval)  
**Estimated Effort:** 4 weeks (160 hours)  
**Risk Level:** Medium (mitigated through incremental approach)
