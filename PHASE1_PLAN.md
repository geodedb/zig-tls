# Phase 1 Implementation Plan: Security & Robustness

**Status:** In Progress
**Estimated Effort:** 3-4 weeks (80-120 hours)
**Started:** 2025-11-07

---

## Overview

Phase 1 from GAP_ANALYSIS.md focuses on three critical security features:
1. HelloRetryRequest (HRR) flow
2. Full X.509 certificate chain validation
3. Key update integration with AEAD limits

This document breaks down the implementation into manageable sub-tasks with dependencies.

---

## Task 1: HelloRetryRequest Implementation

### Background
RFC 8446 §4.1.4: HelloRetryRequest is NOT a separate message type. It's a ServerHello with:
- Special random value: SHA-256("HelloRetryRequest") = `0xcf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c`
- MUST include `supported_versions` extension
- MUST include one of: `key_share`, `cookie`, or `pre_shared_key`
- Cookie extension prevents DoS attacks

### Sub-tasks

#### 1.1 Add HRR Detection Constants
**File:** `src/tls13/messages/server_hello.zig`
**Effort:** 30 minutes

```zig
// RFC 8446 §4.1.3: HelloRetryRequest special random value
pub const HELLO_RETRY_REQUEST_RANDOM: [32]u8 = .{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

pub fn isHelloRetryRequest(random: [32]u8) bool {
    return std.mem.eql(u8, &random, &HELLO_RETRY_REQUEST_RANDOM);
}
```

#### 1.2 Add Cookie Extension Parsing
**File:** `src/tls13/messages/extensions/cookie.zig` (new file)
**Effort:** 2 hours

```zig
//! Cookie Extension (RFC 8446 §4.2.2)
//! Used in HelloRetryRequest to prevent DoS attacks

pub fn parseCookie(data: []const u8) ![]const u8 {
    // Extension format: uint16 length + opaque cookie<1..2^16-1>
    if (data.len < 2) return error.InvalidCookie;
    const len = std.mem.readInt(u16, data[0..2], .big);
    if (data.len < 2 + len) return error.TruncatedCookie;
    return data[2..2+len];
}

pub fn encodeCookie(alloc: std.mem.Allocator, cookie: []const u8) ![]u8 {
    var buf = try alloc.alloc(u8, 2 + cookie.len);
    std.mem.writeInt(u16, buf[0..2], @intCast(cookie.len), .big);
    @memcpy(buf[2..], cookie);
    return buf;
}
```

#### 1.3 Add Selected Group Extension
**File:** `src/tls13/messages/extensions/mod.zig`
**Effort:** 1 hour

Add parsing for `selected_group` extension (0x0033 in HRR context).

#### 1.4 HRR Transcript Hash Handling
**File:** `src/tls13/transcript.zig`
**Effort:** 3 hours

RFC 8446 §4.4.1: When HRR is used, the transcript becomes:
```
Hash(ClientHello1) + "HelloRetryRequest" + Hash(ServerHello=HRR) + ClientHello2 + ...
```

This requires:
1. Detect HRR from random value
2. Compute Hash(ClientHello1)
3. Create synthetic "message254" with the hash
4. Continue with normal transcript

```zig
pub fn handleHelloRetryRequest(
    self: *Transcript,
    client_hello1: []const u8,
    hrr: []const u8,
) !void {
    // Compute Hash(ClientHello1)
    var ch1_hash: [max_digest_length]u8 = undefined;
    const digest_len = self.hashLength();
    self.hash.update(client_hello1);
    self.hash.final(ch1_hash[0..digest_len]);

    // Reset and add synthetic message
    // message_hash = Hash("message254" + Hash(ClientHello1))
    // Then add HRR + future messages

    // Implementation details per RFC 8446 §4.4.1
}
```

#### 1.5 Server-Side HRR Generation
**File:** `src/tls13/context.zig`
**Effort:** 4 hours

When server detects no matching key_share group:
1. Generate random cookie value
2. Create ServerHello with HRR random
3. Include `cookie` and `selected_group` extensions
4. Send to client

#### 1.6 Client-Side HRR Handling
**File:** `src/tls13/context.zig`
**Effort:** 5 hours

When client receives HRR:
1. Detect HRR from random value
2. Extract `selected_group` from extensions
3. Generate new key_share for selected group
4. Echo `cookie` extension in ClientHello2
5. Update transcript with synthetic message
6. Resend ClientHello with new key_share

**Challenges:**
- Must support multiple named groups (currently only X25519)
- Need to preserve ClientHello1 for transcript
- State machine must handle "retry" state

#### 1.7 HRR State Machine Integration
**File:** `src/tls13/handshake_state.zig`
**Effort:** 2 hours

Add new phase: `waiting_hrr_response` for client.

**Total Effort for HRR:** ~17-20 hours

---

## Task 2: Full Certificate Chain Validation

### Background
RFC 5280 §6: Current implementation validates only the leaf certificate. Full path validation requires:
- Building trust paths from leaf to root
- Verifying each link's signature
- Enforcing path length constraints
- Validating name constraints

### Sub-tasks

#### 2.1 Chain Building Algorithm
**File:** `src/x509.zig`
**Effort:** 6 hours

```zig
pub const CertificateChain = struct {
    certificates: []const []const u8, // DER-encoded certs
    trust_anchor: ?[]const u8, // Root CA

    pub fn validate(
        self: *const CertificateChain,
        alloc: std.mem.Allocator,
        trust_store: ?TrustStore,
    ) !ValidationResult {
        // 1. Parse all certificates
        // 2. Build path: leaf -> intermediate(s) -> root
        // 3. Verify each signature
        // 4. Check validity periods
        // 5. Enforce path length constraints
        // 6. Validate name constraints
        // 7. Check against trust anchor
    }
};
```

#### 2.2 Trust Store Integration
**File:** `src/tls13/config.zig`
**Effort:** 3 hours

Add trust store callback:
```zig
pub const Config = struct {
    // ... existing fields ...

    /// Optional trust store for validating certificate chains.
    /// If null, chains must terminate in a self-signed root.
    trust_store: ?TrustStore = null,
};

pub const TrustStore = struct {
    /// Check if cert is a trusted root.
    /// Returns true if cert is in trust store.
    is_trusted: *const fn (cert_der: []const u8) bool,

    /// Optional: Get issuer cert for subject.
    /// Returns DER-encoded issuer cert or null.
    find_issuer: ?*const fn (subject_der: []const u8) ?[]const u8 = null,
};
```

#### 2.3 Path Length Constraint Enforcement
**File:** `src/x509.zig`
**Effort:** 2 hours

RFC 5280 §4.2.1.9: Basic Constraints extension includes pathLenConstraint.

#### 2.4 Name Constraints Enforcement
**File:** `src/x509.zig`
**Effort:** 4 hours

RFC 5280 §4.2.1.10: Enforce permitted/excluded DNS name subtrees.
Already parsed, need to enforce during chain validation.

#### 2.5 Signature Verification for Each Link
**File:** `src/sig.zig`
**Effort:** 3 hours

Verify each cert's signature using issuer's public key.

**Total Effort for Chain Validation:** ~18-22 hours

---

## Task 3: Key Update Integration

### Background
RFC 8446 §4.6.3 + RFC 9001 §6: Key updates allow refreshing traffic secrets without full handshake. Currently `key_schedule.zig` has derivation code but it's not integrated.

### Sub-tasks

#### 3.1 AEAD Limit Tracking Integration
**File:** `src/record/aead.zig`
**Effort:** 2 hours

Add counter tracking:
```zig
pub const AeadCipher = struct {
    // ... existing fields ...
    records_encrypted: u64 = 0,
    auth_failures: u64 = 0,

    pub fn nearingLimit(self: *const AeadCipher) bool {
        const limits = self.suite.default_limits;
        // Trigger key update at 90% of limit
        return self.records_encrypted >= (limits.confidentiality * 9 / 10);
    }
};
```

#### 3.2 KeyUpdate Message Encoding/Decoding
**File:** `src/tls13/messages.zig`
**Effort:** 2 hours

Add to HsType:
```zig
pub const HsType = enum(u8) {
    // ... existing types ...
    key_update = 24,
};
```

RFC 8446 §4.6.3:
```
struct {
    KeyUpdateRequest request_update;
} KeyUpdate;

enum { update_not_requested(0), update_requested(1) } KeyUpdateRequest;
```

#### 3.3 Context-Level Key Update API
**File:** `src/tls13/context.zig`
**Effort:** 4 hours

```zig
pub const Context = struct {
    // ... existing methods ...

    /// Initiate key update (send KeyUpdate message).
    /// RFC 8446 §4.6.3: Updates application traffic secrets.
    pub fn updateKeys(self: *Context, request_peer_update: bool) !void {
        // 1. Derive new application traffic secrets
        // 2. Install new secrets via callback
        // 3. Send KeyUpdate message
        // 4. Reset AEAD counters
    }

    /// Handle received KeyUpdate message.
    fn handleKeyUpdate(self: *Context, request_update: bool) !void {
        // 1. Derive new receive traffic secret
        // 2. Install new secret
        // 3. If request_update, send own KeyUpdate
    }
};
```

#### 3.4 Secret Manager Integration
**File:** `src/tls13/secret_manager.zig`
**Effort:** 3 hours

Track key update generation number for each direction.

#### 3.5 Automatic Key Update on Limit
**File:** `src/tls13/context.zig`
**Effort:** 2 hours

Check limit before each encryption, trigger update if needed.

**Total Effort for Key Update:** ~13-15 hours

---

## Task 4: Conformance Tests

### 4.1 HelloRetryRequest Tests
**File:** `tests/conformance/boringssl/hello_retry_request.zig`
**Effort:** 8 hours (10 tests)

**Dependencies:** Task 1 complete

### 4.2 Chain Validation Tests
**File:** `tests/conformance/openssl/chain_validation.zig`
**Effort:** 10 hours (15 tests)

**Dependencies:** Task 2 complete

### 4.3 Key Update Tests
**File:** `tests/conformance/boringssl/key_update.zig`
**Effort:** 6 hours (8 tests)

**Dependencies:** Task 3 complete

### 4.4 Security Test Suite
**File:** `tests/security/phase1_security.zig`
**Effort:** 12 hours (20 tests)

Includes:
- Downgrade attack prevention
- HRR replay protection
- Chain validation edge cases
- Key update race conditions
- Malformed message handling

**Total Effort for Tests:** ~36-40 hours

---

## Task 5: Downgrade Protection Verification

### Background
RFC 8446 §4.1.3: ServerHello.random contains sentinel values to detect downgrade attacks to TLS 1.2 or earlier.

### Sub-tasks

#### 5.1 Downgrade Sentinel Constants
**File:** `src/tls13/messages/server_hello.zig`
**Effort:** 1 hour

```zig
// RFC 8446 §4.1.3: Last 8 bytes of random for TLS 1.2 downgrade
pub const TLS12_DOWNGRADE_SENTINEL = [8]u8{
    0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01
};

// Last 8 bytes for TLS 1.1 or below downgrade
pub const TLS11_DOWNGRADE_SENTINEL = [8]u8{
    0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00
};
```

#### 5.2 Client-Side Downgrade Detection
**File:** `src/tls13/context.zig`
**Effort:** 2 hours

Check ServerHello.random last 8 bytes. If sentinel detected, abort with illegal_parameter alert.

#### 5.3 Server-Side Sentinel Injection (Defense)
**File:** `src/tls13/context.zig`
**Effort:** 1 hour

If server supports TLS 1.3 but negotiates lower version (impossible in QUIC), inject sentinel.

**Total Effort for Downgrade:** ~4 hours

---

## Overall Phase 1 Timeline

| Task | Effort | Dependencies |
|------|--------|--------------|
| HRR Implementation | 20h | None |
| Chain Validation | 22h | None (can parallelize) |
| Key Update | 15h | None (can parallelize) |
| Conformance Tests | 40h | Tasks 1-3 |
| Downgrade Protection | 4h | None |
| **Total** | **~101 hours** | **3-4 weeks** |

---

## Implementation Order

### Week 1: Foundation
- [ ] HRR constants and detection (1.1)
- [ ] Cookie extension (1.2)
- [ ] Transcript handling for HRR (1.4)
- [ ] Chain building algorithm (2.1)
- [ ] Trust store integration (2.2)

### Week 2: Core Logic
- [ ] Server-side HRR generation (1.5)
- [ ] Client-side HRR handling (1.6)
- [ ] HRR state machine (1.7)
- [ ] Path length constraints (2.3)
- [ ] Name constraints (2.4)

### Week 3: Key Update & Integration
- [ ] AEAD limit tracking (3.1)
- [ ] KeyUpdate messages (3.2)
- [ ] Context key update API (3.3)
- [ ] Secret manager integration (3.4)
- [ ] Automatic key update (3.5)
- [ ] Signature verification for chains (2.5)

### Week 4: Testing & Verification
- [ ] HRR conformance tests (4.1)
- [ ] Chain validation tests (4.2)
- [ ] Key update tests (4.3)
- [ ] Security test suite (4.4)
- [ ] Downgrade protection (5.1-5.3)
- [ ] Integration testing
- [ ] Documentation updates

---

## Risks & Mitigations

### Technical Risks

1. **HRR requires multi-group support**
   - **Risk:** Currently only X25519 implemented
   - **Mitigation:** Implement P-256 alongside HRR (adds ~8 hours)

2. **Chain validation complexity**
   - **Risk:** Path building can be exponential with multiple intermediates
   - **Mitigation:** Limit to 10 certs max, depth-first search with memoization

3. **Key update race conditions**
   - **Risk:** Concurrent key updates from both sides
   - **Mitigation:** Formal state machine verification, sequence numbering

4. **Test vector availability**
   - **Risk:** BoringSSL HRR vectors may be hard to extract
   - **Mitigation:** Generate own test cases with OpenSSL s_server

### Schedule Risks

1. **Underestimated complexity**
   - **Buffer:** 20% contingency (20 hours) built in

2. **Dependency on external tools**
   - **Mitigation:** Cache OpenSSL test certificates, use known versions

---

## Success Criteria

**Phase 1 Complete When:**
- ✅ All 53 conformance tests passing (10 HRR + 15 chain + 8 key update + 20 security)
- ✅ No regression in existing 629 tests
- ✅ HelloRetryRequest flow works with P-256 and X25519
- ✅ Certificate chains up to 5 levels validated correctly
- ✅ Key update triggered automatically at AEAD limit
- ✅ Downgrade attack detection functional
- ✅ Memory leak free (Valgrind clean)
- ✅ Documentation updated (CLAUDE.md, API docs)

---

## Next Steps

**Immediate Actions (This Session):**
1. ✅ Create PHASE1_PLAN.md (this document)
2. [ ] Implement HRR detection constants (1.1) - **15 minutes**
3. [ ] Add Cookie extension parsing (1.2) - **2 hours**
4. [ ] Create test file structure
5. [ ] Set up BoringSSL vector extraction

**Follow-up Actions:**
- Schedule code review after each major task
- Update GAP_ANALYSIS.md with progress
- Track hours spent vs. estimated

---

**Document Owner:** Claude Code
**Last Updated:** 2025-11-07
**Status:** Planning → Implementation
