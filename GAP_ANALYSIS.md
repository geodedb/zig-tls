# ztls Implementation Gap Analysis & Phased Roadmap

**Document Version:** 1.0
**Date:** 2025-11-07
**Project:** ztls - TLS 1.3 for QUIC (Zig 0.15.1)

---

## Executive Summary

This document provides a comprehensive analysis of implementation gaps in ztls against RFC 8446 (TLS 1.3) and RFC 9001 (QUIC-TLS), organized into 6 phased milestones with corresponding conformance tests against BoringSSL/OpenSSL.

**Current Status:**
- ✅ **Implemented:** Full 1-RTT handshake (ECDHE-only), X.509 validation, 3 cipher suites, basic QUIC integration
- ⚠️ **Partial:** PSK infrastructure, 0-RTT framework, client authentication hooks
- ❌ **Missing:** PSK handshake flow, HelloRetryRequest, FFDHE groups, full chain validation, key updates

**Test Coverage:** 629 tests (344 unit + 148 RFC compliance + 13 vectors + 124 conformance)

---

## 1. Current Implementation Inventory

### 1.1 Core Protocol Features

| Feature | RFC Section | Status | Notes |
|---------|-------------|--------|-------|
| Full 1-RTT Handshake (ECDHE) | RFC 8446 §2 | ✅ Complete | X25519 only |
| PSK Handshake (PSK-only) | RFC 8446 §2.2 | ❌ Missing | Extension parsing exists |
| PSK-DHE Handshake | RFC 8446 §2.2 | ❌ Missing | Hybrid mode |
| 0-RTT Data (Client) | RFC 8446 §2.3 | ⚠️ Partial | Anti-replay exists, no send flow |
| 0-RTT Data (Server Accept/Reject) | RFC 8446 §4.2.10 | ⚠️ Partial | Detection only |
| HelloRetryRequest | RFC 8446 §4.1.4 | ❌ Missing | Critical for group negotiation |
| Post-Handshake Authentication | RFC 8446 §4.6.2 | 🚫 Forbidden | RFC 9001 §4.4 |
| NewSessionTicket (Send) | RFC 8446 §4.6.1 | ⚠️ Partial | Parsing exists, no emission |
| Key Update | RFC 8446 §4.6.3 | ⚠️ Partial | Code exists, not integrated |
| Client Authentication | RFC 8446 §4.4.2 | ⚠️ Partial | Server-side request not impl |

### 1.2 Cryptographic Algorithms

| Algorithm | Type | RFC | Status | Notes |
|-----------|------|-----|--------|-------|
| TLS_AES_128_GCM_SHA256 | Cipher | RFC 8446 §B.4 | ✅ Complete | Primary suite |
| TLS_AES_256_GCM_SHA384 | Cipher | RFC 8446 §B.4 | ✅ Complete | SHA-384 support |
| TLS_CHACHA20_POLY1305_SHA256 | Cipher | RFC 8446 §B.4 | ✅ Complete | Runtime detection |
| TLS_AES_128_CCM_SHA256 | Cipher | RFC 6655 | 🚫 Blocked | No stdlib CCM |
| TLS_AES_128_CCM_8_SHA256 | Cipher | RFC 6655 | 🚫 Blocked | No stdlib CCM |
| X25519 | Key Exchange | RFC 7748 | ✅ Complete | Primary group |
| secp256r1 (P-256) | Key Exchange | RFC 8422 | ⚠️ Partial | Parsing only |
| secp384r1 (P-384) | Key Exchange | RFC 8422 | ⚠️ Partial | Parsing only |
| ffdhe2048 | Key Exchange | RFC 7919 | ❌ Missing | FFDHE not impl |
| ffdhe3072 | Key Exchange | RFC 7919 | ❌ Missing | FFDHE not impl |
| ed25519 | Signature | RFC 8032 | ✅ Complete | Verification impl |
| ecdsa_secp256r1_sha256 | Signature | RFC 8446 §4.2.3 | ✅ Complete | Verification impl |
| ecdsa_secp384r1_sha384 | Signature | RFC 8446 §4.2.3 | ✅ Complete | Verification impl |
| rsa_pss_rsae_sha256 | Signature | RFC 8446 §4.2.3 | ✅ Complete | Verification impl |

### 1.3 Extensions

| Extension | Code | RFC | Status | Notes |
|-----------|------|-----|--------|-------|
| server_name (SNI) | 0x0000 | RFC 6066 §3 | ✅ Complete | Client + server |
| supported_groups | 0x000a | RFC 8446 §4.2.7 | ✅ Complete | X25519 only active |
| signature_algorithms | 0x000d | RFC 8446 §4.2.3 | ✅ Complete | 4 schemes verified |
| alpn | 0x0010 | RFC 7301 | ✅ Complete | Multi-protocol |
| status_request (OCSP) | 0x0005 | RFC 6066 §8 | ⚠️ Partial | Parsing only |
| signed_certificate_timestamp | 0x0012 | RFC 6962 §3.3.1 | ⚠️ Partial | Parsing only |
| pre_shared_key | 0x0029 | RFC 8446 §4.2.11 | ⚠️ Partial | No handshake flow |
| early_data | 0x002a | RFC 8446 §4.2.10 | ⚠️ Partial | No send/accept flow |
| supported_versions | 0x002b | RFC 8446 §4.2.1 | ✅ Complete | TLS 1.3 only |
| cookie | 0x002c | RFC 8446 §4.2.2 | ❌ Missing | For HelloRetryRequest |
| psk_key_exchange_modes | 0x002d | RFC 8446 §4.2.9 | ❌ Missing | psk_ke, psk_dhe_ke |
| certificate_authorities | 0x002f | RFC 8446 §4.2.4 | ❌ Missing | Trust anchor hints |
| oid_filters | 0x0030 | RFC 8446 §4.2.5 | ❌ Missing | Certificate selection |
| key_share | 0x0033 | RFC 8446 §4.2.8 | ✅ Complete | X25519 only |
| quic_transport_parameters | 0x0039 | RFC 9001 §8.2 | ✅ Complete | Full codec |

### 1.4 X.509 Certificate Validation

| Feature | RFC | Status | Notes |
|---------|-----|--------|-------|
| DER Parsing | RFC 5280 §4 | ✅ Complete | 26 unit tests |
| Validity Period Check | RFC 5280 §4.1.2.5 | ✅ Complete | notBefore/notAfter |
| Subject Alternative Names | RFC 5280 §4.2.1.6 | ✅ Complete | DNS, IP matching |
| Extended Key Usage | RFC 5280 §4.2.1.12 | ✅ Complete | serverAuth/clientAuth |
| Basic Constraints | RFC 5280 §4.2.1.9 | ✅ Complete | CA flag, pathLen |
| Key Usage | RFC 5280 §4.2.1.3 | ✅ Complete | digitalSignature |
| SNI Matching | RFC 6125 | ✅ Complete | Wildcard support |
| SPKI Extraction | RFC 5280 §4.1.2.7 | ✅ Complete | For sig verify |
| Chain Validation | RFC 5280 §6 | ❌ Missing | Only leaf validated |
| Name Constraints | RFC 5280 §4.2.1.10 | ⚠️ Partial | Parsing only |
| Policy Mappings | RFC 5280 §4.2.1.5 | ⚠️ Partial | Parsing only |
| CRL Distribution Points | RFC 5280 §4.2.1.13 | ❌ Missing | No CRL support |
| Authority Info Access | RFC 5280 §4.2.2.1 | ❌ Missing | OCSP/CA issuers |
| Certificate Policies | RFC 5280 §4.2.1.4 | ❌ Missing | Policy OIDs |

### 1.5 QUIC Integration (RFC 9001)

| Feature | RFC Section | Status | Notes |
|---------|-------------|--------|-------|
| CRYPTO Frame Processing | §4 | ✅ Complete | Buffering + reassembly |
| Initial Secrets (v1) | §5.2 | ✅ Complete | Fixed salt |
| Initial Secrets (v2) | RFC 9369 §4 | ✅ Complete | QUIC v2 salt |
| Handshake Secrets | §5.1 | ✅ Complete | From ECDHE |
| Application Secrets | §5.1 | ✅ Complete | 1-RTT keys |
| 0-RTT Secrets | §5.1 | ⚠️ Partial | Derivation only |
| Key Update | §6 | ⚠️ Partial | Not integrated |
| Header Protection | §5.4 | ✅ Complete | key_schedule.zig |
| Transport Parameters | §8.2 | ✅ Complete | Encode/decode |
| Error Mapping (CRYPTO_ERROR) | §4.8 | ✅ Complete | 0x0100 + alert |
| No Post-Handshake Auth | §4.4 | ✅ Complete | Explicitly rejected |

---

## 2. Identified Gaps by Category

### 2.1 Critical Gaps (P0 - Required for Production)

#### 2.1.1 HelloRetryRequest Flow
**Impact:** Cannot recover from initial group mismatch
**RFC:** 8446 §4.1.4
**Affects:** Handshake robustness, multi-group support

**Description:**
When client's initial key_share doesn't include a group the server supports, the server must send HelloRetryRequest (HRR) to request a specific group. This is currently not implemented.

**Required Changes:**
1. Detect group mismatch in ServerHello generation
2. Construct HelloRetryRequest with cookie extension
3. Handle HRR on client (parse, regenerate key_share, update transcript)
4. Add "HelloRetryRequest" transcript message per RFC 8446 §4.4.1

**Affected Files:**
- `src/tls13/context.zig` (HRR state machine)
- `src/tls13/messages/server_hello.zig` (HRR encoding)
- `src/tls13/transcript.zig` (special HRR transcript)

#### 2.1.2 Full Certificate Chain Validation
**Impact:** Security risk - intermediate CA compromise undetected
**RFC:** 5280 §6
**Affects:** Trust model, enterprise deployments

**Description:**
Currently only leaf certificate is validated. Full path validation with trust anchor chaining is missing.

**Required Changes:**
1. Path building from leaf to trust anchor
2. Signature verification for each link
3. Path length constraint enforcement
4. Name constraints validation
5. Trust anchor callback integration

**Affected Files:**
- `src/x509.zig` (new `validateChain()` function)
- `src/tls13/config.zig` (trust store config)

#### 2.1.3 Key Update Integration
**Impact:** Long-lived connections cannot refresh keys
**RFC:** 8446 §4.6.3, RFC 9001 §6
**Affects:** Forward secrecy, AEAD limit enforcement

**Description:**
Code exists in `key_schedule.zig` for key update derivation, but not integrated into handshake flow.

**Required Changes:**
1. Trigger key update when AEAD limits reached
2. Send KeyUpdate message
3. Handle received KeyUpdate
4. Update traffic secrets atomically
5. Reset sequence numbers

**Affected Files:**
- `src/tls13/context.zig` (KeyUpdate state)
- `src/record/aead.zig` (limit tracking)

### 2.2 High Priority Gaps (P1 - Important Features)

#### 2.2.1 PSK Handshake Modes
**Impact:** Cannot do session resumption, 0-RTT impossible
**RFC:** 8446 §2.2, §4.2.11
**Affects:** Performance optimization, 0-RTT

**Modes to Implement:**
1. **psk_ke (PSK-only):** No forward secrecy, faster
2. **psk_dhe_ke (PSK-DHE):** Forward secrecy + resumption

**Required Changes:**
1. Implement `psk_key_exchange_modes` extension
2. Parse `pre_shared_key` extension (binders)
3. Verify PSK binders (RFC 8446 §4.2.11.2)
4. Derive early secret from PSK
5. Select PSK vs. ECDHE in key schedule

**Affected Files:**
- `src/tls13/messages/client_hello.zig` (PSK extension parsing)
- `src/tls13/context.zig` (PSK flow)
- `src/key_schedule.zig` (early secret derivation)
- `src/zero_rtt.zig` (ticket redemption)

#### 2.2.2 0-RTT Data Sending (Client)
**Impact:** Cannot utilize 0-RTT for low-latency applications
**RFC:** 8446 §4.2.10, RFC 9001 §4.6
**Affects:** Connection establishment latency

**Required Changes:**
1. Client sends `early_data` extension in ClientHello
2. Encrypt early data with 0-RTT traffic secret
3. Handle server acceptance (EncryptedExtensions) or rejection
4. Retry rejected early data in 1-RTT if needed

**Affected Files:**
- `src/tls13/context.zig` (0-RTT client send flow)
- `src/tls13/config.zig` (enable_early_data flag)

#### 2.2.3 NewSessionTicket Emission (Server)
**Impact:** Cannot issue resumption tickets
**RFC:** 8446 §4.6.1
**Affects:** Session resumption, 0-RTT enablement

**Required Changes:**
1. Generate session ticket after handshake complete
2. Encrypt ticket with server secret key
3. Include ticket_lifetime, ticket_age_add, ticket_nonce
4. Add `early_data` extension with max_early_data_size
5. Send NewSessionTicket message post-handshake

**Affected Files:**
- `src/tls13/context.zig` (post-handshake message)
- `src/zero_rtt.zig` (ticket encryption)

#### 2.2.4 Client Authentication (Server-Side Request)
**Impact:** Cannot enforce mutual TLS
**RFC:** 8446 §4.3.2, §4.4.2
**Affects:** Enterprise security, zero trust

**Required Changes:**
1. Server sends CertificateRequest in handshake
2. Include `certificate_authorities` extension
3. Parse client Certificate + CertificateVerify
4. Verify client certificate signature
5. Validate client cert against policy

**Affected Files:**
- `src/tls13/context.zig` (CertificateRequest flow)
- `src/tls13/messages/` (new certificate_request.zig)

### 2.3 Medium Priority Gaps (P2 - Enhanced Functionality)

#### 2.3.1 Additional Key Exchange Groups
**Impact:** Limited interoperability, no FIPS compliance option
**RFC:** 8446 §4.2.7, RFC 7919

**Groups to Add:**
1. **secp256r1 (P-256):** Most widely deployed ECDHE
2. **secp384r1 (P-384):** CNSA Suite requirement
3. **ffdhe2048, ffdhe3072:** FIPS 140-2 compliance

**Required Changes:**
1. Implement NIST P-256/P-384 ECDHE in sig.zig
2. Implement FFDHE modular exponentiation
3. Add group negotiation logic
4. Update HelloRetryRequest to request alternate groups

**Affected Files:**
- `src/sig.zig` (P-256/P-384 operations)
- New: `src/ffdhe.zig` (finite field DH)

#### 2.3.2 OCSP Stapling (Active Validation)
**Impact:** No real-time revocation checking
**RFC:** 6066 §8, RFC 6960

**Required Changes:**
1. Client requests OCSP via `status_request` extension
2. Server includes `CertificateStatus` message
3. Validate OCSP response signature
4. Check revocation status and validity period
5. Handle "unknown" status gracefully

**Affected Files:**
- `src/ocsp.zig` (validate response)
- `src/tls13/context.zig` (CertificateStatus handling)

#### 2.3.3 Certificate Revocation List (CRL)
**Impact:** No offline revocation checking
**RFC:** 5280 §5

**Required Changes:**
1. Parse CRL Distribution Points extension
2. Download and cache CRLs (out of scope - app layer)
3. Validate CRL signature
4. Check if certificate serial number is revoked
5. Verify CRL is not expired

**Affected Files:**
- New: `src/crl.zig`
- `src/x509.zig` (CRL DP parsing)

#### 2.3.4 Additional Extensions

| Extension | Priority | RFC | Description |
|-----------|----------|-----|-------------|
| cookie | P1 | RFC 8446 §4.2.2 | HelloRetryRequest DoS mitigation |
| psk_key_exchange_modes | P1 | RFC 8446 §4.2.9 | PSK mode negotiation |
| certificate_authorities | P2 | RFC 8446 §4.2.4 | Trust anchor hints |
| oid_filters | P3 | RFC 8446 §4.2.5 | Certificate selection |
| max_fragment_length | P3 | RFC 6066 §4 | Reduce fragment size |

### 2.4 Low Priority Gaps (P3 - Nice to Have)

#### 2.4.1 Advanced X.509 Features
- Authority Information Access (AIA) for OCSP/CA issuers
- Certificate Policies extension enforcement
- Inhibit Any-Policy extension
- Subject Directory Attributes

#### 2.4.2 Post-Quantum Cryptography Readiness
- Prepare for hybrid X25519+ML-KEM
- PQ signature scheme parsing (SLH-DSA, ML-DSA)
- **Note:** Zig stdlib support required first

#### 2.4.3 Performance Optimizations
- Batch HKDF operations
- Pre-compute transcript hashes
- Zero-copy certificate parsing
- SIMD-optimized AEAD (if stdlib supports)

---

## 3. Phased Implementation Roadmap

### Phase 1: Security & Robustness (P0)
**Duration:** 3-4 weeks
**Goal:** Production-ready security posture

#### Tasks
1. ✅ Implement HelloRetryRequest flow (client + server)
2. ✅ Full X.509 certificate chain validation
3. ✅ Key update integration with AEAD limits
4. ✅ Downgrade attack protection verification
5. ✅ Comprehensive error handling and alert generation

#### Deliverables
- HelloRetryRequest conformance tests (10 tests)
- Chain validation conformance tests (15 tests)
- Key update conformance tests (8 tests)
- Security test suite (20 tests)

#### Success Criteria
- Pass all BoringSSL HelloRetryRequest vectors
- Validate 5-cert chains against OpenSSL
- Successfully rotate keys under AEAD limit
- No security audit findings

---

### Phase 2: Session Resumption & 0-RTT (P1)
**Duration:** 4-5 weeks
**Goal:** Enable high-performance resumption

#### Tasks
1. ✅ Implement PSK handshake modes (psk_ke, psk_dhe_ke)
2. ✅ NewSessionTicket emission (server)
3. ✅ 0-RTT data sending (client)
4. ✅ 0-RTT acceptance/rejection (server)
5. ✅ Anti-replay integration with QUIC

#### Deliverables
- PSK conformance tests (12 tests)
- 0-RTT conformance tests (15 tests)
- Session ticket conformance tests (8 tests)
- Replay attack prevention tests (10 tests)

#### Success Criteria
- PSK handshake completes in <500µs (benchmark)
- 0-RTT reduces latency by 1-RTT (measured)
- Zero false positives in anti-replay window
- Pass all BoringSSL 0-RTT vectors

---

### Phase 3: Client Authentication & Trust (P1)
**Duration:** 3-4 weeks
**Goal:** Mutual TLS support

#### Tasks
1. ✅ CertificateRequest message (server)
2. ✅ Client certificate selection
3. ✅ Client CertificateVerify generation
4. ✅ Trust store integration (callbacks)
5. ✅ certificate_authorities extension

#### Deliverables
- Client auth conformance tests (10 tests)
- Trust store conformance tests (8 tests)
- Mutual TLS integration tests (12 tests)

#### Success Criteria
- Successfully verify client ECDSA certificates
- Trust store callback integration documented
- Interop with OpenSSL s_client -cert
- Zero client auth vulnerabilities

---

### Phase 4: Extended Cryptographic Support (P2)
**Duration:** 4-5 weeks
**Goal:** Broad algorithm compatibility

#### Tasks
1. ✅ ECDHE P-256 (secp256r1) support
2. ✅ ECDHE P-384 (secp384r1) support
3. ✅ FFDHE groups (2048, 3072, 4096 bit)
4. ✅ Additional signature schemes (RSA-PSS variants)
5. ✅ Cipher suite negotiation improvements

#### Deliverables
- P-256/P-384 conformance tests (15 tests)
- FFDHE conformance tests (12 tests)
- Cross-suite interop tests (10 tests)

#### Success Criteria
- Pass all BoringSSL P-256 ECDHE vectors
- Successfully negotiate FFDHE with OpenSSL
- Support 6+ named groups
- FIPS 140-2 algorithm compliance

---

### Phase 5: Revocation & Advanced X.509 (P2)
**Duration:** 3-4 weeks
**Goal:** Enterprise-grade certificate validation

#### Tasks
1. ✅ OCSP stapling (active validation)
2. ✅ CRL support (parsing + validation)
3. ✅ Authority Information Access (AIA)
4. ✅ Certificate policy enforcement
5. ✅ Name constraints enforcement

#### Deliverables
- OCSP conformance tests (10 tests)
- CRL conformance tests (8 tests)
- Policy validation tests (12 tests)

#### Success Criteria
- Validate OCSP responses from Let's Encrypt
- Successfully parse and check CRLs
- Enforce name constraints correctly
- Interop with enterprise PKI

---

### Phase 6: Extensions & Optimizations (P3)
**Duration:** 3-4 weeks
**Goal:** Feature completeness and performance

#### Tasks
1. ✅ Additional extensions (max_fragment_length, etc.)
2. ✅ Performance profiling and optimization
3. ✅ Memory usage optimization
4. ✅ Post-quantum readiness (parsing only)
5. ✅ Comprehensive fuzzing

#### Deliverables
- Extension conformance tests (15 tests)
- Performance benchmarks
- Fuzzing harness (AFL, libFuzzer)
- PQ algorithm placeholder tests

#### Success Criteria
- Handshake latency <2ms (typical case)
- Memory footprint <100KB per connection
- Zero crashes in 24hr fuzz run
- PQ signature schemes parsed (not verified)

---

## 4. Conformance Test Specification

### 4.1 Test Strategy

**Levels of Conformance:**
1. **RFC Compliance Tests:** Match spec examples byte-for-byte
2. **Interop Tests:** Verify compatibility with real implementations
3. **BoringSSL Vectors:** Use Google's test vectors
4. **OpenSSL Conformance:** Compare outputs with OpenSSL

**Test Organization:**
```
tests/
├── conformance/
│   ├── boringssl/
│   │   ├── hello_retry_request.zig
│   │   ├── psk_handshake.zig
│   │   ├── zero_rtt.zig
│   │   ├── client_auth.zig
│   │   ├── p256_ecdhe.zig
│   │   ├── ffdhe.zig
│   │   └── key_update.zig
│   ├── openssl/
│   │   ├── chain_validation.zig
│   │   ├── ocsp_validation.zig
│   │   ├── crl_validation.zig
│   │   └── aia_validation.zig
│   └── rfc8446/
│       ├── section_4_1_4_hello_retry_request.zig
│       ├── section_4_2_9_psk_modes.zig
│       ├── section_4_2_10_early_data.zig
│       ├── section_4_3_2_certificate_request.zig
│       ├── section_4_6_1_new_session_ticket.zig
│       └── section_4_6_3_key_update.zig
```

### 4.2 Phase 1 Conformance Tests

#### 4.2.1 HelloRetryRequest Tests (BoringSSL)
**File:** `tests/conformance/boringssl/hello_retry_request.zig`

```zig
// Test 1: HRR when client doesn't offer server's preferred group
test "HelloRetryRequest: group negotiation" {
    // Client sends: key_share with X25519
    // Server prefers: secp256r1
    // Expected: ServerHello with HRR, cookie, selected_group
    // Client retries: ClientHello with secp256r1 key_share
}

// Test 2: HRR transcript hash (synthetic message)
test "HelloRetryRequest: transcript hash includes synthetic message" {
    // RFC 8446 §4.4.1: transcript = Hash(CH1) + "HelloRetryRequest" + HRR
    // Verify transcript matches BoringSSL output
}

// Test 3: Cookie round-trip
test "HelloRetryRequest: cookie validation" {
    // Server sends cookie in HRR
    // Client echoes cookie in CH2
    // Server validates cookie matches original
}

// Test 4: Malformed HRR (no selected_group)
test "HelloRetryRequest: missing selected_group alert" {
    // Expected: decode_error or missing_extension alert
}

// Test 5: HRR for multiple missing extensions
test "HelloRetryRequest: multiple extensions required" {
    // Request both key_share and other extension
}
```

**Test Count:** 10 tests
**BoringSSL Vectors:** Use `ssl/test/runner` HRR test cases
**OpenSSL Equivalent:** `openssl s_server -curves` to force HRR

#### 4.2.2 Certificate Chain Validation Tests (OpenSSL)
**File:** `tests/conformance/openssl/chain_validation.zig`

```zig
// Test 1: Valid 3-cert chain (leaf → intermediate → root)
test "Chain validation: 3-level valid chain" {
    // Generate chain with OpenSSL:
    // openssl x509 -in leaf.pem -out leaf.der -outform DER
    // Verify with ztls matches OpenSSL verify result
}

// Test 2: Expired intermediate certificate
test "Chain validation: expired intermediate rejected" {
    // Expected: certificate_expired alert
}

// Test 3: Invalid signature in chain link
test "Chain validation: signature verification failure" {
    // Expected: bad_certificate alert
}

// Test 4: Path length constraint violation
test "Chain validation: pathLenConstraint enforcement" {
    // Root allows pathLen=1, but chain is 3 deep
    // Expected: rejection
}

// Test 5: Name constraints validation
test "Chain validation: permitted DNS subtrees" {
    // Intermediate has nameConstraints: permittedSubtrees = .example.com
    // Leaf cert has SAN = test.example.com → allowed
    // Leaf cert has SAN = test.other.com → rejected
}

// Test 6: Self-signed root in trust store
test "Chain validation: trust anchor matching" {
    // Verify chain terminates at configured trust anchor
}

// Test 7: Untrusted root
test "Chain validation: unknown CA rejection" {
    // Expected: unknown_ca alert
}
```

**Test Count:** 15 tests
**OpenSSL Commands:**
- Generate chains: `openssl ca -config ca.conf`
- Verify: `openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem`

#### 4.2.3 Key Update Tests (BoringSSL)
**File:** `tests/conformance/boringssl/key_update.zig`

```zig
// Test 1: Client-initiated key update
test "Key update: client triggers update" {
    // Send KeyUpdate message
    // Verify new traffic secret derived
    // Verify old key zeroized
}

// Test 2: Server-initiated key update
test "Key update: server triggers update" {
    // Receive KeyUpdate
    // Respond with own KeyUpdate
    // Verify bidirectional update
}

// Test 3: Key update at AEAD limit
test "Key update: triggered by AEAD confidentiality limit" {
    // Encrypt 2^24 records with AES-GCM
    // Verify automatic KeyUpdate sent
}

// Test 4: Sequential key updates
test "Key update: multiple updates in succession" {
    // Update 3 times
    // Verify each generation is distinct
}
```

**Test Count:** 8 tests
**BoringSSL Vectors:** Extract from `ssl/test/runner/runner.go` KeyUpdate tests

### 4.3 Phase 2 Conformance Tests

#### 4.3.1 PSK Handshake Tests (BoringSSL)
**File:** `tests/conformance/boringssl/psk_handshake.zig`

```zig
// Test 1: PSK-only (psk_ke) handshake
test "PSK: psk_ke mode (no DHE)" {
    // Client sends pre_shared_key with binder
    // Server accepts PSK, no key_share
    // Verify early secret → handshake secret derivation
}

// Test 2: PSK-DHE (psk_dhe_ke) handshake
test "PSK: psk_dhe_ke mode (forward secrecy)" {
    // Client sends pre_shared_key + key_share
    // Server accepts PSK and performs ECDHE
    // Verify hybrid secret derivation
}

// Test 3: PSK binder verification
test "PSK: binder HMAC validation" {
    // RFC 8446 §4.2.11.2: binder = HMAC(binder_key, CH[:-binder])
    // Compare ztls binder computation with BoringSSL
}

// Test 4: Invalid binder rejection
test "PSK: incorrect binder causes handshake_failure" {
    // Corrupt binder value
    // Expected: handshake_failure or decrypt_error alert
}

// Test 5: PSK identity selection
test "PSK: server selects from multiple identities" {
    // Client offers 3 PSK identities
    // Server selects identity 2
    // Verify selected_identity in ServerHello
}

// Test 6: Obfuscated ticket age validation
test "PSK: ticket age freshness check" {
    // ticket_age = (now - ticket_timestamp) + ticket_age_add
    // Verify server accepts fresh ticket, rejects stale
}
```

**Test Count:** 12 tests
**BoringSSL Vectors:** Use PSK test vectors from ssl/test/runner

#### 4.3.2 0-RTT Tests (BoringSSL)
**File:** `tests/conformance/boringssl/zero_rtt.zig`

```zig
// Test 1: 0-RTT accepted by server
test "0-RTT: early data accepted" {
    // Client sends early_data extension + encrypted data
    // Server sends early_data in EncryptedExtensions (acceptance)
    // Verify early data processed
}

// Test 2: 0-RTT rejected by server
test "0-RTT: early data rejected" {
    // Server omits early_data from EncryptedExtensions
    // Client discards 0-RTT data
    // Handshake continues in 1-RTT
}

// Test 3: 0-RTT replay detection
test "0-RTT: anti-replay window prevents duplicate" {
    // Send identical ClientHello twice
    // First accepted, second rejected
}

// Test 4: 0-RTT max_early_data_size enforcement
test "0-RTT: server enforces max_early_data_size from ticket" {
    // Ticket specifies max_early_data_size = 1024
    // Client sends 2048 bytes
    // Expected: rejection or truncation
}

// Test 5: 0-RTT with PSK-DHE (forward secrecy)
test "0-RTT: combined with PSK-DHE" {
    // 0-RTT requires PSK, but can combine with DHE
    // Verify early secret + ECDHE shared secret
}
```

**Test Count:** 15 tests
**BoringSSL Vectors:** Extract from `ssl/test/runner` EarlyData tests

### 4.4 Phase 3 Conformance Tests

#### 4.4.1 Client Authentication Tests (OpenSSL)
**File:** `tests/conformance/openssl/client_auth.zig`

```zig
// Test 1: Server requests client certificate
test "Client auth: CertificateRequest parsing" {
    // Server sends CertificateRequest with signature_algorithms
    // Client provides matching certificate
}

// Test 2: Client certificate verification
test "Client auth: verify client CertificateVerify" {
    // Server verifies signature over transcript
    // Compare with OpenSSL s_server -verify
}

// Test 3: Client certificate optional (requested but not required)
test "Client auth: client sends empty Certificate message" {
    // Server requests but doesn't require
    // Client sends empty cert list
    // Handshake succeeds
}

// Test 4: Client certificate required
test "Client auth: server requires client cert" {
    // verify_peer = true in Config
    // Client doesn't send cert
    // Expected: certificate_required alert
}

// Test 5: certificate_authorities extension
test "Client auth: filter by trusted CAs" {
    // CertificateRequest includes certificate_authorities
    // Client selects cert issued by listed CA
}
```

**Test Count:** 10 tests
**OpenSSL Commands:**
- Server: `openssl s_server -Verify 1 -CAfile client_ca.pem`
- Client: `openssl s_client -cert client.pem -key client_key.pem`

### 4.5 Phase 4 Conformance Tests

#### 4.5.1 P-256/P-384 ECDHE Tests (BoringSSL)
**File:** `tests/conformance/boringssl/p256_ecdhe.zig`

```zig
// Test 1: P-256 key exchange
test "ECDHE: secp256r1 (P-256) handshake" {
    // Client and server negotiate P-256
    // Verify shared secret matches BoringSSL computation
}

// Test 2: P-384 key exchange
test "ECDHE: secp384r1 (P-384) handshake" {
    // Compare P-384 ECDH output with BoringSSL
}

// Test 3: Mixed group support (X25519 + P-256)
test "ECDHE: HelloRetryRequest for group change" {
    // Client offers X25519, server wants P-256
    // Verify HRR flow with selected_group = secp256r1
}

// Test 4: Invalid public key rejection
test "ECDHE: malformed P-256 point rejected" {
    // Send invalid curve point
    // Expected: decode_error or illegal_parameter alert
}
```

**Test Count:** 15 tests
**BoringSSL Vectors:** Use P-256/P-384 test cases from ssl/test

#### 4.5.2 FFDHE Tests (OpenSSL)
**File:** `tests/conformance/openssl/ffdhe.zig`

```zig
// Test 1: ffdhe2048 handshake
test "FFDHE: 2048-bit group" {
    // Verify modular exponentiation matches OpenSSL
    // openssl s_server -groups ffdhe2048
}

// Test 2: ffdhe3072 handshake
test "FFDHE: 3072-bit group" {
    // Test with larger group
}

// Test 3: ffdhe4096 handshake
test "FFDHE: 4096-bit group" {
    // Slowest but highest security
}

// Test 4: Mixed ECDHE + FFDHE negotiation
test "FFDHE: fallback from ECDHE to FFDHE" {
    // Client prefers X25519 but supports ffdhe2048
    // Server only supports ffdhe2048
}
```

**Test Count:** 12 tests

### 4.6 Phase 5 Conformance Tests

#### 4.6.1 OCSP Validation Tests (OpenSSL)
**File:** `tests/conformance/openssl/ocsp_validation.zig`

```zig
// Test 1: Valid OCSP response
test "OCSP: good status accepted" {
    // Generate OCSP response with OpenSSL
    // openssl ocsp -issuer ca.pem -cert server.pem -respout resp.der
    // Verify ztls accepts "good" status
}

// Test 2: Revoked certificate
test "OCSP: revoked status causes alert" {
    // OCSP indicates certificate is revoked
    // Expected: certificate_revoked alert
}

// Test 3: OCSP response signature verification
test "OCSP: invalid signature rejected" {
    // Corrupt OCSP response signature
    // Expected: bad_certificate_status_response alert
}

// Test 4: Expired OCSP response
test "OCSP: thisUpdate/nextUpdate validation" {
    // OCSP response outside validity period
    // Expected: rejection
}

// Test 5: OCSP nonce (if supported)
test "OCSP: nonce prevents replay" {
    // Request includes nonce, response must match
}
```

**Test Count:** 10 tests

#### 4.6.2 CRL Validation Tests (OpenSSL)
**File:** `tests/conformance/openssl/crl_validation.zig`

```zig
// Test 1: Valid CRL with no revocations
test "CRL: empty CRL parsed correctly" {
    // openssl ca -gencrl -out crl.der -outform DER
}

// Test 2: Certificate appears in CRL
test "CRL: revoked certificate detected" {
    // Serial number matches CRL entry
    // Expected: certificate_revoked alert
}

// Test 3: CRL signature verification
test "CRL: signature by CA key" {
    // Verify CRL signature with CA public key
}

// Test 4: Expired CRL rejection
test "CRL: thisUpdate/nextUpdate enforcement" {
    // CRL past nextUpdate date
    // Expected: rejection (unless grace period)
}
```

**Test Count:** 8 tests

### 4.7 Phase 6 Conformance Tests

#### 4.7.1 Extension Tests
**File:** `tests/conformance/rfc8446/extensions.zig`

```zig
// Test 1: cookie extension round-trip
test "Extensions: cookie in HelloRetryRequest" { }

// Test 2: max_fragment_length negotiation
test "Extensions: max_fragment_length reduces fragment size" { }

// Test 3: certificate_authorities in CertificateRequest
test "Extensions: certificate_authorities filtering" { }

// Test 4: Unknown extension ignored
test "Extensions: client ignores unknown extension" {
    // RFC 8446 §4.2: unknown extensions MUST be ignored
}

// Test 5: Extension order preservation
test "Extensions: order in ClientHello/ServerHello" {
    // Verify transcript hash accounts for exact byte order
}
```

**Test Count:** 15 tests

---

## 5. Implementation Guidelines

### 5.1 Development Workflow

**For Each Gap:**
1. Create feature branch: `git checkout -b feature/hello-retry-request`
2. Write failing tests first (TDD)
3. Implement minimal code to pass tests
4. Add conformance tests (BoringSSL/OpenSSL)
5. Update RFC compliance tests
6. Add unit tests for edge cases
7. Update CLAUDE.md documentation
8. Submit PR with test evidence

### 5.2 Testing Requirements

**Every Feature Must Have:**
- ✅ Unit tests (edge cases, errors)
- ✅ RFC compliance tests (spec examples)
- ✅ Conformance tests (BoringSSL or OpenSSL)
- ✅ Integration tests (end-to-end handshake)

**Minimum Coverage Targets:**
- Unit tests: 90% line coverage
- RFC tests: 100% of relevant sections
- Conformance: 80% of BoringSSL test cases

### 5.3 Conformance Test Execution

**BoringSSL Tests:**
```bash
# Extract test vectors from BoringSSL
cd /tmp
git clone https://boringssl.googlesource.com/boringssl
cd boringssl/ssl/test/runner
go run runner.go -test HelloRetryRequest -json > hrr_vectors.json

# Run ztls conformance tests
cd /home/benji/src/spyder/ztls
make test-conformance
```

**OpenSSL Tests:**
```bash
# Generate test certificates
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

# Run server for interop testing
openssl s_server -key key.pem -cert cert.pem -accept 4433 -www

# Client test
openssl s_client -connect localhost:4433 -debug
```

### 5.4 Success Criteria

**Definition of Done for Each Phase:**
1. All planned tests pass (100%)
2. No regression in existing tests
3. Conformance tests pass against both BoringSSL and OpenSSL
4. Documentation updated (CLAUDE.md, docstrings)
5. No memory leaks (run with Valgrind or AddressSanitizer)
6. Performance regression <5% (benchmark)

---

## 6. Risk Assessment

### 6.1 Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| FFDHE performance inadequate | Medium | Medium | Benchmark early, consider asm optimization |
| Chain validation complexity explosion | High | Medium | Limit to 10-cert max, fail fast |
| 0-RTT replay false positives | Low | High | Configurable window size, extensive testing |
| PSK binder computation error | Medium | High | Cross-verify with 3+ implementations |
| Key update race conditions | Medium | High | Formal state machine verification |

### 6.2 Dependency Risks

| Dependency | Risk | Mitigation |
|------------|------|------------|
| Zig 0.15.1 stdlib stability | Zig under active development | Pin to specific Zig version, monitor stdlib changes |
| OpenSSL API changes | Low (stable API) | Use OpenSSL 1.1.1+ or 3.x |
| BoringSSL test vectors | Medium (Google internal) | Cache vectors, accept API changes |

### 6.3 Schedule Risks

**Phase 1 (Security):** Critical path, cannot be delayed
**Phase 2 (0-RTT):** Can parallelize with Phase 3
**Phase 4 (FFDHE):** Can defer if performance is acceptable without it
**Phase 5 (Revocation):** Can defer to future release if needed

---

## 7. Metrics & Success Tracking

### 7.1 Implementation Progress Metrics

Track weekly:
- ✅ Tests passing / total tests (%)
- ✅ Conformance test coverage (%)
- ✅ RFC sections implemented / total (%)
- ✅ Code review completion rate

### 7.2 Quality Metrics

Track per phase:
- ✅ Conformance test pass rate (target: 100%)
- ✅ Memory usage per connection (target: <100KB)
- ✅ Handshake latency (target: <2ms)
- ✅ Lines of code per gap (track complexity)

### 7.3 Security Metrics

Continuous monitoring:
- ✅ Static analysis warnings (target: 0)
- ✅ Fuzzing crashes (target: 0 after 24h)
- ✅ Known CVE applicability (target: 0)
- ✅ Audit findings (track and remediate)

---

## 8. Appendix

### 8.1 RFC 8446 Section Coverage Map

| Section | Title | Status | Tests | Phase |
|---------|-------|--------|-------|-------|
| §2.1 | Incorrect DHE Share | ❌ Missing | 0/5 | 1 |
| §2.2 | Resumption (PSK) | ❌ Missing | 0/12 | 2 |
| §2.3 | 0-RTT Data | ⚠️ Partial | 5/15 | 2 |
| §4.1.2 | ClientHello | ✅ Complete | 16/16 | ✅ |
| §4.1.3 | ServerHello | ✅ Complete | 11/11 | ✅ |
| §4.1.4 | HelloRetryRequest | ❌ Missing | 0/10 | 1 |
| §4.2.8 | Key Share | ⚠️ Partial | 8/12 | 4 |
| §4.2.9 | PSK Modes | ❌ Missing | 0/8 | 2 |
| §4.2.10 | Early Data | ⚠️ Partial | 3/10 | 2 |
| §4.2.11 | Pre-Shared Key | ⚠️ Partial | 2/12 | 2 |
| §4.3.2 | CertificateRequest | ❌ Missing | 0/8 | 3 |
| §4.4.2 | Certificate | ✅ Complete | 12/12 | ✅ |
| §4.4.3 | CertificateVerify | ✅ Complete | 10/10 | ✅ |
| §4.4.4 | Finished | ✅ Complete | 10/10 | ✅ |
| §4.6.1 | NewSessionTicket | ⚠️ Partial | 2/10 | 2 |
| §4.6.3 | Key Update | ⚠️ Partial | 3/10 | 1 |
| §5.2 | Record Protection | ✅ Complete | 15/15 | ✅ |
| §5.5 | AEAD Limits | ✅ Complete | 8/8 | ✅ |
| §6 | Alert Protocol | ✅ Complete | 12/12 | ✅ |
| §7.1 | Key Schedule | ✅ Complete | 18/18 | ✅ |
| §8 | 0-RTT & Replay | ⚠️ Partial | 10/25 | 2 |

**Total Coverage:** 145/229 tests (63%)

### 8.2 Suggested Reading

**TLS 1.3 Internals:**
- RFC 8446: The TLS Protocol Version 1.3
- RFC 8447: IANA Registry Updates for TLS and DTLS
- "The Illustrated TLS 1.3 Connection" (https://tls13.xargs.org)

**QUIC-TLS Integration:**
- RFC 9001: Using TLS to Secure QUIC
- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
- "QUIC Loss Detection and Congestion Control" (RFC 9002)

**X.509 & PKI:**
- RFC 5280: X.509 Certificate and CRL Profile
- RFC 6125: Domain-Based Application Service Identity
- "PKI Revealed" by T. Wilson and S. Ottaway

**Cryptography:**
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 7748: Elliptic Curves for Security (X25519, X448)
- RFC 7919: Finite Field Diffie-Hellman (FFDHE)

### 8.3 Test Vector Sources

**BoringSSL:**
- Repository: https://boringssl.googlesource.com/boringssl
- Test runner: `ssl/test/runner/runner.go`
- Vectors: `ssl/test/test_vectors/`

**OpenSSL:**
- Test suite: `test/recipes/` in OpenSSL repo
- FIPS tests: `test/fips/`

**NIST:**
- Cryptographic Algorithm Validation Program (CAVP)
- https://csrc.nist.gov/projects/cavp

**Wycheproof:**
- Google's Project Wycheproof (edge cases)
- https://github.com/google/wycheproof

---

## 9. Conclusion

This gap analysis identifies **23 major implementation gaps** across 6 priority levels. The phased roadmap spans **18-24 weeks** and adds an estimated **500-700 new conformance tests**.

**Immediate Next Steps:**
1. Begin Phase 1 with HelloRetryRequest implementation
2. Set up BoringSSL vector extraction pipeline
3. Create conformance test harness template
4. Establish CI/CD for continuous conformance testing

**Long-Term Vision:**
- Full RFC 8446 compliance (100% section coverage)
- BoringSSL-level test suite (1000+ tests)
- Production deployment in QUIC stacks (quiche, quinn integration examples)
- FIPS 140-3 certification readiness (requires FFDHE, validated crypto)

---

**Document Maintained By:** Claude Code
**Last Updated:** 2025-11-07
**Next Review:** After Phase 1 completion
