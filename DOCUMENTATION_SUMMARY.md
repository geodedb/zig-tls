# ZTLS Documentation Enhancement Summary

This document summarizes the comprehensive documentation additions made to the ZTLS codebase, including RFC references, function documentation, and inline implementation comments.

## Completed Files

### 1. key_schedule.zig - FULLY DOCUMENTED ✓
**Status**: Complete with comprehensive RFC references

#### File-level Documentation
- Detailed module overview explaining HKDF-based key derivation for TLS 1.3 and QUIC
- Listed all primary RFC references (RFC 8446 §7.1, RFC 9001 §5.1, RFC 9369 §3)
- Key features section highlighting QUIC v1/v2 support, label conventions, and test vector validation
- Design notes explaining zero external dependencies

#### Constants
- `H` (SHA-256): Documented as hash function for TLS_AES_128_GCM_SHA256
- `HkdfSha256`: Documented HKDF-SHA256 implementation combining RFC 5869 + RFC 2104
- `initial_salt_v1`: Full documentation including RFC 9001 §5.2 reference and hex value
- `initial_salt_v2`: Full documentation including RFC 9369 §A.1 reference and version separation rationale

#### Functions with Complete Documentation

**Core HKDF Operations:**
- `hkdfLabel()`: Private helper with HkdfLabel structure definition from RFC 8446 §7.1
- `hmacSha256()`: Public HMAC helper with RFC 2104 and RFC 8446 §4.4.4 references
- `expandLabel()`: Full TLS 1.3 HKDF-Expand-Label documentation with formula
- `extract()`: RFC 5869 §2.2 HKDF-Extract with usage context

**QUIC Initial Secrets:**
- `deriveInitialSecretV1()`: RFC 9001 §5.2 initial secret derivation with formula
- `deriveInitialSecretV2()`: RFC 9369 §A.1 v2-specific derivation
- `deriveInitialSecret()`: Version dispatcher with both RFC references
- `deriveClientServerInitial()`: Client/server secret split with RFC 9001 Appendix A.1 references

**Key Material Derivation:**
- `deriveKeyIvHp()`: QUIC v1 packet protection keys (RFC 9001 §5.1, §5.4, Appendix A.1)
- `deriveKeyIvHpV2()`: QUIC v2 keys with "quicv2" label prefix (RFC 9369 §3)

**Post-Handshake:**
- `updateTrafficSecret()`: Key update documentation (RFC 8446 §7.2, §4.6.3, RFC 9001 §6)
- `deriveSecret()`: Generic Derive-Secret wrapper with RFC 8446 §7.1 formula

#### Test Documentation
All 20+ test cases already had good RFC references. Tests validate:
- RFC 9001 Appendix A.1 test vectors (initial secrets, client/server split, key derivation)
- RFC 9369 QUIC v2 label differences
- RFC 8446 §7.1 HKDF-Expand-Label behavior
- RFC 8446 §7.2 traffic secret updates

### 2. alert.zig - ALREADY WELL DOCUMENTED ✓
**Status**: Verification complete - existing documentation is excellent

#### Strengths
- Comprehensive file-level documentation explaining RFC 8446 §6 and RFC 9001 §4.8
- All 26 alert descriptions with correct enum values
- `AlertDescription.format()` method for diagnostics
- Alert encoding/decoding with round-trip tests
- QUIC CRYPTO_ERROR mapping (0x0100 + alert)
- Handshake error to alert mapping with 12+ error types
- 20+ test cases covering all alert types, levels, and mappings

#### RFC Coverage
- RFC 8446 §6 - Alert protocol
- RFC 8446 §6.1 - Alert levels
- RFC 8446 §6.2 - Alert descriptions
- RFC 9001 §4.8 - QUIC CRYPTO_ERROR mapping

## Remaining Files - Documentation Requirements

### 3. record.zig - PARTIAL DOCUMENTATION
**Current State**: Good file-level docs and structure, needs inline RFC comments

**Additions Needed:**
```zig
// At top - already good, enhance:
//! ## AEAD Cipher Suites
//! Supports three AEAD algorithms per RFC 8446 §5.1:
//! - TLS_AES_128_GCM_SHA256 (mandatory, RFC 5116)
//! - TLS_AES_256_GCM_SHA384 (RFC 5116)
//! - TLS_CHACHA20_POLY1305_SHA256 (RFC 7539)

// For ContentType enum:
/// TLS record content types as defined in RFC 8446 §5.1.
/// TLS 1.3 uses content_type to distinguish message types within records.
pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,  // RFC 8446 §5 - CCS for middlebox compatibility
    alert = 21,               // RFC 8446 §6 - Alert messages
    handshake = 22,           // RFC 8446 §4 - Handshake messages
    application_data = 23,    // RFC 8446 §5.4 - Protected records
    heartbeat = 24,           // RFC 6520 - Connection keepalive
};

// For encodePlaintext():
/// Pack content into a TLSPlaintext record (RFC 8446 §5.1).
///
/// Creates a record with fixed legacy_version 0x0303 (TLS 1.2) per RFC 8446 §5.1:
/// ```
/// struct {
///     ContentType type;
///     ProtocolVersion legacy_record_version = 0x0303;
///     uint16 length;
///     opaque fragment[TLSPlaintext.length];
/// } TLSPlaintext;
/// ```
///
/// ## RFC References
/// - RFC 8446 §5.1 - TLSPlaintext structure
/// - RFC 8446 §5.1 - Maximum fragment size (2^14 bytes)
pub fn encodePlaintext(...) {
    // ... existing implementation ...
    // RFC 8446 §5.1 - Legacy version must be 0x0303
    out[1] = 0x03;
    out[2] = 0x03;
}

// For packInnerPlaintext():
/// Encode content + padding into TLSInnerPlaintext (RFC 8446 §5.4).
///
/// TLS 1.3 encrypted records use TLSInnerPlaintext which adds the real
/// content type after the payload:
/// ```
/// struct {
///     opaque content[TLSPlaintext.length];
///     ContentType type;
///     uint8 zeros[length_of_padding];
/// } TLSInnerPlaintext;
/// ```
///
/// ## RFC References
/// - RFC 8446 §5.4 - Record Padding for traffic analysis resistance

// For AeadCipher.seal():
/// Encrypt TLSInnerPlaintext into TLSCiphertext (RFC 8446 §5.2).
///
/// Uses AEAD encryption with per-record nonce derived from sequence number:
/// ```
/// nonce = iv XOR pad_left(sequence_number, 12)
/// ```
///
/// ## RFC References
/// - RFC 8446 §5.2 - Record Payload Protection
/// - RFC 8446 §5.3 - Per-Record Nonce derivation
/// - RFC 8446 §5.5 - Usage limits (confidentiality and integrity bounds)

// For xorNonce():
/// Derive per-record nonce by XORing static IV with sequence number (RFC 8446 §5.3).
///
/// The per-record nonce is constructed as:
/// ```
/// nonce = write_iv XOR padded(sequence_number)
/// ```
/// Where sequence_number is zero-padded on the left to IV length.
///
/// ## RFC References
/// - RFC 8446 §5.3 - Per-Record Nonce construction

// For suiteSpec():
/// AEAD usage limits per RFC 8446 §5.5.
///
/// Confidentiality limits (records before rekey):
/// - AES-GCM: 2^24 records (§5.5 - conservative limit for 96-bit nonce)
/// - ChaCha20-Poly1305: 2^32 records (§5.5 - full 96-bit nonce space)
///
/// Integrity limits (auth failures before connection termination):
/// - All AEAD: 2^36 failures (§5.5)
```

**Test Documentation:**
All tests already reference RFC sections appropriately.

### 4. x509.zig - NEEDS INLINE RFC COMMENTS
**Current State**: Good structure, needs RFC references inline

**Additions Needed:**
```zig
//! X.509 Certificate Parsing and Validation Module
//!
//! Implements the certificate processing subset required by RFC 5280 for
//! TLS 1.3 server authentication in QUIC connections.
//!
//! ## RFC Coverage
//! - RFC 5280 - X.509 Public Key Infrastructure
//! - RFC 5280 §4.1 - Certificate structure (TBSCertificate)
//! - RFC 5280 §4.2.1.6 - Subject Alternative Name extension
//! - RFC 5280 §4.2.1.9 - Basic Constraints extension
//! - RFC 5280 §4.2.1.3 - Key Usage extension
//! - RFC 5280 §4.2.1.12 - Extended Key Usage extension
//! - RFC 8446 §4.4.2 - Server Certificate requirements
//!
//! ## Validation Features
//! - Certificate chain validation from leaf to root
//! - Validity period checking (notBefore/notAfter)
//! - Subject Alternative Name (SAN) matching with wildcard support
//! - Key Usage and Extended Key Usage validation (serverAuth required)
//! - Basic Constraints for CA certificates
//! - Signature verification (ECDSA P-256/P-384, RSA-PSS, Ed25519)

// For Certificate struct:
/// Parsed X.509 certificate view (RFC 5280 §4.1).
///
/// Provides access to the TBSCertificate fields required for TLS 1.3
/// server authentication per RFC 8446 §4.4.2.
pub const Certificate = struct {
    tbs: []const u8,  // RFC 5280 §4.1.2 - TBSCertificate for signature verification
    subject: Name,    // RFC 5280 §4.1.2.6 - Subject Distinguished Name
    san: ?SubjectAltName,  // RFC 5280 §4.2.1.6 - Subject Alternative Name
    basic: ?BasicConstraints,  // RFC 5280 §4.2.1.9 - Basic Constraints (CA flag)
    ku: ?KeyUsage,    // RFC 5280 §4.2.1.3 - Key Usage flags
    eku: ?ExtKeyUsage,  // RFC 5280 §4.2.1.12 - Extended Key Usage (serverAuth)
    not_before_unix: i64,  // RFC 5280 §4.1.2.5 - Validity.notBefore
    not_after_unix: i64,   // RFC 5280 §4.1.2.5 - Validity.notAfter
    spki: []const u8,  // RFC 5280 §4.1.2.7 - SubjectPublicKeyInfo
};

// For parseCert():
/// Parse a DER-encoded X.509 certificate (RFC 5280 §4.1).
///
/// Extracts the TBSCertificate fields required for TLS authentication:
/// - Subject name (CN from RDNSequence)
/// - Validity period (notBefore/notAfter as Unix timestamps)
/// - SubjectPublicKeyInfo (for signature verification)
/// - Extensions (SAN, BasicConstraints, KeyUsage, ExtKeyUsage)
///
/// ## RFC References
/// - RFC 5280 §4.1 - Certificate structure
/// - RFC 5280 §4.2 - Certificate Extensions

// For matchDnsName():
/// Match a DNS name against certificate SAN or CN (RFC 6125 §6).
///
/// Implements DNS-ID matching per RFC 6125 with wildcard support:
/// - Exact match: "example.com" matches "example.com"
/// - Wildcard: "*.example.com" matches "foo.example.com" (single label only)
/// - SAN takes precedence over Subject CN per RFC 6125 §6.4.4
///
/// ## RFC References
/// - RFC 6125 §6 - DNS-ID representation and matching
/// - RFC 8446 §4.4.2.2 - Server Name Indication validation

// For validateChain():
/// Validate X.509 certificate chain (RFC 5280 §6).
///
/// Performs full path validation per RFC 5280 §6:
/// 1. Leaf certificate validity period check
/// 2. DNS name matching (SAN or CN)
/// 3. Extended Key Usage serverAuth check
/// 4. Key Usage digitalSignature requirement
/// 5. Intermediate CA validation (basicConstraints.cA = true)
/// 6. Path length constraints (basicConstraints.pathLenConstraint)
/// 7. Signature verification for each cert in chain
/// 8. Root trust anchor validation (if TrustStore configured)
///
/// ## RFC References
/// - RFC 5280 §6 - Certification Path Validation
/// - RFC 5280 §4.2.1.9 - Basic Constraints
/// - RFC 5280 §4.2.1.3 - Key Usage
/// - RFC 5280 §4.2.1.12 - Extended Key Usage
```

### 5. sig.zig - NEEDS INLINE RFC COMMENTS
**Current State**: Good structure, needs more RFC references

**Additions Needed:**
```zig
//! Signature Scheme Parsing and Verification Module
//!
//! Implements TLS 1.3 signature algorithms for certificate authentication
//! per RFC 8446 §4.2.3 and §4.4.3.
//!
//! ## Supported Algorithms
//! - ECDSA with P-256/SHA-256 (RFC 8446, RFC 8422)
//! - ECDSA with P-384/SHA-384 (RFC 8446, RFC 8422)
//! - RSA-PSS with SHA-256 (RFC 8446, RFC 8017 §8.1)
//! - Ed25519 (RFC 8446, RFC 8032)
//!
//! ## TLS 1.3 Context String
//! RFC 8446 §4.4.3 requires signatures over:
//! ```
//! 0x20 * 64 || context || 0x00 || transcript_hash
//! ```
//! Where context is "TLS 1.3, server CertificateVerify" or similar.

// For SigAlg enum:
/// TLS 1.3 signature algorithms (RFC 8446 §4.2.3).
///
/// These correspond to SignatureScheme registry values, supporting
/// only the signature algorithms required for TLS 1.3 authentication.
pub const SigAlg = enum {
    ecdsa_secp256r1_sha256,  // RFC 8446 - 0x0403
    ecdsa_secp384r1_sha384,  // RFC 8446 - 0x0503
    rsa_pss_sha256,          // RFC 8446 - 0x0804
    ed25519,                 // RFC 8446 - 0x0807
};

// For verifyCertificateVerify():
/// Verify TLS 1.3 CertificateVerify signature (RFC 8446 §4.4.3).
///
/// Validates the signature over the TLS 1.3 signing context:
/// ```
/// digital_signature = Sign(
///     0x20 * 64 || context_string || 0x00 || Transcript-Hash(...)
/// )
/// ```
///
/// ## Parameters
/// - `alg`: Signature algorithm to use
/// - `pubkey_spki_der`: DER-encoded SubjectPublicKeyInfo from certificate
/// - `sig`: Signature bytes (DER for ECDSA, raw for Ed25519/RSA-PSS)
/// - `context`: TLS context string (e.g., "TLS 1.3, server CertificateVerify")
/// - `transcript_hash`: Hash of handshake messages up to CertificateVerify
///
/// ## RFC References
/// - RFC 8446 §4.4.3 - CertificateVerify signature construction
/// - RFC 8446 §4.2.3 - Signature algorithms

// For rsa_pss_verify_sha256():
/// Verify RSA-PSS signature with SHA-256 (RFC 8017 §8.1).
///
/// Implements RSASSA-PSS-VERIFY per RFC 8017 with:
/// - Hash: SHA-256
/// - MGF: MGF1-SHA-256
/// - Salt length: 32 bytes (same as hash output)
///
/// ## RFC References
/// - RFC 8017 §8.1 - RSASSA-PSS signature scheme
/// - RFC 8446 - RSA-PSS required for TLS 1.3
```

### 6. asn1.zig - NEEDS INLINE RFC COMMENTS
**Current State**: Minimal docs, straightforward DER decoder

**Additions Needed:**
```zig
//! ASN.1 DER Decoder Module
//!
//! Minimal Distinguished Encoding Rules (DER) decoder for X.509 certificate
//! parsing in TLS 1.3 QUIC connections.
//!
//! ## RFC Coverage
//! - X.690 - ASN.1 encoding rules (DER subset)
//! - RFC 5280 - X.509 uses ASN.1 DER encoding
//!
//! ## Supported Universal Types
//! - SEQUENCE (tag 16, constructed)
//! - INTEGER (tag 2)
//! - OCTET STRING (tag 4)
//! - BIT STRING (tag 3)
//! - OBJECT IDENTIFIER (tag 6)
//! - UTF8String (tag 12)
//! - IA5String (tag 22)
//!
//! ## Migration Note
//! TODO: Migrate to std.crypto.codecs.asn1 when stable (Zig 0.15.x+)

/// ASN.1 tag class from tag byte bits 7-6 (X.690 §8.1.2.2).
pub const TagClass = enum { universal, application, context, private };

/// Extract tag class from DER tag byte (X.690 §8.1.2).
pub fn tagClass(b: u8) TagClass { ... }

/// Check if tag indicates constructed encoding (X.690 §8.1.2.5).
pub fn isConstructed(b: u8) bool { ... }

/// Extract tag number from tag byte bits 4-0 (X.690 §8.1.2.3).
pub fn tagNumber(b: u8) u8 { ... }

// For Decoder.readSequence():
/// Read a SEQUENCE and return its content (X.690 §8.9).
///
/// SEQUENCE is tag 0x30 (universal class, constructed, tag number 16).
/// Used extensively in X.509 for certificate structure.

// For Decoder.readInteger():
/// Read an INTEGER as u64 (X.690 §8.3).
///
/// Supports non-negative integers up to 64 bits in big-endian
/// two's complement encoding.

// For Decoder.readBitString():
/// Read a BIT STRING payload (X.690 §8.6).
///
/// Returns content after removing the initial "unused bits" byte.
/// Used for SubjectPublicKeyInfo and signatures in X.509.

// For Decoder.readOID():
/// Read an OBJECT IDENTIFIER (X.690 §8.19).
///
/// Returns the encoded OID bytes. Caller interprets OID arc values.
/// Used for algorithm identifiers and certificate extensions.
```

### 7. tls13.zig - LARGE FILE, STRATEGIC DOCUMENTATION
**Current State**: Well-structured with some RFC comments

**Key Sections Needing Documentation:**
```zig
//! TLS 1.3 Handshake State Machine for QUIC
//!
//! Implements the TLS 1.3 protocol (RFC 8446) as a QUIC-TLS integration layer
//! per RFC 9001 §4. This module provides:
//!
//! - Transcript hash management (§4.4.1)
//! - Secret derivation and callback notifications (§7.1)
//! - Handshake message parsing and generation
//! - QUIC transport parameter exchange (RFC 9001 §8.2)
//! - ALPN negotiation (RFC 7301)
//! - 0-RTT early data support (§8)
//!
//! ## Design Principle: INTEROP FIRST
//! This implementation ALWAYS attempts real TLS 1.3 format parsing BEFORE
//! falling back to minimal/test formats. This ensures out-of-the-box
//! compatibility with quic-go, quinn, msquic, and other real-world QUIC stacks.
//!
//! ## Key RFC References
//! - RFC 8446 - TLS 1.3 core protocol
//! - RFC 9001 - Using TLS to Secure QUIC
//! - RFC 7301 - ALPN
//! - RFC 9000 - QUIC transport
//! - RFC 9369 - QUIC v2

/// TLS 1.3 handshake configuration (RFC 8446 §4).
///
/// Captures all negotiable parameters for driving a compliant TLS 1.3
/// exchange in the QUIC context. Roles, cipher suites, and extensions
/// are configured here.
pub const Config = struct { ... }

/// Callback hooks during handshake lifecycle (RFC 8446 §4.1–§4.6).
///
/// Notifies the QUIC layer about:
/// - New encryption secrets becoming available (install packet protection)
/// - Handshake metadata (ALPN, transport parameters)
/// - Peer Finished verification (can send 1-RTT data)
/// - Handshake completion (connection fully established)
pub const Callbacks = struct { ... }

/// QUIC encryption levels (RFC 9001 §4.1.4).
///
/// Corresponds to QUIC packet number spaces:
/// - Initial: Unverified handshake packets
/// - Handshake: Certificate exchange and authentication
/// - Application: 1-RTT protected data
pub const EncryptionLevel = enum { Initial, Handshake, Application };

/// Transcript hash accumulator (RFC 8446 §4.4.1).
///
/// Maintains a running hash of all handshake messages in order.
/// The transcript hash is used for:
/// - Deriving handshake secrets (§7.1)
/// - Finished message verification (§4.4.4)
/// - Certificate signature context (§4.4.3)
pub const Transcript = struct { ... }
```

### 8. tls13_full.zig - EXTENSION PARSING
**Needs**: RFC references for each extension type

```zig
//! Full TLS 1.3 Message Parsing Module
//!
//! Implements wire-format parsing for TLS 1.3 handshake messages and
//! extensions per RFC 8446 §4. This module handles:
//!
//! - ClientHello / ServerHello messages (§4.1.2, §4.1.3)
//! - EncryptedExtensions (§4.3.1)
//! - All TLS 1.3 extensions (§4.2)
//! - QUIC-specific extensions (RFC 9001 §8.2)
//!
//! ## Extension Registry
//! Implements TLS ExtensionType registry (IANA):
//! - server_name (0) - RFC 6066
//! - supported_groups (10) - RFC 8446
//! - signature_algorithms (13) - RFC 8446
//! - application_layer_protocol_negotiation (16) - RFC 7301
//! - supported_versions (43) - RFC 8446
//! - key_share (51) - RFC 8446
//! - pre_shared_key (41) - RFC 8446
//! - early_data (42) - RFC 8446
//! - quic_transport_parameters (0x39/57) - RFC 9001

/// TLS extension types (RFC 8446 §4.2 and various extension RFCs).
pub const ExtensionType = enum(u16) {
    server_name = 0,  // RFC 6066
    supported_groups = 10,  // RFC 8446 §4.2.7
    signature_algorithms = 13,  // RFC 8446 §4.2.3
    alpn = 16,  // RFC 7301
    supported_versions = 43,  // RFC 8446 §4.2.1
    key_share = 51,  // RFC 8446 §4.2.8
    pre_shared_key = 41,  // RFC 8446 §4.2.11
    early_data = 42,  // RFC 8446 §4.2.10
    quic_transport_parameters = 0x0039,  // RFC 9001 §8.2
    // ...
};

/// Named elliptic curve groups (RFC 8446 §4.2.7).
///
/// Supported groups for ECDHE key exchange in TLS 1.3.
pub const NamedGroup = enum(u16) {
    x25519 = 0x001d,  // RFC 7748
    secp256r1 = 0x0017,  // RFC 8422 (P-256)
    secp384r1 = 0x0018,  // RFC 8422 (P-384)
    // ...
};

/// Cipher suites (RFC 8446 §B.4).
///
/// TLS 1.3 defines only AEAD cipher suites with integrated authentication.
pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301,  // RFC 8446 (mandatory)
    TLS_AES_256_GCM_SHA384 = 0x1302,  // RFC 8446
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,  // RFC 8446
    TLS_AES_128_CCM_SHA256 = 0x1304,  // RFC 8446
    // ...
};
```

### 9. zero_rtt.zig - 0-RTT AND PSK
**Needs**: RFC 8446 §8 references throughout

```zig
//! 0-RTT Early Data and Session Resumption Module
//!
//! Implements TLS 1.3 0-RTT (zero round-trip time) early data and
//! pre-shared key (PSK) resumption per RFC 8446 §8 and §4.2.11.
//!
//! ## Security Considerations (RFC 8446 §8)
//! 0-RTT data is NOT forward secret and vulnerable to replay attacks.
//! This module provides:
//! - Anti-replay protection via single-use tickets
//! - Ticket age verification with obfuscation (§8.1.1)
//! - FIFO eviction for bounded memory usage
//!
//! ## RFC Coverage
//! - RFC 8446 §8 - 0-RTT and Anti-Replay
//! - RFC 8446 §4.2.11 - Pre-Shared Key Extension
//! - RFC 8446 §4.6.1 - New Session Ticket Message
//! - RFC 9001 §4.6.1 - 0-RTT in QUIC

/// 0-RTT anti-replay window (RFC 8446 §8.1).
///
/// Tracks recently used PSK identities to prevent replay attacks.
/// Uses a FIFO queue with bounded capacity for memory efficiency.
pub const AntiReplayWindow = struct { ... }

/// Session ticket state (RFC 8446 §4.6.1).
///
/// Represents a resumption PSK with:
/// - Ticket identity (opaque handle)
/// - PSK value (derived from resumption_master_secret)
/// - Ticket lifetime and age_add for obfuscation
/// - Associated cipher suite and ALPN
pub const TicketState = struct { ... }
```

### 10. quic_transport_params.zig - QUIC INTEGRATION
**Needs**: RFC 9000 §18 references

```zig
//! QUIC Transport Parameters Module
//!
//! Implements QUIC transport parameters exchange via TLS extension
//! per RFC 9001 §8.2. Transport parameters configure connection-level
//! behavior for flow control, stream limits, and QUIC features.
//!
//! ## RFC Coverage
//! - RFC 9000 §18 - Transport Parameters
//! - RFC 9001 §8.2 - QUIC Transport Parameters Extension
//! - RFC 9000 §7.3 - Connection ID management
//! - RFC 9000 §10 - Flow control parameters

/// Transport parameter types (RFC 9000 §18.2).
pub const TransportParameterId = enum(u64) {
    original_destination_connection_id = 0x00,  // RFC 9000 §18.2
    max_idle_timeout = 0x01,  // RFC 9000 §18.2
    stateless_reset_token = 0x02,  // RFC 9000 §18.2
    max_udp_payload_size = 0x03,  // RFC 9000 §18.2
    initial_max_data = 0x04,  // RFC 9000 §18.2 - Connection flow control
    // ... more parameters ...
};

/// Parse QUIC transport parameters from TLS extension (RFC 9001 §8.2).
///
/// Transport parameters are encoded as variable-length integers and
/// byte strings per RFC 9000 §16 (variable-length integer encoding).
pub fn parseTransportParameters(...) { ... }

/// Encode QUIC transport parameters for TLS extension (RFC 9001 §8.2).
pub fn encodeTransportParameters(...) { ... }
```

### 11. quic_logger.zig - LOGGING UTILITY
**Needs**: Basic module documentation

```zig
//! QUIC Connection Logging Module
//!
//! Provides structured logging for TLS and QUIC events during handshake
//! and connection lifetime. Useful for debugging interop issues and
//! analyzing handshake flows.
//!
//! ## Log Categories
//! - Handshake progress (ClientHello, ServerHello, Finished)
//! - Secret installation (encryption level transitions)
//! - Extension negotiation (ALPN, transport parameters, key shares)
//! - Error conditions (alert generation, validation failures)

/// Log levels for filtering output verbosity.
pub const LogLevel = enum { debug, info, warn, err };

/// Structured logger for connection events.
pub const Logger = struct { ... }
```

### 12. lib.zig - LIBRARY ENTRY POINT
**Needs**: Public API documentation

```zig
//! ZTLS - TLS 1.3 for QUIC Implementation
//!
//! Public API for integrating TLS 1.3 handshake functionality into QUIC
//! transport implementations. Provides:
//!
//! - TLS 1.3 handshake state machine (RFC 8446)
//! - QUIC-TLS integration (RFC 9001)
//! - Secret derivation and key schedule (RFC 8446 §7)
//! - Certificate validation (RFC 5280)
//! - 0-RTT early data support (RFC 8446 §8)
//!
//! ## Usage Example
//! ```zig
//! const ztls = @import("ztls");
//!
//! var config = ztls.Config{
//!     .role = .Client,
//!     .alpn_protocols = &.{"h3"},
//!     .supported_groups = &.{.x25519},
//!     // ...
//! };
//!
//! var ctx = try ztls.Context.init(allocator, config, callbacks);
//! defer ctx.deinit();
//!
//! // Process CRYPTO frames from QUIC
//! try ctx.processCrypto(crypto_data, encryption_level);
//! ```
//!
//! ## Re-exported Modules
//! All core types and functions are re-exported for convenience:

pub const tls13 = @import("tls13.zig");
pub const key_schedule = @import("key_schedule.zig");
pub const record = @import("record.zig");
pub const x509 = @import("x509.zig");
pub const sig = @import("sig.zig");
pub const alert = @import("alert.zig");
pub const zero_rtt = @import("zero_rtt.zig");

// Re-export primary types
pub const Config = tls13.Config;
pub const Context = tls13.Context;
pub const EncryptionLevel = tls13.EncryptionLevel;
// ...
```

## Documentation Patterns Applied

### 1. File-Level Documentation (`//!`)
- Module purpose and scope
- Primary RFC references with section numbers
- Key features and capabilities
- Design notes and limitations
- Migration notes (e.g., stdlib transition)

### 2. Public Function Documentation (`///`)
- What the function does (imperative description)
- Algorithm or formula being implemented
- Parameters section with descriptions
- Returns section explaining output
- RFC References section with specific citations
- Example usage where helpful

### 3. Inline RFC Comments (`//`)
- Placed BEFORE or BESIDE the line implementing a specific requirement
- Format: `// RFC XXXX §Y.Z - Brief explanation`
- Examples:
  - `// RFC 8446 §5.1 - Legacy version must be 0x0303`
  - `// RFC 9001 §5.2 - Use QUIC v1 initial salt`
  - `// RFC 8446 §7.1 - Construct HkdfLabel as HKDF info parameter`

### 4. Struct/Type Documentation (`///`)
- Purpose of the type in the TLS/QUIC context
- RFC reference for the data structure
- Field explanations for complex types
- Invariants or constraints

### 5. Test Documentation
- Test name follows pattern: `test "RFC XXXX §Y.Z - description"`
- Tests grouped by RFC section
- Each test validates a specific requirement

## RFC Reference Quick Guide

### Primary RFCs
- **RFC 8446** - TLS 1.3 (Transport Layer Security 1.3)
- **RFC 9001** - Using TLS to Secure QUIC
- **RFC 9000** - QUIC: A UDP-Based Multiplexed and Secure Transport
- **RFC 9369** - QUIC Version 2

### Supporting RFCs
- **RFC 5280** - X.509 Public Key Infrastructure
- **RFC 5869** - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- **RFC 7301** - Application-Layer Protocol Negotiation (ALPN)
- **RFC 8017** - PKCS #1: RSA Cryptography Specifications (RSA-PSS)
- **RFC 8032** - Edwards-Curve Digital Signature Algorithm (Ed25519)
- **RFC 6125** - Representation and Verification of Domain-Based Names (DNS-ID)
- **RFC 2104** - HMAC: Keyed-Hashing for Message Authentication
- **X.690** - ASN.1 encoding rules (DER)

### RFC Section Patterns
- **§4** - Handshake Protocol
- **§5** - Record Protocol
- **§6** - Alert Protocol
- **§7** - Cryptographic Computations (Key Schedule)
- **§8** - 0-RTT and Anti-Replay
- **Appendix A** - Protocol State Machine
- **Appendix B** - Protocol Data Structures
- **Appendix C/D** - Cipher Suites and Test Vectors

## Next Steps

### Immediate Actions
1. Apply inline RFC comments to `record.zig` (AEAD operations)
2. Add function documentation to `x509.zig` (certificate validation)
3. Document signature verification in `sig.zig` (RSA-PSS, ECDSA, Ed25519)
4. Add ASN.1 references to `asn1.zig`
5. Strategic documentation additions to `tls13.zig` (focus on state machine)

### Medium-term Documentation
6. Extension documentation in `tls13_full.zig`
7. 0-RTT security notes in `zero_rtt.zig`
8. QUIC parameter encoding in `quic_transport_params.zig`
9. Logging categories in `quic_logger.zig`
10. Public API examples in `lib.zig`

### Testing Documentation
- All test files should follow RFC section naming
- Add test descriptions explaining what requirement is validated
- Cross-reference test vectors to RFC appendices

## Documentation Quality Checklist

For each documented item:
- [ ] File-level `//!` documentation present
- [ ] RFC references included (with section numbers)
- [ ] Public functions have `///` doc comments
- [ ] Parameters and returns documented
- [ ] Inline `//` comments at RFC implementation points
- [ ] Test names reference RFC sections
- [ ] Complex algorithms explained with formulas
- [ ] Security considerations noted where applicable

## Estimated Remaining Effort

- **High Priority (record, x509, sig, asn1)**: 2-3 hours
- **Medium Priority (tls13, tls13_full)**: 3-4 hours
- **Low Priority (zero_rtt, quic_*, lib)**: 1-2 hours
- **Total**: 6-9 hours for complete documentation coverage

## Tools and Verification

### Running Tests
```bash
# Test individual files
zig test src/key_schedule.zig
zig test src/record.zig
zig test src/alert.zig

# Test all modules
find src -name "*.zig" -exec zig test {} \;
```

### Documentation Generation
Zig documentation is generated from `///` and `//!` comments:
```bash
zig build-exe -femit-docs=docs src/lib.zig
```

### RFC Quick Reference
All referenced RFCs are available in `/home/benji/src/spyder/ztls/specs/`:
- `rfc8446.txt` - TLS 1.3
- `rfc9001.txt` - QUIC-TLS
- `rfc5280.txt` - X.509
- `rfc5869.txt` - HKDF
- ... (full list in specs directory)

---

**Generated**: 2025-11-05
**Author**: Claude (Anthropic)
**Purpose**: Comprehensive documentation enhancement for ZTLS codebase
