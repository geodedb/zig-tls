# Architecture

This document describes the architecture of the ztls TLS 1.3 library.

## Module Structure

```text
src/
├── lib.zig                 # Main library entry point and re-exports
├── tls13/                  # Modularized TLS 1.3 implementation (canonical root)
│   ├── mod.zig             # Module aggregation
│   ├── config.zig          # Config struct
│   ├── context.zig         # Context + Callbacks (main driver)
│   ├── types.zig           # Core types (Role, errors, metadata)
│   ├── transcript.zig      # Transcript hash management
│   ├── handshake_state.zig # State machine, CRYPTO buffering
│   ├── secrets.zig         # Traffic secret storage
│   ├── finished.zig        # Finished message verification
│   ├── key_derivation.zig  # Key schedule wrappers
│   └── messages/           # Message parsing/encoding
│       ├── client_hello.zig
│       ├── server_hello.zig
│       ├── certificate.zig
│       ├── certificate_verify.zig
│       ├── finished.zig
│       └── extensions/
│           └── cookie.zig
├── key_schedule.zig        # HKDF-based key derivation
├── record.zig              # Record layer + AEAD operations
├── record/                 # Modularized record layer
│   ├── mod.zig
│   ├── plaintext.zig       # TLSPlaintext/TLSInnerPlaintext
│   └── aead.zig            # AEAD cipher operations
├── x509.zig                # Certificate parsing and validation
├── sig.zig                 # Signature verification
├── asn1.zig                # ASN.1 DER decoder
├── alert.zig               # TLS alert protocol
├── entropy.zig             # Fail-closed RNG helper (SEC-074)
├── zero_rtt.zig            # 0-RTT anti-replay support (shipped)
├── ocsp.zig                # OCSP stapling
├── sct.zig                 # Signed Certificate Timestamps
├── varint.zig              # QUIC/TLS variable-length integer codec
├── byteorder.zig           # Endianness helpers (big-endian writers)
├── quic_logger.zig         # Structured logger for QUIC/TLS events
├── tls13_full.zig          # Full-message builders for TLS 1.3 flights
├── rfc_compliance_test.zig # Aggregate RFC-compliance tests
└── quic_transport_params.zig # QUIC transport parameter encoding
```

## Core Concepts

### TLS 1.3 Context (`tls13/context.zig`)

The `Context` struct is the main driver for TLS 1.3 handshakes:

```zig
pub const Context = struct {
    config: Config,
    callbacks: Callbacks,
    state: HandshakeState,
    transcripts: TranscriptSet,
    secrets: SecretSchedule,
    // ...

    pub fn init(config: Config, callbacks: Callbacks) !Context;
    pub fn deinit(self: *Context) void;
    pub fn processCrypto(self: *Context, level: EncryptionLevel, data: []const u8) !void;
    pub fn getOutgoingCrypto(self: *Context) ?CryptoFrame;
};
```

### Handshake State Machine

The handshake progresses through defined phases:

```zig
pub const HandshakePhase = enum {
    Initial,           // Waiting for/sending ClientHello
    ServerHello,       // Processing ServerHello
    EncryptedExtensions,
    Certificate,
    CertificateVerify,
    Finished,
    Complete,          // Handshake done
};
```

### Encryption Levels (RFC 9001 Section 4.1)

QUIC uses distinct encryption levels that map to handshake stages:

| Level | Messages | Keys Derived From |
|-------|----------|-------------------|
| `Initial` | ClientHello, ServerHello | DCID (fixed algorithm) |
| `Handshake` | EncryptedExtensions, Certificate, CertificateVerify, Finished | ECDHE shared secret |
| `Application` | 1-RTT data | Handshake completion |

### Key Schedule (`key_schedule.zig`)

Implements RFC 8446 Section 7.1 key derivation:

```text
                            0
                            |
                            v
              PSK ->  HKDF-Extract = Early Secret
                            |
                            +-----> Derive-Secret(., "ext binder", "")
                            |                     = binder_key
                            +-----> Derive-Secret(., "res binder", "")
                            |                     = resumption_binder_key
                            +-----> Derive-Secret(., "c e traffic", ClientHello)
                            |                     = client_early_traffic_secret
                            +-----> Derive-Secret(., "e exp master", ClientHello)
                            |                     = early_exporter_master_secret
                            v
                      Derive-Secret(., "derived", "")
                            |
                            v
    (EC)DHE -> HKDF-Extract = Handshake Secret
                            |
                            +-----> Derive-Secret(., "c hs traffic", ClientHello...ServerHello)
                            |                     = client_handshake_traffic_secret
                            +-----> Derive-Secret(., "s hs traffic", ClientHello...ServerHello)
                            |                     = server_handshake_traffic_secret
                            v
                      Derive-Secret(., "derived", "")
                            |
                            v
               0 -> HKDF-Extract = Master Secret
                            |
                            +-----> Derive-Secret(., "c ap traffic", ClientHello...server Finished)
                            |                     = client_application_traffic_secret_0
                            +-----> Derive-Secret(., "s ap traffic", ClientHello...server Finished)
                            |                     = server_application_traffic_secret_0
                            +-----> Derive-Secret(., "exp master", ClientHello...server Finished)
                            |                     = exporter_master_secret
                            +-----> Derive-Secret(., "res master", ClientHello...client Finished)
                                                  = resumption_master_secret
```

### Transcript Hash Management (`tls13/transcript.zig`)

Maintains incremental hash of handshake messages:

```zig
pub const Transcript = struct {
    sha256: std.crypto.hash.sha2.Sha256,
    sha384: std.crypto.hash.sha2.Sha384,

    pub fn update(self: *Transcript, data: []const u8) void;
    pub fn currentHash(self: *const Transcript, hash: Hash) Secret;
};
```

The transcript hash is used for:

- Deriving traffic secrets
- Finished message verify_data
- CertificateVerify signature

### AEAD Protection (`record/aead.zig`)

Implements authenticated encryption for TLS records:

```zig
pub const AeadCipher = struct {
    suite: CipherSuite,
    key: [32]u8,           // AES-128: 16 bytes, AES-256/ChaCha: 32 bytes
    iv: [12]u8,            // 96-bit nonce base
    usage: AeadUsageStats,

    pub fn seal(allocator, seq: u64, aad: []const u8, plaintext: []const u8) ![]u8;
    pub fn open(allocator, seq: u64, aad: []const u8, ciphertext: []const u8) ![]u8;
    pub fn wipe(self: *AeadCipher) void;
};
```

Nonce derivation (RFC 8446 Section 5.3):

```text
nonce = base_iv XOR pad64(sequence_number)
```

### X.509 Certificate Validation (`x509.zig`)

Validates certificate chains per RFC 5280:

```zig
pub fn validateChain(
    allocator: Allocator,
    chain_der: []const []const u8,
    now_unix: i64,
    server_name: []const u8,
    allow_insecure: bool,
) !void;
```

Validation steps:

1. Parse all certificates in chain
2. Check leaf validity period (notBefore/notAfter)
3. Verify server_name matches SAN or CN
4. Check ExtendedKeyUsage (serverAuth)
5. Check KeyUsage (digitalSignature)
6. Verify intermediate CAs have BasicConstraints CA=true
7. Enforce path length constraints
8. Verify signatures along chain
9. Validate root against trust store

## Data Flow

### Client Handshake Flow

```text
┌─────────┐                                           ┌─────────┐
│  QUIC   │                                           │   TLS   │
│ Layer   │                                           │ Context │
└────┬────┘                                           └────┬────┘
     │                                                     │
     │  1. Connection established                          │
     │────────────────────────────────────────────────────>│
     │                                                     │
     │  2. generateClientHello()                           │
     │<────────────────────────────────────────────────────│
     │                                                     │
     │  3. Send CRYPTO frame (Initial)                     │
     │════════════════════════════════>                    │
     │                                                     │
     │  4. Receive ServerHello                             │
     │<════════════════════════════════                    │
     │                                                     │
     │  5. processCrypto(.Initial, server_hello)           │
     │────────────────────────────────────────────────────>│
     │                                                     │
     │  6. on_secret_available(.Handshake, ...)            │
     │<────────────────────────────────────────────────────│
     │                                                     │
     │  7. Receive EncryptedExtensions, Cert, CV, Finished │
     │<════════════════════════════════                    │
     │                                                     │
     │  8. processCrypto(.Handshake, ...)                  │
     │────────────────────────────────────────────────────>│
     │                                                     │
     │  9. on_secret_available(.Application, ...)          │
     │<────────────────────────────────────────────────────│
     │                                                     │
     │ 10. on_handshake_complete()                         │
     │<────────────────────────────────────────────────────│
     │                                                     │
```

### Secret Installation Flow

```text
┌──────────────────────────────────────────────────────────────────┐
│                    Secret Derivation Pipeline                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  DCID ─────> deriveInitialSecretV1() ─────> Initial Secret       │
│                      │                                           │
│                      v                                           │
│              deriveClientServerInitial()                         │
│                      │                                           │
│         ┌───────────┴───────────┐                               │
│         v                       v                                │
│  client_initial_secret   server_initial_secret                   │
│         │                       │                                │
│         v                       v                                │
│  deriveKeyIvHp()         deriveKeyIvHp()                        │
│         │                       │                                │
│    ┌────┼────┐             ┌────┼────┐                          │
│    v    v    v             v    v    v                          │
│   key  iv   hp            key  iv   hp                          │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ECDHE ─────> deriveHandshakeTraffic() ─────> Handshake Secrets  │
│                                                                  │
│  Transcript ─> deriveApplicationTraffic() ─> Application Secrets │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Design Principles

### 1. RFC-Driven Development

Every implementation block cites the relevant RFC section:

```zig
/// RFC 9001 Section 5.2 - Initial Secrets
/// initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
pub fn deriveInitialSecretV1(dcid: []const u8) [32]u8 {
    return extract(&initial_salt_v1, dcid);
}
```

### 2. Zero External Dependencies

Uses only Zig standard library:

- `std.crypto.kdf.hkdf` - HKDF operations
- `std.crypto.aead` - AEAD ciphers (AES-GCM, ChaCha20-Poly1305)
- `std.crypto.hash` - SHA-256, SHA-384
- `std.crypto.sign` - ECDSA, Ed25519
- `std.mem` - Memory operations

### 3. QUIC-Native Design

Designed for QUIC integration (RFC 9001):

- No traditional TLS record layer
- Direct CRYPTO frame processing
- Encryption level abstraction
- Transport parameter extension support

### 4. Interoperability First

Compatible with real-world implementations:

- quic-go
- quinn (Rust)
- msquic
- BoringSSL
- OpenSSL

### 5. Memory Safety

- Explicit allocator passing
- Deferred cleanup patterns
- Secret zeroization via `std.crypto.secureZero()`
- No global state (except optional trust store)

## Security Considerations

### Constant-Time Operations

- Secret comparisons use `std.crypto.timing_safe.eql()`
- AEAD implementations use constant-time algorithms

### AEAD Usage Limits

RFC 8446 Section 5.5 limits enforced:

- AES-GCM: 2^24 messages before key rotation
- ChaCha20-Poly1305: 2^36 messages

### Transcript Integrity

- All handshake messages included in transcript hash
- Finished message provides cryptographic binding
- Tampering causes `FinishedVerifyFailed`

### Certificate Validation

- Validity period checked against current time
- Server name (SNI) matched against SAN/CN
- Chain signatures verified
- Path constraints enforced
- Trust anchor validation via callback

### Anti-Replay (0-RTT)

- Sliding window for ticket deduplication
- FIFO eviction for bounded memory
- Configurable window size

## Testing Strategy

### Unit Tests

Per-module tests in source files:

```bash
zig test src/key_schedule.zig
zig test src/record.zig
zig test src/x509.zig
```

### RFC Test Vectors

Official vectors from RFC appendices:

- RFC 8446 Appendix A - TLS 1.3 vectors
- RFC 9001 Appendix A.1 - QUIC initial secret vectors

### Conformance Tests

Parity testing against:

- BoringSSL (HKDF, AEAD, signatures)
- OpenSSL 3.x (EVP API, X.509)

```bash
make test-conformance
```

## Future Enhancements

- [ ] HKDF-Expand-Label wrapper optimization
- [ ] Full OCSP stapling validation
- [ ] Complete certificate chain validation
- [ ] Additional cipher suites (AES-256-GCM-SHA384)
- [ ] Migration to stdlib X.509 when stable
- [ ] Post-quantum algorithm readiness

## Dependencies

External Zig libraries: **None**

All cryptographic operations use `std.crypto`:

- `std.crypto.kdf.hkdf` - Key derivation
- `std.crypto.aead.aes_gcm` - AES-GCM
- `std.crypto.aead.chacha_poly` - ChaCha20-Poly1305
- `std.crypto.hash.sha2` - SHA-256, SHA-384
- `std.crypto.sign.ecdsa` - ECDSA
- `std.crypto.sign.Ed25519` - EdDSA
