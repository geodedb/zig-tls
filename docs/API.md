# API Reference

This document provides an overview of the ztls API. For full documentation, generate the autodocs using `zig build docs`.

## Quick Reference

### Main Module: `ztls`

```zig
const ztls = @import("ztls");
```

## Core Types

### Context

Main TLS 1.3 connection state machine.

```zig
var ctx = try ztls.Context.init(config, callbacks);
defer ctx.deinit();

// Process incoming CRYPTO frame
try ctx.processCrypto(.Handshake, crypto_data);

// Get outgoing CRYPTO data
while (ctx.getOutgoingCrypto()) |frame| {
    try quic.sendCryptoFrame(frame.level, frame.data);
}
```

### Config

TLS 1.3 configuration parameters.

| Field | Type | Description |
|-------|------|-------------|
| `allocator` | `std.mem.Allocator` | Memory allocator for buffers |
| `role` | `Role` | `.Client` or `.Server` |
| `supported_cipher_suites` | `[]const CipherSuite` | Cipher suite preferences |
| `supported_groups` | `[]const NamedGroup` | ECDHE groups (x25519, etc.) |
| `supported_signature_schemes` | `[]const SignatureScheme` | Signature algorithms |
| `alpn_protocols` | `?[]const []const u8` | ALPN protocol list |
| `quic_transport_parameters` | `?[]const u8` | QUIC transport params |
| `server_name` | `?[]const u8` | SNI hostname (client) |
| `server_cert_der` | `?[]const u8` | DER certificate (server) |
| `server_key_der` | `?[]const u8` | DER private key (server) |
| `allow_insecure` | `bool` | Skip cert validation (testing) |
| `enable_early_data` | `bool` | Enable 0-RTT |

### Callbacks

QUIC integration callback hooks.

```zig
const callbacks = ztls.Callbacks{
    .on_secret_available = onSecretAvailable,
    .on_handshake_complete = onHandshakeComplete,
    .on_peer_finished = onPeerFinished,
    .on_handshake_metadata = onHandshakeMetadata,
    .fetch_certificate_chain = fetchCertChain,
};
```

| Callback | Description |
|----------|-------------|
| `on_secret_available` | Traffic secrets ready for key derivation |
| `on_handshake_complete` | Handshake finished successfully |
| `on_peer_finished` | Peer Finished message verified |
| `on_handshake_metadata` | ALPN and transport params available |
| `fetch_certificate_chain` | Dynamic certificate retrieval (server) |

### EncryptionLevel

QUIC encryption levels (RFC 9001 Section 4.1).

```zig
pub const EncryptionLevel = enum {
    Initial,      // ClientHello, ServerHello
    Handshake,    // EncryptedExtensions, Certificate, Finished
    Application,  // 1-RTT application data
};
```

## Key Schedule Module

HKDF-based key derivation (RFC 8446 Section 7, RFC 9001 Section 5).

### Initial Secret Derivation

```zig
// QUIC v1 initial secret from DCID
const initial = ztls.key_schedule.deriveInitialSecretV1(&dcid);

// QUIC v2 initial secret
const initial_v2 = ztls.key_schedule.deriveInitialSecretV2(&dcid);

// Split into client/server secrets
const secrets = ztls.key_schedule.deriveClientServerInitial(initial);
// secrets.client, secrets.server
```

### Packet Protection Keys

```zig
// Derive key (16), IV (12), HP (16) from traffic secret
const keys = ztls.key_schedule.deriveKeyIvHp(traffic_secret);
// keys.key, keys.iv, keys.hp

// QUIC v2 labels
const keys_v2 = ztls.key_schedule.deriveKeyIvHpV2(traffic_secret);
```

### Key Update

```zig
// TLS 1.3 key update (RFC 8446 Section 7.2)
const next_secret = ztls.key_schedule.updateTrafficSecret(current_secret);

// QUIC-specific key update (RFC 9001 Section 6)
const next_quic = ztls.key_schedule.updateQuicSecret(current_secret);
```

### HKDF Operations

```zig
// HKDF-Extract
const prk = ztls.key_schedule.extract(salt, ikm);

// HKDF-Expand-Label
var out: [32]u8 = undefined;
try ztls.key_schedule.expandLabel(&prk, "label", context, &out);

// HMAC-SHA256
const mac = ztls.key_schedule.hmacSha256(key, data);
```

## Record Layer Module

AEAD encryption and TLS record primitives.

### Cipher Suites

```zig
pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
};
```

### AEAD Cipher

```zig
var cipher = try ztls.record.AeadCipher.init(
    .TLS_AES_128_GCM_SHA256,
    &key,
    &iv,
    null, // Optional usage limits
);
defer cipher.wipe();

// Seal (encrypt + authenticate)
const ciphertext = try cipher.seal(allocator, seq_num, aad, plaintext);
defer allocator.free(ciphertext);

// Open (decrypt + verify)
const plaintext = try cipher.open(allocator, seq_num, aad, ciphertext);
defer allocator.free(plaintext);
```

### Nonce Derivation

```zig
var nonce: [12]u8 = undefined;
try ztls.record.xorNonce(&nonce, &base_iv, sequence_number);
```

### AEAD Usage Limits

RFC 8446 Section 5.5 limits to prevent key exhaustion.

```zig
const limits = ztls.record.AeadUsageLimits{
    .confidentiality = 1 << 23, // Max encryptions
    .integrity = 1 << 36,       // Max auth failures
};
```

## X.509 Certificate Module

Certificate parsing and validation (RFC 5280).

### Certificate Parsing

```zig
const cert = try ztls.x509.parseCert(allocator, der_bytes);
// cert.subject.cn - Common Name
// cert.san - Subject Alternative Names
// cert.spki - SubjectPublicKeyInfo
// cert.not_before_unix, cert.not_after_unix - Validity period
// cert.basic - BasicConstraints
// cert.ku - KeyUsage
// cert.eku - ExtendedKeyUsage
```

### Chain Validation

```zig
const chain = [_][]const u8{ leaf_der, intermediate_der, root_der };

try ztls.x509.validateChain(
    allocator,
    &chain,
    std.time.timestamp(), // current time
    "example.com",        // expected server name
    false,                // allow_insecure
);
```

### DNS Name Matching

```zig
const matches = ztls.x509.matchDnsName(&cert, "www.example.com");
```

### Trust Store

```zig
ztls.x509.setTrustStore(.{
    .isTrustedSpki = myTrustCallback,
});

// Callback signature
fn myTrustCallback(spki_der: []const u8) bool {
    // Return true if SPKI is a trusted root
}
```

### Name Constraints

```zig
const constraints = ztls.x509.NameConstraints{
    .permitted_dns = &.{".example.com"},
    .excluded_dns = &.{".forbidden.example.com"},
};

const allowed = ztls.x509.checkNameConstraints("www.example.com", constraints);
```

## Alert Module

TLS alert protocol (RFC 8446 Section 6).

### Alert Types

```zig
pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    handshake_failure = 40,
    bad_certificate = 42,
    certificate_expired = 45,
    decode_error = 50,
    internal_error = 80,
    // ... and more
};

pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
};
```

### QUIC Error Mapping

```zig
// Map TLS alert to QUIC CRYPTO_ERROR (RFC 9001 Section 4.8)
const quic_error = ztls.alert.toQuicCryptoError(.handshake_failure);
// Returns 0x0100 + 40 = 0x0128
```

### Error to Alert Conversion

```zig
const alert = ztls.alert.fromHandshakeError(error.AlpnNegotiationFailed);
// Returns .no_application_protocol
```

## Signature Module

Signature verification for CertificateVerify (RFC 8446 Section 4.4.3).

### Signature Schemes

```zig
pub const SignatureScheme = enum(u16) {
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    rsa_pss_rsae_sha256 = 0x0804,
    ed25519 = 0x0807,
};
```

### SPKI Parsing

```zig
// Ed25519
const pubkey = try ztls.sig.parseEd25519Spki(spki_der);

// ECDSA
var spki = try ztls.sig.parseEcdsaSpki(spki_der, allocator);
defer spki.deinit();

// RSA
var rsa_spki = try ztls.sig.parseRsaSpki(spki_der, allocator);
defer rsa_spki.deinit();
```

## Zero-RTT Module

0-RTT session resumption support (RFC 8446 Section 8).

### Anti-Replay Window

```zig
var window = try ztls.zero_rtt.AntiReplayWindow.init(allocator, 1000);
defer window.deinit();

// Check if ticket is replay
const is_replay = window.checkAndAdd(ticket_nonce);
```

## Constants

### Initial Salts

```zig
// QUIC v1 initial salt (RFC 9001 Section 5.2)
pub const initial_salt_v1: [20]u8 = .{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

// QUIC v2 initial salt (RFC 9369 Section A.1)
pub const initial_salt_v2: [20]u8 = .{
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};
```

### Record Layer Constants

```zig
pub const max_plaintext_fragment = 16384;  // RFC 8446 Section 5.1
pub const max_inner_padding = 255;         // RFC 8446 Section 5.4
```

## Error Types

### HandshakeError

```zig
pub const HandshakeError = error{
    UnexpectedMessage,
    DuplicateClientHello,
    UnsupportedVersion,
    MissingKeyShare,
    UnsupportedKeyShareGroup,
    NoCipherSuite,
    MissingTransportParameters,
    AlpnNegotiationFailed,
    NoSignatureScheme,
    FinishedVerifyFailed,
    DowngradeAttempt,
    EmptyCertificateChain,
    MissingCertificate,
    CertificateValidationFailed,
    InvalidSignature,
    UnsupportedSignatureAlgorithm,
};
```

### RecordError

```zig
pub const RecordError = error{
    RecordTooShort,
    LengthMismatch,
    FragmentTooLarge,
    InvalidContentType,
    MissingContentType,
    UnsupportedLegacyVersion,
    InvalidKeyLength,
    InvalidIvLength,
    AuthenticationFailed,
    AeadLimitExceeded,
    CiphertextTooShort,
};
```

## Generating Full Documentation

```bash
# Generate HTML documentation
zig build docs

# View documentation
open zig-out/docs/index.html
```

The generated documentation includes full API details from doc comments in the source code.
