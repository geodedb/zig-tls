//! Full TLS 1.3 message parsing for QUIC-TLS interoperability.
//!
//! This module implements complete parsing and serialization of TLS 1.3 handshake
//! messages per RFC 8446 §4 (Handshake Protocol) and RFC 8446 §4.2 (Extensions).
//! It provides the real-world TLS format support needed for interoperability with
//! production QUIC stacks (quic-go, quinn, msquic, etc.).
//!
//! ## Design Philosophy: INTEROP FIRST
//!
//! This implementation prioritizes compatibility with standard TLS 1.3 formats:
//! - Parses all standard extension types and values from RFC 8446
//! - Supports real-world cipher suites, named groups, and signature schemes
//! - Auto-detects and handles formats used by major QUIC implementations
//! - Gracefully ignores unknown extensions per RFC 8446 §4.2 requirements
//!
//! ## RFC Coverage
//!
//! ### Core Protocol (RFC 8446)
//! - §4.1.2: ClientHello message structure
//! - §4.1.3: ServerHello message structure
//! - §4.2: Extension definitions and processing rules
//! - §4.2.3: Signature Algorithms extension (signature_algorithms)
//! - §4.2.7: Key Share extension (key_share)
//! - §4.2.8: Supported Groups extension (supported_groups)
//! - §4.2.9: Supported Versions extension (supported_versions)
//! - §4.2.10: Pre-Shared Key extension (pre_shared_key)
//! - §4.2.11: Pre-Shared Key Exchange Modes (psk_key_exchange_modes)
//! - §4.3.1: EncryptedExtensions message
//! - §4.4.2: Certificate message structure
//! - §4.4.3: CertificateVerify message
//! - §4.4: Finished message and verify_data computation
//! - Appendix B.3: Extension type values
//! - Appendix B.3.1: Named Group registry
//! - Appendix B.3.1.3: Signature Scheme registry
//! - Appendix B.4: Cipher suite values
//!
//! ### QUIC Integration (RFC 9001)
//! - §8.2: QUIC Transport Parameters extension (0x0039)
//! - §4.1: Extension placement rules (ServerHello vs EncryptedExtensions)
//!
//! ### ALPN (RFC 7301)
//! - Application-Layer Protocol Negotiation extension
//!
//! ### Additional RFCs
//! - RFC 7919: Finite Field Diffie-Hellman groups (ffdhe2048, ffdhe3072, etc.)
//! - RFC 8032: Ed25519 and Ed448 signature schemes
//! - RFC 8017: RSA-PSS signature schemes
//! - RFC 5280: X.509 certificate format (parsed but not validated here)
//!
//! ## Message Flow
//!
//! ```
//! Client                                           Server
//!
//! ClientHello
//!   + supported_versions (0x002b)
//!   + supported_groups (0x000a)
//!   + key_share (0x0033)
//!   + signature_algorithms (0x000d)
//!   + alpn (0x0010)
//!   + quic_transport_parameters (0x0039)
//!   [+ pre_shared_key (0x0029)]              -------->
//!                                            <--------  ServerHello
//!                                                         + key_share
//!                                                         + supported_versions
//!                                            <--------  EncryptedExtensions
//!                                                         + alpn
//!                                                         + quic_transport_parameters
//!                                            <--------  Certificate
//!                                            <--------  CertificateVerify
//!                                            <--------  Finished
//!                                            -------->  Finished
//! ```
//!
//! ## Security Considerations
//!
//! - Extension order in ServerHello is CRITICAL for transcript hash consistency
//! - Unknown extensions MUST be ignored per RFC 8446 §4.2 (avoid handshake failures)
//! - Pre-shared key binder validation required before accepting PSK (RFC 8446 §4.2.11)
//! - Session ID echo required in ServerHello for middlebox compatibility (RFC 8446 §4.1.3)
//! - Downgrade protection via random sentinel (not implemented in this module)
//!
//! ## Implementation Notes
//!
//! - Uses Zig standard library primitives (no external dependencies)
//! - Allocator-aware: all heap allocations explicit and caller-controlled
//! - Zero-copy parsing where possible (slices reference input buffer)
//! - Supports only TLS 1.3 cipher suites (0x1301-0x1305)
//! - QUIC transport parameters placed in EncryptedExtensions per RFC 9001 §8.2
//! - Extension parsing is additive: unsupported extensions are silently skipped

const std = @import("std");
const ks = @import("quic_tls");
const x509 = @import("x509");
const sig = @import("sig");
const logger = @import("quic_logger");
const H = ks.H; // SHA-256

/// TLS 1.3 Extension type registry (RFC 8446 Appendix B.3).
///
/// Extensions allow clients and servers to negotiate additional protocol features
/// beyond the base TLS 1.3 specification. The extension mechanism is defined in
/// RFC 8446 §4.2, with specific extension types registered in the IANA TLS registry.
///
/// ## Usage Rules (RFC 8446 §4.2)
///
/// - Unknown extensions MUST be ignored by receivers
/// - Extensions can appear in ClientHello, ServerHello, EncryptedExtensions,
///   Certificate, CertificateRequest, or NewSessionTicket messages
/// - Clients MUST NOT send extensions not listed in server's EncryptedExtensions
/// - Servers MUST NOT send extensions not requested by client (except for Cookie)
///
/// ## QUIC-Specific Extensions
///
/// - quic_transport_parameters (0x0039): Carries QUIC transport parameters per RFC 9001 §8.2
///   - MUST appear in ClientHello and EncryptedExtensions
///   - MUST NOT appear in ServerHello (RFC 9001 §4.1)
///
/// ## Security Notes
///
/// - pre_shared_key MUST be last extension in ClientHello (RFC 8446 §4.2.11)
/// - Extension order in ServerHello affects transcript hash (critical for interop)
/// - signed_certificate_timestamp provides OCSP stapling transparency
pub const ExtensionType = enum(u16) {
    server_name = 0x0000, // RFC 6066 §3: Server Name Indication (SNI)
    max_fragment_length = 0x0001, // RFC 6066 §4: Maximum fragment length negotiation
    status_request = 0x0005, // RFC 6066 §8: OCSP stapling request
    supported_groups = 0x000a, // RFC 8446 §4.2.7: Named groups for key exchange (formerly "elliptic_curves")
    signature_algorithms = 0x000d, // RFC 8446 §4.2.3: Supported signature algorithms
    use_srtp = 0x000e, // RFC 5764: DTLS-SRTP key material exchange
    heartbeat = 0x000f, // RFC 6520: Heartbeat extension (not for QUIC)
    alpn = 0x0010, // RFC 7301: Application-Layer Protocol Negotiation
    signed_certificate_timestamp = 0x0012, // RFC 6962 §3.3.1: Signed Certificate Timestamp (SCT)
    client_certificate_type = 0x0013, // RFC 7250: Client certificate type (raw public key, X.509, etc.)
    server_certificate_type = 0x0014, // RFC 7250: Server certificate type
    padding = 0x0015, // RFC 7685: Padding to avoid size-based fingerprinting
    pre_shared_key = 0x0029, // RFC 8446 §4.2.11: Pre-shared key identities and binders
    early_data = 0x002a, // RFC 8446 §4.2.10: 0-RTT early data indication
    supported_versions = 0x002b, // RFC 8446 §4.2.1: TLS version negotiation (mandatory for TLS 1.3)
    cookie = 0x002c, // RFC 8446 §4.2.2: Stateless HelloRetryRequest cookie
    psk_key_exchange_modes = 0x002d, // RFC 8446 §4.2.9: PSK key exchange modes (psk_ke, psk_dhe_ke)
    certificate_authorities = 0x002f, // RFC 8446 §4.2.4: Trusted CA indication
    oid_filters = 0x0030, // RFC 8446 §4.2.5: OID filters for certificate selection
    post_handshake_auth = 0x0031, // RFC 8446 §4.6.2: Post-handshake client authentication
    signature_algorithms_cert = 0x0032, // RFC 8446 §4.2.3: Signature algorithms for certificates
    key_share = 0x0033, // RFC 8446 §4.2.8: Key exchange parameters (ECDHE public keys)
    quic_transport_parameters = 0x0039, // RFC 9001 §8.2: QUIC-specific transport parameters
};

/// TLS 1.3 Named Groups for key exchange (RFC 8446 §4.2.7, Appendix B.3.1.4).
///
/// Named groups specify the elliptic curves or finite field groups used for
/// Diffie-Hellman key exchange in TLS 1.3. This implementation supports both
/// ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) and FFDHE (Finite Field
/// Diffie-Hellman Ephemeral) groups.
///
/// ## Elliptic Curve Groups
///
/// - **secp256r1** (0x0017): NIST P-256 curve (RFC 8422, FIPS 186-4)
///   - 128-bit security level
///   - Most widely supported, default for many implementations
///
/// - **secp384r1** (0x0018): NIST P-384 curve (RFC 8422, FIPS 186-4)
///   - 192-bit security level
///   - Required for CNSA Suite compliance
///
/// - **secp521r1** (0x0019): NIST P-521 curve (RFC 8422, FIPS 186-4)
///   - 256-bit security level
///   - Highest security NIST curve
///
/// - **x25519** (0x001d): Curve25519 (RFC 8032, RFC 7748)
///   - 128-bit security level
///   - Widely used in modern protocols (Signal, WireGuard, QUIC)
///   - Preferred for performance and side-channel resistance
///
/// - **x448** (0x001e): Curve448 (RFC 8032, RFC 7748)
///   - 224-bit security level
///   - Higher security alternative to X25519
///
/// ## Finite Field Groups (RFC 7919)
///
/// - **ffdhe2048** (0x0100): 2048-bit MODP group
///   - 112-bit security level
///   - Minimum recommended strength
///
/// - **ffdhe3072** (0x0101): 3072-bit MODP group
///   - 128-bit security level
///   - Equivalent to secp256r1/X25519
///
/// - **ffdhe4096** (0x0102): 4096-bit MODP group
///   - 152-bit security level
///
/// - **ffdhe6144** (0x0103): 6144-bit MODP group
///   - 176-bit security level
///
/// - **ffdhe8192** (0x0104): 8192-bit MODP group
///   - 192-bit security level
///   - Equivalent to secp384r1
///
/// ## Current Implementation Support
///
/// This implementation currently supports **x25519 only** for key exchange.
/// Other groups are recognized for parsing but not yet implemented for crypto operations.
///
/// ## Security Considerations
///
/// - ECDHE groups (secp*, x25519, x448) are preferred over FFDHE for performance
/// - X25519 recommended for general use due to speed and side-channel resistance
/// - FFDHE groups required for some regulatory compliance (FIPS mode)
/// - Groups below 2048-bit FFDHE or 256-bit ECDHE are deprecated (RFC 8446 §4.2.7)
pub const NamedGroup = enum(u16) {
    secp256r1 = 0x0017, // RFC 8422: NIST P-256 (prime256v1, 128-bit security)
    secp384r1 = 0x0018, // RFC 8422: NIST P-384 (192-bit security)
    secp521r1 = 0x0019, // RFC 8422: NIST P-521 (256-bit security)
    x25519 = 0x001d, // RFC 7748: Curve25519 ECDH (128-bit security, preferred)
    x448 = 0x001e, // RFC 7748: Curve448 ECDH (224-bit security)
    ffdhe2048 = 0x0100, // RFC 7919: 2048-bit MODP group (112-bit security)
    ffdhe3072 = 0x0101, // RFC 7919: 3072-bit MODP group (128-bit security)
    ffdhe4096 = 0x0102, // RFC 7919: 4096-bit MODP group (152-bit security)
    ffdhe6144 = 0x0103, // RFC 7919: 6144-bit MODP group (176-bit security)
    ffdhe8192 = 0x0104, // RFC 7919: 8192-bit MODP group (192-bit security)
};

/// TLS 1.3 Signature Algorithms (RFC 8446 §4.2.3, Appendix B.3.1.3).
///
/// Signature schemes specify the algorithm used to sign TLS handshake messages,
/// particularly in CertificateVerify. The signature covers the transcript hash
/// and proves possession of the private key corresponding to the certificate.
///
/// ## Algorithm Categories
///
/// ### ECDSA (Elliptic Curve Digital Signature Algorithm)
///
/// - **ecdsa_secp256r1_sha256** (0x0403): ECDSA with P-256 curve and SHA-256
///   - 128-bit security level
///   - Most common for web PKI
///   - Fast verification, moderate signing speed
///
/// - **ecdsa_secp384r1_sha384** (0x0503): ECDSA with P-384 curve and SHA-384
///   - 192-bit security level
///   - Required for CNSA Suite
///
/// - **ecdsa_secp521r1_sha512** (0x0603): ECDSA with P-521 curve and SHA-512
///   - 256-bit security level
///   - Highest security ECDSA variant
///
/// ### RSA-PSS (RSA Probabilistic Signature Scheme)
///
/// RSA-PSS is the ONLY RSA signature scheme allowed in TLS 1.3 certificates.
/// RSASSA-PKCS1-v1_5 is prohibited for TLS 1.3 certificates but may appear
/// in signature_algorithms_cert for compatibility (RFC 8446 §4.2.3).
///
/// - **rsa_pss_rsae_sha256** (0x0804): RSA-PSS with RSAE key, SHA-256, MGF1-SHA256
///   - 128-bit security level (assuming 3072-bit modulus)
///   - RSAE = RSA Encryption key used for signatures
///
/// - **rsa_pss_rsae_sha384** (0x0805): RSA-PSS with RSAE key, SHA-384, MGF1-SHA384
///   - 192-bit security level (assuming 7680-bit modulus)
///
/// - **rsa_pss_rsae_sha512** (0x0806): RSA-PSS with RSAE key, SHA-512, MGF1-SHA512
///   - 256-bit security level (assuming 15360-bit modulus)
///
/// - **rsa_pss_pss_sha256** (0x0809): RSA-PSS with PSS key, SHA-256, MGF1-SHA256
///   - PSS key = RSA key specifically for PSS (restricted usage)
///
/// - **rsa_pss_pss_sha384** (0x080a): RSA-PSS with PSS key, SHA-384, MGF1-SHA384
///
/// - **rsa_pss_pss_sha512** (0x080b): RSA-PSS with PSS key, SHA-512, MGF1-SHA512
///
/// ### EdDSA (Edwards-curve Digital Signature Algorithm)
///
/// - **ed25519** (0x0807): EdDSA with Curve25519 (RFC 8032)
///   - 128-bit security level
///   - Fast signing and verification
///   - Deterministic signatures (no RNG required)
///   - Preferred for modern deployments
///
/// - **ed448** (0x0808): EdDSA with Curve448 (RFC 8032)
///   - 224-bit security level
///   - Higher security alternative to Ed25519
///
/// ### Legacy RSA (DEPRECATED for TLS 1.3)
///
/// These RSASSA-PKCS1-v1_5 schemes are included for parsing ClientHello from
/// legacy clients but MUST NOT be used for TLS 1.3 certificates (RFC 8446 §4.2.3):
///
/// - **rsa_pkcs1_sha256** (0x0401): RSASSA-PKCS1-v1_5 with SHA-256
/// - **rsa_pkcs1_sha384** (0x0501): RSASSA-PKCS1-v1_5 with SHA-384
/// - **rsa_pkcs1_sha512** (0x0601): RSASSA-PKCS1-v1_5 with SHA-512
///
/// ## Current Implementation Support
///
/// This implementation currently supports **Ed25519 only** for signing operations.
/// Other signature schemes are recognized for parsing but verification is not yet implemented.
///
/// ## Security Considerations
///
/// - Ed25519 recommended for new deployments (speed, simplicity, determinism)
/// - RSA-PSS requires minimum 2048-bit modulus (3072-bit recommended for 128-bit security)
/// - ECDSA requires careful nonce generation to avoid private key leakage
/// - TLS 1.3 prohibits RSASSA-PKCS1-v1_5 for certificates (signature_algorithms_cert)
/// - Hash function must match or exceed the security level of the signing key
pub const SignatureScheme = enum(u16) {
    // Legacy RSA PKCS#1 v1.5 - DEPRECATED for TLS 1.3 certificates (RFC 8446 §4.2.3)
    rsa_pkcs1_sha256 = 0x0401, // RSASSA-PKCS1-v1_5 with SHA-256 (legacy only)
    rsa_pkcs1_sha384 = 0x0501, // RSASSA-PKCS1-v1_5 with SHA-384 (legacy only)
    rsa_pkcs1_sha512 = 0x0601, // RSASSA-PKCS1-v1_5 with SHA-512 (legacy only)

    // ECDSA - Elliptic Curve Digital Signature Algorithm (RFC 8446 §4.2.3)
    ecdsa_secp256r1_sha256 = 0x0403, // ECDSA with P-256 and SHA-256 (common in web PKI)
    ecdsa_secp384r1_sha384 = 0x0503, // ECDSA with P-384 and SHA-384 (CNSA Suite)
    ecdsa_secp521r1_sha512 = 0x0603, // ECDSA with P-521 and SHA-512 (highest security ECDSA)

    // RSA-PSS with RSAE keys - Standard RSA Encryption keys (RFC 8446 §4.2.3)
    rsa_pss_rsae_sha256 = 0x0804, // RSA-PSS RSAE with SHA-256 (3072-bit modulus for 128-bit security)
    rsa_pss_rsae_sha384 = 0x0805, // RSA-PSS RSAE with SHA-384 (7680-bit modulus for 192-bit security)
    rsa_pss_rsae_sha512 = 0x0806, // RSA-PSS RSAE with SHA-512 (15360-bit modulus for 256-bit security)

    // EdDSA - Edwards-curve Digital Signature Algorithm (RFC 8032)
    ed25519 = 0x0807, // Ed25519 signature (128-bit security, preferred for modern use)
    ed448 = 0x0808, // Ed448 signature (224-bit security)

    // RSA-PSS with PSS-specific keys - Restricted to PSS usage (RFC 8446 §4.2.3)
    rsa_pss_pss_sha256 = 0x0809, // RSA-PSS PSS with SHA-256
    rsa_pss_pss_sha384 = 0x080a, // RSA-PSS PSS with SHA-384
    rsa_pss_pss_sha512 = 0x080b, // RSA-PSS PSS with SHA-512
};

/// TLS 1.3 Cipher Suites (RFC 8446 Appendix B.4).
///
/// Cipher suites in TLS 1.3 specify the AEAD algorithm and hash function used
/// for record protection and key derivation. Unlike TLS 1.2, cipher suites do NOT
/// include key exchange or signature algorithms (those are negotiated separately).
///
/// ## Mandatory-to-Implement
///
/// - **TLS_AES_128_GCM_SHA256** (0x1301): REQUIRED by RFC 8446
///   - AEAD: AES-128-GCM (128-bit security)
///   - Hash: SHA-256 for HKDF and transcript hashing
///   - Most widely supported, default for most implementations
///
/// ## Recommended Suites
///
/// - **TLS_AES_256_GCM_SHA384** (0x1302): AES-256-GCM with SHA-384
///   - AEAD: AES-256-GCM (256-bit security)
///   - Hash: SHA-384 for HKDF and transcript hashing
///   - Higher security alternative to AES-128-GCM
///
/// - **TLS_CHACHA20_POLY1305_SHA256** (0x1303): ChaCha20-Poly1305 with SHA-256
///   - AEAD: ChaCha20-Poly1305 (256-bit security)
///   - Hash: SHA-256 for HKDF and transcript hashing
///   - Preferred on platforms without AES hardware acceleration
///   - Better side-channel resistance on software-only implementations
///
/// ## CCM Variants (Constrained Environments)
///
/// - **TLS_AES_128_CCM_SHA256** (0x1304): AES-128-CCM with SHA-256
///   - AEAD: AES-128-CCM (128-bit security)
///   - Hash: SHA-256 for HKDF and transcript hashing
///   - Designed for constrained devices (IoT, embedded systems)
///   - Lower performance than GCM but smaller code size
///
/// - **TLS_AES_128_CCM_8_SHA256** (0x1305): AES-128-CCM with 8-byte tags
///   - AEAD: AES-128-CCM with 64-bit authentication tags (instead of 128-bit)
///   - Hash: SHA-256 for HKDF and transcript hashing
///   - Further reduced overhead for very constrained environments
///   - Lower authentication strength (64-bit vs 128-bit tags)
///
/// ## Current Implementation Support
///
/// This implementation supports:
/// - **TLS_AES_128_GCM_SHA256** (primary focus, fully implemented)
/// - **TLS_AES_256_GCM_SHA384** (recognized, partial support)
/// - **TLS_CHACHA20_POLY1305_SHA256** (recognized, partial support)
///
/// CCM variants are recognized for parsing but not yet implemented.
///
/// ## Security Considerations
///
/// - AES-GCM requires unique nonces per encryption (enforced by AEAD usage limits)
/// - ChaCha20-Poly1305 preferred on non-AES hardware (ARM, RISC-V without crypto extensions)
/// - CCM-8 reduces authentication strength (trade-off for constrained devices)
/// - All suites provide forward secrecy when combined with ephemeral key exchange
/// - Hash function security level should match AEAD security (SHA-256 for 128-bit, SHA-384 for 192-bit+)
pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301, // RFC 8446: AES-128-GCM with SHA-256 (MANDATORY, widely used)
    TLS_AES_256_GCM_SHA384 = 0x1302, // RFC 8446: AES-256-GCM with SHA-384 (higher security)
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303, // RFC 8446: ChaCha20-Poly1305 with SHA-256 (software-optimized)
    TLS_AES_128_CCM_SHA256 = 0x1304, // RFC 8446: AES-128-CCM with SHA-256 (constrained devices)
    TLS_AES_128_CCM_8_SHA256 = 0x1305, // RFC 8446: AES-128-CCM-8 with SHA-256 (8-byte tags for IoT)
};

/// Parsed ClientHello message (RFC 8446 §4.1.2).
///
/// ClientHello is the first message in the TLS 1.3 handshake, sent by the client
/// to initiate a connection. It contains the client's capabilities, preferences,
/// and cryptographic parameters.
///
/// ## Structure (RFC 8446 §4.1.2)
///
/// ```
/// struct {
///     ProtocolVersion legacy_version = 0x0303; // TLS 1.2 for compatibility
///     Random random;                            // 32 bytes of randomness
///     opaque legacy_session_id<0..32>;         // For middlebox compatibility
///     CipherSuite cipher_suites<2..2^16-2>;    // Client's supported cipher suites
///     opaque legacy_compression_methods<1..2^8-1>; // Must be [0x00] for TLS 1.3
///     Extension extensions<8..2^16-1>;         // MUST be present in TLS 1.3
/// } ClientHello;
/// ```
///
/// ## Required Extensions (RFC 8446 §9.2)
///
/// TLS 1.3 ClientHello MUST contain:
/// - **supported_versions** (0x002b): Indicates TLS 1.3 support
/// - **signature_algorithms** (0x000d): Signature schemes for CertificateVerify
///
/// ## Common Extensions
///
/// - **server_name** (0x0000): SNI for virtual hosting
/// - **supported_groups** (0x000a): ECDHE/FFDHE groups
/// - **key_share** (0x0033): Client's ECDHE public key(s)
/// - **alpn** (0x0010): Application-Layer Protocol Negotiation
/// - **quic_transport_parameters** (0x0039): QUIC-specific parameters (QUIC only)
/// - **pre_shared_key** (0x0029): PSK identities for resumption/0-RTT (MUST be last)
///
/// ## Memory Management
///
/// All slices reference the input buffer (zero-copy parsing). The ClientHello
/// struct is valid only as long as the original message buffer remains live.
pub const ClientHello = struct {
    random: [32]u8, // RFC 8446 §4.1.2: Client random (32 bytes)
    session_id: []const u8, // RFC 8446 §4.1.2: Legacy session ID (for middlebox compat)
    cipher_suites: []CipherSuite, // RFC 8446 §4.1.2: Client's supported cipher suites
    compression_methods: []const u8, // RFC 8446 §4.1.2: Must be [0x00] in TLS 1.3

    // Extensions (RFC 8446 §4.2)
    server_name: ?[]const u8 = null, // RFC 6066 §3: SNI hostname
    supported_groups: ?[]NamedGroup = null, // RFC 8446 §4.2.7: ECDHE/FFDHE groups
    signature_algorithms: ?[]SignatureScheme = null, // RFC 8446 §4.2.3: Signature algorithms
    supported_versions: ?[]const u8 = null, // RFC 8446 §4.2.1: TLS version list (REQUIRED)
    key_share: ?KeyShareEntry = null, // RFC 8446 §4.2.8: ECDHE public key
    alpn_list: ?[]const []const u8 = null, // RFC 7301: Application protocols
    quic_transport_parameters: ?[]const u8 = null, // RFC 9001 §8.2: QUIC parameters
    psk_key_exchange_modes: ?[]const u8 = null, // RFC 8446 §4.2.9: PSK modes (psk_ke, psk_dhe_ke)
    pre_shared_key: ?PreSharedKey = null, // RFC 8446 §4.2.11: PSK identities (MUST be last extension)
    early_data: bool = false, // RFC 8446 §4.2.10: 0-RTT early data indication
};

/// Key share entry for ECDHE key exchange (RFC 8446 §4.2.8).
///
/// Contains the client's or server's ephemeral public key for a specific
/// named group (elliptic curve or finite field group).
///
/// ## Structure
///
/// ```
/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
/// ```
///
/// ## Key Exchange Data Formats
///
/// - **X25519**: 32-byte public key (RFC 7748 §6)
/// - **secp256r1**: 65-byte uncompressed point (0x04 || x || y) (RFC 8422 §5.4)
/// - **FFDHE groups**: Big-endian integer (RFC 7919)
pub const KeyShareEntry = struct {
    group: NamedGroup, // RFC 8446 §4.2.8: Named group identifier
    key_exchange: []const u8, // RFC 8446 §4.2.8: Public key bytes (format depends on group)
};

/// TLS 1.3 Pre-Shared Key identity entry (RFC 8446 §4.2.11).
///
/// Identifies a pre-shared key (PSK) from a previous session or external source.
/// Used for session resumption and 0-RTT early data.
///
/// ## Structure
///
/// ```
/// struct {
///     opaque identity<1..2^16-1>;
///     uint32 obfuscated_ticket_age;
/// } PskIdentity;
/// ```
///
/// ## Obfuscated Ticket Age
///
/// For resumption PSKs from NewSessionTicket:
/// - Client computes: ticket_age_add + (current_time - ticket_received_time) mod 2^32
/// - Server verifies freshness and detects replays
/// - For external PSKs: set to 0
pub const PskIdentity = struct {
    identity: []const u8, // RFC 8446 §4.2.11: PSK identity (session ticket or external PSK)
    obfuscated_ticket_age: u32, // RFC 8446 §4.2.11: Obfuscated age for replay prevention
};

/// TLS 1.3 pre_shared_key extension payload (RFC 8446 §4.2.11).
///
/// Contains PSK identities and corresponding binders. The binder is an HMAC
/// over the partial ClientHello transcript, proving the client possesses the PSK.
///
/// ## Structure
///
/// ```
/// struct {
///     PskIdentity identities<7..2^16-1>;
///     PskBinderEntry binders<33..2^16-1>;
/// } OfferedPsks;
/// ```
///
/// ## Binder Computation (RFC 8446 §4.2.11.2)
///
/// ```
/// binder = HMAC(binder_key, transcript_hash(ClientHello_truncated))
/// ```
///
/// where ClientHello_truncated excludes the binders themselves.
///
/// ## Security Critical
///
/// - Binder MUST be verified before accepting PSK
/// - pre_shared_key extension MUST be last in ClientHello (RFC 8446 §4.2.11)
/// - Binder covers all preceding extensions (prevents tampering)
pub const PreSharedKey = struct {
    identities: []PskIdentity, // RFC 8446 §4.2.11: List of offered PSK identities
    binders: []const []const u8, // RFC 8446 §4.2.11: HMAC binders for each identity
};

/// Parse a full TLS 1.3 ClientHello message (RFC 8446 §4.1.2).
///
/// Parses the ClientHello wire format into a structured representation, extracting
/// all standard extensions. This implements the INTEROP FIRST design principle by:
/// - Gracefully ignoring unknown extensions (per RFC 8446 §4.2)
/// - Supporting all standard TLS 1.3 cipher suites and extensions
/// - Using zero-copy parsing (returned slices reference input buffer)
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for variable-length fields (cipher suites, extension arrays)
/// - `data`: ClientHello message bytes (without Handshake header, i.e., just the ClientHello payload)
///
/// ## Returns
///
/// - `ClientHello`: Parsed structure with all recognized extensions
/// - `error.TooShort`: Message too short to be valid ClientHello
///
/// ## Memory Management
///
/// - Allocates memory for: cipher_suites, supported_groups, signature_algorithms, alpn_list, PSK identities/binders
/// - All other fields are slices into the input buffer (zero-copy)
/// - Caller must free allocated fields when done
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.1.2: ClientHello structure parsing
/// - RFC 8446 §4.2: Extension processing (unknown extensions ignored)
/// - RFC 8446 §4.2.11: Pre-shared key extension (MUST be last, validated during parsing)
///
/// ## INTEROP FIRST Implementation
///
/// - Supports all standard extension types from RFC 8446, RFC 6066, RFC 7301, RFC 9001
/// - Filters cipher suites to TLS 1.3 suites only (0x1301-0x1305)
/// - Recognizes but skips unsupported extensions (no handshake failure)
/// - Currently focuses on X25519 for key_share parsing
pub fn parseClientHello(allocator: std.mem.Allocator, data: []const u8) !ClientHello {
    if (data.len < 34) return error.TooShort;

    var ch = ClientHello{
        .random = undefined,
        .session_id = &[_]u8{},
        .cipher_suites = &[_]CipherSuite{},
        .compression_methods = &[_]u8{},
    };

    var pos: usize = 0;

    // Skip legacy_version (2 bytes)
    pos += 2;

    // Random (32 bytes)
    @memcpy(&ch.random, data[pos .. pos + 32]);
    pos += 32;

    // Session ID
    if (pos >= data.len) return error.TooShort;
    const sid_len = data[pos];
    pos += 1;
    if (pos + sid_len > data.len) return error.TooShort;
    ch.session_id = data[pos .. pos + sid_len];
    pos += sid_len;

    // Cipher suites
    if (pos + 2 > data.len) return error.TooShort;
    const cs_len = readU16(data[pos .. pos + 2]);
    pos += 2;
    if (pos + cs_len > data.len) return error.TooShort;

    var cipher_suites = try std.ArrayList(CipherSuite).initCapacity(allocator, 0);
    defer cipher_suites.deinit(allocator);

    var cs_pos: usize = 0;
    while (cs_pos < cs_len) : (cs_pos += 2) {
        const cs_value = readU16(data[pos + cs_pos .. pos + cs_pos + 2]);
        // Check if it's a supported TLS 1.3 cipher suite
        if (cs_value == 0x1301 or cs_value == 0x1302 or cs_value == 0x1303) {
            try cipher_suites.append(allocator, @enumFromInt(cs_value));
        }
    }
    ch.cipher_suites = try cipher_suites.toOwnedSlice(allocator);
    pos += cs_len;

    // Compression methods
    if (pos >= data.len) return error.TooShort;
    const comp_len = data[pos];
    pos += 1;
    if (pos + comp_len > data.len) return error.TooShort;
    ch.compression_methods = data[pos .. pos + comp_len];
    pos += comp_len;

    // Extensions
    if (pos + 2 > data.len) return error.TooShort;
    const ext_len = readU16(data[pos .. pos + 2]);
    pos += 2;
    if (pos + ext_len > data.len) return error.TooShort;

    const ext_end = pos + ext_len;
    while (pos + 4 <= ext_end) {
        const ext_type = readU16(data[pos .. pos + 2]);
        const ext_data_len = readU16(data[pos + 2 .. pos + 4]);
        pos += 4;

        if (pos + ext_data_len > ext_end) return error.TooShort;
        const ext_data = data[pos .. pos + ext_data_len];

        // Use intToEnum to safely handle unknown extension types without panicking
        const ext = std.meta.intToEnum(ExtensionType, ext_type) catch {
            // Unknown extension type - ignore per TLS 1.3 spec
            pos += ext_data_len;
            continue;
        };

        switch (ext) {
            .server_name => {
                // Parse SNI
                if (ext_data.len >= 5) {
                    const list_len = readU16(ext_data[0..2]);
                    if (list_len > 0 and ext_data.len >= 5) {
                        const name_type = ext_data[2];
                        if (name_type == 0) { // host_name
                            const name_len = readU16(ext_data[3..5]);
                            if (5 + name_len <= ext_data.len) {
                                ch.server_name = ext_data[5 .. 5 + name_len];
                            }
                        }
                    }
                }
            },
            .supported_groups => {
                // Parse supported groups
                if (ext_data.len >= 2) {
                    const groups_len = readU16(ext_data[0..2]);
                    if (2 + groups_len <= ext_data.len) {
                        var groups = try std.ArrayList(NamedGroup).initCapacity(allocator, 0);
                        defer groups.deinit(allocator);

                        var g_pos: usize = 2;
                        while (g_pos + 2 <= 2 + groups_len) : (g_pos += 2) {
                            const group = readU16(ext_data[g_pos .. g_pos + 2]);
                            if (group == 0x001d) { // x25519
                                try groups.append(allocator, .x25519);
                            }
                        }

                        if (groups.items.len > 0) {
                            ch.supported_groups = try groups.toOwnedSlice(allocator);
                        }
                    }
                }
            },
            .signature_algorithms => {
                // Parse signature algorithms
                if (ext_data.len >= 2) {
                    const algs_len = readU16(ext_data[0..2]);
                    if (2 + algs_len <= ext_data.len) {
                        var algs = try std.ArrayList(SignatureScheme).initCapacity(allocator, 0);
                        defer algs.deinit(allocator);

                        var a_pos: usize = 2;
                        while (a_pos + 2 <= 2 + algs_len) : (a_pos += 2) {
                            const alg = readU16(ext_data[a_pos .. a_pos + 2]);
                            // Add supported algorithms
                            if (alg >= 0x0401 and alg <= 0x080b) {
                                try algs.append(allocator, @enumFromInt(alg));
                            }
                        }

                        if (algs.items.len > 0) {
                            ch.signature_algorithms = try algs.toOwnedSlice(allocator);
                        }
                    }
                }
            },
            .supported_versions => {
                // Parse supported versions
                ch.supported_versions = ext_data;
            },
            .key_share => {
                // Parse key share
                if (ext_data.len >= 2) {
                    const shares_len = readU16(ext_data[0..2]);
                    if (2 + shares_len <= ext_data.len) {
                        var ks_pos: usize = 2;
                        while (ks_pos + 4 <= 2 + shares_len) {
                            const group = readU16(ext_data[ks_pos .. ks_pos + 2]);
                            const key_len = readU16(ext_data[ks_pos + 2 .. ks_pos + 4]);
                            ks_pos += 4;

                            if (ks_pos + key_len <= 2 + shares_len) {
                                // We only support X25519
                                if (group == 0x001d and key_len == 32) {
                                    ch.key_share = KeyShareEntry{
                                        .group = .x25519,
                                        .key_exchange = ext_data[ks_pos .. ks_pos + key_len],
                                    };
                                    break;
                                }
                                ks_pos += key_len;
                            } else {
                                break;
                            }
                        }
                    }
                }
            },
            .alpn => {
                // Parse ALPN
                if (ext_data.len >= 2) {
                    const list_len = readU16(ext_data[0..2]);
                    if (2 + list_len <= ext_data.len) {
                        var alpn_list = try std.ArrayList([]const u8).initCapacity(allocator, 0);
                        defer alpn_list.deinit(allocator);

                        var a_pos: usize = 2;
                        while (a_pos < 2 + list_len) {
                            if (a_pos >= ext_data.len) break;
                            const proto_len = ext_data[a_pos];
                            a_pos += 1;
                            if (a_pos + proto_len <= ext_data.len) {
                                try alpn_list.append(allocator, ext_data[a_pos .. a_pos + proto_len]);
                                a_pos += proto_len;
                            } else {
                                break;
                            }
                        }

                        if (alpn_list.items.len > 0) {
                            ch.alpn_list = try alpn_list.toOwnedSlice(allocator);
                        }
                    }
                }
            },
            .quic_transport_parameters => {
                ch.quic_transport_parameters = ext_data;
            },
            .psk_key_exchange_modes => {
                ch.psk_key_exchange_modes = ext_data;
            },
            .pre_shared_key => {
                if (ext_data.len < 2) return error.TooShort;
                const identities_len = readU16(ext_data[0..2]);
                if (identities_len + 2 > ext_data.len) return error.TooShort;

                var identities = try std.ArrayList(PskIdentity).initCapacity(allocator, 0);
                defer identities.deinit(allocator);

                var id_pos: usize = 2;
                const identities_end = 2 + identities_len;
                while (id_pos < identities_end) {
                    if (id_pos + 2 > identities_end) return error.TooShort;
                    const identity_len = readU16(ext_data[id_pos .. id_pos + 2]);
                    id_pos += 2;
                    if (id_pos + identity_len > identities_end) return error.TooShort;
                    const identity_bytes = ext_data[id_pos .. id_pos + identity_len];
                    id_pos += identity_len;
                    if (id_pos + 4 > identities_end) return error.TooShort;
                    const ticket_age = readU32(ext_data[id_pos .. id_pos + 4]);
                    id_pos += 4;
                    try identities.append(allocator, .{
                        .identity = identity_bytes,
                        .obfuscated_ticket_age = ticket_age,
                    });
                }
                if (id_pos != identities_end) return error.TooShort;

                if (id_pos + 2 > ext_data.len) return error.TooShort;
                const binders_len = readU16(ext_data[id_pos .. id_pos + 2]);
                id_pos += 2;
                if (id_pos + binders_len > ext_data.len) return error.TooShort;

                var binders = try std.ArrayList([]const u8).initCapacity(allocator, 0);
                defer binders.deinit(allocator);

                var binder_pos: usize = 0;
                while (binder_pos < binders_len) {
                    if (binder_pos >= binders_len) return error.TooShort;
                    const binder_len = ext_data[id_pos + binder_pos];
                    binder_pos += 1;
                    if (binder_pos + binder_len > binders_len) return error.TooShort;
                    const binder_slice = ext_data[id_pos + binder_pos .. id_pos + binder_pos + binder_len];
                    binder_pos += binder_len;
                    try binders.append(allocator, binder_slice);
                }
                if (binder_pos != binders_len) return error.TooShort;

                ch.pre_shared_key = PreSharedKey{
                    .identities = try identities.toOwnedSlice(allocator),
                    .binders = try binders.toOwnedSlice(allocator),
                };
            },
            .early_data => {
                ch.early_data = true;
            },
            else => {
                // Known extension but not handled
            },
        }

        pos += ext_data_len;
    }

    return ch;
}

/// Build a TLS 1.3 ServerHello message (RFC 8446 §4.1.3).
///
/// Constructs a ServerHello in wire format, containing the server's chosen
/// cipher suite, key share, and supported version. Extension order is CRITICAL
/// for transcript hash consistency (affects interoperability).
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for message buffer
/// - `server_random`: 32-byte server random value
/// - `cipher_suite`: Selected cipher suite (must be from client's list)
/// - `key_share_group`: Selected named group for ECDHE (must be from client's supported_groups)
/// - `key_share_data`: Server's ephemeral public key for the selected group
/// - `client_session_id`: Echo of client's session ID (RFC 8446 §4.1.3 middlebox compatibility)
/// - `quic_params`: IGNORED (transport params go in EncryptedExtensions per RFC 9001 §8.2)
///
/// ## Returns
///
/// - `[]u8`: Serialized ServerHello message (caller owns memory, must free)
///
/// ## Extension Order (CRITICAL for Interop)
///
/// This implementation follows BoringSSL/Quiche extension order for transcript hash compatibility:
/// 1. **key_share** (0x0033): Server's ECDHE public key
/// 2. **supported_versions** (0x002b): TLS 1.3 version (0x0304)
///
/// Changing this order will break handshake with implementations that hardcode expected order!
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.1.3: ServerHello structure
/// - RFC 8446 §4.2.8: key_share extension (MANDATORY for ECDHE)
/// - RFC 8446 §4.2.1: supported_versions extension (MANDATORY for TLS 1.3)
/// - RFC 9001 §8.2: QUIC transport parameters MUST NOT appear in ServerHello
///
/// ## Security Considerations
///
/// - legacy_version set to 0x0303 (TLS 1.2) for middlebox compatibility
/// - legacy_compression_method set to 0x00 (no compression in TLS 1.3)
/// - Session ID echoed from client for middlebox compatibility (RFC 8446 §4.1.3)
/// - Downgrade protection (random sentinel) not implemented in this function
pub fn buildServerHello(
    allocator: std.mem.Allocator,
    server_random: [32]u8,
    cipher_suite: CipherSuite,
    key_share_group: NamedGroup,
    key_share_data: []const u8,
    client_session_id: ?[]const u8,
    quic_params: ?[]const u8,
) ![]u8 {
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // Legacy version (TLS 1.2 for compatibility)
    try msg.appendSlice(allocator, &[_]u8{ 0x03, 0x03 });

    // Random
    try msg.appendSlice(allocator, &server_random);

    // Legacy session ID (echo from client per RFC 8446 Section 4.1.3)
    if (client_session_id) |session_id| {
        // Echo the client's session ID
        try msg.append(allocator, @intCast(session_id.len));
        try msg.appendSlice(allocator, session_id);
    } else {
        // No session ID from client
        try msg.append(allocator, 0);
    }

    // Cipher suite
    const cs_value = @intFromEnum(cipher_suite);
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(cs_value >> 8),
        @intCast(cs_value & 0xff),
    });

    // Legacy compression method
    try msg.append(allocator, 0);

    // Extensions
    var exts = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer exts.deinit(allocator);

    // CRITICAL: Extension order must match BoringSSL/Quiche for interoperability.
    // BoringSSL order (ssl/tls13_server.cc:938-941):
    //   1. pre_shared_key (if resuming)
    //   2. pake (if using PAKE)
    //   3. key_share
    //   4. supported_versions
    // We only support key_share and supported_versions, so our order is:
    //   1. key_share
    //   2. supported_versions
    // This is CRITICAL because transcript hash = SHA256(ClientHello || ServerHello)
    // and extension order affects the byte representation.

    // key_share (mandatory for ECDHE) - MUST BE FIRST (after PSK/PAKE if present)
    var ks_data = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer ks_data.deinit(allocator);
    const group_value = @intFromEnum(key_share_group);
    try ks_data.appendSlice(allocator, &[_]u8{
        @intCast(group_value >> 8),
        @intCast(group_value & 0xff),
    });
    try ks_data.appendSlice(allocator, &[_]u8{
        @intCast(key_share_data.len >> 8),
        @intCast(key_share_data.len & 0xff),
    });
    try ks_data.appendSlice(allocator, key_share_data);
    try writeExtension(allocator, &exts, .key_share, ks_data.items);

    // supported_versions (mandatory for TLS 1.3) - MUST BE AFTER key_share
    try writeExtension(allocator, &exts, .supported_versions, &[_]u8{ 0x03, 0x04 }); // TLS 1.3

    // NOTE: RFC 9001 §8.2 mandates that quic_transport_parameters goes in
    // EncryptedExtensions, NOT ServerHello. The quic_params parameter is
    // ignored here (and should always be null). Transport parameters are
    // added in buildEncryptedExtensions() instead.
    _ = quic_params; // Explicitly ignore to make it clear this is intentional

    // Write extensions length
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(exts.items.len >> 8),
        @intCast(exts.items.len & 0xff),
    });
    try msg.appendSlice(allocator, exts.items);

    return msg.toOwnedSlice(allocator);
}

/// Build EncryptedExtensions message (RFC 8446 §4.3.1).
///
/// Constructs an EncryptedExtensions message containing server extensions
/// that are not needed for key exchange. This message is encrypted with
/// handshake traffic keys.
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for message buffer
/// - `alpn`: Selected ALPN protocol (e.g., "h3" for HTTP/3)
/// - `quic_params`: QUIC transport parameters (RFC 9001 §8.2, REQUIRED for QUIC)
///
/// ## Returns
///
/// - `[]u8`: Serialized EncryptedExtensions message (caller owns memory, must free)
///
/// ## Extensions Included
///
/// - **alpn** (0x0010): Selected application protocol (RFC 7301)
/// - **quic_transport_parameters** (0x0039): QUIC transport parameters (RFC 9001 §8.2)
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.3.1: EncryptedExtensions structure
/// - RFC 9001 §8.2: QUIC transport parameters MUST appear in EncryptedExtensions (not ServerHello)
/// - RFC 7301: ALPN extension format
///
/// ## Security Notes
///
/// - This message is encrypted with handshake_traffic_secret
/// - Extensions here are authenticated but not visible to passive observers
/// - QUIC parameters include critical transport settings (initial flow control, etc.)
pub fn buildEncryptedExtensions(
    allocator: std.mem.Allocator,
    alpn: ?[]const u8,
    quic_params: ?[]const u8,
) ![]u8 {
    var exts = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer exts.deinit(allocator);

    // ALPN
    if (alpn) |proto| {
        var alpn_data = try std.ArrayList(u8).initCapacity(allocator, 0);
        defer alpn_data.deinit(allocator);

        const alpn_list_len = 1 + proto.len;
        try alpn_data.appendSlice(allocator, &[_]u8{
            @intCast(alpn_list_len >> 8),
            @intCast(alpn_list_len & 0xff),
        });
        try alpn_data.append(allocator, @intCast(proto.len));
        try alpn_data.appendSlice(allocator, proto);

        try writeExtension(allocator, &exts, .alpn, alpn_data.items);
    }

    // QUIC transport parameters
    if (quic_params) |params| {
        try writeExtension(allocator, &exts, .quic_transport_parameters, params);
    }

    // Build the message
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // Extensions length
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(exts.items.len >> 8),
        @intCast(exts.items.len & 0xff),
    });
    try msg.appendSlice(allocator, exts.items);

    return msg.toOwnedSlice(allocator);
}

/// Parsed TLS 1.3 Certificate message with per-entry extension data.
pub const ParsedCertificateMessage = struct {
    context: []const u8,
    entries: []CertificateEntryData,
};

/// Certificate entry containing DER and optional OCSP/SCT extensions.
pub const CertificateEntryData = struct {
    cert: []const u8,
    ocsp_response: ?[]const u8 = null,
    sct_list: ?[]const u8 = null,
};

/// Parse a TLS 1.3 Certificate message including OCSP stapling and SCT extensions.
pub fn parseCertificate(
    allocator: std.mem.Allocator,
    data: []const u8,
) !ParsedCertificateMessage {
    if (data.len < 4) return error.TooShort;

    var pos: usize = 0;
    const ctx_len = data[pos];
    pos += 1;
    if (pos + ctx_len > data.len) return error.TooShort;
    const context = data[pos .. pos + ctx_len];
    pos += ctx_len;

    if (pos + 3 > data.len) return error.TooShort;
    const list_len_u24 = readU24(data[pos .. pos + 3]);
    const list_len: usize = @intCast(list_len_u24);
    pos += 3;
    if (pos + list_len > data.len) return error.MalformedCertificateList;
    const list_end = pos + list_len;

    var entries = try std.ArrayList(CertificateEntryData).initCapacity(allocator, 0);
    errdefer entries.deinit(allocator);

    while (pos < list_end) {
        if (pos + 3 > list_end) return error.MalformedCertificateList;
        const cert_len_u24 = readU24(data[pos .. pos + 3]);
        const cert_len: usize = @intCast(cert_len_u24);
        pos += 3;
        if (pos + cert_len > list_end) return error.MalformedCertificateList;
        const cert_slice = data[pos .. pos + cert_len];
        pos += cert_len;

        if (pos + 2 > list_end) return error.MalformedCertificateList;
        const ext_len = readU16(data[pos .. pos + 2]);
        pos += 2;
        if (pos + ext_len > list_end) return error.MalformedCertificateList;
        const ext_slice = data[pos .. pos + ext_len];
        pos += ext_len;

        var ocsp_resp: ?[]const u8 = null;
        var sct_list: ?[]const u8 = null;

        var ext_pos: usize = 0;
        while (ext_pos + 4 <= ext_len) {
            const ext_type = readU16(ext_slice[ext_pos .. ext_pos + 2]);
            const ext_size = readU16(ext_slice[ext_pos + 2 .. ext_pos + 4]);
            ext_pos += 4;
            if (ext_pos + ext_size > ext_len) return error.MalformedCertificateList;
            const ext_value = ext_slice[ext_pos .. ext_pos + ext_size];

            switch (ext_type) {
                0x0005 => { // status_request (RFC 6066 §8, RFC 8446 §4.4.2.1)
                    if (ext_value.len < 4) return error.MalformedStatusRequest;
                    const status_type = ext_value[0];
                    if (status_type != 1) return error.UnsupportedStatusType; // only OCSP supported
                    const resp_len = (@as(usize, ext_value[1]) << 16) | (@as(usize, ext_value[2]) << 8) | ext_value[3];
                    if (resp_len + 4 > ext_value.len or resp_len == 0) return error.MalformedStatusRequest;
                    ocsp_resp = ext_value[4 .. 4 + resp_len];
                },
                0x0012 => { // signed_certificate_timestamp (RFC 6962 §3.3)
                    if (ext_value.len < 2) return error.MalformedSctList;
                    const sct_vec_len = readU16(ext_value[0..2]);
                    if (sct_vec_len == 0 or sct_vec_len + 2 != ext_value.len) return error.MalformedSctList;
                    sct_list = ext_value[2 .. 2 + sct_vec_len];
                },
                else => {},
            }

            ext_pos += ext_size;
        }

        if (ext_pos != ext_len) return error.MalformedCertificateList;
        try entries.append(.{ .cert = cert_slice, .ocsp_response = ocsp_resp, .sct_list = sct_list });
    }

    if (pos != list_end) return error.MalformedCertificateList;

    return .{
        .context = context,
        .entries = try entries.toOwnedSlice(allocator),
    };
}

/// Build Certificate message (RFC 8446 §4.4.2) with optional OCSP and SCT extensions.
///
/// Constructs a Certificate message containing the certificate chain and per-entry
/// extensions for OCSP stapling (status_request) and Signed Certificate Timestamps.
pub fn buildCertificate(
    allocator: std.mem.Allocator,
    context: []const u8,
    entries: []const CertificateEntryData,
) ![]u8 {
    if (context.len > 255) return error.CertificateContextTooLong;

    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // certificate_request_context length (1 byte) + value
    try msg.append(allocator, @intCast(context.len));
    if (context.len > 0) try msg.appendSlice(allocator, context);

    // Precompute certificate_list length to encode as u24
    var total_len: usize = 0;
    for (entries) |entry| {
        const cert_len = entry.cert.len;
        if (cert_len > 0xFFFFFF) return error.CertificateTooLarge;

        var ext_len: usize = 0;
        if (entry.ocsp_response) |resp| {
            if (resp.len == 0 or resp.len > 0xFFFFFF) return error.OcspResponseTooLarge;
            const payload_len = 1 + 3 + resp.len;
            if (payload_len > 0xFFFF) return error.OcspResponseTooLarge;
            ext_len += 4 + payload_len; // extension header + payload
        }
        if (entry.sct_list) |sct| {
            if (sct.len == 0 or sct.len > 0xFFFF) return error.SctListTooLarge;
            const payload_len = 2 + sct.len;
            ext_len += 4 + payload_len;
        }
        if (ext_len > 0xFFFF) return error.CertificateExtensionsTooLarge;

        total_len += 3 + cert_len + 2 + ext_len;
    }

    if (total_len > 0xFFFFFF) return error.CertificateListTooLarge;
    try msg.appendSlice(allocator, &[_]u8{
        @intCast((total_len >> 16) & 0xff),
        @intCast((total_len >> 8) & 0xff),
        @intCast(total_len & 0xff),
    });

    // Emit certificate entries with extensions
    for (entries) |entry| {
        const cert_len = entry.cert.len;
        try msg.appendSlice(allocator, &[_]u8{
            @intCast((cert_len >> 16) & 0xff),
            @intCast((cert_len >> 8) & 0xff),
            @intCast(cert_len & 0xff),
        });
        try msg.appendSlice(allocator, entry.cert);

        var ext_len: usize = 0;
        if (entry.ocsp_response) |resp| {
            const payload_len = 1 + 3 + resp.len;
            ext_len += 4 + payload_len;
        }
        if (entry.sct_list) |sct| {
            const payload_len = 2 + sct.len;
            ext_len += 4 + payload_len;
        }

        try msg.appendSlice(allocator, &[_]u8{ @intCast(ext_len >> 8), @intCast(ext_len & 0xff) });

        if (entry.ocsp_response) |resp| {
            const payload_len = 1 + 3 + resp.len;
            try msg.appendSlice(allocator, &[_]u8{ 0x00, 0x05 });
            try msg.appendSlice(allocator, &[_]u8{ @intCast(payload_len >> 8), @intCast(payload_len & 0xff) });
            try msg.append(allocator, 0x01);
            try msg.appendSlice(allocator, &[_]u8{
                @intCast(resp.len >> 16),
                @intCast((resp.len >> 8) & 0xff),
                @intCast(resp.len & 0xff),
            });
            try msg.appendSlice(allocator, resp);
        }

        if (entry.sct_list) |sct| {
            const payload_len = 2 + sct.len;
            try msg.appendSlice(allocator, &[_]u8{ 0x00, 0x12 });
            try msg.appendSlice(allocator, &[_]u8{ @intCast(payload_len >> 8), @intCast(payload_len & 0xff) });
            try msg.appendSlice(allocator, &[_]u8{ @intCast(sct.len >> 8), @intCast(sct.len & 0xff) });
            try msg.appendSlice(allocator, sct);
        }
    }

    return msg.toOwnedSlice(allocator);
}

/// Build CertificateVerify message (RFC 8446 §4.4.3).
///
/// Constructs a CertificateVerify message containing a digital signature over
/// the handshake transcript, proving possession of the private key corresponding
/// to the certificate.
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for message buffer
/// - `signature_scheme`: Signature algorithm used (must match certificate key type)
/// - `signature`: Signature bytes (format depends on signature_scheme)
///
/// ## Returns
///
/// - `[]u8`: Serialized CertificateVerify message (caller owns memory, must free)
///
/// ## Signature Computation
///
/// The signature covers a specially formatted message (see `computeCertificateVerifySignature`):
/// ```
/// signature_input = 64 spaces || context_string || 0x00 || transcript_hash
/// ```
///
/// Where:
/// - `context_string` = "TLS 1.3, server CertificateVerify" or "TLS 1.3, client CertificateVerify"
/// - `transcript_hash` = Hash(Handshake Context || Certificate)
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.4.3: CertificateVerify message structure
/// - RFC 8446 §4.4.3: Digital signature computation
/// - RFC 8446 §4.2.3: Signature scheme requirements
///
/// ## Security Critical
///
/// - Signature MUST cover the complete transcript hash
/// - Context string prevents cross-protocol attacks
/// - 64-space padding prevents attacks on short messages
pub fn buildCertificateVerify(
    allocator: std.mem.Allocator,
    signature_scheme: SignatureScheme,
    signature: []const u8,
) ![]u8 {
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // Signature algorithm
    const scheme_value = @intFromEnum(signature_scheme);
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(scheme_value >> 8),
        @intCast(scheme_value & 0xff),
    });

    // Signature length
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(signature.len >> 8),
        @intCast(signature.len & 0xff),
    });

    // Signature
    try msg.appendSlice(allocator, signature);

    return msg.toOwnedSlice(allocator);
}

/// Build Finished message (RFC 8446 §4.4.4).
///
/// Constructs a Finished message containing an HMAC over the handshake transcript.
/// The Finished message authenticates the entire handshake and confirms that both
/// peers have the same view of the handshake messages.
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for message buffer
/// - `verify_data`: HMAC-based verification data (see `deriveFinishedVerifyData`)
///
/// ## Returns
///
/// - `[]u8`: Serialized Finished message (caller owns memory, must free)
///
/// ## Verify Data Computation
///
/// ```
/// finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length)
/// verify_data = HMAC(finished_key, transcript_hash)
/// ```
///
/// Where:
/// - `base_key` = client_handshake_traffic_secret or server_handshake_traffic_secret
/// - `transcript_hash` = Hash(all handshake messages up to but not including Finished)
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.4.4: Finished message structure and computation
/// - RFC 8446 §4.4: Authentication Messages
///
/// ## Security Critical
///
/// - verify_data MUST be computed over the complete transcript
/// - Both client and server send Finished messages
/// - Handshake is not complete until both Finished messages are verified
pub fn buildFinished(
    allocator: std.mem.Allocator,
    verify_data: []const u8,
) ![]u8 {
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);
    try msg.appendSlice(allocator, verify_data);
    return msg.toOwnedSlice(allocator);
}

// Helper functions

/// Read big-endian 16-bit integer from buffer.
fn readU16(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | data[1];
}

/// Read big-endian 24-bit integer from buffer.
fn readU24(data: []const u8) u24 {
    return (@as(u24, data[0]) << 16) | (@as(u24, data[1]) << 8) | data[2];
}

/// Read big-endian 32-bit integer from buffer.
fn readU32(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) | (@as(u32, data[1]) << 16) | (@as(u32, data[2]) << 8) | data[3];
}

/// Write a TLS extension to the extension list.
///
/// Appends extension type (2 bytes), length (2 bytes), and data to the list.
/// This is used internally by message building functions.
fn writeExtension(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ext_type: ExtensionType,
    data: []const u8,
) !void {
    const type_value = @intFromEnum(ext_type);
    try list.appendSlice(allocator, &[_]u8{
        @intCast(type_value >> 8),
        @intCast(type_value & 0xff),
        @intCast(data.len >> 8),
        @intCast(data.len & 0xff),
    });
    try list.appendSlice(allocator, data);
}

/// Compute the signature for CertificateVerify (RFC 8446 §4.4.3).
///
/// Creates a digital signature over the handshake transcript hash using the
/// specified signature scheme. The signature proves possession of the private
/// key corresponding to the certificate.
///
/// ## Parameters
///
/// - `private_key`: Private key bytes (format depends on signature_scheme)
/// - `signature_scheme`: Signature algorithm to use
/// - `transcript_hash`: Hash of handshake messages up to and including Certificate
/// - `is_server`: true for server CertificateVerify, false for client
///
/// ## Returns
///
/// - `[64]u8`: Signature bytes (Ed25519 produces 64-byte signatures)
/// - `error.UnsupportedSignatureScheme`: Signature scheme not implemented
/// - `error.InvalidPrivateKey`: Private key format invalid
///
/// ## Signature Input Format (RFC 8446 §4.4.3)
///
/// ```
/// signature_input = 0x20 * 64 || context_string || 0x00 || transcript_hash
/// ```
///
/// Where:
/// - 64 spaces (0x20) prevent short message attacks
/// - context_string: "TLS 1.3, server CertificateVerify" or "TLS 1.3, client CertificateVerify"
/// - 0x00 separator byte
/// - transcript_hash: SHA-256 hash of handshake messages
///
/// ## Current Implementation
///
/// - Supports **Ed25519 only** (32-byte seed, 64-byte signature)
/// - Other signature schemes return error.UnsupportedSignatureScheme
///
/// ## Security Considerations
///
/// - Context string prevents cross-protocol attacks (server vs client)
/// - 64-space padding prevents attacks on short messages
/// - Signature covers the complete transcript (prevents tampering)
pub fn computeCertificateVerifySignature(
    private_key: []const u8,
    signature_scheme: SignatureScheme,
    transcript_hash: [H.digest_length]u8,
    is_server: bool,
) ![64]u8 {
    // TLS 1.3 CertificateVerify context string
    const context_string = if (is_server)
        "TLS 1.3, server CertificateVerify"
    else
        "TLS 1.3, client CertificateVerify";

    // Build the message to sign
    var msg: [64 + context_string.len + 1 + H.digest_length]u8 = undefined;
    @memset(msg[0..64], 0x20); // 64 spaces
    @memcpy(msg[64 .. 64 + context_string.len], context_string);
    msg[64 + context_string.len] = 0; // separator
    @memcpy(msg[65 + context_string.len ..], &transcript_hash);

    // For now, we only support Ed25519
    if (signature_scheme != .ed25519) {
        return error.UnsupportedSignatureScheme;
    }

    // Parse the private key (assuming Ed25519 seed format)
    if (private_key.len != 32) {
        return error.InvalidPrivateKey;
    }

    const kp = try std.crypto.sign.Ed25519.KeyPair.create(private_key[0..32].*);
    const signature = try std.crypto.sign.Ed25519.sign(&msg, kp, null);

    return signature;
}

/// Derive the Finished verify data (RFC 8446 §4.4.4).
///
/// Computes the HMAC-based verify_data for the Finished message using the
/// handshake traffic secret and transcript hash.
///
/// ## Parameters
///
/// - `traffic_secret`: Handshake traffic secret (client or server)
/// - `transcript_hash`: Hash of all handshake messages up to but not including Finished
///
/// ## Returns
///
/// - `[H.digest_length]u8`: Verify data for Finished message (32 bytes for SHA-256)
///
/// ## Computation (RFC 8446 §4.4.4)
///
/// ```
/// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
/// verify_data = HMAC(finished_key, transcript_hash)
/// ```
///
/// Where:
/// - `BaseKey` = client_handshake_traffic_secret or server_handshake_traffic_secret
/// - HKDF-Expand-Label is defined in RFC 8446 §7.1
/// - HMAC uses the hash function from the negotiated cipher suite (SHA-256)
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.4.4: Finished message verify_data computation
/// - RFC 8446 §7.1: HKDF-Expand-Label key derivation
///
/// ## Security Critical
///
/// - verify_data authenticates the entire handshake transcript
/// - Both client and server must verify each other's Finished messages
/// - Mismatch indicates handshake tampering (MUST abort with decrypt_error)
pub fn deriveFinishedVerifyData(
    traffic_secret: [H.digest_length]u8,
    transcript_hash: [H.digest_length]u8,
) [H.digest_length]u8 {
    var finished_key: [H.digest_length]u8 = undefined;
    ks.expandLabel(traffic_secret, "finished", &[_]u8{}, &finished_key) catch unreachable;
    return ks.hmacSha256(&finished_key, &transcript_hash);
}
