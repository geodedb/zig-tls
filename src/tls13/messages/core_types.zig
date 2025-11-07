//! TLS 1.3 Core Type Enumerations
//!
//! RFC 8446 Appendix B: Protocol Constants
//!
//! This module defines the fundamental enumeration types used throughout TLS 1.3:
//! - ExtensionType: Extension type registry (RFC 8446 Appendix B.3)
//! - NamedGroup: Groups for key exchange (RFC 8446 Appendix B.3.1.4)
//! - SignatureScheme: Signature algorithms (RFC 8446 Appendix B.3.1.3)
//! - CipherSuite: AEAD cipher suites (RFC 8446 Appendix B.4)
//!
//! These types are used during handshake negotiation to establish common
//! cryptographic parameters between client and server.

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
/// - **ffdhe2048** (0x0100): 2048-bit MODP group (112-bit security)
/// - **ffdhe3072** (0x0101): 3072-bit MODP group (128-bit security)
/// - **ffdhe4096** (0x0102): 4096-bit MODP group (152-bit security)
/// - **ffdhe6144** (0x0103): 6144-bit MODP group (176-bit security)
/// - **ffdhe8192** (0x0104): 8192-bit MODP group (192-bit security)
///
/// ## Current Implementation Support
///
/// This implementation currently focuses on **X25519** for ECDHE key exchange.
/// Other groups are recognized for parsing but not yet fully implemented.
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
/// - **ecdsa_secp256r1_sha256** (0x0403): ECDSA with P-256 and SHA-256
///   - 128-bit security level
///   - Most common for web PKI
///
/// - **ecdsa_secp384r1_sha384** (0x0503): ECDSA with P-384 and SHA-384
///   - 192-bit security level
///   - Required for CNSA Suite
///
/// - **ecdsa_secp521r1_sha512** (0x0603): ECDSA with P-521 and SHA-512
///   - 256-bit security level
///
/// ### RSA-PSS (RSA Probabilistic Signature Scheme)
///
/// RSA-PSS is the ONLY RSA signature scheme allowed in TLS 1.3 certificates.
/// RSASSA-PKCS1-v1_5 is prohibited for TLS 1.3 certificates (RFC 8446 §4.2.3).
///
/// - **rsa_pss_rsae_sha256** (0x0804): RSA-PSS with RSAE key and SHA-256
/// - **rsa_pss_rsae_sha384** (0x0805): RSA-PSS with RSAE key and SHA-384
/// - **rsa_pss_rsae_sha512** (0x0806): RSA-PSS with RSAE key and SHA-512
/// - **rsa_pss_pss_sha256** (0x0809): RSA-PSS with PSS-specific key and SHA-256
/// - **rsa_pss_pss_sha384** (0x080a): RSA-PSS with PSS-specific key and SHA-384
/// - **rsa_pss_pss_sha512** (0x080b): RSA-PSS with PSS-specific key and SHA-512
///
/// ### EdDSA (Edwards-curve Digital Signature Algorithm)
///
/// - **ed25519** (0x0807): EdDSA with Curve25519 (RFC 8032)
///   - 128-bit security level
///   - Fast signing and verification
///   - Deterministic signatures
///   - Preferred for modern deployments
///
/// - **ed448** (0x0808): EdDSA with Curve448 (RFC 8032)
///   - 224-bit security level
///
/// ### Legacy RSA (DEPRECATED for TLS 1.3)
///
/// These RSASSA-PKCS1-v1_5 schemes are included for parsing legacy ClientHello
/// but MUST NOT be used for TLS 1.3 certificates (RFC 8446 §4.2.3):
///
/// - **rsa_pkcs1_sha256** (0x0401)
/// - **rsa_pkcs1_sha384** (0x0501)
/// - **rsa_pkcs1_sha512** (0x0601)
///
/// ## Current Implementation Support
///
/// This implementation currently supports **Ed25519 only** for signing operations.
/// Other schemes are recognized for parsing but verification is not yet implemented.
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
///   - Designed for constrained devices (IoT, embedded systems)
///
/// - **TLS_AES_128_CCM_8_SHA256** (0x1305): AES-128-CCM with 8-byte tags
///   - AEAD: AES-128-CCM with 64-bit authentication tags
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
/// - ChaCha20-Poly1305 preferred on non-AES hardware
/// - All suites provide forward secrecy when combined with ephemeral key exchange
/// - Hash function security should match AEAD security level
pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301, // RFC 8446: AES-128-GCM with SHA-256 (MANDATORY, widely used)
    TLS_AES_256_GCM_SHA384 = 0x1302, // RFC 8446: AES-256-GCM with SHA-384 (higher security)
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303, // RFC 8446: ChaCha20-Poly1305 with SHA-256 (software-optimized)
    TLS_AES_128_CCM_SHA256 = 0x1304, // RFC 8446: AES-128-CCM with SHA-256 (constrained devices)
    TLS_AES_128_CCM_8_SHA256 = 0x1305, // RFC 8446: AES-128-CCM-8 with SHA-256 (8-byte tags for IoT)
};
