//! Core TLS 1.3 Types and Error Definitions
//!
//! RFC 8446 §4: Handshake Protocol
//! RFC 9001 §4: TLS for QUIC
//!
//! This module defines the fundamental types used throughout the TLS 1.3
//! handshake state machine, including role identification, metadata views,
//! and error types.

const tls13_full = @import("tls13_full");
const sct = @import("sct");

/// TLS endpoint role (RFC 8446 §4).
pub const Role = enum {
    /// Client initiates handshake, verifies server certificate
    Client,
    /// Server responds to handshake, provides certificate
    Server,
};

/// View of negotiated handshake metadata surfaced to the QUIC connection layer.
///
/// This structure provides read-only access to negotiated parameters after
/// the handshake progresses to the appropriate point.
pub const HandshakeMetadata = struct {
    /// Negotiated ALPN protocol (e.g., "h3" for HTTP/3)
    /// Available after EncryptedExtensions processed
    alpn: ?[]const u8 = null,

    /// Local QUIC transport parameters advertised in handshake
    /// Available immediately after configuration
    local_transport_parameters: ?[]const u8 = null,
};

/// Mirror of the TLS 1.3 signature scheme enumeration (RFC 8446 §4.2.3).
pub const SignatureScheme = tls13_full.SignatureScheme;

/// Error type for TLS API operations.
pub const ApiError = error{
    /// Requested operation not yet implemented.
    Unimplemented,
};

/// Errors surfaced during TLS 1.3 handshake message parsing and validation.
///
/// These errors map to TLS alerts (alert.zig) which are then converted to QUIC
/// CRYPTO_ERROR codes per RFC 9001 §4.8. The alert mapping is defined in
/// `alert.fromHandshakeError()`.
///
/// # Error to Alert Mapping Examples
/// - `UnexpectedMessage` → unexpected_message (0x0A)
/// - `UnsupportedVersion` → protocol_version (0x46)
/// - `NoCipherSuite` → handshake_failure (0x28)
/// - `FinishedVerifyFailed` → decrypt_error (0x33)
/// - `AlpnNegotiationFailed` → no_application_protocol (0x78)
///
/// All handshake errors are fatal and abort the connection.
pub const HandshakeError = error{
    /// Received handshake message in wrong state or unexpected message type.
    /// RFC 8446 §4: Handshake messages must follow strict ordering.
    /// Example: ServerHello received by server, or Finished before Certificate.
    UnexpectedMessage,

    /// ClientHello received when already processed (server role).
    /// RFC 8446 §4.1.2: Only one ClientHello per handshake (excluding HelloRetryRequest).
    DuplicateClientHello,

    /// Client/server version mismatch or TLS 1.3 not supported.
    /// RFC 8446 §4.2.1: supported_versions extension must contain 0x0304 (TLS 1.3).
    UnsupportedVersion,

    /// ClientHello missing key_share extension.
    /// RFC 8446 §4.2.8: key_share required for ECDHE in TLS 1.3.
    MissingKeyShare,

    /// key_share contains unsupported group or invalid key length.
    /// RFC 8446 §4.2.8: Must match a group in supported_groups extension.
    /// Example: Received secp384r1 when only x25519 configured.
    UnsupportedKeyShareGroup,

    /// No mutually supported cipher suite found.
    /// RFC 8446 §4.1.3: Server must select from client's offered suites.
    /// Example: Client offers only TLS_AES_256_GCM_SHA384 but server supports only TLS_AES_128_GCM_SHA256.
    NoCipherSuite,

    /// QUIC transport parameters extension missing.
    /// RFC 9001 §8.2: quic_transport_parameters (0x0039) mandatory for QUIC.
    /// Both ClientHello and EncryptedExtensions must include it.
    MissingTransportParameters,

    /// No mutually supported ALPN protocol.
    /// RFC 7301: Server must select from client's offered protocols.
    /// Example: Client offers ["h2"] but server only supports ["h3"].
    AlpnNegotiationFailed,

    /// No mutually supported signature algorithm for CertificateVerify.
    /// RFC 8446 §4.2.3: signature_algorithms extension required.
    /// Example: Client offers only rsa_pss but server has Ed25519 key.
    NoSignatureScheme,

    /// Finished verify_data does not match expected HMAC.
    /// RFC 8446 §4.4.4: verify_data = HMAC(finished_key, transcript_hash).
    /// Indicates transcript tampering or incorrect secret derivation.
    FinishedVerifyFailed,

    /// ServerHello contains downgrade protection sentinel.
    /// RFC 8446 §4.1.3: Last 8 bytes of server random signal TLS 1.2 if client supports 1.3.
    /// Prevents version downgrade attacks.
    DowngradeAttempt,

    /// Post-handshake authentication (CertificateRequest after handshake completion) is unsupported for QUIC.
    PostHandshakeAuthUnsupported,
};
