// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

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
const ks = @import("quic_tls");

/// Map a TLS 1.3 CipherSuite to its associated hash algorithm (RFC 8446 Appendix B.4).
///
/// This is the canonical mapping used by both Context and Engine during key
/// derivation. All SHA-256-based suites (AES-128-GCM, ChaCha20-Poly1305,
/// AES-128-CCM variants) return `.sha256`; AES-256-GCM returns `.sha384`.
pub fn cipherSuiteHash(suite: tls13_full.CipherSuite) ks.Hash {
    return switch (suite) {
        .TLS_AES_128_GCM_SHA256, .TLS_CHACHA20_POLY1305_SHA256, .TLS_AES_128_CCM_SHA256, .TLS_AES_128_CCM_8_SHA256 => .sha256,
        .TLS_AES_256_GCM_SHA384 => .sha384,
    };
}

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

    /// Peer QUIC transport parameters received in handshake
    /// - Client: Received in EncryptedExtensions from server
    /// - Server: Received in ClientHello from client
    /// Available after EncryptedExtensions processed
    peer_transport_parameters: ?[]const u8 = null,
};

/// Mirror of the TLS 1.3 signature scheme enumeration (RFC 8446 §4.2.3).
pub const SignatureScheme = tls13_full.SignatureScheme;

/// Error type for TLS API operations.
pub const ApiError = error{
    /// Requested operation not yet implemented.
    Unimplemented,
    /// No outbound data available at the requested encryption level.
    NothingToRead,
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

    /// Server sent an empty certificate chain.
    /// RFC 8446 §4.4.2: Certificate message must contain at least one certificate.
    EmptyCertificateChain,

    /// CertificateVerify received but no Certificate message was processed.
    /// RFC 8446 §4.4: Certificate must precede CertificateVerify.
    MissingCertificate,

    /// Certificate chain validation failed (RFC 5280 §6).
    /// This includes validity period, hostname mismatch, chain verification, etc.
    CertificateValidationFailed,

    /// OCSP response required but not provided by server.
    /// RFC 6960 + RFC 8446 §4.4.2.1: OCSP stapling when require_ocsp=true.
    MissingOcspResponse,

    /// OCSP response validation failed (status revoked, bad signature, etc.).
    /// RFC 6960 §2.2: Response must be signed by trusted responder and show good status.
    OcspValidationFailed,

    /// SCT list required but not provided by server.
    /// RFC 6962 + RFC 8446 §4.4.2.1: Certificate Transparency when require_scts=true.
    MissingSctList,

    /// Failed to parse SCT list from certificate extensions.
    /// RFC 6962 §3.3: SCT list must be properly encoded.
    SctParsingFailed,

    /// SCT list is empty when require_scts=true.
    /// RFC 6962: At least one valid SCT required for Certificate Transparency.
    EmptySctList,

    /// SCT list validation callback rejected the provided SCTs.
    /// User-defined validation (e.g., checking log inclusion) failed.
    SctCallbackRejected,

    /// CertificateVerify signature verification failed.
    /// RFC 8446 §4.4.3: Signature must verify using leaf certificate's public key.
    InvalidSignature,

    /// Signature algorithm in CertificateVerify is not supported.
    /// RFC 8446 §4.2.3: Algorithm must be in client's signature_algorithms extension.
    UnsupportedSignatureAlgorithm,

    /// Decryption or authentication failure (e.g., PSK binder mismatch).
    /// RFC 8446 §4.2.11.2: Invalid binders MUST be rejected.
    DecryptError,

    /// Cryptographic operation failed (HKDF, HMAC, or signature calculation).
    /// RFC 8446 §7: Cryptographic computations must succeed to proceed.
    CryptoError,

    /// PSK offered but psk_key_exchange_modes extension missing.
    /// RFC 8446 §4.2.9: Required when using PSK authentication.
    MissingPskKeyExchangeModes,

    /// PSK offered but psk_dhe_ke mode not supported.
    /// RFC 8446 §4.2.9: psk_dhe_ke required for forward secrecy.
    PskDheKeModeRequired,

    /// resumption_psk is set but resumption_ticket is null.
    /// RFC 8446 §4.2.11: PSK identity (ticket) is required when offering PSK resumption.
    MissingResumptionTicket,

    /// Server sent pre_shared_key extension but client did not offer PSK.
    /// RFC 8446 §4.2.11: Server MUST NOT send pre_shared_key if client did not offer one.
    UnexpectedPskExtension,

    /// Server selected a PSK identity index that exceeds the number of identities offered.
    /// RFC 8446 §4.2.11: selected_identity MUST be in range [0, num_identities).
    PskIndexOutOfRange,

    /// Client sent server-only transport parameters or transport params failed validation.
    /// RFC 9000 §18.2: original_destination_connection_id, preferred_address,
    /// retry_source_connection_id, and stateless_reset_token MUST NOT be sent by clients.
    InvalidTransportParameters,
};
