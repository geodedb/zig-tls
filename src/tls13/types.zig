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
const ks = @import("quic_tls");

/// Map a TLS 1.3 CipherSuite to its associated hash algorithm (RFC 8446 Appendix B.4).
///
/// This is the canonical mapping used by Context during key derivation.
/// All SHA-256-based suites (AES-128-GCM, ChaCha20-Poly1305,
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

/// Transport mode for the TLS 1.3 handshake.
///
/// - `.quic` (default): RFC 9001 §8.2 — `quic_transport_parameters` (extension
///   0x0039) is MANDATORY on both peers; a ClientHello or EncryptedExtensions
///   that omits it aborts the handshake with `HandshakeError.MissingTransportParameters`.
///   This is the historical behavior and is unchanged for every existing QUIC consumer.
/// - `.tls`: RFC 8446 plain TLS 1.3 over a reliable byte stream (TCP). Peer
///   transport parameters are OPTIONAL (absent or omitted is accepted), and this
///   endpoint emits no `quic_transport_parameters` extension. Use this for a
///   non-QUIC TLS client/server (e.g. an HTTPS fetch over TCP).
pub const TransportMode = enum { quic, tls };

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
///
/// # QUAL-352: ApiError vs HandshakeError
///
/// This library uses two distinct error sets for two distinct concerns:
///
/// - `ApiError` — **Non-fatal, caller-workflow** errors. These signal that
///   the embedder asked for something the library cannot (yet) do or that
///   no data is available right now. An `ApiError` DOES NOT abort the
///   handshake. It does not map to a TLS alert. Callers are expected to
///   handle these (e.g. retry, pump more data, feature-detect).
///
/// - `HandshakeError` — **Fatal protocol** errors. These indicate the peer
///   sent bytes that violate RFC 8446. They map 1:1 to TLS alerts (see
///   `alert.fromHandshakeError()`) and, in QUIC, to CRYPTO_ERROR codes per
///   RFC 9001 §4.8. They always abort the connection.
///
/// Rule of thumb:
///   - If the embedder can recover (more data, different arg, next poll),
///     use `ApiError`.
///   - If a byte-level RFC violation is detected, use `HandshakeError`.
///
/// Mixed return types (`ApiError || HandshakeError`) are expressed via
/// Zig error-set unions. Callers typically `try` them and let the error
/// propagate; boundary code distinguishes by the specific error tag.
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

    /// SEC-029: Client did not configure server_name (SNI) for hostname validation.
    /// Without a server_name, any valid certificate from any CA would be accepted,
    /// enabling man-in-the-middle attacks. Either set config.server_name or
    /// set config.allow_insecure = .testing_only_i_know_what_i_am_doing for
    /// test environments (build with -Dtls-insecure-testing=true — SEC-077).
    MissingServerName,

    /// Internal state invariant violated. This indicates a programming error
    /// where an expected value was not set before being used.
    InternalError,

    /// GAP-0133: inbound fatal alert terminated the connection.
    PeerFatalAlert,

    /// GAP-0133: inbound alert payload was not exactly 2 bytes.
    InvalidAlert,

    /// SEC-086: post-HelloRetryRequest cookie validation failed.
    /// RFC 8446 §4.2.2: ClientHello2 MUST echo the cookie issued in HRR;
    /// servers verify it via HMAC over (server_secret, client_random,
    /// CH1_transcript_hash). Triggered when the cookie is absent on
    /// CH2, malformed, stale beyond max-age, or HMAC-mismatched. Maps
    /// to TLS alert `illegal_parameter` (RFC 8446 §6.2).
    InvalidCookie,

    /// SEC-092 (subsumes SEC-078): A peer sent two extensions of the same
    /// type in the same extension block. RFC 8446 §4.2: "There MUST NOT be
    /// more than one extension of the same type in a given extension
    /// block." Maps to TLS alert `decode_error` (or `illegal_parameter`
    /// per implementation choice; ClientHello path returns the bare
    /// `error.DecodeError` to align with SEC-066's existing alert mapping).
    DuplicateExtension,

    /// APPSEC-04: an extension block carried more than 64 DISTINCT extension
    /// types, exceeding the duplicate-detection tracker capacity. Distinct
    /// from `DuplicateExtension`; maps to TLS alert `decode_error`.
    TooManyExtensions,

    /// NEWGAP-06: ServerHello.legacy_session_id_echo did not match the
    /// (empty) legacy_session_id the client sent. RFC 8446 §4.1.3 MUST abort
    /// with `illegal_parameter`.
    IllegalSessionIdEcho,

    /// NEWGAP-06 (minor): ServerHello.legacy_version was not 0x0303.
    /// RFC 8446 §4.1.3 MUST be 0x0303; maps to `illegal_parameter`.
    IllegalLegacyVersion,

    /// NEWGAP-09: a handshake message carried an extension forbidden in that
    /// message (e.g. key_share / pre_shared_key inside EncryptedExtensions).
    /// RFC 8446 §4.2 MUST abort with `illegal_parameter`.
    ForbiddenExtension,

    /// NEWGAP-10: a Certificate message carried a `certificate_request_context`
    /// that violated RFC 8446 §4.4.2 — non-zero on the server-auth path, or not
    /// matching the CertificateRequest context on the mTLS path. Maps to
    /// `illegal_parameter`.
    IllegalCertificateRequestContext,

    /// NEWGAP08-N1: the client received a ServerHello/HelloRetryRequest whose
    /// `cipher_suite` was never offered (or, post-HRR, differs from the HRR's).
    /// RFC 8446 §4.1.3/§4.1.4 MUST abort with `illegal_parameter`. Distinct from
    /// `NoCipherSuite` (server-side "no mutually supported suite" ->
    /// `handshake_failure`).
    IllegalCipherSuiteSelected,

    /// NEWGAP-13: the client received a HelloRetryRequest that would not change
    /// the ClientHello (it selected an already-offered key_share group and
    /// carried no cookie). RFC 8446 §4.1.4 MUST abort with `illegal_parameter`.
    HrrNoChange,

    /// NEWGAP-12: a CertificateRequest omitted the mandatory
    /// `signature_algorithms` extension (RFC 8446 §4.3.2 -> `missing_extension`).
    MissingSignatureAlgorithms,

    /// SEC-088: ClientHello/ServerHello carried a `legacy_compression_methods`
    /// field that violates RFC 8446 §4.1.2 / §4.1.3 (must be exactly one byte
    /// equal to 0x00 on CH; must equal 0x00 on SH). Maps to TLS alert
    /// `illegal_parameter` (RFC 8446 §6.2 via alert.fromHandshakeError).
    IllegalCompressionMethods,

    /// SEC-099: ClientHello.cipher_suites_length was odd. RFC 8446 §4.1.2
    /// declares `CipherSuite cipher_suites<2..2^16-2>;` and each `CipherSuite`
    /// is exactly two bytes, so the length MUST be a multiple of two. An odd
    /// length combined with a tail-aligned record would cause an out-of-bounds
    /// read in the cipher-suite loop (PoC-confirmed pre-auth panic). Maps to
    /// TLS alert `illegal_parameter` so the handshake terminates without a
    /// crash.
    IllegalCipherSuites,

    /// GAP-0135: Peer exceeded the max_peer_key_updates budget.
    /// Defends against CPU exhaustion (CWE-400) from rapid inbound KeyUpdates.
    /// Maps to TLS alert `decode_error` (or `unexpected_message`).
    TooManyKeyUpdates,

    /// SEC-098: pre_shared_key extension carried mismatched cardinalities for
    /// `identities` and `binders`. RFC 8446 §4.2.11 mandates `len(identities)
    /// == len(binders)`; downstream PSK selection indexes binders by the
    /// chosen identity index and would otherwise read out of bounds (CWE-345
    /// → potential OOB array access). Maps to TLS alert `illegal_parameter`.
    PskBinderMismatch,
};
