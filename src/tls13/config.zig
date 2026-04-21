// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TLS 1.3 Configuration
//!
//! This module provides the Config struct for configuring TLS 1.3 handshake behavior.
//!
//! # RFC References
//! - **RFC 8446 §4.1.2**: ClientHello (cipher_suites, supported_groups, signature_algorithms)
//! - **RFC 8446 §4.2**: Extensions (ALPN, key_share)
//! - **RFC 8446 §4.4.2**: Certificate message
//! - **RFC 8446 §4.2.10**: 0-RTT early data extension
//! - **RFC 7301**: Application-Layer Protocol Negotiation (ALPN)
//! - **RFC 9001 §8.2**: QUIC transport parameters extension
//!
//! # Usage
//!
//! ```zig
//! const config = Config{
//!     .allocator = allocator,
//!     .role = .Client,
//!     .supported_cipher_suites = &.{.TLS_AES_128_GCM_SHA256},
//!     .supported_groups = &.{.x25519},
//!     .supported_signature_schemes = &.{.ed25519},
//!     .alpn_protocols = &.{"h3"},
//!     .quic_transport_parameters = encoded_params,
//! };
//! ```

const std = @import("std");
const tls13_full = @import("tls13_full");
const sct = @import("sct");
const zero_rtt = @import("zero_rtt");
const x509 = @import("x509");

// Import types from modularized tls13 package
const types = @import("types.zig");
pub const Role = types.Role;

/// TLS 1.3 Configuration
///
/// Defines parameters for TLS 1.3 handshake negotiation including:
/// - Cipher suite preferences
/// - ECDHE group selection
/// - Signature algorithm support
/// - ALPN protocol list
/// - QUIC transport parameters
/// - Certificate and private key (server role)
/// - 0-RTT and OCSP/SCT requirements
///
/// RFC 8446 §4: Handshake Protocol
/// - §4.1.2: ClientHello message fields
/// - §4.2: Extensions (ALPN, supported_groups, signature_algorithms, key_share)
/// - §7: Cryptographic Computations (key schedule driven by negotiated suite)
///
/// # Usage
///
/// ```zig
/// const config = Config{
///     .allocator = allocator,
///     .role = .Client,
///     .supported_cipher_suites = &.{.TLS_AES_128_GCM_SHA256},
///     .supported_groups = &.{.x25519},
///     .supported_signature_schemes = &.{.ed25519},
///     .alpn_protocols = &.{"h3"},
///     .quic_transport_parameters = encoded_params,
/// };
/// ```
pub const Config = struct {
    /// Allocator used for handshake buffers, transcript storage, and temporary allocations.
    /// All Context operations use this allocator for memory management.
    allocator: std.mem.Allocator,

    /// Role of the local endpoint (Client or Server).
    /// Drives handshake flow direction and message generation logic.
    /// - Client: Initiates handshake with ClientHello, verifies server certificate
    /// - Server: Responds to ClientHello, provides certificate and Finished first
    role: Role,

    /// Cipher suites offered (client) or accepted (server) in preference order.
    /// RFC 8446 §4.1.2: ClientHello cipher_suites, §4.1.3: ServerHello cipher_suite.
    ///
    /// **Role:** Both (client offers, server selects).
    ///
    /// **Valid values:** TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
    /// TLS_CHACHA20_POLY1305_SHA256. Slice must be non-empty.
    ///
    /// Negotiation: First match between client offer and server preference wins.
    ///
    /// **Default:** [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256]
    supported_cipher_suites: []const tls13_full.CipherSuite = &.{
        tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256,
        tls13_full.CipherSuite.TLS_AES_256_GCM_SHA384,
        tls13_full.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    },

    /// Named groups advertised for ECDHE key agreement (RFC 8446 §4.2.7).
    /// Used in supported_groups and key_share extensions.
    ///
    /// **Role:** Both (client advertises, server selects).
    ///
    /// **Valid values:** x25519 (currently the only implemented group).
    /// Slice must be non-empty.
    ///
    /// Negotiation: Client sends key_share for preferred groups; server selects one.
    ///
    /// **Default:** [x25519]
    supported_groups: []const tls13_full.NamedGroup = &.{tls13_full.NamedGroup.x25519},

    /// Signature algorithms allowed for certificate authentication (RFC 8446 §4.2.3).
    /// Sent in signature_algorithms extension, used to verify CertificateVerify.
    ///
    /// **Role:** Both (client advertises, server selects for signing).
    ///
    /// **Valid values:** ed25519, ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384,
    /// rsa_pss_rsae_sha256. Slice must be non-empty. The selected scheme must
    /// be compatible with the certificate key type (server_cert_der / client_cert_der).
    ///
    /// **Default:** [ed25519]
    supported_signature_schemes: []const tls13_full.SignatureScheme = &.{tls13_full.SignatureScheme.ed25519},

    /// Ordered list of ALPN protocol identifiers to negotiate (RFC 7301).
    /// Sent in application_layer_protocol_negotiation extension.
    ///
    /// **Role:** Both (client offers list, server selects one).
    ///
    /// **Valid values:** Each protocol name is 1-255 bytes (RFC 7301 length constraint).
    /// Common values: ["h3"] for HTTP/3, ["h2"] for HTTP/2.
    /// Server selects first match in its preference order from client's list.
    ///
    /// **Default:** null (ALPN not negotiated; acceptable for some QUIC applications).
    alpn_protocols: ?[]const []const u8 = null,

    /// Raw QUIC transport parameters to advertise (RFC 9001 §8.2).
    /// Carried in quic_transport_parameters extension (0x0039).
    ///
    /// **Role:** Both.
    /// - Client: Sent in ClientHello extensions.
    /// - Server: Sent in EncryptedExtensions.
    ///
    /// **Valid values:** Opaque binary blob in RFC 9000 §18 encoding.
    /// Contains max_idle_timeout, initial_max_data, etc.
    /// Maximum length bounded by ClientHello / EncryptedExtensions size limits.
    ///
    /// **Default:** null (no transport parameters; will cause handshake failure in QUIC).
    quic_transport_parameters: ?[]const u8 = null,

    /// Enable receipt and processing of 0-RTT early data (RFC 8446 §4.2.10).
    /// When true, server accepts early_data extension and processes 0-RTT packets.
    ///
    /// **Role:** Server only (client 0-RTT is controlled by resumption_psk presence).
    ///
    /// **Requires:**
    /// - PSK resumption with compatible cipher suite (resumption_psk on client)
    /// - Anti-replay protection (zero_rtt.zig)
    /// - Application-level replay safety
    /// - `zero_rtt_limits` should be configured to bound early data volume
    ///
    /// **Default:** false (0-RTT disabled)
    enable_early_data: bool = false,

    /// Limits for 0-RTT early data (RFC 8446 §4.2.10, CWE-400 prevention).
    ///
    /// Controls the maximum amount of 0-RTT data that can be accepted to prevent
    /// DoS attacks. The max_early_data_size value is enforced at the record layer.
    ///
    /// ## Security Considerations
    ///
    /// - **Default 16KB**: Balances utility and DoS risk
    /// - **Higher limits**: Increase replay/amplification attack surface
    /// - **Lower limits**: Reduce attack surface but limit 0-RTT utility
    ///
    /// ## Example
    ///
    /// ```zig
    /// .zero_rtt_limits = .{ .max_early_data_size = 8192 }, // 8KB limit
    /// ```
    ///
    /// Default: 16KB max_early_data_size
    zero_rtt_limits: zero_rtt.ZeroRttLimits = .{},

    /// SEC-065/085: Optional persistent cross-connection anti-replay store.
    ///
    /// When non-null, the server checks every inbound 0-RTT ClientHello
    /// random against this backend before accepting early data. A backend
    /// error (BackendUnavailable / BackendError) is treated fail-closed —
    /// the 0-RTT attempt is rejected and the handshake falls back to 1-RTT.
    ///
    /// When null, 0-RTT replay protection is limited to the per-Context
    /// in-memory `AntiReplayWindow` (default 64 entries), which does NOT
    /// defend against cross-connection replay or server restart. Single-
    /// server deployments may accept this trade-off; multi-server / load-
    /// balanced deployments MUST configure a persistent backend.
    ///
    /// See `src/zero_rtt.zig:PersistentAntiReplayStore` for the interface
    /// and an example Redis implementation in the doc comments.
    persistent_anti_replay_store: ?zero_rtt.PersistentAntiReplayStore = null,

    /// DER-encoded server certificate (leaf) for authentication.
    /// RFC 8446 §4.4.2: Certificate message contains certificate_list.
    ///
    /// **Role:** Server only.
    ///
    /// **Requires:** `server_key_der` must also be set (the private key that
    /// corresponds to this certificate's public key).
    ///
    /// Must be valid X.509v3 certificate with:
    /// - digitalSignature key usage
    /// - serverAuth extended key usage
    /// - Valid subject alternative names matching peer's SNI
    ///
    /// **Default:** null (no certificate; client role or testing).
    server_cert_der: ?[]const u8 = null,

    /// DER-encoded private key (PKCS#8 format) for server authentication.
    /// Used to generate CertificateVerify signature over transcript hash (RFC 8446 §4.4.3).
    ///
    /// **Role:** Server only.
    ///
    /// **Requires:** `server_cert_der` must also be set (the certificate whose
    /// public key corresponds to this private key).
    ///
    /// **Valid values:** PKCS#8 DER-encoded private key. Supported key types:
    /// Ed25519, ECDSA P-256/P-384, RSA-PSS. Must match the key type used in
    /// `supported_signature_schemes`.
    ///
    /// **Default:** null (no private key; client role or testing).
    server_key_der: ?[]const u8 = null,

    /// Server secret for HelloRetryRequest cookie generation (Server role only).
    /// RFC 8446 §4.1.4: Used to create HMAC-authenticated cookies for stateless HRR.
    ///
    /// The cookie is generated as: HMAC-SHA256(server_secret, client_random || transcript_hash || timestamp)
    ///
    /// Security properties:
    /// - Should be randomly generated at server startup (32+ bytes recommended)
    /// - Must be kept secret (compromise allows cookie forgery)
    /// - Can be rotated periodically for key hygiene
    /// - Same secret can be shared across server instances for load balancing
    ///
    /// If null, a random secret will be generated on first HRR (less secure for multi-server).
    ///
    /// Default: null (auto-generated)
    server_secret: ?[]const u8 = null,

    /// Require the peer to present a stapled OCSP response (RFC 6960, RFC 6066 §8).
    ///
    /// When `true`:
    /// - Handshake aborts if Certificate message omits OCSP data
    /// - Handshake aborts if OCSP response validation fails
    /// - Provides revocation checking without client-side OCSP queries
    ///
    /// When `false` (default):
    /// - Certificates are accepted without revocation status verification
    /// - Revoked certificates may be accepted if attacker controls the connection
    /// - Suitable only when revocation checking is handled externally or
    ///   for environments where OCSP stapling is not universally deployed
    ///
    /// ## Security Warning
    ///
    /// **Default `false` accepts certificates without revocation checking!**
    ///
    /// Compromised or revoked certificates will be accepted unless OCSP stapling
    /// is required. This is a security trade-off for compatibility:
    /// - Many servers don't support OCSP stapling
    /// - Requiring stapling would break connections to those servers
    ///
    /// ## Recommendations
    ///
    /// - **High-security environments**: Set `require_ocsp = true`
    /// - **General use**: Leave as `false`, but monitor for revocation issues
    /// - **Internal/trusted networks**: May leave as `false` if CA controls revocation
    ///
    /// ## RFC References
    /// - RFC 6960: Online Certificate Status Protocol (OCSP)
    /// - RFC 6066 §8: Certificate Status Request extension (status_request)
    /// - RFC 8446 §4.4.2.1: OCSP status in TLS 1.3 Certificate message
    ///
    /// ## Limitations
    ///
    /// This implementation only validates OCSP responses stapled by the server.
    /// Active OCSP queries (client-side fetching) are not implemented.
    /// For full revocation checking, consider implementing CRL checking or
    /// an external OCSP client.
    require_ocsp: bool = false,

    /// Require Signed Certificate Timestamps (SCTs) (RFC 6962).
    /// When true, the handshake aborts if no SCT list is present or if the list
    /// is empty or rejected by `on_sct_list`.
    ///
    /// **Role:** Client only (validates server certificate transparency).
    ///
    /// **Interactions:** When `on_sct_list` is also set, the callback is invoked
    /// for additional validation or logging. If `on_sct_list` returns an error,
    /// the handshake aborts regardless of this field's value.
    ///
    /// **Default:** false (SCTs not required).
    require_scts: bool = false,

    /// Optional callback invoked with the parsed SCT list for additional
    /// validation or telemetry. The callback must not retain references to the
    /// provided slice beyond its lifetime.
    ///
    /// **Role:** Client only.
    ///
    /// **Interactions:** Called when SCT data is present in the Certificate message,
    /// regardless of `require_scts` setting. If the callback returns an error,
    /// the handshake aborts.
    ///
    /// **Default:** null (no SCT callback).
    on_sct_list: ?*const fn ([]const sct.SignedCertificateTimestamp) anyerror!void = null,

    /// Server name (SNI) for certificate hostname validation.
    /// RFC 6066 §3: Server Name Indication extension.
    ///
    /// **Role:** Client only.
    ///
    /// When set, the client will:
    /// - Include SNI extension in ClientHello
    /// - Validate server certificate against this hostname (RFC 5280 §4.2.1.6)
    ///
    /// **Valid values:** DNS hostname (e.g., "example.com"). Must not be an IP address.
    /// Supports wildcard matching against certificate SANs (e.g., "*.example.com").
    ///
    /// **Security:** Setting this to null skips hostname validation, allowing any
    /// valid certificate to be accepted (MITM risk, see SEC-029).
    ///
    /// **Default:** null (no SNI extension; hostname validation skipped).
    server_name: ?[]const u8 = null,

    /// SEC-077: Certificate-validation mode. Defaults to full validation.
    /// To use `.testing_only_i_know_what_i_am_doing`, the library must be
    /// built with `-Dtls-insecure-testing=true`; otherwise a runtime panic
    /// fires on any handshake that traverses cert validation.
    ///
    /// **Role:** Both (affects validation of peer's certificate).
    ///
    /// When `.testing_only_i_know_what_i_am_doing`:
    /// - Certificate chain validation is skipped
    /// - Hostname/SNI validation is skipped
    /// - Expiry checks are skipped
    /// - EKU and KeyUsage checks are skipped
    ///
    /// **Security:** This is a **DANGEROUS** option. Production builds
    /// (where `-Dtls-insecure-testing` is absent / false) will `@panic`
    /// if this variant reaches chain validation, preventing accidental use.
    ///
    /// **Default:** `.secure` (full validation required).
    allow_insecure: x509.InsecureValidation = .secure,

    /// Server: request client certificate during handshake (RFC 8446 §4.3.2).
    /// When true, the server sends a CertificateRequest message after
    /// EncryptedExtensions, and the client responds with Certificate +
    /// CertificateVerify before Finished.
    ///
    /// Note: RFC 9001 forbids *post-handshake* client auth in QUIC, but
    /// *initial handshake* client auth (CertificateRequest before server
    /// Finished) is fully supported.
    ///
    /// Default: false (no client certificate requested)
    request_client_cert: bool = false,

    /// DER-encoded client certificate for mutual TLS authentication.
    /// Sent in the Certificate message when the server requests client auth.
    /// Must be valid X.509v3 certificate.
    ///
    /// **Role:** Client only (sent in response to server's CertificateRequest).
    ///
    /// **Requires:** `client_key_der` must also be set (the private key that
    /// corresponds to this certificate's public key).
    ///
    /// **Default:** null (no client certificate; will send empty Certificate if requested).
    client_cert_der: ?[]const u8 = null,

    /// DER-encoded private key (PKCS#8 format) for client authentication.
    /// Used to generate CertificateVerify signature when server requests client auth.
    ///
    /// **Role:** Client only.
    ///
    /// **Requires:** `client_cert_der` must also be set (the certificate whose
    /// public key corresponds to this private key).
    ///
    /// **Default:** null (no client private key).
    client_key_der: ?[]const u8 = null,

    /// Trusted CA certificates for client certificate validation (optional).
    /// If set, included in the certificate_authorities extension of CertificateRequest.
    ///
    /// **Role:** Server only (sent in CertificateRequest message).
    ///
    /// **Interactions:** Only relevant when `request_client_cert` is true.
    /// Each entry is a DER-encoded X.509 distinguished name.
    ///
    /// **Default:** null (no certificate_authorities extension sent).
    client_auth_ca_certs: ?[]const []const u8 = null,

    /// External pre-shared key bytes for out-of-band PSK authentication (RFC 8446 §4.2.11).
    /// When set, the client will offer this PSK in the ClientHello using the "ext binder" label.
    /// External PSKs are provisioned out-of-band (not via NewSessionTicket).
    ///
    /// **Role:** Client only.
    ///
    /// **Requires:** `external_psk_identity` must also be set.
    ///
    /// **Valid values:** Arbitrary byte slice (typically 32 bytes for SHA-256 based suites).
    /// RFC 8446 §7.1: External PSKs use "ext binder" label for binder key derivation,
    /// while resumption PSKs use "res binder". This distinction is critical for security.
    ///
    /// **Interactions:** If both `external_psk` and `resumption_psk` are set,
    /// `resumption_psk` takes priority (resumption is preferred over external PSK).
    ///
    /// **Default:** null (no external PSK configured).
    external_psk: ?[]const u8 = null,

    /// Identity to advertise for the external PSK (RFC 8446 §4.2.11).
    /// This is the opaque identity sent in the PskIdentity structure in
    /// the ClientHello pre_shared_key extension.
    ///
    /// **Role:** Client only.
    ///
    /// **Requires:** `external_psk` must also be set.
    /// For external PSKs, the identity format is application-defined (not a ticket).
    ///
    /// **Default:** null (no external PSK identity).
    external_psk_identity: ?[]const u8 = null,

    /// Pre-shared key for session resumption (RFC 8446 §4.2.11).
    /// If set, the client will offer this PSK in the ClientHello.
    ///
    /// **Role:** Client only.
    ///
    /// **Requires:** `resumption_ticket` and `resumption_ticket_age_add` must also be set.
    ///
    /// **Valid values:** The PSK derived from NewSessionTicket's nonce and resumption_master_secret
    /// (typically 32 bytes for SHA-256 based suites).
    ///
    /// **Interactions:** Takes priority over `external_psk` if both are set.
    ///
    /// **Default:** null (no resumption PSK).
    resumption_psk: ?[]const u8 = null,

    /// Session ticket identity for resumption (RFC 8446 §4.6.1).
    /// This is the opaque ticket value received from the server in NewSessionTicket.
    ///
    /// **Role:** Client only.
    ///
    /// **Requires:** `resumption_psk` must also be set.
    ///
    /// **Default:** null (no resumption ticket).
    resumption_ticket: ?[]const u8 = null,

    /// Obfuscated ticket age add value from NewSessionTicket (RFC 8446 §4.6.1).
    ///
    /// **Role:** Client only.
    ///
    /// **Requires:** `resumption_psk` and `resumption_ticket` must also be set.
    ///
    /// **Valid range:** 0 to 2^32-1 (u32). Value received from server's NewSessionTicket.
    ///
    /// **Default:** 0 (no obfuscated ticket age).
    resumption_ticket_age_add: u32 = 0,
};
