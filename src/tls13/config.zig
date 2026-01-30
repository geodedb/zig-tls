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
    /// Negotiation: First match between client offer and server preference wins.
    /// Supports TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, and TLS_CHACHA20_POLY1305_SHA256.
    ///
    /// Default: [TLS_AES_128_GCM_SHA256]
    supported_cipher_suites: []const tls13_full.CipherSuite = &.{
        tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256,
        tls13_full.CipherSuite.TLS_AES_256_GCM_SHA384,
        tls13_full.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    },

    /// Named groups advertised for ECDHE key agreement (RFC 8446 §4.2.7).
    /// Used in supported_groups and key_share extensions.
    ///
    /// Negotiation: Client sends key_share for preferred groups; server selects one.
    /// Currently focused on X25519 for QUIC implementations.
    ///
    /// Default: [x25519]
    supported_groups: []const tls13_full.NamedGroup = &.{tls13_full.NamedGroup.x25519},

    /// Signature algorithms allowed for certificate authentication (RFC 8446 §4.2.3).
    /// Sent in signature_algorithms extension, used to verify CertificateVerify.
    ///
    /// Common schemes: ed25519, ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256.
    /// Server selects one supported by both peers for signing transcript.
    ///
    /// Default: [ed25519]
    supported_signature_schemes: []const tls13_full.SignatureScheme = &.{tls13_full.SignatureScheme.ed25519},

    /// Ordered list of ALPN protocol identifiers to negotiate (RFC 7301).
    /// Sent in application_layer_protocol_negotiation extension.
    ///
    /// Server selects first match in its preference order from client's list.
    /// Common values: ["h3"] for HTTP/3, ["h2"] for HTTP/2.
    ///
    /// null = ALPN not negotiated (acceptable for some QUIC applications).
    alpn_protocols: ?[]const []const u8 = null,

    /// Raw QUIC transport parameters to advertise (RFC 9001 §8.2).
    /// Carried in quic_transport_parameters extension (0x0039).
    ///
    /// - Client: Sent in ClientHello extensions
    /// - Server: Sent in EncryptedExtensions
    ///
    /// Format: Opaque binary blob parsed by QUIC layer (not TLS).
    /// Contains max_idle_timeout, initial_max_data, etc.
    ///
    /// null = No transport parameters (will cause handshake failure in QUIC).
    quic_transport_parameters: ?[]const u8 = null,

    /// Enable receipt and processing of 0-RTT early data (RFC 8446 §4.2.10).
    /// When true, server accepts early_data extension and processes 0-RTT packets.
    ///
    /// Requires:
    /// - PSK resumption with compatible cipher suite
    /// - Anti-replay protection (zero_rtt.zig)
    /// - Application-level replay safety
    ///
    /// Default: false (0-RTT disabled)
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

    /// DER-encoded server certificate (leaf) for authentication (Server role only).
    /// RFC 8446 §4.4.2: Certificate message contains certificate_list.
    ///
    /// Must be valid X.509v3 certificate with:
    /// - digitalSignature key usage
    /// - serverAuth extended key usage
    /// - Valid subject alternative names for SNI matching
    ///
    /// null = No certificate (client role or testing).
    server_cert_der: ?[]const u8 = null,

    /// DER-encoded private key (PKCS#8 format) for server authentication.
    /// Used to generate CertificateVerify signature over transcript hash (RFC 8446 §4.4.3).
    ///
    /// Must correspond to public key in server_cert_der.
    /// Supported key types: Ed25519, ECDSA P-256/P-384, RSA-PSS.
    ///
    /// null = No private key (client role or testing).
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

    /// Require Signed Certificate Timestamps (SCTs). When true, the handshake
    /// aborts if no SCT list is present or if the list is empty or rejected by
    /// `on_sct_list`.
    require_scts: bool = false,

    /// Optional callback invoked with the parsed SCT list for additional
    /// validation or telemetry. The callback must not retain references to the
    /// provided slice beyond its lifetime.
    on_sct_list: ?*const fn ([]const sct.SignedCertificateTimestamp) anyerror!void = null,

    /// Server name (SNI) for certificate hostname validation (Client role only).
    /// RFC 6066 §3: Server Name Indication extension.
    ///
    /// When set, the client will:
    /// - Include SNI extension in ClientHello
    /// - Validate server certificate against this hostname (RFC 5280 §4.2.1.6)
    ///
    /// Example: "example.com"
    ///
    /// null = No SNI extension (hostname validation skipped).
    server_name: ?[]const u8 = null,

    /// Skip certificate validation for testing purposes.
    /// **WARNING**: Setting this to true disables ALL certificate validation!
    /// Only use for testing with self-signed certificates.
    ///
    /// When true:
    /// - Certificate chain validation is skipped
    /// - Hostname/SNI validation is skipped
    /// - Expiry checks are skipped
    ///
    /// Default: false (full validation required)
    allow_insecure: bool = false,

    /// Pre-shared key for session resumption (Client role only).
    /// If set, the client will offer this PSK in the ClientHello.
    /// RFC 8446 §4.2.11: pre_shared_key extension.
    resumption_psk: ?[]const u8 = null,

    /// Session ticket identity for resumption (Client role only).
    /// This is the opaque ticket value received from the server in NewSessionTicket.
    /// Required if resumption_psk is set.
    /// RFC 8446 §4.6.1: ticket field from NewSessionTicket message.
    resumption_ticket: ?[]const u8 = null,

    /// Obfuscated ticket age add value from NewSessionTicket (Client role only).
    /// Required if resumption_psk is set.
    /// RFC 8446 §4.6.1: ticket_age_add field from NewSessionTicket message.
    resumption_ticket_age_add: u32 = 0,
};
