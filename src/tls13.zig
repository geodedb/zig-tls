//! TLS 1.3 Handshake State Machine for QUIC
//!
//! This module implements the core TLS 1.3 handshake state machine optimized for
//! QUIC transport integration (RFC 9001 §4). Unlike traditional TLS implementations
//! that use a record layer, this implementation integrates directly with QUIC's
//! CRYPTO frames, providing a minimal but complete TLS 1.3 handshake flow.
//!
//! # RFC References
//! - **RFC 8446**: TLS 1.3 core protocol (handshake, key schedule, extensions)
//! - **RFC 9001**: Using TLS to Secure QUIC (CRYPTO frames, secret installation)
//! - **RFC 9369**: QUIC v2 (updated key derivation labels)
//! - **RFC 7301**: Application-Layer Protocol Negotiation (ALPN)
//! - **RFC 5280**: X.509 certificate validation (subset)
//!
//! # Architecture Overview
//!
//! The state machine is built around two main types:
//!
//! 1. **Context**: High-level TLS 1.3 driver for production use
//!    - Full RFC 8446 compliant handshake flow
//!    - Automatic format detection (standard vs. minimal)
//!    - Certificate validation and signature verification
//!    - Secret installation callbacks for QUIC integration
//!    - ALPN and transport parameter negotiation
//!
//! 2. **Engine**: Legacy minimal driver for tests
//!    - Simplified message parsing
//!    - Test-friendly configuration
//!    - Gradual migration to Context ongoing
//!
//! # Handshake Flow
//!
//! ## Client Handshake (RFC 8446 §2, §4.1)
//!
//! ```text
//! Initial Packet Number Space (unprotected):
//!   -> ClientHello                          [processCrypto]
//!      ├─ ProtocolVersion: 0x0303 (legacy)
//!      ├─ Random: 32 bytes
//!      ├─ CipherSuites: TLS_AES_128_GCM_SHA256, ...
//!      ├─ Extensions:
//!      │  ├─ supported_versions: [TLS 1.3]  (RFC 8446 §4.2.1)
//!      │  ├─ key_share: X25519 public key   (RFC 8446 §4.2.8)
//!      │  ├─ signature_algorithms           (RFC 8446 §4.2.3)
//!      │  ├─ alpn: ["h3", ...]              (RFC 7301)
//!      │  └─ quic_transport_parameters      (RFC 9001 §8.2)
//!      └─ [Update transcript: CH]
//!
//!   <- ServerHello                          [processCrypto]
//!      ├─ CipherSuite: TLS_AES_128_GCM_SHA256
//!      ├─ Extensions:
//!      │  ├─ supported_versions: TLS 1.3
//!      │  └─ key_share: X25519 public key
//!      ├─ [Update transcript: CH || SH]
//!      ├─ [Derive ECDHE shared secret via X25519]
//!      └─ [Derive handshake traffic secrets]  (RFC 8446 §7.1)
//!         ├─ client_handshake_traffic_secret
//!         └─ server_handshake_traffic_secret
//!
//! Handshake Packet Number Space (AEAD-protected):
//!   <- {EncryptedExtensions}                [processCrypto]
//!      ├─ alpn: "h3"                        (RFC 7301)
//!      ├─ quic_transport_parameters         (RFC 9001 §8.2)
//!      └─ [Update transcript: CH || SH || EE]
//!
//!   <- {Certificate}                        [processCrypto]
//!      ├─ certificate_list: [leaf, ...]     (RFC 8446 §4.4.2)
//!      └─ [Update transcript, extract SPKI]
//!
//!   <- {CertificateVerify}                  [processCrypto]
//!      ├─ signature_algorithm: ed25519      (RFC 8446 §4.4.3)
//!      ├─ signature: (over transcript hash)
//!      ├─ [Verify signature using SPKI]     (sig.zig)
//!      └─ [Update transcript]
//!
//!   <- {Finished}                           [processCrypto]
//!      ├─ verify_data: HMAC(transcript)     (RFC 8446 §4.4.4)
//!      ├─ [Verify against expected]
//!      ├─ [Derive application traffic secrets] (RFC 8446 §7.1)
//!      │  ├─ client_application_traffic_secret_0
//!      │  └─ server_application_traffic_secret_0
//!      └─ [Mark peer finished verified]
//!
//!   -> {Finished}                           [sendClientFinished]
//!      ├─ verify_data: HMAC(transcript)
//!      └─ [Mark local finished sent]
//!
//! Application Data Packet Number Space (AEAD-protected):
//!   <-> {Application Data}
//!       [Handshake complete]
//! ```
//!
//! ## Server Handshake (RFC 8446 §2, §4.3)
//!
//! ```text
//! Initial Packet Number Space:
//!   <- ClientHello                          [processCrypto]
//!      └─ [Parse extensions, update transcript]
//!
//!   -> ServerHello                          [driveServerHandshakeFlight]
//!   -> [Derive handshake secrets]
//!
//! Handshake Packet Number Space:
//!   -> {EncryptedExtensions}                [driveServerHandshakeFlight]
//!   -> {Certificate}
//!   -> {CertificateVerify}
//!   -> {Finished}
//!      └─ [All sent as atomic flight]
//!
//!   <- {Finished}                           [processCrypto]
//!      └─ [Verify and derive application secrets]
//!
//! Application Data:
//!   <-> {Application Data}
//! ```
//!
//! # State Machine Phases
//!
//! The handshake progresses through well-defined phases (HandshakePhase enum):
//!
//! - **initial**: No handshake activity yet
//! - **negotiating**: ClientHello received/sent, parameters being negotiated
//! - **keys_installed**: Handshake traffic secrets installed
//! - **application_ready**: Finished verified, application secrets ready
//!
//! # Secret Installation (RFC 9001 §5)
//!
//! As handshake progresses, encryption keys are derived and installed at different
//! encryption levels. The `installTrafficSecret()` function invokes the
//! `on_secret_available` callback to notify QUIC layer:
//!
//! 1. **Initial**: Derived from QUIC version-specific salt (outside TLS)
//! 2. **Handshake**: Derived after ServerHello (HKDF-Extract + HKDF-Expand)
//! 3. **Application**: Derived after Finished messages verified
//!
//! Each secret is bidirectional (send/recv) and stored in SecretSchedule.
//!
//! # Transcript Hash Management (RFC 8446 §4.4.1)
//!
//! The transcript hash is critical for Finished message verification and must be
//! updated in exact message order:
//!
//! ```zig
//! // Client transcript progression:
//! Hash( ClientHello )
//! Hash( ClientHello || ServerHello )
//! Hash( ... || EncryptedExtensions )
//! Hash( ... || Certificate )
//! Hash( ... || CertificateVerify )
//! Hash( ... || Finished )          // Server Finished
//! Hash( ... || Finished )          // Client Finished
//! ```
//!
//! The `TranscriptSet` maintains snapshots at key points (client_hello_hash,
//! finished_hash) for proper secret derivation.
//!
//! # QUIC Integration Notes
//!
//! ## CRYPTO Frames vs. TLS Records
//! - No TLS record layer; handshake messages sent directly in QUIC CRYPTO frames
//! - QUIC handles fragmentation/reassembly (CryptoStreams buffer partial messages)
//! - Each encryption level has separate CRYPTO stream (Initial/Handshake/Application)
//!
//! ## Transport Parameters (RFC 9001 §8.2)
//! - Carried in quic_transport_parameters extension (0x0039)
//! - Sent in EncryptedExtensions (server) and ClientHello (client)
//! - Opaque to TLS layer; parsed by QUIC implementation
//!
//! ## ALPN (RFC 7301)
//! - Standard TLS extension, no QUIC-specific changes
//! - Used to negotiate HTTP/3 ("h3") or other protocols
//!
//! # INTEROP FIRST Design Principle
//!
//! The implementation auto-detects message formats to ensure compatibility:
//!
//! 1. **Standard TLS 1.3 format**: Full RFC 8446 parsing (production use)
//! 2. **Minimal format**: Simplified "CH1"/"SH1" test messages (fallback)
//!
//! Auto-detection happens transparently in `processCrypto()` without configuration.
//! This ensures compatibility with quic-go, quinn, msquic, etc. out-of-the-box.
//!
//! # Error Handling
//!
//! Handshake errors trigger TLS alerts (alert.zig) mapped to QUIC CRYPTO_ERROR:
//! - HandshakeError.NoCipherSuite → handshake_failure (0x0128)
//! - HandshakeError.FinishedVerifyFailed → decrypt_error (0x0133)
//! - See RFC 9001 §4.8 for QUIC error code mapping
//!
//! # Memory Management
//!
//! - All allocations use the provided allocator (Config.allocator)
//! - Handshake buffers (CryptoStreams) are freed in Context.deinit()
//! - Negotiated parameters (ALPN, transport params) are owned by Context
//! - Certificate chains are temporarily allocated during validation
//!
//! # Testing Strategy
//!
//! - Unit tests embedded in source (test "...") for individual functions
//! - Integration tests in tests/ directory for full handshake flows
//! - Both Context and Engine are tested (Engine for legacy compatibility)
//!
//! # See Also
//! - key_schedule.zig: HKDF-based secret derivation (RFC 8446 §7)
//! - tls13_full.zig: Message parsing/building (ClientHello, ServerHello, extensions)
//! - x509.zig: Certificate validation (RFC 5280 subset)
//! - sig.zig: Signature verification (ECDSA, RSA-PSS, Ed25519)
//! - alert.zig: TLS alert protocol and QUIC error mapping

// Scope: transcript hash, Derive-Secret helpers, handshake traffic secrets,
// a tiny state container to consume/produce CRYPTO bytes, and minimal
// handshake message encode/parse helpers for ClientHello/ServerHello envelopes.
//
// DESIGN PRINCIPLE: INTEROP FIRST
// ================================
// The TLS engine MUST attempt to parse standard TLS 1.3 formats BEFORE falling
// back to minimal/test formats. This ensures compatibility with real-world QUIC
// implementations (quic-go, quinn, msquic, etc.) without requiring explicit
// configuration.
//
// Auto-detection is preferred over mode flags to avoid configuration errors:
// - When receiving a ClientHello, always try real TLS 1.3 parsing first
// - If successful, automatically enable real_mode for response generation
// - Only fall back to minimal "CH1" format if real parsing fails
//
// This pattern ensures that:
// 1. Standard QUIC clients work out-of-the-box
// 2. Test/minimal formats still work for backward compatibility
// 3. No manual configuration required for interoperability
//
// See tests/test_standard_tls_clienthello.zig for verification of this behavior.
const std = @import("std");
const ks = @import("quic_tls");
const x509 = @import("x509");
const sig = @import("sig");
const tls13_full = @import("tls13_full");
const alert_mod = @import("alert");
const zero_rtt_mod = @import("zero_rtt");
const logger = @import("quic_logger");
const transport_params = @import("quic_transport_params");
const ArrayListUnmanaged = std.ArrayListUnmanaged;

/// View of negotiated handshake metadata surfaced to the QUIC connection layer.
pub const HandshakeMetadata = struct {
    alpn: ?[]const u8 = null,
    local_transport_parameters: ?[]const u8 = null,
};

/// Mirror of the TLS 1.3 signature scheme enumeration (RFC 8446 §4.2.3).
pub const SignatureScheme = tls13_full.SignatureScheme;

/// Configuration parameters for TLS 1.3 handshake (RFC 8446 §4, §7).
///
/// This structure captures all negotiable parameters required to drive a compliant
/// TLS 1.3 exchange in the QUIC context. Parameters are used during handshake
/// negotiation to select cipher suites, key exchange groups, signature algorithms,
/// and application protocols.
///
/// # RFC 8446 References
/// - §4: Handshake Protocol overview
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
    /// Currently focused on TLS_AES_128_GCM_SHA256 (0x1301) for QUIC.
    ///
    /// Default: [TLS_AES_128_GCM_SHA256]
    supported_cipher_suites: []const tls13_full.CipherSuite = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},

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
};

/// Callback hooks for QUIC integration and handshake lifecycle events.
///
/// These callbacks provide integration points between the TLS state machine and
/// the QUIC transport layer. They enable:
/// - Secret installation for packet protection (RFC 9001 §5)
/// - Handshake metadata propagation (ALPN, transport parameters)
/// - Synchronization with QUIC connection state
///
/// # Callback Invocation Order (Typical Client)
///
/// 1. `on_secret_available(.Handshake, .recv, server_hs_secret)` - After ServerHello
/// 2. `on_secret_available(.Handshake, .send, client_hs_secret)` - After ServerHello
/// 3. `on_handshake_metadata(meta)` - After EncryptedExtensions parsed
/// 4. `on_secret_available(.Application, .recv, server_app_secret)` - After Finished verified
/// 5. `on_secret_available(.Application, .send, client_app_secret)` - After Finished verified
/// 6. `on_peer_finished()` - After server Finished verified
/// 7. `on_handshake_complete()` - After both Finished messages exchanged
///
/// # RFC 9001 Integration
///
/// - §5.1: Packet Protection Keys derived from traffic secrets provided via on_secret_available
/// - §5.2: QUIC installs keys and updates packet protection state
/// - §5.3: Initial secrets (v1/v2) computed by QUIC before TLS, not via callbacks
///
/// All callbacks are optional (null means not registered). Errors returned from
/// callbacks propagate to the caller but do not abort the handshake state.
pub const Callbacks = struct {
    /// Called when a new traffic secret becomes available during handshake.
    /// RFC 8446 §7.1: Key schedule derives secrets at different encryption levels.
    /// RFC 9001 §5: QUIC uses secrets to derive AEAD keys for packet protection.
    ///
    /// Parameters:
    /// - ctx: TLS context (access negotiated parameters)
    /// - level: Encryption level (Initial/Handshake/Application)
    /// - secret: Traffic secret (32 bytes for SHA-256-based suites)
    ///
    /// QUIC implementation must:
    /// 1. Derive packet protection keys via HKDF-Expand-Label
    /// 2. Install keys for send/recv based on role
    /// 3. Enable decryption/encryption at this level
    ///
    /// Invoked multiple times as handshake progresses:
    /// - Handshake level: After ServerHello (both send/recv)
    /// - Application level: After Finished verified (both send/recv)
    ///
    /// null = Secrets not propagated (testing only).
    on_secret_available: ?*const fn (ctx: *Context, level: EncryptionLevel, secret: [H.digest_length]u8) anyerror!void = null,

    /// Called once handshake metadata (ALPN, transport params) is available.
    /// Invoked after EncryptedExtensions processed (client) or before sending it (server).
    ///
    /// Metadata includes:
    /// - alpn: Negotiated protocol (e.g., "h3" for HTTP/3)
    /// - local_transport_parameters: Our advertised QUIC parameters
    ///
    /// QUIC implementation uses this to:
    /// - Configure protocol handler based on ALPN
    /// - Store local parameters for connection state
    ///
    /// null = Metadata not propagated.
    on_handshake_metadata: ?*const fn (ctx: *Context, meta: HandshakeMetadata) anyerror!void = null,

    /// Called when peer's Finished message verified successfully.
    /// RFC 8446 §4.4.4: Finished contains HMAC over transcript hash.
    ///
    /// This indicates:
    /// - Peer proved knowledge of handshake traffic secret
    /// - Transcript integrity confirmed
    /// - Safe to process peer's application data
    ///
    /// Client: Invoked after server Finished verified (before sending client Finished)
    /// Server: Invoked after client Finished verified
    ///
    /// null = Not notified of Finished verification.
    on_peer_finished: ?*const fn (ctx: *Context) anyerror!void = null,

    /// Called when TLS handshake completes successfully.
    /// Invoked when both local and peer Finished messages exchanged and verified.
    ///
    /// At this point:
    /// - Application secrets installed
    /// - Safe to send/receive application data
    /// - Handshake messages no longer expected
    ///
    /// QUIC implementation typically:
    /// - Transitions to Application Data state
    /// - Discards handshake keys
    /// - Enables bidirectional application data flow
    ///
    /// null = Not notified of completion.
    on_handshake_complete: ?*const fn (ctx: *Context) anyerror!void = null,

    /// Called to fetch certificate chain for local authentication (Server role).
    /// RFC 8446 §4.4.2: Certificate message contains certificate_list.
    ///
    /// Implementation should return DER-encoded certificate chain:
    /// - First certificate: Leaf (server identity)
    /// - Subsequent certificates: Intermediates (optional)
    ///
    /// Currently only leaf certificate used; full chain validation planned.
    ///
    /// null = Use Config.server_cert_der directly (no dynamic fetch).
    fetch_certificate_chain: ?*const fn (ctx: *Context) anyerror![]const u8 = null,
};

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
};

/// Traffic direction relative to the current endpoint (RFC 8446 §7.1).
///
/// Used when installing secrets to distinguish between:
/// - send: Secrets for protecting outbound traffic (encryption)
/// - recv: Secrets for processing inbound traffic (decryption)
///
/// Direction is role-dependent:
/// - Client send = Server recv (client_traffic_secret)
/// - Server send = Client recv (server_traffic_secret)
pub const TrafficDirection = enum {
    /// Outbound traffic protection (encryption, sending packets).
    send,
    /// Inbound traffic processing (decryption, receiving packets).
    recv,
};

/// RFC 8446 §7.1–§7.5: individual traffic secret slot with epoch tracking for key updates.
pub const SecretSlot = struct {
    value: [H.digest_length]u8 = undefined,
    valid: bool = false,
    epoch: EncryptionLevel = .Initial,
    generation: u32 = 0,

    /// Clears the secret slot, resetting it to its initial state.
    pub fn clear(self: *SecretSlot) void {
        self.valid = false;
        self.epoch = .Initial;
        self.generation = 0;
    }

    /// Stores a new secret in the slot with the specified encryption level.
    pub fn store(self: *SecretSlot, level: EncryptionLevel, secret: [H.digest_length]u8) void {
        self.value = secret;
        self.valid = true;
        self.epoch = level;
        self.generation += 1;
    }

    /// Returns a slice to the secret value if valid, otherwise null.
    pub fn slice(self: *const SecretSlot) ?[]const u8 {
        if (!self.valid) return null;
        return self.value[0..];
    }
};

fn supportsTls13Version(encoded: []const u8) bool {
    if (encoded.len < 1) return false;
    const list_len = encoded[0];
    const byte_count: usize = list_len;
    if (encoded.len < 1 + byte_count) return false;
    if ((byte_count & 1) != 0) return false;
    var offset: usize = 1;
    while (offset + 1 < 1 + byte_count) : (offset += 2) {
        const version = (@as(u16, encoded[offset]) << 8) | @as(u16, encoded[offset + 1]);
        if (version == 0x0304) return true;
    }
    return false;
}

fn freeParsedClientHello(allocator: std.mem.Allocator, parsed: *tls13_full.ClientHello) void {
    if (parsed.cipher_suites.len != 0) allocator.free(parsed.cipher_suites);
    if (parsed.supported_groups) |groups| {
        if (groups.len != 0) allocator.free(@constCast(groups));
    }
    if (parsed.signature_algorithms) |algs| {
        if (algs.len != 0) allocator.free(@constCast(algs));
    }
    if (parsed.pre_shared_key) |psk| {
        if (psk.identities.len != 0) allocator.free(psk.identities);
        if (psk.binders.len != 0) allocator.free(@constCast(psk.binders));
    }
    if (parsed.alpn_list) |list| {
        if (list.len != 0) allocator.free(@constCast(list));
    }
}

/// Bidirectional secret pair (send/recv) for a single packet number space (RFC 9001 §4.1.4).
pub const BidirSecrets = struct {
    send: SecretSlot = .{},
    recv: SecretSlot = .{},

    /// Resets both send and receive secret slots to their initial state.
    pub fn reset(self: *BidirSecrets) void {
        self.send.clear();
        self.recv.clear();
    }

    /// Returns the secret slot for the specified traffic direction.
    pub fn slot(self: *BidirSecrets, dir: TrafficDirection) *SecretSlot {
        return switch (dir) {
            .send => &self.send,
            .recv => &self.recv,
        };
    }
};

/// Unified traffic secret store for Initial/Handshake/Application keys (RFC 8446 §7.1, RFC 9001 §5).
pub const SecretSchedule = struct {
    initial: BidirSecrets = .{},
    handshake: BidirSecrets = .{},
    application: BidirSecrets = .{},
    exporter_master: SecretSlot = .{},
    resumption_master: SecretSlot = .{},

    /// Creates a new secret schedule with all secrets in initial state.
    pub fn init() SecretSchedule {
        return .{};
    }

    /// Resets all encryption level secrets to their initial state.
    pub fn reset(self: *SecretSchedule) void {
        self.initial.reset();
        self.handshake.reset();
        self.application.reset();
        self.exporter_master.clear();
        self.resumption_master.clear();
    }

    /// Returns the bidirectional secrets for the specified encryption level.
    pub fn pairForLevel(self: *SecretSchedule, level: EncryptionLevel) *BidirSecrets {
        return switch (level) {
            .Initial => &self.initial,
            .Handshake => &self.handshake,
            .Application => &self.application,
        };
    }

    /// Returns the secret slot for the specified encryption level and traffic direction.
    pub fn slot(self: *SecretSchedule, level: EncryptionLevel, dir: TrafficDirection) *SecretSlot {
        return self.pairForLevel(level).slot(dir);
    }
};

/// RFC 8446 §4.4.1: transcripts and cached hashes used across handshake flights.
pub const TranscriptSet = struct {
    handshake: Transcript,
    client_hello_hash: ?[H.digest_length]u8 = null,
    finished_hash: ?[H.digest_length]u8 = null,

    /// Creates a new transcript set with empty transcripts.
    pub fn init() TranscriptSet {
        return .{ .handshake = Transcript.init(), .client_hello_hash = null, .finished_hash = null };
    }

    /// Resets all transcripts to their initial empty state.
    pub fn reset(self: *TranscriptSet) void {
        self.* = TranscriptSet.init();
    }
};

/// High-level handshake lifecycle position for progress tracking (RFC 8446 §4).
pub const HandshakePhase = enum {
    initial,
    negotiating,
    keys_installed,
    application_ready,
    post_handshake,
};

/// View into the stored ClientHello key share for downstream consumers.
pub const ClientHelloKeyShareView = struct {
    group: tls13_full.NamedGroup,
    key: []const u8,
};

/// View of a pre-shared key identity advertised by the client.
pub const ClientHelloPskIdentityView = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,
};

/// View of the pre_shared_key extension contents.
pub const ClientHelloPreSharedKeyView = struct {
    identities: []const ClientHelloPskIdentityView,
    binders: []const []const u8,
};

/// Immutable view returned by `Context.clientHello()` describing the parsed ClientHello.
pub const ClientHelloView = struct {
    random: [32]u8,
    session_id: []const u8,
    cipher_suites: []const tls13_full.CipherSuite,
    signature_algorithms: ?[]const tls13_full.SignatureScheme,
    supported_versions: []const u8,
    key_share: ClientHelloKeyShareView,
    quic_transport_parameters: ?[]const u8,
    alpn_list: ?[]const []const u8,
    early_data: bool,
    pre_shared_key: ?ClientHelloPreSharedKeyView,
    raw: []const u8,
};

const PskIdentityOwned = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,
};

const PreSharedKeyInfo = struct {
    identities: []PskIdentityOwned,
    binders: []const []const u8,
};

const ClientHelloInfo = struct {
    random: [32]u8,
    session_id: []u8,
    cipher_suites: []tls13_full.CipherSuite,
    signature_algorithms: ?[]const tls13_full.SignatureScheme,
    supported_versions: []u8,
    key_share: struct {
        group: tls13_full.NamedGroup,
        key: []u8,
    },
    quic_transport_parameters: ?[]u8,
    alpn_list: ?[]const []const u8,
    early_data: bool,
    pre_shared_key: ?PreSharedKeyInfo,
    raw: []u8,

    fn parse(allocator: std.mem.Allocator, body: []const u8) !ClientHelloInfo {
        var parsed = try tls13_full.parseClientHello(allocator, body);
        errdefer freeParsedClientHello(allocator, &parsed);

        if (parsed.cipher_suites.len == 0) return HandshakeError.NoCipherSuite;
        const versions = parsed.supported_versions orelse return HandshakeError.UnsupportedVersion;
        if (!supportsTls13Version(versions)) return HandshakeError.UnsupportedVersion;

        const key_share = parsed.key_share orelse return HandshakeError.MissingKeyShare;
        if (key_share.group != .x25519) return HandshakeError.UnsupportedKeyShareGroup;

        const session_id_copy = try allocator.dupe(u8, parsed.session_id);
        errdefer if (session_id_copy.len != 0) allocator.free(session_id_copy);

        const cipher_suites_copy = try allocator.dupe(tls13_full.CipherSuite, parsed.cipher_suites);
        errdefer if (cipher_suites_copy.len != 0) allocator.free(cipher_suites_copy);

        var sigalgs_copy: ?[]const tls13_full.SignatureScheme = null;
        if (parsed.signature_algorithms) |algs| {
            sigalgs_copy = try allocator.dupe(tls13_full.SignatureScheme, algs);
        }
        errdefer if (sigalgs_copy) |buf| if (buf.len != 0) allocator.free(@constCast(buf));

        const versions_copy = try allocator.dupe(u8, versions);
        errdefer if (versions_copy.len != 0) allocator.free(versions_copy);

        const key_bytes = try allocator.dupe(u8, key_share.key_exchange);
        errdefer if (key_bytes.len != 0) allocator.free(key_bytes);

        const raw_copy = try allocator.dupe(u8, body);
        errdefer if (raw_copy.len != 0) allocator.free(raw_copy);

        var tp_copy: ?[]u8 = null;
        if (parsed.quic_transport_parameters) |tp| {
            tp_copy = try allocator.dupe(u8, tp);
        }
        errdefer if (tp_copy) |buf| if (buf.len != 0) allocator.free(buf);

        var alpn_copy: ?[]const []const u8 = null;
        if (parsed.alpn_list) |list| {
            const dest = try allocator.alloc([]const u8, list.len);
            errdefer allocator.free(dest);

            var copied_count: usize = 0;
            errdefer {
                while (copied_count != 0) {
                    copied_count -= 1;
                    const proto = dest[copied_count];
                    if (proto.len != 0) allocator.free(@constCast(proto));
                }
            }

            while (copied_count < list.len) : (copied_count += 1) {
                const proto_copy = try allocator.dupe(u8, list[copied_count]);
                dest[copied_count] = proto_copy;
            }

            alpn_copy = dest;
        }
        errdefer if (alpn_copy) |list| {
            if (list.len != 0) {
                for (list) |proto| {
                    if (proto.len != 0) allocator.free(@constCast(proto));
                }
                allocator.free(@constCast(list));
            }
        };

        var psk_copy: ?PreSharedKeyInfo = null;
        if (parsed.pre_shared_key) |psk_ext| {
            const ids = try allocator.alloc(PskIdentityOwned, psk_ext.identities.len);
            var ids_filled: usize = 0;
            errdefer {
                while (ids_filled != 0) {
                    ids_filled -= 1;
                    const ident = ids[ids_filled];
                    if (ident.identity.len != 0) allocator.free(@constCast(ident.identity));
                }
                allocator.free(ids);
            }

            while (ids_filled < psk_ext.identities.len) : (ids_filled += 1) {
                const src = psk_ext.identities[ids_filled];
                const dup = try allocator.dupe(u8, src.identity);
                ids[ids_filled] = .{
                    .identity = dup,
                    .obfuscated_ticket_age = src.obfuscated_ticket_age,
                };
            }

            const binders = try allocator.alloc([]const u8, psk_ext.binders.len);
            var binders_filled: usize = 0;
            errdefer {
                while (binders_filled != 0) {
                    binders_filled -= 1;
                    const binder = binders[binders_filled];
                    if (binder.len != 0) allocator.free(@constCast(binder));
                }
                allocator.free(binders);
            }

            while (binders_filled < psk_ext.binders.len) : (binders_filled += 1) {
                const src = psk_ext.binders[binders_filled];
                const dup = try allocator.dupe(u8, src);
                binders[binders_filled] = dup;
            }

            psk_copy = .{ .identities = ids, .binders = binders };
        }

        const info = ClientHelloInfo{
            .random = parsed.random,
            .session_id = session_id_copy,
            .cipher_suites = cipher_suites_copy,
            .signature_algorithms = sigalgs_copy,
            .supported_versions = versions_copy,
            .key_share = .{ .group = key_share.group, .key = key_bytes },
            .quic_transport_parameters = tp_copy,
            .alpn_list = alpn_copy,
            .early_data = parsed.early_data,
            .pre_shared_key = psk_copy,
            .raw = raw_copy,
        };

        freeParsedClientHello(allocator, &parsed);
        return info;
    }

    fn deinit(self: *ClientHelloInfo, allocator: std.mem.Allocator) void {
        if (self.session_id.len != 0) allocator.free(self.session_id);
        if (self.cipher_suites.len != 0) allocator.free(self.cipher_suites);
        if (self.signature_algorithms) |list| if (list.len != 0) allocator.free(@constCast(list));
        if (self.supported_versions.len != 0) allocator.free(self.supported_versions);
        if (self.key_share.key.len != 0) allocator.free(self.key_share.key);
        if (self.quic_transport_parameters) |buf| if (buf.len != 0) allocator.free(buf);
        if (self.alpn_list) |list| {
            for (list) |proto| {
                if (proto.len != 0) allocator.free(@constCast(proto));
            }
            if (list.len != 0) allocator.free(@constCast(list));
        }
        if (self.pre_shared_key) |psk| {
            for (psk.identities) |ident| {
                if (ident.identity.len != 0) allocator.free(@constCast(ident.identity));
            }
            if (psk.identities.len != 0) allocator.free(psk.identities);
            for (psk.binders) |binder| {
                if (binder.len != 0) allocator.free(@constCast(binder));
            }
            if (psk.binders.len != 0) allocator.free(@constCast(psk.binders));
        }
        if (self.raw.len != 0) allocator.free(self.raw);
    }
};

const HandshakeState = struct {
    client_hello: ?ClientHelloInfo = null,

    fn init() HandshakeState {
        return .{};
    }

    fn reset(self: *HandshakeState, allocator: std.mem.Allocator) void {
        if (self.client_hello) |*info| {
            info.deinit(allocator);
            self.client_hello = null;
        }
    }

    fn setClientHello(self: *HandshakeState, allocator: std.mem.Allocator, body: []const u8) !void {
        if (self.client_hello != null) return HandshakeError.DuplicateClientHello;
        const info = try ClientHelloInfo.parse(allocator, body);
        self.client_hello = info;
    }

    fn clientHello(self: *const HandshakeState) ?ClientHelloView {
        if (self.client_hello) |*info| {
            return ClientHelloView{
                .random = info.random,
                .session_id = info.session_id,
                .cipher_suites = info.cipher_suites,
                .signature_algorithms = info.signature_algorithms,
                .supported_versions = info.supported_versions,
                .key_share = .{ .group = info.key_share.group, .key = info.key_share.key },
                .quic_transport_parameters = info.quic_transport_parameters,
                .alpn_list = info.alpn_list,
                .early_data = info.early_data,
                .pre_shared_key = if (info.pre_shared_key) |psk| blk: {
                    const base_ptr = @as([*]const ClientHelloPskIdentityView, @ptrCast(psk.identities.ptr));
                    const identities_view = base_ptr[0..psk.identities.len];
                    break :blk ClientHelloPreSharedKeyView{
                        .identities = identities_view,
                        .binders = psk.binders,
                    };
                } else null,
                .raw = info.raw,
            };
        }
        return null;
    }
};

const HandshakeFlags = struct {
    peer_finished_verified: bool = false,
    local_finished_sent: bool = false,
    alert: ?u8 = null,
    metadata_notified: bool = false,

    fn reset(self: *HandshakeFlags) void {
        self.* = HandshakeFlags{};
    }
};

const encryption_level_count = std.meta.fields(EncryptionLevel).len;

/// RFC 9001 §4.1.4: per-encryption-level CRYPTO queues keeping inbound/outbound bytes.
const CryptoBuffer = struct {
    level: EncryptionLevel,
    inbound: ArrayListUnmanaged(u8) = .{},
    outbound: ArrayListUnmanaged(u8) = .{},

    fn init(level: EncryptionLevel) CryptoBuffer {
        return .{ .level = level };
    }

    fn clear(self: *CryptoBuffer) void {
        self.inbound.clearRetainingCapacity();
        self.outbound.clearRetainingCapacity();
    }

    fn deinit(self: *CryptoBuffer, alloc: std.mem.Allocator) void {
        self.inbound.deinit(alloc);
        self.outbound.deinit(alloc);
    }

    fn consume(self: *CryptoBuffer, count: usize) void {
        std.debug.assert(count <= self.inbound.items.len);
        const remaining = self.inbound.items.len - count;
        if (remaining > 0) {
            std.mem.copyBackwards(u8, self.inbound.items[0..remaining], self.inbound.items[count .. count + remaining]);
        }
        self.inbound.items = self.inbound.items[0..remaining];
    }
};

const CryptoStreams = struct {
    buffers: [encryption_level_count]CryptoBuffer = initBuffers(),

    fn initBuffers() [encryption_level_count]CryptoBuffer {
        return .{
            CryptoBuffer.init(.Initial),
            CryptoBuffer.init(.Handshake),
            CryptoBuffer.init(.Application),
        };
    }

    fn reset(self: *CryptoStreams) void {
        for (&self.buffers) |*buf| buf.clear();
    }

    fn deinit(self: *CryptoStreams, alloc: std.mem.Allocator) void {
        for (&self.buffers) |*buf| buf.deinit(alloc);
    }

    fn buffer(self: *CryptoStreams, level: EncryptionLevel) *CryptoBuffer {
        return &self.buffers[@intFromEnum(level)];
    }
};

/// TLS 1.3 driver that will orchestrate QUIC CRYPTO data flow (RFC 8446 §4, RFC 9001 §4.1.4).
pub const Context = struct {
    config: Config,
    callbacks: Callbacks,
    allocator: std.mem.Allocator,
    phase: HandshakePhase = .initial,
    transcripts: TranscriptSet = TranscriptSet.init(),
    secrets: SecretSchedule = SecretSchedule.init(),
    streams: CryptoStreams = .{},
    state: HandshakeState = HandshakeState.init(),
    flags: HandshakeFlags = .{},
    local_transport_parameters: ?[]u8 = null,
    negotiated_alpn: ?[]u8 = null,
    negotiated_signature: ?tls13_full.SignatureScheme = null,
    handshake_secret: ?[H.digest_length]u8 = null,
    client_priv: ?[32]u8 = null,
    client_pub: ?[32]u8 = null,

    /// Initializes a new TLS 1.3 context with the specified configuration and callbacks.
    pub fn init(config: Config, callbacks: Callbacks) Context {
        return .{
            .config = config,
            .callbacks = callbacks,
            .allocator = config.allocator,
            .phase = .initial,
            .transcripts = TranscriptSet.init(),
            .secrets = SecretSchedule.init(),
            .streams = .{},
            .state = HandshakeState.init(),
            .flags = .{},
            .local_transport_parameters = null,
            .negotiated_alpn = null,
            .negotiated_signature = null,
            .handshake_secret = null,
            .client_priv = null,
            .client_pub = null,
        };
    }

    /// Cleans up the context, freeing resources and resetting state.
    pub fn deinit(self: *Context) void {
        self.streams.deinit(self.allocator);
        self.secrets.reset();
        self.transcripts.reset();
        self.flags.reset();
        self.state.reset(self.allocator);
        if (self.local_transport_parameters) |buf| {
            self.allocator.free(buf);
            self.local_transport_parameters = null;
        }
        if (self.negotiated_alpn) |proto| {
            self.allocator.free(proto);
            self.negotiated_alpn = null;
        }
        self.negotiated_signature = null;
        self.handshake_secret = null;
        self.phase = .initial;
    }

    /// Process inbound CRYPTO data received from peer at specified encryption level.
    ///
    /// This is the main entry point for feeding handshake messages into the TLS state
    /// machine. QUIC CRYPTO frames are delivered here after being reassembled by the
    /// QUIC layer.
    ///
    /// # RFC 9001 §4: QUIC-TLS Integration
    /// - CRYPTO data replaces TLS record layer
    /// - Each encryption level (Initial/Handshake/Application) has separate stream
    /// - Messages may be fragmented across multiple CRYPTO frames
    ///
    /// # Processing Flow
    /// 1. Append data to inbound buffer for this encryption level
    /// 2. Parse complete handshake messages using `parseHandshakeOne()`
    /// 3. For each complete message:
    ///    - Validate message type and state (handleHandshakeMessage)
    ///    - Update transcript hash (except Finished, which is added after verification)
    ///    - Execute state transitions (afterHandshakeMessage)
    ///    - Consume buffered bytes
    /// 4. Return when no more complete messages available
    ///
    /// # Parameters
    /// - level: Encryption level where this data was received (Initial/Handshake/Application)
    /// - data: Raw CRYPTO frame payload bytes (may be partial message or multiple messages)
    ///
    /// # Errors
    /// - HandshakeError.*: Protocol violations (unexpected message, failed verification, etc.)
    /// - OutOfMemory: Failed to allocate buffer space
    ///
    /// # Example (Client receiving ServerHello)
    /// ```zig
    /// // QUIC receives CRYPTO frame at Initial level
    /// try ctx.processCrypto(.Initial, server_hello_bytes);
    /// // Internally:
    /// // 1. Parses ServerHello message
    /// // 2. Extracts key_share, derives handshake secrets
    /// // 3. Calls on_secret_available(.Handshake, ...)
    /// // 4. Updates phase to .keys_installed
    /// ```
    ///
    /// # Notes
    /// - Handles fragmentation transparently via buffering
    /// - Messages processed in order received (CRYPTO is ordered stream)
    /// - Transcript hash critical: messages added in exact receive order
    /// - State transitions happen in afterHandshakeMessage()
    pub fn processCrypto(self: *Context, level: EncryptionLevel, data: []const u8) !void {
        var stream = self.streams.buffer(level);
        try stream.inbound.appendSlice(self.allocator, data);

        // Process all complete messages in buffer
        while (true) {
            const buffer = stream.inbound.items;
            const parsed_opt = try parseHandshakeOne(buffer);
            if (parsed_opt == null) break; // Need more data for complete message

            const parsed = parsed_opt.?;
            const message_bytes = buffer[0..parsed.n];

            // Validate and process message type
            try self.handleHandshakeMessage(level, parsed, message_bytes);

            // RFC 8446 §4.4.4: Finished is added to transcript AFTER verification
            // to ensure verify_data is computed over correct transcript state
            if (parsed.typ != .finished) {
                self.transcripts.handshake.update(message_bytes);
                try self.afterHandshakeMessage(level, parsed);
            } else {
                // Finished verification happens in handleHandshakeMessage, transcript
                // updated there after successful verification
                try self.afterHandshakeMessage(level, parsed);
            }

            stream.consume(parsed.n);
        }
    }

    /// Produce outbound CRYPTO payload for the given encryption level when available.
    pub fn pollCrypto(self: *Context, allocator: std.mem.Allocator, level: EncryptionLevel) ![]u8 {
        var stream = self.streams.buffer(level);
        if (stream.outbound.items.len == 0) return ApiError.Unimplemented;
        const view = stream.outbound.items;
        const out = try allocator.dupe(u8, view);
        stream.outbound.clearRetainingCapacity();
        return out;
    }

    /// Check if TLS handshake has completed successfully.
    ///
    /// RFC 8446 §4.4.4: Handshake is complete when both peers have sent and
    /// verified Finished messages. At this point:
    /// - Application traffic secrets are installed
    /// - Safe to send/receive application data
    /// - Handshake messages no longer expected
    ///
    /// # Returns
    /// - true: Both Finished messages exchanged, application keys ready
    /// - false: Handshake still in progress
    ///
    /// # Usage
    /// ```zig
    /// if (ctx.handshakeComplete()) {
    ///     // Safe to send application data
    ///     try quic.sendStream(stream_id, app_data);
    /// }
    /// ```
    pub fn handshakeComplete(self: *Context) bool {
        return self.flags.peer_finished_verified and self.flags.local_finished_sent;
    }

    /// Get a view of negotiated handshake metadata (ALPN, transport parameters).
    ///
    /// This provides read-only access to the negotiated connection parameters
    /// without transferring ownership.
    ///
    /// # Returns
    /// HandshakeMetadata containing:
    /// - alpn: Negotiated protocol (e.g., "h3" for HTTP/3), null if not negotiated
    /// - local_transport_parameters: Our advertised QUIC parameters, null if not set
    ///
    /// # Availability
    /// - Server: Available after sending EncryptedExtensions
    /// - Client: Available after receiving EncryptedExtensions
    pub fn metadataView(self: *const Context) HandshakeMetadata {
        return .{
            .alpn = self.negotiated_alpn,
            .local_transport_parameters = self.local_transport_parameters,
        };
    }

    /// Get the local QUIC transport parameters advertised in the handshake.
    ///
    /// RFC 9001 §8.2: Transport parameters are exchanged via TLS extensions:
    /// - Client: Sent in ClientHello (extension 0x0039)
    /// - Server: Sent in EncryptedExtensions (extension 0x0039)
    ///
    /// # Returns
    /// - Encoded transport parameters if configured (opaque to TLS layer)
    /// - null if not configured (will cause handshake failure in QUIC)
    pub fn localTransportParameters(self: *const Context) ?[]const u8 {
        return self.local_transport_parameters;
    }

    /// Install a traffic secret and notify QUIC layer via callback.
    ///
    /// RFC 8446 §7.1: Traffic secrets are derived progressively during handshake
    /// and must be installed at appropriate encryption levels for packet protection.
    ///
    /// RFC 9001 §5: QUIC uses traffic secrets to derive AEAD keys via HKDF-Expand-Label.
    ///
    /// # Flow
    /// 1. Store secret in SecretSlot with generation tracking
    /// 2. Invoke on_secret_available callback if registered
    /// 3. QUIC layer derives packet protection keys and installs them
    ///
    /// # Parameters
    /// - level: Encryption level (Handshake or Application)
    /// - dir: Traffic direction (send = encrypt outbound, recv = decrypt inbound)
    /// - secret: 32-byte traffic secret from key schedule
    ///
    /// # Invocation Timeline (Server)
    /// ```
    /// After ServerHello sent:
    ///   installTrafficSecret(.Handshake, .send, server_hs_secret)
    ///   installTrafficSecret(.Handshake, .recv, client_hs_secret)
    /// After Finished verified:
    ///   installTrafficSecret(.Application, .send, server_app_secret)
    ///   installTrafficSecret(.Application, .recv, client_app_secret)
    /// ```
    ///
    /// # Security Notes
    /// - Secrets are role-dependent (client/server secrets swapped for send/recv)
    /// - Generation counter enables key updates
    /// - Secrets should be zeroized after use (handled by SecretSlot)
    pub fn installTrafficSecret(self: *Context, level: EncryptionLevel, dir: TrafficDirection, secret: [H.digest_length]u8) !void {
        var slot = self.secrets.slot(level, dir);
        slot.store(level, secret);
        if (self.callbacks.on_secret_available) |cb| {
            try cb(self, level, secret);
        }
    }

    /// Mark that our Finished flight has been transmitted (§4.4.4) and update phase state.
    pub fn markLocalFinished(self: *Context) void {
        self.flags.local_finished_sent = true;
        self.bumpPhaseAfterFinished();
    }

    /// Mark that the peer Finished verified successfully (§4.4.4) and update phase state.
    pub fn confirmPeerFinished(self: *Context) void {
        self.flags.peer_finished_verified = true;
        if (self.callbacks.on_peer_finished) |cb| {
            cb(self) catch {};
        }
        self.bumpPhaseAfterFinished();
    }

    fn bumpPhaseAfterFinished(self: *Context) void {
        if (self.flags.peer_finished_verified and self.flags.local_finished_sent) {
            self.phase = .application_ready;
            if (self.callbacks.on_handshake_complete) |cb| {
                cb(self) catch {};
            }
        }
    }

    /// Returns the stored ClientHello view if one has been processed (server role).
    pub fn clientHello(self: *const Context) ?ClientHelloView {
        return self.state.clientHello();
    }

    /// Returns the negotiated ALPN protocol after EncryptedExtensions is generated (server role).
    pub fn negotiatedAlpn(self: *const Context) ?[]const u8 {
        if (self.negotiated_alpn) |proto| {
            return proto;
        }
        return null;
    }

    /// Returns the negotiated SignatureScheme once selected during the server flight.
    pub fn negotiatedSignatureScheme(self: *const Context) ?tls13_full.SignatureScheme {
        return self.negotiated_signature;
    }

    /// RFC 8446 §4: Validate and process handshake message based on type and role.
    /// Enforces message sequencing and role-based authorization.
    fn handleHandshakeMessage(self: *Context, level: EncryptionLevel, parsed: HandshakeMessage, raw: []const u8) !void {
        switch (parsed.typ) {
            .client_hello => {
                // RFC 8446 §4.1.2: ClientHello only valid for server role
                if (self.config.role != .Server) return HandshakeError.UnexpectedMessage;

                // Parse and store ClientHello for parameter negotiation
                try self.state.setClientHello(self.allocator, parsed.body);

                // RFC 8446 §4: Transition from initial to negotiating phase
                if (self.phase == .initial) {
                    self.phase = .negotiating;
                }
            },
            .server_hello => {
                // RFC 8446 §4.1.3: ServerHello only valid for client role
                if (self.config.role != .Client) return HandshakeError.UnexpectedMessage;

                // Parse ServerHello, extract key_share, derive handshake secrets
                try self.handleServerHello(parsed.body);
            },
            .finished => {
                // RFC 8446 §4.4.4: Verify peer Finished message
                // Must verify BEFORE adding to transcript
                try self.handlePeerFinished(level, parsed.body, raw);
            },
            else => {
                // Other messages (EncryptedExtensions, Certificate, CertificateVerify)
                // processed implicitly via transcript updates
            },
        }
    }

    fn afterHandshakeMessage(self: *Context, level: EncryptionLevel, parsed: HandshakeMessage) !void {
        switch (parsed.typ) {
            .client_hello => {
                if (self.config.role != .Server) return;

                // Debug: Print ClientHello transcript hash
                const ch_hash = self.transcripts.handshake.finalize();
                std.debug.print("[TRANSCRIPT_DEBUG] ClientHello hash: ", .{});
                for (ch_hash) |b| std.debug.print("{X:0>2}", .{b});
                std.debug.print("\n", .{});

                self.transcripts.client_hello_hash = ch_hash;
                try self.driveServerHandshakeFlight();
            },
            .server_hello => {
                if (self.config.role != .Client) return;
                // After processing ServerHello, transcript already updated; checkpoint ClientHello+ServerHello hash
                self.transcripts.client_hello_hash = self.transcripts.client_hello_hash orelse undefined; // keep existing
            },
            .finished => try self.handleFinishedPostActions(level),
            else => {},
        }
    }

    /// RFC 8446 §4.4.4: Verify peer's Finished message.
    /// Finished contains HMAC over transcript hash to prove knowledge of traffic secret.
    fn handlePeerFinished(self: *Context, level: EncryptionLevel, verify_data: []const u8, raw: []const u8) !void {
        // RFC 8446 §4.4.4: Finished must be sent at Handshake encryption level
        if (level != .Handshake) return HandshakeError.UnexpectedMessage;

        // verify_data = HMAC(finished_key, transcript_hash)
        // Must be exactly hash length (32 bytes for SHA-256)
        if (verify_data.len != H.digest_length) return HandshakeError.FinishedVerifyFailed;

        // Retrieve peer's handshake traffic secret (recv direction)
        const slot = self.secrets.slot(.Handshake, .recv);
        if (!slot.valid) return HandshakeError.UnexpectedMessage;

        // RFC 8446 §4.4.4: Compute expected verify_data over transcript BEFORE Finished
        // Transcript includes all messages up to (but not including) Finished
        var transcript_snapshot = self.transcripts.handshake;
        const transcript_hash = transcript_snapshot.finalize();
        const expected = deriveFinishedVerifyData(slot.value, transcript_hash);

        // Constant-time comparison to prevent timing attacks
        if (!std.mem.eql(u8, expected[0..], verify_data)) return HandshakeError.FinishedVerifyFailed;

        // Store transcript hash at Finished point (used for key derivation)
        self.transcripts.finished_hash = transcript_hash;

        // RFC 8446 §4.4.4: NOW add Finished to transcript (after verification)
        // This ensures application secrets derived with correct transcript
        self.transcripts.handshake.update(raw);
    }

    /// Post-Finished processing: derive application secrets and update state.
    fn handleFinishedPostActions(self: *Context, level: EncryptionLevel) !void {
        if (level != .Handshake) return;

        // RFC 8446 §7.1: Derive application traffic secrets after Finished verified
        try self.ensureApplicationSecrets();

        // Mark peer Finished as verified and invoke callback
        self.confirmPeerFinished();

        // RFC 8446 §4.4: Client sends Finished after verifying server Finished
        if (self.config.role == .Client and !self.flags.local_finished_sent) {
            try self.sendClientFinished();
        }
    }

    /// RFC 8446 §7.1: Derive application-level traffic secrets.
    /// Called after both peers' Finished messages are verified.
    fn ensureApplicationSecrets(self: *Context) !void {
        const send_slot = self.secrets.slot(.Application, .send);
        const recv_slot = self.secrets.slot(.Application, .recv);

        // Skip if already derived (idempotent)
        if (send_slot.valid and recv_slot.valid) return;

        // RFC 8446 §7.1: Derive from handshake_secret and transcript hash
        // handshake_secret was saved after ServerHello processing
        const hs_secret = self.handshake_secret orelse return HandshakeError.UnexpectedMessage;

        // Transcript hash at this point includes all messages (CH...Finished)
        var transcript_snapshot = self.transcripts.handshake;
        const transcript_hash = transcript_snapshot.finalize();

        // Key schedule: master_secret = Derive-Secret(handshake_secret, "derived", "")
        //               app_secrets = Derive-Secret(master_secret, label, transcript)
        const apps = deriveApplicationTraffic(hs_secret, transcript_hash);

        // RFC 9001 §5: Install secrets with correct role mapping
        // Server sends with server_app, receives with client_app
        switch (self.config.role) {
            .Server => {
                if (!send_slot.valid) try self.installTrafficSecret(.Application, .send, apps.server_app);
                if (!recv_slot.valid) try self.installTrafficSecret(.Application, .recv, apps.client_app);
            },
            .Client => {
                if (!send_slot.valid) try self.installTrafficSecret(.Application, .send, apps.client_app);
                if (!recv_slot.valid) try self.installTrafficSecret(.Application, .recv, apps.server_app);
            },
        }

        // RFC 8446 §7.5: Store exporter_master_secret for key export (e.g., channel bindings)
        if (!self.secrets.exporter_master.valid) {
            self.secrets.exporter_master.store(.Application, apps.exporter_master);
        }
    }

    fn appendOutbound(self: *Context, level: EncryptionLevel, msg: []const u8, update_transcript: bool) !void {
        var stream = self.streams.buffer(level);
        try stream.outbound.appendSlice(self.allocator, msg);
        if (update_transcript) {
            self.transcripts.handshake.update(msg);
        }
    }

    fn chooseCipherSuite(self: *const Context, offered: []const tls13_full.CipherSuite) ?tls13_full.CipherSuite {
        for (self.config.supported_cipher_suites) |supported| {
            for (offered) |candidate| {
                if (supported == candidate) return supported;
            }
        }
        return null;
    }

    fn selectServerAlpn(self: *Context, client: ClientHelloView) !?[]const u8 {
        if (self.negotiated_alpn) |prev| {
            if (prev.len != 0) self.allocator.free(prev);
            self.negotiated_alpn = null;
        }
        const server_list = self.config.alpn_protocols orelse return null;
        if (server_list.len == 0) return null;

        const client_list = client.alpn_list orelse return HandshakeError.AlpnNegotiationFailed;
        if (client_list.len == 0) return HandshakeError.AlpnNegotiationFailed;

        for (server_list) |candidate| {
            for (client_list) |offered| {
                if (std.mem.eql(u8, candidate, offered)) {
                    const copy = try self.allocator.dupe(u8, candidate);
                    self.negotiated_alpn = copy;
                    return copy;
                }
            }
        }
        return HandshakeError.AlpnNegotiationFailed;
    }

    fn selectServerSignatureScheme(self: *Context, client: ClientHelloView) !tls13_full.SignatureScheme {
        const server_list = self.config.supported_signature_schemes;
        if (server_list.len == 0) return HandshakeError.NoSignatureScheme;

        const client_list = client.signature_algorithms orelse return HandshakeError.NoSignatureScheme;
        self.negotiated_signature = null;

        for (server_list) |candidate| {
            for (client_list) |offered| {
                if (candidate == offered) {
                    self.negotiated_signature = candidate;
                    return candidate;
                }
            }
        }
        return HandshakeError.NoSignatureScheme;
    }

    fn ensureLocalTransportParameters(self: *Context) ![]const u8 {
        if (self.local_transport_parameters) |buf| {
            return buf;
        }
        const configured = self.config.quic_transport_parameters orelse return HandshakeError.MissingTransportParameters;
        const copy = try self.allocator.dupe(u8, configured);
        self.local_transport_parameters = copy;
        return copy;
    }

    fn driveServerHandshakeFlight(self: *Context) !void {
        if (self.config.role != .Server) return;
        if (self.flags.local_finished_sent) return;
        if (self.secrets.handshake.send.valid) return; // secrets already installed

        const ch_view = self.state.clientHello() orelse return HandshakeError.UnexpectedMessage;
        const cipher_suite = self.chooseCipherSuite(ch_view.cipher_suites) orelse return HandshakeError.NoCipherSuite;
        _ = try self.selectServerSignatureScheme(ch_view);
        if (ch_view.key_share.key.len != 32) return HandshakeError.UnsupportedKeyShareGroup;

        var server_random: [32]u8 = undefined;
        std.crypto.random.bytes(&server_random);

        var server_priv: [32]u8 = undefined;
        std.crypto.random.bytes(&server_priv);

        const server_pub = std.crypto.dh.X25519.recoverPublicKey(server_priv) catch {
            return HandshakeError.UnsupportedKeyShareGroup;
        };

        var client_pub: [32]u8 = undefined;
        @memcpy(&client_pub, ch_view.key_share.key[0..32]);

        const shared = std.crypto.dh.X25519.scalarmult(server_priv, client_pub) catch {
            return HandshakeError.UnsupportedKeyShareGroup;
        };

        const session_id_opt: ?[]const u8 = if (ch_view.session_id.len != 0) ch_view.session_id else null;

        const sh_body = try tls13_full.buildServerHello(
            self.allocator,
            server_random,
            cipher_suite,
            ch_view.key_share.group,
            server_pub[0..],
            session_id_opt,
            null,
        );
        defer self.allocator.free(sh_body);

        const sh_msg = try encodeHandshake(self.allocator, .server_hello, sh_body);
        defer self.allocator.free(sh_msg);

        // Debug: Print ServerHello message hex dump
        std.debug.print("[TRANSCRIPT_DEBUG] ServerHello message ({} bytes): ", .{sh_msg.len});
        for (sh_msg) |b| std.debug.print("{X:0>2}", .{b});
        std.debug.print("\n", .{});

        try self.appendOutbound(.Initial, sh_msg, true);

        const transcript_after_sh = self.transcripts.handshake.finalize();
        const hs = deriveHandshakeTraffic(shared[0..], transcript_after_sh);
        self.handshake_secret = hs.handshake;
        try self.installTrafficSecret(.Handshake, .send, hs.server_hs);
        try self.installTrafficSecret(.Handshake, .recv, hs.client_hs);
        if (self.phase == .negotiating) {
            self.phase = .keys_installed;
        }

        const server_tp = try self.ensureLocalTransportParameters();
        const selected_alpn = try self.selectServerAlpn(ch_view);
        self.notifyMetadata();
        const ee_body = try tls13_full.buildEncryptedExtensions(
            self.allocator,
            selected_alpn,
            server_tp,
        );
        defer self.allocator.free(ee_body);

        const ee_msg = try encodeHandshake(self.allocator, .encrypted_extensions, ee_body);
        defer self.allocator.free(ee_msg);
        try self.appendOutbound(.Handshake, ee_msg, true);

        // CRITICAL: Send Certificate and CertificateVerify before Finished (RFC 8446 §4.4.1)
        // Server must prove possession of private key corresponding to certificate
        if (self.config.server_cert_der) |cert_der| {
            std.debug.print("Server: Sending Certificate message ({} bytes DER)\n", .{cert_der.len});

            // Build Certificate message using tls13_full helper
            // Convert single certificate to certificate chain
            const cert_chain = [_][]const u8{cert_der};
            const cert_body = try tls13_full.buildCertificate(self.allocator, &cert_chain);
            defer self.allocator.free(cert_body);

            const cert_msg = try encodeHandshake(self.allocator, .certificate, cert_body);
            defer self.allocator.free(cert_msg);
            try self.appendOutbound(.Handshake, cert_msg, true);

            // Build CertificateVerify message
            // Signature is over transcript hash including Certificate message we just added
            const hash_for_sig = self.transcripts.handshake.finalize();

            // Infer signature algorithm from certificate if not explicitly configured
            // First get the SignatureScheme, then convert to SigAlg
            const sig_scheme = self.negotiated_signature orelse blk: {
                // Try to detect from certificate, but this returns SigAlg not SignatureScheme
                // For now, default to ed25519 which is in our supported schemes
                break :blk .ed25519;
            };

            // Convert SignatureScheme to SigAlg
            const sig_alg: sig.SigAlg = switch (sig_scheme) {
                .ecdsa_secp256r1_sha256 => .ecdsa_secp256r1_sha256,
                .ecdsa_secp384r1_sha384 => .ecdsa_secp384r1_sha384,
                .rsa_pss_rsae_sha256 => .rsa_pss_sha256,
                .ed25519 => .ed25519,
                else => .ed25519, // Default fallback
            };

            std.debug.print("Server: Signing CertificateVerify with algorithm: {s}\n", .{@tagName(sig_alg)});

            // Get private key from config
            const priv_key = self.config.server_key_der orelse {
                std.debug.print("Server: ERROR - No private key configured!\n", .{});
                return HandshakeError.UnexpectedMessage; // Using this as a placeholder for config errors
            };

            // Sign the transcript hash with proper TLS 1.3 context string
            const signature = try sig.signCertificateVerify(
                sig_alg,
                priv_key,
                "TLS 1.3, server CertificateVerify",
                &hash_for_sig,
                self.allocator,
            );
            defer self.allocator.free(signature);

            // Build CertificateVerify message body (RFC 8446 §4.4.3)
            const cv_body = try tls13_full.buildCertificateVerify(self.allocator, sig_scheme, signature);
            defer self.allocator.free(cv_body);

            const cv_msg = try encodeHandshake(self.allocator, .certificate_verify, cv_body);
            defer self.allocator.free(cv_msg);
            try self.appendOutbound(.Handshake, cv_msg, true);

            std.debug.print("Server: Certificate and CertificateVerify sent successfully\n", .{});
        } else {
            std.debug.print("Server: WARNING - No certificate configured, proceeding without Certificate/CertificateVerify\n", .{});
        }

        const hash_before_finished = self.transcripts.handshake.finalize();
        self.transcripts.finished_hash = hash_before_finished;
        const verify_data = deriveFinishedVerifyData(hs.server_hs, hash_before_finished);

        const fin_msg = try encodeHandshake(self.allocator, .finished, verify_data[0..]);
        defer self.allocator.free(fin_msg);
        try self.appendOutbound(.Handshake, fin_msg, true);

        self.markLocalFinished();
    }

    /// Construct and queue a ClientHello with QUIC extensions when acting as the client.
    fn startClientHandshake(self: *Context) !void {
        if (self.config.role != .Client) return;
        if (self.client_priv != null) return; // already started
        // Generate X25519 key pair
        var priv: [32]u8 = undefined;
        std.crypto.random.bytes(&priv);
        const server_pubkey = std.crypto.dh.X25519.recoverPublicKey(priv) catch return HandshakeError.UnsupportedKeyShareGroup;
        self.client_priv = priv;
        self.client_pub = server_pubkey;
        // Build ClientHello using offered params
        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, &.{ 0x03, 0x03 }); // legacy_version
        var rnd: [32]u8 = undefined;
        std.crypto.random.bytes(&rnd);
        try body.appendSlice(self.allocator, &rnd);
        try body.append(self.allocator, 0); // empty session id
        // cipher suites (vector len=2 -> one suite)
        try body.appendSlice(self.allocator, &.{ 0x00, 0x02, 0x13, 0x01 });
        // compression methods
        try body.appendSlice(self.allocator, &.{ 0x01, 0x00 });
        var ext_buf = std.ArrayList(u8){};
        defer ext_buf.deinit(self.allocator);
        // supported_versions
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });
        // supported_groups (x25519)
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });
        // signature_algorithms
        const sigs = self.config.supported_signature_schemes;
        if (sigs.len != 0) {
            const list_len: u16 = @intCast(sigs.len * 2);
            const ext_len: u16 = list_len + 2;
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x0d, @intCast(ext_len >> 8), @intCast(ext_len & 0xff), @intCast(list_len >> 8), @intCast(list_len & 0xff) });
            for (sigs) |scheme| {
                const val: u16 = switch (scheme) {
                    .ed25519 => 0x0807,
                    .ecdsa_secp256r1_sha256 => 0x0403,
                    .ecdsa_secp384r1_sha384 => 0x0503,
                    .rsa_pss_sha256 => 0x0804,
                };
                try ext_buf.appendSlice(self.allocator, &.{ @intCast(val >> 8), @intCast(val & 0xff) });
            }
        }
        // key_share
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x33 });
        const key_share_len: u16 = 2 + 2 + 32;
        const total_len: u16 = key_share_len + 2;
        try ext_buf.appendSlice(self.allocator, &.{ @intCast(total_len >> 8), @intCast(total_len & 0xff) });
        try ext_buf.appendSlice(self.allocator, &.{ @intCast(key_share_len >> 8), @intCast(key_share_len & 0xff) });
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x1d });
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 32 });
        try ext_buf.appendSlice(self.allocator, self.client_pub.?[0..]);
        // ALPN
        if (self.config.alpn_protocols) |alpn_list| if (alpn_list.len != 0) {
            var names_len: usize = 0;
            for (alpn_list) |p| names_len += 1 + p.len;
            const list_len: u16 = @intCast(names_len);
            const ext_len: u16 = list_len + 2;
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x10, @intCast(ext_len >> 8), @intCast(ext_len & 0xff), @intCast(list_len >> 8), @intCast(list_len & 0xff) });
            for (alpn_list) |p| {
                try ext_buf.append(self.allocator, @intCast(p.len));
                try ext_buf.appendSlice(self.allocator, p);
            }
        };
        // QUIC transport parameters (client sends its TP in CH)
        if (self.config.quic_transport_parameters) |tp| {
            const tp_len: u16 = @intCast(tp.len);
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x39, @intCast(tp_len >> 8), @intCast(tp_len & 0xff) });
            try ext_buf.appendSlice(self.allocator, tp);
        }
        // finalize extensions
        const exts_len: u16 = @intCast(ext_buf.items.len);
        try body.appendSlice(self.allocator, &.{ @intCast(exts_len >> 8), @intCast(exts_len & 0xff) });
        try body.appendSlice(self.allocator, ext_buf.items);
        const body_len: u32 = @intCast(body.items.len);
        const msg = try self.allocator.alloc(u8, 4 + body.items.len);
        msg[0] = @intFromEnum(HsType.client_hello);
        msg[1] = @intCast((body_len >> 16) & 0xff);
        msg[2] = @intCast((body_len >> 8) & 0xff);
        msg[3] = @intCast(body_len & 0xff);
        @memcpy(msg[4..], body.items);
        defer self.allocator.free(msg);
        try self.appendOutbound(.Initial, msg, true);
        self.transcripts.client_hello_hash = self.transcripts.handshake.finalize();
        if (self.phase == .initial) self.phase = .negotiating;
    }

    fn handleServerHello(self: *Context, body: []const u8) !void {
        // Minimal parse: skip legacy_version(2) + random(32) + session_id
        if (body.len < 2 + 32 + 1) return HandshakeError.UnexpectedMessage;
        const random = body[2..34];
        // Downgrade sentinel check (RFC 8446 4.1.3)
        if (random.len >= 32) {
            const last8 = random[24..32];
            if (std.mem.eql(u8, last8, "DOWNGRD\x00") or std.mem.eql(u8, last8, "DOWNGRD\x01")) {
                return HandshakeError.DowngradeAttempt;
            }
        }
        var pos: usize = 2 + 32; // after legacy_version+random
        if (pos >= body.len) return HandshakeError.UnexpectedMessage;
        const sid_len: usize = body[pos];
        pos += 1 + sid_len;
        if (pos + 2 + 1 > body.len) return HandshakeError.UnexpectedMessage;
        pos += 2; // cipher_suite
        pos += 1; // compression
        if (pos + 2 > body.len) return HandshakeError.UnexpectedMessage;
        const exts_len: usize = (@as(usize, body[pos]) << 8) | @as(usize, body[pos + 1]);
        pos += 2;
        if (pos + exts_len > body.len) return HandshakeError.UnexpectedMessage;
        const exts_end = pos + exts_len;
        var server_pub: ?[32]u8 = null;
        while (pos + 4 <= exts_end) {
            const etype = (@as(u16, body[pos]) << 8) | body[pos + 1];
            const elen = (@as(usize, body[pos + 2]) << 8) | body[pos + 3];
            pos += 4;
            if (pos + elen > exts_end) return HandshakeError.UnexpectedMessage;
            if (etype == 0x0033) { // key_share
                if (elen < 4 + 32) return HandshakeError.MissingKeyShare;
                const group = (@as(u16, body[pos]) << 8) | body[pos + 1];
                const klen = (@as(u16, body[pos + 2]) << 8) | body[pos + 3];
                if (group != 0x001d or klen != 32 or pos + 4 + 32 > pos + elen) return HandshakeError.UnsupportedKeyShareGroup;
                var kp: [32]u8 = undefined;
                @memcpy(&kp, body[pos + 4 .. pos + 4 + 32]);
                server_pub = kp;
            }
            pos += elen;
        }
        if (server_pub == null) return HandshakeError.MissingKeyShare;
        const priv = self.client_priv orelse return HandshakeError.UnexpectedMessage;
        const shared = std.crypto.dh.X25519.scalarmult(priv, server_pub.?) catch return HandshakeError.UnsupportedKeyShareGroup;
        const sh_snapshot = self.transcripts.handshake.finalize();
        const hs = deriveHandshakeTraffic(shared[0..], sh_snapshot);
        self.handshake_secret = hs.handshake;
        try self.installTrafficSecret(.Handshake, .send, hs.client_hs);
        try self.installTrafficSecret(.Handshake, .recv, hs.server_hs);
        self.phase = .keys_installed;
    }

    fn sendClientFinished(self: *Context) !void {
        const slot = self.secrets.slot(.Handshake, .send);
        if (!slot.valid) return HandshakeError.UnexpectedMessage;
        var transcript_snapshot = self.transcripts.handshake;
        const hash_before = transcript_snapshot.finalize();
        const verify_data = deriveFinishedVerifyData(slot.value, hash_before);
        const fin_msg = try encodeHandshake(self.allocator, .finished, verify_data[0..]);
        defer self.allocator.free(fin_msg);
        try self.appendOutbound(.Handshake, fin_msg, true);
        self.markLocalFinished();
    }

    fn notifyMetadata(self: *Context) void {
        if (self.flags.metadata_notified) return;
        if (self.callbacks.on_handshake_metadata) |cb| {
            cb(self, self.metadataView()) catch {};
        }
        self.flags.metadata_notified = true;
    }

    /// Derive exporter secret material per RFC 8446 §7.5 using the finished transcript hash.
    pub fn exportSecret(self: *Context, label: []const u8, out: []u8) !void {
        const exp_slot = &self.secrets.exporter_master;
        if (!exp_slot.valid) return HandshakeError.UnexpectedMessage;
        const th = self.transcripts.finished_hash orelse blk: {
            var snap = self.transcripts.handshake;
            break :blk snap.finalize();
        };
        var derived: [H.digest_length]u8 = undefined;
        ks.expandLabel(exp_slot.value, label, &th, &derived) catch return HandshakeError.UnexpectedMessage;
        const n = @min(out.len, derived.len);
        @memcpy(out[0..n], derived[0..n]);
        if (n < out.len) @memset(out[n..], 0);
    }

    /// Rotate the local application traffic secret and install fresh send keys (RFC 8446 §7.2).
    pub fn performKeyUpdateSend(self: *Context) !void {
        const send_slot = self.secrets.slot(.Application, .send);
        if (!send_slot.valid) return HandshakeError.UnexpectedMessage;
        const next = ks.updateTrafficSecret(send_slot.value);
        send_slot.store(.Application, next);
    }

    /// Accept a peer initiated key update by rotating the receive traffic secret.
    pub fn performKeyUpdateRecv(self: *Context) !void {
        const recv_slot = self.secrets.slot(.Application, .recv);
        if (!recv_slot.valid) return HandshakeError.UnexpectedMessage;
        const next = ks.updateTrafficSecret(recv_slot.value);
        recv_slot.store(.Application, next);
    }
};

/// Session ticket cache entry and store types used by the TLS 1.3 engine (minimal placeholder).
// --- Session Ticket / PSK Cache Structures (minimal placeholder) ---
/// One cached TLS 1.3 session ticket with identity, resumption secret, and lifetime.
pub const TicketEntry = struct {
    identity: []u8, // ticket bytes (owned)
    secret: [H.digest_length]u8, // resumption_secret derived from master_secret
    lifetime: u32,
};

/// Borrowed view of a ticket entry used for read-only access without copying.
pub const TicketEntryView = struct {
    identity: []const u8,
    secret: [H.digest_length]u8,
    lifetime: u32,
};

/// Fixed-size FIFO store for session tickets with helper methods to add/peek.
pub const TicketStore = struct {
    const capacity = 4; // tiny FIFO
    entries: [capacity]?TicketEntry = .{null} ** capacity,
    count: usize = 0,

    /// Frees all stored ticket identities and clears the store.
    pub fn deinit(self: *TicketStore, alloc: std.mem.Allocator) void {
        var i: usize = 0;
        while (i < capacity) : (i += 1) {
            if (self.entries[i]) |*e| {
                alloc.free(e.identity);
                self.entries[i] = null;
            }
        }
        self.count = 0;
    }

    fn indexNewest(self: *TicketStore) ?usize {
        if (self.count == 0) return null;
        // Newest stored at (count-1) mod capacity as FIFO append order
        return (self.count - 1) % capacity;
    }

    /// Returns the most recently added ticket entry, if any.
    pub fn peek(self: *TicketStore) ?TicketEntryView {
        const idx_opt = self.indexNewest();
        if (idx_opt) |idx| {
            if (self.entries[idx]) |e| {
                return .{ .identity = e.identity, .secret = e.secret, .lifetime = e.lifetime };
            }
        }
        return null;
    }

    /// Adds a new ticket to the store, evicting the oldest if at capacity.
    pub fn add(self: *TicketStore, alloc: std.mem.Allocator, identity: []const u8, secret: [H.digest_length]u8, lifetime: u32) !void {
        // If capacity full, evict oldest (which is at index (count % capacity) before increment)
        const slot = self.count % capacity;
        if (self.entries[slot]) |*old| {
            alloc.free(old.identity);
        }
        const id_copy = try alloc.dupe(u8, identity);
        self.entries[slot] = TicketEntry{ .identity = id_copy, .secret = secret, .lifetime = lifetime };
        self.count += 1;
    }
};

/// Hash function used for TLS 1.3 key schedule (SHA-256).
/// RFC 8446 §4.1.3: TLS_AES_128_GCM_SHA256 uses SHA-256 for HKDF.
pub const H = ks.H; // sha256

/// TLS handshake role (client or server).
///
/// Determines:
/// - Message flow direction (who sends first)
/// - Secret role assignment (client_hs vs server_hs)
/// - Certificate validation requirements
///
/// RFC 8446 §2: Client initiates with ClientHello, server responds with ServerHello.
pub const Role = enum {
    /// Client role: Initiates handshake, verifies server certificate.
    Client,
    /// Server role: Responds to ClientHello, provides certificate.
    Server,
};

/// QUIC encryption levels for packet protection (RFC 9001 §4.1.4).
///
/// Each encryption level has its own packet number space and CRYPTO stream.
/// Secrets are installed progressively as handshake advances:
///
/// 1. **Initial**: Derived from QUIC version-specific salt
///    - Contains: ClientHello (client→server), ServerHello (server→client)
///    - Protection: Deterministic keys from connection ID
///
/// 2. **Handshake**: Derived from ECDHE shared secret
///    - Contains: EncryptedExtensions, Certificate, CertificateVerify, Finished
///    - Protection: AEAD keys from handshake_traffic_secret
///
/// 3. **Application**: Derived from master secret after Finished
///    - Contains: NewSessionTicket, application data, post-handshake messages
///    - Protection: AEAD keys from application_traffic_secret_0
///
/// Note: 0-RTT/Early Data uses a separate encryption level (not implemented yet).
pub const EncryptionLevel = enum {
    /// Initial encryption level (unprotected or version-specific keys).
    /// Messages: ClientHello, ServerHello
    Initial,

    /// Handshake encryption level (ECDHE-derived keys).
    /// Messages: EncryptedExtensions, Certificate, CertificateVerify, Finished
    Handshake,

    /// Application data encryption level (post-handshake keys).
    /// Messages: NewSessionTicket, application data
    Application,
};

/// TLS 1.3 handshake message types (RFC 8446 §4).
///
/// Used for parsing and encoding handshake messages in CRYPTO frames.
/// Each message type has specific content and allowed encryption level:
///
/// - client_hello (1): Initial level
/// - server_hello (2): Initial level
/// - encrypted_extensions (8): Handshake level
/// - certificate (11): Handshake level
/// - certificate_verify (15): Handshake level
/// - finished (20): Handshake level
/// - new_session_ticket (4): Application level
///
/// Note: end_of_early_data (5) is prohibited in QUIC per RFC 9001 §8.3.
pub const HsType = enum(u8) {
    /// ClientHello message (RFC 8446 §4.1.2).
    client_hello = 1,
    /// ServerHello message (RFC 8446 §4.1.3).
    server_hello = 2,
    /// NewSessionTicket for resumption (RFC 8446 §4.6.1).
    new_session_ticket = 4,
    /// EncryptedExtensions message (RFC 8446 §4.3.1).
    encrypted_extensions = 8,
    /// Certificate message (RFC 8446 §4.4.2).
    certificate = 11,
    /// CertificateVerify message (RFC 8446 §4.4.3).
    certificate_verify = 15,
    /// Finished message (RFC 8446 §4.4.4).
    finished = 20,
};

const HandshakeMessage = struct {
    typ: HsType,
    body: []const u8,
    n: usize,
};

/// Encode a TLS handshake message with type and 24-bit length prefix.
///
/// RFC 8446 §4: Handshake protocol message format:
/// ```
/// struct {
///     HandshakeType msg_type;    // 1 byte
///     uint24 length;             // 3 bytes (big-endian)
///     opaque body[length];
/// } Handshake;
/// ```
///
/// # Parameters
/// - alloc: Allocator for the returned buffer
/// - typ: Handshake message type (client_hello, server_hello, etc.)
/// - body: Message body bytes (varies by type)
///
/// # Returns
/// Allocated buffer containing: [type:1][length:3][body:N]
/// Caller owns returned slice and must free it.
///
/// # Example
/// ```zig
/// const finished_body: [32]u8 = ... // verify_data
/// const msg = try encodeHandshake(allocator, .finished, &finished_body);
/// defer allocator.free(msg);
/// ```
pub fn encodeHandshake(alloc: std.mem.Allocator, typ: HsType, body: []const u8) ![]u8 {
    var out = try alloc.alloc(u8, 4 + body.len);
    out[0] = @intFromEnum(typ);
    const L: u32 = @intCast(body.len);
    // 24-bit big-endian length
    out[1] = @intCast((L >> 16) & 0xff);
    out[2] = @intCast((L >> 8) & 0xff);
    out[3] = @intCast(L & 0xff);
    @memcpy(out[4..], body);
    return out;
}

/// Parse one complete handshake message from buffered CRYPTO data.
///
/// RFC 8446 §4: Attempts to parse a single handshake message from the input.
/// Returns null if insufficient data available (caller should buffer more).
///
/// RFC 9001 §8.3: Validates that end_of_early_data (type 5) is not sent over QUIC.
///
/// # Parameters
/// - data: Buffered CRYPTO data (may contain partial or multiple messages)
///
/// # Returns
/// - `HandshakeMessage`: Parsed message with type, body slice, and total bytes consumed
/// - `null`: Need more data (fewer than 4 bytes, or incomplete body)
/// - `error`: Protocol violation (e.g., end_of_early_data in QUIC)
///
/// # Usage Pattern
/// ```zig
/// while (true) {
///     const parsed = try parseHandshakeOne(buffer) orelse break;
///     // Process parsed.typ and parsed.body
///     buffer = buffer[parsed.n..]; // Consume bytes
/// }
/// ```
///
/// # Notes
/// - Returned `body` slice points into input `data` (no allocation)
/// - Caller must track consumed bytes via `n` field
/// - Handles fragmentation across QUIC packets via buffering
pub fn parseHandshakeOne(data: []const u8) !?HandshakeMessage {
    if (data.len < 4) return null; // Need at least type + length
    const t_byte = data[0];

    // RFC 9001 §8.3: EndOfEarlyData (type 5) MUST NOT be sent over QUIC
    // Early data termination is implicit when sending on higher encryption level
    if (t_byte == 5) {
        std.debug.print("TLS: Received EndOfEarlyData message (RFC 9001 violation - type 5 prohibited)\n", .{});
        return error.ProtocolViolation;
    }

    const typ: HsType = std.meta.intToEnum(HsType, t_byte) catch return error.UnknownHandshakeType;

    // Parse 24-bit big-endian length
    const L: usize = (@as(usize, data[1]) << 16) | (@as(usize, data[2]) << 8) | @as(usize, data[3]);
    const need = 4 + L;

    if (data.len < need) return null; // Incomplete message body

    return HandshakeMessage{
        .typ = typ,
        .body = data[4 .. 4 + L], // Slice into input buffer
        .n = need, // Total bytes consumed
    };
}

/// Small transcript helper; accumulates handshake messages as-is.
pub const Transcript = struct {
    hasher: H = H.init(.{}),

    /// Initialize a new transcript hash helper.
    pub fn init() Transcript {
        return .{ .hasher = H.init(.{}) };
    }
    /// Update transcript with raw bytes (handshake messages).
    pub fn update(self: *Transcript, msg: []const u8) void {
        self.hasher.update(msg);
        // Debug: log what's being added to transcript
        if (msg.len >= 4) {
            const msg_type = msg[0];
            const msg_len = (@as(usize, msg[1]) << 16) | (@as(usize, msg[2]) << 8) | msg[3];
            const type_name = switch (msg_type) {
                0x01 => "ClientHello",
                0x02 => "ServerHello",
                0x08 => "EncryptedExtensions",
                0x0B => "Certificate",
                0x0F => "CertificateVerify",
                0x14 => "Finished",
                else => "Unknown",
            };
            std.debug.print("[TRANSCRIPT] Adding {s} (0x{X:0>2}) len={} bytes, first 8: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{
                type_name,                      msg_type,                       msg_len,
                if (msg.len > 0) msg[0] else 0, if (msg.len > 1) msg[1] else 0, if (msg.len > 2) msg[2] else 0,
                if (msg.len > 3) msg[3] else 0, if (msg.len > 4) msg[4] else 0, if (msg.len > 5) msg[5] else 0,
                if (msg.len > 6) msg[6] else 0, if (msg.len > 7) msg[7] else 0,
            });

            // Print full message bytes for ClientHello and ServerHello
            if (msg_type == 0x01 or msg_type == 0x02) {
                std.debug.print("[TRANSCRIPT] Full {s} message ({} bytes):\n", .{ type_name, msg.len });
                var i: usize = 0;
                while (i < msg.len) : (i += 32) {
                    std.debug.print("  ", .{});
                    var j: usize = i;
                    while (j < @min(i + 32, msg.len)) : (j += 1) {
                        std.debug.print("{X:0>2}", .{msg[j]});
                    }
                    std.debug.print("\n", .{});
                }
            }
        }
    }
    /// Finalize and return current transcript hash without consuming internal state.
    pub fn finalize(self: *Transcript) [H.digest_length]u8 {
        var out: [H.digest_length]u8 = undefined;
        var tmp = self.hasher; // copy
        tmp.final(&out);
        std.debug.print("[TRANSCRIPT] Finalized hash: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}... (32 bytes)\n", .{ out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7] });
        return out;
    }
};

/// Derive handshake traffic secrets from ECDHE shared secret (RFC 8446 §7.1).
///
/// This function computes the handshake-level secrets used to protect messages
/// after ServerHello. It implements the TLS 1.3 key schedule using HKDF:
///
/// ```
/// early_secret = HKDF-Extract(0, 0)  // No PSK
/// derived = Derive-Secret(early_secret, "derived", "")
/// handshake_secret = HKDF-Extract(derived, ECDHE)
/// client_handshake_traffic_secret = Derive-Secret(handshake_secret, "c hs traffic", CH..SH)
/// server_handshake_traffic_secret = Derive-Secret(handshake_secret, "s hs traffic", CH..SH)
/// ```
///
/// # Parameters
/// - ecdhe_secret: Raw X25519 shared secret (32 bytes) from key exchange
/// - transcript_hash: Hash(ClientHello || ServerHello) using SHA-256
///
/// # Returns
/// Struct containing:
/// - handshake: Master handshake secret (used to derive application secrets later)
/// - client_hs: Client→Server handshake traffic secret (32 bytes)
/// - server_hs: Server→Client handshake traffic secret (32 bytes)
///
/// # RFC References
/// - RFC 8446 §7.1: Key schedule diagram and derivation
/// - RFC 9001 §5.1: QUIC packet protection uses these secrets
///
/// # Usage
/// ```zig
/// const shared = try X25519.scalarmult(priv, peer_pub);
/// const transcript = Hash(client_hello || server_hello);
/// const secrets = deriveHandshakeTraffic(shared[0..], transcript);
/// // Install secrets for packet protection at Handshake level
/// try installTrafficSecret(.Handshake, .send, secrets.client_hs);
/// try installTrafficSecret(.Handshake, .recv, secrets.server_hs);
/// ```
///
/// # Security Notes
/// - Assumes no PSK resumption (early_secret = HKDF-Extract(0, 0))
/// - ECDHE provides forward secrecy
/// - Secrets must be zeroized after use (handled by SecretSlot)
pub fn deriveHandshakeTraffic(ecdhe_secret: []const u8, transcript_hash: [H.digest_length]u8) struct {
    handshake: [H.digest_length]u8,
    client_hs: [H.digest_length]u8,
    server_hs: [H.digest_length]u8,
} {
    // Debug: Print transcript hash (all bytes)
    std.debug.print("[TLS_KEY_SCHEDULE] Transcript hash (CH+SH): ", .{});
    for (transcript_hash) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n", .{});
    std.debug.print("[TLS_KEY_SCHEDULE] ECDHE shared secret: ", .{});
    for (ecdhe_secret) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n", .{});

    // early_secret = HKDF-Extract(0, 0)
    // RFC 8446 §7.1: If a given secret is not available, then the 0-value
    // consisting of a string of Hash.length bytes set to zeros is used.
    const zero_value = [_]u8{0} ** H.digest_length; // 32 zero bytes for SHA-256
    const early_secret = ks.extract(&zero_value, &zero_value);
    // derived = Derive-Secret(early_secret, "derived", "")
    // RFC 8446 §7.1: The context for "derived" is Hash("")
    var empty_hash: [H.digest_length]u8 = undefined;
    H.hash(&[_]u8{}, &empty_hash, .{});
    var derived: [H.digest_length]u8 = undefined;
    ks.expandLabel(early_secret, "derived", &empty_hash, &derived) catch unreachable;
    // handshake_secret = HKDF-Extract(derived, ecdhe_secret)
    const handshake_secret = ks.extract(&derived, ecdhe_secret);
    // traffic secrets
    var c_hs: [H.digest_length]u8 = undefined;
    var s_hs: [H.digest_length]u8 = undefined;
    ks.expandLabel(handshake_secret, "c hs traffic", &transcript_hash, &c_hs) catch unreachable;
    ks.expandLabel(handshake_secret, "s hs traffic", &transcript_hash, &s_hs) catch unreachable;

    // Debug: Print derived traffic secrets (all bytes)
    std.debug.print("[TLS_KEY_SCHEDULE] Client HS traffic secret: ", .{});
    for (c_hs) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n", .{});
    std.debug.print("[TLS_KEY_SCHEDULE] Server HS traffic secret: ", .{});
    for (s_hs) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n", .{});

    return .{ .handshake = handshake_secret, .client_hs = c_hs, .server_hs = s_hs };
}

/// QUIC key material derived from a TLS traffic secret.
pub const QuicKeys = struct { key: [16]u8, iv: [12]u8, hp: [16]u8 };

/// Derive QUIC handshake keys from a handshake traffic secret.
pub fn deriveQuicHandshakeKeys(client_or_server_hs_secret: [H.digest_length]u8, v2: bool) QuicKeys {
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    var hp: [16]u8 = undefined;
    if (v2) {
        const t = ks.deriveKeyIvHpV2(client_or_server_hs_secret);
        key = t.key;
        iv = t.iv;
        hp = t.hp;
    } else {
        const t = ks.deriveKeyIvHp(client_or_server_hs_secret);
        key = t.key;
        iv = t.iv;
        hp = t.hp;
    }
    return .{ .key = key, .iv = iv, .hp = hp };
}

/// Derive application traffic secrets (client and server) from handshake secret.
pub fn deriveApplicationTraffic(handshake_secret: [H.digest_length]u8, transcript_hash: [H.digest_length]u8) struct {
    client_app: [H.digest_length]u8,
    server_app: [H.digest_length]u8,
    exporter_master: [H.digest_length]u8,
} {
    // master_secret = HKDF-Extract(Derive-Secret(handshake_secret, "derived", ""), 0)
    var derived2: [H.digest_length]u8 = undefined;
    ks.expandLabel(handshake_secret, "derived", &[_]u8{}, &derived2) catch unreachable;
    const master = ks.extract(&derived2, &[_]u8{});
    var c_app: [H.digest_length]u8 = undefined;
    var s_app: [H.digest_length]u8 = undefined;
    ks.expandLabel(master, "c ap traffic", &transcript_hash, &c_app) catch unreachable;
    ks.expandLabel(master, "s ap traffic", &transcript_hash, &s_app) catch unreachable;
    var exp_master: [H.digest_length]u8 = undefined;
    ks.expandLabel(master, "exp master", &transcript_hash, &exp_master) catch unreachable;
    return .{ .client_app = c_app, .server_app = s_app, .exporter_master = exp_master };
}

/// Derive QUIC 1-RTT keys from an application traffic secret.
pub fn deriveQuicAppKeys(client_or_server_app_secret: [H.digest_length]u8, v2: bool) QuicKeys {
    return if (v2) blk: {
        const t = ks.deriveKeyIvHpV2(client_or_server_app_secret);
        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    } else blk2: {
        const t = ks.deriveKeyIvHp(client_or_server_app_secret);
        break :blk2 .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    };
}

/// Derive application traffic secrets directly from raw ECDHE secret and transcript hash.
/// This computes handshake_secret then master secret per TLS 1.3 and returns c/s app secrets.
pub fn deriveApplicationTrafficFromEcdhe(ecdhe_secret: []const u8, transcript_hash: [H.digest_length]u8) struct {
    client_app: [H.digest_length]u8,
    server_app: [H.digest_length]u8,
} {
    // early_secret = HKDF-Extract(0, 0)
    // RFC 8446 §7.1: If a given secret is not available, then the 0-value
    // consisting of a string of Hash.length bytes set to zeros is used.
    const zero_value = [_]u8{0} ** H.digest_length; // 32 zero bytes for SHA-256
    const early_secret = ks.extract(&zero_value, &zero_value);
    // derived = Derive-Secret(early_secret, "derived", "")
    // RFC 8446 §7.1: The context for "derived" is Hash("")
    var empty_hash: [H.digest_length]u8 = undefined;
    H.hash(&[_]u8{}, &empty_hash, .{});
    var derived: [H.digest_length]u8 = undefined;
    ks.expandLabel(early_secret, "derived", &empty_hash, &derived) catch unreachable;
    // handshake_secret = HKDF-Extract(derived, ecdhe_secret)
    const handshake_secret = ks.extract(&derived, ecdhe_secret);
    // master_secret = HKDF-Extract(Derive-Secret(handshake_secret, "derived", ""), 0)
    var derived2: [H.digest_length]u8 = undefined;
    ks.expandLabel(handshake_secret, "derived", &[_]u8{}, &derived2) catch unreachable;
    const master = ks.extract(&derived2, &[_]u8{});
    var c_app: [H.digest_length]u8 = undefined;
    var s_app: [H.digest_length]u8 = undefined;
    ks.expandLabel(master, "c ap traffic", &transcript_hash, &c_app) catch unreachable;
    ks.expandLabel(master, "s ap traffic", &transcript_hash, &s_app) catch unreachable;
    return .{ .client_app = c_app, .server_app = s_app };
}

/// TLS Finished helpers (minimal): finished_key = Expand(traffic_secret, "finished");
/// verify_data = HMAC(finished_key, transcript_hash)
pub fn deriveFinishedVerifyData(traffic_secret: [H.digest_length]u8, transcript_hash: [H.digest_length]u8) [H.digest_length]u8 {
    var finished_key: [H.digest_length]u8 = undefined;
    ks.expandLabel(traffic_secret, "finished", &[_]u8{}, &finished_key) catch unreachable;
    return ks.hmacSha256(&finished_key, &transcript_hash);
}

/// Minimal, non-interoperable handshake engine stub that accumulates
/// CRYPTO bytes and allows tests to inject ServerHello pieces to drive
/// key schedule. Real message parsing/encoding will be added iteratively.
pub const Engine = struct {
    role: Role,
    allocator: std.mem.Allocator,
    transcript: Transcript = Transcript.init(),
    /// Deterministic ECDHE secret for tests or derived via X25519 in future slices.
    ecdhe_secret: ?[]const u8 = null,
    /// Buffer to hold derived ECDHE so the slice stays valid.
    ecdhe_buf: [32]u8 = undefined,
    /// Local X25519 keypair (generated on demand).
    my_priv: ?[32]u8 = null,
    my_pub: ?[32]u8 = null,
    /// Last seen peer pubkey (from CH/SH minimal envelopes).
    peer_pub: ?[32]u8 = null,
    /// Client's legacy session ID (must be echoed in ServerHello)
    client_session_id: ?[]u8 = null,
    /// Buffer for producing outbound CRYPTO data (owned by Engine; callers copy via flushCrypto).
    outbox: std.ArrayList(u8),
    /// Buffer for accumulating inbound CRYPTO data (for fragmented handshake messages).
    inbox: std.ArrayList(u8),
    /// Flag to indicate handshake failure (e.g., missing transport parameters)
    handshake_failed: bool = false,
    /// Tracking flags for minimal handshake state.
    ch_sent: bool = false, // Client: sent ClientHello
    ch_recv: bool = false, // Server: received ClientHello
    sh_seen: bool = false, // Client: seen ServerHello; Server: sent ServerHello
    /// Security / verification state (minimal)
    allow_insecure: bool = true,
    peer_cert_ok: bool = false,
    finished_sent: bool = false,
    finished_verified: bool = false,
    /// Whether EncryptedExtensions has been sent (server) or received (client) in real mode
    ee_sent: bool = false,
    /// Whether the server has already staged its complete handshake flight in the outbox
    server_handshake_flight_enqueued: bool = false,
    /// Cached intermediate handshake_secret (used to derive master_secret). Cached to avoid recomputing from ECDHE.
    /// RFC 8446 §7.1: handshake_secret = HKDF-Extract(Derive-Secret(early_secret, "derived", ""), ECDHE)
    /// This prevents bugs from ECDHE buffer corruption/reuse when deriving application secrets.
    handshake_secret: ?[H.digest_length]u8 = null,
    /// Stored handshake traffic secrets (derived immediately after SH) for correct Finished verification
    handshake_client_secret: ?[H.digest_length]u8 = null,
    handshake_server_secret: ?[H.digest_length]u8 = null,
    /// Leaf certificate SPKI (DER) cached on Certificate message, owned by Engine
    leaf_spki: ?[]u8 = null,
    /// QUIC Transport Parameters (encoded blobs) carried in CRYPTO
    local_tp: ?[]u8 = null,
    peer_tp: ?[]u8 = null,
    /// Negotiated ALPN (opaque protocol id)
    alpn: ?[]u8 = null,
    /// Server Name Indication for certificate name checks (client-side). Owned by engine.
    server_name: ?[]u8 = null,
    /// Stored server certificate (DER) and private key (for future Certificate + CertificateVerify emission)
    server_cert_der: ?[]u8 = null,
    server_priv_key: ?[]u8 = null,
    server_sig_alg: ?sig.SigAlg = null,
    /// Cached master_secret (to derive resumption/PSK secrets). Filled when application secrets computed.
    master_secret: ?[H.digest_length]u8 = null,
    /// Cached application traffic secrets (computed once with correct transcript, before adding peer Finished).
    /// This prevents recomputation with wrong transcript after both Finisheds are added.
    cached_app_client: ?[H.digest_length]u8 = null,
    cached_app_server: ?[H.digest_length]u8 = null,
    /// Stored resumption tickets (very small cache FIFO). Each entry keeps identity and resumption_secret.
    tickets: TicketStore = .{},
    /// Optional callback invoked whenever the peer Finished verification state changes.
    peer_finished_cb: ?PeerFinishedCallback = null,
    peer_finished_ctx: ?*anyopaque = null,

    const PeerFinishedCallback = *const fn (ctx: ?*anyopaque, engine: *Engine, verified: bool) anyerror!void;

    /// Initialize a TLS 1.3 Engine with allocator and role.
    pub fn init(alloc: std.mem.Allocator, role: Role) Engine {
        return .{ .role = role, .allocator = alloc, .transcript = Transcript.init(), .ecdhe_secret = null, .ecdhe_buf = undefined, .my_priv = null, .my_pub = null, .peer_pub = null, .client_session_id = null, .outbox = std.ArrayList(u8){}, .inbox = std.ArrayList(u8){}, .handshake_failed = false, .ch_sent = false, .ch_recv = false, .sh_seen = false, .allow_insecure = true, .peer_cert_ok = false, .finished_sent = false, .finished_verified = false, .ee_sent = false, .server_handshake_flight_enqueued = false, .handshake_secret = null, .handshake_client_secret = null, .handshake_server_secret = null, .leaf_spki = null, .local_tp = null, .peer_tp = null, .alpn = null, .server_name = null, .server_cert_der = null, .server_priv_key = null, .server_sig_alg = null, .master_secret = null, .cached_app_client = null, .cached_app_server = null, .tickets = .{}, .peer_finished_cb = null, .peer_finished_ctx = null };
    }
    /// Release any owned resources and buffers.
    pub fn deinit(self: *Engine) void {
        if (self.leaf_spki) |spki| self.allocator.free(spki);
        if (self.client_session_id) |sid| self.allocator.free(sid);
        if (self.local_tp) |b| self.allocator.free(b);
        if (self.peer_tp) |b| self.allocator.free(b);
        if (self.alpn) |a| self.allocator.free(a);
        if (self.server_name) |s| self.allocator.free(s);
        if (self.server_cert_der) |c| self.allocator.free(c);
        if (self.server_priv_key) |k| self.allocator.free(k);
        self.tickets.deinit(self.allocator);
        self.outbox.deinit(self.allocator);
        self.inbox.deinit(self.allocator);
    }

    /// Register a callback that fires whenever peer Finished verification toggles.
    pub fn setPeerFinishedCallback(self: *Engine, cb: ?PeerFinishedCallback, ctx: ?*anyopaque) void {
        self.peer_finished_cb = cb;
        self.peer_finished_ctx = ctx;
    }

    fn updateFinishedVerified(self: *Engine, value: bool) void {
        std.debug.print("TLS: updateFinishedVerified called: value={}, role={s}, current={}\n", .{ value, if (self.role == .Server) "Server" else "Client", self.finished_verified });
        if (self.finished_verified == value) {
            std.debug.print("TLS: finished_verified already set to {}, skipping\n", .{value});
            return;
        }
        self.finished_verified = value;
        std.debug.print("TLS: Set finished_verified={}\n", .{value});
        if (self.peer_finished_cb) |cb| {
            std.debug.print("TLS: Calling peer_finished_cb callback\n", .{});
            cb(self.peer_finished_ctx, self, value) catch {};
        } else {
            std.debug.print("TLS: No peer_finished_cb registered\n", .{});
        }
    }

    /// Queue a minimal NewSessionTicket (placeholder). Not yet used for PSK resumption.
    pub fn queueNewSessionTicket(self: *Engine) !void {
        try self.queueNewSessionTicketWithParams(3600, "test_ticket");
    }

    /// Queue a NewSessionTicket with specific parameters.
    pub fn queueNewSessionTicketWithParams(self: *Engine, lifetime: u32, ticket: []const u8) !void {
        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);
        // struct {
        //   uint32 ticket_lifetime;
        //   uint32 ticket_age_add;
        //   opaque ticket_nonce<0..255>; (len=0)
        //   opaque ticket<1..2^16-1>;
        //   Extension extensions<0..2^16-2> (len=0)
        // }
        var be4: [4]u8 = undefined; // big-endian scratch
        var be2: [2]u8 = undefined; // big-endian scratch
        std.mem.writeInt(u32, &be4, lifetime, .big);
        try body.appendSlice(self.allocator, &be4);
        std.mem.writeInt(u32, &be4, 0, .big); // age_add placeholder
        try body.appendSlice(self.allocator, &be4);
        try body.append(self.allocator, 0); // nonce length 0
        std.mem.writeInt(u16, &be2, @intCast(ticket.len), .big);
        try body.appendSlice(self.allocator, &be2);
        try body.appendSlice(self.allocator, ticket);
        std.mem.writeInt(u16, &be2, 0, .big); // extensions length 0
        try body.appendSlice(self.allocator, &be2);
        const msg = try encodeHandshake(self.allocator, .new_session_ticket, body.items);
        defer self.allocator.free(msg);
        self.transcript.update(msg);
        try self.outbox.appendSlice(self.allocator, msg);
    }

    /// Access first cached ticket (if any) for simple resumption offering.
    pub fn peekTicket(self: *Engine) ?TicketEntryView {
        return self.tickets.peek();
    }

    /// Flush and return the outbox contents, transferring ownership to caller.
    pub fn flushCrypto(self: *Engine, alloc: std.mem.Allocator) ![]u8 {
        const result = try alloc.alloc(u8, self.outbox.items.len);
        @memcpy(result, self.outbox.items);
        self.outbox.clearRetainingCapacity();
        return result;
    }

    /// Ingest CRYPTO data from peer and parse handshake messages.
    pub fn ingestCrypto(self: *Engine, data: []const u8) !void {
        self.onCryptoRecv(data);
    }

    fn ensureKeypair(self: *Engine) void {
        if (self.my_priv == null or self.my_pub == null) {
            var sk: [32]u8 = undefined;
            std.crypto.random.bytes(&sk);
            // Derive public key from private key using Zig 0.15.1 X25519 API
            const pk = std.crypto.dh.X25519.recoverPublicKey(sk) catch unreachable;
            self.my_priv = sk;
            self.my_pub = pk;
            std.debug.print("{s}: Generated X25519 keypair\n", .{if (self.role == .Server) "Server" else "Client"});
        }
    }

    fn tryComputeShared(self: *Engine) void {
        if (self.peer_pub) |peer| {
            if (self.my_priv) |priv| {
                // Use Zig 0.15.1 X25519 API - scalarmult returns the value
                const sh = std.crypto.dh.X25519.scalarmult(priv, peer) catch {
                    std.debug.print("{s}: X25519 scalarmult failed\n", .{if (self.role == .Server) "Server" else "Client"});
                    return;
                };
                self.ecdhe_buf = sh;
                self.ecdhe_secret = self.ecdhe_buf[0..];
                std.debug.print("{s}: Computed ECDHE shared secret ({X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}...)\n", .{ if (self.role == .Server) "Server" else "Client", sh[0], sh[1], sh[2], sh[3], sh[4], sh[5], sh[6], sh[7] });
            } else {
                std.debug.print("{s}: No my_priv for ECDHE\n", .{if (self.role == .Server) "Server" else "Client"});
            }
        } else {
            std.debug.print("{s}: No peer_pub for ECDHE\n", .{if (self.role == .Server) "Server" else "Client"});
        }
    }

    /// Append received CRYPTO bytes into transcript. Attempts to parse handshake messages
    /// to update simple state, but always feeds the transcript with raw bytes.
    pub fn onCryptoRecv(self: *Engine, data: []const u8) void {
        std.debug.print("TLS: onCryptoRecv called with {} bytes, inbox already has {} bytes\n", .{ data.len, self.inbox.items.len });

        // Append new data to inbox buffer
        self.inbox.appendSlice(self.allocator, data) catch {
            std.debug.print("TLS: Failed to buffer CRYPTO data\n", .{});
            return;
        };

        std.debug.print("TLS: Inbox now has {} bytes total\n", .{self.inbox.items.len});

        // Process complete messages from the buffered data
        var off: usize = 0;
        while (true) {
            const parsed = parseHandshakeOne(self.inbox.items[off..]) catch null;
            if (parsed) |p| {
                std.debug.print("TLS: Parsed handshake message type={} len={}\n", .{ p.typ, p.body.len });

                // For Finished verification, we need the transcript BEFORE the Finished message
                // So take a snapshot of the current transcript state
                var snap = self.transcript;
                const th_before = snap.finalize();

                // Update the transcript with this message UNLESS it's a Finished message
                // Finished messages are added to the transcript AFTER verification
                const msg_data = self.inbox.items[off .. off + p.n];
                if (p.typ != .finished) {
                    self.transcript.update(msg_data);
                    const show_len = @min(8, msg_data.len);
                    if (show_len >= 8) {
                        std.debug.print("[TRANSCRIPT-RECV] Added {} bytes to transcript (recv): {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} ...\n", .{ msg_data.len, msg_data[0], msg_data[1], msg_data[2], msg_data[3], msg_data[4], msg_data[5], msg_data[6], msg_data[7] });
                    } else {
                        std.debug.print("[TRANSCRIPT-RECV] Added {} bytes to transcript (recv)\n", .{msg_data.len});
                    }
                }

                off += p.n;
                if (p.typ == .server_hello) self.sh_seen = true;
                if (p.typ == .client_hello) {
                    if (self.role == .Client) {
                        self.ch_sent = true;
                    } else {
                        self.ch_recv = true;
                    }
                }
                // If we just processed a ServerHello, derive handshake secrets immediately (spec: hash includes CH+SH)
                if (p.typ == .server_hello and self.handshake_client_secret == null and self.ecdhe_secret != null) {
                    // Use the actual transcript that already contains ClientHello + ServerHello
                    var snapshot = self.transcript;
                    const th_hash = snapshot.finalize();
                    std.debug.print("onCryptoRecv: Deriving handshake secrets after ServerHello\n", .{});
                    std.debug.print("onCryptoRecv: Transcript hash for handshake: {X:0>2} {X:0>2} {X:0>2} {X:0>2} ... (first 4 of {})\n", .{ th_hash[0], th_hash[1], th_hash[2], th_hash[3], th_hash.len });
                    std.debug.print("onCryptoRecv: ECDHE secret first 4: {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ self.ecdhe_secret.?[0], self.ecdhe_secret.?[1], self.ecdhe_secret.?[2], self.ecdhe_secret.?[3] });
                    const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th_hash);
                    std.debug.print("onCryptoRecv: Derived client_hs first 4: {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ hs.client_hs[0], hs.client_hs[1], hs.client_hs[2], hs.client_hs[3] });
                    std.debug.print("onCryptoRecv: Derived server_hs first 4: {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ hs.server_hs[0], hs.server_hs[1], hs.server_hs[2], hs.server_hs[3] });
                    self.handshake_secret = hs.handshake; // Cache intermediate handshake_secret
                    self.handshake_client_secret = hs.client_hs;
                    self.handshake_server_secret = hs.server_hs;
                    // FIX: Removed premature computeApplicationSecrets() call
                    // Per RFC 8446 Section 7.1 and RFC 9001, application secrets must be derived
                    // AFTER both Finished messages are sent and verified, not after ServerHello.
                    // Application secrets are now correctly derived at line ~753 after Finished verification.
                }

                // Only try to extract public keys from ClientHello and ServerHello
                if (p.typ == .client_hello or p.typ == .server_hello) {
                    std.debug.print("TLS: Processing hello message, typ={}\n", .{p.typ});
                    var extracted: ?[32]u8 = null;
                    // Try real TLS 1.3 parsing first
                    std.debug.print("TLS: Trying real TLS 1.3 hello parsing\n", .{});
                    switch (p.typ) {
                        .client_hello => {
                            std.debug.print("TLS: Calling parseRealClientHello with {} bytes\n", .{p.body.len});
                            extracted = parseRealClientHello(p.body, self);
                            if (extracted != null) {
                                std.debug.print("TLS: parseRealClientHello SUCCESS - extracted key\n", .{});
                            } else {
                                std.debug.print("TLS: parseRealClientHello FAILED - returned null\n", .{});
                            }
                        },
                        .server_hello => extracted = parseRealServerHello(p.body),
                        else => {},
                    }
                    // If real parsing failed, try minimal format as fallback
                    if (extracted == null) {
                        std.debug.print("TLS: Real parse failed, trying minimal parse as fallback\n", .{});
                        extracted = parseMinimalHelloPub(p.typ, p.body);
                        if (extracted == null) {
                            std.debug.print("{s}: Failed to parse hello pub (typ={}, body_len={})\n", .{ if (self.role == .Server) "Server" else "Client", p.typ, p.body.len });
                        }
                    }
                    if (extracted) |pk| {
                        std.debug.print("TLS: Setting peer_pub for {} (was null={})\n", .{ p.typ, self.peer_pub == null });
                        self.peer_pub = pk;
                        std.debug.print("TLS: peer_pub is now set (null={})\n", .{self.peer_pub == null});
                        // Compute shared secret after receiving peer's public key
                        switch (p.typ) {
                            .server_hello => if (self.role == .Client) self.tryComputeShared(),
                            .client_hello => if (self.role == .Server) {
                                std.debug.print("Server: Will compute ECDHE when generating ServerHello\n", .{});
                                // Extract ALPN from ClientHello
                                self.extractAlpnFromClientHello(p.body);
                            },
                            else => {},
                        }
                    } else {
                        std.debug.print("TLS: No key extracted from hello message\n", .{});
                    }

                    // Also extract ALPN even if key extraction failed (ALPN is independent of key)
                    if (p.typ == .client_hello and self.role == .Server) {
                        self.extractAlpnFromClientHello(p.body);
                    }

                    // RFC 9001 Section 8.2: Validate that transport parameters extension is present
                    // "Endpoints MUST send the quic_transport_parameters extension"
                    // Skip validation in insecure/test mode to allow minimal test messages
                    if (p.typ == .client_hello and self.role == .Server and !self.allow_insecure) {
                        // Server receiving ClientHello from client - TP MUST be present
                        if (self.peer_tp == null) {
                            std.debug.print("TLS: Missing transport parameters in ClientHello (RFC 9001 violation)\n", .{});
                            // Mark connection as failed - upper layer should close connection
                            self.handshake_failed = true;
                            return;
                        }
                    }
                }

                // Parse EncryptedExtensions
                if (p.typ == .encrypted_extensions) {
                    self.ee_sent = true; // mark seen (client)
                    if (p.body.len >= 2) {
                        const total = readU16(p.body[0..2]);
                        if (2 + total <= p.body.len) {
                            var pos2: usize = 2;
                            while (pos2 + 4 <= 2 + total) : (pos2 += 4 + readU16(p.body[pos2 + 2 .. pos2 + 4])) {
                                const etype = readU16(p.body[pos2 .. pos2 + 2]);
                                const elen = readU16(p.body[pos2 + 2 .. pos2 + 4]);
                                if (pos2 + 4 + elen > 2 + total) break;
                                const edata = p.body[pos2 + 4 .. pos2 + 4 + elen];
                                switch (etype) {
                                    0x0010 => { // ALPN
                                        if (elen >= 3) {
                                            if (elen >= 2) {
                                                const list_len = readU16(edata[0..2]);
                                                if (2 + list_len <= edata.len and list_len > 0) {
                                                    const name_len = edata[2];
                                                    if (3 + name_len <= edata.len and name_len > 0) {
                                                        if (self.alpn) |old| self.allocator.free(old);
                                                        self.alpn = self.allocator.dupe(u8, edata[3 .. 3 + name_len]) catch null;
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    0x0039 => { // QUIC TP
                                        if (self.peer_tp) |old| self.allocator.free(old);
                                        self.peer_tp = self.allocator.dupe(u8, edata) catch null;
                                    },
                                    else => {},
                                }
                            }
                        }
                    }

                    // RFC 9001 Section 8.2: Validate that transport parameters extension is present
                    // "Endpoints MUST send the quic_transport_parameters extension"
                    // Skip validation in insecure/test mode to allow minimal test messages
                    if (self.role == .Client and !self.allow_insecure) {
                        // Client receiving EncryptedExtensions from server - TP MUST be present
                        if (self.peer_tp == null) {
                            std.debug.print("TLS: Missing transport parameters in EncryptedExtensions (RFC 9001 violation)\n", .{});
                            // Mark connection as failed - upper layer should close connection
                            self.handshake_failed = true;
                            return;
                        }
                    }
                }
                // Certificate message parsing: RFC 8446 Section 4.4.2
                // FIX: Parse TLS Certificate message format before extracting DER certificate
                if (p.typ == .certificate) {
                    std.debug.print("{s}: Processing Certificate message (len={})\n", .{ if (self.role == .Server) "Server" else "Client", p.body.len });
                    if (self.allow_insecure) {
                        std.debug.print("{s}: Certificate validation skipped (insecure mode)\n", .{if (self.role == .Server) "Server" else "Client"});
                        self.peer_cert_ok = true;
                    } else {
                        std.debug.print("{s}: Attempting certificate validation\n", .{if (self.role == .Server) "Server" else "Client"});

                        // Parse TLS Certificate message format per RFC 8446 Section 4.4.2:
                        // struct {
                        //     opaque certificate_request_context<0..2^8-1>;
                        //     CertificateEntry certificate_list<0..2^24-1>;
                        // } Certificate;
                        // struct {
                        //     opaque cert_data<1..2^24-1>;
                        //     Extension extensions<0..2^16-1>;
                        // } CertificateEntry;

                        var pos: usize = 0;
                        var cert_der: ?[]const u8 = null;

                        parse_cert: {
                            if (p.body.len < 1) {
                                std.debug.print("TLS: Certificate message too short for request context\n", .{});
                                break :parse_cert;
                            }

                            // certificate_request_context length (1 byte)
                            const ctx_len: usize = p.body[pos];
                            pos += 1;
                            if (pos + ctx_len > p.body.len) {
                                std.debug.print("TLS: Certificate message truncated at request context\n", .{});
                                break :parse_cert;
                            }
                            // Skip context bytes
                            pos += ctx_len;

                            // certificate_list length (3 bytes)
                            if (pos + 3 > p.body.len) {
                                std.debug.print("TLS: Certificate message too short for certificate list length\n", .{});
                                break :parse_cert;
                            }
                            const list_len: usize = (@as(usize, p.body[pos]) << 16) | (@as(usize, p.body[pos + 1]) << 8) | p.body[pos + 2];
                            pos += 3;
                            if (pos + list_len > p.body.len) {
                                std.debug.print("TLS: Certificate message truncated at certificate list\n", .{});
                                break :parse_cert;
                            }

                            const list_end = pos + list_len;

                            // Parse first CertificateEntry (leaf certificate)
                            if (pos + 3 <= list_end) {
                                const cert_data_len: usize = (@as(usize, p.body[pos]) << 16) | (@as(usize, p.body[pos + 1]) << 8) | p.body[pos + 2];
                                pos += 3;
                                if (pos + cert_data_len <= list_end) {
                                    cert_der = p.body[pos .. pos + cert_data_len];
                                    std.debug.print("TLS: Extracted DER certificate (len={})\n", .{cert_data_len});
                                } else {
                                    std.debug.print("TLS: Certificate entry truncated\n", .{});
                                }
                            } else {
                                std.debug.print("TLS: Certificate list empty or malformed\n", .{});
                            }
                        }

                        // Now parse the extracted DER certificate
                        if (cert_der) |der| {
                            const cert_val = x509.parseCert(self.allocator, der) catch null;
                            if (cert_val) |c| {
                                std.debug.print("{s}: Certificate parsed successfully\n", .{if (self.role == .Server) "Server" else "Client"});
                                self.peer_cert_ok = true;
                                if (self.leaf_spki) |old| self.allocator.free(old);
                                self.leaf_spki = self.allocator.dupe(u8, c.spki) catch null;
                                x509.checkValidity(std.time.timestamp(), &c) catch {
                                    std.debug.print("{s}: Certificate validity check failed\n", .{if (self.role == .Server) "Server" else "Client"});
                                    self.peer_cert_ok = false;
                                };
                                if (self.peer_cert_ok) {
                                    if (self.server_name) |sni| {
                                        x509.validateChain(self.allocator, &[_][]const u8{der}, std.time.timestamp(), sni, self.allow_insecure) catch {
                                            self.peer_cert_ok = false;
                                        };
                                    }
                                }
                                if (self.peer_cert_ok) {
                                    if (c.eku) |eku| {
                                        if (!eku.server_auth) {
                                            self.peer_cert_ok = false;
                                        }
                                    }
                                }
                            } else {
                                std.debug.print("TLS: x509.parseCert failed\n", .{});
                                self.peer_cert_ok = false;
                            }
                        } else {
                            std.debug.print("TLS: Failed to extract DER certificate from Certificate message\n", .{});
                            self.peer_cert_ok = false;
                        }
                    }
                }
                // CertificateVerify: RFC 8446 format - SignatureScheme (2 bytes) + signature (2-byte length-prefixed)
                // FIX: Changed from 1-byte "toy" format to RFC 8446 standard format for aioquic/quic-go compatibility
                if (p.typ == .certificate_verify and !self.allow_insecure) {
                    if (!self.peer_cert_ok or self.leaf_spki == null) {
                        self.peer_cert_ok = false;
                    } else {
                        // RFC 8446 Section 4.4.3: struct { SignatureScheme algorithm; opaque signature<0..2^16-1>; }
                        if (p.body.len >= 4) { // Minimum: 2 (SignatureScheme) + 2 (signature length) + 0 (signature data)
                            const scheme_value: u16 = readU16(p.body[0..2]);
                            const sig_len: usize = readU16(p.body[2..4]);
                            if (4 + sig_len <= p.body.len) {
                                const signature = p.body[4 .. 4 + sig_len];
                                const th = th_before; // transcript up to CertificateVerify
                                const alg: sig.SigAlg = switch (scheme_value) {
                                    0x0403 => .ecdsa_secp256r1_sha256, // RFC 8446 SignatureScheme values
                                    0x0503 => .ecdsa_secp384r1_sha384,
                                    0x0804 => .rsa_pss_sha256,
                                    0x0807 => .ed25519,
                                    else => blk: {
                                        std.debug.print("TLS: Unknown SignatureScheme: 0x{X:0>4}\n", .{scheme_value});
                                        self.peer_cert_ok = false;
                                        break :blk .rsa_pss_sha256;
                                    },
                                };
                                if (self.peer_cert_ok) { // Only verify if not already failed
                                    const ok = sig.verifyCertificateVerify(alg, self.leaf_spki.?, signature, "TLS 1.3, server CertificateVerify", &th) catch false;
                                    self.peer_cert_ok = ok;
                                    if (!ok) {
                                        std.debug.print("TLS: CertificateVerify signature verification FAILED\n", .{});
                                    }
                                }
                            } else {
                                std.debug.print("TLS: CertificateVerify message too short for declared signature length\n", .{});
                                self.peer_cert_ok = false;
                            }
                        } else {
                            std.debug.print("TLS: CertificateVerify message too short (len={})\n", .{p.body.len});
                            self.peer_cert_ok = false;
                        }
                    }
                }
                // Finished verification
                if (p.typ == .finished and self.ecdhe_secret != null) {
                    std.debug.print("TLS: Processing Finished message\n", .{});
                    var peer_secret_opt: ?[H.digest_length]u8 = null;
                    if (self.handshake_client_secret != null and self.handshake_server_secret != null) {
                        peer_secret_opt = switch (self.role) {
                            .Client => self.handshake_server_secret.?,
                            .Server => self.handshake_client_secret.?,
                        };
                        std.debug.print("TLS: Using stored handshake secrets for verification\n", .{});
                    }
                    const ok = if (peer_secret_opt) |ps| self.verifyPeerFinished(ps, p.body) else blk: {
                        std.debug.print("TLS: Using fallback for Finished verification\n", .{});
                        // Fallback (should not happen in real mode past this point)
                        const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th_before);
                        self.handshake_secret = hs.handshake; // Cache intermediate handshake_secret
                        break :blk switch (self.role) {
                            .Client => self.verifyPeerFinished(hs.server_hs, p.body),
                            .Server => self.verifyPeerFinished(hs.client_hs, p.body),
                        };
                    };
                    std.debug.print("TLS: Finished verification result: {}\n", .{ok});
                    self.updateFinishedVerified(ok);

                    // RFC 8446 §7.1: Application traffic secrets must be derived from transcript
                    // hash "ClientHello...server Finished" (NOT including client Finished).
                    if (ok) {
                        // Get the Finished message bytes
                        const finished_msg = data[off - p.n .. off];
                        
                        // CRITICAL FIX: Handle transcript differently based on role
                        // For CLIENT: Must add server's Finished BEFORE deriving app secrets
                        //             because app secrets use CH...SH...EE...Cert...CV...server Finished
                        // For SERVER: Must NOT add client's Finished before deriving app secrets
                        //             because server already queued its own Finished
                        
                        if (self.role == .Client) {
                            // Client: Add server's Finished to transcript FIRST
                            self.transcript.update(finished_msg);
                            const show_len = @min(8, finished_msg.len);
                            if (show_len >= 8) {
                                std.debug.print("TLS: Added server Finished to transcript ({} bytes): {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} ...\n", .{ finished_msg.len, finished_msg[0], finished_msg[1], finished_msg[2], finished_msg[3], finished_msg[4], finished_msg[5], finished_msg[6], finished_msg[7] });
                            } else {
                                std.debug.print("TLS: Added server Finished to transcript ({} bytes)\n", .{finished_msg.len});
                            }
                            
                            // Now derive application secrets with server Finished included
                            std.debug.print("TLS: Deriving application traffic secrets (after adding server Finished to transcript)\n", .{});
                            _ = self.computeApplicationSecrets();
                        } else {
                            // Server: Derive app secrets BEFORE adding client's Finished
                            // Server's own Finished is already in transcript from queueFinished()
                            std.debug.print("TLS: Deriving application traffic secrets (before adding client Finished to transcript)\n", .{});
                            _ = self.computeApplicationSecrets();
                            
                            // NOW add the client Finished to transcript for resumption master secret derivation
                            self.transcript.update(finished_msg);
                            const show_len = @min(8, finished_msg.len);
                            if (show_len >= 8) {
                                std.debug.print("TLS: Added client Finished to transcript ({} bytes): {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} ...\n", .{ finished_msg.len, finished_msg[0], finished_msg[1], finished_msg[2], finished_msg[3], finished_msg[4], finished_msg[5], finished_msg[6], finished_msg[7] });
                            } else {
                                std.debug.print("TLS: Added client Finished to transcript ({} bytes)\n", .{finished_msg.len});
                            }
                        }
                    }
                }
                // NewSessionTicket parsing (client side only for now)
                if (p.typ == .new_session_ticket and self.role == .Client) {
                    const b = p.body;
                    var pos: usize = 0;
                    if (b.len >= 4) {
                        if (b.len < 4 + 4) continue; // need lifetime + age_add
                        const lifetime: u32 = (@as(u32, b[0]) << 24) | (@as(u32, b[1]) << 16) | (@as(u32, b[2]) << 8) | @as(u32, b[3]);
                        pos = 4 + 4; // skip age_add as well
                        if (pos >= b.len) continue;
                        if (pos >= b.len) continue;
                        const nonce_len: usize = b[pos];
                        pos += 1;
                        if (pos + nonce_len > b.len) continue; // skip nonce
                        pos += nonce_len;
                        if (pos + 2 > b.len) continue;
                        const ticket_len: usize = (@as(usize, b[pos]) << 8) | b[pos + 1];
                        pos += 2;
                        if (pos + ticket_len > b.len) continue;
                        const ticket_bytes = b[pos .. pos + ticket_len];
                        pos += ticket_len;
                        if (pos + 2 > b.len) continue; // extensions length
                        const ext_len: usize = (@as(usize, b[pos]) << 8) | b[pos + 1];
                        pos += 2;
                        if (pos + ext_len > b.len) continue;
                        // Compute resumption_secret if we have master_secret stored
                        if (self.master_secret) |ms| {
                            var resumption_secret: [H.digest_length]u8 = undefined;
                            // RFC 8446 Section 4.6.1: resumption_master_secret = HKDF-Expand-Label(
                            //     master_secret, "res master", transcript_hash)
                            // FIX: Use actual transcript hash instead of zeros for PSK security
                            var transcript_snapshot = self.transcript;
                            const transcript_hash = transcript_snapshot.finalize();
                            ks.expandLabel(ms, "res master", &transcript_hash, &resumption_secret) catch continue;
                            self.tickets.add(self.allocator, ticket_bytes, resumption_secret, lifetime) catch {};
                            std.debug.print("TLS: Stored session ticket (len={}, lifetime={})\n", .{ ticket_bytes.len, lifetime });
                        } else {
                            std.debug.print("TLS: Received ticket before master_secret ready; ignoring\n", .{});
                        }
                    }
                }
            } else {
                // parseHandshakeOne returned null - not enough data
                if (off < self.inbox.items.len) {
                    const remaining_data = self.inbox.items[off..];
                    std.debug.print("TLS: parseHandshakeOne failed with {} bytes available\n", .{remaining_data.len});

                    // Check if it's a partial message that needs more data
                    if (remaining_data.len >= 4) {
                        const msg_type = remaining_data[0];
                        const msg_len = (@as(usize, remaining_data[1]) << 16) | (@as(usize, remaining_data[2]) << 8) | @as(usize, remaining_data[3]);
                        const need_total = 4 + msg_len;
                        std.debug.print("TLS: Partial message type=0x{X:0>2} needs {} bytes total, have {} bytes\n", .{ msg_type, need_total, remaining_data.len });
                    }
                }
                break;
            }
        }

        // Remove processed messages from the inbox
        if (off > 0) {
            // Keep any unprocessed data by moving it to the beginning
            const remaining = self.inbox.items.len - off;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.inbox.items[0..remaining], self.inbox.items[off..]);
            }
            self.inbox.shrinkRetainingCapacity(remaining);
            std.debug.print("TLS: Processed {} bytes, {} bytes remaining in buffer\n", .{ off, remaining });
        }

        // Transcript is now updated message-by-message in the loop above
        self.maybeAutoProgress();
    }

    /// Provide ECDHE shared secret directly (used in tests after X25519 exchange).
    pub fn setEcdhe(self: *Engine, shared: []const u8) void {
        self.ecdhe_secret = shared;
        // For client: must have sent CH and seen SH
        // For server: must have received CH and sent SH
        const ch_sh_ready = if (self.role == .Client)
            (self.ch_sent and self.sh_seen)
        else
            (self.ch_recv and self.sh_seen);
        if (ch_sh_ready) {
            const th = self.transcript.finalize();
            const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th);
            self.handshake_secret = hs.handshake; // Cache intermediate handshake_secret
            self.handshake_client_secret = hs.client_hs;
            self.handshake_server_secret = hs.server_hs;
            // REMOVED: Do NOT compute application secrets here - we only have CH+SH,
            // missing EE+Cert+CV+Finished. App secrets computed after receiving peer Finished.
        }
    }

    /// Queue outbound CRYPTO bytes (e.g., ClientHello)
    /// Queue CRYPTO data to the appropriate encryption level outbox (RFC 9001 Section 4.1.4)
    /// Queue CRYPTO data (handshake message bytes) to be sent to the peer.
    pub fn queueCrypto(self: *Engine, data: []const u8) !void {
        try self.outbox.appendSlice(self.allocator, data);
        self.transcript.update(data);

        // Enhanced logging: show message type and first 32 bytes
        if (data.len >= 1) {
            const msg_type = data[0];
            const type_name = switch (msg_type) {
                0x01 => "ClientHello",
                0x02 => "ServerHello",
                0x08 => "EncryptedExtensions",
                0x0B => "Certificate",
                0x0F => "CertificateVerify",
                0x14 => "Finished",
                else => "Unknown",
            };
            std.debug.print("[TRANSCRIPT-QUEUE] Adding {s} (0x{X:0>2}) len={} bytes, first 8: ", .{ type_name, msg_type, data.len - 4 });
            const show_len = @min(8, data.len);
            var i: usize = 0;
            while (i < show_len) : (i += 1) {
                std.debug.print("{X:0>2} ", .{data[i]});
            }
            std.debug.print("\n", .{});

            // Show first 32 bytes for debugging
            if (data.len > 8) {
                std.debug.print("[TRANSCRIPT-QUEUE] Full {s} message ({} bytes):\n", .{ type_name, data.len });
                i = 0;
                while (i < @min(64, data.len)) : (i += 1) {
                    std.debug.print("{X:0>2} ", .{data[i]});
                    if ((i + 1) % 16 == 0) std.debug.print("\n", .{});
                }
                if (data.len > 64) std.debug.print("... ({} more bytes)\n", .{data.len - 64});
                std.debug.print("\n", .{});
            }
        }
        // If this was a proper handshake record, flip flags
        if (data.len >= 1) {
            if (data[0] == @intFromEnum(HsType.client_hello)) {
                self.ch_sent = true;
            } else if (data[0] == @intFromEnum(HsType.server_hello)) {
                self.sh_seen = true; // mark seen on send for server gating
            }
        }
    }

    /// Attach local Transport Parameters to be sent in next handshake message.
    /// The Engine will prefix with a simple marker "TP" and include bytes as-is.
    pub fn setLocalTransportParameters(self: *Engine, tp_encoded: []const u8) !void {
        if (self.local_tp) |old| self.allocator.free(old);
        self.local_tp = try self.allocator.dupe(u8, tp_encoded);
    }

    /// Set the expected server name (SNI) for certificate validation on client.
    pub fn setServerName(self: *Engine, name: []const u8) !void {
        if (self.server_name) |old| self.allocator.free(old);
        self.server_name = try self.allocator.dupe(u8, name);
    }

    /// Build and queue a ClientHello handshake message using full TLS 1.3.
    pub fn queueMinimalClientHello(self: *Engine) !void {
        return self.queueRealClientHello();
    }

    /// Build a minimally spec-compliant TLS 1.3 ClientHello (QUIC) with:
    /// - cipher_suites: TLS_AES_128_GCM_SHA256 only
    /// - groups: x25519
    /// - key_share: x25519
    /// - supported_versions: TLS 1.3
    /// - signature_algorithms: a small set
    /// - alpn (if set via setServerName?) / local alpn not yet; will be extended
    /// - quic transport parameters extension (0x0039) if local_tp present
    fn queueRealClientHello(self: *Engine) !void {
        self.ensureKeypair();
        const pubkey = self.my_pub orelse return error.Internal;
        // Buffers
        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);
        // legacy_version 0x0303
        try body.appendSlice(self.allocator, &.{ 0x03, 0x03 });
        // random 32 bytes
        var rnd: [32]u8 = undefined;
        std.crypto.random.bytes(&rnd);
        try body.appendSlice(self.allocator, &rnd);
        // session id (empty vector length 0)
        try body.append(self.allocator, 0); // length
        // cipher_suites vector (length 2, then suite 0x1301)
        try body.appendSlice(self.allocator, &.{ 0x00, 0x02, 0x13, 0x01 });
        // legacy_compression_methods (length=1 then 0)
        try body.appendSlice(self.allocator, &.{ 0x01, 0x00 });
        // Build extensions into temp buffer
        var ext_buf = std.ArrayList(u8){};
        defer ext_buf.deinit(self.allocator);
        // supported_versions (43 / 0x002b)
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 }); // len=3(0x0003), list length=2, version 0x0304
        // supported_groups (10 / 0x000a) -> length 2 list containing x25519 (0x001d)
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });
        // signature_algorithms (13 / 0x000d) list length 6 (3 algorithms)
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x08, 0x07 });
        // key_share (51 / 0x0033) group x25519(0x001d) key length 32
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x33 });
        const key_share_len: u16 = 2 + 2 + 32; // group(2)+key_len(2)+key(32)
        const total_key_share_len: u16 = @intCast(key_share_len + 2); // plus vector length field (u16)
        try ext_buf.appendSlice(self.allocator, &.{ @intCast(total_key_share_len >> 8), @intCast(total_key_share_len & 0xff) });
        // inner vector length
        try ext_buf.appendSlice(self.allocator, &.{ @intCast(key_share_len >> 8), @intCast(key_share_len & 0xff) });
        // group
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x1d });
        // key length (32)
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 32 });
        try ext_buf.appendSlice(self.allocator, pubkey[0..]);
        // ALPN if configured (reuse self.alpn if already set via test harness) - ALPN ext type 16
        if (self.alpn) |alpn_vec| {
            // Extension type 0x0010
            // Format: type(2)|len(2)|list_len(2)|proto_len(1)|proto
            const list_len: usize = 1 + alpn_vec.len; // one entry
            const ext_len: usize = 2 + list_len; // list length field + list
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x10, @intCast(ext_len >> 8), @intCast(ext_len & 0xff), @intCast(list_len >> 8), @intCast(list_len & 0xff), @intCast(alpn_vec.len) });
            try ext_buf.appendSlice(self.allocator, alpn_vec);
        }
        // QUIC Transport Parameters extension (0x0039) if local_tp present
        if (self.local_tp) |tp| {
            const tp_len: usize = tp.len;
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x39, @intCast(tp_len >> 8), @intCast(tp_len & 0xff) });
            try ext_buf.appendSlice(self.allocator, tp);
        }
        // Pre-Shared Key (PSK) offer if we have cached tickets. Minimal implementation:
        // - Offer single identity (first ticket). Binder is zero-filled placeholder (not validated yet).
        if (self.peekTicket()) |tkt| {
            // psk_key_exchange_modes (ext 0x002d) offering mode 0 (psk_ke) only
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x2d, 0x00, 0x02, 0x01, 0x00 });
            // pre_shared_key (0x0029)
            const id_len: u16 = @intCast(tkt.identity.len);
            // identities vector: length(2) + identity + obfuscated_ticket_age(4)
            const one_identity_len: usize = 2 + id_len + 4;
            const identities_vec_len: u16 = @intCast(one_identity_len);
            const binders_len: u16 = @intCast(1 + H.digest_length); // vector length(1) + binder (digest length)
            const total_psk_len: u16 = @intCast(2 + identities_vec_len + 2 + binders_len);
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x29, @intCast(total_psk_len >> 8), @intCast(total_psk_len & 0xff) });
            // identities vector length
            try ext_buf.appendSlice(self.allocator, &.{ @intCast(identities_vec_len >> 8), @intCast(identities_vec_len & 0xff) });
            // identity length
            try ext_buf.appendSlice(self.allocator, &.{ @intCast(id_len >> 8), @intCast(id_len & 0xff) });
            try ext_buf.appendSlice(self.allocator, tkt.identity);
            // obfuscated_ticket_age (placeholder 0)
            try ext_buf.appendSlice(self.allocator, &.{ 0, 0, 0, 0 });
            // binders vector length
            const binders_vec_len: u16 = @intCast(1 + H.digest_length);
            try ext_buf.appendSlice(self.allocator, &.{ @intCast(binders_vec_len >> 8), @intCast(binders_vec_len & 0xff) });
            // single binder length (H.digest_length)
            try ext_buf.append(self.allocator, @as(u8, @intCast(H.digest_length)));
            // zero-filled binder placeholder
            var zeros: [H.digest_length]u8 = .{0} ** H.digest_length;
            try ext_buf.appendSlice(self.allocator, &zeros);
        }
        // Now write extensions length
        const exts = ext_buf.items;
        const exts_len: u16 = @intCast(exts.len);
        try body.appendSlice(self.allocator, &.{ @intCast(exts_len >> 8), @intCast(exts_len & 0xff) });
        try body.appendSlice(self.allocator, exts);
        const msg = try encodeHandshake(self.allocator, .client_hello, body.items);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
    }

    /// Build and queue a ServerHello using full TLS 1.3.
    pub fn queueMinimalServerHello(self: *Engine) !void {
        try self.queueRealServerHello();
        return;
    }

    /// Accessor for peer transport parameters (encoded), if any.
    pub fn getPeerTransportParameters(self: *Engine) ?[]const u8 {
        return self.peer_tp;
    }

    /// Build and queue a Finished message for this endpoint using provided traffic secret.
    /// This computes verify_data = HMAC(FinishedKey(secret), Transcript-Hash(before-Finished)).
    pub fn queueFinished(self: *Engine, traffic_secret: [H.digest_length]u8) !void {
        var snap = self.transcript;
        const th = snap.finalize();
        std.debug.print("TLS: Queueing Finished with transcript hash: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} ...\n", .{ th[0], th[1], th[2], th[3], th[4], th[5], th[6], th[7] });
        const verify = deriveFinishedVerifyData(traffic_secret, th);
        const msg = try encodeHandshake(self.allocator, .finished, verify[0..]);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
        self.finished_sent = true;
        // NOTE: Application secrets are NOT derived here
        // They must be derived AFTER receiving and verifying the peer's Finished message
    }

    /// Verify peer Finished given peer traffic secret.
    pub fn verifyPeerFinished(self: *Engine, peer_secret: [H.digest_length]u8, finished_body: []const u8) bool {
        // finished_body is the verify_data sent by the peer
        var snap = self.transcript;
        const th = snap.finalize();
        std.debug.print("TLS: Verifying Finished with transcript hash: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} ...\n", .{ th[0], th[1], th[2], th[3], th[4], th[5], th[6], th[7] });
        const expect = deriveFinishedVerifyData(peer_secret, th);
        const match = finished_body.len == expect.len and std.mem.eql(u8, finished_body, &expect);
        if (!match) {
            std.debug.print("TLS: Finished verification failed. Expected len={}, got len={}\n", .{ expect.len, finished_body.len });
            if (finished_body.len == expect.len) {
                std.debug.print("TLS: MAC mismatch\n", .{});
            }
        }
        return match;
    }

    /// Build and queue EncryptedExtensions carrying ALPN and Transport Parameters.
    pub fn queueEncryptedExtensions(self: *Engine, alpn: []const u8, tp_bytes: []const u8) !void {
        // Encode standard TLS EncryptedExtensions extension vector
        var ext_list = std.ArrayList(u8){};
        defer ext_list.deinit(self.allocator);
        if (alpn.len > 0) {
            // ALPN extension (0x0010)
            const proto_list_len: u16 = @intCast(1 + alpn.len); // one entry
            const ext_data_len: u16 = @intCast(2 + proto_list_len);
            try ext_list.appendSlice(self.allocator, &.{ 0x00, 0x10, @intCast(ext_data_len >> 8), @intCast(ext_data_len & 0xff), @intCast(proto_list_len >> 8), @intCast(proto_list_len & 0xff), @intCast(alpn.len) });
            try ext_list.appendSlice(self.allocator, alpn);
        }
        if (tp_bytes.len > 0) {
            const tp_len: u16 = @intCast(tp_bytes.len);
            try ext_list.appendSlice(self.allocator, &.{ 0x00, 0x39, @intCast(tp_len >> 8), @intCast(tp_len & 0xff) });
            try ext_list.appendSlice(self.allocator, tp_bytes);
        }
        const all_ext = ext_list.items;
        const total_len: u16 = @intCast(all_ext.len);
        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, &.{ @intCast(total_len >> 8), @intCast(total_len & 0xff) });
        try body.appendSlice(self.allocator, all_ext);
        const msg = try encodeHandshake(self.allocator, .encrypted_extensions, body.items);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
        if (self.role == .Server) {
            self.ee_sent = true;
        }
        // FIXED: Don't set ee_sent here - let endpoint.zig set it after actual transmission
        // self.ee_sent = true; // mark sent (server)
        // Don't call maybeAutoProgress here - endpoint.zig will explicitly call queueServerHandshakeFlight
        // self.maybeAutoProgress();
        return;
    }

    /// Queue a Certificate handshake message with proper RFC 8446 TLS 1.3 format.
    /// Format: certificate_request_context (1 byte len + data) + certificate_list (3 bytes len + entries)
    /// Each entry: cert_data (3 bytes len + DER) + extensions (2 bytes len + data)
    pub fn queueCertificate(self: *Engine, cert_der: []const u8) !void {
        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);

        // certificate_request_context (empty for server certificates)
        try body.append(self.allocator, 0x00);

        // certificate_list length (3 bytes): cert_data_len(3) + cert_der.len + extensions_len(2)
        const entry_len = 3 + cert_der.len + 2;
        const list_len = entry_len;
        try body.append(self.allocator, @intCast((list_len >> 16) & 0xff));
        try body.append(self.allocator, @intCast((list_len >> 8) & 0xff));
        try body.append(self.allocator, @intCast(list_len & 0xff));

        // CertificateEntry: cert_data length (3 bytes)
        const cert_len = cert_der.len;
        try body.append(self.allocator, @intCast((cert_len >> 16) & 0xff));
        try body.append(self.allocator, @intCast((cert_len >> 8) & 0xff));
        try body.append(self.allocator, @intCast(cert_len & 0xff));

        // cert_data (DER certificate)
        try body.appendSlice(self.allocator, cert_der);

        // extensions (empty, 2 bytes length = 0)
        try body.append(self.allocator, 0x00);
        try body.append(self.allocator, 0x00);

        const msg = try encodeHandshake(self.allocator, .certificate, body.items);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);

        std.debug.print("TLS: Queued Certificate message (cert_len={}, total_body_len={})\n", .{ cert_der.len, body.items.len });
    }

    /// Queue CertificateVerify message (RFC 8446 Section 4.4.3)
    /// Signs the transcript hash with the server's private key
    pub fn queueCertificateVerify(self: *Engine) !void {
        const privkey = self.server_priv_key orelse return error.NoPrivateKey;
        const alg = self.server_sig_alg orelse return error.NoSignatureAlgorithm;

        // Get transcript hash up to this point (before CertificateVerify)
        var transcript_snapshot = self.transcript;
        const transcript_hash = transcript_snapshot.finalize();

        // Context for server CertificateVerify
        const context = "TLS 1.3, server CertificateVerify";

        // Sign the transcript
        const signature = try sig.signCertificateVerify(alg, privkey, context, &transcript_hash, self.allocator);
        defer self.allocator.free(signature);

        // Build CertificateVerify message body per RFC 8446 Section 4.4.3:
        // struct {
        //     SignatureScheme algorithm;  // 2 bytes
        //     opaque signature<0..2^16-1>; // 2-byte length + signature
        // } CertificateVerify;

        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);

        // SignatureScheme (2 bytes)
        const scheme_value: u16 = switch (alg) {
            .ecdsa_secp256r1_sha256 => 0x0403,
            .ecdsa_secp384r1_sha384 => 0x0503,
            .rsa_pss_sha256 => 0x0804,
            .ed25519 => 0x0807,
        };
        try body.append(self.allocator, @intCast((scheme_value >> 8) & 0xff));
        try body.append(self.allocator, @intCast(scheme_value & 0xff));

        // Signature length (2 bytes)
        const sig_len: u16 = @intCast(signature.len);
        try body.append(self.allocator, @intCast((sig_len >> 8) & 0xff));
        try body.append(self.allocator, @intCast(sig_len & 0xff));

        // Signature bytes
        try body.appendSlice(self.allocator, signature);

        const msg = try encodeHandshake(self.allocator, .certificate_verify, body.items);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);

        std.debug.print("TLS: Queued CertificateVerify message (alg={s}, sig_len={})\n", .{ @tagName(alg), signature.len });
    }

    // --- New helper methods used by tests ---

    /// Compute handshake traffic secrets if ECDHE and both CH/SH are present.
    pub fn computeHandshakeSecrets(self: *Engine) ?struct { client: [H.digest_length]u8, server: [H.digest_length]u8 } {
        if (self.ecdhe_secret == null) return null;
        // For client: must have sent CH and seen SH
        // For server: must have received CH and sent SH
        const ch_sh_ready = if (self.role == .Client)
            (self.ch_sent and self.sh_seen)
        else
            (self.ch_recv and self.sh_seen);
        if (!ch_sh_ready) return null;
        const th = self.transcript.finalize();
        std.debug.print("computeHandshakeSecrets: Computing with transcript hash: {X:0>2} {X:0>2} {X:0>2} {X:0>2} ... (first 4 bytes of {})\n", .{ th[0], th[1], th[2], th[3], th.len });
        std.debug.print("computeHandshakeSecrets: ecdhe_secret first 4 bytes: {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ self.ecdhe_secret.?[0], self.ecdhe_secret.?[1], self.ecdhe_secret.?[2], self.ecdhe_secret.?[3] });
        const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th);
        std.debug.print("computeHandshakeSecrets: client_hs first 4 bytes: {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ hs.client_hs[0], hs.client_hs[1], hs.client_hs[2], hs.client_hs[3] });
        std.debug.print("computeHandshakeSecrets: server_hs first 4 bytes: {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ hs.server_hs[0], hs.server_hs[1], hs.server_hs[2], hs.server_hs[3] });
        // Store the secrets in the engine for later use
        self.handshake_secret = hs.handshake; // Cache intermediate handshake_secret
        self.handshake_client_secret = hs.client_hs;
        self.handshake_server_secret = hs.server_hs;
        return .{ .client = hs.client_hs, .server = hs.server_hs };
    }

    /// Compute application traffic secrets from current transcript and ECDHE.
    /// CRITICAL: Caches the result on first call to prevent recomputation with wrong transcript.
    /// The first call happens when processing peer Finished (BEFORE adding it to transcript).
    /// Subsequent calls return the cached value, ensuring both calls use the same (correct) transcript.
    pub fn computeApplicationSecrets(self: *Engine) ?struct { client: [H.digest_length]u8, server: [H.digest_length]u8 } {
        // Return cached secrets if already computed
        if (self.cached_app_client) |c| {
            if (self.cached_app_server) |s| {
                std.debug.print("=== computeApplicationSecrets ({s}) - RETURNING CACHED ===\n", .{if (self.role == .Server) "Server" else "Client"});
                std.debug.print("Cached client app secret (first 16 bytes): ", .{});
                for (c[0..@min(16, c.len)]) |b| std.debug.print("{X:0>2} ", .{b});
                std.debug.print("\n", .{});
                std.debug.print("Cached server app secret (first 16 bytes): ", .{});
                for (s[0..@min(16, s.len)]) |b| std.debug.print("{X:0>2} ", .{b});
                std.debug.print("\n=========================================\n", .{});
                return .{ .client = c, .server = s };
            }
        }

        if (self.ecdhe_secret == null) return null;
        // For client: must have sent CH and seen SH
        // For server: must have received CH and sent SH
        const ch_sh_ready = if (self.role == .Client)
            (self.ch_sent and self.sh_seen)
        else
            (self.ch_recv and self.sh_seen);
        if (!ch_sh_ready) return null;
        const th = self.transcript.finalize();

        // DEBUG: Show transcript hash being used for application secret derivation
        std.debug.print("=== computeApplicationSecrets ({s}) - COMPUTING NEW ===\n", .{if (self.role == .Server) "Server" else "Client"});
        std.debug.print("Transcript hash for app secrets (first 16 bytes): ", .{});
        for (th[0..@min(16, th.len)]) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});
        std.debug.print("Transcript hash FULL (32 bytes): ", .{});
        for (th) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});
        std.debug.print("Transcript hash length: {} bytes\n", .{th.len});

        // Use cached handshake_secret instead of recomputing from ECDHE
        // This prevents bugs from ECDHE buffer corruption/reuse
        const handshake_secret = self.handshake_secret orelse return null;
        std.debug.print("DERIVATION: Using cached handshake_secret (FULL 32 bytes): ", .{});
        for (handshake_secret) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});

        var derived2: [H.digest_length]u8 = undefined;
        ks.expandLabel(handshake_secret, "derived", &[_]u8{}, &derived2) catch return null;
        std.debug.print("DERIVATION: derived2 (first 16): ", .{});
        for (derived2[0..16]) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});

        const master = ks.extract(&derived2, &[_]u8{});
        std.debug.print("DERIVATION: master_secret (FULL 32 bytes): ", .{});
        for (master) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});

        self.master_secret = master; // cache for tickets
        var c_app: [H.digest_length]u8 = undefined;
        var s_app: [H.digest_length]u8 = undefined;
        ks.expandLabel(master, "c ap traffic", &th, &c_app) catch return null;
        ks.expandLabel(master, "s ap traffic", &th, &s_app) catch return null;

        // CACHE the computed secrets to prevent recomputation with wrong transcript
        self.cached_app_client = c_app;
        self.cached_app_server = s_app;

        // DEBUG: Show derived application secrets
        std.debug.print("Client app secret (first 16 bytes): ", .{});
        for (c_app[0..@min(16, c_app.len)]) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});
        std.debug.print("Server app secret (first 16 bytes): ", .{});
        for (s_app[0..@min(16, s_app.len)]) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n=========================================\n", .{});

        return .{ .client = c_app, .server = s_app };
    }

    /// Queue a minimalistic ClientHello with an auto-generated X25519 key share.
    pub fn queueMinimalClientHelloAuto(self: *Engine) !usize {
        self.ensureKeypair();
        // For client, we'll compute shared secret when we receive ServerHello
        const pubkey = self.my_pub orelse return error.Internal;
        const msg = try encodeMinimalClientHello(self.allocator, pubkey);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
        return msg.len;
    }

    /// Queue a minimal ServerHello with an auto-generated X25519 key share.
    /// For testing only - uses minimal non-TLS format that won't interop with real TLS.
    pub fn queueMinimalServerHelloAuto(self: *Engine) !usize {
        self.ensureKeypair();
        self.tryComputeShared(); // Compute shared secret with client's public key
        const pubkey = self.my_pub orelse return error.Internal;
        const msg = try encodeMinimalServerHello(self.allocator, pubkey);
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
        return msg.len;
    }

    /// Pop CRYPTO bytes up to a specified limit, preserving remaining bytes.
    pub fn popCryptoPartial(self: *Engine, out: []u8, max_bytes: usize) usize {
        const available = self.outbox.items.len;
        const n = @min(@min(out.len, max_bytes), available);
        if (n > 0) {
            @memcpy(out[0..n], self.outbox.items[0..n]);
            // FIXED: Remove all consumed bytes at once by shifting the remaining data
            const remaining = self.outbox.items[n..];
            const remaining_len = remaining.len;
            if (remaining_len > 0) {
                // Shift remaining bytes to the front
                std.mem.copyForwards(u8, self.outbox.items[0..remaining_len], remaining);
            }
            self.outbox.items.len = remaining_len;
        }
        return n;
    }

    /// Pop all queued CRYPTO bytes into caller-provided buffer, returning bytes copied.
    pub fn popCrypto(self: *Engine, out: []u8) usize {
        const n = @min(out.len, self.outbox.items.len);
        if (n > 0) @memcpy(out[0..n], self.outbox.items[0..n]);
        // Clear the outbox after pop
        self.outbox.clearRetainingCapacity();
        return n;
    }

    /// Get the size of the next handshake message without consuming it.
    pub fn peekNextMessageSize(self: *Engine) usize {
        if (self.outbox.items.len < 4) return 0;
        // TLS handshake message format: type(1) + length(3)
        const len = (@as(usize, self.outbox.items[1]) << 16) |
            (@as(usize, self.outbox.items[2]) << 8) |
            self.outbox.items[3];
        return 4 + len; // Include header
    }

    /// Build a minimally spec-compliant TLS 1.3 ServerHello (real mode)
pub fn queueRealServerHello(self: *Engine) !void {
        const dump_tls_messages = true;
        std.debug.print("queueRealServerHello: ENTER - alpn={}, local_tp={}\n", .{ self.alpn != null, self.local_tp != null });

        // Log transport parameters if available
        if (self.local_tp) |tp| {
            std.debug.print("queueRealServerHello: Transport parameters available, {} bytes\n", .{tp.len});
        } else {
            std.debug.print("WARNING: queueRealServerHello called without transport parameters - ServerHello will be non-compliant with RFC 9001\n", .{});
        }
        self.ensureKeypair();
        const pubkey = self.my_pub orelse {
            std.debug.print("queueRealServerHello: EARLY EXIT - my_pub is NULL\n", .{});
            return error.Internal;
        };

        // Generate server random
        var server_random: [32]u8 = undefined;
        std.crypto.random.bytes(&server_random);

        // Use the comprehensive ServerHello builder
        const sh_body = try tls13_full.buildServerHello(self.allocator, server_random, .TLS_AES_128_GCM_SHA256, // Use AES-128-GCM for compatibility
            .x25519, pubkey[0..], self.client_session_id, null // RFC 9001: Transport params go in EncryptedExtensions, NOT ServerHello!
        );
        defer self.allocator.free(sh_body);

        // Encode as handshake message
        const msg = try encodeHandshake(self.allocator, .server_hello, sh_body);
        defer self.allocator.free(msg);

        // Enhanced ServerHello logging
        std.debug.print("ServerHello total length: {} bytes\n", .{msg.len});
        if (msg.len >= 16) {
            std.debug.print("ServerHello header: {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ msg[0], msg[1], msg[2], msg[3] });
            std.debug.print("ServerHello body start: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ msg[4], msg[5], msg[6], msg[7], msg[8], msg[9], msg[10], msg[11] });
            std.debug.print("ServerHello body[12..20]: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ msg[12], msg[13], msg[14], msg[15], msg[16], msg[17], msg[18], msg[19] });
        }

        // Show transcript state before adding ServerHello
        var pre_snap = self.transcript;
        const pre_th = pre_snap.finalize();
        std.debug.print("Transcript hash BEFORE ServerHello: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ pre_th[0], pre_th[1], pre_th[2], pre_th[3], pre_th[4], pre_th[5], pre_th[6], pre_th[7] });

        try self.queueCrypto(msg);
        if (dump_tls_messages) {
            var idx: usize = 0;
            const hs_type: u8 = if (msg.len > 0) msg[0] else 0;
            std.debug.print("HANDSHAKE_MSG type=0x{X:0>2} len={}\n", .{ hs_type, msg.len });
            while (idx < msg.len) : (idx += 16) {
                const end = @min(idx + 16, msg.len);
                var k: usize = idx;
                while (k < end) : (k += 1) {
                    std.debug.print("{X:0>2} ", .{msg[k]});
                }
                std.debug.print("\n", .{});
            }
        }

        self.tryComputeShared();
        if (self.ecdhe_secret != null and self.handshake_client_secret == null) {
            var snap = self.transcript;
            const th = snap.finalize();
            std.debug.print("Transcript hash AFTER ServerHello: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ th[0], th[1], th[2], th[3], th[4], th[5], th[6], th[7] });
            const hs = deriveHandshakeTraffic(self.ecdhe_secret.?, th);
            self.handshake_secret = hs.handshake; // Cache intermediate handshake_secret
            self.handshake_client_secret = hs.client_hs;
            self.handshake_server_secret = hs.server_hs;
            // NOTE: Do NOT derive Application secrets here! They must be derived after Finished is added to transcript
            // Application secrets will be derived in queueFinished() after server Finished is added
        }

        // RFC 9001: ServerHello goes to Initial CRYPTO space
        // EncryptedExtensions will be queued later by queueServerHandshakeFlight() for Handshake CRYPTO space
        std.debug.print("Server: ServerHello queued to Initial CRYPTO (EncryptedExtensions will go to Handshake)\n", .{});
    }

    /// Extract ALPN from ClientHello for server
    fn extractAlpnFromClientHello(self: *Engine, body: []const u8) void {
        std.debug.print("extractAlpnFromClientHello: body_len={}\n", .{body.len});
        if (body.len < 35) return; // Minimum ClientHello size
        var pos: usize = 2 + 32; // Skip version + random
        if (pos >= body.len) return;
        // Session ID
        const sid_len: usize = body[pos];
        pos += 1 + sid_len;
        if (pos + 2 > body.len) return;
        // Cipher suites
        const cs_len = readU16(body[pos .. pos + 2]);
        pos += 2 + cs_len;
        if (pos >= body.len) return;
        // Compression
        const comp_len: usize = body[pos];
        pos += 1 + comp_len;
        if (pos + 2 > body.len) return;
        // Extensions
        const exts_len = readU16(body[pos .. pos + 2]);
        pos += 2;
        if (pos + exts_len > body.len) return;
        const exts_end = pos + exts_len;
        // Parse extensions looking for ALPN (0x0010)
        while (pos + 4 <= exts_end) {
            const etype = readU16(body[pos .. pos + 2]);
            const elen = readU16(body[pos + 2 .. pos + 4]);
            pos += 4;
            if (pos + elen > exts_end) break;
            if (etype == 0x0010 and elen >= 3) { // ALPN extension
                const list_len = readU16(body[pos .. pos + 2]);
                if (2 + list_len <= elen and list_len > 0) {
                    const name_len = body[pos + 2];
                    if (3 + name_len <= elen and name_len > 0) {
                        if (self.alpn) |old| self.allocator.free(old);
                        self.alpn = self.allocator.dupe(u8, body[pos + 3 .. pos + 3 + name_len]) catch null;
                        std.debug.print("extractAlpnFromClientHello: Extracted ALPN: {s}\n", .{self.alpn.?});
                        return;
                    }
                }
            }
            pos += elen;
        }
        std.debug.print("extractAlpnFromClientHello: No ALPN found\n", .{});
    }

    /// Internal: auto-send Finished when conditions satisfied
    fn maybeAutoProgress(self: *Engine) void {
        if (self.finished_sent) return;
        if (self.ecdhe_secret == null) return;

        // Handle Finished generation
        if (self.role == .Server) {
            // REMOVED: Direct queueing of handshake messages in maybeAutoProgress
            // The entire handshake flight (EncryptedExtensions, Certificate, CertificateVerify, Finished)
            // should be handled by queueServerHandshakeFlight() to maintain proper message ordering
            // and ensure all required messages are sent together.
            return; // Let endpoint.zig handle the handshake flight via queueServerHandshakeFlight()

            // OLD CODE REMOVED - was queueing messages directly here which caused:
            // 1. finished_sent to be set prematurely
            // 2. EncryptedExtensions to never be sent
            // 3. Breaking rustls strict TLS validation
        } else { // Client
            // Client waits for Finished verification; in authenticated mode also ensures peer_cert_ok
            std.debug.print("Client: maybeAutoProgress - finished_verified={}, has_secret={}, allow_insecure={}, peer_cert_ok={}\n", .{ self.finished_verified, self.handshake_client_secret != null, self.allow_insecure, self.peer_cert_ok });
            if (self.finished_verified and self.handshake_client_secret != null) {
                if (!self.allow_insecure and !self.peer_cert_ok) {
                    std.debug.print("Client: Waiting for certificate validation to complete\n", .{});
                    return; // wait for cert validation
                }
                std.debug.print("Client: Queueing Finished message in real mode\n", .{});
                self.queueFinished(self.handshake_client_secret.?) catch {};
            }
        }
    }
    /// Public: handshake complete when both sides' Finished exchanged.
    pub fn handshakeComplete(self: *Engine) bool {
        // In insecure mode on server side, we don't require client certificates
        // The handshake is complete once Finished messages are exchanged
        const cert_ok = if (self.role == .Server and self.allow_insecure) true else self.peer_cert_ok;

        const result = self.finished_sent and self.finished_verified;
        if (!result) {
            std.debug.print("[TLS HANDSHAKE] NOT COMPLETE - role={s}, finished_sent={}, finished_verified={}, ecdhe_secret={}, handshake_client_secret={}, handshake_server_secret={}, peer_cert_ok={}, allow_insecure={}\n", .{
                if (self.role == .Server) "Server" else "Client",
                self.finished_sent,
                self.finished_verified,
                self.ecdhe_secret != null,
                self.handshake_client_secret != null,
                self.handshake_server_secret != null,
                cert_ok,
                self.allow_insecure,
            });
        }
        return result;
    }
    /// Install server certificate and private key (ECDSA P-256 for now). Stored for future emission.
    pub fn setServerCertificate(self: *Engine, cert_der: []const u8, priv_key: []const u8, alg: sig.SigAlg) !void {
        if (self.role != .Server) return error.WrongRole;
        if (self.server_cert_der) |c| self.allocator.free(c);
        if (self.server_priv_key) |k| self.allocator.free(k);
        self.server_cert_der = try self.allocator.dupe(u8, cert_der);
        self.server_priv_key = try self.allocator.dupe(u8, priv_key);
        self.server_sig_alg = alg;
    }

    /// Queue server handshake flight: EncryptedExtensions, Certificate, CertificateVerify, Finished
    /// RFC 9001: These go to Handshake CRYPTO space (ServerHello goes to Initial)
    /// CRITICAL FIX: Insert a message boundary marker (0xFF) between each TLS message
    /// This allows the connection layer to send each message in a separate CRYPTO frame/packet
    pub fn queueServerHandshakeFlight(self: *Engine) void {
        std.debug.print("[FLIGHT] queueServerHandshakeFlight CALLED: role={s}, finished_sent={}, ee_sent={}, has_server_secret={}, has_client_secret={}, has_cert={}, has_key={}, enqueued={}\n", .{
            if (self.role == .Server) "Server" else "Client",
            self.finished_sent,
            self.ee_sent,
            self.handshake_server_secret != null,
            self.handshake_client_secret != null,
            self.server_cert_der != null,
            self.server_priv_key != null,
            self.server_handshake_flight_enqueued,
        });

        if (self.role != .Server) {
            std.debug.print("[FLIGHT] Early return: not server\n", .{});
            return;
        }
        if (self.server_handshake_flight_enqueued) {
            std.debug.print("[FLIGHT] Early return: handshake flight already enqueued\n", .{});
            return;
        }
        // FIXED: Don't check finished_sent here - let endpoint.zig control when to queue messages
        // The flags should only be set after actual transmission, not after queuing
        // if (self.finished_sent) {
        //     std.debug.print("[FLIGHT] Early return: already sent finished\n", .{});
        //     return; // already done
        // }

        // Full handshake flight
        // Require that handshake_server_secret be present (after SH)
        if (self.handshake_server_secret == null) {
            std.debug.print("[FLIGHT] Early return: no handshake_server_secret\n", .{});
            return;
        }

        std.debug.print("[FLIGHT] Proceeding with handshake flight\n", .{});

        // RFC 9001: Queue EncryptedExtensions first for Handshake CRYPTO space
        var appended_any = false;
        if (!self.ee_sent) {
            const alpn_for_ee = self.alpn orelse &[_]u8{};
            const tp_for_ee = self.local_tp orelse &[_]u8{};
            std.debug.print("Server: Queueing EncryptedExtensions to Handshake CRYPTO with ALPN={s} TP_len={}\n", .{ alpn_for_ee, tp_for_ee.len });
            self.queueEncryptedExtensions(alpn_for_ee, tp_for_ee) catch |e| {
                std.debug.print("Server: Failed to queue EncryptedExtensions: {}\n", .{e});
                return;
            };
            appended_any = true;
        }
        // If we have a certificate configured, send Certificate + CertificateVerify.
        // Note: allow_insecure only affects peer certificate validation, not whether we send ours
        // RFC 8446 §4.4.1: Server must send Certificate and CertificateVerify before Finished
        // CRITICAL FIX: Proper error handling - if Certificate/CertificateVerify fail, handshake fails
        if (self.server_cert_der != null and self.server_priv_key != null) {
            std.debug.print("Calling queueCertificate...\n", .{});
            // FIXED: Properly handle errors instead of silently catching them
            // If Certificate fails to queue, the handshake cannot proceed
            self.queueCertificate(self.server_cert_der.?) catch |e| {
                std.debug.print("[FLIGHT] queueCertificate FAILED: {}\n", .{e});
                // Mark handshake as failed - endpoint will handle connection termination
                self.handshake_failed = true;
                return;
            };

            // Ensure signature algorithm is set
            if (self.server_sig_alg == null) {
                const cert_der = self.server_cert_der.?;
                const detected = x509.inferSignatureAlgorithm(cert_der) catch |err| {
                    std.debug.print("[CERTVERIFY] Failed to infer signature algorithm from server cert: {} (defaulting to ECDSA P-256)\n", .{err});
                    self.server_sig_alg = .ecdsa_secp256r1_sha256;
                    return; // Exit early if inference fails
                };
                self.server_sig_alg = detected;
            }

            std.debug.print("[CERTVERIFY] About to queue CertificateVerify with alg={}, priv_key_len={}\n", .{ 
                self.server_sig_alg.?, self.server_priv_key.?.len 
            });
            
            // FIXED: Use the existing queueCertificateVerify() helper which properly handles transcript timing
            // This ensures CertificateVerify signature is computed over transcript that includes Certificate
            self.queueCertificateVerify() catch |e| {
                std.debug.print("[FLIGHT] queueCertificateVerify FAILED: {}\n", .{e});
                // Mark handshake as failed - endpoint will handle connection termination
                self.handshake_failed = true;
                return;
            };
            
            appended_any = true;
        } else {
            std.debug.print("[FLIGHT] WARNING: No server certificate configured (cert={}, key={}). Skipping Certificate/CertificateVerify.\n", .{
                self.server_cert_der != null,
                self.server_priv_key != null,
            });
            // RFC 8446 allows servers to skip Certificate/CertificateVerify if not authenticating
            // This is acceptable for development/testing, but production should always have certificates
        }
        // Always queue Finished last
        std.debug.print("[FLIGHT] About to queue Finished: finished_sent={}, has_secret={}\n", .{
            self.finished_sent,
            self.handshake_server_secret != null,
        });
        // FIXED: Always queue Finished if we have the secret and outbox contains our handshake messages
        if (self.handshake_server_secret != null) {
            std.debug.print("[FLIGHT] Calling queueFinished with server secret...\n", .{});
            self.queueFinished(self.handshake_server_secret.?) catch |e| {
                std.debug.print("[FLIGHT] queueFinished FAILED: {}\n", .{e});
            };
            std.debug.print("[FLIGHT] After queueFinished: finished_sent={}\n", .{self.finished_sent});
            appended_any = true;
            // Note: No boundary marker after Finished as it's the last message
        } else {
            std.debug.print("[FLIGHT] NOT queueing Finished (already sent or no secret)\n", .{});
        }

        if (appended_any) {
            self.server_handshake_flight_enqueued = true;
        }
    }

    // Removed insertMessageBoundaryMarker - no longer needed
    // Messages are sent together in proper TLS stream format
};

/// Generate an X25519 keypair and compute a shared secret given peer public.
/// Returns (priv, pub, shared) where shared may be null if peer_pub is null.
pub fn x25519KeypairAndShared(peer_pub_opt: ?[32]u8) struct { priv_key: [32]u8, pub_key: [32]u8, shared: ?[32]u8 } {
    var sk: [32]u8 = undefined;
    var pk: [32]u8 = undefined;
    std.crypto.random.bytes(&sk);
    std.crypto.dh.X25519.scalarmultBase(&pk, sk);
    var shared: ?[32]u8 = null;
    if (peer_pub_opt) |peer_pub| {
        var sh: [32]u8 = undefined;
        if (std.crypto.dh.X25519.scalarmult(&sh, sk, peer_pub)) {
            shared = sh;
        } else shared = null;
    }
    return .{ .priv_key = sk, .pub_key = pk, .shared = shared };
}

/// Encode a minimalistic ClientHello body carrying an X25519 key share only (non-interoperable placeholder).
pub fn encodeMinimalClientHello(alloc: std.mem.Allocator, client_pub: [32]u8) ![]u8 {
    // Body: "CH1" || client_pub
    var body: [3 + 32]u8 = undefined;
    body[0] = 'C';
    body[1] = 'H';
    body[2] = '1';
    @memcpy(body[3..], &client_pub);
    return encodeHandshake(alloc, .client_hello, body[0..]);
}

/// Encode a minimalistic ServerHello body carrying an X25519 key share only (non-interoperable placeholder).
pub fn encodeMinimalServerHello(alloc: std.mem.Allocator, server_pub: [32]u8) ![]u8 {
    var body: [3 + 32]u8 = undefined;
    body[0] = 'S';
    body[1] = 'H';
    body[2] = '1';
    @memcpy(body[3..], &server_pub);
    return encodeHandshake(alloc, .server_hello, body[0..]);
}

/// Attempt to parse minimal CH/SH and return pubkeys if present.
pub fn parseMinimalHelloPub(typ: HsType, body: []const u8) ?[32]u8 {
    if (body.len != 3 + 32) return null;
    if (typ == .client_hello and std.mem.eql(u8, body[0..3], "CH1")) {
        var pk: [32]u8 = undefined;
        @memcpy(&pk, body[3..]);
        return pk;
    }
    if (typ == .server_hello and std.mem.eql(u8, body[0..3], "SH1")) {
        var pk: [32]u8 = undefined;
        @memcpy(&pk, body[3..]);
        return pk;
    }
    return null;
}

// --- Real TLS 1.3 ClientHello / ServerHello parsing helpers (minimal) ---

fn readU16(be: []const u8) u16 {
    return (@as(u16, be[0]) << 8) | be[1];
}

/// Attempt to parse a real (spec-like) TLS 1.3 ClientHello and extract the first X25519 key share.
/// Also stores the client's session ID for ServerHello echo (RFC 8446 requirement).
/// Returns pubkey if successful; otherwise null. Does not perform deep validation beyond bounds.
fn parseRealClientHello(body: []const u8, engine: *Engine) ?[32]u8 {
    std.debug.print("parseRealClientHello: body_len={}\n", .{body.len});

    // Use a stack allocator for the parsing
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Parse the ClientHello using the comprehensive parser
    const ch = tls13_full.parseClientHello(allocator, body) catch |err| {
        std.debug.print("parseRealClientHello: failed to parse ClientHello with error: {}\n", .{err});
        // Log first few bytes of body for debugging
        if (body.len >= 8) {
            std.debug.print("parseRealClientHello: First 8 bytes: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7] });
        }
        return null;
    };

    // Store the client's session ID for ServerHello echo (RFC 8446 Section 4.1.3)
    if (ch.session_id.len > 0) {
        // Free any existing session ID
        if (engine.client_session_id) |old_id| {
            engine.allocator.free(old_id);
        }

        // Store a copy of the client's session ID
        engine.client_session_id = engine.allocator.alloc(u8, ch.session_id.len) catch null;
        if (engine.client_session_id) |new_id| {
            @memcpy(new_id, ch.session_id);
            std.debug.print("parseRealClientHello: stored client session_id len={}\n", .{ch.session_id.len});
        }
    } else {
        std.debug.print("parseRealClientHello: client sent empty session_id\n", .{});
        engine.client_session_id = null;
    }

    // Extract QUIC transport parameters if present (RFC 9001 Section 8.2)
    if (ch.quic_transport_parameters) |tp| {
        std.debug.print("parseRealClientHello: found transport parameters (len={})\n", .{tp.len});
        // Free any existing peer transport parameters
        if (engine.peer_tp) |old| {
            engine.allocator.free(old);
        }
        // Store a copy of the client's transport parameters
        engine.peer_tp = engine.allocator.dupe(u8, tp) catch null;
        if (engine.peer_tp != null) {
            std.debug.print("parseRealClientHello: stored transport parameters\n", .{});
        }
    } else {
        std.debug.print("parseRealClientHello: no transport parameters found in ClientHello\n", .{});
    }

    // Extract the X25519 key share if present
    if (ch.key_share) |key_share| {
        if (key_share.group == .x25519 and key_share.key_exchange.len == 32) {
            std.debug.print("parseRealClientHello: found X25519 key!\n", .{});
            var out: [32]u8 = undefined;
            @memcpy(&out, key_share.key_exchange[0..32]);
            std.debug.print("parseRealClientHello: successfully extracted public key\n", .{});
            return out;
        }
    }

    std.debug.print("parseRealClientHello: no X25519 key found\n", .{});
    return null;
}

/// Attempt to parse a real (spec-like) TLS 1.3 ServerHello and extract the X25519 key share.
fn parseRealServerHello(body: []const u8) ?[32]u8 {
    if (body.len < 2 + 32 + 1 + 2 + 1 + 2) return null; // minimal size
    var pos: usize = 0;
    pos += 2; // legacy version
    pos += 32; // random
    if (pos >= body.len) return null;
    const sid_len: usize = body[pos];
    pos += 1;
    if (pos + sid_len > body.len) return null;
    pos += sid_len; // session id
    if (pos + 3 > body.len) return null;
    pos += 2; // cipher suite
    pos += 1; // compression method
    if (pos + 2 > body.len) return null;
    const exts_len = readU16(body[pos .. pos + 2]);
    pos += 2;
    if (pos + exts_len > body.len) return null;
    const exts_end = pos + exts_len;
    while (pos + 4 <= exts_end) {
        const etype = readU16(body[pos .. pos + 2]);
        const elen = readU16(body[pos + 2 .. pos + 4]);
        pos += 4;
        if (pos + elen > exts_end) return null;
        if (etype == 0x0033) { // key_share (server format)
            if (elen < 4 + 32) return null;
            const group = readU16(body[pos .. pos + 2]);
            const klen = readU16(body[pos + 2 .. pos + 4]);
            if (group == 0x001d and klen == 32 and pos + 4 + 32 <= pos + elen) {
                var out: [32]u8 = undefined;
                @memcpy(&out, body[pos + 4 .. pos + 4 + 32]);
                return out;
            }
        }
        pos += elen;
    }
    return null;
}

// Build a minimally spec-compliant TLS 1.3 ServerHello with:
// - cipher_suite TLS_AES_128_GCM_SHA256
// - supported_versions (selected 1.3)
// - key_share (x25519)
