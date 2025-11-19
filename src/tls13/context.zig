//! TLS 1.3 Context and Callbacks
//!
//! This module provides the Context struct (main TLS 1.3 driver) and Callbacks
//! interface for QUIC integration.
//!
//! # RFC References
//! - **RFC 8446 §4**: Handshake Protocol
//! - **RFC 9001 §4**: QUIC-TLS integration (CRYPTO frames, secret installation)
//! - **RFC 9001 §5**: Packet Protection (traffic secret callbacks)
//! - **RFC 7301**: Application-Layer Protocol Negotiation (ALPN)
//! - **RFC 5280**: X.509 certificate validation
//!
//! # Architecture
//!
//! **Callbacks**: Function pointers for QUIC layer integration
//! - on_secret_available: Install traffic secrets for packet protection
//! - on_handshake_metadata: Receive negotiated ALPN and transport params
//! - on_peer_finished: Notification of peer Finished verification
//! - on_handshake_complete: Full handshake completion notification
//! - fetch_certificate_chain: Dynamic certificate retrieval (server)
//!
//! **Context**: High-level TLS 1.3 handshake driver
//! - Full RFC 8446 compliant flow
//! - Automatic format detection (standard vs. minimal)
//! - Certificate validation and signature verification
//! - Transcript hash management
//! - Secret derivation and installation
//! - ALPN and transport parameter negotiation
//!
//! # Usage
//!
//! ```zig
//! const config = Config{ ... };
//! const callbacks = Callbacks{
//!     .on_secret_available = installSecret,
//!     .on_handshake_complete = onComplete,
//! };
//! var ctx = try Context.init(config, callbacks);
//! defer ctx.deinit();
//!
//! // Process incoming CRYPTO frame data
//! try ctx.processCrypto(.Initial, crypto_data);
//! ```

const std = @import("std");
const ks = @import("quic_tls");
const x509 = @import("x509");
const sig = @import("sig");
const tls13_full = @import("tls13_full");
const ocsp = @import("ocsp");
const sct = @import("sct");
const alert_mod = @import("alert");
const zero_rtt_mod = @import("zero_rtt");
const logger = @import("quic_logger");
const transport_params = @import("quic_transport_params");

// Import modularized tls13 types
const types = @import("types.zig");
const config_mod = @import("config.zig");
const handshake_state_mod = @import("handshake_state.zig");
const secrets_mod = @import("secrets.zig");
const transcript_mod = @import("transcript.zig");
const key_derivation_mod = @import("key_derivation.zig");
const messages_mod = @import("messages.zig");
const finished_mod = @import("finished.zig");
const cookie_mod = @import("messages/extensions/cookie.zig");

// Note: The extracted code below contains its own type definitions
// (ApiError, HandshakeError, TrafficDirection, SecretSlot, etc.)
// These were not fully extracted in Phase 1, so they remain here.

// Type aliases needed by extracted code (these are NOT defined in the extracted code)
const Config = config_mod.Config;
const EncryptionLevel = handshake_state_mod.EncryptionLevel;
const Transcript = transcript_mod.Transcript;
const HandshakeMetadata = types.HandshakeMetadata;
const parseHandshakeOne = messages_mod.parseHandshakeOne;
const HandshakeMessage = messages_mod.HandshakeMessage;
const deriveFinishedVerifyData = finished_mod.deriveFinishedVerifyData;
const deriveApplicationTraffic = key_derivation_mod.deriveApplicationTraffic;
const encodeHandshake = messages_mod.encodeHandshake;
const HsType = messages_mod.HsType;
const deriveHandshakeTraffic = key_derivation_mod.deriveHandshakeTraffic;
const buildKeyUpdate = messages_mod.buildKeyUpdate;
const parseKeyUpdate = messages_mod.parseKeyUpdate;
const KeyUpdateRequest = messages_mod.KeyUpdateRequest;
// Note: TrafficDirection, SecretSlot, BidirSecrets, CryptoBuffer are defined in the extracted code below

// Local type aliases
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Hash = ks.Hash;
const Secret = ks.Secret;
const max_digest_length = ks.max_digest_length;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

// Debug tracing (disabled in production)
const handshake_trace_enabled = false;
const secret_trace_enabled = false;

inline fn traceHandshake(comptime fmt: []const u8, args: anytype) void {
    if (handshake_trace_enabled) std.debug.print(fmt, args);
}

inline fn traceSecrets(comptime fmt: []const u8, args: anytype) void {
    if (secret_trace_enabled) std.debug.print(fmt, args);
}

fn cipherSuiteHash(suite: tls13_full.CipherSuite) Hash {
    return switch (suite) {
        .TLS_AES_128_GCM_SHA256, .TLS_CHACHA20_POLY1305_SHA256, .TLS_AES_128_CCM_SHA256, .TLS_AES_128_CCM_8_SHA256 => .sha256,
        .TLS_AES_256_GCM_SHA384 => .sha384,
    };
}

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
    /// RFC 8446 §7.1: Traffic secrets are derived progressively during handshake
    /// and must be installed at appropriate encryption levels for packet protection.
    ///
    /// RFC 9001 §5: QUIC uses traffic secrets to derive AEAD keys via HKDF-Expand-Label.
    ///
    /// # Flow
    /// - TLS derives `secret` (32 or 48 bytes depending on cipher suite hash)
    /// - HKDF-Expand-Label is used to derive AEAD keys for packet protection
    /// - The `secret` is used to derive AEAD keys for all encryption levels
    ///
    /// # Parameters
    /// - ctx: TLS context (access negotiated parameters)
    /// - level: Encryption level (Initial/Handshake/Application)
    /// - secret: Traffic secret (32 or 48 bytes depending on cipher suite hash)
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
    on_secret_available: ?*const fn (ctx: *Context, level: EncryptionLevel, secret: []const u8) anyerror!void = null,

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

    /// Post-handshake authentication (CertificateRequest after handshake completion) is unsupported for QUIC.
    PostHandshakeAuthUnsupported,
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
    value: Secret = Secret.empty(),
    hash: Hash = .sha256,
    valid: bool = false,
    epoch: EncryptionLevel = .Initial,
    generation: u32 = 0,

    const Self = @This();

    pub fn clear(self: *Self) void {
        self.value = Secret.empty();
        self.hash = .sha256;
        self.valid = false;
        self.generation = 0;
        self.epoch = .Initial;
    }

    pub fn store(self: *Self, level: EncryptionLevel, hash: Hash, secret: Secret) void {
        self.value = secret;
        self.hash = hash;
        self.valid = true;
        self.epoch = level;
        self.generation += 1;
    }

    pub fn slice(self: *const Self) []const u8 {
        return self.value.slice();
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

    /// Get current generation number for a specific encryption level and direction.
    ///
    /// RFC 8446 §4.6.3: Each KeyUpdate increments the generation counter,
    /// allowing tracking of how many key updates have occurred.
    ///
    /// # Returns
    /// - Generation number (0 = initial, 1+ = after updates)
    /// - 0 if secret not yet installed
    ///
    /// # Example
    /// ```zig
    /// const gen = ctx.secrets.getGeneration(.Application, .send);
    /// // gen == 0: Initial application secret
    /// // gen == 1: After first key update
    /// // gen == 2: After second key update
    /// ```
    pub fn getGeneration(self: *const SecretSchedule, level: EncryptionLevel, dir: TrafficDirection) u32 {
        const s = switch (level) {
            .Initial => switch (dir) {
                .send => &self.initial.send,
                .recv => &self.initial.recv,
            },
            .Handshake => switch (dir) {
                .send => &self.handshake.send,
                .recv => &self.handshake.recv,
            },
            .Application => switch (dir) {
                .send => &self.application.send,
                .recv => &self.application.recv,
            },
        };
        return if (s.valid) s.generation else 0;
    }

    /// Get generation numbers for both send and receive directions.
    ///
    /// Useful for logging, debugging, and verifying bidirectional key updates.
    ///
    /// # Returns
    /// BidirKeyGenerations struct with send and recv generation numbers
    pub fn getBidirGenerations(self: *const SecretSchedule, level: EncryptionLevel) secrets_mod.BidirKeyGenerations {
        return .{
            .send = self.getGeneration(level, .send),
            .recv = self.getGeneration(level, .recv),
        };
    }
};

const HashDigestCache = struct {
    sha256: ?Secret = null,
    sha384: ?Secret = null,

    pub fn set(self: *HashDigestCache, hash: Hash, digest: Secret) void {
        switch (hash) {
            .sha256 => self.sha256 = digest,
            .sha384 => self.sha384 = digest,
        }
    }

    pub fn get(self: *const HashDigestCache, hash: Hash) ?Secret {
        return switch (hash) {
            .sha256 => self.sha256,
            .sha384 => self.sha384,
        };
    }

    pub fn clear(self: *HashDigestCache) void {
        self.sha256 = null;
        self.sha384 = null;
    }
};

/// RFC 8446 §4.4.1: transcripts and cached hashes used across handshake flights.
pub const TranscriptSet = struct {
    handshake: Transcript,
    client_hello_hash: transcript_mod.HashDigestCache = .{},
    finished_hash: transcript_mod.HashDigestCache = .{},

    /// Creates a new transcript set with empty transcripts.
    pub fn init() TranscriptSet {
        return .{ .handshake = Transcript.init(), .client_hello_hash = .{}, .finished_hash = .{} };
    }

    /// Resets all transcripts to their initial empty state.
    pub fn reset(self: *TranscriptSet) void {
        self.handshake.reset();
        self.client_hello_hash.clear();
        self.finished_hash.clear();
    }
};

/// High-level handshake lifecycle position for progress tracking (RFC 8446 §4).
pub const HandshakePhase = handshake_state_mod.HandshakePhase;

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
    hash_kind: Hash = .sha256,
    local_transport_parameters: ?[]u8 = null,
    peer_quic_transport_parameters: ?[]u8 = null,
    negotiated_alpn: ?[]u8 = null,
    negotiated_signature: ?tls13_full.SignatureScheme = null,
    negotiated_cipher_suite: ?tls13_full.CipherSuite = null,
    handshake_secret: ?Secret = null,
    client_priv: ?[32]u8 = null,
    client_pub: ?[32]u8 = null,
    client_random: ?[32]u8 = null, // Client random from first ClientHello (for HRR)
    hrr_sent: bool = false, // Track if we already sent HelloRetryRequest (server)
    hrr_received: bool = false, // Track if we received HelloRetryRequest (client)
    server_secret_generated: ?[32]u8 = null, // Generated server secret for HRR cookies

    /// Initializes a new TLS 1.3 context with the specified configuration and callbacks.
    pub fn init(config: Config, callbacks: Callbacks) !Context {
        const ctx = Context{
            .config = config,
            .callbacks = callbacks,
            .allocator = config.allocator,
            .phase = .initial,
            .transcripts = TranscriptSet.init(),
            .secrets = SecretSchedule.init(),
            .streams = .{},
            .state = HandshakeState.init(),
            .flags = .{},
            .hash_kind = .sha256,
            .local_transport_parameters = null,
            .negotiated_alpn = null,
            .negotiated_signature = null,
            .negotiated_cipher_suite = null,
            .handshake_secret = null,
            .client_priv = null,
            .client_pub = null,
        };

        // NOTE: For clients, DO NOT automatically call startClientHandshake() here!
        // The QUIC layer needs to set transport parameters FIRST via setTransportParameters(),
        // then explicitly call startClientHandshake(). If we call it here, the ClientHello
        // will be generated without transport parameters.

        return ctx;
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
        if (self.peer_quic_transport_parameters) |buf| {
            self.allocator.free(buf);
            self.peer_quic_transport_parameters = null;
        }
        if (self.negotiated_alpn) |proto| {
            self.allocator.free(proto);
            self.negotiated_alpn = null;
        }
        self.negotiated_signature = null;
        self.negotiated_cipher_suite = null;
        self.handshake_secret = null;
        self.hash_kind = .sha256;
        self.phase = .initial;
    }

    /// Update transport parameters for this Context.
    /// This allows setting transport parameters after Context creation (e.g., when
    /// they're computed lazily after connection establishment).
    ///
    /// Parameters:
    /// - tp_bytes: Encoded transport parameters (TLV format from quic_transport_params.zig)
    ///
    /// Note: This updates the config's quic_transport_parameters pointer to reference
    /// the provided bytes. Caller must ensure the bytes remain valid for the Context's lifetime.
    pub fn setTransportParameters(self: *Context, tp_bytes: []const u8) void {
        // Store in the mutable local_transport_parameters field instead of trying to modify the immutable config
        // The config's quic_transport_parameters is set at Context creation time; this allows updating it later
        // We need to make a mutable copy since local_transport_parameters is ?[]u8, not ?[]const u8
        const mutable_copy = self.allocator.dupe(u8, tp_bytes) catch return;
        // Free any existing allocation
        if (self.local_transport_parameters) |old| {
            self.allocator.free(old);
        }
        self.local_transport_parameters = mutable_copy;
        std.debug.print("Context.setTransportParameters: Set {} bytes of transport params on context={*}\n", .{tp_bytes.len, self});
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
        std.debug.print("Context.processCrypto: role={s}, level={s}, data_len={}\n", .{
            if (self.config.role == .Server) "Server" else "Client", @tagName(level), data.len
        });
        var stream = self.streams.buffer(level);
        try stream.inbound.appendSlice(self.allocator, data);

        // Process all complete messages in buffer
        while (true) {
            const buffer = stream.inbound.items;
            if (self.config.role == .Client and level == .Handshake) {
                const head_len: usize = if (buffer.len < 8) buffer.len else 8;
                std.debug.print("[TLS-HS-CLIENT] buffer len={} head={any}\n", .{ buffer.len, buffer[0..head_len] });
            }
            const parsed_opt = try parseHandshakeOne(buffer);
            if (parsed_opt == null) break; // Need more data for complete message

            const parsed = parsed_opt.?;
            const message_bytes = buffer[0..parsed.n];

            std.debug.print("  Parsed handshake message: type={X:0>2} ({s}), len={}\n", .{
                @intFromEnum(parsed.typ),
                @tagName(parsed.typ),
                parsed.body.len
            });

            // RFC 8446 §4.4.4: Update transcript BEFORE processing message
            // (except Finished which is added AFTER verification)
            // This ensures that when handlers like onPeerServerHello compute
            // Handshake secrets, the transcript includes all messages up to
            // and including the current message (e.g., ClientHello+ServerHello)
            if (parsed.typ != .finished) {
                self.transcripts.handshake.update(message_bytes);
            }

            // Validate and process message type (now transcript includes this message)
            try self.handleHandshakeMessage(level, parsed, message_bytes);

            // Finished verification happens in handleHandshakeMessage, transcript
            // updated there after successful verification
            try self.afterHandshakeMessage(level, parsed);

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
            .peer_transport_parameters = self.peer_quic_transport_parameters,
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
    pub fn installTrafficSecret(self: *Context, level: EncryptionLevel, dir: TrafficDirection, secret: Secret) !void {
        std.debug.print("[installTrafficSecret] level={s} dir={s} secret=", .{ @tagName(level), @tagName(dir) });
        for (secret.slice()) |b| std.debug.print("{X:0>2}", .{b});
        std.debug.print("\n", .{});

        var slot = self.secrets.slot(level, dir);
        slot.store(level, self.hash_kind, secret);
        if (self.callbacks.on_secret_available) |cb| {
            try cb(self, level, secret.slice());
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

    /// Get current key generation number for a traffic direction (RFC 8446 §4.6.3).
    ///
    /// The generation counter tracks how many times keys have been updated:
    /// - Generation 0: Secret not yet installed
    /// - Generation 1: Initial secret installed (handshake complete)
    /// - Generation 2+: After key updates
    ///
    /// # Parameters
    /// - level: Encryption level (.Initial, .Handshake, or .Application)
    /// - dir: Traffic direction (.send or .recv)
    ///
    /// # Returns
    /// Current generation number (0 if secret not installed)
    ///
    /// # Example
    /// ```zig
    /// const send_gen = ctx.getKeyGeneration(.Application, .send);
    /// if (send_gen >= 100) {
    ///     // Many key updates have occurred
    /// }
    /// ```
    pub fn getKeyGeneration(self: *const Context, level: EncryptionLevel, dir: TrafficDirection) u32 {
        return self.secrets.getGeneration(level, dir);
    }

    /// Get generation numbers for both send and receive directions.
    ///
    /// Useful for verifying bidirectional key updates and debugging.
    ///
    /// # Parameters
    /// - level: Encryption level to query
    ///
    /// # Returns
    /// BidirKeyGenerations struct with .send and .recv generation numbers
    ///
    /// # Example
    /// ```zig
    /// const gens = ctx.getBidirKeyGenerations(.Application);
    /// std.debug.print("Send gen: {}, Recv gen: {}\n", .{gens.send, gens.recv});
    /// ```
    pub fn getBidirKeyGenerations(self: *const Context, level: EncryptionLevel) secrets_mod.BidirKeyGenerations {
        return self.secrets.getBidirGenerations(level);
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

                // Phase 36 FIX: Extract peer transport parameters from ClientHello
                // RFC 9001 §8.2: quic_transport_parameters (0x0039) mandatory for QUIC
                // Client sends its transport parameters in ClientHello extension
                if (self.state.clientHello()) |ch| {
                    if (ch.quic_transport_parameters) |tp| {
                        // Store peer (client) transport parameters
                        const tp_copy = try self.allocator.dupe(u8, tp);
                        if (self.peer_quic_transport_parameters) |old| {
                            self.allocator.free(old);
                        }
                        self.peer_quic_transport_parameters = tp_copy;
                    }
                }

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
            // NOTE: certificate_request is not in HsType enum
            // RFC 9001 forbids post-handshake client authentication
            // .certificate_request => {
            //     return HandshakeError.PostHandshakeAuthUnsupported;
            // },
            .finished => {
                // RFC 8446 §4.4.4: Verify peer Finished message
                // Must verify BEFORE adding to transcript
                try self.handlePeerFinished(level, parsed.body, raw);
            },
            .key_update => {
                // RFC 8446 §4.6.3: KeyUpdate can only occur at Application level
                if (level != .Application) return HandshakeError.UnexpectedMessage;

                // Parse KeyUpdate message body
                const request = try parseKeyUpdate(parsed.body);

                // Handle the key update
                try self.handleKeyUpdateMessage(request);
            },
            .encrypted_extensions => {
                // RFC 8446 §4.3.1: EncryptedExtensions only valid for client role
                if (self.config.role != .Client) return HandshakeError.UnexpectedMessage;

                // Parse EncryptedExtensions to extract transport parameters and ALPN
                try self.handleEncryptedExtensions(parsed.body);
            },
            else => {
                // Other messages (Certificate, CertificateVerify)
                // processed implicitly via transcript updates
            },
        }
    }

    fn afterHandshakeMessage(self: *Context, level: EncryptionLevel, parsed: HandshakeMessage) !void {
        switch (parsed.typ) {
            .client_hello => {
                if (self.config.role != .Server) return;

                // Debug: Print ClientHello transcript hash
                const snapshot = self.transcripts.handshake.snapshot();
                if (snapshot.sha256) |digest| {
                    if (secret_trace_enabled) {
                        traceSecrets("[TRANSCRIPT_DEBUG] ClientHello hash (SHA-256): ", .{});
                        for (digest.slice()) |b| traceSecrets("{X:0>2}", .{b});
                        traceSecrets("\n", .{});
                    }
                }
                traceHandshake("\n", .{});

                self.transcripts.client_hello_hash = snapshot;
                try self.driveServerHandshakeFlight();
            },
            .server_hello => {
                if (self.config.role != .Client) return;
                // After processing ServerHello, transcript already updated; snapshot kept during driveServerHandshakeFlight
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

        // Retrieve peer's handshake traffic secret (recv direction)
        const slot = self.secrets.slot(.Handshake, .recv);
        if (!slot.valid) return HandshakeError.UnexpectedMessage;

        // verify_data = HMAC(finished_key, transcript_hash)
        // Must be exactly the digest length for negotiated hash (SHA-256 or SHA-384)
        const expected_len = ks.digestLength(slot.hash);
        if (verify_data.len != expected_len) return HandshakeError.FinishedVerifyFailed;

        // RFC 8446 §4.4.4: Compute expected verify_data over transcript BEFORE Finished
        // Transcript includes all messages up to (but not including) Finished
        var transcript_snapshot = self.transcripts.handshake;
        const transcript_hash = transcript_snapshot.finalize(slot.hash);
        const expected = deriveFinishedVerifyData(slot.hash, &slot.value, transcript_hash);

        // Constant-time comparison to prevent timing attacks (RFC 8446 §4.4.4)
        // CRITICAL: Must use timing_safe.eql to prevent timing side-channel attacks
        const verified = switch (slot.hash) {
            .sha256 => blk: {
                const expected_bytes: *const [32]u8 = expected.slice()[0..32];
                const verify_bytes: *const [32]u8 = verify_data[0..32];
                break :blk std.crypto.timing_safe.eql([32]u8, expected_bytes.*, verify_bytes.*);
            },
            .sha384 => blk: {
                const expected_bytes: *const [48]u8 = expected.slice()[0..48];
                const verify_bytes: *const [48]u8 = verify_data[0..48];
                break :blk std.crypto.timing_safe.eql([48]u8, expected_bytes.*, verify_bytes.*);
            },
        };
        if (!verified) return HandshakeError.FinishedVerifyFailed;

        // Store transcript hash at Finished point (used for key derivation)
        self.transcripts.finished_hash.set(slot.hash, transcript_hash);

        // RFC 8446 §7.1: Application secrets derived with transcript up to server Finished ONLY
        // Server must derive Application secrets BEFORE adding client Finished to transcript
        if (self.config.role == .Server) {
            // Server derives Application secrets now (before client Finished added to transcript)
            // Transcript at this point: CH, SH, EE, Cert, CV, ServerFinished
            try self.ensureApplicationSecrets();
        }

        // RFC 8446 §4.4.4: NOW add Finished to transcript (after verification)
        // For client: this is server Finished (needed for Application secret derivation)
        // For server: this is client Finished (NOT used for Application secret derivation - already derived above)
        self.transcripts.handshake.update(raw);
    }

    /// Post-Finished processing: derive application secrets and update state.
    fn handleFinishedPostActions(self: *Context, level: EncryptionLevel) !void {
        if (level != .Handshake) return;

        // RFC 8446 §7.1: Derive application traffic secrets after Finished verified
        // Client derives here (after server Finished added to transcript above)
        // Server already derived above (before client Finished added to transcript)
        if (self.config.role == .Client) {
            try self.ensureApplicationSecrets();
        }

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
        std.debug.print("[ensureApplicationSecrets] Called for role={}\n", .{self.config.role});
        const send_slot = self.secrets.slot(.Application, .send);
        const recv_slot = self.secrets.slot(.Application, .recv);
        std.debug.print("[ensureApplicationSecrets] send_slot.valid={} recv_slot.valid={}\n", .{ send_slot.valid, recv_slot.valid });

        // Skip if already derived (idempotent)
        if (send_slot.valid and recv_slot.valid) {
            std.debug.print("[ensureApplicationSecrets] Skipping - already derived\n", .{});
            return;
        }

        // RFC 8446 §7.1: Derive from handshake_secret and transcript hash
        // handshake_secret was saved after ServerHello processing
        const hs_secret = self.handshake_secret orelse return HandshakeError.UnexpectedMessage;

        // Transcript hash at this point includes all messages (CH...Finished)
        var transcript_snapshot = self.transcripts.handshake;
        std.debug.print("[ensureApplicationSecrets] About to finalize transcript for role={}\n", .{self.config.role});
        const transcript_hash = transcript_snapshot.finalize(self.hash_kind);
        std.debug.print("[ensureApplicationSecrets] Finalized transcript hash: ", .{});
        for (transcript_hash.slice()) |b| std.debug.print("{X:0>2}", .{b});
        std.debug.print("\n", .{});

        // Key schedule: master_secret = Derive-Secret(handshake_secret, "derived", "")
        //               app_secrets = Derive-Secret(master_secret, label, transcript)
        const apps = deriveApplicationTraffic(self.hash_kind, &hs_secret, transcript_hash);

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
            self.secrets.exporter_master.store(.Application, self.hash_kind, apps.exporter_master);
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

    /// Handle HelloRetryRequest from server (client-side).
    /// RFC 8446 §4.1.4: Parse HRR, extract cookie and selected_group, send ClientHello2.
    fn handleHelloRetryRequest(self: *Context, body: []const u8) !void {
        if (self.hrr_received) {
            // Already received HRR once - server sent HRR twice
            return HandshakeError.UnexpectedMessage;
        }

        traceHandshake("Client: Received HelloRetryRequest\n", .{});

        // Parse extensions to extract cookie and selected_group
        if (body.len < 2 + 32 + 1) return HandshakeError.UnexpectedMessage;
        var pos: usize = 2 + 32; // skip legacy_version + random

        // Skip session_id
        if (pos >= body.len) return HandshakeError.UnexpectedMessage;
        const sid_len: usize = body[pos];
        pos += 1 + sid_len;

        // Skip cipher_suite + compression
        if (pos + 2 + 1 > body.len) return HandshakeError.UnexpectedMessage;
        pos += 2 + 1;

        // Parse extensions
        if (pos + 2 > body.len) return HandshakeError.UnexpectedMessage;
        const exts_len: usize = (@as(usize, body[pos]) << 8) | @as(usize, body[pos + 1]);
        pos += 2;
        if (pos + exts_len > body.len) return HandshakeError.UnexpectedMessage;

        const exts_end = pos + exts_len;
        var cookie: ?[]const u8 = null;
        var selected_group: ?tls13_full.NamedGroup = null;

        while (pos + 4 <= exts_end) {
            const etype = (@as(u16, body[pos]) << 8) | body[pos + 1];
            const elen = (@as(usize, body[pos + 2]) << 8) | body[pos + 3];
            pos += 4;
            if (pos + elen > exts_end) return HandshakeError.UnexpectedMessage;

            // RFC 8446 §4.2.2: cookie extension (0x002c)
            if (etype == 0x002c) {
                cookie = body[pos .. pos + elen];
            }
            // RFC 8446 §4.2.8: key_share extension with selected_group (2 bytes)
            else if (etype == 0x0033) {
                if (elen == 2) {
                    const group_val = (@as(u16, body[pos]) << 8) | body[pos + 1];
                    selected_group = std.meta.intToEnum(tls13_full.NamedGroup, group_val) catch null;
                }
            }

            pos += elen;
        }

        // Cookie is optional in HRR, but selected_group is required
        if (selected_group == null) {
            return HandshakeError.MissingKeyShare;
        }

        traceHandshake("Client: HRR requests group: {s}\n", .{@tagName(selected_group.?)});

        // RFC 8446 §4.4.1: Update transcript for HelloRetryRequest
        // Get the first ClientHello from the buffer we need to re-send
        const ch1_raw = self.streams.buffer(.Initial).outbound.items;

        // Update transcript: replace with message_hash(CH1) || HRR
        self.transcripts.handshake.handleHelloRetryRequest(ch1_raw, self.hash_kind);

        // Now add HRR to transcript
        // Need to get the full HRR message (with handshake framing)
        // We're currently in the ServerHello handler, so the transcript already has it
        // But handleHelloRetryRequest reset the transcript, so we need to add HRR manually
        const hrr_msg = try encodeHandshake(self.allocator, .server_hello, body);
        defer self.allocator.free(hrr_msg);
        self.transcripts.handshake.update(hrr_msg);

        // Mark that we received HRR
        self.hrr_received = true;

        // Send ClientHello2 with new key_share and cookie
        try self.sendClientHello2(selected_group.?, cookie);

        traceHandshake("Client: Sent ClientHello2 with group {s}\n", .{@tagName(selected_group.?)});
    }

    /// Send ClientHello2 after receiving HelloRetryRequest.
    /// RFC 8446 §4.1.4: Second ClientHello includes cookie and new key_share.
    fn sendClientHello2(self: *Context, selected_group: tls13_full.NamedGroup, cookie: ?[]const u8) !void {
        // Generate new key pair for the requested group
        // Currently only X25519 is supported
        if (selected_group != .x25519) {
            return HandshakeError.UnsupportedKeyShareGroup;
        }

        var priv: [32]u8 = undefined;
        std.crypto.random.bytes(&priv);
        const pub_key = std.crypto.dh.X25519.recoverPublicKey(priv) catch {
            return HandshakeError.UnsupportedKeyShareGroup;
        };

        self.client_priv = priv;
        self.client_pub = pub_key;

        // Build ClientHello2 (similar to initial ClientHello but with cookie)
        var body = std.ArrayList(u8){};
        defer body.deinit(self.allocator);

        // legacy_version
        try body.appendSlice(self.allocator, &.{ 0x03, 0x03 });

        // RFC 8446 §4.1.4: MUST use same random as ClientHello1
        const rnd = self.client_random orelse return HandshakeError.UnexpectedMessage;
        try body.appendSlice(self.allocator, &rnd);

        // empty session id
        try body.append(self.allocator, 0);

        // cipher_suites
        try body.appendSlice(self.allocator, &.{ 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03 });

        // compression methods
        try body.appendSlice(self.allocator, &.{ 0x01, 0x00 });

        // Build extensions
        var ext_buf = std.ArrayList(u8){};
        defer ext_buf.deinit(self.allocator);

        // supported_versions (REQUIRED)
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });

        // supported_groups
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });

        // signature_algorithms
        const sigs = self.config.supported_signature_schemes;
        if (sigs.len != 0) {
            const list_len: u16 = @intCast(sigs.len * 2);
            const ext_len: u16 = list_len + 2;
            try ext_buf.appendSlice(self.allocator, &.{
                0x00,
                0x0d,
                @intCast(ext_len >> 8),
                @intCast(ext_len & 0xff),
                @intCast(list_len >> 8),
                @intCast(list_len & 0xff),
            });
            for (sigs) |scheme| {
                const val: u16 = @intFromEnum(scheme);
                try ext_buf.appendSlice(self.allocator, &.{ @intCast(val >> 8), @intCast(val & 0xff) });
            }
        }

        // key_share with the requested group
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x33 });
        const key_share_len: u16 = 2 + 2 + 32;
        const total_len: u16 = key_share_len + 2;
        try ext_buf.appendSlice(self.allocator, &.{ @intCast(total_len >> 8), @intCast(total_len & 0xff) });
        try ext_buf.appendSlice(self.allocator, &.{ @intCast(key_share_len >> 8), @intCast(key_share_len & 0xff) });
        const group_val = @intFromEnum(selected_group);
        try ext_buf.appendSlice(self.allocator, &.{ @intCast(group_val >> 8), @intCast(group_val & 0xff) });
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 32 });
        try ext_buf.appendSlice(self.allocator, &pub_key);

        // cookie extension (if present in HRR)
        if (cookie) |ck| {
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x2c }); // cookie extension type
            const ck_len: u16 = @intCast(ck.len);
            try ext_buf.appendSlice(self.allocator, &.{ @intCast(ck_len >> 8), @intCast(ck_len & 0xff) });
            try ext_buf.appendSlice(self.allocator, ck);
        }

        // ALPN
        if (self.config.alpn_protocols) |alpn_list| if (alpn_list.len != 0) {
            var names_len: usize = 0;
            for (alpn_list) |p| names_len += 1 + p.len;
            const list_len: u16 = @intCast(names_len);
            const ext_len: u16 = list_len + 2;
            try ext_buf.appendSlice(self.allocator, &.{
                0x00,
                0x10,
                @intCast(ext_len >> 8),
                @intCast(ext_len & 0xff),
                @intCast(list_len >> 8),
                @intCast(list_len & 0xff),
            });
            for (alpn_list) |p| {
                try ext_buf.append(self.allocator, @intCast(p.len));
                try ext_buf.appendSlice(self.allocator, p);
            }
        };

        // QUIC transport parameters
        // Check local_transport_parameters first (set via setTransportParameters), then fall back to config
        const tp_bytes_hrr = self.local_transport_parameters orelse self.config.quic_transport_parameters;
        if (tp_bytes_hrr) |tp| {
            const tp_len: u16 = @intCast(tp.len);
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x39, @intCast(tp_len >> 8), @intCast(tp_len & 0xff) });
            try ext_buf.appendSlice(self.allocator, tp);
        }

        // Finalize extensions
        const exts_len: u16 = @intCast(ext_buf.items.len);
        try body.appendSlice(self.allocator, &.{ @intCast(exts_len >> 8), @intCast(exts_len & 0xff) });
        try body.appendSlice(self.allocator, ext_buf.items);

        // Encode as handshake message
        const body_len: u32 = @intCast(body.items.len);
        const msg = try self.allocator.alloc(u8, 4 + body.items.len);
        msg[0] = @intFromEnum(HsType.client_hello);
        msg[1] = @intCast((body_len >> 16) & 0xff);
        msg[2] = @intCast((body_len >> 8) & 0xff);
        msg[3] = @intCast(body_len & 0xff);
        @memcpy(msg[4..], body.items);
        defer self.allocator.free(msg);

        // Send ClientHello2 at Initial encryption level
        try self.appendOutbound(.Initial, msg, true);
    }

    /// Get or generate server secret for HRR cookie generation.
    /// RFC 8446 §4.2.2: Server uses a secret to generate HMAC-authenticated cookies.
    fn ensureServerSecret(self: *Context) ![]const u8 {
        // Use configured server_secret if available
        if (self.config.server_secret) |secret| {
            return secret;
        }

        // Otherwise, generate a random secret (stored in context for session lifetime)
        if (self.server_secret_generated) |*secret| {
            return secret;
        }

        // Generate new random secret (32 bytes for HMAC-SHA256)
        var secret: [32]u8 = undefined;
        std.crypto.random.bytes(&secret);
        self.server_secret_generated = secret;
        return &self.server_secret_generated.?;
    }

    /// Send HelloRetryRequest to client requesting a different key share group.
    /// RFC 8446 §4.1.4: HelloRetryRequest is a ServerHello with special random value.
    fn sendHelloRetryRequest(self: *Context, ch_view: ClientHelloView, selected_group: tls13_full.NamedGroup) !void {
        traceHandshake("Server: Sending HelloRetryRequest (requesting group: {s})\n", .{@tagName(selected_group)});

        // RFC 8446 §4.2.2: Generate cookie binding this HRR to the client's first ClientHello
        const server_secret = try self.ensureServerSecret();

        // Compute transcript hash of first ClientHello
        const ch1_hash = self.transcripts.handshake.finalize(self.hash_kind);

        // Generate HMAC-authenticated cookie
        const cookie = try cookie_mod.generateCookie(
            self.allocator,
            server_secret,
            ch_view.random,
            ch1_hash.slice(),
        );
        defer self.allocator.free(cookie);

        // Build HelloRetryRequest message
        const hrr_body = try tls13_full.buildHelloRetryRequest(
            self.allocator,
            selected_group,
            cookie,
            if (ch_view.session_id.len > 0) ch_view.session_id else null,
        );
        defer self.allocator.free(hrr_body);

        // Encode as ServerHello handshake message
        const hrr_msg = try encodeHandshake(self.allocator, .server_hello, hrr_body);
        defer self.allocator.free(hrr_msg);

        // RFC 8446 §4.4.1: Update transcript hash for HelloRetryRequest
        // Replace transcript with: message_hash(ClientHello1) || HelloRetryRequest
        self.transcripts.handshake.handleHelloRetryRequest(ch_view.raw, self.hash_kind);

        // Now add HRR to the modified transcript
        self.transcripts.handshake.update(hrr_msg);

        // Queue HRR for transmission at Initial encryption level
        try self.appendOutbound(.Initial, hrr_msg, false); // Already updated transcript above

        // Mark that we sent HRR
        self.hrr_sent = true;

        traceHandshake("Server: HelloRetryRequest sent successfully\n", .{});
    }

    fn driveServerHandshakeFlight(self: *Context) !void {
        if (self.config.role != .Server) return;
        if (self.flags.local_finished_sent) return;
        if (self.secrets.handshake.send.valid) return; // secrets already installed

        const ch_view = self.state.clientHello() orelse return HandshakeError.UnexpectedMessage;
        const cipher_suite = self.chooseCipherSuite(ch_view.cipher_suites) orelse return HandshakeError.NoCipherSuite;
        self.hash_kind = cipherSuiteHash(cipher_suite);
        self.negotiated_cipher_suite = cipher_suite;
        _ = try self.selectServerSignatureScheme(ch_view);

        // RFC 8446 §4.1.4: Check if client's key_share group is supported
        // If not supported and we haven't sent HRR yet, send HelloRetryRequest
        if (ch_view.key_share.group != .x25519) {
            if (self.hrr_sent) {
                // Client already received HRR but still sent wrong group
                return HandshakeError.UnsupportedKeyShareGroup;
            }

            // Send HelloRetryRequest requesting x25519
            try self.sendHelloRetryRequest(ch_view, .x25519);
            return; // Don't continue with normal handshake
        }

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
        traceHandshake("[TRANSCRIPT_DEBUG] ServerHello message ({} bytes): ", .{sh_msg.len});
        for (sh_msg) |b| traceHandshake("{X:0>2}", .{b});
        traceHandshake("\n", .{});

        try self.appendOutbound(.Initial, sh_msg, true);

        const transcript_after_sh = self.transcripts.handshake.finalize(self.hash_kind);
        const hs = deriveHandshakeTraffic(self.hash_kind, shared[0..], transcript_after_sh);
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
            traceHandshake("Server: Sending Certificate message ({} bytes DER)\n", .{cert_der.len});

            // Build Certificate message using tls13_full helper
            // Convert single certificate to certificate chain
            const cert_entries = [_]tls13_full.CertificateEntryData{.{ .cert = cert_der }};
            const cert_body = try tls13_full.buildCertificate(self.allocator, &[_]u8{}, &cert_entries);
            defer self.allocator.free(cert_body);

            const cert_msg = try encodeHandshake(self.allocator, .certificate, cert_body);
            defer self.allocator.free(cert_msg);
            try self.appendOutbound(.Handshake, cert_msg, true);

            // Build CertificateVerify message
            // Signature is over transcript hash including Certificate message we just added
            const hash_for_sig = self.transcripts.handshake.finalize(self.hash_kind);

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

            traceHandshake("Server: Signing CertificateVerify with algorithm: {s}\n", .{@tagName(sig_alg)});

            // Get private key from config
            const priv_key = self.config.server_key_der orelse {
                traceHandshake("Server: ERROR - No private key configured!\n", .{});
                return HandshakeError.UnexpectedMessage; // Using this as a placeholder for config errors
            };

            // Sign the transcript hash with proper TLS 1.3 context string
            const signature = try sig.signCertificateVerify(
                sig_alg,
                priv_key,
                "TLS 1.3, server CertificateVerify",
                hash_for_sig.slice(),
                self.allocator,
            );
            defer self.allocator.free(signature);

            // Build CertificateVerify message body (RFC 8446 §4.4.3)
            const cv_body = try tls13_full.buildCertificateVerify(self.allocator, sig_scheme, signature);
            defer self.allocator.free(cv_body);

            const cv_msg = try encodeHandshake(self.allocator, .certificate_verify, cv_body);
            defer self.allocator.free(cv_msg);
            try self.appendOutbound(.Handshake, cv_msg, true);

            traceHandshake("Server: Certificate and CertificateVerify sent successfully\n", .{});
        } else {
            traceHandshake("Server: WARNING - No certificate configured, proceeding without Certificate/CertificateVerify\n", .{});
        }

        const hash_before_finished = self.transcripts.handshake.finalize(self.hash_kind);
        self.transcripts.finished_hash.set(self.hash_kind, hash_before_finished);
        const verify_data = deriveFinishedVerifyData(self.hash_kind, &hs.server_hs, hash_before_finished);

        const fin_msg = try encodeHandshake(self.allocator, .finished, verify_data.slice());
        defer self.allocator.free(fin_msg);
        try self.appendOutbound(.Handshake, fin_msg, true);

        self.markLocalFinished();
    }

    /// Construct and queue a ClientHello with QUIC extensions when acting as the client.
    /// This must be called by the QUIC layer before polling for Initial CRYPTO data.
    pub fn startClientHandshake(self: *Context) !void {
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
        self.client_random = rnd; // Save for potential HRR handling
        try body.appendSlice(self.allocator, &rnd);
        try body.append(self.allocator, 0); // empty session id
        try body.appendSlice(self.allocator, &.{ 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03 });
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
                const val: u16 = @intFromEnum(scheme);
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
        // Check local_transport_parameters first (set via setTransportParameters), then fall back to config
        const tp_bytes = self.local_transport_parameters orelse self.config.quic_transport_parameters;
        if (tp_bytes) |tp| {
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
        self.transcripts.client_hello_hash = self.transcripts.handshake.snapshot();
        if (self.phase == .initial) self.phase = .negotiating;
    }

    fn handleServerHello(self: *Context, body: []const u8) !void {
        // Minimal parse: skip legacy_version(2) + random(32) + session_id
        if (body.len < 2 + 32 + 1) return HandshakeError.UnexpectedMessage;

        var random: [32]u8 = undefined;
        @memcpy(&random, body[2..34]);

        // RFC 8446 §4.1.4: Check if this is a HelloRetryRequest
        if (tls13_full.isHelloRetryRequest(random)) {
            // Handle HelloRetryRequest
            try self.handleHelloRetryRequest(body);
            return;
        }

        // Downgrade sentinel check (RFC 8446 §4.1.3)
        if (tls13_full.containsDowngradeSentinel(random)) {
            return HandshakeError.DowngradeAttempt;
        }
        var pos: usize = 2 + 32; // after legacy_version+random
        if (pos >= body.len) return HandshakeError.UnexpectedMessage;
        const sid_len: usize = body[pos];
        pos += 1 + sid_len;
        if (pos + 2 + 1 > body.len) return HandshakeError.UnexpectedMessage;
        const suite_value: u16 = (@as(u16, body[pos]) << 8) | @as(u16, body[pos + 1]);
        const cipher_suite = std.meta.intToEnum(tls13_full.CipherSuite, suite_value) catch return HandshakeError.NoCipherSuite;
        self.negotiated_cipher_suite = cipher_suite;
        self.hash_kind = cipherSuiteHash(cipher_suite);
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
        const sh_snapshot = self.transcripts.handshake.finalize(self.hash_kind);
        const hs = deriveHandshakeTraffic(self.hash_kind, shared[0..], sh_snapshot);
        self.handshake_secret = hs.handshake;

        // CLIENT uses client_hs for send, server_hs for recv (opposite of server)
        try self.installTrafficSecret(.Handshake, .send, hs.client_hs);
        try self.installTrafficSecret(.Handshake, .recv, hs.server_hs);
        self.phase = .keys_installed;
    }

    fn sendClientFinished(self: *Context) !void {
        const slot = self.secrets.slot(.Handshake, .send);
        if (!slot.valid) return HandshakeError.UnexpectedMessage;
        var transcript_snapshot = self.transcripts.handshake;
        const hash_before = transcript_snapshot.finalize(slot.hash);
        const verify_data = deriveFinishedVerifyData(slot.hash, &slot.value, hash_before);
        const fin_msg = try encodeHandshake(self.allocator, .finished, verify_data.slice());
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
        const hash = exp_slot.hash;
        const th = self.transcripts.finished_hash.get(hash) orelse blk: {
            var snap = self.transcripts.handshake;
            break :blk snap.finalize(hash);
        };
        const derived = ks.deriveSecretHash(hash, &exp_slot.value, label, th.slice());
        const derived_slice = derived.slice();
        const n = @min(out.len, derived_slice.len);
        @memcpy(out[0..n], derived_slice[0..n]);
        if (n < out.len) @memset(out[n..], 0);
    }

    /// Initiate a key update (RFC 8446 §4.6.3).
    ///
    /// This method updates the local sending traffic secret and sends a KeyUpdate
    /// message to the peer. Optionally requests the peer to also update their keys.
    ///
    /// # RFC 8446 §4.6.3: KeyUpdate Message
    /// The KeyUpdate handshake message is used to indicate that the sender is
    /// updating its sending cryptographic keys. This provides forward secrecy
    /// for long-lived connections and allows recovery from AEAD usage limits.
    ///
    /// # RFC 9001 §6: QUIC Key Update
    /// QUIC implementations must ensure that key updates are coordinated with
    /// the QUIC packet number space to avoid decryption failures.
    ///
    /// # Parameters
    /// - request_peer_update: If true, requests peer to also perform key update
    ///
    /// # Flow
    /// 1. Update local sending traffic secret (derive next generation)
    /// 2. Install new sending secret via on_secret_available callback
    /// 3. Build and send KeyUpdate message
    /// 4. Queue message in Application-level CRYPTO stream
    ///
    /// # Errors
    /// - HandshakeError.UnexpectedMessage: Called before handshake complete
    /// - OutOfMemory: Failed to allocate KeyUpdate message
    ///
    /// # Example
    /// ```zig
    /// // Update keys without requesting peer update (one-way)
    /// try ctx.sendKeyUpdate(false);
    ///
    /// // Update keys and request peer to also update (bidirectional)
    /// try ctx.sendKeyUpdate(true);
    /// ```
    ///
    /// # Notes
    /// - Can only be called after handshake complete (Application secrets installed)
    /// - QUIC layer must handle packet number coordination
    /// - New keys take effect immediately for outgoing packets
    pub fn sendKeyUpdate(self: *Context, request_peer_update: bool) !void {
        // RFC 8446 §4.6.3: KeyUpdate only valid at Application encryption level
        // Handshake must be complete and application secrets must be installed
        const send_slot = self.secrets.slot(.Application, .send);
        if (!send_slot.valid) return HandshakeError.UnexpectedMessage;

        // RFC 8446 §7.2: Derive next generation traffic secret
        // application_traffic_secret_N+1 = HKDF-Expand-Label(
        //     application_traffic_secret_N, "traffic upd", "", Hash.length)
        const next_secret = ks.updateTrafficSecretHash(send_slot.hash, &send_slot.value);

        // Install new sending secret via callback (QUIC layer updates packet protection)
        try self.installTrafficSecret(.Application, .send, next_secret);

        // Build KeyUpdate message
        const key_update_msg = try buildKeyUpdate(self.allocator, request_peer_update);
        defer self.allocator.free(key_update_msg);

        // Queue KeyUpdate message in Application-level CRYPTO stream
        var stream = self.streams.buffer(.Application);
        try stream.outbound.appendSlice(self.allocator, key_update_msg);

        traceHandshake("TLS: Sent KeyUpdate (request_update={})\n", .{request_peer_update});
    }

    /// Check AEAD usage and automatically trigger key update if nearing limit.
    ///
    /// This method integrates AEAD limit tracking (RFC 8446 §5.5) with the key update
    /// mechanism (RFC 8446 §4.6.3) to provide automatic key rotation when approaching
    /// confidentiality limits. This prevents connection failures from hitting hard limits.
    ///
    /// ## RFC 8446 §5.5: Limits on Key Usage
    /// AEAD ciphers have confidentiality limits to prevent security degradation:
    /// - AES-128-GCM: 2^24 records
    /// - AES-256-GCM: 2^24 records
    /// - ChaCha20-Poly1305: 2^32 records
    ///
    /// ## RFC 9001 §6: QUIC Key Update
    /// QUIC implementations should proactively update keys before hitting limits
    /// to maintain forward secrecy and avoid connection errors.
    ///
    /// ## Parameters
    /// - `encrypted_count`: Number of records encrypted with current send key
    /// - `confidentiality_limit`: Maximum records allowed (from AEAD suite)
    /// - `threshold_percent`: Percentage of limit at which to trigger (default: 90)
    ///   - 90 = Trigger at 90% of limit (recommended for proactive updates)
    ///   - 100 = Trigger only at hard limit (not recommended)
    ///
    /// ## Returns
    /// `true` if key update was triggered, `false` otherwise
    ///
    /// ## Errors
    /// - HandshakeError.UnexpectedMessage: Handshake not complete
    /// - OutOfMemory: Failed to allocate KeyUpdate message
    ///
    /// ## Usage Pattern
    /// QUIC layer should call this periodically during packet encryption:
    ///
    /// ```zig
    /// // After encrypting a packet
    /// const stats = aead_cipher.getUsageStats();
    /// const triggered = try tls_ctx.checkAndTriggerKeyUpdate(
    ///     stats.encrypted,
    ///     stats.confidentiality_limit,
    ///     90, // Trigger at 90% of limit
    /// );
    /// if (triggered) {
    ///     // Key update in progress, continue encrypting with new keys
    /// }
    /// ```
    ///
    /// ## Design Rationale
    /// - Proactive updates at 90% prevent connection failures
    /// - Gives time for KeyUpdate handshake before limit reached
    /// - Separates limit tracking (QUIC) from update decision (TLS)
    /// - Non-blocking: Returns immediately after queuing KeyUpdate
    ///
    /// ## RFC References
    /// - RFC 8446 §4.6.3 - KeyUpdate message format and processing
    /// - RFC 8446 §5.5 - AEAD usage limits and requirements
    /// - RFC 9001 §6 - QUIC Key Update considerations
    pub fn checkAndTriggerKeyUpdate(
        self: *Context,
        encrypted_count: u64,
        confidentiality_limit: u64,
        threshold_percent: u8,
    ) !bool {
        // Validate threshold percentage
        if (threshold_percent == 0 or threshold_percent > 100) return false;

        // Check if limit is configured
        if (confidentiality_limit == 0) return false; // No limit = no update needed

        // Calculate threshold: (limit * threshold_percent) / 100
        // Use u128 to prevent overflow during multiplication
        const limit_u128: u128 = confidentiality_limit;
        const threshold_u128: u128 = @as(u128, threshold_percent);
        const threshold_count: u64 = @intCast((limit_u128 * threshold_u128) / 100);

        // Check if we've reached the threshold
        if (encrypted_count < threshold_count) {
            return false; // Not at threshold yet
        }

        // RFC 8446 §4.6.3 + §5.5: Trigger key update to refresh keys
        // Send KeyUpdate with update_not_requested (one-way update)
        // Peer will respond with their own KeyUpdate if they also need to update
        try self.sendKeyUpdate(false);

        traceHandshake(
            "TLS: Automatic key update triggered (encrypted={d}, limit={d}, threshold={d}%)\n",
            .{ encrypted_count, confidentiality_limit, threshold_percent },
        );

        return true; // Key update was triggered
    }

    /// Handle received KeyUpdate message (RFC 8446 §4.6.3).
    ///
    /// Updates the local receiving traffic secret and optionally sends a
    /// KeyUpdate in response if the peer requested it.
    ///
    /// # Parameters
    /// - request: The KeyUpdateRequest from peer (update_not_requested or update_requested)
    ///
    /// # Flow
    /// 1. Update local receiving traffic secret
    /// 2. Install new receiving secret via callback
    /// 3. If peer requested update, send our own KeyUpdate
    ///
    /// # Notes
    /// - Automatically called when KeyUpdate message is received
    /// - Private method, not intended for direct use by application
    /// RFC 8446 §4.3.1 + RFC 9001 §8.2: Parse EncryptedExtensions and extract transport parameters.
    fn handleEncryptedExtensions(self: *Context, body: []const u8) !void {
        // Parse EncryptedExtensions message
        const parsed = try tls13_full.parseEncryptedExtensions(body);

        // RFC 9001 §8.2: Extract quic_transport_parameters extension (mandatory for QUIC)
        if (parsed.quic_transport_parameters) |tp| {
            // Store peer transport parameters
            const tp_copy = try self.allocator.dupe(u8, tp);
            if (self.peer_quic_transport_parameters) |old| {
                self.allocator.free(old);
            }
            self.peer_quic_transport_parameters = tp_copy;
        } else {
            // RFC 9001 §8.2: Transport parameters are mandatory for QUIC
            return HandshakeError.MissingTransportParameters;
        }

        // RFC 7301: Store negotiated ALPN
        if (parsed.alpn) |alpn| {
            const alpn_copy = try self.allocator.dupe(u8, alpn);
            if (self.negotiated_alpn) |old| {
                self.allocator.free(old);
            }
            self.negotiated_alpn = alpn_copy;
        }

        // Notify QUIC layer of handshake metadata
        self.notifyMetadata();

        std.debug.print("handleEncryptedExtensions: Extracted {} bytes of transport params, ALPN={s}\n", .{
            if (parsed.quic_transport_parameters) |tp| tp.len else 0,
            if (parsed.alpn) |alpn| alpn else "none"
        });
    }

    fn handleKeyUpdateMessage(self: *Context, request: KeyUpdateRequest) !void {
        // RFC 8446 §7.2: Update receiving traffic secret
        const recv_slot = self.secrets.slot(.Application, .recv);
        if (!recv_slot.valid) return HandshakeError.UnexpectedMessage;

        const next_secret = ks.updateTrafficSecretHash(recv_slot.hash, &recv_slot.value);

        // Install new receiving secret
        try self.installTrafficSecret(.Application, .recv, next_secret);

        traceHandshake("TLS: Received KeyUpdate (request_update={})\n", .{request == .update_requested});

        // RFC 8446 §4.6.3: If peer requested update, send our own KeyUpdate
        // Send with update_not_requested to avoid infinite ping-pong
        if (request == .update_requested) {
            try self.sendKeyUpdate(false); // Don't request peer to update again
        }
    }

    /// Rotate the local application traffic secret and install fresh send keys (RFC 8446 §7.2).
    pub fn performKeyUpdateSend(self: *Context) !void {
        const send_slot = self.secrets.slot(.Application, .send);
        if (!send_slot.valid) return HandshakeError.UnexpectedMessage;
        const next = ks.updateTrafficSecretHash(send_slot.hash, &send_slot.value);
        send_slot.store(.Application, send_slot.hash, next);
    }

    /// Accept a peer initiated key update by rotating the receive traffic secret.
    pub fn performKeyUpdateRecv(self: *Context) !void {
        const recv_slot = self.secrets.slot(.Application, .recv);
        if (!recv_slot.valid) return HandshakeError.UnexpectedMessage;
        const next = ks.updateTrafficSecretHash(recv_slot.hash, &recv_slot.value);
        recv_slot.store(.Application, recv_slot.hash, next);
    }
};
