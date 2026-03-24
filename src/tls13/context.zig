// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

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

// Note: ApiError and HandshakeError are now imported from types.zig (canonical source).
// TrafficDirection, SecretSlot, etc. remain defined here pending further extraction.

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
const encodeHandshakeBuf = messages_mod.encodeHandshakeBuf;
const HsType = messages_mod.HsType;
const deriveHandshakeTraffic = key_derivation_mod.deriveHandshakeTraffic;
const buildKeyUpdate = messages_mod.buildKeyUpdate;
const parseKeyUpdate = messages_mod.parseKeyUpdate;
const KeyUpdateRequest = messages_mod.KeyUpdateRequest;
// Note: TrafficDirection, SecretSlot, BidirSecrets, CryptoBuffer are defined in the extracted code below

// Shared byte helpers (QUAL-084: prefer readU16 over inline bit-shift patterns).
const readU16 = tls13_full.readU16;

// Local type aliases
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Hash = ks.Hash;
const Secret = ks.Secret;
const max_digest_length = ks.max_digest_length;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

// Debug tracing (disabled in production).
// QUAL-082: Per-file trace constants are intentionally NOT extracted to a shared
// module. Each file keeps its own toggle so developers can enable tracing for a
// single module during debugging without flooding output. The compile-time
// @compileError guards also rely on file-local constants.
const handshake_trace_enabled = false;

/// Secret tracing - logs cryptographic secrets for debugging.
///
/// ## Security Warning
///
/// **NEVER enable this in production!** When enabled, traffic secrets,
/// session keys, and other sensitive material may be logged.
///
/// This constant is compile-time checked and will cause a build error
/// if enabled in ReleaseSafe/ReleaseFast/ReleaseSmall builds.
const secret_trace_enabled = false;

// Compile-time safety: prevent secret logging in release builds
comptime {
    if (secret_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: secret_trace_enabled must be false in release builds - secrets would be logged!");
    }
}

inline fn traceHandshake(comptime fmt: []const u8, args: anytype) void {
    if (handshake_trace_enabled) logger.debugPrint(fmt, args);
}

inline fn traceSecrets(comptime fmt: []const u8, args: anytype) void {
    if (secret_trace_enabled) logger.debugPrint(fmt, args);
}

// cipherSuiteHash is now shared via types.cipherSuiteHash (QUAL-081 dedup).
const cipherSuiteHash = types.cipherSuiteHash;

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

    /// Called when the server receives a pre_shared_key extension.
    /// The application should look up the PSK associated with the ticket identity.
    /// Returns the PSK if found, or null if not found.
    on_ticket_lookup: ?*const fn (ctx: *Context, identity: []const u8) ?[]const u8 = null,

    /// Called to fetch certificate chain for local authentication (Server role).
    /// RFC 8446 §4.4.2: Certificate message contains certificate_list.
    ///
    /// Implementation should return DER-encoded certificate chain:
    /// - First certificate: Leaf (server identity)
    /// - Subsequent certificates: Intermediates (optional)
    ///
    /// Currently only leaf certificate used; full chain validation planned.
    /// null = Use Config.server_cert_der directly (no dynamic fetch).
    fetch_certificate_chain: ?*const fn (ctx: *Context) anyerror![]const u8 = null,
};

/// Error type for TLS API operations (canonical definition in types.zig).
pub const ApiError = types.ApiError;

/// Errors surfaced during TLS 1.3 handshake message parsing and validation
/// (canonical definition in types.zig).
pub const HandshakeError = types.HandshakeError;

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

    /// Clear secret and reset to initial state (zeroize).
    /// Security: Uses secureZero to prevent compiler from optimizing away
    /// the zeroization of sensitive key material (CWE-226).
    pub fn clear(self: *Self) void {
        std.crypto.secureZero(u8, &self.value.bytes);
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

// QUAL-070: supportsTls13Version and freeParsedClientHello are now in
// handshake_state.zig, used by the shared ClientHelloInfo.parse().

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

// QUAL-070: ClientHello types consolidated in handshake_state.zig (canonical source).
pub const ClientHelloKeyShareView = handshake_state_mod.ClientHelloKeyShareView;
pub const ClientHelloPskIdentityView = handshake_state_mod.ClientHelloPskIdentityView;
pub const ClientHelloPreSharedKeyView = handshake_state_mod.ClientHelloPreSharedKeyView;
pub const ClientHelloView = handshake_state_mod.ClientHelloView;

// QUAL-070: ClientHelloInfo consolidated in handshake_state.zig (canonical source).
const ClientHelloInfo = handshake_state_mod.ClientHelloInfo;

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
                // [][]u8 -> []const []const u8: safe cast, same memory layout
                .alpn_list = if (info.alpn_list) |list|
                    @as([]const []const u8, @ptrCast(list))
                else
                    null,
                .early_data = info.early_data,
                .pre_shared_key = if (info.pre_shared_key) |psk| ClientHelloPreSharedKeyView{
                    // []OwnedPskIdentity -> []const ClientHelloPskIdentityView: same layout
                    .identities = @as([]const ClientHelloPskIdentityView, @ptrCast(psk.identities)),
                    // [][]u8 -> []const []const u8: safe cast, same memory layout
                    .binders = @as([]const []const u8, @ptrCast(psk.binders)),
                } else null,
                .psk_key_exchange_modes = info.psk_key_exchange_modes,
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
/// PERF-036: Uses offset-based O(1) amortized consume (matching handshake_state.zig pattern).
const CryptoBuffer = struct {
    level: EncryptionLevel,
    inbound: ArrayListUnmanaged(u8) = .{},
    outbound: ArrayListUnmanaged(u8) = .{},
    read_offset: usize = 0,

    fn init(level: EncryptionLevel) CryptoBuffer {
        return .{ .level = level };
    }

    /// Returns the unread portion of the inbound buffer.
    fn data(self: *const CryptoBuffer) []const u8 {
        return self.inbound.items[self.read_offset..];
    }

    /// Returns the unread portion of the inbound buffer as mutable.
    fn dataMut(self: *CryptoBuffer) []u8 {
        return self.inbound.items[self.read_offset..];
    }

    /// Returns the number of unread bytes.
    fn readableLength(self: *const CryptoBuffer) usize {
        return self.inbound.items.len - self.read_offset;
    }

    fn clear(self: *CryptoBuffer) void {
        self.inbound.clearRetainingCapacity();
        self.outbound.clearRetainingCapacity();
        self.read_offset = 0;
    }

    fn deinit(self: *CryptoBuffer, alloc: std.mem.Allocator) void {
        self.inbound.deinit(alloc);
        self.outbound.deinit(alloc);
        self.read_offset = 0;
    }

    /// O(1) amortized consume: advance read_offset, compact when offset > capacity/2.
    fn consume(self: *CryptoBuffer, count: usize) void {
        std.debug.assert(count <= self.readableLength());
        self.read_offset += count;
        self.compact();
    }

    /// Compact: shift remaining data to front when read_offset exceeds half capacity.
    fn compact(self: *CryptoBuffer) void {
        if (self.read_offset > 0 and (self.read_offset > self.inbound.capacity / 2 or self.read_offset == self.inbound.items.len)) {
            const remaining = self.readableLength();
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.inbound.items[0..remaining], self.inbound.items[self.read_offset .. self.read_offset + remaining]);
            }
            self.inbound.items = self.inbound.items[0..remaining];
            self.read_offset = 0;
        }
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
    // Certificate validation state (client role)
    peer_cert_chain: ?[][]const u8 = null, // DER-encoded certificate chain from peer
    peer_cert_verify_sig: ?[]const u8 = null, // CertificateVerify signature from peer
    peer_cert_verify_alg: ?tls13_full.SignatureScheme = null, // Signature algorithm used
    peer_ocsp_response: ?[]const u8 = null, // Stapled OCSP response from peer (leaf cert only)
    peer_sct_list: ?[]const u8 = null, // Signed Certificate Timestamp list from peer (leaf cert only)
    // mTLS state (RFC 8446 §4.3.2)
    client_cert_requested: bool = false, // Client: tracks that server sent CertificateRequest
    client_cert_request_context: ?[]u8 = null, // Client: stores request context from CertificateRequest
    // 0-RTT state (server role)
    // PERF-002: Lazy-allocated anti-replay window.  Only heap-allocated when the
    // context is a server with enable_early_data=true.  Saves ~2KB inline for
    // clients and servers that do not use 0-RTT.
    anti_replay: ?*zero_rtt_mod.AntiReplayWindow = null,

    /// Initializes a new TLS 1.3 context with the specified configuration and callbacks.
    pub fn init(config: Config, callbacks: Callbacks) !Context {
        // GAP-0080: Validate that config.supported_groups only contains implemented groups.
        // Currently only x25519 is implemented for ECDHE key exchange.
        for (config.supported_groups) |group| {
            if (group != .x25519) return HandshakeError.UnsupportedKeyShareGroup;
        }

        // PERF-002: Only allocate anti-replay window for servers with 0-RTT enabled.
        const anti_replay: ?*zero_rtt_mod.AntiReplayWindow = if (config.role == .Server and config.enable_early_data) blk: {
            const ptr = try config.allocator.create(zero_rtt_mod.AntiReplayWindow);
            ptr.* = zero_rtt_mod.AntiReplayWindow.init(config.allocator);
            break :blk ptr;
        } else null;

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
            .anti_replay = anti_replay,
        };

        // NOTE: For clients, DO NOT automatically call startClientHandshake() here!
        // The QUIC layer needs to set transport parameters FIRST via setTransportParameters(),
        // then explicitly call startClientHandshake(). If we call it here, the ClientHello
        // will be generated without transport parameters.

        // SEC-005: Prevent allow_insecure from being used in release builds.
        // This disables ALL certificate validation — only safe in Debug/testing.
        if (config.allow_insecure and @import("builtin").mode != .Debug) {
            @panic("SECURITY: allow_insecure=true is forbidden in release builds — it disables all certificate validation");
        }

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
        // Clean up peer certificate data (client role)
        if (self.peer_cert_chain) |chain| {
            for (chain) |cert| {
                self.allocator.free(cert);
            }
            self.allocator.free(chain);
            self.peer_cert_chain = null;
        }
        if (self.peer_cert_verify_sig) |sig_data| {
            self.allocator.free(sig_data);
            self.peer_cert_verify_sig = null;
        }
        if (self.peer_ocsp_response) |ocsp_data| {
            self.allocator.free(ocsp_data);
            self.peer_ocsp_response = null;
        }
        if (self.peer_sct_list) |sct_data| {
            self.allocator.free(sct_data);
            self.peer_sct_list = null;
        }
        // Clean up mTLS state
        if (self.client_cert_request_context) |ctx_data| {
            self.allocator.free(ctx_data);
            self.client_cert_request_context = null;
        }
        self.client_cert_requested = false;
        // PERF-002: Free heap-allocated anti-replay window (only if allocated)
        if (self.anti_replay) |ar| {
            ar.deinit();
            self.allocator.destroy(ar);
            self.anti_replay = null;
        }
        self.negotiated_signature = null;
        self.negotiated_cipher_suite = null;
        // CWE-226: Zeroize sensitive keying material before freeing
        // Use secureZero to prevent compiler from optimizing away the zeroization
        if (self.handshake_secret) |*hs| {
            std.crypto.secureZero(u8, hs.bytes[0..hs.len]);
        }
        self.handshake_secret = null;
        if (self.client_priv) |*priv| {
            std.crypto.secureZero(u8, priv);
        }
        self.client_priv = null;
        if (self.server_secret_generated) |*ssg| {
            std.crypto.secureZero(u8, ssg);
        }
        self.server_secret_generated = null;
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
    pub fn setTransportParameters(self: *Context, tp_bytes: []const u8) !void {
        // Store in the mutable local_transport_parameters field instead of trying to modify the immutable config
        // The config's quic_transport_parameters is set at Context creation time; this allows updating it later
        // We need to make a mutable copy since local_transport_parameters is ?[]u8, not ?[]const u8
        const mutable_copy = try self.allocator.dupe(u8, tp_bytes);
        // Free any existing allocation
        if (self.local_transport_parameters) |old| {
            self.allocator.free(old);
        }
        self.local_transport_parameters = mutable_copy;
        logger.debugPrint("Context.setTransportParameters: Set {} bytes of transport params on context={*}\n", .{ tp_bytes.len, self });
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
        logger.debugPrint("Context.processCrypto: role={s}, level={s}, data_len={}\n", .{ if (self.config.role == .Server) "Server" else "Client", @tagName(level), data.len });
        var stream = self.streams.buffer(level);

        // SEC-018: Enforce maximum CRYPTO buffer size per RFC 9001 §7.5 recommendation.
        // Prevents memory exhaustion from excessively large or fragmented handshake messages.
        const max_crypto_buffer = 65536; // 64KB per RFC 9001 §7.5
        if (stream.readableLength() + data.len > max_crypto_buffer) {
            return HandshakeError.UnexpectedMessage;
        }

        try stream.inbound.appendSlice(self.allocator, data);

        // Process all complete messages in buffer
        while (true) {
            const buffer = stream.data();
            if (self.config.role == .Client and level == .Handshake) {
                const head_len: usize = if (buffer.len < 8) buffer.len else 8;
                logger.debugPrint("[TLS-HS-CLIENT] buffer len={} head={any}\n", .{ buffer.len, buffer[0..head_len] });
            }
            const parsed_opt = try parseHandshakeOne(buffer);
            if (parsed_opt == null) break; // Need more data for complete message

            const parsed = parsed_opt.?;
            const message_bytes = buffer[0..parsed.n];

            logger.debugPrint("  Parsed handshake message: type={X:0>2} ({s}), len={}\n", .{ @intFromEnum(parsed.typ), @tagName(parsed.typ), parsed.body.len });

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
        if (stream.outbound.items.len == 0) return ApiError.NothingToRead;
        // PERF-018: Use toOwnedSlice to transfer ownership without copying.
        return stream.outbound.toOwnedSlice(allocator);
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
        if (secret_trace_enabled) {
            std.debug.print("[installTrafficSecret] level={s} dir={s} secret=", .{ @tagName(level), @tagName(dir) });
            for (secret.slice()) |b| std.debug.print("{X:0>2}", .{b});
            std.debug.print("\n", .{});
        }

        var slot = self.secrets.slot(level, dir);
        slot.store(level, self.hash_kind, secret);
        if (self.callbacks.on_secret_available) |cb| {
            try cb(self, level, secret.slice());
        }
    }

    /// Mark that our Finished flight has been transmitted (§4.4.4) and update phase state.
    pub fn markLocalFinished(self: *Context) !void {
        self.flags.local_finished_sent = true;
        try self.bumpPhaseAfterFinished();
    }

    /// Mark that the peer Finished verified successfully (§4.4.4) and update phase state.
    /// QUAL-072: Callback errors are now propagated to the caller instead of being swallowed.
    pub fn confirmPeerFinished(self: *Context) !void {
        self.flags.peer_finished_verified = true;
        if (self.callbacks.on_peer_finished) |cb| {
            try cb(self);
        }
        try self.bumpPhaseAfterFinished();
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
    /// logger.debugPrint("Send gen: {}, Recv gen: {}\n", .{gens.send, gens.recv});
    /// ```
    pub fn getBidirKeyGenerations(self: *const Context, level: EncryptionLevel) secrets_mod.BidirKeyGenerations {
        return self.secrets.getBidirGenerations(level);
    }

    /// QUAL-072: Callback errors are now propagated to the caller instead of being swallowed.
    fn bumpPhaseAfterFinished(self: *Context) !void {
        if (self.flags.peer_finished_verified and self.flags.local_finished_sent) {
            self.phase = .application_ready;
            if (self.callbacks.on_handshake_complete) |cb| {
                try cb(self);
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

                // RFC 8446 §4.1.4: After HelloRetryRequest, server must accept a
                // second ClientHello. Reset stored CH state so setClientHello
                // doesn't reject it as DuplicateClientHello.
                if (self.hrr_sent) {
                    self.state.reset(self.allocator);
                }

                // Parse and store ClientHello for parameter negotiation
                try self.state.setClientHello(self.allocator, parsed.body);

                // Phase 36 FIX: Extract peer transport parameters from ClientHello
                // RFC 9001 §8.2: quic_transport_parameters (0x0039) mandatory for QUIC
                // Client sends its transport parameters in ClientHello extension
                if (self.state.clientHello()) |ch| {
                    if (ch.quic_transport_parameters) |tp| {
                        // GAP-0081: Validate client transport params don't contain
                        // server-only parameters per RFC 9000 §18.2.
                        var decoded_tp = transport_params.TransportParameters.decode(tp, self.allocator) catch {
                            return HandshakeError.InvalidTransportParameters;
                        };
                        defer decoded_tp.deinit(self.allocator);
                        decoded_tp.validateClientRole() catch {
                            return HandshakeError.InvalidTransportParameters;
                        };

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
            .certificate_request => {
                // RFC 8446 §4.3.2: CertificateRequest only valid for client role during initial handshake
                if (self.config.role != .Client) return HandshakeError.UnexpectedMessage;

                // Parse CertificateRequest to extract context and signature algorithms
                const cr_parsed = try tls13_full.parseCertificateRequest(self.allocator, parsed.body);
                defer self.allocator.free(cr_parsed.signature_algorithms);

                // QUAL-128: Dupe before free to prevent dangling pointer on OOM.
                const new_ctx = if (cr_parsed.context.len > 0)
                    try self.allocator.dupe(u8, cr_parsed.context)
                else
                    null;
                if (self.client_cert_request_context) |old| {
                    self.allocator.free(old);
                }
                self.client_cert_request_context = new_ctx;

                self.client_cert_requested = true;

                // RFC 8446 §4.4.3: Client selects a signature scheme from the
                // CertificateRequest's signature_algorithms that it supports.
                self.negotiated_signature = null;
                for (self.config.supported_signature_schemes) |ours| {
                    for (cr_parsed.signature_algorithms) |theirs| {
                        if (ours == theirs) {
                            self.negotiated_signature = ours;
                            break;
                        }
                    }
                    if (self.negotiated_signature != null) break;
                }

                traceHandshake("Client: Received CertificateRequest from server\n", .{});
            },
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
            .certificate => {
                // RFC 8446 §4.4.2: Certificate message valid for client role (server cert),
                // or for server role when mTLS is enabled (client cert)
                if (self.config.role == .Client) {
                    try self.handleCertificate(parsed.body);
                } else if (self.config.role == .Server and self.config.request_client_cert) {
                    try self.handleClientCertificate(parsed.body);
                } else {
                    return HandshakeError.UnexpectedMessage;
                }
            },
            .certificate_verify => {
                // RFC 8446 §4.4.3: CertificateVerify valid for client role (server CV),
                // or for server role when mTLS is enabled (client CV)
                if (self.config.role == .Client) {
                    try self.handleCertificateVerify(parsed.body);
                } else if (self.config.role == .Server and self.config.request_client_cert) {
                    try self.handleClientCertificateVerify(parsed.body);
                } else {
                    return HandshakeError.UnexpectedMessage;
                }
            },
            .new_session_ticket => {
                // QUAL-074: RFC 8446 §4.6.1: NewSessionTicket is a post-handshake message
                // sent by the server to the client. It MUST only be accepted by clients
                // at the Application encryption level after the handshake completes.
                if (self.config.role != .Client) return HandshakeError.UnexpectedMessage;
                if (level != .Application) return HandshakeError.UnexpectedMessage;

                // Parse and log the ticket for debugging. Full session resumption
                // storage is handled by the QUIC layer via engine.zig.
                // QUAL-074/QUAL-109: NewSessionTicket is accepted and not silently
                // dropped. An on_session_ticket callback for application-layer
                // session ticket management is deferred as a future enhancement.
                logger.debugPrint("[TLS] Context: Received NewSessionTicket ({} bytes)\n", .{parsed.body.len});
            },
            // GAP-0079: Note — unknown handshake message types are rejected at the parsing
            // layer in parseHandshakeOne() with error.UnknownHandshakeType (RFC 8446 §4).
            // All defined HsType variants are handled above, so no else branch is needed.
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
        try self.confirmPeerFinished();

        // RFC 8446 §4.4: Client sends Finished after verifying server Finished
        if (self.config.role == .Client and !self.flags.local_finished_sent) {
            try self.sendClientFinished();
        }
    }

    /// RFC 8446 §7.1: Derive application-level traffic secrets.
    /// Called after both peers' Finished messages are verified.
    fn ensureApplicationSecrets(self: *Context) !void {
        if (secret_trace_enabled) std.debug.print("[ensureApplicationSecrets] Called for role={}\n", .{self.config.role});
        const send_slot = self.secrets.slot(.Application, .send);
        const recv_slot = self.secrets.slot(.Application, .recv);
        if (secret_trace_enabled) std.debug.print("[ensureApplicationSecrets] send_slot.valid={} recv_slot.valid={}\n", .{ send_slot.valid, recv_slot.valid });

        // Skip if already derived (idempotent)
        if (send_slot.valid and recv_slot.valid) {
            if (secret_trace_enabled) std.debug.print("[ensureApplicationSecrets] Skipping - already derived\n", .{});
            return;
        }

        // RFC 8446 §7.1: Derive from handshake_secret and transcript hash
        // handshake_secret was saved after ServerHello processing
        const hs_secret = self.handshake_secret orelse return HandshakeError.UnexpectedMessage;

        // Transcript hash at this point includes all messages (CH...Finished)
        var transcript_snapshot = self.transcripts.handshake;
        if (secret_trace_enabled) std.debug.print("[ensureApplicationSecrets] About to finalize transcript for role={}\n", .{self.config.role});
        const transcript_hash = transcript_snapshot.finalize(self.hash_kind);
        if (secret_trace_enabled) {
            std.debug.print("[ensureApplicationSecrets] Finalized transcript hash: ", .{});
            for (transcript_hash.slice()) |b| std.debug.print("{X:0>2}", .{b});
            std.debug.print("\n", .{});
        }

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

    /// PERF-013: Zero-allocation outbound framing.  Writes the 4-byte
    /// handshake header + body directly into the outbound CryptoBuffer,
    /// avoiding an intermediate `encodeHandshake` allocation.
    fn appendOutboundFramed(self: *Context, level: EncryptionLevel, typ: HsType, body: []const u8, update_transcript: bool) !void {
        const framed_len = 4 + body.len;
        var stream = self.streams.buffer(level);
        try stream.outbound.ensureUnusedCapacity(self.allocator, framed_len);
        const old_len = stream.outbound.items.len;
        stream.outbound.items.len = old_len + framed_len;
        _ = encodeHandshakeBuf(stream.outbound.items[old_len..][0..framed_len], typ, body) catch unreachable;
        if (update_transcript) {
            self.transcripts.handshake.update(stream.outbound.items[old_len..][0..framed_len]);
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
        // SEC-035: Bounds-check sid_len before advancing pos
        if (pos >= body.len) return HandshakeError.UnexpectedMessage;
        const sid_len: usize = body[pos];
        if (pos + 1 + sid_len > body.len) return HandshakeError.UnexpectedMessage;
        pos += 1 + sid_len;

        // Skip cipher_suite + compression
        if (pos + 2 + 1 > body.len) return HandshakeError.UnexpectedMessage;
        pos += 2 + 1;

        // Parse extensions
        if (pos + 2 > body.len) return HandshakeError.UnexpectedMessage;
        const exts_len: usize = readU16(body[pos .. pos + 2]);
        pos += 2;
        if (pos + exts_len > body.len) return HandshakeError.UnexpectedMessage;

        const exts_end = pos + exts_len;
        var cookie: ?[]const u8 = null;
        var selected_group: ?tls13_full.NamedGroup = null;

        while (pos + 4 <= exts_end) {
            const etype = readU16(body[pos .. pos + 2]);
            const elen: usize = readU16(body[pos + 2 .. pos + 4]);
            pos += 4;
            if (pos + elen > exts_end) return HandshakeError.UnexpectedMessage;

            // RFC 8446 §4.2.2: cookie extension (0x002c)
            if (etype == 0x002c) {
                cookie = body[pos .. pos + elen];
            }
            // RFC 8446 §4.2.8: key_share extension with selected_group (2 bytes)
            else if (etype == 0x0033) {
                if (elen == 2) {
                    const group_val = readU16(body[pos .. pos + 2]);
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

        // SEC-036: Securely zeroize old private key before generating new one.
        // Prevents stale key material from remaining in memory on HRR rekey.
        if (self.client_priv) |*priv| {
            std.crypto.secureZero(u8, priv);
            self.client_priv = null;
        }

        var priv: [32]u8 = undefined;
        std.crypto.random.bytes(&priv);
        // SEC-037: Explicit X25519 clamping per RFC 7748 §5 for defense-in-depth.
        // Zig's X25519 internally clamps during DH computation, but we clamp here
        // too for consistency with engine.zig's ensureKeypair() and to ensure the
        // stored private key bytes are canonical.
        priv[0] &= 248;
        priv[31] &= 127;
        priv[31] |= 64;
        const pub_key = std.crypto.dh.X25519.recoverPublicKey(priv) catch {
            return HandshakeError.UnsupportedKeyShareGroup;
        };

        self.client_priv = priv;
        self.client_pub = pub_key;

        // QUAL-096: Use shared ClientHello builder for ClientHello2.
        // RFC 8446 §4.1.4: MUST use same random as ClientHello1.
        const rnd = self.client_random orelse return HandshakeError.UnexpectedMessage;

        const ch_result = try tls13_full.buildClientHello(self.allocator, .{
            .random = rnd,
            .client_pub = pub_key,
            .key_share_group = selected_group,
            .cipher_suites = self.config.supported_cipher_suites,
            .supported_groups = self.config.supported_groups,
            .signature_algorithms = self.config.supported_signature_schemes,
            .alpn_protocols = self.config.alpn_protocols,
            .quic_transport_parameters = self.local_transport_parameters orelse self.config.quic_transport_parameters,
            .cookie = cookie,
        });
        defer self.allocator.free(ch_result.body);

        // Encode as handshake message
        const msg = try encodeHandshake(self.allocator, .client_hello, ch_result.body);
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

    /// Compute transcript hash for PSK binder verification (RFC 8446 §4.2.11.2).
    ///
    /// The binder is computed over a hash of the ClientHello up to (but not including)
    /// the binders list. This function computes that hash.
    ///
    /// Parameters:
    /// - hash: Hash algorithm (SHA-256 or SHA-384 based on cipher suite)
    /// - header: 4-byte handshake message header (Type + Length)
    /// - truncated_body: ClientHello body truncated before binders list
    ///
    /// Returns:
    /// - Secret containing the transcript hash
    fn computeBinderTranscriptHash(hash: ks.Hash, header: *const [4]u8, truncated_body: []const u8) ks.Secret {
        // RFC 8446 §4.2.11.2: The hash is over the concatenation of:
        // - Handshake header (4 bytes: Type + 3-byte length)
        // - Truncated ClientHello body (up to but not including binders)
        //
        // We compute this incrementally to avoid allocating a buffer.
        return switch (hash) {
            .sha256 => blk: {
                var hasher = std.crypto.hash.sha2.Sha256.init(.{});
                hasher.update(header);
                hasher.update(truncated_body);
                var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
                hasher.final(&digest);
                break :blk ks.Secret.fromSlice(hash, &digest);
            },
            .sha384 => blk: {
                var hasher = std.crypto.hash.sha2.Sha384.init(.{});
                hasher.update(header);
                hasher.update(truncated_body);
                var digest: [std.crypto.hash.sha2.Sha384.digest_length]u8 = undefined;
                hasher.final(&digest);
                break :blk ks.Secret.fromSlice(hash, &digest);
            },
        };
    }

    /// Select a PSK from the ClientHello offered PSKs (RFC 8446 §4.2.11).
    ///
    /// Iterates through offered identities and calls the on_ticket_lookup callback.
    /// If a match is found, verifies the PSK binder.
    ///
    /// ## Ticket Age Validation
    ///
    /// RFC 8446 §4.2.11.1 requires validation of obfuscated_ticket_age to prevent
    /// replay attacks. The ticket age must be within the ticket lifetime bounds.
    ///
    /// **IMPORTANT**: The on_ticket_lookup callback MUST validate ticket age before
    /// returning the PSK. The callback should:
    /// 1. Deobfuscate the ticket age using ticket_age_add
    /// 2. Compare against ticket issue time and lifetime
    /// 3. Return null for expired or invalid tickets
    ///
    /// This implementation provides basic validation but delegates full age checking
    /// to the callback since it has access to ticket metadata.
    ///
    /// Result of PSK selection: carries both the early secret and the selected identity index.
    const PskSelection = struct {
        early_secret: Secret,
        selected_index: u16,
    };

    /// Returns:
    /// - A PskSelection with the early secret and selected identity index
    /// - null if no PSK selected (caller should use zero early secret)
    fn selectPsk(self: *Context, ch_view: ClientHelloView) !?PskSelection {
        const psk_ext = ch_view.pre_shared_key orelse return null;
        const lookup_cb = self.callbacks.on_ticket_lookup orelse return null;

        // RFC 8446 §4.2.9: Validate psk_key_exchange_modes extension is present
        // When using PSK, client MUST include psk_key_exchange_modes extension
        const psk_modes = ch_view.psk_key_exchange_modes orelse {
            traceHandshake("Server: PSK offered but no psk_key_exchange_modes extension (CWE-345)\\n", .{});
            return HandshakeError.MissingPskKeyExchangeModes;
        };

        // RFC 8446 §4.2.9: Verify psk_dhe_ke (0x01) is supported
        // TLS 1.3 requires (EC)DHE with PSK for forward secrecy
        var supports_psk_dhe_ke = false;
        for (psk_modes) |mode| {
            if (mode == 0x01) { // psk_dhe_ke
                supports_psk_dhe_ke = true;
                break;
            }
        }
        if (!supports_psk_dhe_ke) {
            traceHandshake("Server: PSK offered but psk_dhe_ke mode not supported (CWE-345)\\n", .{});
            return HandshakeError.PskDheKeModeRequired;
        }

        // Iterate over identities
        for (psk_ext.identities, 0..) |ident, idx| {
            // RFC 8446 §4.2.11.1: Validate obfuscated_ticket_age bounds
            // The ticket age should not be unreasonably large (e.g., > 7 days in milliseconds)
            // This is a basic sanity check; full validation must be done by the callback
            const max_ticket_age_ms = 7 * 24 * 60 * 60 * 1000; // 7 days
            if (ident.obfuscated_ticket_age > max_ticket_age_ms * 2) {
                // Skip this PSK if the obfuscated age is unreasonably large
                // Note: The factor of 2 accounts for obfuscation via ticket_age_add
                traceHandshake("Server: Skipping PSK with excessive ticket age: {}\\n", .{ident.obfuscated_ticket_age});
                continue;
            }

            // RFC 8446 §4.2.11: Try external PSK config first, then fall back to ticket lookup callback.
            // External PSKs are provisioned out-of-band and use "ext binder" label.
            // Resumption PSKs come from NewSessionTicket and use "res binder" label.
            // SEC-046: Use constant-time comparison for PSK identity matching to prevent
            // timing side-channel leaks (CWE-208). Length check is non-secret.
            const is_external_psk = self.config.external_psk != null and
                self.config.external_psk_identity != null and
                ident.identity.len == self.config.external_psk_identity.?.len and
                std.crypto.timing_safe.compare(u8, ident.identity, self.config.external_psk_identity.?, .big) == .eq;
            const psk_bytes_opt: ?[]const u8 = if (is_external_psk)
                self.config.external_psk
            else
                lookup_cb(self, ident.identity);
            if (psk_bytes_opt) |psk_bytes| {
                // Found a matching PSK. Now verify the binder.
                // RFC 8446 §4.2.11: Binder validation
                // NOTE: For resumption PSKs, the callback MUST have validated ticket age/lifetime before returning PSK

                // 1. Derive early secret and binder key (RFC 8446 §7.1)
                // early_secret = HKDF-Extract(0, psk)
                const early_secret = key_derivation_mod.deriveEarlySecret(self.hash_kind, psk_bytes);
                // binder_key = Derive-Secret(early_secret, "ext binder" | "res binder", "")
                // RFC 8446 §7.1: Use "ext binder" for external PSKs, "res binder" for resumption PSKs.
                const binder_key = key_derivation_mod.deriveBinderKey(self.hash_kind, &early_secret, is_external_psk);

                // 2. Calculate truncated ClientHello for binder verification (RFC 8446 §4.2.11.2)
                // The transcript for binder computation is the ClientHello truncated before the binders list.
                // Calculate binders length (each binder is 1-byte length + binder bytes)
                var binders_len: usize = 0;
                for (psk_ext.binders) |b| {
                    binders_len += 1 + b.len;
                }

                // Validate we have enough bytes for truncation
                // binders_len + 2 = binders list length (2 bytes) + binder entries
                if (ch_view.raw.len < binders_len + 2) return HandshakeError.UnexpectedMessage;
                const truncated_len = ch_view.raw.len - (binders_len + 2);
                const truncated_ch = ch_view.raw[0..truncated_len];

                // Check if we have a binder for this identity
                if (idx >= psk_ext.binders.len) return HandshakeError.UnexpectedMessage;
                const received_binder = psk_ext.binders[idx];

                // 3. Compute transcript hash for binder (RFC 8446 §4.2.11.2)
                // The transcript includes the handshake header (Type + Length) + truncated body.
                // ch_view.raw is just the body, so we need to prepend the header.
                var header: [4]u8 = undefined;
                header[0] = @intFromEnum(HsType.client_hello);
                header[1] = @intCast((ch_view.raw.len >> 16) & 0xFF);
                header[2] = @intCast((ch_view.raw.len >> 8) & 0xFF);
                header[3] = @intCast(ch_view.raw.len & 0xFF);

                // Compute hash of (Header + TruncatedBody)
                // For first ClientHello (no HRR), this is the entire binder transcript.
                // For ClientHello2 after HRR, we would need to include prior messages,
                // but since we handle HRR separately and this is called for the initial CH,
                // we compute the hash directly here.
                const transcript_hash = computeBinderTranscriptHash(self.hash_kind, &header, truncated_ch);

                // 4. Compute expected binder (RFC 8446 §4.2.11.2)
                // finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
                // binder = HMAC(finished_key, Transcript-Hash(Truncated ClientHello))
                const digest_len = ks.digestLength(self.hash_kind);
                var finished_key_buf: [ks.max_digest_length]u8 = undefined;
                const finished_key = finished_key_buf[0..digest_len];
                ks.expandLabelHash(self.hash_kind, &binder_key, "finished", &[_]u8{}, finished_key) catch {
                    return HandshakeError.CryptoError;
                };

                const expected_binder = ks.hmacHash(self.hash_kind, finished_key, transcript_hash.slice());

                // 5. Verify binder using constant-time comparison (security critical!)
                // RFC 8446 §4.2.11.2: "Servers SHOULD check that it is valid"
                // We use constant-time comparison to prevent timing attacks.
                const expected_len = ks.digestLength(self.hash_kind);
                if (received_binder.len != expected_len or expected_binder.len != expected_len) {
                    return HandshakeError.DecryptError; // Binder length mismatch
                }
                const binder_ok = switch (self.hash_kind) {
                    .sha256 => blk: {
                        const received_bytes: *const [32]u8 = received_binder[0..32];
                        const expected_bytes: *const [32]u8 = expected_binder.bytes[0..32];
                        break :blk std.crypto.timing_safe.eql([32]u8, received_bytes.*, expected_bytes.*);
                    },
                    .sha384 => blk: {
                        const received_bytes: *const [48]u8 = received_binder[0..48];
                        const expected_bytes: *const [48]u8 = expected_binder.bytes[0..48];
                        break :blk std.crypto.timing_safe.eql([48]u8, received_bytes.*, expected_bytes.*);
                    },
                };
                if (!binder_ok) {
                    return HandshakeError.DecryptError; // Binder verification failed
                }

                // Binder verified successfully - PSK is authentic
                return PskSelection{
                    .early_secret = early_secret,
                    .selected_index = @intCast(idx),
                };
            }
        }
        return null;
    }
    // QUAL-095: Shared state produced by negotiateCipherAndKeys, consumed by
    // the individual message builders and the flight emitter.
    const ServerNegotiationResult = struct {
        shared: [32]u8,
        server_pub: [32]u8,
        server_random: [32]u8,
        early_secret: Secret,
        selected_psk_index: ?u16,
        psk_selected: bool,
        ch_view: ClientHelloView,
        session_id_opt: ?[]const u8,
    };

    /// QUAL-095 step 1: Negotiate cipher suite, key share, and PSK.
    /// Returns null when an HRR was sent (caller should return immediately).
    fn negotiateCipherAndKeys(self: *Context) !?ServerNegotiationResult {
        const ch_view = self.state.clientHello() orelse return HandshakeError.UnexpectedMessage;
        const cipher_suite = self.chooseCipherSuite(ch_view.cipher_suites) orelse return HandshakeError.NoCipherSuite;
        self.hash_kind = cipherSuiteHash(cipher_suite);
        self.negotiated_cipher_suite = cipher_suite;
        // PERF-004: Lock transcript to the negotiated hash for the server path.
        self.transcripts.handshake.lockHash(self.hash_kind);
        _ = try self.selectServerSignatureScheme(ch_view);

        // RFC 8446 §4.1.4: Check if client's key_share group is supported
        if (ch_view.key_share.group != .x25519) {
            if (self.hrr_sent) return HandshakeError.UnsupportedKeyShareGroup;
            try self.sendHelloRetryRequest(ch_view, .x25519);
            return null; // HRR sent; stop flight
        }

        if (ch_view.key_share.key.len != 32) return HandshakeError.UnsupportedKeyShareGroup;

        var server_random: [32]u8 = undefined;
        std.crypto.random.bytes(&server_random);

        var server_priv: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &server_priv);
        std.crypto.random.bytes(&server_priv);
        // SEC-048: Explicit X25519 clamping per RFC 7748 §5 for defense-in-depth.
        // Zig's X25519 internally clamps during DH computation, but we clamp here
        // too for consistency with sendClientHello2() and engine.zig's ensureKeypair()
        // and to ensure the stored private key bytes are canonical.
        server_priv[0] &= 248;
        server_priv[31] &= 127;
        server_priv[31] |= 64;

        const server_pub = std.crypto.dh.X25519.recoverPublicKey(server_priv) catch {
            return HandshakeError.UnsupportedKeyShareGroup;
        };

        var client_pub: [32]u8 = undefined;
        @memcpy(&client_pub, ch_view.key_share.key[0..32]);

        const shared = std.crypto.dh.X25519.scalarmult(server_priv, client_pub) catch {
            return HandshakeError.UnsupportedKeyShareGroup;
        };

        const session_id_opt: ?[]const u8 = if (ch_view.session_id.len != 0) ch_view.session_id else null;

        const psk_selection = try self.selectPsk(ch_view);
        const early_secret = if (psk_selection) |sel| sel.early_secret else key_derivation_mod.deriveEarlySecret(self.hash_kind, null);
        const selected_psk_index: ?u16 = if (psk_selection) |sel| sel.selected_index else null;

        return .{
            .shared = shared,
            .server_pub = server_pub,
            .server_random = server_random,
            .early_secret = early_secret,
            .selected_psk_index = selected_psk_index,
            .psk_selected = psk_selection != null,
            .ch_view = ch_view,
            .session_id_opt = session_id_opt,
        };
    }

    /// QUAL-095 step 2: Build ServerHello body (allocates; caller frees).
    fn buildServerHelloMsg(self: *Context, neg: *const ServerNegotiationResult) ![]u8 {
        return tls13_full.buildServerHello(
            self.allocator,
            neg.server_random,
            self.negotiated_cipher_suite.?,
            neg.ch_view.key_share.group,
            neg.server_pub[0..],
            neg.session_id_opt,
            null,
            neg.selected_psk_index,
        );
    }

    /// QUAL-095 step 3: Build EncryptedExtensions body (allocates; caller frees).
    fn buildEncryptedExtensionsMsg(self: *Context, ch_view: ClientHelloView) ![]u8 {
        const server_tp = try self.ensureLocalTransportParameters();
        const selected_alpn = try self.selectServerAlpn(ch_view);
        self.notifyMetadata();
        return tls13_full.buildEncryptedExtensions(self.allocator, selected_alpn, server_tp);
    }

    /// QUAL-095 step 4: Build Certificate body.  Returns null for PSK-only auth.
    fn buildCertificateMsg(self: *Context, psk_selected: bool) !?[]u8 {
        const cert_der = self.config.server_cert_der orelse {
            if (!psk_selected) {
                traceHandshake("Server: ERROR - Certificate required when not using PSK authentication\n", .{});
                return HandshakeError.MissingCertificate;
            }
            traceHandshake("Server: Using PSK-only authentication, skipping Certificate/CertificateVerify\n", .{});
            return null;
        };
        traceHandshake("Server: Sending Certificate message ({} bytes DER)\n", .{cert_der.len});
        const cert_entries = [_]tls13_full.CertificateEntryData{.{ .cert = cert_der }};
        const body = try tls13_full.buildCertificate(self.allocator, &[_]u8{}, &cert_entries);
        return body;
    }

    /// QUAL-095 step 5: Build CertificateVerify body (allocates; caller frees).
    fn buildCertificateVerifyMsg(self: *Context) ![]u8 {
        const hash_for_sig = self.transcripts.handshake.finalize(self.hash_kind);

        const sig_scheme = self.negotiated_signature orelse
            return HandshakeError.NoSignatureScheme;

        const sig_alg: sig.SigAlg = switch (sig_scheme) {
            .ecdsa_secp256r1_sha256 => .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384 => .ecdsa_secp384r1_sha384,
            .rsa_pss_rsae_sha256 => .rsa_pss_sha256,
            .ed25519 => .ed25519,
            else => return HandshakeError.UnsupportedSignatureAlgorithm,
        };

        traceHandshake("Server: Signing CertificateVerify with algorithm: {s}\n", .{@tagName(sig_alg)});

        const priv_key = self.config.server_key_der orelse {
            traceHandshake("Server: ERROR - No private key configured!\n", .{});
            return HandshakeError.UnexpectedMessage;
        };

        const signature = try sig.signCertificateVerify(
            sig_alg,
            priv_key,
            "TLS 1.3, server CertificateVerify",
            hash_for_sig.slice(),
            self.allocator,
        );
        defer self.allocator.free(signature);

        return tls13_full.buildCertificateVerify(self.allocator, sig_scheme, signature);
    }

    /// QUAL-095 step 6: Build Finished verify_data (stack-only, no allocation).
    fn buildFinishedMsg(self: *Context, server_hs_secret: *const Secret) Secret {
        const hash_before_finished = self.transcripts.handshake.finalize(self.hash_kind);
        self.transcripts.finished_hash.set(self.hash_kind, hash_before_finished);
        return deriveFinishedVerifyData(self.hash_kind, server_hs_secret, hash_before_finished);
    }

    /// QUAL-095 + PERF-013: Emit the complete server flight using zero-alloc
    /// framing via appendOutboundFramed.  Message bodies are built by the
    /// individual helpers; only the bodies allocate.
    fn emitServerFlight(self: *Context, neg: *ServerNegotiationResult) !void {
        // --- ServerHello (Initial level) ---
        const sh_body = try self.buildServerHelloMsg(neg);
        defer self.allocator.free(sh_body);

        traceHandshake("[TRANSCRIPT_DEBUG] ServerHello body ({} bytes)\n", .{sh_body.len});

        // Snapshot ClientHello-only transcript before ServerHello touches it.
        const ch_only_hash = self.transcripts.handshake.finalize(self.hash_kind);

        // ServerHello goes at the Initial encryption level (unencrypted).
        // We must use appendOutbound here (not appendOutboundFramed) because
        // buildServerHello already returns the body without the 4-byte header
        // and appendOutbound is how the existing code sends it.
        // Actually, use appendOutboundFramed for PERF-013 zero-alloc framing.
        try self.appendOutboundFramed(.Initial, .server_hello, sh_body, true);

        const transcript_after_sh = self.transcripts.handshake.finalize(self.hash_kind);

        // --- 0-RTT early data handling ---
        if (neg.ch_view.early_data and self.config.enable_early_data and neg.early_secret.slice().len > 0) {
            const client_random = neg.ch_view.random;
            var accept_early = true;
            if (self.anti_replay) |ar| {
                ar.add(client_random) catch |err| {
                    traceHandshake("Server: 0-RTT anti-replay detected ({}), rejecting early data\\n", .{err});
                    accept_early = false;
                };
            } else {
                accept_early = false;
            }
            if (accept_early) {
                const early_traffic_secret = key_derivation_mod.deriveEarlyTraffic(self.hash_kind, &neg.early_secret, ch_only_hash.slice());
                try self.installTrafficSecret(.Initial, .recv, early_traffic_secret);
                traceHandshake("Server: Installed 0-RTT early traffic secret for receiving\\n", .{});
            }
        }

        // --- Derive and install handshake traffic secrets ---
        const hs = deriveHandshakeTraffic(self.hash_kind, neg.shared[0..], transcript_after_sh, &neg.early_secret);
        self.handshake_secret = hs.handshake;
        try self.installTrafficSecret(.Handshake, .send, hs.server_hs);
        try self.installTrafficSecret(.Handshake, .recv, hs.client_hs);
        if (self.phase == .negotiating) self.phase = .keys_installed;

        // --- EncryptedExtensions (Handshake level) ---
        const ee_body = try self.buildEncryptedExtensionsMsg(neg.ch_view);
        defer self.allocator.free(ee_body);
        try self.appendOutboundFramed(.Handshake, .encrypted_extensions, ee_body, true);

        // --- CertificateRequest (mTLS, optional) ---
        if (self.config.request_client_cert) {
            const cr_body = try tls13_full.buildCertificateRequest(
                self.allocator,
                self.config.supported_signature_schemes,
                self.config.client_auth_ca_certs,
            );
            defer self.allocator.free(cr_body);
            try self.appendOutboundFramed(.Handshake, .certificate_request, cr_body, true);
            traceHandshake("Server: Sent CertificateRequest message\n", .{});
        }

        // --- Certificate + CertificateVerify (if not PSK-only) ---
        if (try self.buildCertificateMsg(neg.psk_selected)) |cert_body| {
            defer self.allocator.free(cert_body);
            try self.appendOutboundFramed(.Handshake, .certificate, cert_body, true);

            const cv_body = try self.buildCertificateVerifyMsg();
            defer self.allocator.free(cv_body);
            try self.appendOutboundFramed(.Handshake, .certificate_verify, cv_body, true);

            traceHandshake("Server: Certificate and CertificateVerify sent successfully\n", .{});
        }

        // --- Finished ---
        const verify_data = self.buildFinishedMsg(&hs.server_hs);
        try self.appendOutboundFramed(.Handshake, .finished, verify_data.slice(), true);

        try self.markLocalFinished();
    }

    /// QUAL-095: Concise orchestrator for the server handshake flight.
    fn driveServerHandshakeFlight(self: *Context) !void {
        if (self.config.role != .Server) return;
        if (self.flags.local_finished_sent) return;
        if (self.secrets.handshake.send.valid) return;

        var neg = try self.negotiateCipherAndKeys() orelse return; // HRR sent
        defer std.crypto.secureZero(u8, &neg.shared);
        try self.emitServerFlight(&neg);
    }

    /// Construct and queue a ClientHello with QUIC extensions when acting as the client.
    /// This must be called by the QUIC layer before polling for Initial CRYPTO data.
    pub fn startClientHandshake(self: *Context) !void {
        if (self.config.role != .Client) return;
        if (self.client_priv != null) return; // already started
        if (self.config.supported_cipher_suites.len != 0) {
            self.hash_kind = cipherSuiteHash(self.config.supported_cipher_suites[0]);
        }
        // Generate X25519 key pair
        var priv: [32]u8 = undefined;
        std.crypto.random.bytes(&priv);
        // SEC-040: Explicit X25519 clamping per RFC 7748 §5 for defense-in-depth.
        // Zig's X25519 internally clamps during DH computation, but we clamp here
        // too for consistency with sendClientHello2() and engine.zig's ensureKeypair()
        // and to ensure the stored private key bytes are canonical.
        priv[0] &= 248;
        priv[31] &= 127;
        priv[31] |= 64;
        const client_pubkey = std.crypto.dh.X25519.recoverPublicKey(priv) catch return HandshakeError.UnsupportedKeyShareGroup;
        self.client_priv = priv;
        self.client_pub = client_pubkey;

        var rnd: [32]u8 = undefined;
        std.crypto.random.bytes(&rnd);
        self.client_random = rnd; // Save for potential HRR handling

        // Determine PSK parameters
        const has_resumption_psk = self.config.resumption_psk != null;
        const has_external_psk = self.config.external_psk != null and self.config.external_psk_identity != null;
        const has_any_psk = has_resumption_psk or has_external_psk;
        const using_external_psk = has_external_psk and !has_resumption_psk;

        const psk_identity: ?[]const u8 = if (has_any_psk) blk: {
            break :blk if (using_external_psk)
                self.config.external_psk_identity.?
            else
                (self.config.resumption_ticket orelse return HandshakeError.MissingResumptionTicket);
        } else null;

        // QUAL-096: Use shared ClientHello builder.
        const ch_result = try tls13_full.buildClientHello(self.allocator, .{
            .random = rnd,
            .client_pub = client_pubkey,
            .cipher_suites = self.config.supported_cipher_suites,
            .supported_groups = self.config.supported_groups,
            .signature_algorithms = self.config.supported_signature_schemes,
            .alpn_protocols = self.config.alpn_protocols,
            .quic_transport_parameters = self.local_transport_parameters orelse self.config.quic_transport_parameters,
            .include_early_data = has_resumption_psk and self.config.enable_early_data,
            .include_psk = has_any_psk,
            .psk_identity = psk_identity,
            .psk_ticket_age = if (using_external_psk) 0 else self.config.resumption_ticket_age_add,
            .psk_binder_len = if (has_any_psk) @intCast(ks.digestLength(self.hash_kind)) else 0,
        });
        defer self.allocator.free(ch_result.body);

        // PERF-015: Build the full handshake message (header + body) in one allocation
        // so PSK binder computation can hash the complete message in-place.
        const body_len: u32 = @intCast(ch_result.body.len);
        const msg = try self.allocator.alloc(u8, 4 + ch_result.body.len);
        defer self.allocator.free(msg);
        msg[0] = @intFromEnum(HsType.client_hello);
        msg[1] = @intCast((body_len >> 16) & 0xff);
        msg[2] = @intCast((body_len >> 8) & 0xff);
        msg[3] = @intCast(body_len & 0xff);
        @memcpy(msg[4..], ch_result.body);

        // Compute PSK binder if needed
        if (ch_result.binder_offset) |body_binder_offset| {
            const binder_len = ch_result.binder_len;
            if (binder_len == 0) return HandshakeError.CryptoError;

            const psk = if (using_external_psk) self.config.external_psk.? else self.config.resumption_psk.?;
            const early_secret = key_derivation_mod.deriveEarlySecret(self.hash_kind, psk);
            const binder_key = key_derivation_mod.deriveBinderKey(self.hash_kind, &early_secret, using_external_psk);

            // Truncate before binders list (offset relative to full msg including header)
            const truncated_len = msg.len - ch_result.binders_tail_len;

            // Hash truncated message (header is at msg[0..4])
            var transcript = Transcript.init();
            transcript.update(msg[0..truncated_len]);
            const transcript_hash = transcript.finalize(self.hash_kind);

            const binder = finished_mod.deriveFinishedVerifyData(self.hash_kind, &binder_key, transcript_hash);
            // Binder offset in body + 4 for the handshake header
            const msg_binder_offset = body_binder_offset + 4;
            @memcpy(msg[msg_binder_offset..][0..binder_len], binder.slice()[0..binder_len]);

            if (self.config.enable_early_data) {
                const early_traffic_secret = key_derivation_mod.deriveEarlyTraffic(
                    self.hash_kind,
                    &early_secret,
                    transcript_hash.slice(),
                );
                try self.installTrafficSecret(.Initial, .send, early_traffic_secret);
                traceHandshake("Client: Installed 0-RTT early traffic secret for sending\\n", .{});
            }
        }

        // Send the complete framed message
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
        const suite_value: u16 = readU16(body[pos .. pos + 2]);
        const cipher_suite = std.meta.intToEnum(tls13_full.CipherSuite, suite_value) catch return HandshakeError.NoCipherSuite;

        // SEC-028: Verify the server-selected cipher suite was in our offered list.
        // RFC 8446 §4.1.3: Server MUST select from the client's cipher_suites.
        var cipher_suite_offered = false;
        for (self.config.supported_cipher_suites) |offered| {
            if (offered == cipher_suite) {
                cipher_suite_offered = true;
                break;
            }
        }
        if (!cipher_suite_offered) {
            traceHandshake("Client: Server selected cipher suite {x} not in offered list\\n", .{suite_value});
            return HandshakeError.NoCipherSuite;
        }

        self.negotiated_cipher_suite = cipher_suite;
        self.hash_kind = cipherSuiteHash(cipher_suite);
        // PERF-004: Lock transcript to the negotiated hash; subsequent updates
        // skip the unused algorithm.
        self.transcripts.handshake.lockHash(self.hash_kind);
        pos += 2; // cipher_suite
        pos += 1; // compression
        if (pos + 2 > body.len) return HandshakeError.UnexpectedMessage;
        const exts_len: usize = readU16(body[pos .. pos + 2]);
        pos += 2;
        if (pos + exts_len > body.len) return HandshakeError.UnexpectedMessage;
        const exts_end = pos + exts_len;
        var server_pub: ?[32]u8 = null;
        var found_supported_versions = false;
        var server_selected_psk_index: ?u16 = null;
        while (pos + 4 <= exts_end) {
            const etype = readU16(body[pos .. pos + 2]);
            const elen: usize = readU16(body[pos + 2 .. pos + 4]);
            pos += 4;
            if (pos + elen > exts_end) return HandshakeError.UnexpectedMessage;
            if (etype == @intFromEnum(tls13_full.ExtensionType.supported_versions)) {
                // RFC 8446 §4.2.1: In ServerHello, supported_versions contains
                // the single selected version (2 bytes). Must be 0x0304 (TLS 1.3).
                if (elen != 2) return HandshakeError.UnsupportedVersion;
                const selected_version = readU16(body[pos .. pos + 2]);
                if (selected_version != 0x0304) return HandshakeError.UnsupportedVersion;
                found_supported_versions = true;
            } else if (etype == 0x0033) { // key_share
                if (elen < 4 + 32) return HandshakeError.MissingKeyShare;
                const group = readU16(body[pos .. pos + 2]);
                const klen = readU16(body[pos + 2 .. pos + 4]);
                if (group != 0x001d or klen != 32 or pos + 4 + 32 > pos + elen) return HandshakeError.UnsupportedKeyShareGroup;
                var kp: [32]u8 = undefined;
                @memcpy(&kp, body[pos + 4 .. pos + 4 + 32]);
                server_pub = kp;
            } else if (etype == @intFromEnum(tls13_full.ExtensionType.pre_shared_key)) {
                // RFC 8446 §4.2.11: Server's pre_shared_key extension contains
                // a single selected_identity value (u16).
                if (elen != 2) return HandshakeError.UnexpectedMessage;
                server_selected_psk_index = readU16(body[pos .. pos + 2]);
            }
            pos += elen;
        }
        // RFC 8446 §4.2.1: supported_versions is REQUIRED in ServerHello
        if (!found_supported_versions) return HandshakeError.UnsupportedVersion;
        if (server_pub == null) return HandshakeError.MissingKeyShare;
        const priv = self.client_priv orelse return HandshakeError.UnexpectedMessage;

        // RFC 8446 §4.2.11: Validate pre_shared_key extension from server
        const early_secret = if (server_selected_psk_index) |psk_idx| blk: {
            // Server selected a PSK -- validate and use it
            // Check for external PSK first, then resumption PSK
            const client_has_external_psk = self.config.external_psk != null and self.config.external_psk_identity != null;
            const client_has_resumption_psk = self.config.resumption_psk != null;
            const psk = if (client_has_resumption_psk)
                self.config.resumption_psk.?
            else if (client_has_external_psk)
                self.config.external_psk.?
            else {
                // Server sent pre_shared_key but client didn't offer PSK
                return HandshakeError.UnexpectedPskExtension;
            };
            // We only offer one PSK identity, so index must be 0
            if (psk_idx != 0) {
                return HandshakeError.PskIndexOutOfRange;
            }
            break :blk key_derivation_mod.deriveEarlySecret(self.hash_kind, psk);
        } else blk: {
            // No PSK selected by server -- use zero early secret
            break :blk key_derivation_mod.deriveEarlySecret(self.hash_kind, null);
        };

        var shared = std.crypto.dh.X25519.scalarmult(priv, server_pub.?) catch return HandshakeError.UnsupportedKeyShareGroup;
        defer std.crypto.secureZero(u8, &shared);
        const sh_snapshot = self.transcripts.handshake.finalize(self.hash_kind);
        const hs = deriveHandshakeTraffic(self.hash_kind, shared[0..], sh_snapshot, &early_secret);
        self.handshake_secret = hs.handshake;

        // CLIENT uses client_hs for send, server_hs for recv (opposite of server)
        try self.installTrafficSecret(.Handshake, .send, hs.client_hs);
        try self.installTrafficSecret(.Handshake, .recv, hs.server_hs);
        self.phase = .keys_installed;
    }

    fn sendClientFinished(self: *Context) !void {
        const slot = self.secrets.slot(.Handshake, .send);
        if (!slot.valid) return HandshakeError.UnexpectedMessage;

        // RFC 8446 §4.4.2: Client sends Certificate + CertificateVerify before Finished
        // if the server sent a CertificateRequest
        if (self.client_cert_requested) {
            const request_context = if (self.client_cert_request_context) |ctx| ctx else &[_]u8{};

            if (self.config.client_cert_der) |cert_der| {
                // Client has a certificate: send Certificate with the cert
                const cert_entries = [_]tls13_full.CertificateEntryData{.{ .cert = cert_der }};
                const cert_body = try tls13_full.buildCertificate(self.allocator, request_context, &cert_entries);
                defer self.allocator.free(cert_body);

                const cert_msg = try encodeHandshake(self.allocator, .certificate, cert_body);
                defer self.allocator.free(cert_msg);
                try self.appendOutbound(.Handshake, cert_msg, true);

                traceHandshake("Client: Sent Certificate message for mTLS\n", .{});

                // Send CertificateVerify signed with client private key
                if (self.config.client_key_der) |priv_key| {
                    const hash_for_sig = self.transcripts.handshake.finalize(self.hash_kind);

                    // RFC 8446 §4.4.3: Client MUST use a scheme from the server's
                    // CertificateRequest signature_algorithms extension.
                    const sig_scheme = self.negotiated_signature orelse
                        return HandshakeError.NoSignatureScheme;
                    const sig_alg: sig.SigAlg = switch (sig_scheme) {
                        .ecdsa_secp256r1_sha256 => .ecdsa_secp256r1_sha256,
                        .ecdsa_secp384r1_sha384 => .ecdsa_secp384r1_sha384,
                        .rsa_pss_rsae_sha256 => .rsa_pss_sha256,
                        .ed25519 => .ed25519,
                        else => return HandshakeError.UnsupportedSignatureAlgorithm,
                    };

                    const signature = try sig.signCertificateVerify(
                        sig_alg,
                        priv_key,
                        "TLS 1.3, client CertificateVerify",
                        hash_for_sig.slice(),
                        self.allocator,
                    );
                    defer self.allocator.free(signature);

                    const cv_body = try tls13_full.buildCertificateVerify(self.allocator, sig_scheme, signature);
                    defer self.allocator.free(cv_body);

                    const cv_msg = try encodeHandshake(self.allocator, .certificate_verify, cv_body);
                    defer self.allocator.free(cv_msg);
                    try self.appendOutbound(.Handshake, cv_msg, true);

                    traceHandshake("Client: Sent CertificateVerify for mTLS\n", .{});
                }
            } else {
                // No client certificate configured: send empty Certificate (RFC 8446 §4.4.2)
                const cert_body = try tls13_full.buildCertificate(self.allocator, request_context, &[_]tls13_full.CertificateEntryData{});
                defer self.allocator.free(cert_body);

                const cert_msg = try encodeHandshake(self.allocator, .certificate, cert_body);
                defer self.allocator.free(cert_msg);
                try self.appendOutbound(.Handshake, cert_msg, true);

                traceHandshake("Client: Sent empty Certificate (no client cert configured)\n", .{});
            }
        }

        var transcript_snapshot = self.transcripts.handshake;
        const hash_before = transcript_snapshot.finalize(slot.hash);
        const verify_data = deriveFinishedVerifyData(slot.hash, &slot.value, hash_before);
        const fin_msg = try encodeHandshake(self.allocator, .finished, verify_data.slice());
        defer self.allocator.free(fin_msg);
        try self.appendOutbound(.Handshake, fin_msg, true);
        try self.markLocalFinished();
    }

    fn notifyMetadata(self: *Context) void {
        if (self.flags.metadata_notified) return;
        if (self.callbacks.on_handshake_metadata) |cb| {
            // QUAL-110 (by-design): Metadata callback errors are intentionally logged
            // and not propagated. The on_handshake_metadata callback is informational --
            // a failure to process metadata (e.g., ALPN logging) should not abort a
            // valid handshake. This differs from security-critical callbacks like
            // on_sct_list which correctly propagate errors.
            cb(self, self.metadataView()) catch |err| {
                logger.debugPrint("[TLS] on_handshake_metadata callback error: {}\n", .{err});
            };
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

    /// RFC 8446 §4.4.2: Parse and store server Certificate message.
    /// The certificate chain will be validated when CertificateVerify is processed.
    fn handleCertificate(self: *Context, body: []const u8) !void {
        // Parse Certificate message using tls13_full
        const parsed = try tls13_full.parseCertificate(self.allocator, body);
        // Free the parsed entries slice when done (the cert data itself points into body, not allocated)
        defer self.allocator.free(parsed.entries);

        if (parsed.entries.len == 0) {
            return HandshakeError.EmptyCertificateChain;
        }

        // Free any previously stored chain
        if (self.peer_cert_chain) |old_chain| {
            for (old_chain) |cert| {
                self.allocator.free(cert);
            }
            self.allocator.free(old_chain);
        }

        // Allocate and copy the certificate chain
        var chain = try self.allocator.alloc([]const u8, parsed.entries.len);
        var allocated_count: usize = 0;
        errdefer {
            for (chain[0..allocated_count]) |cert| {
                self.allocator.free(cert);
            }
            self.allocator.free(chain);
        }

        for (parsed.entries, 0..) |cert_entry, i| {
            chain[i] = try self.allocator.dupe(u8, cert_entry.cert);
            allocated_count += 1;
        }

        self.peer_cert_chain = chain;

        // Store OCSP response and SCT list from leaf certificate (first entry)
        // RFC 8446 §4.4.2.1: Extensions in leaf certificate entry
        // QUAL-128: Dupe before free to prevent dangling pointer on OOM.
        if (parsed.entries[0].ocsp_response) |ocsp_data| {
            const new_copy = try self.allocator.dupe(u8, ocsp_data);
            if (self.peer_ocsp_response) |old| {
                self.allocator.free(old);
            }
            self.peer_ocsp_response = new_copy;
            traceHandshake("Client: Received OCSP response ({} bytes)\\n", .{ocsp_data.len});
        }

        if (parsed.entries[0].sct_list) |sct_data| {
            const new_copy = try self.allocator.dupe(u8, sct_data);
            if (self.peer_sct_list) |old| {
                self.allocator.free(old);
            }
            self.peer_sct_list = new_copy;
            traceHandshake("Client: Received SCT list ({} bytes)\\n", .{sct_data.len});
        }

        traceHandshake("Client: Received Certificate with {} cert(s)\\n", .{chain.len});
    }

    /// RFC 8446 §4.4.3: Parse CertificateVerify and perform full certificate validation.
    /// This validates the entire certificate chain and verifies the signature over the transcript.
    fn handleCertificateVerify(self: *Context, body: []const u8) !void {
        // Parse CertificateVerify message
        const parsed = try tls13_full.parseCertificateVerify(body);

        // QUAL-128: Dupe before free to prevent dangling pointer on OOM.
        const sig_copy = try self.allocator.dupe(u8, parsed.signature);
        if (self.peer_cert_verify_sig) |old_sig| {
            self.allocator.free(old_sig);
        }
        self.peer_cert_verify_sig = sig_copy;
        self.peer_cert_verify_alg = parsed.algorithm;

        // Validate certificate chain
        const chain = self.peer_cert_chain orelse return HandshakeError.MissingCertificate;

        // Get current time for certificate validity checking
        const now_unix = std.time.timestamp();

        // SEC-029: Require server_name for hostname validation unless allow_insecure.
        // Without a server_name, any valid cert from any CA would be accepted (MITM risk).
        if (self.config.server_name == null and !self.config.allow_insecure) {
            traceHandshake("Client: ERROR - server_name is null and allow_insecure is false\\n", .{});
            return HandshakeError.MissingServerName;
        }

        // Get server name from SNI for hostname validation
        const server_name = if (self.config.server_name) |sni| sni else "";

        // RFC 5280 §6: Perform full chain validation
        // This includes:
        // - Validity period checks
        // - Hostname (SNI) verification
        // - Extended Key Usage (id-kp-serverAuth)
        // - Basic Constraints enforcement
        // - Signature verification along the chain
        x509.validateChain(
            self.allocator,
            chain,
            now_unix,
            server_name,
            self.config.allow_insecure,
            .server_auth,
        ) catch |err| {
            traceHandshake("Client: Certificate chain validation failed: {}\\n", .{err});
            return HandshakeError.CertificateValidationFailed;
        };

        // RFC 6960 + RFC 8446 §4.4.2.1: OCSP stapling validation
        if (!self.config.allow_insecure) {
            if (self.config.require_ocsp) {
                // OCSP is required - fail if not present
                if (self.peer_ocsp_response == null) {
                    traceHandshake("Client: ERROR - OCSP response required but not provided\\n", .{});
                    return HandshakeError.MissingOcspResponse;
                }
            }

            // Validate OCSP response if present
            if (self.peer_ocsp_response) |ocsp_bytes| {
                // Parse leaf certificate to get issuer information
                const leaf_parsed = try x509.parseCert(self.allocator, chain[0]);
                defer leaf_parsed.deinit(self.allocator);

                // Determine issuer info for OCSP validation
                var issuer_parsed: x509.Certificate = undefined;
                var has_issuer = false;
                const issuer_info: ?ocsp.IssuerInfo = if (chain.len >= 2) blk: {
                    issuer_parsed = try x509.parseCert(self.allocator, chain[1]);
                    has_issuer = true;
                    break :blk ocsp.IssuerInfo{ .cert = &issuer_parsed, .der = chain[1] };
                } else null;
                defer if (has_issuer) issuer_parsed.deinit(self.allocator);

                // Validate the stapled OCSP response
                ocsp.validateStapledResponse(
                    self.allocator,
                    ocsp_bytes,
                    &leaf_parsed,
                    chain[0],
                    issuer_info,
                    now_unix,
                ) catch |err| {
                    traceHandshake("Client: OCSP validation failed: {}\\n", .{err});
                    return HandshakeError.OcspValidationFailed;
                };

                traceHandshake("Client: OCSP response validated successfully\\n", .{});
            }

            // RFC 6962 + RFC 8446 §4.4.2.1: Signed Certificate Timestamp (SCT) validation
            if (self.config.require_scts) {
                // SCT is required - fail if not present
                if (self.peer_sct_list == null) {
                    traceHandshake("Client: ERROR - SCT list required but not provided\\n", .{});
                    return HandshakeError.MissingSctList;
                }
            }

            // Validate and invoke callback for SCT list if present
            if (self.peer_sct_list) |sct_bytes| {
                const parsed_scts = sct.parseList(self.allocator, sct_bytes) catch |err| {
                    traceHandshake("Client: Failed to parse SCT list: {}\\n", .{err});
                    return HandshakeError.SctParsingFailed;
                };
                defer self.allocator.free(parsed_scts);

                if (parsed_scts.len == 0 and self.config.require_scts) {
                    traceHandshake("Client: ERROR - Empty SCT list when SCTs required\\n", .{});
                    return HandshakeError.EmptySctList;
                }

                // Invoke user callback for additional validation if configured
                if (self.config.on_sct_list) |callback| {
                    callback(parsed_scts) catch |err| {
                        traceHandshake("Client: SCT list callback rejected: {}\\n", .{err});
                        return HandshakeError.SctCallbackRejected;
                    };
                }

                traceHandshake("Client: SCT list validated ({} SCTs)\\n", .{parsed_scts.len});
            }
        }

        // RFC 8446 §4.4.3: Verify CertificateVerify signature
        // Skip signature verification when allow_insecure is set (testing only)
        if (!self.config.allow_insecure) {
            // The signature is computed over the transcript hash up to (but not including) CertificateVerify
            const transcript_hash = self.transcripts.handshake.finalize(self.hash_kind);

            // RFC 8446 §4.2.3: Enforce signature algorithm policy
            // Verify that the algorithm used in CertificateVerify is in our supported list
            var algorithm_supported = false;
            for (self.config.supported_signature_schemes) |scheme| {
                if (scheme == parsed.algorithm) {
                    algorithm_supported = true;
                    break;
                }
            }
            if (!algorithm_supported) {
                traceHandshake("Client: CertificateVerify algorithm {} not in supported list\\n", .{parsed.algorithm});
                return HandshakeError.UnsupportedSignatureAlgorithm;
            }

            // Get the leaf certificate's SPKI for signature verification
            const sig_alg = sig.fromTls13SignatureScheme(parsed.algorithm) catch {
                return HandshakeError.UnsupportedSignatureAlgorithm;
            };

            // Extract SPKI from leaf certificate for signature verification
            const leaf_cert = try x509.parseCert(self.allocator, chain[0]);
            defer leaf_cert.deinit(self.allocator);

            // Verify the signature using the leaf certificate's public key (SPKI)
            const verified = try sig.verifyCertificateVerify(
                sig_alg,
                leaf_cert.spki, // SPKI DER, not full certificate
                parsed.signature,
                "TLS 1.3, server CertificateVerify", // RFC 8446 §4.4.3 context string
                transcript_hash.slice(),
                self.allocator,
            );

            if (!verified) {
                traceHandshake("Client: CertificateVerify signature verification failed\\n", .{});
                return HandshakeError.InvalidSignature;
            }

            traceHandshake("Client: Certificate chain validated and CertificateVerify signature verified\\n", .{});
        } else {
            traceHandshake("Client: Certificate validation skipped (allow_insecure=true)\\n", .{});
        }
    }

    /// RFC 8446 §4.4.2: Parse and store client Certificate message (server-side mTLS).
    /// Reuses the existing peer_cert_chain storage (role-neutral).
    fn handleClientCertificate(self: *Context, body: []const u8) !void {
        const parsed = try tls13_full.parseCertificate(self.allocator, body);
        defer self.allocator.free(parsed.entries);

        // Empty certificate list is allowed (RFC 8446 §4.4.2) - client has no cert
        if (parsed.entries.len == 0) {
            traceHandshake("Server: Client sent empty Certificate (no client cert)\n", .{});
            // Store empty chain so handleClientCertificateVerify knows no cert was sent
            if (self.peer_cert_chain) |old_chain| {
                for (old_chain) |cert| self.allocator.free(cert);
                self.allocator.free(old_chain);
            }
            self.peer_cert_chain = null;
            return;
        }

        // Free any previously stored chain
        if (self.peer_cert_chain) |old_chain| {
            for (old_chain) |cert| self.allocator.free(cert);
            self.allocator.free(old_chain);
        }

        // Allocate and copy the certificate chain
        var chain = try self.allocator.alloc([]const u8, parsed.entries.len);
        var client_allocated_count: usize = 0;
        errdefer {
            for (chain[0..client_allocated_count]) |cert| self.allocator.free(cert);
            self.allocator.free(chain);
        }

        for (parsed.entries, 0..) |cert_entry, i| {
            chain[i] = try self.allocator.dupe(u8, cert_entry.cert);
            client_allocated_count += 1;
        }

        self.peer_cert_chain = chain;
        traceHandshake("Server: Received client Certificate with {} cert(s)\n", .{chain.len});
    }

    /// RFC 8446 §4.4.3: Parse and verify client CertificateVerify (server-side mTLS).
    /// Uses "TLS 1.3, client CertificateVerify" context string and skips hostname validation.
    fn handleClientCertificateVerify(self: *Context, body: []const u8) !void {
        const parsed = try tls13_full.parseCertificateVerify(body);

        // QUAL-128: Dupe before free to prevent dangling pointer on OOM.
        const sig_copy = try self.allocator.dupe(u8, parsed.signature);
        if (self.peer_cert_verify_sig) |old_sig| self.allocator.free(old_sig);
        self.peer_cert_verify_sig = sig_copy;
        self.peer_cert_verify_alg = parsed.algorithm;

        // Need a certificate chain to verify against
        const chain = self.peer_cert_chain orelse return HandshakeError.MissingCertificate;
        if (chain.len == 0) return HandshakeError.MissingCertificate;

        if (!self.config.allow_insecure) {
            // RFC 5280 §6: Validate client certificate chain
            // Skip hostname validation for client certs (no SNI to match against)
            const now_unix = std.time.timestamp();
            // SEC-031: Pass client_auth EKU purpose for mTLS client certs
            x509.validateChain(
                self.allocator,
                chain,
                now_unix,
                "", // No hostname validation for client certs
                false, // Don't skip validation
                .client_auth,
            ) catch |err| {
                traceHandshake("Server: Client certificate chain validation failed: {}\n", .{err});
                return HandshakeError.CertificateValidationFailed;
            };

            // Verify CertificateVerify signature with client context string
            const transcript_hash = self.transcripts.handshake.finalize(self.hash_kind);

            // Check signature algorithm is supported
            var algorithm_supported = false;
            for (self.config.supported_signature_schemes) |scheme| {
                if (scheme == parsed.algorithm) {
                    algorithm_supported = true;
                    break;
                }
            }
            if (!algorithm_supported) {
                return HandshakeError.UnsupportedSignatureAlgorithm;
            }

            const sig_alg = sig.fromTls13SignatureScheme(parsed.algorithm) catch {
                return HandshakeError.UnsupportedSignatureAlgorithm;
            };

            // Extract SPKI from leaf certificate for signature verification
            const client_leaf = try x509.parseCert(self.allocator, chain[0]);
            defer client_leaf.deinit(self.allocator);

            const verified = try sig.verifyCertificateVerify(
                sig_alg,
                client_leaf.spki, // SPKI DER, not full certificate
                parsed.signature,
                "TLS 1.3, client CertificateVerify", // Client context string
                transcript_hash.slice(),
                self.allocator,
            );

            if (!verified) {
                traceHandshake("Server: Client CertificateVerify signature verification failed\n", .{});
                return HandshakeError.InvalidSignature;
            }

            traceHandshake("Server: Client certificate validated and CertificateVerify verified\n", .{});
        } else {
            traceHandshake("Server: Client certificate validation skipped (allow_insecure=true)\n", .{});
        }
    }

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

        logger.debugPrint("handleEncryptedExtensions: Extracted {} bytes of transport params, ALPN={s}\n", .{ if (parsed.quic_transport_parameters) |tp| tp.len else 0, if (parsed.alpn) |alpn| alpn else "none" });
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

/// Validate the supported_versions extension in a ServerHello extensions block.
///
/// RFC 8446 Section 4.2.1: The ServerHello MUST contain a supported_versions
/// extension with the selected version set to 0x0304 (TLS 1.3).
///
/// This function is used by tests to validate the same logic implemented
/// inline in Context.handleServerHello. It scans the extensions starting at
/// the given offset within the body and checks:
///   - The supported_versions extension (0x002B) is present
///   - Its data is exactly 2 bytes (selected version)
///   - The selected version is 0x0304 (TLS 1.3)
///
/// Returns the selected version if valid, or an error otherwise.
fn validateServerHelloSupportedVersions(body: []const u8, ext_start: usize, exts_len: usize) HandshakeError!u16 {
    var pos = ext_start;
    const exts_end = ext_start + exts_len;
    if (exts_end > body.len) return HandshakeError.UnexpectedMessage;

    var found = false;
    var version: u16 = 0;
    while (pos + 4 <= exts_end) {
        const etype = readU16(body[pos .. pos + 2]);
        const elen: usize = readU16(body[pos + 2 .. pos + 4]);
        pos += 4;
        if (pos + elen > exts_end) return HandshakeError.UnexpectedMessage;
        if (etype == @intFromEnum(tls13_full.ExtensionType.supported_versions)) {
            if (elen != 2) return HandshakeError.UnsupportedVersion;
            version = readU16(body[pos .. pos + 2]);
            if (version != 0x0304) return HandshakeError.UnsupportedVersion;
            found = true;
        }
        pos += elen;
    }
    if (!found) return HandshakeError.UnsupportedVersion;
    return version;
}

test "RFC 8446 §4.2.1: ServerHello supported_versions=0x0304 is accepted" {
    // Build a minimal extensions block with supported_versions=0x0304 and key_share
    var exts: [50]u8 = [_]u8{0} ** 50;
    // supported_versions: type=0x002b, len=0x0002, value=0x0304
    exts[0] = 0x00;
    exts[1] = 0x2b;
    exts[2] = 0x00;
    exts[3] = 0x02;
    exts[4] = 0x03;
    exts[5] = 0x04;

    const version = try validateServerHelloSupportedVersions(&exts, 0, 6);
    try std.testing.expectEqual(@as(u16, 0x0304), version);
}

test "RFC 8446 §4.2.1: ServerHello missing supported_versions returns error" {
    // Build extensions block with only key_share (0x0033), no supported_versions
    var exts: [44]u8 = [_]u8{0} ** 44;
    // key_share: type=0x0033, len=0x0024 (36 bytes), group=0x001d, klen=0x0020, key=32 zeros
    exts[0] = 0x00;
    exts[1] = 0x33;
    exts[2] = 0x00;
    exts[3] = 0x24;
    exts[4] = 0x00;
    exts[5] = 0x1d;
    exts[6] = 0x00;
    exts[7] = 0x20;
    // key data is already zeroed

    const result = validateServerHelloSupportedVersions(&exts, 0, 40);
    try std.testing.expectError(HandshakeError.UnsupportedVersion, result);
}

test "RFC 8446 §4.2.1: ServerHello supported_versions with non-TLS-1.3 version returns error" {
    // Build extensions block with supported_versions=0x0303 (TLS 1.2)
    var exts: [6]u8 = [_]u8{0} ** 6;
    exts[0] = 0x00;
    exts[1] = 0x2b;
    exts[2] = 0x00;
    exts[3] = 0x02;
    exts[4] = 0x03;
    exts[5] = 0x03; // TLS 1.2

    const result = validateServerHelloSupportedVersions(&exts, 0, 6);
    try std.testing.expectError(HandshakeError.UnsupportedVersion, result);
}

test "RFC 8446 §4.2.1: ServerHello supported_versions with wrong length returns error" {
    // Build extensions block with supported_versions with 3-byte data (invalid)
    var exts: [7]u8 = [_]u8{0} ** 7;
    exts[0] = 0x00;
    exts[1] = 0x2b;
    exts[2] = 0x00;
    exts[3] = 0x03; // wrong length (should be 2)
    exts[4] = 0x03;
    exts[5] = 0x04;
    exts[6] = 0x00;

    const result = validateServerHelloSupportedVersions(&exts, 0, 7);
    try std.testing.expectError(HandshakeError.UnsupportedVersion, result);
}

// ============================================================================
// PSK Extension Round-Trip Tests (GAP-001/GAP-002)
// ============================================================================

/// Parse pre_shared_key extension from a ServerHello body.
/// Returns the selected PSK identity index if found, null otherwise.
/// This mirrors the parsing logic in handleServerHello for testability.
fn parseServerHelloPskExtension(body: []const u8) !?u16 {
    if (body.len < 2 + 32 + 1) return HandshakeError.UnexpectedMessage;
    var pos: usize = 2 + 32; // skip legacy_version + random
    if (pos >= body.len) return HandshakeError.UnexpectedMessage;
    const sid_len: usize = body[pos];
    pos += 1 + sid_len;
    if (pos + 2 + 1 > body.len) return HandshakeError.UnexpectedMessage;
    pos += 2; // cipher_suite
    pos += 1; // compression
    if (pos + 2 > body.len) return HandshakeError.UnexpectedMessage;
    const exts_len: usize = readU16(body[pos .. pos + 2]);
    pos += 2;
    if (pos + exts_len > body.len) return HandshakeError.UnexpectedMessage;
    const exts_end = pos + exts_len;
    var selected_psk_index: ?u16 = null;
    while (pos + 4 <= exts_end) {
        const etype = readU16(body[pos .. pos + 2]);
        const elen: usize = readU16(body[pos + 2 .. pos + 4]);
        pos += 4;
        if (pos + elen > exts_end) return HandshakeError.UnexpectedMessage;
        if (etype == @intFromEnum(tls13_full.ExtensionType.pre_shared_key)) {
            if (elen != 2) return HandshakeError.UnexpectedMessage;
            selected_psk_index = readU16(body[pos .. pos + 2]);
        }
        pos += elen;
    }
    return selected_psk_index;
}

test "RFC 8446 §4.2.11: ServerHello with PSK extension round-trip" {
    // Build a ServerHello WITH PSK extension, then parse it back
    const allocator = std.testing.allocator;
    var server_random: [32]u8 = undefined;
    std.crypto.random.bytes(&server_random);
    const key_data = &[_]u8{0x42} ** 32;

    const sh = try tls13_full.buildServerHello(
        allocator,
        server_random,
        .TLS_AES_128_GCM_SHA256,
        .x25519,
        key_data,
        null,
        null,
        0, // PSK index 0
    );
    defer allocator.free(sh);

    // Parse and verify PSK extension is present with correct index
    const psk_idx = try parseServerHelloPskExtension(sh);
    try std.testing.expect(psk_idx != null);
    try std.testing.expectEqual(@as(u16, 0), psk_idx.?);
}

test "RFC 8446 §4.2.11: ServerHello without PSK extension returns null" {
    // Build a ServerHello WITHOUT PSK extension, then parse it back
    const allocator = std.testing.allocator;
    var server_random: [32]u8 = undefined;
    std.crypto.random.bytes(&server_random);
    const key_data = &[_]u8{0x42} ** 32;

    const sh = try tls13_full.buildServerHello(
        allocator,
        server_random,
        .TLS_AES_128_GCM_SHA256,
        .x25519,
        key_data,
        null,
        null,
        null, // No PSK
    );
    defer allocator.free(sh);

    // Parse and verify PSK extension is NOT present
    const psk_idx = try parseServerHelloPskExtension(sh);
    try std.testing.expect(psk_idx == null);
}

test "RFC 8446 §4.2.11: PSK early_secret derived from PSK when server selects it" {
    // Verify that deriving early_secret with a PSK produces a different result
    // than with null (non-PSK handshake)
    const psk = "my_test_resumption_key_material";
    const early_with_psk = key_derivation_mod.deriveEarlySecret(.sha256, psk);
    const early_without_psk = key_derivation_mod.deriveEarlySecret(.sha256, null);

    // The two early secrets MUST be different
    try std.testing.expect(!std.mem.eql(u8, early_with_psk.slice(), early_without_psk.slice()));

    // Verify both have the correct length for SHA-256
    try std.testing.expectEqual(@as(usize, 32), early_with_psk.slice().len);
    try std.testing.expectEqual(@as(usize, 32), early_without_psk.slice().len);
}

test "RFC 8446 §4.2.11: Non-PSK handshake early_secret unchanged (regression)" {
    // Regression test: verify that non-PSK handshake still uses null early secret
    const early = key_derivation_mod.deriveEarlySecret(.sha256, null);
    // Known value from RFC 8448 test vectors
    const expected = [_]u8{
        0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
        0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
        0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
        0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a,
    };
    try std.testing.expectEqualSlices(u8, &expected, early.slice());
}

test "RFC 8446 §4.2.11: ServerHello PSK index non-zero round-trip" {
    // Verify PSK index 5 round-trips correctly through build+parse
    const allocator = std.testing.allocator;
    var server_random: [32]u8 = undefined;
    std.crypto.random.bytes(&server_random);
    const key_data = &[_]u8{0x42} ** 32;

    const sh = try tls13_full.buildServerHello(
        allocator,
        server_random,
        .TLS_AES_128_GCM_SHA256,
        .x25519,
        key_data,
        null,
        null,
        5, // PSK index 5
    );
    defer allocator.free(sh);

    const psk_idx = try parseServerHelloPskExtension(sh);
    try std.testing.expect(psk_idx != null);
    try std.testing.expectEqual(@as(u16, 5), psk_idx.?);
}

// ============================================================================
// HRR (HelloRetryRequest) Tests (QUAL-099)
// ============================================================================

test "QUAL-099: Client handles HelloRetryRequest and generates ClientHello2" {
    // Exercises the full HRR code path through the Context API:
    //   1. Client sends ClientHello1 (with x25519)
    //   2. Server sends HRR requesting x25519 (with cookie)
    //   3. Client handles HRR: updates transcript, generates ClientHello2
    //   4. Verify: hrr_received flag, new outbound data, key regeneration
    const allocator = std.testing.allocator;

    const tp_bytes: []const u8 = &[_]u8{};

    var config = Config{
        .allocator = allocator,
        .role = .Client,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{tls13_full.NamedGroup.x25519},
        .supported_signature_schemes = &.{tls13_full.SignatureScheme.ed25519},
        .quic_transport_parameters = tp_bytes,
        .allow_insecure = true,
    };
    _ = &config;

    var ctx = try Context.init(config, .{});
    defer ctx.deinit();

    try ctx.startClientHandshake();

    const initial_buf = ctx.streams.buffer(.Initial);
    try std.testing.expect(initial_buf.outbound.items.len > 0);

    const original_pub = ctx.client_pub.?;

    // Build a HelloRetryRequest asking for x25519 with a cookie
    const cookie_data = "test_cookie_for_hrr_binding";
    const hrr_body = try tls13_full.buildHelloRetryRequest(
        allocator,
        .x25519,
        cookie_data,
        null,
    );
    defer allocator.free(hrr_body);

    // Verify the HRR body contains the special random value
    try std.testing.expect(hrr_body.len >= 34);
    var hrr_random: [32]u8 = undefined;
    @memcpy(&hrr_random, hrr_body[2..34]);
    try std.testing.expect(tls13_full.isHelloRetryRequest(hrr_random));

    // Frame the HRR as a handshake message and feed it to the client
    const hrr_msg = try encodeHandshake(allocator, .server_hello, hrr_body);
    defer allocator.free(hrr_msg);

    initial_buf.outbound.clearRetainingCapacity();

    try ctx.processCrypto(.Initial, hrr_msg);

    // Verify the client handled HRR correctly
    try std.testing.expect(ctx.hrr_received);
    try std.testing.expect(initial_buf.outbound.items.len > 0);
    // First byte of outbound should be 0x01 (ClientHello message type)
    try std.testing.expectEqual(@as(u8, 0x01), initial_buf.outbound.items[0]);

    // Client must regenerate its key share
    const new_pub = ctx.client_pub.?;
    try std.testing.expect(!std.mem.eql(u8, &original_pub, &new_pub));
}

test "QUAL-099: Client rejects duplicate HelloRetryRequest" {
    // RFC 8446 §4.1.4: A client which receives a second HRR in the same
    // connection MUST abort the handshake with an "unexpected_message" alert.
    const allocator = std.testing.allocator;

    const tp_bytes: []const u8 = &[_]u8{};

    var config = Config{
        .allocator = allocator,
        .role = .Client,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{tls13_full.NamedGroup.x25519},
        .supported_signature_schemes = &.{tls13_full.SignatureScheme.ed25519},
        .quic_transport_parameters = tp_bytes,
        .allow_insecure = true,
    };
    _ = &config;

    var ctx = try Context.init(config, .{});
    defer ctx.deinit();

    try ctx.startClientHandshake();

    // First HRR should succeed
    const hrr_body = try tls13_full.buildHelloRetryRequest(allocator, .x25519, "cookie1", null);
    defer allocator.free(hrr_body);

    const hrr_msg = try encodeHandshake(allocator, .server_hello, hrr_body);
    defer allocator.free(hrr_msg);

    try ctx.processCrypto(.Initial, hrr_msg);
    try std.testing.expect(ctx.hrr_received);

    // Second HRR must be rejected
    const hrr_body2 = try tls13_full.buildHelloRetryRequest(allocator, .x25519, "cookie2", null);
    defer allocator.free(hrr_body2);

    const hrr_msg2 = try encodeHandshake(allocator, .server_hello, hrr_body2);
    defer allocator.free(hrr_msg2);

    const result = ctx.processCrypto(.Initial, hrr_msg2);
    try std.testing.expectError(HandshakeError.UnexpectedMessage, result);
}

test "QUAL-099: HRR transcript manipulation preserves integrity" {
    // Verifies the transcript hash changes after HRR processing per
    // RFC 8446 §4.4.1 (message_hash construct).
    const allocator = std.testing.allocator;

    const tp_bytes: []const u8 = &[_]u8{};

    var config = Config{
        .allocator = allocator,
        .role = .Client,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{tls13_full.NamedGroup.x25519},
        .supported_signature_schemes = &.{tls13_full.SignatureScheme.ed25519},
        .quic_transport_parameters = tp_bytes,
        .allow_insecure = true,
    };
    _ = &config;

    var ctx = try Context.init(config, .{});
    defer ctx.deinit();

    try ctx.startClientHandshake();

    // Snapshot transcript hash before HRR
    const hash_before = ctx.transcripts.handshake.finalize(.sha256);

    const hrr_body = try tls13_full.buildHelloRetryRequest(allocator, .x25519, "test_cookie", null);
    defer allocator.free(hrr_body);

    const hrr_msg = try encodeHandshake(allocator, .server_hello, hrr_body);
    defer allocator.free(hrr_msg);

    try ctx.processCrypto(.Initial, hrr_msg);

    // Transcript hash must differ after HRR processing
    const hash_after = ctx.transcripts.handshake.finalize(.sha256);
    try std.testing.expect(!std.mem.eql(u8, hash_before.slice(), hash_after.slice()));

    // Hash must not be all zeros
    var all_zero = true;
    for (hash_after.slice()) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}
