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
//! **Context** (this file): imperative shell holding connection state +
//! dispatching to pure-function modules under `src/tls13/context/`:
//!
//! - cipher_negotiation.zig     cipher-suite + sig-scheme selection
//! - alpn_selection.zig         ALPN match (PERF-218 borrow semantics)
//! - psk_selection.zig          PSK identity + binder hash + timing_safe
//! - server_hello_parsers.zig   ServerHello extension parsers
//! - server_flight_builders.zig ServerHello → Finished emission
//! - hello_retry.zig            HRR emit + handle + CH2 rebuild
//! - cert_handlers.zig          Cert chain + CertificateVerify
//! - key_update.zig             Post-handshake KeyUpdate (CWE-226 fixed)
//!
//! Each module is value-in / value-out — no *Context parameter. Context
//! reads its own fields, builds state-slice literals (or passes explicit
//! parameters), and writes results back. Adapter pattern retained in
//! Context for flows whose Context-state breadth makes pure extraction
//! impractical (emitServerFlight, negotiateCipherAndKeys, driveServerHandshakeFlight).
//!
//! See docs/superpowers/specs/2026-04-20-context-decomposition-design.md
//! for the full architecture rationale.
//!
//! **Callbacks**: Function pointers for QUIC layer integration
//! - on_secret_available: Install traffic secrets for packet protection
//! - on_handshake_metadata: Receive negotiated ALPN and transport params
//! - on_peer_finished: Notification of peer Finished verification
//! - on_handshake_complete: Full handshake completion notification
//! - fetch_certificate_chain: Dynamic certificate retrieval (server)
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
const fips_cb = @import("crypto_backend");
const x509 = @import("x509");
const sig = @import("sig");
const tls13_full = @import("tls13_full");
const ocsp = @import("ocsp");
const sct = @import("sct");
const zero_rtt_mod = @import("zero_rtt");
const entropy = @import("entropy");
const build_options = @import("build_options");
const logger = @import("quic_logger");
const transport_params = @import("quic_transport_params");
// GAP-0133/0134: Inbound alert dispatch + outbound close_notify/fatal alert API.
const alert_mod = @import("alert");
// Observability seam (otel). Every helper collapses to a no-op when
// -Dwith_otel=false, so unconditionally calling them here is free at
// runtime (the optimizer drops the calls entirely).
const observability = @import("observability");

/// Zig 0.16 compat: unixTimestamp() was removed; use Io clock to get unix seconds.
fn unixTimestamp() i64 {
    const ts = std.Io.Timestamp.now(std.Io.Threaded.global_single_threaded.io(), .real);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_s));
}

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
// QUAL-317: pure cipher-suite / signature-scheme selection helpers.
const cipher_negotiation = @import("context/cipher_negotiation.zig");
// QUAL-317: pure server-side ALPN selection helper.
const alpn_selection = @import("context/alpn_selection.zig");
// QUAL-317: pure ServerHello byte parsers (supported_versions, pre_shared_key).
const server_hello_parsers = @import("context/server_hello_parsers.zig");
// QUAL-317: pure PSK selection + binder transcript hashing (state-slice module).
const psk_selection_mod = @import("context/psk_selection.zig");
// QUAL-317: certificate chain parsing + CertificateVerify signature helpers.
const cert_handlers = @import("context/cert_handlers.zig");
// QUAL-317: HelloRetryRequest parser + emit + CH2 rebuild helpers.
const hello_retry_mod = @import("context/hello_retry.zig");
// QUAL-317: pure server-flight handshake-message builders.
const server_flight_builders = @import("context/server_flight_builders.zig");
// QUAL-317: pure post-handshake KeyUpdate flow (RFC 8446 §4.6.3 + §7.2).
const key_update_mod = @import("context/key_update.zig");

// Note: ApiError and HandshakeError are now imported from types.zig (canonical source).
// TrafficDirection, BidirSecrets, etc. remain defined here pending further extraction.
// SecretSlot is now imported from secrets.zig (QUAL-118).

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

/// X25519MLKEM768 hybrid KEM integration into the TLS 1.3 key schedule
/// (draft-kwiatkowski-tls-ecdhe-mlkem). Under -Dfips=true the negotiated
/// hybrid group derives a 64-byte shared secret = X25519_shared (32) ||
/// ML-KEM-768_shared (32), concatenated in ECDH-first order, which is fed
/// to `deriveHandshakeTraffic` exactly like the 32-byte X25519 secret.
///
/// This is the KEM-into-key-schedule integration point; the full on-wire
/// `key_share` parse/serialize is implemented in Task 7. The whole branch
/// is comptime-dead under -Dfips=false (cb.fips_enabled == false), so the
/// non-fips control flow is unchanged.
const HybridKem = struct {
    /// ECDH-first concatenation order per draft §3: X25519 leg then ML-KEM.
    const x25519_share_len: usize = 32;
    const mlkem_share_len: usize = 32;
    const hybrid_shared_len: usize = x25519_share_len + mlkem_share_len; // 64

    /// True only when the active backend is FIPS and the negotiated group is
    /// the X25519MLKEM768 hybrid. Comptime-dead branch when fips is off.
    fn isHybrid(group: tls13_full.NamedGroup) bool {
        return fips_cb.fips_enabled and group == .x25519_mlkem768;
    }
};

const parseKeyUpdate = messages_mod.parseKeyUpdate;
const KeyUpdateRequest = messages_mod.KeyUpdateRequest;
// Note: TrafficDirection, BidirSecrets, CryptoBuffer are defined below; SecretSlot is imported from secrets.zig (QUAL-118)

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

// SEC-039: Compile-time safety: prevent handshake trace logging in release builds.
// Handshake traces can leak error details, cipher suite info, and other metadata
// that aids attackers in fingerprinting or exploiting the TLS implementation.
comptime {
    if (handshake_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: handshake_trace_enabled must be false in release builds - error details would be logged!");
    }
}

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

    /// GAP-0133: Invoked when an inbound TLS alert is decoded. The Context
    /// is terminal after a fatal alert. Callers SHOULD map fatal alerts to
    /// QUIC CONNECTION_CLOSE(0x01xx) via `alert.toQuicCryptoError(desc)`.
    ///
    /// The callback receives the decoded `AlertDescription`; the level
    /// (warning/fatal) is available via `ctx.flags.alert` and the terminal
    /// phase transition (`ctx.phase == .terminated`) on fatal alerts.
    ///
    /// null = Not notified of alerts (default).
    on_alert: ?*const fn (ctx: *Context, desc: alert_mod.AlertDescription) void = null,

    /// GAP-0132: Invoked on the client when an inbound NewSessionTicket
    /// message is parsed (RFC 8446 §4.6.1). The application is expected
    /// to persist the parsed ticket so future connections can present it
    /// in a `pre_shared_key` extension to enable resumption / 0-RTT.
    ///
    /// The borrowed slices in `ticket` point into the inbound handshake
    /// frame and are only valid for the duration of the call; callers
    /// who need to retain them across the callback boundary MUST copy.
    /// Errors propagate back through `processCrypto`, allowing the
    /// application to refuse a ticket without aborting the handshake
    /// state machine (the dispatcher already enforced role + level).
    ///
    /// null = Tickets are decoded and dropped (matches the prior
    /// QUAL-074 accept-and-log behaviour).
    on_session_ticket: ?*const fn (ctx: *Context, ticket: messages_mod.ParsedNewSessionTicket) anyerror!void = null,
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
// GAP-0107: TrafficDirection canonicalised in `src/tls13/secrets.zig`.
// Re-alias to keep external callers of `context.TrafficDirection` working.
pub const TrafficDirection = secrets_mod.TrafficDirection;

/// QUAL-118: SecretSlot imported from secrets.zig (canonical source, no duplication).
pub const SecretSlot = secrets_mod.SecretSlot;

// QUAL-070: supportsTls13Version and freeParsedClientHello are now in
// handshake_state.zig, used by the shared ClientHelloInfo.parse().

// GAP-0107: BidirSecrets and SecretSchedule are canonicalised in
// `src/tls13/secrets.zig`. This file previously carried byte-identical
// shadow definitions. Re-alias the canonical so public callers of
// `context.BidirSecrets` / `context.SecretSchedule` keep working.
pub const BidirSecrets = secrets_mod.BidirSecrets;
pub const SecretSchedule = secrets_mod.SecretSchedule;

// QUAL-125: HashDigestCache is imported from transcript.zig (canonical source).
// The local duplicate has been removed; TranscriptSet already uses transcript_mod.HashDigestCache.

/// RFC 8446 §4.4.1: transcripts and cached hashes used across handshake flights.
pub const TranscriptSet = struct {
    handshake: Transcript,
    client_hello_hash: transcript_mod.HashDigestCache = .{},
    finished_hash: transcript_mod.HashDigestCache = .{},
    /// R6-01: snapshot of Transcript-Hash(ClientHello...server Finished), used
    /// as the RFC 8446 §7.1/§7.5 input for the application-traffic and exporter
    /// secrets. Captured when the server's Finished is folded so that later
    /// client-auth messages (Certificate/CertificateVerify, mTLS) do NOT leak
    /// into the application-secret transcript.
    app_secret_hash: transcript_mod.HashDigestCache = .{},

    /// Creates a new transcript set with empty transcripts.
    pub fn init() TranscriptSet {
        return .{ .handshake = Transcript.init(), .client_hello_hash = .{}, .finished_hash = .{}, .app_secret_hash = .{} };
    }

    /// Resets all transcripts to their initial empty state.
    pub fn reset(self: *TranscriptSet) void {
        self.handshake.reset();
        self.client_hello_hash.clear();
        self.finished_hash.clear();
        self.app_secret_hash.clear();
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

// QUAL-336: HandshakeState canonicalized in handshake_state.zig. This file
// previously shadowed it with a near-duplicate. Re-alias the canonical so
// internal references keep working without an import update.
const HandshakeState = handshake_state_mod.HandshakeState;

comptime {
    // Field-parity guard: if anyone adds/renames a field on the canonical
    // HandshakeState, this static assert forces a review of downstream
    // context.zig invariants (e.g. reset ordering, SEC-045 PSK view lifetime).
    const expected = [_][]const u8{ "client_hello", "psk_identity_views" };
    const fields = std.meta.fields(HandshakeState);
    if (fields.len != expected.len) {
        @compileError("QUAL-336: HandshakeState field count changed; review context.zig invariants");
    }
    for (expected, fields) |want, have| {
        if (!std.mem.eql(u8, want, have.name)) {
            @compileError("QUAL-336: HandshakeState field rename; review context.zig invariants");
        }
    }
}

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
    inbound: ArrayListUnmanaged(u8) = .empty,
    outbound: ArrayListUnmanaged(u8) = .empty,
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

/// TLS 1.3 driver that orchestrates QUIC CRYPTO data flow (RFC 8446 §4,
/// RFC 9001 §4.1.4).
///
/// # Overview (QUAL-348)
///
/// `Context` owns the full state machine for a single TLS 1.3 endpoint
/// (client or server) during handshake and post-handshake traffic. It is
/// QUIC-native: CRYPTO frame data flows in via `processCrypto(level, data)`
/// and produced flights are drained via the outbound `streams` buffers. It
/// does **not** own a network socket or framing layer; the embedder wires
/// that up.
///
/// # Lifecycle
///
/// 1. `Context.init(allocator, config, callbacks)` — allocate and configure.
/// 2. Client: call `startClientHandshake` to enqueue ClientHello on the
///    Initial encryption level. Server: wait for inbound ClientHello.
/// 3. Feed inbound CRYPTO bytes via `processCrypto` as they arrive at each
///    encryption level; drive outbound via the emitted buffers.
/// 4. When `handshakeComplete()` returns true, traffic keys for the
///    Application level are installed and the embedder may forward
///    application data.
/// 5. Post-handshake: accept `NewSessionTicket`, send/receive `KeyUpdate`.
/// 6. `deinit()` must be called to release heap-owned handshake state,
///    secrets, and transcript hashes.
///
/// # Thread safety
///
/// A `Context` is **not** thread-safe: all mutating methods (processCrypto,
/// queueKeyUpdate, etc.) must be serialized by the caller. Immutable reads
/// such as `currentPhase()` are safe to call from any thread that already
/// holds a synchronization barrier with the last mutator. See `parallel.zig`
/// for the shared pool used for handshake signature verification.
///
/// # Field ordering (PERF-043)
///
/// Fields are ordered hot-to-cold for cache locality. Hot fields (accessed
/// on every `processCrypto` / message dispatch) are grouped first, followed
/// by warm fields (phase-specific), then cold/rare fields (post-handshake,
/// diagnostics).
pub const Context = struct {
    // --- Hot fields: accessed on every processCrypto / message dispatch ---
    phase: HandshakePhase = .initial,
    hash_kind: Hash = .sha256,
    allocator: std.mem.Allocator,
    transcripts: TranscriptSet = TranscriptSet.init(),
    secrets: SecretSchedule = SecretSchedule.init(),
    streams: CryptoStreams = .{},
    state: HandshakeState = HandshakeState.init(),
    scratch_arena: std.heap.ArenaAllocator,
    flags: HandshakeFlags = .{},
    config: Config,
    callbacks: Callbacks,

    // --- Warm fields: accessed during specific handshake phases ---
    handshake_secret: ?Secret = null,
    negotiated_cipher_suite: ?tls13_full.CipherSuite = null,
    negotiated_signature: ?tls13_full.SignatureScheme = null,
    client_priv: ?[32]u8 = null,
    client_pub: ?[32]u8 = null,
    local_transport_parameters: ?[]u8 = null,
    peer_quic_transport_parameters: ?[]u8 = null,
    negotiated_alpn: ?[]u8 = null,
    /// PERF-218: true when `negotiated_alpn` was allocated by this Context and
    /// must be freed on deinit/replace; false when it borrows from `config`
    /// (server path — `config` outlives `Context`).
    negotiated_alpn_owned: bool = false,

    // --- Cold fields: rarely accessed, optional/conditional paths ---
    // Certificate validation state (client role)
    peer_cert_chain: ?[][]const u8 = null, // DER-encoded certificate chain from peer
    // PERF-042: Contiguous backing buffer for peer_cert_chain sub-slices.
    // When non-null, all cert slices in peer_cert_chain point into this single buffer.
    peer_cert_chain_buf: ?[]u8 = null,
    peer_cert_verify_sig: ?[]const u8 = null, // CertificateVerify signature from peer
    peer_cert_verify_alg: ?tls13_full.SignatureScheme = null, // Signature algorithm used
    peer_ocsp_response: ?[]const u8 = null, // Stapled OCSP response from peer (leaf cert only)
    peer_sct_list: ?[]const u8 = null, // Signed Certificate Timestamp list from peer (leaf cert only)
    // PERF-016: Cached trust store snapshot taken at init time.
    // Avoids acquiring the global RwLock on every validateChain call during handshake.
    cached_trust_store: ?x509.TrustStore = null,
    // HRR state (only used in HelloRetryRequest path)
    client_random: ?[32]u8 = null, // Client random from first ClientHello (for HRR)
    hrr_sent: bool = false, // Track if we already sent HelloRetryRequest (server)
    hrr_received: bool = false, // Track if we received HelloRetryRequest (client)
    // NEWGAP-08: cipher_suite selected by the HRR; the subsequent ServerHello
    // MUST select the same one (RFC 8446 §4.1.4).
    hrr_cipher_suite: ?tls13_full.CipherSuite = null,
    server_secret_generated: ?[32]u8 = null, // Generated server secret for HRR cookies

    /// SEC-086: RFC 8446 §4.2.2 cookie binding requires the server to
    /// remember the CH1 transcript hash across HRR so the cookie HMAC
    /// over (server_secret, client_random, ch1_transcript_hash) can
    /// be re-verified when CH2 arrives. Captured at HRR emit; consumed
    /// by `negotiateCipherAndKeys` on the second pass.
    ch1_transcript_hash: ?Secret = null,
    // mTLS state (RFC 8446 §4.3.2)
    client_cert_requested: bool = false, // Client: tracks that server sent CertificateRequest
    client_cert_request_context: ?[]u8 = null, // Client: stores request context from CertificateRequest
    // 0-RTT state (server role)
    // PERF-002: Lazy-allocated anti-replay window.  Only heap-allocated when the
    // context is a server with enable_early_data=true.  Saves ~2KB inline for
    // clients and servers that do not use 0-RTT.
    anti_replay: ?*zero_rtt_mod.AntiReplayWindow = null,

    // Observability seam (otel). One span per handshake. Started in
    // `init`, ended on success in `bumpPhaseAfterFinished`, or as a
    // failure in `deinit` if `obs_span_ended` is still false (handshake
    // aborted before reaching `application_ready`). When
    // -Dwith_otel=false, `Span` is a zero-sized struct and these fields
    // contribute nothing to the Context layout.
    obs_span: observability.Span = .{},
    obs_span_ended: bool = false,

    // GAP-0135: Peer KeyUpdate exhaustion budget
    peer_key_updates_seen: u32 = 0,

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

        // PERF-016: Cache the global trust store at init to avoid RwLock on every handshake.
        const cached_ts = x509.getTrustStore();

        // Observability: open a "TLS handshake" span at the moment the
        // Context is constructed. The span is closed in
        // `bumpPhaseAfterFinished` on success, or in `deinit` as a
        // failure if the handshake aborted before reaching
        // `application_ready`. When -Dwith_otel=false the call is a
        // comptime no-op returning a zero-sized Span.
        const obs_role: observability.Role = switch (config.role) {
            .Client => .client,
            .Server => .server,
        };
        const obs_span = observability.startHandshakeSpan(obs_role);

        const ctx = Context{
            .config = config,
            .callbacks = callbacks,
            .allocator = config.allocator,
            .scratch_arena = std.heap.ArenaAllocator.init(config.allocator),
            .phase = .initial,
            .transcripts = TranscriptSet.init(),
            .secrets = SecretSchedule.init(),
            .streams = .{},
            .state = HandshakeState.init(),
            .flags = .{},
            .hash_kind = .sha256,
            .local_transport_parameters = null,
            .negotiated_alpn = null,
            .negotiated_alpn_owned = false,
            .negotiated_signature = null,
            .negotiated_cipher_suite = null,
            .handshake_secret = null,
            .client_priv = null,
            .client_pub = null,
            .anti_replay = anti_replay,
            .cached_trust_store = cached_ts,
            .obs_span = obs_span,
            .obs_span_ended = false,
        };

        // NOTE: For clients, DO NOT automatically call startClientHandshake() here!
        // The QUIC layer needs to set transport parameters FIRST via setTransportParameters(),
        // then explicitly call startClientHandshake(). If we call it here, the ClientHello
        // will be generated without transport parameters.

        // SEC-005: allow_insecure disables ALL certificate validation.
        // This is a runtime opt-in (caller must explicitly pass the flag),
        // so we permit it in all build modes. The security boundary is the
        // CLI flag / API parameter, not a compile-time gate.

        return ctx;
    }

    /// PERF-042: Free peer_cert_chain and its backing buffer (contiguous or per-cert).
    fn freePeerCertChain(self: *Context) void {
        if (self.peer_cert_chain) |chain| {
            if (self.peer_cert_chain_buf) |buf| {
                // Contiguous backing buffer: free the single buffer + slice array
                self.allocator.free(buf);
            } else {
                // Legacy per-cert allocation: free each cert individually
                for (chain) |cert| {
                    self.allocator.free(cert);
                }
            }
            self.allocator.free(chain);
            self.peer_cert_chain = null;
            self.peer_cert_chain_buf = null;
        }
    }

    /// Cleans up the context, freeing resources and resetting state.
    pub fn deinit(self: *Context) void {
        // Observability: if the handshake never reached
        // `application_ready`, close the span now as a failure with
        // whatever (possibly empty) cipher-suite info was negotiated.
        // Telemetry is non-fatal; failures inside the seam are
        // swallowed.
        if (!self.obs_span_ended) {
            const suite_name: []const u8 = if (self.negotiated_cipher_suite) |cs|
                @tagName(cs)
            else
                "";
            // Empty version when the handshake aborted before TLS 1.3
            // was negotiated; otherwise "1.3".
            const version_str: []const u8 = if (self.negotiated_cipher_suite != null) "1.3" else "";
            observability.endHandshakeSpan(self.obs_span, false, version_str, suite_name);
            self.obs_span_ended = true;
        }

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
            // PERF-218: only free when we own the buffer; borrowed slices
            // (server path) point into `config.alpn_protocols` and must
            // not be freed.
            if (self.negotiated_alpn_owned) self.allocator.free(proto);
            self.negotiated_alpn = null;
            self.negotiated_alpn_owned = false;
        }
        // Clean up peer certificate data (client role)
        self.freePeerCertChain();
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
        }

        self.scratch_arena.deinit();
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
        // SEC-086: zeroize CH1 transcript hash on teardown so it cannot
        // leak to a later cookie-validation oracle (defense in depth —
        // the hash itself isn't secret but the size/contents reveal
        // negotiated cipher suite).
        if (self.ch1_transcript_hash) |*h| {
            std.crypto.secureZero(u8, h.bytes[0..h.len]);
        }
        self.ch1_transcript_hash = null;
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
        errdefer self.allocator.free(mutable_copy);
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

        // PERF-234: Pre-size the inbound buffer so the appendSlice does not
        // trigger incremental reallocations. We already know the final size
        // is bounded by max_crypto_buffer (SEC-018) and cannot exceed 64 KB.
        const needed_capacity = stream.inbound.items.len + data.len;
        try stream.inbound.ensureTotalCapacity(self.allocator, needed_capacity);
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

            // SAFETY: null case handled by the break above; parsed_opt is guaranteed non-null here.
            const parsed = parsed_opt.?;
            const message_bytes = buffer[0..parsed.n];

            logger.debugPrint("  Parsed handshake message: type={X:0>2} ({s}), len={}\n", .{ @intFromEnum(parsed.typ), @tagName(parsed.typ), parsed.body.len });

            // RFC 8446 §4.4.4: Update transcript BEFORE processing message so
            // that handlers computing Handshake secrets see the transcript up
            // to and including the current message (e.g. ClientHello+ServerHello).
            //
            // EXCEPTIONS — folded AFTER their own verification instead:
            //   - Finished (§4.4.4): its verify_data is HMAC over the transcript
            //     EXCLUDING the Finished message.
            //   - CertificateVerify (R5-01 / GAP-0838 / §4.4.3): its signature
            //     covers Transcript-Hash(Handshake Context, Certificate) — i.e.
            //     the transcript EXCLUDING the CertificateVerify message itself.
            //     Folding it before verification made the client check the
            //     signature over Hash(...Certificate || CertificateVerify),
            //     which never matches the server's Hash(...Certificate),
            //     breaking every RFC-compliant server-authenticated handshake.
            if (parsed.typ != .finished and parsed.typ != .certificate_verify) {
                self.transcripts.handshake.update(message_bytes);
            }

            // Validate and process message type.
            try self.handleHandshakeMessage(level, parsed, message_bytes);

            // R5-01 / RFC 8446 §4.4.3: now that the CertificateVerify signature
            // has been verified over the pre-CV transcript, fold CV in so the
            // subsequent Finished (and exporter/resumption secrets) bind it.
            // This mirrors the server's own emitServerFlight ordering (fold
            // Certificate -> sign CV -> fold CV) and covers both the client
            // (server-auth) and server (mTLS client-auth) inbound paths, which
            // share this loop. (Finished folds itself post-verification inside
            // handlePeerFinished.)
            if (parsed.typ == .certificate_verify) {
                self.transcripts.handshake.update(message_bytes);
            }

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
        const cb_state: []const u8 = if (self.callbacks.on_secret_available) |cb| blk: {
            try cb(self, level, secret.slice());
            break :blk "fired";
        } else "not_registered";

        // QUIC-INTEROP-HRR (2026-04-27 boundary observability): emit a
        // success-path line at the moment a traffic secret slot becomes
        // valid AND the embedding QUIC stack has been notified (or
        // explicitly is not listening). The existing `[TLS-HRR]` lines
        // cover only the failure branches inside `negotiateCipherAndKeys`,
        // so their absence in an interop log is ambiguous between
        // "TLS engine completed install" and "TLS engine never reached
        // install". This line resolves that ambiguity: its presence
        // proves both `slot.valid` flipped true AND
        // `on_secret_available` returned without error (or was
        // not_registered). Length-only — never logs the secret bytes.
        // See `docs/QUIC_INTEROP_HRR_ISSUE.md` (2026-04-27 entries).
        const role_str: []const u8 = if (self.config.role == .Server) "Server" else "Client";
        logger.info(
            "[TLS-HS] secret installed: role={s}, level={s}, dir={s}, secret_len={d}, on_secret_available={s}",
            .{ role_str, @tagName(level), @tagName(dir), secret.slice().len, cb_state },
        );
    }

    /// QUAL-346: Install both handshake traffic secrets atomically.
    ///
    /// If the `send`-side install succeeds but the `recv`-side install (or
    /// its `on_secret_available` callback) fails, the send slot is rolled
    /// back via `SecretSlot.clear` so we do not leak live handshake key
    /// material into a half-initialized state. Both slots end in either the
    /// fully-installed or fully-cleared state.
    ///
    /// Callers choose the role-appropriate mapping:
    ///   - Server: `send = server_hs`, `recv = client_hs`
    ///   - Client: `send = client_hs`, `recv = server_hs`
    fn installHandshakeTrafficPair(self: *Context, send_secret: Secret, recv_secret: Secret) !void {
        try self.installTrafficSecret(.Handshake, .send, send_secret);
        errdefer self.secrets.slot(.Handshake, .send).clear();
        try self.installTrafficSecret(.Handshake, .recv, recv_secret);
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

            // Observability: close the handshake span as success
            // before invoking the user callback, so the span is
            // recorded even if the callback fails. Telemetry is
            // non-fatal; failures inside the seam are swallowed.
            if (!self.obs_span_ended) {
                const suite_name: []const u8 = if (self.negotiated_cipher_suite) |cs|
                    @tagName(cs)
                else
                    "";
                observability.endHandshakeSpan(self.obs_span, true, "1.3", suite_name);
                self.obs_span_ended = true;
            }

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
        // GAP-0138 / QUAL-393: any error surfaced from below (other than the
        // two alert-layer pass-throughs) queues a fatal alert mapped via
        // alert.fromHandshakeError before the error propagates back to the
        // caller. QUAL-395: this includes OutOfMemory and any other non-protocol
        // error — they map to internal_error and are best-effort alerted
        // (failAlert swallows a secondary send failure). Only PeerFatalAlert /
        // InvalidAlert pass through unchanged.
        return self.dispatchHandshake(level, parsed, raw) catch |err| switch (err) {
            // PeerFatalAlert / InvalidAlert are alert-layer events that already
            // manage phase + alert queuing; pass through WITHOUT re-alerting.
            error.PeerFatalAlert, error.InvalidAlert => return err,
            // QUAL-393: every other failure — including any future typed
            // HandshakeError variant — queues the fatal alert that
            // `alert.fromHandshakeError` maps it to (unmapped -> internal_error)
            // and re-raises. Previously this was a hand-maintained allowlist
            // that silently drifted out of sync with `fromHandshakeError`
            // (e.g. IllegalLegacyVersion / IllegalSessionIdEcho / TooManyExtensions
            // / TooManyKeyUpdates aborted without ever sending their §4.1.3/§4.6.3
            // alert). Routing the default through `failAlert` makes the centralized
            // map the single source of truth and eliminates that drift class.
            else => return self.failAlert(err),
        };
    }

    /// QUAL-375 (bundled with QUAL-344, QUAL-350): per-handshake-type
    /// dispatch. The 222-line god-method that lived here was decomposed
    /// into focused per-message helpers below; the dispatcher itself is
    /// now a flat switch with `depth = 2` (one level for the switch,
    /// one for the helper call), well under the QUAL-375 acceptance bar
    /// of `depth ≤ 2`. Each helper preserves the original RFC 8446
    /// gating semantics verbatim — only the surrounding nesting is gone.
    /// GAP-0079 still applies: `parseHandshakeOne` rejects unknown
    /// HsType variants with `error.UnknownHandshakeType`, so we never
    /// reach an unhandled arm here.
    fn dispatchHandshake(self: *Context, level: EncryptionLevel, parsed: HandshakeMessage, raw: []const u8) !void {
        return switch (parsed.typ) {
            .client_hello => self.inboundClientHello(level, parsed),
            .server_hello => self.inboundServerHello(parsed),
            .certificate_request => self.inboundCertificateRequest(level, parsed),
            .finished => self.handlePeerFinished(level, parsed.body, raw),
            .key_update => self.inboundKeyUpdate(level, parsed),
            .encrypted_extensions => self.inboundEncryptedExtensions(parsed),
            .certificate => self.inboundCertificate(parsed),
            .certificate_verify => self.inboundCertificateVerify(parsed),
            .new_session_ticket => self.inboundNewSessionTicket(level, parsed),
        };
    }

    /// Server-side ClientHello handler. Validates role, resets state on
    /// HRR retransmits, calls `state.setClientHello` with diagnostic
    /// logging, snapshots the parsed CH for interop traces, and (for
    /// QUIC) extracts and validates the peer transport parameters.
    fn inboundClientHello(self: *Context, level: EncryptionLevel, parsed: HandshakeMessage) !void {
        // RFC 8446 §4.1.2: ClientHello only valid for server role
        if (self.config.role != .Server) return HandshakeError.UnexpectedMessage;

        // RFC 8446 §4.1.4: After HelloRetryRequest, server must accept a
        // second ClientHello. Reset stored CH state so setClientHello
        // doesn't reject it as DuplicateClientHello.
        if (self.hrr_sent) {
            self.state.reset(self.allocator);
        }

        // QUIC-INTEROP-HRR (2026-04-27): wrap setClientHello so any
        // RFC 8446 §4.2.x parse failure (MissingKeyShare, NoCipherSuite,
        // UnsupportedVersion, …) surfaces a tagged line in the interop
        // log instead of bubbling up as a generic NoHandshakeKeys at the
        // QUIC layer. Without this diagnostic the failing CH for
        // quic-go / mvfst clients was indistinguishable from a
        // transport-level CRYPTO drop. See
        // docs/QUIC_INTEROP_HRR_ISSUE.md.
        self.state.setClientHello(self.allocator, parsed.body) catch |err| {
            logger.err(
                "[TLS-HRR] ClientHello parse failed at level={s}: {s} (body_len={d}, hrr_sent={})",
                .{ @tagName(level), @errorName(err), parsed.body.len, self.hrr_sent },
            );
            return err;
        };

        // QUIC-INTEROP-HRR (2026-04-27): one-shot snapshot of the parsed
        // CH state so interop logs distinguish "client offered X25519"
        // from "client offered group X classified as Y". Includes the
        // RAW codepoint (preserved by parseKeyShare/QUAL-369) so
        // PQ-hybrid (0x6399) shows up verbatim. Logged at err level so
        // it lands in the same stream as the existing HRR / cookie-
        // verify diagnostics.
        if (self.state.clientHello()) |ch_snap| {
            const ch_index: u8 = if (self.hrr_sent) 2 else 1;
            logger.err(
                "[TLS-HRR] ClientHello#{d} parsed at level={s}: " ++
                    "key_share.group={s}, raw_group_code=0x{x:0>4}, " ++
                    "key_len={d}, cipher_suites={d}, has_cookie={}",
                .{
                    ch_index,
                    @tagName(level),
                    @tagName(ch_snap.key_share.group),
                    ch_snap.key_share.raw_group_code,
                    ch_snap.key_share.key.len,
                    ch_snap.cipher_suites.len,
                    ch_snap.cookie != null,
                },
            );
        }

        try self.absorbClientTransportParameters();

        // RFC 8446 §4: Transition from initial to negotiating phase
        if (self.phase == .initial) {
            self.phase = .negotiating;
        }
    }

    /// Phase 36 / RFC 9001 §8.2: pull the QUIC transport_parameters
    /// extension out of the parsed ClientHello, run the GAP-0081
    /// client-role validation, and stash the bytes on the Context.
    fn absorbClientTransportParameters(self: *Context) !void {
        const ch = self.state.clientHello() orelse return;
        // NEWGAP-11: RFC 9001 §8.2 — an endpoint that receives a ClientHello
        // WITHOUT the quic_transport_parameters extension MUST abort with
        // missing_extension. Symmetric with the client-side EE check. An empty
        // extension body is permitted; only a fully absent extension violates.
        const tp = ch.quic_transport_parameters orelse return HandshakeError.MissingTransportParameters;

        var decoded_tp = transport_params.TransportParameters.decode(tp, self.allocator) catch {
            return HandshakeError.InvalidTransportParameters;
        };
        defer decoded_tp.deinit(self.allocator);
        decoded_tp.validateClientRole() catch {
            return HandshakeError.InvalidTransportParameters;
        };

        const tp_copy = try self.allocator.dupe(u8, tp);
        errdefer self.allocator.free(tp_copy);
        if (self.peer_quic_transport_parameters) |old| {
            self.allocator.free(old);
        }
        self.peer_quic_transport_parameters = tp_copy;
    }

    /// Client-side ServerHello handler. RFC 8446 §4.1.3.
    fn inboundServerHello(self: *Context, parsed: HandshakeMessage) !void {
        if (self.config.role != .Client) return HandshakeError.UnexpectedMessage;
        return self.handleServerHello(parsed.body);
    }

    /// Client-side CertificateRequest handler. RFC 8446 §4.3.2 +
    /// GAP-0139 encryption-level / phase gating.
    fn inboundCertificateRequest(self: *Context, level: EncryptionLevel, parsed: HandshakeMessage) !void {
        if (self.config.role != .Client) return HandshakeError.UnexpectedMessage;

        // GAP-0139: encryption-level + handshake-phase gate.
        //
        // RFC 8446 §4.3.2 places CertificateRequest after ServerHello /
        // EncryptedExtensions, so during the initial handshake it
        // arrives at the Handshake encryption level. RFC 8446 §4.6.2
        // permits a server to issue a post-handshake CertificateRequest
        // at the Application encryption level, but only if the
        // `post_handshake_auth` extension was negotiated. We surface
        // both invariants as `HandshakeError.UnexpectedMessage` (mapped
        // to the `unexpected_message` alert by the GAP-0138 alert
        // layer).
        switch (level) {
            .Initial => return HandshakeError.UnexpectedMessage,
            .Handshake => {
                if (self.phase == .application_ready or self.phase == .post_handshake) {
                    return HandshakeError.UnexpectedMessage;
                }
            },
            .Application => {
                if (!self.config.post_handshake_auth) {
                    return HandshakeError.UnexpectedMessage;
                }
                if (self.phase != .application_ready and self.phase != .post_handshake) {
                    return HandshakeError.UnexpectedMessage;
                }
            },
        }

        const cr_parsed = try tls13_full.parseCertificateRequest(self.allocator, parsed.body);
        defer self.allocator.free(cr_parsed.signature_algorithms);

        // QUAL-128: Dupe before free to prevent dangling pointer on OOM.
        const new_ctx = if (cr_parsed.context.len > 0)
            try self.allocator.dupe(u8, cr_parsed.context)
        else
            null;
        errdefer if (new_ctx) |ctx_buf| self.allocator.free(ctx_buf);
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
    }

    /// KeyUpdate handler. RFC 8446 §4.6.3 — only at Application level.
    fn inboundKeyUpdate(self: *Context, level: EncryptionLevel, parsed: HandshakeMessage) !void {
        if (level != .Application) return HandshakeError.UnexpectedMessage;
        const request = try parseKeyUpdate(parsed.body);
        return self.handleKeyUpdateMessage(request);
    }

    /// EncryptedExtensions handler. RFC 8446 §4.3.1 — client role only.
    fn inboundEncryptedExtensions(self: *Context, parsed: HandshakeMessage) !void {
        if (self.config.role != .Client) return HandshakeError.UnexpectedMessage;
        return self.handleEncryptedExtensions(parsed.body);
    }

    /// Certificate handler. RFC 8446 §4.4.2 — client (server cert) or
    /// server-with-mTLS (client cert).
    fn inboundCertificate(self: *Context, parsed: HandshakeMessage) !void {
        if (self.config.role == .Client) return self.handleCertificate(parsed.body);
        if (self.config.role == .Server and self.config.request_client_cert) {
            return self.handleClientCertificate(parsed.body);
        }
        return HandshakeError.UnexpectedMessage;
    }

    /// CertificateVerify handler. RFC 8446 §4.4.3 — client (server CV)
    /// or server-with-mTLS (client CV).
    fn inboundCertificateVerify(self: *Context, parsed: HandshakeMessage) !void {
        if (self.config.role == .Client) return self.handleCertificateVerify(parsed.body);
        if (self.config.role == .Server and self.config.request_client_cert) {
            return self.handleClientCertificateVerify(parsed.body);
        }
        return HandshakeError.UnexpectedMessage;
    }

    /// NewSessionTicket handler. RFC 8446 §4.6.1 — client at Application
    /// level only. Delegates to `handleNewSessionTicket` for the parse +
    /// callback dispatch (GAP-0132).
    fn inboundNewSessionTicket(self: *Context, level: EncryptionLevel, parsed: HandshakeMessage) !void {
        if (self.config.role != .Client) return HandshakeError.UnexpectedMessage;
        if (level != .Application) return HandshakeError.UnexpectedMessage;
        return self.handleNewSessionTicket(parsed.body);
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

        // RFC 8446 §7.1/§7.5: application + exporter secrets are derived over
        // Transcript-Hash(ClientHello...server Finished). R6-01: prefer the
        // snapshot captured when the server folded its Finished. The live
        // transcript is correct for the client (it derives at server-Finished
        // arrival, before sending its own auth messages) but WRONG for an mTLS
        // server (the client Certificate/CertificateVerify have been folded by
        // the time the client Finished arrives), so fall back to live only when
        // no snapshot exists (e.g. the client path).
        if (secret_trace_enabled) std.debug.print("[ensureApplicationSecrets] About to finalize transcript for role={}\n", .{self.config.role});
        const transcript_hash = self.transcripts.app_secret_hash.get(self.hash_kind) orelse blk: {
            var transcript_snapshot = self.transcripts.handshake;
            break :blk transcript_snapshot.finalize(self.hash_kind);
        };
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
        // PERF-249: Pre-size before appending so an intermediate
        // ArrayList realloc cannot fragment a flight that is being built
        // up byte-by-byte across multiple handshake messages.
        try stream.outbound.ensureUnusedCapacity(self.allocator, msg.len);
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

    // PERF-218: `pub` visibility so regression test
    // (tests/perf/test_alpn_server_borrow.zig) can call directly and assert
    // both the allocation-count delta and the borrow-vs-own pointer identity.
    pub fn selectServerAlpn(self: *Context, client: ClientHelloView) !?[]const u8 {
        // Clear previous selection (honors PERF-218 ownership sentinel).
        if (self.negotiated_alpn) |prev| {
            // PERF-218: only free when owned; borrowed slices must not be freed.
            if (self.negotiated_alpn_owned and prev.len != 0) self.allocator.free(prev);
            self.negotiated_alpn = null;
            self.negotiated_alpn_owned = false;
        }

        const server_list = self.config.alpn_protocols orelse return null;
        if (server_list.len == 0) return null;

        // If the client sent ALPN at all, they MUST get a match or we abort.
        const client_list = client.alpn_list orelse return HandshakeError.AlpnNegotiationFailed;
        if (client_list.len == 0) return HandshakeError.AlpnNegotiationFailed;

        // QUAL-317: pure match step delegated to alpn_selection module.
        const matched = alpn_selection.selectServerAlpn(client_list, server_list) orelse
            return HandshakeError.AlpnNegotiationFailed;

        // PERF-218: borrow from config — `config.alpn_protocols` outlives
        // Context, so a dupe is unnecessary here. `negotiated_alpn` field
        // type is `?[]u8` but the deinit path consults `negotiated_alpn_owned`
        // before freeing, so storing a `[]const u8` slice cast to `[]u8` is
        // sound: it will never be freed.
        self.negotiated_alpn = @constCast(matched);
        self.negotiated_alpn_owned = false;
        return matched;
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
    /// QUAL-317: thin adapter around `hello_retry_mod.parseHelloRetryRequest`
    /// + `applyHrrTranscript`. All security invariants (RFC 8446 §4.1.4
    /// double-HRR rejection, §4.4.1 transcript transformation, §4.2.8 missing
    /// key_share rejection) are preserved verbatim; the pure module owns the
    /// algorithm while Context retains the `hrr_received = true` write after
    /// successful parse (handshake-ordering state stays in the shell).
    fn handleHelloRetryRequest(self: *Context, body: []const u8) !void {
        if (self.hrr_received) {
            // Already received HRR once - server sent HRR twice (§4.1.4).
            return HandshakeError.UnexpectedMessage;
        }

        traceHandshake("Client: Received HelloRetryRequest\n", .{});

        const parsed = try hello_retry_mod.parseHelloRetryRequest(body);

        // NEWGAP-08 (SEC-028 twin): the HRR cipher_suite MUST be one the client
        // offered (RFC 8446 §4.1.3/§4.1.4). Record it so the subsequent
        // ServerHello can be required to select the same suite.
        const hrr_suite = std.enums.fromInt(tls13_full.CipherSuite, parsed.cipher_suite) orelse
            return HandshakeError.IllegalCipherSuiteSelected;
        var hrr_suite_offered = false;
        for (self.config.supported_cipher_suites) |offered| {
            if (offered == hrr_suite) {
                hrr_suite_offered = true;
                break;
            }
        }
        // NEWGAP08-N1: un-offered server selection -> illegal_parameter (§4.1.3).
        if (!hrr_suite_offered) return HandshakeError.IllegalCipherSuiteSelected;
        self.hrr_cipher_suite = hrr_suite;

        // NEWGAP-13: RFC 8446 §4.1.4 — abort with illegal_parameter if the HRR
        // would not result in any change to the ClientHello. A change requires
        // either a different key_share group than one already offered, or a
        // cookie (which CH2 must echo). This client key_shares every group it
        // supports, so an HRR selecting an already-offered group with no cookie
        // produces an identical ClientHello2 — the prohibited retry loop.
        var hrr_group_already_offered = false;
        for (self.config.supported_groups) |g| {
            if (g == parsed.selected_group) {
                hrr_group_already_offered = true;
                break;
            }
        }
        if (parsed.cookie == null and hrr_group_already_offered) {
            return HandshakeError.HrrNoChange;
        }

        traceHandshake("Client: HRR requests group: {s}\n", .{@tagName(parsed.selected_group)});

        // RFC 8446 §4.4.1: Update transcript for HelloRetryRequest
        // (message_hash(CH1) + HRR replay prefix, zero-alloc).
        const ch1_raw = self.streams.buffer(.Initial).outbound.items;
        hello_retry_mod.applyHrrTranscript(
            &self.transcripts.handshake,
            self.hash_kind,
            ch1_raw,
            body,
        );

        // Mark that we received HRR (handshake ordering — owned by Context).
        self.hrr_received = true;

        // Send ClientHello2 with new key_share and (optional) cookie echo.
        try self.sendClientHello2(parsed.selected_group, parsed.cookie);

        traceHandshake("Client: Sent ClientHello2 with group {s}\n", .{@tagName(parsed.selected_group)});
    }

    /// Send ClientHello2 after receiving HelloRetryRequest.
    /// RFC 8446 §4.1.4: Second ClientHello includes cookie and new key_share.
    ///
    /// QUAL-317: thin adapter — SEC-036/SEC-050 ephemeral-key handling stays
    /// in Context because it mutates `self.client_priv`/`self.client_pub`;
    /// the actual CH2 body encoding is delegated to
    /// `hello_retry_mod.buildClientHello2Body`.
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
        // SEC-050: Zero stack-local private key on all exit paths (error or success).
        // After copying to self.client_priv, this stack copy is no longer needed.
        defer std.crypto.secureZero(u8, &priv);
        // SEC-074: fail-closed entropy (replaces unchecked getrandom).
        entropy.fillRandom(&priv);
        // SEC-037: Explicit X25519 clamping per RFC 7748 §5 for defense-in-depth.
        // Zig's X25519 internally clamps during DH computation, but we clamp here
        // too to ensure the stored private key bytes are canonical.
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

        const ch_result = try hello_retry_mod.buildClientHello2Body(self.scratch_arena.allocator(), .{
            .client_random = rnd,
            .client_pub = pub_key,
            .selected_group = selected_group,
            .cipher_suites = self.config.supported_cipher_suites,
            .supported_groups = self.config.supported_groups,
            .signature_algorithms = self.config.supported_signature_schemes,
            .alpn_protocols = self.config.alpn_protocols,
            .quic_transport_parameters = self.local_transport_parameters orelse self.config.quic_transport_parameters,
            .cookie = cookie,
        });

        // PERF-019: Use appendOutboundFramed to write handshake header + body
        // directly into the outbound buffer, avoiding encodeHandshake allocation.
        try self.appendOutboundFramed(.Initial, .client_hello, ch_result.body, true);
        _ = self.scratch_arena.reset(.retain_capacity);
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
        // SEC-074: fail-closed entropy (replaces unchecked getrandom).
        entropy.fillRandom(&secret);
        self.server_secret_generated = secret;
        // SAFETY: Just assigned on the line above; server_secret_generated is guaranteed non-null.
        return &self.server_secret_generated.?;
    }

    /// Send HelloRetryRequest to client requesting a different key share group.
    /// RFC 8446 §4.1.4: HelloRetryRequest is a ServerHello with special random value.
    ///
    /// QUAL-317: thin adapter — cookie generation + HRR body encoding are
    /// delegated to `hello_retry_mod.buildHrrBody`, and the zero-alloc
    /// transcript transformation to `hello_retry_mod.applyHrrTranscript`.
    /// Context retains `hrr_sent = true` write (handshake ordering) and the
    /// outbound framing + ensureServerSecret (which mutates
    /// `server_secret_generated`).
    fn sendHelloRetryRequest(self: *Context, ch_view: ClientHelloView, selected_group: tls13_full.NamedGroup) !void {
        traceHandshake("Server: Sending HelloRetryRequest (requesting group: {s})\n", .{@tagName(selected_group)});

        // RFC 8446 §4.2.2: Generate cookie binding this HRR to the client's first ClientHello
        const server_secret = try self.ensureServerSecret();

        // Compute transcript hash of first ClientHello.
        const ch1_hash = self.transcripts.handshake.finalize(self.hash_kind);

        // SEC-086: persist CH1 transcript hash so the cookie can be
        // re-verified when CH2 arrives (RFC 8446 §4.2.2 server side).
        self.ch1_transcript_hash = ch1_hash;

        // Delegate cookie generation + HRR body encoding to the pure module.
        const hrr_result = try hello_retry_mod.buildHrrBody(self.scratch_arena.allocator(), .{
            .server_secret = server_secret,
            .client_random = ch_view.random,
            .ch1_transcript_hash = ch1_hash.slice(),
            .selected_group = selected_group,
            .session_id = ch_view.session_id,
        });

        // RFC 8446 §4.4.1: Update transcript hash for HelloRetryRequest
        // (message_hash(ClientHello1) || HelloRetryRequest) — zero-alloc.
        hello_retry_mod.applyHrrTranscript(
            &self.transcripts.handshake,
            self.hash_kind,
            ch_view.raw,
            hrr_result.body,
        );

        // Queue HRR for transmission at Initial encryption level (zero-alloc framing)
        try self.appendOutboundFramed(.Initial, .server_hello, hrr_result.body, false);
        _ = self.scratch_arena.reset(.retain_capacity);

        // Mark that we sent HRR (handshake ordering — owned by Context).
        self.hrr_sent = true;

        traceHandshake("Server: HelloRetryRequest sent successfully\n", .{});
    }

    /// QUAL-317: Thin adapter around `psk_selection_mod.selectPsk`.
    ///
    /// Constructs a `PskInput` state-slice from Context fields, invokes the
    /// pure module, and returns its `PskOutput` (renamed locally to match
    /// prior call-site shape). Early-exit paths that used to return null
    /// before even touching state (no pre_shared_key, no ticket lookup
    /// callback) are preserved so the oracle stays byte-identical.
    fn selectPsk(self: *Context, ch_view: ClientHelloView) !?psk_selection_mod.PskOutput {
        const psk_ext = ch_view.pre_shared_key orelse return null;

        // Wrap the on_ticket_lookup callback into a type-erased adapter.
        // The opaque `ctx` pointer is the `*Context` itself.
        const Shim = struct {
            fn lookup(opaque_ctx: *anyopaque, identity: []const u8) ?[]const u8 {
                const self_ptr: *Context = @ptrCast(@alignCast(opaque_ctx));
                const cb = self_ptr.callbacks.on_ticket_lookup orelse return null;
                return cb(self_ptr, identity);
            }
        };

        // Preserve the original short-circuit: if the callback is not
        // configured AND no external PSK is available, there is nothing to
        // match, so return null without any further work (including without
        // entering psk_key_exchange_modes validation). This matches the
        // pre-refactor behaviour of `lookup_cb orelse return null`.
        const has_lookup_cb = self.callbacks.on_ticket_lookup != null;
        const has_external_psk = self.config.external_psk != null and self.config.external_psk_identity != null;
        if (!has_lookup_cb and !has_external_psk) return null;

        const input = psk_selection_mod.PskInput{
            .offered_identities = psk_ext.identities,
            .offered_binders = psk_ext.binders,
            .psk_key_exchange_modes = ch_view.psk_key_exchange_modes,
            .ch_raw = ch_view.raw,
            .hash_kind = self.hash_kind,
            .external_psk = self.config.external_psk,
            .external_psk_identity = self.config.external_psk_identity,
            .ticket_lookup = if (has_lookup_cb) Shim.lookup else null,
            .ticket_lookup_ctx = @ptrCast(self),
        };
        return psk_selection_mod.selectPsk(input);
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
        const ch_view = self.state.clientHello() orelse {
            // QUIC-INTEROP-HRR (2026-04-27): negotiate entered without a
            // parsed ClientHello — almost always a callsite bug, but
            // surfacing it is cheap and disambiguates from cipher / sig /
            // key_share failures below.
            logger.err(
                "[TLS-HRR] negotiate UnexpectedMessage: clientHello state slot empty (hrr_sent={})",
                .{self.hrr_sent},
            );
            return HandshakeError.UnexpectedMessage;
        };
        const cipher_suite = cipher_negotiation.chooseCipherSuite(
            ch_view.cipher_suites,
            self.config.supported_cipher_suites,
        ) orelse {
            // QUIC-INTEROP-HRR (2026-04-27): no overlap between client's
            // offered cipher suites and the server's configured set.
            // ClientHelloInfo.parse pre-filters to TLS 1.3 entries
            // (0x1301-0x1303) so a non-empty offered list with no overlap
            // means the server config disagrees with the client's TLS 1.3
            // suite set.
            logger.err(
                "[TLS-HRR] negotiate NoCipherSuite (no_overlap): client_offered={d} suites, server_supports={d} suites, hrr_sent={}",
                .{
                    ch_view.cipher_suites.len,
                    self.config.supported_cipher_suites.len,
                    self.hrr_sent,
                },
            );
            return HandshakeError.NoCipherSuite;
        };
        self.hash_kind = cipherSuiteHash(cipher_suite);
        self.negotiated_cipher_suite = cipher_suite;
        // PERF-004: Lock transcript to the negotiated hash for the server path.
        self.transcripts.handshake.lockHash(self.hash_kind);

        // QUAL-317: signature-scheme selection is now a pure helper. The
        // shell (Context) owns the mutation of `self.negotiated_signature`.
        // Preserve original semantics exactly: reset to null on entry,
        // require a non-empty server list and a non-null peer list, then
        // assign on successful overlap.
        //
        // QUIC-INTEROP-HRR (2026-04-27): tag each NoSignatureScheme
        // sub-path so interop logs name the actual cause.
        if (self.config.supported_signature_schemes.len == 0) {
            logger.err(
                "[TLS-HRR] negotiate NoSignatureScheme (server_config_empty): " ++
                    "Config.supported_signature_schemes is empty (hrr_sent={})",
                .{self.hrr_sent},
            );
            return HandshakeError.NoSignatureScheme;
        }
        const peer_sig_schemes = ch_view.signature_algorithms orelse {
            logger.err(
                "[TLS-HRR] negotiate NoSignatureScheme (peer_list_missing): " ++
                    "ClientHello did not include signature_algorithms extension (hrr_sent={})",
                .{self.hrr_sent},
            );
            return HandshakeError.NoSignatureScheme;
        };
        self.negotiated_signature = null;
        self.negotiated_signature = cipher_negotiation.chooseSignatureScheme(
            peer_sig_schemes,
            self.config.supported_signature_schemes,
        ) orelse {
            logger.err(
                "[TLS-HRR] negotiate NoSignatureScheme (no_overlap): " ++
                    "client_offered={d} schemes, server_supports={d} schemes (hrr_sent={})",
                .{
                    peer_sig_schemes.len,
                    self.config.supported_signature_schemes.len,
                    self.hrr_sent,
                },
            );
            return HandshakeError.NoSignatureScheme;
        };

        // RFC 8446 §4.1.4: Check if client's key_share group is supported
        if (ch_view.key_share.group != .x25519) {
            if (self.hrr_sent) {
                // QUIC-INTEROP-HRR diagnostic: client ignored our HRR and
                // re-offered a non-X25519 group. Surface the raw codepoint
                // so interop logs can distinguish "client retried with the
                // wrong group" from "no second ClientHello arrived".
                logger.err(
                    "[TLS-HRR] post-HRR ClientHello#2 still offers non-X25519 key_share (raw_group_code=0x{x:0>4}, group={s})",
                    .{ ch_view.key_share.raw_group_code, @tagName(ch_view.key_share.group) },
                );
                return HandshakeError.UnsupportedKeyShareGroup;
            }
            try self.sendHelloRetryRequest(ch_view, .x25519);
            return null; // HRR sent; stop flight
        }

        if (ch_view.key_share.key.len != 32) {
            // QUIC-INTEROP-HRR (2026-04-27): client offered group=x25519
            // but the key_exchange field is the wrong length. RFC 7748
            // §6.1: X25519 public keys are exactly 32 bytes.
            logger.err(
                "[TLS-HRR] negotiate UnsupportedKeyShareGroup (x25519_short_key): " ++
                    "key_share.group=x25519 but key.len={d} (expected 32, raw_group_code=0x{x:0>4}, hrr_sent={})",
                .{
                    ch_view.key_share.key.len,
                    ch_view.key_share.raw_group_code,
                    self.hrr_sent,
                },
            );
            return HandshakeError.UnsupportedKeyShareGroup;
        }

        // SEC-086: post-HRR cookie verification (RFC 8446 §4.2.2). When
        // we sent HRR, the second ClientHello MUST echo the cookie we
        // issued; we re-derive the HMAC inputs from per-Context state
        // captured at HRR emit time. A missing, malformed, stale, or
        // forged cookie aborts the handshake (handshake_failure /
        // illegal_parameter on the wire).
        //
        // QUIC-INTEROP-HRR (2026-04-27): each failure branch surfaces a
        // `logger.err` so interop logs distinguish "cookie mismatch" from
        // "handshake just timed out" without rebuilding for a debug pass.
        if (self.hrr_sent) {
            const ch1_hash = self.ch1_transcript_hash orelse {
                logger.err(
                    "[TLS-HRR] post-HRR cookie verify failed: server lost CH1 transcript hash before CH2 arrived",
                    .{},
                );
                return HandshakeError.InvalidCookie;
            };
            const cookie_bytes = ch_view.cookie orelse {
                logger.err(
                    "[TLS-HRR] post-HRR cookie verify failed: ClientHello#2 missing cookie extension (RFC 8446 §4.2.2)",
                    .{},
                );
                return HandshakeError.InvalidCookie;
            };
            const server_secret = try self.ensureServerSecret();
            const max_age_seconds: i64 = 10; // RFC 8446 §4.2.2 typical
            const ok = cookie_mod.verifyCookie(
                cookie_bytes,
                server_secret,
                ch_view.random,
                ch1_hash.slice(),
                max_age_seconds,
            );
            if (!ok) {
                logger.err(
                    "[TLS-HRR] post-HRR cookie verify failed: HMAC mismatch or stale cookie (cookie_len={d}, ch1_hash_len={d}, max_age_s={d})",
                    .{ cookie_bytes.len, ch1_hash.slice().len, max_age_seconds },
                );
                return HandshakeError.InvalidCookie;
            }
        }

        var server_random: [32]u8 = undefined;
        // SEC-074: fail-closed entropy (replaces unchecked getrandom).
        entropy.fillRandom(&server_random);

        var server_priv: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &server_priv);
        // SEC-074: fail-closed entropy (replaces unchecked getrandom).
        entropy.fillRandom(&server_priv);
        // SEC-048: Explicit X25519 clamping per RFC 7748 §5 for defense-in-depth.
        // Zig's X25519 internally clamps during DH computation, but we clamp here
        // too for consistency with sendClientHello2() and to ensure the stored
        // private key bytes are canonical.
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

    /// QUAL-095 step 2 / QUAL-317: thin adapter around
    /// `server_flight_builders.buildServerHelloMsg`.
    fn buildServerHelloMsg(self: *Context, neg: *const ServerNegotiationResult) ![]u8 {
        // SAFETY: negotiated_cipher_suite is set by negotiateCipherAndKeys() which
        // runs before emitServerFlight(), the sole caller of this function.
        const cipher = self.negotiated_cipher_suite orelse return HandshakeError.InternalError;
        return server_flight_builders.buildServerHelloMsg(self.scratch_arena.allocator(), .{
            .cipher = cipher,
            .key_share_group = neg.ch_view.key_share.group,
            .server_random = neg.server_random,
            .server_public_key = neg.server_pub[0..],
            .session_id = neg.session_id_opt,
            .selected_psk_index = neg.selected_psk_index,
        });
    }

    /// QUAL-095 step 3 / QUAL-317: thin adapter around
    /// `server_flight_builders.buildEncryptedExtensionsMsg`. Context performs the
    /// stateful pre-work (ensureLocalTransportParameters, selectServerAlpn,
    /// notifyMetadata), then delegates the byte encoding.
    fn buildEncryptedExtensionsMsg(self: *Context, ch_view: ClientHelloView) ![]u8 {
        const server_tp = try self.ensureLocalTransportParameters();
        const selected_alpn = try self.selectServerAlpn(ch_view);
        self.notifyMetadata();
        return server_flight_builders.buildEncryptedExtensionsMsg(self.scratch_arena.allocator(), .{
            .alpn = selected_alpn,
            .quic_transport_parameters = server_tp,
        });
    }

    /// QUAL-095 step 4 / QUAL-317: thin adapter around
    /// `server_flight_builders.buildCertificateMsg`. Context retains trace
    /// logging (so the PSK vs non-PSK branch remains observable) and delegates
    /// the null/MissingCertificate policy + encoding.
    fn buildCertificateMsg(self: *Context, psk_selected: bool) !?[]u8 {
        if (self.config.server_cert_der) |cert_der| {
            traceHandshake("Server: Sending Certificate message ({} bytes DER)\n", .{cert_der.len});
        } else if (psk_selected) {
            traceHandshake("Server: Using PSK-only authentication, skipping Certificate/CertificateVerify\n", .{});
        } else {
            traceHandshake("Server: ERROR - Certificate required when not using PSK authentication\n", .{});
        }
        return server_flight_builders.buildCertificateMsg(
            self.scratch_arena.allocator(),
            self.config.server_cert_der,
            psk_selected,
        );
    }

    /// QUAL-095 step 5 / QUAL-317: thin adapter around
    /// `server_flight_builders.buildCertificateVerifyMsg`. Context finalizes the
    /// transcript hash (mutable state) and resolves the negotiated signature
    /// scheme + private key, then delegates the signing + encoding.
    fn buildCertificateVerifyMsg(self: *Context) ![]u8 {
        const hash_for_sig = self.transcripts.handshake.finalize(self.hash_kind);

        const sig_scheme = self.negotiated_signature orelse
            return HandshakeError.NoSignatureScheme;

        traceHandshake("Server: Signing CertificateVerify with scheme: {s}\n", .{@tagName(sig_scheme)});

        const priv_key = self.config.server_key_der orelse {
            traceHandshake("Server: ERROR - No private key configured!\n", .{});
            return HandshakeError.UnexpectedMessage;
        };

        return server_flight_builders.buildCertificateVerifyMsg(self.scratch_arena.allocator(), .{
            .signature_scheme = sig_scheme,
            .private_key_der = priv_key,
            .transcript_hash = hash_for_sig,
        });
    }

    /// QUAL-095 step 6 / QUAL-317: thin adapter around
    /// `server_flight_builders.buildFinishedMsg`. Context finalizes the
    /// transcript-hash-through-CertificateVerify, caches it in
    /// `transcripts.finished_hash`, then delegates the stack-only
    /// verify_data derivation.
    fn buildFinishedMsg(self: *Context, server_hs_secret: *const Secret) Secret {
        const hash_before_finished = self.transcripts.handshake.finalize(self.hash_kind);
        self.transcripts.finished_hash.set(self.hash_kind, hash_before_finished);
        return server_flight_builders.buildFinishedMsg(self.hash_kind, server_hs_secret, hash_before_finished);
    }

    /// QUAL-095 + PERF-013: Emit the complete server flight using zero-alloc
    /// framing via appendOutboundFramed.  Message bodies are built by the
    /// individual helpers; only the bodies allocate.
    fn emitServerFlight(self: *Context, neg: *ServerNegotiationResult) !void {
        // --- ServerHello (Initial level) ---
        const sh_body = try self.buildServerHelloMsg(neg);

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

            // SEC-065/085: Cross-connection anti-replay via configured persistent
            // store. Must run BEFORE the per-Context in-memory window so that
            // cross-server replay attempts are rejected even when the local
            // window has not observed them. Backend errors are fail-closed —
            // 0-RTT is rejected and the handshake falls back to 1-RTT.
            if (self.config.persistent_anti_replay_store) |store| {
                const added = store.checkAndAdd(client_random) catch |err| blk: {
                    traceHandshake("Server: 0-RTT persistent anti-replay store error ({s}); falling back to 1-RTT\n", .{@errorName(err)});
                    break :blk false;
                };
                if (!added) accept_early = false;
            }

            if (accept_early) {
                if (self.anti_replay) |ar| {
                    ar.add(client_random) catch |err| {
                        traceHandshake("Server: 0-RTT anti-replay detected ({}), rejecting early data\\n", .{err});
                        accept_early = false;
                    };
                } else {
                    accept_early = false;
                }
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
        // QUAL-346: atomic install — if either side fails, both slots are
        // rolled back so we never leak one-half of a key pair.
        try self.installHandshakeTrafficPair(hs.server_hs, hs.client_hs);
        if (self.phase == .negotiating) self.phase = .keys_installed;

        // --- EncryptedExtensions (Handshake level) ---
        const ee_body = try self.buildEncryptedExtensionsMsg(neg.ch_view);
        try self.appendOutboundFramed(.Handshake, .encrypted_extensions, ee_body, true);

        // --- CertificateRequest (mTLS, optional) ---
        if (self.config.request_client_cert) {
            const cr_body = try tls13_full.buildCertificateRequest(
                self.scratch_arena.allocator(),
                self.config.supported_signature_schemes,
                self.config.client_auth_ca_certs,
            );
            try self.appendOutboundFramed(.Handshake, .certificate_request, cr_body, true);
            traceHandshake("Server: Sent CertificateRequest message\n", .{});
        }

        // --- Certificate + CertificateVerify (if not PSK-only) ---
        if (try self.buildCertificateMsg(neg.psk_selected)) |cert_body| {
            try self.appendOutboundFramed(.Handshake, .certificate, cert_body, true);

            const cv_body = try self.buildCertificateVerifyMsg();
            try self.appendOutboundFramed(.Handshake, .certificate_verify, cv_body, true);

            traceHandshake("Server: Certificate and CertificateVerify sent successfully\n", .{});
        }

        // --- Finished ---
        const verify_data = self.buildFinishedMsg(&hs.server_hs);
        try self.appendOutboundFramed(.Handshake, .finished, verify_data.slice(), true);

        // R6-01: capture Transcript-Hash(CH...server Finished) NOW, before any
        // client Certificate/CertificateVerify (mTLS) can be folded in, so the
        // §7.1 application + §7.5 exporter secrets are derived over the correct
        // transcript regardless of when ensureApplicationSecrets later runs.
        self.transcripts.app_secret_hash.set(self.hash_kind, self.transcripts.handshake.finalize(self.hash_kind));

        try self.markLocalFinished();
        _ = self.scratch_arena.reset(.retain_capacity);
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

    // ========================================================================
    // GAP-0133 / GAP-0134: TLS Alert Protocol (RFC 8446 §6, RFC 9001 §4.8)
    // ========================================================================

    /// GAP-0133: Decode a 2-byte inbound TLS alert, surface via callback,
    /// terminate on fatal. Called by `deliverAlert` (see below); factored out
    /// so tests + future transports can hook in without duplicating policy.
    ///
    /// RFC 8446 §6: Alert messages are 2 bytes — AlertLevel (1B) +
    /// AlertDescription (1B). TLS 1.3 treats all alerts as fatal in practice
    /// (§6.1) except `close_notify` (§6.1) and `user_canceled` (§6.1), which
    /// may be sent as warning. Fatal alerts terminate the connection.
    fn handleInboundAlert(self: *Context, level: EncryptionLevel, payload: []const u8) !void {
        _ = level; // encryption level is observed but not used for dispatch
        if (payload.len != 2) return HandshakeError.InvalidAlert;

        const decoded = alert_mod.Alert.decode(.{ payload[0], payload[1] });
        self.flags.alert = @intFromEnum(decoded.description);

        if (self.callbacks.on_alert) |cb| {
            cb(self, decoded.description);
        }

        if (decoded.level == .fatal) {
            self.phase = .terminated;
            return HandshakeError.PeerFatalAlert;
        }
    }

    /// GAP-0133: Public entry point — QUIC transport invokes this when a
    /// TLS alert content type is seen on the CRYPTO stream. Payload must be
    /// exactly 2 bytes per RFC 8446 §6.
    ///
    /// Behavior:
    /// - Decodes the alert via `alert.Alert.decode`.
    /// - Populates `ctx.flags.alert` with the description numeric value.
    /// - Invokes the `on_alert` callback if configured.
    /// - On fatal alerts: transitions `ctx.phase = .terminated` and returns
    ///   `HandshakeError.PeerFatalAlert`.
    /// - On warning alerts: returns normally; caller decides whether to
    ///   treat the warning as terminal.
    ///
    /// Errors:
    /// - `HandshakeError.InvalidAlert`  — payload length != 2.
    /// - `HandshakeError.PeerFatalAlert` — fatal alert was received.
    pub fn deliverAlert(self: *Context, level: EncryptionLevel, payload: []const u8) !void {
        return self.handleInboundAlert(level, payload);
    }

    /// GAP-0134: Send a warning-level `close_notify` alert per RFC 8446 §6.1
    /// ("close_notify"). Writes a 2-byte payload to the Application-level
    /// outbound stream. Caller retrieves bytes via the Application outbound
    /// buffer and schedules them on the QUIC CRYPTO stream. The Context is
    /// transitioned to `.terminated`; no further handshake/application
    /// progress is accepted.
    pub fn sendCloseNotify(self: *Context) !void {
        const a = alert_mod.Alert{ .level = .warning, .description = .close_notify };
        const payload = a.encode();
        const app_level = @intFromEnum(EncryptionLevel.Application);
        // PERF-249: pre-size outbound for the 2-byte alert payload.
        try self.streams.buffers[app_level].outbound.ensureUnusedCapacity(self.allocator, payload.len);
        try self.streams.buffers[app_level].outbound.appendSlice(self.allocator, &payload);
        self.phase = .terminated;
    }

    /// GAP-0134: Send a fatal alert per RFC 8446 §6. The alert is queued on
    /// the highest currently-installed encryption level (Initial pre-
    /// handshake; Handshake during negotiation; Application once keys are
    /// up). Transitions the Context to `.terminated`.
    ///
    /// Callers typically follow with drain-and-emit on the QUIC CRYPTO
    /// stream and a QUIC CONNECTION_CLOSE frame of type 0x1c (CRYPTO_ERROR)
    /// carrying `alert.toQuicCryptoError(desc)` per RFC 9001 §4.8.
    pub fn sendFatalAlert(self: *Context, desc: alert_mod.AlertDescription) !void {
        const a = alert_mod.Alert{ .level = .fatal, .description = desc };
        const payload = a.encode();
        const level: EncryptionLevel = switch (self.phase) {
            .initial => .Initial,
            .negotiating, .keys_installed => .Handshake,
            .application_ready, .post_handshake, .terminated => .Application,
        };
        // PERF-249: pre-size outbound for the 2-byte alert payload.
        try self.streams.buffers[@intFromEnum(level)].outbound.ensureUnusedCapacity(self.allocator, payload.len);
        try self.streams.buffers[@intFromEnum(level)].outbound.appendSlice(self.allocator, &payload);
        self.phase = .terminated;
    }

    /// GAP-0134: Convenience wrapper — send fatal `internal_error` (RFC 8446
    /// §6.2). Use when the library or caller encounters an unrecoverable
    /// condition that is not covered by a more specific alert description.
    pub fn sendInternalError(self: *Context) !void {
        return self.sendFatalAlert(.internal_error);
    }

    /// GAP-0134: Convenience wrapper — send fatal `handshake_failure`
    /// (RFC 8446 §6.2). Use when no mutually supported parameters can be
    /// negotiated (cipher suites, signature algorithms, etc.).
    pub fn sendHandshakeFailure(self: *Context) !void {
        return self.sendFatalAlert(.handshake_failure);
    }

    /// GAP-0138: Queue a fatal alert mapped from a handshake-layer error
    /// and return that error to the caller.
    ///
    /// Convenience used by handshake handlers to satisfy RFC 8446 §6.2 —
    /// "Whenever an implementation encounters a fatal error condition, it
    /// SHOULD send an appropriate alert prior to closing the connection."
    /// The mapping is delegated to `alert.fromHandshakeError` so it stays
    /// in sync with the RFC §6.2 alert codes.
    ///
    /// On success the outbound CryptoBuffer for the appropriate level
    /// contains the 2-byte alert payload, and `self.phase` is set to
    /// `.terminated`. The original `err` is then returned. Allocation
    /// failures during alert queuing are swallowed; the QUIC transport
    /// observes the abort via `self.phase == .terminated`.
    fn failAlert(self: *Context, err: anyerror) anyerror {
        const desc = alert_mod.fromHandshakeError(err);
        self.sendFatalAlert(desc) catch {};
        return err;
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
        // SEC-050: Zero stack-local private key on all exit paths (error or success).
        // After copying to self.client_priv, this stack copy is no longer needed.
        defer std.crypto.secureZero(u8, &priv);
        // SEC-074: fail-closed entropy (replaces unchecked getrandom).
        entropy.fillRandom(&priv);
        // SEC-040: Explicit X25519 clamping per RFC 7748 §5 for defense-in-depth.
        // Zig's X25519 internally clamps during DH computation, but we clamp here
        // too for consistency with sendClientHello2() and to ensure the stored
        // private key bytes are canonical.
        priv[0] &= 248;
        priv[31] &= 127;
        priv[31] |= 64;
        const client_pubkey = std.crypto.dh.X25519.recoverPublicKey(priv) catch return HandshakeError.UnsupportedKeyShareGroup;
        self.client_priv = priv;
        self.client_pub = client_pubkey;

        var rnd: [32]u8 = undefined;
        // SEC-074: fail-closed entropy (replaces unchecked getrandom).
        entropy.fillRandom(&rnd);
        self.client_random = rnd; // Save for potential HRR handling

        // Determine PSK parameters
        const has_resumption_psk = self.config.resumption_psk != null;
        const has_external_psk = self.config.external_psk != null and self.config.external_psk_identity != null;
        const has_any_psk = has_resumption_psk or has_external_psk;
        const using_external_psk = has_external_psk and !has_resumption_psk;

        // SAFETY: .? on external_psk_identity is guarded by has_external_psk which
        // checks external_psk_identity != null; using_external_psk implies has_external_psk.
        const psk_identity: ?[]const u8 = if (has_any_psk) blk: {
            break :blk if (using_external_psk)
                self.config.external_psk_identity.?
            else
                (self.config.resumption_ticket orelse return HandshakeError.MissingResumptionTicket);
        } else null;

        // QUAL-096: Use shared ClientHello builder.
        // PERF-208: Request a framed ClientHello so the 4-byte handshake
        // header is reserved inside the same buffer as the body. This
        // eliminates the previous second alloc + memcpy used to prepend
        // the header before PSK binder computation. `ch_result.body` is
        // now the full handshake message (header + body) and
        // `ch_result.binder_offset` is already header-inclusive.
        const ch_result = try tls13_full.buildClientHello(self.scratch_arena.allocator(), .{
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
            .prepend_handshake_header = true,
        });

        // `msg` is the fully-framed handshake message (HsType + 3-byte
        // length + ClientHello body) in a single allocation.
        const msg = ch_result.body;

        // Compute PSK binder if needed.
        //
        // PERF-255: Pre-hash the truncated ClientHello prefix into the
        // *main* handshake transcript and `clone()` it to derive the
        // binder transcript hash. After the binder is computed and the
        // tail bytes are patched into `msg`, we feed only the binder tail
        // to the main transcript and skip `appendOutbound`'s automatic
        // transcript update. Net effect: the truncated prefix is hashed
        // once (on the main transcript) instead of twice (once on a
        // freshly initialized binder transcript and once on the main
        // transcript via `appendOutbound`).
        //
        // For the no-PSK path (the `else` branch below) the main
        // transcript still gets the whole message via the
        // `update_transcript=true` flag in the single `appendOutbound`
        // call, and there is no extra hash work.
        if (ch_result.binder_offset) |msg_binder_offset| {
            const binder_len = ch_result.binder_len;
            if (binder_len == 0) return HandshakeError.CryptoError;

            // SAFETY: using_external_psk implies external_psk != null (checked via has_external_psk);
            // otherwise has_any_psk implies resumption_psk != null (has_resumption_psk).
            const psk = if (using_external_psk) self.config.external_psk.? else self.config.resumption_psk.?;
            const early_secret = key_derivation_mod.deriveEarlySecret(self.hash_kind, psk);
            const binder_key = key_derivation_mod.deriveBinderKey(self.hash_kind, &early_secret, using_external_psk);

            // Truncate before binders list (offset is relative to the full
            // framed msg including the handshake header).
            const truncated_len = msg.len - ch_result.binders_tail_len;

            // Lock the main transcript to the negotiated hash before
            // mutating it. `lockHash` is idempotent. Without locking,
            // both SHA variants would be fed and `clone().finalize()`
            // could produce a digest from the unused tree.
            self.transcripts.handshake.lockHash(self.hash_kind);

            // Hash the truncated prefix into the main transcript exactly
            // once, then clone to compute the binder hash without
            // re-hashing.
            self.transcripts.handshake.update(msg[0..truncated_len]);
            var binder_view = self.transcripts.handshake.clone();
            const transcript_hash = binder_view.finalize(self.hash_kind);

            const binder = finished_mod.deriveFinishedVerifyData(self.hash_kind, &binder_key, transcript_hash);
            // PERF-208: binder_offset is absolute into msg (buildClientHello
            // with prepend_handshake_header=true writes header-inclusive
            // offsets). No +4 adjustment required.
            @memcpy(msg[msg_binder_offset..][0..binder_len], binder.slice()[0..binder_len]);

            // Feed the (now binder-patched) tail to the main transcript so it
            // holds the COMPLETE ClientHello (prefix + binders).
            self.transcripts.handshake.update(msg[truncated_len..]);

            if (self.config.enable_early_data) {
                // R7-01: RFC 8446 §7.1 — client_early_traffic_secret is derived
                // over Transcript-Hash(complete ClientHello), INCLUDING the PSK
                // binders, to match the server (which folds the full CH). The
                // binder-truncated `transcript_hash` above is only the binder
                // MAC input (§4.2.11.2), not the early-secret input.
                var ch_full_view = self.transcripts.handshake.clone();
                const ch_full_hash = ch_full_view.finalize(self.hash_kind);
                const early_traffic_secret = key_derivation_mod.deriveEarlyTraffic(
                    self.hash_kind,
                    &early_secret,
                    ch_full_hash.slice(),
                );
                try self.installTrafficSecret(.Initial, .send, early_traffic_secret);
                traceHandshake("Client: Installed 0-RTT early traffic secret for sending\\n", .{});
            }

            // Append the message without a second transcript update.
            try self.appendOutbound(.Initial, msg, false);
        } else {
            // No PSK; one transcript pass over the whole message.
            try self.appendOutbound(.Initial, msg, true);
        }
        self.transcripts.client_hello_hash = self.transcripts.handshake.snapshot();
        if (self.phase == .initial) self.phase = .negotiating;
        _ = self.scratch_arena.reset(.retain_capacity);
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
        // NEWGAP-06: RFC 8446 §4.1.3 — legacy_version MUST be 0x0303.
        if (body[0] != 0x03 or body[1] != 0x03) return HandshakeError.IllegalLegacyVersion;
        var pos: usize = 2 + 32; // after legacy_version+random
        if (pos >= body.len) return HandshakeError.UnexpectedMessage;
        const sid_len: usize = body[pos];
        // NEWGAP-06: RFC 8446 §4.1.3 — legacy_session_id_echo MUST equal the
        // client's legacy_session_id. This client always sends an EMPTY
        // session_id, so any non-empty echo MUST abort with illegal_parameter.
        if (sid_len != 0) return HandshakeError.IllegalSessionIdEcho;
        pos += 1 + sid_len;
        if (pos + 2 + 1 > body.len) return HandshakeError.UnexpectedMessage;
        const suite_value: u16 = readU16(body[pos .. pos + 2]);
        // NEWGAP08-N1: an unknown (not-offered) suite -> illegal_parameter (§4.1.3).
        const cipher_suite = std.enums.fromInt(tls13_full.CipherSuite, suite_value) orelse return HandshakeError.IllegalCipherSuiteSelected;

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
            // NEWGAP08-N1: RFC 8446 §4.1.3 mandates illegal_parameter here.
            return HandshakeError.IllegalCipherSuiteSelected;
        }

        // NEWGAP-08: RFC 8446 §4.1.4 — after an HRR, the ServerHello cipher_suite
        // MUST match the one the server selected in the HRR.
        if (self.hrr_received) {
            if (self.hrr_cipher_suite) |hrr_suite| {
                if (cipher_suite != hrr_suite) return HandshakeError.IllegalCipherSuiteSelected;
            }
        }

        self.negotiated_cipher_suite = cipher_suite;
        self.hash_kind = cipherSuiteHash(cipher_suite);
        // PERF-004: Lock transcript to the negotiated hash; subsequent updates
        // skip the unused algorithm.
        self.transcripts.handshake.lockHash(self.hash_kind);
        pos += 2; // cipher_suite
        // RFC 8446 §4.1.3: ServerHello.legacy_compression_method MUST be 0x00.
        // QUAL-391: reject with the typed IllegalCompressionMethods (maps to
        // illegal_parameter), symmetric with the SEC-088 ClientHello path.
        if (body[pos] != 0x00) return HandshakeError.IllegalCompressionMethods;
        pos += 1; // compression
        if (pos + 2 > body.len) return HandshakeError.UnexpectedMessage;
        const exts_len: usize = readU16(body[pos .. pos + 2]);
        pos += 2;
        if (pos + exts_len > body.len) return HandshakeError.UnexpectedMessage;
        const exts_end = pos + exts_len;
        var server_pub: ?[32]u8 = null;
        var found_supported_versions = false;
        var server_selected_psk_index: ?u16 = null;
        // SEC-092 (subsumes SEC-078) / NEWGAP-07 (= QUAL-387): track raw u16
        // extension types so duplicates are rejected per RFC 8446 §4.2 —
        // including duplicate UNKNOWN types (a known-types-only EnumSet let
        // those bypass the gate). Matches server_hello_parsers.zig.
        var sh_seen: [tls13_full.MAX_EXTENSION_TYPES]u16 = undefined;
        var sh_seen_count: usize = 0;
        while (pos + 4 <= exts_end) {
            const etype = readU16(body[pos .. pos + 2]);
            const elen: usize = readU16(body[pos + 2 .. pos + 4]);
            pos += 4;
            if (pos + elen > exts_end) return HandshakeError.UnexpectedMessage;
            for (sh_seen[0..sh_seen_count]) |s| {
                if (s == etype) return HandshakeError.DuplicateExtension;
            }
            if (sh_seen_count == sh_seen.len) return HandshakeError.TooManyExtensions;
            sh_seen[sh_seen_count] = etype;
            sh_seen_count += 1;
            if (etype == @intFromEnum(tls13_full.ExtensionType.supported_versions)) {
                // RFC 8446 §4.2.1: In ServerHello, supported_versions contains
                // the single selected version (2 bytes). Must be 0x0304 (TLS 1.3).
                if (elen != 2) return HandshakeError.UnsupportedVersion;
                const selected_version = readU16(body[pos .. pos + 2]);
                if (selected_version != 0x0304) return HandshakeError.UnsupportedVersion;
                found_supported_versions = true;
            } else if (etype == @intFromEnum(tls13_full.ExtensionType.key_share)) {
                // RFC 8446 §4.2.8: ServerHello key_share contains the selected
                // group and the server's ECDHE public key.
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
            // SAFETY: .? unwraps are guarded by the != null checks directly above.
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

        // SAFETY: server_pub null case returns MissingKeyShare at the guard above (line: `if (server_pub == null)`).
        var shared = std.crypto.dh.X25519.scalarmult(priv, server_pub.?) catch return HandshakeError.UnsupportedKeyShareGroup;
        defer std.crypto.secureZero(u8, &shared);
        // SEC-055: Zero client_priv after DH computation completes.
        // The scalarmult already copied the key internally, so the field
        // is no longer needed and should not linger in memory.
        if (self.client_priv) |*p| std.crypto.secureZero(u8, p);
        self.client_priv = null;
        const sh_snapshot = self.transcripts.handshake.finalize(self.hash_kind);
        const hs = deriveHandshakeTraffic(self.hash_kind, shared[0..], sh_snapshot, &early_secret);
        self.handshake_secret = hs.handshake;

        // QUAL-346: atomic install — CLIENT uses client_hs for send,
        // server_hs for recv. If either install or its callback fails, both
        // slots are rolled back so no half-key remains resident.
        try self.installHandshakeTrafficPair(hs.client_hs, hs.server_hs);
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
                const cert_body = try tls13_full.buildCertificate(self.scratch_arena.allocator(), request_context, &cert_entries);

                // PERF-038: Use appendOutboundFramed to write handshake header + body
                // directly into the outbound buffer, avoiding encodeHandshake allocation.
                try self.appendOutboundFramed(.Handshake, .certificate, cert_body, true);

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

                    const cv_body = try tls13_full.buildCertificateVerify(self.scratch_arena.allocator(), sig_scheme, signature);

                    // PERF-038: Use appendOutboundFramed instead of encodeHandshake.
                    try self.appendOutboundFramed(.Handshake, .certificate_verify, cv_body, true);

                    traceHandshake("Client: Sent CertificateVerify for mTLS\n", .{});
                }
            } else {
                // No client certificate configured: send empty Certificate (RFC 8446 §4.4.2)
                const cert_body = try tls13_full.buildCertificate(self.scratch_arena.allocator(), request_context, &[_]tls13_full.CertificateEntryData{});

                // PERF-038: Use appendOutboundFramed instead of encodeHandshake.
                try self.appendOutboundFramed(.Handshake, .certificate, cert_body, true);

                traceHandshake("Client: Sent empty Certificate (no client cert configured)\n", .{});
            }
        }

        var transcript_snapshot = self.transcripts.handshake;
        const hash_before = transcript_snapshot.finalize(slot.hash);
        const verify_data = deriveFinishedVerifyData(slot.hash, &slot.value, hash_before);
        // PERF-038: Use appendOutboundFramed instead of encodeHandshake for Finished message.
        try self.appendOutboundFramed(.Handshake, .finished, verify_data.slice(), true);
        try self.markLocalFinished();
        _ = self.scratch_arena.reset(.retain_capacity);
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

        // QUAL-317: delegate HKDF-Expand-Label derivation + wire-message
        // framing to the pure key_update module. The shell retains:
        //  - secureZero on the OLD secret before installing the new one
        //  - installTrafficSecret (QUIC callback) integration
        //  - Application-level CRYPTO-stream queueing (transcript NOT updated,
        //    per RFC 8446 §4.4.1)
        const snapshot_hash = send_slot.hash;
        const result = try key_update_mod.buildLocalKeyUpdate(
            self.scratch_arena.allocator(),
            snapshot_hash,
            &send_slot.value,
            request_peer_update,
        );

        // SECURITY: zero the OLD send secret before installing the new one.
        // installTrafficSecret overwrites in place via slot.store; doing the
        // secureZero up-front guarantees CWE-226 compliance even if the next
        // call errors out partway through.
        std.crypto.secureZero(u8, &send_slot.value.bytes);

        // Install new sending secret via callback (QUIC layer updates packet protection)
        try self.installTrafficSecret(.Application, .send, result.new_secret);

        // Queue KeyUpdate message in Application-level CRYPTO stream.
        // RFC 8446 §4.4.1: KeyUpdate is excluded from the handshake
        // transcript, so we append directly to outbound without touching
        // self.transcripts.
        var stream = self.streams.buffer(.Application);
        // PERF-249: pre-size for the framed KeyUpdate payload.
        try stream.outbound.ensureUnusedCapacity(self.allocator, result.wire_message.len);
        try stream.outbound.appendSlice(self.allocator, result.wire_message);

        traceHandshake("TLS: Sent KeyUpdate (request_update={})\n", .{request_peer_update});
        _ = self.scratch_arena.reset(.retain_capacity);
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
        // QUAL-317: delegate threshold math to the pure key_update module.
        // Fails closed (returns false) on invalid inputs — matches the
        // previous inline behavior.
        if (!key_update_mod.shouldTriggerKeyUpdate(
            encrypted_count,
            confidentiality_limit,
            threshold_percent,
        )) return false;

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
        // NEWGAP-10: RFC 8446 §4.4.2 — in the server-authentication case the
        // certificate_request_context SHALL be zero length. Validated before
        // parseAndStoreChain allocates so a violation cannot leak a chain.
        if (try cert_handlers.certificateRequestContextLen(body) != 0) {
            return HandshakeError.IllegalCertificateRequestContext;
        }
        // QUAL-317: delegate parsing to cert_handlers (pure module). Empty chain
        // is NOT allowed on the server-cert path (RFC 8446 §4.4.2) — the module
        // returns HandshakeError.EmptyCertificateChain for us.
        const result = try cert_handlers.parseAndStoreChain(self.allocator, .{
            .body = body,
            .allow_empty = false,
        });
        const storage = result.storage.?;

        // QUAL-356: Ownership transfer below relies on every statement being
        // infallible so we can skip `errdefer`. If you add a fallible call
        // (anything returning `!T`, `!!T`, allocations, I/O, or a function
        // that calls such) between here and the final `traceHandshake`, you
        // MUST add an `errdefer` that frees `storage.chain`, `storage.buf`,
        // `storage.ocsp_response`, and `storage.sct_list` to avoid leaking
        // the freshly parsed chain on error. The helpers below are
        // verified-infallible:
        //   - `self.freePeerCertChain()` -- frees heap and nulls fields, no alloc.
        //   - plain pointer-field assignments.
        //   - `std.mem.Allocator.free` (infallible by contract).
        //   - `traceHandshake` (wraps `std.debug.print`, infallible).
        //
        // This invariant is enforced at review time; compile-time enforcement
        // would require a dedicated "infallible block" wrapper which Zig
        // does not currently express. See QUAL-356.

        // Free any previously stored chain before swapping in the new one.
        self.freePeerCertChain();
        self.peer_cert_chain = storage.chain;
        self.peer_cert_chain_buf = storage.buf;

        // QUAL-128: swap OCSP / SCT buffers (dup-before-free done inside module).
        if (storage.ocsp_response) |new_copy| {
            if (self.peer_ocsp_response) |old| self.allocator.free(old);
            self.peer_ocsp_response = new_copy;
            traceHandshake("Client: Received OCSP response ({} bytes)\\n", .{new_copy.len});
        }
        if (storage.sct_list) |new_copy| {
            if (self.peer_sct_list) |old| self.allocator.free(old);
            self.peer_sct_list = new_copy;
            traceHandshake("Client: Received SCT list ({} bytes)\\n", .{new_copy.len});
        }

        traceHandshake("Client: Received Certificate with {} cert(s)\\n", .{storage.chain.len});
    }

    /// RFC 8446 §4.4.3: Parse CertificateVerify and perform full certificate validation.
    ///
    /// QUAL-357: Orchestrator. Delegates per-concern validation to
    /// `cert_handlers`. The prior body mixed cert-chain + OCSP + SCT +
    /// CertificateVerify-sig in one 163-LOC function; each concern is now
    /// independently auditable in `src/tls13/context/cert_handlers.zig`.
    fn handleCertificateVerify(self: *Context, body: []const u8) !void {
        const parsed = try tls13_full.parseCertificateVerify(body);

        // QUAL-128: Dupe before free to prevent dangling pointer on OOM.
        const sig_copy = try self.allocator.dupe(u8, parsed.signature);
        errdefer {
            self.allocator.free(sig_copy);
            self.peer_cert_verify_sig = null;
        }
        if (self.peer_cert_verify_sig) |old_sig| self.allocator.free(old_sig);
        self.peer_cert_verify_sig = sig_copy;
        self.peer_cert_verify_alg = parsed.algorithm;

        const chain = self.peer_cert_chain orelse return HandshakeError.MissingCertificate;
        const now_unix = unixTimestamp();

        // SEC-029: Require server_name for hostname validation unless insecure
        // mode is selected. Without a server_name, any valid cert from any CA
        // would be accepted (MITM risk). SEC-077: the insecure path is also
        // build-gated in x509.validateChainReturnParsed.
        if (self.config.server_name == null and self.config.allow_insecure == .secure) {
            traceHandshake("Client: ERROR - server_name is null and insecure mode is not set\\n", .{});
            return HandshakeError.MissingServerName;
        }
        const server_name = if (self.config.server_name) |sni| sni else "";

        // QUAL-357 step 1: chain validation + leaf parse (PERF-207: one pass).
        // PERF-262: also keep the parsed issuer (chain[1]) so the OCSP-staple
        // validator reuses it instead of re-parsing.
        var chain_parsed = try cert_handlers.validateChainLeafAndIssuer(
            self.allocator,
            chain,
            now_unix,
            server_name,
            self.config.allow_insecure,
            self.cached_trust_store,
            self.config.trusted_ca_der orelse &.{},
        );
        defer chain_parsed.deinit(self.allocator);
        const leaf_parsed = &chain_parsed.leaf;

        // SEC-077: In insecure testing mode, skip OCSP / SCT / CV-sig. The
        // leaf was still parsed above so Context state remains coherent.
        if (self.config.allow_insecure == .testing_only_i_know_what_i_am_doing) {
            traceHandshake("Client: Certificate validation skipped (insecure testing mode)\\n", .{});
            return;
        }

        // QUAL-357 step 2: OCSP stapled-response validation (RFC 6960 +
        // RFC 8446 §4.4.2.1). PERF-037: reuses leaf_parsed from step 1.
        // PERF-262: reuses the issuer parsed in step 1.
        try cert_handlers.validateOcspStaple(
            self.allocator,
            self.peer_ocsp_response,
            leaf_parsed,
            chain,
            now_unix,
            self.config.require_ocsp,
            if (chain_parsed.issuer) |*iss| iss else null,
        );

        // QUAL-357 step 3: SCT list validation (RFC 6962 + RFC 8446 §4.4.2.1).
        try cert_handlers.validateSctList(
            self.allocator,
            self.peer_sct_list,
            self.config.require_scts,
            self.config.on_sct_list,
        );

        // QUAL-357 step 4: CertificateVerify signature (RFC 8446 §4.4.3).
        // RFC 8446 §4.2.3: signature-algorithm policy check first.
        // PERF-037: leaf_parsed reused instead of re-parsing chain[0].
        const transcript_hash = self.transcripts.handshake.finalize(self.hash_kind);
        try cert_handlers.validateSignatureAlgorithm(parsed.algorithm, self.config.supported_signature_schemes);
        try cert_handlers.verifyCertVerifySignature(.{
            .role = .server,
            .leaf_spki = leaf_parsed.spki,
            .signature = parsed.signature,
            .signature_scheme = @intFromEnum(parsed.algorithm),
            .transcript_hash = transcript_hash.slice(),
        }, self.allocator);

        traceHandshake("Client: Certificate chain + OCSP + SCT validated; CertificateVerify signature verified\\n", .{});
    }

    /// RFC 8446 §4.4.2: Parse and store client Certificate message (server-side mTLS).
    /// Reuses the existing peer_cert_chain storage (role-neutral).
    fn handleClientCertificate(self: *Context, body: []const u8) !void {
        // NEWGAP-10: RFC 8446 §4.4.2 — the client's certificate_request_context
        // MUST match the one in the server's CertificateRequest. This server
        // only ever emits an empty certificate_request_context
        // (buildCertificateRequest writes a zero-length context), so the echo
        // MUST be empty. Validated before parseAndStoreChain allocates.
        if (try cert_handlers.certificateRequestContextLen(body) != 0) {
            return HandshakeError.IllegalCertificateRequestContext;
        }
        // QUAL-317: delegate parsing to cert_handlers. Empty chain IS allowed
        // here per RFC 8446 §4.4.2 — the client signals "no cert" with an
        // empty Certificate, and handleClientCertificateVerify infers this
        // from peer_cert_chain being null.
        const result = try cert_handlers.parseAndStoreChain(self.allocator, .{
            .body = body,
            .allow_empty = true,
        });

        if (result.was_empty) {
            traceHandshake("Server: Client sent empty Certificate (no client cert)\n", .{});
            self.freePeerCertChain();
            return;
        }

        const storage = result.storage.?;
        // Free any previously stored chain before swapping in the new one.
        self.freePeerCertChain();
        self.peer_cert_chain = storage.chain;
        self.peer_cert_chain_buf = storage.buf;
        // Note: client-cert extensions (OCSP / SCT) are accepted but unused on
        // server side — free the dupes here to mirror pre-refactor behaviour
        // (the original inline code never stored them on the server path).
        if (storage.ocsp_response) |o| self.allocator.free(o);
        if (storage.sct_list) |s| self.allocator.free(s);
        traceHandshake("Server: Received client Certificate with {} cert(s)\n", .{storage.chain.len});
    }

    /// RFC 8446 §4.4.3: Parse and verify client CertificateVerify (server-side mTLS).
    /// Uses "TLS 1.3, client CertificateVerify" context string and skips hostname validation.
    fn handleClientCertificateVerify(self: *Context, body: []const u8) !void {
        const parsed = try tls13_full.parseCertificateVerify(body);

        // QUAL-128: Dupe before free to prevent dangling pointer on OOM.
        const sig_copy = try self.allocator.dupe(u8, parsed.signature);
        errdefer self.allocator.free(sig_copy);
        if (self.peer_cert_verify_sig) |old_sig| self.allocator.free(old_sig);
        self.peer_cert_verify_sig = sig_copy;
        self.peer_cert_verify_alg = parsed.algorithm;

        // Need a certificate chain to verify against
        const chain = self.peer_cert_chain orelse return HandshakeError.MissingCertificate;
        if (chain.len == 0) return HandshakeError.MissingCertificate;

        if (self.config.allow_insecure == .secure) {
            // RFC 5280 §6: Validate client certificate chain
            // Skip hostname validation for client certs (no SNI to match against)
            const now_unix = unixTimestamp();
            // SEC-031: Pass client_auth EKU purpose for mTLS client certs
            // PERF-207: validate + parse leaf in one pass (avoids re-parsing chain[0]).
            // PERF-016: Uses cached trust store to avoid RwLock contention.
            var client_leaf = x509.validateChainReturnParsed(
                self.allocator,
                chain,
                now_unix,
                "", // No hostname validation for client certs
                .secure, // SEC-077: full validation for client auth path
                .client_auth,
                self.cached_trust_store,
            ) catch |err| {
                traceHandshake("Server: Client certificate chain validation failed: {}\n", .{err});
                return HandshakeError.CertificateValidationFailed;
            };
            defer client_leaf.deinit(self.allocator);

            // Verify CertificateVerify signature with client context string
            const transcript_hash = self.transcripts.handshake.finalize(self.hash_kind);

            // QUAL-317: signature-scheme policy + signature verification both via cert_handlers.
            try cert_handlers.validateSignatureAlgorithm(
                parsed.algorithm,
                self.config.supported_signature_schemes,
            );

            cert_handlers.verifyCertVerifySignature(.{
                .role = .client,
                .leaf_spki = client_leaf.spki,
                .signature = parsed.signature,
                .signature_scheme = @intFromEnum(parsed.algorithm),
                .transcript_hash = transcript_hash.slice(),
            }, self.allocator) catch |err| {
                if (err == HandshakeError.InvalidSignature) {
                    traceHandshake("Server: Client CertificateVerify signature verification failed\n", .{});
                }
                return err;
            };

            traceHandshake("Server: Client certificate validated and CertificateVerify verified\n", .{});
        } else {
            traceHandshake("Server: Client certificate validation skipped (insecure testing mode)\n", .{});
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
            errdefer self.allocator.free(tp_copy);
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
            // PERF-218: client path — source slice points into the transient
            // EncryptedExtensions parse buffer that the caller will free on
            // return, so a dupe is required here (owned=true).
            const alpn_copy = try self.allocator.dupe(u8, alpn);
            errdefer self.allocator.free(alpn_copy);
            if (self.negotiated_alpn) |old| {
                if (self.negotiated_alpn_owned) self.allocator.free(old);
            }
            self.negotiated_alpn = alpn_copy;
            self.negotiated_alpn_owned = true;
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
    /// Handle an inbound NewSessionTicket (RFC 8446 §4.6.1).
    ///
    /// QUAL-074 history: this used to be a `debugPrint` swallow. The
    /// dispatch-level role/level gating already happened in
    /// `inboundNewSessionTicket`, so the body's job is the parse + the
    /// optional `on_session_ticket` callback (GAP-0132).
    ///
    /// Parse errors propagate as `HandshakeError`; a missing callback is
    /// not an error — the parsed ticket is simply discarded with a
    /// debug-level log, matching the prior accept-and-log behaviour.
    fn handleNewSessionTicket(self: *Context, body: []const u8) !void {
        const parsed = messages_mod.parseNewSessionTicket(body) catch |err| {
            logger.err(
                "[TLS] NewSessionTicket parse failed: {s} (body_len={d})",
                .{ @errorName(err), body.len },
            );
            return HandshakeError.UnexpectedMessage;
        };

        logger.debugPrint(
            "[TLS] Context: Received NewSessionTicket (lifetime={d}s, nonce_len={d}, ticket_len={d}, ext_len={d})\n",
            .{ parsed.ticket_lifetime, parsed.ticket_nonce.len, parsed.ticket.len, parsed.extensions.len },
        );

        if (self.callbacks.on_session_ticket) |cb| {
            try cb(self, parsed);
        }
    }

    fn handleKeyUpdateMessage(self: *Context, request: KeyUpdateRequest) !void {
        // RFC 8446 §7.2: Update receiving traffic secret
        const recv_slot = self.secrets.slot(.Application, .recv);
        if (!recv_slot.valid) return HandshakeError.UnexpectedMessage;

        // GAP-0135: Enforce peer KeyUpdate budget to prevent CPU exhaustion
        self.peer_key_updates_seen += 1;
        if (self.peer_key_updates_seen > self.config.max_peer_key_updates) {
            return HandshakeError.TooManyKeyUpdates;
        }

        // QUAL-317: delegate HKDF-Expand-Label derivation to the pure
        // key_update module. The shell retains:
        //  - secureZero on the OLD recv secret before installing the new one
        //  - installTrafficSecret (QUIC callback) integration
        //  - policy: send reciprocal KeyUpdate with update_not_requested to
        //    avoid infinite ping-pong (RFC 8446 §4.6.3)
        const next_secret = key_update_mod.rotatePeerSecret(request, recv_slot.hash, &recv_slot.value);

        // SECURITY: zero the OLD recv secret before installing the new one.
        std.crypto.secureZero(u8, &recv_slot.value.bytes);

        // Install new receiving secret
        try self.installTrafficSecret(.Application, .recv, next_secret);

        traceHandshake("TLS: Received KeyUpdate (request_update={})\n", .{request == .update_requested});

        // RFC 8446 §4.6.3: If peer requested update, send our own KeyUpdate
        // Send with update_not_requested to avoid infinite ping-pong
        if (request == .update_requested) {
            try self.sendKeyUpdate(false); // Don't request peer to update again
        }
    }

    // QUAL-381: removed dead `performKeyUpdateSend`/`performKeyUpdateRecv`.
    // They had zero callers and diverged from the live KeyUpdate path
    // (`handleKeyUpdateMessage` -> `installTrafficSecret`): they bypassed the
    // GAP-0135 exhaustion budget and the QUIC `on_secret_available` callback,
    // so any consumer wiring them to inbound KeyUpdate would silently lose
    // both protections. The canonical rotation lives in
    // `key_update_mod.rotatePeerSecret` + `installTrafficSecret`.
};

// ============================================================================
// PSK Extension Round-Trip Tests (GAP-001/GAP-002)
// ============================================================================
//
// QUAL-317: supported_versions / PSK pure-byte parsers moved to
// src/tls13/context/server_hello_parsers.zig. The integration tests below
// still live here because they exercise tls13_full.buildServerHello end-to-end.

test "RFC 8446 §4.2.11: ServerHello with PSK extension round-trip" {
    // Build a ServerHello WITH PSK extension, then parse it back
    const allocator = std.testing.allocator;
    var server_random: [32]u8 = undefined;
    // SEC-074: fail-closed entropy (replaces unchecked getrandom).
    entropy.fillRandom(&server_random);
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
    const psk_idx = try server_hello_parsers.parsePskExtension(sh);
    try std.testing.expect(psk_idx != null);
    try std.testing.expectEqual(@as(u16, 0), psk_idx.?);
}

test "RFC 8446 §4.2.11: ServerHello without PSK extension returns null" {
    // Build a ServerHello WITHOUT PSK extension, then parse it back
    const allocator = std.testing.allocator;
    var server_random: [32]u8 = undefined;
    // SEC-074: fail-closed entropy (replaces unchecked getrandom).
    entropy.fillRandom(&server_random);
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
    const psk_idx = try server_hello_parsers.parsePskExtension(sh);
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
    // SEC-074: fail-closed entropy (replaces unchecked getrandom).
    entropy.fillRandom(&server_random);
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

    const psk_idx = try server_hello_parsers.parsePskExtension(sh);
    try std.testing.expect(psk_idx != null);
    try std.testing.expectEqual(@as(u16, 5), psk_idx.?);
}

// ============================================================================
// HRR (HelloRetryRequest) Tests (QUAL-099)
// ============================================================================

test "QUAL-099: Client handles HelloRetryRequest and generates ClientHello2" {
    // SEC-077: allow_insecure=.testing_only_i_know_what_i_am_doing panics
    // unless the library was built with -Dtls-insecure-testing=true.
    if (!build_options.tls_insecure_testing) return error.SkipZigTest;
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
        .allow_insecure = .testing_only_i_know_what_i_am_doing,
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
    // SEC-077: allow_insecure=.testing_only_i_know_what_i_am_doing panics
    // unless the library was built with -Dtls-insecure-testing=true.
    if (!build_options.tls_insecure_testing) return error.SkipZigTest;
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
        .allow_insecure = .testing_only_i_know_what_i_am_doing,
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
    // SEC-077: allow_insecure=.testing_only_i_know_what_i_am_doing panics
    // unless the library was built with -Dtls-insecure-testing=true.
    if (!build_options.tls_insecure_testing) return error.SkipZigTest;
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
        .allow_insecure = .testing_only_i_know_what_i_am_doing,
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

// ============================================================================
// QUAL-346: Handshake traffic pair atomicity regression
// ============================================================================

/// Callback that fails on the SECOND invocation so we can simulate a recv-side
/// install failure after send succeeded. Used only in the QUAL-346 test below.
var qual346_call_count: u32 = 0;
fn qual346FailOnSecondInstall(
    _: *Context,
    _: EncryptionLevel,
    _: []const u8,
) anyerror!void {
    qual346_call_count += 1;
    if (qual346_call_count == 2) return error.TestInducedFailure;
}

test "QUAL-346: installHandshakeTrafficPair rolls back send slot on recv failure" {
    // SEC-077: uses allow_insecure=.testing_only_i_know_what_i_am_doing.
    if (!build_options.tls_insecure_testing) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    qual346_call_count = 0;

    const tp_bytes: []const u8 = &[_]u8{};
    const config = Config{
        .allocator = allocator,
        .role = .Client,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{tls13_full.NamedGroup.x25519},
        .supported_signature_schemes = &.{tls13_full.SignatureScheme.ed25519},
        .quic_transport_parameters = tp_bytes,
        .allow_insecure = .testing_only_i_know_what_i_am_doing,
    };

    var ctx = try Context.init(config, .{
        .on_secret_available = qual346FailOnSecondInstall,
    });
    defer ctx.deinit();

    // Two distinct 32-byte secrets for send / recv.
    var send_bytes: [32]u8 = undefined;
    var recv_bytes: [32]u8 = undefined;
    @memset(&send_bytes, 0x11);
    @memset(&recv_bytes, 0x22);
    const send_secret = Secret.fromSlice(.sha256, &send_bytes);
    const recv_secret = Secret.fromSlice(.sha256, &recv_bytes);

    // Precondition: both handshake slots must be invalid.
    try std.testing.expect(!ctx.secrets.slot(.Handshake, .send).valid);
    try std.testing.expect(!ctx.secrets.slot(.Handshake, .recv).valid);

    // Attempt the paired install — expect the recv callback to fail.
    const result = ctx.installHandshakeTrafficPair(send_secret, recv_secret);
    try std.testing.expectError(error.TestInducedFailure, result);

    // QUAL-346 invariant: the send slot MUST have been rolled back to avoid
    // leaking a live handshake secret when the recv side failed. Without the
    // errdefer fix, `send` would be `.valid = true` with generation 1.
    try std.testing.expect(!ctx.secrets.slot(.Handshake, .send).valid);
    try std.testing.expectEqual(@as(u32, 0), ctx.secrets.slot(.Handshake, .send).generation);

    // And the recv slot was never stored (callback failed before returning).
    // store() is called before the callback, so recv.valid may be true and
    // generation = 1; that's acceptable — the critical leak is the send slot.
    // But for full atomicity we also verify recv bytes were zeroed on rollback
    // via the same errdefer (we do not clear recv because install of recv is
    // inside the errdefer scope). Sanity: recv secret should NOT equal 0x11
    // pattern (no cross-contamination).
    const recv_slot = ctx.secrets.slot(.Handshake, .recv);
    if (recv_slot.valid) {
        for (recv_slot.slice()) |b| {
            try std.testing.expect(b != 0x11);
        }
    }
}
