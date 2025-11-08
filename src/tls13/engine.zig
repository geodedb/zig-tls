//! TLS 1.3 Engine - Legacy Minimal Driver
//!
//! This module provides the Engine struct, a simplified TLS 1.3 driver for testing.
//!
//! # Status: LEGACY
//!
//! The Engine struct is a legacy implementation being gradually migrated to Context.
//! New code should use Context from context.zig instead.
//!
//! # RFC References
//! - **RFC 8446 §4**: Handshake Protocol (minimal subset)
//! - **RFC 9001 §4**: QUIC-TLS integration
//!
//! # Architecture
//!
//! Engine provides a minimal TLS 1.3 handshake flow with:
//! - Simplified message parsing (minimal vs. standard format)
//! - Basic transcript hash management
//! - X25519 ECDHE key agreement
//! - Traffic secret derivation
//! - Test-friendly configuration
//!
//! Unlike Context, Engine:
//! - Supports both minimal and standard message formats
//! - Has simpler error handling
//! - Lacks full certificate validation
//! - Is primarily used in unit tests
//!
//! # Migration Path
//!
//! Engine is being phased out in favor of Context. Tests should gradually
//! migrate to Context for better RFC compliance and real-world interoperability.

const std = @import("std");
const ks = @import("quic_tls");
const x509 = @import("x509");
const sig = @import("sig");
const tls13_full = @import("tls13_full");
const alert_mod = @import("alert");
const logger = @import("quic_logger");
const ocsp = @import("ocsp");
const sct = @import("sct");

// Import modularized tls13 types
const types = @import("types.zig");
const config_mod = @import("config.zig");
const handshake_state_mod = @import("handshake_state.zig");
const secrets_mod = @import("secrets.zig");
const transcript_mod = @import("transcript.zig");
const key_derivation_mod = @import("key_derivation.zig");
const messages_mod = @import("messages.zig");
const finished_mod = @import("finished.zig");

// Note: The extracted code below contains its own type and function definitions
// These were not fully extracted in Phase 1, so they remain here.

// Local type aliases from modularized modules
const Role = types.Role;
const Transcript = transcript_mod.Transcript;
const encodeHandshake = messages_mod.encodeHandshake;
const parseHandshakeOne = messages_mod.parseHandshakeOne;
const HsType = messages_mod.HsType;
const deriveHandshakeTraffic = key_derivation_mod.deriveHandshakeTraffic;
const deriveApplicationTraffic = key_derivation_mod.deriveApplicationTraffic;
const deriveFinishedVerifyData = finished_mod.deriveFinishedVerifyData;
// Note: x25519KeypairAndShared, encodeMinimalClientHello, encodeMinimalServerHello,
// and parseMinimalHelloPub are defined in the extracted code below

// Standard library type aliases
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Hash = ks.Hash;
const Secret = ks.Secret;
const max_digest_length = ks.max_digest_length;
const Sha256 = std.crypto.hash.sha2.Sha256;

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

// Helper types (may be referenced by Engine)
pub const TicketEntry = struct {
    identity: []u8,
    secret: Secret,
    lifetime: u32,
};

pub const TicketEntryView = struct {
    identity: []const u8,
    secret: Secret,
    lifetime: u32,
};

pub const TicketStore = struct {
    tickets: ArrayListUnmanaged(TicketEntry) = .{},
    allocator: std.mem.Allocator = undefined,

    pub fn init(allocator: std.mem.Allocator) TicketStore {
        return .{ .allocator = allocator, .tickets = .{} };
    }

    pub fn deinit(self: *TicketStore) void {
        for (self.tickets.items) |*t| {
            self.allocator.free(t.identity);
        }
        self.tickets.deinit(self.allocator);
    }

    pub fn store(self: *TicketStore, identity: []const u8, secret: Secret, lifetime: u32) !void {
        const ident_copy = try self.allocator.dupe(u8, identity);
        try self.tickets.append(self.allocator, .{
            .identity = ident_copy,
            .secret = secret,
            .lifetime = lifetime,
        });
    }

    pub fn lookup(self: *const TicketStore, identity: []const u8) ?TicketEntryView {
        for (self.tickets.items) |*t| {
            if (std.mem.eql(u8, t.identity, identity)) {
                return .{ .identity = t.identity, .secret = t.secret, .lifetime = t.lifetime };
            }
        }
        return null;
    }
};

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
    hash_kind: Hash = .sha256,
    finished_sent: bool = false,
    finished_verified: bool = false,
    /// Whether EncryptedExtensions has been sent (server) or received (client) in real mode
    ee_sent: bool = false,
    /// Whether the server has already staged its complete handshake flight in the outbox
    server_handshake_flight_enqueued: bool = false,
    /// Cached intermediate handshake_secret (used to derive master_secret). Cached to avoid recomputing from ECDHE.
    /// RFC 8446 §7.1: handshake_secret = HKDF-Extract(Derive-Secret(early_secret, "derived", ""), ECDHE)
    /// This prevents bugs from ECDHE buffer corruption/reuse when deriving application secrets.
    handshake_secret: ?Secret = null,
    /// Stored handshake traffic secrets (derived immediately after SH) for correct Finished verification
    handshake_client_secret: ?Secret = null,
    handshake_server_secret: ?Secret = null,
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
    master_secret: ?Secret = null,
    /// Cached application traffic secrets (computed once with correct transcript, before adding peer Finished).
    /// This prevents recomputation with wrong transcript after both Finisheds are added.
    cached_app_client: ?Secret = null,
    cached_app_server: ?Secret = null,
    /// Stored resumption tickets (very small cache FIFO). Each entry keeps identity and resumption_secret.
    tickets: TicketStore = .{},
    /// Optional callback invoked whenever the peer Finished verification state changes.
    peer_finished_cb: ?PeerFinishedCallback = null,
    peer_finished_ctx: ?*anyopaque = null,

    const PeerFinishedCallback = *const fn (ctx: ?*anyopaque, engine: *Engine, verified: bool) anyerror!void;

    /// Initialize a TLS 1.3 Engine with allocator and role.
    pub fn init(alloc: std.mem.Allocator, role: Role) Engine {
        return .{ .role = role, .allocator = alloc, .transcript = Transcript.init(), .ecdhe_secret = null, .ecdhe_buf = undefined, .my_priv = null, .my_pub = null, .peer_pub = null, .client_session_id = null, .outbox = std.ArrayList(u8){}, .inbox = std.ArrayList(u8){}, .handshake_failed = false, .ch_sent = false, .ch_recv = false, .sh_seen = false, .allow_insecure = true, .peer_cert_ok = false, .hash_kind = .sha256, .finished_sent = false, .finished_verified = false, .ee_sent = false, .server_handshake_flight_enqueued = false, .handshake_secret = null, .handshake_client_secret = null, .handshake_server_secret = null, .leaf_spki = null, .local_tp = null, .peer_tp = null, .alpn = null, .server_name = null, .server_cert_der = null, .server_priv_key = null, .server_sig_alg = null, .master_secret = null, .cached_app_client = null, .cached_app_server = null, .tickets = .{}, .peer_finished_cb = null, .peer_finished_ctx = null };
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
        traceHandshake("TLS: updateFinishedVerified called: value={}, role={s}, current={}\n", .{ value, if (self.role == .Server) "Server" else "Client", self.finished_verified });
        if (self.finished_verified == value) {
            traceHandshake("TLS: finished_verified already set to {}, skipping\n", .{value});
            return;
        }
        self.finished_verified = value;
        traceHandshake("TLS: Set finished_verified={}\n", .{value});
        if (self.peer_finished_cb) |cb| {
            traceHandshake("TLS: Calling peer_finished_cb callback\n", .{});
            cb(self.peer_finished_ctx, self, value) catch {};
        } else {
            traceHandshake("TLS: No peer_finished_cb registered\n", .{});
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
            // Clamp the private key per RFC 7748 §5 to ensure interoperability
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
            // Derive public key from private key using Zig 0.15.1 X25519 API
            const pk = std.crypto.dh.X25519.recoverPublicKey(sk) catch unreachable;
            self.my_priv = sk;
            self.my_pub = pk;
            if (secret_trace_enabled) {
                traceSecrets("{s}: Generated X25519 keypair\n", .{if (self.role == .Server) "Server" else "Client"});
                traceSecrets("    priv: ", .{});
                for (sk) |b| traceSecrets("{X:0>2}", .{b});
                traceSecrets("\n", .{});
                traceSecrets("    pub: ", .{});
                for (pk) |b| traceSecrets("{X:0>2}", .{b});
                traceSecrets("\n", .{});
            }
        }
    }

    fn tryComputeShared(self: *Engine) void {
        if (self.peer_pub) |peer| {
            if (self.my_priv) |priv| {
                // Use Zig 0.15.1 X25519 API - scalarmult returns the value
                const sh = std.crypto.dh.X25519.scalarmult(priv, peer) catch {
                    traceHandshake("{s}: X25519 scalarmult failed\n", .{if (self.role == .Server) "Server" else "Client"});
                    return;
                };
                self.ecdhe_buf = sh;
                self.ecdhe_secret = self.ecdhe_buf[0..];
                if (secret_trace_enabled) {
                    traceSecrets("{s}: Computed ECDHE shared secret ({X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}...)\n", .{ if (self.role == .Server) "Server" else "Client", sh[0], sh[1], sh[2], sh[3], sh[4], sh[5], sh[6], sh[7] });
                }
            } else {
                traceHandshake("{s}: No my_priv for ECDHE\n", .{if (self.role == .Server) "Server" else "Client"});
            }
        } else {
            traceHandshake("{s}: No peer_pub for ECDHE\n", .{if (self.role == .Server) "Server" else "Client"});
        }
    }

    /// Append received CRYPTO bytes into transcript. Attempts to parse handshake messages
    /// to update simple state, but always feeds the transcript with raw bytes.
    pub fn onCryptoRecv(self: *Engine, data: []const u8) void {
        traceHandshake("TLS: onCryptoRecv called with {} bytes, inbox already has {} bytes\n", .{ data.len, self.inbox.items.len });

        // Append new data to inbox buffer
        self.inbox.appendSlice(self.allocator, data) catch {
            traceHandshake("TLS: Failed to buffer CRYPTO data\n", .{});
            return;
        };

        traceHandshake("TLS: Inbox now has {} bytes total\n", .{self.inbox.items.len});

        // Process complete messages from the buffered data
        var off: usize = 0;
        while (true) {
            const parsed = parseHandshakeOne(self.inbox.items[off..]) catch null;
            if (parsed) |p| {
                traceHandshake("TLS: Parsed handshake message type={} len={}\n", .{ p.typ, p.body.len });

                // For Finished verification, we need the transcript BEFORE the Finished message
                // So take a snapshot of the current transcript state
                var snap = self.transcript;
                const th_before = snap.finalize(self.hash_kind);

                // Update the transcript with this message UNLESS it's a Finished message
                // Finished messages are added to the transcript AFTER verification
                const msg_data = self.inbox.items[off .. off + p.n];
                if (p.typ != .finished) {
                    self.transcript.update(msg_data);
                    const show_len = @min(8, msg_data.len);
                    if (show_len >= 8) {
                        traceHandshake("[TRANSCRIPT-RECV] Added {} bytes to transcript (recv): {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} ...\n", .{ msg_data.len, msg_data[0], msg_data[1], msg_data[2], msg_data[3], msg_data[4], msg_data[5], msg_data[6], msg_data[7] });
                    } else {
                        traceHandshake("[TRANSCRIPT-RECV] Added {} bytes to transcript (recv)\n", .{msg_data.len});
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
                    const th_secret = snapshot.finalize(self.hash_kind);
                    const th_hash = th_secret.slice();
                    if (secret_trace_enabled and th_hash.len >= 4) {
                        traceSecrets("onCryptoRecv: Deriving handshake secrets after ServerHello\n", .{});
                        traceSecrets("onCryptoRecv: Transcript hash for handshake: {X:0>2} {X:0>2} {X:0>2} {X:0>2} ... (first 4 of {})\n", .{ th_hash[0], th_hash[1], th_hash[2], th_hash[3], th_hash.len });
                        traceSecrets("onCryptoRecv: ECDHE secret first 4: {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ self.ecdhe_secret.?[0], self.ecdhe_secret.?[1], self.ecdhe_secret.?[2], self.ecdhe_secret.?[3] });
                    }
                    const hs = deriveHandshakeTraffic(self.hash_kind, self.ecdhe_secret.?, th_secret);
                    const client_slice = hs.client_hs.slice();
                    const server_slice = hs.server_hs.slice();
                    if (secret_trace_enabled and client_slice.len >= 4 and server_slice.len >= 4) {
                        traceSecrets("onCryptoRecv: Derived client_hs first 4: {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ client_slice[0], client_slice[1], client_slice[2], client_slice[3] });
                        traceSecrets("onCryptoRecv: Derived server_hs first 4: {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ server_slice[0], server_slice[1], server_slice[2], server_slice[3] });
                    }
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
                    traceHandshake("TLS: Processing hello message, typ={}\n", .{p.typ});
                    var extracted: ?[32]u8 = null;
                    // Try real TLS 1.3 parsing first
                    traceHandshake("TLS: Trying real TLS 1.3 hello parsing\n", .{});
                    switch (p.typ) {
                        .client_hello => {
                            traceHandshake("TLS: Calling parseRealClientHello with {} bytes\n", .{p.body.len});
                            extracted = parseRealClientHello(p.body, self);
                            if (extracted != null) {
                                traceHandshake("TLS: parseRealClientHello SUCCESS - extracted key\n", .{});
                            } else {
                                traceHandshake("TLS: parseRealClientHello FAILED - returned null\n", .{});
                            }
                        },
                        .server_hello => extracted = parseRealServerHello(p.body),
                        else => {},
                    }
                    // If real parsing failed, try minimal format as fallback
                    if (extracted == null) {
                        traceHandshake("TLS: Real parse failed, trying minimal parse as fallback\n", .{});
                        extracted = parseMinimalHelloPub(p.typ, p.body);
                        if (extracted == null) {
                            traceHandshake("{s}: Failed to parse hello pub (typ={}, body_len={})\n", .{ if (self.role == .Server) "Server" else "Client", p.typ, p.body.len });
                        }
                    }
                    if (extracted) |pk| {
                        traceHandshake("TLS: Setting peer_pub for {} (was null={})\n", .{ p.typ, self.peer_pub == null });
                        self.peer_pub = pk;
                        traceHandshake("TLS: peer_pub is now set (null={})\n", .{self.peer_pub == null});
                        // Compute shared secret after receiving peer's public key
                        switch (p.typ) {
                            .server_hello => if (self.role == .Client) self.tryComputeShared(),
                            .client_hello => if (self.role == .Server) {
                                traceHandshake("Server: Will compute ECDHE when generating ServerHello\n", .{});
                                // Extract ALPN from ClientHello
                                self.extractAlpnFromClientHello(p.body);
                            },
                            else => {},
                        }
                    } else {
                        traceHandshake("TLS: No key extracted from hello message\n", .{});
                    }
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
                        traceHandshake("TLS: Missing transport parameters in ClientHello (RFC 9001 violation)\n", .{});
                        // Mark connection as failed - upper layer should close connection
                        self.handshake_failed = true;
                        return;
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
                            traceHandshake("TLS: Missing transport parameters in EncryptedExtensions (RFC 9001 violation)\n", .{});
                            // Mark connection as failed - upper layer should close connection
                            self.handshake_failed = true;
                            return;
                        }
                    }
                }
                // Certificate message parsing: RFC 8446 Section 4.4.2
                if (p.typ == .certificate) {
                    traceHandshake("{s}: Processing Certificate message (len={})\n", .{ if (self.role == .Server) "Server" else "Client", p.body.len });
                    if (self.allow_insecure) {
                        traceHandshake("{s}: Certificate validation skipped (insecure mode)\n", .{if (self.role == .Server) "Server" else "Client"});
                        self.peer_cert_ok = true;
                    } else {
                        traceHandshake("{s}: Attempting certificate validation\n", .{if (self.role == .Server) "Server" else "Client"});
                        self.peer_cert_ok = false;

                        const parsed_cert_msg_opt = blk_parsed_cert: {
                            const msg = tls13_full.parseCertificate(self.allocator, p.body) catch |err| {
                                traceHandshake("TLS: Failed to parse Certificate message structure: {}\n", .{err});
                                break :blk_parsed_cert null;
                            };
                            break :blk_parsed_cert msg;
                        };

                        if (parsed_cert_msg_opt) |parsed_cert_msg| {
                            defer self.allocator.free(parsed_cert_msg.entries);

                            if (parsed_cert_msg.entries.len == 0) {
                                traceHandshake("TLS: Certificate list empty\n", .{});
                            } else {
                                if (self.leaf_spki) |old| {
                                    self.allocator.free(old);
                                    self.leaf_spki = null;
                                }

                                const validation_ok = blk: {
                                    var chain_der = self.allocator.alloc([]const u8, parsed_cert_msg.entries.len) catch {
                                        traceHandshake("TLS: Out of memory allocating certificate chain view\n", .{});
                                        break :blk false;
                                    };
                                    defer self.allocator.free(chain_der);

                                    var parsed_certs = self.allocator.alloc(x509.Certificate, parsed_cert_msg.entries.len) catch {
                                        traceHandshake("TLS: Out of memory allocating parsed certificate array\n", .{});
                                        break :blk false;
                                    };
                                    defer self.allocator.free(parsed_certs);

                                    for (parsed_cert_msg.entries, 0..) |entry, idx| {
                                        chain_der[idx] = entry.cert;
                                        parsed_certs[idx] = x509.parseCert(self.allocator, entry.cert) catch {
                                            traceHandshake("TLS: Failed to parse certificate {} in chain\n", .{idx});
                                            break :blk false;
                                        };
                                    }

                                    const leaf = parsed_certs[0];
                                    const leaf_entry = parsed_cert_msg.entries[0];
                                    self.leaf_spki = self.allocator.dupe(u8, leaf.spki) catch {
                                        traceHandshake("TLS: Out of memory duplicating leaf SPKI\n", .{});
                                        break :blk false;
                                    };

                                    const now = std.time.timestamp();
                                    const server_name_slice: []const u8 = if (self.server_name) |sni| sni else &[_]u8{};

                                    x509.validateChain(self.allocator, chain_der, now, server_name_slice, self.allow_insecure) catch |err| {
                                        traceHandshake("TLS: Certificate chain validation failed: {}\n", .{err});
                                        break :blk false;
                                    };

                                    if (leaf.eku) |eku| {
                                        if (!eku.server_auth) {
                                            traceHandshake("TLS: Leaf certificate missing serverAuth EKU\n", .{});
                                            break :blk false;
                                        }
                                    }

                                    if (leaf_entry.ocsp_response) |ocsp_bytes| {
                                        if (parsed_cert_msg.entries.len >= 2) {
                                            const issuer_info: ocsp.IssuerInfo = .{ .cert = &parsed_certs[1], .der = chain_der[1] };
                                            ocsp.validateStapledResponse(self.allocator, ocsp_bytes, &leaf, chain_der[0], issuer_info, now) catch |err| {
                                                traceHandshake("TLS: OCSP validation failed: {}\n", .{err});
                                                break :blk false;
                                            };
                                        } else {
                                            ocsp.validateStapledResponse(self.allocator, ocsp_bytes, &leaf, chain_der[0], null, now) catch |err| {
                                                traceHandshake("TLS: OCSP validation failed: {}\n", .{err});
                                                break :blk false;
                                            };
                                        }
                                    }

                                    if (leaf_entry.sct_list) |sct_bytes| {
                                        if (sct.parseList(self.allocator, sct_bytes)) |parsed_scts| {
                                            self.allocator.free(parsed_scts);
                                        } else |err| {
                                            traceHandshake("TLS: Failed to parse SCT list: {} (non-fatal)\n", .{err});
                                        }
                                    }

                                    break :blk true;
                                };

                                self.peer_cert_ok = validation_ok;
                            }
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
                                        traceHandshake("TLS: Unknown SignatureScheme: 0x{X:0>4}\n", .{scheme_value});
                                        self.peer_cert_ok = false;
                                        break :blk .rsa_pss_sha256;
                                    },
                                };
                                if (self.peer_cert_ok) { // Only verify if not already failed
                                    const ok = sig.verifyCertificateVerify(alg, self.leaf_spki.?, signature, "TLS 1.3, server CertificateVerify", th.slice()) catch false;
                                    self.peer_cert_ok = ok;
                                    if (!ok) {
                                        traceHandshake("TLS: CertificateVerify signature verification FAILED\n", .{});
                                    }
                                }
                            } else {
                                traceHandshake("TLS: CertificateVerify message too short for declared signature length\n", .{});
                                self.peer_cert_ok = false;
                            }
                        } else {
                            traceHandshake("TLS: CertificateVerify message too short (len={})\n", .{p.body.len});
                            self.peer_cert_ok = false;
                        }
                    }
                }
                // Finished verification
                if (p.typ == .finished and self.ecdhe_secret != null) {
                    traceHandshake("TLS: Processing Finished message\n", .{});
                    var peer_secret_opt: ?Secret = null;
                    if (self.handshake_client_secret != null and self.handshake_server_secret != null) {
                        peer_secret_opt = switch (self.role) {
                            .Client => self.handshake_server_secret.?,
                            .Server => self.handshake_client_secret.?,
                        };
                        traceHandshake("TLS: Using stored handshake secrets for verification\n", .{});
                    }
                    const ok = if (peer_secret_opt) |ps| self.verifyPeerFinished(ps, p.body) else blk: {
                        traceHandshake("TLS: Using fallback for Finished verification\n", .{});
                        // Fallback (should not happen in real mode past this point)
                        const hs = deriveHandshakeTraffic(self.hash_kind, self.ecdhe_secret.?, th_before);
                        self.handshake_secret = hs.handshake; // Cache intermediate handshake_secret
                        self.handshake_client_secret = hs.client_hs;
                        self.handshake_server_secret = hs.server_hs;
                        break :blk switch (self.role) {
                            .Client => self.verifyPeerFinished(hs.server_hs, p.body),
                            .Server => self.verifyPeerFinished(hs.client_hs, p.body),
                        };
                    };
                    traceHandshake("TLS: Finished verification result: {}\n", .{ok});
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
                                traceHandshake("TLS: Added server Finished to transcript ({} bytes): {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} ...\n", .{ finished_msg.len, finished_msg[0], finished_msg[1], finished_msg[2], finished_msg[3], finished_msg[4], finished_msg[5], finished_msg[6], finished_msg[7] });
                            } else {
                                traceHandshake("TLS: Added server Finished to transcript ({} bytes)\n", .{finished_msg.len});
                            }

                            // Now derive application secrets with server Finished included
                            traceHandshake("TLS: Deriving application traffic secrets (after adding server Finished to transcript)\n", .{});
                            _ = self.computeApplicationSecrets();
                        } else {
                            // Server: Derive app secrets BEFORE adding client's Finished
                            // Server's own Finished is already in transcript from queueFinished()
                            traceHandshake("TLS: Deriving application traffic secrets (before adding client Finished to transcript)\n", .{});
                            _ = self.computeApplicationSecrets();

                            // NOW add the client Finished to transcript for resumption master secret derivation
                            self.transcript.update(finished_msg);
                            const show_len = @min(8, finished_msg.len);
                            if (show_len >= 8) {
                                traceHandshake("TLS: Added client Finished to transcript ({} bytes): {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} ...\n", .{ finished_msg.len, finished_msg[0], finished_msg[1], finished_msg[2], finished_msg[3], finished_msg[4], finished_msg[5], finished_msg[6], finished_msg[7] });
                            } else {
                                traceHandshake("TLS: Added client Finished to transcript ({} bytes)\n", .{finished_msg.len});
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
                            // RFC 8446 Section 4.6.1: resumption_master_secret = HKDF-Expand-Label(
                            //     master_secret, "res master", transcript_hash)
                            var transcript_snapshot = self.transcript;
                            const transcript_hash = transcript_snapshot.finalize(self.hash_kind);
                            var master_local = ms;
                            const res_secret = ks.deriveSecretHash(self.hash_kind, &master_local, "res master", transcript_hash.slice());
                            self.tickets.add(self.allocator, ticket_bytes, res_secret, lifetime) catch {};
                            traceHandshake("TLS: Stored session ticket (len={}, lifetime={})\n", .{ ticket_bytes.len, lifetime });
                        } else {
                            traceHandshake("TLS: Received ticket before master_secret ready; ignoring\n", .{});
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
            var snap = self.transcript;
            const th = snap.finalize(self.hash_kind);
            const hs = deriveHandshakeTraffic(self.hash_kind, shared, th);
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
        const suites = &[_]tls13_full.CipherSuite{
            tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256,
            tls13_full.CipherSuite.TLS_AES_256_GCM_SHA384,
            tls13_full.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        };
        const suites_len: u16 = @intCast(suites.len * 2);
        try body.appendSlice(self.allocator, &.{ @intCast(suites_len >> 8), @intCast(suites_len & 0xff) });
        for (suites) |suite| {
            const value: u16 = @intFromEnum(suite);
            try body.appendSlice(self.allocator, &.{ @intCast(value >> 8), @intCast(value & 0xff) });
        }
        // compression methods
        try body.appendSlice(self.allocator, &.{ 0x01, 0x00 });
        var ext_buf = std.ArrayList(u8){};
        defer ext_buf.deinit(self.allocator);
        // supported_versions
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });
        // supported_groups (x25519)
        try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });
        // signature_algorithms
        const sigs = &[_]tls13_full.SignatureScheme{
            tls13_full.SignatureScheme.ed25519,
            tls13_full.SignatureScheme.ecdsa_secp256r1_sha256,
            tls13_full.SignatureScheme.ecdsa_secp384r1_sha384,
            tls13_full.SignatureScheme.rsa_pss_rsae_sha256,
        };
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
        try ext_buf.appendSlice(self.allocator, pubkey[0..]);
        // ALPN
        if (self.alpn) |alpn_protocol| {
            const names_len: usize = 1 + alpn_protocol.len;
            const list_len: u16 = @intCast(names_len);
            const ext_len: u16 = list_len + 2;
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x10, @intCast(ext_len >> 8), @intCast(ext_len & 0xff), @intCast(list_len >> 8), @intCast(list_len & 0xff) });
            try ext_buf.append(self.allocator, @intCast(alpn_protocol.len));
            try ext_buf.appendSlice(self.allocator, alpn_protocol);
        }
        // QUIC transport parameters (client sends its TP in CH)
        if (self.local_tp) |tp| {
            const tp_len: u16 = @intCast(tp.len);
            try ext_buf.appendSlice(self.allocator, &.{ 0x00, 0x39, @intCast(tp_len >> 8), @intCast(tp_len & 0xff) });
            try ext_buf.appendSlice(self.allocator, tp);
        }
        // finalize extensions
        const exts_len: u16 = @intCast(ext_buf.items.len);
        try body.appendSlice(self.allocator, &.{ @intCast(exts_len >> 8), @intCast(exts_len & 0xff) });
        try body.appendSlice(self.allocator, ext_buf.items);
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
    pub fn queueFinished(self: *Engine, traffic_secret: Secret) !void {
        var snap = self.transcript;
        const th = snap.finalize(self.hash_kind);
        const th_slice = th.slice();
        if (th_slice.len >= 8) {
            std.debug.print("TLS: Queueing Finished with transcript hash: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} ...\n", .{ th_slice[0], th_slice[1], th_slice[2], th_slice[3], th_slice[4], th_slice[5], th_slice[6], th_slice[7] });
        }
        const verify = deriveFinishedVerifyData(self.hash_kind, &traffic_secret, th);
        const msg = try encodeHandshake(self.allocator, .finished, verify.slice());
        defer self.allocator.free(msg);
        try self.queueCrypto(msg);
        self.finished_sent = true;
        // NOTE: Application secrets are NOT derived here
        // They must be derived AFTER receiving and verifying the peer's Finished message
    }

    /// Verify peer Finished given peer traffic secret.
    pub fn verifyPeerFinished(self: *Engine, peer_secret: Secret, finished_body: []const u8) bool {
        // finished_body is the verify_data sent by the peer
        var snap = self.transcript;
        const th = snap.finalize(self.hash_kind);
        const th_slice = th.slice();
        if (th_slice.len >= 8) {
            std.debug.print("TLS: Verifying Finished with transcript hash: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} ...\n", .{ th_slice[0], th_slice[1], th_slice[2], th_slice[3], th_slice[4], th_slice[5], th_slice[6], th_slice[7] });
        }
        const expect = deriveFinishedVerifyData(self.hash_kind, &peer_secret, th);
        const expect_slice = expect.slice();

        // Length check first (not timing-sensitive)
        if (finished_body.len != expect_slice.len) {
            std.debug.print("TLS: Finished verification failed. Expected len={}, got len={}\n", .{ expect_slice.len, finished_body.len });
            return false;
        }

        // Constant-time comparison to prevent timing attacks (RFC 8446 §4.4.4)
        const match = switch (self.hash_kind) {
            .sha256 => blk: {
                const expected_bytes: *const [32]u8 = expect_slice[0..32];
                const verify_bytes: *const [32]u8 = finished_body[0..32];
                break :blk std.crypto.timing_safe.eql([32]u8, expected_bytes.*, verify_bytes.*);
            },
            .sha384 => blk: {
                const expected_bytes: *const [48]u8 = expect_slice[0..48];
                const verify_bytes: *const [48]u8 = finished_body[0..48];
                break :blk std.crypto.timing_safe.eql([48]u8, expected_bytes.*, verify_bytes.*);
            },
        };

        if (!match) {
            std.debug.print("TLS: MAC mismatch\n", .{});
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
        const transcript_hash = transcript_snapshot.finalize(self.hash_kind);

        // Context for server CertificateVerify
        const context = "TLS 1.3, server CertificateVerify";

        // Sign the transcript
        const signature = try sig.signCertificateVerify(alg, privkey, context, transcript_hash.slice(), self.allocator);
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
    pub fn computeHandshakeSecrets(self: *Engine) ?struct { client: Secret, server: Secret } {
        const shared = self.ecdhe_secret orelse return null;
        const ready = if (self.role == .Client)
            (self.ch_sent and self.sh_seen)
        else
            (self.ch_recv and self.sh_seen);
        if (!ready) return null;

        var snap = self.transcript;
        const th = snap.finalize(self.hash_kind);
        const hs = deriveHandshakeTraffic(self.hash_kind, shared, th);
        self.handshake_secret = hs.handshake;
        self.handshake_client_secret = hs.client_hs;
        self.handshake_server_secret = hs.server_hs;
        return .{ .client = hs.client_hs, .server = hs.server_hs };
    }

    /// Compute application traffic secrets from current transcript and ECDHE.
    /// CRITICAL: Caches the result on first call to prevent recomputation with wrong transcript.
    /// The first call happens when processing peer Finished (BEFORE adding it to transcript).
    pub fn computeApplicationSecrets(self: *Engine) ?struct { client: Secret, server: Secret } {
        if (self.cached_app_client) |client| {
            if (self.cached_app_server) |server| {
                return .{ .client = client, .server = server };
            }
        }

        const shared = self.ecdhe_secret orelse return null;
        const ready = if (self.role == .Client)
            (self.ch_sent and self.sh_seen)
        else
            (self.ch_recv and self.sh_seen);
        if (!ready) return null;

        var snap = self.transcript;
        const th = snap.finalize(self.hash_kind);
        const handshake_secret = self.handshake_secret orelse blk: {
            const hs = deriveHandshakeTraffic(self.hash_kind, shared, th);
            self.handshake_secret = hs.handshake;
            self.handshake_client_secret = hs.client_hs;
            self.handshake_server_secret = hs.server_hs;
            break :blk hs.handshake;
        };

        const master = blk2: {
            const derived = ks.deriveSecretHash(self.hash_kind, &handshake_secret, "derived", &[_]u8{});
            break :blk2 ks.extractHash(self.hash_kind, derived.slice(), &[_]u8{});
        };
        self.master_secret = master;

        const client_app = ks.deriveSecretHash(self.hash_kind, &master, "c ap traffic", th.slice());
        const server_app = ks.deriveSecretHash(self.hash_kind, &master, "s ap traffic", th.slice());

        self.cached_app_client = client_app;
        self.cached_app_server = server_app;

        return .{ .client = client_app, .server = server_app };
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
        const pre_th = pre_snap.finalize(self.hash_kind);
        const pre_slice = pre_th.slice();
        if (pre_slice.len >= 8) {
            std.debug.print("Transcript hash BEFORE ServerHello: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ pre_slice[0], pre_slice[1], pre_slice[2], pre_slice[3], pre_slice[4], pre_slice[5], pre_slice[6], pre_slice[7] });
        }

        try self.queueCrypto(msg);

        self.hash_kind = cipherSuiteHash(.TLS_AES_128_GCM_SHA256);
        self.tryComputeShared();
        if (self.ecdhe_secret != null and self.handshake_client_secret == null) {
            var snap = self.transcript;
            const th = snap.finalize(self.hash_kind);
            const th_slice = th.slice();
            if (th_slice.len >= 8) {
                std.debug.print("Transcript hash AFTER ServerHello: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{ th_slice[0], th_slice[1], th_slice[2], th_slice[3], th_slice[4], th_slice[5], th_slice[6], th_slice[7] });
            }
            const hs = deriveHandshakeTraffic(self.hash_kind, self.ecdhe_secret.?, th);
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

            std.debug.print("[CERTVERIFY] About to queue CertificateVerify with alg={}, priv_key_len={}\n", .{ self.server_sig_alg.?, self.server_priv_key.?.len });

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
