// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Handshake State Machine
//!
//! RFC 8446 §4: Handshake Protocol
//! RFC 9001 §4: TLS Handshake
//!
//! This module manages the TLS 1.3 handshake state, including phase tracking,
//! flags for message exchange, and CRYPTO frame buffering per encryption level.

const std = @import("std");
const tls13_full = @import("tls13_full");
const readU16 = tls13_full.readU16;

const ArrayListUnmanaged = std.ArrayListUnmanaged;

/// RFC 8446 §4: Handshake protocol phases
///
/// The handshake progresses through well-defined phases used for progress tracking
/// and ensuring messages are processed in correct order.
pub const HandshakePhase = enum {
    /// RFC 8446 §4: Before any messages
    initial,
    /// RFC 8446 §4.1.2: After ClientHello received/sent
    negotiating,
    /// RFC 9001 §5: After handshake secrets installed
    keys_installed,
    /// RFC 8446 §4.4.4: After both Finished messages
    application_ready,
    /// Post-handshake state (key updates, NewSessionTicket)
    post_handshake,
};

/// Handshake completion flags (RFC 8446 §4.4.4).
///
/// Tracks the state of Finished message exchange to determine when the handshake
/// is complete and application data can flow.
pub const HandshakeFlags = struct {
    peer_finished_verified: bool = false,
    local_finished_sent: bool = false,
    alert: ?u8 = null,
    metadata_notified: bool = false,

    pub fn reset(self: *HandshakeFlags) void {
        self.* = HandshakeFlags{};
    }
};

/// Encryption levels for QUIC integration (RFC 9001 §4.1.4).
pub const EncryptionLevel = enum {
    Initial,
    Handshake,
    Application,
};

const encryption_level_count = std.meta.fields(EncryptionLevel).len;

/// RFC 9001 §4.1.4: per-encryption-level CRYPTO queues keeping inbound/outbound bytes.
///
/// Each encryption level (Initial, Handshake, Application) has separate buffering
/// for CRYPTO frame data. This allows messages to be reassembled from multiple
/// QUIC packets before processing.
pub const CryptoBuffer = struct {
    level: EncryptionLevel,
    inbound: ArrayListUnmanaged(u8) = .{},
    outbound: ArrayListUnmanaged(u8) = .{},

    pub fn init(level: EncryptionLevel) CryptoBuffer {
        return .{ .level = level };
    }

    pub fn clear(self: *CryptoBuffer) void {
        self.inbound.clearRetainingCapacity();
        self.outbound.clearRetainingCapacity();
    }

    pub fn deinit(self: *CryptoBuffer, alloc: std.mem.Allocator) void {
        self.inbound.deinit(alloc);
        self.outbound.deinit(alloc);
    }

    /// Consume `count` bytes from the inbound buffer after processing.
    pub fn consume(self: *CryptoBuffer, count: usize) void {
        std.debug.assert(count <= self.inbound.items.len);
        const remaining = self.inbound.items.len - count;
        if (remaining > 0) {
            // Shift remaining bytes toward the front; use forwards copy to preserve data when overlapping
            std.mem.copyForwards(u8, self.inbound.items[0..remaining], self.inbound.items[count .. count + remaining]);
        }
        self.inbound.items = self.inbound.items[0..remaining];
    }
};

/// Container for CRYPTO buffers at all encryption levels.
pub const CryptoStreams = struct {
    buffers: [encryption_level_count]CryptoBuffer = initBuffers(),

    fn initBuffers() [encryption_level_count]CryptoBuffer {
        return .{
            CryptoBuffer.init(.Initial),
            CryptoBuffer.init(.Handshake),
            CryptoBuffer.init(.Application),
        };
    }

    pub fn reset(self: *CryptoStreams) void {
        for (&self.buffers) |*buf| buf.clear();
    }

    pub fn deinit(self: *CryptoStreams, alloc: std.mem.Allocator) void {
        for (&self.buffers) |*buf| buf.deinit(alloc);
    }

    pub fn buffer(self: *CryptoStreams, level: EncryptionLevel) *CryptoBuffer {
        return &self.buffers[@intFromEnum(level)];
    }
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
    psk_key_exchange_modes: ?[]const u8, // RFC 8446 §4.2.9: Required when using PSK
    raw: []const u8,
};

/// Internal owned copy of pre-shared key info.
const PreSharedKeyInfo = struct {
    identities: []ClientHelloPskIdentityView,
    binders: []const []const u8,
};

/// Internal storage for parsed ClientHello data.
pub const ClientHelloInfo = struct {
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
    psk_key_exchange_modes: ?[]u8, // RFC 8446 §4.2.9
    raw: []u8,

    /// Parse ClientHello message body and allocate owned copies.
    /// Callers must call deinit() to free allocated memory.
    pub fn parse(allocator: std.mem.Allocator, body: []const u8) !ClientHelloInfo {
        // Import parse logic from tls13_full
        var parsed = try tls13_full.parseClientHello(allocator, body);
        errdefer freeParsedClientHello(allocator, &parsed);

        // Validation
        const HandshakeError = error{
            NoCipherSuite,
            UnsupportedVersion,
            MissingKeyShare,
            UnsupportedKeyShareGroup,
        };

        if (parsed.cipher_suites.len == 0) return HandshakeError.NoCipherSuite;
        const versions = parsed.supported_versions orelse return HandshakeError.UnsupportedVersion;
        if (!supportsTls13Version(versions)) return HandshakeError.UnsupportedVersion;

        const key_share = parsed.key_share orelse return HandshakeError.MissingKeyShare;
        if (key_share.group != .x25519) return HandshakeError.UnsupportedKeyShareGroup;

        // Allocate owned copies
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
            const ids = try allocator.alloc(ClientHelloPskIdentityView, psk_ext.identities.len);
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

        // RFC 8446 §4.2.9: Copy psk_key_exchange_modes if present
        var psk_modes_copy: ?[]u8 = null;
        if (parsed.psk_key_exchange_modes) |modes| {
            psk_modes_copy = try allocator.dupe(u8, modes);
        }
        errdefer if (psk_modes_copy) |buf| if (buf.len != 0) allocator.free(buf);

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
            .psk_key_exchange_modes = psk_modes_copy,
            .raw = raw_copy,
        };

        freeParsedClientHello(allocator, &parsed);
        return info;
    }

    /// Free all allocated memory from ClientHelloInfo.
    pub fn deinit(self: *ClientHelloInfo, allocator: std.mem.Allocator) void {
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
        if (self.pre_shared_key) |*psk| {
            for (psk.identities) |ident| {
                if (ident.identity.len != 0) allocator.free(@constCast(ident.identity));
            }
            if (psk.identities.len != 0) allocator.free(psk.identities);
            for (psk.binders) |binder| {
                if (binder.len != 0) allocator.free(@constCast(binder));
            }
            if (psk.binders.len != 0) allocator.free(@constCast(psk.binders));
        }
        if (self.psk_key_exchange_modes) |buf| if (buf.len != 0) allocator.free(buf);
        if (self.raw.len != 0) allocator.free(self.raw);
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
        const version = readU16(encoded[offset .. offset + 2]);
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

/// Handshake state container (server stores ClientHello for parameter negotiation).
pub const HandshakeState = struct {
    client_hello: ?ClientHelloInfo = null,

    pub fn init() HandshakeState {
        return .{};
    }

    pub fn reset(self: *HandshakeState, allocator: std.mem.Allocator) void {
        if (self.client_hello) |*info| {
            info.deinit(allocator);
            self.client_hello = null;
        }
    }

    /// Store parsed ClientHello for parameter negotiation (server role).
    /// Returns error if ClientHello already received.
    pub fn setClientHello(self: *HandshakeState, allocator: std.mem.Allocator, body: []const u8) !void {
        const HandshakeError = error{DuplicateClientHello};
        if (self.client_hello != null) return HandshakeError.DuplicateClientHello;
        const info = try ClientHelloInfo.parse(allocator, body);
        self.client_hello = info;
    }

    /// Get immutable view of stored ClientHello.
    pub fn clientHello(self: *const HandshakeState) ?ClientHelloView {
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
                .pre_shared_key = if (info.pre_shared_key) |psk| ClientHelloPreSharedKeyView{
                    .identities = psk.identities,
                    .binders = psk.binders,
                } else null,
                .psk_key_exchange_modes = info.psk_key_exchange_modes,
                .raw = info.raw,
            };
        }
        return null;
    }
};
