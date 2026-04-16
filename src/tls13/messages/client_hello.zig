// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TLS 1.3 ClientHello Message
//!
//! Implements ClientHello message parsing per RFC 8446 §4.1.2. The ClientHello
//! is the first message in the TLS 1.3 handshake, containing the client's
//! capabilities, preferences, and cryptographic parameters.
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.1.2: ClientHello message structure
//! - RFC 8446 §4.2: Extension definitions and processing
//! - RFC 8446 §9.2: Required extensions for TLS 1.3
//! - RFC 6066 §3: Server Name Indication (SNI)
//! - RFC 7301: ALPN extension
//! - RFC 9001 §8.2: QUIC transport parameters
//!
//! ## INTEROP FIRST Design
//!
//! This implementation follows the INTEROP FIRST principle:
//! - Parses all standard extension types from RFC 8446
//! - Gracefully ignores unknown extensions (per RFC 8446 §4.2)
//! - Zero-copy parsing (slices reference input buffer)
//! - Supports real-world QUIC implementations
//!
//! ## QUAL-096: Shared ClientHello Builder
//!
//! The `buildClientHello` function provides a single, shared implementation
//! for encoding TLS 1.3 ClientHello message bodies. It is used by:
//! - `context.zig:startClientHandshake` (initial ClientHello with PSK support)
//! - `context.zig:sendClientHello2` (ClientHello2 after HelloRetryRequest)
//! - `engine.zig:queueRealClientHello` (legacy engine)
//!
//! The builder uses a single-buffer pattern (PERF-015) where extensions are
//! written directly into the output buffer with length fields patched at the
//! end, eliminating the ext_buf double-copy pattern.
//!
//! This module contains both parsing and building.

const std = @import("std");
const core_types = @import("core_types.zig");
const helpers = @import("helpers.zig");

/// Parsed ClientHello message (RFC 8446 §4.1.2).
///
/// ClientHello is the first message in the TLS 1.3 handshake, sent by the client
/// to initiate a connection. It contains the client's capabilities, preferences,
/// and cryptographic parameters.
///
/// ## Structure (RFC 8446 §4.1.2)
///
/// ```
/// struct {
///     ProtocolVersion legacy_version = 0x0303; // TLS 1.2 for compatibility
///     Random random;                            // 32 bytes of randomness
///     opaque legacy_session_id<0..32>;         // For middlebox compatibility
///     CipherSuite cipher_suites<2..2^16-2>;    // Client's supported cipher suites
///     opaque legacy_compression_methods<1..2^8-1>; // Must be [0x00] for TLS 1.3
///     Extension extensions<8..2^16-1>;         // MUST be present in TLS 1.3
/// } ClientHello;
/// ```
///
/// ## Required Extensions (RFC 8446 §9.2)
///
/// TLS 1.3 ClientHello MUST contain:
/// - **supported_versions** (0x002b): Indicates TLS 1.3 support
/// - **signature_algorithms** (0x000d): Signature schemes for CertificateVerify
///
/// ## Common Extensions
///
/// - **server_name** (0x0000): SNI for virtual hosting
/// - **supported_groups** (0x000a): ECDHE/FFDHE groups
/// - **key_share** (0x0033): Client's ECDHE public key(s)
/// - **alpn** (0x0010): Application-Layer Protocol Negotiation
/// - **quic_transport_parameters** (0x0039): QUIC-specific parameters (QUIC only)
/// - **pre_shared_key** (0x0029): PSK identities for resumption/0-RTT (MUST be last)
///
/// ## Memory Management
///
/// All slices reference the input buffer (zero-copy parsing). The ClientHello
/// struct is valid only as long as the original message buffer remains live.
pub const ClientHello = struct {
    random: [32]u8, // RFC 8446 §4.1.2: Client random (32 bytes)
    session_id: []const u8, // RFC 8446 §4.1.2: Legacy session ID (for middlebox compat)
    cipher_suites: []core_types.CipherSuite, // RFC 8446 §4.1.2: Client's supported cipher suites
    compression_methods: []const u8, // RFC 8446 §4.1.2: Must be [0x00] in TLS 1.3

    // Extensions (RFC 8446 §4.2)
    server_name: ?[]const u8 = null, // RFC 6066 §3: SNI hostname
    supported_groups: ?[]core_types.NamedGroup = null, // RFC 8446 §4.2.7: ECDHE/FFDHE groups
    signature_algorithms: ?[]core_types.SignatureScheme = null, // RFC 8446 §4.2.3: Signature algorithms
    supported_versions: ?[]const u8 = null, // RFC 8446 §4.2.1: TLS version list (REQUIRED)
    key_share: ?KeyShareEntry = null, // RFC 8446 §4.2.8: ECDHE public key
    alpn_list: ?[][]const u8 = null, // RFC 7301: Application protocols
    quic_transport_parameters: ?[]const u8 = null, // RFC 9001 §8.2: QUIC parameters
    psk_key_exchange_modes: ?[]const u8 = null, // RFC 8446 §4.2.9: PSK modes (psk_ke, psk_dhe_ke)
    pre_shared_key: ?PreSharedKey = null, // RFC 8446 §4.2.11: PSK identities (MUST be last extension)
    early_data: bool = false, // RFC 8446 §4.2.10: 0-RTT early data indication
};

/// Key share entry for ECDHE key exchange (RFC 8446 §4.2.8).
///
/// Contains the client's or server's ephemeral public key for a specific
/// named group (elliptic curve or finite field group).
///
/// ## Structure
///
/// ```
/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
/// ```
///
/// ## Key Exchange Data Formats
///
/// - **X25519**: 32-byte public key (RFC 7748 §6)
/// - **secp256r1**: 65-byte uncompressed point (0x04 || x || y) (RFC 8422 §5.4)
/// - **FFDHE groups**: Big-endian integer (RFC 7919)
pub const KeyShareEntry = struct {
    group: core_types.NamedGroup, // RFC 8446 §4.2.8: Named group identifier
    key_exchange: []const u8, // RFC 8446 §4.2.8: Public key bytes (format depends on group)
};

/// TLS 1.3 Pre-Shared Key identity entry (RFC 8446 §4.2.11).
///
/// Identifies a pre-shared key (PSK) from a previous session or external source.
/// Used for session resumption and 0-RTT early data.
///
/// ## Structure
///
/// ```
/// struct {
///     opaque identity<1..2^16-1>;
///     uint32 obfuscated_ticket_age;
/// } PskIdentity;
/// ```
///
/// ## Obfuscated Ticket Age
///
/// For resumption PSKs from NewSessionTicket:
/// - Client computes: ticket_age_add + (current_time - ticket_received_time) mod 2^32
/// - Server verifies freshness and detects replays
/// - For external PSKs: set to 0
pub const PskIdentity = struct {
    identity: []const u8, // RFC 8446 §4.2.11: PSK identity (session ticket or external PSK)
    obfuscated_ticket_age: u32, // RFC 8446 §4.2.11: Obfuscated age for replay prevention
};

/// TLS 1.3 pre_shared_key extension payload (RFC 8446 §4.2.11).
///
/// Contains PSK identities and corresponding binders. The binder is an HMAC
/// over the partial ClientHello transcript, proving the client possesses the PSK.
///
/// ## Structure
///
/// ```
/// struct {
///     PskIdentity identities<7..2^16-1>;
///     PskBinderEntry binders<33..2^16-1>;
/// } OfferedPsks;
/// ```
///
/// ## Binder Computation (RFC 8446 §4.2.11.2)
///
/// ```
/// binder = HMAC(binder_key, transcript_hash(ClientHello_truncated))
/// ```
///
/// where ClientHello_truncated excludes the binders themselves.
///
/// ## Security Critical
///
/// - Binder MUST be verified before accepting PSK
/// - pre_shared_key extension MUST be last in ClientHello (RFC 8446 §4.2.11)
/// - Binder covers all preceding extensions (prevents tampering)
pub const PreSharedKey = struct {
    identities: []PskIdentity, // RFC 8446 §4.2.11: List of offered PSK identities
    binders: [][]const u8, // RFC 8446 §4.2.11: HMAC binders for each identity
};

/// Parse a full TLS 1.3 ClientHello message (RFC 8446 §4.1.2).
///
/// Parses the ClientHello wire format into a structured representation, extracting
/// all standard extensions. This implements the INTEROP FIRST design principle by:
/// - Gracefully ignoring unknown extensions (per RFC 8446 §4.2)
/// - Supporting all standard TLS 1.3 cipher suites and extensions
/// - Using zero-copy parsing (returned slices reference input buffer)
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for variable-length fields (cipher suites, extension arrays)
/// - `data`: ClientHello message bytes (without Handshake header, i.e., just the ClientHello payload)
///
/// ## Returns
///
/// - `ClientHello`: Parsed structure with all recognized extensions
/// - `error.TooShort`: Message too short to be valid ClientHello
///
/// ## Memory Management
///
/// - Allocates memory for: cipher_suites, supported_groups, signature_algorithms, alpn_list, PSK identities/binders
/// - All other fields are slices into the input buffer (zero-copy)
/// - Caller must free allocated fields when done
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.1.2: ClientHello structure parsing
/// - RFC 8446 §4.2: Extension processing (unknown extensions ignored)
/// - RFC 8446 §4.2.11: Pre-shared key extension (MUST be last, validated during parsing)
///
/// ## INTEROP FIRST Implementation
///
/// - Supports all standard extension types from RFC 8446, RFC 6066, RFC 7301, RFC 9001
/// - Filters cipher suites to TLS 1.3 suites only (0x1301-0x1305)
/// - Recognizes but skips unsupported extensions (no handshake failure)
/// - Currently focuses on X25519 for key_share parsing
///
/// ## Extension Parsing
///
/// The following extensions are parsed and extracted:
/// - **server_name** (0x0000): SNI hostname
/// - **supported_groups** (0x000a): Named groups for ECDHE
/// - **signature_algorithms** (0x000d): Signature schemes
/// - **supported_versions** (0x002b): TLS version list
/// - **key_share** (0x0033): Client's ECDHE public key
/// - **alpn** (0x0010): Application protocols
/// - **quic_transport_parameters** (0x0039): QUIC parameters
/// - **psk_key_exchange_modes** (0x002d): PSK modes
/// - **pre_shared_key** (0x0029): PSK identities and binders
/// - **early_data** (0x002a): 0-RTT indication
///
/// Unknown extensions are silently ignored per RFC 8446 §4.2.
///
/// ## Usage
///
/// ```zig
/// const ch = try parseClientHello(allocator, client_hello_bytes);
/// defer {
///     allocator.free(ch.cipher_suites);
///     if (ch.supported_groups) |groups| allocator.free(groups);
///     if (ch.signature_algorithms) |algs| allocator.free(algs);
///     if (ch.alpn_list) |list| allocator.free(list);
///     if (ch.pre_shared_key) |psk| {
///         allocator.free(psk.identities);
///         allocator.free(psk.binders);
///     }
/// }
/// ```
pub fn parseClientHello(allocator: std.mem.Allocator, data: []const u8) !ClientHello {
    if (data.len < 34) return error.TooShort;

    var ch = ClientHello{
        .random = undefined,
        .session_id = &[_]u8{},
        .cipher_suites = &[_]core_types.CipherSuite{},
        .compression_methods = &[_]u8{},
    };

    // SEC-054: On any error after partial allocation, free all owned slices
    // to prevent memory leaks from repeated malformed ClientHello messages.
    errdefer {
        if (ch.cipher_suites.len > 0) allocator.free(ch.cipher_suites);
        if (ch.supported_groups) |sg| allocator.free(sg);
        if (ch.signature_algorithms) |sa| allocator.free(sa);
        if (ch.alpn_list) |al| allocator.free(al);
        if (ch.pre_shared_key) |psk| {
            allocator.free(psk.identities);
            allocator.free(psk.binders);
        }
    }

    var pos: usize = 0;

    // Skip legacy_version (2 bytes)
    pos += 2;

    // Random (32 bytes)
    @memcpy(&ch.random, data[pos .. pos + 32]);
    pos += 32;

    // Session ID
    if (pos >= data.len) return error.TooShort;
    const sid_len = data[pos];
    pos += 1;
    if (pos + sid_len > data.len) return error.TooShort;
    ch.session_id = data[pos .. pos + sid_len];
    pos += sid_len;

    // Cipher suites
    if (pos + 2 > data.len) return error.TooShort;
    const cs_len = helpers.readU16(data[pos .. pos + 2]);
    pos += 2;
    if (pos + cs_len > data.len) return error.TooShort;

    var cipher_suites = try std.ArrayList(core_types.CipherSuite).initCapacity(allocator, 4);
    defer cipher_suites.deinit(allocator);

    var cs_pos: usize = 0;
    while (cs_pos < cs_len) : (cs_pos += 2) {
        const cs_value = helpers.readU16(data[pos + cs_pos .. pos + cs_pos + 2]);
        // Check if it's a supported TLS 1.3 cipher suite
        if (cs_value == 0x1301 or cs_value == 0x1302 or cs_value == 0x1303) {
            try cipher_suites.append(allocator, @enumFromInt(cs_value));
        }
    }
    ch.cipher_suites = try cipher_suites.toOwnedSlice(allocator);
    pos += cs_len;

    // Compression methods
    if (pos >= data.len) return error.TooShort;
    const comp_len = data[pos];
    pos += 1;
    if (pos + comp_len > data.len) return error.TooShort;
    ch.compression_methods = data[pos .. pos + comp_len];
    pos += comp_len;

    // Extensions
    if (pos + 2 > data.len) return error.TooShort;
    const ext_len = helpers.readU16(data[pos .. pos + 2]);
    pos += 2;
    if (pos + ext_len > data.len) return error.TooShort;

    const ext_end = pos + ext_len;
    var psk_seen = false; // RFC 8446 §4.2.11: Track if pre_shared_key was seen

    while (pos + 4 <= ext_end) {
        const ext_type = helpers.readU16(data[pos .. pos + 2]);
        const ext_data_len = helpers.readU16(data[pos + 2 .. pos + 4]);
        pos += 4;

        if (pos + ext_data_len > ext_end) return error.TooShort;
        const ext_data = data[pos .. pos + ext_data_len];

        // Use intToEnum to safely handle unknown extension types without panicking
        const ext = @as(core_types.ExtensionType, @enumFromInt(ext_type)) catch {
            // Unknown extension type - ignore per TLS 1.3 spec
            // But still check if PSK was already seen (it must be last)
            if (psk_seen) {
                return error.PskNotLastExtension; // CWE-345: pre_shared_key must be last
            }
            pos += ext_data_len;
            continue;
        };

        // RFC 8446 §4.2.11: pre_shared_key MUST be the last extension
        // If we've already seen PSK and we're processing another extension, fail
        if (psk_seen and ext != .pre_shared_key) {
            return error.PskNotLastExtension;
        }

        switch (ext) {
            .server_name => {
                // Parse SNI
                if (ext_data.len >= 5) {
                    const list_len = helpers.readU16(ext_data[0..2]);
                    if (list_len > 0 and ext_data.len >= 5) {
                        const name_type = ext_data[2];
                        if (name_type == 0) { // host_name
                            const name_len = helpers.readU16(ext_data[3..5]);
                            if (5 + name_len <= ext_data.len) {
                                ch.server_name = ext_data[5 .. 5 + name_len];
                            }
                        }
                    }
                }
            },
            .supported_groups => {
                // Parse supported groups
                if (ext_data.len >= 2) {
                    const groups_len = helpers.readU16(ext_data[0..2]);
                    if (2 + groups_len <= ext_data.len) {
                        var groups = try std.ArrayList(core_types.NamedGroup).initCapacity(allocator, 4);
                        defer groups.deinit(allocator);

                        var g_pos: usize = 2;
                        while (g_pos + 2 <= 2 + groups_len) : (g_pos += 2) {
                            const group = helpers.readU16(ext_data[g_pos .. g_pos + 2]);
                            if (group == 0x001d) { // x25519
                                try groups.append(allocator, .x25519);
                            }
                        }

                        if (groups.items.len > 0) {
                            ch.supported_groups = try groups.toOwnedSlice(allocator);
                        }
                    }
                }
            },
            .signature_algorithms => {
                // Parse signature algorithms
                if (ext_data.len >= 2) {
                    const algs_len = helpers.readU16(ext_data[0..2]);
                    if (2 + algs_len <= ext_data.len) {
                        var algs = try std.ArrayList(core_types.SignatureScheme).initCapacity(allocator, 8);
                        defer algs.deinit(allocator);

                        var a_pos: usize = 2;
                        while (a_pos + 2 <= 2 + algs_len) : (a_pos += 2) {
                            const alg = helpers.readU16(ext_data[a_pos .. a_pos + 2]);
                            // Add supported algorithms
                            if (alg >= 0x0401 and alg <= 0x080b) {
                                try algs.append(allocator, @enumFromInt(alg));
                            }
                        }

                        if (algs.items.len > 0) {
                            ch.signature_algorithms = try algs.toOwnedSlice(allocator);
                        }
                    }
                }
            },
            .supported_versions => {
                // Parse supported versions
                ch.supported_versions = ext_data;
            },
            .key_share => {
                // Parse key share
                if (ext_data.len >= 2) {
                    const shares_len = helpers.readU16(ext_data[0..2]);
                    if (2 + shares_len <= ext_data.len) {
                        var ks_pos: usize = 2;
                        while (ks_pos + 4 <= 2 + shares_len) {
                            const group = helpers.readU16(ext_data[ks_pos .. ks_pos + 2]);
                            const key_len = helpers.readU16(ext_data[ks_pos + 2 .. ks_pos + 4]);
                            ks_pos += 4;

                            if (ks_pos + key_len <= 2 + shares_len) {
                                // We only support X25519
                                if (group == 0x001d and key_len == 32) {
                                    ch.key_share = KeyShareEntry{
                                        .group = .x25519,
                                        .key_exchange = ext_data[ks_pos .. ks_pos + key_len],
                                    };
                                    break;
                                }
                                ks_pos += key_len;
                            } else {
                                break;
                            }
                        }
                    }
                }
            },
            .alpn => {
                // Parse ALPN
                if (ext_data.len >= 2) {
                    const list_len = helpers.readU16(ext_data[0..2]);
                    if (2 + list_len <= ext_data.len) {
                        var alpn_list = try std.ArrayList([]const u8).initCapacity(allocator, 4);
                        defer alpn_list.deinit(allocator);

                        var a_pos: usize = 2;
                        while (a_pos < 2 + list_len) {
                            if (a_pos >= ext_data.len) break;
                            const proto_len = ext_data[a_pos];
                            a_pos += 1;
                            if (a_pos + proto_len <= ext_data.len) {
                                try alpn_list.append(allocator, ext_data[a_pos .. a_pos + proto_len]);
                                a_pos += proto_len;
                            } else {
                                break;
                            }
                        }

                        if (alpn_list.items.len > 0) {
                            ch.alpn_list = try alpn_list.toOwnedSlice(allocator);
                        }
                    }
                }
            },
            .quic_transport_parameters => {
                ch.quic_transport_parameters = ext_data;
            },
            .psk_key_exchange_modes => {
                ch.psk_key_exchange_modes = ext_data;
            },
            .pre_shared_key => {
                if (ext_data.len < 2) return error.TooShort;
                const identities_len = helpers.readU16(ext_data[0..2]);
                if (identities_len + 2 > ext_data.len) return error.TooShort;

                var identities = try std.ArrayList(PskIdentity).initCapacity(allocator, 2);
                defer identities.deinit(allocator);

                var id_pos: usize = 2;
                const identities_end = 2 + identities_len;
                while (id_pos < identities_end) {
                    if (id_pos + 2 > identities_end) return error.TooShort;
                    const identity_len = helpers.readU16(ext_data[id_pos .. id_pos + 2]);
                    id_pos += 2;
                    if (id_pos + identity_len > identities_end) return error.TooShort;
                    const identity_bytes = ext_data[id_pos .. id_pos + identity_len];
                    id_pos += identity_len;
                    if (id_pos + 4 > identities_end) return error.TooShort;
                    const ticket_age = helpers.readU32(ext_data[id_pos .. id_pos + 4]);
                    id_pos += 4;
                    try identities.append(allocator, .{
                        .identity = identity_bytes,
                        .obfuscated_ticket_age = ticket_age,
                    });
                }
                if (id_pos != identities_end) return error.TooShort;

                if (id_pos + 2 > ext_data.len) return error.TooShort;
                const binders_len = helpers.readU16(ext_data[id_pos .. id_pos + 2]);
                id_pos += 2;
                if (id_pos + binders_len > ext_data.len) return error.TooShort;

                var binders = try std.ArrayList([]const u8).initCapacity(allocator, 2);
                defer binders.deinit(allocator);

                var binder_pos: usize = 0;
                while (binder_pos < binders_len) {
                    if (binder_pos >= binders_len) return error.TooShort;
                    const binder_len = ext_data[id_pos + binder_pos];
                    binder_pos += 1;
                    if (binder_pos + binder_len > binders_len) return error.TooShort;
                    const binder_slice = ext_data[id_pos + binder_pos .. id_pos + binder_pos + binder_len];
                    binder_pos += binder_len;
                    try binders.append(allocator, binder_slice);
                }
                if (binder_pos != binders_len) return error.TooShort;

                ch.pre_shared_key = PreSharedKey{
                    .identities = try identities.toOwnedSlice(allocator),
                    .binders = try binders.toOwnedSlice(allocator),
                };
                psk_seen = true; // Mark that we've seen PSK extension
            },
            .early_data => {
                ch.early_data = true;
            },
            else => {
                // Known extension but not handled
            },
        }

        pos += ext_data_len;
    }

    return ch;
}

// ============================================================================
// ClientHello Builder (QUAL-096)
// ============================================================================

/// Parameters for building a TLS 1.3 ClientHello message body.
///
/// Encapsulates all varying inputs so that `startClientHandshake`,
/// `sendClientHello2`, and the Engine's `queueRealClientHello` can share
/// the same wire-encoding logic.
///
/// ## RFC Coverage
///
/// - RFC 8446 §4.1.2: ClientHello structure
/// - RFC 8446 §4.2: Extensions
/// - RFC 9001 §8.2: QUIC transport parameters extension
pub const ClientHelloParams = struct {
    /// 32-byte client random (RFC 8446 §4.1.2).
    random: [32]u8,

    /// Client public key for key_share extension (RFC 8446 §4.2.8).
    client_pub: [32]u8,

    /// Named group for the key_share entry (default: x25519).
    key_share_group: core_types.NamedGroup = .x25519,

    /// Cipher suites to offer (RFC 8446 §4.1.2).
    /// If empty, defaults to AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305.
    cipher_suites: []const core_types.CipherSuite = &.{},

    /// Supported groups to advertise (RFC 8446 §4.2.7).
    /// If empty, the extension is omitted.
    supported_groups: []const core_types.NamedGroup = &.{},

    /// Signature algorithms to advertise (RFC 8446 §4.2.3).
    /// If empty, the extension is omitted.
    signature_algorithms: []const core_types.SignatureScheme = &.{},

    /// ALPN protocol names (RFC 7301). If empty/null, the extension is omitted.
    alpn_protocols: ?[]const []const u8 = null,

    /// QUIC transport parameters (RFC 9001 §8.2). If null, the extension is omitted.
    quic_transport_parameters: ?[]const u8 = null,

    /// Cookie from HelloRetryRequest (RFC 8446 §4.2.2). If null, the extension is omitted.
    cookie: ?[]const u8 = null,

    /// Whether to include the early_data extension (RFC 8446 §4.2.10).
    include_early_data: bool = false,

    /// Whether to include psk_key_exchange_modes + pre_shared_key extensions.
    /// When true, `psk_identity` must be set.
    include_psk: bool = false,

    /// PSK identity bytes (session ticket or external PSK identity).
    psk_identity: ?[]const u8 = null,

    /// Obfuscated ticket age for the PSK identity (RFC 8446 §4.2.11).
    psk_ticket_age: u32 = 0,

    /// Digest length for the PSK binder (e.g. 32 for SHA-256, 48 for SHA-384).
    /// Only used when `include_psk` is true.
    psk_binder_len: u8 = 0,
};

/// Result from `buildClientHello` containing the encoded body and optional
/// PSK binder metadata needed by the caller to compute and patch the binder.
pub const ClientHelloResult = struct {
    /// The fully-encoded ClientHello body (NOT including the 4-byte handshake
    /// header). Caller owns this memory and must free it via the same allocator.
    body: []u8,

    /// If a PSK extension was written, this is the byte offset (within `body`)
    /// where the binder placeholder (zeros) starts. Null when no PSK was included.
    binder_offset: ?usize = null,

    /// Length of the binder placeholder in bytes (same as `psk_binder_len`).
    binder_len: u8 = 0,

    /// Number of trailing bytes that form the binders list
    /// (binders_list_len_field(2) + binder_len_field(1) + binder_data).
    /// The truncated message for binder computation is `body[0 .. body.len - binders_tail_len]`.
    binders_tail_len: usize = 0,
};

/// Build a TLS 1.3 ClientHello message body (RFC 8446 §4.1.2).
///
/// Encodes the ClientHello body bytes suitable for wrapping in a handshake
/// message (type 0x01 + 3-byte length prefix). The caller is responsible for
/// adding the handshake header and, when PSK is used, computing and patching
/// the binder into the placeholder returned via `ClientHelloResult`.
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for the returned body buffer.
/// - `params`: All varying inputs for the ClientHello.
///
/// ## Returns
///
/// - `ClientHelloResult`: Encoded body and optional PSK binder metadata.
///
/// ## Extension Order (RFC 8446 §4.2)
///
/// 1. supported_versions (REQUIRED)
/// 2. supported_groups
/// 3. signature_algorithms
/// 4. key_share
/// 5. cookie (if present, from HRR)
/// 6. ALPN
/// 7. QUIC transport parameters
/// 8. early_data (if enabled)
/// 9. psk_key_exchange_modes (if PSK)
/// 10. pre_shared_key (MUST be last per RFC 8446 §4.2.11)
pub fn buildClientHello(allocator: std.mem.Allocator, params: ClientHelloParams) !ClientHelloResult {
    // Use the same cipher suites defaulting logic as all 3 call sites.
    const cipher_suites = if (params.cipher_suites.len > 0)
        params.cipher_suites
    else
        &[_]core_types.CipherSuite{
            .TLS_AES_128_GCM_SHA256,
            .TLS_AES_256_GCM_SHA384,
            .TLS_CHACHA20_POLY1305_SHA256,
        };

    // Pre-allocate with a typical ClientHello size (~256 bytes).
    var buf = try std.ArrayList(u8).initCapacity(allocator, 256);
    errdefer buf.deinit(allocator);

    // --- ClientHello body ---

    // legacy_version (RFC 8446 §4.1.2: MUST be 0x0303)
    try buf.appendSlice(allocator, &.{ 0x03, 0x03 });

    // random (32 bytes)
    try buf.appendSlice(allocator, &params.random);

    // legacy_session_id (empty for QUIC, RFC 9001 §8.4)
    try buf.append(allocator, 0);

    // cipher_suites
    const cipher_list_len: u16 = @intCast(cipher_suites.len * 2);
    try buf.appendSlice(allocator, &.{ @intCast(cipher_list_len >> 8), @intCast(cipher_list_len & 0xff) });
    for (cipher_suites) |suite| {
        const val: u16 = @intFromEnum(suite);
        try buf.appendSlice(allocator, &.{ @intCast(val >> 8), @intCast(val & 0xff) });
    }

    // compression_methods (MUST be [0x00] for TLS 1.3)
    try buf.appendSlice(allocator, &.{ 0x01, 0x00 });

    // Reserve 2 bytes for extensions length (patched at end)
    const exts_len_offset = buf.items.len;
    try buf.appendSlice(allocator, &.{ 0x00, 0x00 });
    const exts_start = buf.items.len;

    // --- Extensions ---

    // 1. supported_versions (REQUIRED, RFC 8446 §4.2.1)
    //    list_len=2 containing 0x0304 (TLS 1.3)
    try buf.appendSlice(allocator, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });

    // 2. supported_groups (RFC 8446 §4.2.7)
    if (params.supported_groups.len != 0) {
        const group_list_len: u16 = @intCast(params.supported_groups.len * 2);
        const group_ext_len: u16 = group_list_len + 2;
        try buf.appendSlice(allocator, &.{
            0x00,
            0x0a,
            @intCast(group_ext_len >> 8),
            @intCast(group_ext_len & 0xff),
            @intCast(group_list_len >> 8),
            @intCast(group_list_len & 0xff),
        });
        for (params.supported_groups) |group| {
            const gval: u16 = @intFromEnum(group);
            try buf.appendSlice(allocator, &.{ @intCast(gval >> 8), @intCast(gval & 0xff) });
        }
    }

    // 3. signature_algorithms (RFC 8446 §4.2.3)
    if (params.signature_algorithms.len != 0) {
        const list_len: u16 = @intCast(params.signature_algorithms.len * 2);
        const ext_len: u16 = list_len + 2;
        try buf.appendSlice(allocator, &.{
            0x00,
            0x0d,
            @intCast(ext_len >> 8),
            @intCast(ext_len & 0xff),
            @intCast(list_len >> 8),
            @intCast(list_len & 0xff),
        });
        for (params.signature_algorithms) |scheme| {
            const val: u16 = @intFromEnum(scheme);
            try buf.appendSlice(allocator, &.{ @intCast(val >> 8), @intCast(val & 0xff) });
        }
    }

    // 4. key_share (RFC 8446 §4.2.8)
    {
        const group_val: u16 = @intFromEnum(params.key_share_group);
        const key_share_entry_len: u16 = 2 + 2 + 32; // group(2) + key_len(2) + key(32)
        const key_share_ext_len: u16 = key_share_entry_len + 2; // entries_list_len(2) + entry
        try buf.appendSlice(allocator, &.{
            0x00,
            0x33,
            @intCast(key_share_ext_len >> 8),
            @intCast(key_share_ext_len & 0xff),
            @intCast(key_share_entry_len >> 8),
            @intCast(key_share_entry_len & 0xff),
            @intCast(group_val >> 8),
            @intCast(group_val & 0xff),
            0x00,
            32,
        });
        try buf.appendSlice(allocator, &params.client_pub);
    }

    // 5. cookie (RFC 8446 §4.2.2, only after HRR)
    if (params.cookie) |ck| {
        const ck_len: u16 = @intCast(ck.len);
        try buf.appendSlice(allocator, &.{ 0x00, 0x2c, @intCast(ck_len >> 8), @intCast(ck_len & 0xff) });
        try buf.appendSlice(allocator, ck);
    }

    // 6. ALPN (RFC 7301)
    if (params.alpn_protocols) |alpn_list| {
        if (alpn_list.len != 0) {
            var names_len: usize = 0;
            for (alpn_list) |p| names_len += 1 + p.len;
            const list_len: u16 = @intCast(names_len);
            const ext_len: u16 = list_len + 2;
            try buf.appendSlice(allocator, &.{
                0x00,
                0x10,
                @intCast(ext_len >> 8),
                @intCast(ext_len & 0xff),
                @intCast(list_len >> 8),
                @intCast(list_len & 0xff),
            });
            for (alpn_list) |p| {
                try buf.append(allocator, @intCast(p.len));
                try buf.appendSlice(allocator, p);
            }
        }
    }

    // 7. QUIC transport parameters (RFC 9001 §8.2)
    if (params.quic_transport_parameters) |tp| {
        const tp_len: u16 = @intCast(tp.len);
        try buf.appendSlice(allocator, &.{ 0x00, 0x39, @intCast(tp_len >> 8), @intCast(tp_len & 0xff) });
        try buf.appendSlice(allocator, tp);
    }

    // 8. early_data (RFC 8446 §4.2.10, before PSK which must be last)
    if (params.include_early_data) {
        try buf.appendSlice(allocator, &.{ 0x00, 0x2a, 0x00, 0x00 });
    }

    // --- PSK-related extensions (9 & 10) ---
    var result = ClientHelloResult{
        .body = undefined,
    };

    if (params.include_psk) {
        const identity = params.psk_identity orelse return error.MissingPskIdentity;
        const binder_len = params.psk_binder_len;
        if (binder_len == 0) return error.InvalidBinderLength;

        // 9. psk_key_exchange_modes (RFC 8446 §4.2.9) - psk_dhe_ke(1)
        try buf.appendSlice(allocator, &.{ 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01 });

        // 10. pre_shared_key (MUST be last, RFC 8446 §4.2.11)
        try buf.appendSlice(allocator, &.{ 0x00, 0x29 }); // extension type

        const ext_data_start = buf.items.len + 2; // after ext length field
        try buf.appendSlice(allocator, &.{ 0x00, 0x00 }); // placeholder for ext length

        // Identities list: list_len(2) + identity_len(2) + identity + ticket_age(4)
        const identity_len: u16 = @intCast(identity.len);
        const identities_list_len: u16 = 2 + identity_len + 4;
        try buf.appendSlice(allocator, &.{ @intCast(identities_list_len >> 8), @intCast(identities_list_len & 0xff) });
        try buf.appendSlice(allocator, &.{ @intCast(identity_len >> 8), @intCast(identity_len & 0xff) });
        try buf.appendSlice(allocator, identity);

        const ticket_age = params.psk_ticket_age;
        try buf.appendSlice(allocator, &.{
            @intCast((ticket_age >> 24) & 0xff),
            @intCast((ticket_age >> 16) & 0xff),
            @intCast((ticket_age >> 8) & 0xff),
            @intCast(ticket_age & 0xff),
        });

        // Binders list: list_len(2) + binder_entry_len(1) + binder_data(binder_len)
        const binders_list_len: u16 = 1 + @as(u16, binder_len);
        try buf.appendSlice(allocator, &.{ @intCast(binders_list_len >> 8), @intCast(binders_list_len & 0xff) });
        try buf.append(allocator, binder_len);

        // Record binder placeholder position
        const binder_offset = buf.items.len;

        // Write zero placeholder for binder
        const zeros = [_]u8{0} ** 64; // max digest length
        try buf.appendSlice(allocator, zeros[0..binder_len]);

        // Patch PSK extension length
        const ext_data_len = buf.items.len - ext_data_start;
        buf.items[ext_data_start - 2] = @intCast((ext_data_len >> 8) & 0xff);
        buf.items[ext_data_start - 1] = @intCast(ext_data_len & 0xff);

        // Fill result with binder metadata
        // binders_tail_len = binders_list_len_field(2) + binder_len_field(1) + binder_data
        result.binder_offset = binder_offset;
        result.binder_len = binder_len;
        result.binders_tail_len = 2 + 1 + binder_len;
    }

    // Patch extensions length
    const exts_total: u16 = @intCast(buf.items.len - exts_start);
    buf.items[exts_len_offset] = @intCast(exts_total >> 8);
    buf.items[exts_len_offset + 1] = @intCast(exts_total & 0xff);

    result.body = try buf.toOwnedSlice(allocator);
    return result;
}
