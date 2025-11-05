//! Full TLS 1.3 implementation for QUIC.
//!
//! Provides the full handshake machinery from RFC 8446 (§3–§4) needed when QUIC
//! peers negotiate standard TLS messages. Transport parameter handling aligns
//! with RFC 9001 §8.2 to keep the QUIC handshake interoperable with other stacks.

const std = @import("std");
const ks = @import("quic_tls");
const x509 = @import("x509");
const sig = @import("sig");
const logger = @import("quic_logger");
const H = ks.H; // SHA-256

/// TLS 1.3 Extension types
pub const ExtensionType = enum(u16) {
    server_name = 0x0000,
    max_fragment_length = 0x0001,
    status_request = 0x0005,
    supported_groups = 0x000a,
    signature_algorithms = 0x000d,
    use_srtp = 0x000e,
    heartbeat = 0x000f,
    alpn = 0x0010,
    signed_certificate_timestamp = 0x0012,
    client_certificate_type = 0x0013,
    server_certificate_type = 0x0014,
    padding = 0x0015,
    pre_shared_key = 0x0029,
    early_data = 0x002a,
    supported_versions = 0x002b,
    cookie = 0x002c,
    psk_key_exchange_modes = 0x002d,
    certificate_authorities = 0x002f,
    oid_filters = 0x0030,
    post_handshake_auth = 0x0031,
    signature_algorithms_cert = 0x0032,
    key_share = 0x0033,
    quic_transport_parameters = 0x0039,
};

/// TLS 1.3 Named Groups for key exchange
pub const NamedGroup = enum(u16) {
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001d,
    x448 = 0x001e,
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,
};

/// TLS 1.3 Signature Algorithms
pub const SignatureScheme = enum(u16) {
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    ed25519 = 0x0807,
    ed448 = 0x0808,
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,
};

/// TLS 1.3 Cipher Suites
pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,
};

/// Parsed ClientHello structure
pub const ClientHello = struct {
    random: [32]u8,
    session_id: []const u8,
    cipher_suites: []CipherSuite,
    compression_methods: []const u8,
    // Extensions
    server_name: ?[]const u8 = null,
    supported_groups: ?[]NamedGroup = null,
    signature_algorithms: ?[]SignatureScheme = null,
    supported_versions: ?[]const u8 = null,
    key_share: ?KeyShareEntry = null,
    alpn_list: ?[]const []const u8 = null,
    quic_transport_parameters: ?[]const u8 = null,
    psk_key_exchange_modes: ?[]const u8 = null,
    pre_shared_key: ?PreSharedKey = null,
    early_data: bool = false,
};

/// Key share entry for ECDHE
pub const KeyShareEntry = struct {
    group: NamedGroup,
    key_exchange: []const u8,
};

/// TLS 1.3 Pre-Shared Key identity entry (RFC 8446 §4.2.11).
pub const PskIdentity = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,
};

/// TLS 1.3 pre_shared_key extension payload contents.
pub const PreSharedKey = struct {
    identities: []PskIdentity,
    binders: []const []const u8,
};

/// Parse a full TLS 1.3 ClientHello
pub fn parseClientHello(allocator: std.mem.Allocator, data: []const u8) !ClientHello {
    if (data.len < 34) return error.TooShort;

    var ch = ClientHello{
        .random = undefined,
        .session_id = &[_]u8{},
        .cipher_suites = &[_]CipherSuite{},
        .compression_methods = &[_]u8{},
    };

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
    const cs_len = readU16(data[pos .. pos + 2]);
    pos += 2;
    if (pos + cs_len > data.len) return error.TooShort;

    var cipher_suites = try std.ArrayList(CipherSuite).initCapacity(allocator, 0);
    defer cipher_suites.deinit(allocator);

    var cs_pos: usize = 0;
    while (cs_pos < cs_len) : (cs_pos += 2) {
        const cs_value = readU16(data[pos + cs_pos .. pos + cs_pos + 2]);
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
    const ext_len = readU16(data[pos .. pos + 2]);
    pos += 2;
    if (pos + ext_len > data.len) return error.TooShort;

    const ext_end = pos + ext_len;
    while (pos + 4 <= ext_end) {
        const ext_type = readU16(data[pos .. pos + 2]);
        const ext_data_len = readU16(data[pos + 2 .. pos + 4]);
        pos += 4;

        if (pos + ext_data_len > ext_end) return error.TooShort;
        const ext_data = data[pos .. pos + ext_data_len];

        // Use intToEnum to safely handle unknown extension types without panicking
        const ext = std.meta.intToEnum(ExtensionType, ext_type) catch {
            // Unknown extension type - ignore per TLS 1.3 spec
            pos += ext_data_len;
            continue;
        };

        switch (ext) {
            .server_name => {
                // Parse SNI
                if (ext_data.len >= 5) {
                    const list_len = readU16(ext_data[0..2]);
                    if (list_len > 0 and ext_data.len >= 5) {
                        const name_type = ext_data[2];
                        if (name_type == 0) { // host_name
                            const name_len = readU16(ext_data[3..5]);
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
                    const groups_len = readU16(ext_data[0..2]);
                    if (2 + groups_len <= ext_data.len) {
                        var groups = try std.ArrayList(NamedGroup).initCapacity(allocator, 0);
                        defer groups.deinit(allocator);

                        var g_pos: usize = 2;
                        while (g_pos + 2 <= 2 + groups_len) : (g_pos += 2) {
                            const group = readU16(ext_data[g_pos .. g_pos + 2]);
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
                    const algs_len = readU16(ext_data[0..2]);
                    if (2 + algs_len <= ext_data.len) {
                        var algs = try std.ArrayList(SignatureScheme).initCapacity(allocator, 0);
                        defer algs.deinit(allocator);

                        var a_pos: usize = 2;
                        while (a_pos + 2 <= 2 + algs_len) : (a_pos += 2) {
                            const alg = readU16(ext_data[a_pos .. a_pos + 2]);
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
                    const shares_len = readU16(ext_data[0..2]);
                    if (2 + shares_len <= ext_data.len) {
                        var ks_pos: usize = 2;
                        while (ks_pos + 4 <= 2 + shares_len) {
                            const group = readU16(ext_data[ks_pos .. ks_pos + 2]);
                            const key_len = readU16(ext_data[ks_pos + 2 .. ks_pos + 4]);
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
                    const list_len = readU16(ext_data[0..2]);
                    if (2 + list_len <= ext_data.len) {
                        var alpn_list = try std.ArrayList([]const u8).initCapacity(allocator, 0);
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
                const identities_len = readU16(ext_data[0..2]);
                if (identities_len + 2 > ext_data.len) return error.TooShort;

                var identities = try std.ArrayList(PskIdentity).initCapacity(allocator, 0);
                defer identities.deinit(allocator);

                var id_pos: usize = 2;
                const identities_end = 2 + identities_len;
                while (id_pos < identities_end) {
                    if (id_pos + 2 > identities_end) return error.TooShort;
                    const identity_len = readU16(ext_data[id_pos .. id_pos + 2]);
                    id_pos += 2;
                    if (id_pos + identity_len > identities_end) return error.TooShort;
                    const identity_bytes = ext_data[id_pos .. id_pos + identity_len];
                    id_pos += identity_len;
                    if (id_pos + 4 > identities_end) return error.TooShort;
                    const ticket_age = readU32(ext_data[id_pos .. id_pos + 4]);
                    id_pos += 4;
                    try identities.append(allocator, .{
                        .identity = identity_bytes,
                        .obfuscated_ticket_age = ticket_age,
                    });
                }
                if (id_pos != identities_end) return error.TooShort;

                if (id_pos + 2 > ext_data.len) return error.TooShort;
                const binders_len = readU16(ext_data[id_pos .. id_pos + 2]);
                id_pos += 2;
                if (id_pos + binders_len > ext_data.len) return error.TooShort;

                var binders = try std.ArrayList([]const u8).initCapacity(allocator, 0);
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

/// Build a proper TLS 1.3 ServerHello
pub fn buildServerHello(
    allocator: std.mem.Allocator,
    server_random: [32]u8,
    cipher_suite: CipherSuite,
    key_share_group: NamedGroup,
    key_share_data: []const u8,
    client_session_id: ?[]const u8,
    quic_params: ?[]const u8,
) ![]u8 {
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // Legacy version (TLS 1.2 for compatibility)
    try msg.appendSlice(allocator, &[_]u8{ 0x03, 0x03 });

    // Random
    try msg.appendSlice(allocator, &server_random);

    // Legacy session ID (echo from client per RFC 8446 Section 4.1.3)
    if (client_session_id) |session_id| {
        // Echo the client's session ID
        try msg.append(allocator, @intCast(session_id.len));
        try msg.appendSlice(allocator, session_id);
    } else {
        // No session ID from client
        try msg.append(allocator, 0);
    }

    // Cipher suite
    const cs_value = @intFromEnum(cipher_suite);
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(cs_value >> 8),
        @intCast(cs_value & 0xff),
    });

    // Legacy compression method
    try msg.append(allocator, 0);

    // Extensions
    var exts = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer exts.deinit(allocator);

    // CRITICAL: Extension order must match BoringSSL/Quiche for interoperability.
    // BoringSSL order (ssl/tls13_server.cc:938-941):
    //   1. pre_shared_key (if resuming)
    //   2. pake (if using PAKE)
    //   3. key_share
    //   4. supported_versions
    // We only support key_share and supported_versions, so our order is:
    //   1. key_share
    //   2. supported_versions
    // This is CRITICAL because transcript hash = SHA256(ClientHello || ServerHello)
    // and extension order affects the byte representation.

    // key_share (mandatory for ECDHE) - MUST BE FIRST (after PSK/PAKE if present)
    var ks_data = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer ks_data.deinit(allocator);
    const group_value = @intFromEnum(key_share_group);
    try ks_data.appendSlice(allocator, &[_]u8{
        @intCast(group_value >> 8),
        @intCast(group_value & 0xff),
    });
    try ks_data.appendSlice(allocator, &[_]u8{
        @intCast(key_share_data.len >> 8),
        @intCast(key_share_data.len & 0xff),
    });
    try ks_data.appendSlice(allocator, key_share_data);
    try writeExtension(allocator, &exts, .key_share, ks_data.items);

    // supported_versions (mandatory for TLS 1.3) - MUST BE AFTER key_share
    try writeExtension(allocator, &exts, .supported_versions, &[_]u8{ 0x03, 0x04 }); // TLS 1.3

    // NOTE: RFC 9001 §8.2 mandates that quic_transport_parameters goes in
    // EncryptedExtensions, NOT ServerHello. The quic_params parameter is
    // ignored here (and should always be null). Transport parameters are
    // added in buildEncryptedExtensions() instead.
    _ = quic_params; // Explicitly ignore to make it clear this is intentional

    // Write extensions length
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(exts.items.len >> 8),
        @intCast(exts.items.len & 0xff),
    });
    try msg.appendSlice(allocator, exts.items);

    return msg.toOwnedSlice(allocator);
}

/// Build EncryptedExtensions message
pub fn buildEncryptedExtensions(
    allocator: std.mem.Allocator,
    alpn: ?[]const u8,
    quic_params: ?[]const u8,
) ![]u8 {
    var exts = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer exts.deinit(allocator);

    // ALPN
    if (alpn) |proto| {
        var alpn_data = try std.ArrayList(u8).initCapacity(allocator, 0);
        defer alpn_data.deinit(allocator);

        const alpn_list_len = 1 + proto.len;
        try alpn_data.appendSlice(allocator, &[_]u8{
            @intCast(alpn_list_len >> 8),
            @intCast(alpn_list_len & 0xff),
        });
        try alpn_data.append(allocator, @intCast(proto.len));
        try alpn_data.appendSlice(allocator, proto);

        try writeExtension(allocator, &exts, .alpn, alpn_data.items);
    }

    // QUIC transport parameters
    if (quic_params) |params| {
        try writeExtension(allocator, &exts, .quic_transport_parameters, params);
    }

    // Build the message
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // Extensions length
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(exts.items.len >> 8),
        @intCast(exts.items.len & 0xff),
    });
    try msg.appendSlice(allocator, exts.items);

    return msg.toOwnedSlice(allocator);
}

/// Build Certificate message
pub fn buildCertificate(
    allocator: std.mem.Allocator,
    cert_chain: []const []const u8,
) ![]u8 {
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // Certificate request context (empty for server)
    try msg.append(allocator, 0);

    // Calculate total certificate list length
    var total_len: u24 = 0;
    for (cert_chain) |cert| {
        total_len += 3 + @as(u24, @intCast(cert.len)) + 2; // cert_data length + cert_data + extensions length
    }

    // Certificate list length (3 bytes)
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(total_len >> 16),
        @intCast((total_len >> 8) & 0xff),
        @intCast(total_len & 0xff),
    });

    // Certificate entries
    for (cert_chain) |cert| {
        // Certificate data length (3 bytes)
        const cert_len: u24 = @intCast(cert.len);
        try msg.appendSlice(allocator, &[_]u8{
            @intCast(cert_len >> 16),
            @intCast((cert_len >> 8) & 0xff),
            @intCast(cert_len & 0xff),
        });

        // Certificate data
        try msg.appendSlice(allocator, cert);

        // Certificate extensions (empty)
        try msg.appendSlice(allocator, &[_]u8{ 0x00, 0x00 });
    }

    return msg.toOwnedSlice(allocator);
}

/// Build CertificateVerify message
pub fn buildCertificateVerify(
    allocator: std.mem.Allocator,
    signature_scheme: SignatureScheme,
    signature: []const u8,
) ![]u8 {
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // Signature algorithm
    const scheme_value = @intFromEnum(signature_scheme);
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(scheme_value >> 8),
        @intCast(scheme_value & 0xff),
    });

    // Signature length
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(signature.len >> 8),
        @intCast(signature.len & 0xff),
    });

    // Signature
    try msg.appendSlice(allocator, signature);

    return msg.toOwnedSlice(allocator);
}

/// Build Finished message
pub fn buildFinished(
    allocator: std.mem.Allocator,
    verify_data: []const u8,
) ![]u8 {
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);
    try msg.appendSlice(allocator, verify_data);
    return msg.toOwnedSlice(allocator);
}

// Helper functions

fn readU16(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | data[1];
}

fn readU24(data: []const u8) u24 {
    return (@as(u24, data[0]) << 16) | (@as(u24, data[1]) << 8) | data[2];
}

fn readU32(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) | (@as(u32, data[1]) << 16) | (@as(u32, data[2]) << 8) | data[3];
}

fn writeExtension(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ext_type: ExtensionType,
    data: []const u8,
) !void {
    const type_value = @intFromEnum(ext_type);
    try list.appendSlice(allocator, &[_]u8{
        @intCast(type_value >> 8),
        @intCast(type_value & 0xff),
        @intCast(data.len >> 8),
        @intCast(data.len & 0xff),
    });
    try list.appendSlice(allocator, data);
}

/// Compute the signature for CertificateVerify
pub fn computeCertificateVerifySignature(
    private_key: []const u8,
    signature_scheme: SignatureScheme,
    transcript_hash: [H.digest_length]u8,
    is_server: bool,
) ![64]u8 {
    // TLS 1.3 CertificateVerify context string
    const context_string = if (is_server)
        "TLS 1.3, server CertificateVerify"
    else
        "TLS 1.3, client CertificateVerify";

    // Build the message to sign
    var msg: [64 + context_string.len + 1 + H.digest_length]u8 = undefined;
    @memset(msg[0..64], 0x20); // 64 spaces
    @memcpy(msg[64 .. 64 + context_string.len], context_string);
    msg[64 + context_string.len] = 0; // separator
    @memcpy(msg[65 + context_string.len ..], &transcript_hash);

    // For now, we only support Ed25519
    if (signature_scheme != .ed25519) {
        return error.UnsupportedSignatureScheme;
    }

    // Parse the private key (assuming Ed25519 seed format)
    if (private_key.len != 32) {
        return error.InvalidPrivateKey;
    }

    const kp = try std.crypto.sign.Ed25519.KeyPair.create(private_key[0..32].*);
    const signature = try std.crypto.sign.Ed25519.sign(&msg, kp, null);

    return signature;
}

/// Derive the Finished verify data
pub fn deriveFinishedVerifyData(
    traffic_secret: [H.digest_length]u8,
    transcript_hash: [H.digest_length]u8,
) [H.digest_length]u8 {
    var finished_key: [H.digest_length]u8 = undefined;
    ks.expandLabel(traffic_secret, "finished", &[_]u8{}, &finished_key) catch unreachable;
    return ks.hmacSha256(&finished_key, &transcript_hash);
}
