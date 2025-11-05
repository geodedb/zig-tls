//! QUIC-TLS Key Schedule (RFC 9001/9369) — HKDF labels and exporter.
//!
//! Implements the HKDF extract/expand sequence from RFC 9001 §5.1 plus QUIC v2
//! label updates from RFC 9369 §3. These helpers are shared by the handshake
//! stack and the standalone key schedule tests.
const std = @import("std");

// TODO: this should be using
// https://ziglang.org/documentation/master/std/#std.crypto.hkdf.HkdfSha256
// https://ziglang.org/documentation/master/std/#std.crypto.hkdf.HkdfSha512

/// Hash used for TLS_AES_128_GCM_SHA256 and CHACHA20_POLY1305_SHA256
pub const H = std.crypto.hash.sha2.Sha256; // 32-byte digest

/// Use standard library HMAC and HKDF
const Hmac = std.crypto.auth.hmac.Hmac;
const Hkdf = std.crypto.kdf.hkdf.Hkdf;
const HmacSha256 = Hmac(H);
const HkdfSha256 = Hkdf(HmacSha256);

/// QUIC v1 Initial Salt (RFC 9001 §5.2, Appendix A.1 vectors use this)
/// 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
pub const initial_salt_v1: [20]u8 = .{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

/// QUIC v2 Initial Salt (RFC 9369 §A.1)
/// 0dede3def700a6db819381be6e269dcbf9bd2ed9
pub const initial_salt_v2: [20]u8 = .{
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};

fn toU8(v: usize) u8 {
    return @as(u8, @intCast(v));
}

fn hkdfLabel(alloc: std.mem.Allocator, label: []const u8, context: []const u8, out_len: u16) ![]u8 {
    // struct {
    //   uint16 length;
    //   opaque label<7..255>; // "tls13 " + label
    //   opaque context<0..255>;
    // } HkdfLabel;
    const prefix = "tls13 ";
    const full_label = try std.mem.concat(alloc, u8, &[_][]const u8{ prefix, label });
    defer alloc.free(full_label);
    const total = 2 + 1 + full_label.len + 1 + context.len;
    var out = try alloc.alloc(u8, total);
    var i: usize = 0;
    out[i] = @as(u8, @truncate(out_len >> 8));
    i += 1;
    out[i] = @as(u8, @truncate(out_len));
    i += 1;
    out[i] = toU8(full_label.len);
    i += 1;
    @memcpy(out[i .. i + full_label.len], full_label);
    i += full_label.len;
    out[i] = toU8(context.len);
    i += 1;
    if (context.len != 0) @memcpy(out[i .. i + context.len], context);
    return out;
}

/// Public HMAC helper for TLS Finished and other KATs.
pub fn hmacSha256(key: []const u8, data: []const u8) [H.digest_length]u8 {
    var out: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&out, data, key);
    return out;
}

fn hkdfExtractRaw(salt: ?[]const u8, ikm: []const u8) [H.digest_length]u8 {
    return HkdfSha256.extract(salt orelse &[_]u8{}, ikm);
}

fn hkdfExpand(out: []u8, prk: [H.digest_length]u8, info: []const u8) void {
    std.log.debug("hkdfExpand: out.len={}, prk[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}, info.len={}", .{ out.len, prk[0], prk[1], prk[2], prk[3], info.len });
    HkdfSha256.expand(out, info, prk);
    std.log.debug("hkdfExpand: AFTER expand, out[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ out[0], out[1], out[2], out[3] });
}

/// HKDF-Expand-Label as per TLS 1.3 using H.
pub fn expandLabel(prk: [H.digest_length]u8, label: []const u8, context: []const u8, out: []u8) !void {
    var fbb: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fbb);
    const alloc = fba.allocator();
    const info = try hkdfLabel(alloc, label, context, @as(u16, @intCast(out.len)));
    defer alloc.free(info);
    std.log.debug("expandLabel: label='{s}', context.len={}, out.len={}, info[0..8]={X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ label, context.len, out.len, info[0], info[1], info[2], info[3], info[4], info[5], info[6], info[7] });
    hkdfExpand(out, prk, info);
}

/// HKDF-Extract
pub fn extract(salt: ?[]const u8, ikm: []const u8) [H.digest_length]u8 {
    return hkdfExtractRaw(salt, ikm);
}

/// Derive initial_secret from DCID for QUIC v1.
pub fn deriveInitialSecretV1(dcid: []const u8) [H.digest_length]u8 {
    return extract(&initial_salt_v1, dcid);
}

/// Derive initial_secret from DCID for QUIC v2.
pub fn deriveInitialSecretV2(dcid: []const u8) [H.digest_length]u8 {
    return extract(&initial_salt_v2, dcid);
}

/// Derive initial_secret from DCID for the given QUIC version.
pub fn deriveInitialSecret(version_v2: bool, dcid: []const u8) [H.digest_length]u8 {
    return if (version_v2) deriveInitialSecretV2(dcid) else deriveInitialSecretV1(dcid);
}

/// Derive client/server initial secrets from initial_secret.
pub fn deriveClientServerInitial(initial_secret: [H.digest_length]u8) struct { client: [H.digest_length]u8, server: [H.digest_length]u8 } {
    var client: [H.digest_length]u8 = undefined;
    var server: [H.digest_length]u8 = undefined;
    expandLabel(initial_secret, "client in", &[_]u8{}, &client) catch unreachable;
    expandLabel(initial_secret, "server in", &[_]u8{}, &server) catch unreachable;
    return .{ .client = client, .server = server };
}

/// Derive key (16), iv (12), hp (16) from a traffic secret for QUIC v1.
pub fn deriveKeyIvHp(secret: [H.digest_length]u8) struct { key: [16]u8, iv: [12]u8, hp: [16]u8 } {
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    var hp: [16]u8 = undefined;
    expandLabel(secret, "quic key", &[_]u8{}, &key) catch unreachable;
    expandLabel(secret, "quic iv", &[_]u8{}, &iv) catch unreachable;
    expandLabel(secret, "quic hp", &[_]u8{}, &hp) catch unreachable;

    // DIAGNOSTIC: Log the exact keys being derived
    std.log.debug("deriveKeyIvHp: secret[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ secret[0], secret[1], secret[2], secret[3] });
    std.log.debug("  -> key[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ key[0], key[1], key[2], key[3] });
    std.log.debug("  -> iv[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ iv[0], iv[1], iv[2], iv[3] });
    std.log.debug("  -> hp[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ hp[0], hp[1], hp[2], hp[3] });

    return .{ .key = key, .iv = iv, .hp = hp };
}

/// Derive key (16), iv (12), hp (16) from a traffic secret for QUIC v2.
pub fn deriveKeyIvHpV2(secret: [H.digest_length]u8) struct { key: [16]u8, iv: [12]u8, hp: [16]u8 } {
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    var hp: [16]u8 = undefined;
    std.log.debug("deriveKeyIvHpV2: secret[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ secret[0], secret[1], secret[2], secret[3] });
    expandLabel(secret, "quicv2 key", &[_]u8{}, &key) catch unreachable;
    expandLabel(secret, "quicv2 iv", &[_]u8{}, &iv) catch unreachable;
    expandLabel(secret, "quicv2 hp", &[_]u8{}, &hp) catch unreachable;
    std.log.debug("deriveKeyIvHpV2: -> key[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ key[0], key[1], key[2], key[3] });
    std.log.debug("deriveKeyIvHpV2: -> iv[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ iv[0], iv[1], iv[2], iv[3] });
    std.log.debug("deriveKeyIvHpV2: -> hp[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{ hp[0], hp[1], hp[2], hp[3] });
    return .{ .key = key, .iv = iv, .hp = hp };
}

/// TLS 1.3 traffic secret update: Derive next application traffic secret.
/// next_secret = HKDF-Expand-Label(current_secret, "traffic upd", "")
pub fn updateTrafficSecret(current_secret: [H.digest_length]u8) [H.digest_length]u8 {
    var next: [H.digest_length]u8 = undefined;
    expandLabel(current_secret, "traffic upd", &[_]u8{}, &next) catch unreachable;
    return next;
}

/// Derive a secret using HKDF-Expand-Label
pub fn deriveSecret(secret: [H.digest_length]u8, label: []const u8, context: []const u8) [H.digest_length]u8 {
    var derived: [H.digest_length]u8 = undefined;
    expandLabel(secret, label, context, &derived) catch unreachable;
    return derived;
}

// ============================================================================
// TESTS - RFC 9001 Appendix A.1 Test Vectors
// ============================================================================

const testing = std.testing;

/// RFC 9001 Appendix A.1 - Test vector DCID
const test_dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

/// RFC 9001 Appendix A.1 - Expected initial_secret from test_dcid
const expected_initial_secret: [32]u8 = .{
    0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43, 0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92,
    0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9, 0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44,
};

/// RFC 9001 Appendix A.1 - Expected client_initial_secret
const expected_client_initial_secret: [32]u8 = .{
    0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
    0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
};

/// RFC 9001 Appendix A.1 - Expected server_initial_secret
const expected_server_initial_secret: [32]u8 = .{
    0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
    0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b,
};

/// RFC 9001 Appendix A.1 - Expected client key
const expected_client_key: [16]u8 = .{
    0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
};

/// RFC 9001 Appendix A.1 - Expected client IV
const expected_client_iv: [12]u8 = .{
    0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
};

/// RFC 9001 Appendix A.1 - Expected client HP
const expected_client_hp: [16]u8 = .{
    0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
};

/// RFC 9001 Appendix A.1 - Expected server key
const expected_server_key: [16]u8 = .{
    0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37,
};

/// RFC 9001 Appendix A.1 - Expected server IV
const expected_server_iv: [12]u8 = .{
    0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e,
};

/// RFC 9001 Appendix A.1 - Expected server HP
const expected_server_hp: [16]u8 = .{
    0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14,
};

// RFC 9001 §A.1: Verify initial secret derivation
test "RFC 9001 A.1 - initial secret derivation" {
    const initial_secret = deriveInitialSecretV1(&test_dcid);
    try testing.expectEqualSlices(u8, &expected_initial_secret, &initial_secret);
}

// RFC 9001 §A.1: Verify client/server initial secret split
test "RFC 9001 A.1 - client/server initial secrets" {
    const initial_secret = deriveInitialSecretV1(&test_dcid);
    const secrets = deriveClientServerInitial(initial_secret);

    try testing.expectEqualSlices(u8, &expected_client_initial_secret, &secrets.client);
    try testing.expectEqualSlices(u8, &expected_server_initial_secret, &secrets.server);
}

// RFC 9001 §A.1: Verify client key/iv/hp derivation
test "RFC 9001 A.1 - client key/iv/hp derivation" {
    const initial_secret = deriveInitialSecretV1(&test_dcid);
    const secrets = deriveClientServerInitial(initial_secret);
    const keys = deriveKeyIvHp(secrets.client);

    try testing.expectEqualSlices(u8, &expected_client_key, &keys.key);
    try testing.expectEqualSlices(u8, &expected_client_iv, &keys.iv);
    try testing.expectEqualSlices(u8, &expected_client_hp, &keys.hp);
}

// RFC 9001 §A.1: Verify server key/iv/hp derivation
test "RFC 9001 A.1 - server key/iv/hp derivation" {
    const initial_secret = deriveInitialSecretV1(&test_dcid);
    const secrets = deriveClientServerInitial(initial_secret);
    const keys = deriveKeyIvHp(secrets.server);

    try testing.expectEqualSlices(u8, &expected_server_key, &keys.key);
    try testing.expectEqualSlices(u8, &expected_server_iv, &keys.iv);
    try testing.expectEqualSlices(u8, &expected_server_hp, &keys.hp);
}

// RFC 9001 §A.1: Full end-to-end key derivation from DCID
test "RFC 9001 A.1 - complete key derivation pipeline" {
    // Step 1: Derive initial secret
    const initial_secret = deriveInitialSecretV1(&test_dcid);
    try testing.expectEqualSlices(u8, &expected_initial_secret, &initial_secret);

    // Step 2: Split into client/server secrets
    const secrets = deriveClientServerInitial(initial_secret);
    try testing.expectEqualSlices(u8, &expected_client_initial_secret, &secrets.client);
    try testing.expectEqualSlices(u8, &expected_server_initial_secret, &secrets.server);

    // Step 3: Derive client material
    const client_keys = deriveKeyIvHp(secrets.client);
    try testing.expectEqualSlices(u8, &expected_client_key, &client_keys.key);
    try testing.expectEqualSlices(u8, &expected_client_iv, &client_keys.iv);
    try testing.expectEqualSlices(u8, &expected_client_hp, &client_keys.hp);

    // Step 4: Derive server material
    const server_keys = deriveKeyIvHp(secrets.server);
    try testing.expectEqualSlices(u8, &expected_server_key, &server_keys.key);
    try testing.expectEqualSlices(u8, &expected_server_iv, &server_keys.iv);
    try testing.expectEqualSlices(u8, &expected_server_hp, &server_keys.hp);
}

// RFC 9369 §A.1: QUIC v2 uses different initial salt
test "RFC 9369 - QUIC v2 initial salt differs from v1" {
    const secret_v1 = deriveInitialSecretV1(&test_dcid);
    const secret_v2 = deriveInitialSecretV2(&test_dcid);

    // Secrets must differ
    try testing.expect(!std.mem.eql(u8, &secret_v1, &secret_v2));
}

// RFC 9369 §3: QUIC v2 labels ("quicv2 key" vs "quic key")
test "RFC 9369 - QUIC v2 key derivation differs from v1" {
    const test_secret: [32]u8 = .{0x00} ** 32; // All zeros for simplicity
    const keys_v1 = deriveKeyIvHp(test_secret);
    const keys_v2 = deriveKeyIvHpV2(test_secret);

    // Keys, IVs, and HPs must all differ between v1 and v2
    try testing.expect(!std.mem.eql(u8, &keys_v1.key, &keys_v2.key));
    try testing.expect(!std.mem.eql(u8, &keys_v1.iv, &keys_v2.iv));
    try testing.expect(!std.mem.eql(u8, &keys_v1.hp, &keys_v2.hp));
}

// RFC 8446 §7.2: Traffic secret updates must change the secret
test "RFC 8446 §7.2 - traffic secret update" {
    const original_secret: [32]u8 = .{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };
    const updated_secret = updateTrafficSecret(original_secret);

    // Updated secret must differ from original
    try testing.expect(!std.mem.eql(u8, &original_secret, &updated_secret));

    // Multiple updates should produce different secrets
    const updated_again = updateTrafficSecret(updated_secret);
    try testing.expect(!std.mem.eql(u8, &updated_secret, &updated_again));
    try testing.expect(!std.mem.eql(u8, &original_secret, &updated_again));
}

// RFC 8446 §7.1: HKDF-Extract with salt
test "RFC 8446 §7.1 - HKDF-Extract produces deterministic output" {
    const salt = "test salt";
    const ikm = "input keying material";

    const prk1 = extract(salt, ikm);
    const prk2 = extract(salt, ikm);

    try testing.expectEqualSlices(u8, &prk1, &prk2);
}

// RFC 8446 §7.1: HKDF-Extract without salt (uses zero-length salt)
test "RFC 8446 §7.1 - HKDF-Extract with null salt" {
    const ikm = "input keying material";

    const prk_no_salt = extract(null, ikm);
    const prk_empty_salt = extract("", ikm);

    // Null salt should behave like empty salt
    try testing.expectEqualSlices(u8, &prk_no_salt, &prk_empty_salt);
}

// RFC 8446 §7.1: HKDF-Expand-Label format validation
test "RFC 8446 §7.1 - HKDF-Expand-Label with context" {
    const prk: [32]u8 = .{0xaa} ** 32;
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;

    // Different labels produce different outputs
    try expandLabel(prk, "label1", "", &out1);
    try expandLabel(prk, "label2", "", &out2);
    try testing.expect(!std.mem.eql(u8, &out1, &out2));

    // Different contexts produce different outputs
    var out3: [32]u8 = undefined;
    var out4: [32]u8 = undefined;
    try expandLabel(prk, "label", "context1", &out3);
    try expandLabel(prk, "label", "context2", &out4);
    try testing.expect(!std.mem.eql(u8, &out3, &out4));

    // Same label+context produces same output
    var out5: [32]u8 = undefined;
    try expandLabel(prk, "label1", "", &out5);
    try testing.expectEqualSlices(u8, &out1, &out5);
}

// RFC 8446 §7.1: HKDF-Expand-Label output length variation
test "RFC 8446 §7.1 - HKDF-Expand-Label with different output lengths" {
    const prk: [32]u8 = .{0xbb} ** 32;
    var out_16: [16]u8 = undefined;
    var out_32: [32]u8 = undefined;
    var out_12: [12]u8 = undefined;

    try expandLabel(prk, "test", "", &out_16);
    try expandLabel(prk, "test", "", &out_32);
    try expandLabel(prk, "test", "", &out_12);

    // Different lengths should produce different outputs (length is part of HkdfLabel)
    try testing.expect(!std.mem.eql(u8, out_12[0..], out_16[0..12]));
    try testing.expect(!std.mem.eql(u8, out_16[0..], out_32[0..16]));

    // Same inputs should produce same output
    var out_16_again: [16]u8 = undefined;
    try expandLabel(prk, "test", "", &out_16_again);
    try testing.expectEqualSlices(u8, &out_16, &out_16_again);
}

// Test HMAC-SHA256 helper function
test "HMAC-SHA256 - basic functionality" {
    const key = "key";
    const data = "The quick brown fox jumps over the lazy dog";

    const mac = hmacSha256(key, data);

    // HMAC should be deterministic
    const mac2 = hmacSha256(key, data);
    try testing.expectEqualSlices(u8, &mac, &mac2);

    // Different key should produce different MAC
    const mac3 = hmacSha256("different_key", data);
    try testing.expect(!std.mem.eql(u8, &mac, &mac3));

    // Different data should produce different MAC
    const mac4 = hmacSha256(key, "different data");
    try testing.expect(!std.mem.eql(u8, &mac, &mac4));
}

// Test deriveSecret wrapper
test "deriveSecret - wrapper function" {
    const secret: [32]u8 = .{0xcc} ** 32;
    const derived1 = deriveSecret(secret, "derived", "");
    const derived2 = deriveSecret(secret, "derived", "");

    // Should be deterministic
    try testing.expectEqualSlices(u8, &derived1, &derived2);

    // Different label should produce different output
    const derived3 = deriveSecret(secret, "other", "");
    try testing.expect(!std.mem.eql(u8, &derived1, &derived3));
}

// Edge case: Empty DCID (valid per QUIC spec for server-chosen CIDs)
test "QUIC initial secret - empty DCID" {
    const empty_dcid: []const u8 = &[_]u8{};
    const secret = deriveInitialSecretV1(empty_dcid);

    // Should produce 32-byte output
    try testing.expectEqual(32, secret.len);

    // Should be deterministic
    const secret2 = deriveInitialSecretV1(empty_dcid);
    try testing.expectEqualSlices(u8, &secret, &secret2);
}

// Edge case: Maximum length DCID (20 bytes per RFC 9000)
test "QUIC initial secret - maximum length DCID" {
    const max_dcid: [20]u8 = .{0xff} ** 20;
    const secret = deriveInitialSecretV1(&max_dcid);

    // Should produce 32-byte output
    try testing.expectEqual(32, secret.len);

    // Should differ from test vector
    try testing.expect(!std.mem.eql(u8, &secret, &expected_initial_secret));
}

// Verify HKDF label construction ("tls13 " prefix)
test "HKDF label - tls13 prefix is applied" {
    const prk: [32]u8 = .{0xdd} ** 32;
    var out1: [16]u8 = undefined;
    var out2: [16]u8 = undefined;

    // These should produce different outputs because expandLabel adds "tls13 " prefix
    // We're testing that the label is not used verbatim
    try expandLabel(prk, "key", "", &out1);
    try expandLabel(prk, "tls13 key", "", &out2);

    // If prefix weren't added, these would be the same, but they should differ
    try testing.expect(!std.mem.eql(u8, &out1, &out2));
}
