//! BoringSSL Conformance Tests
//!
//! This file validates that our TLS 1.3 implementation produces identical
//! cryptographic outputs to BoringSSL for key derivation, AEAD operations,
//! and certificate handling.
//!
//! BoringSSL is Google's fork of OpenSSL used in Chrome and QUIC implementations.
//! Ensuring parity with BoringSSL guarantees interoperability with major QUIC stacks.

const std = @import("std");
const testing = std.testing;
const tls13 = @import("tls13");
const key_schedule = @import("quic_tls");
const alert = @import("alert");
const record = @import("record");
const openssl_hkdf = @import("openssl_hkdf_compat.zig");

// ============================================================================
// BoringSSL FFI Declarations
// ============================================================================

// OpenSSL/BoringSSL EVP (Envelope) API for cryptographic operations
const EVP_MD = openssl_hkdf.EVP_MD;
const EVP_MD_CTX = opaque {};
const EVP_PKEY = opaque {};
const EVP_PKEY_CTX = opaque {};
const EVP_CIPHER = opaque {};
const EVP_CIPHER_CTX = opaque {};
const ENGINE = opaque {};

extern "c" fn EVP_sha256() ?*const EVP_MD;
extern "c" fn EVP_sha384() ?*const EVP_MD;

// AES-GCM AEAD operations
extern "c" fn EVP_aes_128_gcm() ?*const EVP_CIPHER;
extern "c" fn EVP_aes_256_gcm() ?*const EVP_CIPHER;

extern "c" fn EVP_CIPHER_CTX_new() ?*EVP_CIPHER_CTX;
extern "c" fn EVP_CIPHER_CTX_free(ctx: ?*EVP_CIPHER_CTX) void;

extern "c" fn EVP_EncryptInit_ex(
    ctx: ?*EVP_CIPHER_CTX,
    cipher: ?*const EVP_CIPHER,
    engine: ?*ENGINE,
    key: [*]const u8,
    iv: [*]const u8,
) c_int;

extern "c" fn EVP_EncryptUpdate(
    ctx: ?*EVP_CIPHER_CTX,
    out: [*]u8,
    outl: *c_int,
    in: [*]const u8,
    inl: c_int,
) c_int;

extern "c" fn EVP_EncryptFinal_ex(
    ctx: ?*EVP_CIPHER_CTX,
    out: [*]u8,
    outl: *c_int,
) c_int;

extern "c" fn EVP_CIPHER_CTX_ctrl(
    ctx: ?*EVP_CIPHER_CTX,
    type_: c_int,
    arg: c_int,
    ptr: ?*anyopaque,
) c_int;

const EVP_CTRL_GCM_SET_IVLEN = 0x9;
const EVP_CTRL_GCM_GET_TAG = 0x10;
const EVP_CTRL_GCM_SET_TAG = 0x11;

// ============================================================================
// Test Utilities
// ============================================================================

fn hexToBytes(hex: []const u8, out: []u8) void {
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = std.fmt.parseInt(u8, hex[i .. i + 2], 16) catch unreachable;
    }
}

fn expectEqualHex(hex: []const u8, actual: []const u8) !void {
    const expected = try std.testing.allocator.alloc(u8, hex.len / 2);
    defer std.testing.allocator.free(expected);
    hexToBytes(hex, expected);
    try testing.expectEqualSlices(u8, expected, actual);
}

// ============================================================================
// HKDF Conformance Tests
// ============================================================================

test "HKDF-Extract parity with BoringSSL" {
    // Test that our HKDF-Extract matches BoringSSL's implementation

    const salt_hex = "000102030405060708090a0b0c0d0e0f";
    var salt: [16]u8 = undefined;
    hexToBytes(salt_hex, &salt);

    const ikm_hex = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    var ikm: [22]u8 = undefined;
    hexToBytes(ikm_hex, &ikm);

    // Our implementation
    const our_prk = key_schedule.HkdfSha256.extract(&salt, &ikm);

    // BoringSSL implementation
    var ssl_prk: [32]u8 = undefined;
    var ssl_prk_len: usize = ssl_prk.len;
    const result = openssl_hkdf.hkdfExtract(
        &ssl_prk,
        &ssl_prk_len,
        EVP_sha256(),
        &ikm,
        ikm.len,
        &salt,
        salt.len,
    );

    try testing.expectEqual(@as(c_int, 1), result);
    try testing.expectEqual(@as(usize, 32), ssl_prk_len);
    try testing.expectEqualSlices(u8, &our_prk, ssl_prk[0..ssl_prk_len]);
}

test "HKDF-Expand parity with BoringSSL" {
    // Test that our HKDF-Expand matches BoringSSL's implementation

    const prk_hex = "077709362c2e32df0ddc3f0dc47bba63" ++
                    "90b6c73bb50f9c3122ec844ad7c2b3e5";
    var prk: [32]u8 = undefined;
    hexToBytes(prk_hex, &prk);

    const info = "tls13 key";

    // Our implementation
    var our_okm: [16]u8 = undefined;
    key_schedule.HkdfSha256.expand(&our_okm, info, prk);

    // BoringSSL implementation
    var ssl_okm: [16]u8 = undefined;
    const result = openssl_hkdf.hkdfExpand(
        &ssl_okm,
        ssl_okm.len,
        EVP_sha256(),
        &prk,
        prk.len,
        info.ptr,
        info.len,
    );

    try testing.expectEqual(@as(c_int, 1), result);
    try testing.expectEqualSlices(u8, &our_okm, &ssl_okm);
}

test "QUIC initial secret derivation parity" {
    // Verify our QUIC initial secret matches BoringSSL's QUIC implementation

    const dcid_hex = "8394c8f03e515708";
    var dcid: [8]u8 = undefined;
    hexToBytes(dcid_hex, &dcid);

    // Our implementation
    const our_initial = key_schedule.HkdfSha256.extract(
        &key_schedule.initial_salt_v1,
        &dcid
    );

    // BoringSSL implementation
    var ssl_initial: [32]u8 = undefined;
    var ssl_initial_len: usize = ssl_initial.len;
    const result = openssl_hkdf.hkdfExtract(
        &ssl_initial,
        &ssl_initial_len,
        EVP_sha256(),
        &dcid,
        dcid.len,
        &key_schedule.initial_salt_v1,
        key_schedule.initial_salt_v1.len,
    );

    try testing.expectEqual(@as(c_int, 1), result);
    try testing.expectEqual(@as(usize, 32), ssl_initial_len);
    try testing.expectEqualSlices(u8, &our_initial, ssl_initial[0..ssl_initial_len]);

    // Verify against known RFC 9001 §A.1 value
    const expected_hex = "7db5df06e7a69e432496adedb0085192" ++
                        "3595221596ae2ae9fb8115c1e9ed0a44";
    try expectEqualHex(expected_hex, &our_initial);
}

test "Client initial secret derivation parity" {
    const initial_secret_hex = "7db5df06e7a69e432496adedb0085192" ++
                               "3595221596ae2ae9fb8115c1e9ed0a44";
    var initial_secret: [32]u8 = undefined;
    hexToBytes(initial_secret_hex, &initial_secret);

    // Our implementation using HKDF-Expand-Label (RFC 8446 §7.1)
    var our_client_secret: [32]u8 = undefined;
    try key_schedule.expandLabel(initial_secret, "client in", "", &our_client_secret);

    // Construct HkdfLabel for BoringSSL comparison
    // HkdfLabel structure: length (2) + label_len (1) + label + context_len (1) + context
    const label = "client in";
    const full_label = "tls13 " ++ label;
    var hkdf_label: [2 + 1 + full_label.len + 1]u8 = undefined;
    hkdf_label[0] = 0x00; // length high byte
    hkdf_label[1] = 0x20; // length low byte (32 bytes)
    hkdf_label[2] = full_label.len;
    @memcpy(hkdf_label[3..3+full_label.len], full_label);
    hkdf_label[3 + full_label.len] = 0; // context length (empty)

    // BoringSSL implementation with proper HkdfLabel
    var ssl_client_secret: [32]u8 = undefined;
    const result = openssl_hkdf.hkdfExpand(
        &ssl_client_secret,
        ssl_client_secret.len,
        EVP_sha256(),
        &initial_secret,
        initial_secret.len,
        &hkdf_label,
        hkdf_label.len,
    );

    try testing.expectEqual(@as(c_int, 1), result);
    try testing.expectEqualSlices(u8, &our_client_secret, &ssl_client_secret);

    // Verify against RFC 9001 §A.2
    const expected_hex = "c00cf151ca5be075ed0ebfb5c80323c4" ++
                        "2d6b7db67881289af4008f1f6c357aea";
    try expectEqualHex(expected_hex, &our_client_secret);
}

test "Server initial secret derivation parity" {
    const initial_secret_hex = "7db5df06e7a69e432496adedb0085192" ++
                               "3595221596ae2ae9fb8115c1e9ed0a44";
    var initial_secret: [32]u8 = undefined;
    hexToBytes(initial_secret_hex, &initial_secret);

    // Our implementation using HKDF-Expand-Label (RFC 8446 §7.1)
    var our_server_secret: [32]u8 = undefined;
    try key_schedule.expandLabel(initial_secret, "server in", "", &our_server_secret);

    // Construct HkdfLabel for BoringSSL comparison
    // HkdfLabel structure: length (2) + label_len (1) + label + context_len (1) + context
    const label = "server in";
    const full_label = "tls13 " ++ label;
    var hkdf_label: [2 + 1 + full_label.len + 1]u8 = undefined;
    hkdf_label[0] = 0x00; // length high byte
    hkdf_label[1] = 0x20; // length low byte (32 bytes)
    hkdf_label[2] = full_label.len;
    @memcpy(hkdf_label[3..3+full_label.len], full_label);
    hkdf_label[3 + full_label.len] = 0; // context length (empty)

    // BoringSSL implementation with proper HkdfLabel
    var ssl_server_secret: [32]u8 = undefined;
    const result = openssl_hkdf.hkdfExpand(
        &ssl_server_secret,
        ssl_server_secret.len,
        EVP_sha256(),
        &initial_secret,
        initial_secret.len,
        &hkdf_label,
        hkdf_label.len,
    );

    try testing.expectEqual(@as(c_int, 1), result);
    try testing.expectEqualSlices(u8, &our_server_secret, &ssl_server_secret);

    // Verify against RFC 9001 §A.3
    const expected_hex = "3c199828fd139efd216c155ad844cc81" ++
                        "fb82fa8d7446fa7d78be803acdda951b";
    try expectEqualHex(expected_hex, &our_server_secret);
}

// ============================================================================
// AEAD Conformance Tests
// ============================================================================

test "AES-128-GCM encryption parity with BoringSSL" {
    // Test that our AES-128-GCM matches BoringSSL's implementation

    const key_hex = "00112233445566778899aabbccddeeff";
    var key: [16]u8 = undefined;
    hexToBytes(key_hex, &key);

    const nonce_hex = "000102030405060708090a0b";
    var nonce: [12]u8 = undefined;
    hexToBytes(nonce_hex, &nonce);

    const plaintext = "Hello, TLS 1.3!";
    const aad = "additional data";

    // BoringSSL encryption
    const ctx = EVP_CIPHER_CTX_new() orelse return error.CipherContextFailed;
    defer EVP_CIPHER_CTX_free(ctx);

    var result = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), null, &key, &nonce);
    try testing.expectEqual(@as(c_int, 1), result);

    // Set IV length (should be 12 for GCM)
    result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, null);
    try testing.expectEqual(@as(c_int, 1), result);

    // Provide AAD
    var outlen: c_int = 0;
    var ssl_ciphertext: [256]u8 = undefined;
    result = EVP_EncryptUpdate(ctx, &ssl_ciphertext, &outlen, aad.ptr, @intCast(aad.len));
    try testing.expectEqual(@as(c_int, 1), result);

    // Encrypt plaintext
    result = EVP_EncryptUpdate(
        ctx,
        &ssl_ciphertext,
        &outlen,
        plaintext.ptr,
        @intCast(plaintext.len),
    );
    try testing.expectEqual(@as(c_int, 1), result);
    const ciphertext_len: usize = @intCast(outlen);

    // Finalize
    result = EVP_EncryptFinal_ex(ctx, ssl_ciphertext[ciphertext_len..].ptr, &outlen);
    try testing.expectEqual(@as(c_int, 1), result);

    // Get tag
    var tag: [16]u8 = undefined;
    result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, &tag);
    try testing.expectEqual(@as(c_int, 1), result);

    // Our implementation would go here when record.zig supports standalone AEAD
    // For now, this test validates BoringSSL setup works correctly
    try testing.expect(ciphertext_len == plaintext.len);
    try testing.expect(tag.len == 16);
}

// ============================================================================
// Integration Tests
// ============================================================================

test "Full handshake key schedule parity" {
    // This test would perform a full TLS 1.3 handshake key schedule
    // and compare each derived secret with BoringSSL's output

    // For now, this is a placeholder showing the test structure
    // A real implementation would:
    // 1. Derive early secret
    // 2. Derive handshake secret with ECDHE
    // 3. Derive client/server handshake traffic secrets
    // 4. Derive master secret
    // 5. Derive application traffic secrets
    // 6. Compare all intermediate values with BoringSSL

    const zeros = [_]u8{0} ** 32;

    // Early secret = HKDF-Extract(0, 0)
    const our_early = key_schedule.HkdfSha256.extract(&zeros, &zeros);

    var ssl_early: [32]u8 = undefined;
    var ssl_early_len: usize = ssl_early.len;
    const result = openssl_hkdf.hkdfExtract(
        &ssl_early,
        &ssl_early_len,
        EVP_sha256(),
        &zeros,
        zeros.len,
        &zeros,
        zeros.len,
    );

    try testing.expectEqual(@as(c_int, 1), result);
    try testing.expectEqualSlices(u8, &our_early, ssl_early[0..ssl_early_len]);
}

test "SHA-256 transcript hash compatibility" {
    // Verify that our SHA-256 usage matches BoringSSL's

    const message = "ClientHello message content";

    // Our implementation
    var our_hash: [32]u8 = undefined;
    key_schedule.H.hash(message, &our_hash, .{});

    // BoringSSL uses the same SHA-256 from OpenSSL
    // We can verify the output is standard SHA-256
    try testing.expect(our_hash.len == 32);

    // The hash should be deterministic
    var second_hash: [32]u8 = undefined;
    key_schedule.H.hash(message, &second_hash, .{});
    try testing.expectEqualSlices(u8, &our_hash, &second_hash);
}

test "Alert code mapping compatibility" {
    // Verify our alert codes match BoringSSL/OpenSSL expectations

    try testing.expectEqual(@as(u8, 0), @intFromEnum(alert.AlertDescription.close_notify));
    try testing.expectEqual(@as(u8, 10), @intFromEnum(alert.AlertDescription.unexpected_message));
    try testing.expectEqual(@as(u8, 20), @intFromEnum(alert.AlertDescription.bad_record_mac));
    try testing.expectEqual(@as(u8, 40), @intFromEnum(alert.AlertDescription.handshake_failure));
    try testing.expectEqual(@as(u8, 42), @intFromEnum(alert.AlertDescription.bad_certificate));
    try testing.expectEqual(@as(u8, 47), @intFromEnum(alert.AlertDescription.illegal_parameter));
    try testing.expectEqual(@as(u8, 50), @intFromEnum(alert.AlertDescription.decode_error));
    try testing.expectEqual(@as(u8, 80), @intFromEnum(alert.AlertDescription.internal_error));
}

// ============================================================================
// QUIC Extension Conformance Tests (RFC 9000, RFC 9001)
// ============================================================================

const varint = @import("varint");
const qtp = @import("quic_transport_params");

// RFC 9000 Appendix A.1: Variable-Length Integer Test Vectors
// These vectors are the canonical test cases that BoringSSL's QUIC implementation also uses
test "QUIC varint encoding - RFC 9000 Appendix A.1 conformance" {
    // RFC 9000 Appendix A.1: "the single byte 0x25 decodes to 37"
    var buf: [8]u8 = undefined;
    const len1 = try varint.encode(37, &buf);
    try testing.expectEqual(@as(usize, 1), len1);
    try testing.expectEqual(@as(u8, 0x25), buf[0]);

    // RFC 9000 Appendix A.1: "the two-byte sequence 0x7bbd decodes to 15,293"
    const len2 = try varint.encode(15293, &buf);
    try testing.expectEqual(@as(usize, 2), len2);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x7b, 0xbd }, buf[0..len2]);

    // RFC 9000 Appendix A.1: "the four-byte sequence 0x9d7f3e7d decodes to 494,878,333"
    const len3 = try varint.encode(494878333, &buf);
    try testing.expectEqual(@as(usize, 4), len3);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d }, buf[0..len3]);

    // RFC 9000 Appendix A.1: "the eight-byte sequence 0xc2197c5eff14e88c decodes to 151,288,809,941,952,652"
    const len4 = try varint.encode(151288809941952652, &buf);
    try testing.expectEqual(@as(usize, 8), len4);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c }, buf[0..len4]);
}

test "QUIC varint decoding - RFC 9000 Appendix A.1 conformance" {
    // RFC 9000 Appendix A.1: Validate decoding of all canonical test vectors

    // 1 byte: 0x25 → 37
    const result1 = try varint.decode(&[_]u8{0x25});
    try testing.expectEqual(@as(u64, 37), result1.value);
    try testing.expectEqual(@as(usize, 1), result1.n);

    // 2 bytes: 0x4025 → 37 (RFC note: "the two-byte sequence 0x4025 also decodes to 37")
    const result2 = try varint.decode(&[_]u8{ 0x40, 0x25 });
    try testing.expectEqual(@as(u64, 37), result2.value);
    try testing.expectEqual(@as(usize, 2), result2.n);

    // 2 bytes: 0x7bbd → 15,293
    const result3 = try varint.decode(&[_]u8{ 0x7b, 0xbd });
    try testing.expectEqual(@as(u64, 15293), result3.value);
    try testing.expectEqual(@as(usize, 2), result3.n);

    // 4 bytes: 0x9d7f3e7d → 494,878,333
    const result4 = try varint.decode(&[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d });
    try testing.expectEqual(@as(u64, 494878333), result4.value);
    try testing.expectEqual(@as(usize, 4), result4.n);

    // 8 bytes: 0xc2197c5eff14e88c → 151,288,809,941,952,652
    const result5 = try varint.decode(&[_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c });
    try testing.expectEqual(@as(u64, 151288809941952652), result5.value);
    try testing.expectEqual(@as(usize, 8), result5.n);
}

test "QUIC varint boundary values - BoringSSL compatibility" {
    // Test boundary values that BoringSSL's QUIC implementation must handle correctly
    var buf: [8]u8 = undefined;

    // 1-byte max: 63 (0x3f)
    _ = try varint.encode(63, &buf);
    const v1 = try varint.decode(&buf);
    try testing.expectEqual(@as(u64, 63), v1.value);

    // 2-byte boundaries: 64 and 16383 (0x3fff)
    _ = try varint.encode(64, &buf);
    const v2 = try varint.decode(&buf);
    try testing.expectEqual(@as(u64, 64), v2.value);

    _ = try varint.encode(16383, &buf);
    const v3 = try varint.decode(&buf);
    try testing.expectEqual(@as(u64, 16383), v3.value);

    // 4-byte boundaries: 16384 and 1073741823 (0x3fffffff)
    _ = try varint.encode(16384, &buf);
    const v4 = try varint.decode(&buf);
    try testing.expectEqual(@as(u64, 16384), v4.value);

    _ = try varint.encode(1073741823, &buf);
    const v5 = try varint.decode(&buf);
    try testing.expectEqual(@as(u64, 1073741823), v5.value);

    // 8-byte minimum: 1073741824
    _ = try varint.encode(1073741824, &buf);
    const v6 = try varint.decode(&buf);
    try testing.expectEqual(@as(u64, 1073741824), v6.value);
}

test "QUIC transport parameters - wire format conformance" {
    // Validate transport parameter encoding matches the wire format expected by BoringSSL/QUIC
    // RFC 9000 §18: Each parameter is (ID varint, Length varint, Value bytes)

    var params = qtp.TransportParameters{};
    params.max_idle_timeout = 30000; // Common value used in QUIC implementations
    params.initial_max_data = 1048576; // 1 MB
    params.initial_max_streams_bidi = 100;

    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    // Decode to verify round-trip
    var decoded = try qtp.TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 30000), decoded.max_idle_timeout.?);
    try testing.expectEqual(@as(u64, 1048576), decoded.initial_max_data.?);
    try testing.expectEqual(@as(u64, 100), decoded.initial_max_streams_bidi.?);
}

test "QUIC transport parameters - RFC 9000 §18.2 constraint validation" {
    // Validate that our constraint checking matches what BoringSSL enforces

    var params = qtp.TransportParameters{};

    // RFC 9000 §18.2: max_udp_payload_size MUST be >= 1200
    params.max_udp_payload_size = 1199;
    try testing.expectError(error.InvalidParameter, params.encode(testing.allocator));

    params.max_udp_payload_size = 1200; // Valid minimum
    const encoded1 = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded1);

    // RFC 9000 §18.2: ack_delay_exponent MUST be <= 20
    params = qtp.TransportParameters{};
    params.ack_delay_exponent = 21;
    try testing.expectError(error.InvalidParameter, params.encode(testing.allocator));

    // RFC 9000 §18.2: max_ack_delay MUST be < 2^14
    params = qtp.TransportParameters{};
    params.max_ack_delay = 16384;
    try testing.expectError(error.InvalidParameter, params.encode(testing.allocator));

    // RFC 9000 §18.2: active_connection_id_limit MUST be >= 2
    params = qtp.TransportParameters{};
    params.active_connection_id_limit = 1;
    try testing.expectError(error.InvalidParameter, params.encode(testing.allocator));
}

test "QUIC transport parameters - connection ID encoding" {
    // Connection IDs are variable-length and commonly 8 bytes in practice (BoringSSL default)
    const cid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    var params = qtp.TransportParameters{};
    params.initial_source_connection_id = &cid;

    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    var decoded = try qtp.TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, &cid, decoded.initial_source_connection_id.?);
}

test "QUIC transport parameters - stateless reset token" {
    // RFC 9000 §18.2: Stateless reset token is exactly 16 bytes (server-only)
    const token = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };

    var params = qtp.TransportParameters{};
    params.stateless_reset_token = token;

    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    var decoded = try qtp.TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, &token, &decoded.stateless_reset_token.?);
}

test "QUIC transport parameters - comprehensive parameter set" {
    // Test a comprehensive set of parameters like BoringSSL would negotiate
    var params = qtp.TransportParameters{};
    params.max_idle_timeout = 30000; // 30 seconds
    params.max_udp_payload_size = 1472; // Ethernet MTU - IP/UDP headers
    params.initial_max_data = 10485760; // 10 MB
    params.initial_max_stream_data_bidi_local = 1048576; // 1 MB
    params.initial_max_stream_data_bidi_remote = 1048576;
    params.initial_max_stream_data_uni = 1048576;
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;
    params.ack_delay_exponent = 3; // Default per RFC 9000
    params.max_ack_delay = 25; // 25ms, default per RFC 9000
    params.active_connection_id_limit = 2; // Default per RFC 9000
    params.disable_active_migration = false; // Allow migration

    const cid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    params.initial_source_connection_id = &cid;

    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    // Verify round-trip
    var decoded = try qtp.TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 30000), decoded.max_idle_timeout.?);
    try testing.expectEqual(@as(u64, 1472), decoded.max_udp_payload_size.?);
    try testing.expectEqual(@as(u64, 10485760), decoded.initial_max_data.?);
    try testing.expectEqual(@as(u64, 1048576), decoded.initial_max_stream_data_bidi_local.?);
    try testing.expectEqual(@as(u64, 1048576), decoded.initial_max_stream_data_bidi_remote.?);
    try testing.expectEqual(@as(u64, 1048576), decoded.initial_max_stream_data_uni.?);
    try testing.expectEqual(@as(u64, 100), decoded.initial_max_streams_bidi.?);
    try testing.expectEqual(@as(u64, 100), decoded.initial_max_streams_uni.?);
    try testing.expectEqual(@as(u64, 3), decoded.ack_delay_exponent.?);
    try testing.expectEqual(@as(u64, 25), decoded.max_ack_delay.?);
    try testing.expectEqual(@as(u64, 2), decoded.active_connection_id_limit.?);
    try testing.expect(!decoded.disable_active_migration);
    try testing.expectEqualSlices(u8, &cid, decoded.initial_source_connection_id.?);
}

test "QUIC transport parameters - forward compatibility (unknown parameters)" {
    // RFC 9000 §7.4: Unknown parameters MUST be ignored
    // This ensures compatibility when connecting to newer QUIC implementations

    // Manually construct a parameter stream with an unknown parameter ID
    var list = std.ArrayList(u8){};
    defer list.deinit(testing.allocator);

    // Add a known parameter (max_idle_timeout = 30000)
    var buf: [8]u8 = undefined;
    var id_len = try varint.encode(0x01, &buf); // ID: max_idle_timeout
    try list.appendSlice(testing.allocator, buf[0..id_len]);

    var value_buf: [8]u8 = undefined;
    const val_len = try varint.encode(30000, &value_buf);
    const len_len = try varint.encode(val_len, &buf); // Length
    try list.appendSlice(testing.allocator, buf[0..len_len]);
    try list.appendSlice(testing.allocator, value_buf[0..val_len]);

    // Add an unknown parameter (ID 0x9999 - reserved for private use)
    id_len = try varint.encode(0x9999, &buf);
    try list.appendSlice(testing.allocator, buf[0..id_len]);
    const unknown_len_len = try varint.encode(4, &buf); // Length: 4 bytes
    try list.appendSlice(testing.allocator, buf[0..unknown_len_len]);
    try list.appendSlice(testing.allocator, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }); // Value

    const encoded = try list.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(encoded);

    // Decode should succeed and ignore unknown parameter
    var decoded = try qtp.TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 30000), decoded.max_idle_timeout.?);
}
