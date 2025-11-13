//! Handshake Secret Derivation Conformance Tests
//!
//! This test suite validates that ztls derives TLS 1.3 handshake secrets
//! identically to OpenSSL/BoringSSL reference implementations.
//!
//! Critical for QUIC interop - secret mismatch causes decryption failures.

const std = @import("std");
const testing = std.testing;
const key_schedule = @import("quic_tls");
const tls13 = @import("tls13");

// OpenSSL C bindings for reference implementation
const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/kdf.h");
    @cInclude("openssl/hkdf.h");
    @cInclude("openssl/sha.h");
});

/// Helper to convert hex string to bytes
fn hexToBytes(comptime hex: []const u8, out: []u8) void {
    comptime var i: usize = 0;
    inline while (i < hex.len) : (i += 2) {
        out[i / 2] = std.fmt.parseInt(u8, hex[i .. i + 2], 16) catch unreachable;
    }
}

/// Helper to compare hex string with bytes
fn expectEqualHex(comptime hex: []const u8, actual: []const u8) !void {
    var expected: [hex.len / 2]u8 = undefined;
    hexToBytes(hex, &expected);

    std.debug.print("\nExpected ({} bytes): ", .{expected.len});
    for (expected) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\nActual   ({} bytes): ", .{actual.len});
    for (actual) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n", .{});

    try testing.expectEqualSlices(u8, &expected, actual);
}

// Test HKDF-Expand-Label against OpenSSL's implementation
test "HKDF-Expand-Label - OpenSSL parity" {
    // Test vector: derive a 16-byte key from a 32-byte secret
    const prk_hex =
        "33ad0a1c607ec03b09e6cd9893680ce2" ++
        "10adf300aa1f2660e1b22e10f170f92a";
    var prk: [32]u8 = undefined;
    hexToBytes(prk_hex, &prk);

    const label = "key";
    const context = "";
    var ztls_out: [16]u8 = undefined;

    // Derive using ztls
    try key_schedule.expandLabel(prk[0..], label, context, &ztls_out);

    // Derive using OpenSSL HKDF-Expand
    // We need to manually construct the HkdfLabel structure:
    // struct {
    //     uint16 length;           // 16 (0x0010)
    //     opaque label<7..255>;    // "tls13 key" (length=9, 0x09 + "tls13 key")
    //     opaque context<0..255>;  // "" (length=0, 0x00)
    // }

    const full_label = "tls13 " ++ label; // "tls13 key" = 9 bytes
    var info: [2 + 1 + full_label.len + 1]u8 = undefined;
    info[0] = 0x00; // length high byte
    info[1] = 0x10; // length low byte (16)
    info[2] = @intCast(full_label.len); // label length
    @memcpy(info[3 .. 3 + full_label.len], full_label);
    info[3 + full_label.len] = 0x00; // context length (empty)

    var openssl_out: [16]u8 = undefined;
    const ret = c.HKDF_expand(
        openssl_out[0..].ptr,
        openssl_out.len,
        c.EVP_sha256(),
        prk[0..].ptr,
        prk.len,
        info[0..].ptr,
        info.len,
    );
    try testing.expect(ret == 1); // OpenSSL success

    std.debug.print("\nHKDF-Expand-Label test:\n", .{});
    std.debug.print("PRK:     ", .{});
    for (prk) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\nLabel:   \"{s}\"\n", .{full_label});
    std.debug.print("Info:    ", .{});
    for (info) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\nztls:    ", .{});
    for (ztls_out) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\nOpenSSL: ", .{});
    for (openssl_out) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n", .{});

    try testing.expectEqualSlices(u8, &openssl_out, &ztls_out);
}

// Test full handshake secret derivation against OpenSSL
test "Handshake Traffic Secrets - OpenSSL parity" {
    // Simulate a TLS 1.3 handshake with known values

    // ECDHE shared secret (32 bytes from X25519)
    const ecdhe_hex =
        "8bd4054fb55b9d63fdfbacf9f04b9f0d" ++
        "35e6d63f537563efd46272900f89492d";
    var ecdhe: [32]u8 = undefined;
    hexToBytes(ecdhe_hex, &ecdhe);

    // Transcript hash of ClientHello + ServerHello (32 bytes for SHA-256)
    const transcript_hex =
        "860c06edc07858ee8e78f0e7428c58ed" ++
        "d6b43f2ca3e6e95f02ed063cf0e1cad8";
    var transcript: [32]u8 = undefined;
    hexToBytes(transcript_hex, &transcript);

    // ===== Derive using ztls =====
    const transcript_secret = key_schedule.Secret.fromSlice(.sha256, transcript[0..]);
    const hs = tls13.deriveHandshakeTraffic(.sha256, ecdhe[0..], transcript_secret);

    std.debug.print("\n=== Handshake Secret Derivation ===\n", .{});
    std.debug.print("ECDHE shared secret: ", .{});
    for (ecdhe) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\nTranscript hash:     ", .{});
    for (transcript) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n\nztls results:\n", .{});
    std.debug.print("Client HS secret: ", .{});
    for (hs.client_hs.slice()) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\nServer HS secret: ", .{});
    for (hs.server_hs.slice()) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n\n", .{});

    // ===== Derive using OpenSSL =====
    // Step 1: Early Secret = HKDF-Extract(0, 0)
    const zero: [32]u8 = .{0} ** 32;
    var early_secret: [32]u8 = undefined;
    const ret1 = c.HKDF_extract(
        early_secret[0..].ptr,
        null,
        c.EVP_sha256(),
        zero[0..].ptr,
        0, // IKM length = 0 (no PSK)
        zero[0..].ptr,
        0, // salt length = 0
    );
    try testing.expect(ret1 == 1);

    // Step 2: Derived-Secret(early_secret, "derived", "")
    // derived = HKDF-Expand-Label(early_secret, "derived", Hash(""), 32)
    var empty_hash: [32]u8 = undefined;
    _ = c.SHA256(null, 0, empty_hash[0..].ptr);

    var derived_secret: [32]u8 = undefined;
    {
        const full_label = "tls13 derived";
        var info: [2 + 1 + full_label.len + 1 + 32]u8 = undefined;
        info[0] = 0x00;
        info[1] = 0x20; // length = 32
        info[2] = @intCast(full_label.len);
        @memcpy(info[3 .. 3 + full_label.len], full_label);
        info[3 + full_label.len] = 32; // context length
        @memcpy(info[4 + full_label.len .. 4 + full_label.len + 32], empty_hash[0..]);

        const ret2 = c.HKDF_expand(
            derived_secret[0..].ptr,
            32,
            c.EVP_sha256(),
            early_secret[0..].ptr,
            32,
            info[0..].ptr,
            info.len,
        );
        try testing.expect(ret2 == 1);
    }

    // Step 3: Handshake Secret = HKDF-Extract(derived_secret, ECDHE)
    var handshake_secret: [32]u8 = undefined;
    const ret3 = c.HKDF_extract(
        handshake_secret[0..].ptr,
        null,
        c.EVP_sha256(),
        ecdhe[0..].ptr,
        32,
        derived_secret[0..].ptr,
        32,
    );
    try testing.expect(ret3 == 1);

    // Step 4: Client Handshake Traffic Secret = Derive-Secret(hs, "c hs traffic", transcript)
    var openssl_client_hs: [32]u8 = undefined;
    {
        const full_label = "tls13 c hs traffic";
        var info: [2 + 1 + full_label.len + 1 + 32]u8 = undefined;
        info[0] = 0x00;
        info[1] = 0x20;
        info[2] = @intCast(full_label.len);
        @memcpy(info[3 .. 3 + full_label.len], full_label);
        info[3 + full_label.len] = 32;
        @memcpy(info[4 + full_label.len .. 4 + full_label.len + 32], transcript[0..]);

        const ret4 = c.HKDF_expand(
            openssl_client_hs[0..].ptr,
            32,
            c.EVP_sha256(),
            handshake_secret[0..].ptr,
            32,
            info[0..].ptr,
            info.len,
        );
        try testing.expect(ret4 == 1);
    }

    // Step 5: Server Handshake Traffic Secret = Derive-Secret(hs, "s hs traffic", transcript)
    var openssl_server_hs: [32]u8 = undefined;
    {
        const full_label = "tls13 s hs traffic";
        var info: [2 + 1 + full_label.len + 1 + 32]u8 = undefined;
        info[0] = 0x00;
        info[1] = 0x20;
        info[2] = @intCast(full_label.len);
        @memcpy(info[3 .. 3 + full_label.len], full_label);
        info[3 + full_label.len] = 32;
        @memcpy(info[4 + full_label.len .. 4 + full_label.len + 32], transcript[0..]);

        const ret5 = c.HKDF_expand(
            openssl_server_hs[0..].ptr,
            32,
            c.EVP_sha256(),
            handshake_secret[0..].ptr,
            32,
            info[0..].ptr,
            info.len,
        );
        try testing.expect(ret5 == 1);
    }

    std.debug.print("OpenSSL results:\n", .{});
    std.debug.print("Client HS secret: ", .{});
    for (openssl_client_hs) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\nServer HS secret: ", .{});
    for (openssl_server_hs) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n\n", .{});

    // Compare
    try testing.expectEqualSlices(u8, &openssl_client_hs, hs.client_hs.slice());
    try testing.expectEqualSlices(u8, &openssl_server_hs, hs.server_hs.slice());
}

// Test transcript hash computation
test "Transcript Hash - message ordering" {
    // Ensure transcript hash matches expected value for known messages

    const client_hello_hex =
        "010000c40303" ++ // Type=ClientHello(01), Length=196(0x0000c4), TLS1.3
        "000102030405060708090a0b0c0d0e0f" ++ // client_random (32 bytes)
        "101112131415161718191a1b1c1d1e1f" ++
        "00" ++ // session_id length = 0
        "0002" ++ "1301" ++ // cipher_suites: TLS_AES_128_GCM_SHA256
        "0100" ++ // compression_methods: null
        "0000"; // extensions length = 0 (simplified)

    var client_hello: [200]u8 = undefined;
    hexToBytes(client_hello_hex, client_hello[0 .. client_hello_hex.len / 2]);
    const ch_len = client_hello_hex.len / 2;

    const server_hello_hex =
        "020000460303" ++ // Type=ServerHello(02), Length=70(0x000046)
        "202122232425262728292a2b2c2d2e2f" ++ // server_random (32 bytes)
        "303132333435363738393a3b3c3d3e3f" ++
        "00" ++ // session_id length = 0
        "1301" ++ // cipher_suite: TLS_AES_128_GCM_SHA256
        "00" ++ // compression_method: null
        "0000"; // extensions length = 0 (simplified)

    var server_hello: [200]u8 = undefined;
    hexToBytes(server_hello_hex, server_hello[0 .. server_hello_hex.len / 2]);
    const sh_len = server_hello_hex.len / 2;

    // Hash using ztls
    var transcript = tls13.Transcript.init();
    transcript.update(client_hello[0..ch_len]);
    transcript.update(server_hello[0..sh_len]);
    const ztls_hash = transcript.finalize(.sha256);

    // Hash using OpenSSL
    var concat: [400]u8 = undefined;
    @memcpy(concat[0..ch_len], client_hello[0..ch_len]);
    @memcpy(concat[ch_len .. ch_len + sh_len], server_hello[0..sh_len]);

    var openssl_hash: [32]u8 = undefined;
    _ = c.SHA256(concat[0..ch_len + sh_len].ptr, ch_len + sh_len, openssl_hash[0..].ptr);

    std.debug.print("\n=== Transcript Hash ===\n", .{});
    std.debug.print("Messages ({} bytes total):\n", .{ch_len + sh_len});
    std.debug.print("ClientHello ({} bytes): ", .{ch_len});
    for (client_hello[0..ch_len]) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\nServerHello ({} bytes): ", .{sh_len});
    for (server_hello[0..sh_len]) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n\nztls hash:    ", .{});
    for (ztls_hash.slice()) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\nOpenSSL hash: ", .{});
    for (openssl_hash) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n\n", .{});

    try testing.expectEqualSlices(u8, &openssl_hash, ztls_hash.slice());
}

// Test HKDF-Extract parity
test "HKDF-Extract - OpenSSL parity" {
    const salt_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    var salt: [32]u8 = undefined;
    hexToBytes(salt_hex, &salt);

    const ikm_hex = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    var ikm: [22]u8 = undefined;
    hexToBytes(ikm_hex, &ikm);

    // ztls extract
    const ztls_prk = key_schedule.extract(&salt, &ikm);

    // OpenSSL extract
    var openssl_prk: [32]u8 = undefined;
    const ret = c.HKDF_extract(
        openssl_prk[0..].ptr,
        null,
        c.EVP_sha256(),
        ikm[0..].ptr,
        ikm.len,
        salt[0..].ptr,
        salt.len,
    );
    try testing.expect(ret == 1);

    std.debug.print("\n=== HKDF-Extract ===\n", .{});
    std.debug.print("Salt: ", .{});
    for (salt) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\nIKM:  ", .{});
    for (ikm) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\nztls PRK:    ", .{});
    for (ztls_prk) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\nOpenSSL PRK: ", .{});
    for (openssl_prk) |b| std.debug.print("{X:0>2}", .{b});
    std.debug.print("\n\n", .{});

    try testing.expectEqualSlices(u8, &openssl_prk, &ztls_prk);
}
