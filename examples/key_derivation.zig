// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
//! Key Derivation Example
//!
//! Demonstrates the HKDF-based key derivation functions used in TLS 1.3 and QUIC.
//! Shows how to derive:
//! - Initial secrets from QUIC connection ID (RFC 9001 Section 5.2)
//! - Handshake and application traffic secrets
//! - Packet protection keys (key, IV, header protection)
//!
//! ## RFC References
//! - RFC 8446 Section 7.1: Key Schedule
//! - RFC 9001 Section 5.1: Packet Protection Keys
//! - RFC 9001 Section 5.2: Initial Secrets
//! - RFC 9001 Appendix A.1: Test Vectors

const std = @import("std");
const ztls = @import("ztls");

pub fn main() !void {
    std.debug.print("=== TLS 1.3 / QUIC Key Derivation Examples ===\n\n", .{});

    // =========================================================================
    // Example 1: QUIC Initial Secret Derivation (RFC 9001 Section 5.2)
    // =========================================================================
    std.debug.print("1. QUIC Initial Secret Derivation\n", .{});
    std.debug.print("   RFC 9001 Section 5.2: Initial secrets from DCID\n\n", .{});

    // Test vector from RFC 9001 Appendix A.1
    const test_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    // Derive initial secret using QUIC v1 salt
    const initial_secret = ztls.key_schedule.deriveInitialSecretV1(&test_dcid);

    std.debug.print("   Destination Connection ID: ", .{});
    for (test_dcid) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});

    std.debug.print("   Initial Secret: ", .{});
    for (initial_secret[0..16]) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("...\n\n", .{});

    // =========================================================================
    // Example 2: Client/Server Initial Secrets
    // =========================================================================
    std.debug.print("2. Client/Server Initial Secret Split\n", .{});
    std.debug.print("   RFC 9001 Section 5.2: Derive directional secrets\n\n", .{});

    const secrets = ztls.key_schedule.deriveClientServerInitial(initial_secret);

    std.debug.print("   Client Initial Secret: ", .{});
    for (secrets.client[0..16]) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("...\n", .{});

    std.debug.print("   Server Initial Secret: ", .{});
    for (secrets.server[0..16]) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("...\n\n", .{});

    // =========================================================================
    // Example 3: Packet Protection Keys (Key, IV, HP)
    // =========================================================================
    std.debug.print("3. Packet Protection Key Derivation\n", .{});
    std.debug.print("   RFC 9001 Section 5.1: key, iv, hp from traffic secret\n\n", .{});

    const client_keys = ztls.key_schedule.deriveKeyIvHp(secrets.client);

    std.debug.print("   Client Initial Key (16 bytes): ", .{});
    for (client_keys.key) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});

    std.debug.print("   Client Initial IV  (12 bytes): ", .{});
    for (client_keys.iv) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});

    std.debug.print("   Client Initial HP  (16 bytes): ", .{});
    for (client_keys.hp) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n\n", .{});

    // =========================================================================
    // Example 4: QUIC v2 vs v1 Comparison
    // =========================================================================
    std.debug.print("4. QUIC v1 vs v2 Salt Comparison\n", .{});
    std.debug.print("   RFC 9369 Section A.1: Different salts for v2\n\n", .{});

    const v1_secret = ztls.key_schedule.deriveInitialSecretV1(&test_dcid);
    const v2_secret = ztls.key_schedule.deriveInitialSecretV2(&test_dcid);

    std.debug.print("   QUIC v1 Initial: ", .{});
    for (v1_secret[0..8]) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("...\n", .{});

    std.debug.print("   QUIC v2 Initial: ", .{});
    for (v2_secret[0..8]) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("...\n", .{});

    const same = std.mem.eql(u8, &v1_secret, &v2_secret);
    std.debug.print("   Secrets match: {} (expected: false)\n\n", .{same});

    // =========================================================================
    // Example 5: Traffic Secret Update (Key Update)
    // =========================================================================
    std.debug.print("5. Traffic Secret Update (RFC 8446 Section 7.2)\n", .{});
    std.debug.print("   Post-handshake key rotation for forward secrecy\n\n", .{});

    // Simulate an application traffic secret
    const app_secret = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    // Derive next generation secret using "traffic upd" label
    const updated_secret = ztls.key_schedule.updateTrafficSecret(app_secret);

    std.debug.print("   Original Secret:  ", .{});
    for (app_secret[0..8]) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("...\n", .{});

    std.debug.print("   Updated Secret:   ", .{});
    for (updated_secret[0..8]) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("...\n\n", .{});

    // =========================================================================
    // Example 6: HKDF-Expand-Label
    // =========================================================================
    std.debug.print("6. HKDF-Expand-Label (RFC 8446 Section 7.1)\n", .{});
    std.debug.print("   Generic labeled expansion with 'tls13 ' prefix\n\n", .{});

    const prk = [_]u8{0xaa} ** 32;
    var derived_key: [16]u8 = undefined;

    try ztls.key_schedule.expandLabel(&prk, "quic key", "", &derived_key);

    std.debug.print("   PRK:           ", .{});
    for (prk[0..8]) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("...\n", .{});

    std.debug.print("   Label:         'quic key' (with 'tls13 ' prefix)\n", .{});
    std.debug.print("   Derived Key:   ", .{});
    for (derived_key) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n\n", .{});

    // =========================================================================
    // Example 7: HMAC-SHA256
    // =========================================================================
    std.debug.print("7. HMAC-SHA256 (RFC 8446 Section 4.4.4)\n", .{});
    std.debug.print("   Used for Finished message verify_data\n\n", .{});

    const hmac_key = "finished_key_example";
    const hmac_data = "transcript_hash_example";
    const hmac_result = ztls.key_schedule.hmacSha256(hmac_key, hmac_data);

    std.debug.print("   HMAC Key:      '{s}'\n", .{hmac_key});
    std.debug.print("   HMAC Data:     '{s}'\n", .{hmac_data});
    std.debug.print("   HMAC Result:   ", .{});
    for (hmac_result[0..16]) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("...\n\n", .{});

    std.debug.print("=== Key Derivation Examples Complete ===\n", .{});
}
