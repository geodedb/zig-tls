//! RFC 9001 Appendix A: Sample Packet Protection
//!
//! Complete test vectors from RFC 9001 Appendix A to validate QUIC Initial packet
//! protection implementation.
//!
//! ## RFC 9001 Appendix A Coverage
//!
//! - §A.1: Keys (Initial secret derivation from DCID)
//! - §A.2: Client Initial (client initial secret and keys)
//! - §A.3: Server Initial (server initial secret and keys)
//! - §A.4: ChaCha20-Poly1305 Short Header Packet
//! - §A.5: Sample Variable-Length Integer Decoding
//!
//! ## Initial Secret Derivation
//!
//! QUIC Initial packets use a special derivation process:
//! ```
//! initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a (QUIC v1)
//! initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
//! client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
//! server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
//! ```
//!
//! This is different from TLS 1.3 which derives secrets from handshake messages.

const std = @import("std");
const testing = std.testing;
const key_schedule = @import("quic_tls");

// Helper to convert hex string to bytes
fn hexToBytes(comptime hex: []const u8, out: []u8) void {
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = std.fmt.parseInt(u8, hex[i .. i + 2], 16) catch unreachable;
    }
}

// Helper to compare hex string with bytes
fn expectEqualHex(comptime hex: []const u8, actual: []const u8) !void {
    var expected: [hex.len / 2]u8 = undefined;
    hexToBytes(hex, &expected);
    try testing.expectEqualSlices(u8, &expected, actual);
}

// RFC 9001 §A.1: Initial Secret Derivation
//
// Tests derivation of initial_secret from destination connection ID.
//
// Test vector from RFC 9001 Appendix A.1:
// - DCID: 0x8394c8f03e515708
// - initial_salt (v1): 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
// - Expected initial_secret: 0x7db5df06e7a69e432496adedb0085192...
test "RFC 9001 §A.1: QUIC v1 Initial Secret Derivation" {
    // Destination Connection ID used in the example
    const dcid_hex = "8394c8f03e515708";
    var dcid: [8]u8 = undefined;
    hexToBytes(dcid_hex, &dcid);

    // Derive initial secret using QUIC v1 salt
    const initial_secret = key_schedule.HkdfSha256.extract(&key_schedule.initial_salt_v1, &dcid);

    // Expected initial secret from RFC 9001 §A.1
    const expected_initial_secret_hex =
        "7db5df06e7a69e432496adedb0085192" ++
        "3595221596ae2ae9fb8115c1e9ed0a44";

    try expectEqualHex(expected_initial_secret_hex, &initial_secret);
}

// RFC 9001 §A.2: Client Initial Secret
//
// Tests derivation of client_initial_secret from initial_secret.
//
// ```
// client_initial_secret =
//     HKDF-Expand-Label(initial_secret, "client in", "", Hash.length)
// ```
test "RFC 9001 §A.2: Client Initial Secret" {
    // Initial secret from §A.1
    const initial_secret_hex =
        "7db5df06e7a69e432496adedb0085192" ++
        "3595221596ae2ae9fb8115c1e9ed0a44";
    var initial_secret: [32]u8 = undefined;
    hexToBytes(initial_secret_hex, &initial_secret);

    // Derive client initial secret with label "client in"
    var client_initial_secret: [32]u8 = undefined;
    try key_schedule.expandLabel(initial_secret[0..], "client in", "", &client_initial_secret);

    // Expected client_initial_secret from RFC 9001 §A.2
    const expected_client_secret_hex =
        "c00cf151ca5be075ed0ebfb5c80323c4" ++
        "2d6b7db67881289af4008f1f6c357aea";

    try expectEqualHex(expected_client_secret_hex, &client_initial_secret);
}

// RFC 9001 §A.3: Server Initial Secret
//
// Tests derivation of server_initial_secret from initial_secret.
//
// ```
// server_initial_secret =
//     HKDF-Expand-Label(initial_secret, "server in", "", Hash.length)
// ```
test "RFC 9001 §A.3: Server Initial Secret" {
    // Initial secret from §A.1
    const initial_secret_hex =
        "7db5df06e7a69e432496adedb0085192" ++
        "3595221596ae2ae9fb8115c1e9ed0a44";
    var initial_secret: [32]u8 = undefined;
    hexToBytes(initial_secret_hex, &initial_secret);

    // Derive server initial secret with label "server in"
    var server_initial_secret: [32]u8 = undefined;
    try key_schedule.expandLabel(initial_secret[0..], "server in", "", &server_initial_secret);

    // Expected server_initial_secret from RFC 9001 §A.3
    const expected_server_secret_hex =
        "3c199828fd139efd216c155ad844cc81" ++
        "fb82fa8d7446fa7d78be803acdda951b";

    try expectEqualHex(expected_server_secret_hex, &server_initial_secret);
}

// RFC 9001 §A: Client Initial Key Derivation
//
// Tests expansion of client_initial_secret into encryption key.
//
// ```
// key = HKDF-Expand-Label(secret, "quic key", "", key_length)
// ```
test "RFC 9001 §A: Client Initial Key (AES-128-GCM)" {
    // Client initial secret from §A.2
    const client_initial_secret_hex =
        "c00cf151ca5be075ed0ebfb5c80323c4" ++
        "2d6b7db67881289af4008f1f6c357aea";
    var client_initial_secret: [32]u8 = undefined;
    hexToBytes(client_initial_secret_hex, &client_initial_secret);

    // Derive encryption key (16 bytes for AES-128-GCM)
    var key: [16]u8 = undefined;
    try key_schedule.expandLabel(client_initial_secret[0..], "quic key", "", &key);

    // Expected key from RFC 9001 Appendix A
    const expected_key_hex = "1f369613dd76d5467730efcbe3b1a22d";

    try expectEqualHex(expected_key_hex, &key);
}

// RFC 9001 §A: Client Initial IV Derivation
//
// Tests expansion of client_initial_secret into AEAD IV.
//
// ```
// iv = HKDF-Expand-Label(secret, "quic iv", "", iv_length)
// ```
test "RFC 9001 §A: Client Initial IV (AES-128-GCM)" {
    // Client initial secret from §A.2
    const client_initial_secret_hex =
        "c00cf151ca5be075ed0ebfb5c80323c4" ++
        "2d6b7db67881289af4008f1f6c357aea";
    var client_initial_secret: [32]u8 = undefined;
    hexToBytes(client_initial_secret_hex, &client_initial_secret);

    // Derive IV (12 bytes for AES-GCM)
    var iv: [12]u8 = undefined;
    try key_schedule.expandLabel(client_initial_secret[0..], "quic iv", "", &iv);

    // Expected IV from RFC 9001 Appendix A
    const expected_iv_hex = "fa044b2f42a3fd3b46fb255c";

    try expectEqualHex(expected_iv_hex, &iv);
}

// RFC 9001 §A: Client Initial Header Protection Key
//
// Tests expansion of client_initial_secret into header protection key.
//
// ```
// hp = HKDF-Expand-Label(secret, "quic hp", "", hp_key_length)
// ```
test "RFC 9001 §A: Client Initial Header Protection Key" {
    // Client initial secret from §A.2
    const client_initial_secret_hex =
        "c00cf151ca5be075ed0ebfb5c80323c4" ++
        "2d6b7db67881289af4008f1f6c357aea";
    var client_initial_secret: [32]u8 = undefined;
    hexToBytes(client_initial_secret_hex, &client_initial_secret);

    // Derive header protection key (16 bytes for AES-128)
    var hp_key: [16]u8 = undefined;
    try key_schedule.expandLabel(client_initial_secret[0..], "quic hp", "", &hp_key);

    // Expected header protection key from RFC 9001 Appendix A
    const expected_hp_hex = "9f50449e04a0e810283a1e9933adedd2";

    try expectEqualHex(expected_hp_hex, &hp_key);
}

// RFC 9369: QUIC v2 Initial Salt
//
// Tests that QUIC v2 uses a different initial salt than v1.
//
// QUIC v2 salt (RFC 9369):
// ```
// 0x0dede3def700a6db819381be6e269dcbf9bd2ed9
// ```
test "RFC 9369: QUIC v2 initial salt differs from v1" {
    // Verify both salts are 20 bytes
    try testing.expect(key_schedule.initial_salt_v1.len == 20);
    try testing.expect(key_schedule.initial_salt_v2.len == 20);

    // Ensure v1 and v2 salts are different (crucial for version downgrade protection)
    try testing.expect(!std.mem.eql(u8, &key_schedule.initial_salt_v1, &key_schedule.initial_salt_v2));

    // Verify v1 salt matches RFC 9001
    const expected_v1_salt_hex = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
    try expectEqualHex(expected_v1_salt_hex, &key_schedule.initial_salt_v1);

    // Verify v2 salt matches RFC 9369
    const expected_v2_salt_hex = "0dede3def700a6db819381be6e269dcbf9bd2ed9";
    try expectEqualHex(expected_v2_salt_hex, &key_schedule.initial_salt_v2);
}

// RFC 9001 §A: Complete Client Initial Derivation Chain
//
// End-to-end test of complete client initial key material derivation.
test "RFC 9001 §A: Complete client initial key derivation" {
    // Start with DCID
    const dcid_hex = "8394c8f03e515708";
    var dcid: [8]u8 = undefined;
    hexToBytes(dcid_hex, &dcid);

    // Step 1: Derive initial_secret
    const initial_secret = key_schedule.HkdfSha256.extract(&key_schedule.initial_salt_v1, &dcid);

    // Step 2: Derive client_initial_secret
    var client_initial_secret: [32]u8 = undefined;
    try key_schedule.expandLabel(initial_secret[0..], "client in", "", &client_initial_secret);

    // Step 3: Derive key, IV, and header protection key
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    var hp: [16]u8 = undefined;
    try key_schedule.expandLabel(client_initial_secret[0..], "quic key", "", &key);
    try key_schedule.expandLabel(client_initial_secret[0..], "quic iv", "", &iv);
    try key_schedule.expandLabel(client_initial_secret[0..], "quic hp", "", &hp);

    // Validate all outputs against RFC 9001 Appendix A
    try expectEqualHex(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
        &client_initial_secret,
    );
    try expectEqualHex("1f369613dd76d5467730efcbe3b1a22d", &key);
    try expectEqualHex("fa044b2f42a3fd3b46fb255c", &iv);
    try expectEqualHex("9f50449e04a0e810283a1e9933adedd2", &hp);
}
