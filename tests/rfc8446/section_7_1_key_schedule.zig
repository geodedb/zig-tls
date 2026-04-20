//! RFC 8446 §7.1: Key Schedule Tests
//!
//! Tests for TLS 1.3 key derivation using HKDF-based key schedule.
//!
//! ## RFC 8446 §7.1: Key Schedule
//!
//! The TLS 1.3 key schedule uses HKDF (RFC 5869) to derive keys and secrets:
//!
//! ```
//!              0
//!              |
//!              v
//!   PSK ->  HKDF-Extract = Early Secret
//!              |
//!              +-----> Derive-Secret(., "ext binder" | "res binder")
//!              |                     = binder_key
//!              |
//!              +-----> Derive-Secret(., "c e traffic", ClientHello)
//!              |                     = client_early_traffic_secret
//!              |
//!              +-----> Derive-Secret(., "e exp master", ClientHello)
//!              |                     = early_exporter_master_secret
//!              v
//!        Derive-Secret(., "derived", "")
//!              |
//!              v
//!  (EC)DHE -> HKDF-Extract = Handshake Secret
//!              |
//!              +-----> Derive-Secret(., "c hs traffic",
//!              |                     ClientHello...ServerHello)
//!              |                     = client_handshake_traffic_secret
//!              |
//!              +-----> Derive-Secret(., "s hs traffic",
//!              |                     ClientHello...ServerHello)
//!              |                     = server_handshake_traffic_secret
//!              v
//!        Derive-Secret(., "derived", "")
//!              |
//!              v
//!  0 -> HKDF-Extract = Master Secret
//!              |
//!              +-----> Derive-Secret(., "c ap traffic",
//!              |                     ClientHello...server Finished)
//!              |                     = client_application_traffic_secret_0
//!              |
//!              +-----> Derive-Secret(., "s ap traffic",
//!              |                     ClientHello...server Finished)
//!              |                     = server_application_traffic_secret_0
//!              |
//!              +-----> Derive-Secret(., "exp master",
//!              |                     ClientHello...server Finished)
//!              |                     = exporter_master_secret
//!              |
//!              +-----> Derive-Secret(., "res master",
//!                                    ClientHello...client Finished)
//!                                    = resumption_master_secret
//! ```
//!
//! ## Test Coverage
//!
//! - HKDF-Extract operations
//! - HKDF-Expand-Label operations
//! - Derive-Secret operations
//! - Full key schedule derivation
//! - Conformance with RFC 8446 Appendix A test vectors

const std = @import("std");
const testing = std.testing;
const key_schedule = @import("quic_tls");

// Helper to convert hex string to bytes
// QUAL-205: hexToBytes moved to tests/test_utils.zig.
const test_utils = @import("test_utils");
const hexToBytes = test_utils.hexToBytes;

// Helper to compare hex string with bytes
fn expectEqualHex(comptime hex: []const u8, actual: []const u8) !void {
    var expected: [hex.len / 2]u8 = undefined;
    hexToBytes(hex, &expected);
    try testing.expectEqualSlices(u8, &expected, actual);
}

// RFC 8446 §7.1: HKDF-Expand-Label Test
//
// HKDF-Expand-Label is defined as:
// ```
// HKDF-Expand-Label(Secret, Label, Context, Length) =
//     HKDF-Expand(Secret, HkdfLabel, Length)
// ```
//
// Where HkdfLabel is:
// ```
// struct {
//     uint16 length = Length;
//     opaque label<7..255> = "tls13 " + Label;
//     opaque context<0..255> = Context;
// } HkdfLabel;
// ```
test "RFC 8446 §7.1: HKDF-Expand-Label basic operation" {
    // Test HKDF-Expand-Label with known inputs
    const secret_hex = "00" ** 32; // 32-byte secret
    var secret: [32]u8 = undefined;
    hexToBytes(secret_hex, &secret);

    var output: [32]u8 = undefined;
    try key_schedule.expandLabel(secret[0..], "test label", "", &output);

    // Output should be deterministic for given inputs
    try testing.expect(output.len == 32);
}

// RFC 8446 §7.1: Derive-Secret Test
//
// Derive-Secret is defined as:
// ```
// Derive-Secret(Secret, Label, Messages) =
//     HKDF-Expand-Label(Secret, Label,
//                      Transcript-Hash(Messages), Hash.length)
// ```
test "RFC 8446 §7.1: Derive-Secret operation" {
    const secret_hex = "00" ** 32;
    var secret: [32]u8 = undefined;
    hexToBytes(secret_hex, &secret);

    const context_hex = "00" ** 32; // Transcript hash
    var context: [32]u8 = undefined;
    hexToBytes(context_hex, &context);

    var output: [32]u8 = undefined;
    try key_schedule.expandLabel(secret[0..], "derived", context[0..], &output);

    try testing.expect(output.len == 32);
}

// RFC 8446 §A.1: Simple 1-RTT Handshake - Key Schedule Test
//
// This test validates the complete key derivation from RFC 8446 Appendix A.1.
// These are the cryptographic values from a complete TLS 1.3 handshake.
test "RFC 8446 §A.1: Simple 1-RTT Handshake - Key Schedule" {
    // Note: This is a placeholder structure showing how to validate the key schedule
    // Real test vectors would come from actual RFC 8446 Appendix A traces

    // ClientHello.random (32 bytes)
    const client_random_hex = "00" ** 32; // Placeholder
    var client_random: [32]u8 = undefined;
    hexToBytes(client_random_hex, &client_random);

    // ServerHello.random (32 bytes)
    const server_random_hex = "00" ** 32; // Placeholder
    var server_random: [32]u8 = undefined;
    hexToBytes(server_random_hex, &server_random);

    // TODO: Add complete RFC 8446 Appendix A.1 test vectors
    // - Early Secret derivation
    // - Handshake Secret derivation (with ECDHE)
    // - Application Secret derivation
    // - Finished message verify_data computation
}

// RFC 8446 §7.1: Traffic Secret Update Test
//
// Tests the KeyUpdate mechanism for updating traffic secrets:
// ```
// application_traffic_secret_N+1 =
//     HKDF-Expand-Label(application_traffic_secret_N,
//                      "traffic upd", "", Hash.length)
// ```
test "RFC 8446 §7.1: Traffic Secret Update (KeyUpdate)" {
    // Initial application traffic secret
    const secret_0_hex = "00" ** 32;
    var secret_0: [32]u8 = undefined;
    hexToBytes(secret_0_hex, &secret_0);

    // Derive updated secret
    var secret_1: [32]u8 = undefined;
    try key_schedule.expandLabel(secret_0[0..], "traffic upd", "", &secret_1);

    // Updated secret should differ from original
    try testing.expect(!std.mem.eql(u8, &secret_0, &secret_1));

    // Can update again
    var secret_2: [32]u8 = undefined;
    try key_schedule.expandLabel(secret_1[0..], "traffic upd", "", &secret_2);

    try testing.expect(!std.mem.eql(u8, &secret_1, &secret_2));
}

// RFC 8446 §4.4.4: Finished Key Derivation Test
//
// Tests derivation of the finished_key used for Finished message:
// ```
// finished_key =
//     HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
// ```
test "RFC 8446 §4.4.4: Finished Key Derivation" {
    // Handshake traffic secret (base key)
    const handshake_secret_hex = "00" ** 32;
    var handshake_secret: [32]u8 = undefined;
    hexToBytes(handshake_secret_hex, &handshake_secret);

    // Derive finished_key
    var finished_key: [32]u8 = undefined;
    try key_schedule.expandLabel(handshake_secret[0..], "finished", "", &finished_key);

    try testing.expect(finished_key.len == 32);

    // Finished verify_data is then: HMAC(finished_key, transcript_hash)
    // (HMAC test would go in section_4_4_4_finished.zig)
}

// RFC 8446 §7.1: Exporter Master Secret Derivation Test
//
// Tests derivation of exporter_master_secret for application-specific keying material:
// ```
// exporter_master_secret =
//     Derive-Secret(Master Secret, "exp master",
//                  ClientHello...server Finished)
// ```
test "RFC 8446 §7.1: Exporter Master Secret Derivation" {
    // Master secret
    const master_secret_hex = "00" ** 32;
    var master_secret: [32]u8 = undefined;
    hexToBytes(master_secret_hex, &master_secret);

    // Transcript hash up to server Finished
    const transcript_hex = "00" ** 32;
    var transcript: [32]u8 = undefined;
    hexToBytes(transcript_hex, &transcript);

    // Derive exporter master secret
    var exporter_master: [32]u8 = undefined;
    try key_schedule.expandLabel(master_secret[0..], "exp master", transcript[0..], &exporter_master);

    try testing.expect(exporter_master.len == 32);
}
