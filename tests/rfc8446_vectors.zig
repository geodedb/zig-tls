//! RFC 8446/8448 Test Vectors
//!
//! This file contains test vectors to validate the TLS 1.3 key schedule
//! implementation against official RFC specifications.
//!
//! Test vector sources:
//! - RFC 8448: Example Handshake Traces for TLS 1.3 (Section 3)
//! - RFC 9001 Appendix A: QUIC-TLS test vectors

const std = @import("std");
const testing = std.testing;
const key_schedule = @import("quic_tls");
const record = @import("record");

// ============================================================================
// Helpers
// ============================================================================

/// Convert a comptime hex string to a fixed-size byte array.
fn hexLiteral(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(hex.len * 100);
    var result: [hex.len / 2]u8 = undefined;
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        result[i / 2] = (charToNibble(hex[i]) << 4) | charToNibble(hex[i + 1]);
    }
    return result;
}

fn charToNibble(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => unreachable,
    };
}

fn expectEqualHex(comptime hex: []const u8, actual: []const u8) !void {
    const expected = hexLiteral(hex);
    try testing.expectEqualSlices(u8, &expected, actual);
}

// ============================================================================
// RFC 8448 §3: TLS 1.3 Key Schedule Test Vectors
// ============================================================================

test "RFC 8448 §3: Early Secret (HKDF-Extract with zero PSK)" {
    // Early Secret = HKDF-Extract(salt=zeros(32), IKM=zeros(32))
    const zero32 = [_]u8{0} ** 32;
    const early_secret = key_schedule.HkdfSha256.extract(&zero32, &zero32);

    try expectEqualHex(
        "33ad0a1c607ec03b09e6cd9893680ce2" ++
            "10adf300aa1f2660e1b22e10f170f92a",
        &early_secret,
    );
}

test "RFC 8448 §3: Derived secret (early to handshake)" {
    // derived = Derive-Secret(early_secret, "derived", "")
    //         = HKDF-Expand-Label(early_secret, "derived", Hash(""), 32)
    const early_secret = key_schedule.Secret.fromSlice(
        .sha256,
        &hexLiteral("33ad0a1c607ec03b09e6cd9893680ce2" ++ "10adf300aa1f2660e1b22e10f170f92a"),
    );
    const empty_hash = key_schedule.hashBytes(.sha256, &[_]u8{});
    const derived = key_schedule.deriveSecretHash(.sha256, &early_secret, "derived", empty_hash.slice());

    try expectEqualHex(
        "6f2615a108c702c5678f54fc9dbab697" ++
            "16c076189c48250cebeac3576c3611ba",
        derived.slice(),
    );
}

test "RFC 8448 §3: Handshake Secret" {
    // handshake_secret = HKDF-Extract(salt=derived, IKM=DHE)
    const derived = hexLiteral(
        "6f2615a108c702c5678f54fc9dbab697" ++
            "16c076189c48250cebeac3576c3611ba",
    );
    const dhe = hexLiteral(
        "8bd4054fb55b9d63fdfbacf9f04b9f0d" ++
            "35e6d63f537563efd46272900f89492d",
    );
    const handshake_secret = key_schedule.HkdfSha256.extract(&derived, &dhe);

    try expectEqualHex(
        "1dc826e93606aa6fdc0aadc12f741b01" ++
            "046aa6b99f691ed221a9f0ca043fbeac",
        &handshake_secret,
    );
}

test "RFC 8448 §3: Client/Server Handshake Traffic Secrets" {
    const hs_secret = key_schedule.Secret.fromSlice(
        .sha256,
        &hexLiteral("1dc826e93606aa6fdc0aadc12f741b01" ++ "046aa6b99f691ed221a9f0ca043fbeac"),
    );
    const transcript_ch_sh = hexLiteral(
        "860c06edc07858ee8e78f0e7428c58ed" ++
            "d6b43f2ca3e6e95f02ed063cf0e1cad8",
    );

    const client_hs = key_schedule.deriveSecretHash(.sha256, &hs_secret, "c hs traffic", &transcript_ch_sh);
    try expectEqualHex(
        "b3eddb126e067f35a780b3abf45e2d8f" ++
            "3b1a950738f52e9600746a0e27a55a21",
        client_hs.slice(),
    );

    const server_hs = key_schedule.deriveSecretHash(.sha256, &hs_secret, "s hs traffic", &transcript_ch_sh);
    try expectEqualHex(
        "b67b7d690cc16c4e75e54213cb2d37b4" ++
            "e9c912bcded9105d42befd59d391ad38",
        server_hs.slice(),
    );
}

test "RFC 8448 §3: Handshake Keys and IVs" {
    // Client handshake key/IV from client_handshake_traffic_secret
    const client_hs = key_schedule.Secret.fromSlice(
        .sha256,
        &hexLiteral("b3eddb126e067f35a780b3abf45e2d8f" ++ "3b1a950738f52e9600746a0e27a55a21"),
    );
    var client_key: [16]u8 = undefined;
    try key_schedule.expandLabelHash(.sha256, &client_hs, "key", &[_]u8{}, &client_key);
    try expectEqualHex("dbfaa693d1762c5b666af5d950258d01", &client_key);

    var client_iv: [12]u8 = undefined;
    try key_schedule.expandLabelHash(.sha256, &client_hs, "iv", &[_]u8{}, &client_iv);
    try expectEqualHex("5bd3c71b836e0b76bb73265f", &client_iv);

    // Server handshake key/IV from server_handshake_traffic_secret
    const server_hs = key_schedule.Secret.fromSlice(
        .sha256,
        &hexLiteral("b67b7d690cc16c4e75e54213cb2d37b4" ++ "e9c912bcded9105d42befd59d391ad38"),
    );
    var server_key: [16]u8 = undefined;
    try key_schedule.expandLabelHash(.sha256, &server_hs, "key", &[_]u8{}, &server_key);
    try expectEqualHex("3fce516009c21727d0f2e4e86ee403bc", &server_key);

    var server_iv: [12]u8 = undefined;
    try key_schedule.expandLabelHash(.sha256, &server_hs, "iv", &[_]u8{}, &server_iv);
    try expectEqualHex("5d313eb2671276ee13000b30", &server_iv);
}

test "RFC 8448 §3: Master Secret" {
    // derived = Derive-Secret(handshake_secret, "derived", "")
    // master_secret = HKDF-Extract(salt=derived, IKM=zeros(32))
    const derived = hexLiteral(
        "43de77e0c77713859a944db9db2590b5" ++
            "3190a65b3ee2e4f12dd7a0bb7ce254b4",
    );
    const zero32 = [_]u8{0} ** 32;
    const master_secret = key_schedule.HkdfSha256.extract(&derived, &zero32);

    try expectEqualHex(
        "18df06843d13a08bf2a449844c5f8a47" ++
            "8001bc4d4c627984d5a41da8d0402919",
        &master_secret,
    );
}

test "RFC 8448 §3: Application Traffic Secrets and Keys" {
    const master = key_schedule.Secret.fromSlice(
        .sha256,
        &hexLiteral("18df06843d13a08bf2a449844c5f8a47" ++ "8001bc4d4c627984d5a41da8d0402919"),
    );
    const transcript_ch_sf = hexLiteral(
        "9608102a0f1ccc6db6250b7b7e417b1a" ++
            "000eaada3daae4777a7686c9ff83df13",
    );

    // Client application traffic secret
    const client_app = key_schedule.deriveSecretHash(.sha256, &master, "c ap traffic", &transcript_ch_sf);
    try expectEqualHex(
        "9e40646ce79a7f9dc05af8889bce6552" ++
            "875afa0b06df0087f792ebb7c17504a5",
        client_app.slice(),
    );

    // Server application traffic secret
    const server_app = key_schedule.deriveSecretHash(.sha256, &master, "s ap traffic", &transcript_ch_sf);
    try expectEqualHex(
        "a11af9f05531f856ad47116b45a95032" ++
            "8204b4f44bfb6b3a4b4f1f3fcb631643",
        server_app.slice(),
    );

    // Client application key/IV
    var client_key: [16]u8 = undefined;
    try key_schedule.expandLabelHash(.sha256, &client_app, "key", &[_]u8{}, &client_key);
    try expectEqualHex("17422dda596ed5d9acd890e3c63f5051", &client_key);

    var client_iv: [12]u8 = undefined;
    try key_schedule.expandLabelHash(.sha256, &client_app, "iv", &[_]u8{}, &client_iv);
    try expectEqualHex("5b78923dee08579033e523d9", &client_iv);

    // Server application key/IV
    var server_key: [16]u8 = undefined;
    try key_schedule.expandLabelHash(.sha256, &server_app, "key", &[_]u8{}, &server_key);
    try expectEqualHex("9f02283b6c9c07efc26bb9f2ac92e356", &server_key);

    var server_iv: [12]u8 = undefined;
    try key_schedule.expandLabelHash(.sha256, &server_app, "iv", &[_]u8{}, &server_iv);
    try expectEqualHex("cf782b88dd83549aadf1e984", &server_iv);
}

test "RFC 8448 §3: Exporter Master Secret" {
    const master = key_schedule.Secret.fromSlice(
        .sha256,
        &hexLiteral("18df06843d13a08bf2a449844c5f8a47" ++ "8001bc4d4c627984d5a41da8d0402919"),
    );
    const transcript_ch_sf = hexLiteral(
        "9608102a0f1ccc6db6250b7b7e417b1a" ++
            "000eaada3daae4777a7686c9ff83df13",
    );

    const exporter = key_schedule.deriveSecretHash(.sha256, &master, "exp master", &transcript_ch_sf);
    try expectEqualHex(
        "fe22f881176eda18eb8f44529e6792c5" ++
            "0c9a3f89452f68d8ae311b4309d3cf50",
        exporter.slice(),
    );
}

test "RFC 8448 §3: Resumption Master Secret" {
    const master = key_schedule.Secret.fromSlice(
        .sha256,
        &hexLiteral("18df06843d13a08bf2a449844c5f8a47" ++ "8001bc4d4c627984d5a41da8d0402919"),
    );
    const transcript_ch_cf = hexLiteral(
        "209145a96ee8e2a122ff810047cc9526" ++
            "84658d6049e86429426db87c54ad143d",
    );

    const resumption = key_schedule.deriveSecretHash(.sha256, &master, "res master", &transcript_ch_cf);
    try expectEqualHex(
        "7df235f2031d2a051287d02b0241b0bf" ++
            "daf86cc856231f2d5aba46c434ec196c",
        resumption.slice(),
    );
}

// ============================================================================
// RFC 9001 Test Vectors (QUIC-TLS)
// ============================================================================

test "RFC 9001 §A.1: QUIC Initial Secret Derivation" {
    const dcid = hexLiteral("8394c8f03e515708");
    const initial_secret = key_schedule.HkdfSha256.extract(&key_schedule.initial_salt_v1, &dcid);

    try expectEqualHex(
        "7db5df06e7a69e432496adedb0085192" ++
            "3595221596ae2ae9fb8115c1e9ed0a44",
        &initial_secret,
    );
}

test "RFC 9001 §A.2: Client Initial Secret" {
    const initial_secret = hexLiteral(
        "7db5df06e7a69e432496adedb0085192" ++
            "3595221596ae2ae9fb8115c1e9ed0a44",
    );

    var client_initial_secret: [32]u8 = undefined;
    try key_schedule.expandLabel(initial_secret[0..], "client in", "", &client_initial_secret);

    try expectEqualHex(
        "c00cf151ca5be075ed0ebfb5c80323c4" ++
            "2d6b7db67881289af4008f1f6c357aea",
        &client_initial_secret,
    );
}

test "RFC 9001 §A.3: Server Initial Secret" {
    const initial_secret = hexLiteral(
        "7db5df06e7a69e432496adedb0085192" ++
            "3595221596ae2ae9fb8115c1e9ed0a44",
    );

    var server_initial_secret: [32]u8 = undefined;
    try key_schedule.expandLabel(initial_secret[0..], "server in", "", &server_initial_secret);

    try expectEqualHex(
        "3c199828fd139efd216c155ad844cc81" ++
            "fb82fa8d7446fa7d78be803acdda951b",
        &server_initial_secret,
    );
}

test "QUIC v1/v2 initial salts are distinct" {
    try testing.expect(key_schedule.initial_salt_v1.len == 20);
    try testing.expect(key_schedule.initial_salt_v2.len == 20);
    try testing.expect(!std.mem.eql(u8, &key_schedule.initial_salt_v1, &key_schedule.initial_salt_v2));
}

test "Traffic secret update produces distinct secret" {
    const current = hexLiteral(
        "9e40646ce79a7f9dc05af8889bce6552" ++
            "875afa0b06df0087f792ebb7c17504a5",
    );

    var next: [32]u8 = undefined;
    try key_schedule.expandLabel(current[0..], "traffic upd", "", &next);

    try testing.expect(!std.mem.eql(u8, &current, &next));
    try testing.expect(next.len == 32);
}
