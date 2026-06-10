// Client Authentication Conformance Tests
//
// These tests exercise the REAL X.509 client-authentication EKU logic against a
// REAL OpenSSL-generated fixture: a self-signed certificate that doubles as its
// own trust anchor and carries EKU = clientAuth (CN/SAN client.example.com).
//
//     client_cert (gen_client_auth.sh):
//         basicConstraints = critical, CA:TRUE   (valid self-signed trust anchor)
//         keyUsage         = critical, digitalSignature, keyCertSign
//         extendedKeyUsage = clientAuth (1.3.6.1.5.5.7.3.2)
//         SAN DNS          = client.example.com
//
// This file is the positive complement to mutual_tls.zig, which proves a
// serverAuth-only leaf is REJECTED for the .client_auth purpose (there is no
// clientAuth fixture in that corpus). Here we prove the inverse with a real
// clientAuth cert:
//   1. A real clientAuth self-signed cert is ACCEPTED for the .client_auth
//      purpose (single-cert self-signed chain, hostname match).
//   2. The same clientAuth cert is REJECTED for the .server_auth purpose
//      (EkuNotAllowed) — EKU purpose enforcement is bidirectional.
//   3. Direct unit assertions on x509.checkEkuPurpose against the parsed EKUs of
//      both the clientAuth cert and the serverAuth leaf, confirming each maps to
//      its own purpose and not the other.
//
// RFC References:
// - RFC 8446 §4.3.2: CertificateRequest message (server requests client cert)
// - RFC 8446 §4.4.2: Certificate message (client sends its chain)
// - RFC 5280 §4.2.1.12: Extended Key Usage (id-kp-clientAuth vs id-kp-serverAuth)
// - RFC 5280 §6.1: Path validation (self-signed anchor handling)
//
// OpenSSL Equivalents:
// - Server: openssl s_server -Verify 1 -CAfile client_ca.pem
// - Client: openssl s_client -cert client.pem -key client_key.pem
// - Fixture: gen_client_auth.sh mints a self-signed clientAuth cert; verified via
//     openssl x509 ... | grep "Extended Key Usage" => TLS Web Client Authentication

const std = @import("std");
const testing = std.testing;
const x509 = @import("x509");
const test_certs = @import("test_certs");

// A fixed instant inside the client_cert validity window (notBefore 2026-06,
// notAfter ~2036). The same constant is used across the conformance suite.
const NOW_VALID: i64 = 1767225600; // 2026-01-01

var g_trust_spki: []const u8 = &[_]u8{};
fn isTrustedSpki(spki: []const u8) bool {
    return g_trust_spki.len != 0 and std.mem.eql(u8, spki, g_trust_spki);
}

// ============================================================================
// Test 1: Real clientAuth self-signed cert validates under .client_auth
// RFC 5280 §6.1 (self-signed anchor) + §4.2.1.12 (EKU clientAuth)
// ============================================================================

test "client_auth conformance - clientAuth self-signed cert validates under client_auth purpose" {
    // The self-signed clientAuth cert is its own trust anchor: parse it, install
    // its SPKI as the sole trusted root, then validate the single-cert chain for
    // the .client_auth purpose with a matching hostname. This exercises real
    // parsing, self-signature verification, BasicConstraints (CA:TRUE) and EKU
    // (clientAuth) enforcement — the positive path mutual_tls.zig cannot cover.
    const a = testing.allocator;
    var cert = try x509.parseCert(a, test_certs.client_cert);
    defer cert.deinit(a);
    g_trust_spki = cert.spki;
    x509.setTrustStore(.{ .isTrustedSpki = isTrustedSpki });
    defer {
        x509.setTrustStore(null);
        g_trust_spki = &[_]u8{};
    }
    const chain = [_][]const u8{test_certs.client_cert};
    try x509.validateChain(a, &chain, NOW_VALID, "client.example.com", .secure, .client_auth);
}

// ============================================================================
// Test 2: The same clientAuth cert is rejected under .server_auth
// RFC 5280 §4.2.1.12: EKU purpose enforcement is bidirectional.
// ============================================================================

test "client_auth conformance - clientAuth cert is rejected under server_auth purpose (EkuNotAllowed)" {
    // The cert carries EKU = clientAuth only (no serverAuth). Validating it for
    // the .server_auth purpose must be rejected — proving the EKU check does not
    // silently accept the wrong purpose.
    const a = testing.allocator;
    var cert = try x509.parseCert(a, test_certs.client_cert);
    defer cert.deinit(a);
    g_trust_spki = cert.spki;
    x509.setTrustStore(.{ .isTrustedSpki = isTrustedSpki });
    defer {
        x509.setTrustStore(null);
        g_trust_spki = &[_]u8{};
    }
    const chain = [_][]const u8{test_certs.client_cert};
    try testing.expectError(error.EkuNotAllowed, x509.validateChain(a, &chain, NOW_VALID, "client.example.com", .secure, .server_auth));
}

// ============================================================================
// Test 3: checkEkuPurpose maps real cert EKUs to the right purpose
// RFC 5280 §4.2.1.12: direct unit assertions on the purpose-mapping function.
// ============================================================================

test "client_auth conformance - checkEkuPurpose maps real cert EKUs correctly" {
    // Parse both real fixtures and assert the EKU-purpose mapping directly:
    //   clientAuth cert  -> client_auth (yes), server_auth (no)
    //   serverAuth leaf  -> server_auth (yes), client_auth (no)
    // This pins the function's behavior to real, parsed EKU bitsets rather than
    // synthetic flags.
    const a = testing.allocator;
    var client = try x509.parseCert(a, test_certs.client_cert);
    defer client.deinit(a);
    var server = try x509.parseCert(a, test_certs.leaf); // serverAuth leaf
    defer server.deinit(a);

    try testing.expect(x509.checkEkuPurpose(client.eku.?, .client_auth));
    try testing.expect(!x509.checkEkuPurpose(client.eku.?, .server_auth));
    try testing.expect(x509.checkEkuPurpose(server.eku.?, .server_auth));
    try testing.expect(!x509.checkEkuPurpose(server.eku.?, .client_auth));
}
