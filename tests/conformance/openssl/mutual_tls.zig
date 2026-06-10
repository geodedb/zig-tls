// Mutual TLS (mTLS) Integration Conformance Tests
// Phase 3, Task 3: End-to-end mutual authentication validation
//
// These tests exercise the REAL X.509 chain validator (x509.validateChain)
// against the REAL OpenSSL-generated fixture chain shipped in test_certs:
//
//     leaf (serverAuth EKU, CN/SAN leaf.example.com) -> intermediate -> root
//
// `openssl verify` accepts this chain, so the validator must too. The tests
// then assert the validator's negative behavior (tamper rejection, EKU purpose
// enforcement, hostname enforcement) so each assertion depends on real
// certificate parsing, signature verification, and policy checks rather than
// hardcoded constants.
//
// RFC References:
// - RFC 8446 §4.3.2: CertificateRequest message
// - RFC 8446 §4.4.2: Certificate message (client)
// - RFC 8446 §4.4.3: CertificateVerify (client signature)
// - RFC 5280 §6: Certification path validation (both directions)
// - RFC 5280 §4.2.1.12: Extended Key Usage (serverAuth vs clientAuth)
//
// OpenSSL Equivalents:
// - Server: openssl s_server -Verify 1 -CAfile client_ca.pem -cert server.pem -key server_key.pem
// - Client: openssl s_client -cert client.pem -key client_key.pem -CAfile server_ca.pem
// - Chain:  openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem  (=> OK)
//
// Coverage:
// 1. Real server chain validates for the .server_auth purpose with hostname match.
// 2. A tampered leaf (corrupted TBS byte) is rejected (BadSignature).
// 3. The serverAuth-only leaf is rejected when validated for the .client_auth
//    purpose, proving EKU purpose enforcement (there is no clientAuth fixture in
//    this corpus, so client-auth enforcement is proven by rejection).
// 4. A hostname mismatch is rejected (NameMismatch).

const std = @import("std");
const testing = std.testing;
const x509 = @import("x509");
const test_certs = @import("test_certs");

// A fixed instant inside the leaf/intermediate/root validity window
// (leaf notBefore 2025-11-06, notAfter 2026-11-06). chain_validation.zig uses
// the same constant successfully.
const NOW_VALID: i64 = 1767225600; // 2026-01-01

var g_trust_spki: []const u8 = &[_]u8{};
fn isTrustedRoot(spki: []const u8) bool {
    return g_trust_spki.len != 0 and std.mem.eql(u8, spki, g_trust_spki);
}

/// Parse the real root and install its SPKI as the sole trust anchor for the
/// duration of a test. Mirrors chain_validation.zig's established helper.
fn withRealRootTrusted(alloc: std.mem.Allocator) !x509.Certificate {
    const root = try x509.parseCert(alloc, test_certs.root);
    g_trust_spki = root.spki;
    x509.setTrustStore(.{ .isTrustedSpki = isTrustedRoot });
    return root;
}
fn clearTrust(root: *x509.Certificate, alloc: std.mem.Allocator) void {
    x509.setTrustStore(null);
    g_trust_spki = &[_]u8{};
    root.deinit(alloc);
}

// ============================================================================
// Test 1: Real server chain validates for server_auth + hostname match
// RFC 5280 §6 + RFC 6125 (identity match)
// ============================================================================

test "mTLS conformance - server chain validates for server_auth and matches hostname" {
    const a = testing.allocator;
    var root = try withRealRootTrusted(a);
    defer clearTrust(&root, a);
    const chain = [_][]const u8{ test_certs.leaf, test_certs.intermediate, test_certs.root };
    try x509.validateChain(a, &chain, NOW_VALID, "leaf.example.com", .secure, .server_auth);
}

// ============================================================================
// Test 2: Tampered leaf is rejected (BadSignature)
// RFC 5280 §6.1.3(a): each cert's signature must verify against its issuer.
// ============================================================================

test "mTLS conformance - tampered leaf is rejected (BadSignature)" {
    const a = testing.allocator;
    var root = try withRealRootTrusted(a);
    defer clearTrust(&root, a);
    var bad = try a.dupe(u8, test_certs.leaf);
    defer a.free(bad);
    // Flip a byte in the middle of the DER. For these fixtures the mid-cert
    // offset lands inside TBSCertificate, so the issuer's signature over the
    // (now altered) TBS no longer verifies -> BadSignature. Verified empirically
    // against the fixture (see run output): the validator rejects with
    // error.BadSignature, not a parse error.
    bad[bad.len / 2] ^= 0xFF;
    const chain = [_][]const u8{ bad, test_certs.intermediate, test_certs.root };
    try testing.expectError(error.BadSignature, x509.validateChain(a, &chain, NOW_VALID, "leaf.example.com", .secure, .server_auth));
}

// ============================================================================
// Test 3: serverAuth leaf is rejected under client_auth purpose
// RFC 5280 §4.2.1.12: EKU restricts certificate purpose.
// ============================================================================

test "mTLS conformance - serverAuth leaf is rejected under client_auth purpose (EkuNotAllowed)" {
    // The fixture leaf carries EKU = TLS Web Server Authentication only (no
    // clientAuth). Validating it for the .client_auth purpose must be rejected.
    // This is how mTLS client-auth purpose enforcement is exercised, since the
    // corpus ships no clientAuth fixture.
    const a = testing.allocator;
    var root = try withRealRootTrusted(a);
    defer clearTrust(&root, a);
    const chain = [_][]const u8{ test_certs.leaf, test_certs.intermediate, test_certs.root };
    try testing.expectError(error.EkuNotAllowed, x509.validateChain(a, &chain, NOW_VALID, "leaf.example.com", .secure, .client_auth));
}

// ============================================================================
// Test 4: Hostname mismatch is rejected (NameMismatch)
// RFC 6125: the presented identity must match the reference identity.
// ============================================================================

test "mTLS conformance - hostname mismatch is rejected (NameMismatch)" {
    const a = testing.allocator;
    var root = try withRealRootTrusted(a);
    defer clearTrust(&root, a);
    const chain = [_][]const u8{ test_certs.leaf, test_certs.intermediate, test_certs.root };
    try testing.expectError(error.NameMismatch, x509.validateChain(a, &chain, NOW_VALID, "wrong.example.com", .secure, .server_auth));
}
