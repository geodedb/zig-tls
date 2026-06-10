// Name Constraints Enforcement Conformance Tests
// Phase 5, Task 5: Name constraints validation
//
// These tests exercise the REAL x509 path-validation engine against generated
// fixtures: a self-signed CA carrying a critical nameConstraints extension
// (permitted;DNS:.example.com) and two leaves signed by that CA — one inside
// the permitted subtree (host.example.com) and one outside it (evil.test).
// validateChain accumulates the CA's name constraints and enforces them
// against the leaf, accepting the in-subtree leaf and rejecting the
// out-of-subtree leaf with error.NameConstraintsViolation.
//
// RFC References:
// - RFC 5280 §4.2.1.10: Name Constraints extension
// - RFC 5280 §6.1.4(k): Name constraints processing in path validation
// - RFC 6125: Domain-Based Application Service Identity (SNI matching)
//
// OpenSSL Equivalents:
// - openssl x509 -in nc_constrained_ca.pem -text -noout (view name constraints)
// - openssl verify -CAfile nc_constrained_ca.pem nc_permitted_leaf.pem  (accepts)
// - openssl verify -CAfile nc_constrained_ca.pem nc_excluded_leaf.pem   (rejects)
//
// Fixtures (tests/test_certs/*.der):
// - nc_constrained_ca:   self-signed CA, nameConstraints critical,
//                        permitted;DNS:.example.com, CA:TRUE, KU keyCertSign+cRLSign
// - nc_permitted_leaf:   leaf signed by the CA, CN/SAN host.example.com, EKU serverAuth
// - nc_excluded_leaf:    leaf signed by the CA, CN/SAN evil.test, EKU serverAuth

const std = @import("std");
const testing = std.testing;
const x509 = @import("x509");
const test_certs = @import("test_certs");

// 2027-06-10T00:00:00Z — within the validity window of all three fixtures
// (notBefore 2026-06-10, notAfter 2036-06-07).
const NOW_VALID: i64 = 1812585600;

// Single-anchor trust store: trust exactly the constrained CA's SPKI.
var g_trust_spki: []const u8 = &[_]u8{};
fn isTrustedSpki(spki: []const u8) bool {
    return g_trust_spki.len != 0 and std.mem.eql(u8, spki, g_trust_spki);
}

// RFC 5280 §4.2.1.10 / §6.1.4(k): a leaf whose name is within the constrained
// CA's permitted subtree (.example.com) is accepted under full path validation.
test "name_constraints conformance - permitted leaf (host.example.com) accepted under constrained CA" {
    const a = testing.allocator;
    var ca = try x509.parseCert(a, test_certs.nc_constrained_ca);
    defer ca.deinit(a);
    g_trust_spki = ca.spki;
    x509.setTrustStore(.{ .isTrustedSpki = isTrustedSpki });
    defer {
        x509.setTrustStore(null);
        g_trust_spki = &[_]u8{};
    }

    const chain = [_][]const u8{ test_certs.nc_permitted_leaf, test_certs.nc_constrained_ca };
    try x509.validateChain(a, &chain, NOW_VALID, "host.example.com", .secure, .server_auth);
}

// RFC 5280 §4.2.1.10 / §6.1.4(k): a leaf whose name (evil.test) is outside the
// constrained CA's permitted subtree is rejected with NameConstraintsViolation.
test "name_constraints conformance - out-of-subtree leaf (evil.test) rejected (NameConstraintsViolation)" {
    const a = testing.allocator;
    var ca = try x509.parseCert(a, test_certs.nc_constrained_ca);
    defer ca.deinit(a);
    g_trust_spki = ca.spki;
    x509.setTrustStore(.{ .isTrustedSpki = isTrustedSpki });
    defer {
        x509.setTrustStore(null);
        g_trust_spki = &[_]u8{};
    }

    const chain = [_][]const u8{ test_certs.nc_excluded_leaf, test_certs.nc_constrained_ca };
    try testing.expectError(
        error.NameConstraintsViolation,
        x509.validateChain(a, &chain, NOW_VALID, "evil.test", .secure, .server_auth),
    );
}

// Tie the unit-level matcher to the fixture's leading-dot constraint semantics:
// .example.com matches host.example.com but not evil.test.
test "name_constraints conformance - matcher agrees with fixture constraint semantics" {
    try testing.expect(x509.matchesNameConstraint("host.example.com", ".example.com"));
    try testing.expect(!x509.matchesNameConstraint("evil.test", ".example.com"));
}
