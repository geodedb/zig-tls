// Certificate Policy Conformance Tests
//
// These tests parse a REAL OpenSSL-generated certificate (policy_leaf.der,
// produced by tests/test_certs/gen_policy.sh) carrying a certificatePolicies
// extension asserting policy OID 1.3.6.1.4.1.99999.1, then assert the values
// the library's parser exposes (RFC 5280 §4.2.1.4).
//
// The policyIdentifier OID 1.3.6.1.4.1.99999.1 encodes to the 9 value bytes
// 2B 06 01 04 01 86 8D 1F 01 (confirmed against the generated fixture via
// `openssl asn1parse`).
//
// RFC References:
// - RFC 5280 §4.2.1.4: Certificate Policies extension
// - RFC 5280 §6.1: Basic Path Validation (policy-tree processing)
//
// Scope: the library PARSES and EXPOSES policy OIDs (a single-cert presence
// model via x509.certHasPolicy). Full RFC 5280 §6.1 policy-tree processing
// (policy mapping, anyPolicy inhibition across a chain) is intentionally NOT
// implemented; that boundary is pinned by the last test below.

const std = @import("std");
const testing = std.testing;
const x509 = @import("x509");
const test_certs = @import("test_certs");

// 1.3.6.1.4.1.99999.1 OID value bytes (confirmed against the generated cert).
const POLICY_OID = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x01 };

test "policy conformance - certificatePolicies OID parsed from real cert" {
    const a = testing.allocator;
    var leaf = try x509.parseCert(a, test_certs.policy_leaf);
    defer leaf.deinit(a);
    try testing.expect(leaf.certificate_policies != null);
    try testing.expect(x509.certHasPolicy(&leaf, &POLICY_OID));
}

test "policy conformance - absent policy not reported present" {
    const a = testing.allocator;
    var leaf = try x509.parseCert(a, test_certs.policy_leaf);
    defer leaf.deinit(a);
    const absent = [_]u8{ 0x55, 0x1D, 0x99 }; // not a policy this cert asserts
    try testing.expect(!x509.certHasPolicy(&leaf, &absent));
}

test "policy conformance - full RFC 5280 §6.1 policy-tree processing is out of scope (documented)" {
    // certificatePolicies / policyMappings / policyConstraints / inhibitAnyPolicy
    // are PARSED and EXPOSED, but full chain policy-tree intersection per
    // RFC 5280 §6.1 (mapping, anyPolicy inhibition across a path) is
    // intentionally NOT implemented. This test pins the parsed-and-exposed
    // contract, not tree processing.
    const a = testing.allocator;
    var leaf = try x509.parseCert(a, test_certs.policy_leaf);
    defer leaf.deinit(a);
    try testing.expect(leaf.certificate_policies != null);
}
