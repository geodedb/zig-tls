// CRL (Certificate Revocation List) Validation Conformance Tests
// Phase 5, Task 2: CRL parsing and revocation checking
//
// These tests validate REAL CRL support for certificate revocation checking as
// specified in RFC 5280 §5.1, exercising the `crl` module against
// OpenSSL-generated CRL fixtures (see tests/test_certs/gen_crl.sh).
//
// RFC References:
// - RFC 5280 §5.1:    CRL Fields (CertificateList / TBSCertList)
// - RFC 5280 §5.1.2.6: Revoked Certificates
// - RFC 5280 §5.1.1.2: Signature Algorithm
// - RFC 5280 §6.3:    CRL validation
//
// OpenSSL provenance of the fixtures (gen_crl.sh):
// - `crl_ca`           : RSA-2048 issuing CA (CN=CRL Test CA)
// - `crl_leaf`         : leaf issued by crl_ca, serial 0x1000
// - `crl_with_revoked` : v2 CRL signed by crl_ca, revoking serial 0x1000
// - `crl_empty`        : v2 CRL signed by crl_ca, revoking nothing
//   `openssl crl -in crl_with_revoked.der -inform DER \
//        -CAfile <(openssl x509 -in crl_ca.der -inform DER) -noout` => "verify OK".
//
// What these tests prove against the real fixtures:
// 1. A revoked leaf is detected against a CRL whose signature verifies.
// 2. An empty (but validly-signed) CRL leaves the leaf `.good`.
// 3. A CRL "verified" against the WRONG issuer is rejected (CrlBadSignature).
// 4. The revoked serial parsed from DER matches OpenSSL's 0x1000.

const std = @import("std");
const testing = std.testing;
const x509 = @import("x509");
const crl = @import("crl");
const test_certs = @import("test_certs");

// 2027-06-10T00:00:00Z. The fixtures' thisUpdate is ~2026-06-10 and nextUpdate
// is ~2036-06, so NOW sits comfortably inside the CRL validity window.
const NOW: i64 = 1812585600;

test "crl conformance - revoked leaf detected against signed CRL" {
    const a = testing.allocator;
    var cl = try crl.CertificateList.parse(a, test_certs.crl_with_revoked);
    defer cl.deinit(a);
    var ca = try x509.parseCert(a, test_certs.crl_ca);
    defer ca.deinit(a);
    var leaf = try x509.parseCert(a, test_certs.crl_leaf);
    defer leaf.deinit(a);
    try testing.expectEqual(
        crl.RevocationStatus.revoked,
        try crl.checkRevocation(a, &leaf, &cl, &ca, NOW),
    );
}

test "crl conformance - empty CRL leaves leaf good" {
    const a = testing.allocator;
    var cl = try crl.CertificateList.parse(a, test_certs.crl_empty);
    defer cl.deinit(a);
    var ca = try x509.parseCert(a, test_certs.crl_ca);
    defer ca.deinit(a);
    var leaf = try x509.parseCert(a, test_certs.crl_leaf);
    defer leaf.deinit(a);
    try testing.expectEqual(
        crl.RevocationStatus.good,
        try crl.checkRevocation(a, &leaf, &cl, &ca, NOW),
    );
}

test "crl conformance - CRL signed by wrong issuer is rejected (CrlBadSignature)" {
    const a = testing.allocator;
    var cl = try crl.CertificateList.parse(a, test_certs.crl_with_revoked);
    defer cl.deinit(a);
    var wrong = try x509.parseCert(a, test_certs.root); // unrelated CA
    defer wrong.deinit(a);
    var leaf = try x509.parseCert(a, test_certs.crl_leaf);
    defer leaf.deinit(a);
    try testing.expectError(
        crl.CheckError.CrlBadSignature,
        crl.checkRevocation(a, &leaf, &cl, &wrong, NOW),
    );
}

test "crl conformance - revoked serial matches OpenSSL (0x1000)" {
    const a = testing.allocator;
    var cl = try crl.CertificateList.parse(a, test_certs.crl_with_revoked);
    defer cl.deinit(a);
    const serial_0x1000 = [_]u8{ 0x10, 0x00 };
    try testing.expect(cl.isRevoked(&serial_0x1000));
}
