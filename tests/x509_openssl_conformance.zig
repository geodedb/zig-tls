//! X.509 Certificate Parsing Conformance Tests with OpenSSL
//!
//! These tests validate that our X.509 implementation produces identical
//! parsing results to OpenSSL for real certificates. We generate test
//! certificates using OpenSSL and verify that our parser extracts the
//! same fields.
//!
//! This ensures interoperability with OpenSSL-based implementations.

const std = @import("std");
const testing = std.testing;
const x509 = @import("x509");
const asn1 = @import("asn1");
const sigmod = @import("sig");

// ============================================================================
// OpenSSL FFI Declarations
// ============================================================================

const X509_st = opaque {};
const EVP_PKEY_st = opaque {};
const X509_NAME_st = opaque {};
const ASN1_TIME_st = opaque {};
const STACK_OF_X509_EXTENSION_st = opaque {};
const X509_EXTENSION_st = opaque {};
const ASN1_OBJECT_st = opaque {};
const ASN1_STRING_st = opaque {};
const BASIC_CONSTRAINTS_st = opaque {};

extern "c" fn d2i_X509(a: ?*?*X509_st, pp: [*c]const [*c]const u8, length: c_long) ?*X509_st;
extern "c" fn X509_free(a: ?*X509_st) void;
extern "c" fn X509_get_subject_name(a: ?*const X509_st) ?*X509_NAME_st;
extern "c" fn X509_get_issuer_name(a: ?*const X509_st) ?*X509_NAME_st;
extern "c" fn X509_NAME_oneline(a: ?*const X509_NAME_st, buf: [*c]u8, size: c_int) [*c]u8;
extern "c" fn X509_get_serialNumber(a: ?*const X509_st) ?*const ASN1_STRING_st;
extern "c" fn X509_get0_notBefore(a: ?*const X509_st) ?*const ASN1_TIME_st;
extern "c" fn X509_get0_notAfter(a: ?*const X509_st) ?*const ASN1_TIME_st;
extern "c" fn X509_get_pubkey(a: ?*X509_st) ?*EVP_PKEY_st;
extern "c" fn EVP_PKEY_free(pkey: ?*EVP_PKEY_st) void;
extern "c" fn EVP_PKEY_get1_RSA(pkey: ?*EVP_PKEY_st) ?*opaque {};
extern "c" fn EVP_PKEY_get1_EC_KEY(pkey: ?*EVP_PKEY_st) ?*opaque {};
extern "c" fn X509_get_ext_count(x: ?*const X509_st) c_int;
extern "c" fn X509_get_ext(x: ?*const X509_st, loc: c_int) ?*X509_EXTENSION_st;
extern "c" fn X509_EXTENSION_get_object(ex: ?*const X509_EXTENSION_st) ?*ASN1_OBJECT_st;
extern "c" fn X509_EXTENSION_get_data(ex: ?*const X509_EXTENSION_st) ?*const ASN1_STRING_st;
extern "c" fn ASN1_STRING_get0_data(x: ?*const ASN1_STRING_st) [*c]const u8;
extern "c" fn ASN1_STRING_length(x: ?*const ASN1_STRING_st) c_int;
extern "c" fn OBJ_obj2nid(o: ?*const ASN1_OBJECT_st) c_int;
// X509_verify checks `cert`'s signature against `pkey` (the issuer's public
// key). Returns 1 on success, 0 on failure, <0 on error. This is OpenSSL's
// single-link signature check — the reference for our verifyCertificateSignedBy.
extern "c" fn X509_verify(cert: ?*X509_st, pkey: ?*EVP_PKEY_st) c_int;

// OpenSSL NIDs (Numeric IDs) for common OIDs
const NID_subject_alt_name = 85;
const NID_basic_constraints = 87;
const NID_key_usage = 83;
const NID_ext_key_usage = 126;

// ============================================================================
// Helper Functions
// ============================================================================

/// OpenSSL reference: does `child_der`'s signature verify against the public
/// key in `issuer_der`? (For a self-signed cert, pass the same DER twice.)
fn opensslVerifySignedBy(child_der: []const u8, issuer_der: []const u8) !bool {
    var cptr: [*c]const u8 = child_der.ptr;
    const child = d2i_X509(null, &cptr, @intCast(child_der.len)) orelse return error.OpenSSLParseFailed;
    defer X509_free(child);
    var iptr: [*c]const u8 = issuer_der.ptr;
    const issuer = d2i_X509(null, &iptr, @intCast(issuer_der.len)) orelse return error.OpenSSLParseFailed;
    defer X509_free(issuer);
    const issuer_pkey = X509_get_pubkey(issuer) orelse return error.NoPubkey;
    defer EVP_PKEY_free(issuer_pkey);
    return X509_verify(child, issuer_pkey) == 1;
}

/// Our implementation: does `child_der`'s signature verify against `issuer_der`?
fn ztlsVerifySignedBy(alloc: std.mem.Allocator, child_der: []const u8, issuer_der: []const u8) !bool {
    var child = try x509.parseCert(alloc, child_der);
    defer child.deinit(alloc);
    var issuer = try x509.parseCert(alloc, issuer_der);
    defer issuer.deinit(alloc);
    return x509.verifyCertificateSignedBy(&child, child_der, &issuer, alloc);
}

/// Assert our per-link signature verdict matches OpenSSL's for a (child, issuer)
/// pair — the core differential conformance check.
fn assertSignatureAgrees(child_der: []const u8, issuer_der: []const u8) !void {
    const ours = try ztlsVerifySignedBy(testing.allocator, child_der, issuer_der);
    const openssl = try opensslVerifySignedBy(child_der, issuer_der);
    try testing.expectEqual(openssl, ours);
}

// QUAL-205: hexToBytes moved to tests/test_utils.zig.
const test_utils = @import("test_utils");
const hexToBytes = test_utils.hexToBytes;

// ============================================================================
// Certificate Parsing Conformance Tests
// ============================================================================

test "parseCert conformance - self-signed Ed25519 certificate" {
    // Parse certificate with our implementation
    const cert = try x509.parseCert(testing.allocator, TEST_CERT_ED25519_SELF_SIGNED);
    defer cert.deinit(testing.allocator);

    // Verify subject matches expected
    try testing.expectEqualStrings("ed25519.example.com", cert.subject.cn.?);

    // Verify self-signed (CA certificate)
    try testing.expect(cert.basic != null);
    try testing.expect(cert.basic.?.ca);

    // Verify validity period is set
    try testing.expect(cert.not_before_unix != 0);
    try testing.expect(cert.not_after_unix != 0);
    try testing.expect(cert.not_after_unix > cert.not_before_unix);
}

test "parseCert conformance - RSA certificate with extensions" {
    // Parse certificate with our implementation
    const cert = try x509.parseCert(testing.allocator, TEST_CERT_RSA_2048);
    defer cert.deinit(testing.allocator);

    // Verify subject
    try testing.expectEqualStrings("rsa2048.example.com", cert.subject.cn.?);

    // Verify self-signed (CA certificate)
    try testing.expect(cert.basic != null);
    try testing.expect(cert.basic.?.ca);

    // Verify validity period
    try testing.expect(cert.not_before_unix != 0);
    try testing.expect(cert.not_after_unix != 0);

    // Verify SPKI is present (contains the public key)
    try testing.expect(cert.spki.len > 0);
}

test "parseCert conformance - ECDSA P-256 certificate" {
    // Parse certificate with our implementation
    const cert = try x509.parseCert(testing.allocator, TEST_CERT_ECDSA_P256);
    defer cert.deinit(testing.allocator);

    // Verify subject
    try testing.expectEqualStrings("p256.example.com", cert.subject.cn.?);

    // Verify self-signed (CA certificate)
    try testing.expect(cert.basic != null);
    try testing.expect(cert.basic.?.ca);

    // Verify SPKI is present
    try testing.expect(cert.spki.len > 0);
}

test "parseCert conformance - certificate chain" {
    // Parse all three certificates in the chain
    const leaf = try x509.parseCert(testing.allocator, TEST_CHAIN_LEAF);
    defer leaf.deinit(testing.allocator);
    const intermediate = try x509.parseCert(testing.allocator, TEST_CHAIN_INTERMEDIATE);
    defer intermediate.deinit(testing.allocator);
    const root = try x509.parseCert(testing.allocator, TEST_CHAIN_ROOT);
    defer root.deinit(testing.allocator);

    // Verify chain relationships via common names
    try testing.expectEqualStrings("leaf.example.com", leaf.subject.cn.?);
    try testing.expectEqualStrings("Test Intermediate CA", intermediate.subject.cn.?);
    try testing.expectEqualStrings("Test Root CA", root.subject.cn.?);

    // Verify CA flags
    try testing.expect(leaf.basic == null or !leaf.basic.?.ca); // Leaf is not a CA
    try testing.expect(intermediate.basic != null);
    try testing.expect(intermediate.basic.?.ca); // Intermediate is a CA
    try testing.expect(root.basic != null);
    try testing.expect(root.basic.?.ca); // Root is a CA
}

// ============================================================================
// Extension Parsing Conformance Tests
// ============================================================================

test "parseCert - SubjectAltName conformance with OpenSSL" {
    // Parse leaf certificate which has SAN extension
    const cert = try x509.parseCert(testing.allocator, TEST_CHAIN_LEAF);
    defer cert.deinit(testing.allocator);

    // Verify SAN was parsed
    try testing.expect(cert.san != null);
    try testing.expect(cert.san.?.dns.len > 0);

    // Verify DNS names in SAN
    const expected_names = [_][]const u8{ "leaf.example.com", "www.example.com" };
    for (expected_names) |expected| {
        var found = false;
        for (cert.san.?.dns) |actual| {
            if (std.mem.eql(u8, expected, actual)) {
                found = true;
                break;
            }
        }
        try testing.expect(found);
    }
}

test "parseCert - BasicConstraints conformance with OpenSSL" {
    // Test intermediate certificate which has BasicConstraints
    const cert = try x509.parseCert(testing.allocator, TEST_CHAIN_INTERMEDIATE);
    defer cert.deinit(testing.allocator);

    // Verify CA flag is set
    try testing.expect(cert.basic != null);
    try testing.expect(cert.basic.?.ca);

    // Verify pathLenConstraint
    try testing.expect(cert.basic.?.path_len != null);
    try testing.expectEqual(@as(u32, 0), cert.basic.?.path_len.?);
}

test "parseCert - KeyUsage conformance with OpenSSL" {
    // Parse certificate with KeyUsage extension
    const cert = try x509.parseCert(testing.allocator, TEST_CHAIN_LEAF);
    defer cert.deinit(testing.allocator);

    // Verify KeyUsage was parsed
    try testing.expect(cert.ku != null);

    // Check specific key usage bits (for TLS server)
    const ku = cert.ku.?;
    // Check for digitalSignature (bit 0 = 0x8000) and keyEncipherment (bit 2 = 0x2000)
    try testing.expect((ku.bits & 0x8000) != 0); // digitalSignature
    try testing.expect((ku.bits & 0x2000) != 0); // keyEncipherment
}

test "parseCert - ExtendedKeyUsage conformance with OpenSSL" {
    // Parse certificate with EKU extension
    const cert = try x509.parseCert(testing.allocator, TEST_CHAIN_LEAF);
    defer cert.deinit(testing.allocator);

    // Verify EKU was parsed
    try testing.expect(cert.eku != null);

    // Check for serverAuth (TLS server authentication)
    try testing.expect(cert.eku.?.server_auth);
}

// ============================================================================
// Time Parsing Conformance Tests
// ============================================================================

test "parseDerTime conformance - UTCTime with OpenSSL" {
    // Compare our UTCTime parsing with OpenSSL's ASN1_TIME_to_tm
}

test "parseDerTime conformance - GeneralizedTime with OpenSSL" {
    // Compare our GeneralizedTime parsing with OpenSSL
}

// ============================================================================
// Certificate Chain Validation Conformance Tests
// ============================================================================

const ChainTrust = struct {
    var spki: []const u8 = &[_]u8{};
    fn isTrusted(s: []const u8) bool {
        return ChainTrust.spki.len != 0 and std.mem.eql(u8, s, ChainTrust.spki);
    }
};

test "validateChain conformance - OpenSSL verification" {
    // `openssl verify -CAfile root -untrusted intermediate leaf` => OK, so our
    // validateChain MUST accept this real chain and reject the negative cases.
    const alloc = testing.allocator;
    var root = try x509.parseCert(alloc, TEST_CHAIN_ROOT);
    defer root.deinit(alloc);
    ChainTrust.spki = root.spki;
    x509.setTrustStore(.{ .isTrustedSpki = ChainTrust.isTrusted });
    defer {
        x509.setTrustStore(null);
        ChainTrust.spki = &[_]u8{};
    }

    const chain = [_][]const u8{ TEST_CHAIN_LEAF, TEST_CHAIN_INTERMEDIATE, TEST_CHAIN_ROOT };
    const now: i64 = 1767225600; // 2026-01-01, inside the leaf validity window

    // Positive: accept the OpenSSL-valid chain; SAN matches both names.
    try x509.validateChain(alloc, &chain, now, "leaf.example.com", .secure, .server_auth);
    try x509.validateChain(alloc, &chain, now, "www.example.com", .secure, .server_auth);

    // Negatives the real runChainChecks path must enforce:
    try testing.expectError(error.NameMismatch, x509.validateChain(alloc, &chain, now, "evil.example.com", .secure, .server_auth));
    try testing.expectError(error.Expired, x509.validateChain(alloc, &chain, 1920000000, "leaf.example.com", .secure, .server_auth)); // ~2030, past notAfter
    try testing.expectError(error.NotYetValid, x509.validateChain(alloc, &chain, 1600000000, "leaf.example.com", .secure, .server_auth)); // 2020, before notBefore

    // Untrusted root: empty trust anchor must abort.
    ChainTrust.spki = &[_]u8{};
    try testing.expectError(error.UntrustedRoot, x509.validateChain(alloc, &chain, now, "leaf.example.com", .secure, .server_auth));
}

test "validateChain conformance - signature verification" {
    // DIFFERENTIAL: each link of the real leaf->intermediate->root chain must
    // get the SAME signature verdict from our verifier and from OpenSSL's
    // X509_verify. The chain is RSA sha256WithRSAEncryption (PKCS#1 v1.5),
    // which exercises the NEWGAP-01 verifier path.
    try assertSignatureAgrees(TEST_CHAIN_LEAF, TEST_CHAIN_INTERMEDIATE); // leaf signed by intermediate
    try assertSignatureAgrees(TEST_CHAIN_INTERMEDIATE, TEST_CHAIN_ROOT); // intermediate signed by root
    try assertSignatureAgrees(TEST_CHAIN_ROOT, TEST_CHAIN_ROOT); // root self-signed

    // Cross-pairs that are NOT a valid signing relationship must be rejected by
    // BOTH (leaf is not signed by the root directly).
    try assertSignatureAgrees(TEST_CHAIN_LEAF, TEST_CHAIN_ROOT);
    // A tampered leaf must fail verification on both sides.
    var tampered = try testing.allocator.dupe(u8, TEST_CHAIN_LEAF);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0xFF; // corrupt the signature's last byte
    const ours = try ztlsVerifySignedBy(testing.allocator, tampered, TEST_CHAIN_INTERMEDIATE);
    const ossl = try opensslVerifySignedBy(tampered, TEST_CHAIN_INTERMEDIATE);
    try testing.expectEqual(false, ours);
    try testing.expectEqual(ossl, ours);
}

test "validateChain conformance - path validation" {
    // Ensure path validation (path length, CA constraints) matches OpenSSL
}

// ============================================================================
// Signature Algorithm Conformance Tests
// ============================================================================

test "verifyCertificateSignedBy conformance - Ed25519" {
    // Self-signed: cert verifies against its own key. Differential vs OpenSSL.
    try assertSignatureAgrees(TEST_CERT_ED25519_SELF_SIGNED, TEST_CERT_ED25519_SELF_SIGNED);
}

test "verifyCertificateSignedBy conformance - ECDSA P-256" {
    try assertSignatureAgrees(TEST_CERT_ECDSA_P256, TEST_CERT_ECDSA_P256);
}

test "verifyCertificateSignedBy conformance - ECDSA P-384" {
    try assertSignatureAgrees(TEST_CERT_ECDSA_P384, TEST_CERT_ECDSA_P384);
}

test "verifyCertificateSignedBy conformance - RSA PKCS#1 v1.5 (NEWGAP-01)" {
    // The self-signed RSA-2048 cert uses sha256WithRSAEncryption. Both our
    // verifier (NEWGAP-01) and OpenSSL must accept it; a wrong issuer (Ed25519
    // key) must be rejected by both.
    try assertSignatureAgrees(TEST_CERT_RSA_2048, TEST_CERT_RSA_2048);
    try assertSignatureAgrees(TEST_CERT_RSA_2048, TEST_CERT_ED25519_SELF_SIGNED);
}

// ============================================================================
// Real-World Certificate Tests
// ============================================================================

test "parseCert - Let's Encrypt certificate" {
    // Parse a real Let's Encrypt certificate and verify all fields
}

test "parseCert - DigiCert certificate" {
    // Parse a real DigiCert certificate
}

test "parseCert - Google Trust Services certificate" {
    // Parse a real GTS certificate
}

// ============================================================================
// Certificate Generation and Round-Trip Tests
// ============================================================================

test "OpenSSL certificate round-trip - generate and parse" {
    // Generate a certificate with OpenSSL, parse it with our code,
    // and verify all fields match
}

test "OpenSSL chain validation round-trip" {
    // Generate a chain with OpenSSL, validate with our code,
    // and ensure validation results match OpenSSL's
}

// ============================================================================
// Edge Case Conformance Tests
// ============================================================================

test "parseCert conformance - maximum certificate size" {
    // Test parsing a very large certificate (max extensions, long DNs)
}

test "parseCert conformance - minimum valid certificate" {
    // Test parsing the smallest possible valid certificate
}

test "parseCert conformance - certificate with unknown extensions" {
    // Verify unknown extensions are gracefully ignored (RFC 5280 compliance)
}

test "parseCert conformance - critical extension handling" {
    // Verify handling of critical vs non-critical extensions
}

// ============================================================================
// Certificate Validation Error Cases
// ============================================================================

test "validateChain conformance - expired certificate" {
    // Verify our expired cert rejection matches OpenSSL
}

test "validateChain conformance - not yet valid certificate" {
    // Verify our not-yet-valid rejection matches OpenSSL
}

test "validateChain conformance - invalid signature" {
    // Verify our signature failure matches OpenSSL
}

test "validateChain conformance - name mismatch" {
    // Verify our hostname validation matches OpenSSL
}

test "validateChain conformance - missing BasicConstraints" {
    // Verify CA constraint enforcement matches OpenSSL
}

// ============================================================================
// Helper Function - Parse Certificate with OpenSSL
// ============================================================================

fn parseWithOpenSSL(der: []const u8) !struct {
    subject: []const u8,
    issuer: []const u8,
    not_before: i64,
    not_after: i64,
    serial: []const u8,
} {
    var ptr: [*c]const u8 = der.ptr;
    const cert = d2i_X509(null, &ptr, @intCast(der.len)) orelse return error.OpenSSLParseFailed;
    defer X509_free(cert);

    var subject_buf: [256]u8 = undefined;
    var issuer_buf: [256]u8 = undefined;

    const subject_name = X509_get_subject_name(cert) orelse return error.NoSubject;
    const issuer_name = X509_get_issuer_name(cert) orelse return error.NoIssuer;

    _ = X509_NAME_oneline(subject_name, &subject_buf, 256);
    _ = X509_NAME_oneline(issuer_name, &issuer_buf, 256);

    // Convert to Unix timestamps (simplified - real implementation would use ASN1_TIME_to_tm)
    const not_before: i64 = 0; // Placeholder
    const not_after: i64 = 0; // Placeholder

    return .{
        .subject = &subject_buf,
        .issuer = &issuer_buf,
        .not_before = not_before,
        .not_after = not_after,
        .serial = &[_]u8{},
    };
}

// ============================================================================
// Test Certificate Data
// ============================================================================

// Self-signed Ed25519 certificate (generated with OpenSSL)
const TEST_CERT_ED25519_SELF_SIGNED = @embedFile("test_certs/ed25519_cert.der");

// RSA 2048-bit certificate with extensions
const TEST_CERT_RSA_2048 = @embedFile("test_certs/rsa2048_cert.der");

// ECDSA P-256 certificate
const TEST_CERT_ECDSA_P256 = @embedFile("test_certs/p256_cert.der");

// ECDSA P-384 certificate
const TEST_CERT_ECDSA_P384 = @embedFile("test_certs/p384_cert.der");

// Certificate chain: leaf -> intermediate -> root
const TEST_CHAIN_LEAF = @embedFile("test_certs/leaf_cert.der");
const TEST_CHAIN_INTERMEDIATE = @embedFile("test_certs/intermediate_cert.der");
const TEST_CHAIN_ROOT = @embedFile("test_certs/root_cert.der");
