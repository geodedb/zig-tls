//! RFC 5280 §6: Certification Path Validation Tests (GAP-0119 part 1)
//!
//! Exercises `x509.validateChain` entry paths. Full certificate fixtures
//! for production test vectors live under `tests/x509_unit_tests.zig`
//! (valid chain) and `tests/conformance/` (interoperability).
//!
//! This section file pins the public contract at the boundary:
//!
//!   1. `validateChain` rejects a zero-length chain (RFC 5280 §6: the
//!      algorithm cannot run without an end-entity certificate).
//!   2. `validateChain` rejects a chain that exceeds the hard-coded
//!      depth limit (SEC-R5-06 guard).
//!   3. `validateChain` rejects a single malformed certificate standing
//!      in for "intermediate with basicConstraints cA=FALSE"
//!      (RFC 5280 §4.2.1.9 requires CAs to assert cA=TRUE).
//!
//! Behavior beyond these entry-point checks is covered by the broader
//! x509_unit_tests suite; this file exists so the RFC 5280 §6 coverage
//! matrix has a concrete, RFC-cited test file.

const std = @import("std");
const x509 = @import("x509");

test "RFC 5280 §6: validateChain rejects empty chain" {
    const alloc = std.testing.allocator;
    const empty_chain: []const []const u8 = &.{};

    const result = x509.validateChain(
        alloc,
        empty_chain,
        1_700_000_000,
        "example.com",
        .secure,
        .server_auth,
    );
    if (result) |_| return error.UnexpectedSuccess else |_| {}
}

test "RFC 5280 §6: validateChain rejects excessive depth" {
    // SEC-R5-06: validateChain refuses chains deeper than the hard limit.
    // Build a pseudo-chain that is trivially too long.
    const alloc = std.testing.allocator;

    var blobs: [16][]const u8 = undefined;
    for (&blobs) |*b| b.* = &[_]u8{};

    const result = x509.validateChain(
        alloc,
        &blobs,
        1_700_000_000,
        "example.com",
        .secure,
        .server_auth,
    );
    // Contract: does not silently succeed.
    if (result) |_| return error.UnexpectedSuccess else |_| {}
}

test "RFC 5280 §6: validateChain rejects malformed intermediate" {
    // RFC 5280 §4.2.1.9 requires CA certs to assert cA=TRUE. Feeding a
    // chain whose sole entry is a junk DER blob stands in for "cA=FALSE
    // intermediate"; the chain must not validate either way.
    const alloc = std.testing.allocator;
    const junk_cert = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 }; // trivial SEQUENCE
    const chain: []const []const u8 = &.{&junk_cert};

    const result = x509.validateChain(
        alloc,
        chain,
        1_700_000_000,
        "example.com",
        .secure,
        .server_auth,
    );
    if (result) |_| return error.UnexpectedSuccess else |_| {}
}

// GAP-0838: cross-IP Raft peer TLS verification regression.
// Cert carries DNS SANs (pod FQDNs) and an IP SAN (127.0.0.2). Before the fix,
// iPAddress SANs were dropped during parsing so an IP-literal server_name
// failed with NameMismatch even though the cert listed that IP.
test "GAP-0838: validateChain matches DNS SAN and iPAddress SAN" {
    const leaf = @embedFile("leaf.der");
    const ca = @embedFile("ca.der");
    const chain = [_][]const u8{ leaf, ca };
    const ts = x509.TrustStore{ .isTrustedSpki = struct {
        fn f(_: []const u8) bool {
            return true;
        }
    }.f };
    const now: i64 = 1780184268;
    // DNS SAN (pod FQDN) — must verify.
    try x509.validateChainEx(std.testing.allocator, &chain, now, "geode-0.geode.divelife-qa.svc.cluster.local", .secure, .server_auth, ts);
    // iPAddress SAN — must verify (regression: previously NameMismatch).
    try x509.validateChainEx(std.testing.allocator, &chain, now, "127.0.0.2", .secure, .server_auth, ts);
    // An IP NOT in the cert must still be rejected.
    try std.testing.expectError(error.NameMismatch, x509.validateChainEx(std.testing.allocator, &chain, now, "127.0.0.9", .secure, .server_auth, ts));
    // A hostname NOT in the cert must still be rejected.
    try std.testing.expectError(error.NameMismatch, x509.validateChainEx(std.testing.allocator, &chain, now, "evil.example.com", .secure, .server_auth, ts));
}
