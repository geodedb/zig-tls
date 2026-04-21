// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! SEC-076: Regression test for OID canonical-equality semantics.

const std = @import("std");
const asn1 = @import("asn1");
const ocsp = @import("ocsp");

// 2.16.840.1.101.3.4.2.1 (SHA-256)
const sha256_oid = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };

test "SEC-076: oidEqual rejects prefix-attack encodings" {
    const attack = [_]u8{0xFF} ++ sha256_oid;
    try std.testing.expect(!asn1.oidEqual(&attack, &sha256_oid));
}

test "SEC-076: oidEqual accepts exact canonical encoding" {
    try std.testing.expect(asn1.oidEqual(&sha256_oid, &sha256_oid));
}

test "SEC-076: oidEqual rejects length mismatch" {
    const short = sha256_oid[0 .. sha256_oid.len - 1];
    try std.testing.expect(!asn1.oidEqual(short, &sha256_oid));
}

test "SEC-076: hashAlgFromOid rejects prefix-attack" {
    const attack = [_]u8{0xFF} ++ sha256_oid;
    try std.testing.expectError(error.UnsupportedHashAlgorithm, ocsp.hashAlgFromOid(&attack));
}

test "SEC-076: hashAlgFromOid accepts canonical SHA-256" {
    try std.testing.expectEqual(ocsp.HashAlg.sha256, try ocsp.hashAlgFromOid(&sha256_oid));
}
