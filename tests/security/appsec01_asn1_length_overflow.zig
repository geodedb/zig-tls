// SPDX-License-Identifier: Apache-2.0
//! APPSEC-2026-06-10-01 regression: the DER length-bounds checks in the ASN.1
//! decoder and the X.509 parser computed `off + attacker_len` BEFORE the
//! `> buf.len` guard. A DER long-form length near `maxInt(usize)` (e.g. an
//! 8-octet `0x88 FF FF FF FF FF FF FF FF`) made the `usize` add wrap to a
//! small value, bypassing the guard and producing an inverted slice
//! (`start > end`). Under ReleaseSafe/Debug this panics (pre-auth remote DoS);
//! under ReleaseFast it is undefined behavior / out-of-bounds read on
//! attacker-controlled certificate, OCSP, and SCT bytes.
//!
//! The fix validates `len > remaining` (`buf.len - off`) before the add, so
//! every site cleanly returns `error.Truncated`. These tests assert that
//! clean rejection at the two distinct slice sites:
//!   - asn1.zig `readTLV`  (the chokepoint for readSequence/readInteger/...)
//!   - x509.zig  `parseCert` TBSCertificate slice capture
//!
//! Must hold under every optimize mode, including
//! `zig build test -Doptimize=ReleaseFast`.

const std = @import("std");
const asn1 = @import("asn1");
const x509 = @import("x509");

test "APPSEC-01: asn1.readTLV rejects 8-octet near-max length without overflow" {
    // tag=0x04 (OCTET STRING), long-form length with 8 octets all 0xFF =>
    // declared length 0xFFFF_FFFF_FFFF_FFFF. buf is exactly the 10-byte header
    // with no value bytes, so `off (10) + len (2^64-1)` wraps to 9 and the old
    // `end > buf.len` guard (9 > 10 == false) was bypassed.
    const bytes = [_]u8{ 0x04, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    var dec = asn1.Decoder.init(&bytes);
    try std.testing.expectError(error.Truncated, dec.readTLV());
}

test "APPSEC-01: asn1.readTLV rejects near-max length that wraps below off" {
    // A second wrap point: length 0xFFFF_FFFF_FFFF_FFF8 with off=10 wraps to 2,
    // which is < buf.len, again bypassing the old guard.
    const bytes = [_]u8{ 0x04, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8 };
    var dec = asn1.Decoder.init(&bytes);
    try std.testing.expectError(error.Truncated, dec.readTLV());
}

test "APPSEC-01: asn1.readSequence (via readTLV) rejects near-max length" {
    const bytes = [_]u8{ 0x30, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    var dec = asn1.Decoder.init(&bytes);
    try std.testing.expectError(error.Truncated, dec.readSequence());
}

test "APPSEC-01: x509.parseCert rejects near-max TBS length without overflow" {
    const alloc = std.testing.allocator;
    // Outer Certificate SEQUENCE (valid length 10) wrapping a TBSCertificate
    // header whose long-form length is 0xFFFF_FFFF_FFFF_FFFF. `readSequence`
    // for the outer SEQUENCE succeeds; the overflow is reached at the inner
    // `tbs_end = ci.off + tbs_hdr.len` slice-capture site in parseCert.
    const der = [_]u8{
        0x30, 0x0A, // Certificate ::= SEQUENCE, length 10
        0x30, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // TBSCertificate header, len 2^64-1
    };
    const result = x509.parseCert(alloc, &der);
    try std.testing.expectError(error.Truncated, result);
}
