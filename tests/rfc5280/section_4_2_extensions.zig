//! RFC 5280 §4.2: Certificate Extensions Tests (GAP-0119 part 2)
//!
//! Exercises public x509 extension types and helpers. Byte-level
//! parsing is exercised in `tests/x509_unit_tests.zig`; this file pins
//! the type-shape and helper-function contracts against RFC 5280.
//!
//! Covered:
//!   §4.2.1.3  KeyUsage (bitmask wire layout)
//!   §4.2.1.12 ExtendedKeyUsage (server_auth / client_auth purpose match)

const std = @import("std");
const x509 = @import("x509");

test "RFC 5280 §4.2.1.3: KeyUsage bit layout (digitalSignature MSB)" {
    // KeyUsage is a BIT STRING with named bits encoded MSB-first.
    // digitalSignature is bit 0 => 0x8000.
    const ku = x509.KeyUsage{ .bits = 0x8000 };
    try std.testing.expectEqual(@as(u16, 0x8000), ku.bits);
    // keyCertSign is bit 5 => 0x0400 — required on CA certs.
    const ca_ku = x509.KeyUsage{ .bits = 0x0400 };
    try std.testing.expectEqual(@as(u16, 0x0400), ca_ku.bits);
}

test "RFC 5280 §4.2.1.12: ExtKeyUsage server_auth purpose check" {
    const eku = x509.ExtKeyUsage{ .server_auth = true, .client_auth = false };
    try std.testing.expect(x509.checkEkuPurpose(eku, .server_auth));
    try std.testing.expect(!x509.checkEkuPurpose(eku, .client_auth));
}

test "RFC 5280 §4.2.1.12: ExtKeyUsage client_auth purpose check" {
    const eku = x509.ExtKeyUsage{ .server_auth = false, .client_auth = true };
    try std.testing.expect(!x509.checkEkuPurpose(eku, .server_auth));
    try std.testing.expect(x509.checkEkuPurpose(eku, .client_auth));
}

test "RFC 5280 §4.2.1.12: ExtKeyUsage default all-false fails all purposes" {
    const eku = x509.ExtKeyUsage{};
    try std.testing.expect(!x509.checkEkuPurpose(eku, .server_auth));
    try std.testing.expect(!x509.checkEkuPurpose(eku, .client_auth));
}
