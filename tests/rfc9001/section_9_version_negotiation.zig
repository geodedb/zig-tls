//! RFC 9001 §9 + RFC 9369: QUIC Version Negotiation Tests (GAP-0121 part 2)
//!
//! QUIC versions differ in the Initial salt used for HKDF-Extract when
//! deriving the Initial secret from the client's destination connection
//! ID. This file pins those salt constants so an accidental byte-level
//! mutation is caught at test time.

const std = @import("std");
const ks = @import("quic_tls");

test "RFC 9001 §5.2: QUIC v1 initial salt bytes" {
    const expected: [20]u8 = .{
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    };
    try std.testing.expectEqualSlices(u8, &expected, &ks.initial_salt_v1);
}

test "RFC 9369 §A.1: QUIC v2 initial salt bytes" {
    const expected: [20]u8 = .{
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    };
    try std.testing.expectEqualSlices(u8, &expected, &ks.initial_salt_v2);
}

test "RFC 9001/9369: v1 and v2 salts MUST differ" {
    // Cross-version replay protection depends on these salts being distinct.
    try std.testing.expect(!std.mem.eql(u8, &ks.initial_salt_v1, &ks.initial_salt_v2));
}
