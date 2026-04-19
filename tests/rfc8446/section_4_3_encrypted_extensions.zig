//! RFC 8446 §4.3: EncryptedExtensions Message Tests (GAP-0120 part 1)
//!
//! §4.3 specifies that the server MUST send EncryptedExtensions
//! immediately after ServerHello to convey extensions that are not
//! needed to establish cryptographic context (e.g., ALPN,
//! quic_transport_parameters).
//!
//! This file pins the public build/parse roundtrip for the two
//! EncryptedExtensions fields we care about in this crate (ALPN and
//! QUIC transport parameters).

const std = @import("std");
const tls13_full = @import("tls13_full");

test "RFC 8446 §4.3: EncryptedExtensions build/parse roundtrip with ALPN" {
    const alloc = std.testing.allocator;
    const msg = try tls13_full.buildEncryptedExtensions(alloc, "h3", null);
    defer alloc.free(msg);

    const parsed = try tls13_full.parseEncryptedExtensions(msg);
    try std.testing.expect(parsed.alpn != null);
    try std.testing.expectEqualStrings("h3", parsed.alpn.?);
    try std.testing.expect(parsed.quic_transport_parameters == null);
}

test "RFC 8446 §4.3: EncryptedExtensions build/parse with QUIC params" {
    const alloc = std.testing.allocator;
    const qtp = [_]u8{ 0x01, 0x02, 0x30, 0x00 };
    const msg = try tls13_full.buildEncryptedExtensions(alloc, null, &qtp);
    defer alloc.free(msg);

    const parsed = try tls13_full.parseEncryptedExtensions(msg);
    try std.testing.expect(parsed.alpn == null);
    try std.testing.expect(parsed.quic_transport_parameters != null);
    try std.testing.expectEqualSlices(u8, &qtp, parsed.quic_transport_parameters.?);
}

test "RFC 8446 §4.3: EncryptedExtensions empty extensions vector parses cleanly" {
    const alloc = std.testing.allocator;
    const msg = try tls13_full.buildEncryptedExtensions(alloc, null, null);
    defer alloc.free(msg);

    const parsed = try tls13_full.parseEncryptedExtensions(msg);
    try std.testing.expect(parsed.alpn == null);
    try std.testing.expect(parsed.quic_transport_parameters == null);
}
