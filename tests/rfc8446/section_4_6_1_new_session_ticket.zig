//! RFC 8446 §4.6.1 — NewSessionTicket build / parse / callback (GAP-0132).
//!
//! Wire layout:
//!     struct {
//!         uint32 ticket_lifetime;
//!         uint32 ticket_age_add;
//!         opaque ticket_nonce<0..255>;
//!         opaque ticket<1..2^16-1>;
//!         Extension extensions<0..2^16-2>;
//!     } NewSessionTicket;

const std = @import("std");
const tls13 = @import("tls13");

test "RFC 8446 §4.6.1: NewSessionTicket build / parse round-trip" {
    const alloc = std.testing.allocator;

    const params = tls13.NewSessionTicketParams{
        .ticket_lifetime = 7200,
        .ticket_age_add = 0xDEADBEEF,
        .ticket_nonce = &[_]u8{ 0x01, 0x02, 0x03 },
        .ticket = &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE },
    };

    const body = try tls13.buildNewSessionTicket(alloc, params);
    defer alloc.free(body);

    // Layout assertions — pin the byte-level shape.
    // 4 (lifetime) + 4 (age_add) + 1 (nonce_len) + 3 (nonce) + 2 (ticket_len)
    // + 5 (ticket) + 2 (ext_len) + 0 (no extensions) = 21 bytes.
    try std.testing.expectEqual(@as(usize, 21), body.len);

    const parsed = try tls13.parseNewSessionTicket(body);
    try std.testing.expectEqual(@as(u32, 7200), parsed.ticket_lifetime);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parsed.ticket_age_add);
    try std.testing.expectEqualSlices(u8, params.ticket_nonce, parsed.ticket_nonce);
    try std.testing.expectEqualSlices(u8, params.ticket, parsed.ticket);
    try std.testing.expectEqual(@as(usize, 0), parsed.extensions.len);
}

test "RFC 8446 §4.6.1: NewSessionTicket build rejects empty ticket" {
    const alloc = std.testing.allocator;

    const params = tls13.NewSessionTicketParams{
        .ticket_lifetime = 1,
        .ticket_age_add = 0,
        .ticket_nonce = &[_]u8{},
        .ticket = &[_]u8{}, // RFC 8446 §4.6.1: ticket<1..2^16-1>
    };

    try std.testing.expectError(error.InvalidTicketLength, tls13.buildNewSessionTicket(alloc, params));
}

test "RFC 8446 §4.6.1: NewSessionTicket build rejects ticket_nonce > 255" {
    const alloc = std.testing.allocator;

    var nonce_buf: [256]u8 = undefined;
    @memset(&nonce_buf, 0x42);

    const params = tls13.NewSessionTicketParams{
        .ticket_lifetime = 1,
        .ticket_age_add = 0,
        .ticket_nonce = &nonce_buf,
        .ticket = &[_]u8{0xAB},
    };

    try std.testing.expectError(error.TicketNonceTooLong, tls13.buildNewSessionTicket(alloc, params));
}

test "RFC 8446 §4.6.1: NewSessionTicket parse rejects truncated body" {
    // Body too short to even contain the fixed-width header (4+4+1+2+1+2=14B).
    const truncated = [_]u8{ 0x00, 0x00, 0x00, 0x01 };
    try std.testing.expectError(error.TooShort, tls13.parseNewSessionTicket(&truncated));
}

test "RFC 8446 §4.6.1: NewSessionTicket parse rejects ticket_len = 0" {
    // Hand-rolled body: lifetime=1, age_add=0, nonce_len=0, ticket_len=0,
    // ext_len=0. ticket_len=0 violates `opaque ticket<1..2^16-1>`.
    const body = [_]u8{
        0x00, 0x00, 0x00, 0x01, // ticket_lifetime
        0x00, 0x00, 0x00, 0x00, // ticket_age_add
        0x00, // ticket_nonce<0..255>: empty
        0x00, 0x00, // ticket_len = 0 (illegal)
        0x00, 0x00, // ext_len = 0
    };
    try std.testing.expectError(error.InvalidTicketLength, tls13.parseNewSessionTicket(&body));
}

test "RFC 8446 §4.6.1: NewSessionTicket parse rejects trailing bytes" {
    const alloc = std.testing.allocator;
    const params = tls13.NewSessionTicketParams{
        .ticket_lifetime = 1,
        .ticket_age_add = 0,
        .ticket_nonce = &[_]u8{},
        .ticket = &[_]u8{0xAB},
    };
    const body = try tls13.buildNewSessionTicket(alloc, params);
    defer alloc.free(body);

    // Append a stray byte; the parser must surface it instead of silently
    // ignoring junk after the extensions slot.
    var with_trailer = try alloc.alloc(u8, body.len + 1);
    defer alloc.free(with_trailer);
    @memcpy(with_trailer[0..body.len], body);
    with_trailer[body.len] = 0xFF;

    try std.testing.expectError(error.TrailingBytes, tls13.parseNewSessionTicket(with_trailer));
}
