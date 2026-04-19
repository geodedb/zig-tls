//! RFC 8446 §4.6.3: KeyUpdate Post-Handshake Message Tests (GAP-0120 part 2)

const std = @import("std");
const tls13 = @import("tls13");

test "RFC 8446 §4.6.3: KeyUpdate build/parse (update_not_requested)" {
    const alloc = std.testing.allocator;
    const msg = try tls13.buildKeyUpdate(alloc, false);
    defer alloc.free(msg);

    // buildKeyUpdate wraps in handshake header (1B type + 3B length + 1B body).
    try std.testing.expectEqual(@as(usize, 5), msg.len);
    try std.testing.expectEqual(@as(u8, 24), msg[0]); // handshake type key_update = 24
    try std.testing.expectEqual(@as(u8, 0), msg[4]); // body byte

    const parsed = try tls13.parseKeyUpdate(msg[4..]);
    try std.testing.expectEqual(tls13.KeyUpdateRequest.update_not_requested, parsed);
}

test "RFC 8446 §4.6.3: KeyUpdate build/parse (update_requested)" {
    const alloc = std.testing.allocator;
    const msg = try tls13.buildKeyUpdate(alloc, true);
    defer alloc.free(msg);

    try std.testing.expectEqual(@as(usize, 5), msg.len);
    try std.testing.expectEqual(@as(u8, 24), msg[0]);
    try std.testing.expectEqual(@as(u8, 1), msg[4]);

    const parsed = try tls13.parseKeyUpdate(msg[4..]);
    try std.testing.expectEqual(tls13.KeyUpdateRequest.update_requested, parsed);
}

test "RFC 8446 §4.6.3: KeyUpdate parse rejects invalid byte" {
    const invalid = [_]u8{0x02};
    const r = tls13.parseKeyUpdate(&invalid);
    if (r) |_| return error.UnexpectedSuccess else |_| {}
}

test "RFC 8446 §4.6.3: KeyUpdate parse rejects wrong-length body" {
    const empty: []const u8 = &.{};
    const r1 = tls13.parseKeyUpdate(empty);
    if (r1) |_| return error.UnexpectedSuccess else |_| {}

    const too_long = [_]u8{ 0x00, 0x00 };
    const r2 = tls13.parseKeyUpdate(&too_long);
    if (r2) |_| return error.UnexpectedSuccess else |_| {}
}
