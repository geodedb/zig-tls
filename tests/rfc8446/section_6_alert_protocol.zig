//! RFC 8446 §6: Alert Protocol Tests (GAP-0120 part 3)
//!
//! TLS 1.3 alerts are 2 bytes (level + description). Level is legacy
//! (fatal=2 for all TLS 1.3 alerts per §6); description is the
//! AlertDescription enum. This file pins the encode/decode contract and
//! the well-known description code points.

const std = @import("std");
const alert = @import("alert");

test "RFC 8446 §6: Alert encode/decode roundtrip" {
    const a = alert.Alert{
        .level = .fatal,
        .description = .handshake_failure,
    };
    const encoded = a.encode();
    try std.testing.expectEqual(@as(u8, 2), encoded[0]);
    try std.testing.expectEqual(@as(u8, 40), encoded[1]);

    const decoded = alert.Alert.decode(encoded);
    try std.testing.expectEqual(a.level, decoded.level);
    try std.testing.expectEqual(a.description, decoded.description);
}

test "RFC 8446 §6: well-known AlertDescription code points" {
    // RFC 8446 §6 table — these integer values are part of the wire
    // format and must not drift.
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(alert.AlertDescription.close_notify));
    try std.testing.expectEqual(@as(u8, 10), @intFromEnum(alert.AlertDescription.unexpected_message));
    try std.testing.expectEqual(@as(u8, 20), @intFromEnum(alert.AlertDescription.bad_record_mac));
    try std.testing.expectEqual(@as(u8, 40), @intFromEnum(alert.AlertDescription.handshake_failure));
    try std.testing.expectEqual(@as(u8, 42), @intFromEnum(alert.AlertDescription.bad_certificate));
    try std.testing.expectEqual(@as(u8, 50), @intFromEnum(alert.AlertDescription.decode_error));
}

test "RFC 8446 §6: AlertLevel fatal/warning wire codes" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(alert.AlertLevel.warning));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(alert.AlertLevel.fatal));
}
