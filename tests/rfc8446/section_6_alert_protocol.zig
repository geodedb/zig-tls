//! RFC 8446 §6: Alert Protocol Tests (GAP-0120 part 3)
//!
//! TLS 1.3 alerts are 2 bytes (level + description). Level is legacy
//! (fatal=2 for all TLS 1.3 alerts per §6); description is the
//! AlertDescription enum. This file pins the encode/decode contract and
//! the well-known description code points.

const std = @import("std");
const alert = @import("alert");
const tls13 = @import("tls13");

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

// ============================================================================
// GAP-0133 / GAP-0134 — Alert dispatch + outbound alert API
// ============================================================================

const Context = tls13.Context;
const Callbacks = tls13.Callbacks;
const Config = tls13.Config;
const Role = tls13.Role;
const AlertDescription = alert.AlertDescription;
const EncryptionLevel = tls13.EncryptionLevel;

var captured_alert_desc: ?AlertDescription = null;

fn captureAlertCb(_: *Context, desc: AlertDescription) void {
    captured_alert_desc = desc;
}

test "GAP-0133: Context.deliverAlert decodes, populates flags, invokes callback, terminates on fatal" {
    const alloc = std.testing.allocator;
    captured_alert_desc = null;

    const config = Config{
        .role = .Server,
        .allocator = alloc,
    };
    const callbacks = Callbacks{
        .on_alert = &captureAlertCb,
    };
    var ctx = try Context.init(config, callbacks);
    defer ctx.deinit();

    // fatal handshake_failure (level=2, desc=40)
    const payload = [_]u8{ 2, 40 };
    const result = ctx.deliverAlert(.Handshake, &payload);
    try std.testing.expectError(error.PeerFatalAlert, result);

    try std.testing.expectEqual(AlertDescription.handshake_failure, captured_alert_desc.?);
    try std.testing.expectEqual(@as(u8, 40), ctx.flags.alert.?);
}

test "GAP-0133: warning alert populates flag but does NOT terminate" {
    const alloc = std.testing.allocator;
    captured_alert_desc = null;

    const config = Config{ .role = .Client, .allocator = alloc };
    var ctx = try Context.init(config, .{ .on_alert = &captureAlertCb });
    defer ctx.deinit();

    const payload = [_]u8{ 1, 90 }; // warning user_canceled
    try ctx.deliverAlert(.Application, &payload);
    try std.testing.expectEqual(AlertDescription.user_canceled, captured_alert_desc.?);
    try std.testing.expectEqual(@as(u8, 90), ctx.flags.alert.?);
}

test "GAP-0133: InvalidAlert on non-2-byte payload" {
    const alloc = std.testing.allocator;
    const config = Config{ .role = .Client, .allocator = alloc };
    var ctx = try Context.init(config, .{});
    defer ctx.deinit();

    const bad1 = [_]u8{2}; // 1 byte
    try std.testing.expectError(error.InvalidAlert, ctx.deliverAlert(.Handshake, &bad1));

    const bad3 = [_]u8{ 2, 40, 0 }; // 3 bytes
    try std.testing.expectError(error.InvalidAlert, ctx.deliverAlert(.Handshake, &bad3));
}

test "GAP-0134: sendCloseNotify writes 2-byte warning close_notify to outbound" {
    const alloc = std.testing.allocator;
    const config = Config{ .role = .Client, .allocator = alloc };
    var ctx = try Context.init(config, .{});
    defer ctx.deinit();

    try ctx.sendCloseNotify();

    // After sendCloseNotify, the last 2 bytes written to the Application
    // outbound stream must be [1, 0] (level=warning, desc=close_notify).
    const app_level = @intFromEnum(EncryptionLevel.Application);
    const outbound = ctx.streams.buffers[app_level].outbound.items;
    try std.testing.expect(outbound.len >= 2);
    try std.testing.expectEqual(@as(u8, 1), outbound[outbound.len - 2]);
    try std.testing.expectEqual(@as(u8, 0), outbound[outbound.len - 1]);
}

test "GAP-0134: sendFatalAlert writes 2-byte fatal alert" {
    const alloc = std.testing.allocator;
    const config = Config{ .role = .Client, .allocator = alloc };
    var ctx = try Context.init(config, .{});
    defer ctx.deinit();

    try ctx.sendFatalAlert(.internal_error);

    // Initial phase is .initial, so level should be .Initial
    const initial_level = @intFromEnum(EncryptionLevel.Initial);
    const outbound = ctx.streams.buffers[initial_level].outbound.items;
    try std.testing.expect(outbound.len >= 2);
    try std.testing.expectEqual(@as(u8, 2), outbound[outbound.len - 2]);
    try std.testing.expectEqual(@as(u8, 80), outbound[outbound.len - 1]); // internal_error = 80
}
