// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Alert protocol helpers for TLS 1.3 and QUIC.
//!
//! Implements RFC 8446 §6 alert descriptions/levels and the QUIC mapping from
//! RFC 9001 §4.8 so transport code can surface TLS failures as CRYPTO_ERRORs.
const std = @import("std");

/// RFC 8446 §6.2 Alert descriptions
pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
    _,
    /// Human-readable formatting for diagnostics and logging.
    pub fn format(self: AlertDescription, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        const name = switch (self) {
            .close_notify => "close_notify",
            .unexpected_message => "unexpected_message",
            .bad_record_mac => "bad_record_mac",
            .record_overflow => "record_overflow",
            .handshake_failure => "handshake_failure",
            .bad_certificate => "bad_certificate",
            .unsupported_certificate => "unsupported_certificate",
            .certificate_revoked => "certificate_revoked",
            .certificate_expired => "certificate_expired",
            .certificate_unknown => "certificate_unknown",
            .illegal_parameter => "illegal_parameter",
            .unknown_ca => "unknown_ca",
            .access_denied => "access_denied",
            .decode_error => "decode_error",
            .decrypt_error => "decrypt_error",
            .protocol_version => "protocol_version",
            .insufficient_security => "insufficient_security",
            .internal_error => "internal_error",
            .inappropriate_fallback => "inappropriate_fallback",
            .user_canceled => "user_canceled",
            .missing_extension => "missing_extension",
            .unsupported_extension => "unsupported_extension",
            .unrecognized_name => "unrecognized_name",
            .bad_certificate_status_response => "bad_certificate_status_response",
            .unknown_psk_identity => "unknown_psk_identity",
            .certificate_required => "certificate_required",
            .no_application_protocol => "no_application_protocol",
            else => "unknown",
        };
        try writer.print("Alert({s}:{})", .{ name, @intFromEnum(self) });
    }
};

/// RFC 8446 §6.1 Alert levels
pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
    _,
};

/// Packed TLS alert message (2 bytes: level + description)
pub const Alert = packed struct {
    level: AlertLevel,
    description: AlertDescription,

    /// Encode the alert as the on-the-wire two byte TLS alert payload.
    pub fn encode(self: Alert) [2]u8 {
        return .{ @intFromEnum(self.level), @intFromEnum(self.description) };
    }

    /// Decode a TLS alert payload into strongly typed fields.
    pub fn decode(bytes: [2]u8) Alert {
        return .{
            .level = @enumFromInt(bytes[0]),
            .description = @enumFromInt(bytes[1]),
        };
    }
};

/// RFC 9001 §4.8 maps TLS alerts to QUIC CRYPTO_ERROR codes (0x0100 + alert)
pub fn toQuicCryptoError(alert: AlertDescription) u64 {
    return 0x0100 + @as(u64, @intFromEnum(alert));
}

/// Map common handshake errors to appropriate TLS alerts
pub fn fromHandshakeError(err: anyerror) AlertDescription {
    // This mapping follows RFC 8446 §6 guidance
    return switch (err) {
        error.UnexpectedMessage => .unexpected_message,
        error.UnsupportedVersion => .protocol_version,
        error.MissingKeyShare => .missing_extension,
        error.UnsupportedKeyShareGroup => .illegal_parameter,
        error.NoCipherSuite => .handshake_failure,
        error.MissingTransportParameters => .missing_extension,
        error.AlpnNegotiationFailed => .no_application_protocol,
        error.NoSignatureScheme => .handshake_failure,
        error.FinishedVerifyFailed => .decrypt_error,
        error.DowngradeAttempt => .illegal_parameter,
        error.DuplicateClientHello => .unexpected_message,
        error.PostHandshakeAuthUnsupported => .unexpected_message,
        error.OutOfMemory => .internal_error,
        else => .internal_error,
    };
}

test "alert encoding round-trip" {
    const alert = Alert{ .level = .fatal, .description = .handshake_failure };
    const encoded = alert.encode();
    try std.testing.expectEqual(@as(u8, 2), encoded[0]);
    try std.testing.expectEqual(@as(u8, 40), encoded[1]);
    const decoded = Alert.decode(encoded);
    try std.testing.expectEqual(alert.level, decoded.level);
    try std.testing.expectEqual(alert.description, decoded.description);
}

test "QUIC crypto error mapping" {
    const desc = AlertDescription.handshake_failure;
    const quic_err = toQuicCryptoError(desc);
    try std.testing.expectEqual(@as(u64, 0x0100 + 40), quic_err);
}

test "handshake error to alert mapping" {
    try std.testing.expectEqual(AlertDescription.unexpected_message, fromHandshakeError(error.UnexpectedMessage));
    try std.testing.expectEqual(AlertDescription.protocol_version, fromHandshakeError(error.UnsupportedVersion));
    try std.testing.expectEqual(AlertDescription.no_application_protocol, fromHandshakeError(error.AlpnNegotiationFailed));
    try std.testing.expectEqual(AlertDescription.decrypt_error, fromHandshakeError(error.FinishedVerifyFailed));
}

// ============================================================================
// COMPREHENSIVE ALERT TESTS - RFC 8446 §6
// ============================================================================

// RFC 8446 §6: Test all alert description values
test "RFC 8446 §6.2 - all alert descriptions have correct values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(AlertDescription.close_notify));
    try std.testing.expectEqual(@as(u8, 10), @intFromEnum(AlertDescription.unexpected_message));
    try std.testing.expectEqual(@as(u8, 20), @intFromEnum(AlertDescription.bad_record_mac));
    try std.testing.expectEqual(@as(u8, 22), @intFromEnum(AlertDescription.record_overflow));
    try std.testing.expectEqual(@as(u8, 40), @intFromEnum(AlertDescription.handshake_failure));
    try std.testing.expectEqual(@as(u8, 42), @intFromEnum(AlertDescription.bad_certificate));
    try std.testing.expectEqual(@as(u8, 43), @intFromEnum(AlertDescription.unsupported_certificate));
    try std.testing.expectEqual(@as(u8, 44), @intFromEnum(AlertDescription.certificate_revoked));
    try std.testing.expectEqual(@as(u8, 45), @intFromEnum(AlertDescription.certificate_expired));
    try std.testing.expectEqual(@as(u8, 46), @intFromEnum(AlertDescription.certificate_unknown));
    try std.testing.expectEqual(@as(u8, 47), @intFromEnum(AlertDescription.illegal_parameter));
    try std.testing.expectEqual(@as(u8, 48), @intFromEnum(AlertDescription.unknown_ca));
    try std.testing.expectEqual(@as(u8, 49), @intFromEnum(AlertDescription.access_denied));
    try std.testing.expectEqual(@as(u8, 50), @intFromEnum(AlertDescription.decode_error));
    try std.testing.expectEqual(@as(u8, 51), @intFromEnum(AlertDescription.decrypt_error));
    try std.testing.expectEqual(@as(u8, 70), @intFromEnum(AlertDescription.protocol_version));
    try std.testing.expectEqual(@as(u8, 71), @intFromEnum(AlertDescription.insufficient_security));
    try std.testing.expectEqual(@as(u8, 80), @intFromEnum(AlertDescription.internal_error));
    try std.testing.expectEqual(@as(u8, 86), @intFromEnum(AlertDescription.inappropriate_fallback));
    try std.testing.expectEqual(@as(u8, 90), @intFromEnum(AlertDescription.user_canceled));
    try std.testing.expectEqual(@as(u8, 109), @intFromEnum(AlertDescription.missing_extension));
    try std.testing.expectEqual(@as(u8, 110), @intFromEnum(AlertDescription.unsupported_extension));
    try std.testing.expectEqual(@as(u8, 112), @intFromEnum(AlertDescription.unrecognized_name));
    try std.testing.expectEqual(@as(u8, 113), @intFromEnum(AlertDescription.bad_certificate_status_response));
    try std.testing.expectEqual(@as(u8, 115), @intFromEnum(AlertDescription.unknown_psk_identity));
    try std.testing.expectEqual(@as(u8, 116), @intFromEnum(AlertDescription.certificate_required));
    try std.testing.expectEqual(@as(u8, 120), @intFromEnum(AlertDescription.no_application_protocol));
}

// RFC 8446 §6.1: Test alert levels
test "RFC 8446 §6.1 - alert levels" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(AlertLevel.warning));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(AlertLevel.fatal));
}

// RFC 8446 §6: Test alert encoding for all levels
test "RFC 8446 §6 - alert encoding for different levels" {
    const fatal = Alert{ .level = .fatal, .description = .bad_certificate };
    const fatal_encoded = fatal.encode();
    try std.testing.expectEqual(@as(u8, 2), fatal_encoded[0]);
    try std.testing.expectEqual(@as(u8, 42), fatal_encoded[1]);

    const warning = Alert{ .level = .warning, .description = .close_notify };
    const warning_encoded = warning.encode();
    try std.testing.expectEqual(@as(u8, 1), warning_encoded[0]);
    try std.testing.expectEqual(@as(u8, 0), warning_encoded[1]);
}

// RFC 8446 §6: Test alert decoding with unknown values
test "RFC 8446 §6 - alert decode with unknown alert codes" {
    const unknown_bytes = [_]u8{ 99, 255 };
    const decoded = Alert.decode(unknown_bytes);

    // Should decode without error (uses non-exhaustive enum)
    try std.testing.expectEqual(@as(u8, 99), @intFromEnum(decoded.level));
    try std.testing.expectEqual(@as(u8, 255), @intFromEnum(decoded.description));
}

// RFC 9001 §4.8: QUIC CRYPTO_ERROR mapping for all standard alerts
test "RFC 9001 §4.8 - QUIC CRYPTO_ERROR mapping" {
    try std.testing.expectEqual(@as(u64, 0x0100), toQuicCryptoError(.close_notify));
    try std.testing.expectEqual(@as(u64, 0x010A), toQuicCryptoError(.unexpected_message));
    try std.testing.expectEqual(@as(u64, 0x0114), toQuicCryptoError(.bad_record_mac));
    try std.testing.expectEqual(@as(u64, 0x0128), toQuicCryptoError(.handshake_failure));
    try std.testing.expectEqual(@as(u64, 0x012A), toQuicCryptoError(.bad_certificate));
    try std.testing.expectEqual(@as(u64, 0x0150), toQuicCryptoError(.internal_error));
    try std.testing.expectEqual(@as(u64, 0x0178), toQuicCryptoError(.no_application_protocol));
}

// Test error to alert mapping - complete coverage
test "fromHandshakeError - comprehensive mapping" {
    try std.testing.expectEqual(AlertDescription.unexpected_message, fromHandshakeError(error.UnexpectedMessage));
    try std.testing.expectEqual(AlertDescription.protocol_version, fromHandshakeError(error.UnsupportedVersion));
    try std.testing.expectEqual(AlertDescription.missing_extension, fromHandshakeError(error.MissingKeyShare));
    try std.testing.expectEqual(AlertDescription.illegal_parameter, fromHandshakeError(error.UnsupportedKeyShareGroup));
    try std.testing.expectEqual(AlertDescription.handshake_failure, fromHandshakeError(error.NoCipherSuite));
    try std.testing.expectEqual(AlertDescription.missing_extension, fromHandshakeError(error.MissingTransportParameters));
    try std.testing.expectEqual(AlertDescription.no_application_protocol, fromHandshakeError(error.AlpnNegotiationFailed));
    try std.testing.expectEqual(AlertDescription.handshake_failure, fromHandshakeError(error.NoSignatureScheme));
    try std.testing.expectEqual(AlertDescription.decrypt_error, fromHandshakeError(error.FinishedVerifyFailed));
    try std.testing.expectEqual(AlertDescription.illegal_parameter, fromHandshakeError(error.DowngradeAttempt));
    try std.testing.expectEqual(AlertDescription.unexpected_message, fromHandshakeError(error.DuplicateClientHello));
    try std.testing.expectEqual(AlertDescription.internal_error, fromHandshakeError(error.OutOfMemory));
}

// Test error to alert mapping - unknown errors default to internal_error
test "fromHandshakeError - unknown error defaults to internal_error" {
    try std.testing.expectEqual(AlertDescription.internal_error, fromHandshakeError(error.SomeRandomError));
    try std.testing.expectEqual(AlertDescription.internal_error, fromHandshakeError(error.FileNotFound));
}

// Test alert format method
test "AlertDescription format method" {
    var buf: [100]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    try AlertDescription.handshake_failure.format("", .{}, writer);
    const output = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "handshake_failure") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "40") != null);
}

// Test format method with unknown alert
test "AlertDescription format - unknown alert" {
    var buf: [100]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const unknown: AlertDescription = @enumFromInt(254);
    try unknown.format("", .{}, writer);
    const output = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "unknown") != null);
}

// Test encode/decode round-trip for multiple alerts
test "Alert encode/decode round-trip - multiple alerts" {
    const test_cases = [_]Alert{
        .{ .level = .fatal, .description = .close_notify },
        .{ .level = .warning, .description = .user_canceled },
        .{ .level = .fatal, .description = .certificate_expired },
        .{ .level = .fatal, .description = .unknown_ca },
        .{ .level = .fatal, .description = .decode_error },
    };

    for (test_cases) |original| {
        const encoded = original.encode();
        const decoded = Alert.decode(encoded);
        try std.testing.expectEqual(original.level, decoded.level);
        try std.testing.expectEqual(original.description, decoded.description);
    }
}

// Test that alert bytes are in correct order (level, description)
test "Alert encoding byte order" {
    const alert = Alert{ .level = .fatal, .description = .decrypt_error };
    const bytes = alert.encode();

    // First byte should be level
    try std.testing.expectEqual(@intFromEnum(AlertLevel.fatal), bytes[0]);
    // Second byte should be description
    try std.testing.expectEqual(@intFromEnum(AlertDescription.decrypt_error), bytes[1]);
}
