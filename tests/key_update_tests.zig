//! TLS 1.3 Key Update Integration Tests
//!
//! These tests verify the key update mechanism defined in RFC 8446 §4.6.3
//! and RFC 9001 §6 (QUIC-specific considerations).
//!
//! Test Coverage:
//! - Sending KeyUpdate messages (with/without peer request)
//! - Secret rotation and installation
//! - Error handling (called before handshake complete)

const std = @import("std");
const testing = std.testing;
const tls13 = @import("tls13");
const key_schedule = @import("quic_tls");

// ============================================================================
// Key Update API Tests
// ============================================================================

test "Context.sendKeyUpdate - before handshake complete fails" {
    // RFC 8446 §4.6.3: KeyUpdate only valid after handshake complete

    const callbacks = tls13.Callbacks{};
    const config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .alpn_protocols = &.{"h3"},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    };

    var ctx = tls13.Context.init(config, callbacks);
    defer ctx.deinit();

    // Attempt to send KeyUpdate before handshake complete
    const result = ctx.sendKeyUpdate(false);
    try testing.expectError(error.UnexpectedMessage, result);
}

test "Context.sendKeyUpdate - queues message" {
    // Verify KeyUpdate message is built and queued

    const callbacks = tls13.Callbacks{};
    const config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .alpn_protocols = &.{"h3"},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    };

    var ctx = tls13.Context.init(config, callbacks);
    defer ctx.deinit();

    // Simulate handshake complete by installing Application secrets manually
    var dummy_secret = key_schedule.Secret.initZero(.sha256);
    @memset(dummy_secret.bytes[0..32], 0xAA);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, dummy_secret);

    // Send KeyUpdate
    try ctx.sendKeyUpdate(false);

    // Verify KeyUpdate message was queued by polling CRYPTO data
    const msg = try ctx.pollCrypto(testing.allocator, .Application);
    defer testing.allocator.free(msg);

    // KeyUpdate message format: [type:1][length:3][body:1] = 5 bytes total
    try testing.expectEqual(@as(usize, 5), msg.len);

    // Verify message type (byte 0 = 24 for key_update)
    try testing.expectEqual(@as(u8, 24), msg[0]);
}

test "Context.sendKeyUpdate - secret rotation" {
    // Verify that sending KeyUpdate actually rotates the secret

    const callbacks = tls13.Callbacks{};
    const config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .alpn_protocols = &.{"h3"},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    };

    var ctx = tls13.Context.init(config, callbacks);
    defer ctx.deinit();

    // Install initial Application secret
    var initial_secret = key_schedule.Secret.initZero(.sha256);
    @memset(initial_secret.bytes[0..32], 0xEE);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, initial_secret);

    // Capture initial secret value
    const initial_bytes = ctx.secrets.slot(.Application, .send).value;

    // Send first KeyUpdate
    try ctx.sendKeyUpdate(false);

    // Verify secret was updated (different from initial)
    const first_updated = ctx.secrets.slot(.Application, .send).value;
    try testing.expect(!std.mem.eql(u8, initial_bytes.slice(), first_updated.slice()));

    // Send second KeyUpdate
    try ctx.sendKeyUpdate(false);

    // Verify secret was updated again (different from first)
    const second_updated = ctx.secrets.slot(.Application, .send).value;
    try testing.expect(!std.mem.eql(u8, first_updated.slice(), second_updated.slice()));
}

test "Context.sendKeyUpdate - both directions" {
    // Verify multiple key updates work correctly

    const callbacks = tls13.Callbacks{};
    const config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Server,
        .alpn_protocols = &.{"h3"},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    };

    var ctx = tls13.Context.init(config, callbacks);
    defer ctx.deinit();

    // Simulate handshake complete
    var dummy_secret = key_schedule.Secret.initZero(.sha256);
    @memset(dummy_secret.bytes[0..32], 0xBB);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, dummy_secret);

    // Send first KeyUpdate with request_peer_update=false
    try ctx.sendKeyUpdate(false);

    // Send second KeyUpdate with request_peer_update=true
    try ctx.sendKeyUpdate(true);

    // Verify messages were queued by polling (should get both messages)
    const msg = try ctx.pollCrypto(testing.allocator, .Application);
    defer testing.allocator.free(msg);

    // Should be two KeyUpdate messages (5 bytes each = 10 bytes total)
    try testing.expectEqual(@as(usize, 10), msg.len);
    try testing.expectEqual(@as(u8, 24), msg[0]); // First message type
    try testing.expectEqual(@as(u8, 24), msg[5]); // Second message type
}

test "Context.sendKeyUpdate - RFC 8446 message format" {
    // Verify KeyUpdate implementation matches RFC 8446 §4.6.3 format

    const callbacks = tls13.Callbacks{};
    const config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Server,
        .alpn_protocols = &.{"h3"},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    };

    var ctx = tls13.Context.init(config, callbacks);
    defer ctx.deinit();

    // Simulate handshake complete
    var dummy_secret = key_schedule.Secret.initZero(.sha256);
    @memset(dummy_secret.bytes[0..32], 0xFF);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, dummy_secret);

    // Send KeyUpdate
    try ctx.sendKeyUpdate(true);

    // Parse message structure
    const msg = try ctx.pollCrypto(testing.allocator, .Application);
    defer testing.allocator.free(msg);

    // Verify handshake message framing: [type:1][length:3][body:1]
    try testing.expectEqual(@as(usize, 5), msg.len);
    try testing.expectEqual(@as(u8, 24), msg[0]); // type = key_update
    try testing.expectEqual(@as(u8, 0), msg[1]); // length high byte
    try testing.expectEqual(@as(u8, 0), msg[2]); // length mid byte
    try testing.expectEqual(@as(u8, 1), msg[3]); // length low byte (1-byte body)

    // Body is single byte: KeyUpdateRequest enum (0 or 1)
    try testing.expect(msg[4] == 0 or msg[4] == 1);
}
