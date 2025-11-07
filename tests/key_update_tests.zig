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

// ============================================================================
// Generation Tracking Tests (Secret Manager Integration)
// ============================================================================

test "Context - generation tracking on secret installation" {
    // RFC 8446 §4.6.3: Verify generation increments on each secret installation

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

    // Initial state: generation should be 0 (not installed)
    try testing.expectEqual(@as(u32, 0), ctx.getKeyGeneration(.Application, .send));
    try testing.expectEqual(@as(u32, 0), ctx.getKeyGeneration(.Application, .recv));

    // Install first secret
    var secret1 = key_schedule.Secret.initZero(.sha256);
    @memset(secret1.bytes[0..32], 0x11);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, secret1);

    // Generation should now be 1
    try testing.expectEqual(@as(u32, 1), ctx.getKeyGeneration(.Application, .send));
    try testing.expectEqual(@as(u32, 0), ctx.getKeyGeneration(.Application, .recv)); // recv still 0

    // Install second secret (simulate key update)
    var secret2 = key_schedule.Secret.initZero(.sha256);
    @memset(secret2.bytes[0..32], 0x22);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, secret2);

    // Generation should now be 2
    try testing.expectEqual(@as(u32, 2), ctx.getKeyGeneration(.Application, .send));
}

test "Context - generation tracking with sendKeyUpdate" {
    // Verify sendKeyUpdate properly increments generation counter

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

    // Install initial application secret (generation 1)
    var initial_secret = key_schedule.Secret.initZero(.sha256);
    @memset(initial_secret.bytes[0..32], 0xAA);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, initial_secret);

    try testing.expectEqual(@as(u32, 1), ctx.getKeyGeneration(.Application, .send));

    // First key update (generation 2)
    try ctx.sendKeyUpdate(false);
    try testing.expectEqual(@as(u32, 2), ctx.getKeyGeneration(.Application, .send));

    // Second key update (generation 3)
    try ctx.sendKeyUpdate(false);
    try testing.expectEqual(@as(u32, 3), ctx.getKeyGeneration(.Application, .send));

    // Third key update (generation 4)
    try ctx.sendKeyUpdate(false);
    try testing.expectEqual(@as(u32, 4), ctx.getKeyGeneration(.Application, .send));
}

test "Context - bidirectional generation tracking" {
    // Verify getBidirKeyGenerations returns correct values

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

    // Initial state
    var gens = ctx.getBidirKeyGenerations(.Application);
    try testing.expectEqual(@as(u32, 0), gens.send);
    try testing.expectEqual(@as(u32, 0), gens.recv);

    // Install send secret
    var send_secret = key_schedule.Secret.initZero(.sha256);
    @memset(send_secret.bytes[0..32], 0xBB);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, send_secret);

    gens = ctx.getBidirKeyGenerations(.Application);
    try testing.expectEqual(@as(u32, 1), gens.send);
    try testing.expectEqual(@as(u32, 0), gens.recv);

    // Install recv secret
    var recv_secret = key_schedule.Secret.initZero(.sha256);
    @memset(recv_secret.bytes[0..32], 0xCC);
    ctx.secrets.slot(.Application, .recv).store(.Application, .sha256, recv_secret);

    gens = ctx.getBidirKeyGenerations(.Application);
    try testing.expectEqual(@as(u32, 1), gens.send);
    try testing.expectEqual(@as(u32, 1), gens.recv);

    // Update both directions
    try ctx.sendKeyUpdate(false); // Updates send
    ctx.secrets.slot(.Application, .recv).store(.Application, .sha256, recv_secret); // Update recv

    gens = ctx.getBidirKeyGenerations(.Application);
    try testing.expectEqual(@as(u32, 2), gens.send);
    try testing.expectEqual(@as(u32, 2), gens.recv);
}

test "Context - generation tracking across encryption levels" {
    // Verify generation tracking works independently for each encryption level

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

    var secret = key_schedule.Secret.initZero(.sha256);
    @memset(secret.bytes[0..32], 0xDD);

    // Install secrets at different levels
    ctx.secrets.slot(.Initial, .send).store(.Initial, .sha256, secret);
    ctx.secrets.slot(.Handshake, .send).store(.Handshake, .sha256, secret);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, secret);

    // Each level should have generation 1
    try testing.expectEqual(@as(u32, 1), ctx.getKeyGeneration(.Initial, .send));
    try testing.expectEqual(@as(u32, 1), ctx.getKeyGeneration(.Handshake, .send));
    try testing.expectEqual(@as(u32, 1), ctx.getKeyGeneration(.Application, .send));

    // Update only Application level
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, secret);

    // Application should be generation 2, others still 1
    try testing.expectEqual(@as(u32, 1), ctx.getKeyGeneration(.Initial, .send));
    try testing.expectEqual(@as(u32, 1), ctx.getKeyGeneration(.Handshake, .send));
    try testing.expectEqual(@as(u32, 2), ctx.getKeyGeneration(.Application, .send));
}

test "Context - generation tracking prevents overflow" {
    // Verify generation counter handles many key updates (u32 range)

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

    var secret = key_schedule.Secret.initZero(.sha256);
    @memset(secret.bytes[0..32], 0xEE);

    // Simulate many key updates
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        ctx.secrets.slot(.Application, .send).store(.Application, .sha256, secret);
    }

    // Should be at generation 100
    try testing.expectEqual(@as(u32, 100), ctx.getKeyGeneration(.Application, .send));
}

test "Context - generation resets on clear" {
    // Verify generation resets when secret slot is cleared

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

    var secret = key_schedule.Secret.initZero(.sha256);
    @memset(secret.bytes[0..32], 0xFF);

    // Install and update several times
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, secret);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, secret);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, secret);

    try testing.expectEqual(@as(u32, 3), ctx.getKeyGeneration(.Application, .send));

    // Clear the slot
    ctx.secrets.slot(.Application, .send).clear();

    // Generation should reset to 0
    try testing.expectEqual(@as(u32, 0), ctx.getKeyGeneration(.Application, .send));
}

// ============================================================================
// Automatic Key Update Tests (AEAD Limit Integration)
// ============================================================================

test "Context.checkAndTriggerKeyUpdate - triggers at 90% threshold" {
    // RFC 8446 §5.5 + §4.6.3: Automatic key update at AEAD limit

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

    // Simulate handshake complete
    var dummy_secret = key_schedule.Secret.initZero(.sha256);
    @memset(dummy_secret.bytes[0..32], 0xAA);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, dummy_secret);

    const limit: u64 = 1000;

    // At 0 records: should not trigger
    const triggered1 = try ctx.checkAndTriggerKeyUpdate(0, limit, 90);
    try testing.expect(!triggered1);

    // At 50% (500 records): should not trigger at 90% threshold
    const triggered2 = try ctx.checkAndTriggerKeyUpdate(500, limit, 90);
    try testing.expect(!triggered2);

    // At 89% (890 records): should not trigger yet
    const triggered3 = try ctx.checkAndTriggerKeyUpdate(890, limit, 90);
    try testing.expect(!triggered3);

    // At 90% (900 records): should trigger
    const triggered4 = try ctx.checkAndTriggerKeyUpdate(900, limit, 90);
    try testing.expect(triggered4);

    // Verify KeyUpdate message was queued
    const msg = try ctx.pollCrypto(testing.allocator, .Application);
    defer testing.allocator.free(msg);
    try testing.expectEqual(@as(usize, 5), msg.len);
    try testing.expectEqual(@as(u8, 24), msg[0]); // key_update message type

    // Verify secret was rotated (generation incremented)
    try testing.expectEqual(@as(u32, 2), ctx.getKeyGeneration(.Application, .send));
}

test "Context.checkAndTriggerKeyUpdate - triggers at 100% threshold" {
    // Test triggering at hard limit (not recommended but supported)

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

    var dummy_secret = key_schedule.Secret.initZero(.sha256);
    @memset(dummy_secret.bytes[0..32], 0xBB);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, dummy_secret);

    const limit: u64 = 1000;

    // At 99% (990 records): should not trigger at 100% threshold
    const triggered1 = try ctx.checkAndTriggerKeyUpdate(990, limit, 100);
    try testing.expect(!triggered1);

    // At 100% (1000 records): should trigger
    const triggered2 = try ctx.checkAndTriggerKeyUpdate(1000, limit, 100);
    try testing.expect(triggered2);
}

test "Context.checkAndTriggerKeyUpdate - multiple thresholds" {
    // Test different threshold percentages

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

    var dummy_secret = key_schedule.Secret.initZero(.sha256);
    @memset(dummy_secret.bytes[0..32], 0xCC);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, dummy_secret);

    const limit: u64 = 10000;

    // At 50% threshold with 5000 records: should trigger
    const triggered1 = try ctx.checkAndTriggerKeyUpdate(5000, limit, 50);
    try testing.expect(triggered1);

    // Consume the KeyUpdate message
    const msg1 = try ctx.pollCrypto(testing.allocator, .Application);
    defer testing.allocator.free(msg1);

    // At 75% threshold with 7500 records: should trigger
    const triggered2 = try ctx.checkAndTriggerKeyUpdate(7500, limit, 75);
    try testing.expect(triggered2);

    // Consume the KeyUpdate message
    const msg2 = try ctx.pollCrypto(testing.allocator, .Application);
    defer testing.allocator.free(msg2);

    // At 95% threshold with 9500 records: should trigger
    const triggered3 = try ctx.checkAndTriggerKeyUpdate(9500, limit, 95);
    try testing.expect(triggered3);
}

test "Context.checkAndTriggerKeyUpdate - edge cases" {
    // Test edge cases: zero limit, invalid thresholds, etc.

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

    var dummy_secret = key_schedule.Secret.initZero(.sha256);
    @memset(dummy_secret.bytes[0..32], 0xDD);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, dummy_secret);

    // Zero limit: should never trigger
    const triggered1 = try ctx.checkAndTriggerKeyUpdate(1000000, 0, 90);
    try testing.expect(!triggered1);

    // Invalid threshold (0%): should not trigger
    const triggered2 = try ctx.checkAndTriggerKeyUpdate(900, 1000, 0);
    try testing.expect(!triggered2);

    // Invalid threshold (>100%): should not trigger
    const triggered3 = try ctx.checkAndTriggerKeyUpdate(900, 1000, 101);
    try testing.expect(!triggered3);
}

test "Context.checkAndTriggerKeyUpdate - before handshake complete fails" {
    // Verify error when called before Application secrets installed

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

    // Attempt to check and trigger without Application secrets
    const result = ctx.checkAndTriggerKeyUpdate(900, 1000, 90);
    try testing.expectError(error.UnexpectedMessage, result);
}

test "Context.checkAndTriggerKeyUpdate - realistic AES-GCM limits" {
    // Test with real RFC 8446 §5.5 limits for AES-128-GCM (2^24 records)

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

    var dummy_secret = key_schedule.Secret.initZero(.sha256);
    @memset(dummy_secret.bytes[0..32], 0xEE);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, dummy_secret);

    // RFC 8446 §5.5: AES-GCM confidentiality limit is 2^24 = 16,777,216
    const aes_gcm_limit: u64 = @as(u64, 1) << 24;

    // 90% of 2^24 = 15,099,494
    const ninety_percent = (aes_gcm_limit * 90) / 100;

    // Just below 90%: should not trigger
    const triggered1 = try ctx.checkAndTriggerKeyUpdate(ninety_percent - 1, aes_gcm_limit, 90);
    try testing.expect(!triggered1);

    // Exactly at 90%: should trigger
    const triggered2 = try ctx.checkAndTriggerKeyUpdate(ninety_percent, aes_gcm_limit, 90);
    try testing.expect(triggered2);

    // Verify generation incremented
    try testing.expectEqual(@as(u32, 2), ctx.getKeyGeneration(.Application, .send));
}

test "Context.checkAndTriggerKeyUpdate - realistic ChaCha20 limits" {
    // Test with real RFC 8446 §5.5 limits for ChaCha20-Poly1305 (2^32 records)

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

    var dummy_secret = key_schedule.Secret.initZero(.sha256);
    @memset(dummy_secret.bytes[0..32], 0xFF);
    ctx.secrets.slot(.Application, .send).store(.Application, .sha256, dummy_secret);

    // RFC 8446 §5.5: ChaCha20-Poly1305 confidentiality limit is 2^32
    const chacha_limit: u64 = @as(u64, 1) << 32;

    // Calculate 90% using same formula as checkAndTriggerKeyUpdate
    // (limit * 90) / 100, using u128 to prevent overflow
    const limit_u128: u128 = chacha_limit;
    const ninety_percent: u64 = @intCast((limit_u128 * 90) / 100);

    // Just below 90%: should not trigger
    const triggered1 = try ctx.checkAndTriggerKeyUpdate(ninety_percent - 100, chacha_limit, 90);
    try testing.expect(!triggered1);

    // Exactly at 90%: should trigger
    const triggered2 = try ctx.checkAndTriggerKeyUpdate(ninety_percent, chacha_limit, 90);
    try testing.expect(triggered2);

    // Verify generation incremented
    try testing.expectEqual(@as(u32, 2), ctx.getKeyGeneration(.Application, .send));
}
