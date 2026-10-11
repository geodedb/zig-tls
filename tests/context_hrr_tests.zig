//! QUAL-099: HelloRetryRequest (HRR) Context-Level Tests
//!
//! Tests for the TLS 1.3 HelloRetryRequest mechanism at the Context layer,
//! verifying client-side HRR handling: state reset, key material secure
//! zeroing, and second ClientHello correctness.
//!
//! Test approach: build a synthetic HRR ServerHello via tls13_full helpers
//! and feed it to a client Context via processCrypto.  The parser in
//! handshake_state.zig rejects non-x25519 ClientHellos before the server
//! flight builder, so server-side HRR triggering is validated by
//! constructing the HRR message directly.
//!
//! RFC 8446 section 4.1.4.

const std = @import("std");
const testing = std.testing;
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");

// ============================================================================
// Helpers
// ============================================================================

/// Find the key_share extension (type 0x0033) inside a framed ClientHello
/// message and return the offset of the 2-byte NamedGroup within the first
/// KeyShareEntry.  The message starts with the 4-byte handshake header.
fn findKeyShareGroupOffset(msg: []const u8) ?usize {
    if (msg.len < 4) return null;
    const body = msg[4..];

    if (body.len < 35) return null;
    var pos: usize = 2 + 32;
    const sid_len: usize = body[pos];
    pos += 1 + sid_len;
    if (pos + 2 > body.len) return null;

    const cs_len: usize = @as(usize, body[pos]) << 8 | body[pos + 1];
    pos += 2 + cs_len;
    if (pos + 1 > body.len) return null;

    const comp_len: usize = body[pos];
    pos += 1 + comp_len;
    if (pos + 2 > body.len) return null;

    const exts_len: usize = @as(usize, body[pos]) << 8 | body[pos + 1];
    pos += 2;
    const exts_end = pos + exts_len;
    if (exts_end > body.len) return null;

    while (pos + 4 <= exts_end) {
        const etype: u16 = @as(u16, body[pos]) << 8 | body[pos + 1];
        const elen: usize = @as(usize, body[pos + 2]) << 8 | body[pos + 3];
        pos += 4;
        if (pos + elen > exts_end) return null;

        if (etype == 0x0033) {
            if (elen < 6) return null;
            return 4 + pos + 2; // absolute offset of group in msg
        }
        pos += elen;
    }
    return null;
}

/// Create a client context with standard test configuration.
fn makeClientCtx() !tls13.Context {
    // This helper configures a standalone-X25519 client. Standalone X25519 is
    // not a FIPS-approved key-agreement, so under -Dfips=true the handshake
    // fails closed; these X25519-config tests skip in that mode.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    return tls13.Context.init(.{
        .allocator = testing.allocator,
        .role = .Client,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    }, .{});
}

/// Build a framed (4-byte header + body) HRR ServerHello message requesting
/// the given group, suitable for feeding to client_ctx.processCrypto().
fn buildFramedHrr(group: ?tls13_full.NamedGroup, cookie: []const u8) ![]u8 {
    const hrr_body = try tls13_full.buildHelloRetryRequest(
        testing.allocator,
        group orelse .x25519,
        cookie,
        null, // no session_id echo
    );
    defer testing.allocator.free(hrr_body);

    var body_len = hrr_body.len;
    if (group == null) {
        // RFC 8446 §4.2.8 forbids selecting a share already present in CH1.
        // A cookie-only retry has no key_share extension and retains the key.
        const ext_offset: usize = 38; // empty session id
        var pos: usize = ext_offset + 2;
        while (pos < body_len) {
            const kind = std.mem.readInt(u16, hrr_body[pos..][0..2], .big);
            const len = std.mem.readInt(u16, hrr_body[pos + 2 ..][0..2], .big);
            if (kind == 0x33) {
                std.mem.copyForwards(u8, hrr_body[pos..], hrr_body[pos + 4 + len ..]);
                body_len -= 4 + len;
                std.mem.writeInt(u16, hrr_body[ext_offset..][0..2], @intCast(body_len - ext_offset - 2), .big);
                break;
            }
            pos += 4 + len;
        }
    }
    const framed = try tls13.encodeHandshake(testing.allocator, .server_hello, hrr_body[0..body_len]);
    return framed;
}

// ============================================================================
// Test 1: Client state reset after HRR
// ============================================================================

test "QUAL-099: cookie-only HRR retains the original key pair" {
    var client_ctx = try makeClientCtx();
    defer client_ctx.deinit();
    try client_ctx.startClientHandshake();

    // Capture original keys
    const original_priv = client_ctx.client_priv orelse return error.TestSetupFailed;
    const original_pub = client_ctx.client_pub orelse return error.TestSetupFailed;

    // Drain the outbound CH so the client doesn't try to read it as inbound
    const ch_msg = try client_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(ch_msg);

    // Build synthetic cookie-only HRR
    const hrr_msg = try buildFramedHrr(null, "test-cookie");
    defer testing.allocator.free(hrr_msg);

    // Feed HRR to client
    try client_ctx.processCrypto(.Initial, hrr_msg);

    // After HRR processing:
    // 1. hrr_received flag should be set
    try testing.expect(client_ctx.hrr_received);

    // 2. Cookie-only retries must retain the original key pair.
    const new_priv = client_ctx.client_priv orelse return error.TestSetupFailed;
    const new_pub = client_ctx.client_pub orelse return error.TestSetupFailed;

    try testing.expect(std.mem.eql(u8, &original_priv, &new_priv));
    try testing.expect(std.mem.eql(u8, &original_pub, &new_pub));

    // 3. client_random preserved (RFC 8446 section 4.1.4)
    try testing.expect(client_ctx.client_random != null);
}

// ============================================================================
// Test 2: SecureZero on key material during HRR reset
// ============================================================================

test "QUAL-099: retained key pair remains valid after cookie-only HRR" {
    // Verify that the retained key pair is consistent after the retry.
    var client_ctx = try makeClientCtx();
    defer client_ctx.deinit();
    try client_ctx.startClientHandshake();

    const ch_msg = try client_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(ch_msg);

    const hrr_msg = try buildFramedHrr(null, "test-cookie");
    defer testing.allocator.free(hrr_msg);

    try client_ctx.processCrypto(.Initial, hrr_msg);

    const new_priv = client_ctx.client_priv orelse return error.TestSetupFailed;
    const new_pub = client_ctx.client_pub orelse return error.TestSetupFailed;

    // Verify stored public key matches what we'd derive from the private key
    // after applying RFC 7748 section 5 clamping (as sendClientHello2 does).
    var clamped_priv = new_priv;
    clamped_priv[0] &= 248;
    clamped_priv[31] &= 127;
    clamped_priv[31] |= 64;
    const derived_pub = std.crypto.dh.X25519.recoverPublicKey(clamped_priv) catch {
        return error.TestSetupFailed;
    };
    try testing.expectEqualSlices(u8, &derived_pub, &new_pub);
}

// ============================================================================
// Test 3: Second ClientHello includes correct key share
// ============================================================================

test "QUAL-099: second ClientHello contains x25519 key share" {
    var client_ctx = try makeClientCtx();
    defer client_ctx.deinit();
    try client_ctx.startClientHandshake();

    // Drain first ClientHello
    const ch1_msg = try client_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(ch1_msg);

    // Send HRR
    const hrr_msg = try buildFramedHrr(null, "test-cookie");
    defer testing.allocator.free(hrr_msg);
    try client_ctx.processCrypto(.Initial, hrr_msg);

    // Drain the second ClientHello
    const ch2_msg = try client_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(ch2_msg);

    // Verify CH2 has x25519 key share (0x001d)
    const ch2_group_offset = findKeyShareGroupOffset(ch2_msg) orelse {
        return error.TestSetupFailed;
    };
    try testing.expectEqual(@as(u8, 0x00), ch2_msg[ch2_group_offset]);
    try testing.expectEqual(@as(u8, 0x1d), ch2_msg[ch2_group_offset + 1]);

    // Verify the public key in CH2 matches context's client_pub
    const key_data_offset = ch2_group_offset + 4; // group(2) + key_len(2)
    if (key_data_offset + 32 <= ch2_msg.len) {
        const pub_in_msg = ch2_msg[key_data_offset..][0..32];
        const client_pub = client_ctx.client_pub orelse return error.TestSetupFailed;
        try testing.expectEqualSlices(u8, &client_pub, pub_in_msg);
    }
}

// ============================================================================
// Test 4: Client rejects second HRR
// ============================================================================

test "QUAL-099: client rejects second HRR (RFC 8446 section 4.1.4)" {
    var client_ctx = try makeClientCtx();
    defer client_ctx.deinit();
    try client_ctx.startClientHandshake();

    const ch_msg = try client_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(ch_msg);

    const hrr_msg = try buildFramedHrr(null, "test-cookie");
    defer testing.allocator.free(hrr_msg);

    // First HRR should succeed
    try client_ctx.processCrypto(.Initial, hrr_msg);
    try testing.expect(client_ctx.hrr_received);

    // Drain CH2 to clear outbound
    const ch2_msg = try client_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(ch2_msg);

    // Second HRR should fail with UnexpectedMessage
    try testing.expectError(
        tls13.HandshakeError.UnexpectedMessage,
        client_ctx.processCrypto(.Initial, hrr_msg),
    );
}

// ============================================================================
// Test 5: CH2 preserves client_random from CH1
// ============================================================================

test "QUAL-099: CH2 uses same random as CH1 (RFC 8446 section 4.1.4)" {
    var client_ctx = try makeClientCtx();
    defer client_ctx.deinit();
    try client_ctx.startClientHandshake();

    // Get CH1 and extract random
    const ch1_msg = try client_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(ch1_msg);

    // CH1 random is at offset 4 (header) + 2 (legacy_version) = 6
    if (ch1_msg.len < 38) return error.TestSetupFailed;
    var ch1_random: [32]u8 = undefined;
    @memcpy(&ch1_random, ch1_msg[6..38]);

    const hrr_msg = try buildFramedHrr(null, "test-cookie");
    defer testing.allocator.free(hrr_msg);
    try client_ctx.processCrypto(.Initial, hrr_msg);

    // Get CH2 and extract random
    const ch2_msg = try client_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(ch2_msg);

    if (ch2_msg.len < 38) return error.TestSetupFailed;
    const ch2_random = ch2_msg[6..38];

    // RFC 8446 section 4.1.4: MUST use same random
    try testing.expectEqualSlices(u8, &ch1_random, ch2_random);
}

// ============================================================================
// Test 6: CH2 includes cookie from HRR
// ============================================================================

test "QUAL-099: CH2 includes cookie extension from HRR" {
    var client_ctx = try makeClientCtx();
    defer client_ctx.deinit();
    try client_ctx.startClientHandshake();

    const ch1_msg = try client_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(ch1_msg);

    const test_cookie = "hrr-test-cookie-value";
    const hrr_msg = try buildFramedHrr(null, test_cookie);
    defer testing.allocator.free(hrr_msg);
    try client_ctx.processCrypto(.Initial, hrr_msg);

    const ch2_msg = try client_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(ch2_msg);

    // Search for cookie extension (type 0x002c) in CH2
    const body = ch2_msg[4..]; // skip handshake header
    if (body.len < 35) return error.TestSetupFailed;
    var pos: usize = 2 + 32; // skip version + random
    const sid_len: usize = body[pos];
    pos += 1 + sid_len;
    if (pos + 2 > body.len) return error.TestSetupFailed;
    const cs_len: usize = @as(usize, body[pos]) << 8 | body[pos + 1];
    pos += 2 + cs_len;
    if (pos + 1 > body.len) return error.TestSetupFailed;
    const comp_len: usize = body[pos];
    pos += 1 + comp_len;
    if (pos + 2 > body.len) return error.TestSetupFailed;
    const exts_len: usize = @as(usize, body[pos]) << 8 | body[pos + 1];
    pos += 2;
    const exts_end = pos + exts_len;
    if (exts_end > body.len) return error.TestSetupFailed;

    var found_cookie = false;
    while (pos + 4 <= exts_end) {
        const etype: u16 = @as(u16, body[pos]) << 8 | body[pos + 1];
        const elen: usize = @as(usize, body[pos + 2]) << 8 | body[pos + 3];
        pos += 4;
        if (pos + elen > exts_end) break;

        if (etype == 0x002c) {
            // Cookie extension found
            found_cookie = true;
            // The cookie data in HRR is wrapped in a 2-byte length prefix
            // inside the extension. But sendClientHello2 writes the raw
            // cookie bytes from the HRR cookie extension directly.
            // The HRR cookie extension body has: len(2) + cookie_data.
            // Verify the cookie data contains our test cookie.
            if (elen >= test_cookie.len) {
                // Check if the extension data contains our cookie
                const ext_data = body[pos .. pos + elen];
                var found_in_ext = false;
                if (ext_data.len >= test_cookie.len) {
                    var i: usize = 0;
                    while (i + test_cookie.len <= ext_data.len) : (i += 1) {
                        if (std.mem.eql(u8, ext_data[i..][0..test_cookie.len], test_cookie)) {
                            found_in_ext = true;
                            break;
                        }
                    }
                }
                try testing.expect(found_in_ext);
            }
        }
        pos += elen;
    }

    try testing.expect(found_cookie);
}

// ============================================================================
// Test 7: HRR is a ServerHello with special random
// ============================================================================

test "QUAL-099: HRR message has special random value" {
    // Verify that buildHelloRetryRequest produces a ServerHello with the
    // HRR special random (SHA-256("HelloRetryRequest")).
    const hrr_body = try tls13_full.buildHelloRetryRequest(
        testing.allocator,
        .x25519,
        "test-cookie",
        null,
    );
    defer testing.allocator.free(hrr_body);

    // Body layout: legacy_version(2) + random(32) + ...
    try testing.expect(hrr_body.len >= 34);

    // Extract random and verify it's the HRR sentinel
    try testing.expect(tls13_full.isHelloRetryRequest(hrr_body[2..34].*));
}

// RFC 8446 §4.2.8 requires rejection even when an HRR also has a cookie.
test "SONNY-4794 HRR cannot request an already offered classical share" {
    var client = try makeClientCtx();
    defer client.deinit();
    try client.startClientHandshake();
    const msg = try buildFramedHrr(.x25519, "cookie");
    defer testing.allocator.free(msg);
    try testing.expectError(error.HrrNoChange, client.processCrypto(.Initial, msg));
    try testing.expect(client.client_priv == null);
    try testing.expectEqual(tls13.HandshakePhase.terminated, client.phase);
}
