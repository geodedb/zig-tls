// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Cookie Extension (RFC 8446 §4.2.2)
//!
//! The cookie extension is used by servers in HelloRetryRequest to enable
//! stateless operation and protect against DoS attacks. The cookie contains
//! state needed to recreate the handshake context when the client retries.
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.2.2: Cookie Extension
//! - RFC 8446 §4.1.4: HelloRetryRequest
//!
//! ## Message Flow
//!
//! ```
//! Client                                           Server
//!   ClientHello1          -------->
//!                                    (No matching key_share group)
//!                         <--------  HelloRetryRequest
//!                                      + cookie
//!                                      + selected_group
//!   ClientHello2          -------->
//!     + cookie (echoed)
//!     + key_share (new group)
//!                         <--------  ServerHello
//!                                    (Handshake continues)
//! ```
//!
//! ## Security Considerations
//!
//! ### DoS Protection (RFC 8446 §4.2.2)
//!
//! The cookie allows the server to be stateless:
//! - Server doesn't store ClientHello1 state
//! - Cookie contains encrypted/HMACed state
//! - Client must echo cookie in ClientHello2
//! - Server verifies cookie and recreates state
//!
//! This prevents memory exhaustion attacks where an attacker sends many
//! ClientHello messages with unsupported groups, forcing the server to
//! allocate memory for each connection.
//!
//! ### Cookie Structure (Implementation-Defined)
//!
//! RFC 8446 does not specify cookie structure. Common approaches:
//!
//! 1. **HMAC-based**: `HMAC(secret_key, ClientHello1_hash || timestamp)`
//! 2. **Encrypted state**: `AES-GCM(secret_key, state, timestamp)`
//! 3. **Signed token**: `state || signature`
//!
//! This implementation uses approach (1) for simplicity and performance.
//!
//! ### Replay Protection
//!
//! Cookies should include:
//! - Timestamp: Reject stale cookies (e.g., >10 seconds old)
//! - Client random: Bind cookie to specific client
//! - Transcript hash: Prevent cookie reuse across handshakes
//!
//! ## Wire Format (RFC 8446 §4.2.2)
//!
//! ```
//! struct {
//!     opaque cookie<1..2^16-1>;
//! } Cookie;
//! ```
//!
//! Extension format:
//! ```
//! ExtensionType extension_type = cookie(44);
//! uint16 length;
//! opaque cookie<1..2^16-1>;
//! ```

const std = @import("std");

/// Zig 0.16 compat: milliTimestamp() was removed; use Io clock.
fn milliTimestamp() i64 {
    const ts = std.Io.Timestamp.now(std.Io.Threaded.global_single_threaded.io(), .real);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}

/// Maximum cookie size (64 KB - 1 per RFC wire format)
pub const MAX_COOKIE_SIZE: usize = 65535;

/// Recommended cookie size for HMAC-based cookies
/// SHA-256 HMAC (32 bytes) + timestamp (8 bytes) = 40 bytes
pub const RECOMMENDED_COOKIE_SIZE: usize = 40;

/// Cookie parsing error
pub const CookieError = error{
    /// Extension data too short to contain length field
    TooShort,
    /// Cookie length exceeds available data
    Truncated,
    /// Cookie is empty (length = 0)
    EmptyCookie,
    /// Cookie exceeds maximum size
    TooLarge,
};

/// Parse the cookie extension data.
///
/// RFC 8446 §4.2.2: Cookie extension contains an opaque cookie value
/// with a 2-byte length prefix.
///
/// ## Parameters
///
/// - `data`: Extension value (NOT including extension type/length header)
///
/// ## Returns
///
/// - Cookie bytes (slice into `data`)
///
/// ## Errors
///
/// - `TooShort`: Data has fewer than 2 bytes
/// - `Truncated`: Declared length exceeds available data
/// - `EmptyCookie`: Cookie length is 0 (invalid per RFC)
/// - `TooLarge`: Cookie exceeds MAX_COOKIE_SIZE
///
/// ## Wire Format
///
/// ```
/// +--------+--------+-------------------+
/// | Length (2 bytes) | Cookie (N bytes) |
/// +--------+--------+-------------------+
/// ```
///
/// ## Usage
///
/// ```zig
/// // Extension value from HelloRetryRequest
/// const ext_data: []const u8 = ...;
/// const cookie = try parseCookie(ext_data);
/// // Echo cookie in ClientHello2
/// const cookie_ext = try encodeCookie(allocator, cookie);
/// ```
pub fn parseCookie(data: []const u8) CookieError![]const u8 {
    // Need at least 2 bytes for length field
    if (data.len < 2) return error.TooShort;

    // Read 2-byte big-endian length
    const len = std.mem.readInt(u16, data[0..2], .big);

    // Check for empty cookie (invalid per RFC)
    if (len == 0) return error.EmptyCookie;

    // Check for oversized cookie
    if (len > MAX_COOKIE_SIZE) return error.TooLarge;

    // Check for truncation
    if (data.len < 2 + len) return error.Truncated;

    // Return cookie bytes (slice into input)
    return data[2 .. 2 + len];
}

/// Encode a cookie into extension wire format.
///
/// RFC 8446 §4.2.2: Prepends 2-byte length to cookie data.
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for the output buffer
/// - `cookie`: Cookie bytes to encode
///
/// ## Returns
///
/// - Encoded extension value: [length:2][cookie:N]
/// - Caller owns returned slice and must free it
///
/// ## Errors
///
/// - `OutOfMemory`: Allocation failed
/// - `EmptyCookie`: Cookie is empty
/// - `TooLarge`: Cookie exceeds MAX_COOKIE_SIZE
///
/// ## Usage
///
/// ```zig
/// const cookie: []const u8 = ...; // e.g., HMAC output
/// const ext_value = try encodeCookie(allocator, cookie);
/// defer allocator.free(ext_value);
/// // Now wrap in extension: writeExtension(alloc, buf, .cookie, ext_value)
/// ```
pub fn encodeCookie(allocator: std.mem.Allocator, cookie: []const u8) ![]u8 {
    // Validate cookie
    if (cookie.len == 0) return error.EmptyCookie;
    if (cookie.len > MAX_COOKIE_SIZE) return error.TooLarge;

    // Allocate buffer: 2 bytes (length) + cookie
    var buf = try allocator.alloc(u8, 2 + cookie.len);

    // Write length (big-endian)
    std.mem.writeInt(u16, buf[0..2], @intCast(cookie.len), .big);

    // Write cookie
    @memcpy(buf[2..], cookie);

    return buf;
}

/// Generate a simple HMAC-based cookie for HelloRetryRequest.
///
/// This is a reference implementation that creates a cookie containing:
/// - HMAC-SHA256(server_secret, client_random || transcript_hash || timestamp)
/// - Timestamp (8 bytes, milliseconds since epoch)
///
/// The cookie binds the HelloRetryRequest to:
/// 1. The specific client (via client_random)
/// 2. The handshake transcript (via transcript_hash)
/// 3. A time window (via timestamp)
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for cookie buffer
/// - `server_secret`: Server's secret key for HMAC (32+ bytes recommended)
/// - `client_random`: Client's random from ClientHello1 (32 bytes)
/// - `transcript_hash`: Hash of ClientHello1 (32 or 48 bytes depending on cipher suite)
///
/// ## Returns
///
/// - Cookie bytes (40 bytes: 32 HMAC + 8 timestamp)
/// - Caller owns and must free
///
/// ## Security Notes
///
/// - `server_secret` must be kept confidential and rotated periodically
/// - Timestamp allows rejecting stale cookies (e.g., >10 seconds old)
/// - HMAC prevents cookie forgery
///
/// ## Usage
///
/// ```zig
/// const cookie = try generateCookie(
///     allocator,
///     server_secret,
///     client_random,
///     transcript_hash,
/// );
/// defer allocator.free(cookie);
///
/// const ext_value = try encodeCookie(allocator, cookie);
/// defer allocator.free(ext_value);
/// ```
pub fn generateCookie(
    allocator: std.mem.Allocator,
    server_secret: []const u8,
    client_random: [32]u8,
    transcript_hash: []const u8,
) ![]u8 {
    // Cookie structure: [HMAC:32][timestamp:8]
    var cookie = try allocator.alloc(u8, 40);
    errdefer allocator.free(cookie);

    // Get current timestamp (milliseconds since UNIX epoch)
    const timestamp = milliTimestamp();
    std.mem.writeInt(i64, cookie[32..40], timestamp, .big);

    // Compute HMAC over: client_random || transcript_hash || timestamp
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(server_secret);
    hmac.update(&client_random);
    hmac.update(transcript_hash);
    hmac.update(cookie[32..40]); // timestamp bytes
    hmac.final(cookie[0..32]);

    return cookie;
}

/// Verify a cookie received in ClientHello2.
///
/// Checks that the cookie:
/// 1. Has valid HMAC (not forged)
/// 2. Is not stale (timestamp within acceptable window)
/// 3. Matches the expected client_random and transcript_hash
///
/// ## Parameters
///
/// - `cookie`: Cookie bytes from ClientHello2
/// - `server_secret`: Server's secret key for HMAC verification
/// - `client_random`: Client's random from ClientHello2 (must match CH1)
/// - `transcript_hash`: Hash of ClientHello1
/// - `max_age_seconds`: Maximum cookie age in seconds (e.g., 10)
///
/// ## Returns
///
/// - `true`: Cookie is valid and fresh
/// - `false`: Cookie is invalid or stale
///
/// ## Security Notes
///
/// - Uses constant-time comparison for HMAC verification
/// - Rejects cookies older than `max_age_seconds`
/// - Returns false (not error) for invalid cookies to prevent timing attacks
///
/// ## Usage
///
/// ```zig
/// const cookie = ...; // from ClientHello2
/// if (!verifyCookie(cookie, server_secret, client_random, transcript_hash, 10)) {
///     return error.InvalidCookie; // Abort handshake
/// }
/// // Cookie valid, proceed with handshake
/// ```
pub fn verifyCookie(
    cookie: []const u8,
    server_secret: []const u8,
    client_random: [32]u8,
    transcript_hash: []const u8,
    max_age_seconds: i64,
) bool {
    // Cookie must be exactly 40 bytes (32 HMAC + 8 timestamp)
    if (cookie.len != 40) return false;

    // Extract timestamp
    const timestamp = std.mem.readInt(i64, cookie[32..40], .big);

    // Check freshness
    const now = milliTimestamp();
    const age_ms = now - timestamp;
    if (age_ms < 0 or age_ms > max_age_seconds * 1000) return false;

    // Recompute HMAC
    var expected_hmac: [32]u8 = undefined;
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(server_secret);
    hmac.update(&client_random);
    hmac.update(transcript_hash);
    hmac.update(cookie[32..40]); // timestamp bytes
    hmac.final(&expected_hmac);

    // Constant-time comparison (critical for security)
    const actual_hmac: *const [32]u8 = cookie[0..32];
    return std.crypto.timing_safe.eql([32]u8, expected_hmac, actual_hmac.*);
}

// ============================================================================
// Unit Tests
// ============================================================================

test "parseCookie - valid cookie" {
    const testing = std.testing;

    // Cookie: length=5, data="hello"
    const data = [_]u8{ 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
    const cookie = try parseCookie(&data);

    try testing.expectEqualSlices(u8, "hello", cookie);
}

test "parseCookie - too short" {
    const testing = std.testing;

    // Only 1 byte (need 2 for length)
    const data = [_]u8{0x00};
    try testing.expectError(error.TooShort, parseCookie(&data));

    // Empty data
    const empty: []const u8 = &.{};
    try testing.expectError(error.TooShort, parseCookie(empty));
}

test "parseCookie - truncated" {
    const testing = std.testing;

    // Length says 10 bytes, but only 5 provided
    const data = [_]u8{ 0x00, 0x0A, 'h', 'e', 'l', 'l', 'o' };
    try testing.expectError(error.Truncated, parseCookie(&data));
}

test "parseCookie - empty cookie" {
    const testing = std.testing;

    // Length = 0 (invalid per RFC)
    const data = [_]u8{ 0x00, 0x00 };
    try testing.expectError(error.EmptyCookie, parseCookie(&data));
}

test "encodeCookie - valid cookie" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const cookie = "test_cookie_data";
    const encoded = try encodeCookie(allocator, cookie);
    defer allocator.free(encoded);

    // Check length prefix
    const len = std.mem.readInt(u16, encoded[0..2], .big);
    try testing.expectEqual(cookie.len, len);

    // Check cookie data
    try testing.expectEqualSlices(u8, cookie, encoded[2..]);
}

test "encodeCookie - empty cookie error" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const empty: []const u8 = &.{};
    try testing.expectError(error.EmptyCookie, encodeCookie(allocator, empty));
}

test "encodeCookie - roundtrip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const original = "roundtrip_test";
    const encoded = try encodeCookie(allocator, original);
    defer allocator.free(encoded);

    const decoded = try parseCookie(encoded);
    try testing.expectEqualSlices(u8, original, decoded);
}

test "generateCookie and verifyCookie - valid flow" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const server_secret = "super_secret_key_32_bytes_long!";
    var client_random: [32]u8 = undefined;
    std.testing.io.random(&client_random);
    var transcript_hash: [32]u8 = undefined;
    std.testing.io.random(&transcript_hash);

    // Generate cookie
    const cookie = try generateCookie(allocator, server_secret, client_random, &transcript_hash);
    defer allocator.free(cookie);

    try testing.expectEqual(40, cookie.len);

    // Verify cookie (should succeed)
    const valid = verifyCookie(cookie, server_secret, client_random, &transcript_hash, 10);
    try testing.expect(valid);
}

test "verifyCookie - invalid HMAC" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const server_secret = "super_secret_key_32_bytes_long!";
    var client_random: [32]u8 = undefined;
    std.testing.io.random(&client_random);
    var transcript_hash: [32]u8 = undefined;
    std.testing.io.random(&transcript_hash);

    // Generate cookie
    const cookie = try generateCookie(allocator, server_secret, client_random, &transcript_hash);
    defer allocator.free(cookie);

    // Corrupt HMAC
    cookie[0] ^= 0x01;

    // Verify should fail
    const valid = verifyCookie(cookie, server_secret, client_random, &transcript_hash, 10);
    try testing.expect(!valid);
}

test "verifyCookie - wrong client random" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const server_secret = "super_secret_key_32_bytes_long!";
    var client_random1: [32]u8 = undefined;
    var client_random2: [32]u8 = undefined;
    std.testing.io.random(&client_random1);
    std.testing.io.random(&client_random2);
    var transcript_hash: [32]u8 = undefined;
    std.testing.io.random(&transcript_hash);

    // Generate cookie with client_random1
    const cookie = try generateCookie(allocator, server_secret, client_random1, &transcript_hash);
    defer allocator.free(cookie);

    // Verify with different client_random2 (should fail)
    const valid = verifyCookie(cookie, server_secret, client_random2, &transcript_hash, 10);
    try testing.expect(!valid);
}

test "verifyCookie - wrong secret" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const server_secret1 = "super_secret_key_32_bytes_long!";
    const server_secret2 = "different_secret_key_32_bytes!!";
    var client_random: [32]u8 = undefined;
    std.testing.io.random(&client_random);
    var transcript_hash: [32]u8 = undefined;
    std.testing.io.random(&transcript_hash);

    // Generate cookie with secret1
    const cookie = try generateCookie(allocator, server_secret1, client_random, &transcript_hash);
    defer allocator.free(cookie);

    // Verify with secret2 (should fail)
    const valid = verifyCookie(cookie, server_secret2, client_random, &transcript_hash, 10);
    try testing.expect(!valid);
}

test "verifyCookie - invalid size" {
    const testing = std.testing;

    const server_secret = "super_secret_key_32_bytes_long!";
    var client_random: [32]u8 = undefined;
    std.testing.io.random(&client_random);
    var transcript_hash: [32]u8 = undefined;
    std.testing.io.random(&transcript_hash);

    // Cookie must be exactly 40 bytes
    const short_cookie = [_]u8{0} ** 39;
    const long_cookie = [_]u8{0} ** 41;

    try testing.expect(!verifyCookie(&short_cookie, server_secret, client_random, &transcript_hash, 10));
    try testing.expect(!verifyCookie(&long_cookie, server_secret, client_random, &transcript_hash, 10));
}
