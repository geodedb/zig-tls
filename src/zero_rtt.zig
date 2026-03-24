// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! 0-RTT data and anti-replay protection (RFC 8446 §8, RFC 9001 §4.6).
//!
//! This module implements 0-RTT (Zero Round-Trip Time) resumption support for
//! TLS 1.3 over QUIC. 0-RTT allows clients to send encrypted application data
//! in the first flight, reducing connection establishment latency from 1-RTT to 0-RTT.
//!
//! ## Overview
//!
//! 0-RTT is enabled when a client possesses a valid session ticket from a previous
//! connection. The client can immediately send early data encrypted with keys derived
//! from the Pre-Shared Key (PSK) associated with the ticket.
//!
//! ## Key Challenges
//!
//! ### Replay Attacks (RFC 8446 §8.1)
//!
//! Unlike regular TLS handshakes, 0-RTT data is **not replay-protected** by the protocol.
//! An attacker can capture and replay a ClientHello with 0-RTT data to the server.
//! This module provides mechanisms to detect and prevent such replays.
//!
//! ### Ticket Management (RFC 8446 §8.2)
//!
//! Session tickets must be carefully managed to prevent replay attacks:
//! - Single-use tickets: Each ticket can only be used once
//! - Time-based windows: Tickets expire after a configured lifetime
//! - Anti-replay cache: Recently seen ClientHello randoms are tracked
//!
//! ## RFC Coverage
//!
//! ### TLS 1.3 (RFC 8446)
//! - §8: 0-RTT Data
//! - §8.1: Anti-Replay mechanisms (client random tracking, time windows)
//! - §8.2: Client Hello Recording (single-use tickets)
//! - §8.3: 0-RTT and Anti-Replay security considerations
//! - §4.2.10: Early Data Indication extension
//! - §4.6.1: NewSessionTicket message
//!
//! ### QUIC-TLS (RFC 9001)
//! - §4.6: Using Early Data with QUIC
//! - §4.6.1: Enabling 0-RTT
//! - §4.6.2: Accepting and Rejecting 0-RTT
//! - §5.2: Early Data protection (0-RTT packet encryption)
//!
//! ## Security Considerations (RFC 8446 §8.3)
//!
//! ### Replay Risks
//!
//! - 0-RTT data can be replayed by network attackers
//! - Applications MUST ensure 0-RTT data is idempotent (safe to replay)
//! - Non-idempotent operations (POST, DELETE, etc.) MUST NOT use 0-RTT
//! - Recommended for read-only operations (GET requests)
//!
//! ### Anti-Replay Strategies
//!
//! 1. **Single-use tickets**: Server invalidates ticket after first use
//! 2. **Client random tracking**: Server remembers recent ClientHello randoms
//! 3. **Time windows**: Reject 0-RTT outside of allowed time window
//! 4. **Freshness checks**: Verify obfuscated_ticket_age is recent
//!
//! ### Implementation Trade-offs
//!
//! - **Strict replay prevention**: Requires distributed state (cache)
//! - **Relaxed mode**: Accept replay risk for specific applications
//! - **QUIC advantage**: QUIC's connection migration can mitigate some replay risks
//!
//! ## Data Flow
//!
//! ```
//! Client                                           Server
//!
//! (Possess valid PSK from previous session)
//!
//! ClientHello
//!   + early_data extension
//!   + pre_shared_key extension
//! (0-RTT Application Data)          -------->
//!                                                  Anti-Replay Check:
//!                                                  - Check client random
//!                                                  - Verify ticket freshness
//!                                                  - Validate PSK binder
//!                                   <--------  ServerHello
//!                                   <--------  EncryptedExtensions
//!                                                + early_data (accept/reject)
//!                                   <--------  Finished
//!                                   -------->  Finished
//!
//! (If accepted: 0-RTT data processed)
//! (If rejected: 0-RTT data discarded, client retransmits in 1-RTT)
//! ```
//!
//! ## Implementation Notes
//!
//! - Anti-replay window is a simple sliding FIFO (configurable size)
//! - Ticket state tracking is in-memory (not persistent across restarts)
//! - Window size trade-off: larger = better replay detection, more memory
//! - For production: consider distributed cache (Redis, etc.) for multi-server setups
//!
//! ## Limitations
//!
//! - Current implementation: in-memory only (single-server)
//! - No persistence across server restarts
//! - No distributed synchronization for multi-server deployments
//! - Future work: pluggable anti-replay backends (Redis, database, etc.)
const std = @import("std");

/// Session ticket state for 0-RTT replay prevention (RFC 8446 §8.2).
///
/// Tracks the usage state of session tickets issued via NewSessionTicket.
/// Single-use tickets are a critical anti-replay mechanism: each ticket can
/// only be used once to establish a 0-RTT connection.
///
/// ## States
///
/// - **unused**: Ticket has been issued but not yet used for 0-RTT resumption
/// - **used**: Ticket has been used once; subsequent attempts should be rejected
/// - **revoked**: Ticket has been explicitly invalidated (e.g., due to security event)
///
/// ## RFC Compliance
///
/// - RFC 8446 §8.2: ClientHello Recording (single-use ticket enforcement)
/// - RFC 8446 §4.6.1: NewSessionTicket message
///
/// ## Security Critical
///
/// - Tickets MUST transition from `unused` to `used` atomically
/// - Race conditions can allow replay attacks (use proper locking)
/// - Revoked tickets MUST never be accepted for 0-RTT
///
/// ## Implementation Notes
///
/// This enum is used in conjunction with ticket storage (database, cache, etc.)
/// to track which tickets have been consumed. For production systems, ticket
/// state must be synchronized across all servers in a cluster.
pub const TicketState = enum {
    unused, // RFC 8446 §8.2: Ticket issued but not yet used
    used, // RFC 8446 §8.2: Ticket consumed for 0-RTT (prevent replay)
    revoked, // Ticket explicitly invalidated (security event, expiration, etc.)
};

/// Default window size for anti-replay protection.
/// 64 entries is suitable for low-to-moderate traffic scenarios.
pub const default_window_size: usize = 64;

/// Configurable anti-replay window size recommendations.
///
/// ## Sizing Guidelines (RFC 8446 §8.1)
///
/// The window should be sized based on expected 0-RTT connection rate:
/// - **64 entries**: Low traffic (<100 0-RTT connections/sec) - 2KB memory
/// - **256 entries**: Moderate traffic (~500 0-RTT connections/sec) - 8KB memory
/// - **1024 entries**: High traffic (~2000 0-RTT connections/sec) - 32KB memory
/// - **4096 entries**: Very high traffic (~8000 0-RTT connections/sec) - 128KB memory
///
/// For traffic exceeding these levels, consider using a distributed cache
/// (Redis, Memcached) instead of this in-memory window.
///
/// ## Formula
///
/// window_size >= connections_per_second × ticket_lifetime_seconds / safety_factor
/// Example: 500 conn/sec × 0.5 sec window ÷ 2 ≈ 125 → use 256 entries
pub const WindowSizeRecommendations = struct {
    pub const low_traffic: usize = 64;
    pub const moderate_traffic: usize = 256;
    pub const high_traffic: usize = 1024;
    pub const very_high_traffic: usize = 4096;
};

/// Sliding window anti-replay cache for 0-RTT replay detection (RFC 8446 §8.1).
///
/// Implements a simple FIFO-based cache that remembers recently seen ClientHello
/// random values. When a ClientHello with early_data is received, the server checks
/// this window to detect replay attempts.
///
/// ## Algorithm
///
/// 1. When a 0-RTT ClientHello arrives, extract the 32-byte random field
/// 2. Check if the random exists in the anti-replay window
/// 3. If found: REJECT (replay detected)
/// 4. If not found: ADD to window and ACCEPT
///
/// ## Window Behavior
///
/// - **Size**: Configurable via comptime parameter (default: 64 entries)
/// - **Eviction**: FIFO (oldest entry evicted when full)
/// - **Storage**: In-memory array (stack-allocated for small windows)
/// - **Lookup**: Linear scan (O(n), acceptable for windows up to ~1024)
///
/// ## Configuring Window Size
///
/// Use `AntiReplayWindowSized(N)` to create a window with N entries:
/// ```zig
/// // For high-traffic servers (1024 entries)
/// var window = AntiReplayWindowSized(1024).init(allocator);
///
/// // Default size (64 entries)
/// var window = AntiReplayWindow.init(allocator);
/// ```
///
/// See `WindowSizeRecommendations` for sizing guidance.
///
/// ## RFC Compliance
///
/// - RFC 8446 §8.1: Single-Use Tickets (anti-replay window)
/// - RFC 8446 §8.2: ClientHello Recording
///
/// ## Trade-offs
///
/// ### Window Size
/// - **Small window** (e.g., 64): Lower memory, higher replay risk (old randoms forgotten)
/// - **Large window** (e.g., 1024): Higher memory, better replay detection
///
/// ### Implementation
/// - **In-memory**: Fast, but lost on server restart (replay risk across restarts)
/// - **Persistent**: Slower, but survives restarts (better security)
///
/// ## Security Considerations
///
/// - Window must be large enough to cover expected 0-RTT traffic volume
/// - For high-traffic servers, consider distributed cache (Redis, etc.)
/// - Window does NOT persist across server restarts (replay risk)
/// - Combine with ticket freshness checks (obfuscated_ticket_age)
///
/// ## Production Deployment
///
/// For multi-server deployments, this in-memory window is insufficient:
/// - Use distributed cache (Redis, Memcached) shared across all servers
/// - Store (client_random, timestamp) pairs with TTL
/// - Alternative: use stateless time-window approach (RFC 8446 §8.1.3)
///
/// ## Performance
///
/// - Linear scan: O(window_size) per lookup
/// - For window_size=64, this is fast enough (negligible vs crypto ops)
/// - For larger windows (1024+), consider hash table or bloom filter
pub fn AntiReplayWindowSized(comptime size: usize) type {
    return struct {
        const Self = @This();
        pub const window_size = size;

        randoms: [window_size][32]u8 = undefined, // Fixed-size FIFO buffer
        count: usize = 0, // Total randoms added (wraps for FIFO index)
        allocator: std.mem.Allocator, // Reserved for future heap-based extensions

        /// Initialize an empty anti-replay window.
        ///
        /// ## Parameters
        ///
        /// - `allocator`: Memory allocator (currently unused, reserved for future use)
        ///
        /// ## Returns
        ///
        /// - `AntiReplayWindowSized`: Initialized window with no entries
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .randoms = undefined,
                .count = 0,
                .allocator = allocator,
            };
        }

        /// Release resources held by the anti-replay window.
        ///
        /// Currently a no-op (stack-allocated buffer), but included for API consistency
        /// and future heap-based implementations.
        pub fn deinit(_: *Self) void {
            // No heap allocations in this simple implementation
        }

        /// Check if a ClientHello random has been seen before (replay detection).
        ///
        /// Performs a linear scan over the window to detect duplicates.
        ///
        /// ## Complexity
        ///
        /// O(n) where n = min(count, window_size). At the default window_size=64, this
        /// is ~200ns. For high-traffic servers needing window_size > 256, consider
        /// replacing with a hash-based lookup (e.g., HashMap keyed on the random value)
        /// to achieve O(1) amortized lookup. The constant-time comparison per entry would
        /// need to be preserved in any replacement to prevent timing side-channels.
        ///
        /// ## Parameters
        ///
        /// - `random`: 32-byte ClientHello random field (from TLS handshake)
        ///
        /// ## Returns
        ///
        /// - `true`: Random found in window (REPLAY DETECTED)
        /// - `false`: Random not seen before (ACCEPT)
        ///
        /// ## RFC Compliance
        ///
        /// - RFC 8446 §8.1: Anti-replay mechanism based on ClientHello recording
        ///
        /// ## Security Note
        ///
        /// Uses constant-time comparison to prevent timing side-channels from
        /// leaking information about which randoms are in the anti-replay window.
        pub fn contains(self: *const Self, random: [32]u8) bool {
            const limit = @min(self.count, window_size);
            var found: bool = false;
            var i: usize = 0;
            while (i < limit) : (i += 1) {
                // Constant-time comparison - always check all entries to avoid timing leak
                const match = std.crypto.timing_safe.eql([32]u8, self.randoms[i], random);
                found = found or match;
            }
            return found;
        }

        /// Add a new ClientHello random to the anti-replay window.
        ///
        /// Checks for duplicates before adding (replay detection). If the window is full,
        /// the oldest entry is evicted (FIFO behavior).
        ///
        /// ## Parameters
        ///
        /// - `random`: 32-byte ClientHello random field to record
        ///
        /// ## Returns
        ///
        /// - `void`: Random successfully added
        /// - `error.ReplayDetected`: Random already exists in window (MUST reject 0-RTT)
        ///
        /// ## RFC Compliance
        ///
        /// - RFC 8446 §8.2: ClientHello Recording (single-use enforcement)
        ///
        /// ## Security Critical
        ///
        /// This function MUST be called before accepting 0-RTT data. If it returns
        /// `error.ReplayDetected`, the server MUST reject the 0-RTT attempt and
        /// treat the connection as a regular 1-RTT handshake.
        pub fn add(self: *Self, random: [32]u8) !void {
            if (self.contains(random)) {
                return error.ReplayDetected; // RFC 8446 §8.1: Reject replay
            }
            const idx = self.count % window_size; // FIFO eviction
            self.randoms[idx] = random;
            self.count += 1;
        }

        /// Clear all entries from the anti-replay window.
        ///
        /// **WARNING**: This resets replay protection! Only use for testing or when
        /// explicitly required (e.g., server restart with fresh state).
        ///
        /// ## Security Warning
        ///
        /// Resetting the window allows previously seen ClientHello randoms to be
        /// replayed. Only call this in controlled scenarios.
        pub fn reset(self: *Self) void {
            self.count = 0;
        }
    };
}

/// Default anti-replay window with 64 entries.
/// For custom sizes, use `AntiReplayWindowSized(N)` instead.
pub const AntiReplayWindow = AntiReplayWindowSized(default_window_size);

/// Interface for persistent anti-replay storage backends (RFC 8446 §8.1).
///
/// ## Overview
///
/// For single-server deployments, the in-memory `AntiReplayWindow` is sufficient.
/// However, production multi-server deployments require shared persistent storage
/// to prevent cross-server replay attacks and survive server restarts.
///
/// This interface defines the contract that persistent backends must implement.
/// Implementations can use Redis, Memcached, PostgreSQL, or any other backend
/// that supports atomic check-and-set operations.
///
/// ## Security Requirements
///
/// Implementations MUST:
/// - Provide atomic check-and-add semantics (no race conditions)
/// - Expire entries after the configured TTL (typically ticket lifetime)
/// - Be available across all servers in the deployment
/// - Handle network failures gracefully (fail-closed: reject 0-RTT on errors)
///
/// ## Example Implementation (Redis)
///
/// ```zig
/// const RedisPersistentStore = struct {
///     const Self = @This();
///     client: *RedisClient,
///     ttl_seconds: u32,
///
///     pub fn checkAndAdd(self: *Self, random: [32]u8) PersistentStoreError!bool {
///         const key = formatKey(&random);
///         // SETNX returns 1 if key was set (not seen before)
///         // SETNX returns 0 if key already exists (replay detected)
///         const result = self.client.setnxWithExpiry(key, "1", self.ttl_seconds)
///             catch return error.BackendUnavailable;
///         return result == 1; // true = added (not a replay), false = replay detected
///     }
///
///     fn formatKey(random: *const [32]u8) []const u8 {
///         // Format as "tls13:ar:{hex}" for namespacing
///         // ...
///     }
/// };
/// ```
///
/// ## TTL Considerations
///
/// The TTL should match or exceed the maximum ticket lifetime:
/// - Typical ticket lifetime: 7 days (604800 seconds)
/// - Recommended TTL: 7 days + clock skew tolerance (e.g., 605000 seconds)
/// - Storage requirement: ~40 bytes per entry (32-byte random + overhead)
///
/// ## Error Handling
///
/// When the backend is unavailable, servers SHOULD:
/// - Reject 0-RTT and fall back to 1-RTT (fail-closed, more secure)
/// - NOT accept 0-RTT without replay protection (fail-open, dangerous)
///
/// ## Future Work
///
/// This interface is designed for future integration. To use it:
/// 1. Implement the interface for your chosen backend
/// 2. Inject the implementation into your TLS server configuration
/// 3. The TLS engine will call checkAndAdd() before accepting 0-RTT
pub const PersistentAntiReplayStore = struct {
    /// Opaque pointer to backend-specific state
    ptr: *anyopaque,

    /// VTable for dynamic dispatch
    vtable: *const VTable,

    pub const VTable = struct {
        /// Check if a ClientHello random has been seen and atomically add it.
        ///
        /// ## Parameters
        /// - `random`: 32-byte ClientHello random field
        ///
        /// ## Returns
        /// - `true`: Random was NOT seen before (added successfully, accept 0-RTT)
        /// - `false`: Random was seen before (replay detected, reject 0-RTT)
        /// - `error.BackendUnavailable`: Cannot reach backend (reject 0-RTT)
        /// - `error.BackendError`: Backend returned an error (reject 0-RTT)
        checkAndAdd: *const fn (ptr: *anyopaque, random: [32]u8) PersistentStoreError!bool,

        /// Optional: Clear all entries (for testing only, not recommended in production)
        reset: ?*const fn (ptr: *anyopaque) void,
    };

    pub const PersistentStoreError = error{
        /// Backend storage is unreachable (network error, timeout, etc.)
        BackendUnavailable,
        /// Backend returned an error (auth failure, quota exceeded, etc.)
        BackendError,
    };

    /// Check if random has been seen; atomically add if not.
    pub fn checkAndAdd(self: PersistentAntiReplayStore, random: [32]u8) PersistentStoreError!bool {
        return self.vtable.checkAndAdd(self.ptr, random);
    }

    /// Reset the store (testing only).
    pub fn reset(self: PersistentAntiReplayStore) void {
        if (self.vtable.reset) |resetFn| {
            resetFn(self.ptr);
        }
    }
};

/// Limits on 0-RTT early data usage (RFC 8446 §8.3).
///
/// Defines constraints on the amount and timing of 0-RTT data that can be sent.
/// These limits mitigate replay attack risks and ensure bounded resource consumption.
///
/// ## Fields
///
/// - **max_early_data_size**: Maximum bytes of 0-RTT data allowed (default: 16KB)
///
/// ## RFC Compliance
///
/// - RFC 8446 §8.3: 0-RTT and Anti-Replay security considerations
/// - RFC 8446 §4.2.10: early_data extension (max_early_data_size in NewSessionTicket)
/// - RFC 9001 §4.6.1: Enabling 0-RTT in QUIC (early_data_size limit)
///
/// ## Security Rationale
///
/// ### Size Limits
///
/// Restricting 0-RTT data size limits the impact of replay attacks:
/// - Small limit (e.g., 4KB): Minimal replay risk, limited utility
/// - Large limit (e.g., 64KB): Higher replay risk, more useful for applications
/// - Recommended: 16KB (balance between usability and security)
///
/// ### Time Windows
///
/// While not enforced by this struct, servers SHOULD also implement time-based limits:
/// - Reject 0-RTT if ticket age exceeds configured window (e.g., 7 days)
/// - Check obfuscated_ticket_age in pre_shared_key extension
/// - Combine with anti-replay window for defense-in-depth
///
/// ## Application Guidance
///
/// Applications using 0-RTT MUST ensure early data is idempotent:
/// - **Safe**: HTTP GET requests for static resources
/// - **Safe**: Database reads (SELECT queries)
/// - **UNSAFE**: HTTP POST/PUT/DELETE (state-changing operations)
/// - **UNSAFE**: Financial transactions, account creation
///
/// ## Future Extensions
///
/// Additional fields could include:
/// - `max_ticket_age`: Maximum ticket lifetime (seconds)
/// - `allow_non_idempotent`: Explicit opt-in for risky operations (NOT RECOMMENDED)
/// - `time_window_tolerance`: Clock skew tolerance (seconds)
pub const ZeroRttLimits = struct {
    /// Minimum allowed value for max_early_data_size (1KB).
    /// Smaller values provide minimal utility for 0-RTT.
    pub const min_early_data_size: u32 = 1024;

    /// Maximum allowed value for max_early_data_size (16MB - 1).
    /// Per RFC 8446 §4.2.10, max_early_data_size is a uint32, but TLS record
    /// layer limits individual records. 16MB is a practical upper bound.
    pub const max_early_data_size_limit: u32 = 0xFFFFFF; // 2^24 - 1 (TLS record layer max)

    /// Maximum bytes of 0-RTT data allowed.
    /// Default: 16KB (balance of security and utility per RFC 8446 §4.2.10)
    max_early_data_size: u32 = 16384,

    /// Validate that all limits are within acceptable bounds.
    ///
    /// ## Returns
    /// - `void` if all limits are valid
    /// - `error.InvalidEarlyDataSize` if max_early_data_size is out of bounds
    ///
    /// ## Security Note
    /// Applications should call this after constructing ZeroRttLimits to ensure
    /// the configuration doesn't allow dangerously large or uselessly small values.
    pub fn validate(self: ZeroRttLimits) !void {
        if (self.max_early_data_size < min_early_data_size) {
            return error.InvalidEarlyDataSize;
        }
        if (self.max_early_data_size > max_early_data_size_limit) {
            return error.InvalidEarlyDataSize;
        }
    }

    /// Create a validated ZeroRttLimits with the given early data size.
    ///
    /// ## Parameters
    /// - `size`: Maximum early data size in bytes (must be between 1KB and 16MB-1)
    ///
    /// ## Returns
    /// - Validated `ZeroRttLimits` struct
    /// - `error.InvalidEarlyDataSize` if size is out of bounds
    pub fn withEarlyDataSize(size: u32) !ZeroRttLimits {
        const limits = ZeroRttLimits{ .max_early_data_size = size };
        try limits.validate();
        return limits;
    }
};

test "anti-replay window detects duplicates" {
    var window = AntiReplayWindow.init(std.testing.allocator);
    defer window.deinit();

    const random1: [32]u8 = .{0x01} ** 32;
    const random2: [32]u8 = .{0x02} ** 32;

    // Add first random
    try window.add(random1);
    try std.testing.expect(window.contains(random1));
    try std.testing.expect(!window.contains(random2));

    // Try to add same random again - should fail
    try std.testing.expectError(error.ReplayDetected, window.add(random1));

    // Add different random - should succeed
    try window.add(random2);
    try std.testing.expect(window.contains(random2));
}

test "anti-replay window FIFO eviction" {
    var window = AntiReplayWindow.init(std.testing.allocator);
    defer window.deinit();

    // Fill window beyond capacity
    var i: usize = 0;
    while (i < AntiReplayWindow.window_size + 10) : (i += 1) {
        var random: [32]u8 = undefined;
        @memset(&random, @as(u8, @intCast(i & 0xFF)));
        try window.add(random);
    }

    // Oldest entries should be evicted
    const old_random: [32]u8 = .{0x00} ** 32;
    try std.testing.expect(!window.contains(old_random));

    // Recent entries should still be present
    var recent_random: [32]u8 = undefined;
    @memset(&recent_random, @as(u8, @intCast((AntiReplayWindow.window_size + 9) & 0xFF)));
    try std.testing.expect(window.contains(recent_random));
}

test "anti-replay window reset" {
    var window = AntiReplayWindow.init(std.testing.allocator);
    defer window.deinit();

    const random: [32]u8 = .{0xAB} ** 32;
    try window.add(random);
    try std.testing.expect(window.contains(random));

    window.reset();
    try std.testing.expect(!window.contains(random));
    try std.testing.expectEqual(@as(usize, 0), window.count);
}

test "configurable anti-replay window size" {
    // Test with custom window size (128 entries)
    const LargeWindow = AntiReplayWindowSized(128);
    var window = LargeWindow.init(std.testing.allocator);
    defer window.deinit();

    // Verify the window size is as configured
    try std.testing.expectEqual(@as(usize, 128), LargeWindow.window_size);

    // Test basic functionality with unique random
    var first_random: [32]u8 = undefined;
    @memset(&first_random, 0);
    first_random[0] = 0xAA;
    first_random[1] = 0xBB;
    try window.add(first_random);
    try std.testing.expect(window.contains(first_random));

    // Test FIFO eviction at custom size - generate unique randoms
    var i: usize = 0;
    while (i < LargeWindow.window_size + 5) : (i += 1) {
        var rand: [32]u8 = undefined;
        @memset(&rand, 0);
        // Encode i as little-endian bytes in first 4 bytes to ensure uniqueness
        rand[0] = @as(u8, @intCast((i + 1) & 0xFF));
        rand[1] = @as(u8, @intCast(((i + 1) >> 8) & 0xFF));
        rand[2] = @as(u8, @intCast(((i + 1) >> 16) & 0xFF));
        rand[3] = @as(u8, @intCast(((i + 1) >> 24) & 0xFF));
        try window.add(rand);
    }

    // Original random (0xAABB...) should be evicted after filling window
    try std.testing.expect(!window.contains(first_random));
}

test "ZeroRttLimits validation" {
    // Default limits should be valid
    const default_limits = ZeroRttLimits{};
    try default_limits.validate();

    // Valid custom limit
    const valid_limits = try ZeroRttLimits.withEarlyDataSize(32768);
    try std.testing.expectEqual(@as(u32, 32768), valid_limits.max_early_data_size);

    // Too small - should fail
    try std.testing.expectError(
        error.InvalidEarlyDataSize,
        ZeroRttLimits.withEarlyDataSize(512),
    );

    // Too large - should fail
    try std.testing.expectError(
        error.InvalidEarlyDataSize,
        ZeroRttLimits.withEarlyDataSize(0xFFFFFFFF),
    );

    // Boundary values
    const min_valid = try ZeroRttLimits.withEarlyDataSize(ZeroRttLimits.min_early_data_size);
    try std.testing.expectEqual(ZeroRttLimits.min_early_data_size, min_valid.max_early_data_size);

    const max_valid = try ZeroRttLimits.withEarlyDataSize(ZeroRttLimits.max_early_data_size_limit);
    try std.testing.expectEqual(ZeroRttLimits.max_early_data_size_limit, max_valid.max_early_data_size);
}
