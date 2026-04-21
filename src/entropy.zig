// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Cross-platform entropy helper for TLS 1.3.
//!
//! SEC-074 / SEC-081: Replaces direct `std.os.linux.getrandom` calls
//! with a portable, fail-closed wrapper. The underlying Zig 0.16
//! `std.Io.Threaded.global_single_threaded.io().random` returns void
//! and panics on entropy failure — the correct fail-closed behavior
//! for a cryptographic library.

const std = @import("std");

/// Fill `buf` with cryptographically secure random bytes.
///
/// # Fail-Closed Semantics
///
/// On entropy-source failure (e.g., seccomp blocks the syscall, kernel
/// reports ENOSYS, or EAGAIN/EINTR cannot be resolved), this function
/// panics. This is the correct behavior for cryptographic material:
/// silently continuing with uninitialized bytes would produce predictable
/// keys (SEC-074).
///
/// # Platform Support
///
/// Backed by `std.Io.Threaded.global_single_threaded.io().random`, which
/// routes to the platform entropy source (`getrandom` on Linux,
/// `getentropy` on macOS/BSD, `BCryptGenRandom` on Windows). Closes
/// SEC-081.
pub fn fillRandom(buf: []u8) void {
    std.Io.Threaded.global_single_threaded.io().random(buf);
}

test "fillRandom produces non-zero bytes" {
    var buf: [32]u8 = undefined;
    @memset(&buf, 0);
    fillRandom(&buf);
    var all_zero = true;
    for (buf) |b| if (b != 0) {
        all_zero = false;
        break;
    };
    try std.testing.expect(!all_zero);
}
