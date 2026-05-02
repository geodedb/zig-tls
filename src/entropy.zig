// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Cross-platform entropy helper for TLS 1.3.
//!
//! SEC-074 / SEC-081: Wraps Zig 0.16's `std.Io.Threaded.global_single_threaded.io().randomSecure`
//! to obtain cryptographically strong random bytes, panicking on the
//! only error path (`error.EntropyUnavailable`).
//!
//! # Why randomSecure, not random
//!
//! `io().random` is a user-space CSPRNG seeded lazily from the OS. Per
//! Zig 0.16 stdlib `std/Io/Threaded.zig` (lines ~16930-16965), if the
//! seed-fetch fails it **silently falls back** to a weak mix of PID,
//! clock, and ASLR address. Using `random` would defeat the SEC-074 fix:
//! a seccomp-blocked process would silently mint deterministic keys.
//!
//! `io().randomSecure` returns `error.EntropyUnavailable` on the same
//! failure path (stdlib `Threaded.zig:17008+`), giving a genuine
//! panic-on-failure chokepoint.
//!
//! # Fail-Closed Semantics
//!
//! On entropy-source failure (seccomp, ENOSYS, unrecoverable EINTR,
//! kernel refusal), this function panics with a TLS-specific message.
//! This is the correct behavior for cryptographic material: silently
//! continuing with predictable bytes would defeat the fix.
//!
//! # Platform Support
//!
//! `randomSecure` routes to the platform entropy source (`getrandom` on
//! Linux, `getentropy` on macOS/BSD, `BCryptGenRandom` on Windows).
//! Closes SEC-081.

const std = @import("std");

pub fn fillRandom(buf: []u8) void {
    std.Io.Threaded.global_single_threaded.io().randomSecure(buf) catch |err| {
        // SEC-074: Actual fail-closed point. randomSecure returns
        // error.EntropyUnavailable on seccomp/ENOSYS/EINTR-unresolvable
        // kernel refusal. We must NOT continue with undefined or
        // fallback-seeded bytes masquerading as a cryptographic key —
        // panic with TLS-specific context so operators can diagnose.
        std.debug.panic("TLS RNG fail-closed: entropy unavailable ({t})", .{err});
    };
}

/// A per-handshake entropy reservoir to amortize the cost of `getrandom` syscalls.
/// A typical TLS 1.3 handshake needs up to ~160 bytes of random material.
/// This struct fetches a large chunk of entropy at once and doles it out.
pub const Reservoir = struct {
    buffer: [160]u8 = undefined,
    used: usize = 160, // Initially marked as fully used to trigger fetch on first take

    /// Takes `dest.len` bytes of entropy from the reservoir.
    /// If the reservoir is empty, it refills the entire buffer using `fillRandom`.
    pub fn take(self: *Reservoir, dest: []u8) void {
        var needed = dest.len;
        var out_idx: usize = 0;

        while (needed > 0) {
            const available = self.buffer.len - self.used;
            if (available == 0) {
                fillRandom(&self.buffer);
                self.used = 0;
            }

            const chunk_size = @min(needed, self.buffer.len - self.used);
            @memcpy(dest[out_idx .. out_idx + chunk_size], self.buffer[self.used .. self.used + chunk_size]);
            self.used += chunk_size;
            out_idx += chunk_size;
            needed -= chunk_size;
        }
    }
};
