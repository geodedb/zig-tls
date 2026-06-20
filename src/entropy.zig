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
const cb = @import("crypto_backend");

pub fn fillRandom(buf: []u8) void {
    if (comptime cb.fips_enabled) {
        // FIPS: route through the SP 800-90A DRBG (OpenSSL RAND_bytes under
        // the FIPS provider). Fail-closed if the validated DRBG is
        // unavailable — never fall back to non-FIPS entropy.
        cb.Csprng.bytes(buf) catch |err|
            std.debug.panic("TLS RNG fail-closed: FIPS DRBG unavailable ({t})", .{err});
        return;
    }
    std.Io.Threaded.global_single_threaded.io().randomSecure(buf) catch |err| {
        // SEC-074: Actual fail-closed point. randomSecure returns
        // error.EntropyUnavailable on seccomp/ENOSYS/EINTR-unresolvable
        // kernel refusal. We must NOT continue with undefined or
        // fallback-seeded bytes masquerading as a cryptographic key —
        // panic with TLS-specific context so operators can diagnose.
        std.debug.panic("TLS RNG fail-closed: entropy unavailable ({t})", .{err});
    };
}

test "fillRandom yields non-zero bytes via active backend" {
    var buf: [32]u8 = .{0} ** 32;
    fillRandom(&buf);
    var all_zero = true;
    for (buf) |b| if (b != 0) {
        all_zero = false;
    };
    try @import("std").testing.expect(!all_zero);
}
