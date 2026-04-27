// SPDX-License-Identifier: Apache-2.0
//! SEC-099: ClientHello.cipher_suites length-parity check.
//!
//! RFC 8446 §4.1.2 wire layout:
//!     CipherSuite cipher_suites<2..2^16-2>;
//! Each `CipherSuite` is exactly 2 bytes, so `cipher_suites_length` MUST be a
//! multiple of 2. Before this fix the parser at
//! `src/tls13/messages/client_hello.zig:303-321` only verified
//! `pos + cs_len <= data.len` and then walked `cs_pos += 2`, which on an odd
//! `cs_len` reads `data[pos+cs_len-1 .. pos+cs_len+1]` — a one-byte over-read
//! that:
//!   * silently corrupts the parser's view of cipher_suites when downstream
//!     bytes exist (`with_tail = true`); and
//!   * panics outright when the ClientHello ends exactly at the cipher_suites
//!     tail (`with_tail = false`).
//!
//! The fix added `if (cs_len % 2 != 0) return error.IllegalCipherSuites;`
//! immediately after the bounds check, and `error.IllegalCipherSuites` is
//! mapped to TLS alert `illegal_parameter` (RFC 8446 §6.2). This file pins
//! both the panic path and the silent-corruption path with positive
//! assertions.
//!
//! History: filed as a PoC at `tests/security/sec094_cipher_suites_parity_poc.zig`
//! during the Phase 22 audit and renamed to `sec099_cipher_suites_parity.zig`
//! on landing of the fix.

const std = @import("std");
const tls13_full = @import("tls13_full");

/// Wire helper: write big-endian u16.
fn writeU16(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, v: u16) !void {
    try buf.append(alloc, @intCast((v >> 8) & 0xff));
    try buf.append(alloc, @intCast(v & 0xff));
}

/// Build a ClientHello body with attacker-controlled cipher_suites_length and
/// raw cipher_suites bytes. `with_tail` controls whether compression_methods
/// + empty extensions are appended after the cipher_suites field.
fn buildClientHelloOddCipherSuites(
    alloc: std.mem.Allocator,
    cs_len: u16,
    cs_bytes: []const u8,
    with_tail: bool,
) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(alloc);

    // legacy_version = TLS 1.2
    try buf.appendSlice(alloc, &.{ 0x03, 0x03 });
    // random (32 bytes)
    try buf.appendNTimes(alloc, 0xA5, 32);
    // session_id (u8 len + 0)
    try buf.append(alloc, 0x00);
    // cipher_suites: declared length + raw bytes (intentionally odd length).
    try writeU16(&buf, alloc, cs_len);
    try buf.appendSlice(alloc, cs_bytes);

    if (with_tail) {
        // compression_methods: u8 len + null
        try buf.appendSlice(alloc, &.{ 0x01, 0x00 });
        // extensions: u16 len + 0
        try writeU16(&buf, alloc, 0);
    }

    return try buf.toOwnedSlice(alloc);
}

test "SEC-099: odd cipher_suites_length=5 with valid tail is rejected" {
    const alloc = std.testing.allocator;

    // Pre-fix this input was silently accepted: the final loop iteration read
    // bytes [4..6) of cs_bytes, leaking one byte from compression_methods into
    // the parser's `cs_value` u16. The fix surfaces this as a typed error.
    const cs_raw = [_]u8{ 0x13, 0x01, 0x13, 0x02, 0x13 };
    const body = try buildClientHelloOddCipherSuites(alloc, 5, &cs_raw, true);
    defer alloc.free(body);

    try std.testing.expectError(
        error.IllegalCipherSuites,
        tls13_full.parseClientHello(alloc, body),
    );
}

test "SEC-099: odd cipher_suites_length=5 at exact data tail does not panic" {
    const alloc = std.testing.allocator;

    // Pre-fix this input panicked with `index out of bounds: index 43, len 42`
    // because the final loop iteration tried to read past the end of `data`.
    // Post-fix the parity gate trips before the loop runs and the parser
    // returns the typed error cleanly.
    const cs_raw = [_]u8{ 0x13, 0x01, 0x13, 0x02, 0x13 };
    const body = try buildClientHelloOddCipherSuites(alloc, 5, &cs_raw, false);
    defer alloc.free(body);

    try std.testing.expectError(
        error.IllegalCipherSuites,
        tls13_full.parseClientHello(alloc, body),
    );
}

test "SEC-099: odd cipher_suites_length=3 (sub-suite) is rejected" {
    const alloc = std.testing.allocator;

    // 3 bytes is below a single CipherSuite's two-byte boundary plus one — a
    // strictly odd length the bounds check alone cannot detect.
    const cs_raw = [_]u8{ 0x13, 0x01, 0x13 };
    const body = try buildClientHelloOddCipherSuites(alloc, 3, &cs_raw, true);
    defer alloc.free(body);

    try std.testing.expectError(
        error.IllegalCipherSuites,
        tls13_full.parseClientHello(alloc, body),
    );
}

test "SEC-099: even cipher_suites_length=4 still parses normally" {
    const alloc = std.testing.allocator;

    // Regression guard: the fix must only reject odd lengths; a well-formed
    // pair of CipherSuites continues to land in the parsed ClientHello.
    const cs_raw = [_]u8{ 0x13, 0x01, 0x13, 0x02 };
    const body = try buildClientHelloOddCipherSuites(alloc, 4, &cs_raw, true);
    defer alloc.free(body);

    const ch = try tls13_full.parseClientHello(alloc, body);
    defer {
        if (ch.cipher_suites.len > 0) alloc.free(ch.cipher_suites);
        if (ch.supported_groups) |sg| alloc.free(sg);
        if (ch.signature_algorithms) |sa| alloc.free(sa);
        if (ch.alpn_list) |al| alloc.free(al);
        if (ch.pre_shared_key) |psk| {
            alloc.free(psk.identities);
            alloc.free(psk.binders);
        }
    }
    try std.testing.expectEqual(@as(usize, 2), ch.cipher_suites.len);
}
