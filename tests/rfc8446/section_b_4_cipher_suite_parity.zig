//! RFC 8446 §B.4 Cipher Suite Parity (QUAL-337)
//!
//! Two `CipherSuite` enums exist in this codebase:
//!
//! - `tls13_full.CipherSuite` (enum(u16)) — IANA wire-format values
//!   from `src/tls13/messages/core_types.zig`. Includes CCM variants
//!   recognised for parsing but not implemented for AEAD.
//! - `record.CipherSuite` (plain enum) — the 3 AEAD suites that the
//!   record layer actually supports. Defined in `src/record/aead.zig`.
//!
//! The split is deliberate per `src/record/aead.zig:80-85` (layer
//! isolation). This file pins the parity contract so the two enums
//! cannot drift silently:
//!
//!   1. Every variant name in the AEAD enum must exist in the wire enum.
//!   2. The wire enum must contain exactly 5 variants (RFC 8446 §B.4).
//!   3. The AEAD enum must contain exactly 3 variants (implemented AEADs).
//!
//! If any of these break, the code fails to compile, forcing a
//! deliberate review of the duplicate-type policy.

const std = @import("std");
const tls13_full = @import("tls13_full");
const record = @import("record");

test "QUAL-337: RFC 8446 §B.4 cipher suite enum parity" {
    const WireSuite = tls13_full.CipherSuite;
    const AeadSuite = record.CipherSuite;

    // RFC 8446 §B.4 lists exactly 5 cipher suites.
    const wire_fields = std.meta.fields(WireSuite);
    try std.testing.expectEqual(@as(usize, 5), wire_fields.len);

    // The AEAD layer implements exactly 3 of them.
    const aead_fields = std.meta.fields(AeadSuite);
    try std.testing.expectEqual(@as(usize, 3), aead_fields.len);

    // Every AEAD variant name MUST also exist on the wire enum.
    inline for (aead_fields) |af| {
        comptime var found = false;
        inline for (wire_fields) |wf| {
            if (comptime std.mem.eql(u8, af.name, wf.name)) {
                found = true;
            }
        }
        if (!found) {
            @compileError("QUAL-337: AEAD CipherSuite variant '" ++ af.name ++
                "' is missing from wire-format CipherSuite");
        }
    }

    // The 3 AEAD names MUST be the well-known TLS 1.3 AEAD identifiers.
    const expected_aead = [_][]const u8{
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    };
    inline for (expected_aead) |name| {
        comptime var ok = false;
        inline for (aead_fields) |af| {
            if (comptime std.mem.eql(u8, name, af.name)) ok = true;
        }
        if (!ok) @compileError("QUAL-337: AEAD CipherSuite missing " ++ name);
    }

    // Wire-format IANA codes for the 3 AEAD suites (RFC 8446 §B.4).
    try std.testing.expectEqual(
        @as(u16, 0x1301),
        @intFromEnum(WireSuite.TLS_AES_128_GCM_SHA256),
    );
    try std.testing.expectEqual(
        @as(u16, 0x1302),
        @intFromEnum(WireSuite.TLS_AES_256_GCM_SHA384),
    );
    try std.testing.expectEqual(
        @as(u16, 0x1303),
        @intFromEnum(WireSuite.TLS_CHACHA20_POLY1305_SHA256),
    );
}

test "QUAL-337: size invariants" {
    // tls13_full.CipherSuite is a wire-format enum backed by u16.
    try std.testing.expectEqual(@as(usize, @sizeOf(u16)), @sizeOf(tls13_full.CipherSuite));

    // record.CipherSuite is an implementation-layer enum with 3 variants;
    // it fits in a single byte.
    try std.testing.expect(@sizeOf(record.CipherSuite) <= @sizeOf(u8));
}
