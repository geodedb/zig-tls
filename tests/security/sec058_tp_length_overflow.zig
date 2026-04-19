// SPDX-License-Identifier: Apache-2.0
//! SEC-058 regression: TransportParameters.decode must reject a varint
//! length >= 2^32 cleanly (with error.Truncated) rather than panicking
//! via @intCast on 32-bit targets. On 64-bit targets the panic is not
//! reachable; the test still asserts clean rejection.

const std = @import("std");
const transport_params = @import("quic_transport_params");

test "SEC-058: TP varint length 2^32 is rejected, not panicked" {
    const alloc = std.testing.allocator;

    // Parameter ID: 0x01 (max_idle_timeout) — single-byte varint, value 1.
    // Parameter length: 8-byte varint encoding 2^32 (= 0x1_0000_0000).
    //
    // QUIC varint 8-byte form: top 2 bits = 11; value stored in remaining 62 bits.
    // 2^32 = 0x1_0000_0000 -> prefix 0xC0 (= 11_000000) + 7 bytes of value.
    const bytes = [_]u8{
        0x01, // id = 1 (1-byte varint)
        0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // length = 2^32 (8-byte varint)
        // (no value bytes — decoder must reject before reading)
    };

    const result = transport_params.TransportParameters.decode(&bytes, alloc);
    try std.testing.expectError(error.Truncated, result);
}

test "SEC-058: TP varint length just over data.len is rejected" {
    const alloc = std.testing.allocator;

    // Same shape but a modest overflow: length = 100, but only 4 value bytes supplied.
    const bytes = [_]u8{
        0x01, // id = 1
        0x40, 0x64, // length = 100 (2-byte varint)
        0xAA, 0xBB, 0xCC, 0xDD, // only 4 value bytes
    };

    const result = transport_params.TransportParameters.decode(&bytes, alloc);
    try std.testing.expectError(error.Truncated, result);
}
