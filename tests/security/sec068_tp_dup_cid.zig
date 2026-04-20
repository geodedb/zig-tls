// SPDX-License-Identifier: Apache-2.0
//! SEC-068 regression: TransportParameters.decode must reject a QUIC
//! transport-parameters blob that contains the same connection-ID parameter
//! twice with error.InvalidParameter (RFC 9000 §18 forbids duplicates).
//! Without the guard the second allocation would overwrite the first's
//! pointer and leak the first allocation.

const std = @import("std");
const transport_params = @import("quic_transport_params");

/// Minimal encoder: write a single-byte varint parameter id, a single-byte
/// varint length, and the raw payload bytes.
fn appendParam(
    buf: *std.ArrayList(u8),
    alloc: std.mem.Allocator,
    id: u8,
    payload: []const u8,
) !void {
    try buf.append(alloc, id);
    try buf.append(alloc, @intCast(payload.len));
    try buf.appendSlice(alloc, payload);
}

test "SEC-068: duplicate initial_source_connection_id is rejected" {
    const alloc = std.testing.allocator;
    // Param id 0x0f = initial_source_connection_id
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(alloc);
    try appendParam(&buf, alloc, 0x0f, &.{ 0xDE, 0xAD, 0xBE, 0xEF });
    try appendParam(&buf, alloc, 0x0f, &.{ 0xCA, 0xFE, 0xBA, 0xBE });

    const result = transport_params.TransportParameters.decode(buf.items, alloc);
    try std.testing.expectError(error.InvalidParameter, result);
}

test "SEC-068: duplicate original_destination_connection_id is rejected" {
    const alloc = std.testing.allocator;
    // Param id 0x00 = original_destination_connection_id
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(alloc);
    try appendParam(&buf, alloc, 0x00, &.{ 0x11, 0x22, 0x33, 0x44 });
    try appendParam(&buf, alloc, 0x00, &.{ 0x55, 0x66, 0x77, 0x88 });

    const result = transport_params.TransportParameters.decode(buf.items, alloc);
    try std.testing.expectError(error.InvalidParameter, result);
}

test "SEC-068: duplicate retry_source_connection_id is rejected" {
    const alloc = std.testing.allocator;
    // Param id 0x10 = retry_source_connection_id
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(alloc);
    try appendParam(&buf, alloc, 0x10, &.{ 0x11, 0x22, 0x33, 0x44 });
    try appendParam(&buf, alloc, 0x10, &.{ 0x55, 0x66, 0x77, 0x88 });

    const result = transport_params.TransportParameters.decode(buf.items, alloc);
    try std.testing.expectError(error.InvalidParameter, result);
}
