//! Endian helpers used to satisfy QUIC wire encodings.
//!
//! RFC 9000 §17 encodes multi-byte integers in network byte order; these
//! wrappers centralise the conversions so packet and frame modules stay tidy.
const std = @import("std");

/// Errors returned by byteorder encode/decode helpers.
pub const Error = error{
    BufferTooSmall,
    BufferTooShort,
};

pub inline fn toEndian(comptime T: type, endian: std.builtin.Endian, value: T) T {
    return switch (endian) {
        .big => std.mem.nativeToBig(T, value),
        .little => std.mem.nativeToLittle(T, value),
    };
}

pub inline fn fromEndian(comptime T: type, endian: std.builtin.Endian, value: T) T {
    return switch (endian) {
        .big => std.mem.bigToNative(T, value),
        .little => std.mem.littleToNative(T, value),
    };
}

/// Encode `value` into `out` using the provided `endian`. Returns the remaining slice.
pub fn encode(comptime T: type, endian: std.builtin.Endian, value: T, out: []u8) Error![]u8 {
    const size = @sizeOf(T);
    if (out.len < size) return Error.BufferTooSmall;

    var tmp = toEndian(T, endian, value);
    const bytes = std.mem.asBytes(&tmp);
    @memcpy(out[0..size], bytes);
    return out[size..];
}

/// Decode an integer of type `T` from the front of `data` using `endian`.
/// Returns the decoded value alongside the remaining slice.
pub fn decode(comptime T: type, endian: std.builtin.Endian, data: []const u8) Error!struct { value: T, rest: []const u8 } {
    const size = @sizeOf(T);
    if (data.len < size) return Error.BufferTooShort;

    var tmp: T = undefined;
    @memcpy(std.mem.asBytes(&tmp), data[0..size]);
    const native = fromEndian(T, endian, tmp);
    return .{ .value = native, .rest = data[size..] };
}
