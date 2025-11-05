//! QUIC varint utilities (RFC 9000 §16).
//
// 16.  Variable-Length Integer Encoding

//    QUIC packets and frames commonly use a variable-length encoding for
//    non-negative integer values.  This encoding ensures that smaller
//    integer values need fewer bytes to encode.

//    The QUIC variable-length integer encoding reserves the two most
//    significant bits of the first byte to encode the base-2 logarithm of
//    the integer encoding length in bytes.  The integer value is encoded
//    on the remaining bits, in network byte order.

//    This means that integers are encoded on 1, 2, 4, or 8 bytes and can
//    encode 6-, 14-, 30-, or 62-bit values, respectively.  Table 4
//    summarizes the encoding properties.

//           +======+========+=============+=======================+
//           | 2MSB | Length | Usable Bits | Range                 |
//           +======+========+=============+=======================+
//           | 00   | 1      | 6           | 0-63                  |
//           +------+--------+-------------+-----------------------+
//           | 01   | 2      | 14          | 0-16383               |
//           +------+--------+-------------+-----------------------+
//           | 10   | 4      | 30          | 0-1073741823          |
//           +------+--------+-------------+-----------------------+
//           | 11   | 8      | 62          | 0-4611686018427387903 |
//           +------+--------+-------------+-----------------------+

//                    Table 4: Summary of Integer Encodings

//    An example of a decoding algorithm and sample encodings are shown in
//    Appendix A.1.

//    Values do not need to be encoded on the minimum number of bytes
//    necessary, with the sole exception of the Frame Type field; see
//    Section 12.4.

//    Versions (Section 15), packet numbers sent in the header
//    (Section 17.1), and the length of connection IDs in long header
//    packets (Section 17.2) are described using integers but do not use
//    this encoding.
const std = @import("std");
const byteorder = @import("byteorder");

/// Errors for varint encoding/decoding.
pub const Error = error{ Truncated, Overflow };

/// Decode a QUIC varint from the front of data. Returns bytes consumed and value.
pub fn decode(data: []const u8) Error!struct { n: usize, value: u64 } {
    if (data.len == 0) return Error.Truncated;

    // First Byte is the: "two most significant bits of the first byte to encode
    // the base-2 logarithm of the integer encoding length in bytes"
    const first = data[0];
    const prefix = first >> 6;
    const len: usize = switch (prefix) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };

    // Check if we have enough data
    if (data.len < len) return Error.Truncated;

    // Decode value using centralized byteorder helpers for the multi-byte forms.
    //           +======+========+=============+=======================+
    //           | 2MSB | Length | Usable Bits | Range                 |
    //           +======+========+=============+=======================+
    //           | 00   | 1      | 6           | 0-63                  |
    //           +------+--------+-------------+-----------------------+
    //           | 01   | 2      | 14          | 0-16383               |
    //           +------+--------+-------------+-----------------------+
    //           | 10   | 4      | 30          | 0-1073741823          |
    //           +------+--------+-------------+-----------------------+
    //           | 11   | 8      | 62          | 0-4611686018427387903 |
    //           +------+--------+-------------+-----------------------+
    var v: u64 = 0;
    switch (len) {
        1 => v = (first & 0x3f),
        2 => {
            var tmp: [2]u8 = .{ @as(u8, first & 0x3f), data[1] };
            const decoded = byteorder.decode(
                u16,
                .big,
                tmp[0..],
            ) catch unreachable;
            v = @as(u64, decoded.value);
        },
        4 => {
            var tmp: [4]u8 = undefined;
            tmp[0] = first & 0x3f;
            @memcpy(tmp[1..], data[1..4]);
            const decoded = byteorder.decode(
                u32,
                .big,
                tmp[0..],
            ) catch unreachable;
            v = @as(u64, decoded.value);
        },
        8 => {
            var tmp: [8]u8 = undefined;
            tmp[0] = first & 0x3f;
            @memcpy(tmp[1..], data[1..8]);
            const decoded = byteorder.decode(
                u64,
                .big,
                tmp[0..],
            ) catch unreachable;
            v = decoded.value;
        },
        else => unreachable,
    }
    return .{ .n = len, .value = v };
}

/// Encode value using QUIC varint into out. Returns bytes written.
/// RFC 9000 §16 defines the encoding sizes, while §12.4 mandates using the
/// minimum-length encoding for integer fields unless otherwise specified (for
/// example, the Length field in long headers).
pub fn encode(value: u64, out: []u8) Error!usize {
    if (value > ((1 << 62) - 1)) return Error.Overflow;

    // First Byte is the: "two most significant bits of the first byte to encode
    // the base-2 logarithm of the integer encoding length in bytes"
    const len: usize =
        if (value < (1 << 6)) 1 else if (value < (1 << 14)) 2 else if (value < (1 << 30)) 4 else 8;

    if (out.len < len) return Error.Truncated;

    // Encode value using centralized byteorder helpers for the multi-byte forms.
    //           +======+========+=============+=======================+
    //           | 2MSB | Length | Usable Bits | Range                 |
    //           +======+========+=============+=======================+
    //           | 00   | 1      | 6           | 0-63                  |
    //           +------+--------+-------------+-----------------------+
    //           | 01   | 2      | 14          | 0-16383               |
    //           +------+--------+-------------+-----------------------+
    //           | 10   | 4      | 30          | 0-1073741823          |
    //           +------+--------+-------------+-----------------------+
    //           | 11   | 8      | 62          | 0-4611686018427387903 |
    //           +------+--------+-------------+-----------------------+
    switch (len) {
        1 => {
            _ = byteorder.encode(
                u8,
                .big,
                @as(u8, @intCast(value)),
                out[0..1],
            ) catch unreachable;
            out[0] = (out[0] & 0x3f) | @as(u8, 0b00 << 6);
        },
        2 => {
            _ = byteorder.encode(
                u16,
                .big,
                @as(u16, @intCast(value)),
                out[0..2],
            ) catch unreachable;
            out[0] = (out[0] & 0x3f) | @as(u8, 0b01 << 6);
        },
        4 => {
            _ = byteorder.encode(
                u32,
                .big,
                @as(u32, @intCast(value)),
                out[0..4],
            ) catch unreachable;
            out[0] = (out[0] & 0x3f) | @as(u8, 0b10 << 6);
        },
        8 => {
            _ = byteorder.encode(
                u64,
                .big,
                value,
                out[0..8],
            ) catch unreachable;
            out[0] = (out[0] & 0x3f) | @as(u8, 0b11 << 6);
        },
        else => unreachable,
    }
    return len;
}

/// Encode value using QUIC varint with a forced byte length (1, 2, 4, or 8).
/// This helper is retained for interoperability tests that need to exercise
/// non-minimal encodings; RFC 9000 §12.4 otherwise requires emitters to choose
/// the shortest encoding.
pub fn encodeWithLen(value: u64, out: []u8, byte_len: usize) Error!usize {
    if (value > ((1 << 62) - 1)) return Error.Overflow;
    if (out.len < byte_len) return Error.Truncated;

    // Validate byte_len and value fit
    const max_for_len: u64 = switch (byte_len) {
        1 => (1 << 6) - 1,
        2 => (1 << 14) - 1,
        4 => (1 << 30) - 1,
        8 => (1 << 62) - 1,
        else => return Error.Overflow,
    };

    if (value > max_for_len) return Error.Overflow;

    // Encode value using centralized byteorder helpers for the multi-byte forms.
    //           +======+========+=============+=======================+
    //           | 2MSB | Length | Usable Bits | Range                 |
    //           +======+========+=============+=======================+
    //           | 00   | 1      | 6           | 0-63                  |
    //           +------+--------+-------------+-----------------------+
    //           | 01   | 2      | 14          | 0-16383               |
    //           +------+--------+-------------+-----------------------+
    //           | 10   | 4      | 30          | 0-1073741823          |
    //           +------+--------+-------------+-----------------------+
    //           | 11   | 8      | 62          | 0-4611686018427387903 |
    //           +------+--------+-------------+-----------------------+
    switch (byte_len) {
        1 => {
            _ = byteorder.encode(
                u8,
                .big,
                @as(u8, @intCast(value)),
                out[0..1],
            ) catch unreachable;
            out[0] = (out[0] & 0x3f) | @as(u8, 0b00 << 6);
        },
        2 => {
            _ = byteorder.encode(
                u16,
                .big,
                @as(u16, @intCast(value)),
                out[0..2],
            ) catch unreachable;
            out[0] = (out[0] & 0x3f) | @as(u8, 0b01 << 6);
        },
        4 => {
            _ = byteorder.encode(
                u32,
                .big,
                @as(u32, @intCast(value)),
                out[0..4],
            ) catch unreachable;
            out[0] = (out[0] & 0x3f) | @as(u8, 0b10 << 6);
        },
        8 => {
            _ = byteorder.encode(
                u64,
                .big,
                value,
                out[0..8],
            ) catch unreachable;
            out[0] = (out[0] & 0x3f) | @as(u8, 0b11 << 6);
        },
        else => return Error.Overflow,
    }

    return byte_len;
}
