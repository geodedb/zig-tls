//! Minimal ASN.1 DER decoder utilities used by X.509 parsing.
//!
//! Covers the subset of DER rules required for X.509 certificate handling in
//! accordance with RFC 5280. TLS integration code relies on these helpers when
//! processing certificate chains during the QUIC handshake.
const std = @import("std");

// TODO: This should be using https://ziglang.org/documentation/master/std/#std.crypto.codecs.asn1

/// ASN.1 tag class categories for DER TLV headers.
pub const TagClass = enum { universal, application, context, private };

/// Return the tag class from a TLV tag byte.
pub fn tagClass(b: u8) TagClass {
    return switch (b >> 6) {
        0 => .universal,
        1 => .application,
        2 => .context,
        else => .private,
    };
}
/// Whether a TLV tag denotes a constructed form.
pub fn isConstructed(b: u8) bool {
    return (b & 0x20) != 0;
}
/// Return the tag number (low 5 bits) from a TLV tag byte.
pub fn tagNumber(b: u8) u8 {
    return b & 0x1f;
}

/// A streaming DER decoder over a byte slice with helpers for common universal types.
pub const Decoder = struct {
    buf: []const u8,
    off: usize = 0,

    /// Initialize a decoder over buf starting at offset 0.
    pub fn init(buf: []const u8) Decoder {
        return .{ .buf = buf, .off = 0 };
    }

    fn readByte(self: *Decoder) !u8 {
        if (self.off >= self.buf.len) return error.Truncated;
        const b = self.buf[self.off];
        self.off += 1;
        return b;
    }

    fn readLen(self: *Decoder) !usize {
        const b = try self.readByte();
        if ((b & 0x80) == 0) return b; // short form
        const n = b & 0x7f;
        if (n == 0) return error.IndefiniteLength;
        if (n > 8) return error.LengthTooLarge;
        var val: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            val = (val << 8) | try self.readByte();
        }
        return val;
    }

    /// Read the next TLV header returning tag, content length and header length.
    pub fn nextHeader(self: *Decoder) !struct { tag: u8, len: usize, hdr_len: usize } {
        const start = self.off;
        const tag = try self.readByte();
        const len = try self.readLen();
        return .{ .tag = tag, .len = len, .hdr_len = self.off - start };
    }

    /// Read one complete TLV returning the tag and the value (content slice).
    pub fn readTLV(self: *Decoder) !struct { tag: u8, val: []const u8 } {
        const h = try self.nextHeader();
        if (self.off + h.len > self.buf.len) return error.Truncated;
        const val = self.buf[self.off .. self.off + h.len];
        self.off += h.len;
        return .{ .tag = h.tag, .val = val };
    }

    /// Read a SEQUENCE value and return its content bytes (to be decoded by a nested Decoder).
    pub fn readSequence(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 16 or !isConstructed(tlv.tag))
            return error.UnexpectedTag;
        return tlv.val;
    }

    /// Read an INTEGER and return it as u64 (only non-negative up to 64 bits supported).
    pub fn readInteger(self: *Decoder) !u64 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 2)
            return error.UnexpectedTag;
        // Big-endian two's complement; support non-negative values up to 64 bits.
        var v: u64 = 0;
        for (tlv.val) |b| {
            v = (v << 8) | b;
        }
        return v;
    }

    /// Read an OCTET STRING and return a view of its bytes.
    pub fn readOctetString(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 4)
            return error.UnexpectedTag;
        return tlv.val;
    }

    /// Read a BIT STRING and return its payload (without the leading 'unused bits' byte).
    pub fn readBitString(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 3)
            return error.UnexpectedTag;
        if (tlv.val.len == 0) return error.Truncated;
        const unused = tlv.val[0];
        if (unused > 7) return error.InvalidBitString;
        // Return payload without the initial 'unused bits' byte.
        return tlv.val[1..];
    }

    /// Read an OBJECT IDENTIFIER and return its bytes.
    pub fn readOID(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 6)
            return error.UnexpectedTag;
        return tlv.val; // caller interprets if needed
    }

    /// Read a UTF8String and return a view of its bytes.
    pub fn readUtf8String(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 12)
            return error.UnexpectedTag;
        return tlv.val;
    }

    /// Read an IA5String and return a view of its bytes.
    pub fn readIa5String(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 22)
            return error.UnexpectedTag;
        return tlv.val;
    }
};
