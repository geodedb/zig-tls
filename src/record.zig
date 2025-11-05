//! TLS 1.3 record layer primitives for QUIC handshake support.
//!
//! Implements framing and AEAD encapsulation per RFC 8446 §5 so the QUIC
//! handshake code can serialise TLSPlaintext/TLSInnerPlaintext without relying
//! on the standard library record stack.
const std = @import("std");
const crypto = std.crypto;
const math = std.math;

const AuthenticationError = crypto.errors.AuthenticationError;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;

/// TLS 1.3 record layer primitives (RFC 8446 §5).
/// Provides TLSPlaintext framing, TLSInnerPlaintext packing, and AEAD
/// protection helpers used by the QUIC handshake engine.
/// Legacy record protocol versions carried on the wire (RFC 8446 §5.1).
pub const LegacyVersion = enum(u16) {
    ssl_3_0 = 0x0300,
    tls_1_0 = 0x0301,
    tls_1_1 = 0x0302,
    tls_1_2 = 0x0303,
};

/// TLS 1.3 fixes the outer record version to 0x0303 (TLS 1.2).
/// Default legacy version to use in TLS 1.3 records.
pub const default_legacy_version = LegacyVersion.tls_1_2;

/// Record content types as defined in RFC 8446 §5.1.
pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    heartbeat = 24,
};

/// Maximum TLSPlaintext fragment permitted by RFC 8446 §5.1.
pub const max_plaintext_fragment = 16384; // 2^14 bytes

/// Maximum padding we accept for TLSInnerPlaintext. RFC 8446 allows up to 2^14
/// bytes; we mirror that bound to simplify validation.
pub const max_inner_padding = max_plaintext_fragment;

/// Errors that can occur during TLS record processing.
pub const RecordError = error{
    FragmentTooLarge,
    RecordTooShort,
    LengthMismatch,
    InvalidContentType,
    MissingContentType,
    PaddingTooLarge,
    UnsupportedLegacyVersion,
    InvalidKeyLength,
    InvalidIvLength,
    CiphertextTooShort,
    AuthenticationFailed,
    AeadLimitExceeded,
    OutOfMemory,
};

/// Lightweight view over a TLSPlaintext record (RFC 8446 §5.1).
pub const PlaintextView = struct {
    content_type: ContentType,
    legacy_version: LegacyVersion,
    fragment: []const u8,
};

/// Pack content into a TLSPlaintext record. Caller owns the returned buffer.
pub fn encodePlaintext(allocator: std.mem.Allocator, content_type: ContentType, fragment: []const u8) ![]u8 {
    if (fragment.len > max_plaintext_fragment) return RecordError.FragmentTooLarge;
    const header_len: usize = 5;
    var out = try allocator.alloc(u8, header_len + fragment.len);
    out[0] = @intFromEnum(content_type);
    // RFC 8446 mandates the legacy record version 0x0303.
    out[1] = 0x03;
    out[2] = 0x03;
    const length: u16 = @intCast(fragment.len);
    out[3] = @intCast(length >> 8);
    out[4] = @intCast(length & 0xff);
    @memcpy(out[header_len..], fragment);
    return out;
}

/// Parse a TLSPlaintext record from `data`. Returned view references the
/// original slice; the caller is responsible for lifetime management.
pub fn decodePlaintext(data: []const u8) RecordError!PlaintextView {
    if (data.len < 5) return RecordError.RecordTooShort;
    const declared_len = (@as(u16, data[3]) << 8) | @as(u16, data[4]);
    const total_len: usize = 5 + declared_len;
    if (data.len != total_len) return RecordError.LengthMismatch;
    const ct = try parseContentType(data[0]);
    const version = try parseLegacyVersion(data[1], data[2]);
    const fragment = data[5..total_len];
    return PlaintextView{
        .content_type = ct,
        .legacy_version = version,
        .fragment = fragment,
    };
}

/// TLSInnerPlaintext structure (RFC 8446 §5.4) after unpacking.
pub const InnerPlaintext = struct {
    content_type: ContentType,
    content: []const u8,
    padding_len: usize,
};

/// Encode content + padding into a TLSInnerPlaintext buffer (RFC 8446 §5.4).
pub fn packInnerPlaintext(allocator: std.mem.Allocator, content_type: ContentType, content: []const u8, padding_len: usize) ![]u8 {
    if (padding_len > max_inner_padding) return RecordError.PaddingTooLarge;
    if (content.len + 1 + padding_len > max_plaintext_fragment) return RecordError.FragmentTooLarge;
    if (content_type == .invalid) return RecordError.InvalidContentType;

    const total_len = content.len + 1 + padding_len;
    var out = try allocator.alloc(u8, total_len);
    @memcpy(out[0..content.len], content);
    out[content.len] = @intFromEnum(content_type);
    if (padding_len > 0) {
        @memset(out[content.len + 1 ..], 0);
    }
    return out;
}

/// Recover content, content type, and padding count from a TLSInnerPlaintext
/// buffer. The returned slices borrow from the provided `buffer`.
pub fn unpackInnerPlaintext(buffer: []const u8) RecordError!InnerPlaintext {
    if (buffer.len == 0) return RecordError.MissingContentType;

    var idx = buffer.len;
    var pad: usize = 0;
    while (idx > 0 and buffer[idx - 1] == 0) : (idx -= 1) {
        pad += 1;
    }
    if (idx == 0) return RecordError.MissingContentType;
    const ct_byte = buffer[idx - 1];
    const ct = try parseContentType(ct_byte);
    const content = buffer[0 .. idx - 1];
    return InnerPlaintext{
        .content_type = ct,
        .content = content,
        .padding_len = pad,
    };
}

fn parseContentType(byte: u8) RecordError!ContentType {
    return switch (byte) {
        @intFromEnum(ContentType.change_cipher_spec) => .change_cipher_spec,
        @intFromEnum(ContentType.alert) => .alert,
        @intFromEnum(ContentType.handshake) => .handshake,
        @intFromEnum(ContentType.application_data) => .application_data,
        @intFromEnum(ContentType.heartbeat) => .heartbeat,
        else => RecordError.InvalidContentType,
    };
}

fn parseLegacyVersion(hi: u8, lo: u8) RecordError!LegacyVersion {
    const value: u16 = (@as(u16, hi) << 8) | @as(u16, lo);
    return switch (value) {
        @intFromEnum(LegacyVersion.ssl_3_0) => .ssl_3_0,
        @intFromEnum(LegacyVersion.tls_1_0) => .tls_1_0,
        @intFromEnum(LegacyVersion.tls_1_1) => .tls_1_1,
        @intFromEnum(LegacyVersion.tls_1_2) => .tls_1_2,
        else => RecordError.UnsupportedLegacyVersion,
    };
}

/// TLS 1.3 authenticated encryption suites supported by QUIC (RFC 8446 §5.1).
pub const CipherSuite = enum {
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
};

const SuiteSpec = struct {
    key_len: usize,
    nonce_len: usize,
    tag_len: usize,
    default_limits: AeadUsageLimits,
};

const MaxNonceLength = @max(@max(Aes128Gcm.nonce_length, Aes256Gcm.nonce_length), ChaCha20Poly1305.nonce_length);
const MaxTagLength = @max(@max(Aes128Gcm.tag_length, Aes256Gcm.tag_length), ChaCha20Poly1305.tag_length);

/// RFC 8446 §5.5 confidentiality/integrity limits (records before rekey).
pub const AeadUsageLimits = struct {
    confidentiality: u64,
    integrity: u64,
};

/// AEAD context for TLS 1.3 records (RFC 8446 §5.2–§5.5).
pub const AeadCipher = struct {
    suite: CipherSuite,
    key_material: KeyMaterial,
    base_iv: [MaxNonceLength]u8,
    nonce_len: u8,
    tag_len: u8,
    usage: Usage,

    const Usage = struct {
        encrypted: u64,
        auth_failures: u64,
        limits: AeadUsageLimits,
    };

    const KeyMaterial = union(enum) {
        aes128: [Aes128Gcm.key_length]u8,
        aes256: [Aes256Gcm.key_length]u8,
        chacha20: [ChaCha20Poly1305.key_length]u8,
    };

    /// Initialize an AEAD context with the traffic key/IV pair for one epoch.
    pub fn init(
        suite: CipherSuite,
        key: []const u8,
        iv: []const u8,
        limits_override: ?AeadUsageLimits,
    ) RecordError!AeadCipher {
        const spec = suiteSpec(suite);
        if (key.len != spec.key_len) return RecordError.InvalidKeyLength;
        if (iv.len != spec.nonce_len or spec.nonce_len < 8 or spec.nonce_len > MaxNonceLength)
            return RecordError.InvalidIvLength;

        const limits = limits_override orelse spec.default_limits;
        const key_material = switch (suite) {
            .TLS_AES_128_GCM_SHA256 => blk: {
                var arr: [Aes128Gcm.key_length]u8 = undefined;
                std.mem.copyForwards(u8, arr[0..], key[0..Aes128Gcm.key_length]);
                break :blk KeyMaterial{ .aes128 = arr };
            },
            .TLS_AES_256_GCM_SHA384 => blk: {
                var arr: [Aes256Gcm.key_length]u8 = undefined;
                std.mem.copyForwards(u8, arr[0..], key[0..Aes256Gcm.key_length]);
                break :blk KeyMaterial{ .aes256 = arr };
            },
            .TLS_CHACHA20_POLY1305_SHA256 => blk: {
                var arr: [ChaCha20Poly1305.key_length]u8 = undefined;
                std.mem.copyForwards(u8, arr[0..], key[0..ChaCha20Poly1305.key_length]);
                break :blk KeyMaterial{ .chacha20 = arr };
            },
        };

        var cipher = AeadCipher{
            .suite = suite,
            .key_material = key_material,
            .base_iv = [_]u8{0} ** MaxNonceLength,
            .nonce_len = @intCast(spec.nonce_len),
            .tag_len = @intCast(spec.tag_len),
            .usage = .{ .encrypted = 0, .auth_failures = 0, .limits = limits },
        };
        std.mem.copyForwards(u8, cipher.base_iv[0..spec.nonce_len], iv);
        return cipher;
    }

    /// Encrypt TLSInnerPlaintext into TLSCiphertext, appending the tag.
    pub fn seal(
        self: *AeadCipher,
        allocator: std.mem.Allocator,
        seq: u64,
        aad: []const u8,
        plaintext: []const u8,
    ) RecordError![]u8 {
        if (limitReached(self.usage.encrypted, self.usage.limits.confidentiality))
            return RecordError.AeadLimitExceeded;
        if (self.usage.encrypted == math.maxInt(u64))
            return RecordError.AeadLimitExceeded;

        const out = try allocator.alloc(u8, plaintext.len + self.tag_len);
        errdefer allocator.free(out);

        const ct = out[0..plaintext.len];
        const tag_slice = out[plaintext.len..];
        const tag_len: usize = @intCast(self.tag_len);
        var nonce_full = self.deriveNonce(seq);
        defer {
            const nonce_len: usize = @intCast(self.nonce_len);
            crypto.secureZero(u8, nonce_full[0..nonce_len]);
        }

        switch (self.key_material) {
            .aes128 => |key| {
                var nonce_arr: [Aes128Gcm.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..Aes128Gcm.nonce_length]);
                var tag_arr: [Aes128Gcm.tag_length]u8 = undefined;
                Aes128Gcm.encrypt(ct, &tag_arr, plaintext, aad, nonce_arr, key);
                std.mem.copyForwards(u8, tag_slice, tag_arr[0..tag_len]);
            },
            .aes256 => |key| {
                var nonce_arr: [Aes256Gcm.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..Aes256Gcm.nonce_length]);
                var tag_arr: [Aes256Gcm.tag_length]u8 = undefined;
                Aes256Gcm.encrypt(ct, &tag_arr, plaintext, aad, nonce_arr, key);
                std.mem.copyForwards(u8, tag_slice, tag_arr[0..tag_len]);
            },
            .chacha20 => |key| {
                var nonce_arr: [ChaCha20Poly1305.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..ChaCha20Poly1305.nonce_length]);
                var tag_arr: [ChaCha20Poly1305.tag_length]u8 = undefined;
                ChaCha20Poly1305.encrypt(ct, &tag_arr, plaintext, aad, nonce_arr, key);
                std.mem.copyForwards(u8, tag_slice, tag_arr[0..tag_len]);
            },
        }

        self.usage.encrypted += 1;
        return out;
    }

    /// Decrypt and authenticate a TLSCiphertext buffer.
    pub fn open(
        self: *AeadCipher,
        allocator: std.mem.Allocator,
        seq: u64,
        aad: []const u8,
        ciphertext: []const u8,
    ) RecordError![]u8 {
        if (ciphertext.len < self.tag_len) return RecordError.CiphertextTooShort;

        const ct_len = ciphertext.len - self.tag_len;
        const out = try allocator.alloc(u8, ct_len);
        errdefer allocator.free(out);

        const ct = ciphertext[0..ct_len];
        var tag_buf: [MaxTagLength]u8 = [_]u8{0} ** MaxTagLength;
        const tag_len: usize = @intCast(self.tag_len);
        std.mem.copyForwards(u8, tag_buf[0..tag_len], ciphertext[ct_len..]);
        var nonce_full = self.deriveNonce(seq);
        defer {
            const nonce_len: usize = @intCast(self.nonce_len);
            crypto.secureZero(u8, nonce_full[0..nonce_len]);
            crypto.secureZero(u8, tag_buf[0..tag_len]);
        }

        switch (self.key_material) {
            .aes128 => |key| {
                var nonce_arr: [Aes128Gcm.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..Aes128Gcm.nonce_length]);
                var tag_arr: [Aes128Gcm.tag_length]u8 = undefined;
                std.mem.copyForwards(u8, tag_arr[0..], tag_buf[0..Aes128Gcm.tag_length]);
                Aes128Gcm.decrypt(out, ct, tag_arr, aad, nonce_arr, key) catch |err| {
                    switch (err) {
                        AuthenticationError.AuthenticationFailed => return self.onAuthFailure(),
                    }
                };
            },
            .aes256 => |key| {
                var nonce_arr: [Aes256Gcm.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..Aes256Gcm.nonce_length]);
                var tag_arr: [Aes256Gcm.tag_length]u8 = undefined;
                std.mem.copyForwards(u8, tag_arr[0..], tag_buf[0..Aes256Gcm.tag_length]);
                Aes256Gcm.decrypt(out, ct, tag_arr, aad, nonce_arr, key) catch |err| {
                    switch (err) {
                        AuthenticationError.AuthenticationFailed => return self.onAuthFailure(),
                    }
                };
            },
            .chacha20 => |key| {
                var nonce_arr: [ChaCha20Poly1305.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..ChaCha20Poly1305.nonce_length]);
                var tag_arr: [ChaCha20Poly1305.tag_length]u8 = undefined;
                std.mem.copyForwards(u8, tag_arr[0..], tag_buf[0..ChaCha20Poly1305.tag_length]);
                ChaCha20Poly1305.decrypt(out, ct, tag_arr, aad, nonce_arr, key) catch |err| {
                    switch (err) {
                        AuthenticationError.AuthenticationFailed => return self.onAuthFailure(),
                    }
                };
            },
        }

        return out;
    }

    /// Zero key material and reset per-direction usage counters.
    pub fn wipe(self: *AeadCipher) void {
        switch (self.key_material) {
            .aes128 => |*key| crypto.secureZero(u8, key.*[0..]),
            .aes256 => |*key| crypto.secureZero(u8, key.*[0..]),
            .chacha20 => |*key| crypto.secureZero(u8, key.*[0..]),
        }
        const nonce_len: usize = @intCast(self.nonce_len);
        crypto.secureZero(u8, self.base_iv[0..nonce_len]);
        const limits = self.usage.limits;
        self.usage = .{ .encrypted = 0, .auth_failures = 0, .limits = limits };
    }

    fn deriveNonce(self: *const AeadCipher, seq: u64) [MaxNonceLength]u8 {
        var tmp: [MaxNonceLength]u8 = [_]u8{0} ** MaxNonceLength;
        const nonce_len: usize = @intCast(self.nonce_len);
        // Safe: xorNonce validates lengths and copies the IV prior to XOR.
        xorNonce(tmp[0..nonce_len], self.base_iv[0..nonce_len], seq) catch unreachable;
        return tmp;
    }

    fn onAuthFailure(self: *AeadCipher) RecordError {
        if (self.usage.auth_failures == math.maxInt(u64))
            return RecordError.AeadLimitExceeded;
        self.usage.auth_failures += 1;
        if (limitExceeded(self.usage.auth_failures, self.usage.limits.integrity))
            return RecordError.AeadLimitExceeded;
        return RecordError.AuthenticationFailed;
    }
};

fn suiteSpec(suite: CipherSuite) SuiteSpec {
    return switch (suite) {
        .TLS_AES_128_GCM_SHA256 => .{
            .key_len = Aes128Gcm.key_length,
            .nonce_len = Aes128Gcm.nonce_length,
            .tag_len = Aes128Gcm.tag_length,
            .default_limits = .{
                .confidentiality = @as(u64, 1) << 24,
                .integrity = @as(u64, 1) << 36,
            },
        },
        .TLS_AES_256_GCM_SHA384 => .{
            .key_len = Aes256Gcm.key_length,
            .nonce_len = Aes256Gcm.nonce_length,
            .tag_len = Aes256Gcm.tag_length,
            .default_limits = .{
                .confidentiality = @as(u64, 1) << 24,
                .integrity = @as(u64, 1) << 36,
            },
        },
        .TLS_CHACHA20_POLY1305_SHA256 => .{
            .key_len = ChaCha20Poly1305.key_length,
            .nonce_len = ChaCha20Poly1305.nonce_length,
            .tag_len = ChaCha20Poly1305.tag_length,
            .default_limits = .{
                .confidentiality = @as(u64, 1) << 32,
                .integrity = @as(u64, 1) << 36,
            },
        },
    };
}

fn limitReached(count: u64, limit: u64) bool {
    return limit != 0 and count >= limit;
}

fn limitExceeded(count: u64, limit: u64) bool {
    return limit != 0 and count > limit;
}

/// Derive the per-record nonce by XORing the static IV with the sequence number (RFC 8446 §5.3).
pub fn xorNonce(out: []u8, base_iv: []const u8, seq: u64) RecordError!void {
    if (out.len != base_iv.len or out.len < 8) return RecordError.InvalidIvLength;
    std.mem.copyForwards(u8, out, base_iv);
    var seq_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_bytes, seq, .big);
    const offset = out.len - seq_bytes.len;
    for (seq_bytes, 0..) |byte, idx| {
        out[offset + idx] ^= byte;
    }
}

// ============================================================================
// TESTS - RFC 8446 §5 Record Layer
// ============================================================================

const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectEqualSlices = testing.expectEqualSlices;
const expectError = testing.expectError;

// RFC 8446 §5.1: TLSPlaintext encoding/decoding
test "RFC 8446 §5.1 - TLSPlaintext encode/decode round-trip" {
    const allocator = testing.allocator;
    const content = "Hello, TLS 1.3!";

    const encoded = try encodePlaintext(allocator, .handshake, content);
    defer allocator.free(encoded);

    // Verify header format
    try expectEqual(@as(u8, @intFromEnum(ContentType.handshake)), encoded[0]);
    try expectEqual(@as(u8, 0x03), encoded[1]); // TLS 1.2 legacy version hi
    try expectEqual(@as(u8, 0x03), encoded[2]); // TLS 1.2 legacy version lo
    try expectEqual(@as(u16, content.len), (@as(u16, encoded[3]) << 8) | @as(u16, encoded[4]));

    const decoded = try decodePlaintext(encoded);
    try expectEqual(ContentType.handshake, decoded.content_type);
    try expectEqual(LegacyVersion.tls_1_2, decoded.legacy_version);
    try expectEqualSlices(u8, content, decoded.fragment);
}

// RFC 8446 §5.1: Maximum fragment size enforcement
test "RFC 8446 §5.1 - TLSPlaintext maximum fragment size" {
    const allocator = testing.allocator;
    var large_fragment: [max_plaintext_fragment]u8 = undefined;
    @memset(&large_fragment, 0xAA);

    // Exactly at the limit should succeed
    const encoded = try encodePlaintext(allocator, .application_data, &large_fragment);
    defer allocator.free(encoded);
    try expectEqual(5 + max_plaintext_fragment, encoded.len);

    // One byte over should fail
    var oversized: [max_plaintext_fragment + 1]u8 = undefined;
    try expectError(RecordError.FragmentTooLarge, encodePlaintext(allocator, .application_data, &oversized));
}

// RFC 8446 §5.1: Empty fragment is valid
test "RFC 8446 §5.1 - TLSPlaintext with empty fragment" {
    const allocator = testing.allocator;
    const encoded = try encodePlaintext(allocator, .alert, &[_]u8{});
    defer allocator.free(encoded);

    try expectEqual(@as(usize, 5), encoded.len);
    const decoded = try decodePlaintext(encoded);
    try expectEqual(@as(usize, 0), decoded.fragment.len);
}

// RFC 8446 §5.1: Decode errors - truncated record
test "RFC 8446 §5.1 - TLSPlaintext decode truncated" {
    try expectError(RecordError.RecordTooShort, decodePlaintext(&[_]u8{22})); // Only 1 byte
    try expectError(RecordError.RecordTooShort, decodePlaintext(&[_]u8{ 22, 3, 3, 0 })); // 4 bytes
}

// RFC 8446 §5.1: Decode errors - length mismatch
test "RFC 8446 §5.1 - TLSPlaintext decode length mismatch" {
    // Claims 10 bytes but only provides 5
    const malformed = [_]u8{ 22, 3, 3, 0, 10, 1, 2, 3, 4, 5 };
    try expectError(RecordError.LengthMismatch, decodePlaintext(&malformed));
}

// RFC 8446 §5.4: TLSInnerPlaintext pack/unpack round-trip
test "RFC 8446 §5.4 - TLSInnerPlaintext pack/unpack round-trip" {
    const allocator = testing.allocator;
    const content = "Handshake message";

    // Pack with no padding
    const inner_plaintext = try packInnerPlaintext(allocator, .handshake, content, 0);
    defer allocator.free(inner_plaintext);

    try expectEqual(content.len + 1, inner_plaintext.len);
    try expectEqual(@as(u8, @intFromEnum(ContentType.handshake)), inner_plaintext[inner_plaintext.len - 1]);

    // Unpack
    const unpacked = try unpackInnerPlaintext(inner_plaintext);
    try expectEqual(ContentType.handshake, unpacked.content_type);
    try expectEqualSlices(u8, content, unpacked.content);
    try expectEqual(@as(usize, 0), unpacked.padding_len);
}

// RFC 8446 §5.4: TLSInnerPlaintext with padding
test "RFC 8446 §5.4 - TLSInnerPlaintext with padding" {
    const allocator = testing.allocator;
    const content = "Short";
    const padding_len: usize = 10;

    const inner_plaintext = try packInnerPlaintext(allocator, .application_data, content, padding_len);
    defer allocator.free(inner_plaintext);

    try expectEqual(content.len + 1 + padding_len, inner_plaintext.len);

    // Verify padding is zeros
    for (inner_plaintext[content.len + 1 ..]) |byte| {
        try expectEqual(@as(u8, 0), byte);
    }

    const unpacked = try unpackInnerPlaintext(inner_plaintext);
    try expectEqual(ContentType.application_data, unpacked.content_type);
    try expectEqualSlices(u8, content, unpacked.content);
    try expectEqual(padding_len, unpacked.padding_len);
}

// RFC 8446 §5.4: Invalid content type
test "RFC 8446 §5.4 - TLSInnerPlaintext invalid content type" {
    const allocator = testing.allocator;
    try expectError(RecordError.InvalidContentType, packInnerPlaintext(allocator, .invalid, "test", 0));
}

// RFC 8446 §5.4: Empty TLSInnerPlaintext error
test "RFC 8446 §5.4 - TLSInnerPlaintext empty buffer" {
    try expectError(RecordError.MissingContentType, unpackInnerPlaintext(&[_]u8{}));
}

// RFC 8446 §5.4: All-zeros buffer (no content type)
test "RFC 8446 §5.4 - TLSInnerPlaintext all zeros" {
    const all_zeros = [_]u8{0} ** 10;
    try expectError(RecordError.MissingContentType, unpackInnerPlaintext(&all_zeros));
}

// RFC 8446 §5.3: Nonce derivation via XOR
test "RFC 8446 §5.3 - xorNonce basic functionality" {
    const base_iv: [12]u8 = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    var nonce: [12]u8 = undefined;
    const seq: u64 = 0x0000000000000001;

    try xorNonce(&nonce, &base_iv, seq);

    // Verify XOR happened in the last 8 bytes
    try expectEqual(base_iv[0], nonce[0]); // First 4 bytes unchanged
    try expectEqual(base_iv[1], nonce[1]);
    try expectEqual(base_iv[2], nonce[2]);
    try expectEqual(base_iv[3], nonce[3]);

    // Last byte should be base_iv[11] ^ 0x01
    try expectEqual(base_iv[11] ^ 0x01, nonce[11]);
}

// RFC 8446 §5.3: Nonce derivation - sequence number is big-endian
test "RFC 8446 §5.3 - xorNonce sequence number endianness" {
    const base_iv: [12]u8 = [_]u8{0} ** 12;
    var nonce: [12]u8 = undefined;
    const seq: u64 = 0x0102030405060708;

    try xorNonce(&nonce, &base_iv, seq);

    // Verify big-endian encoding in last 8 bytes
    try expectEqual(@as(u8, 0x01), nonce[4]);
    try expectEqual(@as(u8, 0x02), nonce[5]);
    try expectEqual(@as(u8, 0x03), nonce[6]);
    try expectEqual(@as(u8, 0x04), nonce[7]);
    try expectEqual(@as(u8, 0x05), nonce[8]);
    try expectEqual(@as(u8, 0x06), nonce[9]);
    try expectEqual(@as(u8, 0x07), nonce[10]);
    try expectEqual(@as(u8, 0x08), nonce[11]);
}

// RFC 8446 §5.3: Nonce length validation
test "RFC 8446 §5.3 - xorNonce length validation" {
    const base_iv: [12]u8 = [_]u8{0} ** 12;
    var short_nonce: [7]u8 = undefined;

    // Nonce must be at least 8 bytes
    try expectError(RecordError.InvalidIvLength, xorNonce(&short_nonce, &base_iv, 0));
}

// RFC 8446 §5.2: AEAD AES-128-GCM seal/open round-trip
test "RFC 8446 §5.2 - AES-128-GCM seal/open round-trip" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x00} ** 16;
    const iv: [12]u8 = [_]u8{0x01} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "Attack at dawn!";
    const aad = "additional auth data";
    const seq: u64 = 42;

    // Seal
    const ciphertext = try cipher.seal(allocator, seq, aad, plaintext);
    defer allocator.free(ciphertext);

    try expect(ciphertext.len == plaintext.len + 16); // 16-byte tag

    // Open
    const recovered = try cipher.open(allocator, seq, aad, ciphertext);
    defer allocator.free(recovered);

    try expectEqualSlices(u8, plaintext, recovered);
}

// RFC 8446 §5.2: AEAD AES-256-GCM seal/open round-trip
test "RFC 8446 §5.2 - AES-256-GCM seal/open round-trip" {
    const allocator = testing.allocator;
    const key: [32]u8 = [_]u8{0xAA} ** 32;
    const iv: [12]u8 = [_]u8{0xBB} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_256_GCM_SHA384, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "The secret message.";
    const aad = "TLS 1.3 AAD";
    const seq: u64 = 100;

    const ciphertext = try cipher.seal(allocator, seq, aad, plaintext);
    defer allocator.free(ciphertext);

    try expect(ciphertext.len == plaintext.len + 16);

    const recovered = try cipher.open(allocator, seq, aad, ciphertext);
    defer allocator.free(recovered);

    try expectEqualSlices(u8, plaintext, recovered);
}

// RFC 8446 §5.2: AEAD ChaCha20-Poly1305 seal/open round-trip
test "RFC 8446 §5.2 - ChaCha20-Poly1305 seal/open round-trip" {
    const allocator = testing.allocator;
    const key: [32]u8 = [_]u8{0x55} ** 32;
    const iv: [12]u8 = [_]u8{0x66} ** 12;

    var cipher = try AeadCipher.init(.TLS_CHACHA20_POLY1305_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "ChaCha20-Poly1305 test vector";
    const aad = "Associated data";
    const seq: u64 = 255;

    const ciphertext = try cipher.seal(allocator, seq, aad, plaintext);
    defer allocator.free(ciphertext);

    try expect(ciphertext.len == plaintext.len + 16);

    const recovered = try cipher.open(allocator, seq, aad, ciphertext);
    defer allocator.free(recovered);

    try expectEqualSlices(u8, plaintext, recovered);
}

// RFC 8446 §5.2: AEAD authentication failure detection
test "RFC 8446 §5.2 - AEAD authentication failure" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x00} ** 16;
    const iv: [12]u8 = [_]u8{0x01} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "Authentic message";
    const aad = "AAD";

    const ciphertext = try cipher.seal(allocator, 0, aad, plaintext);
    defer allocator.free(ciphertext);

    // Tamper with ciphertext
    var tampered = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(tampered);
    @memcpy(tampered, ciphertext);
    tampered[0] ^= 0xFF;

    // Should fail authentication
    try expectError(RecordError.AuthenticationFailed, cipher.open(allocator, 0, aad, tampered));
}

// RFC 8446 §5.2: Different sequence numbers produce different ciphertexts
test "RFC 8446 §5.2 - different sequence numbers" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x42} ** 16;
    const iv: [12]u8 = [_]u8{0x24} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "Same plaintext";
    const aad = "Same AAD";

    const ct1 = try cipher.seal(allocator, 1, aad, plaintext);
    defer allocator.free(ct1);

    const ct2 = try cipher.seal(allocator, 2, aad, plaintext);
    defer allocator.free(ct2);

    // Different sequence numbers should produce different ciphertexts
    try expect(!std.mem.eql(u8, ct1, ct2));
}

// RFC 8446 §5.2: Wrong sequence number fails decryption
test "RFC 8446 §5.2 - wrong sequence number" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x77} ** 16;
    const iv: [12]u8 = [_]u8{0x88} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "Message";
    const aad = "AAD";

    const ciphertext = try cipher.seal(allocator, 5, aad, plaintext);
    defer allocator.free(ciphertext);

    // Try to decrypt with wrong sequence number
    try expectError(RecordError.AuthenticationFailed, cipher.open(allocator, 6, aad, ciphertext));
}

// RFC 8446 §5.5: AEAD usage limits - confidentiality
test "RFC 8446 §5.5 - AEAD confidentiality limit" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x11} ** 16;
    const iv: [12]u8 = [_]u8{0x22} ** 12;

    // Set a low limit for testing
    const limits = AeadUsageLimits{ .confidentiality = 5, .integrity = 100 };
    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, limits);
    defer cipher.wipe();

    const plaintext = "test";
    const aad = "";

    // Encrypt 5 times (should succeed)
    var i: u64 = 0;
    while (i < 5) : (i += 1) {
        const ct = try cipher.seal(allocator, i, aad, plaintext);
        allocator.free(ct);
    }

    // 6th encryption should fail
    try expectError(RecordError.AeadLimitExceeded, cipher.seal(allocator, 5, aad, plaintext));
}

// RFC 8446 §5.5: AEAD usage limits - integrity
test "RFC 8446 §5.5 - AEAD integrity limit" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x33} ** 16;
    const iv: [12]u8 = [_]u8{0x44} ** 12;

    const limits = AeadUsageLimits{ .confidentiality = 100, .integrity = 3 };
    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, limits);
    defer cipher.wipe();

    const plaintext = "authentic";
    const aad = "data";

    const ciphertext = try cipher.seal(allocator, 0, aad, plaintext);
    defer allocator.free(ciphertext);

    // Tamper to cause auth failures
    var tampered = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(tampered);

    // Fail 3 times (should succeed with error)
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        @memcpy(tampered, ciphertext);
        tampered[0] ^= @intCast(i + 1);
        try expectError(RecordError.AuthenticationFailed, cipher.open(allocator, 0, aad, tampered));
    }

    // 4th failure should trigger limit
    @memcpy(tampered, ciphertext);
    tampered[0] ^= 0xAA;
    try expectError(RecordError.AeadLimitExceeded, cipher.open(allocator, 0, aad, tampered));
}

// AEAD init errors
test "AEAD init - invalid key length" {
    const short_key: [8]u8 = [_]u8{0} ** 8;
    const iv: [12]u8 = [_]u8{0} ** 12;

    try expectError(RecordError.InvalidKeyLength, AeadCipher.init(.TLS_AES_128_GCM_SHA256, &short_key, &iv, null));
}

test "AEAD init - invalid IV length" {
    const key: [16]u8 = [_]u8{0} ** 16;
    const short_iv: [7]u8 = [_]u8{0} ** 7;

    try expectError(RecordError.InvalidIvLength, AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &short_iv, null));
}

// AEAD wipe test
test "AEAD wipe - clears key material" {
    const key: [16]u8 = [_]u8{0xAB} ** 16;
    const iv: [12]u8 = [_]u8{0xCD} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);

    // Verify usage is tracked
    try expectEqual(@as(u64, 0), cipher.usage.encrypted);

    cipher.wipe();

    // After wipe, usage should reset
    try expectEqual(@as(u64, 0), cipher.usage.encrypted);
    try expectEqual(@as(u64, 0), cipher.usage.auth_failures);
}

// Content type parsing
test "ContentType parsing" {
    try expectEqual(ContentType.alert, try parseContentType(21));
    try expectEqual(ContentType.handshake, try parseContentType(22));
    try expectEqual(ContentType.application_data, try parseContentType(23));
    try expectError(RecordError.InvalidContentType, parseContentType(99));
}

// Legacy version parsing
test "LegacyVersion parsing" {
    try expectEqual(LegacyVersion.tls_1_2, try parseLegacyVersion(0x03, 0x03));
    try expectEqual(LegacyVersion.tls_1_0, try parseLegacyVersion(0x03, 0x01));
    try expectError(RecordError.UnsupportedLegacyVersion, parseLegacyVersion(0x03, 0x05));
}

// Empty plaintext
test "AEAD seal/open - empty plaintext" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x99} ** 16;
    const iv: [12]u8 = [_]u8{0x88} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "";
    const aad = "AAD";

    const ciphertext = try cipher.seal(allocator, 0, aad, plaintext);
    defer allocator.free(ciphertext);

    // Should only contain tag
    try expectEqual(@as(usize, 16), ciphertext.len);

    const recovered = try cipher.open(allocator, 0, aad, ciphertext);
    defer allocator.free(recovered);

    try expectEqual(@as(usize, 0), recovered.len);
}

// Ciphertext too short
test "AEAD open - ciphertext too short" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x77} ** 16;
    const iv: [12]u8 = [_]u8{0x66} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const short_ct = [_]u8{0x01, 0x02, 0x03}; // Less than 16 bytes (tag length)
    try expectError(RecordError.CiphertextTooShort, cipher.open(allocator, 0, "", &short_ct));
}
