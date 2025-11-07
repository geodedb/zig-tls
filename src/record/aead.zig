//! TLS 1.3 AEAD Operations
//!
//! Implements authenticated encryption with associated data (AEAD) per:
//! - RFC 8446 §5.2: Record Payload Protection
//! - RFC 8446 §5.3: Per-Record Nonce Derivation
//! - RFC 8446 §5.5: Limits on Key Usage
//! - RFC 5116: AEAD Interface
//!
//! ## Overview
//!
//! This module provides AEAD encryption and decryption primitives for TLS 1.3
//! record protection. It supports three cipher suites:
//! - AES-128-GCM-SHA256 (REQUIRED by RFC 8446)
//! - AES-256-GCM-SHA384
//! - ChaCha20-Poly1305-SHA256
//!
//! ## Nonce Derivation (RFC 8446 §5.3)
//!
//! Each record uses a unique nonce derived by XORing the base IV with the
//! sequence number:
//!
//! ```
//! nonce = base_iv XOR sequence_number
//! ```
//!
//! The sequence number is encoded as a big-endian u64 and XORed into the
//! rightmost bytes of the IV.
//!
//! ## Usage Limits (RFC 8446 §5.5)
//!
//! AEAD ciphers have confidentiality and integrity limits to prevent
//! security degradation:
//! - **Confidentiality**: Maximum records encrypted with one key
//! - **Integrity**: Maximum authentication failures tolerated
//!
//! When limits are reached, implementations MUST perform a key update.
//!
//! ## Security Considerations
//!
//! - Keys are zeroized after use via `AeadCipher.wipe()`
//! - Nonces are cleared from stack after operations
//! - Sequence numbers MUST be unique per key
//! - Authentication failures are tracked separately
//! - Constant-time tag comparison (provided by std.crypto.aead)

const std = @import("std");
const crypto = std.crypto;
const math = std.math;
const plaintext_mod = @import("plaintext.zig");

const AuthenticationError = crypto.errors.AuthenticationError;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const RecordError = plaintext_mod.RecordError;

/// TLS 1.3 AEAD cipher suites supported by this implementation.
///
/// These suites provide authenticated encryption with associated data (AEAD)
/// as required by RFC 8446 §5.2. All use 96-bit nonces and 128-bit tags per
/// RFC 5116. QUIC requires support for at least AES-128-GCM.
///
/// ## Cipher Suite Specifications
/// - TLS_AES_128_GCM_SHA256 (0x1301): AES-128-GCM with SHA-256 (REQUIRED)
/// - TLS_AES_256_GCM_SHA384 (0x1302): AES-256-GCM with SHA-384
/// - TLS_CHACHA20_POLY1305_SHA256 (0x1303): ChaCha20-Poly1305 with SHA-256
///
/// ## RFC References
/// - RFC 8446 §5.1 - TLS 1.3 cipher suites
/// - RFC 5116 - AEAD interface specification
/// - RFC 9001 §5 - QUIC packet protection uses same AEAD algorithms
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

/// AEAD usage limits for key lifetime management.
///
/// RFC 8446 §5.5 defines confidentiality and integrity limits to prevent
/// AEAD security degradation. When these limits are reached, implementations
/// MUST perform a key update to derive fresh keying material.
///
/// ## Limits
/// - `confidentiality`: Maximum records encrypted with this key (seal operations)
/// - `integrity`: Maximum authentication failures tolerated (failed open operations)
///
/// ## Default Limits (per RFC 8446 §5.5)
/// - AES-GCM: 2^24 records confidentiality, 2^36 integrity failures
/// - ChaCha20-Poly1305: 2^32 records confidentiality, 2^36 integrity failures
///
/// ## RFC References
/// - RFC 8446 §5.5 - Limits on Key Usage
/// - RFC 8446 §4.6.3 - KeyUpdate message for rekeying
pub const AeadUsageLimits = struct {
    confidentiality: u64,
    integrity: u64,
};

/// AEAD cipher context for TLS 1.3 record protection.
///
/// Encapsulates keying material, nonce state, and usage tracking for
/// authenticated encryption. Supports all TLS 1.3 AEAD algorithms:
/// AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
///
/// ## Lifecycle
/// 1. Initialize with `init()` providing key and IV from key schedule
/// 2. Encrypt records with `seal()` (increments sequence number)
/// 3. Decrypt records with `open()` (validates authentication tag)
/// 4. Monitor usage limits and perform key update when exceeded
/// 5. Zeroize with `wipe()` when discarding old keys
///
/// ## Security Considerations
/// - Keys are zeroized on `wipe()` to prevent memory disclosure
/// - Nonces are derived per-record and cleared after use
/// - Usage limits enforce RFC 8446 §5.5 security requirements
/// - Authentication failures are tracked separately from successful decryptions
///
/// ## RFC References
/// - RFC 8446 §5.2 - Record Payload Protection with AEAD
/// - RFC 8446 §5.3 - Per-Record Nonce derivation
/// - RFC 8446 §5.5 - Limits on Key Usage
/// - RFC 5116 - AEAD Interface
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

    /// Initialize AEAD cipher with traffic key and IV.
    ///
    /// Creates a new AEAD context from keying material derived via the TLS 1.3
    /// key schedule (typically from `key_schedule.deriveKeyIvHp()`). The key and
    /// IV lengths are validated against the cipher suite requirements.
    ///
    /// ## Parameters
    /// - `suite`: AEAD cipher suite to use (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
    /// - `key`: AEAD encryption key (length depends on suite: 16 or 32 bytes)
    /// - `iv`: Base IV for nonce derivation (12 bytes for all supported suites)
    /// - `limits_override`: Optional custom usage limits (uses RFC defaults if null)
    ///
    /// ## Returns
    /// Initialized AeadCipher ready for seal/open operations
    ///
    /// ## Errors
    /// - `InvalidKeyLength`: Key length doesn't match cipher suite
    /// - `InvalidIvLength`: IV length is not 12 bytes or outside valid range
    ///
    /// ## RFC References
    /// - RFC 8446 §5.3 - Per-record nonce uses static IV from key schedule
    /// - RFC 9001 §5.1 - Packet Protection Keys derivation
    /// - RFC 5116 - AEAD key and nonce length requirements
    ///
    /// ## Security Considerations
    /// The IV must be derived from the key schedule, never reused across
    /// different traffic secrets. Each record uses a unique nonce derived
    /// by XORing this base IV with the sequence number.
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

    /// Encrypt plaintext with AEAD and append authentication tag.
    ///
    /// Performs AEAD encryption (RFC 5116) with the following steps:
    /// 1. Check confidentiality usage limit (RFC 8446 §5.5)
    /// 2. Derive per-record nonce via XOR with sequence number (RFC 8446 §5.3)
    /// 3. Encrypt plaintext and compute authentication tag
    /// 4. Zeroize nonce from stack
    /// 5. Increment encryption counter
    ///
    /// ## Parameters
    /// - `self`: AEAD cipher context (mutated to track usage)
    /// - `allocator`: Memory allocator for output buffer
    /// - `seq`: Record sequence number (used for nonce derivation, per-direction)
    /// - `aad`: Additional authenticated data (TLS record header for TLS, QUIC header for QUIC)
    /// - `plaintext`: Data to encrypt (typically TLSInnerPlaintext)
    ///
    /// ## Returns
    /// Newly allocated buffer: ciphertext || tag. Caller owns the buffer.
    /// Length = plaintext.len + tag_len (16 bytes for all supported suites)
    ///
    /// ## Errors
    /// - `AeadLimitExceeded`: Confidentiality limit reached, key update required
    /// - `OutOfMemory`: Allocation failed
    ///
    /// ## RFC References
    /// - RFC 8446 §5.2 - AEAD-Encrypt(write_key, nonce, additional_data, plaintext)
    /// - RFC 8446 §5.3 - Nonce is base_iv XOR sequence_number (big-endian)
    /// - RFC 8446 §5.5 - Confidentiality limits must be enforced
    /// - RFC 5116 - AEAD encryption interface
    ///
    /// ## Security Considerations
    /// - Sequence number MUST be unique for each record with the same key
    /// - Nonce is zeroized after encryption to prevent stack disclosure
    /// - Caller must not reuse the same (key, nonce) pair
    pub fn seal(
        self: *AeadCipher,
        allocator: std.mem.Allocator,
        seq: u64,
        aad: []const u8,
        plaintext: []const u8,
    ) RecordError![]u8 {
        // RFC 8446 §5.5 - Check confidentiality limit before encrypting
        if (limitReached(self.usage.encrypted, self.usage.limits.confidentiality))
            return RecordError.AeadLimitExceeded;
        if (self.usage.encrypted == math.maxInt(u64))
            return RecordError.AeadLimitExceeded;

        const out = try allocator.alloc(u8, plaintext.len + self.tag_len);
        errdefer allocator.free(out);

        const ct = out[0..plaintext.len];
        const tag_slice = out[plaintext.len..];
        const tag_len: usize = @intCast(self.tag_len);
        // RFC 8446 §5.3 - Derive per-record nonce: base_iv XOR seq
        var nonce_full = self.deriveNonce(seq);
        defer {
            // Security: Zeroize nonce after use
            const nonce_len: usize = @intCast(self.nonce_len);
            crypto.secureZero(u8, nonce_full[0..nonce_len]);
        }

        // RFC 5116 - AEAD encryption: ciphertext || tag = AEAD-Encrypt(key, nonce, plaintext, aad)
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

        // RFC 8446 §5.5 - Track successful encryption for usage limits
        self.usage.encrypted += 1;
        return out;
    }

    /// Decrypt and authenticate AEAD-protected ciphertext.
    ///
    /// Performs AEAD decryption (RFC 5116) with the following steps:
    /// 1. Validate ciphertext length (must include tag)
    /// 2. Derive per-record nonce via XOR with sequence number (RFC 8446 §5.3)
    /// 3. Decrypt ciphertext and verify authentication tag
    /// 4. Zeroize nonce and tag from stack
    /// 5. Track authentication failures for integrity limits
    ///
    /// ## Parameters
    /// - `self`: AEAD cipher context (mutated to track auth failures)
    /// - `allocator`: Memory allocator for output buffer
    /// - `seq`: Record sequence number (must match value used in seal)
    /// - `aad`: Additional authenticated data (must match value used in seal)
    /// - `ciphertext`: Encrypted data with appended tag (ciphertext || tag)
    ///
    /// ## Returns
    /// Newly allocated plaintext buffer. Caller owns the buffer.
    /// Length = ciphertext.len - tag_len
    ///
    /// ## Errors
    /// - `CiphertextTooShort`: Buffer is shorter than tag length
    /// - `AuthenticationFailed`: Tag verification failed (tampering or wrong key/nonce/AAD)
    /// - `AeadLimitExceeded`: Integrity limit reached after too many auth failures
    /// - `OutOfMemory`: Allocation failed
    ///
    /// ## RFC References
    /// - RFC 8446 §5.2 - AEAD-Decrypt(write_key, nonce, additional_data, ciphertext)
    /// - RFC 8446 §5.3 - Nonce is base_iv XOR sequence_number (big-endian)
    /// - RFC 8446 §5.5 - Integrity limits on authentication failures
    /// - RFC 5116 - AEAD decryption interface
    ///
    /// ## Security Considerations
    /// - Authentication failures indicate tampering or implementation bugs
    /// - Too many failures trigger AeadLimitExceeded per RFC 8446 §5.5
    /// - Tag comparison is constant-time (provided by std.crypto.aead)
    /// - Plaintext is NOT returned if authentication fails
    pub fn open(
        self: *AeadCipher,
        allocator: std.mem.Allocator,
        seq: u64,
        aad: []const u8,
        ciphertext: []const u8,
    ) RecordError![]u8 {
        // RFC 5116 - Ciphertext must include authentication tag
        if (ciphertext.len < self.tag_len) return RecordError.CiphertextTooShort;

        const ct_len = ciphertext.len - self.tag_len;
        const out = try allocator.alloc(u8, ct_len);
        errdefer allocator.free(out);

        const ct = ciphertext[0..ct_len];
        var tag_buf: [MaxTagLength]u8 = [_]u8{0} ** MaxTagLength;
        const tag_len: usize = @intCast(self.tag_len);
        std.mem.copyForwards(u8, tag_buf[0..tag_len], ciphertext[ct_len..]);
        // RFC 8446 §5.3 - Derive per-record nonce: base_iv XOR seq
        var nonce_full = self.deriveNonce(seq);
        defer {
            // Security: Zeroize nonce and tag after use
            const nonce_len: usize = @intCast(self.nonce_len);
            crypto.secureZero(u8, nonce_full[0..nonce_len]);
            crypto.secureZero(u8, tag_buf[0..tag_len]);
        }

        // RFC 5116 - AEAD decryption: plaintext = AEAD-Decrypt(key, nonce, ciphertext, tag, aad)
        switch (self.key_material) {
            .aes128 => |key| {
                var nonce_arr: [Aes128Gcm.nonce_length]u8 = undefined;
                std.mem.copyForwards(u8, nonce_arr[0..], nonce_full[0..Aes128Gcm.nonce_length]);
                var tag_arr: [Aes128Gcm.tag_length]u8 = undefined;
                std.mem.copyForwards(u8, tag_arr[0..], tag_buf[0..Aes128Gcm.tag_length]);
                Aes128Gcm.decrypt(out, ct, tag_arr, aad, nonce_arr, key) catch |err| {
                    switch (err) {
                        // RFC 8446 §5.2 - Authentication failure indicates tampering
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

    /// Zeroize key material and reset usage counters.
    ///
    /// Securely erases AEAD keys and IV from memory to prevent disclosure after
    /// the keys are no longer needed (e.g., after key update or connection close).
    /// Resets encryption and authentication failure counters while preserving limits.
    ///
    /// ## RFC References
    /// - RFC 8446 §4.6.3 - KeyUpdate causes old keys to be discarded
    ///
    /// ## Security Considerations
    /// Call this function when:
    /// - Performing a key update (old keys no longer needed)
    /// - Closing a connection (all keys discarded)
    /// - Switching to a new encryption level in QUIC
    ///
    /// Uses `crypto.secureZero()` to prevent compiler optimizations from
    /// removing the zeroization.
    pub fn wipe(self: *AeadCipher) void {
        // Security: Zeroize key material to prevent memory disclosure
        switch (self.key_material) {
            .aes128 => |*key| crypto.secureZero(u8, key.*[0..]),
            .aes256 => |*key| crypto.secureZero(u8, key.*[0..]),
            .chacha20 => |*key| crypto.secureZero(u8, key.*[0..]),
        }
        // Security: Zeroize base IV
        const nonce_len: usize = @intCast(self.nonce_len);
        crypto.secureZero(u8, self.base_iv[0..nonce_len]);
        // Reset usage counters but preserve limits
        const limits = self.usage.limits;
        self.usage = .{ .encrypted = 0, .auth_failures = 0, .limits = limits };
    }

    /// Derive per-record nonce from base IV and sequence number (RFC 8446 §5.3).
    ///
    /// Computes nonce = base_iv XOR sequence_number (padded as big-endian u64).
    /// This ensures each record encrypted with the same key uses a unique nonce.
    ///
    /// ## Parameters
    /// - `seq`: Record sequence number (per-direction counter)
    ///
    /// ## Returns
    /// Derived nonce (12 bytes for all supported suites)
    ///
    /// ## RFC References
    /// - RFC 8446 §5.3 - Per-Record Nonce construction
    fn deriveNonce(self: *const AeadCipher, seq: u64) [MaxNonceLength]u8 {
        var tmp: [MaxNonceLength]u8 = [_]u8{0} ** MaxNonceLength;
        const nonce_len: usize = @intCast(self.nonce_len);
        // RFC 8446 §5.3 - XOR base_iv with padded sequence number
        xorNonce(tmp[0..nonce_len], self.base_iv[0..nonce_len], seq) catch unreachable;
        return tmp;
    }

    /// Track authentication failure and check integrity limit (RFC 8446 §5.5).
    ///
    /// Increments the authentication failure counter and returns AeadLimitExceeded
    /// if the integrity limit is reached. This prevents attackers from repeatedly
    /// attempting to forge authenticated records.
    ///
    /// ## RFC References
    /// - RFC 8446 §5.5 - Integrity limits on authentication failures
    fn onAuthFailure(self: *AeadCipher) RecordError {
        if (self.usage.auth_failures == math.maxInt(u64))
            return RecordError.AeadLimitExceeded;
        // RFC 8446 §5.5 - Track authentication failures
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

/// Derive per-record nonce by XORing base IV with sequence number.
///
/// Implements RFC 8446 §5.3 nonce construction for AEAD operations:
///
/// ```
/// The 64-bit record sequence number is encoded in network byte order
/// and padded to the left with zeros to the IV length. The padded
/// sequence number is XORed with the static IV to form the nonce.
/// ```
///
/// This ensures that each record encrypted with the same key uses a unique
/// nonce, which is critical for AEAD security.
///
/// ## Parameters
/// - `out`: Output buffer for derived nonce (modified in-place)
/// - `base_iv`: Static IV from key schedule (typically 12 bytes)
/// - `seq`: Record sequence number (per-direction, starts at 0)
///
/// ## Errors
/// - `InvalidIvLength`: out.len != base_iv.len or length < 8 bytes
///
/// ## RFC References
/// - RFC 8446 §5.3 - Per-Record Nonce construction
/// - RFC 9001 §5.3 - QUIC uses same nonce derivation for packet protection
///
/// ## Algorithm
/// 1. Copy base_iv to out
/// 2. Encode seq as big-endian u64
/// 3. Pad seq to IV length (zeros on left)
/// 4. XOR the last 8 bytes of out with seq
///
/// ## Security Considerations
/// - Sequence numbers MUST be unique per key (never rewind or reuse)
/// - Sequence number overflow requires key update before wrapping
/// - Nonce uniqueness is critical for AEAD security
pub fn xorNonce(out: []u8, base_iv: []const u8, seq: u64) RecordError!void {
    // RFC 8446 §5.3 - IV must be at least 8 bytes to accommodate sequence number
    if (out.len != base_iv.len or out.len < 8) return RecordError.InvalidIvLength;
    // RFC 8446 §5.3 - Start with static IV
    std.mem.copyForwards(u8, out, base_iv);
    // RFC 8446 §5.3 - Encode sequence number as big-endian u64
    var seq_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_bytes, seq, .big);
    // RFC 8446 §5.3 - XOR sequence number into last 8 bytes of nonce
    const offset = out.len - seq_bytes.len;
    for (seq_bytes, 0..) |byte, idx| {
        out[offset + idx] ^= byte;
    }
}
