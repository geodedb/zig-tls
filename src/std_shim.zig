// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! CANONICAL FILE — copied verbatim into each consumer's src/ for the
//! NON-fips path (alongside policy.zig). Imports ONLY `std` + the local
//! sibling `policy.zig` (`@import("policy.zig")`), so a non-fips build
//! needs NO `fips` dependency, NO OpenSSL, NO @cImport.
//!
//! std.crypto-backed backend mirroring the fips backend's public surface
//! EXACTLY (Hash/Mac/Kdf incl. hkdfExpand, Aead, Sig, Kem incl. the
//! pinned Kem.EncapResult, Csprng, assertActive). RSA and all PQC
//! (ML-DSA/SLH-DSA, ML-KEM + hybrids) are fips-only and return
//! error.Unsupported here.
const std = @import("std");
pub const policy = @import("policy.zig");

fn randomBytes(out: []u8) error{OpensslFailure}!void {
    // Non-fips shim CSPRNG: fresh OS entropy via std.Io.randomSecure, which
    // picks the platform source per target: getrandom(2) on Linux,
    // arc4random_buf on macOS/BSD, the \Device\CNG kernel RNG on Windows.
    // It never falls back to a process-local PRNG; any failure is returned
    // and mapped here to OpensslFailure (fail closed). The global
    // single-threaded Io is used only for this call, which std documents
    // as thread-safe (the cached Windows CNG handle is mutex-guarded).
    // The FIPS backend uses the validated DRBG instead (src/csprng.zig).
    std.Io.Threaded.global_single_threaded.io().randomSecure(out) catch return error.OpensslFailure;
}

pub const Hash = struct {
    pub const Error = error{ Unsupported, OpensslFailure };
    pub fn digest(alg: policy.Hash, msg: []const u8, out: []u8) Error!usize {
        switch (alg) {
            .sha256 => return one(std.crypto.hash.sha2.Sha256, msg, out),
            .sha384 => return one(std.crypto.hash.sha2.Sha384, msg, out),
            .sha512 => return one(std.crypto.hash.sha2.Sha512, msg, out),
            .sha3_256 => return one(std.crypto.hash.sha3.Sha3_256, msg, out),
            .sha3_384 => return one(std.crypto.hash.sha3.Sha3_384, msg, out),
            .sha3_512 => return one(std.crypto.hash.sha3.Sha3_512, msg, out),
        }
    }
    fn one(comptime H: type, msg: []const u8, out: []u8) Error!usize {
        var d: [H.digest_length]u8 = undefined;
        H.hash(msg, &d, .{});
        if (out.len < d.len) return error.OpensslFailure;
        @memcpy(out[0..d.len], &d);
        return d.len;
    }

    /// Streaming / incremental digest over std.crypto's incremental hash
    /// state. Public surface mirrors the fips backend's `Hash.Stream`
    /// EXACTLY (init/update/final/clone/deinit), so a consumer can route
    /// incremental hashing (TLS 1.3 transcript, DNSSEC canonical hashing)
    /// through the seam unchanged across -Dfips.
    ///
    /// `clone` is a by-value copy of the running state (std hash states
    /// are plain structs), producing a fully independent Stream. `deinit`
    /// is a no-op (no heap state) but is provided for API parity with the
    /// OpenSSL backend, which DOES own heap state.
    pub const Stream = struct {
        const Sha256 = std.crypto.hash.sha2.Sha256;
        const Sha384 = std.crypto.hash.sha2.Sha384;
        const Sha512 = std.crypto.hash.sha2.Sha512;
        const Sha3_256 = std.crypto.hash.sha3.Sha3_256;
        const Sha3_384 = std.crypto.hash.sha3.Sha3_384;
        const Sha3_512 = std.crypto.hash.sha3.Sha3_512;

        state: union(enum) {
            sha256: Sha256,
            sha384: Sha384,
            sha512: Sha512,
            sha3_256: Sha3_256,
            sha3_384: Sha3_384,
            sha3_512: Sha3_512,
        },

        pub fn init(alg: policy.Hash) Error!Stream {
            return .{ .state = switch (alg) {
                .sha256 => .{ .sha256 = Sha256.init(.{}) },
                .sha384 => .{ .sha384 = Sha384.init(.{}) },
                .sha512 => .{ .sha512 = Sha512.init(.{}) },
                .sha3_256 => .{ .sha3_256 = Sha3_256.init(.{}) },
                .sha3_384 => .{ .sha3_384 = Sha3_384.init(.{}) },
                .sha3_512 => .{ .sha3_512 = Sha3_512.init(.{}) },
            } };
        }

        pub fn update(self: *Stream, bytes: []const u8) Error!void {
            switch (self.state) {
                inline else => |*h| h.update(bytes),
            }
        }

        pub fn final(self: *Stream, out: []u8) Error!usize {
            switch (self.state) {
                inline else => |*h| {
                    const H = @TypeOf(h.*);
                    if (out.len < H.digest_length) return error.OpensslFailure;
                    var d: [H.digest_length]u8 = undefined;
                    h.final(&d);
                    @memcpy(out[0..H.digest_length], &d);
                    return H.digest_length;
                },
            }
        }

        /// By-value snapshot: the returned Stream shares no mutable state.
        pub fn clone(self: *Stream) Error!Stream {
            return .{ .state = self.state };
        }

        /// No-op in the shim (no heap state); present for API parity.
        pub fn deinit(self: *Stream) void {
            _ = self;
        }
    };
};

pub const Mac = struct {
    pub const Error = error{OpensslFailure};
    pub fn hmac(alg: policy.Hash, key: []const u8, msg: []const u8, out: []u8) Error!usize {
        switch (alg) {
            .sha256 => return one(std.crypto.auth.hmac.sha2.HmacSha256, key, msg, out),
            .sha384 => return one(std.crypto.auth.hmac.sha2.HmacSha384, key, msg, out),
            .sha512 => return one(std.crypto.auth.hmac.sha2.HmacSha512, key, msg, out),
            // HMAC over SHA-3 is not a std builtin; build it generically.
            .sha3_256 => return one(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_256), key, msg, out),
            .sha3_384 => return one(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_384), key, msg, out),
            .sha3_512 => return one(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_512), key, msg, out),
        }
    }

    /// HMAC-SHA1 for RFC 6238 TOTP / RFC 4226 HOTP consumers.
    ///
    /// SHA-1 is barred from the `policy.Hash` enum (bare SHA-1 is not an
    /// approved digest for new hashing or signing), but HMAC-SHA1 IS an
    /// approved MAC (SP 800-131A Rev 2 Table 7; FIPS 198-1). This dedicated
    /// function is the ONLY approved path to SHA-1 inside the seam — do NOT
    /// add `sha1` to policy.Hash.
    ///
    /// `out` must be ≥ 20 bytes. Writes exactly 20 bytes; returns 20.
    pub fn hmacSha1(key: []const u8, msg: []const u8, out: []u8) Error!usize {
        return one(std.crypto.auth.hmac.HmacSha1, key, msg, out);
    }

    fn one(comptime M: type, key: []const u8, msg: []const u8, out: []u8) Error!usize {
        var t: [M.mac_length]u8 = undefined;
        M.create(&t, msg, key);
        if (out.len < t.len) return error.OpensslFailure;
        @memcpy(out[0..t.len], &t);
        return t.len;
    }
};

pub const Kdf = struct {
    pub const Error = error{OpensslFailure};

    pub fn hkdf(hash: policy.Hash, ikm: []const u8, salt: []const u8, info: []const u8, out: []u8) Error!void {
        switch (hash) {
            .sha256 => return hk(std.crypto.auth.hmac.sha2.HmacSha256, ikm, salt, info, out),
            .sha384 => return hk(std.crypto.auth.hmac.sha2.HmacSha384, ikm, salt, info, out),
            .sha512 => return hk(std.crypto.auth.hmac.sha2.HmacSha512, ikm, salt, info, out),
            .sha3_256 => return hk(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_256), ikm, salt, info, out),
            .sha3_384 => return hk(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_384), ikm, salt, info, out),
            .sha3_512 => return hk(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_512), ikm, salt, info, out),
        }
    }
    fn hk(comptime Hmac: type, ikm: []const u8, salt: []const u8, info: []const u8, out: []u8) Error!void {
        const H = std.crypto.kdf.hkdf.Hkdf(Hmac);
        const prk = H.extract(salt, ikm);
        if (out.len > H.prk_length * 255) return error.OpensslFailure;
        H.expand(out, info, prk);
    }

    pub fn hkdfExpand(hash: policy.Hash, prk: []const u8, info: []const u8, out: []u8) Error!void {
        switch (hash) {
            .sha256 => return hke(std.crypto.auth.hmac.sha2.HmacSha256, prk, info, out),
            .sha384 => return hke(std.crypto.auth.hmac.sha2.HmacSha384, prk, info, out),
            .sha512 => return hke(std.crypto.auth.hmac.sha2.HmacSha512, prk, info, out),
            .sha3_256 => return hke(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_256), prk, info, out),
            .sha3_384 => return hke(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_384), prk, info, out),
            .sha3_512 => return hke(std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_512), prk, info, out),
        }
    }
    fn hke(comptime Hmac: type, prk: []const u8, info: []const u8, out: []u8) Error!void {
        const H = std.crypto.kdf.hkdf.Hkdf(Hmac);
        if (prk.len != H.prk_length) return error.OpensslFailure;
        if (out.len > H.prk_length * 255) return error.OpensslFailure;
        var prk_arr: [H.prk_length]u8 = undefined;
        defer secureZero(&prk_arr);
        @memcpy(&prk_arr, prk[0..H.prk_length]);
        H.expand(out, info, prk_arr);
    }

    pub fn pbkdf2(hash: policy.Hash, password: []const u8, salt: []const u8, iters: u32, out: []u8) Error!void {
        // SP 800-132: >= 1000 iterations, >= 128-bit salt.
        if (iters < 1000 or salt.len < 16) return error.OpensslFailure;
        switch (hash) {
            .sha256 => std.crypto.pwhash.pbkdf2(out, password, salt, iters, std.crypto.auth.hmac.sha2.HmacSha256) catch return error.OpensslFailure,
            .sha384 => std.crypto.pwhash.pbkdf2(out, password, salt, iters, std.crypto.auth.hmac.sha2.HmacSha384) catch return error.OpensslFailure,
            .sha512 => std.crypto.pwhash.pbkdf2(out, password, salt, iters, std.crypto.auth.hmac.sha2.HmacSha512) catch return error.OpensslFailure,
            .sha3_256 => std.crypto.pwhash.pbkdf2(out, password, salt, iters, std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_256)) catch return error.OpensslFailure,
            .sha3_384 => std.crypto.pwhash.pbkdf2(out, password, salt, iters, std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_384)) catch return error.OpensslFailure,
            .sha3_512 => std.crypto.pwhash.pbkdf2(out, password, salt, iters, std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_512)) catch return error.OpensslFailure,
        }
    }
};

pub const Aead = struct {
    pub const Error = error{ Unsupported, AuthFailed, OpensslFailure };
    pub fn seal(alg: policy.Aead, key: []const u8, nonce: []const u8, ad: []const u8, plaintext: []const u8, ciphertext: []u8, tag: []u8) Error!void {
        switch (alg) {
            .aes_128_gcm => return sl(std.crypto.aead.aes_gcm.Aes128Gcm, key, nonce, ad, plaintext, ciphertext, tag),
            .aes_256_gcm => return sl(std.crypto.aead.aes_gcm.Aes256Gcm, key, nonce, ad, plaintext, ciphertext, tag),
        }
    }
    pub fn open(alg: policy.Aead, key: []const u8, nonce: []const u8, ad: []const u8, ciphertext: []const u8, tag: []const u8, plaintext: []u8) Error!void {
        switch (alg) {
            .aes_128_gcm => return op(std.crypto.aead.aes_gcm.Aes128Gcm, key, nonce, ad, ciphertext, tag, plaintext),
            .aes_256_gcm => return op(std.crypto.aead.aes_gcm.Aes256Gcm, key, nonce, ad, ciphertext, tag, plaintext),
        }
    }
    fn sl(comptime A: type, key: []const u8, nonce: []const u8, ad: []const u8, pt: []const u8, ct: []u8, tag: []u8) Error!void {
        if (key.len != A.key_length or nonce.len != A.nonce_length or tag.len != A.tag_length or ct.len < pt.len or
            pt.len > std.math.maxInt(c_int) or ad.len > std.math.maxInt(c_int)) return error.OpensslFailure;
        var t: [A.tag_length]u8 = undefined;
        A.encrypt(ct[0..pt.len], &t, pt, ad, nonce[0..A.nonce_length].*, key[0..A.key_length].*);
        @memcpy(tag[0..A.tag_length], &t);
    }
    fn op(comptime A: type, key: []const u8, nonce: []const u8, ad: []const u8, ct: []const u8, tag: []const u8, pt: []u8) Error!void {
        if (key.len != A.key_length or nonce.len != A.nonce_length or tag.len != A.tag_length or pt.len < ct.len or
            ct.len > std.math.maxInt(c_int) or ad.len > std.math.maxInt(c_int)) return error.OpensslFailure;
        A.decrypt(pt[0..ct.len], ct, tag[0..A.tag_length].*, ad, nonce[0..A.nonce_length].*, key[0..A.key_length].*) catch {
            secureZero(pt[0..ct.len]);
            return error.AuthFailed;
        };
    }
};

pub const Sig = struct {
    pub const Error = error{ Unsupported, VerifyFailed, OpensslFailure };

    const Ed25519 = std.crypto.sign.Ed25519;
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
    // NB: std.crypto has no P-521 curve, so ECDSA P-521 is fips-only in
    // the non-fips shim (returns error.Unsupported), like RSA/PQC.

    const Inner = union(enum) {
        ed25519: Ed25519.KeyPair,
        p256: P256.KeyPair,
        p384: P384.KeyPair,
        ed25519_pub: Ed25519.PublicKey,
        p256_pub: P256.PublicKey,
        p384_pub: P384.PublicKey,
    };

    pub const KeyPair = struct {
        inner: Inner,

        pub fn deinit(self: *KeyPair) void {
            _ = self; // std keys carry no heap state
        }

        pub fn publicBytes(self: *KeyPair, out: []u8) Error!usize {
            return switch (self.inner) {
                .ed25519 => |kp| copyOut(out, &kp.public_key.toBytes()),
                .ed25519_pub => |pk| copyOut(out, &pk.toBytes()),
                .p256 => |kp| copyOut(out, &kp.public_key.toCompressedSec1()),
                .p256_pub => |pk| copyOut(out, &pk.toCompressedSec1()),
                .p384 => |kp| copyOut(out, &kp.public_key.toCompressedSec1()),
                .p384_pub => |pk| copyOut(out, &pk.toCompressedSec1()),
            };
        }

        pub fn fromPublicBytes(alg: policy.SigAlg, raw: []const u8) Error!KeyPair {
            return switch (alg) {
                .ed25519 => .{ .inner = .{ .ed25519_pub = (Ed25519.PublicKey.fromBytes(toArr(32, raw) catch return error.OpensslFailure) catch return error.OpensslFailure) } },
                .ecdsa_p256 => .{ .inner = .{ .p256_pub = (P256.PublicKey.fromSec1(raw) catch return error.OpensslFailure) } },
                .ecdsa_p384 => .{ .inner = .{ .p384_pub = (P384.PublicKey.fromSec1(raw) catch return error.OpensslFailure) } },
                else => error.Unsupported, // RSA + P-521 + PQC are fips-only
            };
        }

        pub fn fromPrivateBytes(alg: policy.SigAlg, raw: []const u8) Error!KeyPair {
            return switch (alg) {
                // Ed25519 private key is the 32-byte SEED (matching the
                // FIPS backend's EVP_PKEY_new_raw_private_key_ex, which also
                // takes the 32-byte seed, and geode's stored seed format).
                // Rebuild the full keypair deterministically from the seed.
                .ed25519 => .{ .inner = .{ .ed25519 = Ed25519.KeyPair.generateDeterministic(toArr(Ed25519.KeyPair.seed_length, raw) catch return error.OpensslFailure) catch return error.OpensslFailure } },
                .ecdsa_p256 => blk: {
                    const sk = P256.SecretKey.fromBytes(toArr(P256.SecretKey.encoded_length, raw) catch return error.OpensslFailure) catch return error.OpensslFailure;
                    break :blk .{ .inner = .{ .p256 = P256.KeyPair.fromSecretKey(sk) catch return error.OpensslFailure } };
                },
                .ecdsa_p384 => blk: {
                    const sk = P384.SecretKey.fromBytes(toArr(P384.SecretKey.encoded_length, raw) catch return error.OpensslFailure) catch return error.OpensslFailure;
                    break :blk .{ .inner = .{ .p384 = P384.KeyPair.fromSecretKey(sk) catch return error.OpensslFailure } };
                },
                else => error.Unsupported,
            };
        }

        /// Import an EC public key from a raw SEC1 point (compressed OR
        /// uncompressed; std's `fromSec1` decodes both). Only
        /// `.ecdsa_p256`/`.ecdsa_p384` are supported here (P-521 is
        /// fips-only in the shim). Mirrors the FIPS backend surface so
        /// geode's raw compressed points import under both -Dfips.
        pub fn fromEcPublicPoint(alg: policy.SigAlg, point: []const u8) Error!KeyPair {
            return switch (alg) {
                .ecdsa_p256 => .{ .inner = .{ .p256_pub = (P256.PublicKey.fromSec1(point) catch return error.OpensslFailure) } },
                .ecdsa_p384 => .{ .inner = .{ .p384_pub = (P384.PublicKey.fromSec1(point) catch return error.OpensslFailure) } },
                else => error.Unsupported, // P-521 is fips-only in the shim
            };
        }

        /// Export the raw big-endian EC private scalar for the generated
        /// key. Only `.ecdsa_p256` (32 bytes) and `.ecdsa_p384` (48 bytes)
        /// are supported; other algorithms return `error.Unsupported`.
        ///
        /// CONTRACT: `out` must be at least `coord_len` bytes (32 for
        /// P-256, 48 for P-384). The output is FIXED-WIDTH: std's
        /// SecretKey stores the scalar as a fixed-width byte array, so no
        /// padding is needed. Mirrors the FIPS backend's `BN_bn2binpad`
        /// guarantee so callers always receive exactly `coord_len` bytes.
        pub fn privateScalar(self: *KeyPair, alg: policy.SigAlg, out: []u8) Error!usize {
            switch (alg) {
                .ecdsa_p256 => {
                    if (out.len < P256.SecretKey.encoded_length) return error.OpensslFailure;
                    const sk: P256.SecretKey = switch (self.inner) {
                        .p256 => |kp| kp.secret_key,
                        else => return error.Unsupported,
                    };
                    const bytes = sk.toBytes();
                    @memcpy(out[0..bytes.len], &bytes);
                    return bytes.len;
                },
                .ecdsa_p384 => {
                    if (out.len < P384.SecretKey.encoded_length) return error.OpensslFailure;
                    const sk: P384.SecretKey = switch (self.inner) {
                        .p384 => |kp| kp.secret_key,
                        else => return error.Unsupported,
                    };
                    const bytes = sk.toBytes();
                    @memcpy(out[0..bytes.len], &bytes);
                    return bytes.len;
                },
                else => return error.Unsupported,
            }
        }

        /// Export the raw 32-byte Ed25519 seed. Only valid for Ed25519
        /// keypairs (not public-only variants); `out` must be at least 32
        /// bytes. Returns 32 on success. Mirrors the FIPS backend surface
        /// so geode can store the seed and re-derive keys cross-backend.
        pub fn privateSeed(self: *KeyPair, out: []u8) Error!usize {
            const seed_len = Ed25519.KeyPair.seed_length;
            if (out.len < seed_len) return error.OpensslFailure;
            switch (self.inner) {
                .ed25519 => |kp| {
                    // std's Ed25519.KeyPair stores the secret key as the 64-byte
                    // (seed ++ public) form. The seed is the first 32 bytes.
                    const sk_bytes = kp.secret_key.toBytes();
                    @memcpy(out[0..seed_len], sk_bytes[0..seed_len]);
                    return seed_len;
                },
                else => return error.Unsupported,
            }
        }

        /// Import an EC private key from a raw big-endian scalar.
        /// CONTRACT: `scalar` must be FIXED-WIDTH for the curve (32 bytes for
        /// P-256, 48 for P-384). This shim rejects shorter inputs (e.g. a
        /// leading-zero-stripped scalar) with `error.OpensslFailure`. The FIPS
        /// backend's `BN_bin2bn` accepts variable-length scalars, so callers
        /// must store/pass fixed-width scalars for cross-backend parity.
        pub fn fromEcPrivateScalar(alg: policy.SigAlg, scalar: []const u8) Error!KeyPair {
            return switch (alg) {
                .ecdsa_p256 => blk: {
                    const sk = P256.SecretKey.fromBytes(toArr(P256.SecretKey.encoded_length, scalar) catch return error.OpensslFailure) catch return error.OpensslFailure;
                    break :blk .{ .inner = .{ .p256 = P256.KeyPair.fromSecretKey(sk) catch return error.OpensslFailure } };
                },
                .ecdsa_p384 => blk: {
                    const sk = P384.SecretKey.fromBytes(toArr(P384.SecretKey.encoded_length, scalar) catch return error.OpensslFailure) catch return error.OpensslFailure;
                    break :blk .{ .inner = .{ .p384 = P384.KeyPair.fromSecretKey(sk) catch return error.OpensslFailure } };
                },
                else => error.Unsupported, // P-521 is fips-only in the shim
            };
        }

        /// Export the COMPRESSED SEC1 public point for an EC keypair.
        /// Only `.ecdsa_p256` (33 bytes) and `.ecdsa_p384` (49 bytes) are
        /// supported; other algorithms return `error.Unsupported`. `out`
        /// must be at least the compressed size; shorter buffers return
        /// `error.OpensslFailure`. A key whose inner type does not match
        /// the requested `alg` (e.g. an Ed25519 or RSA inner on an EC alg)
        /// returns `error.Unsupported`, matching the FIPS backend's EC-type
        /// guard. Mirrors the FIPS backend surface exactly so consumers can
        /// call `ecPublicPoint` under both -Dfips paths.
        pub fn ecPublicPoint(self: *KeyPair, alg: policy.SigAlg, out: []u8) Error!usize {
            switch (alg) {
                .ecdsa_p256 => {
                    const compressed: [P256.PublicKey.compressed_sec1_encoded_length]u8 = switch (self.inner) {
                        .p256 => |kp| kp.public_key.toCompressedSec1(),
                        .p256_pub => |pk| pk.toCompressedSec1(),
                        else => return error.Unsupported,
                    };
                    return copyOut(out, &compressed);
                },
                .ecdsa_p384 => {
                    const compressed: [P384.PublicKey.compressed_sec1_encoded_length]u8 = switch (self.inner) {
                        .p384 => |kp| kp.public_key.toCompressedSec1(),
                        .p384_pub => |pk| pk.toCompressedSec1(),
                        else => return error.Unsupported,
                    };
                    return copyOut(out, &compressed);
                },
                else => return error.Unsupported,
            }
        }

        /// RSA SPKI import is fips-only (std has no RSA). Present for API
        /// parity with the fips backend; consumers needing RSA in non-fips
        /// mode swap in their own backend (see SEAM_CONTRACT.md).
        pub fn fromRsaSpki(der: []const u8) Error!KeyPair {
            _ = der;
            return error.Unsupported;
        }

        /// RSA (n,e) import is fips-only (std has no RSA). Present for API
        /// parity with the fips backend.
        pub fn fromRsaComponents(n: []const u8, e: []const u8) Error!KeyPair {
            _ = n;
            _ = e;
            return error.Unsupported;
        }
    };

    pub fn generate(alg: policy.SigAlg) Error!KeyPair {
        var seed: [64]u8 = undefined;
        defer secureZero(&seed);
        try randomBytes(&seed);
        return switch (alg) {
            .ed25519 => .{ .inner = .{ .ed25519 = Ed25519.KeyPair.generateDeterministic(seed[0..Ed25519.KeyPair.seed_length].*) catch return error.OpensslFailure } },
            .ecdsa_p256 => .{ .inner = .{ .p256 = P256.KeyPair.generateDeterministic(seed[0..P256.KeyPair.seed_length].*) catch return error.OpensslFailure } },
            .ecdsa_p384 => .{ .inner = .{ .p384 = P384.KeyPair.generateDeterministic(seed[0..P384.KeyPair.seed_length].*) catch return error.OpensslFailure } },
            else => error.Unsupported, // RSA + P-521 + PQC are fips-only
        };
    }

    pub fn sign(alg: policy.SigAlg, kp: *KeyPair, msg: []const u8, sig_out: []u8) Error!usize {
        _ = alg;
        switch (kp.inner) {
            .ed25519 => |k| return copyOut(sig_out, &(k.sign(msg, null) catch return error.OpensslFailure).toBytes()),
            // ECDSA: emit DER-encoded SEQUENCE { INTEGER r, INTEGER s } to
            // match the FIPS/OpenSSL backend (EVP_DigestSign outputs DER).
            // toDer writes into a fixed-size stack buffer and returns a
            // sub-slice whose length is the actual (variable) DER length.
            .p256 => |k| {
                const raw_sig = k.sign(msg, null) catch return error.OpensslFailure;
                var der_buf: [P256.Signature.der_encoded_length_max]u8 = undefined;
                const der = raw_sig.toDer(&der_buf);
                return copyOut(sig_out, der);
            },
            .p384 => |k| {
                const raw_sig = k.sign(msg, null) catch return error.OpensslFailure;
                var der_buf: [P384.Signature.der_encoded_length_max]u8 = undefined;
                const der = raw_sig.toDer(&der_buf);
                return copyOut(sig_out, der);
            },
            else => return error.Unsupported, // public-only keys cannot sign
        }
    }

    pub fn verify(alg: policy.SigAlg, kp: *KeyPair, msg: []const u8, sig: []const u8) Error!void {
        _ = alg;
        switch (kp.inner) {
            .ed25519 => |k| try verifyEd(k.public_key, msg, sig),
            .ed25519_pub => |pk| try verifyEd(pk, msg, sig),
            .p256 => |k| try verifyEc(P256, k.public_key, msg, sig),
            .p256_pub => |pk| try verifyEc(P256, pk, msg, sig),
            .p384 => |k| try verifyEc(P384, k.public_key, msg, sig),
            .p384_pub => |pk| try verifyEc(P384, pk, msg, sig),
        }
    }

    /// Classical RSA verify with an explicit digest. std has no RSA, so
    /// this is fips-only: consumers keep their own RSA implementation
    /// behind the non-fips branch (see SEAM_CONTRACT.md). Mirrors the fips
    /// backend signature EXACTLY so call sites compile under both -Dfips.
    pub fn verifyRsa(
        scheme: policy.RsaScheme,
        digest: policy.Hash,
        kp: *KeyPair,
        msg: []const u8,
        sig: []const u8,
    ) Error!void {
        _ = scheme;
        _ = digest;
        _ = kp;
        _ = msg;
        _ = sig;
        return error.Unsupported;
    }

    /// ECDSA verify with an explicit (curve, digest), so off-diagonal
    /// combos (e.g. P-256 with SHA-384) route. std covers P-256/P-384 with
    /// SHA-256/384/512; P-521, SHA-3, and non-EC algs are fips-only and
    /// return error.Unsupported here, matching the fips backend surface.
    pub fn verifyEcdsa(
        alg: policy.SigAlg,
        digest: policy.Hash,
        kp: *KeyPair,
        msg: []const u8,
        sig: []const u8,
    ) Error!void {
        // Recover the stored public key as SEC1 so it can be re-parsed
        // under the off-diagonal (curve, hash) scheme. std's PublicKey is
        // hash-parametric only in name; the underlying curve point is the
        // same, and SEC1 is the stable bridge between the two wrappers.
        var sec1: [65]u8 = undefined;
        const pk_len: usize = switch (kp.inner) {
            .p256, .p256_pub => if (alg == .ecdsa_p256) try kp.publicBytes(&sec1) else return error.Unsupported,
            .p384, .p384_pub => if (alg == .ecdsa_p384) try kp.publicBytes(&sec1) else return error.Unsupported,
            else => return error.Unsupported,
        };
        const sec1_pk = sec1[0..pk_len];
        switch (alg) {
            .ecdsa_p256 => switch (digest) {
                .sha256 => return verifyEcExplicit(std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, std.crypto.hash.sha2.Sha256), sec1_pk, msg, sig),
                .sha384 => return verifyEcExplicit(std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, std.crypto.hash.sha2.Sha384), sec1_pk, msg, sig),
                .sha512 => return verifyEcExplicit(std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, std.crypto.hash.sha2.Sha512), sec1_pk, msg, sig),
                else => return error.Unsupported,
            },
            .ecdsa_p384 => switch (digest) {
                .sha256 => return verifyEcExplicit(std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P384, std.crypto.hash.sha2.Sha256), sec1_pk, msg, sig),
                .sha384 => return verifyEcExplicit(std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P384, std.crypto.hash.sha2.Sha384), sec1_pk, msg, sig),
                .sha512 => return verifyEcExplicit(std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P384, std.crypto.hash.sha2.Sha512), sec1_pk, msg, sig),
                else => return error.Unsupported,
            },
            else => return error.Unsupported,
        }
    }

    fn verifyEcExplicit(comptime S: type, sec1_pk: []const u8, msg: []const u8, sig: []const u8) Error!void {
        const pk = S.PublicKey.fromSec1(sec1_pk) catch return error.OpensslFailure;
        // Parse DER (same contract as verifyEc and sign).
        const s = S.Signature.fromDer(sig) catch return error.VerifyFailed;
        s.verify(msg, pk) catch return error.VerifyFailed;
    }

    fn verifyEd(pk: Ed25519.PublicKey, msg: []const u8, sig: []const u8) Error!void {
        const s = Ed25519.Signature.fromBytes(toArr(64, sig) catch return error.VerifyFailed);
        s.verify(msg, pk) catch return error.VerifyFailed;
    }
    fn verifyEc(comptime S: type, pk: S.PublicKey, msg: []const u8, sig: []const u8) Error!void {
        // Expect DER-encoded SEQUENCE { INTEGER r, INTEGER s }, matching what
        // sign() now emits and what the FIPS/OpenSSL backend produces.
        const s = S.Signature.fromDer(sig) catch return error.VerifyFailed;
        s.verify(msg, pk) catch return error.VerifyFailed;
    }
};

pub const Kem = struct {
    pub const Error = error{ Unsupported, DecapMismatch, OpensslFailure };
    /// Same pinned named type as the fips backend.
    pub const EncapResult = struct { ct_len: usize, ss_len: usize };
    pub const KeyPair = struct {
        pub fn deinit(self: *KeyPair) void {
            _ = self;
        }
    };
    pub const PublicKey = struct {
        pub fn deinit(self: *PublicKey) void {
            _ = self;
        }
    };
    pub fn exportPublic(alg: policy.KemAlg, kp: *KeyPair, out: []u8) Error!usize {
        _ = alg;
        _ = kp;
        _ = out;
        return error.Unsupported;
    }
    pub fn importPublic(alg: policy.KemAlg, wire: []const u8) Error!PublicKey {
        _ = alg;
        _ = wire;
        return error.Unsupported;
    }
    pub fn encapsulatePublic(alg: policy.KemAlg, pk: *PublicKey, ct_out: []u8, ss_out: []u8) Error!EncapResult {
        _ = alg;
        _ = pk;
        _ = ct_out;
        _ = ss_out;
        return error.Unsupported;
    }
    // ML-KEM + hybrids are fips-only (std has no ML-KEM).
    pub fn generate(alg: policy.KemAlg) Error!KeyPair {
        _ = alg;
        return error.Unsupported;
    }
    pub fn encapsulate(alg: policy.KemAlg, kp: *KeyPair, ct_out: []u8, ss_out: []u8) Error!EncapResult {
        _ = alg;
        _ = kp;
        _ = ct_out;
        _ = ss_out;
        return error.Unsupported;
    }
    pub fn decapsulate(alg: policy.KemAlg, kp: *KeyPair, ct: []const u8, ss_out: []u8) Error!usize {
        _ = alg;
        _ = kp;
        _ = ct;
        _ = ss_out;
        return error.Unsupported;
    }
};

pub const Csprng = struct {
    pub const Error = error{OpensslFailure};
    pub fn bytes(out: []u8) Error!void {
        try randomBytes(out);
    }
};

/// Best-effort guaranteed wipe (mirrors fips.secureZero). std's
/// secureZero uses volatile writes the optimizer cannot elide.
pub fn secureZero(buf: []u8) void {
    std.crypto.secureZero(u8, buf);
}

pub fn timingSafeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

/// No-op in the non-fips backend (there is no FIPS provider to assert).
pub fn assertActive() void {}

/// Fallible FIPS startup gate. No-op success in the non-fips shim (there
/// is no FIPS provider to load). The fips backend returns
/// `error.FipsProviderUnavailable` when the FIPS module cannot be loaded
/// or self-tested. Use this at program startup under `-Dfips=true` for a
/// graceful error instead of a panic.
pub fn ensureFips() error{FipsProviderUnavailable}!void {
    return; // shim: always succeeds — no provider to load
}

fn copyOut(out: []u8, src: []const u8) Sig.Error!usize {
    if (out.len < src.len) return error.OpensslFailure;
    @memcpy(out[0..src.len], src);
    return src.len;
}

fn toArr(comptime n: usize, raw: []const u8) error{BadLen}![n]u8 {
    if (raw.len != n) return error.BadLen;
    var a: [n]u8 = undefined;
    @memcpy(&a, raw[0..n]);
    return a;
}

test "randomBytes: OS entropy is non-zero and two draws differ" {
    var a: [32]u8 = @splat(0);
    var b: [32]u8 = @splat(0);
    try Csprng.bytes(&a);
    try Csprng.bytes(&b);
    const zero: [32]u8 = @splat(0);
    try std.testing.expect(!std.mem.eql(u8, &a, &zero));
    try std.testing.expect(!std.mem.eql(u8, &b, &zero));
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    try Csprng.bytes(a[0..0]); // empty request is a successful no-op
}

// -------------------------------------------------------------------------
// Tests: privateScalar / privateSeed round-trips (both backends must pass).
// -------------------------------------------------------------------------

test "privateScalar P-256 round-trip: export → fromEcPrivateScalar + fromEcPublicPoint → sign/verify" {
    var kp = try Sig.generate(.ecdsa_p256);
    defer kp.deinit();

    // Export private scalar (must be fixed-width 32 bytes).
    var scalar: [32]u8 = undefined;
    const slen = try kp.privateScalar(.ecdsa_p256, &scalar);
    try std.testing.expectEqual(@as(usize, 32), slen);

    // Export public point as compressed SEC1.
    var point: [65]u8 = undefined;
    const plen = try kp.publicBytes(&point);

    // Re-import scalar and point independently.
    var priv_kp = try Sig.KeyPair.fromEcPrivateScalar(.ecdsa_p256, scalar[0..slen]);
    defer priv_kp.deinit();
    var pub_kp = try Sig.KeyPair.fromEcPublicPoint(.ecdsa_p256, point[0..plen]);
    defer pub_kp.deinit();

    // Sign with the imported scalar; verify with the imported public point.
    const msg = "privateScalar p256 round-trip";
    var sig: [128]u8 = undefined;
    const n = try Sig.sign(.ecdsa_p256, &priv_kp, msg, &sig);
    try Sig.verify(.ecdsa_p256, &pub_kp, msg, sig[0..n]);
    try std.testing.expectError(error.VerifyFailed, Sig.verify(.ecdsa_p256, &pub_kp, "tampered", sig[0..n]));
}

test "privateScalar P-384 round-trip: export → fromEcPrivateScalar + fromEcPublicPoint → sign/verify" {
    var kp = try Sig.generate(.ecdsa_p384);
    defer kp.deinit();

    // Export private scalar (must be fixed-width 48 bytes).
    var scalar: [48]u8 = undefined;
    const slen = try kp.privateScalar(.ecdsa_p384, &scalar);
    try std.testing.expectEqual(@as(usize, 48), slen);

    // Export public point as compressed SEC1.
    var point: [65]u8 = undefined;
    const plen = try kp.publicBytes(&point);

    // Re-import scalar and point independently.
    var priv_kp = try Sig.KeyPair.fromEcPrivateScalar(.ecdsa_p384, scalar[0..slen]);
    defer priv_kp.deinit();
    var pub_kp = try Sig.KeyPair.fromEcPublicPoint(.ecdsa_p384, point[0..plen]);
    defer pub_kp.deinit();

    // Sign with the imported scalar; verify with the imported public point.
    const msg = "privateScalar p384 round-trip";
    var sig: [128]u8 = undefined;
    const n = try Sig.sign(.ecdsa_p384, &priv_kp, msg, &sig);
    try Sig.verify(.ecdsa_p384, &pub_kp, msg, sig[0..n]);
    try std.testing.expectError(error.VerifyFailed, Sig.verify(.ecdsa_p384, &pub_kp, "tampered", sig[0..n]));
}

test "privateSeed Ed25519 round-trip: export → fromPrivateBytes → sign/verify + pubkey match" {
    var kp = try Sig.generate(.ed25519);
    defer kp.deinit();

    // Export the seed (32 bytes).
    var seed: [32]u8 = undefined;
    const seed_len = try kp.privateSeed(&seed);
    try std.testing.expectEqual(@as(usize, 32), seed_len);

    // Export original public key.
    var pub_orig: [32]u8 = undefined;
    const pn = try kp.publicBytes(&pub_orig);
    try std.testing.expectEqual(@as(usize, 32), pn);

    // Re-import from seed; re-derive signing keypair.
    var reimported = try Sig.KeyPair.fromPrivateBytes(.ed25519, seed[0..seed_len]);
    defer reimported.deinit();

    // Sign with the re-imported keypair and verify with the original.
    const msg = "privateSeed ed25519 round-trip";
    var sig: [64]u8 = undefined;
    const n = try Sig.sign(.ed25519, &reimported, msg, &sig);
    try Sig.verify(.ed25519, &kp, msg, sig[0..n]);

    // The re-derived public key must match the original.
    var pub_reimported: [32]u8 = undefined;
    const pn2 = try reimported.publicBytes(&pub_reimported);
    try std.testing.expectEqual(@as(usize, 32), pn2);
    try std.testing.expectEqualSlices(u8, &pub_orig, &pub_reimported);
}

test "privateScalar rejects non-EC algs and short output buffers" {
    // privateScalar rejects Ed25519.
    var ed_kp = try Sig.generate(.ed25519);
    defer ed_kp.deinit();
    var buf32 = [_]u8{0} ** 32;
    try std.testing.expectError(error.Unsupported, ed_kp.privateScalar(.ed25519, &buf32));

    // privateScalar rejects a buf that is too short.
    var ec_kp = try Sig.generate(.ecdsa_p256);
    defer ec_kp.deinit();
    var buf16 = [_]u8{0} ** 16;
    try std.testing.expectError(error.OpensslFailure, ec_kp.privateScalar(.ecdsa_p256, &buf16));

    // privateSeed rejects a buf that is too short.
    var buf16b = [_]u8{0} ** 16;
    try std.testing.expectError(error.OpensslFailure, ed_kp.privateSeed(&buf16b));

    // privateSeed rejects a non-Ed25519 (EC) key.
    var buf32b = [_]u8{0} ** 32;
    try std.testing.expectError(error.Unsupported, ec_kp.privateSeed(&buf32b));
}
