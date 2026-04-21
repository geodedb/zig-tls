// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Signature Scheme Handling and Verification for TLS 1.3
//!
//! Implements digital signature processing for TLS 1.3 CertificateVerify messages
//! and X.509 certificate chain validation. Supports the signature algorithms
//! specified in:
//! - RFC 8446 §4.2.3 (Signature Algorithms Extension)
//! - RFC 8446 §4.4.3 (Certificate Verify Message)
//! - RFC 5480 (Elliptic Curve Cryptography Subject Public Key Information)
//! - RFC 8017 (PKCS #1: RSA Cryptography Specifications - RSA-PSS)
//! - RFC 8032 (Edwards-Curve Digital Signature Algorithm - Ed25519)
//! - RFC 3279 (Algorithms and Identifiers for PKIX)
//!
//! This module provides:
//! - SubjectPublicKeyInfo (SPKI) parsing for ECDSA, RSA, and Ed25519 keys
//! - TLS 1.3 CertificateVerify signature verification with context string
//! - X.509 certificate signature verification for chain validation
//! - Signature scheme inference from certificate public keys
//! - PKCS#8 private key parsing for signature generation (testing/client auth)
//!
//! ## Supported Signature Algorithms
//! ### ECDSA (RFC 5480, RFC 8446 §4.2.3)
//! - **ecdsa_secp256r1_sha256** (0x0403): ECDSA with P-256 curve and SHA-256
//! - **ecdsa_secp384r1_sha384** (0x0503): ECDSA with P-384 curve and SHA-384
//! - Signatures use ASN.1 DER encoding: SEQUENCE { r INTEGER, s INTEGER }
//!
//! ### RSA-PSS (RFC 8017, RFC 8446 §4.2.3)
//! - **rsa_pss_rsae_sha256** (0x0804): RSA-PSS with SHA-256, salt length 32
//! - Uses RSASSA-PSS signature scheme with MGF1-SHA256 mask generation
//! - Salt length equals hash output length (32 bytes for SHA-256)
//!
//! ### EdDSA (RFC 8032, RFC 8446 §4.2.3)
//! - **ed25519** (0x0807): Ed25519 pure EdDSA signature
//! - Signatures are 64 bytes (R || S), no DER encoding
//!
//! ## TLS 1.3 CertificateVerify (RFC 8446 §4.4.3)
//! The CertificateVerify message proves possession of the private key corresponding
//! to the certificate. The signature is computed over a constructed message:
//!
//! ```
//! digital-signature-content = 0x20 * 64 || context-string || 0x00 || transcript-hash
//!
//! context-string (client): "TLS 1.3, client CertificateVerify"
//! context-string (server): "TLS 1.3, server CertificateVerify"
//! ```
//!
//! This construction prevents cross-protocol attacks and provides domain separation.
//!
//! ## SubjectPublicKeyInfo Parsing
//! Extracts public key material from X.509 SubjectPublicKeyInfo structures:
//! - **ECDSA**: Parses curve OID and SEC1-encoded public key (uncompressed point)
//! - **RSA**: Parses RSAPublicKey SEQUENCE containing modulus and exponent
//! - **Ed25519**: Extracts 32-byte public key from BIT STRING
//!
//! ## RFC References
//! ### TLS 1.3 Signature Processing
//! - RFC 8446 §4.2.3 - SignatureScheme and supported_signature_algorithms
//! - RFC 8446 §4.4.3 - CertificateVerify message and signature construction
//! - RFC 8446 §4.4.2.2 - Certificate public key requirements
//!
//! ### Cryptographic Specifications
//! - RFC 5480 - EC Subject Public Key Information Format
//! - RFC 8017 - PKCS #1 v2.2: RSA Cryptography (RSA-PSS)
//! - RFC 8032 - Edwards-Curve Digital Signature Algorithm (Ed25519)
//! - RFC 3279 - Algorithms and Identifiers for PKIX
//! - RFC 5758 - Additional Algorithms for PKIX (SHA-256/384/512)
//!
//! ### ASN.1 Encoding
//! - RFC 5280 §4.1.2.7 - SubjectPublicKeyInfo encoding in certificates
//! - RFC 5958 - Asymmetric Key Packages (PKCS#8 private key format)
//! - RFC 5915 - Elliptic Curve Private Key Structure (ECPrivateKey)
//!
//! ## Security Considerations
//! - **Signature Verification**: All signature verification uses Zig stdlib crypto
//!   primitives with constant-time operations where applicable
//! - **Context String**: TLS 1.3 context string prevents signature reuse across protocols
//! - **Curve Validation**: Only P-256 and P-384 curves supported; others rejected
//! - **RSA-PSS Parameters**: Fixed to SHA-256 with 32-byte salt (no parameter negotiation)
//! - **Ed25519 Domain**: Pure Ed25519 (no Ed25519ph or Ed25519ctx variants)
//! - **Private Key Handling**: PKCS#8 parsing for testing; production should use HSM/KMS
//!
//! ## Design Notes
//! - Uses Zig standard library crypto: std.crypto.sign.ecdsa, std.crypto.sign.Ed25519
//! - RSA-PSS verification via std.crypto.Certificate.rsa (constant-time Montgomery arithmetic)
//! - ASN.1 parsing via asn1.zig module for DER decoding
//! - Signature generation primarily for testing and client authentication scenarios
//! - Production signature generation should use hardware security modules
//!
//! ## Future Work
//! - Additional curves: P-521, X25519 (though not used in TLS signatures)
//! - RSA-PSS with SHA-384/512 (currently only SHA-256 supported)
//! - ECDSA with SHA-384 on P-256 (rare but allowed by some implementations)
//! - Dilithium post-quantum signatures (TLS 1.3 extension draft)
//! - Hardware-backed signature generation via PKCS#11 or similar
const std = @import("std");
const asn1 = @import("asn1");

// Use standard library crypto
// https://ziglang.org/documentation/master/std/#std.crypto.sign.Ed25519
const Ed25519 = std.crypto.sign.Ed25519;

/// Debug tracing for signature operations.
///
/// ## Security Warning
///
/// **NEVER enable this in production!** When enabled, private keys and
/// other sensitive cryptographic material may be logged to stdout.
///
/// This constant is compile-time checked and will cause a build error
/// if enabled in ReleaseSafe/ReleaseFast/ReleaseSmall builds.
const sig_trace_enabled = false;

// Compile-time safety: prevent secret logging in release builds
comptime {
    if (sig_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: sig_trace_enabled must be false in release builds - secrets would be logged!");
    }
}

/// Comptime-gated trace helper. When `sig_trace_enabled` is `false` (the
/// default and only allowed value in release builds) the body is
/// dead-code-eliminated, so `traceSig(...)` compiles down to a no-op and
/// leaves zero runtime cost. All internal crypto-trace prints in this
/// module must route through this helper rather than calling
/// `std.debug.print` directly (GAP-0118 / QUAL-320).
inline fn traceSig(comptime fmt: []const u8, args: anytype) void {
    if (comptime sig_trace_enabled) std.debug.print(fmt, args);
}

/// Variant for trace blocks that dump a byte buffer; same comptime gating.
inline fn traceSigBytes(prefix: []const u8, bytes: []const u8) void {
    if (comptime sig_trace_enabled) {
        std.debug.print("{s}", .{prefix});
        for (bytes) |b| std.debug.print("{x:0>2} ", .{b});
        std.debug.print("\n", .{});
    }
}

/// TLS 1.3 signature algorithms supported by this implementation.
///
/// Enum of signature schemes from RFC 8446 §4.2.3 SignatureScheme registry.
/// These values appear in the signature_algorithms extension and CertificateVerify.
///
/// ## RFC References
/// - RFC 8446 §4.2.3 - SignatureScheme definition and values
/// - RFC 8446 §B.3.1.3 - SignatureScheme values in TLS registry
///
/// ## Supported Algorithms
/// - `ecdsa_secp256r1_sha256` (0x0403): ECDSA with P-256 and SHA-256
/// - `ecdsa_secp384r1_sha384` (0x0503): ECDSA with P-384 and SHA-384
/// - `rsa_pss_sha256` (0x0804): RSA-PSS with SHA-256 and 32-byte salt
/// - `ed25519` (0x0807): Ed25519 pure signature scheme
pub const SigAlg = enum {
    /// ECDSA with NIST P-256 curve and SHA-256 (RFC 8446 §4.2.3, value 0x0403)
    ecdsa_secp256r1_sha256,
    /// ECDSA with NIST P-384 curve and SHA-384 (RFC 8446 §4.2.3, value 0x0503)
    ecdsa_secp384r1_sha384,
    /// RSA-PSS with SHA-256, MGF1-SHA256, salt=32 (RFC 8446 §4.2.3, value 0x0804)
    rsa_pss_sha256,
    /// Ed25519 pure signature (RFC 8446 §4.2.3, value 0x0807)
    ed25519,
};

/// Convert from TLS 1.3 SignatureScheme (raw u16 value) to SigAlg.
///
/// Maps the TLS 1.3 signature scheme wire format to our internal SigAlg enum.
/// Returns error.UnsupportedSignatureScheme for unrecognized or unsupported schemes.
///
/// ## Supported Mappings
/// - 0x0403 (ecdsa_secp256r1_sha256) -> SigAlg.ecdsa_secp256r1_sha256
/// - 0x0503 (ecdsa_secp384r1_sha384) -> SigAlg.ecdsa_secp384r1_sha384
/// - 0x0804 (rsa_pss_rsae_sha256) -> SigAlg.rsa_pss_sha256
/// - 0x0807 (ed25519) -> SigAlg.ed25519
pub fn fromTls13SignatureScheme(scheme: anytype) !SigAlg {
    const value: u16 = switch (@TypeOf(scheme)) {
        u16 => scheme,
        else => @intFromEnum(scheme),
    };
    return switch (value) {
        0x0403 => SigAlg.ecdsa_secp256r1_sha256,
        0x0503 => SigAlg.ecdsa_secp384r1_sha384,
        0x0804 => SigAlg.rsa_pss_sha256,
        0x0807 => SigAlg.ed25519,
        else => error.UnsupportedSignatureScheme,
    };
}

/// Parsed ECDSA public key from SubjectPublicKeyInfo.
///
/// Represents an elliptic curve public key extracted from the X.509 SPKI structure.
/// The public key is stored in SEC1 uncompressed format (0x04 || X || Y).
///
/// ## RFC References
/// - RFC 5480 §2 - Elliptic Curve Cryptography Subject Public Key Information
/// - RFC 5480 §2.2 - Subject Public Key (SEC1 encoding)
/// - SECG SEC1 v2.0 §2.3.3 - Elliptic-Curve-Point-to-Octet-String Conversion
///
/// ## Supported Curves
/// - **P-256** (secp256r1): OID 1.2.840.10045.3.1.7, 65-byte public key (1 + 32 + 32)
/// - **P-384** (secp384r1): OID 1.3.132.0.34, 97-byte public key (1 + 48 + 48)
///
/// ## Lifetime
/// The sec1_uncompressed slice is allocated and owned by this struct. Call
/// `deinit()` to free the memory when done.
pub const EcdsaSpki = struct {
    /// True if P-256 curve, false if P-384 curve.
    /// RFC 5480 §2.1.1 - ECParameters namedCurve identification
    curve_p256: bool,

    /// SEC1 uncompressed elliptic curve point: 0x04 || X || Y.
    /// RFC 5480 §2.2 - subjectPublicKey contains ECPoint as BIT STRING
    /// SECG SEC1 §2.3.3 - Uncompressed form with prefix byte 0x04
    sec1_uncompressed: []const u8,

    /// Allocator used for sec1_uncompressed buffer.
    allocator: std.mem.Allocator,

    /// Free allocated public key buffer and invalidate the struct.
    ///
    /// ## Security Considerations
    /// This does NOT zeroize the public key (public keys are not secret).
    /// Call this when done with the SPKI to free memory.
    pub fn deinit(self: *EcdsaSpki) void {
        self.allocator.free(self.sec1_uncompressed);
        self.* = undefined;
    }
};

/// Parsed RSA public key from SubjectPublicKeyInfo.
///
/// Represents an RSA public key extracted from the X.509 SPKI structure.
/// Contains the modulus (n) and public exponent (e) for RSA operations.
///
/// ## RFC References
/// - RFC 3279 §2.3.1 - RSA Keys (rsaEncryption OID 1.2.840.113549.1.1.1)
/// - RFC 8017 §A.1.1 - RSAPublicKey ASN.1 structure
///
/// ## RSAPublicKey Structure
/// ```
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
/// ```
///
/// ## Typical Values
/// - Modulus: 2048-bit (256 bytes) or 4096-bit (512 bytes), big-endian
/// - Exponent: Usually 65537 (0x010001), limited to 64-bit in this implementation
///
/// ## Lifetime
/// The modulus slice is allocated and owned by this struct. Call `deinit()`
/// to free the memory when done.
pub const RsaSpki = struct {
    /// RSA modulus (n) in big-endian byte encoding.
    /// RFC 8017 §A.1.1 - Modulus n = p * q (product of two primes)
    modulus: []const u8,

    /// RSA public exponent (e), typically 65537.
    /// RFC 8017 §A.1.1 - Public exponent e with 1 < e < n
    /// Limited to 64-bit for simplicity (sufficient for standard exponents)
    exponent: u64,

    /// Allocator used for modulus buffer.
    allocator: std.mem.Allocator,

    /// Free allocated modulus buffer and invalidate the struct.
    ///
    /// ## Security Considerations
    /// This does NOT zeroize the modulus (public keys are not secret).
    /// Call this when done with the SPKI to free memory.
    pub fn deinit(self: *RsaSpki) void {
        self.allocator.free(self.modulus);
        self.* = undefined;
    }
};

/// Parse a DER-encoded SubjectPublicKeyInfo into ECDSA components.
pub fn parseEcdsaSpki(spki_der: []const u8, alloc: std.mem.Allocator) !EcdsaSpki {
    var d = asn1.Decoder.init(spki_der);
    const seq = try d.readSequence();
    var s1 = asn1.Decoder.init(seq);
    const algo_seq = try s1.readSequence();
    var a1 = asn1.Decoder.init(algo_seq);
    const algo_oid = try a1.readOID();
    // SEC-076: canonical equality for algorithm and curve OIDs.
    const id_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 }; // 1.2.840.10045.2.1
    if (!asn1.oidEqual(algo_oid, &id_ec_public_key)) return error.UnexpectedAlgorithm;

    const curve_oid = try a1.readOID();
    const secp256r1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 }; // 1.2.840.10045.3.1.7
    const secp384r1 = [_]u8{ 0x2B, 0x81, 0x04, 0x00, 0x22 }; // 1.3.132.0.34
    var is_p256 = false;
    if (asn1.oidEqual(curve_oid, &secp256r1)) {
        is_p256 = true;
    } else if (!asn1.oidEqual(curve_oid, &secp384r1)) {
        return error.UnsupportedCurve;
    }
    // subjectPublicKey BIT STRING
    const bitstr = try s1.readBitString();
    if (bitstr.len == 0 or bitstr[0] != 0x04) return error.InvalidEcPoint; // require uncompressed
    const out = try alloc.dupe(u8, bitstr);
    return .{ .curve_p256 = is_p256, .sec1_uncompressed = out, .allocator = alloc };
}

/// Parse a DER-encoded SubjectPublicKeyInfo into RSA components.
pub fn parseRsaSpki(spki_der: []const u8, alloc: std.mem.Allocator) !RsaSpki {
    var d = asn1.Decoder.init(spki_der);
    const seq = try d.readSequence();
    var s1 = asn1.Decoder.init(seq);
    const algo_seq = try s1.readSequence();
    var a1 = asn1.Decoder.init(algo_seq);
    const algo_oid = try a1.readOID();
    // SEC-076: canonical equality. rsaEncryption: 1.2.840.113549.1.1.1
    const rsa_encryption = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    if (!asn1.oidEqual(algo_oid, &rsa_encryption)) return error.UnexpectedAlgorithm;
    // Optional NULL params may follow; tolerate
    _ = a1.readTLV() catch null;
    const bitstr = try s1.readBitString();
    // Inside is RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    var d2 = asn1.Decoder.init(bitstr);
    const rsaseq = try d2.readSequence();
    var r = asn1.Decoder.init(rsaseq);
    // Read modulus as raw bytes via TLV to preserve leading 0x00
    const mod_tlv = try r.readTLV();
    if (asn1.tagClass(mod_tlv.tag) != .universal or asn1.tagNumber(mod_tlv.tag) != 2) return error.UnexpectedTag;
    const modulus = try alloc.dupe(u8, mod_tlv.val);
    const e_val = try r.readInteger();
    return .{ .modulus = modulus, .exponent = e_val, .allocator = alloc };
}

fn tls13_build_context_and_hash(alg: SigAlg, context: []const u8, th: []const u8, buf: *[512]u8) []u8 {
    _ = alg; // context depends only on TLS; alg included for future use
    // Per RFC8446 4.4.3: signed_content = 0x20 * 64 || context || 0x00 || transcript_hash
    // Max size: 64 + 255 + 1 + 48 = 368 bytes; 512-byte stack buffer is sufficient.
    const hash_len: usize = th.len; // sha256 or sha384 length
    const ctx_len: usize = context.len;
    const total = 64 + ctx_len + 1 + hash_len;
    var out = buf[0..total];
    @memset(out[0..64], 0x20);
    @memcpy(out[64 .. 64 + ctx_len], context);
    out[64 + ctx_len] = 0x00;
    @memcpy(out[64 + ctx_len + 1 ..][0..hash_len], th);
    return out;
}

fn der_decode_ecdsa_sig(sig_der: []const u8, r_out: []u8, s_out: []u8) !void {
    // ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
    var d = asn1.Decoder.init(sig_der);
    const seq = try d.readSequence();
    var s1 = asn1.Decoder.init(seq);
    const r_tlv = try s1.readTLV();
    const s_tlv = try s1.readTLV();
    if (asn1.tagClass(r_tlv.tag) != .universal or asn1.tagNumber(r_tlv.tag) != 2) return error.UnexpectedTag;
    if (asn1.tagClass(s_tlv.tag) != .universal or asn1.tagNumber(s_tlv.tag) != 2) return error.UnexpectedTag;
    // Copy right aligned into fixed size buffers
    if (r_tlv.val.len > r_out.len or s_tlv.val.len > s_out.len) return error.InvalidSignature;
    const r_pad = r_out.len - r_tlv.val.len;
    const s_pad = s_out.len - s_tlv.val.len;
    @memset(r_out[0..r_pad], 0);
    @memcpy(r_out[r_pad..][0..r_tlv.val.len], r_tlv.val);
    @memset(s_out[0..s_pad], 0);
    @memcpy(s_out[s_pad..][0..s_tlv.val.len], s_tlv.val);
}

// ---- RSA-PSS (SHA-256) verification via stdlib ----
//
// Uses std.crypto.Certificate.rsa which provides:
// - Constant-time Montgomery multiplication (no timing oracle)
// - Constant-time PSS signature verification
// - Hardware-optimized big integer arithmetic
//
// This replaces the previous custom big-integer implementation that had:
// - Variable-time modular exponentiation (timing side-channel)
// - Variable-time comparison via std.mem.eql for hash verification
// - ~60-100x slower performance than stdlib Montgomery multiplication

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

/// Stdlib RSA module with constant-time operations.
const rsa = std.crypto.Certificate.rsa;

/// Generic RSA-PSS verification over any `std.crypto.hash` type.
///
/// Shared core used by:
/// - `rsa_pss_verify_sha256` (this file) — TLS 1.3 CertificateVerify SHA-256 path
/// - `parallel.verifyRsaPssWithHash` — parallel-verify path (SHA-256 + SHA-384)
///
/// Supports 1024-/2048-/3072-/4096-bit RSA moduli. Returns `true` on valid
/// signature; `false` on any verification failure; propagates allocator
/// errors from `parseRsaSpki`.
///
/// Per RFC 8446 §4.2.3, salt length equals the hash output length;
/// `std.crypto.Certificate.rsa.PSSSignature.verify` enforces this internally.
pub fn rsaPssVerifyGeneric(
    comptime Hash: type,
    pubkey_spki_der: []const u8,
    msg_signed_content: []const u8,
    sig: []const u8,
    alloc: std.mem.Allocator,
) !bool {
    // Parse SPKI to get modulus and exponent
    var spki = try parseRsaSpki(pubkey_spki_der, alloc);
    defer spki.deinit();

    // Strip leading zero bytes from modulus (ASN.1 INTEGER may have leading 0x00
    // to indicate positive sign, but the crypto API needs the raw magnitude)
    const modulus_raw = spki.modulus;
    const modulus_offset = for (modulus_raw, 0..) |byte, i| {
        if (byte != 0) break i;
    } else modulus_raw.len;
    const modulus = modulus_raw[modulus_offset..];

    // Convert u64 exponent to big-endian bytes (trimmed)
    var exp_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &exp_buf, spki.exponent, .big);
    const exp_offset = for (exp_buf, 0..) |byte, i| {
        if (byte != 0) break i;
    } else exp_buf.len - 1; // keep at least one byte
    const exponent = exp_buf[exp_offset..];

    if (exponent.len > modulus.len) return false;
    if (sig.len != modulus.len) return false;

    // Use inline switch on modulus length to satisfy comptime requirement.
    // Supports 1024-bit (128), 2048-bit (256), 3072-bit (384), 4096-bit (512) RSA keys.
    switch (modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            const public_key = rsa.PublicKey.fromBytes(exponent, modulus) catch
                return false;
            rsa.PSSSignature.verify(modulus_len, sig[0..modulus_len].*, msg_signed_content, public_key, Hash) catch
                return false;
            return true;
        },
        else => return false,
    }
}

/// RSA-PSS SHA-256 verification entry point. Exposed `pub` so the
/// GAP-0109 differential fuzz harness (`tests/fuzz/rsa_pss_verify.zig`)
/// can drive it alongside `parallel.verifyRsaPssWithHash`. Internal
/// callers go through `verifyCertificateVerify`.
///
/// Thin wrapper over `rsaPssVerifyGeneric(Sha256, ...)`. Preserves the
/// original 5-argument signature so the TLS 1.3 CertificateVerify call
/// site at `verifyCertificateVerify` continues to compile unchanged.
pub fn rsa_pss_verify_sha256(pubkey_spki_der: []const u8, msg_signed_content: []const u8, sig: []const u8, salt_len: usize, alloc: std.mem.Allocator) !bool {
    _ = salt_len; // stdlib uses Hash.digest_length (32 for SHA-256) as salt length
    return rsaPssVerifyGeneric(Sha256, pubkey_spki_der, msg_signed_content, sig, alloc);
}

/// Verify a TLS 1.3 CertificateVerify signature.
///
/// Verifies the digital signature from a TLS 1.3 CertificateVerify message,
/// which proves possession of the private key corresponding to the certificate.
///
/// ## TLS 1.3 Signature Construction (RFC 8446 §4.4.3)
/// The signature is computed over a specially constructed message:
/// ```
/// content = 0x20 * 64 || context || 0x00 || transcript_hash
/// signature = Sign(private_key, content)
/// ```
///
/// This construction provides:
/// - **Transcript binding**: Signature covers handshake transcript hash
/// - **Context separation**: Different contexts prevent cross-protocol attacks
/// - **Replay prevention**: Unique transcript hash prevents signature reuse
///
/// ## Parameters
/// - `alg`: Signature algorithm (ECDSA, RSA-PSS, or Ed25519)
/// - `pubkey_spki_der`: DER-encoded SubjectPublicKeyInfo from certificate
/// - `sig`: Signature bytes (DER-encoded for ECDSA, raw for Ed25519/RSA-PSS)
/// - `context`: TLS 1.3 context string:
///   - Client: "TLS 1.3, client CertificateVerify" (33 bytes)
///   - Server: "TLS 1.3, server CertificateVerify" (33 bytes)
/// - `transcript_hash`: SHA-256/SHA-384 hash of all handshake messages up to CertificateVerify
///
/// ## Returns
/// - `true` if signature verification succeeds
/// - `false` if signature is invalid (wrong key, tampered data, or bad signature)
///
/// ## Errors
/// Returns errors for:
/// - Malformed SPKI or signature encoding
/// - Unsupported algorithm parameters
/// - Curve/key size mismatches
/// - Memory allocation failures
///
/// ## RFC References
/// - RFC 8446 §4.4.3 - CertificateVerify message structure and signature
/// - RFC 8446 §4.4.3 - Digital signature content construction
/// - RFC 8446 §4.2.3 - SignatureScheme values and requirements
/// - RFC 5480 - ECDSA signature verification
/// - RFC 8017 §8.1 - RSASSA-PSS signature verification
/// - RFC 8032 §5.1.7 - Ed25519 signature verification
///
/// ## Algorithm-Specific Details
/// ### ECDSA (P-256/SHA-256, P-384/SHA-384)
/// - Signature: DER-encoded SEQUENCE { r INTEGER, s INTEGER }
/// - Hash: SHA-256 for P-256, SHA-384 for P-384
/// - Verification via std.crypto.sign.ecdsa.Ecdsa
///
/// ### RSA-PSS (SHA-256)
/// - Signature: Raw signature bytes (modulus length)
/// - Hash: SHA-256
/// - Salt length: 32 bytes (matches hash length)
/// - MGF: MGF1-SHA256
/// - Verification via std.crypto.Certificate.rsa.PSSSignature (constant-time)
///
/// ### Ed25519
/// - Signature: 64 bytes (R || S), no DER encoding
/// - Pure Ed25519 (no hash-then-sign, signature algorithm handles hashing)
/// - Verification via std.crypto.sign.Ed25519
///
/// ## Security Considerations
/// - Signature verification uses constant-time operations where available
/// - Context string prevents signature reuse in different protocols
/// - Transcript hash binding prevents man-in-the-middle attacks
/// - Public key validation is implicit in verification (invalid keys cause failure)
/// - Returns false on ANY verification failure (do not distinguish failure modes)
///
/// ## Usage Example
/// ```zig
/// const ok = try verifyCertificateVerify(
///     .ecdsa_secp256r1_sha256,
///     cert.spki,
///     signature_from_cert_verify,
///     "TLS 1.3, server CertificateVerify",
///     transcript_hash_sha256
/// );
/// if (!ok) return error.BadCertificateVerify;
/// ```
pub fn verifyCertificateVerify(alg: SigAlg, pubkey_spki_der: []const u8, sig: []const u8, context: []const u8, transcript_hash: []const u8, alloc: std.mem.Allocator) !bool {
    // QUAL-341: Table-driven dispatch over SigAlg. Bit-exact RFC 8446 §4.2.3
    // behaviour preserved — each per-scheme verifier contains the same
    // steps that previously lived in the inline switch arms.
    const entry = schemeEntry(alg);
    return entry.verify(pubkey_spki_der, sig, context, transcript_hash, alloc);
}

/// Sign a TLS 1.3 CertificateVerify for given algorithm using a DER private key blob (currently supports raw PKCS#8 EC for P-256 and Ed25519) and transcript hash.
pub fn signCertificateVerify(alg: SigAlg, privkey_der: []const u8, context: []const u8, transcript_hash: []const u8, alloc: std.mem.Allocator) ![]u8 {
    // QUAL-341: Table-driven dispatch over SigAlg. Schemes without a
    // signer (RSA-PSS, ECDSA P-384) surface error.Unsupported exactly as
    // the prior inline switch's default arm did.
    const entry = schemeEntry(alg);
    const signer = entry.sign orelse return error.Unsupported;
    return signer(privkey_der, context, transcript_hash, alloc);
}

// --- QUAL-341: Scheme-dispatch infrastructure ---------------------------------
//
// Each TLS 1.3 signature scheme is described by a SchemeEntry holding function
// pointers for its verifier and (optionally) signer. verifyCertificateVerify
// and signCertificateVerify look up the entry for the incoming `alg` and
// dispatch; bit-exact behaviour with the pre-refactor inline switches is
// preserved by lifting the original switch-arm bodies verbatim into the
// verifyXxx / signXxx helpers below.

const VerifyFn = *const fn (
    pubkey_spki_der: []const u8,
    sig: []const u8,
    context: []const u8,
    transcript_hash: []const u8,
    alloc: std.mem.Allocator,
) anyerror!bool;

const SignFn = *const fn (
    privkey_der: []const u8,
    context: []const u8,
    transcript_hash: []const u8,
    alloc: std.mem.Allocator,
) anyerror![]u8;

const SchemeEntry = struct {
    alg: SigAlg,
    verify: VerifyFn,
    sign: ?SignFn,
};

const SCHEMES = [_]SchemeEntry{
    .{ .alg = .ed25519, .verify = verifyEd25519, .sign = signEd25519 },
    .{ .alg = .rsa_pss_sha256, .verify = verifyRsaPssSha256, .sign = null },
    .{ .alg = .ecdsa_secp256r1_sha256, .verify = verifyEcdsaP256Sha256, .sign = signEcdsaP256Sha256 },
    .{ .alg = .ecdsa_secp384r1_sha384, .verify = verifyEcdsaP384Sha384, .sign = null },
};

fn schemeEntry(alg: SigAlg) SchemeEntry {
    // Small N=4 linear scan; the enum values are not guaranteed to be
    // contiguous with the array order, so prefer an explicit lookup over
    // @intFromEnum indexing.
    for (SCHEMES) |entry| {
        if (entry.alg == alg) return entry;
    }
    // SigAlg is a closed enum; every variant is represented in SCHEMES.
    unreachable;
}

// --- Per-scheme verifiers (bodies lifted verbatim from pre-refactor switch) ---

fn verifyEd25519(
    pubkey_spki_der: []const u8,
    sig: []const u8,
    context: []const u8,
    transcript_hash: []const u8,
    alloc: std.mem.Allocator,
) anyerror!bool {
    _ = alloc;
    // Parse Ed25519 public key from SPKI
    const pubkey_bytes = try parseEd25519Spki(pubkey_spki_der);
    const pubkey = try Ed25519.PublicKey.fromBytes(pubkey_bytes);
    // Build TLS 1.3 signed content
    var sc_buf: [512]u8 = undefined;
    const sc = tls13_build_context_and_hash(.ed25519, context, transcript_hash, &sc_buf);
    // Verify Ed25519 signature
    if (sig.len != 64) return false;
    const signature = Ed25519.Signature.fromBytes(sig[0..64].*);
    signature.verify(sc, pubkey) catch return false;
    return true;
}

fn verifyRsaPssSha256(
    pubkey_spki_der: []const u8,
    sig: []const u8,
    context: []const u8,
    transcript_hash: []const u8,
    alloc: std.mem.Allocator,
) anyerror!bool {
    // Build TLS 1.3 signed content: 64 spaces || context || 0x00 || transcript_hash
    var sc_buf: [512]u8 = undefined;
    const sc = tls13_build_context_and_hash(.rsa_pss_sha256, context, transcript_hash, &sc_buf);
    return rsa_pss_verify_sha256(pubkey_spki_der, sc, sig, 32, alloc);
}

fn verifyEcdsaP256Sha256(
    pubkey_spki_der: []const u8,
    sig: []const u8,
    context: []const u8,
    transcript_hash: []const u8,
    alloc: std.mem.Allocator,
) anyerror!bool {
    // Parse SPKI and use std.crypto ECDSA (P-256/SHA-256)
    var spki = try parseEcdsaSpki(pubkey_spki_der, alloc);
    defer spki.deinit();
    if (!spki.curve_p256) return false;
    const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, Sha256);
    const signature = Ecdsa.Signature.fromDer(sig) catch return false;
    const pubkey = Ecdsa.PublicKey.fromSec1(spki.sec1_uncompressed) catch return false;
    var sc_buf: [512]u8 = undefined;
    const sc = tls13_build_context_and_hash(.ecdsa_secp256r1_sha256, context, transcript_hash, &sc_buf);
    signature.verify(sc, pubkey) catch return false;
    return true;
}

fn verifyEcdsaP384Sha384(
    pubkey_spki_der: []const u8,
    sig: []const u8,
    context: []const u8,
    transcript_hash: []const u8,
    alloc: std.mem.Allocator,
) anyerror!bool {
    // Parse SPKI and use std.crypto ECDSA (P-384/SHA-384)
    var spki = try parseEcdsaSpki(pubkey_spki_der, alloc);
    defer spki.deinit();
    if (spki.curve_p256) return false; // expect P-384
    const Ecdsa384 = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P384, Sha384);
    const signature = Ecdsa384.Signature.fromDer(sig) catch return false;
    const pubkey = Ecdsa384.PublicKey.fromSec1(spki.sec1_uncompressed) catch return false;
    var sc_buf: [512]u8 = undefined;
    const sc = tls13_build_context_and_hash(.ecdsa_secp384r1_sha384, context, transcript_hash, &sc_buf);
    signature.verify(sc, pubkey) catch return false;
    return true;
}

// --- Per-scheme signers (bodies lifted verbatim from pre-refactor switch) ----

fn signEd25519(
    privkey_der: []const u8,
    context: []const u8,
    transcript_hash: []const u8,
    alloc: std.mem.Allocator,
) anyerror![]u8 {
    // Parse Ed25519 private key from PKCS#8
    var seed = try parsePkcs8Ed25519PrivateKey(privkey_der);
    defer std.crypto.secureZero(u8, &seed);
    // Use standard library Ed25519 - generate keypair from seed
    var kp = try Ed25519.KeyPair.generateDeterministic(seed);
    defer std.crypto.secureZero(u8, &kp.secret_key.bytes);
    // Build TLS 1.3 signed content
    var ts_buf: [512]u8 = undefined;
    const to_sign = tls13_build_context_and_hash(.ed25519, context, transcript_hash, &ts_buf);
    // Sign the message
    const sig = try kp.sign(to_sign, null);
    // Return signature (Ed25519 signatures are always 64 bytes, no DER encoding)
    const result = try alloc.alloc(u8, 64);
    @memcpy(result, &sig.toBytes());
    return result;
}

fn signEcdsaP256Sha256(
    privkey_der: []const u8,
    context: []const u8,
    transcript_hash: []const u8,
    alloc: std.mem.Allocator,
) anyerror![]u8 {
    // Preferred: parse PKCS#8 -> ECPrivateKey -> scalar. Fallback to legacy pattern scan.
    var sk: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &sk);
    traceSig("[SIG] Starting ECDSA P-256 signature, privkey_der len={d}\n", .{privkey_der.len});
    if (parsePkcs8EcdsaP256PrivateKey(privkey_der, &sk)) |ok| {
        _ = ok; // already written into sk
        traceSigBytes("[SIG] Successfully parsed PKCS#8, scalar: ", &sk);
    } else |err| switch (err) {
        error.BadKey, error.Unsupported, error.Parse => {
            // Legacy heuristic fallback (scan for 0x04 0x20 <32-bytes>) used by early tests.
            if (privkey_der.len < 34) return error.BadKey;
            var idx: ?usize = null;
            var i: usize = 0;
            while (i + 34 <= privkey_der.len) : (i += 1) {
                if (privkey_der[i] == 0x04 and privkey_der[i + 1] == 0x20) {
                    idx = i + 2;
                    break;
                }
            }
            const off = idx orelse return error.BadKey;
            @memcpy(sk[0..], privkey_der[off .. off + 32]);
        },
    }
    const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, Sha256);
    // Build signing context content
    var ts_buf: [512]u8 = undefined;
    const to_sign = tls13_build_context_and_hash(.ecdsa_secp256r1_sha256, context, transcript_hash, &ts_buf);
    traceSig("[SIG] Message to sign len={d}\n", .{to_sign.len});
    const secret = try Ecdsa.SecretKey.fromBytes(sk);
    const key_pair = try Ecdsa.KeyPair.fromSecretKey(secret);
    // Pass message then optional random noise (null => deterministic per RFC6979)
    const signature = try key_pair.sign(to_sign, null);
    traceSigBytes("[SIG] Generated signature r=", signature.r[0..8]);
    traceSigBytes("[SIG] ..., s=", signature.s[0..8]);

    // Manually DER-encode (SEQUENCE { r INTEGER, s INTEGER }) per RFC 3279/5480
    const r_full = signature.r; // [32]u8
    const s_full = signature.s; // [32]u8

    // Trim leading zeros but keep at least one byte
    const r_trim = trimLeading(&r_full);
    const s_trim = trimLeading(&s_full);
    const r_need_pad: bool = (r_trim[0] & 0x80) != 0;
    const s_need_pad: bool = (s_trim[0] & 0x80) != 0;
    // Use @intFromBool to avoid comptime_int dependency on runtime control flow
    const r_len: usize = r_trim.len + @intFromBool(r_need_pad);
    const s_len: usize = s_trim.len + @intFromBool(s_need_pad);
    const seq_len: usize = 2 + r_len + 2 + s_len; // INTEGER headers + values
    if (seq_len + 2 >= 128) return error.Encode; // should never happen for P-256
    var out = try alloc.alloc(u8, 2 + seq_len);
    var o: usize = 0;
    out[o] = 0x30;
    o += 1; // SEQUENCE
    out[o] = @intCast(seq_len);
    o += 1;
    out[o] = 0x02;
    o += 1; // INTEGER r
    out[o] = @intCast(r_len);
    o += 1;
    if (r_need_pad) {
        out[o] = 0x00;
        o += 1;
    }
    @memcpy(out[o .. o + r_trim.len], r_trim);
    o += r_trim.len;
    out[o] = 0x02;
    o += 1; // INTEGER s
    out[o] = @intCast(s_len);
    o += 1;
    if (s_need_pad) {
        out[o] = 0x00;
        o += 1;
    }
    @memcpy(out[o .. o + s_trim.len], s_trim);
    o += s_trim.len;
    // Security: Use explicit error handling instead of debug.assert
    // (debug.assert is stripped in release builds, CWE-617)
    if (o != out.len) return error.Encode;
    return out;
}

fn trimLeading(x: []const u8) []const u8 {
    var j: usize = 0;
    while (j + 1 < x.len and x[j] == 0) : (j += 1) {}
    return x[j..];
}

// ---- Minimal PKCS#8 / ECPrivateKey parsing (P-256 only) ----
// Returns error.BadKey on generic structural or OID mismatch, error.Parse on malformed DER.
// Writes 32-byte scalar into out and returns void on success.
/// Parse Ed25519 public key from SubjectPublicKeyInfo (returns 32-byte public key)
pub fn parseEd25519Spki(spki_der: []const u8) ![32]u8 {
    var d = asn1.Decoder.init(spki_der);
    const seq = try d.readSequence();
    var s1 = asn1.Decoder.init(seq);
    const algo_seq = try s1.readSequence();
    var a1 = asn1.Decoder.init(algo_seq);
    const algo_oid = try a1.readOID();
    // id-Ed25519: 1.3.101.112 -> DER: 06 03 2B 65 70
    const ed25519_oid = [_]u8{ 0x2B, 0x65, 0x70 };
    if (!std.mem.eql(u8, algo_oid, &ed25519_oid)) return error.UnexpectedAlgorithm;
    // No parameters for Ed25519
    // subjectPublicKey BIT STRING
    const bitstr = try s1.readBitString();
    if (bitstr.len != 32) return error.InvalidPublicKey;
    var result: [32]u8 = undefined;
    @memcpy(&result, bitstr);
    return result;
}

/// Parse Ed25519 private key (seed) from PKCS#8 (returns 32-byte seed)
fn parsePkcs8Ed25519PrivateKey(der: []const u8) ![32]u8 {
    var d = asn1.Decoder.init(der);
    const seq = try d.readSequence();
    var s1 = asn1.Decoder.init(seq);
    // version INTEGER (expect 0)
    const ver_tlv = try s1.readTLV();
    if (asn1.tagClass(ver_tlv.tag) != .universal or asn1.tagNumber(ver_tlv.tag) != 2) return error.UnexpectedTag;
    if (ver_tlv.val.len != 1 or ver_tlv.val[0] != 0x00) return error.BadKey;
    // algorithm AlgorithmIdentifier = SEQUENCE
    const algo_seq = try s1.readSequence();
    var a1 = asn1.Decoder.init(algo_seq);
    const algo_oid = try a1.readOID();
    // id-Ed25519: 1.3.101.112 -> DER: 06 03 2B 65 70
    const ed25519_oid = [_]u8{ 0x2B, 0x65, 0x70 };
    if (!std.mem.eql(u8, algo_oid, &ed25519_oid)) return error.UnexpectedAlgorithm;
    // privateKey OCTET STRING containing the 32-byte seed wrapped in OCTET STRING
    const pk_oct = try s1.readOctetString();
    // Ed25519 private key is wrapped as OCTET STRING containing the 32-byte seed
    if (pk_oct.len < 34) return error.BadKey;
    // Parse inner OCTET STRING
    var d2 = asn1.Decoder.init(pk_oct);
    const seed_oct = try d2.readOctetString();
    if (seed_oct.len != 32) return error.BadKey;
    var result: [32]u8 = undefined;
    @memcpy(&result, seed_oct);
    return result;
}

fn parsePkcs8EcdsaP256PrivateKey(der: []const u8, out: *[32]u8) !void {
    if (der.len < 16) return error.Parse;
    var i: usize = 0;
    const T = struct {
        fn need(n: usize, total: usize) !void {
            if (n > total) return error.Parse;
        }
        fn readLen(data: []const u8, idx: *usize) !usize {
            var pos = idx.*;
            if (pos >= data.len) return error.Parse;
            const b = data[pos];
            pos += 1;
            if ((b & 0x80) == 0) {
                idx.* = pos;
                return b;
            } // short form
            const nbytes = b & 0x7f;
            if (nbytes == 0 or nbytes > 2) return error.Parse; // limit length size
            if (pos + nbytes > data.len) return error.Parse;
            var l: usize = 0;
            var j: usize = 0;
            while (j < nbytes) : (j += 1) {
                l = (l << 8) | data[pos + j];
            }
            pos += nbytes;
            idx.* = pos;
            return l;
        }
    };

    // PrivateKeyInfo ::= SEQUENCE
    if (der[i] != 0x30) return error.Parse;
    i += 1;
    const seq_len = try T.readLen(der, &i);
    if (i + seq_len != der.len) return error.Parse;

    // version INTEGER (expect 0)
    if (der[i] != 0x02) return error.Parse;
    i += 1;
    const ver_len = try T.readLen(der, &i);
    if (ver_len != 1 or i + ver_len > der.len) return error.Parse;
    if (der[i] != 0x00) return error.BadKey; // version must be 0
    i += ver_len;

    // algorithm AlgorithmIdentifier = SEQUENCE
    if (der[i] != 0x30) return error.Parse;
    i += 1;
    const alg_len = try T.readLen(der, &i);
    if (i + alg_len > der.len) return error.Parse;
    const alg_end = i + alg_len;
    // OID ecPublicKey
    if (i >= alg_end or der[i] != 0x06) return error.Parse;
    i += 1;
    const oid1_len = try T.readLen(der, &i);
    if (i + oid1_len > alg_end) return error.Parse;
    const oid_ec = der[i .. i + oid1_len];
    i += oid1_len;
    // parameters OID namedCurve
    if (i >= alg_end or der[i] != 0x06) return error.Parse;
    i += 1;
    const oid2_len = try T.readLen(der, &i);
    if (i + oid2_len > alg_end) return error.Parse;
    const oid_curve = der[i .. i + oid2_len];
    i += oid2_len;
    if (i != alg_end) return error.Parse;
    // id-ecPublicKey 1.2.840.10045.2.1  -> DER: 06 07 2A 86 48 CE 3D 02 01
    const ec_pub_const = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    if (!asn1.oidEqual(oid_ec, &ec_pub_const)) return error.BadKey;
    // prime256v1 / secp256r1 1.2.840.10045.3.1.7 -> 06 08 2A 86 48 CE 3D 03 01 07
    const p256_const = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    if (!asn1.oidEqual(oid_curve, &p256_const)) return error.Unsupported; // not P-256

    // privateKey OCTET STRING containing ECPrivateKey structure
    if (der[i] != 0x04) return error.Parse;
    i += 1;
    const pk_oct_len = try T.readLen(der, &i);
    if (i + pk_oct_len > der.len) return error.Parse;
    const pk_oct = der[i .. i + pk_oct_len];
    i += pk_oct_len;
    // ignore optional attributes / publicKey

    // Parse ECPrivateKey inside pk_oct
    var j: usize = 0;
    if (pk_oct.len < 4) return error.Parse;
    if (pk_oct[j] != 0x30) return error.Parse;
    j += 1;
    const ec_seq_len = try T.readLen(pk_oct, &j);
    if (j + ec_seq_len != pk_oct.len) return error.Parse;
    // version INTEGER (expect 1)
    if (pk_oct[j] != 0x02) return error.Parse;
    j += 1;
    const ec_ver_len = try T.readLen(pk_oct, &j);
    if (ec_ver_len != 1 or j + ec_ver_len > pk_oct.len) return error.Parse;
    if (pk_oct[j] != 0x01) return error.BadKey; // expect 1
    j += ec_ver_len;
    // privateKey OCTET STRING (expect 32 bytes)
    if (pk_oct[j] != 0x04) return error.Parse;
    j += 1;
    const sk_len = try T.readLen(pk_oct, &j);
    if (sk_len != 32 or j + sk_len > pk_oct.len) return error.BadKey;
    @memcpy(out[0..], pk_oct[j .. j + sk_len]);
    // success
    return;
}
