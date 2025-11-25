//! TLS 1.3 CertificateVerify Message
//!
//! Implements CertificateVerify message construction and signature computation
//! per RFC 8446 §4.4.3. The CertificateVerify message contains a digital signature
//! over the handshake transcript, proving possession of the private key.
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.4.3: CertificateVerify message structure and computation
//! - RFC 8446 §4.2.3: Signature Scheme requirements
//! - RFC 8446 §4.4: Authentication Messages
//!
//! ## Message Flow
//!
//! CertificateVerify is sent immediately after Certificate to prove key possession:
//! ```
//! Server                                           Client
//!   Certificate
//!   CertificateVerify     -------->
//!   Finished              -------->
//!                         <--------  Finished
//! ```
//!
//! ## Security Considerations
//!
//! - Signature MUST cover the complete transcript hash
//! - Context string prevents cross-protocol attacks
//! - 64-space padding prevents attacks on short messages

const std = @import("std");
const ks = @import("quic_tls");
const H = ks.H; // SHA-256
const core_types = @import("core_types.zig");

/// Build CertificateVerify message (RFC 8446 §4.4.3).
///
/// Constructs a CertificateVerify message containing a digital signature over
/// the handshake transcript, proving possession of the private key corresponding
/// to the certificate.
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for message buffer
/// - `signature_scheme`: Signature algorithm used (must match certificate key type)
/// - `signature`: Signature bytes (format depends on signature_scheme)
///
/// ## Returns
///
/// - `[]u8`: Serialized CertificateVerify message (caller owns memory, must free)
///
/// ## Message Format (RFC 8446 §4.4.3)
///
/// ```
/// struct {
///     SignatureScheme algorithm;
///     opaque signature<0..2^16-1>;
/// } CertificateVerify;
/// ```
///
/// ## Signature Computation
///
/// The signature covers a specially formatted message (see `computeCertificateVerifySignature`):
/// ```
/// signature_input = 64 spaces || context_string || 0x00 || transcript_hash
/// ```
///
/// Where:
/// - `context_string` = "TLS 1.3, server CertificateVerify" or "TLS 1.3, client CertificateVerify"
/// - `transcript_hash` = Hash(Handshake Context || Certificate)
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.4.3: CertificateVerify message structure
/// - RFC 8446 §4.4.3: Digital signature computation
/// - RFC 8446 §4.2.3: Signature scheme requirements
///
/// ## Security Critical
///
/// - Signature MUST cover the complete transcript hash
/// - Context string prevents cross-protocol attacks
/// - 64-space padding prevents attacks on short messages
///
/// ## Usage
///
/// ```zig
/// const signature = try computeCertificateVerifySignature(
///     private_key,
///     .ed25519,
///     transcript_hash,
///     true  // is_server
/// );
/// const cert_verify_msg = try buildCertificateVerify(
///     allocator,
///     .ed25519,
///     &signature
/// );
/// defer allocator.free(cert_verify_msg);
/// ```
pub fn buildCertificateVerify(
    allocator: std.mem.Allocator,
    signature_scheme: core_types.SignatureScheme,
    signature: []const u8,
) ![]u8 {
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // Signature algorithm
    const scheme_value = @intFromEnum(signature_scheme);
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(scheme_value >> 8),
        @intCast(scheme_value & 0xff),
    });

    // Signature length
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(signature.len >> 8),
        @intCast(signature.len & 0xff),
    });

    // Signature
    try msg.appendSlice(allocator, signature);

    return msg.toOwnedSlice(allocator);
}

/// Compute the signature for CertificateVerify (RFC 8446 §4.4.3).
///
/// Creates a digital signature over the handshake transcript hash using the
/// specified signature scheme. The signature proves possession of the private
/// key corresponding to the certificate.
///
/// ## Parameters
///
/// - `private_key`: Private key bytes (format depends on signature_scheme)
/// - `signature_scheme`: Signature algorithm to use
/// - `transcript_hash`: Hash of handshake messages up to and including Certificate
/// - `is_server`: true for server CertificateVerify, false for client
///
/// ## Returns
///
/// - `[64]u8`: Signature bytes (Ed25519 produces 64-byte signatures)
/// - `error.UnsupportedSignatureScheme`: Signature scheme not implemented
/// - `error.InvalidPrivateKey`: Private key format invalid
///
/// ## Signature Input Format (RFC 8446 §4.4.3)
///
/// ```
/// signature_input = 0x20 * 64 || context_string || 0x00 || transcript_hash
/// ```
///
/// Where:
/// - 64 spaces (0x20) prevent short message attacks
/// - context_string: "TLS 1.3, server CertificateVerify" or "TLS 1.3, client CertificateVerify"
/// - 0x00 separator byte
/// - transcript_hash: SHA-256 hash of handshake messages
///
/// ## Context String (RFC 8446 §4.4.3)
///
/// The context string prevents cross-protocol attacks by binding the signature
/// to the specific role (server vs client) and protocol version (TLS 1.3):
/// - Server: "TLS 1.3, server CertificateVerify" (33 bytes)
/// - Client: "TLS 1.3, client CertificateVerify" (33 bytes)
///
/// ## Current Implementation
///
/// - Supports **Ed25519 only** (32-byte seed, 64-byte signature)
/// - Other signature schemes return error.UnsupportedSignatureScheme
///
/// ## Security Considerations
///
/// - Context string prevents cross-protocol attacks (server vs client)
/// - 64-space padding prevents attacks on short messages
/// - Signature covers the complete transcript (prevents tampering)
///
/// ## Usage
///
/// ```zig
/// // Server signing
/// const server_sig = try computeCertificateVerifySignature(
///     server_private_key,
///     .ed25519,
///     transcript_hash,
///     true  // is_server
/// );
///
/// // Client signing (for mutual TLS)
/// const client_sig = try computeCertificateVerifySignature(
///     client_private_key,
///     .ed25519,
///     transcript_hash,
///     false  // is_server
/// );
/// ```
pub fn computeCertificateVerifySignature(
    private_key: []const u8,
    signature_scheme: core_types.SignatureScheme,
    transcript_hash: [H.digest_length]u8,
    is_server: bool,
) ![64]u8 {
    // TLS 1.3 CertificateVerify context string
    const context_string = if (is_server)
        "TLS 1.3, server CertificateVerify"
    else
        "TLS 1.3, client CertificateVerify";

    // Build the message to sign
    var msg: [64 + context_string.len + 1 + H.digest_length]u8 = undefined;
    @memset(msg[0..64], 0x20); // 64 spaces
    @memcpy(msg[64 .. 64 + context_string.len], context_string);
    msg[64 + context_string.len] = 0; // separator
    @memcpy(msg[65 + context_string.len ..], &transcript_hash);

    // For now, we only support Ed25519
    if (signature_scheme != .ed25519) {
        return error.UnsupportedSignatureScheme;
    }

    // Parse the private key (assuming Ed25519 seed format)
    if (private_key.len != 32) {
        return error.InvalidPrivateKey;
    }

    const kp = try std.crypto.sign.Ed25519.KeyPair.create(private_key[0..32].*);
    const signature = try std.crypto.sign.Ed25519.sign(&msg, kp, null);

    return signature;
}

/// Parsed CertificateVerify message result.
///
/// Contains the signature algorithm and signature bytes extracted from
/// a CertificateVerify message.
pub const ParsedCertificateVerify = struct {
    algorithm: core_types.SignatureScheme,
    signature: []const u8,
};

/// Parse a CertificateVerify message (RFC 8446 §4.4.3).
///
/// Extracts the signature algorithm and signature from a CertificateVerify message.
/// The signature should be verified against the transcript hash using the
/// peer's public key from their certificate.
///
/// ## Parameters
///
/// - `body`: Raw CertificateVerify message body (after handshake header)
///
/// ## Returns
///
/// - `ParsedCertificateVerify`: Parsed algorithm and signature
/// - `error.InvalidMessage`: Message too short or malformed
///
/// ## Message Format (RFC 8446 §4.4.3)
///
/// ```
/// struct {
///     SignatureScheme algorithm;
///     opaque signature<0..2^16-1>;
/// } CertificateVerify;
/// ```
pub fn parseCertificateVerify(body: []const u8) !ParsedCertificateVerify {
    // Minimum length: 2 (algorithm) + 2 (signature length) = 4 bytes
    if (body.len < 4) {
        return error.InvalidMessage;
    }

    // Parse SignatureScheme (2 bytes)
    const algo_raw = (@as(u16, body[0]) << 8) | body[1];
    const algorithm = std.meta.intToEnum(core_types.SignatureScheme, algo_raw) catch {
        return error.UnsupportedSignatureScheme;
    };

    // Parse signature length (2 bytes)
    const sig_len = (@as(u16, body[2]) << 8) | body[3];

    // Validate signature length
    if (body.len < 4 + sig_len) {
        return error.InvalidMessage;
    }

    // Extract signature slice
    const signature = body[4 .. 4 + sig_len];

    return ParsedCertificateVerify{
        .algorithm = algorithm,
        .signature = signature,
    };
}
