// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TLS 1.3 Finished Message
//!
//! Implements the Finished message construction and verify_data computation
//! per RFC 8446 §4.4.4. The Finished message provides key confirmation and
//! binds the endpoint's identity to the handshake messages.
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.4.4: Finished message structure and computation
//! - RFC 8446 §4.4: Authentication Messages
//! - RFC 8446 §7.1: HKDF-Expand-Label key derivation
//!
//! ## Message Flow
//!
//! Both client and server send Finished messages to complete the handshake:
//! ```
//! Server                                           Client
//!   ...
//!   Certificate
//!   CertificateVerify
//!   Finished              -------->
//!                         <--------  Finished
//! ```
//!
//! ## Security Considerations
//!
//! - verify_data authenticates the entire handshake transcript
//! - Both client and server must verify each other's Finished messages
//! - Mismatch indicates handshake tampering (MUST abort with decrypt_error)
//! - Finished messages are encrypted with handshake traffic keys

const std = @import("std");
const ks = @import("quic_tls");
const H = ks.H; // SHA-256

/// Build Finished message (RFC 8446 §4.4.4).
///
/// Constructs a Finished message containing an HMAC over the handshake transcript.
/// The Finished message authenticates the entire handshake and confirms that both
/// peers have the same view of the handshake messages.
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for message buffer
/// - `verify_data`: HMAC-based verification data (see `deriveFinishedVerifyData`)
///
/// ## Returns
///
/// - `[]u8`: Serialized Finished message (caller owns memory, must free)
///
/// ## Verify Data Computation
///
/// ```
/// finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length)
/// verify_data = HMAC(finished_key, transcript_hash)
/// ```
///
/// Where:
/// - `base_key` = client_handshake_traffic_secret or server_handshake_traffic_secret
/// - `transcript_hash` = Hash(all handshake messages up to but not including Finished)
///
/// ## Message Format (RFC 8446 §4.4.4)
///
/// ```
/// struct {
///     opaque verify_data[Hash.length];
/// } Finished;
/// ```
///
/// For SHA-256 cipher suites, verify_data is 32 bytes.
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.4.4: Finished message structure and computation
/// - RFC 8446 §4.4: Authentication Messages
///
/// ## Security Critical
///
/// - verify_data MUST be computed over the complete transcript
/// - Both client and server send Finished messages
/// - Handshake is not complete until both Finished messages are verified
///
/// ## Usage
///
/// ```zig
/// const verify_data = deriveFinishedVerifyData(handshake_secret, transcript_hash);
/// const finished_msg = try buildFinished(allocator, &verify_data);
/// defer allocator.free(finished_msg);
/// ```
pub fn buildFinished(
    allocator: std.mem.Allocator,
    verify_data: []const u8,
) ![]u8 {
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);
    try msg.appendSlice(allocator, verify_data);
    return msg.toOwnedSlice(allocator);
}

/// Derive the Finished verify data (RFC 8446 §4.4.4).
///
/// Computes the HMAC-based verify_data for the Finished message using the
/// handshake traffic secret and transcript hash.
///
/// ## Parameters
///
/// - `traffic_secret`: Handshake traffic secret (client or server)
/// - `transcript_hash`: Hash of all handshake messages up to but not including Finished
///
/// ## Returns
///
/// - `[H.digest_length]u8`: Verify data for Finished message (32 bytes for SHA-256)
///
/// ## Computation (RFC 8446 §4.4.4)
///
/// ```
/// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
/// verify_data = HMAC(finished_key, transcript_hash)
/// ```
///
/// Where:
/// - `BaseKey` = client_handshake_traffic_secret or server_handshake_traffic_secret
/// - HKDF-Expand-Label is defined in RFC 8446 §7.1
/// - HMAC uses the hash function from the negotiated cipher suite (SHA-256)
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.4.4: Finished message verify_data computation
/// - RFC 8446 §7.1: HKDF-Expand-Label key derivation
///
/// ## Security Critical
///
/// - verify_data authenticates the entire handshake transcript
/// - Both client and server must verify each other's Finished messages
/// - Mismatch indicates handshake tampering (MUST abort with decrypt_error)
///
/// ## Usage
///
/// ```zig
/// // Server computes Finished verify_data
/// const server_verify = deriveFinishedVerifyData(
///     server_handshake_traffic_secret,
///     transcript_hash
/// );
///
/// // Client computes Finished verify_data
/// const client_verify = deriveFinishedVerifyData(
///     client_handshake_traffic_secret,
///     transcript_hash
/// );
/// ```
pub fn deriveFinishedVerifyData(
    traffic_secret: [H.digest_length]u8,
    transcript_hash: [H.digest_length]u8,
) [H.digest_length]u8 {
    var finished_key: [H.digest_length]u8 = undefined;
    // SAFETY: traffic_secret is [H.digest_length]u8 (Sha256, 32 bytes), so expandLabel matches
    // sha256 and will not return InvalidSecretLength. Label "finished" (14 bytes with "tls13 "
    // prefix) and empty context fit within the 256-byte fixed buffer. Allocation cannot fail.
    ks.expandLabel(traffic_secret[0..], "finished", &[_]u8{}, &finished_key) catch unreachable;
    return ks.hmacSha256(&finished_key, &transcript_hash);
}
