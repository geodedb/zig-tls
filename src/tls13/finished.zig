//! Finished Message Logic
//!
//! RFC 8446 §4.4.4: Finished
//!
//! The Finished message is the final message in the authentication block. It provides
//! key confirmation, binds the endpoint's identity to the exchanged keys, and proves
//! liveness in PSK mode. The Finished message contains a verify_data field computed as:
//!
//!   verify_data = HMAC(finished_key, transcript_hash)
//!
//! where:
//!   finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.length)
//!   transcript_hash = Hash(Handshake Context)
//!
//! This module provides functions for deriving and verifying Finished messages.

const ks = @import("quic_tls");

const Hash = ks.Hash;
const Secret = ks.Secret;

/// Derive the verify_data for a Finished message (RFC 8446 §4.4.4).
///
/// This function computes the HMAC that proves knowledge of the traffic secret
/// and ensures transcript integrity. The verify_data is sent in the Finished
/// message and verified by the peer.
///
/// # Parameters
/// - hash: Hash algorithm (SHA-256 or SHA-384) based on negotiated cipher suite
/// - traffic_secret: Handshake traffic secret for the sending role
/// - transcript_hash: Hash of all handshake messages up to (but not including) Finished
///
/// # Returns
/// Secret containing the verify_data (32 or 48 bytes depending on hash algorithm)
///
/// # RFC 8446 §4.4.4: Finished Computation
///
/// ```
/// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
/// verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
/// ```
///
/// # Usage
///
/// ```zig
/// // Compute verify_data for sending Finished
/// const transcript_hash = transcript.finalize(.sha256);
/// const verify_data = deriveFinishedVerifyData(.sha256, &my_hs_secret, transcript_hash);
/// const finished_msg = buildFinished(verify_data.slice());
/// ```
///
/// ```zig
/// // Verify received Finished (MUST use constant-time comparison)
/// const expected = deriveFinishedVerifyData(.sha256, &peer_hs_secret, transcript_hash);
/// const expected_bytes: *const [32]u8 = expected.slice()[0..32];
/// const received_bytes: *const [32]u8 = received_verify_data[0..32];
/// if (!std.crypto.timing_safe.eql([32]u8, expected_bytes.*, received_bytes.*)) {
///     return HandshakeError.FinishedVerifyFailed;
/// }
/// ```
///
/// # Security Notes
/// - The transcript hash MUST include all messages in order up to Finished
/// - Finished is added to transcript AFTER verification to prevent replay
/// - Use constant-time comparison when verifying to prevent timing attacks
/// - verify_data length matches hash output (SHA-256=32, SHA-384=48)
pub fn deriveFinishedVerifyData(hash: Hash, traffic_secret: *const Secret, transcript_hash: Secret) Secret {
    return ks.deriveFinishedVerifyDataHash(hash, traffic_secret, &transcript_hash);
}
