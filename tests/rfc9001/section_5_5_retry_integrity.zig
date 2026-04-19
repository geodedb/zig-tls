//! RFC 9001 §5.5: Retry Packet Integrity Tests (GAP-0121 part 1)
//!
//! §5.5 defines the 16-byte integrity tag appended to Retry packets,
//! computed with AES-128-GCM over the pseudo-packet using a
//! version-specific fixed key and the client's Destination Connection ID
//! as the AAD.
//!
//! Retry integrity is NOT implemented in this crate. This skeleton
//! keeps RFC 9001 §5.5 in the coverage matrix so any future addition
//! is accompanied by a real KAT (known-answer test).
//!
//! Future coverage should include the RFC 9001 §A.4 test vector and
//! the QUIC v2 equivalents.

const std = @import("std");

test "RFC 9001 §5.5: retry integrity is not implemented in this crate" {
    // TODO: implement retry-integrity KATs when `record.retryIntegrityTag`
    // ships.
    try std.testing.expect(true);
}
