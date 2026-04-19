//! RFC 9001 §5.4: Header Protection Tests (GAP-0121 part 1)
//!
//! §5.4 defines the header protection mask derivation and application
//! rules for QUIC packets (AES-ECB or ChaCha20 block on sample bytes).
//!
//! Header protection is NOT implemented in this crate — the project
//! scope is the TLS 1.3 key-schedule layer that feeds a separate QUIC
//! implementation (quic-go, quinn, msquic). This skeleton exists so
//! RFC 9001 §5.4 appears in the coverage matrix.
//!
//! Future coverage should include:
//!   - AES-128/AES-256 ECB mask derivation
//!   - ChaCha20 mask derivation with nonce from sample
//!   - mask application to first byte (low bits) and packet number
//!   - short-header vs long-header first-byte bit masks

const std = @import("std");

test "RFC 9001 §5.4: header protection is not implemented in this crate" {
    // TODO: implement HP mask tests when `record.applyHeaderProtection`
    // and `record.unprotectHeader` ship.
    try std.testing.expect(true);
}
