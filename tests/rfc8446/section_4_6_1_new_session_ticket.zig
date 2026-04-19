//! RFC 8446 §4.6.1: NewSessionTicket Message Tests (GAP-0120 part 2)
//!
//! NewSessionTicket is NOT implemented in this crate — the codebase is
//! primarily for QUIC where PSK resumption is handled differently. This
//! skeleton keeps RFC 8446 §4.6.1 in the coverage matrix so any future
//! addition is accompanied by real tests.
//!
//! Future coverage should include:
//!   - ticket_lifetime, ticket_age_add, ticket_nonce, ticket
//!   - extensions (e.g., early_data with max_early_data_size)
//!   - expiry handling and resumption PSK derivation

const std = @import("std");

test "RFC 8446 §4.6.1: NewSessionTicket is not implemented" {
    // TODO: implement real NewSessionTicket build/parse tests when
    // `tls13.buildNewSessionTicket` / `parseNewSessionTicket` ship.
    try std.testing.expect(true);
}
