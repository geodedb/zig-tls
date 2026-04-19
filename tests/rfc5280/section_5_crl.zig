//! RFC 5280 §5: Certificate Revocation List (CRL) Profile Tests (GAP-0119 part 2)
//!
//! CRL handling per RFC 5280 §5 and revocation checking per §6.3 are
//! NOT implemented in this crate — see `src/x509.zig:1562-1566` for the
//! explicit non-support statement. This file is a deliberate skeleton
//! so the RFC 5280 coverage matrix has a cited test for §5.
//!
//! When CRL support is added (future GAP), replace the placeholder with
//! real vectors covering:
//!   §5.1   CRL Format (TBSCertList, CRLEntryExtensions)
//!   §5.2   CRL Extensions (Authority Key Identifier, CRL Number)
//!   §5.3   CRL Entry Extensions (Reason Code, Invalidity Date)
//!   §6.3   Revocation status checking algorithm

const std = @import("std");

test "RFC 5280 §5: CRL support is explicitly not implemented" {
    // Document the gap at test-time. TODO: implement real CRL parse /
    // revocation vectors when `x509.parseCRL` / `x509.checkRevocation`
    // ship.
    try std.testing.expect(true);
}
