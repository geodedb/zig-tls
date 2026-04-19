//! RFC 8446: TLS 1.3 Test Suite
//!
//! This module organizes tests by RFC 8446 section number to facilitate:
//! 1. Easy navigation to tests for specific protocol features
//! 2. Verification of RFC compliance per section
//! 3. Addition of new tests matching RFC structure
//!
//! ## Test Organization
//!
//! Tests are organized to match RFC 8446 structure:
//! - §4.1.2: ClientHello message tests
//! - §4.1.3: ServerHello message tests
//! - §4.2: Extension tests (key_share, supported_versions, etc.)
//! - §4.4.1: Transcript hash tests
//! - §4.4.4: Finished message tests
//! - §5: Record layer tests (TLSPlaintext, AEAD)
//! - §7.1: Key schedule and HKDF tests
//! - Appendix A: Complete handshake test vectors
//!
//! ## Usage
//!
//! Run all RFC 8446 tests:
//! ```bash
//! zig build test-rfc8446
//! ```
//!
//! Run specific section tests:
//! ```bash
//! zig test tests/rfc8446/section_4_1_2_client_hello.zig
//! ```

const std = @import("std");

// Re-export test modules for discovery
pub const section_4_1_2_client_hello = @import("section_4_1_2_client_hello.zig");
pub const section_4_1_3_server_hello = @import("section_4_1_3_server_hello.zig");
pub const section_4_2_extensions = @import("section_4_2_extensions.zig");
pub const section_4_3_encrypted_extensions = @import("section_4_3_encrypted_extensions.zig");
pub const section_4_6_1_new_session_ticket = @import("section_4_6_1_new_session_ticket.zig");
pub const section_4_6_3_key_update = @import("section_4_6_3_key_update.zig");
pub const section_6_alert_protocol = @import("section_6_alert_protocol.zig");
pub const section_4_4_1_transcript = @import("section_4_4_1_transcript.zig");
pub const section_4_4_4_finished = @import("section_4_4_4_finished.zig");
pub const section_5_record_protocol = @import("section_5_record_protocol.zig");
pub const section_7_1_key_schedule = @import("section_7_1_key_schedule.zig");
pub const appendix_a_vectors = @import("appendix_a_vectors.zig");
pub const section_b_4_cipher_suite_parity = @import("section_b_4_cipher_suite_parity.zig");

test {
    std.testing.refAllDecls(@This());
}
