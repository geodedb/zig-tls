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
