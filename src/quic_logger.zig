//! Structured logging interface for TLS 1.3 debugging.
//!
//! Provides a minimal, dependency-free logging abstraction for the TLS
//! implementation. This allows protocol events, errors, and state transitions
//! to be logged for debugging without coupling to a specific logging framework.
//!
//! ## Purpose
//!
//! This module serves as a logging facade between the TLS implementation and
//! the embedding QUIC stack. It enables:
//!
//! - **Protocol debugging**: Log handshake state transitions, message parsing,
//!   and cryptographic operations for troubleshooting interop issues
//! - **Security auditing**: Record certificate validation, signature verification,
//!   and alert conditions
//! - **Performance analysis**: Track timing of key derivation, AEAD operations,
//!   and handshake completion
//!
//! ## Integration with QUIC Implementations
//!
//! QUIC stacks typically have their own logging infrastructure (qlog, structured
//! logging, tracing frameworks). To integrate this TLS library:
//!
//! 1. **No-op mode** (default): Logging calls compile to no-ops, zero runtime overhead
//! 2. **Callback mode**: Replace `log()` implementation to forward to QUIC logger
//! 3. **Build-time configuration**: Use Zig build options to enable/disable logging
//!
//! Example integration:
//! ```zig
//! // In QUIC stack's TLS integration layer
//! pub fn log(comptime level: Level, comptime fmt: []const u8, args: anytype) void {
//!     quic_stack.logger.log(@tagName(level), fmt, args);
//! }
//! ```
//!
//! ## Log Levels
//!
//! - **debug**: Verbose protocol details (message parsing, key derivation steps)
//! - **info**: High-level events (handshake start/complete, cipher suite selection)
//! - **warn**: Non-fatal issues (unknown extensions, optional validation failures)
//! - **err**: Fatal errors (handshake failure, invalid certificates, AEAD decrypt failure)
//!
//! ## Structured Logging
//!
//! While this module uses simple format strings, QUIC implementations often
//! prefer structured logging (key-value pairs, JSON). Consider wrapping these
//! calls to add context:
//! ```zig
//! logger.info("handshake_complete", .{
//!     .cipher_suite = "TLS_AES_128_GCM_SHA256",
//!     .alpn = "h3",
//!     .duration_ms = 42,
//! });
//! ```
//!
//! ## qlog Integration (RFC 9000 Appendix A)
//!
//! QUIC's standardized logging format (qlog) captures protocol events for
//! visualization and analysis. TLS events relevant to qlog include:
//! - `crypto:key_updated` - New encryption level keys installed
//! - `security:key_discarded` - Old keys retired
//! - `connectivity:connection_closed` - Alert-triggered closure
//!
//! ## Placeholder Implementation
//!
//! This is a no-op implementation to keep the TLS library dependency-free.
//! All logging calls compile to nothing unless explicitly replaced by the
//! embedding QUIC stack.
//!
//! See also:
//! - RFC 9000 Appendix A (qlog event logging)
//! - draft-ietf-quic-qlog (QUIC event logging schema)

const std = @import("std");

/// Log severity levels.
///
/// Ordered from most verbose (debug) to most critical (err). Loggers
/// typically filter messages by level to control output verbosity.
pub const Level = enum {
    /// Verbose debugging information.
    ///
    /// Examples:
    /// - "Parsing ClientHello extensions (143 bytes)"
    /// - "Derived handshake traffic secret (32 bytes)"
    /// - "AEAD encryption with sequence number 42"
    ///
    /// Use for detailed protocol tracing during development and troubleshooting.
    debug,

    /// Informational messages about normal operation.
    ///
    /// Examples:
    /// - "TLS handshake started (client role)"
    /// - "Selected cipher suite: TLS_AES_128_GCM_SHA256"
    /// - "Certificate validated: example.com"
    ///
    /// Use for high-level events that indicate progress through the protocol.
    info,

    /// Warnings about potentially problematic conditions.
    ///
    /// Examples:
    /// - "Unknown extension type 0x1234 ignored"
    /// - "Certificate chain incomplete, using provided trust anchor"
    /// - "Approaching AEAD usage limit (90% of 2^23 messages)"
    ///
    /// Use for non-fatal issues that may indicate misconfiguration or future problems.
    warn,

    /// Error conditions that prevent normal operation.
    ///
    /// Examples:
    /// - "Handshake failed: decode_error (invalid extension length)"
    /// - "Certificate validation failed: expired certificate"
    /// - "AEAD decryption failed: bad_record_mac"
    ///
    /// Use for fatal errors that will terminate the connection or handshake.
    err,
};

/// Log a message at the specified level.
///
/// This is the core logging primitive. All level-specific functions (debug,
/// info, warn, err) delegate to this function.
///
/// Parameters:
/// - `level`: Severity level of the message
/// - `format`: Format string (std.fmt compatible)
/// - `args`: Format arguments
///
/// **Placeholder**: Currently a no-op. Replace this function to integrate
/// with your QUIC stack's logging system.
///
/// Example replacement for integration:
/// ```zig
/// pub fn log(comptime level: Level, comptime format: []const u8, args: anytype) void {
///     const level_str = switch (level) {
///         .debug => "DEBUG",
///         .info => "INFO",
///         .warn => "WARN",
///         .err => "ERROR",
///     };
///     std.log.scoped(.ztls).log(@enumFromInt(@intFromEnum(level)), "[{s}] " ++ format, .{level_str} ++ args);
/// }
/// ```
pub fn log(comptime level: Level, comptime format: []const u8, args: anytype) void {
    _ = level;
    _ = format;
    _ = args;
    // No-op placeholder to keep library dependency-free
    // Compiles to nothing (zero runtime cost)
}

/// Log a debug-level message.
///
/// Use for verbose protocol details during development and troubleshooting.
/// Debug logs are typically disabled in production for performance.
///
/// Parameters:
/// - `format`: Format string
/// - `args`: Format arguments
///
/// Example usage:
/// ```zig
/// logger.debug("Parsed extension type={x:0>4} length={}", .{ ext_type, ext_len });
/// ```
pub fn debug(comptime format: []const u8, args: anytype) void {
    log(.debug, format, args);
}

/// Log an info-level message.
///
/// Use for high-level events indicating normal protocol progress.
///
/// Parameters:
/// - `format`: Format string
/// - `args`: Format arguments
///
/// Example usage:
/// ```zig
/// logger.info("Handshake complete, cipher={s}", .{cipher_suite_name});
/// ```
pub fn info(comptime format: []const u8, args: anytype) void {
    log(.info, format, args);
}

/// Log a warning-level message.
///
/// Use for non-fatal issues that may indicate misconfiguration or
/// potential future problems.
///
/// Parameters:
/// - `format`: Format string
/// - `args`: Format arguments
///
/// Example usage:
/// ```zig
/// logger.warn("Unknown transport parameter ID 0x{x}, ignoring", .{param_id});
/// ```
pub fn warn(comptime format: []const u8, args: anytype) void {
    log(.warn, format, args);
}

/// Log an error-level message.
///
/// Use for fatal errors that will cause connection or handshake failure.
///
/// Parameters:
/// - `format`: Format string
/// - `args`: Format arguments
///
/// Example usage:
/// ```zig
/// logger.err("Certificate validation failed: {s}", .{@errorName(err)});
/// ```
pub fn err(comptime format: []const u8, args: anytype) void {
    log(.err, format, args);
}
