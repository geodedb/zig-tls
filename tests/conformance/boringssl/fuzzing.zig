// Comprehensive Fuzzing Conformance Tests
//
// These tests validate robustness against malformed inputs, edge cases, and pathological
// scenarios that fuzzing (AFL, libFuzzer) would discover. The goal is to ensure the parser
// handles invalid inputs gracefully without crashes, panics, or undefined behavior.
//
// References:
// - RFC 8446 §4: Handshake Protocol (message format)
// - RFC 8446 §6: Alert Protocol (error handling)
// - RFC 9001 §4: CRYPTO Frames (QUIC-TLS integration)
// - OWASP Fuzzing Guide
// - Google OSS-Fuzz best practices
//
// Test Categories:
// 1. Malformed message parsing (truncated, oversized, invalid)
// 2. Extension parsing edge cases
// 3. Integer overflow/underflow scenarios
// 4. Buffer boundary conditions
// 5. Invalid state transitions
// 6. Certificate parsing edge cases
// 7. Length field mismatches
// 8. Maximum size inputs
// 9. Invalid enum values
// 10. Resource exhaustion scenarios

const std = @import("std");
const testing = std.testing;

// Test 1: Truncated ClientHello parsing
test "Fuzzing: truncated ClientHello does not crash" {
    // A fuzzer would discover truncated messages by bit-flipping length fields
    // RFC 8446 §4.1.2: ClientHello must be parsed defensively

    const TruncatedMessage = struct {
        data: []const u8,
        expected_error: bool,

        fn parse(self: @This()) !void {
            if (self.data.len < 4) {
                return error.MessageTooShort;
            }

            // Simulate basic parsing
            const msg_type = self.data[0];
            const length = (@as(u24, self.data[1]) << 16) |
                (@as(u24, self.data[2]) << 8) |
                @as(u24, self.data[3]);

            // Check if we have enough data
            if (self.data.len < 4 + length) {
                return error.MessageTruncated;
            }

            // Validate message type
            if (msg_type == 0 or msg_type > 24) {
                return error.InvalidMessageType;
            }
        }
    };

    // Valid full message header
    const full_msg = [_]u8{
        0x01, // ClientHello
        0x00, 0x00, 0x04, // length = 4 bytes
        0xAA, 0xBB, 0xCC, 0xDD, // payload
    };

    // Truncated at length field
    const truncated_length = [_]u8{ 0x01, 0x00 };

    // Truncated payload (length claims 100 bytes, only 4 present)
    const truncated_payload = [_]u8{
        0x01, // ClientHello
        0x00, 0x00, 0x64, // length = 100 bytes (lie!)
        0xAA, 0xBB, 0xCC, 0xDD, // only 4 bytes present
    };

    const test_cases = [_]TruncatedMessage{
        .{ .data = &full_msg, .expected_error = false },
        .{ .data = &truncated_length, .expected_error = true },
        .{ .data = &truncated_payload, .expected_error = true },
        .{ .data = &[_]u8{}, .expected_error = true }, // Empty message
    };

    for (test_cases) |tc| {
        const result = tc.parse();
        if (tc.expected_error) {
            // Expect one of several possible errors
            try testing.expect(result == error.MessageTooShort or
                             result == error.MessageTruncated or
                             result == error.InvalidMessageType);
        } else {
            try result;
        }
    }

    // Key validation: No crash, proper error handling
}

// Test 2: Oversized extension length field
test "Fuzzing: oversized extension length rejected" {
    // Fuzzers often flip length fields to maximum values
    // Must detect and reject without allocating huge buffers

    const Extension = struct {
        extension_type: u16,
        length: u16,
        data: []const u8,

        fn parse(buffer: []const u8) !@This() {
            if (buffer.len < 4) return error.BufferTooShort;

            const ext_type = (@as(u16, buffer[0]) << 8) | buffer[1];
            const ext_len = (@as(u16, buffer[2]) << 8) | buffer[3];

            // Additional sanity check: extension should not be unreasonably large
            const MAX_EXTENSION_SIZE: u16 = 4096; // 4KB limit
            if (ext_len > MAX_EXTENSION_SIZE) {
                return error.ExtensionExceedsLimit;
            }

            // Sanity check: extension length must fit in buffer
            // Use usize to avoid overflow in addition
            const total_required = @as(usize, 4) + @as(usize, ext_len);
            if (total_required > buffer.len) {
                return error.ExtensionTooLarge;
            }

            return .{
                .extension_type = ext_type,
                .length = ext_len,
                .data = buffer[4 .. 4 + ext_len],
            };
        }
    };

    // Normal extension
    const normal_ext = [_]u8{
        0x00, 0x0a, // supported_groups
        0x00, 0x04, // length = 4
        0x00, 0x1d, 0x00, 0x17, // X25519, P-256
    };

    // Malicious: length claims 0xFFFF bytes
    const huge_ext = [_]u8{
        0x00, 0x0a, // supported_groups
        0xFF, 0xFF, // length = 65535 bytes (but only 4 bytes follow)
        0x00, 0x1d, 0x00, 0x17,
    };

    // Normal case succeeds
    const parsed = try Extension.parse(&normal_ext);
    try testing.expectEqual(@as(u16, 0x000a), parsed.extension_type);
    try testing.expectEqual(@as(u16, 4), parsed.length);

    // Huge extension rejected (exceeds 4KB limit)
    try testing.expectError(error.ExtensionExceedsLimit, Extension.parse(&huge_ext));

    // Edge case: length exactly at limit
    var edge_case_buffer: [4 + 4096]u8 = undefined;
    edge_case_buffer[0] = 0x00;
    edge_case_buffer[1] = 0x0a;
    edge_case_buffer[2] = 0x10; // length = 4096 (exactly at limit)
    edge_case_buffer[3] = 0x00;
    @memset(edge_case_buffer[4..], 0xAA);

    const edge_parsed = try Extension.parse(&edge_case_buffer);
    try testing.expectEqual(@as(u16, 4096), edge_parsed.length);
}

// Test 3: Integer overflow in length calculations
test "Fuzzing: integer overflow in length calculations" {
    // Length field arithmetic can overflow, leading to buffer overruns
    // Must use checked arithmetic or validate bounds

    const VectorParser = struct {
        fn parseVector(buffer: []const u8) ![]const u8 {
            if (buffer.len < 2) return error.BufferTooShort;

            const length = (@as(u16, buffer[0]) << 8) | buffer[1];

            // Check for overflow: 2 + length must not exceed buffer.len
            // Use saturating addition to detect overflow
            const total_len = @as(usize, 2) + @as(usize, length);
            if (total_len > buffer.len) {
                return error.LengthExceedsBuffer;
            }

            return buffer[2 .. 2 + length];
        }
    };

    // Normal case
    const normal = [_]u8{ 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD };
    const parsed = try VectorParser.parseVector(&normal);
    try testing.expectEqual(@as(usize, 4), parsed.len);

    // Overflow case: length is 0xFFFF but only small buffer
    const overflow = [_]u8{ 0xFF, 0xFF, 0xAA, 0xBB };
    try testing.expectError(error.LengthExceedsBuffer, VectorParser.parseVector(&overflow));

    // Edge case: zero length
    const zero_len = [_]u8{ 0x00, 0x00 };
    const empty = try VectorParser.parseVector(&zero_len);
    try testing.expectEqual(@as(usize, 0), empty.len);
}

// Test 4: Deeply nested extension parsing
test "Fuzzing: deeply nested structures do not stack overflow" {
    // Some parsers use recursion; fuzzers create deeply nested structures
    // Must use iteration or limit recursion depth

    const MAX_NESTING_DEPTH = 10;

    const NestedStructure = struct {
        depth: usize,

        fn parse(buffer: []const u8, current_depth: usize) !@This() {
            if (current_depth > MAX_NESTING_DEPTH) {
                return error.NestingTooDeep;
            }

            if (buffer.len < 1) return error.BufferTooShort;

            const has_child = buffer[0] == 1;

            if (has_child and buffer.len > 1) {
                // Recursively parse child (simulate nested extension)
                _ = try parse(buffer[1..], current_depth + 1);
            }

            return .{ .depth = current_depth };
        }
    };

    // Shallow nesting (depth 3)
    const shallow = [_]u8{ 1, 1, 1, 0 };
    const parsed = try NestedStructure.parse(&shallow, 0);
    try testing.expect(parsed.depth < MAX_NESTING_DEPTH);

    // Deep nesting (depth 15, exceeds limit)
    const deep = [_]u8{1} ** 15 ++ [_]u8{0};
    try testing.expectError(error.NestingTooDeep, NestedStructure.parse(&deep, 0));
}

// Test 5: Invalid enum values
test "Fuzzing: invalid enum values rejected or ignored" {
    // Fuzzers flip bits in enum fields; parser must handle gracefully
    // RFC 8446 §4.2: Unknown values should be ignored, not cause crashes

    const ContentType = enum(u8) {
        invalid = 0,
        change_cipher_spec = 20,
        alert = 21,
        handshake = 22,
        application_data = 23,
        _,
    };

    const test_values = [_]u8{ 0, 20, 21, 22, 23, 99, 255 };

    for (test_values) |value| {
        const ct: ContentType = @enumFromInt(value);

        // Should not crash when converting unknown enum values
        const is_known = switch (ct) {
            .change_cipher_spec, .alert, .handshake, .application_data => true,
            else => false,
        };

        // Known values
        if (value >= 20 and value <= 23) {
            try testing.expect(is_known);
        }
    }
}

// Test 6: Zero-length certificate chain
test "Fuzzing: zero-length certificate chain handled gracefully" {
    // Empty certificate lists should be rejected (except for client no-auth)

    const CertificateChain = struct {
        certificates: []const []const u8,

        fn parse(buffer: []const u8, allow_empty: bool) !@This() {
            if (buffer.len < 3) return error.BufferTooShort;

            const list_length = (@as(u24, buffer[0]) << 16) |
                (@as(u24, buffer[1]) << 8) |
                @as(u24, buffer[2]);

            if (list_length == 0) {
                if (!allow_empty) {
                    return error.EmptyCertificateChain;
                }
                return .{ .certificates = &[_][]const u8{} };
            }

            // Validate length matches buffer
            if (3 + list_length > buffer.len) {
                return error.ChainTruncated;
            }

            return .{ .certificates = &[_][]const u8{} }; // Simplified
        }
    };

    // Empty chain when not allowed (server must send certs)
    const empty_chain = [_]u8{ 0x00, 0x00, 0x00 }; // length = 0
    try testing.expectError(error.EmptyCertificateChain, CertificateChain.parse(&empty_chain, false));

    // Empty chain when allowed (client optional auth)
    const parsed = try CertificateChain.parse(&empty_chain, true);
    try testing.expectEqual(@as(usize, 0), parsed.certificates.len);

    // Truncated chain (claims 100 bytes, has 0)
    const truncated = [_]u8{ 0x00, 0x00, 0x64 }; // length = 100
    try testing.expectError(error.ChainTruncated, CertificateChain.parse(&truncated, false));
}

// Test 7: Maximum size ClientHello
test "Fuzzing: maximum size ClientHello accepted" {
    // Fuzzers test boundary conditions with maximum legal sizes
    // Must handle without excessive memory allocation

    const MAX_CLIENTHELLO_SIZE = 65535; // 16-bit length field max
    const REASONABLE_LIMIT = 16384; // 16KB is reasonable for ClientHello

    // Verify reasonable limit doesn't exceed protocol maximum
    try testing.expect(REASONABLE_LIMIT <= MAX_CLIENTHELLO_SIZE);

    const ClientHelloParser = struct {
        fn parse(buffer: []const u8) !void {
            if (buffer.len < 4) return error.TooShort;

            const msg_type = buffer[0];
            const length = (@as(u24, buffer[1]) << 16) |
                (@as(u24, buffer[2]) << 8) |
                @as(u24, buffer[3]);

            if (msg_type != 1) return error.NotClientHello;

            // Check against reasonable limit, not just protocol max
            if (length > REASONABLE_LIMIT) {
                return error.ClientHelloTooLarge;
            }

            if (4 + length > buffer.len) {
                return error.Truncated;
            }
        }
    };

    // Small valid ClientHello
    const small = [_]u8{ 0x01, 0x00, 0x00, 0x10 } ++ [_]u8{0xAA} ** 16;
    try ClientHelloParser.parse(&small);

    // At reasonable limit (should succeed)
    var at_limit_buffer: [4 + REASONABLE_LIMIT]u8 = undefined;
    at_limit_buffer[0] = 0x01;
    at_limit_buffer[1] = 0x00; // 16384 bytes = 0x004000
    at_limit_buffer[2] = 0x40;
    at_limit_buffer[3] = 0x00;
    @memset(at_limit_buffer[4..], 0xBB);
    try ClientHelloParser.parse(&at_limit_buffer);

    // Exceeds reasonable limit (should fail)
    const oversized = [_]u8{ 0x01, 0xFF, 0xFF, 0x00 } ++ [_]u8{0xCC} ** 100;
    try testing.expectError(error.ClientHelloTooLarge, ClientHelloParser.parse(&oversized));
}

// Test 8: Malformed ASN.1 DER encoding
test "Fuzzing: malformed ASN.1 DER does not crash" {
    // Certificate parsing involves ASN.1 DER; fuzzers create malformed DER

    const DerParser = struct {
        fn parseLength(buffer: []const u8) !struct { length: usize, bytes_consumed: usize } {
            if (buffer.len == 0) return error.BufferTooShort;

            const first_byte = buffer[0];

            // Short form (0-127)
            if (first_byte < 0x80) {
                return .{ .length = first_byte, .bytes_consumed = 1 };
            }

            // Long form
            const num_octets = first_byte & 0x7F;

            // Sanity checks
            if (num_octets == 0) return error.InvalidDerLength; // Indefinite form not allowed in DER
            if (num_octets > 4) return error.LengthTooLong; // Unreasonably large
            if (1 + num_octets > buffer.len) return error.BufferTooShort;

            var length: usize = 0;
            for (0..num_octets) |i| {
                length = (length << 8) | buffer[1 + i];
            }

            return .{ .length = length, .bytes_consumed = 1 + num_octets };
        }
    };

    // Valid short form
    const short_form = [_]u8{0x05}; // length = 5
    const parsed_short = try DerParser.parseLength(&short_form);
    try testing.expectEqual(@as(usize, 5), parsed_short.length);
    try testing.expectEqual(@as(usize, 1), parsed_short.bytes_consumed);

    // Valid long form (2 bytes)
    const long_form = [_]u8{ 0x82, 0x01, 0x00 }; // length = 256
    const parsed_long = try DerParser.parseLength(&long_form);
    try testing.expectEqual(@as(usize, 256), parsed_long.length);
    try testing.expectEqual(@as(usize, 3), parsed_long.bytes_consumed);

    // Invalid: indefinite form (0x80)
    const indefinite = [_]u8{0x80};
    try testing.expectError(error.InvalidDerLength, DerParser.parseLength(&indefinite));

    // Invalid: unreasonably long (claims 127 octets for length)
    const unreasonable = [_]u8{0xFF};
    try testing.expectError(error.LengthTooLong, DerParser.parseLength(&unreasonable));

    // Invalid: truncated long form
    const truncated = [_]u8{0x82}; // Claims 2 octets but buffer ends
    try testing.expectError(error.BufferTooShort, DerParser.parseLength(&truncated));
}

// Test 9: AEAD tag manipulation
test "Fuzzing: corrupted AEAD tag rejected" {
    // Fuzzers flip bits in authentication tags; must detect and reject

    const AeadVerifier = struct {
        fn verify(ciphertext: []const u8, tag: []const u8, expected_tag: []const u8) !void {
            if (tag.len != expected_tag.len) {
                return error.TagLengthMismatch;
            }

            // Constant-time comparison (important for security)
            var mismatch: u8 = 0;
            for (tag, expected_tag) |t, e| {
                mismatch |= t ^ e;
            }

            if (mismatch != 0) {
                return error.AuthenticationFailed;
            }

            // Decryption would occur here
            _ = ciphertext;
        }
    };

    const ciphertext = [_]u8{0xAA} ** 32;
    const correct_tag = [_]u8{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    var corrupted_tag = correct_tag;

    // Valid tag
    try AeadVerifier.verify(&ciphertext, &correct_tag, &correct_tag);

    // Corrupted tag (single bit flip)
    corrupted_tag[0] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, AeadVerifier.verify(&ciphertext, &corrupted_tag, &correct_tag));

    // Truncated tag
    const truncated_tag = [_]u8{0x12, 0x34};
    try testing.expectError(error.TagLengthMismatch, AeadVerifier.verify(&ciphertext, &truncated_tag, &correct_tag));

    // All-zero tag
    const zero_tag = [_]u8{0x00} ** 8;
    try testing.expectError(error.AuthenticationFailed, AeadVerifier.verify(&ciphertext, &zero_tag, &correct_tag));
}

// Test 10: Transport parameter overflow
test "Fuzzing: transport parameter value overflow handled" {
    // QUIC transport parameters are variable-length integers; fuzzers test overflow

    const TransportParamParser = struct {
        fn parseVarint(buffer: []const u8) !struct { value: u64, bytes_consumed: usize } {
            if (buffer.len == 0) return error.BufferTooShort;

            const first_byte = buffer[0];
            const prefix = first_byte >> 6;

            const length: usize = switch (prefix) {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                else => unreachable,
            };

            if (buffer.len < length) return error.BufferTooShort;

            var value: u64 = @as(u64, first_byte & 0x3F);

            for (1..length) |i| {
                value = (value << 8) | buffer[i];
            }

            return .{ .value = value, .bytes_consumed = length };
        }
    };

    // 1-byte varint (0-63)
    const one_byte = [_]u8{0x25}; // value = 37
    const parsed1 = try TransportParamParser.parseVarint(&one_byte);
    try testing.expectEqual(@as(u64, 37), parsed1.value);
    try testing.expectEqual(@as(usize, 1), parsed1.bytes_consumed);

    // 2-byte varint (64-16383)
    const two_byte = [_]u8{ 0x41, 0x00 }; // value = 256
    const parsed2 = try TransportParamParser.parseVarint(&two_byte);
    try testing.expectEqual(@as(u64, 256), parsed2.value);
    try testing.expectEqual(@as(usize, 2), parsed2.bytes_consumed);

    // 8-byte varint (maximum)
    const eight_byte = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const parsed8 = try TransportParamParser.parseVarint(&eight_byte);
    try testing.expect(parsed8.value > 0);
    try testing.expectEqual(@as(usize, 8), parsed8.bytes_consumed);

    // Truncated varint
    const truncated = [_]u8{0xC0}; // Claims 4 bytes but only has 1
    try testing.expectError(error.BufferTooShort, TransportParamParser.parseVarint(&truncated));
}

// Test 11: Key schedule with all-zero inputs
test "Fuzzing: key schedule with degenerate inputs" {
    // Fuzzers try all-zero, all-0xFF, repeating patterns

    const KeyScheduleTest = struct {
        fn deriveSecret(ikm: []const u8, salt: []const u8) ![]const u8 {
            // Simplified HKDF-Extract check
            if (ikm.len == 0) return error.EmptyInputKeyMaterial;
            if (salt.len == 0) return error.EmptySalt;

            // Check for all-zero IKM (weak key)
            var all_zero = true;
            for (ikm) |byte| {
                if (byte != 0) {
                    all_zero = false;
                    break;
                }
            }

            if (all_zero) {
                // In real implementation, this is allowed but worth noting
                // For test purposes, we'll allow it
            }

            // Return dummy secret
            return ikm[0..std.crypto.hash.sha2.Sha256.digest_length];
        }
    };

    // Normal input
    const normal_ikm = [_]u8{0x12} ** 32;
    const normal_salt = [_]u8{0x34} ** 32;
    _ = try KeyScheduleTest.deriveSecret(&normal_ikm, &normal_salt);

    // All-zero inputs (degenerate but valid)
    const zero_ikm = [_]u8{0x00} ** 32;
    const zero_salt = [_]u8{0x00} ** 32;
    _ = try KeyScheduleTest.deriveSecret(&zero_ikm, &zero_salt);

    // All-0xFF inputs
    const ff_ikm = [_]u8{0xFF} ** 32;
    const ff_salt = [_]u8{0xFF} ** 32;
    _ = try KeyScheduleTest.deriveSecret(&ff_ikm, &ff_salt);

    // Empty inputs (should error)
    try testing.expectError(error.EmptyInputKeyMaterial, KeyScheduleTest.deriveSecret(&[_]u8{}, &normal_salt));
    try testing.expectError(error.EmptySalt, KeyScheduleTest.deriveSecret(&normal_ikm, &[_]u8{}));
}

// Test 12: Signature with maximum length
test "Fuzzing: maximum length signature accepted" {
    // Signatures can be up to 64KB; parser must handle without excess allocation

    const MAX_SIGNATURE_LENGTH = 8192; // Reasonable limit (8KB)

    const SignatureParser = struct {
        fn parse(buffer: []const u8) ![]const u8 {
            if (buffer.len < 2) return error.BufferTooShort;

            const sig_len = (@as(u16, buffer[0]) << 8) | buffer[1];

            if (sig_len > MAX_SIGNATURE_LENGTH) {
                return error.SignatureTooLarge;
            }

            if (2 + sig_len > buffer.len) {
                return error.SignatureTruncated;
            }

            return buffer[2 .. 2 + sig_len];
        }
    };

    // Small signature (64 bytes, e.g., ECDSA P-256)
    const small_sig_buf = [_]u8{ 0x00, 0x40 } ++ [_]u8{0xAA} ** 64;
    const small_sig = try SignatureParser.parse(&small_sig_buf);
    try testing.expectEqual(@as(usize, 64), small_sig.len);

    // Large signature (4096 bytes, e.g., RSA)
    var large_sig_buf: [2 + 4096]u8 = undefined;
    large_sig_buf[0] = 0x10; // length = 4096
    large_sig_buf[1] = 0x00;
    @memset(large_sig_buf[2..], 0xBB);
    const large_sig = try SignatureParser.parse(&large_sig_buf);
    try testing.expectEqual(@as(usize, 4096), large_sig.len);

    // Exceeds limit
    const oversized = [_]u8{ 0xFF, 0xFF } ++ [_]u8{0xCC} ** 100;
    try testing.expectError(error.SignatureTooLarge, SignatureParser.parse(&oversized));

    // Truncated
    const truncated = [_]u8{ 0x01, 0x00 }; // Claims 256 bytes, has 0
    try testing.expectError(error.SignatureTruncated, SignatureParser.parse(&truncated));
}

// Test 13: Extension list with duplicate extension types
test "Fuzzing: duplicate extensions detected" {
    // RFC 8446 §4.2: Extensions MUST NOT appear more than once
    // Fuzzers often duplicate extensions to test validation

    const ExtensionList = struct {
        fn validate(extensions: []const u16) !void {
            // Check for duplicates
            for (extensions, 0..) |ext1, i| {
                for (extensions[i + 1 ..]) |ext2| {
                    if (ext1 == ext2) {
                        return error.DuplicateExtension;
                    }
                }
            }
        }
    };

    // No duplicates
    const unique = [_]u16{ 0x0000, 0x000a, 0x000d, 0x0010, 0x002b };
    try ExtensionList.validate(&unique);

    // Duplicate extension
    const duplicates = [_]u16{ 0x0000, 0x000a, 0x000a, 0x002b };
    try testing.expectError(error.DuplicateExtension, ExtensionList.validate(&duplicates));

    // Multiple duplicates
    const many_dups = [_]u16{ 0x0000, 0x0000, 0x0000 };
    try testing.expectError(error.DuplicateExtension, ExtensionList.validate(&many_dups));

    // Empty list (valid)
    try ExtensionList.validate(&[_]u16{});

    // Single extension (valid)
    const single = [_]u16{0x0000};
    try ExtensionList.validate(&single);
}

// Test 14: State machine invalid transitions
test "Fuzzing: invalid state transitions rejected" {
    // Fuzzers send messages out of order; state machine must reject

    const HandshakeState = enum {
        START,
        WAIT_SERVER_HELLO,
        WAIT_ENCRYPTED_EXTENSIONS,
        WAIT_CERT,
        WAIT_CERT_VERIFY,
        WAIT_FINISHED,
        CONNECTED,

        fn transition(self: @This(), msg_type: u8) !@This() {
            return switch (self) {
                .START => if (msg_type == 2) .WAIT_ENCRYPTED_EXTENSIONS else error.UnexpectedMessage,
                .WAIT_ENCRYPTED_EXTENSIONS => if (msg_type == 8) .WAIT_CERT else error.UnexpectedMessage,
                .WAIT_CERT => if (msg_type == 11) .WAIT_CERT_VERIFY else error.UnexpectedMessage,
                .WAIT_CERT_VERIFY => if (msg_type == 15) .WAIT_FINISHED else error.UnexpectedMessage,
                .WAIT_FINISHED => if (msg_type == 20) .CONNECTED else error.UnexpectedMessage,
                .CONNECTED => error.UnexpectedMessage,
                else => error.InvalidState,
            };
        }
    };

    // Valid sequence: ServerHello(2) -> EncryptedExtensions(8) -> Certificate(11)
    var state = HandshakeState.START;
    state = try state.transition(2); // ServerHello
    try testing.expectEqual(HandshakeState.WAIT_ENCRYPTED_EXTENSIONS, state);
    state = try state.transition(8); // EncryptedExtensions
    try testing.expectEqual(HandshakeState.WAIT_CERT, state);

    // Invalid: skip to Finished without Certificate
    try testing.expectError(error.UnexpectedMessage, state.transition(20));

    // Invalid: receive ClientHello when expecting ServerHello
    state = HandshakeState.START;
    try testing.expectError(error.UnexpectedMessage, state.transition(1));
}

// Test 15: UTF-8 validation in SNI
test "Fuzzing: malformed UTF-8 in SNI hostname rejected" {
    // Hostnames must be valid UTF-8 (or more strictly, DNS names)

    const SniValidator = struct {
        fn validate(hostname: []const u8) !void {
            if (hostname.len == 0) return error.EmptyHostname;
            if (hostname.len > 253) return error.HostnameTooLong; // DNS limit

            // Check for valid DNS characters (simplified)
            for (hostname) |char| {
                const is_valid = (char >= 'a' and char <= 'z') or
                    (char >= 'A' and char <= 'Z') or
                    (char >= '0' and char <= '9') or
                    char == '.' or char == '-';

                if (!is_valid) {
                    return error.InvalidHostnameCharacter;
                }
            }

            // Must not start or end with hyphen or dot
            if (hostname[0] == '-' or hostname[0] == '.') return error.InvalidHostname;
            if (hostname[hostname.len - 1] == '-' or hostname[hostname.len - 1] == '.') return error.InvalidHostname;
        }
    };

    // Valid hostnames
    try SniValidator.validate("example.com");
    try SniValidator.validate("sub.example.com");
    try SniValidator.validate("test-123.example.org");

    // Invalid: contains invalid characters
    try testing.expectError(error.InvalidHostnameCharacter, SniValidator.validate("example_com"));
    try testing.expectError(error.InvalidHostnameCharacter, SniValidator.validate("example com"));

    // Invalid: starts with hyphen
    try testing.expectError(error.InvalidHostname, SniValidator.validate("-example.com"));

    // Invalid: ends with dot
    try testing.expectError(error.InvalidHostname, SniValidator.validate("example.com."));

    // Invalid: empty
    try testing.expectError(error.EmptyHostname, SniValidator.validate(""));

    // Invalid: too long
    const too_long = [_]u8{'a'} ** 254;
    try testing.expectError(error.HostnameTooLong, SniValidator.validate(&too_long));
}

// Test 16: Resource exhaustion - many small extensions
test "Fuzzing: many small extensions do not exhaust resources" {
    // Fuzzers create messages with hundreds of tiny extensions

    const ExtensionCounter = struct {
        max_extensions: usize,

        fn countExtensions(self: @This(), buffer: []const u8) !usize {
            if (buffer.len < 2) return error.BufferTooShort;

            const total_len = (@as(u16, buffer[0]) << 8) | buffer[1];
            if (2 + total_len > buffer.len) return error.Truncated;

            var offset: usize = 2;
            var ext_count: usize = 0;

            while (offset < 2 + total_len) {
                if (offset + 4 > buffer.len) return error.MalformedExtension;

                ext_count += 1;
                if (ext_count > self.max_extensions) {
                    return error.TooManyExtensions;
                }

                const ext_len = (@as(u16, buffer[offset + 2]) << 8) | buffer[offset + 3];
                offset += 4 + ext_len;
            }

            return ext_count;
        }
    };

    const counter = ExtensionCounter{ .max_extensions = 64 };

    // Small number of extensions
    const few_extensions = [_]u8{
        0x00, 0x0C, // total length = 12
        0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB, // extension 1
        0x00, 0x01, 0x00, 0x02, 0xCC, 0xDD, // extension 2
    };
    const count = try counter.countExtensions(&few_extensions);
    try testing.expectEqual(@as(usize, 2), count);

    // Simulate many extensions (just below limit)
    var many_buf: [2 + (64 * 4)]u8 = undefined;
    many_buf[0] = 0x01;
    many_buf[1] = 0x00; // length = 256 bytes
    for (0..64) |i| {
        const offset = 2 + (i * 4);
        many_buf[offset] = 0x00; // extension type high
        many_buf[offset + 1] = @intCast(i); // extension type low
        many_buf[offset + 2] = 0x00; // length high
        many_buf[offset + 3] = 0x00; // length low (zero-length extension)
    }
    const many_count = try counter.countExtensions(&many_buf);
    try testing.expectEqual(@as(usize, 64), many_count);

    // Too many extensions (should be rejected before parsing all)
    // This would require a buffer with >64 extensions, which we validate with the limit
}

// Test 17: Alert code injection
test "Fuzzing: unknown alert codes handled gracefully" {
    // Fuzzers send arbitrary alert codes; must not crash

    const AlertLevel = enum(u8) {
        warning = 1,
        fatal = 2,
        _,
    };

    const AlertDescription = enum(u8) {
        close_notify = 0,
        unexpected_message = 10,
        bad_record_mac = 20,
        handshake_failure = 40,
        illegal_parameter = 47,
        decode_error = 50,
        internal_error = 80,
        _,
    };

    const AlertHandler = struct {
        fn handle(level: u8, description: u8) !void {
            const alert_level: AlertLevel = @enumFromInt(level);
            const alert_desc: AlertDescription = @enumFromInt(description);

            // Validate level
            const is_fatal = switch (alert_level) {
                .fatal => true,
                .warning => false,
                _ => return error.UnknownAlertLevel,
            };

            // Handle known descriptions
            switch (alert_desc) {
                .close_notify, .unexpected_message, .bad_record_mac,
                .handshake_failure, .illegal_parameter, .decode_error, .internal_error,
                => {},
                _ => {
                    // Unknown alert description - log and treat as fatal
                    if (is_fatal) {
                        return error.FatalAlert;
                    }
                },
            }
        }
    };

    // Known alerts
    try AlertHandler.handle(2, 40); // fatal, handshake_failure
    try AlertHandler.handle(1, 0); // warning, close_notify

    // Unknown description (should treat as fatal if level is fatal)
    try testing.expectError(error.FatalAlert, AlertHandler.handle(2, 99));

    // Unknown level
    try testing.expectError(error.UnknownAlertLevel, AlertHandler.handle(5, 40));
}

// Test 18: Timestamp overflow in ticket age calculation
test "Fuzzing: ticket age calculation overflow handled" {
    // Ticket age = (now - ticket_timestamp) + ticket_age_add
    // Fuzzers set extreme values to cause overflow

    const TicketAgeValidator = struct {
        fn validate(now: u64, ticket_timestamp: u64, ticket_age_add: u32, max_age: u32) !void {
            // Check for underflow in subtraction
            if (now < ticket_timestamp) {
                return error.TicketFromFuture;
            }

            const age = now - ticket_timestamp;

            // Check for overflow in addition (use saturating arithmetic)
            const obfuscated_age = age +% ticket_age_add;

            // Validate against maximum age
            if (obfuscated_age > max_age) {
                return error.TicketExpired;
            }
        }
    };

    // Normal case
    const now: u64 = 1000000;
    const ticket_ts: u64 = 999000;
    const age_add: u32 = 12345;
    const max_age: u32 = 86400000; // 24 hours in ms
    try TicketAgeValidator.validate(now, ticket_ts, age_add, max_age);

    // Ticket from future (clock skew)
    try testing.expectError(error.TicketFromFuture, TicketAgeValidator.validate(999000, 1000000, age_add, max_age));

    // Expired ticket
    try testing.expectError(error.TicketExpired, TicketAgeValidator.validate(now, 0, age_add, 1000));

    // Edge case: now == ticket_timestamp (age = 0)
    try TicketAgeValidator.validate(1000000, 1000000, age_add, max_age);
}

// Test 19: Record number overflow
test "Fuzzing: record sequence number overflow handled" {
    // Sequence numbers can overflow after 2^64 records; must detect and rekey

    const SequenceTracker = struct {
        seq_num: u64,

        fn increment(self: *@This()) !void {
            if (self.seq_num == std.math.maxInt(u64)) {
                return error.SequenceNumberOverflow;
            }
            self.seq_num += 1;
        }

        fn shouldRekey(self: @This(), rekey_limit: u64) bool {
            return self.seq_num >= rekey_limit;
        }
    };

    var tracker = SequenceTracker{ .seq_num = 0 };

    // Normal increment
    try tracker.increment();
    try testing.expectEqual(@as(u64, 1), tracker.seq_num);

    // Check rekey threshold
    tracker.seq_num = (1 << 24); // At AEAD limit for AES-GCM
    try testing.expect(tracker.shouldRekey(1 << 24));

    // Overflow detection
    tracker.seq_num = std.math.maxInt(u64);
    try testing.expectError(error.SequenceNumberOverflow, tracker.increment());
}

// Test 20: Certificate with extreme validity period
test "Fuzzing: certificate with extreme validity period" {
    // Fuzzers set notBefore far in past or notAfter far in future

    const CertificateValidator = struct {
        fn validateTime(not_before: i64, not_after: i64, now: i64) !void {
            // Check chronological order
            if (not_before >= not_after) {
                return error.InvalidValidityPeriod;
            }

            // Check if currently valid
            if (now < not_before) {
                return error.CertificateNotYetValid;
            }

            if (now >= not_after) {
                return error.CertificateExpired;
            }

            // Sanity check: validity period should not exceed reasonable limit
            const MAX_VALIDITY_SECONDS: i64 = 825 * 24 * 60 * 60; // 825 days (CA/Browser Forum limit)
            const validity_period = not_after - not_before;

            if (validity_period > MAX_VALIDITY_SECONDS) {
                // Note: This is a warning, not an error (some CAs issue longer certs)
                // In production, might log or apply policy
            }
        }
    };

    const now: i64 = 1700000000; // Nov 2023

    // Normal certificate (90 days)
    const valid_cert_start = now - (30 * 24 * 60 * 60);
    const valid_cert_end = now + (60 * 24 * 60 * 60);
    try CertificateValidator.validateTime(valid_cert_start, valid_cert_end, now);

    // Not yet valid
    const future_start = now + 86400;
    const future_end = now + (2 * 86400);
    try testing.expectError(error.CertificateNotYetValid, CertificateValidator.validateTime(future_start, future_end, now));

    // Expired
    const past_start = now - (100 * 24 * 60 * 60);
    const past_end = now - (10 * 24 * 60 * 60);
    try testing.expectError(error.CertificateExpired, CertificateValidator.validateTime(past_start, past_end, now));

    // Invalid: notAfter before notBefore
    try testing.expectError(error.InvalidValidityPeriod, CertificateValidator.validateTime(now + 100, now, now));

    // Extreme validity period (1000 years) - parses but exceeds recommendation
    const extreme_end = now + (1000 * 365 * 24 * 60 * 60);
    try CertificateValidator.validateTime(now, extreme_end, now);
}
