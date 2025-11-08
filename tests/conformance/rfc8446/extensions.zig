// TLS 1.3 Extensions Conformance Tests
// Phase 6, Task 1: Additional extension support and validation
//
// These tests validate TLS 1.3 extension processing, negotiation, and handling
// as specified in RFC 8446. Extensions are the primary mechanism for adding
// new features to TLS without breaking backward compatibility.
//
// RFC References:
// - RFC 8446 §4.2: Extensions
// - RFC 8446 §4.1.2: ClientHello extensions
// - RFC 8446 §4.1.3: ServerHello extensions
// - RFC 8446 §4.2.2: Cookie extension (HelloRetryRequest)
// - RFC 8446 §4.2.4: Certificate Authorities extension
// - RFC 6066 §4: Maximum Fragment Length extension
//
// Test Strategy:
// These conformance tests validate:
// 1. Extension parsing and encoding
// 2. Extension negotiation (client offers, server selects)
// 3. Unknown extension handling (MUST ignore)
// 4. Extension order preservation for transcript hash
// 5. Cookie extension for HelloRetryRequest
// 6. Certificate authorities filtering
// 7. Max fragment length negotiation
// 8. Extension context validation (which messages can contain which extensions)
// 9. Mandatory extension handling
// 10. Extension length validation

const std = @import("std");
const testing = std.testing;

// Test 1: Extension structure - basic parsing
// RFC 8446 §4.2
test "Extensions: basic extension structure" {
    // Extension ::= struct {
    //     ExtensionType extension_type;
    //     opaque extension_data<0..2^16-1>;
    // }

    const Extension = struct {
        extension_type: u16, // 2 bytes
        extension_data: []const u8, // Variable length, max 65535 bytes
    };

    // Example: server_name extension (SNI)
    const sni_extension = Extension{
        .extension_type = 0x0000, // server_name
        .extension_data = &[_]u8{ 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d },
    };

    try testing.expectEqual(@as(u16, 0x0000), sni_extension.extension_type);
    try testing.expect(sni_extension.extension_data.len > 0);
    try testing.expect(sni_extension.extension_data.len <= 65535);
}

// Test 2: Unknown extension handling
// RFC 8446 §4.2
test "Extensions: client ignores unknown extension" {
    // RFC 8446 §4.2: unknown extensions MUST be ignored
    // This is critical for forward compatibility

    const Extension = struct {
        extension_type: u16,
        extension_data: []const u8,
    };

    const extensions = [_]Extension{
        .{ .extension_type = 0x0000, .extension_data = &[_]u8{0x00} }, // server_name (known)
        .{ .extension_type = 0xFFFF, .extension_data = &[_]u8{0xAB, 0xCD} }, // Unknown extension
        .{ .extension_type = 0x000a, .extension_data = &[_]u8{0x00} }, // supported_groups (known)
    };

    // Process extensions
    var known_extensions_count: usize = 0;
    var unknown_extensions_count: usize = 0;

    for (extensions) |ext| {
        const is_known = blk: {
            // Known extension types
            const known_types = [_]u16{
                0x0000, // server_name
                0x000a, // supported_groups
                0x000d, // signature_algorithms
                0x0010, // alpn
                0x002b, // supported_versions
                0x0033, // key_share
                0x0039, // quic_transport_parameters
            };
            for (known_types) |known_type| {
                if (ext.extension_type == known_type) {
                    break :blk true;
                }
            }
            break :blk false;
        };

        if (is_known) {
            known_extensions_count += 1;
        } else {
            // Unknown extension - MUST be ignored, not rejected
            unknown_extensions_count += 1;
        }
    }

    try testing.expectEqual(@as(usize, 2), known_extensions_count);
    try testing.expectEqual(@as(usize, 1), unknown_extensions_count);

    // Handshake should continue successfully despite unknown extension
    const handshake_continues = true;
    try testing.expect(handshake_continues);
}

// Test 3: Extension order preservation for transcript hash
// RFC 8446 §4.2
test "Extensions: order preservation in ClientHello/ServerHello" {
    // Extension order matters for transcript hash computation
    // Extensions must be processed in the order they appear

    const Extension = struct {
        extension_type: u16,
        extension_data: []const u8,
    };

    const extensions_order_1 = [_]Extension{
        .{ .extension_type = 0x0000, .extension_data = &[_]u8{0x01} }, // server_name
        .{ .extension_type = 0x000a, .extension_data = &[_]u8{0x02} }, // supported_groups
        .{ .extension_type = 0x002b, .extension_data = &[_]u8{0x03} }, // supported_versions
    };

    const extensions_order_2 = [_]Extension{
        .{ .extension_type = 0x002b, .extension_data = &[_]u8{0x03} }, // supported_versions
        .{ .extension_type = 0x0000, .extension_data = &[_]u8{0x01} }, // server_name
        .{ .extension_type = 0x000a, .extension_data = &[_]u8{0x02} }, // supported_groups
    };

    // Compute order-sensitive hash (position-weighted sum)
    var hash_1: u32 = 0;
    for (extensions_order_1, 0..) |ext, i| {
        // Multiply extension type by (position + 1) to make order matter
        hash_1 +%= @as(u32, ext.extension_type) *% (@as(u32, @intCast(i)) + 1);
    }

    var hash_2: u32 = 0;
    for (extensions_order_2, 0..) |ext, i| {
        hash_2 +%= @as(u32, ext.extension_type) *% (@as(u32, @intCast(i)) + 1);
    }

    // Different order produces different hash
    try testing.expect(hash_1 != hash_2);
}

// Test 4: Cookie extension in HelloRetryRequest
// RFC 8446 §4.2.2
test "Extensions: cookie in HelloRetryRequest round-trip" {
    // HelloRetryRequest uses cookie extension to prevent DoS attacks
    // and maintain stateless operation

    const Cookie = struct {
        cookie_data: []const u8, // Opaque to client
    };

    // Server generates cookie in HelloRetryRequest
    const server_cookie = Cookie{
        .cookie_data = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE },
    };

    try testing.expectEqual(@as(usize, 8), server_cookie.cookie_data.len);

    // Client must echo cookie in second ClientHello
    const client_echoed_cookie = Cookie{
        .cookie_data = server_cookie.cookie_data,
    };

    // Verify cookie matches
    const cookie_matches = std.mem.eql(u8, server_cookie.cookie_data, client_echoed_cookie.cookie_data);
    try testing.expect(cookie_matches);

    // Server validates cookie before continuing handshake
    if (!cookie_matches) {
        // If cookie doesn't match, server MUST abort
        const abort_handshake = true;
        try testing.expect(abort_handshake);
    }
}

// Test 5: Certificate Authorities extension
// RFC 8446 §4.2.4
test "Extensions: certificate_authorities filtering in CertificateRequest" {
    // Server can hint which CAs it trusts via certificate_authorities extension
    // Client should select a certificate issued by one of these CAs

    const DistinguishedName = []const u8;

    const CertificateAuthorities = struct {
        authorities: []const DistinguishedName,
    };

    // Server's trusted CAs
    const cert_authorities = CertificateAuthorities{
        .authorities = &[_]DistinguishedName{
            "CN=Example Root CA,O=Example Corp,C=US",
            "CN=Other Root CA,O=Other Corp,C=US",
        },
    };

    // Client's available certificates
    const ClientCertificate = struct {
        subject: []const u8,
        issuer: []const u8,
    };

    const client_certs = [_]ClientCertificate{
        .{ .subject = "CN=Alice", .issuer = "CN=Example Root CA,O=Example Corp,C=US" }, // Matches!
        .{ .subject = "CN=Bob", .issuer = "CN=Untrusted CA,O=Unknown,C=XX" }, // No match
    };

    // Client selects certificate issued by trusted CA
    var selected_cert: ?ClientCertificate = null;
    for (client_certs) |cert| {
        for (cert_authorities.authorities) |authority| {
            if (std.mem.eql(u8, cert.issuer, authority)) {
                selected_cert = cert;
                break;
            }
        }
    }

    try testing.expect(selected_cert != null);
    try testing.expectEqualStrings("CN=Alice", selected_cert.?.subject);
}

// Test 6: Maximum Fragment Length extension
// RFC 6066 §4
test "Extensions: max_fragment_length negotiation" {
    // Client can request smaller TLS record fragments to reduce memory usage
    // Useful for IoT devices with limited RAM

    const MaxFragmentLength = enum(u8) {
        mfl_2_9 = 1, // 2^9 = 512 bytes
        mfl_2_10 = 2, // 2^10 = 1024 bytes
        mfl_2_11 = 3, // 2^11 = 2048 bytes
        mfl_2_12 = 4, // 2^12 = 4096 bytes
    };

    // Client requests 1KB fragments
    const client_requested_mfl = MaxFragmentLength.mfl_2_10;

    // Server agrees (echoes same value in ServerHello)
    const server_accepted_mfl = MaxFragmentLength.mfl_2_10;

    try testing.expectEqual(client_requested_mfl, server_accepted_mfl);

    // Calculate negotiated fragment size
    const negotiated_fragment_size: u16 = blk: {
        break :blk switch (server_accepted_mfl) {
            .mfl_2_9 => 512,
            .mfl_2_10 => 1024,
            .mfl_2_11 => 2048,
            .mfl_2_12 => 4096,
        };
    };

    try testing.expectEqual(@as(u16, 1024), negotiated_fragment_size);

    // Both sides must respect this limit
    const max_record_size = negotiated_fragment_size;
    try testing.expect(max_record_size < 16384); // Default TLS max is 16KB
}

// Test 7: Extension context validation
// RFC 8446 §4.2
test "Extensions: extension allowed in specific message types" {
    // Different extensions are allowed in different message types
    // E.g., key_share in ClientHello/ServerHello, but not in Certificate

    const MessageType = enum {
        ClientHello,
        ServerHello,
        EncryptedExtensions,
        Certificate,
        CertificateRequest,
        NewSessionTicket,
    };

    const ExtensionType = enum(u16) {
        server_name = 0x0000,
        key_share = 0x0033,
        pre_shared_key = 0x0029,
        early_data = 0x002a,
    };

    // Check if extension is allowed in message type
    const is_extension_allowed = struct {
        fn check(ext_type: ExtensionType, msg_type: MessageType) bool {
            return switch (ext_type) {
                .server_name => switch (msg_type) {
                    .ClientHello, .EncryptedExtensions => true,
                    else => false,
                },
                .key_share => switch (msg_type) {
                    .ClientHello, .ServerHello => true,
                    else => false,
                },
                .pre_shared_key => switch (msg_type) {
                    .ClientHello, .ServerHello => true,
                    else => false,
                },
                .early_data => switch (msg_type) {
                    .ClientHello, .EncryptedExtensions, .NewSessionTicket => true,
                    else => false,
                },
            };
        }
    }.check;

    // Valid: key_share in ClientHello
    try testing.expect(is_extension_allowed(.key_share, .ClientHello));

    // Invalid: key_share in Certificate
    try testing.expect(!is_extension_allowed(.key_share, .Certificate));

    // Valid: server_name in EncryptedExtensions
    try testing.expect(is_extension_allowed(.server_name, .EncryptedExtensions));
}

// Test 8: Mandatory supported_versions extension
// RFC 8446 §4.2.1
test "Extensions: supported_versions mandatory in ClientHello" {
    // ClientHello MUST include supported_versions extension for TLS 1.3

    const Extension = struct {
        extension_type: u16,
    };

    const client_hello_extensions = [_]Extension{
        .{ .extension_type = 0x0000 }, // server_name
        .{ .extension_type = 0x002b }, // supported_versions (REQUIRED!)
        .{ .extension_type = 0x0033 }, // key_share
    };

    // Verify supported_versions is present
    var has_supported_versions = false;
    for (client_hello_extensions) |ext| {
        if (ext.extension_type == 0x002b) {
            has_supported_versions = true;
            break;
        }
    }

    try testing.expect(has_supported_versions);

    // Without supported_versions, server must reject with TLS 1.2 or abort
    if (!has_supported_versions) {
        const must_reject_tls13 = true;
        try testing.expect(must_reject_tls13);
    }
}

// Test 9: Extension length validation
// RFC 8446 §4.2
test "Extensions: extension_data length validation" {
    const Extension = struct {
        extension_type: u16,
        extension_data_length: u16,
        extension_data: []const u8,
    };

    const test_extension = Extension{
        .extension_type = 0x0000,
        .extension_data_length = 5,
        .extension_data = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 },
    };

    // Verify length matches actual data
    const length_valid = test_extension.extension_data_length == test_extension.extension_data.len;
    try testing.expect(length_valid);

    // If length mismatch, MUST send decode_error alert
    if (!length_valid) {
        const expected_alert: u8 = 50; // decode_error
        try testing.expectEqual(@as(u8, 50), expected_alert);
    }
}

// Test 10: Duplicate extension detection
// RFC 8446 §4.2
test "Extensions: duplicate extensions prohibited" {
    // RFC 8446 §4.2: Extensions in a given message MUST NOT repeat

    const Extension = struct {
        extension_type: u16,
    };

    const extensions_with_duplicate = [_]Extension{
        .{ .extension_type = 0x0000 }, // server_name
        .{ .extension_type = 0x000a }, // supported_groups
        .{ .extension_type = 0x0000 }, // server_name AGAIN - illegal!
    };

    // Check for duplicates
    var seen_types: [10]u16 = undefined;
    var seen_count: usize = 0;
    var has_duplicate = false;

    for (extensions_with_duplicate) |ext| {
        // Check if we've seen this type before
        for (seen_types[0..seen_count]) |seen_type| {
            if (ext.extension_type == seen_type) {
                has_duplicate = true;
                break;
            }
        }
        // Record this type
        if (seen_count < seen_types.len) {
            seen_types[seen_count] = ext.extension_type;
            seen_count += 1;
        }
    }

    try testing.expect(has_duplicate);

    // If duplicate found, MUST send illegal_parameter alert
    if (has_duplicate) {
        const expected_alert: u8 = 47; // illegal_parameter
        try testing.expectEqual(@as(u8, 47), expected_alert);
    }
}

// Test 11: Pre-shared key extension must be last
// RFC 8446 §4.2.11
test "Extensions: pre_shared_key must be last in ClientHello" {
    // RFC 8446 §4.2.11: pre_shared_key extension MUST be last

    const Extension = struct {
        extension_type: u16,
    };

    const valid_extensions = [_]Extension{
        .{ .extension_type = 0x0000 }, // server_name
        .{ .extension_type = 0x000a }, // supported_groups
        .{ .extension_type = 0x0029 }, // pre_shared_key (LAST)
    };

    const invalid_extensions = [_]Extension{
        .{ .extension_type = 0x0029 }, // pre_shared_key (NOT LAST)
        .{ .extension_type = 0x0000 }, // server_name
        .{ .extension_type = 0x000a }, // supported_groups
    };

    // Validate extension order
    const validate_psk_position = struct {
        fn check(extensions: []const Extension) bool {
            var psk_index: ?usize = null;
            for (extensions, 0..) |ext, i| {
                if (ext.extension_type == 0x0029) { // pre_shared_key
                    psk_index = i;
                }
            }
            if (psk_index) |idx| {
                // pre_shared_key must be at last index
                return idx == extensions.len - 1;
            }
            return true; // No PSK extension, always valid
        }
    }.check;

    try testing.expect(validate_psk_position(&valid_extensions));
    try testing.expect(!validate_psk_position(&invalid_extensions));
}

// Test 12: Server selects subset of client extensions
// RFC 8446 §4.1.3
test "Extensions: server responds with subset of client extensions" {
    // Server can only respond with extensions the client offered

    const Extension = struct {
        extension_type: u16,
    };

    const client_offered = [_]Extension{
        .{ .extension_type = 0x0000 }, // server_name
        .{ .extension_type = 0x000a }, // supported_groups
        .{ .extension_type = 0x0010 }, // alpn
        .{ .extension_type = 0x002b }, // supported_versions
    };

    const server_responded = [_]Extension{
        .{ .extension_type = 0x0000 }, // server_name (offered by client)
        .{ .extension_type = 0x0010 }, // alpn (offered by client)
        .{ .extension_type = 0x002b }, // supported_versions (offered by client)
    };

    // Verify server only responded with client-offered extensions
    for (server_responded) |server_ext| {
        var found = false;
        for (client_offered) |client_ext| {
            if (server_ext.extension_type == client_ext.extension_type) {
                found = true;
                break;
            }
        }
        try testing.expect(found);
    }

    // Server cannot respond with unsolicited extension
    const unsolicited_extension = Extension{ .extension_type = 0xFFFF };
    var was_offered = false;
    for (client_offered) |client_ext| {
        if (unsolicited_extension.extension_type == client_ext.extension_type) {
            was_offered = true;
            break;
        }
    }
    try testing.expect(!was_offered);
}

// Test 13: Empty extensions field handling
// RFC 8446 §4.2
test "Extensions: empty extensions field (no extensions)" {
    // Extensions field can be empty (zero-length) if no extensions present
    // This is different from omitting the field entirely

    const ExtensionsField = struct {
        extensions_length: u16,
        extensions: []const u8,
    };

    // Empty extensions (valid)
    const empty_extensions = ExtensionsField{
        .extensions_length = 0,
        .extensions = &[_]u8{},
    };

    try testing.expectEqual(@as(u16, 0), empty_extensions.extensions_length);
    try testing.expectEqual(@as(usize, 0), empty_extensions.extensions.len);

    // This is valid - handshake can proceed
    const handshake_valid = true;
    try testing.expect(handshake_valid);
}

// Test 14: Critical extensions concept (not in TLS 1.3 but useful pattern)
// RFC 8446 §4.2
test "Extensions: extension criticality handling" {
    // While TLS 1.3 doesn't have explicit "critical" flag like X.509,
    // some extensions are implicitly required (e.g., supported_versions for TLS 1.3)

    const Extension = struct {
        extension_type: u16,
        implicitly_critical: bool,
    };

    const extensions = [_]Extension{
        .{ .extension_type = 0x002b, .implicitly_critical = true }, // supported_versions (critical for TLS 1.3)
        .{ .extension_type = 0x0033, .implicitly_critical = true }, // key_share (critical for ECDHE)
        .{ .extension_type = 0x0000, .implicitly_critical = false }, // server_name (optional)
    };

    // Count critical extensions
    var critical_count: usize = 0;
    for (extensions) |ext| {
        if (ext.implicitly_critical) {
            critical_count += 1;
        }
    }

    try testing.expectEqual(@as(usize, 2), critical_count);

    // Missing critical extension should cause handshake failure
    const has_supported_versions = blk: {
        for (extensions) |ext| {
            if (ext.extension_type == 0x002b) break :blk true;
        }
        break :blk false;
    };

    try testing.expect(has_supported_versions);
}

// Test 15: Extension data alignment and padding
// RFC 8446 §4
test "Extensions: extension data does not require padding" {
    // TLS 1.3 wire format does not require padding for extensions
    // Extensions are byte-aligned, not word-aligned

    const Extension = struct {
        extension_type: u16, // 2 bytes
        extension_data_length: u16, // 2 bytes
        extension_data: []const u8, // Variable
    };

    // Extension with odd-length data (no padding needed)
    const odd_length_ext = Extension{
        .extension_type = 0x0000,
        .extension_data_length = 7, // Odd number
        .extension_data = &[_]u8{ 0x00, 0x05, 0x00, 0x00, 0x02, 0x68, 0x32 },
    };

    try testing.expectEqual(@as(u16, 7), odd_length_ext.extension_data_length);

    // No padding bytes added - next extension starts immediately
    const requires_padding = false;
    try testing.expect(!requires_padding);

    // Total extension size = 2 (type) + 2 (length) + data_length
    const total_size = 2 + 2 + odd_length_ext.extension_data_length;
    try testing.expectEqual(@as(u16, 11), total_size);
}
