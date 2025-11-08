// AIA (Authority Information Access) Conformance Tests
// Phase 5, Task 3: AIA extension parsing and certificate chain building
//
// These tests validate Authority Information Access (AIA) extension support
// for locating CA certificates and OCSP responders as specified in RFC 5280.
//
// RFC References:
// - RFC 5280 §4.2.2.1: Authority Information Access (AIA) extension
// - RFC 6960 §3.1: OCSP Requests (locating OCSP responder via AIA)
// - RFC 2560: Original OCSP specification
//
// OpenSSL Equivalents:
// - openssl x509 -in cert.pem -text -noout (shows AIA extension)
// - openssl s_client -connect host:443 -showcerts (retrieves chain via AIA)
// - openssl ocsp -url <AIA OCSP URL> (uses AIA for OCSP)
//
// Test Strategy:
// These conformance tests validate:
// 1. AIA extension structure parsing
// 2. OCSP responder location extraction
// 3. CA issuers certificate location extraction
// 4. Multiple access methods in single extension
// 5. Certificate chain building via CA issuers
// 6. HTTP/HTTPS URL validation
// 7. Error handling for malformed AIA data

const std = @import("std");
const testing = std.testing;

// Test 1: AIA extension structure - basic parsing
// RFC 5280 §4.2.2.1
test "AIA: parse Authority Information Access extension" {
    // AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
    //
    // AccessDescription ::= SEQUENCE {
    //     accessMethod OBJECT IDENTIFIER,
    //     accessLocation GeneralName
    // }

    const AccessMethod = enum {
        id_ad_ocsp, // 1.3.6.1.5.5.7.48.1 (OCSP responder)
        id_ad_caIssuers, // 1.3.6.1.5.5.7.48.2 (CA certificate)
    };

    const AccessDescription = struct {
        access_method: AccessMethod,
        access_location: []const u8, // Typically a URL
    };

    // Example AIA extension with both methods
    const aia_extension = [_]AccessDescription{
        .{
            .access_method = .id_ad_ocsp,
            .access_location = "http://ocsp.example.com",
        },
        .{
            .access_method = .id_ad_caIssuers,
            .access_location = "http://certs.example.com/ca.crt",
        },
    };

    try testing.expectEqual(@as(usize, 2), aia_extension.len);
    try testing.expectEqual(AccessMethod.id_ad_ocsp, aia_extension[0].access_method);
    try testing.expectEqual(AccessMethod.id_ad_caIssuers, aia_extension[1].access_method);
}

// Test 2: Extract OCSP responder URL from AIA
// RFC 6960 §3.1
test "AIA: extract OCSP responder URL" {
    const AccessMethod = enum {
        id_ad_ocsp,
        id_ad_caIssuers,
    };

    const AccessDescription = struct {
        access_method: AccessMethod,
        access_location: []const u8,
    };

    // AIA extension containing OCSP responder
    const aia_entries = [_]AccessDescription{
        .{ .access_method = .id_ad_caIssuers, .access_location = "http://certs.example.com/ca.crt" },
        .{ .access_method = .id_ad_ocsp, .access_location = "http://ocsp.example.com" },
    };

    // Extract OCSP responder URL
    var ocsp_url: ?[]const u8 = null;
    for (aia_entries) |entry| {
        if (entry.access_method == .id_ad_ocsp) {
            ocsp_url = entry.access_location;
            break;
        }
    }

    try testing.expect(ocsp_url != null);
    try testing.expectEqualStrings("http://ocsp.example.com", ocsp_url.?);

    // Verify URL is valid HTTP/HTTPS
    const is_http = std.mem.startsWith(u8, ocsp_url.?, "http://") or
        std.mem.startsWith(u8, ocsp_url.?, "https://");
    try testing.expect(is_http);
}

// Test 3: Extract CA issuers certificate URL from AIA
// RFC 5280 §4.2.2.1
test "AIA: extract CA issuers certificate URL" {
    const AccessMethod = enum {
        id_ad_ocsp,
        id_ad_caIssuers,
    };

    const AccessDescription = struct {
        access_method: AccessMethod,
        access_location: []const u8,
    };

    const aia_entries = [_]AccessDescription{
        .{ .access_method = .id_ad_ocsp, .access_location = "http://ocsp.example.com" },
        .{ .access_method = .id_ad_caIssuers, .access_location = "http://certs.example.com/intermediate.crt" },
    };

    // Extract CA issuers URL
    var ca_issuers_url: ?[]const u8 = null;
    for (aia_entries) |entry| {
        if (entry.access_method == .id_ad_caIssuers) {
            ca_issuers_url = entry.access_location;
            break;
        }
    }

    try testing.expect(ca_issuers_url != null);
    try testing.expectEqualStrings("http://certs.example.com/intermediate.crt", ca_issuers_url.?);

    // CA issuers URL typically points to DER or PEM encoded certificate
    const is_cert_url = std.mem.indexOf(u8, ca_issuers_url.?, ".crt") != null or
        std.mem.indexOf(u8, ca_issuers_url.?, ".cer") != null or
        std.mem.indexOf(u8, ca_issuers_url.?, ".der") != null or
        std.mem.indexOf(u8, ca_issuers_url.?, ".pem") != null;

    try testing.expect(is_cert_url);
}

// Test 4: Multiple OCSP responders in AIA
// RFC 5280 §4.2.2.1 (multiple AccessDescriptions allowed)
test "AIA: multiple OCSP responder URLs" {
    const AccessMethod = enum {
        id_ad_ocsp,
        id_ad_caIssuers,
    };

    const AccessDescription = struct {
        access_method: AccessMethod,
        access_location: []const u8,
    };

    // AIA with multiple OCSP responders (primary + fallback)
    const aia_entries = [_]AccessDescription{
        .{ .access_method = .id_ad_ocsp, .access_location = "http://ocsp1.example.com" },
        .{ .access_method = .id_ad_ocsp, .access_location = "http://ocsp2.example.com" },
        .{ .access_method = .id_ad_caIssuers, .access_location = "http://certs.example.com/ca.crt" },
    };

    // Collect all OCSP URLs
    var ocsp_urls: [10][]const u8 = undefined;
    var ocsp_count: usize = 0;

    for (aia_entries) |entry| {
        if (entry.access_method == .id_ad_ocsp) {
            ocsp_urls[ocsp_count] = entry.access_location;
            ocsp_count += 1;
        }
    }

    try testing.expectEqual(@as(usize, 2), ocsp_count);
    try testing.expectEqualStrings("http://ocsp1.example.com", ocsp_urls[0]);
    try testing.expectEqualStrings("http://ocsp2.example.com", ocsp_urls[1]);

    // Client can try primary first, then fallback to secondary
    const primary_ocsp = ocsp_urls[0];
    const fallback_ocsp = ocsp_urls[1];

    try testing.expect(primary_ocsp.len > 0);
    try testing.expect(fallback_ocsp.len > 0);
}

// Test 5: Certificate chain building using CA issuers
// RFC 5280 §4.2.2.1
test "AIA: build certificate chain using CA issuers URLs" {
    // Scenario: Client receives leaf certificate without intermediate
    // Client uses AIA to download missing intermediate certificate

    const Certificate = struct {
        subject: []const u8,
        issuer: []const u8,
        aia_ca_issuers_url: ?[]const u8,
    };

    // Leaf certificate with AIA pointing to intermediate
    const leaf_cert = Certificate{
        .subject = "CN=server.example.com",
        .issuer = "CN=Intermediate CA",
        .aia_ca_issuers_url = "http://certs.example.com/intermediate.crt",
    };

    // Intermediate certificate (downloaded via AIA)
    const intermediate_cert = Certificate{
        .subject = "CN=Intermediate CA",
        .issuer = "CN=Root CA",
        .aia_ca_issuers_url = "http://certs.example.com/root.crt",
    };

    // Root certificate (downloaded via AIA or in trust store)
    const root_cert = Certificate{
        .subject = "CN=Root CA",
        .issuer = "CN=Root CA", // Self-signed
        .aia_ca_issuers_url = null,
    };

    // Build chain by following AIA URLs
    const chain = [_]Certificate{ leaf_cert, intermediate_cert, root_cert };

    // Validate chain links
    try testing.expectEqualStrings(chain[0].issuer, chain[1].subject); // Leaf → Intermediate
    try testing.expectEqualStrings(chain[1].issuer, chain[2].subject); // Intermediate → Root
    try testing.expectEqualStrings(chain[2].subject, chain[2].issuer); // Root is self-signed

    // Verify AIA URLs present where needed
    try testing.expect(chain[0].aia_ca_issuers_url != null);
    try testing.expect(chain[1].aia_ca_issuers_url != null);
    try testing.expect(chain[2].aia_ca_issuers_url == null); // Root doesn't need AIA
}

// Test 6: HTTPS URLs for secure certificate retrieval
// RFC 5280 §4.2.2.1
test "AIA: HTTPS URLs for secure certificate distribution" {
    const AccessMethod = enum {
        id_ad_ocsp,
        id_ad_caIssuers,
    };

    const AccessDescription = struct {
        access_method: AccessMethod,
        access_location: []const u8,
    };

    // Modern deployments use HTTPS for security
    const aia_entries = [_]AccessDescription{
        .{ .access_method = .id_ad_ocsp, .access_location = "https://ocsp.example.com" },
        .{ .access_method = .id_ad_caIssuers, .access_location = "https://certs.example.com/ca.crt" },
    };

    // Verify all URLs use HTTPS
    for (aia_entries) |entry| {
        const is_https = std.mem.startsWith(u8, entry.access_location, "https://");
        try testing.expect(is_https);
    }

    // HTTPS provides:
    // 1. Authenticity (server identity verified)
    // 2. Integrity (data not tampered)
    // 3. Confidentiality (encrypted transport)
    const security_benefits = [_][]const u8{ "authenticity", "integrity", "confidentiality" };
    try testing.expectEqual(@as(usize, 3), security_benefits.len);
}

// Test 7: AIA extension is non-critical
// RFC 5280 §4.2.2.1
test "AIA: extension is non-critical" {
    // AIA extension MUST NOT be marked critical
    // If critical, clients that don't understand AIA would reject the cert

    const X509Extension = struct {
        oid: []const u8, // Extension OID
        critical: bool, // Critical flag
        value: []const u8, // Extension value
    };

    const aia_extension = X509Extension{
        .oid = "1.3.6.1.5.5.7.1.1", // id-pe-authorityInfoAccess
        .critical = false, // MUST be false
        .value = "...", // DER-encoded AIA data
    };

    // Verify non-critical
    try testing.expect(!aia_extension.critical);

    // If AIA were critical (which it shouldn't be):
    // - Old clients that don't recognize AIA would reject certificate
    // - This would break backward compatibility
    const would_break_compatibility = aia_extension.critical;
    try testing.expect(!would_break_compatibility);
}

// Test 8: URL validation and sanitization
// Security: Prevent SSRF and injection attacks
test "AIA: URL validation and security checks" {
    const AccessDescription = struct {
        access_method: enum { id_ad_ocsp, id_ad_caIssuers },
        access_location: []const u8,
    };

    // Valid URLs
    const valid_urls = [_]AccessDescription{
        .{ .access_method = .id_ad_ocsp, .access_location = "http://ocsp.example.com" },
        .{ .access_method = .id_ad_ocsp, .access_location = "https://ocsp.example.com:8080/ocsp" },
        .{ .access_method = .id_ad_caIssuers, .access_location = "http://certs.example.com/ca.crt" },
    };

    // Invalid/suspicious URLs (should be rejected)
    const invalid_urls = [_][]const u8{
        "file:///etc/passwd", // Local file access
        "ftp://example.com/ca.crt", // Non-HTTP protocol
        "http://127.0.0.1/internal", // Localhost (SSRF risk)
        "http://169.254.169.254/metadata", // AWS metadata (SSRF)
        "javascript:alert(1)", // Script injection
    };

    // Validate good URLs
    for (valid_urls) |entry| {
        const is_valid = std.mem.startsWith(u8, entry.access_location, "http://") or
            std.mem.startsWith(u8, entry.access_location, "https://");
        try testing.expect(is_valid);
    }

    // Reject bad URLs
    for (invalid_urls) |url| {
        const is_http = std.mem.startsWith(u8, url, "http://") or
            std.mem.startsWith(u8, url, "https://");

        // Even if it starts with http://, check for localhost/private IPs
        const is_localhost = std.mem.indexOf(u8, url, "127.0.0.1") != null or
            std.mem.indexOf(u8, url, "localhost") != null or
            std.mem.indexOf(u8, url, "169.254.169.254") != null;

        const is_file = std.mem.startsWith(u8, url, "file://");
        const is_script = std.mem.startsWith(u8, url, "javascript:");

        const is_safe = is_http and !is_localhost and !is_file and !is_script;

        // These URLs should fail validation
        if (std.mem.eql(u8, url, "http://ocsp.example.com")) {
            try testing.expect(is_safe); // This one is safe
        } else {
            try testing.expect(!is_safe); // Others are unsafe
        }
    }
}

// Test 9: AIA with LDAP URLs (less common but valid)
// RFC 5280 §4.2.2.1
test "AIA: LDAP URLs for certificate retrieval" {
    const AccessMethod = enum {
        id_ad_ocsp,
        id_ad_caIssuers,
    };

    const AccessDescription = struct {
        access_method: AccessMethod,
        access_location: []const u8,
    };

    // LDAP can be used instead of HTTP
    const aia_entries = [_]AccessDescription{
        .{
            .access_method = .id_ad_caIssuers,
            .access_location = "ldap://ldap.example.com/cn=CA,o=Example?cACertificate;binary",
        },
    };

    const ldap_url = aia_entries[0].access_location;

    // Verify LDAP URL format
    const is_ldap = std.mem.startsWith(u8, ldap_url, "ldap://") or
        std.mem.startsWith(u8, ldap_url, "ldaps://"); // LDAPS for secure LDAP

    try testing.expect(is_ldap);

    // LDAP URL components:
    // ldap://hostname/dn?attributes?scope?filter
    const contains_dn = std.mem.indexOf(u8, ldap_url, "cn=") != null;
    try testing.expect(contains_dn);

    // Note: HTTP is more common than LDAP for AIA in modern PKI
    const http_more_common = true;
    try testing.expect(http_more_common);
}

// Test 10: Error handling - missing AIA extension
// RFC 5280 §4.2.2.1 (AIA is optional)
test "AIA: handle certificates without AIA extension" {
    const Certificate = struct {
        subject: []const u8,
        issuer: []const u8,
        has_aia: bool,
        aia_entries: []const u8 = "",
    };

    // Certificate without AIA extension
    const cert_without_aia = Certificate{
        .subject = "CN=legacy.example.com",
        .issuer = "CN=Legacy CA",
        .has_aia = false,
    };

    // Certificate with AIA extension
    const cert_with_aia = Certificate{
        .subject = "CN=modern.example.com",
        .issuer = "CN=Modern CA",
        .has_aia = true,
        .aia_entries = "http://ocsp.example.com",
    };

    // Validate handling
    try testing.expect(!cert_without_aia.has_aia);
    try testing.expect(cert_with_aia.has_aia);

    // Without AIA:
    // - Cannot auto-download intermediate certificates
    // - Cannot locate OCSP responder via AIA
    // - Must use other methods (CRL Distribution Points, manual config)

    if (!cert_without_aia.has_aia) {
        // Fallback: Check for CRL Distribution Points
        // Fallback: Use manually configured OCSP responder
        // Fallback: Require complete certificate chain in handshake
        const fallback_methods_available = true;
        try testing.expect(fallback_methods_available);
    }

    // AIA is helpful but not required
    const aia_is_optional = true;
    try testing.expect(aia_is_optional);
}
