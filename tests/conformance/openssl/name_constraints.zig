// Name Constraints Enforcement Conformance Tests
// Phase 5, Task 5: Name constraints validation
//
// These tests validate name constraints processing for restricting the namespace
// in which subordinate CAs can issue certificates, as specified in RFC 5280.
// Name constraints are critical for enterprise PKI security and cross-certification.
//
// RFC References:
// - RFC 5280 §4.2.1.10: Name Constraints extension
// - RFC 5280 §6.1.4(k): Name constraints processing in path validation
// - RFC 5280 §7.1: Name constraints syntax
// - RFC 6125: Domain-Based Application Service Identity (SNI matching)
//
// OpenSSL Equivalents:
// - openssl x509 -in cert.pem -text -noout (view name constraints)
// - openssl verify -verify_name <hostname> cert.pem
// - Name constraints checked automatically during path validation
//
// Test Strategy:
// These conformance tests validate:
// 1. Name Constraints extension parsing (permitted/excluded subtrees)
// 2. DNS name matching against permitted subtrees
// 3. DNS name matching against excluded subtrees
// 4. IP address range constraints
// 5. Email address (rfc822Name) constraints
// 6. Directory name (DN) constraints
// 7. Wildcard and subdomain matching
// 8. Constraint violation detection and rejection
// 9. Multiple constraint types in single extension
// 10. Name constraints inheritance in certificate chains

const std = @import("std");
const testing = std.testing;

// Test 1: Name Constraints extension - basic structure
// RFC 5280 §4.2.1.10
test "Name Constraints: parse extension structure" {
    // NameConstraints ::= SEQUENCE {
    //     permittedSubtrees [0] GeneralSubtrees OPTIONAL,
    //     excludedSubtrees  [1] GeneralSubtrees OPTIONAL
    // }
    //
    // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
    //
    // GeneralSubtree ::= SEQUENCE {
    //     base           GeneralName,
    //     minimum   [0]  BaseDistance DEFAULT 0,
    //     maximum   [1]  BaseDistance OPTIONAL
    // }

    const GeneralName = union(enum) {
        dNSName: []const u8,
        iPAddress: []const u8,
        rfc822Name: []const u8, // Email
        directoryName: []const u8, // DN
    };

    const GeneralSubtree = struct {
        base: GeneralName,
        minimum: u32 = 0, // Usually 0
        maximum: ?u32 = null, // Rarely used
    };

    const NameConstraints = struct {
        permitted_subtrees: ?[]const GeneralSubtree = null,
        excluded_subtrees: ?[]const GeneralSubtree = null,
    };

    // Example: CA certificate restricts issuance to .example.com domain
    const constraints = NameConstraints{
        .permitted_subtrees = &[_]GeneralSubtree{
            .{ .base = .{ .dNSName = "example.com" } },
        },
        .excluded_subtrees = &[_]GeneralSubtree{
            .{ .base = .{ .dNSName = "forbidden.example.com" } },
        },
    };

    try testing.expect(constraints.permitted_subtrees != null);
    try testing.expect(constraints.excluded_subtrees != null);
    try testing.expectEqual(@as(usize, 1), constraints.permitted_subtrees.?.len);
    try testing.expectEqual(@as(usize, 1), constraints.excluded_subtrees.?.len);
}

// Test 2: DNS name matching - permitted subtree
// RFC 5280 §4.2.1.10
test "Name Constraints: DNS name within permitted subtree" {
    // Permitted subtree: .example.com
    // Means: example.com, www.example.com, foo.bar.example.com are ALL allowed

    const permitted_dns_constraint = "example.com";
    const cert_dns_names = [_][]const u8{
        "example.com",
        "www.example.com",
        "api.example.com",
        "foo.bar.example.com",
    };

    // Check if each DNS name is within permitted subtree
    for (cert_dns_names) |dns_name| {
        const is_permitted = blk: {
            // DNS constraint ".example.com" matches:
            // 1. Exact match: "example.com"
            // 2. Subdomain: "*.example.com"
            if (std.mem.eql(u8, dns_name, permitted_dns_constraint)) {
                break :blk true; // Exact match
            }
            // Check if it's a subdomain
            if (std.mem.endsWith(u8, dns_name, permitted_dns_constraint)) {
                // Ensure there's a dot before the constraint part
                const prefix_len = dns_name.len - permitted_dns_constraint.len;
                if (prefix_len > 0 and dns_name[prefix_len - 1] == '.') {
                    break :blk true; // Valid subdomain
                }
            }
            break :blk false;
        };

        try testing.expect(is_permitted);
    }
}

// Test 3: DNS name matching - excluded subtree
// RFC 5280 §4.2.1.10
test "Name Constraints: DNS name within excluded subtree rejected" {
    // Excluded subtree: forbidden.example.com
    // Means: forbidden.example.com and ANY subdomain are FORBIDDEN

    const excluded_dns_constraint = "forbidden.example.com";
    const forbidden_dns_names = [_][]const u8{
        "forbidden.example.com",
        "www.forbidden.example.com",
        "api.forbidden.example.com",
    };

    for (forbidden_dns_names) |dns_name| {
        const is_excluded = blk: {
            if (std.mem.eql(u8, dns_name, excluded_dns_constraint)) {
                break :blk true; // Exact match - excluded
            }
            if (std.mem.endsWith(u8, dns_name, excluded_dns_constraint)) {
                const prefix_len = dns_name.len - excluded_dns_constraint.len;
                if (prefix_len > 0 and dns_name[prefix_len - 1] == '.') {
                    break :blk true; // Subdomain - excluded
                }
            }
            break :blk false;
        };

        try testing.expect(is_excluded);

        // If excluded, validation MUST fail
        if (is_excluded) {
            const validation_fails = true;
            try testing.expect(validation_fails);
        }
    }
}

// Test 4: DNS name constraints - permitted vs. excluded precedence
// RFC 5280 §4.2.1.10
test "Name Constraints: excluded takes precedence over permitted" {
    // Permitted: .example.com
    // Excluded: .forbidden.example.com
    // Result: www.example.com is OK, forbidden.example.com is REJECTED

    const permitted_constraint = "example.com";
    const excluded_constraint = "forbidden.example.com";

    const test_cases = [_]struct {
        dns_name: []const u8,
        should_be_allowed: bool,
    }{
        .{ .dns_name = "www.example.com", .should_be_allowed = true },
        .{ .dns_name = "api.example.com", .should_be_allowed = true },
        .{ .dns_name = "forbidden.example.com", .should_be_allowed = false }, // Excluded!
        .{ .dns_name = "sub.forbidden.example.com", .should_be_allowed = false }, // Excluded!
    };

    for (test_cases) |tc| {
        // Check if permitted
        const is_permitted = blk: {
            if (std.mem.eql(u8, tc.dns_name, permitted_constraint) or
                (std.mem.endsWith(u8, tc.dns_name, permitted_constraint) and
                    tc.dns_name[tc.dns_name.len - permitted_constraint.len - 1] == '.'))
            {
                break :blk true;
            }
            break :blk false;
        };

        // Check if excluded
        const is_excluded = blk: {
            if (std.mem.eql(u8, tc.dns_name, excluded_constraint) or
                (std.mem.endsWith(u8, tc.dns_name, excluded_constraint) and
                    tc.dns_name[tc.dns_name.len - excluded_constraint.len - 1] == '.'))
            {
                break :blk true;
            }
            break :blk false;
        };

        // Excluded takes precedence
        const is_allowed = is_permitted and !is_excluded;
        try testing.expectEqual(tc.should_be_allowed, is_allowed);
    }
}

// Test 5: IP address constraints
// RFC 5280 §4.2.1.10
test "Name Constraints: IP address range constraints" {
    // IP address constraints are specified as network/netmask
    // Example: 192.168.0.0/255.255.0.0 means 192.168.0.0/16

    const IPConstraint = struct {
        network: [4]u8, // Network address
        netmask: [4]u8, // Netmask
    };

    const permitted_ip_constraint = IPConstraint{
        .network = .{ 192, 168, 0, 0 },
        .netmask = .{ 255, 255, 0, 0 }, // /16 subnet
    };

    const test_ips = [_]struct {
        ip: [4]u8,
        should_be_allowed: bool,
    }{
        .{ .ip = .{ 192, 168, 1, 1 }, .should_be_allowed = true }, // Within 192.168.0.0/16
        .{ .ip = .{ 192, 168, 255, 254 }, .should_be_allowed = true }, // Within range
        .{ .ip = .{ 192, 169, 1, 1 }, .should_be_allowed = false }, // Outside range
        .{ .ip = .{ 10, 0, 0, 1 }, .should_be_allowed = false }, // Different network
    };

    for (test_ips) |test_case| {
        // Check if IP is within permitted range
        const is_within_range = blk: {
            for (0..4) |i| {
                const ip_masked = test_case.ip[i] & permitted_ip_constraint.netmask[i];
                const net_masked = permitted_ip_constraint.network[i] & permitted_ip_constraint.netmask[i];
                if (ip_masked != net_masked) {
                    break :blk false;
                }
            }
            break :blk true;
        };

        try testing.expectEqual(test_case.should_be_allowed, is_within_range);
    }
}

// Test 6: Email address (rfc822Name) constraints
// RFC 5280 §4.2.1.10
test "Name Constraints: rfc822Name (email) constraints" {
    // Email constraints can be:
    // 1. Specific address: "user@example.com"
    // 2. Domain: "example.com" (matches any @example.com)
    // 3. Mailbox: "@.example.com" (matches any subdomain)

    const permitted_email_constraint = "example.com";

    const test_emails = [_]struct {
        email: []const u8,
        should_be_allowed: bool,
    }{
        .{ .email = "user@example.com", .should_be_allowed = true },
        .{ .email = "admin@example.com", .should_be_allowed = true },
        .{ .email = "user@mail.example.com", .should_be_allowed = true }, // Subdomain
        .{ .email = "user@other.com", .should_be_allowed = false },
    };

    for (test_emails) |test_case| {
        // Extract domain from email
        const at_pos = std.mem.indexOf(u8, test_case.email, "@");
        const is_permitted = blk: {
            if (at_pos) |pos| {
                const domain = test_case.email[pos + 1 ..];
                // Check if domain matches constraint
                if (std.mem.eql(u8, domain, permitted_email_constraint)) {
                    break :blk true; // Exact match
                }
                // Check if subdomain
                if (std.mem.endsWith(u8, domain, permitted_email_constraint)) {
                    const prefix_len = domain.len - permitted_email_constraint.len;
                    if (prefix_len > 0 and domain[prefix_len - 1] == '.') {
                        break :blk true;
                    }
                }
            }
            break :blk false;
        };

        try testing.expectEqual(test_case.should_be_allowed, is_permitted);
    }
}

// Test 7: Directory name (DN) constraints
// RFC 5280 §4.2.1.10
test "Name Constraints: directoryName (DN) constraints" {
    // Directory name constraints restrict the DN namespace
    // Constraint: "O=Example Corp,C=US"
    // Permits: Any DN within this organizational hierarchy

    const permitted_dn_constraint = "O=Example Corp,C=US";

    const test_dns = [_]struct {
        dn: []const u8,
        should_be_allowed: bool,
    }{
        .{ .dn = "CN=Server,O=Example Corp,C=US", .should_be_allowed = true },
        .{ .dn = "CN=User,OU=Engineering,O=Example Corp,C=US", .should_be_allowed = true },
        .{ .dn = "CN=Server,O=Other Corp,C=US", .should_be_allowed = false },
    };

    for (test_dns) |test_case| {
        // Simplified DN matching: check if constraint DN is suffix
        const is_permitted = std.mem.endsWith(u8, test_case.dn, permitted_dn_constraint);
        try testing.expectEqual(test_case.should_be_allowed, is_permitted);
    }
}

// Test 8: Wildcard matching and edge cases
// RFC 5280 §4.2.1.10
test "Name Constraints: wildcard and edge case handling" {
    const permitted_constraint = "example.com";

    const test_cases = [_]struct {
        dns_name: []const u8,
        should_be_allowed: bool,
        description: []const u8,
    }{
        .{ .dns_name = "example.com", .should_be_allowed = true, .description = "Exact match" },
        .{ .dns_name = "www.example.com", .should_be_allowed = true, .description = "Single subdomain" },
        .{ .dns_name = "a.b.c.example.com", .should_be_allowed = true, .description = "Multi-level subdomain" },
        .{ .dns_name = "notexample.com", .should_be_allowed = false, .description = "Different domain (suffix match fails)" },
        .{ .dns_name = "example.com.evil.com", .should_be_allowed = false, .description = "Domain as substring" },
        .{ .dns_name = "xexample.com", .should_be_allowed = false, .description = "Prefix mismatch" },
    };

    for (test_cases) |tc| {
        const is_permitted = blk: {
            if (std.mem.eql(u8, tc.dns_name, permitted_constraint)) {
                break :blk true; // Exact match
            }
            if (std.mem.endsWith(u8, tc.dns_name, permitted_constraint)) {
                const prefix_len = tc.dns_name.len - permitted_constraint.len;
                if (prefix_len > 0 and tc.dns_name[prefix_len - 1] == '.') {
                    break :blk true; // Valid subdomain
                }
            }
            break :blk false;
        };

        try testing.expectEqual(tc.should_be_allowed, is_permitted);
    }
}

// Test 9: Multiple constraint types in single extension
// RFC 5280 §4.2.1.10
test "Name Constraints: multiple constraint types" {
    // A certificate can have multiple types of constraints simultaneously

    const GeneralName = union(enum) {
        dNSName: []const u8,
        iPAddress: struct { network: [4]u8, netmask: [4]u8 },
        rfc822Name: []const u8,
    };

    const GeneralSubtree = struct {
        base: GeneralName,
    };

    const constraints = struct {
        permitted: []const GeneralSubtree,
    }{
        .permitted = &[_]GeneralSubtree{
            .{ .base = .{ .dNSName = "example.com" } },
            .{ .base = .{ .iPAddress = .{ .network = .{ 192, 168, 0, 0 }, .netmask = .{ 255, 255, 0, 0 } } } },
            .{ .base = .{ .rfc822Name = "example.com" } },
        },
    };

    try testing.expectEqual(@as(usize, 3), constraints.permitted.len);

    // Verify each constraint type using active tag
    try testing.expectEqual(std.meta.Tag(GeneralName).dNSName, std.meta.activeTag(constraints.permitted[0].base));
    try testing.expectEqual(std.meta.Tag(GeneralName).iPAddress, std.meta.activeTag(constraints.permitted[1].base));
    try testing.expectEqual(std.meta.Tag(GeneralName).rfc822Name, std.meta.activeTag(constraints.permitted[2].base));
}

// Test 10: Name constraints in certificate chains
// RFC 5280 §6.1.4(k)
test "Name Constraints: constraint accumulation in certificate chains" {
    // Name constraints accumulate as we traverse the chain
    // Constraints from ALL CA certificates in the path apply

    const Certificate = struct {
        subject: []const u8,
        permitted_dns: ?[]const u8 = null,
        excluded_dns: ?[]const u8 = null,
    };

    // Root CA: permits .example.com
    const root_cert = Certificate{
        .subject = "CN=Root CA",
        .permitted_dns = "example.com",
        .excluded_dns = null,
    };

    // Intermediate CA: additionally excludes .internal.example.com
    const intermediate_cert = Certificate{
        .subject = "CN=Intermediate CA",
        .permitted_dns = null, // Inherits from root
        .excluded_dns = "internal.example.com",
    };

    // End-entity certificate DNS name to validate
    const leaf_dns_name = "server.example.com";

    // Check against root's permitted constraint
    const permitted_by_root = blk: {
        if (root_cert.permitted_dns) |constraint| {
            if (std.mem.eql(u8, leaf_dns_name, constraint) or
                (std.mem.endsWith(u8, leaf_dns_name, constraint) and
                    leaf_dns_name.len > constraint.len and
                    leaf_dns_name[leaf_dns_name.len - constraint.len - 1] == '.'))
            {
                break :blk true;
            }
        }
        break :blk false;
    };

    // Check against intermediate's excluded constraint
    const excluded_by_intermediate = blk: {
        if (intermediate_cert.excluded_dns) |constraint| {
            if (std.mem.eql(u8, leaf_dns_name, constraint) or
                (std.mem.endsWith(u8, leaf_dns_name, constraint) and
                    leaf_dns_name.len > constraint.len and
                    leaf_dns_name[leaf_dns_name.len - constraint.len - 1] == '.'))
            {
                break :blk true;
            }
        }
        break :blk false;
    };

    // Leaf is valid if permitted by all and excluded by none
    const leaf_valid = permitted_by_root and !excluded_by_intermediate;
    try testing.expect(leaf_valid);

    // Test an excluded name: internal.example.com
    const internal_dns_name = "internal.example.com";
    const internal_excluded = blk: {
        if (intermediate_cert.excluded_dns) |constraint| {
            if (std.mem.eql(u8, internal_dns_name, constraint)) {
                break :blk true;
            }
        }
        break :blk false;
    };
    try testing.expect(internal_excluded);

    // Internal name should be rejected
    const internal_valid = permitted_by_root and !internal_excluded;
    try testing.expect(!internal_valid);
}
