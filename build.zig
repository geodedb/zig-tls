const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ========================================================================
    // Define all TLS modules
    // ========================================================================

    const alert_mod = b.addModule("alert", .{
        .root_source_file = b.path("src/alert.zig"),
        .target = target,
    });

    const asn1_mod = b.addModule("asn1", .{
        .root_source_file = b.path("src/asn1.zig"),
        .target = target,
    });

    const key_schedule_mod = b.addModule("quic_tls", .{
        .root_source_file = b.path("src/key_schedule.zig"),
        .target = target,
    });

    const logger_mod = b.addModule("quic_logger", .{
        .root_source_file = b.path("src/quic_logger.zig"),
        .target = target,
    });

    // QUIC varint encoding (RFC 9000 §16)
    const byteorder_mod = b.addModule("byteorder", .{
        .root_source_file = b.path("src/byteorder.zig"),
        .target = target,
    });

    const varint_mod = b.addModule("varint", .{
        .root_source_file = b.path("src/varint.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "byteorder", .module = byteorder_mod },
        },
    });

    const transport_params_mod = b.addModule("quic_transport_params", .{
        .root_source_file = b.path("src/quic_transport_params.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "varint", .module = varint_mod },
        },
    });

    const sig_mod = b.addModule("sig", .{
        .root_source_file = b.path("src/sig.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "asn1", .module = asn1_mod },
        },
    });

    const sct_mod = b.addModule("sct", .{
        .root_source_file = b.path("src/sct.zig"),
        .target = target,
    });

    const x509_mod = b.addModule("x509", .{
        .root_source_file = b.path("src/x509.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "asn1", .module = asn1_mod },
            .{ .name = "sig", .module = sig_mod },
        },
    });

    const ocsp_mod = b.addModule("ocsp", .{
        .root_source_file = b.path("src/ocsp.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "asn1", .module = asn1_mod },
            .{ .name = "x509", .module = x509_mod },
        },
    });

    const record_mod = b.addModule("record", .{
        .root_source_file = b.path("src/record.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "quic_tls", .module = key_schedule_mod },
        },
    });

    const zero_rtt_mod = b.addModule("zero_rtt", .{
        .root_source_file = b.path("src/zero_rtt.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "quic_tls", .module = key_schedule_mod },
        },
    });

    const tls13_full_mod = b.addModule("tls13_full", .{
        .root_source_file = b.path("src/tls13_full.zig"),
        .target = target,
    });

    const tls13_mod = b.addModule("tls13", .{
        .root_source_file = b.path("src/tls13.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "quic_tls", .module = key_schedule_mod },
            .{ .name = "x509", .module = x509_mod },
            .{ .name = "sig", .module = sig_mod },
            .{ .name = "alert", .module = alert_mod },
            .{ .name = "zero_rtt", .module = zero_rtt_mod },
            .{ .name = "tls13_full", .module = tls13_full_mod },
            .{ .name = "quic_logger", .module = logger_mod },
            .{ .name = "quic_transport_params", .module = transport_params_mod },
            .{ .name = "ocsp", .module = ocsp_mod },
            .{ .name = "sct", .module = sct_mod },
        },
    });

    // Main library module that re-exports everything
    const zig_tls_mod = b.addModule("ztls", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "alert", .module = alert_mod },
            .{ .name = "asn1", .module = asn1_mod },
            .{ .name = "quic_tls", .module = key_schedule_mod },
            .{ .name = "record", .module = record_mod },
            .{ .name = "sig", .module = sig_mod },
            .{ .name = "x509", .module = x509_mod },
            .{ .name = "zero_rtt", .module = zero_rtt_mod },
            .{ .name = "tls13_full", .module = tls13_full_mod },
            .{ .name = "tls13", .module = tls13_mod },
            .{ .name = "quic_logger", .module = logger_mod },
            .{ .name = "quic_transport_params", .module = transport_params_mod },
            .{ .name = "ocsp", .module = ocsp_mod },
            .{ .name = "sct", .module = sct_mod },
        },
    });

    // ========================================================================
    // Unit Tests - Test each module independently
    // ========================================================================

    const test_step = b.step("test", "Run all unit tests");

    // Helper to create test with imports
    const TestInfo = struct {
        name: []const u8,
        source: []const u8,
        imports: []const std.Build.Module.Import,
    };

    const tests = [_]TestInfo{
        .{ .name = "alert", .source = "src/alert.zig", .imports = &.{} },
        .{ .name = "asn1", .source = "src/asn1.zig", .imports = &.{} },
        .{ .name = "key_schedule", .source = "src/key_schedule.zig", .imports = &.{} },
        .{ .name = "quic_logger", .source = "src/quic_logger.zig", .imports = &.{} },
        .{
            .name = "quic_transport_params",
            .source = "src/quic_transport_params.zig",
            .imports = &.{
                .{ .name = "varint", .module = varint_mod },
            },
        },
        .{ .name = "tls13_full", .source = "src/tls13_full.zig", .imports = &.{} },
        .{
            .name = "sig",
            .source = "src/sig.zig",
            .imports = &.{
                .{ .name = "asn1", .module = asn1_mod },
            },
        },
        .{
            .name = "x509",
            .source = "src/x509.zig",
            .imports = &.{
                .{ .name = "asn1", .module = asn1_mod },
            },
        },
        .{
            .name = "record",
            .source = "src/record.zig",
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
            },
        },
        .{
            .name = "zero_rtt",
            .source = "src/zero_rtt.zig",
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
            },
        },
    };

    for (tests) |test_info| {
        const unit_test = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(test_info.source),
                .target = target,
                .optimize = optimize,
                .imports = test_info.imports,
            }),
        });

        const run_test = b.addRunArtifact(unit_test);
        test_step.dependOn(&run_test.step);
    }

    // TLS13 tests with full dependencies
    const tls13_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tls13.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "sig", .module = sig_mod },
                .{ .name = "alert", .module = alert_mod },
                .{ .name = "zero_rtt", .module = zero_rtt_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
                .{ .name = "quic_logger", .module = logger_mod },
                .{ .name = "quic_transport_params", .module = transport_params_mod },
                .{ .name = "ocsp", .module = ocsp_mod },
                .{ .name = "sct", .module = sct_mod },
            },
        }),
    });
    const run_tls13_test = b.addRunArtifact(tls13_test);
    test_step.dependOn(&run_tls13_test.step);

    // Lib tests
    const lib_test = b.addTest(.{
        .root_module = zig_tls_mod,
    });
    const run_lib_test = b.addRunArtifact(lib_test);
    test_step.dependOn(&run_lib_test.step);

    // ========================================================================
    // RFC 8446 Test Vectors
    // ========================================================================

    const test_vectors_step = b.step("test-vectors", "Run RFC 8446 test vector validation");

    const vectors_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rfc8446_vectors.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "record", .module = record_mod },
            },
        }),
    });

    const run_vectors_test = b.addRunArtifact(vectors_test);
    test_vectors_step.dependOn(&run_vectors_test.step);

    // Add to main test step
    test_step.dependOn(test_vectors_step);

    // ========================================================================
    // RFC-Specific Test Suites - Organized by RFC section
    // ========================================================================

    // RFC 8446: TLS 1.3 Core Protocol Tests
    const test_rfc8446_step = b.step("test-rfc8446", "Run RFC 8446 (TLS 1.3) test suite");

    const rfc8446_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rfc8446/mod.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        }),
    });

    const run_rfc8446_test = b.addRunArtifact(rfc8446_test);
    test_rfc8446_step.dependOn(&run_rfc8446_test.step);

    // Add RFC 8446 tests to main test suite
    test_step.dependOn(test_rfc8446_step);

    // RFC 9001: QUIC-TLS Tests
    const test_rfc9001_step = b.step("test-rfc9001", "Run RFC 9001 (QUIC-TLS) test suite");

    const rfc9001_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rfc9001/mod.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "record", .module = record_mod },
            },
        }),
    });

    const run_rfc9001_test = b.addRunArtifact(rfc9001_test);
    test_rfc9001_step.dependOn(&run_rfc9001_test.step);

    // Add RFC 9001 tests to main test suite
    test_step.dependOn(test_rfc9001_step);

    // RFC 5280: X.509 Certificate Tests
    const test_rfc5280_step = b.step("test-rfc5280", "Run RFC 5280 (X.509) test suite");

    const rfc5280_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rfc5280/mod.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "asn1", .module = asn1_mod },
                .{ .name = "sig", .module = sig_mod },
            },
        }),
    });

    const run_rfc5280_test = b.addRunArtifact(rfc5280_test);
    test_rfc5280_step.dependOn(&run_rfc5280_test.step);

    // Add RFC 5280 tests to main test suite (when tests are added)
    // test_step.dependOn(test_rfc5280_step);

    // ========================================================================
    // Extended Unit Tests - Comprehensive module-specific tests
    // ========================================================================

    const x509_unit_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/x509_unit_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "asn1", .module = asn1_mod },
                .{ .name = "sig", .module = sig_mod },
            },
        }),
    });
    const run_x509_unit_test = b.addRunArtifact(x509_unit_test);
    test_step.dependOn(&run_x509_unit_test.step);

    const sig_unit_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sig_unit_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "sig", .module = sig_mod },
                .{ .name = "asn1", .module = asn1_mod },
            },
        }),
    });
    const run_sig_unit_test = b.addRunArtifact(sig_unit_test);
    test_step.dependOn(&run_sig_unit_test.step);

    // OCSP unit tests
    const ocsp_unit_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/ocsp_unit_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ocsp", .module = ocsp_mod },
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "asn1", .module = asn1_mod },
            },
        }),
    });
    const run_ocsp_unit_test = b.addRunArtifact(ocsp_unit_test);
    test_step.dependOn(&run_ocsp_unit_test.step);

    // SCT unit tests
    const sct_unit_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sct_unit_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "sct", .module = sct_mod },
            },
        }),
    });
    const run_sct_unit_test = b.addRunArtifact(sct_unit_test);
    test_step.dependOn(&run_sct_unit_test.step);

    // ========================================================================
    // TLS 1.3 Handshake Integration Tests
    // ========================================================================

    const tls13_handshake_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/tls13_handshake_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "alert", .module = alert_mod },
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "sig", .module = sig_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
                .{ .name = "quic_transport_params", .module = transport_params_mod },
            },
        }),
    });
    const run_tls13_handshake_test = b.addRunArtifact(tls13_handshake_test);
    test_step.dependOn(&run_tls13_handshake_test.step);

    // ========================================================================
    // Conformance Tests - Interoperability with BoringSSL and OpenSSL
    // ========================================================================

    const conformance_step = b.step("test-conformance", "Run conformance tests against BoringSSL and OpenSSL (requires libssl-dev)");

    // BoringSSL conformance tests
    const boringssl_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/boringssl_conformance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "alert", .module = alert_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "varint", .module = varint_mod },
                .{ .name = "quic_transport_params", .module = transport_params_mod },
                .{ .name = "sct", .module = sct_mod },
                .{ .name = "ocsp", .module = ocsp_mod },
            },
        }),
    });
    boringssl_test.linkSystemLibrary("ssl");
    boringssl_test.linkSystemLibrary("crypto");
    boringssl_test.linkLibC();

    const run_boringssl_test = b.addRunArtifact(boringssl_test);
    conformance_step.dependOn(&run_boringssl_test.step);

    // OpenSSL conformance tests
    const openssl_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/openssl_conformance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "alert", .module = alert_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "varint", .module = varint_mod },
                .{ .name = "quic_transport_params", .module = transport_params_mod },
                .{ .name = "sct", .module = sct_mod },
                .{ .name = "ocsp", .module = ocsp_mod },
            },
        }),
    });
    openssl_test.linkSystemLibrary("ssl");
    openssl_test.linkSystemLibrary("crypto");
    openssl_test.linkLibC();

    const run_openssl_test = b.addRunArtifact(openssl_test);
    conformance_step.dependOn(&run_openssl_test.step);

    // X.509 OpenSSL conformance tests
    const x509_openssl_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/x509_openssl_conformance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "asn1", .module = asn1_mod },
                .{ .name = "sig", .module = sig_mod },
            },
        }),
    });
    x509_openssl_test.linkSystemLibrary("ssl");
    x509_openssl_test.linkSystemLibrary("crypto");
    x509_openssl_test.linkLibC();

    const run_x509_openssl_test = b.addRunArtifact(x509_openssl_test);
    conformance_step.dependOn(&run_x509_openssl_test.step);

    // OCSP OpenSSL conformance tests
    const ocsp_openssl_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/ocsp_openssl_conformance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ocsp", .module = ocsp_mod },
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "asn1", .module = asn1_mod },
            },
        }),
    });
    ocsp_openssl_test.linkSystemLibrary("ssl");
    ocsp_openssl_test.linkSystemLibrary("crypto");
    ocsp_openssl_test.linkLibC();

    const run_ocsp_openssl_test = b.addRunArtifact(ocsp_openssl_test);
    conformance_step.dependOn(&run_ocsp_openssl_test.step);

    // SCT OpenSSL conformance tests
    const sct_openssl_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sct_openssl_conformance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "sct", .module = sct_mod },
            },
        }),
    });
    sct_openssl_test.linkSystemLibrary("ssl");
    sct_openssl_test.linkSystemLibrary("crypto");
    sct_openssl_test.linkLibC();

    const run_sct_openssl_test = b.addRunArtifact(sct_openssl_test);
    conformance_step.dependOn(&run_sct_openssl_test.step);

    // TLS 1.3 Handshake conformance tests
    const handshake_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/handshake_conformance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "alert", .module = alert_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        }),
    });
    handshake_conformance_test.linkSystemLibrary("ssl");
    handshake_conformance_test.linkSystemLibrary("crypto");
    handshake_conformance_test.linkLibC();

    const run_handshake_conformance_test = b.addRunArtifact(handshake_conformance_test);
    conformance_step.dependOn(&run_handshake_conformance_test.step);

    // Note: conformance tests require OpenSSL/BoringSSL development libraries
    // They are not included in the default test step
}
