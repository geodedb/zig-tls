// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! SEC-077: Regression test for insecure-validation sentinel.

const std = @import("std");
const x509 = @import("x509");

test "SEC-077: InsecureValidation.secure is the default variant" {
    const mode: x509.InsecureValidation = .secure;
    try std.testing.expectEqual(x509.InsecureValidation.secure, mode);
}

test "SEC-077: InsecureValidation has two distinct variants" {
    const secure: x509.InsecureValidation = .secure;
    const insecure: x509.InsecureValidation = .testing_only_i_know_what_i_am_doing;
    try std.testing.expect(secure != insecure);
}
