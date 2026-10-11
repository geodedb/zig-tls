// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const tls = @import("tls13");
const full = @import("tls13_full");
const x509 = @import("x509");
const cb = @import("crypto_backend");
const alloc = std.testing.allocator;
const cert = @embedFile("test_certs/ed25519_cert.der");
const key = @embedFile("test_certs/ed25519_key.der");
const Trust = struct {
    var spki: []const u8 = &.{};
    fn isTrusted(value: []const u8) bool {
        return std.mem.eql(u8, spki, value);
    }
};

fn config(role: tls.Role) tls.Config {
    return .{
        .allocator = alloc,
        .role = role,
        .supported_cipher_suites = &.{.TLS_AES_128_GCM_SHA256},
        .supported_signature_schemes = &.{.ed25519},
        .server_cert_der = if (role == .Server) cert else null,
        .server_key_der = if (role == .Server) key else null,
        .server_name = if (role == .Client) "ed25519.example.com" else null,
        .transport_mode = .tls,
    };
}

fn relay(from: *tls.Context, to: *tls.Context, level: tls.EncryptionLevel) !bool {
    const bytes = from.pollCrypto(alloc, level) catch |err| {
        if (err == error.NothingToRead) return false;
        return err;
    };
    defer alloc.free(bytes);
    try to.processCrypto(level, bytes);
    return true;
}

test "SONNY-4794 hybrid peers complete authenticated TLS and agree on traffic secrets" {
    if (comptime !cb.fips_enabled) return error.SkipZigTest;
    var anchor = try x509.parseCert(alloc, cert);
    defer anchor.deinit(alloc);
    Trust.spki = anchor.spki;
    x509.setTrustStore(.{ .isTrustedSpki = Trust.isTrusted });
    defer x509.setTrustStore(null);
    var client = try tls.Context.init(config(.Client), .{});
    defer client.deinit();
    var server = try tls.Context.init(config(.Server), .{});
    defer server.deinit();
    try client.startClientHandshake();
    const hello = try client.pollCrypto(alloc, .Initial);
    defer alloc.free(hello);
    try std.testing.expect(hello.len > 1216);
    try server.processCrypto(.Initial, hello);
    const view = server.clientHello().?;
    try std.testing.expectEqual(full.NamedGroup.x25519_mlkem768, view.key_share.group);
    try std.testing.expectEqual(@as(usize, 1216), view.key_share.key.len);
    for (0..12) |_| {
        var progressed = false;
        for ([_]tls.EncryptionLevel{ .Initial, .Handshake, .Application }) |level| {
            if (try relay(&client, &server, level)) progressed = true;
            if (try relay(&server, &client, level)) progressed = true;
        }
        if (!progressed) break;
    }
    try std.testing.expect(client.handshakeComplete());
    try std.testing.expect(server.handshakeComplete());
    for ([_]tls.EncryptionLevel{ .Handshake, .Application }) |level| {
        const client_send = client.secrets.slot(level, .send);
        const server_recv = server.secrets.slot(level, .recv);
        const server_send = server.secrets.slot(level, .send);
        const client_recv = client.secrets.slot(level, .recv);
        try std.testing.expect(client_send.valid and server_recv.valid and server_send.valid and client_recv.valid);
        try std.testing.expectEqualSlices(u8, client_send.value.slice(), server_recv.value.slice());
        try std.testing.expectEqualSlices(u8, server_send.value.slice(), client_recv.value.slice());
    }
}

fn frame(body: []const u8, typ: u8) ![]u8 {
    const msg = try alloc.alloc(u8, body.len + 4);
    msg[0] = typ;
    std.mem.writeInt(u24, msg[1..4], @intCast(body.len), .big);
    @memcpy(msg[4..], body);
    return msg;
}

fn extensionLengthOffset(msg: []const u8) usize {
    var pos: usize = 4 + 34;
    pos += 1 + @as(usize, msg[pos]);
    if (msg[0] == 1) {
        pos += 2 + @as(usize, std.mem.readInt(u16, msg[pos..][0..2], .big));
        pos += 1 + @as(usize, msg[pos]);
    } else pos += 3;
    return pos;
}

fn extensionData(msg: []const u8, tag: u16) ![]const u8 {
    var pos = extensionLengthOffset(msg) + 2;
    while (pos < msg.len) {
        const kind = std.mem.readInt(u16, msg[pos..][0..2], .big);
        const len = std.mem.readInt(u16, msg[pos + 2 ..][0..2], .big);
        if (kind == tag) return msg[pos + 4 ..][0..len];
        pos += 4 + len;
    }
    return error.ExtensionNotFound;
}

fn replaceExtension(msg: []const u8, tag: u16, replacement: ?[]const u8) ![]u8 {
    const length_offset = extensionLengthOffset(msg);
    var pos = length_offset + 2;
    while (pos < msg.len) {
        const kind = std.mem.readInt(u16, msg[pos..][0..2], .big);
        const len = std.mem.readInt(u16, msg[pos + 2 ..][0..2], .big);
        if (kind == tag) {
            const new_len = if (replacement) |v| 4 + v.len else 0;
            const out = try alloc.alloc(u8, msg.len - (4 + len) + new_len);
            @memcpy(out[0..pos], msg[0..pos]);
            if (replacement) |v| {
                std.mem.writeInt(u16, out[pos..][0..2], tag, .big);
                std.mem.writeInt(u16, out[pos + 2 ..][0..2], @intCast(v.len), .big);
                @memcpy(out[pos + 4 ..][0..v.len], v);
            }
            @memcpy(out[pos + new_len ..], msg[pos + 4 + len ..]);
            std.mem.writeInt(u16, out[length_offset..][0..2], @intCast(out.len - length_offset - 2), .big);
            std.mem.writeInt(u24, out[1..4], @intCast(out.len - 4), .big);
            return out;
        }
        pos += 4 + len;
    }
    return error.ExtensionNotFound;
}

fn assertNoKeys(ctx: *tls.Context) !void {
    for ([_]tls.EncryptionLevel{ .Handshake, .Application }) |level| {
        for ([_]tls.TrafficDirection{ .send, .recv }) |direction| {
            const slot = ctx.secrets.slot(level, direction);
            try std.testing.expect(!slot.valid);
            try std.testing.expectEqual(@as(usize, 0), slot.value.slice().len);
        }
    }
    if (comptime cb.fips_enabled) try std.testing.expect(ctx.client_kem == null);
    try std.testing.expect(ctx.handshake_secret == null);
}

fn makeClientHello(share: []const u8, groups: []const full.NamedGroup) ![]u8 {
    const result = try full.buildClientHello(alloc, .{
        .random = .{0x42} ** 32,
        .key_share_bytes = share,
        .key_share_group = .x25519_mlkem768,
        .supported_groups = groups,
        .cipher_suites = &.{.TLS_AES_128_GCM_SHA256},
        .signature_algorithms = &.{.ed25519},
        .prepend_handshake_header = true,
    });
    return result.body;
}

test "SONNY-4794 server rejects malformed hybrid keys and unadvertised groups before installing secrets" {
    if (comptime !cb.fips_enabled) return error.SkipZigTest;
    cb.assertActive();
    var pair = try cb.Kem.generate(.x25519_ml_kem_768);
    defer pair.deinit();
    var original: [1216]u8 = undefined;
    _ = try cb.Kem.exportPublic(.x25519_ml_kem_768, &pair, &original);
    for (0..5) |case| {
        var bytes: [1217]u8 = undefined;
        @memcpy(bytes[0..1216], &original);
        bytes[1216] = 0;
        var len: usize = 1216;
        switch (case) {
            0 => len = 1215,
            1 => len = 1217,
            2 => {
                bytes[0] = 0xff;
                bytes[1] |= 0x0f;
            }, // noncanonical ML-KEM coefficient
            3 => @memset(bytes[1184..1216], 0), // low-order X25519 share
            else => {},
        }
        const groups: []const full.NamedGroup = if (case == 4) &.{.x25519} else &.{.x25519_mlkem768};
        const msg = try makeClientHello(bytes[0..len], groups);
        defer alloc.free(msg);
        var server = try tls.Context.init(config(.Server), .{});
        defer server.deinit();
        try std.testing.expectError(error.UnsupportedKeyShareGroup, server.processCrypto(.Initial, msg));
        try assertNoKeys(&server);
        try std.testing.expectEqual(tls.HandshakePhase.terminated, server.phase);
    }
}

test "SONNY-4794 hybrid selection is independent of key-share ordering and validates the full vector" {
    if (comptime !cb.fips_enabled) return error.SkipZigTest;
    var client = try tls.Context.init(config(.Client), .{});
    defer client.deinit();
    try client.startClientHandshake();
    const hello = try client.pollCrypto(alloc, .Initial);
    defer alloc.free(hello);
    const hybrid = try extensionData(hello, 0x33);
    const classical = [_]u8{ 0x00, 0x1d, 0x00, 0x20 } ++ [_]u8{9} ** 32;
    for ([_]bool{ true, false }) |hybrid_first| {
        var entries = try alloc.alloc(u8, hybrid.len + classical.len);
        defer alloc.free(entries);
        std.mem.writeInt(u16, entries[0..2], @intCast(entries.len - 2), .big);
        if (hybrid_first) {
            @memcpy(entries[2..][0 .. hybrid.len - 2], hybrid[2..]);
            @memcpy(entries[hybrid.len..], &classical);
        } else {
            @memcpy(entries[2..][0..classical.len], &classical);
            @memcpy(entries[2 + classical.len ..], hybrid[2..]);
        }
        const msg = try replaceExtension(hello, 0x33, entries);
        defer alloc.free(msg);
        var server = try tls.Context.init(config(.Server), .{});
        defer server.deinit();
        try server.processCrypto(.Initial, msg);
        try std.testing.expectEqual(full.NamedGroup.x25519_mlkem768, server.clientHello().?.key_share.group);
        try std.testing.expect(server.secrets.slot(.Handshake, .send).valid);
    }
    const duplicate = try alloc.alloc(u8, 2 + 2 * (hybrid.len - 2));
    defer alloc.free(duplicate);
    std.mem.writeInt(u16, duplicate[0..2], @intCast(duplicate.len - 2), .big);
    @memcpy(duplicate[2..][0 .. hybrid.len - 2], hybrid[2..]);
    @memcpy(duplicate[hybrid.len..], hybrid[2..]);
    const bad = try replaceExtension(hello, 0x33, duplicate);
    defer alloc.free(bad);
    var server = try tls.Context.init(config(.Server), .{});
    defer server.deinit();
    try std.testing.expectError(error.UnsupportedKeyShareGroup, server.processCrypto(.Initial, bad));
    try assertNoKeys(&server);
}

test "SONNY-4794 client rejects malformed ciphertext trailing bytes and classical downgrade" {
    if (comptime !cb.fips_enabled) return error.SkipZigTest;
    for (0..5) |case| {
        var client = try tls.Context.init(config(.Client), .{});
        defer client.deinit();
        var server = try tls.Context.init(config(.Server), .{});
        defer server.deinit();
        try client.startClientHandshake();
        _ = try relay(&client, &server, .Initial);
        const sh = try server.pollCrypto(alloc, .Initial);
        defer alloc.free(sh);
        const good = try extensionData(sh, 0x33);
        const share = try alloc.alloc(u8, good.len + 1);
        defer alloc.free(share);
        @memcpy(share[0..good.len], good);
        share[good.len] = 0;
        var len = good.len;
        switch (case) {
            0 => {
                len -= 1;
                std.mem.writeInt(u16, share[2..4], 1119, .big);
            },
            1 => {
                len += 1;
                std.mem.writeInt(u16, share[2..4], 1121, .big);
            },
            2 => len += 1, // Correct inner length with extra extension bytes.
            3 => {
                len = 36;
                std.mem.writeInt(u16, share[0..2], 0x001d, .big);
                std.mem.writeInt(u16, share[2..4], 32, .big);
            },
            else => @memset(share[4 + 1088 .. 4 + 1120], 0),
        }
        const msg = try replaceExtension(sh, 0x33, share[0..len]);
        defer alloc.free(msg);
        const expected = if (case == 4) error.CryptoError else error.UnsupportedKeyShareGroup;
        try std.testing.expectError(expected, client.processCrypto(.Initial, msg));
        try assertNoKeys(&client);
        try std.testing.expectError(error.UnexpectedMessage, client.processCrypto(.Initial, sh));
    }
}

test "SONNY-4794 policy rejection is repeatable and generated keys are freed on errors and alerts" {
    if (comptime !cb.fips_enabled) return error.SkipZigTest;
    var cfg = config(.Client);
    cfg.supported_groups = &.{.x25519};
    var rejected = try tls.Context.init(cfg, .{});
    defer rejected.deinit();
    for (0..2) |_| try std.testing.expectError(error.UnsupportedKeyShareGroup, rejected.startClientHandshake());
    try std.testing.expectEqual(tls.HandshakePhase.initial, rejected.phase);
    try assertNoKeys(&rejected);

    for (0..3) |case| {
        var client = try tls.Context.init(config(.Client), .{});
        defer client.deinit();
        try client.startClientHandshake();
        const retained = client.client_kem.?.pkey;
        try client.startClientHandshake();
        try std.testing.expect(client.client_kem.?.pkey == retained);
        switch (case) {
            0 => try client.sendHandshakeFailure(),
            1 => try std.testing.expectError(error.PeerFatalAlert, client.deliverAlert(.Initial, &.{ 2, 40 })),
            else => try client.sendCloseNotify(),
        }
        try std.testing.expect(client.client_kem == null);
        try std.testing.expectError(error.UnexpectedMessage, client.startClientHandshake());
    }
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    cfg = config(.Client);
    cfg.allocator = failing.allocator();
    var client = try tls.Context.init(cfg, .{});
    defer client.deinit();
    try std.testing.expectError(error.OutOfMemory, client.startClientHandshake());
    try assertNoKeys(&client);
}

test "SONNY-4794 cookie-only HRR preserves the original share and rejects repeated group selection" {
    if (comptime !cb.fips_enabled) return error.SkipZigTest;
    for ([_]bool{ false, true }) |include_group| {
        var client = try tls.Context.init(config(.Client), .{});
        defer client.deinit();
        try client.startClientHandshake();
        const ch1 = try client.pollCrypto(alloc, .Initial);
        defer alloc.free(ch1);
        const retained = client.client_kem.?.pkey;
        const body = try full.buildHelloRetryRequest(alloc, .x25519_mlkem768, "opaque-cookie", null);
        defer alloc.free(body);
        const framed = try frame(body, 2);
        defer alloc.free(framed);
        const cookie_only = try replaceExtension(framed, 0x33, null);
        defer alloc.free(cookie_only);
        if (include_group) {
            try std.testing.expectError(error.HrrNoChange, client.processCrypto(.Initial, framed));
            try assertNoKeys(&client);
        } else {
            try client.processCrypto(.Initial, cookie_only);
            const ch2 = try client.pollCrypto(alloc, .Initial);
            defer alloc.free(ch2);
            try std.testing.expectEqualSlices(u8, try extensionData(ch1, 0x33), try extensionData(ch2, 0x33));
            try std.testing.expectEqualSlices(u8, ch1[6..38], ch2[6..38]);
            try std.testing.expectEqualSlices(u8, "opaque-cookie", (try extensionData(ch2, 0x2c))[2..]);
            try std.testing.expect(client.client_kem.?.pkey == retained);
            try std.testing.expectError(error.UnexpectedMessage, client.processCrypto(.Initial, cookie_only));
            try assertNoKeys(&client);
        }
    }
}

fn finishPair(client: *tls.Context, server: *tls.Context) !void {
    for (0..12) |_| {
        var progress = false;
        for ([_]tls.EncryptionLevel{ .Initial, .Handshake, .Application }) |level| {
            if (try relay(client, server, level)) progress = true;
            if (try relay(server, client, level)) progress = true;
        }
        if (!progress) break;
    }
    try std.testing.expect(client.handshakeComplete() and server.handshakeComplete());
    for ([_]tls.EncryptionLevel{ .Handshake, .Application }) |level| {
        try std.testing.expectEqualSlices(u8, client.secrets.slot(level, .send).slice(), server.secrets.slot(level, .recv).slice());
        try std.testing.expectEqualSlices(u8, client.secrets.slot(level, .recv).slice(), server.secrets.slot(level, .send).slice());
    }
    if (comptime cb.fips_enabled) try std.testing.expect(client.client_kem == null);
}

test "SONNY-4794 hybrid PSK and certificate handshakes agree for SHA256 SHA384 and cookie retries" {
    if (comptime !cb.fips_enabled) return error.SkipZigTest;
    var anchor = try x509.parseCert(alloc, cert);
    defer anchor.deinit(alloc);
    Trust.spki = anchor.spki;
    x509.setTrustStore(.{ .isTrustedSpki = Trust.isTrusted });
    defer x509.setTrustStore(null);
    const psk = [_]u8{0x6a} ** 32;
    const cookie_secret = [_]u8{0x7b} ** 32;
    for ([_]full.CipherSuite{ .TLS_AES_128_GCM_SHA256, .TLS_AES_256_GCM_SHA384 }) |suite| {
        for ([_]bool{ false, true }) |use_psk| {
            for ([_]bool{ false, true }) |retry| {
                var client_cfg = config(.Client);
                var server_cfg = config(.Server);
                const suites = [_]full.CipherSuite{suite};
                client_cfg.supported_cipher_suites = &suites;
                server_cfg.supported_cipher_suites = &suites;
                server_cfg.server_secret = &cookie_secret;
                if (use_psk) {
                    client_cfg.external_psk = &psk;
                    client_cfg.external_psk_identity = "hybrid-psk";
                    server_cfg.external_psk = &psk;
                    server_cfg.external_psk_identity = "hybrid-psk";
                    server_cfg.server_cert_der = null;
                    server_cfg.server_key_der = null;
                }
                var client = try tls.Context.init(client_cfg, .{});
                defer client.deinit();
                var server = try tls.Context.init(server_cfg, .{});
                defer server.deinit();
                try client.startClientHandshake();
                if (retry) {
                    // Independent cookie-only HRR fixture. The server's automatic
                    // HRR trigger requests a missing key share; this fixture emits
                    // a legal address-validation retry instead, then both peers
                    // run their production CH2, binder, certificate and Finished paths.
                    const ch1 = try client.pollCrypto(alloc, .Initial);
                    defer alloc.free(ch1);
                    server.hash_kind = if (suite == .TLS_AES_256_GCM_SHA384) .sha384 else .sha256;
                    server.transcripts.handshake.update(ch1);
                    const hash = server.transcripts.handshake.finalize(server.hash_kind);
                    const cookie = try tls.cookie_mod.generateCookie(alloc, &cookie_secret, ch1[6..38].*, hash.slice());
                    defer alloc.free(cookie);
                    const body = try full.buildHelloRetryRequest(alloc, .x25519_mlkem768, cookie, null);
                    defer alloc.free(body);
                    std.mem.writeInt(u16, body[35..37], @intFromEnum(suite), .big);
                    const original = try frame(body, 2);
                    defer alloc.free(original);
                    const hrr = try replaceExtension(original, 0x33, null);
                    defer alloc.free(hrr);
                    server.transcripts.handshake.handleHelloRetryRequest(ch1, server.hash_kind);
                    server.transcripts.handshake.update(hrr);
                    server.ch1_transcript_hash = hash;
                    server.hrr_sent = true;
                    server.hrr_cipher_suite = suite;
                    server.hrr_message = try alloc.dupe(u8, hrr);
                    try server.streams.buffers[0].outbound.appendSlice(alloc, hrr);
                    _ = try relay(&server, &client, .Initial);
                }
                finishPair(&client, &server) catch |err| {
                    std.debug.print("hybrid matrix suite={s} psk={} retry={}: {s}\n", .{ @tagName(suite), use_psk, retry, @errorName(err) });
                    return err;
                };
            }
        }
    }
}

test "SONNY-4794 failed secret installation clears all hybrid handshake material" {
    if (comptime !cb.fips_enabled) return error.SkipZigTest;
    const Fail = struct {
        fn secret(_: *tls.Context, _: tls.EncryptionLevel, _: []const u8) anyerror!void {
            return error.TestCallbackFailed;
        }
    };
    var client = try tls.Context.init(config(.Client), .{ .on_secret_available = Fail.secret });
    defer client.deinit();
    var server = try tls.Context.init(config(.Server), .{});
    defer server.deinit();
    try client.startClientHandshake();
    _ = try relay(&client, &server, .Initial);
    try std.testing.expectError(error.TestCallbackFailed, relay(&server, &client, .Initial));
    try assertNoKeys(&client);
}

test "SONNY-4794 server requests a missing hybrid share and authenticates the retry Finished" {
    if (comptime !cb.fips_enabled) return error.SkipZigTest;
    for ([_]full.CipherSuite{ .TLS_AES_128_GCM_SHA256, .TLS_AES_256_GCM_SHA384 }) |suite| {
        const suites = [_]full.CipherSuite{suite};
        var cfg = config(.Server);
        cfg.supported_cipher_suites = &suites;
        var server = try tls.Context.init(cfg, .{});
        defer server.deinit();
        const hash = if (suite == .TLS_AES_256_GCM_SHA384) tls.Hash.sha384 else tls.Hash.sha256;
        const groups = [_]full.NamedGroup{ .secp256r1, .x25519_mlkem768 };
        const ch1 = try full.buildClientHello(alloc, .{
            .random = .{0x35} ** 32,
            .key_share_group = .secp256r1,
            .key_share_bytes = &([_]u8{4} ** 65),
            .supported_groups = &groups,
            .cipher_suites = &suites,
            .signature_algorithms = &.{.ed25519},
            .prepend_handshake_header = true,
        });
        defer alloc.free(ch1.body);
        try server.processCrypto(.Initial, ch1.body);
        const hrr = try server.pollCrypto(alloc, .Initial);
        defer alloc.free(hrr);
        try std.testing.expectEqual(@intFromEnum(suite), std.mem.readInt(u16, hrr[39..41], .big));
        try std.testing.expectEqual(@as(u16, 0x11ec), std.mem.readInt(u16, (try extensionData(hrr, 0x33))[0..2], .big));
        try std.testing.expectEqualSlices(u8, hrr, server.hrr_message.?);
        const cookie = (try extensionData(hrr, 0x2c))[2..];
        var kp = try cb.Kem.generate(.x25519_ml_kem_768);
        defer kp.deinit();
        var public: [1216]u8 = undefined;
        _ = try cb.Kem.exportPublic(.x25519_ml_kem_768, &kp, &public);
        const ch2 = try full.buildClientHello(alloc, .{
            .random = .{0x35} ** 32,
            .key_share_group = .x25519_mlkem768,
            .key_share_bytes = &public,
            .supported_groups = &groups,
            .cipher_suites = &suites,
            .signature_algorithms = &.{.ed25519},
            .cookie = cookie,
            .prepend_handshake_header = true,
        });
        defer alloc.free(ch2.body);
        try server.processCrypto(.Initial, ch2.body);
        const sh = try server.pollCrypto(alloc, .Initial);
        defer alloc.free(sh);
        var shared: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &shared);
        _ = try cb.Kem.decapsulate(.x25519_ml_kem_768, &kp, (try extensionData(sh, 0x33))[4..], &shared);
        // Independent peer transcript and key schedule, including synthetic CH1 hash.
        var transcript = tls.Transcript.init();
        defer transcript.deinit();
        transcript.update(ch1.body);
        const ch1_hash = transcript.finalize(hash);
        transcript.reset();
        transcript.update(&.{ 0xfe, 0, 0, @intCast(ch1_hash.len) });
        transcript.update(ch1_hash.slice());
        transcript.update(hrr);
        transcript.update(ch2.body);
        transcript.update(sh);
        const early = tls.deriveEarlySecret(hash, null);
        const secrets = tls.deriveHandshakeTraffic(hash, &shared, transcript.finalize(hash), &early);
        try std.testing.expectEqualSlices(u8, secrets.client_hs.slice(), server.secrets.slot(.Handshake, .recv).slice());
        const flight = try server.pollCrypto(alloc, .Handshake);
        defer alloc.free(flight);
        transcript.update(flight);
        const verify = tls.deriveFinishedVerifyData(hash, &secrets.client_hs, transcript.finalize(hash));
        const finished = try frame(verify.slice(), 20);
        defer alloc.free(finished);
        try server.processCrypto(.Handshake, finished);
        try std.testing.expect(server.handshakeComplete());
    }
}

test "SONNY-4794 modified ML-KEM ciphertext cannot authenticate Finished or retain traffic keys" {
    if (comptime !cb.fips_enabled) return error.SkipZigTest;
    const psk = [_]u8{0x4e} ** 32;
    var client_cfg = config(.Client);
    var server_cfg = config(.Server);
    client_cfg.external_psk = &psk;
    client_cfg.external_psk_identity = "implicit-rejection-test";
    server_cfg.external_psk = &psk;
    server_cfg.external_psk_identity = "implicit-rejection-test";
    server_cfg.server_cert_der = null;
    server_cfg.server_key_der = null;
    var client = try tls.Context.init(client_cfg, .{});
    defer client.deinit();
    var server = try tls.Context.init(server_cfg, .{});
    defer server.deinit();
    try client.startClientHandshake();
    _ = try relay(&client, &server, .Initial);
    const sh = try server.pollCrypto(alloc, .Initial);
    defer alloc.free(sh);
    const share = try alloc.dupe(u8, try extensionData(sh, 0x33));
    defer alloc.free(share);
    share[4] ^= 1; // ML-KEM implicit rejection produces a different secret.
    const changed = try replaceExtension(sh, 0x33, share);
    defer alloc.free(changed);
    try client.processCrypto(.Initial, changed);
    try std.testing.expect(!std.mem.eql(u8, client.secrets.slot(.Handshake, .send).slice(), server.secrets.slot(.Handshake, .recv).slice()));
    try std.testing.expectError(error.FinishedVerifyFailed, relay(&server, &client, .Handshake));
    try assertNoKeys(&client);
    try std.testing.expect(!client.handshakeComplete());
}
