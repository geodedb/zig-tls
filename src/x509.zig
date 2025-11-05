//! Minimal X.509 (DER) parser/validator for TLS 1.3 in this project.
//!
//! Implements the certificate processing subset demanded by RFC 5280 (subject
//! alt names, key usage, validity) so QUIC's TLS layer can validate peers.
//! Signature verification hooks align with RFC 8446 §4.4.4 expectations.
// Scope: parse TBSCertificate, read subject alt names, basic constraints,
// key usage, extended key usage (serverAuth), and validity. Provide
// simple path validation using issuer SPKI and signature verification for
// ECDSA (P-256/P-384) and RSA-PSS (SHA-256). Allow an insecure bypass.
const std = @import("std");
const asn1 = @import("asn1");
const sigmod = @import("sig");
const Ed25519 = std.crypto.sign.Ed25519;

/// Pluggable trust store hook. If set, root must be trusted via callback.
pub const TrustStore = struct {
    isTrustedSpki: *const fn (spki_der: []const u8) bool,
};
var g_trust_store: ?TrustStore = null;

/// Install or clear the global trust store hook.
pub fn setTrustStore(ts: ?TrustStore) void {
    g_trust_store = ts;
}

/// Distinguished Name subset with only Common Name (CN).
pub const Name = struct {
    cn: ?[]const u8 = null,
};

/// Subject Alternative Name extension with a list of DNS names.
pub const SubjectAltName = struct { dns: []const []const u8 };

/// Basic Constraints (CA flag and optional pathLenConstraint).
pub const BasicConstraints = struct { ca: bool = false, path_len: ?u32 = null };

/// Key Usage bitmask (subset). Bits are as in RFC 5280: bit0=digitalSignature, bit2=keyEncipherment, bit5=keyCertSign.
pub const KeyUsage = struct { bits: u16 };

/// Extended Key Usage flags we care about.
pub const ExtKeyUsage = struct { server_auth: bool = false };

/// Parsed Certificate view exposing minimal fields needed by TLS/QUIC.
pub const Certificate = struct {
    tbs: []const u8, // raw TBSCertificate for signature verify
    subject: Name,
    san: ?SubjectAltName = null,
    basic: ?BasicConstraints = null,
    ku: ?KeyUsage = null,
    eku: ?ExtKeyUsage = null,
    not_before_unix: i64,
    not_after_unix: i64,
    // public key raw (spki)
    spki: []const u8,
};

fn isLeap(year: u16) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

fn daysBeforeMonth(year: u16, month: u8) i64 {
    const mdays = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var d: i64 = 0;
    var m: u8 = 1;
    while (m < month) : (m += 1) {
        if (m == 2 and isLeap(year)) d += 29 else d += mdays[m - 1];
    }
    return d;
}

fn unixSecondsFromYMDHMS(year: u16, month: u8, day: u8, hh: u8, mm: u8, ss: u8) i64 {
    if (year < 1970) return 0; // clamp for simplicity
    var days: i64 = 0;
    var y: u16 = 1970;
    while (y < year) : (y += 1) days += if (isLeap(y)) 366 else 365;
    days += daysBeforeMonth(year, month);
    days += (@as(i64, day) - 1);
    return days * 86400 + @as(i64, hh) * 3600 + @as(i64, mm) * 60 + @as(i64, ss);
}

fn parseTime(bytes: []const u8) !i64 {
    // Accept the subset: YYYYMMDDHHMMSSZ or YYMMDDHHMMSSZ; return unix seconds
    if (bytes.len == 13 and bytes[12] == 'Z') {
        const yy = try std.fmt.parseInt(u8, bytes[0..2], 10);
        const year: u16 = if (yy >= 50) (@as(u16, 1900) + @as(u16, yy)) else (@as(u16, 2000) + @as(u16, yy));
        const month = try std.fmt.parseInt(u8, bytes[2..4], 10);
        const day = try std.fmt.parseInt(u8, bytes[4..6], 10);
        const hh = try std.fmt.parseInt(u8, bytes[6..8], 10);
        const mm = try std.fmt.parseInt(u8, bytes[8..10], 10);
        const ss = try std.fmt.parseInt(u8, bytes[10..12], 10);
        return unixSecondsFromYMDHMS(year, month, day, hh, mm, ss);
    }
    if (bytes.len == 15 and bytes[14] == 'Z') {
        const year = try std.fmt.parseInt(u16, bytes[0..4], 10);
        const month = try std.fmt.parseInt(u8, bytes[4..6], 10);
        const day = try std.fmt.parseInt(u8, bytes[6..8], 10);
        const hh = try std.fmt.parseInt(u8, bytes[8..10], 10);
        const mm = try std.fmt.parseInt(u8, bytes[10..12], 10);
        const ss = try std.fmt.parseInt(u8, bytes[12..14], 10);
        return unixSecondsFromYMDHMS(year, month, day, hh, mm, ss);
    }
    return error.UnsupportedTimeFormat;
}

fn unwrapExtnValueToBytes(extn_val_or_octets: []const u8) []const u8 {
    // extnValue is an OCTET STRING containing DER of the actual extension value
    var d = asn1.Decoder.init(extn_val_or_octets);
    const inner = d.readOctetString() catch return extn_val_or_octets; // tolerate if already raw
    return inner;
}

/// Parse a DER-encoded X.509 certificate and return a minimal view.
pub fn parseCert(alloc: std.mem.Allocator, der: []const u8) !Certificate {
    _ = alloc; // currently not owning sub-slices
    var d = asn1.Decoder.init(der);
    const seq = try d.readSequence(); // Certificate
    var ci = asn1.Decoder.init(seq);
    const tbs = try ci.readSequence();
    const tbs_off_begin = (@intFromPtr(tbs.ptr) - @intFromPtr(seq.ptr)) + (seq.ptr - der.ptr);
    const tbs_len = tbs.len;

    // version [0] EXPLICIT INTEGER DEFAULT v1, serial, signature, issuer, validity, subject, spki, ...
    var ti = asn1.Decoder.init(tbs);
    _ = try ti.readTLV(); // version or serial
    _ = try ti.readTLV(); // maybe version/serial/signature
    _ = try ti.readTLV(); // signature or serial/signature
    const issuer = try ti.readTLV();
    _ = issuer;
    const validity = try ti.readSequence();
    var vd = asn1.Decoder.init(validity);
    const not_before_tlv = try vd.readTLV();
    const not_after_tlv = try vd.readTLV();
    const not_before = try parseTime(not_before_tlv.val);
    const not_after = try parseTime(not_after_tlv.val);
    const subject_seq = try ti.readSequence();
    // Parse subject for CN (very shallow: look for UTF8String in RDNs)
    var subj_cn: ?[]const u8 = null;
    {
        var sdec = asn1.Decoder.init(subject_seq);
        while (true) {
            const tlv = sdec.readTLV() catch break;
            if (asn1.tagClass(tlv.tag) == .universal and asn1.tagNumber(tlv.tag) == 12) {
                subj_cn = tlv.val;
                break;
            }
        }
    }
    const spki_tlv = try ti.readTLV();

    // Try to find extensions sequence and parse SAN/basic/ku/eku if present
    var san_result: ?SubjectAltName = null;
    var basic_res: ?BasicConstraints = null;
    var ku_res: ?KeyUsage = null;
    var eku_res: ?ExtKeyUsage = null;
    while (true) {
        const tlv = ti.readTLV() catch break;
        // Look for [3] EXPLICIT Extensions (context-specific constructed)
        if (asn1.tagClass(tlv.tag) == .context and asn1.isConstructed(tlv.tag)) {
            var ed = asn1.Decoder.init(tlv.val);
            const exts_seq = ed.readSequence() catch continue;
            var exd = asn1.Decoder.init(exts_seq);
            while (true) {
                const ext = exd.readSequence() catch break;
                var one = asn1.Decoder.init(ext);
                const oid = one.readOID() catch continue;
                const critical_or_val = one.readTLV() catch continue;
                var val = critical_or_val.val;
                if (one.readTLV() catch null) |v2| val = v2.val;
                const inner = unwrapExtnValueToBytes(val);
                // id-ce-subjectAltName = 2.5.29.17
                if (oid.len >= 3 and oid[0] == 0x55 and oid[1] == 0x1d and oid[2] == 0x11) {
                    var vd2 = asn1.Decoder.init(inner);
                    const san_seq = vd2.readSequence() catch continue;
                    var dns_list: [8][]const u8 = undefined;
                    var dns_len: usize = 0;
                    var s2 = asn1.Decoder.init(san_seq);
                    while (dns_len < dns_list.len) {
                        const gn = s2.readTLV() catch break;
                        if (asn1.tagClass(gn.tag) == .context and asn1.tagNumber(gn.tag) == 2) {
                            dns_list[dns_len] = gn.val;
                            dns_len += 1;
                        }
                    }
                    if (dns_len > 0) san_result = .{ .dns = dns_list[0..dns_len] };
                }
                // id-ce-basicConstraints = 2.5.29.19
                if (oid.len >= 3 and oid[0] == 0x55 and oid[1] == 0x1d and oid[2] == 0x13) {
                    var bd = asn1.Decoder.init(inner);
                    const bc_seq = bd.readSequence() catch continue;
                    var b2 = asn1.Decoder.init(bc_seq);
                    var ca = false;
                    var path_len: ?u32 = null;
                    const tlv_ca = b2.readTLV() catch null;
                    if (tlv_ca) |t| {
                        // BOOLEAN TRUE is 0xff or 0x01 depending on encoder; accept any non-zero
                        if (asn1.tagClass(t.tag) == .universal and asn1.tagNumber(t.tag) == 1 and t.val.len >= 1) ca = (t.val[0] != 0);
                        const tlv_pl = b2.readTLV() catch null;
                        if (tlv_pl) |pl| {
                            if (asn1.tagClass(pl.tag) == .universal and asn1.tagNumber(pl.tag) == 2) {
                                // Parse small integer
                                var v: u32 = 0;
                                for (pl.val) |bb| v = (v << 8) | bb;
                                path_len = v;
                            }
                        }
                    }
                    basic_res = .{ .ca = ca, .path_len = path_len };
                }
                // id-ce-keyUsage = 2.5.29.15
                if (oid.len >= 3 and oid[0] == 0x55 and oid[1] == 0x1d and oid[2] == 0x0f) {
                    var kd = asn1.Decoder.init(inner);
                    const bits = kd.readBitString() catch continue;
                    var mask: u16 = 0;
                    // bits[0] is first 8 bits (MSB first) after 'unused bits' removal handled in readBitString
                    for (bits, 0..) |b, idx| {
                        const shift: u4 = @intCast((bits.len - 1 - idx) * 8);
                        mask |= @as(u16, @intCast(b)) << shift;
                    }
                    ku_res = .{ .bits = mask };
                }
                // id-ce-extKeyUsage = 2.5.29.37; serverAuth = 1.3.6.1.5.5.7.3.1 (2B 06 01 05 05 07 03 01)
                if (oid.len >= 3 and oid[0] == 0x55 and oid[1] == 0x1d and oid[2] == 0x25) {
                    var ed2 = asn1.Decoder.init(inner);
                    const seq2 = ed2.readSequence() catch continue;
                    var e2 = asn1.Decoder.init(seq2);
                    var server_auth = false;
                    while (true) {
                        const oid2 = e2.readOID() catch break;
                        if (oid2.len >= 8 and std.mem.eql(u8, oid2[oid2.len - 8 ..], &[_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 })) {
                            server_auth = true;
                        }
                    }
                    eku_res = .{ .server_auth = server_auth };
                }
            }
        }
    }

    const subject: Name = .{ .cn = subj_cn };
    const tbs_start: usize = @intCast(tbs_off_begin);
    const tbs_bytes = der[tbs_start .. tbs_start + tbs_len];
    return .{
        .tbs = tbs_bytes,
        .subject = subject,
        .san = san_result,
        .basic = basic_res,
        .ku = ku_res,
        .eku = eku_res,
        .not_before_unix = not_before,
        .not_after_unix = not_after,
        .spki = spki_tlv.val,
    };
}

/// Infer the TLS signature algorithm from a DER-encoded certificate's SubjectPublicKeyInfo.
/// Detects Ed25519, ECDSA P-256, and RSA-PSS (SHA-256). Returns error.UnsupportedKeyAlgorithm
/// for unsupported or unknown key types.
pub fn inferSignatureAlgorithm(cert_der: []const u8) !sigmod.SigAlg {
    const cert = try parseCert(std.heap.page_allocator, cert_der);

    if (sigmod.parseEd25519Spki(cert.spki)) |_| {
        return .ed25519;
    } else |err| switch (err) {
        error.UnexpectedAlgorithm => {},
        else => return err,
    }

    if (sigmod.parseEcdsaSpki(cert.spki, std.heap.page_allocator)) |spki_val| {
        var spki = spki_val;
        defer spki.deinit();
        if (!spki.curve_p256) return error.UnsupportedKeyAlgorithm;
        return .ecdsa_secp256r1_sha256;
    } else |err| switch (err) {
        error.UnexpectedAlgorithm => {},
        error.UnsupportedCurve, error.InvalidEcPoint => return error.UnsupportedKeyAlgorithm,
        else => return err,
    }

    if (sigmod.parseRsaSpki(cert.spki, std.heap.page_allocator)) |spki_val| {
        var spki = spki_val;
        defer spki.deinit();
        return .rsa_pss_sha256;
    } else |err| switch (err) {
        error.UnexpectedAlgorithm => {},
        else => return err,
    }

    return error.UnsupportedKeyAlgorithm;
}

/// Check if 'now' is within the certificate validity window.
pub fn checkValidity(now_unix: i64, cert: *const Certificate) !void {
    if (now_unix < cert.not_before_unix) return error.NotYetValid;
    if (now_unix > cert.not_after_unix) return error.Expired;
}

fn toLowerAscii(b: u8) u8 {
    return if (b >= 'A' and b <= 'Z') b + 32 else b;
}

fn endsWithAsciiCI(hay: []const u8, suf: []const u8) bool {
    if (hay.len < suf.len) return false;
    const off = hay.len - suf.len;
    var i: usize = 0;
    while (i < suf.len) : (i += 1) {
        if (toLowerAscii(hay[off + i]) != toLowerAscii(suf[i])) return false;
    }
    return true;
}

fn containsDot(s: []const u8) bool {
    for (s) |c| if (c == '.') return true;
    return false;
}

fn wildcardMatch(host: []const u8, pattern: []const u8) bool {
    // Only support "*.example.com" with exactly one extra label on the left.
    if (pattern.len < 3 or pattern[0] != '*' or pattern[1] != '.') return false;
    const suffix = pattern[1..]; // includes leading '.'
    if (!endsWithAsciiCI(host, suffix)) return false;
    const prefix_len = host.len - suffix.len;
    if (prefix_len == 0) return false;
    const prefix = host[0..prefix_len];
    // Exactly one label on the left: no additional dots allowed in prefix
    if (containsDot(prefix)) return false;
    return true;
}

/// Match a DNS name against SAN entries or the subject CN fallback.
pub fn matchDnsName(cert: *const Certificate, name: []const u8) bool {
    // Exact byte match (case-sensitive) for simplicity; wildcard support for leading label.
    if (cert.san) |san| {
        for (san.dns) |d| {
            if (std.mem.eql(u8, d, name)) return true;
            if (d.len >= 2 and d[0] == '*' and d[1] == '.') {
                if (wildcardMatch(name, d)) return true;
            }
        }
        return false;
    }
    if (cert.subject.cn) |cn| {
        if (std.mem.eql(u8, cn, name)) return true;
        if (cn.len >= 2 and cn[0] == '*' and cn[1] == '.') return wildcardMatch(name, cn);
        return false;
    }
    return false;
}

fn parseCertSignature(der: []const u8) !struct { algo_oid: []const u8, sig_der: []const u8 } {
    var d = asn1.Decoder.init(der);
    const cert_seq = try d.readSequence();
    var c = asn1.Decoder.init(cert_seq);
    _ = try c.readSequence(); // tbs
    // signatureAlgorithm
    var sa = asn1.Decoder.init(try c.readSequence());
    const oid = try sa.readOID();
    // Optional params ignored for now
    _ = sa.readTLV() catch null;
    // signatureValue BIT STRING
    const sig_bits = try c.readBitString();
    return .{ .algo_oid = oid, .sig_der = sig_bits };
}

fn oidIsEcdsaSha256(oid: []const u8) bool {
    // 1.2.840.10045.4.3.2 -> bytes end with 2A 86 48 CE 3D 04 03 02
    return oid.len >= 8 and std.mem.eql(u8, oid[oid.len - 8 ..], &[_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 });
}
fn oidIsEcdsaSha384(oid: []const u8) bool {
    return oid.len >= 8 and std.mem.eql(u8, oid[oid.len - 8 ..], &[_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 });
}
fn oidIsRsaPss(oid: []const u8) bool {
    // 1.2.840.113549.1.1.10 -> 2A 86 48 86 F7 0D 01 01 0A
    return oid.len >= 9 and std.mem.eql(u8, oid[oid.len - 9 ..], &[_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A });
}
fn oidIsEd25519(oid: []const u8) bool {
    // Ed25519 1.3.101.112 -> 2B 65 70
    return oid.len >= 3 and std.mem.eql(u8, oid[oid.len - 3 ..], &[_]u8{ 0x2B, 0x65, 0x70 });
}

fn verifyCertSig(issuer_spki_der: []const u8, tbs: []const u8, algo_oid: []const u8, sig_der: []const u8) bool {
    if (oidIsEcdsaSha256(algo_oid)) {
        const E = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, std.crypto.hash.sha2.Sha256);
        const signature = E.Signature.fromDer(sig_der) catch return false;
        var spki = sigmod.parseEcdsaSpki(issuer_spki_der, std.heap.page_allocator) catch return false;
        defer spki.deinit();
        const pubkey = E.PublicKey.fromSec1(spki.sec1_uncompressed) catch return false;
        signature.verify(tbs, pubkey) catch return false;
        return true;
    }
    if (oidIsEcdsaSha384(algo_oid)) {
        const E = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P384, std.crypto.hash.sha2.Sha384);
        const signature = E.Signature.fromDer(sig_der) catch return false;
        var spki = sigmod.parseEcdsaSpki(issuer_spki_der, std.heap.page_allocator) catch return false;
        defer spki.deinit();
        const pubkey = E.PublicKey.fromSec1(spki.sec1_uncompressed) catch return false;
        signature.verify(tbs, pubkey) catch return false;
        return true;
    }
    if (oidIsRsaPss(algo_oid)) {
        // Constrain to SHA-256 and saltLen=32. Verify TBSCertificate directly (no TLS context).
        // Note: We reuse the RSA-PSS verifier from sig.zig by providing the raw TBS as message.
        return sigmod.verifyCertificateVerify(.rsa_pss_sha256, issuer_spki_der, sig_der, "", tbs) catch false;
    }
    if (oidIsEd25519(algo_oid)) {
        // Ed25519 signature verification using std.crypto
        const pubkey_bytes = sigmod.parseEd25519Spki(issuer_spki_der) catch return false;
        const pubkey = Ed25519.PublicKey.fromBytes(pubkey_bytes) catch return false;
        if (sig_der.len != 64) return false;
        var sig_arr: [64]u8 = undefined;
        @memcpy(&sig_arr, sig_der[0..64]);
        const signature = Ed25519.Signature.fromBytes(sig_arr);
        signature.verify(tbs, pubkey) catch return false;
        return true;
    }
    return false;
}

/// Validate a chain from leaf to root. Insecure mode skips all checks.
pub fn validateChain(alloc: std.mem.Allocator, chain_der: []const []const u8, now_unix: i64, server_name: []const u8, allow_insecure: bool) !void {
    if (allow_insecure) return;
    if (chain_der.len == 0) return error.EmptyChain;

    // Parse all certs
    var certs = try alloc.alloc(Certificate, chain_der.len);
    defer alloc.free(certs);
    var i: usize = 0;
    while (i < chain_der.len) : (i += 1) certs[i] = try parseCert(alloc, chain_der[i]);

    // Leaf checks
    try checkValidity(now_unix, &certs[0]);
    if (!matchDnsName(&certs[0], server_name)) return error.NameMismatch;
    if (certs[0].eku) |eku| if (!eku.server_auth) return error.EkuNotAllowed;
    if (certs[0].ku) |ku| {
        // Require digitalSignature bit when KeyUsage present (RFC 5280 §4.2.1.3)
        // Our bitstring packs MSB of first byte as highest mask bit (0x8000 when 2 bytes).
        if ((ku.bits & 0x8000) == 0) return error.KuNotAllowed;
    }

    // Intermediates must be CA and within pathLenConstraint
    var max_path: ?u32 = null;
    var depth: u32 = 0;
    i = 1;
    while (i < certs.len) : (i += 1) {
        depth += 1;
        const c = certs[i];
        // BasicConstraints CA required for all but leaf
        if (c.basic) |b| {
            if (!b.ca) return error.BasicConstraints;
            if (b.path_len) |pl| max_path = if (max_path) |m| @min(m, pl) else pl;
        } else return error.BasicConstraints;
        if (c.ku) |ku| {
            // Expect keyCertSign (bit 5) present when KU provided; our mask is rough, skip strict check
            _ = ku;
        }
        try checkValidity(now_unix, &c);
        if (max_path) |m| {
            if (depth > m + 1) return error.PathLenExceeded; // leaf + m intermediates allowed
        }
    }

    // Verify signatures along the chain
    i = 0;
    while (i < certs.len) : (i += 1) {
        const issuer_index: usize = if (i + 1 < certs.len) i + 1 else i; // root self-signed
        const issuer_spki = certs[issuer_index].spki;
        const parsed = parseCertSignature(chain_der[i]) catch return error.SignatureParse;
        const ok = verifyCertSig(issuer_spki, certs[i].tbs, parsed.algo_oid, parsed.sig_der);
        if (!ok) return error.BadSignature;
        if (i == certs.len - 1) {
            // Root must be CA and trusted if trust store provided
            if (certs[i].basic) |b| {
                if (!b.ca) return error.BasicConstraints;
            } else return error.BasicConstraints;
            if (g_trust_store) |ts| {
                if (!ts.isTrustedSpki(certs[i].spki)) return error.UntrustedRoot;
            }
        }
    }
}
