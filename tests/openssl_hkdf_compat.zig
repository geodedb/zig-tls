pub const EVP_MD = opaque {};
pub const EVP_PKEY_CTX = opaque {};
pub const ENGINE = opaque {};

extern "c" fn EVP_PKEY_CTX_new_id(id: c_int, engine: ?*ENGINE) ?*EVP_PKEY_CTX;
extern "c" fn EVP_PKEY_CTX_free(ctx: ?*EVP_PKEY_CTX) void;
extern "c" fn EVP_PKEY_derive_init(ctx: ?*EVP_PKEY_CTX) c_int;
extern "c" fn EVP_PKEY_CTX_set_hkdf_mode(ctx: ?*EVP_PKEY_CTX, mode: c_int) c_int;
extern "c" fn EVP_PKEY_CTX_set_hkdf_md(ctx: ?*EVP_PKEY_CTX, md: ?*const EVP_MD) c_int;
extern "c" fn EVP_PKEY_CTX_set1_hkdf_salt(ctx: ?*EVP_PKEY_CTX, salt: ?[*]const u8, saltlen: c_int) c_int;
extern "c" fn EVP_PKEY_CTX_set1_hkdf_key(ctx: ?*EVP_PKEY_CTX, key: ?[*]const u8, keylen: c_int) c_int;
extern "c" fn EVP_PKEY_CTX_add1_hkdf_info(ctx: ?*EVP_PKEY_CTX, info: ?[*]const u8, infolen: c_int) c_int;
extern "c" fn EVP_PKEY_derive(ctx: ?*EVP_PKEY_CTX, key: [*]u8, keylen: *usize) c_int;

pub const EVP_PKEY_HKDF: c_int = 1036;
pub const EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY: c_int = 1;
pub const EVP_PKEY_HKDEF_MODE_EXPAND_ONLY: c_int = 2;

inline fn toCInt(len: usize) c_int {
    return @as(c_int, @intCast(len));
}

fn setSalt(ctx: ?*EVP_PKEY_CTX, salt: ?[*]const u8, salt_len: usize) c_int {
    return EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, toCInt(salt_len));
}

fn setKey(ctx: ?*EVP_PKEY_CTX, key: ?[*]const u8, key_len: usize) c_int {
    return EVP_PKEY_CTX_set1_hkdf_key(ctx, key, toCInt(key_len));
}

fn addInfo(ctx: ?*EVP_PKEY_CTX, info: ?[*]const u8, info_len: usize) c_int {
    if (info_len == 0) return 1;
    return EVP_PKEY_CTX_add1_hkdf_info(ctx, info, toCInt(info_len));
}

fn derive(ctx: ?*EVP_PKEY_CTX, out_key: [*]u8, out_len: *usize) c_int {
    var len = out_len.*;
    const rc = EVP_PKEY_derive(ctx, out_key, &len);
    if (rc == 1) out_len.* = len;
    return rc;
}

fn newContext() ?*EVP_PKEY_CTX {
    return EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, null);
}

pub fn hkdfExtract(
    out_key: [*]u8,
    out_len: *usize,
    digest: ?*const EVP_MD,
    secret: [*]const u8,
    secret_len: usize,
    salt: [*]const u8,
    salt_len: usize,
) c_int {
    const ctx = newContext() orelse return 0;
    defer EVP_PKEY_CTX_free(ctx);

    if (EVP_PKEY_derive_init(ctx) != 1) return 0;
    if (EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1) return 0;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, digest) != 1) return 0;
    if (setSalt(ctx, if (salt_len == 0) null else salt, salt_len) != 1) return 0;
    if (setKey(ctx, if (secret_len == 0) null else secret, secret_len) != 1) return 0;

    return derive(ctx, out_key, out_len);
}

pub fn hkdfExpand(
    out_key: [*]u8,
    out_len: usize,
    digest: ?*const EVP_MD,
    prk: [*]const u8,
    prk_len: usize,
    info: [*]const u8,
    info_len: usize,
) c_int {
    const ctx = newContext() orelse return 0;
    defer EVP_PKEY_CTX_free(ctx);

    if (EVP_PKEY_derive_init(ctx) != 1) return 0;
    if (EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1) return 0;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, digest) != 1) return 0;
    if (setKey(ctx, if (prk_len == 0) null else prk, prk_len) != 1) return 0;
    if (addInfo(ctx, if (info_len == 0) null else info, info_len) != 1) return 0;

    var len = out_len;
    if (derive(ctx, out_key, &len) != 1) return 0;
    return if (len == out_len) 1 else 0;
}
