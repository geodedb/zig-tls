<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# FIPS-140-3 / Post-Quantum Crypto Mode (`tls`)

This document describes the build-flag-gated FIPS-140-3 mode and post-quantum
cryptography added to `tls`. It is the per-library companion to the workspace
spec (`docs/superpowers/specs/2026-06-20-fips-pqc-design.md`).

## 1. `-Dfips` flag semantics

- **Off by default.** `zig build test` builds the standard, non-FIPS library.
  With `-Dfips=false` the seam (`src/crypto_backend.zig`) collapses to the
  local `std_shim` backend: zero OpenSSL link, no `fips` dependency, no lazy
  fetch, and the fips branch of the seam is comptime-dead. Zero overhead.
- **On with `-Dfips=true`.** Security-relevant cryptography routes through the
  linked OpenSSL 3.x FIPS provider (`@import("fips")`). Only this branch pulls
  the lazily-resolved `fips` dependency and links `libcrypto`/`libssl`.
- **`-Dopenssl_path=<prefix>`** selects a non-standard OpenSSL install (e.g.
  the FIPS build at `/usr/local/ssl`). The FIPS provider's `openssl.cnf` must be
  active at runtime: `OPENSSL_CONF=<prefix>/ssl/openssl.cnf`.

Build/test both modes:

```sh
zig build test                                                                 # -Dfips=false (std_shim)
OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf \
  zig build test -Dfips=true -Dopenssl_path=/usr/local/ssl                      # OpenSSL FIPS backend
# or the dual-mode gate:
make test-dual            # runs BOTH of the above
```

## 2. The canonical seam (GAP-0020 single-`build_options` rule)

`tls` carries THREE copy-verbatim files from the `fips` package:

- `src/crypto_backend.zig` — the seam. Call sites import this, never
  `std.crypto` directly, in a security path.
- `src/std_shim.zig` — std.crypto-backed backend for the non-FIPS path. Imports
  its sibling via `@import("policy.zig")` (path-relative, NOT a named module),
  so the non-FIPS path is self-contained.
- `src/policy.zig` — pure-comptime FIPS-approved algorithm allow-list.

`src/link.zig` (also copied from `fips`) provides `linkOpenssl`. The build wires
ONE `b.addOptions()` → ONE `build_options` module instance threaded into every
compile unit and the lazy `fips` dependency. `crypto_backend` and `std_shim`
are SHARED NAMED modules (one module identity each) to avoid Zig 0.16's
module-dedup bug.

### Lazy `fips` dependency wiring

In this workspace the `fips` package has **no git remote yet**, so it is wired
as a LOCAL PATH dependency in `build.zig.zon`:

```zig
.fips = .{ .path = "../../../../../devnw/zig/fips", .lazy = true },
```

(`.path` is relative to the realpath build root.) `.lazy = true` keeps it out of
the `-Dfips=false` build entirely — `b.lazyDependency("fips", ...)` only resolves
it under `-Dfips=true`. The eventual production form (once the repo has a remote
plus a tag) is the git+https lazy dep documented inline in `build.zig.zon`:

```zig
.fips = .{ .url = "git+https://gitlab.com/devnw/zig/fips.git?ref=v0.1.0#<commit-sha>", .hash = "<zig-package-hash>", .lazy = true }
```

## 3. Behavior changes forced under `-Dfips=true`

| Area | Non-FIPS (default) | Under `-Dfips=true` |
|------|--------------------|---------------------|
| Record AEAD | AES-128/256-GCM **+ ChaCha20-Poly1305** | **AES-GCM only**; ChaCha is rejected at `AeadCipher.init` (`RecordError.UnsupportedCipherSuite`) and dropped from the default cipher-suite list |
| Named groups | `[x25519]` | `[x25519_mlkem768, x25519]` — the X25519MLKEM768 post-quantum hybrid is preferred |
| HKDF-Expand-Label | std `HkdfShaXXX.expand` | OpenSSL EVP_KDF "HKDF" `MODE=EXPAND_ONLY` via `Kdf.hkdfExpand` |
| HKDF-Extract / HMAC | std | OpenSSL HMAC / HKDF |
| CSPRNG (`entropy.fillRandom`) | platform `randomSecure` | SP 800-90A DRBG via `Csprng.bytes` (fail-closed) |
| CertificateVerify sigs | std table | classical (Ed25519/ECDSA/RSA-PSS) routed through `cb.Sig` via `fromPublicBytes`/`fromPrivateBytes`; **ML-DSA** handshake sigs available |
| X.509 cert chains | Ed25519/ECDSA/RSA | adds **ML-DSA** certificate-chain verification (`fromPublicBytes`) |

All swaps are covered by dual-mode tests (both `-Dfips=false` and
`-Dfips=true` are green).

## 4. Per-mode classical-signature capability matrix

`signCertificateVerify` capability differs by mode by design:

| Scheme | verify (both modes) | sign `-Dfips=false` | sign `-Dfips=true` |
|--------|---------------------|---------------------|--------------------|
| Ed25519 | ✅ | ✅ (std) | ✅ (`cb.Sig`) |
| ECDSA P-256 | ✅ | ✅ (std) | ✅ (`cb.Sig`) |
| ECDSA P-384 | ✅ | ❌ `error.Unsupported` (pre-existing std limitation, unchanged) | ✅ (`cb.Sig`) |
| RSA-PSS | ✅ | ❌ `error.Unsupported` (pre-existing std limitation, unchanged) | ✅ (`cb.Sig`) |
| ML-DSA-44/65/87 | fips-only | ❌ `error.Unsupported` | ✅ (`cb.Sig`) |

The `-Dfips=false` RSA-PSS / ECDSA-P384 sign limitation is **pre-existing and
unchanged** by this work; under `-Dfips=true` all four classical schemes sign
through the FIPS provider.

## 5. RSA / PQC in non-FIPS mode (escape hatch)

`std_shim` is std-backed and supports only what `std.crypto` covers: `Sig` for
Ed25519 + ECDSA (P-256/P-384). It returns `error.Unsupported` for RSA and all
PQC (ML-DSA/SLH-DSA, ML-KEM/hybrid KEMs).

`tls` keeps full **RSA/ECDSA/Ed25519 certificate verification** in `-Dfips=false`
by **NOT routing those through `std_shim`**: classical verification stays on the
in-tree std-backed paths in `src/sig.zig` / `src/x509.zig` under
`cb.fips_enabled == false`. Only the FIPS path is pure-`crypto_backend`. This
keeps the non-FIPS path RSA-capable with **no `fips` dependency** and no OpenSSL
link. (`src/std_shim.zig` is canonical/copy-verbatim and is never edited for
this.)

## 6. Documented foundation-contract boundary (X25519MLKEM768 on-wire exchange)

The X25519MLKEM768 hybrid KEM is integrated into the TLS 1.3 key schedule and
its `key_share` wire format is implemented and tested:

- `NamedGroup.x25519_mlkem768 = 0x11ec`, the draft-fixed size constants
  (ClientHello key_share 1216, ServerHello key_share 1120), ECDH-first concat
  order, length validators (client offer + server accept + ServerHello parse),
  and a local-keypair encapsulate/decapsulate round-trip are ALL exercised on
  the published contract (`tests/fips_hybrid_kem_test.zig`,
  `tests/fips_hybrid_keyshare_test.zig`).

**Provider note (OpenSSL 3.6.2):** the `X25519MLKEM768` provider KEM is a
*complete* hybrid — `encapsulate` returns the full 1120-byte ServerHello
key_share as the ciphertext (the provider concatenates the X25519 leg) and the
full 64-byte combined shared secret. The consumer does not manually concatenate
the X25519 leg; OpenSSL owns both legs.

**Boundary (a tracked dependency, not an inline marker):** live on-the-wire
hybrid exchange still needs TWO `Kem.KeyPair` capabilities the corrected
foundation contract does not yet publish:

1. **Export** — the client must serialize its generated ML-KEM encapsulation key
   to raw bytes for the offer: `Kem.KeyPair.publicBytes(self, out)`
   (EVP `EVP_PKEY_get_raw_public_key`), mirroring `Sig.KeyPair.publicBytes`.
2. **Import** — the server must build a `Kem.KeyPair` from the client's raw
   encapsulation key to encapsulate against it: `Kem.KeyPair.fromPublicBytes(alg, raw)`
   (EVP `EVP_PKEY_new_raw_public_key_ex` under `"fips=yes"`), mirroring
   `Sig.KeyPair.fromPublicBytes`.

Until both land, the client-offer encap-key fill, the server-accept
encapsulate, and the client ServerHello-parse decapsulate arms return
`HandshakeError.UnsupportedKeyShareGroup` with `// CONTRACT-BOUNDARY:` markers
in `src/tls13/context.zig`. This is tracked as a foundation-plan dependency.

## 7. Dependency on the `fips` package + `make deps`

`-Dfips=true` depends on the `fips` package, which builds the OpenSSL 3.x FIPS
provider via its `make deps` target (always-latest OpenSSL + `enable-fips` +
`fipsinstall`, installed to `OPENSSL_PREFIX`, default `/usr/local/ssl`). The
FIPS provider must be loaded and self-tested at runtime; `fips.assertActive()`
hard-fails otherwise. CI wires `make deps` through the ci-catalog
`zig-fips-build` component before the `test-fips` job (see `.gitlab-ci.yml`).
