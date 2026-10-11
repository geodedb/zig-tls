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
| Named groups | `[x25519]` | `[x25519_mlkem768]` — provider-backed X25519MLKEM768 hybrid exchange. **Standalone X25519 key-agreement is rejected at runtime** (`HandshakeError.UnsupportedKeyShareGroup`) on both client and server because standalone X25519 is not FIPS-approved (only ECDH P-256/384/521 and the hybrid are); see §6 for the wire exchange |
| HKDF-Expand-Label | std `HkdfShaXXX.expand` | OpenSSL EVP_KDF "HKDF" `MODE=EXPAND_ONLY` via `Kdf.hkdfExpand` |
| HKDF-Extract / HMAC | std | OpenSSL HMAC / HKDF |
| CSPRNG (`entropy.fillRandom`) | platform `randomSecure` | SP 800-90A DRBG via `Csprng.bytes` (fail-closed) |
| CertificateVerify sigs (handshake) | std table | classical (Ed25519/ECDSA/RSA-PSS) routed through `cb.Sig` via `fromPublicBytes`/`fromPrivateBytes`; **ML-DSA** handshake sigs available |
| X.509 cert-CHAIN sigs (`verifyCertSig`) | std.crypto (Ed25519/ECDSA/RSA-PKCS#1/RSA-PSS) | classical cert-chain verification routed through the FIPS provider for the canonical (curve/hash) pairings (see §8); residual off-diagonal combos stay on std.crypto with `// fips-exempt` annotations; **ML-DSA** cert-chain verification via `fromPublicBytes` |
| Startup self-test | n/a | `Context.init` calls `cb.assertActive()` → the OpenSSL FIPS provider module self-test (KATs); hard-fails (panic) if the provider is absent or not self-tested (spec §3.1) |

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
`cb.fips_enabled == false`. Under `-Dfips=true` those same paths instead route
through the FIPS provider — see §8 for the cert-CHAIN routing details and the
exact (curve/hash) combinations that remain on `std.crypto`. This keeps the
non-FIPS path RSA-capable with **no `fips` dependency** and no OpenSSL link.
(`src/std_shim.zig` is canonical/copy-verbatim and is never edited for this.)

## 6. Provider-backed X25519MLKEM768 wire exchange

FIPS Context handshakes use `NamedGroup.x25519_mlkem768` (`0x11ec`). The
client generates a provider-owned KEM key and exports its public share using
`Kem.exportPublic`. The server imports the peer share with `Kem.importPublic`
and uses `Kem.encapsulatePublic`; the client uses `Kem.decapsulate`.

OpenSSL owns both components and their encoding. For this group, ML-KEM comes
first: the ClientHello share is 1184 + 32 bytes, the ServerHello share is
1088 + 32 bytes, and the shared secret is 32 + 32 bytes. The full 64-byte
secret enters the TLS key schedule unchanged. See
[draft-ietf-tls-ecdhe-mlkem-05 §4](https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem-05#section-4).

Only the configured active group can be negotiated. Exact lengths, canonical
ML-KEM public-key encoding, provider ownership and the hybrid key agreement
are checked before traffic-secret installation. The client frees its KEM key
after decapsulation and on errors or termination; shared-secret buffers are
wiped. Standalone X25519 has no FIPS fallback.

A cookie-only HelloRetryRequest retains the original key share and recomputes
PSK binders over the retry transcript. A retry selecting an already-offered
share is rejected even if it includes a cookie, as required by
[RFC 8446 §4.2.8](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8).

`tests/fips_hybrid_handshake_test.zig` exercises authenticated Context peers,
traffic-secret agreement, SHA-256/SHA-384 suites, PSKs, retry transcripts,
malformed shares, downgrade rejection and ephemeral-key cleanup. Run it with
`zig build test-hybrid-handshake -Dfips=true -Dopenssl_path=<prefix> -j2`.
The tests also run as part of `zig build test` and the existing dual-mode CI.

## 7. Dependency on the `fips` package + `make deps`

`-Dfips=true` depends on the `fips` package, which builds the OpenSSL 3.x FIPS
provider via its `make deps` target (always-latest OpenSSL + `enable-fips` +
`fipsinstall`, installed to `OPENSSL_PREFIX`, default `/usr/local/ssl`). The
FIPS provider must be loaded and self-tested at runtime; `fips.assertActive()`
hard-fails otherwise. `tls` invokes this self-test from `Context.init` (the
library entry point every consumer reaches), so a `-Dfips=true` consumer
triggers the mandated provider self-test through normal library use. CI wires
`make deps` through the ci-catalog `zig-fips-build` component before the
`test-fips` job (see `.gitlab-ci.yml`).

## 8. Classical certificate-CHAIN signature verification under `-Dfips=true`

`x509.verifyCertSig` (reached via `validateChain` on every TLS handshake)
verifies the signature on each certificate in the chain. Under `-Dfips=true` it
routes the classical ECDSA / RSA-PKCS#1 / RSA-PSS / Ed25519 cert-chain
verification through the OpenSSL FIPS provider (the `crypto_backend` seam,
`fipsVerifyCertSig`), **not** bare `std.crypto`. ML-DSA cert-chain verification
is likewise provider-routed.

The seam's `Sig.verify` pins exactly one digest per `policy.SigAlg`:

| Cert signatureAlgorithm | Routed under `-Dfips=true`? | Notes |
|-------------------------|-----------------------------|-------|
| ECDSA P-256 + SHA-256 | ✅ FIPS provider | `policy.ecdsa_p256` |
| ECDSA P-384 + SHA-384 | ✅ FIPS provider | `policy.ecdsa_p384` |
| RSA-PSS (SHA-256) | ✅ FIPS provider | `policy.rsa_pss` |
| RSA-PKCS#1 + SHA-256 | ✅ FIPS provider | `policy.rsa_pkcs1` |
| Ed25519 | ✅ FIPS provider | `policy.ed25519` (pure) |
| ML-DSA-44/65/87 | ✅ FIPS provider | `fromPublicBytes` raw SPKI key |
| ECDSA off-diagonal (e.g. P-384 key + SHA-256 sig) and ECDSA + SHA-512 | ⚠️ `std.crypto` | `// fips-exempt` — the seam couples one digest per curve and cannot express these; ECDSA + SHA-2 are still FIPS-approved *algorithms* |
| RSA-PKCS#1 + SHA-384 / SHA-512 | ⚠️ `std.crypto` | `// fips-exempt` — the seam pins `rsa_pkcs1`↔SHA-256 only; RSA + SHA-2 are still FIPS-approved |

The two `// fips-exempt`-annotated rows are a foundation-contract limitation
(the published `Sig.verify` does not take a digest selector), not unvetted
crypto: the underlying algorithm families (ECDSA, RSA, SHA-2) are
FIPS-approved; only the exact `(curve/key, digest)` pairing is not expressible
through the seam today. They are explicitly annotated at the call sites in
`src/x509.zig` rather than silently using `std.crypto`. The handshake
`CertificateVerify` path (`sig.zig` `verifyCertificateVerify` /
`signCertificateVerify`) is fully seam-routed and has no such off-diagonal
cases (TLS 1.3 fixes one digest per scheme).
