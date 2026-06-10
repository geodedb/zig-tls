# Application Security Code Review — devnw/zig/tls (`src/`)

**Date:** 2026-06-10
**Reviewer role:** Defensive AppSec code review (OWASP Top 10:2025 + CIS Controls v8.1.2)
**Target:** `/home/benji/src/gl/gitlab.com/devnw/zig/tls` `src/` tree (52 Zig files), pure-Zig TLS 1.3 + QUIC library, v0.1.7
**Commit reviewed:** `b2e58ac` (handshake scratch arena; GAP-0135/SEC-092)

---

## 1. Scope & Assumptions

**In scope (read directly):** ASN.1 (`asn1.zig`), X.509 (`x509.zig`), OCSP (`ocsp.zig`), SCT (`sct.zig`), varint (`varint.zig`), TLS 1.3 handshake parsers (`tls13/messages/*`, `client_hello.zig`, `encrypted_extensions.zig`, `certificate.zig`, `certificate_request.zig`), the `Context` state machine and crypto dispatch (`tls13/context.zig`), key handling (`tls13/secrets.zig`, `key_update.zig`, `entropy.zig`), 0-RTT replay (`zero_rtt.zig`), QUIC transport params, and the new handshake scratch arena.

**Prior-art consumed first (to avoid re-reporting):** `docs/SECURITY_GAP_ANALYSIS.md`, `docs/GAP_ANALYSIS.md`, `docs/SECURITY_REVIEW_NOTES.md`. SEC-001..104, GAP-0131..0145 reviewed. Closed/tracked items were excluded from findings unless I could show a claimed resolution is wrong.

**Assumptions:**

- Attacker model: network MITM / malicious peer sending crafted handshake, record, certificate, OCSP, SCT, and ASN.1 bytes. Certificate bytes and OCSP/SCT staples are fully attacker-controlled; the leaf cert is presented before authentication.
- The library is `standardOptimizeOption`-built; `README.md:83` and `docs/RUNBOOK.md:113` confirm **`-Doptimize=ReleaseFast` is a documented, supported build mode**, so integer-overflow wraps (not panics) must be assumed reachable in production deployments.
- I did not execute code, fuzz, install packages, or call external services (hard rules). The OOB finding is reasoned statically from the source; I provide a non-destructive verification recipe.

**Not fully covered:** the record/AEAD nonce-construction internals, the full RSA-PSS/ECDSA signature verification math, the thread-pool dependency internals, and exhaustive QUIC frame parsing beyond transport params.

---

## 2. Executive Summary

- **One new, untracked High-severity finding:** an integer-overflow in the ASN.1 length bounds check (`asn1.zig:396`, `readTLV`) is reachable from every X.509 / OCSP / SCT parse via an 8-octet DER long-form length. Under `-Doptimize=ReleaseFast` it wraps and produces an inverted slice (`start > end`) → out-of-bounds read; under ReleaseSafe/Debug it panics → pre-auth remote DoS. This is the single chokepoint for all certificate parsing, so blast radius is the entire cert-validation path. Not covered by the prior SEC-052 (readInteger >8 bytes) or SEC-058 (QUIC varint) overflow fixes. **Confidence: High.**
  - **Orchestrator addendum (verified post-review):** the same `off + attacker_len`-then-`> buf.len` pattern exists at **two additional sites** the agent did not enumerate: `src/x509.zig:1063` (`parseSpki`, `spki_end = ti.off + spki_hdr.len`) and `src/x509.zig:1249` (`parseCertificate` TBS capture, `tbs_end = ci.off + tbs_hdr.len`). Both are reachable on the unauthenticated leaf-certificate parse. The remediation must cover all three.
- **The specific question raised — GAP-0135 KeyUpdate budget — is implemented and correctly wired in THIS repo.** The budget check at `context.zig:3306-3308` is reachable on the real inbound dispatch path (`processCrypto → dispatchHandshake → inboundKeyUpdate → handleKeyUpdateMessage`). The failing sibling test reflects a different/older checkout. However, `docs/GAP_ANALYSIS.md` is internally inconsistent (top banner = RESOLVED, detail section §GAP-0135 still = "Open" with stale "zero rate-limit code" evidence). Documentation hygiene finding only.
- **The "open" unknown-extension duplicate-bypass in `docs/SECURITY_REVIEW_NOTES.md` (SEC-101/#350) is already fixed** in the current tree: commit `b2e58ac` (GAP-0145) replaced the bypassable `EnumSet` with raw-`u16` tracking in all four parsers, rejecting duplicate unknown extensions *before* enum mapping. The doc's "primary finding" is stale.
- **The handshake scratch arena (b2e58ac) is sound.** Builders write to the arena, `appendOutboundFramed` copies bodies into the per-level outbound stream before `reset(.retain_capacity)`, so there is no use-after-free. No long-term secret (traffic secret, PSK, private key) is ever placed in the arena — only wire-bound signatures/Finished verify_data — so the non-zeroizing reset does not leak key material.
- **Overall posture is strong.** Constant-time comparisons, fail-closed entropy, secret zeroization on overwrite, SAN-over-CN precedence, path-length enforcement, and supply-chain pinning are all present and correct. The one new finding is a high-value parser hardening gap in an otherwise well-defended codebase.

---

## 3. Findings Table

| ID | Severity | Confidence | Title | Location | OWASP / CWE | Status |
|----|----------|-----------|-------|----------|-------------|--------|
| APPSEC-2026-06-10-01 | **High** | High | ASN.1 / X.509 `off + attacker_len` length-bounds-check integer overflow → OOB read / pre-auth DoS in cert/OCSP/SCT parsing (3 sites) | `src/asn1.zig:396`; `src/x509.zig:1063`; `src/x509.zig:1249` | A10 Mishandling of Exceptional Conditions / A04; CWE-190, CWE-125 | **NEW / Open** |
| APPSEC-2026-06-10-02 | Info | High | `docs/GAP_ANALYSIS.md` GAP-0135 detail section contradicts code + its own banner (stale "Open / zero rate-limit code") | `docs/GAP_ANALYSIS.md` §GAP-0135 vs `src/tls13/context.zig:3306-3308` | A09 (process/observability); CWE-1059 | NEW (doc) |
| APPSEC-2026-06-10-03 | Info | High | `docs/SECURITY_REVIEW_NOTES.md` reports an already-fixed unknown-ext dup-bypass as the "primary finding" | `docs/SECURITY_REVIEW_NOTES.md:26-39` vs `client_hello.zig:359-381` et al. | A09 (process); CWE-1059 | NEW (doc) |
| APPSEC-2026-06-10-04 | Low | Medium | Distinct-extension-type count cap (`seen_count == 64`) rejects valid messages as `DuplicateExtension` | `client_hello.zig:379`, `encrypted_extensions.zig:242`, `certificate.zig`, `certificate_request.zig:215` | A10; CWE-754 | NEW / Open |

---

## 4. Finding Details

### APPSEC-2026-06-10-01 — ASN.1/X.509 `off + attacker_len` integer overflow in length bounds check (High)

**Evidence.**
`src/asn1.zig`, `readLen` accumulates a DER long-form length of up to 8 octets into a `usize` with no value ceiling:

```text
311  fn readLen(self: *Decoder) !usize {
312      const b = try self.readByte();
313      if ((b & 0x80) == 0) return b;
314      const n = b & 0x7f;
315      if (n == 0) return error.IndefiniteLength;
316      if (n > 8) return error.LengthTooLarge;        // caps octet COUNT at 8, not VALUE
317      var val: usize = 0;
...
319      while (i < n) : (i += 1) { val = (val << 8) | try self.readByte(); }
322      return val;                                     // val can be up to 2^64-1
```

The consumers that slice on this length compute `off + len` *before* the bounds check, so the add can wrap:

```text
asn1.zig:396  const end = self.off + hdr.len;                 // OVERFLOW
asn1.zig:397  if (end > self.buf.len) return error.Truncated; // bypassed when end wraps small
asn1.zig:398  const val = self.buf[self.off..end];            // start > end  → OOB / UB slice

x509.zig:1063 const spki_end = ti.off + spki_hdr.len;        // same class, parseSpki
x509.zig:1064 if (spki_end > tbs_seq.len) return error.Truncated;
x509.zig:1065 const spki_bytes = tbs_seq[spki_start..spki_end];

x509.zig:1249 const tbs_end = ci.off + tbs_hdr.len;           // same class, parseCertificate
x509.zig:1250 if (tbs_end > cert_seq.len) return error.Truncated;
x509.zig:1251 const tbs_seq = cert_seq[ci.off..tbs_end];
```

Every typed reader funnels through `readTLV` (`readSequence`, `readInteger`, `readOctetString`, `readBitString`, `readOID`), so the `asn1.zig` flaw is the common chokepoint for all DER parsing; the two `x509.zig` sites add direct slices on the unauthenticated leaf certificate.

**Attack path (source → sink), non-destructive.** A malicious peer sends a `Certificate` message (`src/tls13/messages/certificate.zig:173 parseCertificate`). The per-cert `cert_slice` (up to 2^24-1 bytes, attacker-controlled) is handed to `x509.parseCert` (`src/x509.zig:1231`), which calls `asn1.Decoder.init(der)`. Inside the cert, the attacker encodes a TLV with a long-form length header `0x88 FF FF FF FF FF FF FF F0` (8 octets). `readLen` returns `≈ 2^64 - 16`. In the slice sites, `off + len` wraps to a small value `k`; with `k <= buf.len` and `k < off`, the `> buf.len` guard passes and `buf[off..k]` is evaluated with `start > end`. The identical path is reachable via attacker-supplied stapled OCSP (`src/ocsp.zig`) and SCT structures.

**Impact.**

- `-Doptimize=ReleaseFast` (documented, supported — `README.md:83`, `docs/RUNBOOK.md:113`): safety checks off; `buf[off..end]` with `start > end` is undefined behavior → OOB read / potential info disclosure. Pre-authentication.
- `ReleaseSafe`/`Debug`: the add or slice panics → unauthenticated remote DoS against any server/client that parses a peer certificate or OCSP staple.

**Root cause.** The bound on the *number* of length octets (`n > 8`) is mistaken for a bound on the *value*; the bounds check is performed after an unchecked `usize` add that can wrap.

**Remediation (smallest safe fix, apply at all three sites).** Compute the bound without overflow and validate before slicing:

```zig
// asn1.zig readTLV
if (hdr.len > self.buf.len - self.off) return error.Truncated;
const end = self.off + hdr.len; // cannot overflow after the check above
```

```zig
// x509.zig parseSpki
if (spki_hdr.len > tbs_seq.len - ti.off) return error.Truncated;
const spki_end = ti.off + spki_hdr.len;
```

```zig
// x509.zig parseCertificate
if (tbs_hdr.len > cert_seq.len - ci.off) return error.Truncated;
const tbs_end = ci.off + tbs_hdr.len;
```

Optionally clamp in `readLen` as defense in depth: `if (val > self.buf.len) return error.LengthTooLarge;`.

**Regression tests / verification.** Add a test feeding `asn1.Decoder.init` a buffer whose first TLV uses an 8-octet long-form length near `maxInt(u64)` and assert `error.Truncated` (no panic, no OOB) under all three optimize modes, including `zig build test -Doptimize=ReleaseFast`. Add a malformed-cert corpus seed exercising `parseSpki`/`parseCertificate` directly.

**Mappings.** OWASP A10 (Mishandling of Exceptional Conditions), secondary A04. CWE-190, CWE-125, CWE-754. CIS v8.1.2: 16.1, 16.11, 16.12, 16.13.

---

### APPSEC-2026-06-10-02 — GAP-0135 doc/code inconsistency; KeyUpdate budget actually works here (Info)

The KeyUpdate exhaustion budget IS present and reachable in this repo: `config.zig:488` (`max_peer_key_updates: u32 = 32`), `context.zig:630` (`peer_key_updates_seen`), `context.zig:3306-3308` (increment + `HandshakeError.TooManyKeyUpdates`), wired via `processCrypto → dispatchHandshake → inboundKeyUpdate → handleKeyUpdateMessage`, mapped to `decode_error` at `alert.zig:129`. `docs/GAP_ANALYSIS.md` §GAP-0135 is self-contradictory (banner RESOLVED vs detail "Open"). **Remediation:** mark Closed, cite the code, fix the banner wording, and land the regression test in this repo. OWASP A09; CWE-1059.

---

### APPSEC-2026-06-10-03 — `SECURITY_REVIEW_NOTES.md` reports an already-fixed bypass as open (Info)

`docs/SECURITY_REVIEW_NOTES.md:26-39` claims an open unknown-extension duplicate-bypass (SEC-101/#350). It is fixed in the current tree by commit `b2e58ac` (GAP-0145): raw-`u16` duplicate tracking that rejects duplicates before enum mapping at `client_hello.zig:359-381`, `encrypted_extensions.zig:222-244`, `certificate_request.zig:202-217`, `certificate.zig:217-231`. Also a SEC-101 ID collision (already used for SAN truncation #347). **Remediation:** mark RESOLVED with citations; resolve the ID collision. OWASP A09; CWE-1059.

---

### APPSEC-2026-06-10-04 — Distinct-extension-count cap mislabels valid messages (Low)

The duplicate-extension trackers use a fixed 64-slot array and, on overflow, return a duplicate/malformed error even when all 64+ types are distinct (`client_hello.zig:379`, `encrypted_extensions.zig:242`, `certificate_request.zig:215`, `certificate.zig`). A peer sending >64 distinct extension types (e.g. many GREASE codepoints) is rejected as a duplicate violation. RFC 8446 imposes no 64-type ceiling; impact is interop/false-positive handshake failure, not a bypass — hence Low. **Remediation:** raise the cap and return a distinct `error.TooManyExtensions` mapped to `decode_error`, or document the ceiling as intentional. OWASP A10; CWE-754.

---

## 5. Secure Design Notes (positive controls observed)

- **Fail-closed entropy** (`entropy.zig:37-46`): `io().randomSecure`, panics on `EntropyUnavailable`.
- **Secret zeroization on overwrite/clear** (`secrets.zig:79-106`; KeyUpdate paths `context.zig:3320,3345,3358`).
- **Constant-time comparisons** of secret-derived data (`zero_rtt.zig:312`, `ocsp.zig:163`, PSK-binder/Finished/MAC paths).
- **Handshake scratch arena correctly bounded** (`context.zig:1630-1639`); no dangling arena ref, no long-term secret in arena.
- **Safe enum decoding on attacker bytes** (`std.enums.fromInt(...) orelse`).
- **Parser bounds discipline elsewhere** (`varint.zig`, `sct.zig`, `parseHandshakeOne`, `parseCertificate` u24 bounds).
- **Certificate identity**: SAN over CN with no CN fallback when SAN exists (`x509.zig:1546-1560`); single-left-label wildcard restriction (`x509.zig:1401-1412`).
- **Supply chain**: single hash-pinned `thread_pool` dep; SHA-pinned CI; verified Zig tarball.

---

## 6. Coverage Gaps & Questions

- **Build-mode security contract undocumented**: `standardOptimizeOption` lets consumers pick `ReleaseFast`, degrading "panic on overflow" defenses to UB. Recommend a `SECURITY.md` statement and a CI lane assertion.
- AEAD record-layer nonce/sequence construction and full signature-verification math not exhaustively re-audited.
- SAN truncation cap (SEC-101, tracked Low) fails closed; not re-reported.
- In-memory 0-RTT `AntiReplayWindow` (64 entries, FIFO) is the documented bounded-window limitation; persistent store (SEC-065) is the real defense.

---

## 7. Prioritized Next Actions

1. **Fix APPSEC-2026-06-10-01 (High)** at all three sites (`asn1.zig:396`, `x509.zig:1063`, `x509.zig:1249`) with the overflow-safe `len > remaining` pattern; add ReleaseFast regression tests and malformed-cert seeds.
2. **Land the KeyUpdate-exhaustion regression test here** and reconcile `docs/GAP_ANALYSIS.md` §GAP-0135 (APPSEC-2026-06-10-02).
3. **Resolve `SECURITY_REVIEW_NOTES.md`** (APPSEC-2026-06-10-03) and the SEC-101 ID collision.
4. **Decide/document the build-mode security contract**; add a CI assertion.
5. **Address APPSEC-2026-06-10-04 (Low)** by distinguishing the capacity limit from a duplicate error.

---

*No production secrets were encountered or echoed. No code was executed. Findings are evidence-bound with file:line citations.*
