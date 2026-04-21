# Security Gap Analysis

> **Last updated:** 2026-04-21 (Cycle 7 / Phase 20 — 11 new SEC findings from Phase 3 audit: SEC-074..SEC-084 + SEC-085 carry-forward marker for SEC-065. 5 confidential issues filed.)
> **Scope:** TLS 1.3/QUIC Implementation in Zig
> **Review phase:** Cycle 7 / Phase 20 (Phase 3 security-reviewer sync). **Posture: 0 Critical / 4 High open / 3 Medium open / 2 Low open / 1 Info open.** 11 new findings filed this cycle (SEC-074..SEC-084); SEC-065 remains the 4th High, carried forward as the audit-cycle marker SEC-085 with expanded Phase-3 scope (see issue #249 Phase 3 comment). Phase 14 / Phase 19 history retained below. SEC-077 closed 2026-04-21 (InsecureValidation sentinel + -Dtls-insecure-testing gate).
>
> **Phase 20 banner:** Phase 3 re-audit surfaced a cluster of cert-chain and RNG integrity gaps. Highest risk: **SEC-074** (RNG return value discarded -> potential uninitialized key material under seccomp / EINTR; 9 sites in `src/tls13/context.zig`). Three cert-parser gaps (SEC-075 unknown critical ext silently accepted, SEC-076 OID suffix-match bypass — SEC-069 regression class in ocsp.zig + sig.zig, SEC-077 `allow_insecure` trust-bypass flag on public API). Medium tier extends SEC-066/068 duplicate-extension defenses to ServerHello/EncryptedExtensions (SEC-078), QUIC preferred_address TP (SEC-080), and X.509 extensions (SEC-079, confidential due to dual-SAN impersonation class). All new confidential issues filed under `confidentiality` + `confidence::confirmed`; public issues are regressions of already-disclosed classes (SEC-066, 068, 069). No RCE. No leaked secrets. No Critical-severity finding.

## Cycle 7 / Phase 20 Findings (2026-04-21)

`/codepros:audit` Phase 3 security-reviewer sync. 11 new SEC items filed (5 confidential, 6 public), plus carry-forward comment on SEC-065 (#249) under audit-cycle marker SEC-085.

**New findings (11) + carry-forward (1):**

| SEC-ID | Risk | Severity | Issue | Confidential | Confidence | File:Line | Description | Status |
|--------|------|----------|-------|--------------|------------|-----------|-------------|--------|
| SEC-065 / SEC-085 | **64** | High | [#249](https://gitlab.com/devnw/zig/tls/-/issues/249) | yes | confirmed | `src/zero_rtt.zig:459` + `src/tls13/context.zig:550,1781` | 0-RTT persistent anti-replay unwired; Phase 3 adds default window size (64) insufficient for QUIC QPS, no fail-closed when store unset. CWE-294 / OWASP A07. | **Open** (carry-forward) |
| SEC-074 | **20** | High | [#291](https://gitlab.com/devnw/zig/tls/-/issues/291) | yes | confirmed | `src/tls13/context.zig:1492,1543,1686,1690,1921,1934,+3 test` | RNG return value discarded (9 sites); seccomp/EINTR -> uninitialized ECDHE private / HRR cookie HMAC key / server_random. CWE-338/908. | Closed 2026-04-21 — src/entropy.zig (randomSecure, fail-closed panic) + 9 sites migrated; no raw getrandom in src/ |
| SEC-075 | **16** | High | [#292](https://gitlab.com/devnw/zig/tls/-/issues/292) | yes | confirmed | `src/x509.zig:1097-1118` | Unknown critical extension silently accepted (RFC 5280 §4.2 MUST violation). CWE-295. | **Open** |
| SEC-076 | **15** | High | [#293](https://gitlab.com/devnw/zig/tls/-/issues/293) | yes | confirmed | `src/ocsp.zig:72,76,80,84,147` + `src/sig.zig:288,293,297,316,914,917` | OID suffix-match bypass — SEC-069 regression class across 11 sites. CWE-345. | **Open** |
| SEC-077 | **15** | High | [#294](https://gitlab.com/devnw/zig/tls/-/issues/294) | yes | confirmed | `src/x509.zig:1685,1687,1913-1914,1950-1955,2001` | `allow_insecure: bool` on public `validateChainEx` short-circuits all chain validation; no compile-time guard. CWE-295/693. | Closed 2026-04-21 — replaced bool with InsecureValidation sentinel; gated by -Dtls-insecure-testing build flag; runtime panic on misuse |
| SEC-078 | **12** | Medium | [#296](https://gitlab.com/devnw/zig/tls/-/issues/296) | no | confirmed | `src/tls13/context.zig:2081-2110` + `src/tls13/messages/encrypted_extensions.zig:215-251` + `src/tls13/context/server_hello_parsers.zig:30-86` | ServerHello + EncryptedExtensions lack duplicate-extension detection (SEC-066 regression class). CWE-693. | **Open** |
| SEC-079 | **12** | Medium | [#295](https://gitlab.com/devnw/zig/tls/-/issues/295) | yes | confirmed | `src/x509.zig:1108-1114` | X.509 duplicate extension accepted — last-wins + slice leak. Dual-SAN impersonation class. CWE-295/401. | **Open** |
| SEC-080 | **9** | Medium | [#297](https://gitlab.com/devnw/zig/tls/-/issues/297) | no | confirmed | `src/quic_transport_params.zig:677-680` | QUIC preferred_address TP accepts duplicate + leaks connection_id (SEC-068 regression class). CWE-401/693. | **Open** |
| SEC-081 | **9** | Medium | [#298](https://gitlab.com/devnw/zig/tls/-/issues/298) | no | confirmed | `src/tls13/context.zig` (9 sites) | getrandom hardwired to `std.os.linux` — portability + correctness. Subsumed by SEC-074 fix. | Closed 2026-04-21 — subsumed by SEC-074 via cross-platform std.Io entropy source |
| SEC-082 | **6** | Low | [#299](https://gitlab.com/devnw/zig/tls/-/issues/299) | no | confirmed | `src/tls13/context/key_update.zig:118-129` | KeyUpdate count unbounded (RFC 8446 §5.5 SHOULD). Same as GAP-0135. CWE-400. | **Open** |
| SEC-083 | **6** | Low | [#300](https://gitlab.com/devnw/zig/tls/-/issues/300) | no | confirmed | `tests/fuzz/corpus/` | Fuzz corpora missing for 7 attacker-reachable parsers (ServerHello, EE, Certificate, CertificateVerify, OCSP, SCT, X.509). Test-gap. | **Open** |
| SEC-084 | **3** | Info | [#301](https://gitlab.com/devnw/zig/tls/-/issues/301) | no | confirmed | `tests/sig_unit_tests.zig:146-149` + `tests/x509_unit_tests.zig:533-543` | 2 unit tests skipped unconditionally mask security-relevant coverage. Duplicate-frame of QUAL-364. | **Open** |

**Confidentiality policy note:** confidential issues describe class-level evidence only in this public doc; full exploit details live in the GitLab confidential issues.

### Phase 20 top risks

1. **SEC-065 / SEC-085 Risk 64 (High, confidential)** — 0-RTT cross-connection replay; Phase 3 widens scope (window sizing, fail-closed).
2. **SEC-074 Risk 20 (High, confidential)** — RNG return discarded; uninitialized key material under seccomp/EINTR.
3. **SEC-075 Risk 16 (High, confidential)** — unknown critical X.509 extension accepted; RFC 5280 MUST violation.
4. **SEC-076 Risk 15 (High, confidential)** — OID suffix-match bypass across 11 sites in ocsp.zig + sig.zig (SEC-069 regression class).
5. **SEC-077 Risk 15 (High, confidential)** — `allow_insecure` trust-bypass flag on public API.

### Phase 20 roadmap

- **Quick wins (< 1 day)**: SEC-074 (9 sites -> `std.crypto.random.bytes`); SEC-076 (11 sites -> canonical OID equality, mirrors SEC-069 helper); SEC-080 (extend SEC-068 bitset to preferred_address); SEC-082 (counter on Context); SEC-084 (unskip 2 tests).
- **Medium (1-5 days)**: SEC-075 (critical-boolean parse + unknown-OID rejection + test cert); SEC-078 (extend SEC-066 helper to ServerHello + EE); SEC-079 (extension-seen bitset in `parseExtensionsBlock`); SEC-081 (cross-platform RNG, likely subsumed by SEC-074); SEC-083 (7 fuzz harnesses + corpus seeds + CI wiring).
- **Strategic (> 5 days)**: SEC-077 (public API signature change — either build-flag gating or sentinel type; coordinate with downstream callers); SEC-065/SEC-085 (Config API mini-epic — still deferred, unchanged scope except Phase 3 widens to include window sizing + fail-closed default).

### Areas audited clean in Phase 20

- **Constant-time compare primitives**: all secret-derived comparisons use `std.crypto.timing_safe.*` (HMAC tags, MAC checks, PSK binders, Finished values).
- **AEAD sequence + usage limits**: `AeadLimitExceeded` fires on both record-count and data-volume thresholds; no oracle-distinguishable error branches observed (same-shape alert regardless of which invariant tripped).
- **PKCS#1 v1.5 rejection**: RFC 8446 §4.2.3 enforced — RSASSA-PKCS1-v1_5 signature algorithms rejected on incoming CertificateVerify (only RSASSA-PSS accepted). Legacy_rsa_* sigalg codepoints rejected as unsigned.
- **Path-length constraint enforcement**: `src/x509.zig:1737-1747` computes depth from trust-anchor downward and enforces per-issuer `pathLenConstraint` correctly against the cumulative `basicConstraints` limit.
- **Supply chain**: only `thread_pool` dependency in `build.zig.zon`; pinned by SHA + multihash. `.gitlab-ci.yml` uses SHA-pinned component imports (closed SEC-061 posture maintained). Zig tarball SHA-256 verified by CI.

---

## Phase 14 Findings (2026-04-20)

`/codepros:audit` Phase 3 security-reviewer findings. 9 issues filed, 1 confidential.

**Open (1) + Closed in Cycle 6 / Phase 19 (8):**

| SEC-ID | Risk | Severity | Issue | Confidence | File:Line | Description | Status |
|--------|------|----------|-------|------------|-----------|-------------|--------|
| SEC-065 | **64** | High | [#249](https://gitlab.com/devnw/zig/tls/-/issues/249) (confidential) | confirmed | `src/tls13/context.zig:550,1781` + `src/zero_rtt.zig:459` | 0-RTT anti-replay window per-`Context` only; `PersistentAntiReplayStore` vtable exists but is not wired into `Context`. Cross-connection replay accepted. CWE-294 / OWASP A07. | **Open** (deferred — requires Config API mini-epic) |
| SEC-066 | **48** | Medium | [#253](https://gitlab.com/devnw/zig/tls/-/issues/253) | confirmed | `src/tls13/messages/client_hello_handlers.zig:137,187,310` | ClientHello duplicate-extension heap leak on `supported_groups`, `signature_algorithms`, `alpn_list`; RFC 8446 §4.2 duplicate-extension rule not enforced. Pre-auth DoS. CWE-401/400. | **Closed** (Cycle 6 / Phase 19, commit 159d17b; regression test `tests/security/sec066_clienthello_dup_ext.zig`) |
| SEC-067 | **36** | Medium | [#256](https://gitlab.com/devnw/zig/tls/-/issues/256) | confirmed | `src/zero_rtt.zig:336-343` | `AntiReplayWindow.add` `contains()`->write TOCTOU; no mutex. Docstring at `:129` acknowledges the requirement. CWE-367. | **Closed** (Cycle 6 / Phase 19, commit f3dced5; mutex added) |
| SEC-068 | **36** | Medium | [#258](https://gitlab.com/devnw/zig/tls/-/issues/258) | confirmed | `src/quic_transport_params.zig:651,656,660` | Duplicate QUIC CID TPs re-`dupe` without free; RFC 9000 §18 requires connection error on duplicate. CWE-401. | **Closed** (Cycle 6 / Phase 19, commit b24bf0a; regression test `tests/security/sec068_tp_dup_cid.zig`) |
| SEC-069 | **16** | Low | [#259](https://gitlab.com/devnw/zig/tls/-/issues/259) | confirmed | `src/x509.zig:1471-1485` | Cert sig-algo OID matched by raw-byte suffix (`oidIsRsaPss` etc.); should be canonical full-length equality. CWE-436. | **Closed** (Cycle 6 / Phase 19, commit 98d7fca; canonical full-length OID equality) |
| SEC-070 | **8** | Low | [#261](https://gitlab.com/devnw/zig/tls/-/issues/261) | confirmed | `src/ocsp.zig:129-133` | `parseStatus` accepts arbitrary-length ENUMERATED ending in `0x00` as `successful`. CWE-20 / RFC 6960. | **Closed** (Cycle 6 / Phase 19, commit 528df91; single-byte length required) |
| SEC-071 | **16** | Low | [#262](https://gitlab.com/devnw/zig/tls/-/issues/262) | suspected | `src/tls13/messages/certificate_request.zig:205-218` | CertificateRequest duplicate `signature_algorithms` silently merged. CWE-20 / RFC 8446 §4.2. | **Closed** (Cycle 6 / Phase 19, commit ed4f714; duplicate extension rejected) |
| SEC-072 | **4** | Info | [#264](https://gitlab.com/devnw/zig/tls/-/issues/264) | confirmed | `src/tls13/secrets.zig:94-100` | `SecretSlot.store` does not `secureZero` prior secret before overwrite. Brittle against PQ-hybrid layout changes. CWE-226. | **Closed** (Cycle 6 / Phase 19, commit 342775f; `secureZero` on overwrite) |
| SEC-073 | **4** | Info | [#266](https://gitlab.com/devnw/zig/tls/-/issues/266) | suspected | `src/x509.zig:1940-1987` | `validateChainReturnParsed` uses `parsed_count=0` sentinel to suppress `errdefer`. Latent double-free risk on future edits. CWE-415. | **Closed** (Cycle 6 / Phase 19, commit d081000; ownership state machine documented) |

**Confirmed-clean (no finding filed):**

- **Build supply chain**: `build.zig.zon` multihash pinning, `.gitlab-ci.yml` SHA-pinned component imports (from SEC-061 closure), Zig tarball SHA-256 verified. No new gap.

### Phase 19 top risks (post Cycle 6 / Phase 19 closure)

1. **SEC-065 Risk 64 (High, confidential)** — 0-RTT anti-replay effectively disabled between connections. Remains **Open** after Phase 19; deferred to the `Config.persistent_anti_replay_store` mini-epic.
2. ~~**SEC-066 Risk 48 (Medium)**~~ — **Closed** Cycle 6 / Phase 19 (159d17b).
3. ~~**SEC-067 Risk 36 (Medium)**~~ — **Closed** Cycle 6 / Phase 19 (f3dced5).
4. ~~**SEC-068 Risk 36 (Medium)**~~ — **Closed** Cycle 6 / Phase 19 (b24bf0a).
5. ~~**SEC-069 Risk 16 (Low)**~~ — **Closed** Cycle 6 / Phase 19 (98d7fca).

### Phase 14 roadmap (executed in Cycle 6 / Phase 19)

- **Quick wins (< 1 day)**: SEC-069 (4 helpers → canonical eql) — **done** (98d7fca); SEC-070 (tighten `parseStatus` length check) — **done** (528df91); SEC-072 (`secureZero` prior) — **done** (342775f); SEC-071 (duplicate-extension bitset for CR) — **done** (ed4f714).
- **Medium (1-5 days)**: SEC-066 (dispatcher-level duplicate-extension bitset + tests) — **done** (159d17b, `tests/security/sec066_clienthello_dup_ext.zig`); SEC-067 (mutex + threaded stress test) — **done** (f3dced5); SEC-068 (TP-seen bitset + unit tests) — **done** (b24bf0a, `tests/security/sec068_tp_dup_cid.zig`); SEC-073 (refactor to drop sentinel pattern) — **done** (d081000, ownership state machine documented).
- **Strategic (> 5 days)**: SEC-065 — thread `PersistentAntiReplayStore` through `ContextConfig` + `Context`, wire into 0-RTT accept path with fail-closed semantics, add reference implementations (in-memory, Redis mock), and add cross-context replay test fixture. **Deferred** — separate Config API mini-epic.

---

## Cycle 6 / Phase 19 Gap Closure Run (2026-04-20)

8 SEC items closed across 8 code commits on `main` (+ regression tests for SEC-066 and SEC-068). Verifier (gap-closer-verifier, APPROVED): `zig build` PASS, `zig build test` 668/668 PASS (+9 new tests), both oracles byte-identical, `zig fmt --check` clean, pre-commit clean.

**Closed (8):**

| SEC-ID | Risk | Severity | Issue | Closing commit | Evidence |
|--------|------|----------|-------|----------------|----------|
| SEC-066 | 48 | Medium | [#253](https://gitlab.com/devnw/zig/tls/-/issues/253) | 159d17b | ClientHello duplicate-extension guard implemented via `EnumSet` bitset across `supported_groups`, `signature_algorithms`, `alpn_list` handlers. RFC 8446 §4.2 duplicate-extension rule now enforced pre-auth. Regression test: `tests/security/sec066_clienthello_dup_ext.zig`. |
| SEC-067 | 36 | Medium | [#256](https://gitlab.com/devnw/zig/tls/-/issues/256) | f3dced5 | `AntiReplayWindow.add` TOCTOU fixed: `contains()`→write now atomic under a `std.Thread.Mutex`. Docstring at `:129` contract satisfied. |
| SEC-068 | 36 | Medium | [#258](https://gitlab.com/devnw/zig/tls/-/issues/258) | b24bf0a | QUIC transport-parameter duplicate CID guard added; duplicate CIDs now trigger connection error per RFC 9000 §18 instead of leaking the prior `dupe`. Regression test: `tests/security/sec068_tp_dup_cid.zig`. |
| SEC-069 | 16 | Low | [#259](https://gitlab.com/devnw/zig/tls/-/issues/259) | 98d7fca | Cert signature-algorithm OID match converted from raw-byte suffix to canonical full-length equality. 4 helpers (`oidIsRsaPss`, `oidIsEcdsaSha256`, etc.) rewritten to `eql`. CWE-436 closed. |
| SEC-070 | 8 | Low | [#261](https://gitlab.com/devnw/zig/tls/-/issues/261) | 528df91 | OCSP `parseStatus` now requires a single-byte ENUMERATED payload (RFC 6960 §4.2.1). Arbitrary-length ENUMERATEDs ending in `0x00` no longer accepted as `successful`. |
| SEC-071 | 16 | Low | [#262](https://gitlab.com/devnw/zig/tls/-/issues/262) | ed4f714 | CertificateRequest duplicate `signature_algorithms` extension now rejected (RFC 8446 §4.2 duplicate-extension rule). Previously silently merged. |
| SEC-072 | 4 | Info | [#264](https://gitlab.com/devnw/zig/tls/-/issues/264) | 342775f | `SecretSlot.store` now `secureZero`-s prior secret before overwrite. Resilient against PQ-hybrid layout changes. |
| SEC-073 | 4 | Info | [#266](https://gitlab.com/devnw/zig/tls/-/issues/266) | d081000 | `validateChainReturnParsed` `parsed_count` ownership state machine now explicitly documented; sentinel-`0` suppression of `errdefer` replaced by documented contract covering the four lifecycle transitions. Latent double-free risk on future edits closed. |

**Deferred (1):**

| SEC-ID | Risk | Issue | Reason | Unblock plan |
|--------|------|-------|--------|--------------|
| SEC-065 | 64 (High, confidential) | [#249](https://gitlab.com/devnw/zig/tls/-/issues/249) | Requires new `Config.persistent_anti_replay_store` public API surface + `PersistentAntiReplayStore` vtable wiring + reference implementations (in-memory, Redis mock) + cross-context replay test fixture. Exceeds the scope of a single-cycle closure; needs a Config API mini-epic. | (a) define `persistent_anti_replay_store: ?*PersistentAntiReplayStore` on `ContextConfig`, (b) thread into `Context.initServer` + 0-RTT accept path with fail-closed semantics, (c) add reference in-memory implementation, (d) add cross-context replay test fixture. |

**Cross-ledger cycle scope:** Cycle 6 / Phase 19 also closed 7 QUAL items (QUAL-104, 346, 348, 349, 352, 353, 356) + 1 Won't-Do (QUAL-347) and 3 PERF items (PERF-230, PERF-231, PERF-234). See `docs/QUALITY_GAP_ANALYSIS.md` and `docs/PERF_GAP_ANALYSIS.md` Cycle 6 / Phase 19 sections.

---

## Phase 13 Gap Closure Run (2026-04-19)

4 SEC items closed across 34 commits landed on `main`. Keystone change: commit `4ae8ac7` deleted `src/tls13/engine.zig`, closing SEC-064 (the parallel-code-path divergence finding). Verifier: Step 3 `zig build` PASS, `zig build test` 586/588 PASS, `zig fmt --check` clean.

**Closed (4):**

| SEC-ID | Risk | Issue | Closing commit | Note |
|--------|------|-------|----------------|------|
| SEC-061 | Low (6) | #184 | b864812 | CI catalog components pinned to commit SHAs (8 imports) |
| SEC-062 | Low (8) | #219 | 8e894fe | QUIC transport-params fuzz corpus expanded with 26 new seeds (>=30 total) |
| SEC-063 | Low (4) | #222 | 106a287 | `.semgrepignore` entry added for `specs/**/*.txt`; RFC canonical PEM FPs silenced |
| SEC-064 | Low (12) | #226 | 4ae8ac7 | Legacy `src/tls13/engine.zig` (-2283 LOC) deleted; divergence vector eliminated |

## Phase 11 Alert (RESOLVED 2026-04-18)

**SEC-057 (HIGH regression, Risk 60) — CLOSED 2026-04-18:** `src/tls13/messages/client_hello.zig:403-404` used `@enumFromInt(alg)` on attacker-controlled `signature_algorithms` values filtered only by range, not by the exhaustive enum set. Result: **pre-auth remote DoS** against any TLS 1.3 server using this parser. Panic in Debug / ReleaseSafe / ReleaseSmall; UB in ReleaseFast. Fixed by replacing the unchecked cast with `std.enums.fromInt(SignatureScheme, alg) orelse continue;`. Regression test at `tests/security/sec057_sigalg_panic.zig`. Commits: 98ccfad (test), 39a20b3 (fix). Confidential issue [#162](https://gitlab.com/devnw/zig/tls/-/issues/162) to be closed post-merge.

## Summary

| Risk Level | Open | Closed | Won't Do | Acceptable Risk | Total |
|-----------|------|--------|----------|-----------------|-------|
| Critical  | 0    | 0      | 0        | 0               | 0     |
| High      | 1    | 11     | 0        | 0               | 12    |
| Medium    | 0    | 21     | 0        | 0               | 21    |
| Low       | 0    | 27     | 4        | 0               | 31    |
| Info      | 0    | 5      | 1        | 3               | 9     |
| **Total** | **1** | **64** | **5**   | **3**           | **73** |

*Counts reflect Cycle 6 / Phase 19 closure (2026-04-20):* +8 Closed (SEC-066, SEC-067, SEC-068, SEC-069, SEC-070, SEC-071, SEC-072, SEC-073); SEC-065 remains the sole Open item (deferred — Config API mini-epic).

**Phase 13** (2026-04-19) closed all 4 remaining open SEC findings (SEC-061, SEC-062, SEC-063, SEC-064). **Posture is now STRONG: 0 open at every risk level.** **Phase 12** filed the 4 LOW findings and attached the Phase 3 SHA-pinning patch draft to SEC-061.

**Phase 11** added 5 new findings (SEC-057 through SEC-061) plus 3 info-only notes (NEW-SEC-04, NEW-SEC-05, NEW-SEC-08). As of 2026-04-18, 4 of the 5 new findings (SEC-057, SEC-058, SEC-059, SEC-060) are closed by in-branch remediation; SEC-061 remains open under its 180-day SLA.

**Phase 10** added 8 new findings from adversarial review (SEC-049 through SEC-056). All resolved: 5 closed via code changes, 3 Info accepted as documented risk.

### Phase 12 Findings (2026-04-19 cross-domain audit)

All 3 new findings are **LOW / Open**. They complement SEC-061 (still Open) and do not alter the 0 Critical / 0 High baseline.

- **SEC-062** — **CLOSED (2026-04-19, commit 8e894fe) / Low / Risk 8**: QUIC transport-params fuzz corpus expanded with 26 new seeds (>=30 total) covering each param-ID happy path, zero-length, max-varint, duplicates, server-only role violations, GREASE IDs, TP length > record, malformed PreferredAddress. Issue: [#219](https://gitlab.com/devnw/zig/tls/-/issues/219).
- **SEC-063** — **CLOSED (2026-04-19, commit 106a287) / Low / Risk 4**: Added `.semgrepignore` entry for `specs/**/*.txt` with SEC-063 annotation; RFC canonical PEM false-positives silenced on next scan. Issue: [#222](https://gitlab.com/devnw/zig/tls/-/issues/222).
- **SEC-064** — **CLOSED (2026-04-19, commit 4ae8ac7) / Low / Risk 12**: Legacy `src/tls13/engine.zig` (-2236 LOC file + -47 LOC re-exports = -2283 LOC net) deleted in full per unanimous Phase 3 cross-domain recommendation and the `delete-over-patch` operating rule. All acceptance criteria met: re-exports from `src/tls13/mod.zig` removed, fuzz harnesses retargeted, `zig build test` green 586/588, linked QUAL-319 and PERF-023/040/217/219/220/226 closures filed. Issue: [#226](https://gitlab.com/devnw/zig/tls/-/issues/226).

#### Phase 12 SEC-061 update (no state change)

Phase 3 security reviewer produced a concrete SHA-pinning patch template for `.gitlab-ci.yml:11-24` (8 imports). Patch draft and SHA-resolution procedure (`glab api projects/devnw%2Fci-catalog/repository/tags/v1.7.1` and `v1.2.1` for zig-format) were posted as a comment on [#184](https://gitlab.com/devnw/zig/tls/-/issues/184) on 2026-04-19. Issue remains **Open**; implementation deferred to a follow-up MR.

#### Phase 12 Verification notes (no issue filed)

- **NEW-03**: `src/quic_transport_params.zig:223` exhaustive-enum struct uses the non-exhaustive `_,` marker; the switch at `src/quic_transport_params.zig:675` employs a `_ =>` arm with `continue` per RFC 9000 §7.4 (ignore unknown TP IDs). **Confirmed clean — no finding filed.**

---

### Phase 11 Findings (2026-04-18 audit)

- **SEC-057** — **CLOSED 2026-04-18 / HIGH / Risk 60** (regression): Unauthenticated remote DoS via `@enumFromInt` on `signature_algorithms`. `src/tls13/messages/client_hello.zig:403-404`. Range filter `0x0401 ≤ alg ≤ 0x080b` admitted ~2034 values vs. 14 valid enum tags. Sibling `ExtensionType` parser at line 337 used safe `std.enums.fromInt(...) orelse` pattern. CWE-754 / A05:2021. Confidential issue: [#162](https://gitlab.com/devnw/zig/tls/-/issues/162). **Resolution:** 2026-04-18 — Replaced `@enumFromInt(alg)` with `std.enums.fromInt(SignatureScheme, alg) orelse continue` at `src/tls13/messages/client_hello.zig:406`. Regression test at `tests/security/sec057_sigalg_panic.zig` asserts no panic across the full 0x0401..0x080b range. Commits: 98ccfad, 39a20b3.
- **SEC-058** — **CLOSED 2026-04-18 / Medium / Risk 36** (32-bit only): DoS via `@intCast(varint length)` before bounds check. `src/quic_transport_params.zig:572-578`. On 32-bit targets, a TP length ≥ 2^32 panicked in `@intCast` before the subsequent `offset + len > data.len` guard. CWE-190/681. Issue: [#167](https://gitlab.com/devnw/zig/tls/-/issues/167). **Resolution:** 2026-04-18 — Validated varint length in u64 space before narrowing cast at `src/quic_transport_params.zig:572-586`. Regression tests at `tests/security/sec058_tp_length_overflow.zig`. Commits: a05193c, aac7bbe.
- **SEC-059** — **CLOSED 2026-04-18 / Low / Risk 4**: Missing `errdefer` in parallel AEAD tests. `src/parallel.zig:893,925`. Test allocator catches the leak; fix is hygiene. CWE-401. Issue: [#173](https://gitlab.com/devnw/zig/tls/-/issues/173). **Resolution:** 2026-04-18 — Added `filled` counter + scope-exit defer in both affected test loops at `src/parallel.zig:873-944`. Commit: 62c915b.
- **SEC-060** — **CLOSED 2026-04-18 / Medium / Risk 24** (operational / SDL): Fuzz corpus not persisted (`artifacts: when: on_failure`) + `allow_failure: true` at both job and rule scope + 60s budget. `.gitlab-ci.yml:138-164`. **Root cause the CI lane failed to catch SEC-057.** OWASP A08/A09. Issue: [#181](https://gitlab.com/devnw/zig/tls/-/issues/181). **Resolution:** 2026-04-18 — CI fuzz job is now a real gate: removed `allow_failure:true`, added `cache:` stanza (pull-push, branch-keyed), extended rules to `merge_request_event`+`push`, and seeded the corpus with prior-regression inputs under `tests/fuzz/corpus/`. Commits: 53d581d, 67cb0c8.
- **SEC-061** — **CLOSED (2026-04-19, commit b864812) / Low / Risk 6**: All 8 CI catalog component imports pinned to immutable commit SHAs in `.gitlab-ci.yml:11-24`. Supply-chain posture now matches `build.zig.zon` dependency pinning. Issue: [#184](https://gitlab.com/devnw/zig/tls/-/issues/184).

#### Phase 11 Informational Notes (no issue filed)

- **NEW-SEC-04**: Audited all 8 other production `@enumFromInt` sites — all are safe (operate on values already constrained by exhaustive parse-then-match or are on trusted internal data). Only `client_hello.zig:404` (SEC-057) was unsafe.
- **NEW-SEC-05**: Audited `@intCast` sites on attacker-controlled lengths — all other sites bound the source value appropriately before narrowing. Only `quic_transport_params.zig:577` (SEC-058) is missing the 32-bit guard.
- **NEW-SEC-08**: Dependency pinning in `build.zig.zon:36-43` is correct — each dep is pinned via URL tarball + commit SHA + content hash. This is the "correct" pattern that `.gitlab-ci.yml` should emulate for its catalog imports (SEC-061).

#### Phase 11 Regression Verification (prior HIGH/CRITICAL fixes — all intact)

| Prior ID | Prior Title | File(s) | Verified Intact |
|----------|-------------|---------|-----------------|
| SEC-054 | Memory leak in `parseClientHello` on error paths (errdefer) | `client_hello.zig:295-497` | INTACT |
| SEC-029 | Hostname validation fail-open when `server_name` null | `context.zig:2955`, `types.zig` | INTACT |
| SEC-031 | mTLS client cert missing `clientAuth` EKU | `x509.zig:321-332`, `context.zig:3172` | INTACT |
| SEC-028 | Client did not validate server cipher against offered list | `context.zig:2511-2522` | INTACT |
| SEC-026 | OCSP `compareSlices` non-constant-time | `ocsp.zig:143` | INTACT |
| SEC-046 | PSK identity comparison non-constant-time | `context.zig:1825` | INTACT |

**SEC-057 was the only regression/new High-severity finding this phase. Remediated 2026-04-18 (see Resolution note above).**

---

### Phase 10 Findings (Adversarial Review)

- **SEC-049** -- **CLOSED** (Low, Risk 2.0): Added `@compileError` guards on 4 trace flags: `engine.zig:114`, `transcript.zig:78`, `messages.zig:17`, `ocsp.zig:22`. CWE-215. All trace flags now have compile-time guards matching the `context.zig` pattern.
- **SEC-050** -- **CLOSED** (Medium, Risk 4.5): Added `defer secureZero` for X25519 private key in `startClientHandshake` and `sendClientHello2` at `context.zig`. CWE-226. Private keys now zeroed on all exit paths.
- **SEC-051** -- **ACCEPTABLE RISK** (Info, Risk 0.5): Missing X25519 clamping in `x25519KeypairAndShared` at `messages.zig:237-256`. Non-issue: Zig stdlib clamps internally; function unused in production.
- **SEC-052** -- **CLOSED** (Low, Risk 1.5): Added `IntegerOverflow` guard in `readInteger` for values >8 bytes at `asn1.zig:465-474`. CWE-190. Rejects oversized integers instead of silent truncation.
- **SEC-053** -- **ACCEPTABLE RISK** (Info, Risk 0.3): `encodeHandshake` no 24-bit length check at `messages.zig:91`. CWE-190. Practically unexploitable due to allocation limits.
- **SEC-054** -- **CLOSED** (Low, Risk 2.0): Added errdefer for all allocated slices in `parseClientHello` at `client_hello.zig:295-497`. CWE-401. Memory properly cleaned on all error paths.
- **SEC-055** -- **CLOSED** (Low, Risk 2.0): `client_priv` zeroed after DH computation at `context.zig:2317-2343` via `handleServerHello`. CWE-226. Private key no longer retained until `deinit()`.
- **SEC-056** -- **ACCEPTABLE RISK** (Info, Risk 0.5): Unconditional `logger.debugPrint` in error paths at `messages.zig:178`, `engine.zig:660+`. CWE-209. Not gated by trace flags, but `debugPrint` is a no-op in release.

### Phase 9 Closures

- **SEC-009** -- **CLOSED** (Low): `x25519KeypairAndShared` now returns `X25519Error!X25519Result` error union. File: `src/tls13/messages.zig:228-248`
- **SEC-045** -- **CLOSED** (Info): `@ptrCast` replaced with field-by-field conversion for PSK binder/identity. File: `src/tls13/context.zig:452-489`
- **SEC-039** -- **CLOSED** (Info): `@compileError` guard added for `handshake_trace_enabled` in release builds, matching secret trace pattern. File: `src/tls13/context.zig:121-126`
- **SEC-010** -- **WON'T DO** (Low): OCSP digest comparison uses non-secret public data; `std.mem.eql` is appropriate
- **SEC-011** -- **WON'T DO** (Low): Downgrade sentinel values are public RFC 8446 constants; timing leakage does not benefit an attacker
- **SEC-012** -- **WON'T DO** (Low): Compile-time guard already prevents debug trace of private key scalar in release builds
- **SEC-013** -- **WON'T DO** (Low): P-256 DER lengths always fit u8; Zig's `@intCast` is runtime bounds-checked
- **SEC-038** -- **WON'T DO** (Info): TOCTOU window is benign; Zig lacks dynamic library unloading; trust store changes during handshake are administrative

### Phase 8 Closures

- **SEC-047** -- **CLOSED** (HIGH): Engine `computeApplicationSecrets` now uses `emptyHash()` for context and `zeroSecret()` for IKM per RFC 8446 Section 7.1. Fixed at `engine.zig:1510-1516`.
- **SEC-040** -- **CLOSED** (Low): `startClientHandshake` now has explicit X25519 clamping at `context.zig:2181-2187`. [Issue #126](https://gitlab.com/devnw/zig/tls/-/issues/126)
- **SEC-048** -- **CLOSED** (Low): Server `negotiateCipherAndKeys` now has explicit X25519 clamping at `context.zig:1959-1965`. [Issue #127](https://gitlab.com/devnw/zig/tls/-/issues/127)
- **SEC-046** -- **CLOSED** (Low): PSK identity comparison now uses `timing_safe.compare` at `context.zig:1825`.

### Phase 7 Closures (Security Reviewer)

- **SEC-042** -- **CLOSED**: `deriveHandshakeTraffic` intermediates now zeroized via `defer std.crypto.secureZero` on `derived.bytes`
- **SEC-043** -- **CLOSED**: `deriveApplicationTraffic` intermediates now zeroized via `defer std.crypto.secureZero` on `derived.bytes` and `master.bytes`
- **SEC-041** -- **CLOSED**: `expandLabelHash` PRK copy now zeroized via `defer std.crypto.secureZero` on `arr` in both sha256/sha384 branches
- **SEC-044** -- **CLOSED**: `expandLabelHash` fbb buffer now zeroized via `defer std.crypto.secureZero` on `fbb`
- **SEC-045** -- **CLOSED** (Info): `@ptrCast` replaced with field-by-field conversion at `context.zig:452-489` (Phase 9)

### Recently Closed (Phase 6 -- Round 3)

- **SEC-028** -- CLOSED: Client validates server-selected cipher suite against offered list in `context.zig:2511-2522`
- **SEC-029** -- CLOSED: `MissingServerName` error returned when `server_name` is null in `context.zig:2955`, `types.zig`, `alert.zig`
- **SEC-030** -- CLOSED: Self-signed cert now gets hostname and EKU validation in `x509.zig:1567-1572`
- **SEC-031** -- CLOSED: mTLS client cert validated for `clientAuth` EKU via `EkuPurpose` enum in `x509.zig:321-332`, `context.zig:3172`, `engine.zig`, `parallel.zig`
- **SEC-032** -- CLOSED: `validateTimeFields` validates month/day/hour/min/sec ranges in `x509.zig:603-612`
- **SEC-033** -- CLOSED: `matchesNameConstraint` uses `toLowerAscii` case-insensitive comparison in `x509.zig:1131-1151`
- **SEC-034** -- CLOSED: Dependency pinned to commit SHA `bbf106dc8131` in `build.zig.zon:38`
- **SEC-035** -- CLOSED: HRR `session_id` bounds-checked: `if (pos + 1 + sid_len > body.len)` in `context.zig:1456`
- **SEC-036** -- CLOSED: Old `client_priv` zeroized via `secureZero` before HRR rekey in `context.zig:1534-1538`
- **SEC-037** -- CLOSED: Explicit X25519 clamping (`priv[0] &= 248; priv[31] &= 127; priv[31] |= 64`) in `context.zig:1543-1549`

### Previously Closed (Phases 1-5)

- **SEC-014** -- CLOSED (Phase 5): Duplicate of SEC-027. Dead `.rsa_pss_sha256` fallback already removed; `engine.zig:836-840` now uses `continue`. Resolved by SEC-027 closure.
- **SEC-004-R** -- CLOSED: Ed25519 KeyPair `secret_key.bytes` zeroized via `defer secureZero` in `sig.zig`
- **SEC-015** -- CLOSED: Context ECDHE `server_priv` zeroized via `defer secureZero` in `context.zig`
- **SEC-016** -- CLOSED: Context ECDHE shared secret zeroized (server+client) via `defer secureZero` in `context.zig`
- **SEC-017** -- CLOSED: TicketStore capped at `max_tickets=16` with FIFO eviction in `engine.zig`
- **SEC-018** -- CLOSED: CRYPTO buffer 64KB limit enforced in `context.zig` and `engine.zig`
- **SEC-019** -- CLOSED: `setAllowInsecure` with `@panic` in release mode in `engine.zig`
- **SEC-020** -- CLOSED: Finished failure returns `error.HandshakeFailure` in `engine.zig`
- **SEC-021** -- CLOSED: `cert_ok` check added to `handshakeComplete()` in `engine.zig`
- **SEC-023** -- CLOSED: `defer secureZero(u8, &sk)` added on all paths in `messages.zig`
- **SEC-024** -- CLOSED: `max_chain_depth=10` enforced in `x509.zig`
- **SEC-025** -- CLOSED: Trace message added for absent EKU, RFC 5280 compliant
- **SEC-026** -- CLOSED: Switched to `timing_safe.compare` in `ocsp.zig`
- **SEC-027** -- CLOSED: Dead fallback removed, replaced with `continue` in `engine.zig`

### Positive Observations

- Finished verification uses `timing_safe.eql` correctly (both Context and Engine)
- PSK binder verification uses constant-time comparison
- OCSP response verification uses constant-time comparison
- HRR cookie validation uses `timing_safe.eql`
- AEAD tag verification is constant-time via `std.crypto`
- `secret_trace_enabled` has `@compileError` guards in ALL files
- `allow_insecure` has runtime panic in release builds
- AEAD usage limits enforced per RFC 8446 Section 5.5
- Shared secrets properly zeroed with `defer secureZero`
- `Engine.deinit` and `Context.deinit` comprehensively zero keying material
- `SecretSlot.clear` uses `secureZero` (fixed in cf6586c)
- `client_priv` is zeroized in `Context.deinit` (verified at context.zig:951-954)
- Anti-replay protection implemented for 0-RTT

---

## Stack-Ranked Findings

| Rank | ID | Severity | Risk Score | Finding | Component | CWE / OWASP | Evidence | Issue URL | Fix | Owner | Due | Status |
|------|----|----------|------------|---------|-----------|-------------|----------|-----------|-----|-------|-----|--------|
| 0a | **SEC-057** | **High** | **60** | **Unauthenticated remote DoS via `@enumFromInt` on signature_algorithms (regression)** | `client_hello.zig` | CWE-754 / A05:2021 | `src/tls13/messages/client_hello.zig:403-404` | [#162](https://gitlab.com/devnw/zig/tls/-/issues/162) (confidential) | Replaced unchecked `@enumFromInt(alg)` with `std.enums.fromInt(SignatureScheme, alg) orelse continue;` matching `ExtensionType` pattern at line 337 | Claude | 2026-04-18 | **Closed** |
| 0b | **SEC-058** | **Medium** | **36** | DoS via `@intCast(varint length)` before bounds check on 32-bit builds | `quic_transport_params.zig` | CWE-190, CWE-681 / A05:2021 | `src/quic_transport_params.zig:572-578` | [#167](https://gitlab.com/devnw/zig/tls/-/issues/167) | Compared `length` in u64 vs `data.len` / `maxInt(usize)` before `@intCast` | Claude | 2026-04-18 | **Closed** |
| 0c | **SEC-060** | **Medium** | **24** | Fuzz corpus not persisted + `allow_failure:true` hides regressions (root cause of SEC-057 CI miss) | `.gitlab-ci.yml` | CWE-1269 / A08:2021, A09:2021 | `.gitlab-ci.yml:138-164` | [#181](https://gitlab.com/devnw/zig/tls/-/issues/181) | Removed `allow_failure: true`, persisted corpus via branch-keyed cache, extended rules, seeded regression corpus | Claude | 2026-04-18 | **Closed** |
| 0d | **SEC-061** | **Low** | **6** | CI catalog components pinned to mutable tags, not immutable SHAs | `.gitlab-ci.yml` | CWE-829 / A08:2021 | `.gitlab-ci.yml:11-24` | [#184](https://gitlab.com/devnw/zig/tls/-/issues/184) | Pin 8 catalog imports to 40-char commit SHAs (or protect tags against force-update) | -- | 2026-10-15 (180d) | **Open** |
| 0e | **SEC-059** | **Low** | **4** | Missing `errdefer` in parallel AEAD tests (test hygiene) | `parallel.zig` | CWE-401 / A04:2021 | `src/parallel.zig:893, 925` | [#173](https://gitlab.com/devnw/zig/tls/-/issues/173) | Added `filled` counter + scope-exit defer freeing `outputs[0..filled]` | Claude | 2026-04-18 | **Closed** |
| 1 | SEC-029 | High | 80 | Hostname validation silently skipped when server_name is null | `context.zig`, `x509.zig` | CWE-295 / A07:2021 | `context.zig:2955`, `types.zig:218` | -- | Fail-closed: MissingServerName error when server_name is null | Claude | 2026-03-24 | Closed |
| 2 | SEC-028 | High | 64 | Client does not validate server-selected cipher suite was in offered list | `context.zig` | CWE-757 / A02:2021 | `context.zig:2511-2522` | -- | Cipher suite validated against offered list per RFC 8446 Section 4.1.3 | Claude | 2026-03-24 | Closed |
| 3 | SEC-030 | Medium | 48 | Self-signed cert bypasses EKU, hostname, and KeyUsage checks | `x509.zig` | CWE-295, CWE-863 / A07:2021 | `x509.zig:1567-1572` | -- | Hostname and EKU checks now applied to self-signed certs | Claude | 2026-03-24 | Closed |
| 4 | SEC-032 | Medium | 48 | parseDerTime accepts invalid month/day values | `x509.zig` | CWE-1284, CWE-125 / A07:2021 | `x509.zig:603-612` | -- | validateTimeFields validates month/day/hour/min/sec ranges | Claude | 2026-03-24 | Closed |
| 5 | SEC-033 | Medium | 48 | matchesNameConstraint uses case-sensitive comparison | `x509.zig` | CWE-178 / A07:2021 | `x509.zig:1131-1151` | -- | Uses toLowerAscii case-insensitive comparison per RFC 5280 Section 4.2.1.10 | Claude | 2026-03-24 | Closed |
| 6 | SEC-001 | High | 42.0 | Client mTLS always signs with ed25519 | `context.zig` | CWE-295 / A07:2021 | `context.zig:2691` | -- | Client mTLS now negotiates signature scheme from CertificateRequest | Claude | 2026-03-24 | Closed |
| 7 | SEC-047 | High | 36 | Engine computeApplicationSecrets uses wrong context hash and IKM for master secret | `engine.zig` | CWE-327 / A02:2021 | `engine.zig:1510-1516` | [#123](https://gitlab.com/devnw/zig/tls/-/issues/123) (confidential) | Uses `emptyHash()` for context and `zeroSecret()` for IKM per RFC 8446 S7.1 | Claude | 2026-03-24 | Closed |
| 8 | SEC-031 | Medium | 36 | mTLS client cert validation skips clientAuth EKU check | `context.zig`, `x509.zig` | CWE-295 / A07:2021 | `x509.zig:321-332`, `context.zig:3172` | -- | EkuPurpose enum added; validateChain passes .client_auth for mTLS | Claude | 2026-03-24 | Closed |
| 9 | SEC-034 | Medium | 32 | Dependency fetched from mutable main branch URL | `build.zig.zon` | CWE-829 / A08:2021 | `build.zig.zon:38` | -- | Dependency pinned to commit SHA bbf106dc8131 | Claude | 2026-03-24 | Closed |
| 10 | SEC-002 | High | 32.0 | `SecretSlot.clear()` missing `secureZero` | `context.zig` | CWE-226 / A02:2021 | `context.zig:285-291` | -- | Added `std.crypto.secureZero` to `SecretSlot.clear()` | Claude | 2026-03-24 | Closed |
| 11 | SEC-003 | High | 24.3 | ECDSA P-256 scalar not zeroized after signing | `sig.zig` | CWE-226 / A02:2021 | `sig.zig:559-645` | -- | Added `defer std.crypto.secureZero(u8, &sk)` | Claude | 2026-03-24 | Closed |
| 12 | SEC-004 | High | 24.3 | Ed25519 seed not zeroized after signing | `sig.zig` | CWE-226 / A02:2021 | `sig.zig:544-555` | -- | Seed zeroized; **keypair NOT zeroized** (see SEC-004-R) | Claude | 2026-03-24 | Closed (partial) |
| 13 | SEC-035 | Low | 24 | HRR session_id length not bounds-checked against body.len | `context.zig` | CWE-120 / A07:2021 | `context.zig:1456` | -- | Bounds check added: `if (pos + 1 + sid_len > body.len)` | Claude | 2026-03-24 | Closed |
| 14 | SEC-005 | Medium | 16.0 | `allow_insecure` no compile-time guard for release | `config.zig` | CWE-1188 / A05:2021 | `config.zig:271` | -- | Added runtime panic guard in `Context.init()` | Claude | 2026-03-24 | Closed |
| 15 | SEC-036 | Low | 16 | Client private key not zeroized on HRR rekey path | `context.zig` | CWE-226 / A02:2021 | `context.zig:1534-1538` | -- | Old client_priv secureZero'd before HRR rekey overwrite | Claude | 2026-03-24 | Closed |
| 16 | SEC-006 | Medium | 14.0 | `else => .ed25519` signing fallback masks unknown schemes | `context.zig` | CWE-394 / A07:2021 | `context.zig:2277,2697` | -- | Replaced with error returns | Claude | 2026-03-24 | Closed |
| 17 | SEC-004-R | High | 14.0 | Ed25519 expanded KeyPair not zeroized after signing | `sig.zig` | CWE-226 / A02:2021 | `sig.zig:547` | [#84](https://gitlab.com/devnw/zig/tls/-/issues/84) | Changed `const kp` to `var kp`; added `defer secureZero(u8, &kp.secret_key.bytes)` | Claude | 2026-03-24 | Closed |
| 18 | SEC-015 | High | 14.0 | Context ECDHE `server_priv` not zeroized | `context.zig` | CWE-226 / A02:2021 | `context.zig:2153` | [#87](https://gitlab.com/devnw/zig/tls/-/issues/87) | Added `defer secureZero(u8, &server_priv)` in context.zig | Claude | 2026-03-24 | Closed |
| 19 | SEC-016 | High | 13.0 | Context ECDHE shared secret not zeroized (server+client) | `context.zig` | CWE-226 / A02:2021 | `context.zig:2163,2677` | [#91](https://gitlab.com/devnw/zig/tls/-/issues/91) | Changed `const shared` to `var shared`; added `defer secureZero` on both paths | Claude | 2026-03-24 | Closed |
| 20 | SEC-007 | Medium | 12.6 | No CRL checking; OCSP is optional | `x509.zig` | CWE-299 / A07:2021 | `x509.zig:1451-1479` | -- | Document limitation; add `require_ocsp` enforcement path | -- | 90 days | Closed |
| 21 | SEC-037 | Low | 12 | sendClientHello2 does not explicitly clamp X25519 private key | `context.zig` | CWE-326 / A02:2021 | `context.zig:1543-1549` | -- | Explicit X25519 clamping added (priv[0]&=248, priv[31]&=127\|=64) | Claude | 2026-03-24 | Closed |
| 22 | SEC-038 | Info | 12 | Global mutable TrustStore creates theoretical TOCTOU window | `x509.zig` | CWE-367 / A04:2021 | `x509.zig:134-155` | -- | Won't Do: Benign; Zig lacks dynamic library unloading | -- | -- | Won't Do |
| 23 | SEC-017 | Medium | 10.0 | TicketStore unbounded growth (DoS) | `engine.zig` | CWE-770 / A05:2021 | `engine.zig:128-151` | [#93](https://gitlab.com/devnw/zig/tls/-/issues/93) | Added max_tickets=16 with FIFO eviction; secrets zeroized on eviction | Claude | 2026-03-24 | Closed |
| 24 | SEC-018 | Medium | 10.0 | CRYPTO inbound/inbox buffer unbounded (Context + Engine) | `context.zig`, `engine.zig` | CWE-770 / A05:2021 | `context.zig:1033`, `engine.zig:437` | [#95](https://gitlab.com/devnw/zig/tls/-/issues/95) | Added 64KB MAX_HANDSHAKE_BUFFER limit in both context.zig and engine.zig | Claude | 2026-03-24 | Closed |
| 25 | SEC-019 | Medium | 9.0 | Engine `allow_insecure` no release guard | `engine.zig` | CWE-295 / A05:2021 | `engine.zig:207` | [#96](https://gitlab.com/devnw/zig/tls/-/issues/96) | Added `setAllowInsecure` with `@panic` in release builds matching Context pattern | Claude | 2026-03-24 | Closed |
| 26 | SEC-040 | Low | 8 | `startClientHandshake` missing X25519 clamping | `context.zig` | CWE-326 / A02:2021 | `context.zig:2181-2187` | [#126](https://gitlab.com/devnw/zig/tls/-/issues/126) | Explicit X25519 clamping added (priv[0]&=248, priv[31]&=127\|=64) | Claude | 2026-03-24 | Closed |
| 27 | SEC-039 | Info | 8 | Handshake trace may leak error details in production | `context.zig` | CWE-209 / A09:2021 | `context.zig:121-126` | -- | `@compileError` guard added for `handshake_trace_enabled` in release builds | Claude | 2026-03-24 | Closed |
| 28 | SEC-020 | Medium | 8.0 | Engine Finished verification failure is non-fatal | `engine.zig` | CWE-287 / A07:2021 | `engine.zig:768-792` | [#97](https://gitlab.com/devnw/zig/tls/-/issues/97) | Finished failure now returns `error.HandshakeFailure`; prevents app data exchange | Claude | 2026-03-24 | Closed |
| 29 | SEC-021 | Medium | 8.0 | Engine cert validation failure non-fatal in processing loop | `engine.zig` | CWE-295 / A07:2021 | `engine.zig:621-765` | [#98](https://gitlab.com/devnw/zig/tls/-/issues/98) | Added `cert_ok` check to `handshakeComplete()`; cert failure now gates handshake | Claude | 2026-03-24 | Closed |
| 30 | SEC-008 | Medium | 7.0 | `x25519KeypairAndShared` missing sk zeroize on error (engine.zig) | `engine.zig` | CWE-226 / A02:2021 | `engine.zig:1723-1736` | -- | Added `defer std.crypto.secureZero` | Claude | 2026-03-24 | Closed |
| 31 | SEC-023 | Medium | 7.0 | `x25519KeypairAndShared` priv_key not zeroized on success path | `messages.zig` | CWE-226 / A02:2021 | `messages.zig:191-209` | [#76](https://gitlab.com/devnw/zig/tls/-/issues/76) | Added `defer secureZero(u8, &sk)` on all paths in messages.zig | Claude | 2026-03-24 | Closed |
| 32 | SEC-046 | Low | 6 | PSK identity comparison non-constant-time | `context.zig` | CWE-208 / A02:2021 | `context.zig:1825` | -- | Replaced `std.mem.eql` with `timing_safe.compare` for PSK identity lookup | Claude | 2026-03-24 | Closed |
| 33 | SEC-048 | Low | 6 | Server `negotiateCipherAndKeys` missing X25519 clamping | `context.zig` | CWE-326 / A02:2021 | `context.zig:1959-1965` | [#127](https://gitlab.com/devnw/zig/tls/-/issues/127) | Explicit X25519 clamping added (priv[0]&=248, priv[31]&=127\|=64) | Claude | 2026-03-24 | Closed |
| 34 | SEC-009 | Low | 6.0 | `x25519KeypairAndShared` returns value instead of error on failure | `messages.zig` | CWE-252 / A07:2021 | `messages.zig:228-248` | -- | Returns `X25519Error!X25519Result` error union; callers must handle error | Claude | 2026-03-24 | Closed |
| 35 | SEC-024 | Low | 5.0 | Certificate chain no depth limit | `x509.zig` | CWE-770 / A05:2021 | `x509.zig:1480` | [#99](https://gitlab.com/devnw/zig/tls/-/issues/99) | Added `max_chain_depth=10` guard before allocation in x509.zig | Claude | 2026-03-24 | Closed |
| 36 | SEC-050 | Medium | 4.5 | Private key not zeroed on error in `startClientHandshake` | `context.zig` | CWE-226 / A02:2021 | `context.zig:2134-2144` | -- | Added `defer secureZero` for X25519 priv in `startClientHandshake` and `sendClientHello2` | Claude | 2026-03-25 | **Closed** |
| 37 | SEC-042 | Low | 4 | `deriveHandshakeTraffic` intermediates not zeroized | `key_derivation.zig` | CWE-226 / A02:2021 | `key_derivation.zig:218-222` | -- | Added `defer std.crypto.secureZero(u8, &derived.bytes)` | Claude | 2026-03-24 | **Closed** |
| 38 | SEC-043 | Low | 4 | `deriveApplicationTraffic` intermediates not zeroized | `key_derivation.zig` | CWE-226 / A02:2021 | `key_derivation.zig:340-351` | -- | Added `defer std.crypto.secureZero` on `derived.bytes` and `master.bytes` | Claude | 2026-03-24 | **Closed** |
| 39 | SEC-025 | Low | 4.0 | EKU absent check not enforced (Engine) | `engine.zig` | CWE-295 / A07:2021 | `engine.zig:688-693` | [#100](https://gitlab.com/devnw/zig/tls/-/issues/100) | Added trace message for absent EKU; documented RFC 5280 compliant permissiveness | Claude | 2026-03-24 | Closed |
| 40 | SEC-041 | Low | 3 | `expandLabelHash` PRK copy not zeroized | `key_schedule.zig` | CWE-226 / A02:2021 | `key_schedule.zig:143-150` | -- | Added `defer std.crypto.secureZero(u8, &arr)` in both sha256/sha384 branches | Claude | 2026-03-24 | **Closed** |
| 41 | SEC-026 | Low | 3.0 | OCSP `compareSlices` non-constant-time | `ocsp.zig` | CWE-208 / A02:2021 | `ocsp.zig:143` | [#101](https://gitlab.com/devnw/zig/tls/-/issues/101) | Switched to `timing_safe.compare` for defense-in-depth | Claude | 2026-03-24 | Closed |
| 42 | SEC-027 | Low | 3.0 | Engine CertificateVerify unknown scheme dead fallback | `engine.zig` | CWE-697 / A07:2021 | `engine.zig:744-748` | [#102](https://gitlab.com/devnw/zig/tls/-/issues/102) | Removed dead `.rsa_pss_sha256` fallback; replaced with `continue` | Claude | 2026-03-24 | Closed |
| 43 | SEC-045 | Info | 2 | `@ptrCast` on PSK binder/identity bypasses type safety | `context.zig` | CWE-843 / A07:2021 | `context.zig:452-489` | -- | Replaced `@ptrCast` with explicit field-by-field conversion | Claude | 2026-03-24 | **Closed** |
| 44 | SEC-049 | Low | 2.0 | Missing `@compileError` guards on 4 trace flags | `engine.zig`, `transcript.zig`, `messages.zig`, `ocsp.zig` | CWE-215 / A09:2021 | `engine.zig:114`, `transcript.zig:78`, `messages.zig:17`, `ocsp.zig:22` | -- | Added `@compileError` guards on all 4 files matching `context.zig` pattern | Claude | 2026-03-25 | **Closed** |
| 45 | SEC-054 | Low | 2.0 | Memory leak in `parseClientHello` on error paths | `client_hello.zig` | CWE-401 / A05:2021 | `client_hello.zig:295-497` | -- | Added errdefer for all allocated slices in `parseClientHello` | Claude | 2026-03-25 | **Closed** |
| 46 | SEC-055 | Low | 2.0 | `client_priv` retained after DH computation | `context.zig` | CWE-226 / A02:2021 | `context.zig:2317-2343` | -- | Zeroed `client_priv` after DH computation in `handleServerHello` | Claude | 2026-03-25 | **Closed** |
| 47 | SEC-052 | Low | 1.5 | ASN.1 `readInteger` silent truncation >8 bytes | `asn1.zig` | CWE-190 / A07:2021 | `asn1.zig:465-474` | -- | Added `IntegerOverflow` guard in `readInteger` for values >8 bytes | Claude | 2026-03-25 | **Closed** |
| 48 | SEC-010 | Low | 1.0 | OCSP digest comparison uses `std.mem.eql` | `ocsp.zig` | CWE-208 / A02:2021 | `ocsp.zig:140-141` | -- | Won't Do: Non-secret public data; `std.mem.eql` is appropriate | -- | -- | Won't Do |
| 49 | SEC-044 | Info | 1 | `expandLabelHash` fbb buffer not zeroized | `key_schedule.zig` | CWE-226 / A02:2021 | `key_schedule.zig:134` | -- | Added `defer std.crypto.secureZero(u8, &fbb)` | Claude | 2026-03-24 | **Closed** |
| 50 | SEC-011 | Low | 1.0 | Downgrade sentinel detection uses `std.mem.eql` | `server_hello.zig` | CWE-208 / A02:2021 | `server_hello.zig:145,167,189` | -- | Won't Do: Non-secret public constants; timing leakage does not benefit attacker | -- | -- | Won't Do |
| 51 | SEC-012 | Low | 0.9 | Debug trace logs private key scalar (compile-guarded) | `sig.zig` | CWE-532 / A09:2021 | `sig.zig:564-566` | -- | Won't Do: Compile-time guard already effective in release builds | -- | -- | Won't Do |
| 52 | SEC-013 | Low | 0.6 | `@intCast` in DER encoding (bounds-checked at runtime) | `sig.zig` | CWE-681 / A07:2021 | `sig.zig:620,624,634` | -- | Won't Do: P-256 lengths always fit u8; Zig `@intCast` is runtime bounds-checked | -- | -- | Won't Do |
| 53 | SEC-051 | Info | 0.5 | Missing X25519 clamping in `x25519KeypairAndShared` | `messages.zig` | CWE-326 / A02:2021 | `messages.zig:237-256` | -- | Acceptable Risk: Zig stdlib clamps internally; function unused in production | -- | -- | Acceptable Risk |
| 54 | SEC-056 | Info | 0.5 | Unconditional `logger.debugPrint` in error paths | `messages.zig`, `engine.zig` | CWE-209 / A09:2021 | `messages.zig:178`, `engine.zig:660+` | -- | Acceptable Risk: `debugPrint` is a no-op in release builds | -- | -- | Acceptable Risk |
| 55 | SEC-053 | Info | 0.3 | `encodeHandshake` no 24-bit length check | `messages.zig` | CWE-190 / A07:2021 | `messages.zig:91` | -- | Acceptable Risk: Practically unexploitable due to allocation limits | -- | -- | Acceptable Risk |
| 56 | SEC-014 | Low | 0.3 | Dead default algorithm `.rsa_pss_sha256` for unknown scheme | `engine.zig` | CWE-394 / A07:2021 | `engine.zig:744-748` | [#102](https://gitlab.com/devnw/zig/tls/-/issues/102) | Duplicate of SEC-027; resolved by SEC-027 closure | -- | -- | Closed |

---

## Findings by Area

### Phase 11 — Findings (2026-04-18)

#### SEC-057: Unauthenticated remote DoS via `@enumFromInt` on signature_algorithms (High, Risk 60) — CLOSED 2026-04-18 (regression)

**Summary:** `src/tls13/messages/client_hello.zig:403-404` filters attacker-supplied signature scheme codes by a permissive numeric range (`0x0401..=0x080b`) then calls `@enumFromInt(alg)` without verifying the value is a member of the exhaustive `SignatureScheme` enum (14 valid tags; ~2034 values in range). Unknown-but-in-range values cause a safety-checked panic in Debug/ReleaseSafe/ReleaseSmall and undefined behavior in ReleaseFast.

**Impact:** Pre-auth remote denial of service against any TLS 1.3 server using this parser. No data compromise; process-termination impact only.

**Likelihood:** Impact 3 x Likelihood 5 (pre-auth, remote, trivial, 1-packet) x 4 = **60**. CVSS-ish 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

**Evidence:** `src/tls13/messages/client_hello.zig:400-405`:

```zig
while (a_pos + 2 <= 2 + algs_len) : (a_pos += 2) {
    const alg = helpers.readU16(ext_data[a_pos .. a_pos + 2]);
    if (alg >= 0x0401 and alg <= 0x080b) {
        try algs.append(allocator, @enumFromInt(alg)); // unchecked
    }
}
```

Sibling safe pattern at `client_hello.zig:337` for `ExtensionType`:

```zig
const ext = std.enums.fromInt(core_types.ExtensionType, ext_type) orelse { ... continue; };
```

**Attack scenario:** A ClientHello containing `signature_algorithms` extension with any in-range but non-enumerated value (e.g., `0x0500`) crashes the process. Repeatable with no auth.

**Fix guidance:** Replace line 404 with:

```zig
if (std.enums.fromInt(core_types.SignatureScheme, alg)) |scheme| {
    try algs.append(allocator, scheme);
}
```

Drop the hand-rolled range check; `fromInt` is both correct and exhaustive.

**Acceptance criteria:**

- No `@enumFromInt(SignatureScheme, ...)` on attacker bytes in this file.
- Regression test: ClientHello with `0x0500` in `signature_algorithms` parses without panic.
- Fuzz target covering the full `signature_algorithms` extension byte range passes across Debug, ReleaseSafe, ReleaseSmall, ReleaseFast.

**References:** CWE-754, CWE-1284, RFC 8446 §4.2.3 ("SHOULD ignore any algorithms that it does not recognize"), OWASP A05:2021.

**Affected paths:** `src/tls13/messages/client_hello.zig:400-405`.

**Issue:** [#162](https://gitlab.com/devnw/zig/tls/-/issues/162) (confidential — HIGH security).

**SLA:** 30 days (by 2026-05-18).

**Root-cause for CI miss:** SEC-060.

**Resolution:** 2026-04-18 — Replaced `@enumFromInt(alg)` with `std.enums.fromInt(SignatureScheme, alg) orelse continue` at `src/tls13/messages/client_hello.zig:406`. Regression test at `tests/security/sec057_sigalg_panic.zig` asserts no panic across the full 0x0401..0x080b range. Commits: 98ccfad, 39a20b3.

---

#### SEC-058: DoS via `@intCast(varint length)` before bounds check on 32-bit builds (Medium, Risk 36) — CLOSED 2026-04-18

**Summary:** In `src/quic_transport_params.zig:572-578`, the varint-decoded u64 length value is narrowed with `@intCast` to `usize` **before** the `offset + len > data.len` bounds check. On 32-bit targets, a length ≥ 2^32 panics in `@intCast` — the subsequent bounds check that would have rejected the value safely never runs.

**Impact:** Remote DoS against 32-bit builds (project supports 32-bit per commit 7ec244a). 64-bit builds unaffected because `usize == u64`.

**Likelihood:** Impact 3 x Likelihood 3 (pre-auth remote, needs 32-bit target) x 4 = **36**.

**Evidence:**

```zig
const len_result = try varint.decode(data[offset..]);
const length = len_result.value;       // u64 varint
offset += len_result.n;
const len: usize = @intCast(length);   // 32-bit panic if length >= 2^32
if (offset + len > data.len) return error.Truncated;
```

**Fix guidance:** Compare in u64 first:

```zig
if (length > @as(u64, data.len - offset)) return error.Truncated;
const len: usize = @intCast(length);
```

**Acceptance criteria:** All varint length narrowings in this file are guarded in u64 before `@intCast`; 32-bit cross-compile target passes tests; fuzz target does not panic on oversized length.

**References:** RFC 9000 §16, §18; CWE-190; CWE-681; OWASP A05:2021.

**Affected paths:** `src/quic_transport_params.zig:572-578`.

**Issue:** [#167](https://gitlab.com/devnw/zig/tls/-/issues/167).

**SLA:** 90 days (by 2026-07-17).

**Resolution:** 2026-04-18 — Validated varint length in u64 space before narrowing cast at `src/quic_transport_params.zig:572-586`. Regression tests at `tests/security/sec058_tp_length_overflow.zig`. Commits: a05193c, aac7bbe.

---

#### SEC-060: Fuzz corpus not persisted + `allow_failure:true` hides regressions (Medium, Risk 24) — CLOSED 2026-04-18

**Summary:** `.gitlab-ci.yml:138-164` fuzz job combines three neutralizing settings: 60-second budget, `artifacts: when: on_failure` (corpus discarded on success), and `allow_failure: true` (job-level and rule-level). Net effect: the fuzz lane cannot gate merges and cannot accumulate coverage across runs.

**Impact:** The fuzz control is present but inert. SEC-057 would have been caught by a real fuzz lane but landed on `main` because the lane does not fail pipelines. This is the root-cause of the SEC-057 slip.

**Likelihood:** Observed failure mode; Likelihood 3. Impact 2 (amplifier, not direct vuln). Risk **24**.

**Evidence:** `.gitlab-ci.yml:138-164` — see issue #181 for full quote.

**Fix guidance:**

1. Remove `allow_failure: true` at job level (optionally keep on `web` manual rule only).
2. Persist corpus: `artifacts: when: always` + `cache: { key: fuzz-corpus-…, paths: [zig-out/fuzz/] }`.
3. Raise scheduled budget to ≥ 10 minutes; shard by target.
4. Add scheduled nightly fuzz and surface crashes via issue-creation automation.

**Acceptance criteria:** Scheduled fuzz pipeline fails on real crash; corpus persists across runs; fuzz budget ≥ 600s on schedules; SECURITY.md documents the fuzz pipeline.

**References:** CWE-1269; OWASP A08/A09; SLSA.

**Affected paths:** `.gitlab-ci.yml:138-164`.

**Issue:** [#181](https://gitlab.com/devnw/zig/tls/-/issues/181).

**SLA:** 90 days (recommend expedite to 30 — this gates SEC-057 verification).

**Resolution:** 2026-04-18 — CI fuzz job is now a real gate: removed `allow_failure:true`, added `cache:` stanza (pull-push, branch-keyed), extended rules to `merge_request_event`+`push`, and seeded the corpus with prior-regression inputs under `tests/fuzz/corpus/`. Commits: 53d581d, 67cb0c8.

---

#### SEC-061: CI catalog components pinned to mutable tags (Low, Risk 6) — OPEN

**Summary:** `.gitlab-ci.yml:11-24` imports 8 catalog components via mutable tag references (`@v1.7.1`, `@v1.2.1`). A compromised or mistakenly-moved tag silently alters pipeline behavior (sast, dependency-scanning, secrets, gitleaks, zig-format, sbom-generate, sbom-scan, release-semantic).

**Impact:** Supply-chain hardening gap. Catalog is internal to devnw, so trust is high, but principle of least authority favors immutable refs.

**Likelihood:** Impact 3 x Likelihood 0.5 x 4 = **6**.

**Evidence:** `.gitlab-ci.yml:11-24` (8 `- component:` lines).

**Fix guidance:** Pin to 40-char commit SHAs, or protect tags against force-update/force-delete on the catalog project and document the guarantee. Compare with `build.zig.zon:36-43` (URL + SHA + content hash — the correct supply-chain pattern; see NEW-SEC-08 info note).

**Acceptance criteria:** All 8 imports at immutable refs, or protected tags + drift-alert CI job; documented in SECURITY.md.

**References:** CWE-829; OWASP A08:2021; SLSA Build L3.

**Affected paths:** `.gitlab-ci.yml:11-24`.

**Issue:** [#184](https://gitlab.com/devnw/zig/tls/-/issues/184).

**SLA:** 180 days (by 2026-10-15).

---

#### SEC-059: Missing `errdefer` in parallel AEAD tests (Low, Risk 4) — CLOSED 2026-04-18

**Summary:** Two tests in `src/parallel.zig` allocate per-iteration output buffers inside a loop without `errdefer` guarding partial progress. `std.testing.allocator` catches the functional consequence of any leak today; the fix is hygiene.

**Impact:** Test-only. Production code path is not affected.

**Likelihood:** Impact 1 x Likelihood 1 x 4 = **4**.

**Evidence:** `src/parallel.zig:893` (aes_128_gcm test) and `src/parallel.zig:925` (chacha20_poly1305 test).

**Fix guidance:** Track `allocated: usize` and add `errdefer for (outputs[0..allocated]) |out| allocator.free(out);`.

**Acceptance criteria:** Both tests free partial progress on error; no UAF from blanket `defer for &outputs`.

**References:** CWE-401.

**Affected paths:** `src/parallel.zig:893, 925`.

**Issue:** [#173](https://gitlab.com/devnw/zig/tls/-/issues/173).

**SLA:** 180 days.

**Resolution:** 2026-04-18 — Added `filled` counter + scope-exit defer in both affected test loops at `src/parallel.zig:873-944`. Commit: 62c915b.

---

#### Phase 11 Informational Notes (no issue filed)

- **NEW-SEC-04 (all other `@enumFromInt` sites safe):** Audited the full set of production `@enumFromInt` sites aside from SEC-057. All 8 other sites operate on values that have already been range-or-set-validated (e.g., `quic_transport_params.zig:583` on parameter IDs already accepted by an exhaustive switch, or values derived from internal state). Only `client_hello.zig:404` had an unchecked attacker-to-enum path.
- **NEW-SEC-05 (all other `@intCast` on attacker lengths safe):** Audited `@intCast` sites on attacker-controlled length fields. All other sites either bound the source value to a known-safe maximum before narrowing, or operate on values already limited by MAX_HANDSHAKE_BUFFER (see SEC-018). Only `quic_transport_params.zig:577` lacks the u64 bound check needed for 32-bit correctness (SEC-058).
- **NEW-SEC-08 (dependency pinning is correct):** `build.zig.zon:36-43` pins external Zig dependencies by URL tarball + SHA + content hash — the correct immutable-reference pattern. This is the gold-standard to which SEC-061 (CI catalog tags) should be raised.

---

### Authentication and Signing

#### SEC-001: Client mTLS always signs with ed25519 (High, Risk 42.0) -- CLOSED

**Summary:** On the client side, `negotiated_signature` is never populated from the server's CertificateRequest message. It always defaults to `.ed25519`, causing any non-Ed25519 client key (ECDSA P-256, RSA-PSS) to produce an invalid signature or runtime error.

**Impact:** Client mTLS authentication fails silently or produces incorrect signatures for any key type other than Ed25519. An ECDSA P-256 client certificate will be signed with the wrong algorithm, causing the server to reject the CertificateVerify. This renders mTLS non-functional for the majority of real-world PKI deployments that use ECDSA or RSA keys.

**Likelihood:** Impact 3 (authentication failure / data integrity) x Likelihood 3.5 (any mTLS client with non-Ed25519 key) x 4 = 42.0. Requires mTLS to be configured, but once configured, the failure is deterministic for non-Ed25519 keys.

**Evidence:**

`src/tls13/context.zig:2691`:

```zig
const sig_scheme = self.negotiated_signature orelse .ed25519;
```

The server-side path correctly negotiates via `selectServerSignatureScheme()` at `context.zig:1574-1589`, which iterates server and client lists and sets `self.negotiated_signature`. But on the client path, the CertificateRequest handler never extracts the server's supported signature algorithms to populate `negotiated_signature`.

**Attack scenario:** A server requests client authentication with an ECDSA P-256 certificate. The client signs with Ed25519 algorithm regardless of the actual key type. The server rejects the CertificateVerify, causing a handshake failure. In the worst case, if a server is lenient, a mismatched algorithm could cause undefined cryptographic behavior.

**Fix guidance:**

1. Parse the `signature_algorithms` extension from the CertificateRequest message on the client side.
2. Match the client's private key type against the server's offered algorithms.
3. Set `self.negotiated_signature` to the matched scheme before reaching the signing code at line 2691.
4. Return `HandshakeError.NoSignatureScheme` if no compatible algorithm is found.

**Acceptance criteria:**

- Client mTLS succeeds with ECDSA P-256 certificates against OpenSSL/BoringSSL servers.
- Client mTLS succeeds with Ed25519 certificates.
- Handshake fails cleanly (not silently) when no compatible algorithm exists.
- Unit test covers each key type with a mock CertificateRequest.

**How to verify:** Run the existing `tests/conformance/openssl/mutual_tls.zig` and `tests/conformance/boringssl/mtls_format_parity.zig` with a P-256 client certificate. Currently expected to fail.

**References:** CWE-295 (Improper Certificate Validation), OWASP A07:2021 (Identification and Authentication Failures)

**Affected paths:** `src/tls13/context.zig`

**SLA:** 30 days

---

#### SEC-006: `else => .ed25519` signing fallback masks unknown schemes (Medium, Risk 14.0) -- CLOSED

**Summary:** Both server (`context.zig:2277`) and client (`context.zig:2697`) signing paths silently fall back to Ed25519 for any unrecognized `SignatureScheme` value. This masks negotiation bugs and could cause signing with the wrong algorithm.

**Impact:** If a new signature scheme is negotiated but not mapped in the switch, the code silently signs with Ed25519 instead of returning an error. This produces an invalid CertificateVerify that may be rejected by the peer, or worse, accepted by a permissive peer despite algorithm mismatch.

**Likelihood:** Impact 3.5 x Likelihood 1 (requires a scheme outside the enumerated set) x 4 = 14.0. Low likelihood because the negotiation code only selects from known schemes, but the fallback still violates fail-safe design.

**Evidence:**

`src/tls13/context.zig:2277`:

```zig
else => .ed25519, // Default fallback
```

`src/tls13/context.zig:2697`:

```zig
else => .ed25519,
```

**Fix guidance:** Replace `else => .ed25519` with `else => return error.UnsupportedSignatureScheme` in both locations.

**Acceptance criteria:**

- Unknown signature schemes produce an explicit error, not a silent fallback.
- All existing tests pass (no test relies on the fallback behavior).

**References:** CWE-394 (Unexpected Status Code or Return Value), OWASP A07:2021

**Affected paths:** `src/tls13/context.zig`

**SLA:** 90 days

---

#### SEC-020: Engine Finished verification failure is non-fatal (Medium, Risk 8.0)

**Summary:** In `engine.zig:768-792`, when the peer's Finished message fails verification, the result is stored via `self.updateFinishedVerified(ok)` but execution continues. If `ok` is `false`, the engine does not immediately abort the handshake. Application traffic secrets are only derived when `ok == true`, but the message processing loop continues.

**Impact:** If the Finished verification failure does not prevent application data exchange, an attacker who can tamper with handshake messages could bypass the Finished MAC check and inject/modify application data. The Finished message is the TLS 1.3 handshake integrity guarantee.

**Likelihood:** Impact 4 x Likelihood 0.5 (requires active MITM + must verify that `finished_verified` is not checked downstream) x 4 = 8.0

**Evidence:**

`src/tls13/engine.zig:768-792`:

```zig
if (p.typ == .finished and self.ecdhe_secret != null) {
    // ... verification logic ...
    traceHandshake("TLS: Finished verification result: {}\n", .{ok});
    self.updateFinishedVerified(ok);
    // Execution continues regardless of 'ok' value
    if (ok) {
        // derives application secrets...
    }
}
```

When `ok` is `false`, the function does not return an error. It continues processing subsequent messages.

**How to verify:** Trace all callers of `writeAppData` and `onRecvApplicationData` to verify they check `self.finished_verified`. If any path allows data exchange without checking, this is confirmed as CWE-287.

**Fix guidance:** Return an error immediately when Finished verification fails:

```zig
self.updateFinishedVerified(ok);
if (!ok) return error.FinishedVerificationFailed;
```

**Acceptance criteria:**

- Failed Finished verification produces an immediate error return.
- No application data can be sent or received after a Finished failure.
- Existing tests pass.

**References:** CWE-287 (Improper Authentication), OWASP A07:2021, RFC 8446 Section 4.4.4

**Affected paths:** `src/tls13/engine.zig`

**Issue:** [GitLab #97](https://gitlab.com/devnw/zig/tls/-/issues/97)

**SLA:** 90 days

---

#### SEC-021: Engine certificate validation failure non-fatal in processing loop (Medium, Risk 8.0)

**Summary:** In `engine.zig:621-765`, certificate parsing and validation failures set `self.peer_cert_ok = false` but do not return an error or break out of the message processing loop. The handshake continues processing subsequent messages (CertificateVerify, Finished) even when the certificate is invalid.

**Impact:** If certificate validation failure does not prevent the handshake from completing, an attacker could present an invalid certificate and still establish a connection. The `peer_cert_ok` flag may not be checked before application data exchange.

**Likelihood:** Impact 4 x Likelihood 0.5 (requires active MITM + must verify `peer_cert_ok` blocks data) x 4 = 8.0

**Evidence:**

`src/tls13/engine.zig:621-724`:

```zig
if (p.typ == .certificate) {
    if (self.allow_insecure) {
        self.peer_cert_ok = true;
    } else {
        self.peer_cert_ok = false;
        // ... validation attempts ...
        // All failures: break :blk false;
        self.peer_cert_ok = validation_ok;
    }
}
```

Multiple failure paths set `peer_cert_ok = false` but none return an error. Additionally, at line 688-693, missing EKU extension is silently accepted (see SEC-025).

**How to verify:** Trace whether `peer_cert_ok == false` prevents handshake completion and application data exchange. Check if any code path allows `writeAppData` when `peer_cert_ok == false`.

**Fix guidance:** Return an error immediately when certificate validation fails, or verify and document that `peer_cert_ok == false` prevents all data exchange.

**Acceptance criteria:**

- Certificate validation failure aborts the handshake or prevents data exchange.
- EKU absence is explicitly handled.
- Existing tests pass.

**References:** CWE-295 (Improper Certificate Validation), OWASP A07:2021, RFC 8446 Section 4.4.2

**Affected paths:** `src/tls13/engine.zig`

**Issue:** [GitLab #98](https://gitlab.com/devnw/zig/tls/-/issues/98)

**SLA:** 90 days

---

### Secret Lifecycle and Zeroization

#### SEC-002: `SecretSlot.clear()` in context.zig missing `secureZero` (High, Risk 32.0) -- CLOSED

**Summary:** The `SecretSlot.clear()` method in `context.zig` assigns `Secret.empty()` without first zeroizing the previous secret bytes. The correct implementation exists in `secrets.zig:79-80` which calls `std.crypto.secureZero(u8, &self.value.bytes)` before reassignment.

**Impact:** All TLS 1.3 traffic secrets (client/server handshake and application secrets) remain in process memory after `clear()` is called. If the process memory is later read (core dump, memory disclosure vulnerability, cold-boot attack), the traffic secrets can be recovered and used to decrypt recorded sessions.

**Likelihood:** Impact 4 (credential/key leak) x Likelihood 2 (requires memory access after clear) x 4 = 32.0

**Evidence:**

`src/tls13/context.zig:285-291` (VULNERABLE):

```zig
pub fn clear(self: *Self) void {
    self.value = Secret.empty();
    self.hash = .sha256;
    self.valid = false;
    self.generation = 0;
    self.epoch = .Initial;
}
```

`src/tls13/secrets.zig:79-80` (CORRECT):

```zig
pub fn clear(self: *Self) void {
    std.crypto.secureZero(u8, &self.value.bytes);
    self.value = Secret.empty();
    ...
}
```

**Fix guidance:** Add `std.crypto.secureZero(u8, &self.value.bytes);` as the first line of `SecretSlot.clear()` in `context.zig:285`, exactly matching the pattern in `secrets.zig`.

**Acceptance criteria:**

- `SecretSlot.clear()` in context.zig calls `secureZero` before reassignment.
- Unit test confirms bytes are zeroed after `clear()`.

**How to verify:** Add a test that stores a known secret, calls `clear()`, then inspects the backing memory via `@ptrCast` to confirm it is zeroed.

**References:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), OWASP A02:2021 (Cryptographic Failures)

**Affected paths:** `src/tls13/context.zig`

**SLA:** 30 days

---

#### SEC-003: ECDSA P-256 private key scalar not zeroized after signing (High, Risk 24.3) -- CLOSED

**Summary:** In `signCertificateVerify` for ECDSA P-256, the 32-byte private key scalar `sk` is allocated on the stack and never zeroized after use. The function returns without clearing this sensitive material.

**Impact:** The 32-byte ECDSA private key scalar remains on the stack after `signCertificateVerify` returns. Subsequent function calls may or may not overwrite this memory. If a memory disclosure vulnerability exists elsewhere, the private key can be recovered.

**Likelihood:** Impact 4 (private key leak) x Likelihood 1.5 (requires stack memory read) x 4 = 24.0 (rounded to 24.3 considering the signing function is called per-handshake).

**Evidence:**

`src/sig.zig:559`:

```zig
var sk: [32]u8 = undefined;
```

The `sk` variable is populated at lines 561-581 and used at line 590, but there is no `defer std.crypto.secureZero(u8, &sk);` anywhere in the ECDSA branch.

**Fix guidance:** Add `defer std.crypto.secureZero(u8, &sk);` immediately after the declaration at line 559.

**Acceptance criteria:**

- `sk` is zeroized via `secureZero` after every exit path from the ECDSA branch.
- Existing signing tests pass unchanged.

**How to verify:** Code review confirms `defer secureZero` is present. Optionally, a test can verify stack memory after calling the function in debug mode.

**References:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), OWASP A02:2021

**Affected paths:** `src/sig.zig`

**SLA:** 30 days

---

#### SEC-004: Ed25519 seed not zeroized after signing (High, Risk 24.3) -- CLOSED (partial)

**Summary:** In `signCertificateVerify` for Ed25519, the seed returned by `parsePkcs8Ed25519PrivateKey` was a `const` and was never zeroized. Fixed in cf6586c: seed is now `var` with `defer secureZero`. However, the derived `KeyPair` (containing the 64-byte expanded secret key) is still not zeroized -- see **SEC-004-R**.

**Impact:** The Ed25519 seed (32 bytes) is now properly zeroized. The expanded keypair secret key remains (see SEC-004-R).

**Evidence:**

`src/sig.zig:544-545` (FIXED for seed):

```zig
var seed = try parsePkcs8Ed25519PrivateKey(privkey_der);
defer std.crypto.secureZero(u8, &seed);
```

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/sig.zig`

**SLA:** 30 days

---

#### SEC-004-R: Ed25519 expanded KeyPair not zeroized after signing (High, Risk 14.0) -- CLOSED

**Summary:** The previous fix (cf6586c / SEC-004) only zeroized the Ed25519 seed. The expanded `KeyPair` generated at `sig.zig:547` is declared `const` and contains the 64-byte expanded secret key, which is NOT zeroized after use. This reopens the core concern of SEC-004.

**Impact:** The Ed25519 expanded secret key (64 bytes) persists on the stack after `signCertificateVerify` returns. If a memory disclosure vulnerability exists, or a core dump is captured, the full signing key can be recovered and used to forge CertificateVerify signatures, impersonating the TLS endpoint.

**Likelihood:** Impact 3.5 x Likelihood 1 (requires stack memory read after function return) x 4 = 14.0

**Evidence:**

`src/sig.zig:544-547`:

```zig
var seed = try parsePkcs8Ed25519PrivateKey(privkey_der);
defer std.crypto.secureZero(u8, &seed);  // seed IS zeroized (fix from cf6586c)
const kp = try Ed25519.KeyPair.generateDeterministic(seed);  // kp is NOT zeroized
```

The `kp` variable contains `KeyPair.secret_key` (64 bytes) plus the 32-byte public key. It is declared `const`, preventing `defer secureZero`.

**Attack scenario:**

1. Server uses Ed25519 certificate for TLS 1.3 authentication.
2. Attacker triggers a memory disclosure or captures a core dump.
3. Attacker reads the stack frame containing the un-zeroized 64-byte expanded secret key.
4. Attacker uses the recovered key to forge CertificateVerify signatures.

**Fix guidance:**

1. Change `const kp` to `var kp` at line 547.
2. Add `defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));` immediately after.

**Acceptance criteria:**

- `kp` is declared as `var` (not `const`).
- `defer std.crypto.secureZero(u8, std.mem.asBytes(&kp))` is present.
- Ed25519 signing tests pass without regression.
- Code review confirms all 96 bytes (64-byte secret + 32-byte public) are cleared.

**References:** CWE-226, OWASP A02:2021, RFC 8446 Section 7.1

**Affected paths:** `src/sig.zig:547`

**Issue:** [GitLab #84](https://gitlab.com/devnw/zig/tls/-/issues/84) (confidential)

**SLA:** 30 days (due 2026-04-23)

---

#### SEC-015: Context ECDHE server_priv not zeroized (High, Risk 14.0)

**Summary:** In the server-side handshake path in `context.zig`, the X25519 private key `server_priv` (32 bytes) used for ECDHE key exchange is never zeroized after use. It remains on the stack for the duration of `handleClientHello` and beyond.

**Impact:** The 32-byte X25519 ephemeral private key persists on the stack after the ECDHE computation. If an attacker can read process memory, they can recover this key and compute the shared secret, enabling decryption of the entire TLS session. This defeats forward secrecy for that session.

**Likelihood:** Impact 3.5 x Likelihood 1 (requires memory access after key exchange; long function extends exposure window) x 4 = 14.0

**Evidence:**

`src/tls13/context.zig:2153-2165`:

```zig
var server_priv: [32]u8 = undefined;
std.crypto.random.bytes(&server_priv);

const server_pub = std.crypto.dh.X25519.recoverPublicKey(server_priv) catch {
    return HandshakeError.UnsupportedKeyShareGroup;
};

var client_pub: [32]u8 = undefined;
@memcpy(&client_pub, ch_view.key_share.key[0..32]);

const shared = std.crypto.dh.X25519.scalarmult(server_priv, client_pub) catch {
    return HandshakeError.UnsupportedKeyShareGroup;
};
```

No `defer std.crypto.secureZero(u8, &server_priv);` exists. The private key is also NOT zeroized on error paths (lines 2157, 2164).

**Attack scenario:**

1. TLS server handles client connections using X25519 key exchange.
2. Attacker captures encrypted TLS traffic (passive recording).
3. Attacker later obtains a memory dump of the server process.
4. Attacker finds `server_priv` on the stack and computes the shared secret.
5. Attacker derives all session keys and decrypts the recorded traffic, defeating forward secrecy.

**Fix guidance:** Add `defer std.crypto.secureZero(u8, &server_priv);` immediately after line 2154.

**Acceptance criteria:**

- `defer secureZero` present after `server_priv` generation.
- Error paths also benefit from the defer.
- Handshake tests pass.

**References:** CWE-226, OWASP A02:2021, RFC 8446 Section 7.1

**Affected paths:** `src/tls13/context.zig:2153-2165`

**Issue:** [GitLab #87](https://gitlab.com/devnw/zig/tls/-/issues/87) (confidential)

**SLA:** 30 days (due 2026-04-23)

---

#### SEC-016: Context ECDHE shared secret not zeroized, server + client (High, Risk 13.0)

**Summary:** The X25519 shared secret computed during ECDHE key exchange in `context.zig` is never zeroized after use, on both the server path (line 2163) and the client path (line 2677). The shared secret is the root keying material for all session keys.

**Impact:** The 32-byte X25519 shared secret persists on the stack after being passed to `deriveHandshakeTraffic`. If an attacker can read process memory, they can derive all session keys and decrypt traffic.

**Likelihood:** Impact 3.5 x Likelihood 0.9 (both server and client paths affected; long functions extend exposure) x 4 = 12.6 (rounded to 13.0)

**Evidence:**

**Server path** -- `src/tls13/context.zig:2163`:

```zig
const shared = std.crypto.dh.X25519.scalarmult(server_priv, client_pub) catch {
    return HandshakeError.UnsupportedKeyShareGroup;
};
```

**Client path** -- `src/tls13/context.zig:2677`:

```zig
const shared = std.crypto.dh.X25519.scalarmult(priv, server_pub.?) catch return HandshakeError.UnsupportedKeyShareGroup;
const sh_snapshot = self.transcripts.handshake.finalize(self.hash_kind);
const hs = deriveHandshakeTraffic(self.hash_kind, shared[0..], sh_snapshot, &early_secret);
```

Neither location has `defer secureZero`.

**Fix guidance:** Change `const shared` to `var shared` on both paths and add `defer std.crypto.secureZero(u8, &shared);`.

**Acceptance criteria:**

- `shared` declared as `var` on both server and client ECDHE paths.
- `defer secureZero` present on both paths.
- Handshake tests (including mTLS) pass.

**References:** CWE-226, OWASP A02:2021, RFC 8446 Section 7.1

**Affected paths:** `src/tls13/context.zig:2163`, `src/tls13/context.zig:2677`

**Issue:** [GitLab #91](https://gitlab.com/devnw/zig/tls/-/issues/91) (confidential)

**SLA:** 30 days (due 2026-04-23)

---

#### SEC-008: `x25519KeypairAndShared` in engine.zig missing sk zeroize on error (Medium, Risk 7.0) -- CLOSED

**Summary:** The `x25519KeypairAndShared` function in `engine.zig` does not zeroize the private key `sk` when `scalarmult` fails. The corrected version in `messages.zig:201-205` does zeroize and returns a zeroed key struct.

**Impact:** On `scalarmult` failure, the X25519 private key remains in the returned struct and on the stack. The caller receives `shared = null` but still holds the unzeroized private key.

**Likelihood:** Impact 3.5 x Likelihood 0.5 (requires scalarmult to fail, which happens only with weak/invalid peer keys) x 4 = 7.0

**Evidence:**

`src/tls13/engine.zig:1729-1733` (VULNERABLE):

```zig
if (std.crypto.dh.X25519.scalarmult(&sh, sk, peer_pub)) {
    shared = sh;
} else shared = null;
```

`src/tls13/messages.zig:201-205` (CORRECT):

```zig
const sh = std.crypto.dh.X25519.scalarmult(sk, peer_pub) catch {
    std.crypto.secureZero(u8, &sk);
    return .{ .priv_key = [_]u8{0} ** 32, .pub_key = pk, .shared = null };
};
```

**Fix guidance:** Match the `messages.zig` pattern: zeroize `sk` on error and return a zeroed `priv_key`.

**Acceptance criteria:**

- On `scalarmult` failure, `sk` is zeroized and returned `priv_key` is all zeros.
- Function behavior matches `messages.zig` implementation.

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/tls13/engine.zig`

**SLA:** 90 days

---

#### SEC-023: `x25519KeypairAndShared` priv_key not zeroized on success path (Medium, Risk 7.0)

**Summary:** In `messages.zig`, the `x25519KeypairAndShared` function correctly zeroizes the private key on the error path (line 204), but on the success path (line 209) the stack-local `sk` variable is returned by value in the struct without being zeroized. The stack copy persists.

**Impact:** The private key remains on the stack after the function returns. While the caller receives a copy, the original stack variable is not cleared. In debug builds or with certain optimization levels, this material may be observable.

**Likelihood:** Impact 3.5 x Likelihood 0.5 (requires stack memory inspection) x 4 = 7.0

**Evidence:**

`src/tls13/messages.zig:191-209`:

```zig
pub fn x25519KeypairAndShared(peer_pub_opt: ?[32]u8) ... {
    var sk: [32]u8 = undefined;
    std.crypto.random.bytes(&sk);
    // No defer secureZero(u8, &sk) here
    // ...
    return .{ .priv_key = sk, .pub_key = pk, .shared = shared };
    // sk remains on stack un-zeroized
}
```

**Fix guidance:** Add `defer std.crypto.secureZero(u8, &sk);` after line 193. Zig copies values into the return struct before defer runs, so the caller still receives the key.

**Acceptance criteria:**

- `defer secureZero(u8, &sk)` added after key generation.
- Error path zeroization still functions correctly.
- Existing tests pass.

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/tls13/messages.zig`

**Issue:** [GitLab #76](https://gitlab.com/devnw/zig/tls/-/issues/76)

**SLA:** 90 days

---

#### SEC-050: Private key not zeroed on error in `startClientHandshake` (Medium, Risk 4.5) -- OPEN

**Summary:** In `startClientHandshake`, the stack-local X25519 private key `priv` is not zeroed on early return at line 2143. Additionally, `self.client_priv` is not cleaned by errdefer on subsequent `try` failures at lines 2165-2226. The same pattern exists in `sendClientHello2` at line 1561.

**Impact:** If the handshake fails after the private key is generated but before normal cleanup runs, the 32-byte X25519 private key persists on the stack or in the Context struct. An attacker who can read process memory (core dump, memory disclosure vulnerability) could recover the key. This partially undermines forward secrecy for the failed handshake attempt.

**Likelihood:** Impact 2.5 (private key leak, but only for failed handshakes) x Likelihood 0.9 (requires both handshake failure AND memory access) x 4 = 4.5 (rounded from 9.0 to 4.5 -- lower because it only affects error paths, not successful handshakes)

**Evidence:**

`src/tls13/context.zig:2134-2144`:

```zig
var priv: [32]u8 = undefined;
std.crypto.random.bytes(&priv);
// ... no defer secureZero on priv ...
if (some_condition) return error.SomeError; // line 2143: priv leaked on stack
```

`src/tls13/context.zig:2165-2226`:

```zig
self.client_priv = priv;
// ... subsequent try calls without errdefer to zero client_priv ...
```

Same pattern in `sendClientHello2` at `context.zig:1561`.

**Attack scenario:**

1. Client initiates TLS handshake.
2. Handshake fails at an early stage after key generation but before cleanup.
3. Attacker obtains core dump or exploits a separate memory disclosure.
4. X25519 private key is recovered from the stack frame or Context struct.

**Fix guidance:**

1. Add `defer std.crypto.secureZero(u8, &priv);` immediately after `var priv` declaration.
2. Add `errdefer std.crypto.secureZero(u8, &self.client_priv.?);` after assigning `self.client_priv = priv`.
3. Apply the same pattern in `sendClientHello2` at line 1561.

**Acceptance criteria:**

- `priv` is zeroed on all exit paths (success and error) via `defer secureZero`.
- `self.client_priv` is zeroed on error paths via `errdefer`.
- Same fix applied to `sendClientHello2`.
- Existing handshake tests pass.

**How to verify:** Code review confirms `defer secureZero` is present on `priv` in both functions. Confirm errdefer is added for `client_priv` assignment.

**References:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), OWASP A02:2021 (Cryptographic Failures)

**Affected paths:** `src/tls13/context.zig:2134-2226`, `src/tls13/context.zig:1561`

**SLA:** 90 days (due 2026-06-23)

---

#### SEC-055: `client_priv` retained after DH computation (Low, Risk 2.0) -- OPEN

**Summary:** After `scalarmult` succeeds at `context.zig:2317-2343`, the X25519 private key remains stored in `self.client_priv` within the Context struct until `deinit()` is called. The private key is no longer needed after the shared secret is computed but continues to occupy memory for the remaining connection lifetime.

**Impact:** The private key remains accessible in process memory for the entire duration of the TLS connection (which could be hours or days for long-lived connections). While `Context.deinit()` does zero it eventually, the extended exposure window increases the chance of disclosure via memory dump, heap inspection, or swap file.

**Likelihood:** Impact 2 (ephemeral key leak, limited to single session) x Likelihood 0.5 (requires memory access during active connection) x 4 = 2.0 (rounded from 4.0 -- mitigated by `deinit()` cleanup)

**Evidence:**

`src/tls13/context.zig:2317-2343`:

```zig
const shared = std.crypto.dh.X25519.scalarmult(self.client_priv.?, peer_pub) catch { ... };
// client_priv is no longer needed but remains in self until deinit()
```

**Fix guidance:**

1. After successful `scalarmult`, immediately zero `self.client_priv` via `std.crypto.secureZero(u8, &self.client_priv.?)`.
2. Set `self.client_priv = null` after zeroing.

**Acceptance criteria:**

- `client_priv` is zeroed and nulled immediately after DH shared secret computation.
- Handshake completes successfully (no code reads `client_priv` after this point except HRR, which regenerates it).
- Existing tests pass.

**How to verify:** Code review confirms `secureZero` + null assignment after scalarmult. Verify no later code reads `client_priv` on the non-HRR path.

**References:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), OWASP A02:2021

**Affected paths:** `src/tls13/context.zig:2317-2343`

**SLA:** 180 days (due 2026-09-21)

---

### Resource Exhaustion and DoS

#### SEC-017: TicketStore unbounded growth (Medium, Risk 10.0)

**Summary:** The `TicketStore` in `engine.zig` has no upper bound on the number of stored session tickets. An attacker sending many NewSessionTicket messages can cause unbounded memory growth.

**Impact:** Memory exhaustion leading to OOM and process termination.

**Likelihood:** Impact 2.5 x Likelihood 1 (requires active TLS connection, but NewSessionTicket flood is trivial) x 4 = 10.0

**Evidence:**

`src/tls13/engine.zig:128-151`:

```zig
pub const TicketStore = struct {
    tickets: ArrayListUnmanaged(TicketEntry) = .{},
    pub fn store(self: *TicketStore, identity: []const u8, secret: Secret, lifetime: u32) !void {
        const ident_copy = try self.allocator.dupe(u8, identity);
        try self.tickets.append(self.allocator, .{ ... });
    }
};
```

No maximum capacity check, no eviction policy, no ticket expiry enforcement.

**Fix guidance:** Add `MAX_TICKETS` constant (e.g., 128) and FIFO eviction in `store()`. Zeroize evicted ticket secrets.

**Acceptance criteria:**

- `TicketStore` enforces a maximum number of tickets.
- Oldest tickets are evicted with secret zeroization.
- Session resumption tests pass.

**References:** CWE-770, OWASP A05:2021

**Affected paths:** `src/tls13/engine.zig:128-151`

**Issue:** [GitLab #93](https://gitlab.com/devnw/zig/tls/-/issues/93)

**SLA:** 90 days (due 2026-06-22)

---

#### SEC-018: CRYPTO inbound/inbox buffer unbounded (Medium, Risk 10.0)

**Summary:** Both `Context.processCrypto` and `Engine.onCryptoRecv` append incoming CRYPTO frame data to unbounded `ArrayList` buffers without size limits. A malicious peer can exhaust memory with oversized or never-completing handshake messages.

**Impact:** Memory exhaustion via oversized/fragmented CRYPTO frames.

**Likelihood:** Impact 2.5 x Likelihood 1 (trivial to send oversized CRYPTO frames) x 4 = 10.0

**Evidence:**

`src/tls13/context.zig:1033`:

```zig
try stream.inbound.appendSlice(self.allocator, data);
```

`src/tls13/engine.zig:437`:

```zig
try self.inbox.appendSlice(self.allocator, data);
```

**Fix guidance:** Add `MAX_HANDSHAKE_BUFFER` constant (e.g., 65536) and check before appending.

**Acceptance criteria:**

- Maximum buffer size enforced in both locations.
- Normal handshakes (including large certificate chains) still work.
- Oversized messages produce a clear error.

**References:** CWE-770, OWASP A05:2021

**Affected paths:** `src/tls13/context.zig:1033`, `src/tls13/engine.zig:437`

**Issue:** [GitLab #95](https://gitlab.com/devnw/zig/tls/-/issues/95)

**SLA:** 90 days (due 2026-06-22)

---

#### SEC-024: Certificate chain no depth limit (Low, Risk 5.0)

**Summary:** `validateChain` in `x509.zig` accepts certificate chains of arbitrary length. No maximum depth limit. Typical implementations limit to 10-20 (BoringSSL defaults to 7).

**Impact:** Excessive memory and CPU consumption from pathologically long certificate chains.

**Likelihood:** Impact 2.5 x Likelihood 0.5 x 4 = 5.0

**Evidence:**

`src/x509.zig:1480`:

```zig
pub fn validateChain(alloc: std.mem.Allocator, chain_der: []const []const u8, ...) !void {
    // No check on chain_der.len
    var certs = try alloc.alloc(Certificate, chain_der.len);
```

**Fix guidance:** Add `if (chain_der.len > MAX_CHAIN_DEPTH) return error.ChainTooLong;` with `MAX_CHAIN_DEPTH = 10`.

**References:** CWE-770, OWASP A05:2021

**Affected paths:** `src/x509.zig:1480`

**Issue:** [GitLab #99](https://gitlab.com/devnw/zig/tls/-/issues/99)

**SLA:** 180 days

---

#### SEC-054: Memory leak in `parseClientHello` on error paths (Low, Risk 2.0) -- OPEN

**Summary:** In `parseClientHello` at `client_hello.zig:295-497`, several slices are allocated during parsing (extensions, cipher suites, etc.) but there are no `errdefer` statements to free them if a subsequent allocation or parse step fails. On repeated malformed ClientHello messages, this creates a memory leak.

**Impact:** A remote attacker can send repeated malformed ClientHello messages that trigger allocations before failing. Each failure leaks allocated memory. Over time, this can exhaust server memory, causing denial of service. The attack is pre-authentication and remote.

**Likelihood:** Impact 2 (DoS only, no data compromise) x Likelihood 0.5 (requires sustained attack; server may have connection limits) x 4 = 2.0 (rounded from 4.0 -- mitigated by connection-level cleanup and typical OS limits)

**Evidence:**

`src/tls13/client_hello.zig:295-497`:

```zig
// Multiple allocations without corresponding errdefer:
// e.g., allocated slices for extensions, cipher_suites, etc.
// If a later parse step fails, these allocations leak.
```

**Attack scenario:**

1. Attacker sends crafted ClientHello that passes initial validation but fails at a later parsing stage.
2. Memory allocated for early-parsed fields is not freed on the error path.
3. Repeated requests gradually exhaust server memory.
4. Server becomes unresponsive or crashes with OOM.

**Fix guidance:**

1. Add `errdefer` for each allocation in `parseClientHello` to free on error.
2. Consider using an arena allocator scoped to the parse operation.

**Acceptance criteria:**

- All allocations in `parseClientHello` have corresponding `errdefer` frees.
- Memory does not grow when processing repeated malformed ClientHello messages.
- Existing parsing tests pass.

**How to verify:** Write a test that sends N malformed ClientHellos and checks that memory usage returns to baseline after each failure. Alternatively, code review confirms errdefer coverage.

**References:** CWE-401 (Missing Release of Memory after Effective Lifetime), OWASP A05:2021 (Security Misconfiguration)

**Affected paths:** `src/tls13/client_hello.zig:295-497`

**SLA:** 180 days (due 2026-09-21)

---

### Configuration and Hardening

#### SEC-005: `allow_insecure` has no compile-time guard for release builds (Medium, Risk 16.0) -- CLOSED

**Summary:** The `allow_insecure` configuration field (`config.zig:271`) can be set to `true` in release builds without any compile-time warning or error. By contrast, `secret_trace_enabled` and `sig_trace_enabled` have `comptime` guards that emit `@compileError` in non-Debug builds.

**Impact:** A production deployment could accidentally ship with `allow_insecure = true`, disabling all certificate validation (chain, hostname, expiry). This would allow man-in-the-middle attacks against any TLS connection.

**Likelihood:** Impact 4 (complete certificate bypass) x Likelihood 1 (requires explicit misconfiguration) x 4 = 16.0. The field defaults to `false` and requires deliberate setting, but there is no safety net.

**Evidence:**

`src/tls13/config.zig:271`:

```zig
allow_insecure: bool = false,
```

Compare with `src/sig.zig:117-120`:

```zig
comptime {
    if (sig_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: sig_trace_enabled must be false in release builds - secrets would be logged!");
    }
}
```

No equivalent guard exists for `allow_insecure`.

**Fix guidance:** Since `allow_insecure` is a runtime config field (not a comptime constant), a `comptime` check cannot directly apply. Options:

1. Add a runtime warning log when `allow_insecure` is `true` in release mode.
2. Add a separate comptime constant `allow_insecure_override` that must be set to permit `allow_insecure = true` in release builds.
3. Document prominently that `allow_insecure` must never be used in production.

**Acceptance criteria:**

- Release builds with `allow_insecure = true` produce a visible warning or require an explicit opt-in.
- Default behavior (false) is unchanged.

**References:** CWE-1188 (Initialization with Hard-Coded Network Resource Configuration Data), OWASP A05:2021 (Security Misconfiguration)

**Affected paths:** `src/tls13/config.zig`

**SLA:** 90 days

---

#### SEC-019: Engine `allow_insecure` no release guard (Medium, Risk 9.0)

**Summary:** The `Engine.allow_insecure` field (engine.zig:207) has the same issue as SEC-005, but for the Engine API. The `Context` path was fixed (SEC-005) with a runtime panic guard, but the `Engine` path was not.

**Impact:** Same as SEC-005: production deployment with `allow_insecure = true` disables all certificate validation, enabling MITM attacks.

**Likelihood:** Impact 4.5 x Likelihood 0.5 (requires explicit misconfiguration) x 4 = 9.0

**Evidence:**

`src/tls13/engine.zig:207`:

```zig
allow_insecure: bool = false,
```

Doc comment warns against production use, but there is no programmatic guard.

**Fix guidance:** Add runtime panic or loud warning matching the `Context.init()` pattern.

**References:** CWE-295, OWASP A05:2021

**Affected paths:** `src/tls13/engine.zig:207`

**Issue:** [GitLab #96](https://gitlab.com/devnw/zig/tls/-/issues/96)

**SLA:** 90 days (due 2026-06-22)

---

#### SEC-025: EKU absent check not enforced (Low, Risk 4.0)

**Summary:** The Extended Key Usage check at `engine.zig:688-693` only rejects certificates where EKU is present but lacks `serverAuth`. Certificates with no EKU extension at all pass validation.

**Impact:** A certificate without any EKU (e.g., a CA certificate not intended for TLS server authentication) could be accepted as a server certificate.

**Likelihood:** Impact 2 x Likelihood 0.5 x 4 = 4.0

**Evidence:**

`src/tls13/engine.zig:688-693`:

```zig
if (leaf.eku) |eku| {
    if (!eku.server_auth) {
        break :blk false;
    }
}
// No else -- certificates without EKU extension are accepted
```

**Fix guidance:** Add `else` branch or document intentional permissiveness per RFC 5280 (which allows unrestricted use for certs without EKU).

**References:** CWE-295, RFC 5280 Section 4.2.1.12

**Affected paths:** `src/tls13/engine.zig:688-693`

**Issue:** [GitLab #100](https://gitlab.com/devnw/zig/tls/-/issues/100)

**SLA:** 180 days

---

### Certificate Revocation

#### SEC-007: No CRL checking; OCSP is optional (Medium, Risk 12.6) -- **Status: Closed**

**Summary:** The `validateChain` function in `x509.zig` does not perform any certificate revocation checking. CRL distribution points in certificates are ignored. OCSP stapling is handled separately and is optional (not enforced by default).

**Impact:** A revoked certificate (e.g., due to key compromise) will pass validation. The implementation explicitly documents this as a known limitation with mitigations.

**Likelihood:** Impact 3.5 (accepting compromised certificates) x Likelihood 0.9 (requires a revoked cert in the wild, which does occur) x 4 = 12.6

**Evidence:**

`src/x509.zig:1451-1479` documents the limitation explicitly:

```text
This function does NOT perform certificate revocation checking.
...
A certificate that has been revoked by its CA may still pass validation
```

**Fix guidance:** This is a known architectural limitation. Recommended mitigations:

1. Make `require_ocsp` default to `true` for internet-facing deployments.
2. Document the limitation in the public API and deployment guides.
3. Long-term: implement CRL fetching or integrate with an external revocation service.

**Acceptance criteria:**

- `require_ocsp` enforcement is documented and easy to enable.
- Users are warned when operating without revocation checking on long-lived certificates.

**References:** CWE-299 (Improper Check for Certificate Revocation), OWASP A07:2021

**Affected paths:** `src/x509.zig`

**SLA:** 90 days

**Resolution:** CRL limitation documented in 3 locations:

1. `src/x509.zig:1533-1564` -- comprehensive CRL limitation documentation with workarounds (already present)
2. `src/tls13/config.zig:252,267` -- `require_ocsp` field with documentation (already present)
3. `src/lib.zig` -- CRL limitation added to "Known Limitations" section and x509 module doc comment with SEC-007 reference, pointing users to `require_ocsp = true` mitigation

---

### Error Handling

#### SEC-009: `x25519KeypairAndShared` returns value instead of error on failure (Low, Risk 6.0)

**Summary:** When `scalarmult` fails in `messages.zig:201-205`, the function returns a struct with `shared = null` and a zeroed private key instead of returning an error. Callers must check for `null` shared secret rather than handling an error type.

**Impact:** A caller that does not check `shared == null` may proceed without a shared secret, potentially using uninitialized or zero key material for key derivation. The function's doc comment shows the correct usage pattern (`if (keys.shared) |secret|`).

**Likelihood:** Impact 3 x Likelihood 0.5 (requires caller to skip null check) x 4 = 6.0

**Evidence:**

`src/tls13/messages.zig:201-205`:

```zig
const sh = std.crypto.dh.X25519.scalarmult(sk, peer_pub) catch {
    std.crypto.secureZero(u8, &sk);
    return .{ .priv_key = [_]u8{0} ** 32, .pub_key = pk, .shared = null };
};
```

**Fix guidance:** Consider returning an error union `!struct{...}` so callers are forced to handle the error at compile time via Zig's error handling.

**References:** CWE-252 (Unchecked Return Value), OWASP A07:2021

**Affected paths:** `src/tls13/messages.zig`, `src/tls13/engine.zig`

**SLA:** 180 days

**Status: Closed** (2026-03-24) -- Function now returns `X25519Error!X25519Result` error union. Callers are forced to handle the error at compile time. See `src/tls13/messages.zig:228-248`.

---

#### SEC-014: Dead default algorithm `.rsa_pss_sha256` for unknown scheme (Low, Risk 0.3) -- CLOSED

**Summary:** In `engine.zig:744-748`, an unknown `SignatureScheme` value in a CertificateVerify message falls through to `.rsa_pss_sha256` as the default algorithm. However, the same branch immediately sets `peer_cert_ok = false`, making the algorithm assignment dead code.

**Status:** Closed. Duplicate of SEC-027. The dead `.rsa_pss_sha256` fallback has been removed as part of SEC-027 remediation. `engine.zig:836-840` now uses `continue` to skip verification for unknown schemes, eliminating both the dead assignment and the confusing fallback.

**References:** CWE-394, OWASP A07:2021

**Affected paths:** `src/tls13/engine.zig`

**Issue:** [GitLab #102](https://gitlab.com/devnw/zig/tls/-/issues/102)

---

### Timing and Side Channels

#### SEC-010: OCSP digest comparison uses `std.mem.eql` (Low, Risk 1.0)

**Summary:** The `compareSlices` function in `ocsp.zig:140-141` uses `std.mem.eql` for comparing OCSP response digests. Since OCSP digests are non-secret public data (certificate hashes), this is not a timing vulnerability.

**Impact:** None. The compared values are certificate digests that are already public.

**Likelihood:** Impact 1 x Likelihood 0.25 x 4 = 1.0

**Evidence:**

`src/ocsp.zig:140-141`:

```zig
pub fn compareSlices(expected: []const u8, actual: []const u8) bool {
    return expected.len == actual.len and std.mem.eql(u8, expected, actual);
}
```

**Fix guidance:** No action required. Documented for completeness. If defense-in-depth is desired, switch to `std.crypto.timing_safe.eql`, but this is not necessary for public data.

**References:** CWE-208 (Observable Timing Discrepancy), OWASP A02:2021

**Affected paths:** `src/ocsp.zig`

**SLA:** Backlog

---

#### SEC-026: OCSP `compareSlices` non-constant-time (Low, Risk 3.0)

**Summary:** Same as SEC-010 but captured from Phase 4 review with slightly higher risk score due to defense-in-depth considerations. The `compareSlices` function at `ocsp.zig:143` uses `std.mem.eql` for OCSP digest comparisons. While the data is non-secret, a constant-time comparison would be a stronger defense-in-depth practice.

**Impact:** Minimal. Non-secret data comparison.

**Likelihood:** Impact 1.5 x Likelihood 0.5 x 4 = 3.0

**Fix guidance:** Consider switching to `std.crypto.timing_safe.eql` for defense-in-depth.

**References:** CWE-208, OWASP A02:2021

**Affected paths:** `src/ocsp.zig:143`

**Issue:** [GitLab #101](https://gitlab.com/devnw/zig/tls/-/issues/101)

**SLA:** Backlog

---

#### SEC-027: Engine CertificateVerify unknown scheme dead fallback (Low, Risk 3.0)

**Summary:** See SEC-014. Captured separately as a code cleanliness finding from Phase 4 review. The dead `.rsa_pss_sha256` assignment for unknown signature schemes is confusing and could mask future bugs if the `peer_cert_ok = false` guard is accidentally removed.

**References:** CWE-697, OWASP A07:2021

**Affected paths:** `src/tls13/engine.zig:744-748`

**Issue:** [GitLab #102](https://gitlab.com/devnw/zig/tls/-/issues/102)

**SLA:** Backlog

---

#### SEC-011: Downgrade sentinel detection uses `std.mem.eql` (Low, Risk 1.0)

**Summary:** Downgrade sentinel checks in `server_hello.zig` use `std.mem.eql` to compare the last 8 bytes of the ServerHello random against known sentinel values. These sentinels are public constants defined in RFC 8446.

**Impact:** None. The sentinel values are public, well-known constants. Timing leakage does not benefit an attacker.

**Likelihood:** Impact 1 x Likelihood 0.25 x 4 = 1.0

**Evidence:**

`src/tls13/messages/server_hello.zig:145`:

```zig
return std.mem.eql(u8, &random, &HELLO_RETRY_REQUEST_RANDOM);
```

`src/tls13/messages/server_hello.zig:167`:

```zig
return std.mem.eql(u8, last_8, &TLS12_DOWNGRADE_SENTINEL);
```

`src/tls13/messages/server_hello.zig:189`:

```zig
return std.mem.eql(u8, last_8, &TLS11_DOWNGRADE_SENTINEL);
```

**Fix guidance:** No action required. Informational only.

**References:** CWE-208, OWASP A02:2021

**Affected paths:** `src/tls13/messages/server_hello.zig`

**SLA:** Backlog

---

### Logging and Debug

#### SEC-012: Debug trace logs private key scalar (compile-guarded) (Low, Risk 0.9)

**Summary:** When `sig_trace_enabled` is `true`, the ECDSA P-256 private key scalar is printed to stderr. This is properly guarded by a comptime check that produces `@compileError` in non-Debug builds.

**Impact:** In Debug builds with `sig_trace_enabled = true`, private key material is written to stderr. This is expected behavior for development debugging. The comptime guard prevents this from reaching release builds.

**Likelihood:** Impact 1.5 x Likelihood 0.15 (requires manually changing a const and building in debug mode) x 4 = 0.9

**Evidence:**

`src/sig.zig:564-566`:

```zig
if (sig_trace_enabled) {
    std.debug.print("[SIG] Successfully parsed PKCS#8, scalar: ", .{});
    for (sk) |b| std.debug.print("{x:0>2} ", .{b});
```

`src/sig.zig:117-120` (GUARD):

```zig
comptime {
    if (sig_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: sig_trace_enabled must be false in release builds - secrets would be logged!");
    }
}
```

**Fix guidance:** Acceptable as-is. The comptime guard is effective. Consider replacing the raw scalar print with a truncated hash for additional defense-in-depth, but this is not required.

**References:** CWE-532 (Insertion of Sensitive Information into Log File), OWASP A09:2021 (Security Logging and Monitoring Failures)

**Affected paths:** `src/sig.zig`

**SLA:** Backlog

---

#### SEC-049: Missing `@compileError` guards on 4 trace flags (Low, Risk 2.0) -- OPEN

**Summary:** Four trace flags lack the `@compileError` guard that `secret_trace_enabled` and `handshake_trace_enabled` in `context.zig` already have: `engine_trace_enabled` at `engine.zig:114`, `transcript_trace_enabled` at `transcript.zig:78`, `messages_trace_enabled` at `messages.zig:17`, and `ocsp_trace_enabled` at `ocsp.zig:22`. Currently mitigated because `debugPrint` is a no-op in release builds, but this is a defense-in-depth gap if the logger implementation is ever replaced.

**Impact:** If a future change replaces the no-op `debugPrint` with an actual logging function in release builds, these trace flags could enable verbose debug output including handshake details, message contents, and OCSP response data in production. Currently no data leaks because `debugPrint` compiles to nothing in release mode.

**Likelihood:** Impact 1 (information disclosure of non-secret protocol data) x Likelihood 0.5 (requires both flag set AND logger replacement) x 4 = 2.0

**Evidence:**

`src/tls13/engine.zig:114`:

```zig
const engine_trace_enabled = false;
// No @compileError guard for release builds
```

`src/tls13/transcript.zig:78`:

```zig
const transcript_trace_enabled = false;
// No @compileError guard for release builds
```

`src/tls13/messages.zig:17`:

```zig
const messages_trace_enabled = false;
// No @compileError guard for release builds
```

`src/ocsp.zig:22`:

```zig
const ocsp_trace_enabled = false;
// No @compileError guard for release builds
```

Compare with the guarded pattern in `context.zig:121-126`:

```zig
comptime {
    if (handshake_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: handshake_trace_enabled must be false in release builds!");
    }
}
```

**Fix guidance:** Add `@compileError` guards for each of the 4 trace flags, matching the pattern in `context.zig`. This is a 15-minute fix.

**Acceptance criteria:**

- All 4 trace flags have `@compileError` guards in non-Debug builds.
- Setting any trace flag to `true` in release mode produces a compile error.
- Debug builds with trace flags enabled still work correctly.

**How to verify:** Set each flag to `true` and attempt a release build; confirm compile error is emitted.

**References:** CWE-215 (Insertion of Sensitive Information Into Debugging Code), OWASP A09:2021

**Affected paths:** `src/tls13/engine.zig:114`, `src/tls13/transcript.zig:78`, `src/tls13/messages.zig:17`, `src/ocsp.zig:22`

**SLA:** 180 days (due 2026-09-21)

---

#### SEC-056: Unconditional `logger.debugPrint` in error paths (Info, Risk 0.5) -- ACCEPTABLE RISK

**Summary:** Several error-handling paths call `logger.debugPrint` unconditionally (not gated by any trace flag) at `messages.zig:178` and `engine.zig:660+`. These log error details that could theoretically disclose protocol state information.

**Impact:** Minimal. `debugPrint` is a no-op in release builds regardless of trace flags. The logged information is non-secret protocol error details (alert codes, message types). Even if logging were active, the information would not enable key recovery or session compromise.

**Likelihood:** Impact 1 (non-secret error details) x Likelihood 0.125 (requires logger replacement AND attacker log access) x 4 = 0.5

**Evidence:**

`src/tls13/messages.zig:178`:

```zig
logger.debugPrint("error parsing message: {}", .{err});
// Not gated by messages_trace_enabled
```

`src/tls13/engine.zig:660+`:

```zig
logger.debugPrint("certificate validation error: {}", .{err});
// Not gated by engine_trace_enabled
```

**Fix guidance:** No action required. This is acceptable risk because `debugPrint` is a no-op in release builds. For consistency, these could be wrapped in `if (trace_enabled)` blocks, but this is cosmetic.

**Acceptance criteria:** Documented as acceptable risk.

**References:** CWE-209 (Generation of Error Message Containing Sensitive Information), OWASP A09:2021

**Affected paths:** `src/tls13/messages.zig:178`, `src/tls13/engine.zig:660+`

**SLA:** Backlog (acceptable risk)

---

### Integer Safety

#### SEC-013: `@intCast` in DER encoding (bounds-checked) (Low, Risk 0.6)

**Summary:** Three `@intCast` calls in the DER encoding section of `signCertificateVerify` cast `usize` values to `u8` for ASN.1 length encoding. These values are bounded by P-256 signature component sizes (max 33 bytes per component) and are further guarded by the `seq_len + 2 >= 128` check at line 615.

**Impact:** None in practice. P-256 signature components are always 32 bytes (with possible 1-byte padding), so the cast values are always in range [1, 33]. The guard at line 615 would catch any anomaly.

**Likelihood:** Impact 1 x Likelihood 0.15 x 4 = 0.6

**Evidence:**

`src/sig.zig:620`:

```zig
out[o] = @intCast(seq_len);
```

`src/sig.zig:624`:

```zig
out[o] = @intCast(r_len);
```

`src/sig.zig:634`:

```zig
out[o] = @intCast(s_len);
```

Guard at `src/sig.zig:615`:

```zig
if (seq_len + 2 >= 128) return error.Encode;
```

**Fix guidance:** No action required. The bounds are mathematically guaranteed for P-256 and additionally runtime-checked. Zig's `@intCast` will panic in safe modes if the value does not fit, providing defense-in-depth.

**References:** CWE-681 (Incorrect Conversion between Numeric Types), OWASP A07:2021

**Affected paths:** `src/sig.zig`

**SLA:** Backlog

---

#### SEC-052: ASN.1 `readInteger` silent truncation >8 bytes (Low, Risk 1.5) -- OPEN

**Summary:** The `readInteger` function in `asn1.zig:465-474` reads ASN.1 INTEGER values into a `u64` (8 bytes). If the encoded integer exceeds 8 bytes, the function silently truncates by only reading the last 8 bytes. Current callers only use this for small integer fields (version numbers, serial number components), so this is not exploitable today.

**Impact:** If `readInteger` is ever used for large integers (e.g., RSA modulus parsing, certificate serial number comparison), the silent truncation could cause incorrect comparisons or bypass checks. Currently, all callers pass small values, so no existing vulnerability exists.

**Likelihood:** Impact 1.5 (data integrity issue if misused in future) x Likelihood 0.5 (requires new caller with large integers) x 4 = 1.5 (rounded from 3.0 -- mitigated by current caller profile)

**Evidence:**

`src/asn1.zig:465-474`:

```zig
pub fn readInteger(tlv: TLV) u64 {
    var result: u64 = 0;
    for (tlv.val) |byte| {
        result = (result << 8) | byte;
        // Silent overflow if tlv.val.len > 8
    }
    return result;
}
```

**Fix guidance:** Add a length check: `if (tlv.val.len > 8) return error.IntegerOverflow;`. Change the return type to `!u64` or `error{IntegerOverflow}!u64`.

**Acceptance criteria:**

- `readInteger` returns an error for integers > 8 bytes.
- All existing callers handle the error (or remain unaffected because they pass small values).
- Existing X.509 parsing tests pass.

**How to verify:** Add a test with a 9-byte ASN.1 INTEGER and confirm it returns `error.IntegerOverflow`.

**References:** CWE-190 (Integer Overflow or Wraparound), OWASP A07:2021

**Affected paths:** `src/asn1.zig:465-474`

**SLA:** 180 days (due 2026-09-21)

---

#### SEC-053: `encodeHandshake` no 24-bit length check (Info, Risk 0.3) -- ACCEPTABLE RISK

**Summary:** The `encodeHandshake` function at `messages.zig:91` writes a handshake message length as a 24-bit (3-byte) big-endian value. There is no explicit check that the message length fits in 24 bits (max 16,777,215 bytes). However, this is practically unexploitable because Zig's allocator and the TLS record layer's 16KB fragment limit prevent messages from approaching this size.

**Impact:** None in practice. The TLS record layer fragments messages at 16KB. Even reassembled handshake messages (e.g., large certificate chains) are bounded by the `MAX_HANDSHAKE_BUFFER` limit (64KB, SEC-018). A 16MB handshake message is not achievable.

**Likelihood:** Impact 1 (protocol violation) x Likelihood 0.075 (requires bypassing multiple size limits) x 4 = 0.3

**Evidence:**

`src/tls13/messages.zig:91`:

```zig
// Writes length as 3 bytes (24-bit) without checking overflow
std.mem.writeInt(u24, buf[1..4], @intCast(body.len), .big);
```

**Fix guidance:** No action required. Existing buffer size limits (SEC-018) make overflow impossible. For defense-in-depth, could add `if (body.len > std.math.maxInt(u24)) return error.MessageTooLarge;`.

**Acceptance criteria:** Documented as acceptable risk.

**References:** CWE-190 (Integer Overflow or Wraparound), OWASP A07:2021

**Affected paths:** `src/tls13/messages.zig:91`

**SLA:** Backlog (acceptable risk)

---

### Handshake Negotiation (Phase 5)

#### SEC-028: Client does not validate server-selected cipher suite was in offered list (High, Risk 64)

**Summary:** When the client receives a ServerHello, it accepts whatever cipher suite the server selected without verifying it was in the client's offered list. RFC 8446 Section 4.1.3 requires: "A client which receives a cipher suite that was not offered MUST abort the handshake with an 'illegal_parameter' alert."

**Impact:** A malicious server (or MITM attacker) can force the client to use any cipher suite, including potentially weaker ones that the client intentionally excluded. This undermines the client's security policy for cipher suite selection. Impact 4 (authentication/crypto bypass) x Likelihood 4 (remote, any TLS connection to rogue server) x 4 = 64.

**Likelihood:** Any client connecting to a malicious server is vulnerable. No authentication required. The attack surface is internet-facing.

**Evidence:**

`src/tls13/context.zig:2492-2494`:

```zig
const suite_value: u16 = readU16(body[pos .. pos + 2]);
const cipher_suite = std.meta.intToEnum(tls13_full.CipherSuite, suite_value) catch return HandshakeError.NoCipherSuite;
self.negotiated_cipher_suite = cipher_suite;
```

The code only checks that the value is a valid `CipherSuite` enum variant. It does not verify that this suite was in the list offered in the ClientHello.

**Attack scenario:**

1. Client offers only AES-256-GCM cipher suites in its ClientHello.
2. Malicious server responds with AES-128-GCM (weaker but still a valid enum value).
3. Client accepts the downgraded cipher suite without complaint.
4. All session traffic uses the weaker algorithm the client intended to exclude.

**Fix guidance:**

1. Store the list of cipher suites offered in the ClientHello (or reference the config).
2. After parsing `cipher_suite` from ServerHello, verify it appears in the offered list.
3. If not found, return `HandshakeError.IllegalParameter` and send an `illegal_parameter` alert.

**Acceptance criteria:**

- Client rejects ServerHello containing a cipher suite not in the offered list.
- Test: configure client with restricted cipher suite list, mock server responds with excluded suite, verify handshake fails with `IllegalParameter`.
- Normal handshakes with valid suite selection still succeed.

**How to verify:** Add test case in `tests/rfc8446/section_4_1_3_server_hello.zig` with a server that selects a non-offered suite.

**References:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation), OWASP A02:2021 (Cryptographic Failures), RFC 8446 Section 4.1.3

**Affected paths:** `src/tls13/context.zig`

**SLA:** 30 days

**Status: Closed** (2026-03-24) -- Added cipher suite validation against offered list at `context.zig:2511-2522`. After parsing the server-selected cipher suite, the code iterates `self.config.supported_cipher_suites` and returns `HandshakeError.NoCipherSuite` if the suite is not found.

---

#### SEC-029: Hostname validation silently skipped when server_name is null (High, Risk 80)

**Summary:** When the client's `config.server_name` is null, the code passes an empty string to `validateChain`. Inside `validateChain`, `matchDnsName` is only called when `server_name.len != 0`, meaning hostname validation is entirely skipped. Any valid certificate from any CA is accepted regardless of its subject. This is a fail-open design that enables MITM attacks.

**Impact:** An attacker with any valid certificate (e.g., obtained for a domain they control) can MITM connections from clients that have not set `server_name`. This is particularly dangerous because `server_name` defaults to null in the config, making unvalidated connections the default behavior. Impact 5 (complete authentication bypass / MITM) x Likelihood 4 (remote, requires client config omission) x 4 = 80.

**Likelihood:** Any client that does not explicitly set `server_name` is vulnerable. Internet-facing. The default configuration is the vulnerable state.

**Evidence:**

`src/tls13/context.zig:2934`:

```zig
const server_name = if (self.config.server_name) |sni| sni else "";
```

`src/x509.zig:1511`:

```zig
if (server_name.len != 0 and !matchDnsName(&certs[0], server_name)) return error.NameMismatch;
```

When `server_name` is `""`, the `server_name.len != 0` check is false, so `matchDnsName` is never called. Any certificate with a valid chain passes validation regardless of its subject/SAN.

**Attack scenario:**

1. Application creates TLS context without setting `server_name` (using default null).
2. Attacker obtains a valid certificate for `evil.com` from a public CA.
3. Attacker performs MITM on the connection, presenting the `evil.com` certificate.
4. Client validates the chain (it chains to a trusted CA) but never checks the hostname.
5. Connection succeeds; attacker can read and modify all traffic.

**Fix guidance:**

1. When `server_name` is null and `allow_insecure` is false, return an error from the client handshake path. Hostname validation must be mandatory for secure connections.
2. Alternatively, require `server_name` to be non-null in `Context.init()` when operating in secure mode.
3. Document that `server_name` is security-critical and must always be set.

**Acceptance criteria:**

- Client handshake with null `server_name` and `allow_insecure = false` produces a clear error.
- Client handshake with a valid `server_name` continues to work correctly.
- `allow_insecure = true` still allows null `server_name` for testing.

**How to verify:** Test that `Context.init()` or `processServerHello()` returns an error when `server_name` is null and `allow_insecure` is false.

**References:** CWE-295 (Improper Certificate Validation), OWASP A07:2021 (Identification and Authentication Failures), RFC 6125 Section 6

**Affected paths:** `src/tls13/context.zig`, `src/x509.zig`

**SLA:** 30 days

**Status: Closed** (2026-03-24) -- Added `MissingServerName` error variant to `types.zig:218` and alert mapping in `alert.zig:128`. When `server_name` is null and `allow_insecure` is false, `context.zig:2955` returns `HandshakeError.MissingServerName` instead of passing an empty string.

---

### Certificate Validation (Phase 5)

#### SEC-030: Self-signed cert bypasses EKU, hostname, and KeyUsage checks (Medium, Risk 48)

**Summary:** When `validateChain` encounters a single self-signed certificate (chain length 1, subject equals issuer), it skips hostname validation, EKU checking, and KeyUsage checking. Only validity period and the CA basic constraint are verified. This means a self-signed certificate for `evil.com` would be accepted when connecting to `example.com`.

**Impact:** Any self-signed trust anchor bypasses critical security checks. If a self-signed certificate is in the trust store, it is accepted regardless of hostname mismatch or inappropriate key usage. Impact 4 (authentication bypass for trust anchor scenario) x Likelihood 3 (requires self-signed cert in trust path; common in internal PKI) x 4 = 48.

**Likelihood:** Common in internal PKI deployments, development environments, and any scenario where self-signed certificates are used as trust anchors.

**Evidence:**

`src/x509.zig:1503-1526`:

```zig
const is_single_self_signed = chain_der.len == 1 and
    std.mem.eql(u8, certs[0].subject_der, certs[0].issuer_der);

// Leaf checks (skip for single self-signed certs which are trust anchors)
try checkValidity(now_unix, &certs[0]);

if (!is_single_self_signed) {
    if (server_name.len != 0 and !matchDnsName(&certs[0], server_name)) return error.NameMismatch;
    if (certs[0].eku) |eku| if (!eku.server_auth) return error.EkuNotAllowed;
    if (certs[0].ku) |ku| {
        if (!keyUsageHas(ku, key_usage_digital_signature)) return error.KuNotAllowed;
    }
    // ...
} else {
    // For self-signed roots, verify CA flag is set
    if (certs[0].basic) |b| {
        if (!b.ca) return error.BasicConstraints;
    }
}
```

The `if (!is_single_self_signed)` branch contains all hostname, EKU, and KeyUsage checks. The `else` branch only checks `CA=true`.

**Fix guidance:**

1. Apply hostname validation to self-signed certificates (remove the `is_single_self_signed` exemption for `matchDnsName`).
2. Consider applying EKU checks as well, or document the intentional exemption with a clear security rationale.
3. At minimum, hostname validation should never be skipped for any certificate type.

**Acceptance criteria:**

- Self-signed certificates are validated against `server_name`.
- Self-signed certificate with wrong hostname returns `NameMismatch`.
- Existing self-signed trust anchor tests updated to use matching hostnames.

**References:** CWE-295 (Improper Certificate Validation), CWE-863 (Incorrect Authorization), OWASP A07:2021, RFC 6125

**Affected paths:** `src/x509.zig`

**SLA:** 90 days

**Status: Closed** (2026-03-24) -- Moved hostname and EKU validation outside the `is_single_self_signed` guard at `x509.zig:1567-1572`. Self-signed certs now undergo hostname validation via `matchDnsName` and EKU checking via `checkEkuPurpose`. Only the chain-walk logic (intermediate CA checks, pathLen constraints) is skipped for single self-signed certs.

---

#### SEC-031: mTLS client cert validation skips clientAuth EKU check (Medium, Risk 36)

**Summary:** When the server validates client certificates during mTLS, it calls `validateChain` with an empty hostname (correct, since client certs have no hostname). However, `validateChain` only checks for `server_auth` EKU (line 1512). The mTLS path at `context.zig:3135-3148` does not add a separate `clientAuth` EKU check. A certificate with `serverAuth` EKU but without `clientAuth` EKU would pass validation as a client certificate.

**Impact:** Certificates not authorized for client authentication could be accepted. For example, a server certificate (with only `serverAuth` EKU) could be misused as a client certificate. Impact 3 (authorization bypass) x Likelihood 3 (requires mTLS deployment + cert with wrong EKU) x 4 = 36.

**Likelihood:** Requires mTLS to be configured. The impact depends on whether the environment has certificates with only `serverAuth` that could be presented as client certs.

**Evidence:**

`src/tls13/context.zig:3135-3148`:

```zig
if (!self.config.allow_insecure) {
    // RFC 5280 Section 6: Validate client certificate chain
    // Skip hostname validation for client certs (no SNI to match against)
    const now_unix = std.time.timestamp();
    x509.validateChain(
        self.allocator,
        chain,
        now_unix,
        "", // No hostname validation for client certs
        false, // Don't skip validation
    ) catch |err| {
        traceHandshake("Server: Client certificate chain validation failed: {}\n", .{err});
        return HandshakeError.CertificateValidationFailed;
    };
```

Inside `validateChain`, line 1512 checks `eku.server_auth`:

```zig
if (certs[0].eku) |eku| if (!eku.server_auth) return error.EkuNotAllowed;
```

No `clientAuth` EKU check is performed anywhere in the mTLS validation path.

**Fix guidance:**

1. Add an `eku_mode` parameter to `validateChain` (or a separate `validateClientChain` function) that checks `eku.client_auth` instead of `eku.server_auth` for client certificates.
2. Alternatively, add the `clientAuth` EKU check in the mTLS handler after `validateChain` returns.

**Acceptance criteria:**

- Client certificates with `clientAuth` EKU pass mTLS validation.
- Client certificates with only `serverAuth` EKU (no `clientAuth`) are rejected.
- Client certificates without any EKU still pass (per RFC 5280 permissiveness).

**References:** CWE-295 (Improper Certificate Validation), OWASP A07:2021, RFC 5280 Section 4.2.1.12

**Affected paths:** `src/tls13/context.zig`, `src/x509.zig`

**SLA:** 90 days

**Status: Closed** (2026-03-24) -- Added `EkuPurpose` enum (`server_auth`, `client_auth`) at `x509.zig:321-332` with `checkEkuPurpose` helper at `x509.zig:329-332`. `validateChain` now accepts an `eku_purpose` parameter. Server-side mTLS path at `context.zig:3172` passes `.client_auth`. Client-side path passes `.server_auth`. The `engine.zig` and `parallel.zig` call sites also updated.

---

### X.509 Parsing (Phase 5)

#### SEC-032: parseDerTime accepts invalid month/day values (Medium, Risk 48)

**Summary:** The `parseDerTime` function in `x509.zig` parses ASN.1 DER time values but does not validate that month and day values are within legal ranges. A month value of 14 or higher causes an out-of-bounds array access in `daysBeforeMonth`, where `mdays[m-1]` is accessed with `m=13` (index 12) on a 12-element array. In safe (debug) builds, this triggers a panic. In release builds (`ReleaseFast`/`ReleaseSmall`), this is undefined behavior.

**Impact:** Malformed certificates with invalid date fields can trigger UB in release builds or panics in debug builds. An attacker could craft a certificate with month=14 to crash the TLS handshake process. Impact 4 (denial of service / potential memory corruption in release) x Likelihood 3 (requires malformed cert to reach parser; pre-auth for server-presented certs) x 4 = 48.

**Likelihood:** Any TLS client that parses a malicious server certificate is exposed. The certificate does not need to be signed by a trusted CA to trigger the parsing code (parsing happens before chain validation).

**Evidence:**

`src/x509.zig:552-573` (no range check on month/day):

```zig
const month = try std.fmt.parseInt(u8, bytes[2..4], 10);
const day = try std.fmt.parseInt(u8, bytes[4..6], 10);
// ... no validation that month is in [1,12] or day is in [1,31]
return unixSecondsFromYMDHMS(year, month, day, hh, mm, ss);
```

`src/x509.zig:532-539` (OOB access path):

```zig
fn daysBeforeMonth(year: u16, month: u8) i64 {
    const mdays = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var d: i64 = 0;
    var m: u8 = 1;
    while (m < month) : (m += 1) {
        if (m == 2 and isLeap(year)) d += 29 else d += mdays[m - 1];
    }
    return d;
}
```

When `month >= 14`, the loop variable `m` reaches 13, and `mdays[13 - 1] = mdays[12]` is out of bounds (array has indices 0-11).

**Fix guidance:** Add validation at the start of `parseDerTime` or `unixSecondsFromYMDHMS`:

```zig
if (month < 1 or month > 12) return error.InvalidTime;
if (day < 1 or day > 31) return error.InvalidTime;
if (hh > 23 or mm > 59 or ss > 59) return error.InvalidTime;
```

**Acceptance criteria:**

- `parseDerTime` returns an error for month=0, month=13, day=0, day=32.
- Valid DER time strings continue to parse correctly.
- Test with boundary values: month=1, month=12, day=1, day=31.

**References:** CWE-1284 (Improper Validation of Specified Quantity in Input), CWE-125 (Out-of-bounds Read), OWASP A07:2021

**Affected paths:** `src/x509.zig`

**SLA:** 90 days

**Status: Closed** (2026-03-24) -- Added `validateTimeFields` function at `x509.zig:603-612` that validates month (1-12), day (1-31), hour (0-23), minute (0-59), second (0-59). Called from `parseDerTime` before `unixSecondsFromYMDHMS`. Returns `error.UnsupportedTimeFormat` for out-of-range values.

---

### Name Constraints (Phase 5)

#### SEC-033: matchesNameConstraint uses case-sensitive comparison (Medium, Risk 48)

**Summary:** The `matchesNameConstraint` function in `x509.zig` uses `std.mem.eql` for both exact match and suffix match comparisons. RFC 5280 Section 4.2.1.10 requires case-insensitive matching for DNS name constraints. A name constraint for `.Example.COM` would fail to match `www.example.com` despite being semantically equivalent.

**Impact:** Name constraints can be bypassed by using different letter casing in certificate DNS names. An attacker who obtains a certificate for `WWW.EXAMPLE.COM` could bypass a name constraint that only permits `.example.com`. Impact 4 (constraint bypass / authorization failure) x Likelihood 3 (requires mixed-case names in constrained PKI) x 4 = 48.

**Likelihood:** Likely in environments with name constraints (enterprise PKI, constrained CA hierarchies). Mixed-case DNS names are uncommon but valid per DNS standards.

**Evidence:**

`src/x509.zig:1152-1162`:

```zig
pub fn matchesNameConstraint(name: []const u8, constraint: []const u8) bool {
    if (constraint.len > 0 and constraint[0] == '.') {
        if (name.len < constraint.len) return false;
        const suffix = name[name.len - constraint.len ..];
        return std.mem.eql(u8, suffix, constraint);  // case-sensitive
    } else {
        return std.mem.eql(u8, name, constraint);  // case-sensitive
    }
}
```

Both comparisons use `std.mem.eql` which is byte-exact.

**Fix guidance:** Replace `std.mem.eql(u8, ...)` with `std.ascii.eqlIgnoreCase(...)` in both comparison paths. DNS names are ASCII and case-insensitive per RFC 4343.

**Acceptance criteria:**

- `matchesNameConstraint("www.Example.COM", ".example.com")` returns true.
- `matchesNameConstraint("EXAMPLE.COM", "example.com")` returns true.
- Existing name constraint tests updated with mixed-case scenarios.

**How to verify:** Add test cases in `tests/conformance/openssl/name_constraints.zig` with mixed-case DNS names.

**References:** CWE-178 (Improper Handling of Case Sensitivity), OWASP A07:2021, RFC 5280 Section 4.2.1.10, RFC 4343

**Affected paths:** `src/x509.zig`

**SLA:** 90 days

**Status: Closed** (2026-03-24) -- Replaced `std.mem.eql` with `toLowerAscii`-based case-insensitive comparison at `x509.zig:1131-1151`. Both exact match and suffix match paths now use per-byte `toLowerAscii` comparison per RFC 5280 Section 4.2.1.10 and RFC 4343.

---

### Supply Chain (Phase 5)

#### SEC-034: Dependency fetched from mutable main branch URL (Medium, Risk 32)

**Summary:** The `spice` dependency in `build.zig.zon` is fetched from a mutable URL that references the `main` branch (`spice-main.tar.gz`). While a hash is specified, the URL points to a moving target. If the hash is ever updated without reviewing the new content, a compromised upstream could inject malicious code.

**Impact:** Supply chain compromise if the dependency hash is updated without proper review. The hash provides integrity checking for the current fetch, but the mutable URL means the "expected" content changes over time. Impact 4 (potential code injection) x Likelihood 2 (requires hash update without review; hash currently provides protection) x 4 = 32.

**Likelihood:** Low in practice because the Zig build system enforces hash verification. The risk materializes only when the hash is updated (e.g., via `zig fetch --save`). Requires the upstream `main` branch to be compromised at that moment.

**Evidence:**

`build.zig.zon:37`:

```zig
.spice = .{
    .url = "https://gitlab.com/devnw/zig/spice/-/archive/main/spice-main.tar.gz",
    .hash = "spice-0.0.0-HnDb58jJAACojBd1dquGT-Ngc6TORlC6izlAKf0f4Rno",
},
```

The URL contains `/main/` indicating it tracks the mutable default branch.

**Fix guidance:** Pin the dependency to a specific commit SHA or tagged release:

```zig
.url = "https://gitlab.com/devnw/zig/spice/-/archive/<commit-sha>/spice-<commit-sha>.tar.gz",
```

**Acceptance criteria:**

- Dependency URL references a specific immutable commit SHA or tag, not a branch name.
- Build still succeeds with the pinned version.
- Document the update process for the pinned dependency.

**References:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), OWASP A08:2021 (Software and Data Integrity Failures)

**Affected paths:** `build.zig.zon`

**SLA:** 90 days

**Status: Closed** (2026-03-24) -- Dependency URL pinned to commit SHA `bbf106dc8131a514a4d1687cc2173f124f5c8181` at `build.zig.zon:38`. URL now references immutable archive path instead of mutable `/main/` branch.

---

### HRR and Rekey Paths (Phase 5)

#### SEC-035: HRR session_id length not bounds-checked against body.len (Low, Risk 24)

**Summary:** In the HelloRetryRequest handler at `context.zig:1454-1455`, `sid_len` is read from `body[pos]` and then `pos` is advanced by `1 + sid_len` without first checking that `pos + 1 + sid_len <= body.len`. If a malicious server sends a truncated HRR with a large `sid_len`, this could cause an integer overflow in the `pos` addition in release builds, or a panic in debug builds.

**Impact:** Denial of service via crafted HRR message. In release builds, the overflow could cause out-of-bounds reads. Impact 3 (DoS / potential OOB read) x Likelihood 2 (requires malicious server + HRR negotiation) x 4 = 24.

**Likelihood:** Requires the server to trigger HelloRetryRequest, which is an uncommon handshake path. The attacker must be the server or a MITM.

**Evidence:**

`src/tls13/context.zig:1454-1455`:

```zig
const sid_len: usize = body[pos];
pos += 1 + sid_len;
```

The next check at line 1458 (`if (pos + 2 + 1 > body.len)`) would catch the overflow in many cases, but if `1 + sid_len` wraps `pos` past `body.len` such that the subsequent check passes (possible with large `sid_len`), memory safety is violated.

**Fix guidance:** Add explicit bounds check: `if (pos + 1 + sid_len > body.len) return HandshakeError.UnexpectedMessage;` immediately after reading `sid_len`.

**Acceptance criteria:**

- HRR with `sid_len` exceeding remaining body length returns `UnexpectedMessage`.
- Valid HRR messages still parse correctly.

**References:** CWE-120 (Buffer Copy without Checking Size of Input), OWASP A07:2021

**Affected paths:** `src/tls13/context.zig`

**SLA:** 180 days

**Status: Closed** (2026-03-24) -- Added bounds check `if (pos + 1 + sid_len > body.len) return HandshakeError.UnexpectedMessage;` at `context.zig:1456`, immediately after reading `sid_len`.

---

#### SEC-036: Client private key not zeroized on HRR rekey path (Low, Risk 16)

**Summary:** In `sendClientHello2` at `context.zig:1532-1538`, when a HelloRetryRequest triggers re-keying, a new X25519 private key is generated and written to `self.client_priv`. The previous value of `client_priv` is overwritten without being zeroized first. The old key material remains in memory until the field happens to be reused or freed.

**Impact:** The original X25519 private key persists in the `client_priv` field's previous memory location (if the field is stack-allocated or inline). While `self.client_priv = priv` performs a value copy, the old value in `self.client_priv` is simply overwritten, not securely erased. Impact 2 (ephemeral key leak, limited window) x Likelihood 2 (requires HRR + memory read at precise time) x 4 = 16.

**Likelihood:** Requires HRR to be triggered (uncommon), plus memory inspection between key generation events. Low practical risk.

**Evidence:**

`src/tls13/context.zig:1532-1538`:

```zig
var priv: [32]u8 = undefined;
std.crypto.random.bytes(&priv);
const pub_key = std.crypto.dh.X25519.recoverPublicKey(priv) catch {
    return HandshakeError.UnsupportedKeyShareGroup;
};

self.client_priv = priv;  // Old client_priv overwritten without secureZero
self.client_pub = pub_key;
```

**Fix guidance:** Add `std.crypto.secureZero(u8, &self.client_priv);` before `self.client_priv = priv;` to clear the old key. Also add `defer std.crypto.secureZero(u8, &priv);` to clear the stack copy.

**Acceptance criteria:**

- Old `client_priv` is securely zeroed before being overwritten on the HRR path.
- Stack-local `priv` is zeroed after copy to `self.client_priv`.
- HRR handshake tests pass.

**References:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), OWASP A02:2021

**Affected paths:** `src/tls13/context.zig`

**SLA:** 180 days

**Status: Closed** (2026-03-24) -- Added `secureZero` on old `client_priv` before overwrite at `context.zig:1534-1538`. When `self.client_priv` is non-null, the old key is zeroized and set to null before generating the new key.

---

#### SEC-037: sendClientHello2 does not explicitly clamp X25519 private key (Low, Risk 12)

**Summary:** In `sendClientHello2` at `context.zig:1532-1534`, the X25519 private key is generated from random bytes without explicit clamping (clearing the low 3 bits and setting bit 254). Zig's `std.crypto.dh.X25519.recoverPublicKey` and `scalarmult` perform internal clamping during computation, so the DH output is correct. However, the Engine's equivalent code performs explicit clamping, creating an inconsistency.

**Impact:** No cryptographic impact. Zig's X25519 implementation internally clamps the scalar during computation, so the DH result is correct regardless. The concern is code consistency and defense-in-depth. Impact 3 (code quality / defense-in-depth) x Likelihood 1 (theoretical; no practical exploit) x 4 = 12.

**Likelihood:** Purely theoretical. Would only matter if the X25519 implementation changed to not internally clamp, which would break the public API contract.

**Evidence:**

`src/tls13/context.zig:1532-1534`:

```zig
var priv: [32]u8 = undefined;
std.crypto.random.bytes(&priv);
const pub_key = std.crypto.dh.X25519.recoverPublicKey(priv) catch { ... };
```

No explicit clamping step (`priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;`) before use.

**Fix guidance:** Add explicit clamping after `random.bytes` for consistency with other code paths and defense-in-depth. This makes the code self-documenting about X25519 key requirements.

**Acceptance criteria:**

- Explicit clamping applied to the private key before use.
- Handshake tests pass.
- Comment documents why clamping is applied (defense-in-depth).

**References:** CWE-326 (Inadequate Encryption Strength), OWASP A02:2021, RFC 7748 Section 5

**Affected paths:** `src/tls13/context.zig`

**SLA:** Backlog

**Status: Closed** (2026-03-24) -- Added explicit X25519 clamping at `context.zig:1543-1549`: `priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;` with comment referencing RFC 7748 Section 5 and consistency with `engine.zig`'s `ensureKeypair()`.

---

### Runtime Safety (Phase 5)

#### SEC-038: Global mutable TrustStore creates theoretical TOCTOU window (Info, Risk 12)

**Summary:** The global `TrustStoreState` at `x509.zig:134-155` is a `var` with a read-write lock. The lock protects individual reads and writes, but there is a theoretical TOCTOU (time-of-check-to-time-of-use) window: a trust store could be modified between the time it is read by `validateChain` and the time validation completes. In practice, this is benign because: (1) Zig does not support dynamic library unloading, so the trust store function pointer remains valid; (2) trust store changes during active handshakes are an administrative operation.

**Impact:** Theoretical only. If the trust store is changed mid-validation, a certificate could be validated against the wrong trust store. Impact 3 (validation inconsistency) x Likelihood 1 (requires precise timing + administrative action during handshake) x 4 = 12.

**Likelihood:** Extremely unlikely in practice. Requires simultaneous trust store modification and active handshake validation.

**Evidence:**

`src/x509.zig:134-155`:

```zig
const TrustStoreState = struct {
    store: ?TrustStore = null,
    lock: std.Thread.RwLock = .{},

    fn get(self: *TrustStoreState) ?TrustStore {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.store;
    }

    fn set(self: *TrustStoreState, ts: ?TrustStore) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.store = ts;
    }
};

var g_trust_store_state: TrustStoreState = .{};
```

**Fix guidance:** No action required. Document the design decision. If stronger guarantees are needed in the future, consider using an epoch-based reclamation scheme or holding the read lock for the duration of validation.

**References:** CWE-367 (Time-of-check Time-of-use Race Condition), OWASP A04:2021 (Insecure Design)

**Affected paths:** `src/x509.zig`

**SLA:** Backlog

**Status: Won't Do** (2026-03-24) -- Benign; Zig lacks dynamic library unloading, and trust store changes during active handshakes are an administrative operation with negligible practical risk.

---

### Logging and Debug (Phase 5)

#### SEC-039: Handshake trace may leak error details in production (Info, Risk 8)

**Summary:** The `traceHandshake` calls at `context.zig:2950` and `context.zig:3146` log certificate validation error details. Unlike the secret-trace functions (`sig_trace_enabled`, `secret_trace_enabled`), the handshake trace does not have a `@compileError` guard that prevents it from being active in release builds. If handshake tracing is enabled in production, error messages could leak information about the server's certificate validation logic.

**Impact:** Information disclosure about validation failures. The leaked information (error type, failure point) could help an attacker craft certificates that bypass specific checks. Impact 1 (information leak, limited) x Likelihood 2 (requires trace enabled in production) x 4 = 8.

**Likelihood:** Requires handshake tracing to be explicitly enabled in a production build. Low probability but worth noting for consistency.

**Evidence:**

`src/tls13/context.zig:2950`:

```zig
traceHandshake("Client: Certificate chain validation failed: {}\\n", .{err});
```

`src/tls13/context.zig:3146`:

```zig
traceHandshake("Server: Client certificate chain validation failed: {}\n", .{err});
```

Compare with the secret trace guard pattern in `src/sig.zig:117-120`:

```zig
comptime {
    if (sig_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: sig_trace_enabled must be false in release builds");
    }
}
```

No equivalent guard exists for `handshake_trace_enabled`.

**Fix guidance:** Add a `@compileError` guard for `handshake_trace_enabled` matching the pattern used for `sig_trace_enabled`, or ensure trace output does not include error details (only generic "validation failed" without the error enum).

**Acceptance criteria:**

- Handshake trace in release builds either (a) produces a compile error or (b) omits error-specific details.
- Debug builds retain full error tracing.

**References:** CWE-209 (Generation of Error Message Containing Sensitive Information), OWASP A09:2021 (Security Logging and Monitoring Failures)

**Affected paths:** `src/tls13/context.zig`

**SLA:** Backlog

**Status: Closed** (2026-03-24) -- `@compileError` guard added for `handshake_trace_enabled` in release builds at `src/tls13/context.zig:121-126`, matching the `sig_trace_enabled` and `secret_trace_enabled` patterns.

---

### Key Schedule and Master Secret Derivation (Phase 7)

#### SEC-047: Engine computeApplicationSecrets uses wrong context hash and IKM for master secret (High, Risk 36) -- CLOSED

**Status:** Closed (Phase 8)

**Summary:** In `engine.zig:1474-1475`, `computeApplicationSecrets` derived the master secret with two incorrect inputs: (1) an empty slice `&[_]u8{}` as the context hash for `Derive-Secret`, instead of `Hash("")` (the hash of the empty string); and (2) an empty slice `&[_]u8{}` as the IKM for `HKDF-Extract`, instead of `HashLen` zeros. This produced a master secret that did not match RFC 8446 Section 7.1.

**Resolution:** Added `emptyHash()` and `zeroSecret()` helper functions mirroring the key_derivation.zig pattern. `computeApplicationSecrets` at engine.zig:1510-1516 now uses `emptyHash(self.hash_kind)` for context and `zeroSecret(self.hash_kind)` for IKM.

**Impact:** The Engine API produces incorrect application traffic secrets. Any standards-compliant TLS 1.3 peer (OpenSSL, BoringSSL, etc.) will derive different keys, causing AEAD decryption failure on the first application data record. If both sides use this library's Engine API, the connection works but uses non-standard key material that has not been analyzed for security properties.

**Likelihood:** Impact 3 (interoperability failure, non-standard crypto) x Likelihood 3 (deterministic on every Engine handshake, internet-facing) x 4 = 36

**Evidence:**

**VULNERABLE** -- `src/tls13/engine.zig:1473-1476`:

```zig
const master = blk2: {
    const derived = ks.deriveSecretHash(self.hash_kind, &handshake_secret, "derived", &[_]u8{});
    break :blk2 ks.extractHash(self.hash_kind, derived.slice(), &[_]u8{});
};
```

Two errors:

1. Line 1474: `&[_]u8{}` (length 0) passed as context hash. RFC 8446 requires `Hash("")` -- a 32-byte (SHA-256) or 48-byte (SHA-384) digest of the empty string.
2. Line 1475: `&[_]u8{}` (length 0) passed as IKM. RFC 8446 requires `0^HashLen` -- 32 or 48 zero bytes.

**CORRECT** -- `src/tls13/key_derivation.zig:340-348`:

```zig
const eh = emptyHash(hash);
const derived = ks.deriveSecretHash(hash, handshake_secret, "derived", eh.slice());
const zero_ikm = ks.zeroSecret(hash);
const master = ks.extractHash(hash, derived.slice(), zero_ikm.slice());
```

**Attack scenario:**

1. Application uses the Engine API for TLS 1.3.
2. Handshake traffic keys derive correctly (via `deriveHandshakeTraffic`).
3. `computeApplicationSecrets` at line 1473-1476 derives the master secret with wrong inputs.
4. Application traffic secrets differ from what any RFC-compliant peer would compute.
5. First application data record fails AEAD decryption; connection terminates.

**How to verify:** Compare Engine `computeApplicationSecrets` output against RFC 8448 test vectors or against Context `deriveApplicationTraffic` output for identical handshake transcripts and shared secrets.

**Fix guidance:** Replace the inline derivation with the correct pattern:

```zig
const master = blk2: {
    const eh = key_derivation_mod.emptyHash(self.hash_kind);
    const derived = ks.deriveSecretHash(self.hash_kind, &handshake_secret, "derived", eh.slice());
    const zero_ikm = ks.zeroSecret(self.hash_kind);
    break :blk2 ks.extractHash(self.hash_kind, derived.slice(), zero_ikm.slice());
};
```

Or call `key_derivation_mod.deriveApplicationTraffic()` directly.

**Acceptance criteria:**

- `computeApplicationSecrets` uses `Hash("")` (emptyHash) as context for Derive-Secret
- `computeApplicationSecrets` uses `HashLen` zeros (zeroSecret) as IKM for HKDF-Extract
- Engine produces the same application traffic secrets as the Context path for identical inputs
- Interop test: Engine connects to OpenSSL/BoringSSL and exchanges application data
- Unit test compares output against RFC 8448 test vectors

**References:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), OWASP A02:2021 (Cryptographic Failures), RFC 8446 Section 7.1, RFC 8448

**Affected paths:** `src/tls13/engine.zig:1473-1476`

**Issue:** [GitLab #123](https://gitlab.com/devnw/zig/tls/-/issues/123) (confidential)

**SLA:** 30 days (due 2026-04-23)

---

### ECDHE Key Generation (Phase 7)

#### SEC-040: startClientHandshake missing X25519 clamping (Low, Risk 8) -- CLOSED

**Status:** Closed (Phase 8)

**Summary:** `startClientHandshake` at `context.zig:2122-2126` generated an X25519 private key from random bytes without explicit clamping. Zig's `std.crypto.dh.X25519` internally clamps during computation, so the DH output was correct. However, `sendClientHello2` (fixed in SEC-037) and the Engine's `ensureKeypair` both apply explicit clamping, creating an inconsistency.

**Resolution:** Added explicit clamping (`priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;`) at `context.zig:2181-2187` with RFC 7748 S5 comment. All X25519 key generation paths now consistently clamp.

**Impact:** No cryptographic impact. Defense-in-depth concern only.

**Likelihood:** Impact 2 x Likelihood 1 (theoretical) x 4 = 8

**Evidence:**

`src/tls13/context.zig:2122-2126`:

```zig
var priv: [32]u8 = undefined;
std.crypto.random.bytes(&priv);
const client_pubkey = std.crypto.dh.X25519.recoverPublicKey(priv) catch return HandshakeError.UnsupportedKeyShareGroup;
self.client_priv = priv;
```

No explicit clamping (`priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;`) before use.

**Fix guidance:** Add explicit X25519 clamping after `random.bytes`, matching the SEC-037 pattern at `context.zig:1543-1549`.

**Acceptance criteria:**

- Explicit clamping applied before `recoverPublicKey`
- Comment references RFC 7748 Section 5
- All X25519 key generation paths consistently clamp

**References:** CWE-326 (Inadequate Encryption Strength), OWASP A02:2021, RFC 7748 Section 5

**Affected paths:** `src/tls13/context.zig:2122-2126`

**Issue:** [GitLab #126](https://gitlab.com/devnw/zig/tls/-/issues/126)

**SLA:** 180 days (due 2026-09-20)

---

#### SEC-048: Server negotiateCipherAndKeys missing X25519 clamping (Low, Risk 6) -- CLOSED

**Status:** Closed (Phase 8)

**Summary:** Server-side `negotiateCipherAndKeys` at `context.zig:1907-1909` generated an X25519 private key without explicit clamping. The key already had `defer secureZero` (line 1908), showing security awareness, but lacked the explicit clamping that other paths apply.

**Resolution:** Added explicit clamping at `context.zig:1959-1965` with RFC 7748 S5 comment, matching all other X25519 key generation paths.

**Impact:** No cryptographic impact. Defense-in-depth inconsistency.

**Likelihood:** Impact 2 x Likelihood 0.75 (theoretical) x 4 = 6

**Evidence:**

`src/tls13/context.zig:1907-1909`:

```zig
var server_priv: [32]u8 = undefined;
defer std.crypto.secureZero(u8, &server_priv);
std.crypto.random.bytes(&server_priv);
```

No explicit clamping step before `recoverPublicKey` at line 1911.

**Fix guidance:** Add explicit clamping after `random.bytes`, matching the SEC-037 pattern.

**Acceptance criteria:**

- Explicit clamping applied before `recoverPublicKey`
- Server handshake tests pass

**References:** CWE-326, OWASP A02:2021, RFC 7748 Section 5

**Affected paths:** `src/tls13/context.zig:1907-1909`

**Issue:** [GitLab #127](https://gitlab.com/devnw/zig/tls/-/issues/127)

**SLA:** 180 days (due 2026-09-20)

---

#### SEC-051: Missing X25519 clamping in `x25519KeypairAndShared` (Info, Risk 0.5) -- ACCEPTABLE RISK

**Summary:** The `x25519KeypairAndShared` function in `messages.zig:237-256` does not explicitly clamp the X25519 private key before use. However, this is a non-issue for two reasons: (1) Zig's `std.crypto.dh.X25519` implementation clamps internally per RFC 7748 Section 5, and (2) this function is not used in production handshake paths -- the Context and Engine have their own key generation with explicit clamping (SEC-037, SEC-040, SEC-048).

**Impact:** None. Internal clamping by the standard library ensures correctness. The function exists as a utility/test helper.

**Likelihood:** Impact 1 (theoretical key quality issue) x Likelihood 0.125 (stdlib clamps internally; function unused in prod) x 4 = 0.5

**Evidence:**

`src/tls13/messages.zig:237-256`:

```zig
pub fn x25519KeypairAndShared(peer_pub_opt: ?[32]u8) X25519Error!X25519Result {
    var sk: [32]u8 = undefined;
    std.crypto.random.bytes(&sk);
    // No explicit clamping -- stdlib does it internally
    const pk = std.crypto.dh.X25519.recoverPublicKey(sk) catch return error.IdentityElement;
    // ...
}
```

Zig stdlib clamping (verified in `std.crypto.dh.X25519.clampedMul`): the scalar is clamped before multiplication.

**Fix guidance:** No action required. Documented as acceptable risk. If this function is ever used in production, explicit clamping should be added for consistency with Context/Engine paths.

**Acceptance criteria:** Documented as acceptable risk.

**References:** CWE-326 (Inadequate Encryption Strength), OWASP A02:2021, RFC 7748 Section 5

**Affected paths:** `src/tls13/messages.zig:237-256`

**SLA:** Backlog (acceptable risk)

---

### Timing and Side Channels (Phase 7)

#### SEC-046: PSK identity comparison non-constant-time (Low, Risk 6) -- CLOSED

**Status:** Closed (Phase 8)

**Summary:** At `context.zig:1776`, external PSK identity matching used `std.mem.eql(u8, ident.identity, self.config.external_psk_identity.?)`. PSK identities are not secret (they are sent in cleartext in the ClientHello), but timing differences in the comparison could theoretically reveal whether a partial prefix of the identity matched.

**Resolution:** Replaced with length check followed by `std.crypto.timing_safe.compare` at `context.zig:1825`. Length check is non-secret (lengths visible in cleartext ClientHello), constant-time comparison prevents prefix timing leaks.

**Impact:** Minimal. PSK identities are transmitted in plaintext in the ClientHello per RFC 8446 Section 4.2.11. An attacker already knows the identity being offered. However, for server-side PSK lookup across multiple configured identities, timing could reveal which identity the server recognizes.

**Likelihood:** Impact 2 (limited info disclosure) x Likelihood 0.75 (requires multiple PSK identities + timing measurement) x 4 = 6

**Evidence:**

`src/tls13/context.zig:1776`:

```zig
std.mem.eql(u8, ident.identity, self.config.external_psk_identity.?)
```

**Fix guidance:** Replace with `std.crypto.timing_safe.eql` after verifying length equality. This is defense-in-depth; the data is not secret.

**Acceptance criteria:**

- PSK identity comparison uses constant-time comparison
- PSK handshake tests pass

**References:** CWE-208 (Observable Timing Discrepancy), OWASP A02:2021, RFC 8446 Section 4.2.11

**Affected paths:** `src/tls13/context.zig:1776`

**SLA:** 180 days (due 2026-09-20)

---

### Secret Lifecycle and Zeroization (Phase 7)

#### SEC-042: deriveHandshakeTraffic intermediates not zeroized (Low, Risk 4)

**Summary:** In `key_derivation.zig:218-222`, `deriveHandshakeTraffic` computes `derived`, `handshake_secret`, `client_hs`, and `server_hs` as local `const` values that are returned or discarded. The intermediate `derived` value and the returned secrets persist on the stack without zeroization after the function returns.

**Impact:** Intermediate key derivation values remain on the stack. If a memory disclosure occurs after the function returns, an attacker could recover the handshake secret and derive all session keys.

**Likelihood:** Impact 2 (intermediate key material, not the final secret) x Likelihood 0.5 (requires stack memory read after function return) x 4 = 4

**Evidence:**

`src/tls13/key_derivation.zig:218-222`:

```zig
const derived = ks.deriveSecretHash(hash, early_secret, "derived", eh.slice());
const handshake_secret = ks.extractHash(hash, derived.slice(), ecdhe_secret);
const client_hs = ks.deriveSecretHash(hash, &handshake_secret, "c hs traffic", transcript_hash.slice());
const server_hs = ks.deriveSecretHash(hash, &handshake_secret, "s hs traffic", transcript_hash.slice());
```

All are `const`; no `defer secureZero` is possible without changing to `var`.

**Fix guidance:** Change `const` to `var` for intermediate values and add `defer` zeroization. The return value will be copied before defer runs.

**Acceptance criteria:**

- `derived` and `handshake_secret` intermediates are zeroized after use
- Handshake tests pass

**References:** CWE-226 (Sensitive Information in Resource Not Removed Before Reuse), OWASP A02:2021

**Affected paths:** `src/tls13/key_derivation.zig:218-222`

**SLA:** 180 days (due 2026-09-20)

---

#### SEC-043: deriveApplicationTraffic intermediates not zeroized (Low, Risk 4)

**Summary:** In `key_derivation.zig:340-351`, `deriveApplicationTraffic` computes `derived`, `zero_ikm`, `master`, `client_app`, `server_app`, and `exporter_master` as local `const` values. The intermediate values (`derived`, `zero_ikm`, `master`) are not zeroized after the function returns.

**Impact:** Same as SEC-042 -- intermediate key material persists on the stack.

**Likelihood:** Impact 2 x Likelihood 0.5 x 4 = 4

**Evidence:**

`src/tls13/key_derivation.zig:340-351`:

```zig
const eh = emptyHash(hash);
const derived = ks.deriveSecretHash(hash, handshake_secret, "derived", eh.slice());
const zero_ikm = ks.zeroSecret(hash);
const master = ks.extractHash(hash, derived.slice(), zero_ikm.slice());
const client_app = ks.deriveSecretHash(hash, &master, "c ap traffic", transcript_hash.slice());
const server_app = ks.deriveSecretHash(hash, &master, "s ap traffic", transcript_hash.slice());
const exporter_master = ks.deriveSecretHash(hash, &master, "exp master", transcript_hash.slice());
```

**Fix guidance:** Change `derived`, `zero_ikm`, and `master` to `var` and add `defer secureZero`.

**Acceptance criteria:**

- `derived`, `zero_ikm`, and `master` intermediates zeroized after use
- Application traffic derivation tests pass

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/tls13/key_derivation.zig:340-351`

**SLA:** 180 days (due 2026-09-20)

---

#### SEC-041: expandLabelHash PRK copy not zeroized (Low, Risk 3)

**Summary:** In `key_schedule.zig:143-150`, `expandLabelHash` copies the PRK into a fixed-size array `arr` for HKDF-Expand. The `arr` variable is not zeroized after use. It contains the raw PRK (pseudorandom key), which is intermediate key material.

**Impact:** PRK copy persists on the stack after the function returns. The PRK is also available via the caller's Secret struct, so this is a secondary exposure.

**Likelihood:** Impact 1.5 (secondary copy of already-held key material) x Likelihood 0.5 x 4 = 3

**Evidence:**

`src/key_schedule.zig:143-150`:

```zig
.sha256 => {
    var arr: [Sha256.digest_length]u8 = undefined;
    @memcpy(arr[0..], prk_slice);
    HkdfSha256.expand(out, info, arr);
},
.sha384 => {
    var arr: [Sha384.digest_length]u8 = undefined;
    @memcpy(arr[0..], prk_slice);
    HkdfSha384.expand(out, info, arr);
},
```

No `defer secureZero(u8, &arr)` after the expand call.

**Fix guidance:** Add `defer std.crypto.secureZero(u8, &arr);` after `@memcpy` in both branches.

**Acceptance criteria:**

- `arr` is zeroized after HKDF-Expand completes
- Key schedule tests pass

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/key_schedule.zig:143-150`

**SLA:** 180 days (due 2026-09-20)

---

### Type Safety (Phase 7)

#### SEC-045: @ptrCast on PSK binder/identity bypasses type safety (Info, Risk 2)

**Summary:** At `context.zig:506,512,514`, `@ptrCast` is used to convert between owned and view types for PSK identities, binders, and ALPN lists. While the memory layouts are documented as equivalent, `@ptrCast` bypasses Zig's type system and could cause undefined behavior if the layouts ever diverge.

**Impact:** Theoretical type confusion. The casts are documented with inline comments explaining the layout equivalence. In practice, the types are defined adjacently and reviewed together, making layout divergence unlikely.

**Likelihood:** Impact 1 (theoretical UB) x Likelihood 0.5 (requires type definition changes) x 4 = 2

**Evidence:**

`src/tls13/context.zig:506`:

```zig
.alpn_list = if (info.alpn_list) |list| @as([]const []const u8, @ptrCast(list)) else null,
```

`src/tls13/context.zig:512`:

```zig
.identities = @as([]const ClientHelloPskIdentityView, @ptrCast(psk.identities)),
```

`src/tls13/context.zig:514`:

```zig
.binders = @as([]const []const u8, @ptrCast(psk.binders)),
```

**Fix guidance:** Replace `@ptrCast` with explicit field-by-field construction of the view types, or add comptime assertions verifying layout equivalence:

```zig
comptime {
    std.debug.assert(@sizeOf(OwnedPskIdentity) == @sizeOf(ClientHelloPskIdentityView));
    std.debug.assert(@alignOf(OwnedPskIdentity) == @alignOf(ClientHelloPskIdentityView));
}
```

**Acceptance criteria:**

- Either `@ptrCast` is replaced with safe conversions, or comptime layout assertions are added
- PSK handshake tests pass

**References:** CWE-843 (Access of Resource Using Incompatible Type), OWASP A07:2021

**Affected paths:** `src/tls13/context.zig:506,512,514`

**SLA:** Backlog

**Status: Closed** (2026-03-24) -- `@ptrCast` replaced with explicit field-by-field conversion at `src/tls13/context.zig:452-489`. PSK handshake tests pass.

---

### Buffer Zeroization (Phase 7)

#### SEC-044: expandLabelHash fbb buffer not zeroized (Info, Risk 1)

**Summary:** In `key_schedule.zig:134`, the `fbb` stack buffer (256 bytes) used by `expandLabelHash` to construct the HKDF label is not zeroized after use. The buffer contains the HKDF label bytes (label string + context hash), which are non-secret (they encode public label names and transcript hashes).

**Impact:** None. The fbb buffer contains only HKDF label encoding, which consists of public label strings ("c hs traffic", etc.) and transcript hashes. These are not secret.

**Likelihood:** Impact 1 (non-secret data) x Likelihood 0.25 x 4 = 1

**Evidence:**

`src/key_schedule.zig:134`:

```zig
var fbb: [256]u8 = undefined;
var fba = std.heap.FixedBufferAllocator.init(&fbb);
```

No zeroing after use. The allocated info is freed via `defer alloc.free(info)` but the backing buffer is not zeroized.

**Fix guidance:** Add `defer @memset(&fbb, 0);` for defense-in-depth. Low priority since the data is non-secret.

**Acceptance criteria:**

- `fbb` buffer is zeroized after use (defense-in-depth)

**References:** CWE-226, OWASP A02:2021

**Affected paths:** `src/key_schedule.zig:134`

**SLA:** Backlog

---

## Roadmap

### Phase 11 Open Items (prioritized)

| ID | Severity | Task | Effort | SLA | Issue | Status |
|----|----------|------|--------|-----|-------|--------|
| SEC-057 | High | Replaced `@enumFromInt(SignatureScheme, alg)` with `std.enums.fromInt(...) orelse continue;` | 15 min | 30 days (2026-05-18) | [#162](https://gitlab.com/devnw/zig/tls/-/issues/162) (conf.) | **Closed 2026-04-18** |
| SEC-058 | Medium | Guarded varint length in u64 vs `data.len` / `maxInt(usize)` before `@intCast` | 30 min | 90 days (2026-07-17) | [#167](https://gitlab.com/devnw/zig/tls/-/issues/167) | **Closed 2026-04-18** |
| SEC-060 | Medium | Removed `allow_failure: true`; persisted corpus via cache; extended rules; seeded corpus | 1-2 days | 90 days (recommend 30) | [#181](https://gitlab.com/devnw/zig/tls/-/issues/181) | **Closed 2026-04-18** |
| **SEC-061** | Low | Pin 8 CI catalog components to 40-char SHAs or enable protected tags + drift monitor | 1 day | 180 days (2026-10-15) | [#184](https://gitlab.com/devnw/zig/tls/-/issues/184) | **Open** |
| SEC-059 | Low | Added `filled` counter + scope-exit defer freeing `outputs[0..filled]` in 2 parallel AEAD tests | 15 min | 180 days | [#173](https://gitlab.com/devnw/zig/tls/-/issues/173) | **Closed 2026-04-18** |

### Quick Wins (< 1 day)

| ID | Task | Effort | Status |
|----|------|--------|--------|
| SEC-057 | Replaced `@enumFromInt(SignatureScheme, alg)` at `client_hello.zig:406` with safe `std.enums.fromInt(...) orelse continue;` | 15 min | **Closed 2026-04-18** |
| SEC-058 | Compared varint length in u64 before `@intCast` at `quic_transport_params.zig:572-586` | 30 min | **Closed 2026-04-18** |
| SEC-059 | Added `filled` counter + scope-exit defer freeing partial allocations in 2 parallel AEAD tests | 15 min | **Closed 2026-04-18** |
| SEC-040 | Add explicit X25519 clamping in `startClientHandshake` | 15 min | Closed |
| SEC-048 | Add explicit X25519 clamping in `negotiateCipherAndKeys` | 15 min | Closed |
| SEC-046 | Replace `std.mem.eql` with `timing_safe` for PSK identity comparison | 15 min | Closed |
| SEC-041 | Add `defer secureZero` on PRK copy `arr` in `expandLabelHash` (2 branches) | 15 min | Closed |
| SEC-042 | Add `defer secureZero` on intermediates in `deriveHandshakeTraffic` | 30 min | Closed |
| SEC-043 | Add `defer secureZero` on intermediates in `deriveApplicationTraffic` | 30 min | Closed |
| SEC-044 | Add `defer secureZero` on fbb buffer in `expandLabelHash` | 5 min | Closed |
| SEC-045 | Replace `@ptrCast` with field-by-field conversion for PSK types | 15 min | Closed |
| SEC-032 | Add month/day range validation in `parseDerTime` | 15 min | Closed |
| SEC-033 | Replace `std.mem.eql` with `toLowerAscii` in `matchesNameConstraint` | 15 min | Closed |
| SEC-035 | Add bounds check for `sid_len` in HRR handler | 15 min | Closed |
| SEC-036 | Add `secureZero` on old `client_priv` before HRR rekey overwrite | 15 min | Closed |
| SEC-037 | Add explicit X25519 clamping in `sendClientHello2` | 15 min | Closed |
| SEC-034 | Pin spice dependency to commit SHA in `build.zig.zon` | 15 min | Closed |
| SEC-002 | Add `secureZero` call to `SecretSlot.clear()` in context.zig | 15 min | Closed |
| SEC-003 | Add `defer secureZero` for ECDSA `sk` in sig.zig | 15 min | Closed |
| SEC-004 | Bind Ed25519 seed to `var` and add `defer secureZero` in sig.zig | 15 min | Closed |
| SEC-004-R | Change `const kp` to `var kp` and add `defer secureZero` for Ed25519 KeyPair | 15 min | Closed |
| SEC-006 | Replace `else => .ed25519` with error return in context.zig (2 locations) | 30 min | Closed |
| SEC-008 | Add `secureZero` on error path in engine.zig `x25519KeypairAndShared` | 15 min | Closed |
| SEC-015 | Add `defer secureZero(u8, &server_priv)` in context.zig | 15 min | Closed |
| SEC-016 | Change `const shared` to `var shared` + `defer secureZero` (2 locations) | 15 min | Closed |
| SEC-023 | Add `defer secureZero(u8, &sk)` after key generation in messages.zig | 15 min | Closed |
| SEC-019 | Add runtime panic for `allow_insecure` in Engine release builds | 30 min | Closed |
| SEC-024 | Add `MAX_CHAIN_DEPTH` check in x509.zig | 15 min | Closed |
| SEC-025 | Add EKU absent check or document intentional permissiveness | 15 min | Closed |
| SEC-027 | Clean up dead `.rsa_pss_sha256` fallback | 15 min | Closed |
| SEC-049 | Add `@compileError` guards on 4 trace flags (`engine.zig`, `transcript.zig`, `messages.zig`, `ocsp.zig`) | 15 min | **Closed** |
| SEC-052 | Add `IntegerOverflow` error for >8 byte ASN.1 integers in `readInteger` | 15 min | **Closed** |
| SEC-055 | Zero and null `client_priv` after `scalarmult` succeeds in `context.zig` | 15 min | **Closed** |

### Medium Effort (1-5 days)

| ID | Task | Effort | Status |
|----|------|--------|--------|
| SEC-047 | Fix Engine master secret derivation: use `emptyHash()` + `zeroSecret()` in `computeApplicationSecrets` | 1-2 days | Closed |
| SEC-029 | Fail-closed hostname validation: require server_name or error | 1-2 days | Closed |
| SEC-028 | Validate server-selected cipher suite against offered list | 1-2 days | Closed |
| SEC-030 | Apply hostname/EKU/KU checks to self-signed certs | 1-2 days | Closed |
| SEC-031 | Add clientAuth EKU check in mTLS validation path | 1-2 days | Closed |
| SEC-001 | Parse CertificateRequest signature_algorithms on client side, set `negotiated_signature` | 2-3 days | Closed |
| SEC-005 | Add runtime guard or comptime opt-in for `allow_insecure` in release builds | 1 day | Closed |
| SEC-009 | Refactor `x25519KeypairAndShared` to return error union | 1-2 days | Closed |
| SEC-017 | Add max capacity + FIFO eviction to TicketStore | 1 day | Closed |
| SEC-018 | Add max buffer size to CRYPTO inbound buffers (2 locations) | 1 day | Closed |
| SEC-020 | Return error on Finished verification failure in Engine | 1-2 days | Closed |
| SEC-021 | Make cert validation failure fatal or verify `peer_cert_ok` gates data flow | 1-2 days | Closed |
| SEC-050 | Add `defer secureZero` on `priv` + errdefer for `client_priv` in `startClientHandshake` and `sendClientHello2` | 1-2 days | **Closed** |
| SEC-054 | Add errdefer for allocated slices in `parseClientHello` error paths | 1-2 days | **Closed** |
| SEC-060 | Removed `allow_failure: true`, persisted fuzz corpus via branch-keyed cache, extended rules, seeded regression corpus | 1-2 days | **Closed 2026-04-18** |
| **SEC-061** | Pin 8 CI catalog components to immutable SHAs (or protect tags + add drift alert) | 1 day | **Open** |

### Strategic (> 5 days)

| ID | Task | Effort |
|----|------|--------|
| SEC-007 | Implement CRL distribution point fetching or mandatory OCSP enforcement -- **Closed** (limitation documented in lib.zig + x509.zig) | 5-10 days |

---

## Methodology

- **Manual code review** of all cryptographic signing, key derivation, and secret lifecycle paths.
- **Cross-reference** between duplicate implementations (context.zig vs secrets.zig SecretSlot, messages.zig vs engine.zig x25519).
- **Pattern matching** against CWE/OWASP categories for TLS implementations.
- **Comparison** with RFC 8446 requirements for signature algorithm negotiation and key zeroization.
- **Phase 4 additions**: ECDHE lifecycle audit (server_priv, shared secret), DoS surface analysis (TicketStore, buffer bounds), certificate validation flow analysis (Finished/cert failure handling).
- **Phase 5 additions**: Cipher suite negotiation RFC compliance, hostname validation fail-open analysis, X.509 self-signed bypass, DER time parsing safety, name constraint case sensitivity, mTLS EKU validation, supply chain dependency pinning, HRR rekey path audit.
- **Phase 7 additions**: Engine key schedule correctness audit (emptyHash vs empty slice, zeroSecret vs empty IKM), X25519 clamping consistency across all key generation paths, PSK identity timing analysis, key derivation intermediate zeroization audit, `@ptrCast` type safety review.
- **Phase 10 additions**: Adversarial review of trace flag compile guards across all files, error-path key zeroization audit (`startClientHandshake`, `sendClientHello2`), ASN.1 integer overflow analysis, ClientHello memory leak audit, post-DH private key lifetime analysis, unconditional debug logging in error paths, handshake message length overflow analysis.
- **Phase 11 additions (2026-04-18)**: Full audit of all `@enumFromInt` sites operating on attacker-controlled bytes (9 sites; 1 unsafe → SEC-057); full audit of `@intCast` on attacker-controlled length fields for 32-bit correctness (1 gap → SEC-058); CI/CD pipeline control-failure audit (2 findings → SEC-060, SEC-061); test-hygiene allocator-leak audit in `parallel.zig` (→ SEC-059); regression-verification of 6 prior High-severity resolutions (all intact).

## Confidence Notes

| ID | Confidence | What Would Confirm |
|----|------------|--------------------|
| SEC-001 | `confidence::confirmed` | Code path analysis shows `negotiated_signature` is never set on client side |
| SEC-002 | `confidence::confirmed` | Direct comparison with correct implementation in secrets.zig |
| SEC-003 | `confidence::confirmed` | Code review: no `secureZero` call on `sk` in ECDSA branch |
| SEC-004 | `confidence::confirmed` | Code review: `const seed` prevents zeroization |
| SEC-004-R | `confidence::confirmed` | Code review: `const kp` at sig.zig:547 prevents zeroization of expanded KeyPair |
| SEC-005 | `confidence::confirmed` | Grep confirms no comptime guard exists for `allow_insecure` |
| SEC-006 | `confidence::confirmed` | Direct code observation of `else => .ed25519` |
| SEC-007 | `confidence::confirmed` | Documented in x509.zig comments by the authors |
| SEC-008 | `confidence::confirmed` | Direct comparison with corrected messages.zig version |
| SEC-009 | `confidence::confirmed` | **Closed**: Now returns `X25519Error!X25519Result` error union at messages.zig:228-248 |
| SEC-010 | `confidence::confirmed` | Non-secret data; informational |
| SEC-011 | `confidence::confirmed` | Non-secret data; informational |
| SEC-012 | `confidence::confirmed` | Comptime guard verified present |
| SEC-013 | `confidence::confirmed` | Runtime bounds check verified present |
| SEC-014 | `confidence::confirmed` | Duplicate of SEC-027; dead fallback removed (verified at engine.zig:836-840) |
| SEC-015 | `confidence::confirmed` | `grep secureZero.*server_priv` returns no matches in context.zig |
| SEC-016 | `confidence::confirmed` | `grep secureZero.*shared` returns no matches in context.zig |
| SEC-017 | `confidence::confirmed` | No capacity check in TicketStore.store() |
| SEC-018 | `confidence::confirmed` | No size check before appendSlice in either location |
| SEC-019 | `confidence::confirmed` | No runtime guard on Engine.allow_insecure in release mode |
| SEC-020 | `confidence::suspected` | Need to verify if `finished_verified == false` blocks all data exchange |
| SEC-021 | `confidence::suspected` | Need to verify if `peer_cert_ok == false` blocks all data exchange |
| SEC-023 | `confidence::confirmed` | No defer secureZero on success path in x25519KeypairAndShared |
| SEC-024 | `confidence::confirmed` | No length check on chain_der before allocation |
| SEC-025 | `confidence::confirmed` | No `else` branch on EKU check at engine.zig:688 |
| SEC-026 | `confidence::suspected` | Non-secret data; defense-in-depth consideration |
| SEC-027 | `confidence::confirmed` | Dead code assignment after `peer_cert_ok = false` |
| SEC-028 | `confidence::confirmed` | Code at context.zig:2492-2494 accepts any valid enum value without checking offered list |
| SEC-029 | `confidence::confirmed` | Null server_name produces empty string; x509.zig:1511 skips matchDnsName when len==0 |
| SEC-030 | `confidence::confirmed` | `is_single_self_signed` guard at x509.zig:1510 bypasses hostname/EKU/KU checks |
| SEC-031 | `confidence::confirmed` | validateChain checks `server_auth` EKU (x509.zig:1512); no `client_auth` check exists anywhere |
| SEC-032 | `confidence::confirmed` | No range validation on month/day in parseDerTime; month>=14 causes OOB in daysBeforeMonth |
| SEC-033 | `confidence::confirmed` | `std.mem.eql` at x509.zig:1159,1162 is byte-exact; RFC 5280 requires case-insensitive |
| SEC-034 | `confidence::confirmed` | URL contains `/main/` branch reference at build.zig.zon:37 |
| SEC-035 | `confidence::suspected` | `sid_len` at context.zig:1454 not bounds-checked; confirm exploitability with crafted HRR |
| SEC-036 | `confidence::confirmed` | No secureZero on old client_priv before overwrite at context.zig:1538 |
| SEC-037 | `confidence::confirmed` | No explicit clamping; Zig's X25519 internally clamps (verified in std.crypto source) |
| SEC-038 | `confidence::confirmed` | Global mutable var at x509.zig:155; benign due to Zig's lack of dynamic unloading |
| SEC-039 | `confidence::confirmed` | **Closed**: `@compileError` guard added at context.zig:121-126 |
| SEC-040 | `confidence::confirmed` | No explicit clamping at context.zig:2122-2126; SEC-037 pattern not applied to this path |
| SEC-041 | `confidence::confirmed` | No `defer secureZero` on `arr` in either sha256/sha384 branch at key_schedule.zig:143-150 |
| SEC-042 | `confidence::confirmed` | All intermediates are `const` with no zeroization at key_derivation.zig:218-222 |
| SEC-043 | `confidence::confirmed` | All intermediates are `const` with no zeroization at key_derivation.zig:340-351 |
| SEC-044 | `confidence::confirmed` | `fbb` buffer at key_schedule.zig:134 has no zeroing; contains non-secret HKDF label data |
| SEC-045 | `confidence::confirmed` | **Closed**: `@ptrCast` replaced with field-by-field conversion at context.zig:452-489 |
| SEC-046 | `confidence::confirmed` | `std.mem.eql` at context.zig:1776; PSK identities are cleartext but timing could reveal server state |
| SEC-047 | `confidence::confirmed` | engine.zig:1474 passes `&[_]u8{}` vs key_derivation.zig:340-341 uses `emptyHash()` and `zeroSecret()` |
| SEC-048 | `confidence::confirmed` | No explicit clamping at context.zig:1907-1909; SEC-037 pattern not applied to server path |
| SEC-049 | `confidence::confirmed` | Grep confirms no `@compileError` guard exists in engine.zig, transcript.zig, messages.zig, or ocsp.zig for their trace flags |
| SEC-050 | `confidence::confirmed` | Code review: no `defer secureZero` on `priv` at context.zig:2134; no errdefer for `client_priv` at context.zig:2165+ |
| SEC-051 | `confidence::confirmed` | Code review: no explicit clamping in messages.zig:237-256; verified Zig stdlib clamps internally; function unused in production |
| SEC-052 | `confidence::confirmed` | Code review: `readInteger` at asn1.zig:465-474 reads into u64 without length check; silent truncation for >8 bytes |
| SEC-053 | `confidence::confirmed` | Code review: no 24-bit length check at messages.zig:91; mitigated by MAX_HANDSHAKE_BUFFER (SEC-018) |
| SEC-054 | `confidence::suspected` | Pattern-matched: no errdefer visible in client_hello.zig:295-497; confirm by tracing all allocations and error paths |
| SEC-055 | `confidence::confirmed` | Code review: client_priv not zeroed/nulled after scalarmult at context.zig:2317-2343; stays until deinit() |
| SEC-056 | `confidence::confirmed` | Code review: unconditional debugPrint calls at messages.zig:178 and engine.zig:660+; not gated by trace flags |
| SEC-057 | `confidence::confirmed` | Code review + deep-reviewer: `@enumFromInt(alg)` at client_hello.zig:404 is unchecked; range filter admits ~2034 non-enum values vs 14 valid tags; sibling line 337 uses safe `std.enums.fromInt` pattern; confirm with regression test injecting `0x0500` |
| SEC-058 | `confidence::confirmed` | Code review: `@intCast(length)` at quic_transport_params.zig:577 runs before `offset + len > data.len` check; varint u64 can exceed `usize` on 32-bit per RFC 9000 §16 (max 2^62-1) |
| SEC-059 | `confidence::confirmed` | Code review: no `errdefer` guarding partial loop allocations at parallel.zig:893 and :925; `std.testing.allocator` masks but does not fix |
| SEC-060 | `confidence::confirmed` | Observed: `.gitlab-ci.yml:138-164` contains job-level `allow_failure: true`, `artifacts: when: on_failure`, 60s timeout; SEC-057 slipped through this lane |
| SEC-061 | `confidence::suspected` | Observed: `.gitlab-ci.yml:11-24` pins 8 catalog components to `@v1.7.1`/`@v1.2.1`; would be confirmed by checking catalog tag-protection policy |
