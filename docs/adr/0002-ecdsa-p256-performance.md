# ADR-0002: ECDSA-P256 performance strategy

## Status

Proposed — 2026-04-21. Addresses PERF-229 (previously Open P0).

## Context

The 2026-04-21 audit (Cycle 7 / Phase 20) re-confirmed PERF-229: Zig
stdlib `std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, Sha256)` verify
is ~400-1000 µs vs BoringSSL `nistz256` at ~30-80 µs. For handshakes
where the server or peer cert uses secp256r1, this single operation
consumes 20-50% of the <2 ms handshake SLO stated in
`docs/PERF_GAP_ANALYSIS.md:6`.

P-256 is the most common cert algorithm in the public PKI (Let's Encrypt
serves P-256 by default on new issuance since 2020), so this is not a
niche path.

The library's zero-dependency invariant (stdlib only + `thread_pool`)
rules out dropping to libcrypto as a default. The stdlib implementation
uses generic Montgomery field arithmetic; a hand-optimized `nistz256`
port would be ~4 KLOC of security-critical hand-tuned code.

Three candidate strategies exist:

1. **Port nistz256 to Zig** — full performance parity with BoringSSL;
   cost: 4 KLOC of security-critical hand-tuned code; audit burden;
   ongoing maintenance against upstream Zig stdlib changes.
2. **Optional FFI to libcrypto** — performance parity at
   `-Dp256-libcrypto=true`; cost: breaks zero-deps invariant when
   enabled; callers must link OpenSSL; FFI is not memory-safe in
   Zig 0.16.
3. **Guide users to Ed25519 / RSA-2048** — zero code change; document
   that P-256 workloads will miss the <2 ms SLO until Zig stdlib
   improves or option 1 lands.

Upstream Zig issue tracker shows no in-flight P-256 performance work
(as of 2026-04-21); this option is blocked on a volunteer picking it up.

## Decision

**Adopt option 3 (guide users)** in the short term. Publish guidance in
`docs/RUNBOOK.md` and `README.md#Performance` stating:

- The library meets the <2 ms handshake SLO on Ed25519 and RSA-2048
  certificate configurations.
- For P-256 workloads, users should expect handshakes in the 2-3 ms
  range until PERF-229 is closed.
- Users needing sub-2 ms P-256 may consult their deployment for a
  libcrypto-backed TLS stack if acceptable, or wait for an upstream
  Zig stdlib improvement.

Reserve option 1 (nistz256 port) as a future opt-in module gated
behind a build flag (`-Dnistz256=true`). Do not pursue option 2 (FFI);
breaking the zero-deps invariant is a larger cost than the performance
win justifies.

Tracked benchmark: `tests/bench.zig` `benchEcdsaP256Verify` must
continue running and alerting on >10% regression from baseline. Re-open
this ADR if/when a volunteer proposes a nistz256 port.

## Consequences

- **Positive:** Zero code change required now; zero-deps invariant
  preserved; users get clear, documented expectations. PERF-229 moves
  from Open to `status::wont-fix-yet` with a clear re-open criterion.
- **Negative:** P-256 handshake SLO misses remain visible in benchmarks;
  Ed25519 / RSA-2048 become the de-facto recommended configurations.
- **Mitigations:** Land a CHANGELOG entry + README note flagging the
  P-256 performance gap so users can pick cert types deliberately.

## Follow-up

- Update `docs/PERF_GAP_ANALYSIS.md` PERF-229 row with
  `status::wont-fix-yet` and link to this ADR.
- Add `docs/RUNBOOK.md` §Performance guidance block.
- Add `README.md` §Performance note under the existing Status table.
- If a nistz256 port ever lands, update to ADR-0003 (supersede this one).

## References

- `src/sig.zig:648-654, 731-739` — ECDSA-P256 verify sites
- `tests/bench.zig` — `benchEcdsaP256Verify`
- `docs/PERF_GAP_ANALYSIS.md` — PERF-229 entry
- GitLab issue #243
- BoringSSL `crypto/fipsmodule/ec/p256-nistz.c` — reference for option 1
