# Operational Runbook

This runbook documents operational procedures for maintaining and
responding to incidents in the ztls TLS 1.3 library.

## Table of Contents

- [Build and test](#build-and-test)
- [Release process](#release-process)
- [Security advisory response](#security-advisory-response)
- [Incident triage](#incident-triage)
- [Pipeline failure diagnosis](#pipeline-failure-diagnosis)
- [Fuzz finding response](#fuzz-finding-response)
- [Performance](#performance)

## Build and test

Canonical commands (from project root):

```bash
zig build                           # Debug build
zig build -Doptimize=ReleaseSafe    # Release-safe build
zig build test                      # Unit + integration tests
zig build test --summary all        # With per-step summary
zig build bench                     # Performance benchmarks
zig fmt --check src/ tests/ build.zig
```

Pre-commit hooks run `zig fmt --check` + `zig build` on every commit;
`zig build test` runs on pre-push. If a hook fails, do not skip with
`--no-verify`: fix the underlying issue and re-stage.

## Release process

1. Update `build.zig.zon` `.version` field using SemVer.
2. Update `CHANGELOG.md` `[Unreleased]` block with release date and
   the new version header.
3. Run `zig build test` and `zig build test -Doptimize=ReleaseSafe`
   locally; both must be green.
4. Tag the release: `git tag -a v<semver> -m "Release v<semver>"`.
5. Push: `git push origin main --tags`.
6. GitLab `release-semantic` CI component takes over from there.

## Security advisory response

1. Confirm the finding in a private fork; do not open public issues
   until a patch exists.
2. Draft the fix + regression test on a branch named
   `security/<advisory-id>`.
3. Coordinate disclosure timing with the reporter; aim for a 30-day
   embargo unless active exploitation is reported.
4. On disclosure day: merge, tag, release, and publish a security
   advisory via GitLab's advisory UI.

## Incident triage

For production reports (crashes, handshake failures, protocol
deviations):

1. Gather the handshake capture (pcap) and a minimal reproducer.
2. Reproduce locally with the relevant conformance suite:
   `zig build test-<module>`.
3. If the issue is cipher- or curve-specific, check the relevant
   cross-suite test in `tests/conformance/`.
4. File a bug under `docs/GAP_ANALYSIS.md` with issue link and
   acceptance criteria.

## Pipeline failure diagnosis

| Symptom                              | Likely cause                           |
|--------------------------------------|----------------------------------------|
| `zig fmt --check` fails              | Local `zig fmt` not run before commit  |
| `zig build` fails only in CI         | Version skew between local / CI Zig    |
| Fuzz job exits non-zero (not 124)    | Actual crash; triage seed in artifacts |
| `test-release-fast` fails only       | UB caught only by ReleaseFast opt      |
| Toolchain cache miss on every build  | `ZIG_VERSION` mismatch; invalidate key |

## Fuzz finding response

1. Download the crashing seed from the `zig-out/fuzz/` artifact.
2. Replay locally: `zig build test --fuzz` with
   `ZIG_FUZZ_SEED=<path>`.
3. Reduce the seed to a minimal reproducer and add it to the
   corpus at `tests/fuzz/corpus/<module>/`.
4. Ship the fix + corpus addition in the same commit.

## Performance

### Handshake latency SLO

The library targets <2 ms per TLS 1.3 handshake on commodity x86_64
hardware. This SLO is validated on Ed25519 and RSA-2048 certificate
configurations.

### secp256r1 (P-256) performance note

Handshakes using secp256r1 (P-256) certificates currently run in the
2-3 ms range, above the <2 ms SLO. This is due to an upstream Zig
stdlib limitation: `std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, ...)`
verify is ~400-1000 µs vs ~30-80 µs in optimized implementations
(BoringSSL nistz256).

Guidance:

- **Preferred cert types for meeting the SLO:** Ed25519 or RSA-2048.
- **Deployments that must use P-256:** expect 2-3 ms per handshake
  until Zig stdlib improves or a `-Dnistz256=true` opt-in lands.
- **Tracking:** [PERF-229](https://gitlab.com/devnw/zig/tls/-/issues/243),
  [ADR-0002](adr/0002-ecdsa-p256-performance.md).

### Monitoring regressions

The benchmark suite (`zig build bench -Doptimize=ReleaseFast`) includes:

- `benchEcdsaP256Verify` — P-256 verify micro-benchmark. Baseline
  must not regress >10% between releases.
- `benchAeadSeal` / `benchAeadOpen` — record-layer AEAD throughput.
- `benchKeyDerivation` / `benchTranscriptHash` — handshake path.

See `tests/bench.zig` for the full catalog.

## References

- Architecture overview: [ARCHITECTURE.md](ARCHITECTURE.md)
- ADRs: [adr/README.md](adr/README.md)
- RFC coverage: [RFC_COVERAGE.md](RFC_COVERAGE.md)
