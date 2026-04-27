# ADR-0003: Coverage instrumentation tooling for the Zig 0.16 codebase

> Filed as **ADR-001** in the QUAL-315 re-elevation note; numbered
> 0003 here to keep the existing ADR sequence (`0001-engine-deprecation`,
> `0002-ecdsa-p256-performance`) intact. The QUAL-315 acceptance bar
> only required that the tooling decision be fixed in writing before
> CI work began; the ADR file number is incidental.

## Status

Accepted -- 2026-04-27.

Implemented as a `zig build coverage` step that shells out to `kcov`.
CI wiring (publish coverage report as an artifact + threshold gate)
is the next step and is tracked under PERF-229 / PERF-249 / PERF-255
follow-ups.

## Context

QUAL-315 (#170) has lived as a "Deferred" item since Cycle 5 / Phase 18
because the codebase had no honest way to demonstrate which paths
the test suite exercised. The Phase 22 quality-issue-tracker re-elevated
it to **P1 / priority::high** when three closure decisions in this
cycle (PERF-229, PERF-249, PERF-255) had to be argued from "the test
title implies the path is exercised" rather than from coverage data.

The blocker was a missing tooling decision — `llvm-cov` and `kcov`
both work in principle but have meaningfully different ergonomics on
top of Zig 0.16:

- **`llvm-cov`**: requires `-fprofile-instr-generate -fcoverage-mapping`
  and a matching `clang` toolchain. Zig's source-level coverage flags
  (`-fcoverage-mapping`) reach the linker but the front-end has been
  in flux through the 0.13/0.14/0.15/0.16 series, and the resulting
  `default.profraw` files require a `llvm-profdata` matching the LLVM
  version Zig ships internally. Mixing host LLVM tools with Zig's
  bundled LLVM produces opaque "version mismatch" errors.
- **`kcov`**: a standalone binary-level instrumenter that does not
  require Zig to emit anything special. It runs the unmodified test
  executable under DWARF and walks line-coverage from the debug info
  Zig already produces in `Debug` mode. No toolchain coupling.

The trade-off is fidelity vs. portability:

| Aspect              | `llvm-cov`           | `kcov`                        |
|---------------------|----------------------|-------------------------------|
| Branch coverage     | Yes                  | No (line-level only)          |
| Macro/comptime expansion handling | Best-in-class | Acceptable          |
| Toolchain coupling  | Tight (Zig + clang + llvm-profdata version-matched) | None |
| Setup cost          | High                 | Low (one apt/brew install)    |
| CI runtime overhead | ~5–10 % over the bare test build | Higher (5×–10× slowdown vs. native) |
| Output format       | `.profraw` → `.profdata` → HTML/JSON/lcov | `cobertura` / lcov / HTML directly |

For a security-sensitive parser / state-machine codebase the
*line-level* visibility kcov provides is sufficient to answer the
question every recent gap-closure decision has needed: "was this path
executed by any test?". Branch-level fidelity is desirable but is not
the marginal blocker — the marginal blocker is having any honest
data at all. Bringing kcov in this cycle and revisiting `llvm-cov`
later if branch fidelity becomes a hard requirement is the
lower-friction path.

## Decision

Adopt **`kcov`** as the canonical coverage instrumenter for this
codebase under Zig 0.16.

A `zig build coverage` step is added to `build.zig`:

- It depends on the existing `test` step's compiled binaries.
- For each unit-test executable produced by the existing
  `tests[]` array, it runs `kcov --include-pattern=src/ <out_dir>
  <test_exe>`.
- Output lands in `zig-out/coverage/<test_name>/` with the kcov
  default cobertura + HTML reports.
- The step is intentionally *not* a `default` build target — it
  requires `kcov` on the developer's PATH and is opt-in.
- A small `--coverage-threshold=<N>` env-var hook is reserved for
  CI use; the gate is not wired yet because the initial baseline
  needs to be measured first.

Threshold guidance (advisory, will harden in follow-up):

- Core modules (`src/tls13/`, `src/x509.zig`, `src/sig.zig`,
  `src/asn1.zig`, `src/quic_transport_params.zig`,
  `src/key_schedule.zig`): target ≥ 80 % line coverage.
- Conformance / interop scaffolding (`tests/`): not gated; the
  conformance suites are themselves the coverage source of truth.
- Generated wrappers and re-export barrels: excluded via
  `--exclude-pattern`.

## Consequences

Pros:

- Coverage data becomes a first-class signal again; gap-closure
  reviewers can ask "was this path taken?" and get a real answer.
- Zero impact on developers who don't install kcov — `zig build
  test` is unchanged, the new step is purely additive.
- The ADR fixes the tooling decision in writing so future
  contributors don't relitigate `llvm-cov` vs. `kcov` every cycle.

Cons:

- Line-level coverage understates the real surface; a covered line
  with two branches gives no signal on branch parity. This will be
  revisited if/when branch fidelity becomes load-bearing for a
  closure decision.
- `kcov` is a runtime dependency for the new step; CI images need
  it installed.

## Implementation pointer

- `build.zig` adds a `coverage` step that wraps the existing test
  executables in `kcov` invocations, writing reports under
  `zig-out/coverage/`.
- `tests/perf/baseline.json` (PERF-258) is the analogue for the
  performance lane; the coverage report is its quality-axis sibling.
- CI integration (publish artifact, fail-the-build threshold) is
  out of scope for this ADR and tracked as a follow-up against
  QUAL-315 closure notes.

## Related items

- QUAL-315 (#170) — the canonical filing this ADR resolves.
- QUAL-NEW-J — duplicate filing, subsumed by QUAL-315 re-elevation.
- PERF-229 / PERF-249 / PERF-255 — three closures in 2026-04-27 that
  motivated re-elevating QUAL-315 from Deferred to P1.
