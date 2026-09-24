# Changelog

All notable user-facing changes to the `soroban-testkit` workspace are
documented here. Both workspace crates — `soroban-testkit` (library) and
`soroban-testkit-cli` (binary) — share one version number and one entry per
release (see [`RELEASING.md`](RELEASING.md)).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as interpreted for a `0.x` crate in [`API_STABILITY.md`](API_STABILITY.md).

## How to add an entry

Every PR that changes user-facing behavior adds to the `## [Unreleased]`
section under the matching type. Entries are short, imperative, and aimed
at a contract author, not at the internal implementation:

- **Added** — new public API or CLI feature.
- **Changed** — existing behavior changed (non-breaking).
- **Fixed** — a bug fix that restores documented behavior.
- **Removed** — public API or flags removed (always a breaking change;
  note that under the `API_STABILITY.md` `0.x` policy).

Breaking changes are called out as a `> **Breaking:**` note in the entry.
The [`docs` workflow](.github/workflows/docs.yml) requires the current
workspace version to have either a released section or an `[Unreleased]`
section, so a merge can never land without a place to record the change.

## [Unreleased]

### Added

- Core test environment: `TestEnv` with deterministic seeding
  (`with_seed`), random address generation, and a `TestkitError` type that
  every assertion helper panics with.
- Ledger clock control: `advance`, `advance_ledgers`, `warp_to`, `now`,
  `sequence`, and `at`, so tests stop hand-rolling the timestamp/sequence
  relationship.
- Adversarial money-math generators (`adversarial_amounts`, `amounts_in`,
  `overflow_edge_triples`, `bps_values`) and value-conservation assertions
  (`Conservation::assert_holds`, `assert_conserved_over`).
- Event capture and assertion API (`EventLog`, chainable filters) whose
  failure messages print the full decoded log.
- One-line Stellar Asset Contract token doubles (`TestToken`) with a
  documented whole-units vs base-units mint split and supply tracking.
- `AuthMatrix` to prove every privileged entry point rejects unauthorized
  callers, reporting a pass/fail grid per caller.
- TTL inspection and expiry simulation (`ttl_of`, `expire`,
  `assert_bumps_ttl`, `assert_survives_expiry`).
- `soroban-testkit` CLI with `coverage`, `limits`, and `audit`
  subcommands (published as `soroban-testkit-cli`).
- Project and release documentation: `API_STABILITY.md`,
  `COMPATIBILITY.md`, `RELEASING.md`, this changelog, and the automated
  `docs` and `release` workflows.
- CI quality gates, each guarded by a regression test: `README.md`
  examples run as an explicit doc-test step, rustdoc warnings are denied
  workflow-wide, the test suite runs with network access removed
  (`.github/scripts/test-no-network.sh`), and the crates.io `repository`
  metadata is checked against the canonical repository URL.
- Ledger checkpoints: `TestEnv::checkpoint` captures the full ledger state as
  a restorable `LedgerCheckpoint` value, and `TestEnv::restore_checkpoint`
  returns the environment to it (unlike `warp_to`, it may move the clock
  backwards).
- Sequence-oriented clock control: `advance_to_sequence` moves the ledger to
  an absolute sequence number, advancing the timestamp in proportion via the
  close interval; `try_advance_to_sequence` is its checked counterpart.
- `TestEnv::seed` exposes the seed a deterministic environment was built
  with, so a test can rebuild an identical environment from it.
- `TestkitError::kind` returns the variant name, and `TestkitError::chain`
  walks the error's source chain, for match-free diagnostics and logging.

### Changed

- The `limits` subcommand now mocks authorization on each isolated probe
  and defaults numeric ramp parameters to a non-zero value, making it
  usable against real auth-gated payout contracts out of the box.

### Fixed

- `coverage` command now provides a specific, actionable error message when
  `cargo-llvm-cov` is not installed or not found in PATH, distinguishing
  between the tool being missing and other subprocess errors.
- `limits` command termination is now deterministic: search stops at a
  built-in upper bound rather than when a non-deterministic condition is met,
  and the output notes whether the ceiling was discovered or the upper bound
  was reached.
- `limits` diagnostics now include the first failed ramp value, helping users
  understand where their contract hits resource limits.
- `limits` and `coverage` commands now handle paths with spaces correctly in
  baseline, export, and output operations.
- `limits` never mocked authorization: every ramp attempt failed on a
  `require_auth` call before resource limits were ever reached. Each probe
  now uses `mock_all_auths_allowing_non_root_auth()` on its own
  single-use `Env`.
- `limits` numeric defaults were `0`, which contracts validating positive
  amounts rejected outright; the default is now `1`.
- `soroban_testkit::prelude` re-exports `Actor` and `AddressIter` again, and
  `core` imports `TestkitError` where it uses it; the library did not compile
  without these.

## [0.1.0]

First planned release (not yet published). The complete user-facing surface
is tracked in the `## [Unreleased]` section above; on release, that content
moves into a dated `0.1.0` section here per the [`RELEASING.md`](RELEASING.md)
checklist.

[Unreleased]: https://github.com/soroban-testkit/soroban-testkit/compare/main...HEAD
[0.1.0]: https://github.com/soroban-testkit/soroban-testkit/releases