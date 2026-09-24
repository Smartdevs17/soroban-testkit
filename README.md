# soroban-testkit

**The testing crate you would have written yourself, on the third contract.**

Testing infrastructure for Soroban contracts: property-test generators for
money math, an event-assertion API, ledger time and TTL-expiry control,
token test doubles, and a coverage-aware CLI.

`soroban-sdk` ships `testutils`, which is adequate for basic unit tests. It
is not adequate for testing contracts that hold money. Every serious
Soroban contract repo independently rebuilds some subset of:

- Advancing ledger time correctly, including the interaction between
  `timestamp` and `sequence`
- Asserting on emitted events without hand-decoding `Val` topics
- Generating adversarial `i128` values that actually find overflow bugs
- Deploying and funding a Stellar Asset Contract token double for transfer
  tests
- Proving that every privileged entry point rejects unauthorized callers
- Simulating TTL expiry

`soroban-testkit` is that shared layer, as a dev-dependency crate plus a
small CLI.

## Example

A small escrow contract, tested end to end: mint a token, release it to
the seller, and check the event, the balances, and that no value was
created or destroyed along the way.

```
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};
use soroban_testkit::prelude::*;

#[contract]
struct Escrow;

#[contractimpl]
impl Escrow {
    pub fn release(env: Env, token: Address, from: Address, to: Address, amount: i128) {
        from.require_auth();
        soroban_sdk::token::TokenClient::new(&env, &token)
            .transfer(&from, soroban_sdk::MuxedAddress::from(to), &amount);
        #[allow(deprecated)]
        env.events().publish((symbol_short!("release"),), amount);
    }
}

# fn main() {
let env = TestEnv::new();
let token = env.token();
let buyer = env.address();
let seller = env.address();
token.mint(&buyer, 100);

let escrow_id = env.env().register(Escrow, ());
let client = EscrowClient::new(env.env(), &escrow_id);

env.env().mock_all_auths();
let (_, events) = env.events_during(|| {
    client.release(&token.address(), &buyer, &seller, &1_000_000_000);
});
events
    .from(&escrow_id)
    .assert_emitted(symbol_short!("release"));

// Each of these balance queries is itself a top-level call, so check
// them after reading events — see EventLog's note on scope.
token.assert_balance(&buyer, 0);
token.assert_balance(&seller, 1_000_000_000);

Conservation {
    deposited: 1_000_000_000,
    withdrawn: 1_000_000_000,
    refunded: 0,
    remaining: 0,
}
.assert_holds();
# }
```

## CLI

A companion binary, `soroban-testkit-cli` (installs as `soroban-testkit`),
for things that don't belong in a dev-dependency:

```sh
# Coverage for the WASM target (wraps cargo-llvm-cov, which needs no
# Soroban-specific flags since contract tests run natively).
soroban-testkit coverage --format html --open

# Empirically find how many recipients a batch operation can handle
# before it exceeds mainnet resource limits.
soroban-testkit limits --contract target/wasm32v1-none/release/my_contract.wasm \
  --fn batch_payout --ramp recipients

# Static checks: missing require_auth, unchecked i128 arithmetic,
# storage reads with no TTL bump, ignored token-transfer results, and
# signed amount parameters with no positive-value validation.
soroban-testkit audit ./src --strict

# Stable machine-readable reports for automation and GitHub code scanning.
soroban-testkit audit ./src --format json
soroban-testkit audit ./src --format sarif > audit.sarif
```

`audit --format json` emits a versioned object with `findings` and a finding
count. `audit --format sarif` emits SARIF 2.1.0 with a rule ID, severity,
message, file URI, and start line for every finding. `--strict` remains
independent of presentation format and exits non-zero after writing the report
when findings exist. Audit rules can be disabled or assigned a custom severity
in `.soroban-testkit.toml` by their IDs, including
`ignored-token-transfer-result` and `missing-positive-amount-validation`.

`limits` ramps a numeric parameter directly, or generates addresses for a
`Vec<Address>` parameter — the common "how many recipients" question.
Every ramp attempt runs in its own subprocess: a real `.wasm` contract
that exceeds resource limits can abort the process outright rather than
return an error, and isolating each attempt is the only safe way to probe
past that boundary. Ledger read/write counts and transaction size aren't
reported (they come from a network-side simulated footprint this crate
doesn't produce); instructions and memory, measured locally, are.

## Status

This crate is under active development. See `BUILD_SPEC.md` for the build
plan and module boundaries, and [`ARCHITECTURE.md`](ARCHITECTURE.md) for a
contributor-facing map of the workspace and how its modules fit together.

CI enforces the guarantees that keep this documentation honest: every Rust
example above is compiled and run as a doctest against the public API,
rustdoc warnings fail the build, the test suite runs with network access
removed, and the crates.io `repository` metadata is checked against the
canonical repository URL.

## Documentation

- [`CHANGELOG.md`](CHANGELOG.md) — user-facing release notes for each
  version of both workspace crates.
- [`API_STABILITY.md`](API_STABILITY.md) — the semver/API stability policy
  for the `0.x` releases: what a version bump means and what you may rely
  on.
- [`COMPATIBILITY.md`](COMPATIBILITY.md) — which `soroban-sdk` and Stellar
  protocol versions each release targets.
- [`RELEASING.md`](RELEASING.md) — the release checklist for
  `soroban-testkit` and `soroban-testkit-cli`.
- [`BUILD_SPEC.md`](BUILD_SPEC.md) — the build plan and module boundaries.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — a contributor-facing map of the
  workspace.

## Prior art

[`soroban-fork`](https://crates.io/crates/soroban-fork) does lazy
mainnet/testnet forking for tests. That is a different problem;
`soroban-testkit` does not attempt it.

## License

Apache-2.0
add validation coverage for the recurring contract
add validation coverage for the batch payout auth model

add a line-count and coverage comparison to validation

add benchmark tracking for TestEnv construction
