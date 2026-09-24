use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::xdr::{ContractId, Hash, ScAddress};
use soroban_sdk::{Address, Env, TryFromVal};

use super::error::TestkitError;

// ──────────────────────────────────────────────────────────────────────────
// Issue #35 — builder for deterministic ledger defaults
// ──────────────────────────────────────────────────────────────────────────

/// A builder for the ledger parameters a [`TestEnv`] starts with.
///
/// `LedgerDefaults` lets you pin the initial `timestamp`, `sequence_number`,
/// `protocol_version`, and `base_reserve` so that every environment built
/// from it produces identical starting conditions. Use it when a test needs
/// a specific epoch or a particular protocol version, and you want to state
/// that intent up front rather than calling `env.warp_to(…)` or reaching
/// through `env.env().ledger().set(…)` after construction.
///
/// Unset fields keep the [`soroban_sdk::Env`] defaults (all zeros / SDK
/// defaults as of the pinned `soroban-sdk` version).
///
/// # Example
///
/// ```
/// use soroban_testkit::core::{LedgerDefaults, TestEnv};
///
/// let defaults = LedgerDefaults::new()
///     .timestamp(1_700_000_000)
///     .sequence_number(500_000);
///
/// let env = TestEnv::with_ledger_defaults(defaults);
/// assert_eq!(env.now(), 1_700_000_000);
/// assert_eq!(env.sequence(), 500_000);
/// ```
#[derive(Debug, Clone, Default)]
pub struct LedgerDefaults {
    pub(crate) timestamp: Option<u64>,
    pub(crate) sequence_number: Option<u32>,
    pub(crate) protocol_version: Option<u32>,
    pub(crate) base_reserve: Option<u32>,
}

impl LedgerDefaults {
    /// Create a builder with no overrides; all fields keep the SDK defaults.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::LedgerDefaults;
    ///
    /// let defaults = LedgerDefaults::new();
    /// // All fields are None; the SDK defaults apply.
    /// assert!(defaults.timestamp_override().is_none());
    /// assert!(defaults.sequence_number_override().is_none());
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the initial unix timestamp (whole seconds).
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::{LedgerDefaults, TestEnv};
    ///
    /// let env = TestEnv::with_ledger_defaults(
    ///     LedgerDefaults::new().timestamp(1_700_000_000),
    /// );
    /// assert_eq!(env.now(), 1_700_000_000);
    /// ```
    pub fn timestamp(mut self, value: u64) -> Self {
        self.timestamp = Some(value);
        self
    }

    /// Set the initial ledger sequence number.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::{LedgerDefaults, TestEnv};
    ///
    /// let env = TestEnv::with_ledger_defaults(
    ///     LedgerDefaults::new().sequence_number(42_000),
    /// );
    /// assert_eq!(env.sequence(), 42_000);
    /// ```
    pub fn sequence_number(mut self, value: u32) -> Self {
        self.sequence_number = Some(value);
        self
    }

    /// Set the initial protocol version.
    ///
    /// The protocol version must be compatible with the version of
    /// `soroban-sdk` in use (too old a value is rejected by the host).
    /// Prefer using the current version from the SDK as a baseline when you
    /// need to override this field.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::{LedgerDefaults, TestEnv};
    /// use soroban_sdk::testutils::Ledger as _;
    ///
    /// // Resolve the current protocol version from the SDK itself so that
    /// // this example compiles against any soroban-sdk version.
    /// let current = {
    ///     let base = soroban_sdk::Env::default();
    ///     base.ledger().get().protocol_version
    /// };
    /// let env = TestEnv::with_ledger_defaults(
    ///     LedgerDefaults::new().protocol_version(current),
    /// );
    /// assert_eq!(env.env().ledger().get().protocol_version, current);
    /// ```
    pub fn protocol_version(mut self, value: u32) -> Self {
        self.protocol_version = Some(value);
        self
    }

    /// Set the initial base reserve (in stroops).
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::{LedgerDefaults, TestEnv};
    ///
    /// let env = TestEnv::with_ledger_defaults(
    ///     LedgerDefaults::new().base_reserve(5_000_000),
    /// );
    /// drop(env);
    /// ```
    pub fn base_reserve(mut self, value: u32) -> Self {
        self.base_reserve = Some(value);
        self
    }

    /// The configured timestamp override, if any.
    pub fn timestamp_override(&self) -> Option<u64> {
        self.timestamp
    }

    /// The configured sequence number override, if any.
    pub fn sequence_number_override(&self) -> Option<u32> {
        self.sequence_number
    }

    /// The configured protocol version override, if any.
    pub fn protocol_version_override(&self) -> Option<u32> {
        self.protocol_version
    }

    /// The configured base reserve override, if any.
    pub fn base_reserve_override(&self) -> Option<u32> {
        self.base_reserve
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Issue #39 — test-environment metadata in diagnostic output
// ──────────────────────────────────────────────────────────────────────────

/// A snapshot of [`TestEnv`] state for inclusion in assertion failure
/// messages.
///
/// Every assertion helper in this crate that can fail includes an
/// `EnvMetadata` snapshot in its failure message so that the developer
/// immediately sees *where* in ledger time the failure happened, without
/// having to add manual `println!` calls or re-run under a debugger.
///
/// Use [`TestEnv::metadata`] to capture a snapshot at any point.
///
/// # Example
///
/// ```
/// use soroban_testkit::core::TestEnv;
/// use std::time::Duration;
///
/// let env = TestEnv::with_seed(1);
/// env.advance(Duration::from_secs(300));
///
/// let meta = env.metadata();
/// let display = meta.to_string();
/// assert!(display.contains("timestamp=300"));
/// assert!(display.contains("sequence="));
/// assert!(display.contains("seed=1"));
/// ```
#[derive(Debug, Clone)]
pub struct EnvMetadata {
    /// Current ledger timestamp (unix seconds).
    pub timestamp: u64,
    /// Current ledger sequence number.
    pub sequence: u32,
    /// Current ledger protocol version.
    pub protocol_version: u32,
    /// The RNG seed this environment was built with.
    pub seed: u64,
    /// The configured ledger close interval (seconds), if any was set.
    pub close_interval_override: Option<u64>,
}

impl fmt::Display for EnvMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TestEnv {{ timestamp={}, sequence={}, protocol_version={}, seed={}",
            self.timestamp, self.sequence, self.protocol_version, self.seed,
        )?;
        if let Some(interval) = self.close_interval_override {
            write!(f, ", close_interval={interval}s")?;
        }
        write!(f, " }}")
    }
}

#[derive(Default)]
struct LabelStore {
    address_to_label: Vec<(Address, String)>,
    label_to_address: HashMap<String, Address>,
}

/// A wrapper around [`soroban_sdk::Env`] that carries testkit state
/// (clock position, captured events, registered tokens, address labels) alongside
/// the raw SDK environment.
///
/// Every other module in this crate extends `TestEnv` with additional
/// methods (ledger control, event capture, token doubles, and so on) rather
/// than introducing separate handle types, so a single `TestEnv` is enough
/// to drive an entire test.
///
/// # Generated Address Labels
///
/// Generated addresses in `TestEnv` can optionally have human-readable labels:
///
/// - **When a label is provided** (via [`TestEnv::address_with_label`] or [`TestEnv::address_labeled`]):
///   The generated address is associated with the given label string. The label can be inspected
///   using [`TestEnv::label_of`], and the address can be looked up by label using [`TestEnv::address_for_label`].
/// - **When no label is provided** (via [`TestEnv::address`]): Address generation behavior is
///   unchanged; a fresh random address is generated without any associated label.
/// - **Label exposure**: Labels are represented as string slices (`&str`) / owned strings (`String`)
///   and exposed via [`TestEnv::label_of`] and [`TestEnv::address_for_label`].
///
/// # Example
///
/// ```
/// use soroban_testkit::core::TestEnv;
///
/// let env = TestEnv::new();
/// let alice = env.address_with_label("alice");
/// let bob = env.address();
/// assert_ne!(alice, bob);
/// assert_eq!(env.label_of(&alice), Some("alice".to_string()));
/// assert_eq!(env.label_of(&bob), None);
/// ```
pub struct TestEnv {
    env: Env,
    // Consumed by the `money` module's seeded generators (Module 3).
    #[allow(dead_code)]
    seed: u64,
    // Per-environment override of the ledger close interval, in seconds.
    // `None` means "use the crate default"; the `ledger` module owns both
    // the default and the validation of overrides.
    close_interval_secs: Option<u64>,
    // Deterministic starting ledger parameters provided via LedgerDefaults.
    ledger_defaults: LedgerDefaults,
    // Issue #24 — the position of this environment's own address stream.
    // Keeping the counter here (rather than drawing from the SDK's shared
    // testutils generator) means raw handles obtained through `env()` can
    // never shift the sequence `TestEnv::address()` issues from.
    address_counter: Cell<u64>,
    labels: Mutex<LabelStore>,
}

/// Reusable test setup built around a [`TestEnv`].
///
/// Implement this trait for a fixture struct that owns a `TestEnv` plus the
/// addresses, contracts, or tokens a group of tests share. The provided
/// constructors keep environment creation consistent and make seeded fixtures
/// reproducible without duplicating setup boilerplate.
///
/// # Example
///
/// ```
/// use soroban_testkit::core::{TestEnv, TestFixture};
/// use soroban_sdk::Address;
///
/// struct Fixture {
///     env: TestEnv,
///     alice: Address,
/// }
///
/// impl TestFixture for Fixture {
///     fn from_env(env: TestEnv) -> Self {
///         let alice = env.address();
///         Self { env, alice }
///     }
///
///     fn test_env(&self) -> &TestEnv {
///         &self.env
///     }
/// }
///
/// let a = Fixture::with_seed(7);
/// let b = Fixture::with_seed(7);
/// assert_eq!(a.alice, b.alice);
/// ```
pub trait TestFixture: Sized {
    /// Build the fixture from an already-created test environment.
    fn from_env(env: TestEnv) -> Self;

    /// Borrow the environment owned by this fixture.
    fn test_env(&self) -> &TestEnv;

    /// Build the fixture around a fresh [`TestEnv`].
    fn new() -> Self {
        Self::from_env(TestEnv::new())
    }

    /// Build the fixture around a reproducibly seeded [`TestEnv`].
    fn with_seed(seed: u64) -> Self {
        Self::from_env(TestEnv::with_seed(seed))
    }
}

impl TestFixture for TestEnv {
    fn from_env(env: TestEnv) -> Self {
        env
    }

    fn test_env(&self) -> &TestEnv {
        self
    }
}

impl TestEnv {
    /// Create a fresh environment with a deterministic starting ledger.
    ///
    /// Every `TestEnv` starts at ledger sequence `0` and Unix timestamp `0`.
    /// These values are set explicitly rather than inherited from the SDK's
    /// defaults so tests can rely on them across SDK upgrades. Other ledger
    /// parameters continue to come from the current Soroban SDK test config.
    ///
    /// Uses a non-reproducible seed for any future randomized value
    /// generation; use [`TestEnv::with_seed`] when a test needs to be
    /// reproducible.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let a = TestEnv::new();
    /// let b = TestEnv::new();
    /// // Independent environments: mutating one's ledger doesn't affect the other.
    /// use soroban_sdk::testutils::Ledger;
    /// a.env().ledger().set_sequence_number(1_000);
    /// assert_ne!(a.env().ledger().get().sequence_number, b.env().ledger().get().sequence_number);
    /// ```
    pub fn new() -> Self {
        Self::with_seed(random_seed())
    }

    /// Create an environment whose deterministic RNG seed is fixed, so that
    /// property tests using this crate's generators are reproducible.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let a = TestEnv::with_seed(42);
    /// let b = TestEnv::with_seed(42);
    /// assert_eq!(a.address(), b.address());
    /// ```
    pub fn with_seed(seed: u64) -> Self {
        Self {
            env: Self::fresh_env_with_defaults(&LedgerDefaults::default()),
            seed,
            close_interval_secs: None,
            ledger_defaults: LedgerDefaults::default(),
            address_counter: Cell::new(0),
            labels: Mutex::new(LabelStore::default()),
        }
    }

    /// Create an environment that starts from the given [`LedgerDefaults`].
    ///
    /// This is the primary entry point when a test depends on a specific
    /// epoch, protocol version, or sequence number. Combining it with
    /// [`TestEnv::with_seed`] via [`TestEnv::with_ledger_defaults_and_seed`]
    /// makes the full starting state deterministic.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::{LedgerDefaults, TestEnv};
    ///
    /// let defaults = LedgerDefaults::new()
    ///     .timestamp(1_700_000_000)
    ///     .sequence_number(1_000_000);
    ///
    /// let env = TestEnv::with_ledger_defaults(defaults);
    /// assert_eq!(env.now(), 1_700_000_000);
    /// assert_eq!(env.sequence(), 1_000_000);
    /// ```
    pub fn with_ledger_defaults(defaults: LedgerDefaults) -> Self {
        Self {
            env: Self::fresh_env_with_defaults(&defaults),
            seed: random_seed(),
            close_interval_secs: None,
            ledger_defaults: defaults,
            address_counter: Cell::new(0),
            labels: Mutex::new(LabelStore::default()),
        }
    }

    /// Create an environment with a fixed RNG seed and deterministic starting
    /// ledger.
    ///
    /// Combines [`TestEnv::with_seed`] and [`TestEnv::with_ledger_defaults`]
    /// so that both the randomised value generators and the initial clock
    /// position are fully reproducible.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::{LedgerDefaults, TestEnv};
    ///
    /// let defaults = LedgerDefaults::new().timestamp(1_000_000);
    /// let a = TestEnv::with_ledger_defaults_and_seed(defaults.clone(), 99);
    /// let b = TestEnv::with_ledger_defaults_and_seed(defaults, 99);
    ///
    /// assert_eq!(a.now(), b.now());
    /// assert_eq!(a.address(), b.address());
    /// ```
    pub fn with_ledger_defaults_and_seed(defaults: LedgerDefaults, seed: u64) -> Self {
        Self {
            env: Self::fresh_env_with_defaults(&defaults),
            seed,
            close_interval_secs: None,
            ledger_defaults: defaults,
            address_counter: Cell::new(0),
            labels: Mutex::new(LabelStore::default()),
        }
    }

    /// Create a new, isolated environment that carries this one's
    /// configuration but none of its state.
    ///
    /// The result is built exactly as [`TestEnv::with_seed`] would build it,
    /// then given the settings this environment was configured with:
    ///
    /// | Carried over | Not carried over |
    /// |---|---|
    /// | the RNG seed ([`TestEnv::with_seed`]) | the ledger clock position (`now`, `sequence`) |
    /// | the ledger close interval, if one was set ([`TestEnv::with_ledger_close_interval`]) | deployed contracts and their storage |
    /// | | addresses, labels, clients, and any other value created from this environment |
    /// | | ledger settings changed directly through [`TestEnv::env`] |
    ///
    /// An environment that never set a close interval stays that way: the
    /// clone follows the crate default rather than freezing today's value.
    ///
    /// The two environments share nothing afterwards — advancing the clock,
    /// deploying contracts, or generating addresses in one has no effect on
    /// the other. There is deliberately no `Clone` impl on `TestEnv` for the
    /// same reason: cloning a raw [`soroban_sdk::Env`] yields a second handle
    /// to the *same* underlying host, which would not be isolated.
    ///
    /// Only settings `TestEnv` itself tracks are carried over. Anything
    /// changed by reaching through [`TestEnv::env`] (for example
    /// `env().ledger().set(..)`) must be applied to the clone again.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use std::time::Duration;
    ///
    /// let original = TestEnv::with_seed(7).with_ledger_close_interval(2);
    /// original.advance(Duration::from_secs(60));
    ///
    /// let copy = original.clone_config();
    /// // Configuration is carried over, the clock position is not...
    /// assert_eq!(copy.ledger_close_interval(), 2);
    /// assert_ne!(copy.now(), original.now());
    ///
    /// // ...and the two environments are isolated from each other.
    /// let before = original.now();
    /// copy.advance(Duration::from_secs(10));
    /// assert_eq!(original.now(), before);
    /// ```
    pub fn clone_config(&self) -> Self {
        Self {
            env: Self::fresh_env_with_defaults(&self.ledger_defaults),
            seed: self.seed,
            close_interval_secs: self.close_interval_secs,
            ledger_defaults: self.ledger_defaults.clone(),
            address_counter: Cell::new(0),
            labels: Mutex::new(LabelStore::default()),
        }
    }

    /// Discard all state in this environment and return it to the condition
    /// [`TestEnv::with_seed`] would have built it in, keeping its
    /// configuration.
    ///
    /// After `reset`, this environment behaves exactly like
    /// [`TestEnv::clone_config`] of itself would have: the seed and any
    /// ledger close interval are kept (see [`TestEnv::clone_config`] for the
    /// full list of what is and is not carried over), and everything else —
    /// the ledger clock position, deployed contracts and their storage — is
    /// gone. Addresses are issued from the start again, so the first
    /// [`TestEnv::address`] after a reset equals the first one a freshly
    /// built environment with the same seed would return.
    ///
    /// Values created before the reset (addresses, contract clients, cloned
    /// [`soroban_sdk::Env`] handles) stay bound to the discarded state and
    /// keep observing it; they are not moved into the reset environment.
    /// Recreate them after resetting rather than reusing them.
    ///
    /// `reset` takes `&mut self`, so the borrow checker rejects a reset while
    /// a `&Env` obtained from [`TestEnv::env`] is still alive.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use std::time::Duration;
    ///
    /// let pristine = TestEnv::with_seed(7);
    /// let (start_now, start_sequence) = (pristine.now(), pristine.sequence());
    ///
    /// let mut env = TestEnv::with_seed(7).with_ledger_close_interval(2);
    /// env.advance(Duration::from_secs(600));
    /// assert_ne!(env.now(), start_now);
    ///
    /// env.reset();
    /// // The clock is back at the starting ledger; the configuration is kept.
    /// assert_eq!((env.now(), env.sequence()), (start_now, start_sequence));
    /// assert_eq!(env.ledger_close_interval(), 2);
    /// ```
    pub fn reset(&mut self) {
        self.env = Self::fresh_env_with_defaults(&self.ledger_defaults);
        self.address_counter.set(0);
        if let Ok(store) = self.labels.get_mut() {
            store.address_to_label.clear();
            store.label_to_address.clear();
        }
    }

    /// Build the raw SDK environment every `TestEnv` starts from. Shared by
    /// construction, [`TestEnv::clone_config`] and [`TestEnv::reset`] so the
    /// three cannot drift apart.
    fn fresh_env_with_defaults(defaults: &LedgerDefaults) -> Env {
        let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let mut info = env.ledger().get();
        info.sequence_number = defaults.sequence_number.unwrap_or(0);
        info.timestamp = defaults.timestamp.unwrap_or(0);
        if let Some(pv) = defaults.protocol_version {
            info.protocol_version = pv;
        }
        if let Some(br) = defaults.base_reserve {
            info.base_reserve = br;
        }
        env.ledger().set(info);
        env
    }

    /// Escape hatch to the underlying SDK environment, for calls this crate
    /// does not wrap.
    ///
    /// # Ownership and lifetime
    ///
    /// [`TestEnv`] owns the [`Env`]; `env()` only lends you a shared
    /// reference to it:
    ///
    /// * The returned `&Env` is tied to the lifetime of the borrow of
    ///   `self`, so it cannot outlive the `TestEnv` it came from.
    /// * While that reference is alive the `TestEnv` stays borrowed, so
    ///   [`TestEnv::reset`] (which takes `&mut self`) will not compile —
    ///   the borrow checker enforces this at the call site rather than
    ///   allowing a later use of stale state.
    ///
    /// The reference *aliases* the environment `TestEnv` uses; it is not a
    /// copy. Mutations made through it (for example
    /// `env().ledger().set(..)`) are immediately visible through the
    /// `TestEnv`, and vice versa. Cloning the handle (`env().clone()`)
    /// produces a second handle to that *same* underlying host — contract
    /// storage and other state remain shared, so a clone is not an
    /// independent environment. For an isolated environment that keeps only
    /// the configuration, use [`TestEnv::clone_config`] instead.
    ///
    /// Addresses issued by [`TestEnv::address`] and its batch helpers come
    /// from the stream the `TestEnv` owns, so drawing from the SDK's own
    /// testutils generator through a raw handle (for example with
    /// `Address::generate(env.env())`) never shifts that sequence. The two
    /// streams are not coordinated with each other, so prefer
    /// [`TestEnv::address`] for test participants.
    ///
    /// Cloned handles obtained before a [`TestEnv::reset`] keep observing
    /// the discarded environment; re-fetch `env()` after resetting.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_sdk::testutils::Ledger;
    ///
    /// let env = TestEnv::new();
    /// let _sdk_env: &soroban_sdk::Env = env.env();
    ///
    /// // The escape hatch aliases the environment TestEnv owns.
    /// env.env().ledger().set_sequence_number(1_000);
    /// assert_eq!(env.sequence(), 1_000);
    /// ```
    pub fn env(&self) -> &Env {
        &self.env
    }

    /// Generate a fresh address from this environment's own stream.
    ///
    /// Addresses are issued from a counter the `TestEnv` owns, not from the
    /// SDK's shared testutils generator. The sequence therefore depends
    /// only on this environment's seed and on how many addresses it has
    /// issued: two environments built with the same seed issue identical
    /// sequences, independently built environments' sequences are distinct
    /// (their seeds differ), and the sequence is not shifted by activity on
    /// the raw [`Env`] reached through [`TestEnv::env`] (raw
    /// `Address::generate` calls, contract registration, and similar
    /// SDK-side draws use a separate generator).
    /// The stream's values are disjoint from that generator's namespace, so
    /// generated addresses never collide with registered contract ids or
    /// raw generated addresses. [`TestEnv::reset`] starts the stream over.
    ///
    /// This variant carries no label ([`TestEnv::label_of`] returns
    /// `None`); use [`TestEnv::address_with_label`] for a labeled address.
    /// Labeled addresses draw from the same stream.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let alice = env.address();
    /// let bob = env.address();
    /// assert_ne!(alice, bob);
    /// assert_eq!(env.label_of(&alice), None);
    /// ```
    pub fn address(&self) -> Address {
        let next = match self.address_counter.get().checked_add(1) {
            Some(next) => next,
            None => panic!(
                "{}",
                TestkitError::misuse(
                    "address counter exhausted: this TestEnv has already issued u64::MAX addresses"
                )
            ),
        };
        self.address_counter.set(next);
        // Bytes 0..8 carry this environment's seed and bytes 8..16 the
        // stream position: the layout stays disjoint from the SDK
        // generator's namespace (trailing bytes, so `env.address() #1` can
        // never equal the first registered contract's id), while the seed
        // keeps independent environments' sequences distinct (issue #26)
        // and same-seed environments reproducible.
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&self.seed.to_be_bytes());
        bytes[8..16].copy_from_slice(&next.to_be_bytes());
        Address::try_from_val(&self.env, &ScAddress::Contract(ContractId(Hash(bytes))))
            .unwrap_or_else(|e| {
                panic!(
                    "{}",
                    TestkitError::misuse(format!("failed to construct a generated address: {e:?}"))
                )
            })
    }

    /// Generate a fresh random address associated with an optional human-readable label.
    ///
    /// # User-facing behavior
    ///
    /// - **When a label is provided**: Generates a fresh address, registers the label
    ///   association in this environment, and returns the address. The label can
    ///   subsequently be retrieved via [`TestEnv::label_of`], and the address can be
    ///   looked up via [`TestEnv::address_for_label`].
    /// - **When no label is provided** (via [`TestEnv::address`]): Existing address
    ///   generation behavior is preserved; the address is generated without any label.
    /// - **Label exposure**: Labels are represented as `&str` / `String` values and exposed
    ///   via [`TestEnv::label_of`] and [`TestEnv::address_for_label`].
    ///
    /// # Error behavior
    ///
    /// Panics with a [`TestkitError::Misuse`] if:
    /// - `label` is empty or consists entirely of whitespace.
    /// - `label` is already associated with an address in this environment.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let alice = env.address_with_label("alice");
    /// assert_eq!(env.label_of(&alice), Some("alice".to_string()));
    /// assert_eq!(env.address_for_label("alice"), Some(alice));
    /// ```
    pub fn address_with_label(&self, label: &str) -> Address {
        let trimmed = label.trim();
        if trimmed.is_empty() {
            panic!(
                "{}",
                TestkitError::Misuse(
                    "address label cannot be empty or whitespace-only".to_string()
                )
            );
        }

        let mut store = self
            .labels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if store.label_to_address.contains_key(label) {
            panic!(
                "{}",
                TestkitError::Misuse(format!("address label '{label}' is already in use"))
            );
        }

        let addr = self.address();
        store
            .address_to_label
            .push((addr.clone(), label.to_string()));
        store
            .label_to_address
            .insert(label.to_string(), addr.clone());
        addr
    }

    /// Alias for [`TestEnv::address_with_label`].
    pub fn address_labeled(&self, label: &str) -> Address {
        self.address_with_label(label)
    }

    /// Get the human-readable label associated with an address, if any.
    ///
    /// Returns `Some(label)` if the address was generated with a label (e.g., via
    /// [`TestEnv::address_with_label`]), or `None` if the address has no label.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let alice = env.address_with_label("alice");
    /// let bob = env.address();
    ///
    /// assert_eq!(env.label_of(&alice), Some("alice".to_string()));
    /// assert_eq!(env.label_of(&bob), None);
    /// ```
    pub fn label_of(&self, address: &Address) -> Option<String> {
        let store = self
            .labels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store
            .address_to_label
            .iter()
            .find(|(a, _)| a == address)
            .map(|(_, l)| l.clone())
    }

    /// Alias for [`TestEnv::label_of`].
    pub fn label(&self, address: &Address) -> Option<String> {
        self.label_of(address)
    }

    /// Look up a generated address by its human-readable label, if any.
    ///
    /// Returns `Some(address)` if an address was generated with `label`, or `None`
    /// if no address in this environment has that label.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let alice = env.address_with_label("alice");
    /// assert_eq!(env.address_for_label("alice"), Some(alice));
    /// assert_eq!(env.address_for_label("unknown"), None);
    /// ```
    pub fn address_for_label(&self, label: &str) -> Option<Address> {
        let store = self
            .labels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.label_to_address.get(label).cloned()
    }

    /// Alias for [`TestEnv::address_for_label`].
    pub fn address_by_label(&self, label: &str) -> Option<Address> {
        self.address_for_label(label)
    }

    /// Generate `n` fresh addresses.
    ///
    /// This is the panicking counterpart of [`TestEnv::try_addresses`]:
    /// batch sizes the checked API rejects (zero, or larger than
    /// [`MAX_ADDRESS_BATCH_SIZE`]) are rejected here with a
    /// [`TestkitError::Misuse`] panic *before* any allocation is attempted,
    /// so an oversized request fails with a clear message instead of
    /// exhausting memory or exceeding what an SDK collection could hold.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if `n == 0` or if
    /// `n > MAX_ADDRESS_BATCH_SIZE`.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let addrs = env.addresses(3);
    /// assert_eq!(addrs.len(), 3);
    /// ```
    pub fn addresses(&self, n: usize) -> Vec<Address> {
        self.try_addresses(n).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Return an infinite iterator yielding fresh, distinct [`Address`] values.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let addrs: Vec<_> = env.address_iter().take(4).collect();
    /// assert_eq!(addrs.len(), 4);
    /// ```
    pub fn address_iter(&self) -> AddressIter<'_> {
        AddressIter::new(self)
    }

    /// Plural alias for [`TestEnv::address_iter`].
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let addrs: Vec<_> = env.addresses_iter().take(2).collect();
    /// assert_eq!(addrs.len(), 2);
    /// ```
    pub fn addresses_iter(&self) -> AddressIter<'_> {
        self.address_iter()
    }

    /// Generate a batch of `n` fresh addresses, returning `Err(TestkitError::Misuse)`
    /// if `n == 0` or if `n` exceeds [`MAX_ADDRESS_BATCH_SIZE`].
    ///
    /// # Errors
    ///
    /// Returns a [`TestkitError::Misuse`] if:
    /// - `n == 0`: requesting zero addresses indicates a test setup error.
    /// - `n > MAX_ADDRESS_BATCH_SIZE`: batch size exceeds the allowed threshold.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let addrs = env.try_addresses(3).expect("valid batch size");
    /// assert_eq!(addrs.len(), 3);
    ///
    /// let err = env.try_addresses(0).unwrap_err();
    /// assert_eq!(err.code(), "TESTKIT_MISUSE");
    /// ```
    pub fn try_addresses(&self, n: usize) -> Result<Vec<Address>, TestkitError> {
        if n == 0 {
            return Err(TestkitError::Misuse(
                "address batch size must be at least 1; requested 0 addresses".into(),
            ));
        }
        if n > MAX_ADDRESS_BATCH_SIZE {
            return Err(TestkitError::Misuse(format!(
                "requested address batch size {n} exceeds the maximum limit of {MAX_ADDRESS_BATCH_SIZE}"
            )));
        }
        Ok((0..n).map(|_| self.address()).collect())
    }

    /// Checked variant of address batch generation, equivalent to [`TestEnv::try_addresses`].
    ///
    /// # Errors
    ///
    /// Returns [`TestkitError::Misuse`] if `n == 0` or `n > MAX_ADDRESS_BATCH_SIZE`.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// assert!(env.checked_addresses(2).is_ok());
    /// assert!(env.checked_addresses(0).is_err());
    /// ```
    pub fn checked_addresses(&self, n: usize) -> Result<Vec<Address>, TestkitError> {
        self.try_addresses(n)
    }

    /// Generate a named [`Actor`] pairing the given identifier with a fresh [`Address`].
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if `name` is empty or consists solely of whitespace.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let alice = env.actor("alice");
    /// assert_eq!(alice.name(), "alice");
    /// ```
    pub fn actor(&self, name: &str) -> Actor {
        self.try_actor(name).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Checked variant of [`TestEnv::actor`], returning [`TestkitError::Misuse`]
    /// if `name` is empty or only whitespace.
    ///
    /// # Errors
    ///
    /// Returns [`TestkitError::Misuse`] if `name` is empty or whitespace-only.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// assert!(env.try_actor("alice").is_ok());
    /// assert!(env.try_actor("").is_err());
    /// ```
    pub fn try_actor(&self, name: &str) -> Result<Actor, TestkitError> {
        if name.trim().is_empty() {
            return Err(TestkitError::Misuse(
                "actor name cannot be empty or only whitespace".into(),
            ));
        }
        Ok(Actor::new(name, self.address()))
    }

    /// Alias for [`TestEnv::actor`].
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let bob = env.named_actor("bob");
    /// assert_eq!(bob.name(), "bob");
    /// ```
    pub fn named_actor(&self, name: &str) -> Actor {
        self.actor(name)
    }

    /// Alias for [`TestEnv::try_actor`].
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// assert!(env.try_named_actor("bob").is_ok());
    /// assert!(env.try_named_actor("   ").is_err());
    /// ```
    pub fn try_named_actor(&self, name: &str) -> Result<Actor, TestkitError> {
        self.try_actor(name)
    }

    /// Generate multiple named [`Actor`]s from a slice of names.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if any name is empty/whitespace,
    /// or if duplicate names are specified.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let actors = env.actors(&["alice", "bob", "charlie"]);
    /// assert_eq!(actors.len(), 3);
    /// assert_ne!(actors[0].address(), actors[1].address());
    /// ```
    pub fn actors(&self, names: &[&str]) -> Vec<Actor> {
        self.try_actors(names).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Checked variant of [`TestEnv::actors`].
    ///
    /// # Errors
    ///
    /// Returns [`TestkitError::Misuse`] if any name is blank or if duplicate
    /// actor names are detected in `names`.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// assert!(env.try_actors(&["alice", "bob"]).is_ok());
    /// assert!(env.try_actors(&["alice", "alice"]).is_err());
    /// ```
    pub fn try_actors(&self, names: &[&str]) -> Result<Vec<Actor>, TestkitError> {
        for (i, &name) in names.iter().enumerate() {
            if name.trim().is_empty() {
                return Err(TestkitError::Misuse(
                    "actor name cannot be empty or only whitespace".into(),
                ));
            }
            for &earlier in &names[..i] {
                if earlier == name {
                    return Err(TestkitError::Misuse(format!(
                        "duplicate actor name {name:?} in batch request"
                    )));
                }
            }
        }
        Ok(names
            .iter()
            .map(|&n| Actor::new(n, self.address()))
            .collect())
    }

    /// The seed this environment was constructed with.
    ///
    /// This is the same seed passed to [`TestEnv::with_seed`], and can be used
    /// to reconstruct an environment with identical deterministic behavior
    /// (address generation, seeded property-test generators).
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::with_seed(42);
    /// let seed = env.seed();
    /// let recreated = TestEnv::with_seed(seed);
    /// assert_eq!(env.seed(), recreated.seed());
    /// assert_eq!(env.address(), recreated.address());
    /// ```
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// The ledger close interval configured for this environment, if any.
    pub(crate) fn close_interval_override(&self) -> Option<u64> {
        self.close_interval_secs
    }

    /// Record a ledger close interval for this environment. Callers are
    /// responsible for validating `secs`.
    pub(crate) fn set_close_interval_override(&mut self, secs: u64) {
        self.close_interval_secs = Some(secs);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Issue #35 — LedgerDefaults accessor
    // ──────────────────────────────────────────────────────────────────────

    /// The [`LedgerDefaults`] this environment was built with.
    ///
    /// Useful for cloning configuration or inspecting what was requested when
    /// an assertion produces a failure message.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::{LedgerDefaults, TestEnv};
    ///
    /// let defaults = LedgerDefaults::new().timestamp(1_000_000);
    /// let env = TestEnv::with_ledger_defaults(defaults);
    /// assert_eq!(env.ledger_defaults().timestamp_override(), Some(1_000_000));
    /// ```
    pub fn ledger_defaults(&self) -> &LedgerDefaults {
        &self.ledger_defaults
    }

    // ──────────────────────────────────────────────────────────────────────
    // Issue #39 — test-environment metadata
    // ──────────────────────────────────────────────────────────────────────

    /// Capture a snapshot of this environment's current state for use in
    /// assertion failure messages.
    ///
    /// [`EnvMetadata`] implements [`std::fmt::Display`] so it can be
    /// interpolated directly into a `format!` string. All assertion helpers
    /// in this crate include a metadata snapshot in their failure output so
    /// that a failed test tells you *where* in ledger time and *with which
    /// seed* it failed.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use std::time::Duration;
    ///
    /// let env = TestEnv::with_seed(7);
    /// env.advance(Duration::from_secs(120));
    ///
    /// let meta = env.metadata();
    /// assert_eq!(meta.seed, 7);
    /// assert_eq!(meta.timestamp, 120);
    ///
    /// let display = meta.to_string();
    /// assert!(display.contains("seed=7"), "{display}");
    /// assert!(display.contains("timestamp=120"), "{display}");
    /// ```
    pub fn metadata(&self) -> EnvMetadata {
        let info = self.env().ledger().get();
        EnvMetadata {
            timestamp: info.timestamp,
            sequence: info.sequence_number,
            protocol_version: info.protocol_version,
            seed: self.seed,
            close_interval_override: self.close_interval_secs,
        }
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
    }
}

static SEED_COUNTER: AtomicU64 = AtomicU64::new(0);

fn random_seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let count = SEED_COUNTER.fetch_add(1, Ordering::Relaxed);
    nanos ^ count.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Maximum number of addresses that can be requested in a single batch.
///
/// `soroban_sdk` collections are indexed by `u32` (`soroban_sdk::Vec::len`
/// returns `u32`), so a batch larger than `u32::MAX` could never be held in
/// an SDK collection at all. This constant keeps batches far below that
/// ceiling — and below sizes that would exhaust test resources — and both
/// [`TestEnv::addresses`] and [`TestEnv::try_addresses`] reject anything
/// above it cleanly, before allocating.
pub const MAX_ADDRESS_BATCH_SIZE: usize = 10_000;

/// A named test actor pairing a human-readable identifier (such as `"alice"` or
/// `"treasury"`) with a generated Soroban [`Address`].
///
/// In contract tests, raw cryptographic addresses (for example,
/// `Address(Account(GA...))`) in assertion failures or diagnostic logs make it
/// tedious to track which participant caused a failure. `Actor` bundles the
/// display name alongside the address so test diagnostics, auth matrices, and
/// logs clearly show the actor responsible.
///
/// `Actor` implements [`std::ops::Deref`] targeting [`Address`], so an `&Actor`
/// can be passed directly to any function expecting `&Address`. It also
/// implements [`std::fmt::Display`] for compact name rendering, and provides
/// [`Actor::diagnostic`] for formatting both name and raw address together.
///
/// # Example
///
/// ```
/// use soroban_testkit::core::TestEnv;
///
/// let env = TestEnv::new();
/// let alice = env.actor("alice");
///
/// assert_eq!(alice.name(), "alice");
/// assert_eq!(format!("{alice}"), "alice");
/// assert!(alice.diagnostic().starts_with("alice ("));
///
/// // Deref to Address works seamlessly:
/// let addr: &soroban_sdk::Address = &alice;
/// assert_eq!(addr, alice.address());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    name: String,
    address: Address,
}

impl Actor {
    /// Construct a new `Actor` with the given name and address.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::{Actor, TestEnv};
    ///
    /// let env = TestEnv::new();
    /// let actor = Actor::new("bob", env.address());
    /// assert_eq!(actor.name(), "bob");
    /// ```
    pub fn new(name: impl Into<String>, address: Address) -> Self {
        Self {
            name: name.into(),
            address,
        }
    }

    /// The human-readable name identifying this actor.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let admin = env.actor("admin");
    /// assert_eq!(admin.name(), "admin");
    /// ```
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The underlying Soroban [`Address`] assigned to this actor.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let alice = env.actor("alice");
    /// assert_eq!(alice.address(), &*alice);
    /// ```
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Consume the actor, returning its inner [`Address`].
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let alice = env.actor("alice");
    /// let _addr = alice.into_address();
    /// ```
    pub fn into_address(self) -> Address {
        self.address
    }

    /// Return a formatted diagnostic string pairing the actor name with its
    /// raw address, suitable for detailed assertion failure reports.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let alice = env.actor("alice");
    /// assert!(alice.diagnostic().starts_with("alice ("));
    /// ```
    pub fn diagnostic(&self) -> String {
        format!("{} ({:?})", self.name, self.address)
    }
}

impl std::ops::Deref for Actor {
    type Target = Address;

    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

impl AsRef<Address> for Actor {
    fn as_ref(&self) -> &Address {
        &self.address
    }
}

impl std::fmt::Display for Actor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl PartialEq<Address> for Actor {
    fn eq(&self, other: &Address) -> bool {
        &self.address == other
    }
}

impl PartialEq<Actor> for Address {
    fn eq(&self, other: &Actor) -> bool {
        self == &other.address
    }
}

/// An infinite iterator yielding fresh, distinct [`Address`] values on each step.
///
/// Standard iterator adapters such as [`.take(n)`](Iterator::take) can be chained
/// directly onto `AddressIter` to produce a stream of addresses without needing
/// to allocate an intermediate vector.
///
/// # Example
///
/// ```
/// use soroban_testkit::core::TestEnv;
///
/// let env = TestEnv::new();
/// let addrs: Vec<_> = env.address_iter().take(3).collect();
/// assert_eq!(addrs.len(), 3);
/// assert_ne!(addrs[0], addrs[1]);
/// ```
#[derive(Clone)]
pub struct AddressIter<'a> {
    env: &'a TestEnv,
}

impl<'a> AddressIter<'a> {
    /// Create a new `AddressIter` bound to the given environment.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::{AddressIter, TestEnv};
    ///
    /// let env = TestEnv::new();
    /// let mut iter = AddressIter::new(&env);
    /// let _first = iter.next().unwrap();
    /// ```
    pub fn new(env: &'a TestEnv) -> Self {
        Self { env }
    }
}

impl<'a> Iterator for AddressIter<'a> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.env.address())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }
}

impl<'a> std::iter::FusedIterator for AddressIter<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Ledger;
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    fn benchmark_batch(mut make: impl FnMut(usize)) -> Duration {
        const SAMPLES: usize = 64;
        for i in 0..4 {
            make(i);
        }
        let started = Instant::now();
        for i in 0..SAMPLES {
            make(i);
        }
        started.elapsed()
    }

    #[test]
    fn construction_cost_stays_close_to_the_raw_sdk_env() {
        let raw = benchmark_batch(|_| {
            black_box(TestEnv::fresh_env_with_defaults(&LedgerDefaults::default()));
        });
        let wrapped = benchmark_batch(|i| {
            black_box(TestEnv::with_seed(i as u64));
        });

        // TestEnv construction should remain little more than constructing the
        // SDK Env and storing its small amount of configuration. The fixed
        // 50ms allowance keeps this guard stable on noisy CI runners while
        // still catching accidental I/O, sleeps, or other heavyweight setup.
        let budget = raw.saturating_mul(3) + Duration::from_millis(50);
        assert!(
            wrapped <= budget,
            "constructing TestEnv regressed: wrapped={wrapped:?}, raw={raw:?}, budget={budget:?}"
        );
    }

    #[test]
    fn new_uses_the_documented_starting_ledger() {
        let env = TestEnv::new();
        let ledger = env.env().ledger().get();
        assert_eq!(ledger.sequence_number, 0);
        assert_eq!(ledger.timestamp, 0);
    }

    struct Fixture {
        env: TestEnv,
        first: Address,
    }

    impl TestFixture for Fixture {
        fn from_env(env: TestEnv) -> Self {
            let first = env.address();
            Self { env, first }
        }

        fn test_env(&self) -> &TestEnv {
            &self.env
        }
    }

    #[test]
    fn fixture_with_seed_is_reproducible() {
        let a = Fixture::with_seed(42);
        let b = Fixture::with_seed(42);
        assert_eq!(a.first, b.first);
        assert_eq!(a.test_env().seed(), 42);
        assert_eq!(b.test_env().seed(), 42);
    }

    #[test]
    fn fixture_new_environments_are_isolated() {
        let a = Fixture::new();
        let b = Fixture::new();
        a.test_env().env().ledger().set_sequence_number(9_999);
        assert_ne!(a.test_env().sequence(), b.test_env().sequence());
    }

    #[test]
    fn fixture_accepts_zero_seed_and_existing_env_configuration() {
        let zero = Fixture::with_seed(0);
        assert_eq!(zero.test_env().seed(), 0);

        let configured = Fixture::from_env(TestEnv::with_seed(7).with_ledger_close_interval(2));
        assert_eq!(configured.test_env().seed(), 7);
        assert_eq!(configured.test_env().ledger_close_interval(), 2);
    }

    #[test]
    fn test_env_itself_implements_fixture() {
        let env = <TestEnv as TestFixture>::with_seed(11);
        assert_eq!(env.seed(), 11);
        assert!(std::ptr::eq(<TestEnv as TestFixture>::test_env(&env), &env));
    }

    #[test]
    fn new_twice_produces_independent_environments() {
        let a = TestEnv::new();
        let b = TestEnv::new();
        a.env().ledger().set_sequence_number(12_345);
        assert_ne!(
            a.env().ledger().get().sequence_number,
            b.env().ledger().get().sequence_number
        );
    }

    // Regression test for issue #26: independently created `TestEnv` instances
    // must not share or leak any state — ledger clock, ledger sequence, or
    // address-generation counter — between them.
    #[test]
    fn independently_created_instances_are_fully_isolated() {
        let a = TestEnv::new();
        let b = TestEnv::new();

        // Capture b's baseline before touching a.
        let b_sequence_before = b.env().ledger().get().sequence_number;
        let b_timestamp_before = b.env().ledger().get().timestamp;

        // Mutate a's ledger clock through the SDK directly.
        a.env().ledger().set_sequence_number(77_777);
        a.env().ledger().set_timestamp(999_999);

        // b must observe none of a's mutations.
        assert_eq!(
            b.env().ledger().get().sequence_number,
            b_sequence_before,
            "mutating a's sequence must not affect b"
        );
        assert_eq!(
            b.env().ledger().get().timestamp,
            b_timestamp_before,
            "mutating a's timestamp must not affect b"
        );

        // Addresses from each environment must be independent of each other.
        let addr_from_a = a.address();
        let addr_from_b = b.address();
        assert_ne!(
            addr_from_a, addr_from_b,
            "addresses generated from independent environments must differ"
        );
    }

    #[test]
    fn with_seed_is_reproducible_across_runs() {
        let a = TestEnv::with_seed(42);
        let b = TestEnv::with_seed(42);
        assert_eq!(a.seed(), b.seed());
        assert_eq!(a.address(), b.address());
    }

    // --- seed accessor (#34) ---------------------------------------------

    #[test]
    fn seed_returns_the_seed_passed_to_with_seed() {
        for seed in [0, 1, 42, u64::MAX] {
            assert_eq!(TestEnv::with_seed(seed).seed(), seed);
        }
    }

    #[test]
    fn seed_is_carried_by_the_combined_defaults_constructor() {
        let defaults = LedgerDefaults::new().sequence_number(500);
        let env = TestEnv::with_ledger_defaults_and_seed(defaults, 7);
        assert_eq!(env.seed(), 7);
    }

    // The exposed seed is the round-trip key: rebuilding an environment from
    // the value `seed()` reports must reproduce the seeded generators.
    #[test]
    fn the_exposed_seed_rebuilds_an_identical_generator_stream() {
        let env = TestEnv::with_seed(1234);
        let recreated = TestEnv::with_seed(env.seed());

        assert_eq!(
            crate::money::amounts_in(&env, 0, 1_000_000, 16),
            crate::money::amounts_in(&recreated, 0, 1_000_000, 16)
        );
    }

    // Distinct seeds must drive distinct streams — otherwise `seed()` would
    // report a value that does not actually control the generators.
    #[test]
    fn different_seeds_drive_different_generator_streams() {
        let a = crate::money::amounts_in(&TestEnv::with_seed(1), 0, 1_000_000, 16);
        let b = crate::money::amounts_in(&TestEnv::with_seed(2), 0, 1_000_000, 16);
        assert_ne!(a, b);
    }

    #[test]
    fn seed_zero_is_a_real_seed_not_an_unset_marker() {
        let env = TestEnv::with_seed(0);
        assert_eq!(env.seed(), 0);
        assert_eq!(
            crate::money::amounts_in(&env, 0, 100, 8),
            crate::money::amounts_in(&TestEnv::with_seed(0), 0, 100, 8)
        );
    }

    // The seed is construction-time configuration: drawing addresses and
    // moving the clock must not change it.
    #[test]
    fn the_seed_does_not_change_while_the_environment_is_used() {
        let env = TestEnv::with_seed(42);
        let before = env.seed();

        env.addresses(4);
        env.advance_ledgers(10);

        assert_eq!(env.seed(), before);
    }

    #[test]
    fn addresses_returns_n_distinct_addresses() {
        let env = TestEnv::new();
        let addrs = env.addresses(5);
        assert_eq!(addrs.len(), 5);
        for i in 0..addrs.len() {
            for j in (i + 1)..addrs.len() {
                assert_ne!(addrs[i], addrs[j]);
            }
        }
    }

    // --- clone_config ----------------------------------------------------

    #[test]
    fn clone_config_carries_the_seed() {
        let original = TestEnv::with_seed(42);
        assert_eq!(original.clone_config().seed(), 42);
    }

    #[test]
    fn clone_config_carries_the_close_interval() {
        let original = TestEnv::new().with_ledger_close_interval(2);
        assert_eq!(original.clone_config().ledger_close_interval(), 2);
    }

    #[test]
    fn clone_config_keeps_an_unset_close_interval_unset() {
        let clone = TestEnv::new().clone_config();
        assert_eq!(clone.close_interval_override(), None);
    }

    #[test]
    fn clone_config_does_not_carry_the_clock_position() {
        let original = TestEnv::new();
        original.advance_ledgers(25);
        let pristine = TestEnv::new();

        let clone = original.clone_config();
        assert_eq!(
            (clone.now(), clone.sequence()),
            (pristine.now(), pristine.sequence())
        );
        assert_ne!(clone.sequence(), original.sequence());
    }

    #[test]
    fn clone_config_matches_a_freshly_built_environment() {
        let original = TestEnv::with_seed(42);
        // Consume some addresses so any state leaking into the clone would show.
        original.addresses(3);
        assert_eq!(
            original.clone_config().address(),
            TestEnv::with_seed(42).address()
        );
    }

    #[test]
    fn clone_config_is_isolated_from_the_original() {
        let original = TestEnv::new();
        let clone = original.clone_config();
        let (original_before, clone_before) = (original.sequence(), clone.sequence());

        clone.env().ledger().set_sequence_number(9_000);
        assert_eq!(original.sequence(), original_before);

        original.env().ledger().set_sequence_number(7_000);
        assert_eq!(clone.sequence(), 9_000);
        assert_ne!(clone.sequence(), clone_before);
    }

    #[test]
    fn clone_config_of_a_clone_keeps_the_configuration() {
        let original = TestEnv::with_seed(5).with_ledger_close_interval(3);
        let second = original.clone_config().clone_config();
        assert_eq!(second.seed(), 5);
        assert_eq!(second.ledger_close_interval(), 3);
    }

    #[test]
    fn clone_config_does_not_change_the_original() {
        let original = TestEnv::with_seed(5).with_ledger_close_interval(3);
        original.advance_ledgers(4);
        let (now, sequence) = (original.now(), original.sequence());

        let _ = original.clone_config();
        assert_eq!((original.now(), original.sequence()), (now, sequence));
        assert_eq!(original.seed(), 5);
        assert_eq!(original.ledger_close_interval(), 3);
    }

    // --- reset -------------------------------------------------------------

    #[test]
    fn reset_returns_the_clock_to_the_starting_ledger() {
        let pristine = TestEnv::new();
        let mut env = TestEnv::new();
        env.advance_ledgers(50);
        assert_ne!(env.sequence(), pristine.sequence());

        env.reset();
        assert_eq!(
            (env.now(), env.sequence()),
            (pristine.now(), pristine.sequence())
        );
    }

    #[test]
    fn reset_keeps_the_seed_and_the_close_interval() {
        let mut env = TestEnv::with_seed(42).with_ledger_close_interval(2);
        env.advance_ledgers(10);

        env.reset();
        assert_eq!(env.seed(), 42);
        assert_eq!(env.ledger_close_interval(), 2);
    }

    #[test]
    fn reset_keeps_an_unset_close_interval_unset() {
        let mut env = TestEnv::new();
        env.reset();
        assert_eq!(env.close_interval_override(), None);
    }

    #[test]
    fn reset_issues_addresses_from_the_start_again() {
        let mut env = TestEnv::with_seed(42);
        env.addresses(4);

        env.reset();
        assert_eq!(env.address(), TestEnv::with_seed(42).address());
    }

    #[test]
    fn reset_leaves_earlier_handles_on_the_discarded_environment() {
        let mut env = TestEnv::new();
        env.advance_ledgers(3);
        let (now, sequence) = (env.now(), env.sequence());
        let stale = env.env().clone();

        env.reset();
        // The old handle still observes the old state...
        assert_eq!(stale.ledger().timestamp(), now);
        assert_eq!(stale.ledger().sequence(), sequence);
        // ...while the reset environment does not.
        assert_ne!(env.sequence(), sequence);
    }

    #[test]
    fn reset_environment_is_independent_of_the_discarded_one() {
        let mut env = TestEnv::new();
        let stale = env.env().clone();
        env.reset();

        let stale_before = stale.ledger().sequence();
        env.advance_ledgers(8);
        assert_eq!(stale.ledger().sequence(), stale_before);
    }

    #[test]
    fn reset_on_a_pristine_environment_changes_nothing_observable() {
        let mut env = TestEnv::with_seed(9);
        let (now, sequence) = (env.now(), env.sequence());

        env.reset();
        assert_eq!((env.now(), env.sequence()), (now, sequence));
        assert_eq!(env.seed(), 9);
    }

    #[test]
    fn reset_twice_is_the_same_as_reset_once() {
        let mut env = TestEnv::new().with_ledger_close_interval(4);
        env.advance_ledgers(6);

        env.reset();
        let once = (env.now(), env.sequence(), env.ledger_close_interval());
        env.reset();
        assert_eq!(
            (env.now(), env.sequence(), env.ledger_close_interval()),
            once
        );
    }

    #[test]
    fn reset_environment_is_fully_usable() {
        let mut env = TestEnv::new();
        env.advance_ledgers(2);
        env.reset();

        let before = env.sequence();
        env.advance_ledgers(5);
        assert_eq!(env.sequence(), before + 5);
        assert_ne!(env.address(), env.address());
    }

    // ─────────────────────────────────────────────────────────────────────
    // Issue #35 — LedgerDefaults builder
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn ledger_defaults_new_has_all_none() {
        let d = LedgerDefaults::new();
        assert!(d.timestamp_override().is_none());
        assert!(d.sequence_number_override().is_none());
        assert!(d.protocol_version_override().is_none());
        assert!(d.base_reserve_override().is_none());
    }

    #[test]
    fn ledger_defaults_timestamp_sets_the_starting_timestamp() {
        let env = TestEnv::with_ledger_defaults(LedgerDefaults::new().timestamp(1_700_000_000));
        assert_eq!(env.now(), 1_700_000_000);
    }

    #[test]
    fn ledger_defaults_sequence_sets_the_starting_sequence() {
        let env = TestEnv::with_ledger_defaults(LedgerDefaults::new().sequence_number(999_000));
        assert_eq!(env.sequence(), 999_000);
    }

    #[test]
    fn ledger_defaults_protocol_version_is_applied() {
        // Use the SDK's own current protocol version to avoid the "too old"
        // check in soroban-env-host (which rejects versions below the host's
        // interface version in non-test-mode builds of that crate).
        let current = soroban_sdk::Env::default().ledger().get().protocol_version;
        let env = TestEnv::with_ledger_defaults(LedgerDefaults::new().protocol_version(current));
        assert_eq!(env.env().ledger().get().protocol_version, current);
    }

    #[test]
    fn ledger_defaults_base_reserve_is_applied() {
        let env = TestEnv::with_ledger_defaults(LedgerDefaults::new().base_reserve(5_000_000));
        assert_eq!(env.env().ledger().get().base_reserve, 5_000_000);
    }

    #[test]
    fn ledger_defaults_all_fields_together() {
        // Use the SDK's current protocol version to avoid the "too old" check.
        let current_protocol = soroban_sdk::Env::default().ledger().get().protocol_version;
        let env = TestEnv::with_ledger_defaults(
            LedgerDefaults::new()
                .timestamp(1_700_000_000)
                .sequence_number(42_000)
                .protocol_version(current_protocol)
                .base_reserve(5_000_000),
        );
        let info = env.env().ledger().get();
        assert_eq!(env.now(), 1_700_000_000);
        assert_eq!(env.sequence(), 42_000);
        assert_eq!(info.protocol_version, current_protocol);
        assert_eq!(info.base_reserve, 5_000_000);
    }

    #[test]
    fn with_ledger_defaults_and_seed_is_deterministic() {
        let defaults = LedgerDefaults::new()
            .timestamp(500_000)
            .sequence_number(100);
        let a = TestEnv::with_ledger_defaults_and_seed(defaults.clone(), 7);
        let b = TestEnv::with_ledger_defaults_and_seed(defaults, 7);
        assert_eq!(a.now(), b.now());
        assert_eq!(a.sequence(), b.sequence());
        assert_eq!(a.address(), b.address());
    }

    #[test]
    fn ledger_defaults_are_carried_by_clone_config() {
        let defaults = LedgerDefaults::new()
            .timestamp(1_000_000)
            .sequence_number(500);
        let original = TestEnv::with_ledger_defaults(defaults);
        original.advance_ledgers(10);

        let clone = original.clone_config();
        // The clone starts from the defaults again, not from the original's
        // current position.
        assert_eq!(clone.now(), 1_000_000);
        assert_eq!(clone.sequence(), 500);
    }

    #[test]
    fn ledger_defaults_are_respected_after_reset() {
        let defaults = LedgerDefaults::new()
            .timestamp(2_000_000)
            .sequence_number(300);
        let mut env = TestEnv::with_ledger_defaults(defaults);
        env.advance_ledgers(50);
        assert_ne!(env.now(), 2_000_000);

        env.reset();
        assert_eq!(env.now(), 2_000_000);
        assert_eq!(env.sequence(), 300);
    }

    #[test]
    fn ledger_defaults_accessor_returns_what_was_given() {
        let defaults = LedgerDefaults::new().timestamp(99).sequence_number(7);
        let env = TestEnv::with_ledger_defaults(defaults);
        assert_eq!(env.ledger_defaults().timestamp_override(), Some(99));
        assert_eq!(env.ledger_defaults().sequence_number_override(), Some(7));
    }

    #[test]
    fn ledger_defaults_with_no_fields_is_same_as_new() {
        let with_defaults = TestEnv::with_ledger_defaults(LedgerDefaults::new());
        let plain = TestEnv::new();
        // Starting positions should be the same (both start at 0/0).
        assert_eq!(with_defaults.now(), plain.now());
        assert_eq!(with_defaults.sequence(), plain.sequence());
    }

    // ─────────────────────────────────────────────────────────────────────
    // Issue #39 — EnvMetadata in diagnostic output
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn metadata_captures_current_timestamp_and_sequence() {
        let env = TestEnv::new();
        env.advance_ledgers(10);
        let meta = env.metadata();
        assert_eq!(meta.timestamp, env.now());
        assert_eq!(meta.sequence, env.sequence());
    }

    #[test]
    fn metadata_captures_seed() {
        let env = TestEnv::with_seed(42);
        assert_eq!(env.metadata().seed, 42);
    }

    #[test]
    fn metadata_captures_close_interval_override() {
        let env = TestEnv::new().with_ledger_close_interval(3);
        assert_eq!(env.metadata().close_interval_override, Some(3));
    }

    #[test]
    fn metadata_has_no_close_interval_when_none_was_set() {
        let env = TestEnv::new();
        assert_eq!(env.metadata().close_interval_override, None);
    }

    #[test]
    fn metadata_display_includes_all_key_fields() {
        let env = TestEnv::with_seed(7).with_ledger_close_interval(2);
        env.advance_ledgers(5);
        let display = env.metadata().to_string();
        assert!(display.contains("seed=7"), "{display}");
        assert!(display.contains("close_interval=2s"), "{display}");
        // sequence and timestamp both have non-zero values now
        assert!(display.contains("sequence="), "{display}");
        assert!(display.contains("timestamp="), "{display}");
    }

    #[test]
    fn metadata_display_omits_close_interval_when_not_set() {
        let env = TestEnv::with_seed(5);
        let display = env.metadata().to_string();
        assert!(!display.contains("close_interval"), "{display}");
    }

    #[test]
    fn metadata_updates_after_advancing_the_clock() {
        let env = TestEnv::new();
        let before = env.metadata();
        env.advance_ledgers(20);
        let after = env.metadata();
        assert!(after.timestamp > before.timestamp);
        assert!(after.sequence > before.sequence);
    }

    #[test]
    fn metadata_protocol_version_matches_ledger_info() {
        // Use the SDK's current protocol version to avoid the "too old" check.
        let current_protocol = soroban_sdk::Env::default().ledger().get().protocol_version;
        let env =
            TestEnv::with_ledger_defaults(LedgerDefaults::new().protocol_version(current_protocol));
        assert_eq!(env.metadata().protocol_version, current_protocol);
    }

    // --- Named actor generation (#36) -----------------------------------

    #[test]
    fn actor_creates_actor_with_expected_name_and_address() {
        let env = TestEnv::new();
        let alice = env.actor("alice");
        assert_eq!(alice.name(), "alice");
        assert_eq!(alice.address(), &*alice);
        assert_eq!(format!("{alice}"), "alice");
    }

    #[test]
    fn actor_diagnostic_formats_name_and_debug_address() {
        let env = TestEnv::new();
        let alice = env.actor("alice");
        let diag = alice.diagnostic();
        assert!(diag.starts_with("alice ("));
        assert!(diag.ends_with(')'));
    }

    #[test]
    fn actor_derefs_and_compares_with_address() {
        let env = TestEnv::new();
        let alice = env.actor("alice");
        let raw_addr: &Address = &alice;
        assert_eq!(raw_addr, alice.address());
        assert_eq!(alice, *alice.address());
        assert_eq!(*alice.address(), alice);

        let bob = env.actor("bob");
        assert_ne!(alice, bob);
    }

    #[test]
    fn actor_into_address_returns_underlying_address() {
        let env = TestEnv::new();
        let alice = env.actor("alice");
        let expected = alice.address().clone();
        assert_eq!(alice.into_address(), expected);
    }

    #[test]
    fn try_actor_accepts_valid_names() {
        let env = TestEnv::new();
        assert!(env.try_actor("alice").is_ok());
        assert!(env.try_actor("treasury_1").is_ok());
        assert!(env.try_named_actor("admin").is_ok());
    }

    #[test]
    fn try_actor_rejects_empty_or_whitespace_names() {
        let env = TestEnv::new();
        let err_empty = env.try_actor("").unwrap_err();
        assert_eq!(err_empty.code(), "TESTKIT_MISUSE");
        assert_eq!(
            err_empty.message(),
            "actor name cannot be empty or only whitespace"
        );

        let err_space = env.try_actor("   \t\n").unwrap_err();
        assert_eq!(err_space.code(), "TESTKIT_MISUSE");
    }

    #[test]
    #[should_panic(expected = "actor name cannot be empty or only whitespace")]
    fn actor_panics_on_empty_name() {
        let env = TestEnv::new();
        let _ = env.actor("");
    }

    #[test]
    #[should_panic(expected = "actor name cannot be empty or only whitespace")]
    fn named_actor_panics_on_whitespace_name() {
        let env = TestEnv::new();
        let _ = env.named_actor("   ");
    }

    #[test]
    fn actors_batch_generates_distinct_actors() {
        let env = TestEnv::new();
        let actors = env.actors(&["alice", "bob", "charlie"]);
        assert_eq!(actors.len(), 3);
        assert_eq!(actors[0].name(), "alice");
        assert_eq!(actors[1].name(), "bob");
        assert_eq!(actors[2].name(), "charlie");
        assert_ne!(actors[0].address(), actors[1].address());
        assert_ne!(actors[1].address(), actors[2].address());
        assert_ne!(actors[0].address(), actors[2].address());
    }

    #[test]
    fn try_actors_rejects_duplicate_names() {
        let env = TestEnv::new();
        let err = env.try_actors(&["alice", "bob", "alice"]).unwrap_err();
        assert_eq!(err.code(), "TESTKIT_MISUSE");
        assert!(err.message().contains("duplicate actor name \"alice\""));
    }

    #[test]
    fn try_actors_rejects_blank_name() {
        let env = TestEnv::new();
        let err = env.try_actors(&["alice", ""]).unwrap_err();
        assert_eq!(err.code(), "TESTKIT_MISUSE");
    }

    #[test]
    #[should_panic(expected = "duplicate actor name")]
    fn actors_panics_on_duplicate_name() {
        let env = TestEnv::new();
        let _ = env.actors(&["admin", "admin"]);
    }

    // --- Address iterator (#37) -----------------------------------------

    #[test]
    fn address_iter_yields_fresh_distinct_addresses() {
        let env = TestEnv::new();
        let addrs: Vec<Address> = env.address_iter().take(5).collect();
        assert_eq!(addrs.len(), 5);
        for i in 0..addrs.len() {
            for j in (i + 1)..addrs.len() {
                assert_ne!(addrs[i], addrs[j]);
            }
        }
    }

    #[test]
    fn addresses_iter_alias_behaves_identically() {
        let env = TestEnv::new();
        let mut iter = env.addresses_iter();
        let a = iter.next().unwrap();
        let b = iter.next().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn address_iter_reproducible_with_seed() {
        let env1 = TestEnv::with_seed(12345);
        let env2 = TestEnv::with_seed(12345);
        let seq1: Vec<Address> = env1.address_iter().take(4).collect();
        let seq2: Vec<Address> = env2.address_iter().take(4).collect();
        assert_eq!(seq1, seq2);
    }

    #[test]
    fn address_iter_size_hint_and_cloning() {
        let env = TestEnv::new();
        let iter = env.address_iter();
        let (lower, upper) = iter.size_hint();
        assert_eq!(lower, usize::MAX);
        assert_eq!(upper, None);

        let mut iter_clone = iter.clone();
        assert!(iter_clone.next().is_some());
    }

    // --- Checked address batch API (#38) --------------------------------

    #[test]
    fn try_addresses_succeeds_for_valid_batch_sizes() {
        let env = TestEnv::new();
        let one = env.try_addresses(1).unwrap();
        assert_eq!(one.len(), 1);

        let five = env.try_addresses(5).unwrap();
        assert_eq!(five.len(), 5);
        for i in 0..five.len() {
            for j in (i + 1)..five.len() {
                assert_ne!(five[i], five[j]);
            }
        }
    }

    #[test]
    fn checked_addresses_alias_succeeds() {
        let env = TestEnv::new();
        let res = env.checked_addresses(3);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 3);
    }

    #[test]
    fn try_addresses_rejects_zero_count() {
        let env = TestEnv::new();
        let err = env.try_addresses(0).unwrap_err();
        assert_eq!(err.code(), "TESTKIT_MISUSE");
        assert_eq!(
            err.message(),
            "address batch size must be at least 1; requested 0 addresses"
        );
    }

    #[test]
    fn try_addresses_rejects_excessive_batch_size() {
        let env = TestEnv::new();
        let err = env.try_addresses(MAX_ADDRESS_BATCH_SIZE + 1).unwrap_err();
        assert_eq!(err.code(), "TESTKIT_MISUSE");
        assert!(err.message().contains("exceeds the maximum limit"));

        let err_max = env.try_addresses(usize::MAX).unwrap_err();
        assert_eq!(err_max.code(), "TESTKIT_MISUSE");
    }

    #[test]
    fn try_addresses_reproducible_for_same_seed() {
        let env1 = TestEnv::with_seed(999);
        let env2 = TestEnv::with_seed(999);
        let batch1 = env1.try_addresses(4).unwrap();
        let batch2 = env2.try_addresses(4).unwrap();
        assert_eq!(batch1, batch2);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Issue #24 — seeded address determinism after interleaved batches
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn seeded_address_streams_align_across_interleaved_batches() {
        // Two same-seed environments interleaving batches of different
        // sizes must keep issuing the same global sequence.
        let a = TestEnv::with_seed(42);
        let b = TestEnv::with_seed(42);

        let a1 = a.addresses(3);
        let b1 = b.addresses(5);
        let a2 = a.addresses(2);
        let b2 = b.addresses(4);

        let reference = TestEnv::with_seed(42).addresses(9);

        let mut a_stream = a1.clone();
        a_stream.extend(a2);
        assert_eq!(a_stream, reference[..5]);

        let mut b_stream = b1;
        b_stream.extend(b2);
        assert_eq!(b_stream, reference[..]);
    }

    #[test]
    fn seeded_address_batches_survive_interleaved_raw_env_generation() {
        // Regression test for the root cause: address batches used to draw
        // from the SDK generator shared with every raw handle reachable
        // through `env()`, so interleaving a raw batch shifted every
        // subsequent testkit address and broke the seeded sequence.
        use soroban_sdk::testutils::Address as _;

        let env = TestEnv::with_seed(42);
        let reference = TestEnv::with_seed(42);

        let e1 = env.addresses(3);
        let r1 = reference.addresses(3);
        assert_eq!(e1, r1);

        // Interleave a raw address batch through the escape hatch.
        let handle = env.env().clone();
        let _raw: Vec<Address> = (0..2).map(|_| Address::generate(&handle)).collect();

        let e2 = env.addresses(3);
        let r2 = reference.addresses(3);
        assert_eq!(e2, r2, "seeded batch shifted by interleaved raw batch");
    }

    #[test]
    fn interleaved_raw_generation_does_not_shift_actor_batches() {
        use soroban_sdk::testutils::Address as _;

        let env = TestEnv::with_seed(7);
        let reference = TestEnv::with_seed(7);

        let alice = env.actor("alice");
        let _raw = Address::generate(env.env());
        let bob = env.actor("bob");

        let ref_alice = reference.actor("alice");
        let ref_bob = reference.actor("bob");
        assert_eq!(alice.address(), ref_alice.address());
        assert_eq!(bob.address(), ref_bob.address());
    }

    #[test]
    fn generated_addresses_never_collide_with_the_sdk_generator_stream() {
        // Regression test for the shared-layout root cause: the testkit
        // stream and the SDK generator both start at 1, so a shared byte
        // layout made `env.address() #1` equal the first registered
        // contract's id — breaking auth matrices and balance assertions
        // that treat the two as distinct parties.
        use soroban_sdk::testutils::Address as _;

        let env = TestEnv::new();
        let mine = env.addresses(5);
        let raw: Vec<Address> = (0..5).map(|_| Address::generate(env.env())).collect();
        for m in &mine {
            for r in &raw {
                assert_ne!(m, r, "testkit address collided with raw generator stream");
            }
        }

        let vault_id = env.env().register(vault::Vault, ());
        assert!(
            !mine.contains(&vault_id),
            "testkit address collided with a registered contract id"
        );
        assert_ne!(
            env.address(),
            vault_id,
            "next testkit address collided with a registered contract id"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Issue #25 — clean rejection of oversized address batches
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn addresses_allows_batches_up_to_the_documented_limit() {
        let env = TestEnv::new();
        assert_eq!(
            env.addresses(MAX_ADDRESS_BATCH_SIZE).len(),
            MAX_ADDRESS_BATCH_SIZE
        );
    }

    #[test]
    #[should_panic(
        expected = "misuse of testkit API: requested address batch size 10001 exceeds the maximum limit of 10000"
    )]
    fn addresses_rejects_batches_above_the_limit_cleanly() {
        // Regression test: this used to silently generate the batch instead
        // of rejecting it.
        let _ = TestEnv::new().addresses(MAX_ADDRESS_BATCH_SIZE + 1);
    }

    #[test]
    #[should_panic(expected = "exceeds the maximum limit of 10000")]
    fn addresses_rejects_batches_beyond_sdk_collection_limits_cleanly() {
        // A batch of usize::MAX can never fit an SDK collection (elements
        // are u32-indexed); it must fail with a clear Misuse message before
        // any allocation is attempted.
        let _ = TestEnv::new().addresses(usize::MAX);
    }

    #[test]
    #[should_panic(
        expected = "misuse of testkit API: address batch size must be at least 1; requested 0 addresses"
    )]
    fn addresses_rejects_zero_sized_batches() {
        let _ = TestEnv::new().addresses(0);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Issue #31 — Default matching TestEnv::new
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn default_matches_new_starting_ledger_and_configuration() {
        let default_env = TestEnv::default();
        let new_env = TestEnv::new();

        // Same deterministic starting ledger.
        assert_eq!(
            default_env.env().ledger().get(),
            new_env.env().ledger().get()
        );
        // Same configuration surface.
        assert_eq!(
            default_env.metadata().close_interval_override,
            new_env.metadata().close_interval_override
        );
        assert_eq!(
            default_env.ledger_defaults().timestamp_override(),
            new_env.ledger_defaults().timestamp_override()
        );
        assert_eq!(
            default_env.ledger_defaults().sequence_number_override(),
            new_env.ledger_defaults().sequence_number_override()
        );
    }

    #[test]
    fn default_issues_distinct_addresses_like_new() {
        // Address streams are seed-derived, and default/new each draw a
        // fresh random seed, so the sequences are compared behaviorally
        // rather than byte-for-byte: both must yield `n` distinct
        // addresses, exactly as a same-seed rebuild would.
        for env in [TestEnv::default(), TestEnv::new()] {
            let addrs = env.addresses(3);
            assert_eq!(addrs.len(), 3);
            for i in 0..addrs.len() {
                for j in (i + 1)..addrs.len() {
                    assert_ne!(addrs[i], addrs[j]);
                }
            }
        }
        // Same-seed environments still reproduce each other's sequences.
        assert_eq!(
            TestEnv::with_seed(42).addresses(3),
            TestEnv::with_seed(42).addresses(3)
        );
    }

    #[test]
    fn default_twice_produces_independent_environments() {
        // Mirrors `new_twice_produces_independent_environments`: Default
        // must delegate to `new`, so two defaults are independent too.
        let a = TestEnv::default();
        let b = TestEnv::default();
        a.env().ledger().set_sequence_number(12_345);
        assert_ne!(
            a.env().ledger().get().sequence_number,
            b.env().ledger().get().sequence_number
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Issue #32 — ownership and lifetime of the raw Env escape hatch
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn env_escape_hatch_aliases_the_owned_sdk_env() {
        let env = TestEnv::new();
        let sdk_env: &soroban_sdk::Env = env.env();
        sdk_env.ledger().set_sequence_number(777);
        // Mutations through the `&Env` are visible through the TestEnv:
        // it is a borrow of the same environment, not a copy.
        assert_eq!(env.sequence(), 777);
    }

    #[test]
    fn cloned_env_handle_shares_state_with_the_testenv() {
        let env = TestEnv::new();
        let handle = env.env().clone();
        handle.ledger().set_sequence_number(888);
        assert_eq!(env.sequence(), 888);

        // ...and mutations through the TestEnv are visible through the clone.
        env.advance_ledgers(1);
        assert_eq!(handle.ledger().sequence(), 889);
    }
} // end mod tests
