use std::any::Any;
use std::fmt;

use soroban_sdk::testutils::storage::{Instance as _, Persistent as _, Temporary as _};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{Address, Env, IntoVal, Val};

use crate::core::{TestEnv, TestkitError};

/// Which of Soroban's three storage kinds an entry lives in. TTL semantics
/// differ per kind — see [`TestEnv::ttl_of`] and [`TestEnv::expire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKind {
    /// Cheapest, expires soonest, and once gone is gone — used for data
    /// that's fine to lose (e.g. rate-limit counters, session state).
    Temporary,
    /// Long-lived, rent-paying storage. Expired entries can be restored by
    /// re-writing them; reading an expired entry panics.
    Persistent,
    /// The contract's own instance data (its "self" storage) plus its
    /// code. There is exactly one instance entry per contract, so
    /// [`TestEnv::ttl_of`] ignores the `key` parameter for this kind.
    Instance,
}

/// Protocol version at which Soroban launched with automatic archival of
/// expired entries: a persistent entry that runs out of rent is archived,
/// not destroyed, and is quietly restored on its next read, while a
/// temporary entry is simply deleted.
///
/// Use with [`TestEnv::with_protocol_version`] as a fixture for archival
/// behavior. The same archival rules are simulated by the host at every
/// supported protocol version (that is what makes the fixture useful for
/// pinning intent rather than for observing behavior differences).
pub const ARCHIVAL_PROTOCOL_SOROBAN_LAUNCH: u32 = 20;

/// Protocol version at which contract lifecycle operations (instance and
/// code TTL extension) were introduced, layered on top of the launch-era
/// archival rules. Relevant to archival behavior when contracts or their
/// instance storage are what expires.
pub const ARCHIVAL_PROTOCOL_CONTRACT_LIFECYCLE: u32 = 21;

/// Protocol version at which state archival settings (archival of
/// read-only entries after a grace period) were introduced. A sensible
/// default fixture for testing archival behavior on a modern network.
pub const ARCHIVAL_PROTOCOL_STATE_ARCHIVAL: u32 = 22;

/// The archival-relevant ledger parameters of a [`TestEnv`], captured at
/// runtime rather than hardcoded.
///
/// Whether an expired entry is archived-and-restored (persistent and
/// instance storage) or deleted (temporary storage) is governed by the
/// network's TTL parameters; because those parameters have changed across
/// protocol versions, tests that care about archival behavior should pin a
/// protocol version and snapshot these values rather than assume them.
///
/// # Example
///
/// ```
/// use soroban_testkit::core::TestEnv;
/// use soroban_sdk::testutils::Ledger as _;
///
/// let env = TestEnv::new();
/// let params = env.archival_parameters();
///
/// // The snapshot is taken from the environment's live ledger info, so it
/// // always agrees with what the host actually enforces.
/// let info = env.env().ledger().get();
/// assert_eq!(params.protocol_version, info.protocol_version);
/// assert_eq!(params.max_entry_ttl, info.max_entry_ttl);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchivalParameters {
    /// The protocol version this environment reports.
    pub protocol_version: u32,
    /// The ledger sequence at which the snapshot was taken.
    pub sequence_number: u32,
    /// Minimum TTL (in ledgers) granted to a persistent or instance entry,
    /// including to a persistent entry restored from the archive.
    pub min_persistent_entry_ttl: u32,
    /// Minimum TTL (in ledgers) granted to a temporary entry.
    pub min_temp_entry_ttl: u32,
    /// The maximum TTL (in ledgers) any entry may be extended to.
    pub max_entry_ttl: u32,
}

impl fmt::Display for ArchivalParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "protocol_version={}, sequence={}, min_persistent_entry_ttl={}, \
             min_temp_entry_ttl={}, max_entry_ttl={}",
            self.protocol_version,
            self.sequence_number,
            self.min_persistent_entry_ttl,
            self.min_temp_entry_ttl,
            self.max_entry_ttl,
        )
    }
}

/// A snapshot of where a storage entry sits in its TTL lifetime, taken at a
/// specific ledger.
///
/// Returned by [`TestEnv::ttl_timeline`]. Because the two sequences are
/// recorded, a snapshot taken *before* expiry can continue to answer
/// "has this entry expired yet?" after the ledger advances — see
/// [`TtlTimeline::expired_at`] — without re-reading the entry (which, for
/// persistent storage, would itself restore it from the archive).
///
/// # Example
///
/// ```
/// use soroban_testkit::ttl::{StorageKind, TtlTimeline};
///
/// // A manually assembled snapshot demonstrates the arithmetic helpers.
/// let timeline = TtlTimeline {
///     kind: StorageKind::Persistent,
///     current_sequence: 100,
///     expires_at_sequence: 110,
///     ttl_remaining: 10,
/// };
/// assert_eq!(timeline.ledgers_until_expiry(), 10);
/// assert!(!timeline.expired());
/// assert!(!timeline.expires_next_ledger());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlTimeline {
    /// The storage kind this entry lives in.
    pub kind: StorageKind,
    /// The ledger sequence at which this snapshot was taken.
    pub current_sequence: u32,
    /// The ledger sequence at which the entry expires. Once the ledger
    /// reaches this sequence the entry is gone (temporary) or archived
    /// (persistent and instance storage).
    pub expires_at_sequence: u32,
    /// TTL remaining in ledgers, i.e. `expires_at_sequence - current_sequence`.
    pub ttl_remaining: u32,
}

impl TtlTimeline {
    /// Whether the entry has expired by the given ledger sequence.
    ///
    /// A snapshot taken while the entry was live reports `true` here once
    /// the environment's ledger passes [`TtlTimeline::expires_at_sequence`],
    /// so a test can verify an entry is truly past expiry without touching
    /// it (touching a persistent entry after expiry restores it).
    ///
    /// # Example
    ///
    /// ```
    /// // A manually assembled snapshot: the helper's arithmetic is
    /// // well-defined even without a live entry.
    /// let timeline = soroban_testkit::ttl::TtlTimeline {
    ///     kind: soroban_testkit::ttl::StorageKind::Persistent,
    ///     current_sequence: 10,
    ///     expires_at_sequence: 20,
    ///     ttl_remaining: 10,
    /// };
    /// assert!(!timeline.expired());
    /// assert!(timeline.expired_at(20));
    /// ```
    pub fn expired_at(&self, sequence: u32) -> bool {
        sequence >= self.expires_at_sequence
    }

    /// Whether the entry had already expired when this snapshot was taken.
    ///
    /// Only possible for a manually constructed [`TtlTimeline`]; a snapshot
    /// returned by [`TestEnv::ttl_timeline`] is always of a live entry.
    pub fn expired(&self) -> bool {
        self.expired_at(self.current_sequence)
    }

    /// Whether this entry expires on the very next ledger.
    ///
    /// The last-moment window that [`TestEnv::assert_runs_before_expiry`]
    /// targets.
    ///
    /// # Example
    ///
    /// ```
    /// let timeline = soroban_testkit::ttl::TtlTimeline {
    ///     kind: soroban_testkit::ttl::StorageKind::Persistent,
    ///     current_sequence: 10,
    ///     expires_at_sequence: 11,
    ///     ttl_remaining: 1,
    /// };
    /// assert!(timeline.expires_next_ledger());
    /// ```
    pub fn expires_next_ledger(&self) -> bool {
        self.ttl_remaining == 1
    }

    /// Ledgers remaining until expiry, saturated at zero.
    ///
    /// # Example
    ///
    /// ```
    /// let timeline = soroban_testkit::ttl::TtlTimeline {
    ///     kind: soroban_testkit::ttl::StorageKind::Persistent,
    ///     current_sequence: 10,
    ///     expires_at_sequence: 25,
    ///     ttl_remaining: 15,
    /// };
    /// assert_eq!(timeline.ledgers_until_expiry(), 15);
    /// ```
    pub fn ledgers_until_expiry(&self) -> u32 {
        self.ttl_remaining
    }
}

impl fmt::Display for TtlTimeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{kind:?} entry TTL of {ttl} ledgers, expiring at ledger {expires_at} \
             (snapshot at ledger {current})",
            kind = self.kind,
            ttl = self.ttl_remaining,
            expires_at = self.expires_at_sequence,
            current = self.current_sequence,
        )
    }
}

impl TestEnv {
    /// Build a protocol-version fixture for archival behavior: an
    /// environment whose ledger is pinned to `protocol_version`.
    ///
    /// This is the entry point for the archival fixtures named by
    /// [`ARCHIVAL_PROTOCOL_SOROBAN_LAUNCH`],
    /// [`ARCHIVAL_PROTOCOL_CONTRACT_LIFECYCLE`] and
    /// [`ARCHIVAL_PROTOCOL_STATE_ARCHIVAL`]. The archival parameters the
    /// environment enforces can be inspected with
    /// [`TestEnv::archival_parameters`]; the archival laws — expired
    /// persistent entries are restored on their next read, expired
    /// temporary entries are gone — can be exercised with
    /// [`TestEnv::assert_runs_after_expiry`] and
    /// [`TestEnv::assert_recovers_after_expiry`].
    ///
    /// The version is pinned with the SDK's `testutils::Ledger` override.
    /// It can therefore select any protocol the environment's Soroban host
    /// understands, including era markers older than the host's own
    /// interface version — the host simulates the same archival rules at
    /// every protocol it knows, which is what makes a launch-era fixture
    /// meaningful on a state-archival-era host.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::ARCHIVAL_PROTOCOL_SOROBAN_LAUNCH;
    /// use soroban_sdk::testutils::Ledger as _;
    ///
    /// let env = TestEnv::with_protocol_version(ARCHIVAL_PROTOCOL_SOROBAN_LAUNCH);
    /// assert_eq!(
    ///     env.env().ledger().get().protocol_version,
    ///     ARCHIVAL_PROTOCOL_SOROBAN_LAUNCH
    /// );
    /// ```
    pub fn with_protocol_version(protocol_version: u32) -> Self {
        let env = Self::new();
        env.env().ledger().set_protocol_version(protocol_version);
        env
    }

    /// Snapshot the archival-relevant ledger parameters of this environment.
    ///
    /// Values are read from the environment's live ledger info (never
    /// hardcoded); see [`ArchivalParameters`].
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let params = env.archival_parameters();
    /// assert_eq!(params.sequence_number, env.sequence());
    /// ```
    pub fn archival_parameters(&self) -> ArchivalParameters {
        let info = self.env().ledger().get();
        ArchivalParameters {
            protocol_version: info.protocol_version,
            sequence_number: info.sequence_number,
            min_persistent_entry_ttl: info.min_persistent_entry_ttl,
            min_temp_entry_ttl: info.min_temp_entry_ttl,
            max_entry_ttl: info.max_entry_ttl,
        }
    }

    /// Report where the entry at `contract`/`kind`/`key` sits in its TTL
    /// lifetime, at this ledger.
    ///
    /// Unlike [`TestEnv::ttl_of`], the snapshot carries the boundary ledger
    /// at which the entry expires, so it doubles as a non-panicking way to
    /// know when an entry has crossed into the archived/deleted state — see
    /// [`TtlTimeline::expired_at`].
    ///
    /// # Panics
    ///
    /// Panics if the entry does not exist, or has already expired — that is
    /// the point from which [`TestEnv::assert_runs_after_expiry`] and
    /// [`TestEnv::assert_recovers_after_expiry`] take over.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    /// use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
    ///
    /// #[contract]
    /// struct Store;
    ///
    /// #[contractimpl]
    /// impl Store {
    ///     pub fn set(env: Env, key: Symbol, value: i128) {
    ///         env.storage().persistent().set(&key, &value);
    ///     }
    /// }
    ///
    /// # fn main() {
    /// let env = TestEnv::new();
    /// let id = env.env().register(Store, ());
    /// StoreClient::new(env.env(), &id).set(&symbol_short!("k"), &1);
    ///
    /// let timeline =
    ///     env.ttl_timeline(&id, StorageKind::Persistent, symbol_short!("k"));
    /// assert!(timeline.ttl_remaining > 0);
    /// assert!(timeline.expires_at_sequence >= timeline.current_sequence);
    /// # }
    /// ```
    pub fn ttl_timeline<K: IntoVal<Env, Val>>(
        &self,
        contract: &Address,
        kind: StorageKind,
        key: K,
    ) -> TtlTimeline {
        let key_val = key.into_val(self.env());
        let ttl = self.ttl_of_val(contract, kind, &key_val);
        let sequence = self.env().ledger().get().sequence_number;
        TtlTimeline {
            kind,
            current_sequence: sequence,
            expires_at_sequence: sequence.saturating_add(ttl),
            ttl_remaining: ttl,
        }
    }
}

impl TestEnv {
    /// The current TTL of a storage entry, in ledgers.
    ///
    /// Ignores `key` for [`StorageKind::Instance`], which has one TTL per
    /// contract rather than one per key.
    ///
    /// # Panics
    ///
    /// Panics if the entry does not exist, or — for
    /// [`StorageKind::Persistent`] and [`StorageKind::Temporary`] — has
    /// already expired. This matches `soroban_sdk::testutils`' own
    /// `get_ttl` methods, which this is built on.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    /// use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
    ///
    /// #[contract]
    /// struct Store;
    ///
    /// #[contractimpl]
    /// impl Store {
    ///     pub fn set(env: Env, key: Symbol, value: i128) {
    ///         env.storage().persistent().set(&key, &value);
    ///     }
    /// }
    ///
    /// # fn main() {
    /// let env = TestEnv::new();
    /// let id = env.env().register(Store, ());
    /// StoreClient::new(env.env(), &id).set(&symbol_short!("k"), &1);
    ///
    /// let ttl = env.ttl_of(&id, StorageKind::Persistent, symbol_short!("k"));
    /// assert!(ttl > 0);
    /// # }
    /// ```
    pub fn ttl_of<K: IntoVal<Env, Val>>(
        &self,
        contract: &Address,
        kind: StorageKind,
        key: K,
    ) -> u32 {
        let key_val = key.into_val(self.env());
        self.ttl_of_val(contract, kind, &key_val)
    }

    /// Advance the ledger far enough that every entry — regardless of
    /// `kind` — expires.
    ///
    /// `kind` is accepted for symmetry with the rest of this module and to
    /// document intent at the call site, but does not change the amount
    /// advanced: from outside a contract, there is no way to know how much
    /// TTL headroom a specific entry has without calling
    /// [`TestEnv::ttl_of`] on it individually, and an entry of any kind
    /// may have been extended up to the network's `max_entry_ttl`. So this
    /// reads `max_entry_ttl` from the environment's current ledger info at
    /// runtime (never hardcoded — see [`crate::ledger::LEDGER_CLOSE_TIME_SECS`] for the
    /// same reasoning applied to ledger close time) and advances one
    /// ledger past it, which guarantees expiry for every kind at once.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    ///
    /// let env = TestEnv::new();
    /// env.expire(StorageKind::Persistent);
    /// ```
    pub fn expire(&self, kind: StorageKind) {
        let _ = kind;
        let max_entry_ttl = self.env().ledger().get().max_entry_ttl;
        self.advance_ledgers(max_entry_ttl.saturating_add(1));
    }

    /// Assert that running `f` extends the TTL of the entry at `contract`/
    /// `kind`/`key` beyond what it was before `f` ran.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] showing the before
    /// and after TTLs if `f` did not increase it.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    /// use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
    ///
    /// #[contract]
    /// struct Store;
    ///
    /// #[contractimpl]
    /// impl Store {
    ///     pub fn set(env: Env, key: Symbol, value: i128) {
    ///         env.storage().persistent().set(&key, &value);
    ///     }
    ///     pub fn touch(env: Env, key: Symbol) {
    ///         env.storage().persistent().extend_ttl(&key, 5_000, 10_000);
    ///     }
    /// }
    ///
    /// # fn main() {
    /// let env = TestEnv::new();
    /// let id = env.env().register(Store, ());
    /// let client = StoreClient::new(env.env(), &id);
    /// client.set(&symbol_short!("k"), &1);
    ///
    /// env.assert_bumps_ttl(&id, StorageKind::Persistent, symbol_short!("k"), || {
    ///     client.touch(&symbol_short!("k"));
    /// });
    /// # }
    /// ```
    pub fn assert_bumps_ttl<K: IntoVal<Env, Val>>(
        &self,
        contract: &Address,
        kind: StorageKind,
        key: K,
        f: impl FnOnce(),
    ) {
        let key_val = key.into_val(self.env());
        let before = self.ttl_of_val(contract, kind, &key_val);
        f();
        let after = self.ttl_of_val(contract, kind, &key_val);
        if after <= before {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the call to extend the {kind:?} TTL beyond {before}, but it was {after} afterward"
                ))
            );
        }
    }

    /// Assert that running `f` extends the TTL of **every** entry listed in
    /// `keys` — a bulk version of [`assert_bumps_ttl`](Self::assert_bumps_ttl).
    ///
    /// Takes a slice of `(key, label)` tuples so the failure message can name
    /// which key(s) did not bump.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] listing every key
    /// whose TTL was not extended.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    /// use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
    ///
    /// #[contract]
    /// struct Store;
    ///
    /// #[contractimpl]
    /// impl Store {
    ///     pub fn touch_both(env: Env) {
    ///         env.storage().persistent().extend_ttl(&symbol_short!("a"), 5_000, 10_000);
    ///         env.storage().persistent().extend_ttl(&symbol_short!("b"), 5_000, 10_000);
    ///     }
    /// }
    ///
    /// # fn main() {
    /// let env = TestEnv::new();
    /// let id = env.env().register(Store, ());
    /// let a = symbol_short!("a");
    /// let b = symbol_short!("b");
    ///
    /// env.assert_bumps_ttl_multi(&id, StorageKind::Persistent, &[
    ///     (a, "key_a"),
    ///     (b, "key_b"),
    /// ], || {
    ///     StoreClient::new(env.env(), &id).touch_both();
    /// });
    /// # }
    /// ```
    pub fn assert_bumps_ttl_multi<K: IntoVal<Env, Val>>(
        &self,
        contract: &Address,
        kind: StorageKind,
        keys: &[(K, &str)],
        f: impl FnOnce(),
    ) {
        let befores: Vec<(Val, u32, &str)> = keys
            .iter()
            .map(|(k, label)| {
                let key_val = k.into_val(self.env());
                let ttl = self.ttl_of_val(contract, kind, &key_val);
                (key_val, ttl, *label)
            })
            .collect();

        f();

        let mut failures = Vec::new();
        for (key_val, before, label) in &befores {
            let after = self.ttl_of_val(contract, kind, key_val);
            if after <= *before {
                failures.push(format!("{label}: expected > {before}, got {after}"));
            }
        }

        if !failures.is_empty() {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the call to extend the {kind:?} TTL for all keys, but some did not:\n  {}",
                    failures.join("\n  ")
                ))
            );
        }
    }

    /// Assert that `f` completes without panicking after every entry of
    /// `kind` has expired (via [`TestEnv::expire`]) — i.e. that the
    /// contract handles an expired/missing entry gracefully instead of
    /// trapping on it.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] naming the
    /// underlying panic if `f` panics.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    ///
    /// let env = TestEnv::new();
    /// env.assert_survives_expiry(StorageKind::Temporary, || {
    ///     // A closure that never touches the expired entry trivially survives.
    /// });
    /// ```
    pub fn assert_survives_expiry(&self, kind: StorageKind, f: impl FnOnce()) {
        self.expire(kind);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        if let Err(payload) = result {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the contract to survive {kind:?} storage expiry gracefully, \
                     but it panicked: {}",
                    panic_message(&payload)
                ))
            );
        }
    }

    /// Assert that running `f` does **not** extend the TTL of the entry at
    /// `contract`/`kind`/`key` — the inverse of [`assert_bumps_ttl`](Self::assert_bumps_ttl).
    ///
    /// Useful for verifying that a read-only function does not accidentally
    /// write or touch storage it should not.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] showing the before
    /// and after TTLs if `f` *did* increase the TTL.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    /// use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
    ///
    /// #[contract]
    /// struct Store;
    ///
    /// #[contractimpl]
    /// impl Store {
    ///     pub fn set(env: Env, key: Symbol, value: i128) {
    ///         env.storage().persistent().set(&key, &value);
    ///     }
    ///     pub fn read_only(env: Env, key: Symbol) -> i128 {
    ///         env.storage().persistent().get(&key).unwrap_or(0)
    ///     }
    /// }
    ///
    /// # fn main() {
    /// let env = TestEnv::new();
    /// let id = env.env().register(Store, ());
    /// let client = StoreClient::new(env.env(), &id);
    /// client.set(&symbol_short!("k"), &42);
    ///
    /// env.assert_no_ttl_bump(&id, StorageKind::Persistent, symbol_short!("k"), || {
    ///     let _ = client.read_only(&symbol_short!("k"));
    /// });
    /// # }
    /// ```
    pub fn assert_no_ttl_bump<K: IntoVal<Env, Val>>(
        &self,
        contract: &Address,
        kind: StorageKind,
        key: K,
        f: impl FnOnce(),
    ) {
        let key_val = key.into_val(self.env());
        let before = self.ttl_of_val(contract, kind, &key_val);
        f();
        let after = self.ttl_of_val(contract, kind, &key_val);
        if after > before {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the call to NOT extend the {kind:?} TTL, but it went from {before} to {after}"
                ))
            );
        }
    }

    /// Advance the ledger to **one ledger before** the entry at `contract`/
    /// `kind`/`key` expires, then run `f`.
    ///
    /// This lets you test that a contract correctly handles the last moment
    /// before expiry — e.g. that it can still read the entry and extend it
    /// in time, or that it gracefully degrades.
    ///
    /// # Panics
    ///
    /// Panics if the entry does not exist, has already expired, or if `f`
    /// panics (in which case the panic message is forwarded).
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    /// use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
    ///
    /// #[contract]
    /// struct Store;
    ///
    /// #[contractimpl]
    /// impl Store {
    ///     pub fn set(env: Env, key: Symbol, value: i128) {
    ///         env.storage().persistent().set(&key, &value);
    ///     }
    ///     pub fn touch(env: Env, key: Symbol) {
    ///         env.storage().persistent().extend_ttl(&key, 5_000, 10_000);
    ///     }
    /// }
    ///
    /// # fn main() {
    /// let env = TestEnv::new();
    /// let id = env.env().register(Store, ());
    /// let client = StoreClient::new(env.env(), &id);
    /// client.set(&symbol_short!("k"), &1);
    ///
    /// env.assert_runs_before_expiry(&id, StorageKind::Persistent, symbol_short!("k"), || {
    ///     client.touch(&symbol_short!("k"));
    /// });
    /// # }
    /// ```
    pub fn assert_runs_before_expiry<K: IntoVal<Env, Val>>(
        &self,
        contract: &Address,
        kind: StorageKind,
        key: K,
        f: impl FnOnce(),
    ) {
        let key_val = key.into_val(self.env());
        let ttl = self.ttl_of_val(contract, kind, &key_val);
        if ttl == 0 {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "cannot run before expiry: {kind:?} entry has already expired (TTL is 0)"
                ))
            );
        }
        // Advance to one ledger before expiry.
        self.advance_ledgers(ttl.saturating_sub(1));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        if let Err(payload) = result {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "closure panicked when run just before {kind:?} expiry: {}",
                    panic_message(&payload)
                ))
            );
        }
    }

    /// Advance the ledger to exactly **one ledger after** the entry at
    /// `contract`/`kind`/`key` expires, then run `f` — scoped execution
    /// just after expiry.
    ///
    /// This is the mirror image of [`assert_runs_before_expiry`](Self::assert_runs_before_expiry)
    /// and the per-entry counterpart of [`TestEnv::expire`]: only the
    /// single named entry is pushed past its boundary (via the minimum
    /// advance), so sibling entries and other contracts stay at their
    /// current position in ledger time. What the contract sees on the other
    /// side depends on `kind`:
    ///
    /// - [`StorageKind::Temporary`]: the entry is deleted. Reading it yields
    ///   `None`, so a contract that `.unwrap()`s it panics — and a contract
    ///   that treats it as absent (`unwrap_or(default)`) survives.
    /// - [`StorageKind::Persistent`] / [`StorageKind::Instance`]: the entry
    ///   is archived, not lost. The next read brings the archived value back
    ///   and renews its TTL, so a contract can recover it.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] naming the underlying
    /// panic if `f` panics. Also panics (via the underlying SDK) if the
    /// entry does not exist or has already expired — a timeline snapshot
    /// from [`TestEnv::ttl_timeline`] must be taken while the entry is live.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::ttl::StorageKind;
    /// use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
    ///
    /// #[contract]
    /// struct Store;
    ///
    /// #[contractimpl]
    /// impl Store {
    ///     pub fn set(env: Env, key: Symbol, value: i128) {
    ///         env.storage().persistent().set(&key, &value);
    ///     }
    ///     pub fn read(env: Env, key: Symbol) -> i128 {
    ///         env.storage().persistent().get(&key).unwrap_or(0)
    ///     }
    /// }
    ///
    /// # fn main() {
    /// let env = TestEnv::new();
    /// let id = env.env().register(Store, ());
    /// let client = StoreClient::new(env.env(), &id);
    /// client.set(&symbol_short!("k"), &42);
    ///
    /// // Persistent data is archived, not lost: the value comes back on the
    /// // first read after expiry.
    /// env.assert_runs_after_expiry(&id, StorageKind::Persistent, symbol_short!("k"), || {
    ///     assert_eq!(client.read(&symbol_short!("k")), 42);
    /// });
    /// # }
    /// ```
    pub fn assert_runs_after_expiry<K: IntoVal<Env, Val>>(
        &self,
        contract: &Address,
        kind: StorageKind,
        key: K,
        f: impl FnOnce(),
    ) {
        let key_val = key.into_val(self.env());
        let ttl = self.ttl_of_val(contract, kind, &key_val);
        // Advance to exactly one ledger after expiry.
        self.advance_ledgers(ttl.saturating_add(1));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        if let Err(payload) = result {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "closure panicked when run just after {kind:?} expiry: {}",
                    panic_message(&payload)
                ))
            );
        }
    }

    /// The persistent-storage recovery recipe: drive a persistent entry
    /// through its expiry boundary, then verify that reading it back
    /// recovers the archived value and brings the entry back to life.
    ///
    /// The recipe runs in four steps, each checked:
    ///
    /// 1. The entry's [`TtlTimeline`] is captured while the entry is live.
    /// 2. The ledger is advanced to exactly one ledger after that expiry —
    ///    the window in which the entry has crossed into the archive.
    /// 3. `f` runs and returns what the contract observed; it is compared
    ///    against `expected`. A contract that reads its key back observes
    ///    the original value (the host restores it from the archive); a
    ///    contract that treats the expired entry as gone does not.
    /// 4. The entry is checked to be live again (`ttl_of` reports a
    ///    positive TTL), proving it was restored rather than left dead.
    ///
    /// Because step 3 is what triggers the restore, `f` must perform (or
    /// include) a read of the persisted entry. Reading a persistent entry
    /// after expiry is the recovery operation; see
    /// [`assert_runs_after_expiry`](Self::assert_runs_after_expiry) for the
    /// per-kind behavior on the other side of the boundary.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] naming the stage that
    /// failed: the recovered value not matching `expected`, or the entry not
    /// being live afterward. Also panics (via the underlying SDK) if the
    /// entry does not exist or has already expired before the recipe runs.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
    ///
    /// #[contract]
    /// struct Store;
    ///
    /// #[contractimpl]
    /// impl Store {
    ///     pub fn set(env: Env, key: Symbol, value: i128) {
    ///         env.storage().persistent().set(&key, &value);
    ///     }
    ///     pub fn read(env: Env, key: Symbol) -> i128 {
    ///         env.storage().persistent().get(&key).unwrap_or(0)
    ///     }
    /// }
    ///
    /// # fn main() {
    /// let env = TestEnv::new();
    /// let id = env.env().register(Store, ());
    /// let client = StoreClient::new(env.env(), &id);
    /// client.set(&symbol_short!("k"), &7);
    ///
    /// env.assert_recovers_after_expiry(&id, symbol_short!("k"), || {
    ///     client.read(&symbol_short!("k"))
    /// }, 7);
    /// # }
    /// ```
    pub fn assert_recovers_after_expiry<K, V>(
        &self,
        contract: &Address,
        key: K,
        f: impl FnOnce() -> V,
        expected: V,
    ) where
        K: IntoVal<Env, Val>,
        V: PartialEq + fmt::Debug,
    {
        let kind = StorageKind::Persistent;
        let key_val = key.into_val(self.env());
        let timeline = self.ttl_timeline(contract, kind, &key_val);

        // Cross the expiry boundary scoped to this single entry.
        self.advance_ledgers(timeline.ttl_remaining.saturating_add(1));

        if !timeline.expired_at(self.sequence()) {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "recovery recipe invariant check failed: the {kind:?} entry should have \
                     expired at ledger {} but the ledger is at {}",
                    timeline.expires_at_sequence,
                    self.sequence()
                ))
            );
        }

        let recovered = f();
        if recovered != expected {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the persistent entry to recover to {expected:?} after expiry, \
                     but recovering it produced {recovered:?} (the entry was archived with the \
                     ledger at {}, past its expiry at {})",
                    self.sequence(),
                    timeline.expires_at_sequence
                ))
            );
        }

        // The restore must have brought the entry back to life: a live TTL
        // is only reported once the entry is back on the ledger.
        let renewed = self.ttl_of_val(contract, kind, &key_val);
        if renewed == 0 {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "the persistent entry was not live again after recovery \
                     (TTL is 0 at ledger {})",
                    self.sequence()
                ))
            );
        }
    }

    fn ttl_of_val(&self, contract: &Address, kind: StorageKind, key_val: &Val) -> u32 {
        self.env().as_contract(contract, || match kind {
            StorageKind::Temporary => self.env().storage().temporary().get_ttl(key_val),
            StorageKind::Persistent => self.env().storage().persistent().get_ttl(key_val),
            StorageKind::Instance => self.env().storage().instance().get_ttl(),
        })
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault::{DataKey, Vault, VaultClient};

    #[test]
    fn ttl_of_decreases_as_ledgers_advance() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        let before = env.ttl_of(&id, StorageKind::Persistent, DataKey::Record);
        env.advance_ledgers(10);
        let after = env.ttl_of(&id, StorageKind::Persistent, DataKey::Record);

        assert!(after < before, "expected {after} < {before}");
        assert_eq!(before - after, 10);
    }

    #[test]
    #[should_panic(expected = "expected the call to extend the Persistent TTL")]
    fn assert_bumps_ttl_fails_on_a_contract_that_reads_without_bumping() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        env.assert_bumps_ttl(&id, StorageKind::Persistent, DataKey::Record, || {
            client.touch_record();
        });
    }

    #[test]
    fn assert_bumps_ttl_passes_on_the_fixed_contract() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        env.assert_bumps_ttl(&id, StorageKind::Persistent, DataKey::Record, || {
            client.touch_record_checked();
        });
    }

    #[test]
    #[should_panic(expected = "expected the contract to survive")]
    fn assert_survives_expiry_fails_on_a_contract_that_panics_on_missing_entry() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_temp(&42);

        env.assert_survives_expiry(StorageKind::Temporary, || {
            client.read_temp_unchecked();
        });
    }

    #[test]
    fn assert_survives_expiry_passes_on_the_fixed_contract() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_temp(&42);

        env.assert_survives_expiry(StorageKind::Temporary, || {
            assert_eq!(client.read_temp_checked(), 0);
        });
    }

    #[test]
    fn assert_bumps_ttl_multi_passes_when_all_keys_bump() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        // touch_record_checked bumps Persistent TTL for DataKey::Record.
        // Use the same key twice to exercise the multi-key path.
        env.assert_bumps_ttl_multi(
            &id,
            StorageKind::Persistent,
            &[(DataKey::Record, "record_1"), (DataKey::Record, "record_2")],
            || {
                client.touch_record_checked();
            },
        );
    }

    #[test]
    #[should_panic(expected = "expected the call to extend the Persistent TTL for all keys")]
    fn assert_bumps_ttl_multi_fails_when_key_does_not_bump() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        env.assert_bumps_ttl_multi(
            &id,
            StorageKind::Persistent,
            &[(DataKey::Record, "record")],
            || {
                client.touch_record(); // reads without bumping
            },
        );
    }

    #[test]
    fn assert_no_ttl_bump_passes_on_read_only() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        env.assert_no_ttl_bump(&id, StorageKind::Persistent, DataKey::Record, || {
            client.touch_record(); // reads without bumping
        });
    }

    #[test]
    #[should_panic(expected = "expected the call to NOT extend the Persistent TTL")]
    fn assert_no_ttl_bump_fails_when_ttl_is_extended() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        env.assert_no_ttl_bump(&id, StorageKind::Persistent, DataKey::Record, || {
            client.touch_record_checked(); // bumps TTL
        });
    }

    #[test]
    fn assert_runs_before_expiry_runs_closure() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        env.assert_runs_before_expiry(&id, StorageKind::Persistent, DataKey::Record, || {
            client.touch_record_checked();
        });
    }

    #[test]
    #[should_panic(expected = "closure panicked when run just before")]
    fn assert_runs_before_expiry_forwards_closure_panic() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        env.assert_runs_before_expiry(&id, StorageKind::Persistent, DataKey::Record, || {
            panic!("intentional test panic");
        });
    }

    #[test]
    fn assert_runs_after_expiry_passes_when_persistent_data_is_read_back() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&42);

        env.assert_runs_after_expiry(&id, StorageKind::Persistent, DataKey::Record, || {
            assert_eq!(client.touch_record_checked(), 42);
        });
    }

    #[test]
    fn assert_runs_after_expiry_passes_when_temp_entry_is_gone() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_temp(&42);

        env.assert_runs_after_expiry(&id, StorageKind::Temporary, DataKey::Temp, || {
            assert_eq!(client.read_temp_checked(), 0);
        });
    }

    #[test]
    #[should_panic(expected = "closure panicked when run just after")]
    fn assert_runs_after_expiry_forwards_closure_panic() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_temp(&42);

        env.assert_runs_after_expiry(&id, StorageKind::Temporary, DataKey::Temp, || {
            client.read_temp_unchecked();
        });
    }

    #[test]
    fn ttl_timeline_decreases_as_ledgers_advance() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        let before = env.ttl_timeline(&id, StorageKind::Persistent, DataKey::Record);
        env.advance_ledgers(10);
        let after = env.ttl_timeline(&id, StorageKind::Persistent, DataKey::Record);

        assert_eq!(after.ttl_remaining, before.ttl_remaining - 10);
        assert_eq!(after.expires_at_sequence, before.expires_at_sequence);
        assert_eq!(after.current_sequence, before.current_sequence + 10);
    }

    #[test]
    fn ttl_timeline_flags_an_entry_expiring_on_the_next_ledger() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        let ttl = env.ttl_of(&id, StorageKind::Persistent, DataKey::Record);
        env.advance_ledgers(ttl.saturating_sub(1));

        let timeline = env.ttl_timeline(&id, StorageKind::Persistent, DataKey::Record);
        assert_eq!(timeline.ttl_remaining, 1);
        assert!(timeline.expires_next_ledger());
        assert!(!timeline.expired());
    }

    #[test]
    fn ttl_timeline_knows_when_the_entry_has_expired() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        let timeline = env.ttl_timeline(&id, StorageKind::Persistent, DataKey::Record);
        assert!(!timeline.expired());

        env.advance_ledgers(timeline.ttl_remaining.saturating_add(1));

        assert!(timeline.expired_at(env.sequence()));
        assert!(timeline.expired_at(timeline.expires_at_sequence));
    }

    #[test]
    fn ttl_timeline_display_reports_the_expiry_ledger() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        let timeline = env.ttl_timeline(&id, StorageKind::Persistent, DataKey::Record);
        let report = timeline.to_string();

        assert!(report.contains("expiring at ledger"), "{report}");
        assert!(
            report.contains(&timeline.expires_at_sequence.to_string()),
            "{report}"
        );
        assert!(report.contains("snapshot at ledger"), "{report}");
    }

    #[test]
    fn assert_recovers_after_expiry_passes_when_the_archived_value_comes_back() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&42);

        env.assert_recovers_after_expiry(
            &id,
            DataKey::Record,
            || client.touch_record_checked(),
            42,
        );
    }

    #[test]
    fn assert_recovers_after_expiry_renews_the_ttl() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&1);

        env.assert_recovers_after_expiry(&id, DataKey::Record, || client.touch_record_checked(), 1);

        let renewed = env.ttl_of(&id, StorageKind::Persistent, DataKey::Record);
        assert!(
            renewed > 0,
            "expected the entry to be live after recovery, got TTL {renewed}"
        );
    }

    #[test]
    #[should_panic(expected = "expected the persistent entry to recover to 42")]
    fn assert_recovers_after_expiry_fails_when_the_value_does_not_come_back() {
        let env = TestEnv::new();
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&42);

        // A contract that does not read its key back after expiry reports
        // nothing rather than the archived value; the recipe must reject it.
        env.assert_recovers_after_expiry(&id, DataKey::Record, || 0i128, 42);
    }

    #[test]
    fn protocol_fixture_pins_the_requested_protocol_version() {
        let env = TestEnv::with_protocol_version(ARCHIVAL_PROTOCOL_STATE_ARCHIVAL);

        assert_eq!(
            env.env().ledger().get().protocol_version,
            ARCHIVAL_PROTOCOL_STATE_ARCHIVAL
        );
        assert_eq!(
            env.archival_parameters().protocol_version,
            ARCHIVAL_PROTOCOL_STATE_ARCHIVAL
        );
    }

    #[test]
    fn protocol_fixture_only_changes_the_protocol_version() {
        let baseline = TestEnv::new().archival_parameters();
        let env = TestEnv::with_protocol_version(ARCHIVAL_PROTOCOL_SOROBAN_LAUNCH);
        let pinned = env.archival_parameters();

        // The fixture is a pure protocol pin: every archival-relevant
        // parameter other than the protocol version is untouched.
        assert_eq!(pinned.protocol_version, ARCHIVAL_PROTOCOL_SOROBAN_LAUNCH);
        assert_eq!(
            pinned.min_persistent_entry_ttl,
            baseline.min_persistent_entry_ttl
        );
        assert_eq!(pinned.min_temp_entry_ttl, baseline.min_temp_entry_ttl);
        assert_eq!(pinned.max_entry_ttl, baseline.max_entry_ttl);
        assert_eq!(pinned.sequence_number, baseline.sequence_number);
    }

    #[test]
    fn archival_parameters_match_the_runtime_ledger_info() {
        use soroban_sdk::testutils::Ledger as _;

        let env = TestEnv::new();
        let info = env.env().ledger().get();
        let params = env.archival_parameters();

        assert_eq!(params.protocol_version, info.protocol_version);
        assert_eq!(params.sequence_number, info.sequence_number);
        assert_eq!(
            params.min_persistent_entry_ttl,
            info.min_persistent_entry_ttl
        );
        assert_eq!(params.min_temp_entry_ttl, info.min_temp_entry_ttl);
        assert_eq!(params.max_entry_ttl, info.max_entry_ttl);
    }

    #[test]
    fn archival_laws_hold_at_the_soroban_launch_protocol() {
        let env = TestEnv::with_protocol_version(ARCHIVAL_PROTOCOL_SOROBAN_LAUNCH);
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&7);
        client.set_temp(&7);

        // Temporary data is deleted, not archived (checked first: its TTL is
        // short, and the persistent run below advances far beyond it).
        env.assert_runs_after_expiry(&id, StorageKind::Temporary, DataKey::Temp, || {
            assert_eq!(client.read_temp_checked(), 0);
        });

        // Persistent data lives in the archive and is recovered on read.
        env.assert_runs_after_expiry(&id, StorageKind::Persistent, DataKey::Record, || {
            assert_eq!(client.touch_record_checked(), 7);
        });
    }

    #[test]
    fn archival_laws_hold_at_the_state_archival_protocol() {
        let env = TestEnv::with_protocol_version(ARCHIVAL_PROTOCOL_STATE_ARCHIVAL);
        let id = env.env().register(Vault, ());
        let client = VaultClient::new(env.env(), &id);
        client.set_record(&9);
        client.set_temp(&9);

        // Temporary data is gone after expiry (checked first: its TTL is
        // short, and the persistent recipe below advances far beyond it).
        env.assert_runs_after_expiry(&id, StorageKind::Temporary, DataKey::Temp, || {
            assert_eq!(client.read_temp_checked(), 0);
        });

        env.assert_recovers_after_expiry(&id, DataKey::Record, || client.touch_record_checked(), 9);
    }
}
