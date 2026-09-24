use std::any::Any;

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
}
