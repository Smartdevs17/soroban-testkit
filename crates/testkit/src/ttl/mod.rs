//! Ledger-entry TTL inspection and expiry simulation.
//!
//! Contracts that fail to bump TTL break in production through silent data
//! loss, and the failure mode is close to untestable by hand — this module
//! makes it a normal assertion.
//!
//! Beyond the raw [`StorageKind`] and [`TestEnv::ttl_of`] primitives this
//! module ships the tools a production contract actually needs: scoped
//! execution on either side of the expiry boundary
//! ([`TestEnv::assert_runs_before_expiry`] / [`TestEnv::assert_runs_after_expiry`]),
//! a full [`TtlTimeline`] report per entry, persistent-storage recovery
//! recipes ([`TestEnv::assert_recovers_after_expiry`]), and protocol-version
//! fixtures for archival behavior ([`TestEnv::with_protocol_version`] and
//! [`ArchivalParameters`]).

mod expiry;

pub use expiry::{
    ArchivalParameters, StorageKind, TtlTimeline, ARCHIVAL_PROTOCOL_CONTRACT_LIFECYCLE,
    ARCHIVAL_PROTOCOL_SOROBAN_LAUNCH, ARCHIVAL_PROTOCOL_STATE_ARCHIVAL,
};
