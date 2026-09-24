use std::error::Error;
use std::fmt;

/// Errors raised by testkit assertion helpers and setup routines.
///
/// Assertion helpers throughout this crate panic deliberately when a
/// contract under test misbehaves — that panic is their contract with the
/// caller — but they always panic with a `TestkitError` as context rather
/// than a bare string, so the failure carries a stable, matchable message.
///
/// # Example
///
/// ```
/// use soroban_testkit::core::TestkitError;
///
/// let err = TestkitError::Misuse("events were never captured".into());
/// assert_eq!(
///     err.to_string(),
///     "misuse of testkit API: events were never captured"
/// );
/// ```
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
pub enum TestkitError {
    /// An assertion helper's expectation about contract state or behavior
    /// was not met (for example, an expected event was never emitted, or a
    /// conservation invariant did not hold).
    #[error("assertion failed: {0}")]
    AssertionFailed(String),

    /// A captured value could not be decoded into the requested type.
    #[error("failed to decode value: {0}")]
    DecodeFailed(String),

    /// The testkit API was used in a way its contract does not allow (for
    /// example, asserting on events before capture was enabled, warping
    /// the ledger clock backwards, or providing an invalid address label).
    #[error("misuse of testkit API: {0}")]
    Misuse(String),

    /// Adds high-level context while preserving the nested [`TestkitError`]
    /// as the standard error source.
    ///
    /// This is useful when a helper needs to explain *which operation* failed
    /// without flattening the original error into a string and losing its
    /// source chain.
    #[error("{context}: {source}")]
    Context {
        /// Human-readable operation context.
        context: String,
        /// The underlying testkit error.
        #[source]
        source: Box<TestkitError>,
    },
}

impl TestkitError {
    /// Create a [`TestkitError::AssertionFailed`] with the given message.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let err = TestkitError::assertion_failed("balances do not match");
    /// assert_eq!(err.code(), "TESTKIT_ASSERTION_FAILED");
    /// ```
    pub fn assertion_failed(msg: impl Into<String>) -> Self {
        Self::AssertionFailed(msg.into())
    }

    /// Create a [`TestkitError::DecodeFailed`] with the given message.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let err = TestkitError::decode_failed("failed to parse event data");
    /// assert_eq!(err.code(), "TESTKIT_DECODE_FAILED");
    /// ```
    pub fn decode_failed(msg: impl Into<String>) -> Self {
        Self::DecodeFailed(msg.into())
    }

    /// Create a [`TestkitError::Misuse`] with the given message.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let err = TestkitError::misuse("invalid sequence number");
    /// assert_eq!(err.code(), "TESTKIT_MISUSE");
    /// ```
    pub fn misuse(msg: impl Into<String>) -> Self {
        Self::Misuse(msg.into())
    }

    /// Returns `true` if this error is an [`AssertionFailed`](TestkitError::AssertionFailed).
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let err = TestkitError::assertion_failed("test");
    /// assert!(err.is_assertion_failed());
    /// assert!(!err.is_misuse());
    /// ```
    pub fn is_assertion_failed(&self) -> bool {
        match self {
            Self::Context { source, .. } => source.is_assertion_failed(),
            other => matches!(other, Self::AssertionFailed(_)),
        }
    }

    /// Returns `true` if this error is a [`DecodeFailed`](TestkitError::DecodeFailed).
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let err = TestkitError::decode_failed("test");
    /// assert!(err.is_decode_failed());
    /// assert!(!err.is_misuse());
    /// ```
    pub fn is_decode_failed(&self) -> bool {
        match self {
            Self::Context { source, .. } => source.is_decode_failed(),
            other => matches!(other, Self::DecodeFailed(_)),
        }
    }

    /// Returns `true` if this error is a [`Misuse`](TestkitError::Misuse).
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let err = TestkitError::misuse("test");
    /// assert!(err.is_misuse());
    /// assert!(!err.is_assertion_failed());
    /// ```
    pub fn is_misuse(&self) -> bool {
        match self {
            Self::Context { source, .. } => source.is_misuse(),
            other => matches!(other, Self::Misuse(_)),
        }
    }

    /// The human-readable inner message for this error.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let err = TestkitError::misuse("cannot warp backward");
    /// assert_eq!(err.message(), "cannot warp backward");
    /// ```
    pub fn message(&self) -> &str {
        match self {
            TestkitError::AssertionFailed(m)
            | TestkitError::DecodeFailed(m)
            | TestkitError::Misuse(m) => m.as_str(),
            TestkitError::Context { source, .. } => source.message(),
        }
    }

    /// Assert that a condition holds, returning `Ok(())` on success or
    /// `Err(TestkitError::AssertionFailed)` on failure.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// assert!(TestkitError::ensure(true, "must be valid").is_ok());
    /// assert!(TestkitError::ensure(false, "unexpected state").is_err());
    /// ```
    pub fn ensure(condition: bool, msg: impl Into<String>) -> Result<(), Self> {
        if condition {
            Ok(())
        } else {
            Err(Self::AssertionFailed(msg.into()))
        }
    }

    /// Validate a precondition, returning `Ok(())` on success or
    /// `Err(TestkitError::Misuse)` on failure.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// assert!(TestkitError::require(true, "valid param").is_ok());
    /// assert!(TestkitError::require(false, "invalid param").is_err());
    /// ```
    pub fn require(condition: bool, msg: impl Into<String>) -> Result<(), Self> {
        if condition {
            Ok(())
        } else {
            Err(Self::Misuse(msg.into()))
        }
    }

    /// Wrap a decoding operation, returning `Ok(value)` on success or
    /// `Err(TestkitError::DecodeFailed)` with the provided type context on failure.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let ok_res: Result<i128, &str> = Ok(100);
    /// assert_eq!(TestkitError::check_decode(ok_res, "i128").unwrap(), 100);
    ///
    /// let err_res: Result<i128, &str> = Err("overflow");
    /// assert!(TestkitError::check_decode(err_res, "i128").is_err());
    /// ```
    pub fn check_decode<T, E: std::fmt::Display>(
        result: Result<T, E>,
        type_name: &str,
    ) -> Result<T, Self> {
        result.map_err(|e| Self::DecodeFailed(format!("failed to decode {type_name}: {e}")))
    }

    /// A stable, machine-readable code identifying which kind of error this
    /// is, independent of the human-readable message.
    ///
    /// The message text is meant for people and may be reworded; the code is
    /// meant for tooling (log filters, CI annotations, `match` on a
    /// caught panic payload) and is part of this crate's compatibility
    /// promise: an existing variant's code never changes, and a code is
    /// never reused for a different variant. New variants get new codes.
    ///
    /// | Variant | Code |
    /// |---|---|
    /// | [`TestkitError::AssertionFailed`] | `TESTKIT_ASSERTION_FAILED` |
    /// | [`TestkitError::DecodeFailed`] | `TESTKIT_DECODE_FAILED` |
    /// | [`TestkitError::Misuse`] | `TESTKIT_MISUSE` |
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let err = TestkitError::Misuse("events were never captured".into());
    /// assert_eq!(err.code(), "TESTKIT_MISUSE");
    /// ```
    pub fn code(&self) -> &'static str {
        match self {
            TestkitError::AssertionFailed(_) => "TESTKIT_ASSERTION_FAILED",
            TestkitError::DecodeFailed(_) => "TESTKIT_DECODE_FAILED",
            TestkitError::Misuse(_) => "TESTKIT_MISUSE",
            TestkitError::Context { source, .. } => source.code(),
        }
    }

    /// Attach operation context without discarding this error's source chain.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let err = TestkitError::DecodeFailed("expected i128".into())
    ///     .with_context("decoding transfer amount");
    /// assert_eq!(
    ///     err.to_string(),
    ///     "decoding transfer amount: failed to decode value: expected i128"
    /// );
    /// assert_eq!(err.code(), "TESTKIT_DECODE_FAILED");
    /// ```
    pub fn with_context(self, context: impl Into<String>) -> Self {
        Self::Context {
            context: context.into(),
            source: Box::new(self),
        }
    }

    /// The variant name of this error, as a static string.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let err = TestkitError::Misuse("boom".into());
    /// assert_eq!(err.kind(), "Misuse");
    /// ```
    pub fn kind(&self) -> &'static str {
        match self {
            TestkitError::AssertionFailed { .. } => "AssertionFailed",
            TestkitError::DecodeFailed { .. } => "DecodeFailed",
            TestkitError::Misuse { .. } => "Misuse",
            TestkitError::Context { source, .. } => source.kind(),
        }
    }

    /// Returns a deterministic, human-readable string representation of this error
    /// formatted specifically for snapshot testing.
    ///
    /// # User-facing behavior
    ///
    /// The snapshot output combines the machine-readable error code ([`TestkitError::code`])
    /// with the human-readable error message in the format `"[CODE] message"`.
    ///
    /// - **Deterministic**: Contains no non-deterministic memory addresses, thread IDs, or timestamps.
    /// - **Stable across runs**: Output remains identical across test executions and platforms.
    /// - **Readable**: Clearly demarks the error classification code and failure details for snapshot diffs.
    ///
    /// # Format
    ///
    /// | Variant | Snapshot Output |
    /// |---|---|
    /// | [`TestkitError::AssertionFailed`] | `"[TESTKIT_ASSERTION_FAILED] assertion failed: ..."` |
    /// | [`TestkitError::DecodeFailed`] | `"[TESTKIT_DECODE_FAILED] failed to decode value: ..."` |
    /// | [`TestkitError::Misuse`] | `"[TESTKIT_MISUSE] misuse of testkit API: ..."` |
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let err = TestkitError::Misuse("events were never captured".into());
    /// assert_eq!(
    ///     err.to_snapshot(),
    ///     "[TESTKIT_MISUSE] misuse of testkit API: events were never captured"
    /// );
    /// ```
    pub fn to_snapshot(&self) -> String {
        format!("[{}] {}", self.code(), self)
    }

    /// Alias for [`TestkitError::to_snapshot`].
    pub fn render_snapshot(&self) -> String {
        self.to_snapshot()
    }

    /// Alias for [`TestkitError::to_snapshot`].
    pub fn snapshot(&self) -> String {
        self.to_snapshot()
    }

    /// Alias for [`TestkitError::to_snapshot`].
    pub fn snapshot_display(&self) -> String {
        self.to_snapshot()
    }

    /// The underlying causes of this error, nearest first.
    ///
    /// Walks [`Error::source`] outwards from this error and stops at the
    /// first link with no source, so the result is empty for an error that
    /// wraps nothing. The error itself is never included.
    ///
    /// None of [`TestkitError`]'s variants wrap another error today, so this
    /// returns an empty vector for every error that can currently be
    /// constructed. The helper exists so callers can inspect the chain
    /// without caring whether a variant grows a source later.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestkitError;
    ///
    /// let err = TestkitError::DecodeFailed("could not read".into());
    /// assert!(err.chain().is_empty()); // no variant wraps a source today
    /// ```
    pub fn chain(&self) -> Vec<&(dyn Error + 'static)> {
        source_chain(self)
    }
}

/// Walk the [`Error::source`] chain of `err`, nearest cause first.
///
/// The error itself is not included, and the walk stops at the first link
/// with no source, so the result is empty for an error that wraps nothing.
fn source_chain<'a>(err: &'a (dyn Error + 'static)) -> Vec<&'a (dyn Error + 'static)> {
    let mut chain = Vec::new();
    let mut source = err.source();
    while let Some(next) = source {
        chain.push(next);
        source = next.source();
    }
    chain
}

/// `Debug` forwards to `Display` so that `{:?}` and `{}` both produce the
/// same stable, human-readable message. The derived `Debug` would emit the
/// Rust enum-variant form (`AssertionFailed("assertion failed: …")`), which
/// diverges from `Display` and makes snapshot-style assertions fragile.
impl fmt::Debug for TestkitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_failed_message() {
        let err = TestkitError::AssertionFailed("deposited != withdrawn".into());
        assert_eq!(err.to_string(), "assertion failed: deposited != withdrawn");
    }

    #[test]
    fn decode_failed_message() {
        let err = TestkitError::DecodeFailed("expected i128, got Symbol".into());
        assert_eq!(
            err.to_string(),
            "failed to decode value: expected i128, got Symbol"
        );
    }

    #[test]
    fn misuse_message() {
        let err = TestkitError::Misuse("events were never captured".into());
        assert_eq!(
            err.to_string(),
            "misuse of testkit API: events were never captured"
        );
    }

    // The literals below are the public contract: changing one is a
    // breaking change for anyone matching on codes.
    #[test]
    fn each_variant_has_its_documented_code() {
        assert_eq!(
            TestkitError::AssertionFailed("x".into()).code(),
            "TESTKIT_ASSERTION_FAILED"
        );
        assert_eq!(
            TestkitError::DecodeFailed("x".into()).code(),
            "TESTKIT_DECODE_FAILED"
        );
        assert_eq!(TestkitError::Misuse("x".into()).code(), "TESTKIT_MISUSE");
    }

    #[test]
    fn codes_are_unique_across_variants() {
        let codes = [
            TestkitError::AssertionFailed(String::new()).code(),
            TestkitError::DecodeFailed(String::new()).code(),
            TestkitError::Misuse(String::new()).code(),
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j]);
            }
        }
    }

    #[test]
    fn code_does_not_depend_on_the_message() {
        assert_eq!(
            TestkitError::Misuse(String::new()).code(),
            TestkitError::Misuse("a much longer, different message".into()).code()
        );
    }

    #[test]
    fn codes_are_screaming_snake_case() {
        let errors = [
            TestkitError::AssertionFailed(String::new()),
            TestkitError::DecodeFailed(String::new()),
            TestkitError::Misuse(String::new()),
        ];
        for err in &errors {
            let code = err.code();
            assert!(!code.is_empty());
            assert!(
                code.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "code {code:?} is not SCREAMING_SNAKE_CASE"
            );
        }
    }

    #[test]
    fn code_is_not_added_to_the_display_message() {
        let err = TestkitError::Misuse("boom".into());
        assert!(!err.to_string().contains(err.code()));
    }

    #[test]
    fn kind_returns_variant_name() {
        assert_eq!(
            TestkitError::AssertionFailed("x".into()).kind(),
            "AssertionFailed"
        );
        assert_eq!(
            TestkitError::DecodeFailed("x".into()).kind(),
            "DecodeFailed"
        );
        assert_eq!(TestkitError::Misuse("x".into()).kind(), "Misuse");
    }

    // --- source-chain inspection (#46) ----------------------------------

    // A `TestkitError` never wraps another error today, so the chain must be
    // empty — and must not smuggle the error itself in as its own cause.
    #[test]
    fn chain_is_empty_for_every_variant() {
        let errors = [
            TestkitError::AssertionFailed("x".into()),
            TestkitError::DecodeFailed("x".into()),
            TestkitError::Misuse("x".into()),
        ];
        for err in &errors {
            assert!(
                err.chain().is_empty(),
                "{} carried a hidden source",
                err.kind()
            );
        }
    }

    #[test]
    fn chain_does_not_include_the_error_itself() {
        let err = TestkitError::misuse("boom");
        assert!(err
            .chain()
            .iter()
            .all(|source| source.to_string() != err.to_string()));
    }

    // `TestkitError`'s variants are leaves, so the traversal itself is
    // exercised against a real multi-level chain built from local errors.
    #[test]
    fn source_chain_walks_every_link_nearest_first() {
        let chain = source_chain(&Outer(Middle(Leaf)));
        let rendered: Vec<String> = chain.iter().map(|err| err.to_string()).collect();
        assert_eq!(rendered, ["middle", "leaf"]);
    }

    #[test]
    fn source_chain_stops_at_the_first_link_without_a_source() {
        assert!(source_chain(&Leaf).is_empty());
        assert_eq!(source_chain(&Middle(Leaf)).len(), 1);
        assert_eq!(source_chain(&Outer(Middle(Leaf))).len(), 2);
    }

    /// A leaf error: it has no cause of its own.
    #[derive(Debug)]
    struct Leaf;

    impl std::fmt::Display for Leaf {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("leaf")
        }
    }

    impl Error for Leaf {}

    /// One level of wrapping.
    #[derive(Debug)]
    struct Middle(Leaf);

    impl std::fmt::Display for Middle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("middle")
        }
    }

    impl Error for Middle {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    /// Two levels of wrapping, to prove the walk keeps going.
    #[derive(Debug)]
    struct Outer(Middle);

    impl std::fmt::Display for Outer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("outer")
        }
    }

    impl Error for Outer {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    // --- Pass and failure tests for every TestkitError variant (#29) -----

    #[test]
    fn assertion_failed_pass_and_failure_guarantees() {
        // Pass case: condition holds
        let pass_res = TestkitError::ensure(true, "invariant preserved");
        assert!(pass_res.is_ok());

        // Failure case: condition violated
        let fail_res = TestkitError::ensure(false, "token balance mismatch");
        assert!(fail_res.is_err());
        let err = fail_res.unwrap_err();

        assert_eq!(
            err,
            TestkitError::AssertionFailed("token balance mismatch".into())
        );
        assert!(err.is_assertion_failed());
        assert!(!err.is_decode_failed());
        assert!(!err.is_misuse());
        assert_eq!(err.code(), "TESTKIT_ASSERTION_FAILED");
        assert_eq!(err.message(), "token balance mismatch");
        assert_eq!(err.to_string(), "assertion failed: token balance mismatch");
    }

    #[test]
    #[should_panic(expected = "assertion failed: balance underflow")]
    fn assertion_failed_panic_matches_expected_format() {
        let err = TestkitError::assertion_failed("balance underflow");
        panic!("{err}");
    }

    #[test]
    fn decode_failed_pass_and_failure_guarantees() {
        // Pass case: successful decoding
        let ok_input: Result<i128, &str> = Ok(12345);
        let pass_res = TestkitError::check_decode(ok_input, "i128");
        assert_eq!(pass_res, Ok(12345));

        // Failure case: decode failure with type context
        let err_input: Result<i128, &str> = Err("invalid symbol length");
        let fail_res = TestkitError::check_decode(err_input, "Symbol");
        assert!(fail_res.is_err());
        let err = fail_res.unwrap_err();

        assert_eq!(
            err,
            TestkitError::DecodeFailed("failed to decode Symbol: invalid symbol length".into())
        );
        assert!(err.is_decode_failed());
        assert!(!err.is_assertion_failed());
        assert!(!err.is_misuse());
        assert_eq!(err.code(), "TESTKIT_DECODE_FAILED");
        assert_eq!(
            err.message(),
            "failed to decode Symbol: invalid symbol length"
        );
        assert_eq!(
            err.to_string(),
            "failed to decode value: failed to decode Symbol: invalid symbol length"
        );
    }

    #[test]
    #[should_panic(expected = "failed to decode value: bad scval payload")]
    fn decode_failed_panic_matches_expected_format() {
        let err = TestkitError::decode_failed("bad scval payload");
        panic!("{err}");
    }

    #[test]
    fn misuse_pass_and_failure_guarantees() {
        // Pass case: API contract respected
        let pass_res = TestkitError::require(true, "valid sequence");
        assert!(pass_res.is_ok());

        // Failure case: API contract violated
        let fail_res = TestkitError::require(false, "cannot rewind ledger clock");
        assert!(fail_res.is_err());
        let err = fail_res.unwrap_err();

        assert_eq!(
            err,
            TestkitError::Misuse("cannot rewind ledger clock".into())
        );
        assert!(err.is_misuse());
        assert!(!err.is_assertion_failed());
        assert!(!err.is_decode_failed());
        assert_eq!(err.code(), "TESTKIT_MISUSE");
        assert_eq!(err.message(), "cannot rewind ledger clock");
        assert_eq!(
            err.to_string(),
            "misuse of testkit API: cannot rewind ledger clock"
        );
    }

    #[test]
    #[should_panic(expected = "misuse of testkit API: zero close interval")]
    fn misuse_panic_matches_expected_format() {
        let err = TestkitError::misuse("zero close interval");
        panic!("{err}");
    }

    #[test]
    fn error_traits_partialeq_and_clone() {
        let err1 = TestkitError::misuse("test misuse");
        let err2 = err1.clone();
        assert_eq!(err1, err2);

        let err3 = TestkitError::assertion_failed("test misuse");
        assert_ne!(err1, err3);
    }

    // Regression test for issue #28: `{:?}` must produce the same stable
    // output as `{}` so that snapshot assertions and `#[should_panic]` tests
    // see identical text regardless of which formatter they use.
    #[test]
    fn debug_output_matches_display_for_all_variants() {
        let variants: &[TestkitError] = &[
            TestkitError::AssertionFailed("deposited != withdrawn".into()),
            TestkitError::DecodeFailed("expected i128, got Symbol".into()),
            TestkitError::Misuse("events were never captured".into()),
        ];
        for err in variants {
            assert_eq!(
                format!("{err:?}"),
                err.to_string(),
                "Debug and Display must agree for {}",
                err.code()
            );
        }
    }

    #[test]
    fn nested_context_keeps_the_full_display_chain() {
        let err = TestkitError::DecodeFailed("expected i128, got Symbol".into())
            .with_context("decoding transfer amount")
            .with_context("reading transfer event");

        assert_eq!(
            err.to_string(),
            "reading transfer event: decoding transfer amount: failed to decode value: expected i128, got Symbol"
        );
        assert_eq!(err.code(), "TESTKIT_DECODE_FAILED");
    }

    #[test]
    fn nested_context_preserves_error_sources() {
        use std::error::Error as _;

        let err = TestkitError::Misuse("clock moved backwards".into())
            .with_context("restoring ledger")
            .with_context("running at() closure");

        let first = err.source().expect("outer context must expose a source");
        assert_eq!(
            first.to_string(),
            "restoring ledger: misuse of testkit API: clock moved backwards"
        );
        let second = first.source().expect("inner context must expose a source");
        assert_eq!(
            second.to_string(),
            "misuse of testkit API: clock moved backwards"
        );
        assert!(second.source().is_none());
    }
}
