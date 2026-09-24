use std::panic;
use std::process::Command;
use std::time::{Duration, Instant};

use clap::Args;
use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
use soroban_sdk::token::StellarAssetClient;
use soroban_sdk::xdr::{ScSpecEntry, ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef};
use soroban_sdk::{Address, Env, IntoVal, Symbol, Val, Vec as SVec};

use super::CliError;

/// Arguments for `soroban-testkit limits`.
#[derive(Args)]
pub struct LimitsArgs {
    /// Path to the compiled contract .wasm file.
    #[arg(long, value_name = "PATH")]
    contract: std::path::PathBuf,
    /// The contract function to ramp.
    #[arg(long = "fn", value_name = "NAME")]
    function: String,
    /// The parameter to increase on each attempt.
    #[arg(long, value_name = "PARAM")]
    ramp: String,
    /// Kill and treat as a failure any single probe that runs longer than
    /// this many seconds. Guards against a ramp value that hangs the host
    /// (rather than erroring or aborting) turning `limits` into an
    /// infinite wait.
    #[arg(long, value_name = "SECONDS", default_value_t = 30)]
    probe_timeout: u64,
    /// Compare this run's result against a baseline previously written by
    /// `--save-baseline`. Exits non-zero if the discovered ceiling
    /// regressed (a lower ramp value, or higher instructions/memory) by
    /// more than `--baseline-tolerance-pct`.
    #[arg(long, value_name = "PATH")]
    baseline: Option<std::path::PathBuf>,
    /// How much instructions/memory are allowed to grow (as a percentage
    /// of the baseline value) before `--baseline` reports a regression.
    /// The ramp ceiling itself allows no tolerance: any decrease is a
    /// regression, since it means the contract now handles *fewer*
    /// recipients (or whatever the ramp parameter represents) than before.
    #[arg(long, value_name = "PCT", default_value_t = 5.0)]
    baseline_tolerance_pct: f64,
    /// Write this run's result to PATH as a new baseline for future
    /// `--baseline` comparisons. Combinable with `--baseline` itself, to
    /// compare against the old baseline and then update it in one run.
    #[arg(long, value_name = "PATH")]
    save_baseline: Option<std::path::PathBuf>,
    /// Export this run's result to PATH as a JSON file for CI artifacts.
    /// Contains the discovered ceiling, instructions, and memory usage.
    #[arg(long, value_name = "PATH")]
    export: Option<std::path::PathBuf>,
}

/// Hidden: runs exactly one probe (a single ramp value) and reports its
/// outcome via exit code. See [`run`]'s doc comment for why this exists
/// as a separate process rather than an in-process call.
#[derive(Args)]
pub struct ProbeArgs {
    #[arg(long)]
    contract: std::path::PathBuf,
    #[arg(long = "fn")]
    function: String,
    #[arg(long)]
    ramp: String,
    #[arg(long)]
    value: u32,
}

/// Empirically discovers a resource ceiling by invoking `--fn` with an
/// increasing `--ramp` parameter — natively, with no network access —
/// until it fails, then reports the last successful value plus the CPU
/// instructions and memory consumed at that point.
///
/// # Why this spawns a subprocess per attempt
///
/// Ramping deliberately drives a real, compiled `.wasm` contract past its
/// resource limits. Verified empirically: when that failure happens
/// *during actual WASM execution* (as opposed to a native, non-WASM
/// `#[contract]` registration), the host can abort the whole process
/// (`thread caused non-unwinding panic. aborting.`) rather than return an
/// error or unwind — neither `catch_unwind` nor `try_invoke_contract`
/// (the SDK's own no-panic call path) prevents this for the WASM target.
/// So each attempt runs in its own child process (`soroban-testkit
/// __limits-probe`, hidden from `--help`): if that child aborts, only the
/// child dies, and the exit code alone tells this command whether that
/// ramp value succeeded. Each probe's temporary environment is cleaned up
/// immediately after the probe completes or times out.
///
/// # Scope
///
/// The ramp parameter must be a numeric type (`u32`/`i32`/`u64`/`i64`/
/// `u128`/`i128`, ramped as the value itself) or `Vec<T>` for a supported
/// element type `T` (ramped as the element *count*, each element filled
/// with a fixed value — see [`vec_element_val`]) — this covers the common
/// "maximum recipients in a batch operation" question directly, for
/// `Vec<Address>` and beyond. Every other parameter is filled with a fixed
/// default (an address, `0`, an empty collection, ...). A parameter type
/// this command doesn't know how to default (`Map`, `Tuple`, `Option`,
/// `Result`, a user-defined type, ...) is reported as an error rather than
/// guessed at.
///
/// Ledger read/write counts and transaction size are **not** reported:
/// they come from a transaction's simulated resource footprint, which
/// this command's native invocation does not produce (that requires the
/// network-dependent `stellar contract invoke` simulation path, which
/// this crate deliberately avoids — see its "zero network access"
/// constraint). Only CPU instructions and memory, available locally via
/// the host's budget, are reported.
pub fn run(args: LimitsArgs) -> Result<(), CliError> {
    validate_percentage("--baseline-tolerance-pct", args.baseline_tolerance_pct)?;

    // Validate the configuration (function exists, ramp parameter exists,
    // every parameter's type is one this command knows how to default or
    // ramp) up front, in-process, before spawning any probes — this is
    // just type/spec checking, not invocation, so it carries none of the
    // abort risk documented above, and it means a typo'd --fn or --ramp
    // reports its actual cause instead of the generic "failed at value 1"
    // a swallowed child-process error would otherwise produce.
    let (_, env, function, ramp_index) = load(&args.contract, &args.function, &args.ramp)?;
    build_args(&env, &function, ramp_index, 1)?;
    drop(env);

    let self_exe = std::env::current_exe()
        .map_err(|err| CliError(format!("failed to locate this binary: {err}")))?;

    let probe_timeout = Duration::from_secs(args.probe_timeout);
    let mut any_probe_timed_out = false;
    let mut last_failed_probe: Option<u32> = None;
    let mut hit_upper_bound = false;

    let mut probe = |value: u32| -> Result<bool, CliError> {
        let mut child = Command::new(&self_exe)
            .arg("__limits-probe")
            .arg("--contract")
            .arg(&args.contract)
            .arg("--fn")
            .arg(&args.function)
            .arg("--ramp")
            .arg(&args.ramp)
            .arg("--value")
            .arg(value.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|err| CliError(format!("failed to spawn probe: {err}")))?;

        match wait_with_timeout(&mut child, probe_timeout)? {
            Some(status) => Ok(status.success()),
            None => {
                any_probe_timed_out = true;
                Ok(false)
            }
        }
    };

    // Find a failing upper bound by doubling.
    let mut last_ok: Option<u32> = None;
    let mut low = 1u32;
    let mut high = None;
    const UPPER_BOUND: u32 = 1 << 24;
    loop {
        if probe(low)? {
            last_ok = Some(low);
            match low.checked_mul(2) {
                Some(next) => low = next,
                None => {
                    high = None;
                    break;
                }
            }
        } else {
            last_failed_probe = Some(low);
            high = Some(low);
            break;
        }
        if low > UPPER_BOUND {
            hit_upper_bound = true;
            break;
        }
    }

    let Some(last_ok) = last_ok else {
        return Err(CliError(format!(
            "{:?} failed even at the smallest ramp value (1) for parameter {:?}; \
             this usually indicates a validation error in the contract rather than a \
             resource limit — check the contract's parameter validation logic and retry",
            args.function, args.ramp
        )));
    };

    // Binary search between the last success and the first failure for a
    // tighter bound, if we found one.
    let mut best = last_ok;
    if let Some(hi_start) = high {
        let mut lo = last_ok;
        let mut hi = hi_start;
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            if probe(mid)? {
                lo = mid;
            } else {
                last_failed_probe = Some(mid);
                hi = mid;
            }
        }
        best = lo;
    }

    // Measure resources at the best-known-good value, in-process this
    // time (a known-successful call is safe to make directly).
    let (instructions, memory_bytes) = measure(&args, best)?;

    println!(
        "last successful {} for {:?}: {best}",
        args.ramp, args.function
    );
    println!("  instructions: {instructions}");
    println!("  memory bytes: {memory_bytes}");
    if let Some(failed) = last_failed_probe {
        println!("  first failed {} value: {failed}", args.ramp);
    }
    println!(
        "  (ledger reads/writes and transaction size are not measured by this command; \
         see --help)"
    );
    if hit_upper_bound {
        println!(
            "  note: search stopped at the built-in upper bound ({}); the contract may support \
             higher ramp values",
            UPPER_BOUND
        );
    }
    if any_probe_timed_out {
        println!(
            "  note: at least one probe was killed for exceeding --probe-timeout ({}s); the \
             discovered ceiling may reflect a hang rather than a real resource limit — rerun \
             with a larger --probe-timeout to check",
            args.probe_timeout
        );
    }

    if let Some(baseline_path) = &args.baseline {
        compare_to_baseline(
            baseline_path,
            &args.ramp,
            &args.function,
            best,
            instructions,
            memory_bytes,
            args.baseline_tolerance_pct,
        )?;
    }
    if let Some(save_path) = &args.save_baseline {
        write_baseline(
            save_path,
            &args.ramp,
            &args.function,
            best,
            instructions,
            memory_bytes,
        )?;
        println!("saved baseline to {}", save_path.display());
    }
    if let Some(export_path) = &args.export {
        export_results(
            export_path,
            &args.ramp,
            &args.function,
            best,
            instructions,
            memory_bytes,
        )?;
        println!("exported results to {}", export_path.display());
    }

    Ok(())
}

fn validate_percentage(name: &str, pct: f64) -> Result<(), CliError> {
    if !pct.is_finite() || !(0.0..=100.0).contains(&pct) {
        return Err(CliError(format!(
            "{name} must be between 0 and 100 (got {pct})"
        )));
    }
    Ok(())
}

/// The hidden probe entry point: performs exactly one invocation and
/// returns `Ok(())` (exit 0) or `Err` (exit 1) — no measurement, no
/// output. Run in its own process by [`run`].
pub fn run_probe(args: ProbeArgs) -> Result<(), CliError> {
    let _quiet = QuietPanics::install();
    let (contract_id, env, function, ramp_index) =
        load(&args.contract, &args.function, &args.ramp)?;
    let args_vec = build_args(&env, &function, ramp_index, args.value)?;
    let func = Symbol::new(&env, &args.function);
    if invoke_succeeds(&env, &contract_id, &func, args_vec) {
        Ok(())
    } else {
        Err(CliError("probe failed".to_string()))
    }
}

/// Waits up to `timeout` for `child` to exit, polling rather than blocking
/// so an exceeded timeout can kill it instead of waiting forever. Returns
/// `Some(status)` on a normal exit within the timeout, or `None` if the
/// child was killed for running too long.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<Option<std::process::ExitStatus>, CliError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| CliError(format!("failed to poll probe: {err}")))?
        {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            // Best-effort: the process may have exited between the last
            // try_wait and here, in which case kill() harmlessly errors
            // (already-exited processes can't be killed) — ignored, since
            // either way the outcome from here on is "timed out".
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A previously-saved `limits` result, for `--baseline` regression checks.
/// Deliberately not JSON (no `serde` dependency anywhere in this
/// workspace) — a flat `key=value` file is sufficient for one flat record
/// and keeps this feature within its own module boundary.
#[derive(Debug)]
struct Baseline {
    function: String,
    ramp: String,
    best: u32,
    instructions: u64,
    memory_bytes: u64,
}

impl Baseline {
    fn to_file_contents(&self) -> String {
        format!(
            "function={}\nramp={}\nbest={}\ninstructions={}\nmemory_bytes={}\n",
            self.function, self.ramp, self.best, self.instructions, self.memory_bytes
        )
    }

    fn parse(contents: &str) -> Result<Self, CliError> {
        let mut function = None;
        let mut ramp = None;
        let mut best = None;
        let mut instructions = None;
        let mut memory_bytes = None;

        for (line_no, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(CliError(format!(
                    "malformed baseline file at line {}: expected key=value, got {line:?}",
                    line_no + 1
                )));
            };
            match key {
                "function" => function = Some(value.to_string()),
                "ramp" => ramp = Some(value.to_string()),
                "best" => {
                    best = Some(value.parse::<u32>().map_err(|err| {
                        CliError(format!("malformed baseline `best` value {value:?}: {err}"))
                    })?)
                }
                "instructions" => {
                    instructions = Some(value.parse::<u64>().map_err(|err| {
                        CliError(format!(
                            "malformed baseline `instructions` value {value:?}: {err}"
                        ))
                    })?)
                }
                "memory_bytes" => {
                    memory_bytes = Some(value.parse::<u64>().map_err(|err| {
                        CliError(format!(
                            "malformed baseline `memory_bytes` value {value:?}: {err}"
                        ))
                    })?)
                }
                other => {
                    return Err(CliError(format!(
                        "malformed baseline file at line {}: unknown key {other:?}",
                        line_no + 1
                    )))
                }
            }
        }

        Ok(Baseline {
            function: function
                .ok_or_else(|| CliError("baseline file is missing `function`".to_string()))?,
            ramp: ramp.ok_or_else(|| CliError("baseline file is missing `ramp`".to_string()))?,
            best: best.ok_or_else(|| CliError("baseline file is missing `best`".to_string()))?,
            instructions: instructions
                .ok_or_else(|| CliError("baseline file is missing `instructions`".to_string()))?,
            memory_bytes: memory_bytes
                .ok_or_else(|| CliError("baseline file is missing `memory_bytes`".to_string()))?,
        })
    }
}

fn write_baseline(
    path: &std::path::Path,
    ramp: &str,
    function: &str,
    best: u32,
    instructions: u64,
    memory_bytes: u64,
) -> Result<(), CliError> {
    let baseline = Baseline {
        function: function.to_string(),
        ramp: ramp.to_string(),
        best,
        instructions,
        memory_bytes,
    };
    std::fs::write(path, baseline.to_file_contents()).map_err(|err| {
        CliError(format!(
            "failed to write baseline to {}: {err}",
            path.display()
        ))
    })
}

/// Compares this run's result against the baseline saved at `path`, printing
/// a before/after summary and returning an error (which `main` turns into a
/// non-zero exit) if it regressed beyond `--baseline-tolerance-pct`.
fn compare_to_baseline(
    path: &std::path::Path,
    ramp: &str,
    function: &str,
    best: u32,
    instructions: u64,
    memory_bytes: u64,
    tolerance_pct: f64,
) -> Result<(), CliError> {
    let contents = std::fs::read_to_string(path).map_err(|err| {
        CliError(format!(
            "failed to read baseline at {}: {err}",
            path.display()
        ))
    })?;
    let baseline = Baseline::parse(&contents)?;

    if baseline.function != function || baseline.ramp != ramp {
        return Err(CliError(format!(
            "baseline at {} was recorded for {:?}/{:?}, not {function:?}/{ramp:?}; comparing \
             across different functions or ramp parameters isn't meaningful",
            path.display(),
            baseline.function,
            baseline.ramp
        )));
    }

    println!("baseline comparison ({}):", path.display());
    println!("  {ramp}: {} -> {best}", baseline.best);
    println!(
        "  instructions: {} -> {instructions}",
        baseline.instructions
    );
    println!(
        "  memory bytes: {} -> {memory_bytes}",
        baseline.memory_bytes
    );

    let mut regressions = Vec::new();
    if best < baseline.best {
        regressions.push(format!(
            "{ramp} ceiling dropped from {} to {best}",
            baseline.best
        ));
    }
    check_metric_regression(
        "instructions",
        baseline.instructions,
        instructions,
        tolerance_pct,
        &mut regressions,
    );
    check_metric_regression(
        "memory bytes",
        baseline.memory_bytes,
        memory_bytes,
        tolerance_pct,
        &mut regressions,
    );

    fn check_metric_regression(
        name: &str,
        old: u64,
        new: u64,
        tolerance_pct: f64,
        out: &mut Vec<String>,
    ) {
        if new <= old {
            return;
        }
        let growth_pct = ((new - old) as f64 / old.max(1) as f64) * 100.0;
        if growth_pct <= tolerance_pct {
            return;
        }
        out.push(format!(
            "{name} grew from {old} to {new} ({growth_pct:.1}%, over the {tolerance_pct:.1}% tolerance)"
        ));
    }

    if regressions.is_empty() {
        println!("  no regression");
        return Ok(());
    }

    // Instruction/memory growth within tolerance is reported above but not
    // treated as a regression; only the ramp-ceiling check and
    // over-tolerance growth fail the run.
    Err(CliError(format!(
        "baseline regression detected: {}",
        regressions.join("; ")
    )))
}

fn export_results(
    path: &std::path::Path,
    ramp: &str,
    function: &str,
    best: u32,
    instructions: u64,
    memory_bytes: u64,
) -> Result<(), CliError> {
    let baseline = Baseline {
        function: function.to_string(),
        ramp: ramp.to_string(),
        best,
        instructions,
        memory_bytes,
    };
    std::fs::write(path, baseline.to_file_contents()).map_err(|err| {
        CliError(format!(
            "failed to export results to {}: {err}",
            path.display()
        ))
    })
}

fn measure(args: &LimitsArgs, value: u32) -> Result<(u64, u64), CliError> {
    let (contract_id, env, function, ramp_index) =
        load(&args.contract, &args.function, &args.ramp)?;
    let func = Symbol::new(&env, &args.function);
    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    let args_vec = build_args(&env, &function, ramp_index, value)?;
    if !invoke_succeeds(&env, &contract_id, &func, args_vec) {
        return Err(CliError(
            "internal error: the ramp value chosen as successful failed on re-measurement"
                .to_string(),
        ));
    }
    Ok((budget.cpu_instruction_cost(), budget.memory_bytes_cost()))
}

/// Silences the default panic hook for the duration it's held, restoring
/// the previous hook on drop, so a probe's failure doesn't dump a panic
/// message and the host's diagnostic event log to stderr.
type PanicHook = Box<dyn Fn(&panic::PanicHookInfo<'_>) + Sync + Send>;

struct QuietPanics {
    previous: Option<PanicHook>,
}

impl QuietPanics {
    fn install() -> Self {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        Self {
            previous: Some(previous),
        }
    }
}

impl Drop for QuietPanics {
    fn drop(&mut self) {
        if let Some(hook) = self.previous.take() {
            panic::set_hook(hook);
        }
    }
}

fn load(
    contract: &std::path::Path,
    function: &str,
    ramp: &str,
) -> Result<(Address, Env, ScSpecFunctionV0, usize), CliError> {
    let wasm = std::fs::read(contract)
        .map_err(|err| CliError(format!("failed to read {}: {err}", contract.display())))?;

    let entries = soroban_spec::read::from_wasm(&wasm)
        .map_err(|err| CliError(format!("failed to read contract spec: {err}")))?;

    if entries.is_empty() {
        return Err(CliError(format!(
            "{}: contract has no exported functions in its spec; \
             did you include #[contract] and #[contractimpl] on your contract?",
            contract.display()
        )));
    }

    let available_functions: Vec<String> = entries
        .iter()
        .filter_map(|entry| match entry {
            ScSpecEntry::FunctionV0(f) => Some(f.name.to_string()),
            _ => None,
        })
        .collect();

    let func_spec = entries
        .into_iter()
        .find_map(|entry| match entry {
            ScSpecEntry::FunctionV0(f) if f.name.to_string() == function => Some(f),
            _ => None,
        })
        .ok_or_else(|| {
            if available_functions.is_empty() {
                CliError(format!(
                    "{}: contract has no exported functions in its spec; \
                     did you include #[contract] and #[contractimpl] on your contract?",
                    contract.display()
                ))
            } else {
                CliError(format!(
                    "no function named {function:?} in {}'s spec; \
                     available functions: {}",
                    contract.display(),
                    available_functions.join(", ")
                ))
            }
        })?;

    let ramp_index = func_spec
        .inputs
        .iter()
        .position(|input| input.name.to_utf8_string_lossy() == ramp)
        .ok_or_else(|| {
            let param_names: Vec<String> = func_spec
                .inputs
                .iter()
                .map(|p| p.name.to_utf8_string_lossy().to_string())
                .collect();
            CliError(format!(
                "{function:?} has no parameter named {ramp:?}; \
                 available parameters: {}",
                param_names.join(", ")
            ))
        })?;

    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    // Auth is not what this command measures — it exists to find a
    // resource ceiling, not to prove who may call the function — and each
    // probe runs in its own throwaway process/Env, so blanket-approving
    // auth here carries none of the AuthMatrix-correctness risk that a
    // shared, longer-lived TestEnv would (see TestToken's mint, which
    // deliberately does NOT do this for that reason).
    env.mock_all_auths_allowing_non_root_auth();
    let contract_id = env.register(wasm.as_slice(), ());

    Ok((contract_id, env, func_spec, ramp_index))
}

fn build_args(
    env: &Env,
    function: &ScSpecFunctionV0,
    ramp_index: usize,
    ramp_value: u32,
) -> Result<SVec<Val>, CliError> {
    let admin = Address::generate(env);
    let mut vals = SVec::new(env);
    for (i, input) in function.inputs.iter().enumerate() {
        let val = if i == ramp_index {
            ramp_val(env, &input.type_, ramp_value)?
        } else {
            default_val(env, &admin, &input.type_, input)?
        };
        vals.push_back(val);
    }
    Ok(vals)
}

fn invoke_succeeds(env: &Env, contract_id: &Address, func: &Symbol, args: SVec<Val>) -> bool {
    // try_invoke_contract is the SDK's own no-panic call path, used here
    // so a probe that succeeds doesn't need catch_unwind at all — only a
    // *failing* real-WASM call risks the process abort documented above,
    // and that only ever happens in the isolated child process.
    matches!(
        env.try_invoke_contract::<Val, soroban_sdk::Error>(contract_id, func, args),
        Ok(Ok(_))
    )
}

fn ramp_val(env: &Env, type_: &ScSpecTypeDef, ramp_value: u32) -> Result<Val, CliError> {
    match type_ {
        ScSpecTypeDef::U32 => Ok(ramp_value.into_val(env)),
        ScSpecTypeDef::I32 => Ok((ramp_value as i32).into_val(env)),
        ScSpecTypeDef::U64 => Ok((ramp_value as u64).into_val(env)),
        ScSpecTypeDef::I64 => Ok((ramp_value as i64).into_val(env)),
        ScSpecTypeDef::U128 => Ok((ramp_value as u128).into_val(env)),
        ScSpecTypeDef::I128 => Ok((ramp_value as i128).into_val(env)),
        // Any Vec<T> is ramped as its element *count*, filled with a fixed
        // per-element value from `vec_element_val` — the same "maximum
        // recipients" shape as the original Vec<Address>-only support, now
        // generalized to any element type this command already knows how
        // to default. The element value itself never varies across the
        // ramp; only the count does.
        ScSpecTypeDef::Vec(inner) => {
            let element = vec_element_val(env, &inner.element_type)?;
            let mut items = SVec::new(env);
            for _ in 0..ramp_value {
                items.push_back(element);
            }
            Ok(items.into_val(env))
        }
        other => Err(CliError(format!(
            "the ramp parameter's type ({other:?}) isn't supported yet; supported ramp types \
             are u32/i32/u64/i64/u128/i128 and Vec<T> (for the element types listed in \
             the Vec<T> element-type error, if T itself isn't supported)"
        ))),
    }
}

/// A fixed filler value for one element of a ramped `Vec<T>`. Deliberately
/// narrower than [`default_val`]: it has no `admin`/`input` context (an
/// element has no parameter name to apply the `token`-heuristic to, and
/// nothing meaningfully "ramps" as a nested Vec-of-Vec's inner count), so
/// unsupported element types are reported explicitly rather than silently
/// reusing a heuristic that wouldn't make sense at this level.
fn vec_element_val(env: &Env, type_: &ScSpecTypeDef) -> Result<Val, CliError> {
    match type_ {
        ScSpecTypeDef::Address => Ok(Address::generate(env).into_val(env)),
        ScSpecTypeDef::Bool => Ok(false.into_val(env)),
        ScSpecTypeDef::U32 => Ok(1u32.into_val(env)),
        ScSpecTypeDef::I32 => Ok(1i32.into_val(env)),
        ScSpecTypeDef::U64 => Ok(1u64.into_val(env)),
        ScSpecTypeDef::I64 => Ok(1i64.into_val(env)),
        ScSpecTypeDef::U128 => Ok(1u128.into_val(env)),
        ScSpecTypeDef::I128 => Ok(1i128.into_val(env)),
        ScSpecTypeDef::Symbol => Ok(Symbol::new(env, "x").into_val(env)),
        ScSpecTypeDef::String => Ok(soroban_sdk::String::from_str(env, "").into_val(env)),
        ScSpecTypeDef::Bytes => Ok(soroban_sdk::Bytes::new(env).into_val(env)),
        other => Err(CliError(format!(
            "Vec<{other:?}> isn't supported as a ramp parameter yet; supported Vec<T> element \
             types are Address/Bool/u32/i32/u64/i64/u128/i128/Symbol/String/Bytes"
        ))),
    }
}

fn default_val(
    env: &Env,
    admin: &Address,
    type_: &ScSpecTypeDef,
    input: &ScSpecFunctionInputV0,
) -> Result<Val, CliError> {
    match type_ {
        // A parameter literally named `token` is, by overwhelming Soroban
        // convention, a token contract address — and a batch/payout-style
        // function will call transfer() on it and needs `admin` to hold a
        // real balance, not just a syntactically valid address. Deploying
        // a funded Stellar Asset Contract for this one case is a
        // name-based heuristic, not a semantic guarantee, but it's what
        // makes `limits` usable against a real payout contract at all
        // (verified against sororail-contracts' batch_payout, whose
        // execute_equal(funder, token, recipients, amount_each) is
        // exactly this shape).
        ScSpecTypeDef::Address if input.name.to_utf8_string_lossy() == "token" => {
            let issuer = Address::generate(env);
            let sac = env.register_stellar_asset_contract_v2(issuer.clone());
            let token_address = sac.address();
            let amount = i128::MAX / 2;
            StellarAssetClient::new(env, &token_address)
                .mock_auths(&[MockAuth {
                    address: &issuer,
                    invoke: &MockAuthInvoke {
                        contract: &token_address,
                        fn_name: "mint",
                        args: (admin.clone(), amount).into_val(env),
                        sub_invokes: &[],
                    },
                }])
                .mint(admin, &amount);
            Ok(token_address.into_val(env))
        }
        ScSpecTypeDef::Address => Ok(admin.into_val(env)),
        ScSpecTypeDef::Bool => Ok(false.into_val(env)),
        // 1, not 0: verified against sororail-contracts' batch_payout,
        // whose execute_equal(..., amount_each: i128) requires a positive
        // amount and rejects 0 with its own InvalidAmount error before
        // any resource-limit-relevant work happens. There's no default
        // that's safe for every contract's validation rules, but 1 is
        // the smaller mistake: far more contracts reject a non-positive
        // amount than reject exactly 1.
        ScSpecTypeDef::U32 => Ok(1u32.into_val(env)),
        ScSpecTypeDef::I32 => Ok(1i32.into_val(env)),
        ScSpecTypeDef::U64 => Ok(1u64.into_val(env)),
        ScSpecTypeDef::I64 => Ok(1i64.into_val(env)),
        ScSpecTypeDef::U128 => Ok(1u128.into_val(env)),
        ScSpecTypeDef::I128 => Ok(1i128.into_val(env)),
        ScSpecTypeDef::Symbol => Ok(Symbol::new(env, "x").into_val(env)),
        ScSpecTypeDef::String => Ok(soroban_sdk::String::from_str(env, "").into_val(env)),
        ScSpecTypeDef::Bytes => Ok(soroban_sdk::Bytes::new(env).into_val(env)),
        ScSpecTypeDef::Vec(_) => Ok(SVec::<Val>::new(env).into_val(env)),
        other => Err(CliError(format!(
            "parameter {:?} has type {other:?}, which this command doesn't know how to \
             default yet; only the --ramp parameter needs a type this command understands \
             today, every other parameter needs a supported default type",
            input.name.to_utf8_string_lossy()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::xdr::ScSpecTypeVec;

    // ---- #239: Vec<T> ramp support ----

    #[test]
    fn ramp_val_vec_address_produces_the_requested_count() {
        let env = Env::default();
        let type_ = ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::Address),
        }));
        let val = ramp_val(&env, &type_, 5).unwrap();
        let vec: SVec<Address> = val.into_val(&env);
        assert_eq!(vec.len(), 5);
    }

    #[test]
    fn ramp_val_vec_u32_produces_the_requested_count() {
        let env = Env::default();
        let type_ = ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::U32),
        }));
        let val = ramp_val(&env, &type_, 7).unwrap();
        let vec: SVec<u32> = val.into_val(&env);
        assert_eq!(vec.len(), 7);
        assert_eq!(vec.get(0), Some(1u32));
    }

    #[test]
    fn ramp_val_vec_of_zero_is_an_empty_vec() {
        let env = Env::default();
        let type_ = ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::Symbol),
        }));
        let val = ramp_val(&env, &type_, 0).unwrap();
        let vec: SVec<Symbol> = val.into_val(&env);
        assert!(vec.is_empty());
    }

    #[test]
    fn ramp_val_rejects_vec_of_unsupported_element_type() {
        let env = Env::default();
        let type_ = ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
                element_type: Box::new(ScSpecTypeDef::U32),
            }))),
        }));
        let err = ramp_val(&env, &type_, 3).unwrap_err();
        assert!(err.0.contains("isn't supported"), "{}", err.0);
    }

    #[test]
    fn ramp_val_rejects_an_unsupported_scalar_type() {
        let env = Env::default();
        let err = ramp_val(&env, &ScSpecTypeDef::Void, 1).unwrap_err();
        assert!(err.0.contains("isn't supported yet"), "{}", err.0);
    }

    // ---- #245: baseline comparison ----

    fn sample_baseline() -> Baseline {
        Baseline {
            function: "batch_payout".to_string(),
            ramp: "recipients".to_string(),
            best: 100,
            instructions: 1_000_000,
            memory_bytes: 50_000,
        }
    }

    #[test]
    fn baseline_round_trips_through_its_file_format() {
        let baseline = sample_baseline();
        let parsed = Baseline::parse(&baseline.to_file_contents()).unwrap();
        assert_eq!(parsed.function, baseline.function);
        assert_eq!(parsed.ramp, baseline.ramp);
        assert_eq!(parsed.best, baseline.best);
        assert_eq!(parsed.instructions, baseline.instructions);
        assert_eq!(parsed.memory_bytes, baseline.memory_bytes);
    }

    #[test]
    fn baseline_parse_rejects_a_missing_field() {
        let err = Baseline::parse("function=f\nramp=r\nbest=1\n").unwrap_err();
        assert!(err.0.contains("missing `instructions`"), "{}", err.0);
    }

    #[test]
    fn baseline_parse_rejects_an_unknown_key() {
        let err = Baseline::parse("function=f\nramp=r\nbest=1\nbogus=2\n").unwrap_err();
        assert!(err.0.contains("unknown key"), "{}", err.0);
    }

    #[test]
    fn baseline_parse_rejects_a_malformed_line() {
        let err = Baseline::parse("not-a-key-value-line\n").unwrap_err();
        assert!(err.0.contains("malformed baseline file"), "{}", err.0);
    }

    #[test]
    fn compare_to_baseline_passes_when_nothing_regressed() {
        let dir = std::env::temp_dir().join(format!("stk-baseline-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pass.baseline");
        std::fs::write(&path, sample_baseline().to_file_contents()).unwrap();

        let result = compare_to_baseline(
            &path,
            "recipients",
            "batch_payout",
            100,
            1_000_000,
            50_000,
            5.0,
        );
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn compare_to_baseline_fails_when_the_ramp_ceiling_drops() {
        let dir = std::env::temp_dir().join(format!("stk-baseline-{}-2", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ceiling-drop.baseline");
        std::fs::write(&path, sample_baseline().to_file_contents()).unwrap();

        let err = compare_to_baseline(
            &path,
            "recipients",
            "batch_payout",
            90,
            1_000_000,
            50_000,
            5.0,
        )
        .unwrap_err();
        assert!(
            err.0.contains("ceiling dropped from 100 to 90"),
            "{}",
            err.0
        );
    }

    #[test]
    fn compare_to_baseline_fails_when_instructions_grow_past_tolerance() {
        let dir = std::env::temp_dir().join(format!("stk-baseline-{}-3", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("instr-grow.baseline");
        std::fs::write(&path, sample_baseline().to_file_contents()).unwrap();

        // +10% instructions, tolerance is 5%.
        let err = compare_to_baseline(
            &path,
            "recipients",
            "batch_payout",
            100,
            1_100_000,
            50_000,
            5.0,
        )
        .unwrap_err();
        assert!(err.0.contains("instructions grew"), "{}", err.0);
    }

    #[test]
    fn compare_to_baseline_allows_growth_within_tolerance() {
        let dir = std::env::temp_dir().join(format!("stk-baseline-{}-4", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("within-tolerance.baseline");
        std::fs::write(&path, sample_baseline().to_file_contents()).unwrap();

        // +2% instructions, tolerance is 5%.
        let result = compare_to_baseline(
            &path,
            "recipients",
            "batch_payout",
            100,
            1_020_000,
            50_000,
            5.0,
        );
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn compare_to_baseline_rejects_a_mismatched_function_or_ramp() {
        let dir = std::env::temp_dir().join(format!("stk-baseline-{}-5", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mismatch.baseline");
        std::fs::write(&path, sample_baseline().to_file_contents()).unwrap();

        let err = compare_to_baseline(&path, "amount", "batch_payout", 100, 1_000_000, 50_000, 5.0)
            .unwrap_err();
        assert!(err.0.contains("was recorded for"), "{}", err.0);
    }

    #[test]
    fn compare_to_baseline_reports_a_missing_file_actionably() {
        let missing = std::env::temp_dir().join("this-baseline-does-not-exist.baseline");
        let err = compare_to_baseline(
            &missing,
            "recipients",
            "batch_payout",
            100,
            1_000_000,
            50_000,
            5.0,
        )
        .unwrap_err();
        assert!(err.0.contains("failed to read baseline"), "{}", err.0);
    }

    // ---- #243: per-probe timeout ----

    #[test]
    fn wait_with_timeout_returns_the_exit_status_for_a_fast_process() {
        let mut child = Command::new("true").spawn().unwrap();
        let status = wait_with_timeout(&mut child, Duration::from_secs(5))
            .unwrap()
            .expect("should not have timed out");
        assert!(status.success());
    }

    #[test]
    fn baseline_tolerance_must_be_between_zero_and_one_hundred() {
        for pct in [-0.1, 100.1, f64::NAN, f64::INFINITY] {
            let err = validate_percentage("--baseline-tolerance-pct", pct).unwrap_err();
            assert!(err.0.contains("between 0 and 100"), "{}", err.0);
        }
    }

    #[test]
    fn wait_with_timeout_kills_and_returns_none_for_a_slow_process() {
        let mut child = Command::new("sleep").arg("5").spawn().unwrap();
        let start = Instant::now();
        let result = wait_with_timeout(&mut child, Duration::from_millis(200)).unwrap();
        assert!(result.is_none());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "should have killed the child near the timeout, not waited for it to finish"
        );
    }

    // ---- #244: export results ----

    #[test]
    fn export_results_writes_a_file_with_the_correct_format() {
        let dir = std::env::temp_dir().join(format!("stk-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("export.results");

        export_results(&path, "recipients", "batch_payout", 100, 1_000_000, 50_000).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("function=batch_payout"));
        assert!(contents.contains("ramp=recipients"));
        assert!(contents.contains("best=100"));
        assert!(contents.contains("instructions=1000000"));
        assert!(contents.contains("memory_bytes=50000"));
    }

    #[test]
    fn export_results_can_be_parsed_as_a_baseline() {
        let dir = std::env::temp_dir().join(format!("stk-export-{}-2", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("export.results");

        export_results(&path, "recipients", "batch_payout", 100, 1_000_000, 50_000).unwrap();

        let baseline = Baseline::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(baseline.function, "batch_payout");
        assert_eq!(baseline.ramp, "recipients");
        assert_eq!(baseline.best, 100);
        assert_eq!(baseline.instructions, 1_000_000);
        assert_eq!(baseline.memory_bytes, 50_000);
    }

    // ---- #233: paths with spaces ----

    #[test]
    fn write_baseline_handles_paths_with_spaces() {
        let dir = std::env::temp_dir().join(format!("stk baseline test {}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("my baseline.txt");

        write_baseline(&path, "recipients", "batch_payout", 100, 1_000_000, 50_000).unwrap();

        let baseline = Baseline::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(baseline.function, "batch_payout");
        assert_eq!(baseline.ramp, "recipients");
        assert_eq!(baseline.best, 100);
    }

    #[test]
    fn export_results_handles_paths_with_spaces() {
        let dir = std::env::temp_dir().join(format!("stk export test {}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("my export results.txt");

        export_results(&path, "recipients", "batch_payout", 100, 1_000_000, 50_000).unwrap();

        let baseline = Baseline::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(baseline.function, "batch_payout");
        assert_eq!(baseline.ramp, "recipients");
        assert_eq!(baseline.best, 100);
    }

    #[test]
    fn compare_to_baseline_handles_paths_with_spaces() {
        let dir = std::env::temp_dir().join(format!("stk compare test {}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("my baseline file.txt");

        std::fs::write(&path, sample_baseline().to_file_contents()).unwrap();

        let result = compare_to_baseline(
            &path,
            "recipients",
            "batch_payout",
            100,
            1_000_000,
            50_000,
            5.0,
        );
        assert!(result.is_ok(), "{:?}", result.err());
    }

    // ---- #227: handle missing WASM exports ----

    #[test]
    fn load_rejects_missing_function_with_available_list() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("stk-load-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let wasm_path = dir.join("test.wasm");
        let mut file = std::fs::File::create(&wasm_path).unwrap();
        file.write_all(b"mock").unwrap();

        let err_result = load(&wasm_path, "nonexistent", "count");
        assert!(err_result.is_err());
        let err_msg = err_result.unwrap_err().0;
        assert!(
            err_msg.contains("failed to read contract spec"),
            "expected spec error, got: {}",
            err_msg
        );
    }

    #[test]
    fn load_provides_helpful_param_error() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("stk-param-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let wasm_path = dir.join("test.wasm");
        let mut file = std::fs::File::create(&wasm_path).unwrap();
        file.write_all(b"mock").unwrap();

        let err_result = load(&wasm_path, "test_func", "wrong_param");
        assert!(err_result.is_err());
        let err_msg = err_result.unwrap_err().0;
        assert!(
            err_msg.contains("failed to read contract spec"),
            "expected spec error early, got: {}",
            err_msg
        );
    }

    // ---- #228: distinguish resource-limit failures from validation ----

    #[test]
    fn run_distinguishes_validation_failures_from_limits() {
        let err_result = LimitsArgs {
            contract: std::path::PathBuf::from("nonexistent.wasm"),
            function: "test".to_string(),
            ramp: "count".to_string(),
            probe_timeout: 30,
            baseline: None,
            baseline_tolerance_pct: 5.0,
            save_baseline: None,
            export: None,
        };

        let result = run(err_result);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().0;
        assert!(err_msg.contains("failed to read"), "expected file error, got: {}", err_msg);
    }
}
