//! Integration tests against `examples/vault`, run as a subprocess of the
//! real `soroban-testkit` binary — exercising the CLI the way a user
//! would, not just its internal functions.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .args(args)
        .current_dir(workspace_root())
        .output()
        .expect("failed to run soroban-testkit")
}

#[test]
fn audit_reports_findings_against_vault() {
    let output = run(&["audit", "examples/vault/src"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("missing-require-auth"), "{stdout}");
    assert!(stdout.contains("missing-ttl-bump"), "{stdout}");
    assert!(stdout.contains("unchecked-i128-arithmetic"), "{stdout}");
    assert!(stdout.contains("not a security product"), "{stdout}");
}

#[test]
fn audit_strict_exits_non_zero_on_findings() {
    let output = run(&["audit", "examples/vault/src", "--strict"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("audit finding(s)"), "{stderr}");
}

#[test]
fn audit_reports_no_findings_on_a_clean_directory() {
    let output = run(&["audit", "crates/cli/src/commands/mod.rs"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("no findings"), "{stdout}");
}

#[test]
fn audit_scans_macro_entry_points_from_stdin() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .args(["audit", "-"])
        .current_dir(workspace_root())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to run soroban-testkit");
    std::io::Write::write_all(
        child.stdin.as_mut().unwrap(),
        br#"#[contractimpl] impl Contract { fn transfer(env: Env, from: Address) { let value: i128 = 1; let _ = value + 1i128; } }"#,
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("<stdin>"), "{stdout}");
    assert!(stdout.contains("missing-require-auth"), "{stdout}");
    assert!(stdout.contains("unchecked-i128-arithmetic"), "{stdout}");
}

#[test]
fn limits_finds_the_real_mainnet_write_ceiling_for_batch_payout() {
    let build = Command::new("cargo")
        .args([
            "build",
            "-p",
            "vault",
            "--target",
            "wasm32v1-none",
            "--release",
        ])
        .current_dir(workspace_root())
        .status()
        .expect("failed to build vault.wasm");
    assert!(build.success());

    let wasm = workspace_root().join("target/wasm32v1-none/release/vault.wasm");
    let output = run(&[
        "limits",
        "--contract",
        wasm.to_str().unwrap(),
        "--fn",
        "batch_payout",
        "--ramp",
        "recipients",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("last successful recipients"), "{stdout}");
    assert!(stdout.contains("instructions:"), "{stdout}");
    assert!(stdout.contains("memory bytes:"), "{stdout}");
}

#[test]
fn limits_reports_an_actionable_error_for_an_unknown_function() {
    let wasm = workspace_root().join("target/wasm32v1-none/release/vault.wasm");
    if !wasm.exists() {
        // Built by limits_finds_the_real_mainnet_write_ceiling_for_batch_payout;
        // skip if tests ran in isolation without it.
        return;
    }
    let output = run(&[
        "limits",
        "--contract",
        wasm.to_str().unwrap(),
        "--fn",
        "does_not_exist",
        "--ramp",
        "x",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("no function named"), "{stderr}");
}
