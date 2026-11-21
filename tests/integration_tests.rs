//! Integration tests for DRFW
//!
//! These tests verify end-to-end functionality including apply/revert flows,
//! error handling, CLI operations, and verification with mock nft.
//!
//! **Test Organization:**
//! - Verification plumbing with mock nft is here; real verification is in
//!   `tests/verify_errors.rs` and `tests/real_nft.rs`
//! - Guarded apply plumbing (tokens, watcher, status) with mock nft is here;
//!   real-kernel revert behavior is in `tests/real_nft.rs`
//! - Argument validation of the root scripts (`APPLY_SCRIPT`,
//!   `SAVE_CONFIG_SCRIPT`), run unelevated
//! - CLI command integration tests are here
//! - Profile operations are here
//! - JSON generation tests are in `src/core/tests.rs` (close to implementation)
//!
//! # Running Tests
//!
//! All tests use the mock nft script automatically - no privileges needed:
//! ```bash
//! cargo test --test integration_tests
//! ```
//!
//! The mock script (`tests/mock_nft.sh`) simulates nft behavior for testing.
//! Rule builders and other helpers shared with the other test crates are in
//! `tests/common/mod.rs`.

mod common;

use std::env;
use std::sync::Once;

use drfw::core::firewall::FirewallRuleset;
use drfw::core::root_payload::SavePayload;
use drfw::core::verify;

use crate::common::{
    EnvVarGuard, create_test_rule, create_test_ruleset, mock_nft_path, script_paths_usable,
    write_profile,
};

/// One-time initialization flag for mock nft setup
static MOCK_NFT_INIT: Once = Once::new();

/// Set up environment to use mock nft
///
/// Sets `DRFW_NFT_COMMAND` to the mock script path. This is called once
/// and applies to all subsequent nft operations in the test suite; it is
/// never removed.
fn setup_mock_nft() {
    MOCK_NFT_INIT.call_once(|| {
        // SAFETY: set once, never removed
        unsafe {
            env::set_var("DRFW_NFT_COMMAND", mock_nft_path());
        }
    });
}

/// A temp data/state directory, exclusively in use until dropped. The
/// environment it changed (and whatever a test changes through
/// [`TestDirs::env`]) is restored when it is dropped.
struct TestDirs {
    env: EnvVarGuard,
    dir: tempfile::TempDir,
}

impl TestDirs {
    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }
}

/// Set up a temp directory for tests that access profile/config directories.
///
/// This prevents tests from creating or modifying the user's real data.
/// The directory is removed when the returned value is dropped; until then
/// no other test can redirect the directories.
fn setup_temp_test_dirs() -> TestDirs {
    let mut env = EnvVarGuard::lock();
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    env.set("DRFW_TEST_DATA_DIR", temp_dir.path());
    env.set("DRFW_TEST_STATE_DIR", temp_dir.path());
    TestDirs { env, dir: temp_dir }
}

/// Plumbing only: `verify_ruleset` runs `DRFW_NFT_COMMAND` (the mock) without
/// elevation and maps its exit status. Real verification is in
/// `tests/verify_errors.rs` and `tests/real_nft.rs`.
#[tokio::test]
async fn test_verify_with_mock() {
    setup_mock_nft();

    let ruleset = create_test_ruleset();
    let json = ruleset.to_nftables_json();
    let result = verify::verify_ruleset(json).await;

    assert!(
        result.is_ok(),
        "verify_ruleset should succeed with mock: {:?}",
        result.err()
    );

    let verify_result = result.unwrap();
    assert!(
        verify_result.success,
        "Mock verification should succeed: {:?}",
        verify_result.issues
    );

    // A refusal (the mock wants a non-empty command list) is a failed
    // verification, not an error
    let refused = verify::verify_ruleset(serde_json::json!({ "nftables": [] }))
        .await
        .expect("the check runs");
    assert!(!refused.success);
    assert_eq!(refused.issues.len(), 1, "{:?}", refused.issues);
}

/// Runs the mock nft with `args` and `stdin`; returns its exit code.
fn run_mock(args: &[&str], stdin: &str) -> Option<i32> {
    use std::io::Write;
    let mut child = std::process::Command::new(mock_nft_path())
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("run the mock nft");
    let mut input = child.stdin.take().expect("stdin");
    // The mock may exit without reading everything
    let _ = input.write_all(stdin.as_bytes());
    drop(input);
    child.wait().expect("wait for the mock nft").code()
}

/// The mock accepts only what DRFW really sends: an `nftables` command list
/// of add/delete/flush objects for JSON, revert batches for `-f`.
#[test]
fn test_mock_nft_rejects_malformed_input() {
    let ruleset = create_test_ruleset().to_nftables_json().to_string();
    for args in [
        &["--json", "--check", "-f", "-"][..],
        &["--json", "-f", "-"],
    ] {
        assert_eq!(run_mock(args, &ruleset), Some(0), "{args:?}");
        for bad in [
            "not json",
            "{}",
            r#"{"nftables": []}"#,
            r#"{"nftables": {}}"#,
            r#"{"nftables": [{"list": {"ruleset": null}}]}"#,
            r#"{"nftables": ["add"]}"#,
        ] {
            assert_eq!(run_mock(args, bad), Some(1), "{args:?} accepted {bad}");
        }
    }
    let revert = "add table inet drfw\ndelete table inet drfw\n";
    assert_eq!(run_mock(&["-f", "-"], revert), Some(0));
    assert_eq!(run_mock(&["-f", "-"], "flush ruleset\n"), Some(1));
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("revert.nft");
    std::fs::write(&file, format!("{revert}table inet drfw {{\n}}\n")).unwrap();
    assert_eq!(run_mock(&["-f", file.to_str().unwrap()], ""), Some(0));
    std::fs::write(&file, "flush ruleset\n").unwrap();
    assert_eq!(run_mock(&["-f", file.to_str().unwrap()], ""), Some(1));
}

/// The audit helpers write one JSON line per event to the state dir's
/// `audit.log`, and nothing when the event log is off.
#[tokio::test]
async fn test_audit_logging_writes_events() {
    let dirs = setup_temp_test_dirs();

    drfw::audit::log_apply(true, 5, 3, true, None).await;
    drfw::audit::log_apply(true, 5, 3, false, Some("Test error".to_string())).await;
    drfw::audit::log_revert(true, true, None).await;
    drfw::audit::log_revert(false, false, Some("not logged".to_string())).await;

    let log = std::fs::read_to_string(dirs.path().join("audit.log")).expect("audit.log");
    let events: Vec<serde_json::Value> = log
        .lines()
        .map(|line| serde_json::from_str(line).expect("one JSON event per line"))
        .collect();
    assert_eq!(events.len(), 3, "{log}");
    assert_eq!(events[0]["event_type"], "apply_rules");
    assert_eq!(events[0]["success"], true);
    assert_eq!(events[0]["details"]["rule_count"], 5);
    assert_eq!(events[0]["details"]["enabled_count"], 3);
    assert_eq!(events[1]["success"], false);
    assert_eq!(events[1]["error"], "Test error");
    assert_eq!(events[2]["event_type"], "revert_rules");
    assert!(!log.contains("not logged"));
}

// ============================================================================
// `drfw export` and profile loading
// ============================================================================

/// `drfw export` prints exactly the text Save to System writes, or exactly
/// the JSON Apply sends.
#[test]
fn test_cli_export_formats() {
    let root = tempfile::tempdir().unwrap();
    let ruleset = create_test_ruleset();
    write_profile(root.path(), "web", &ruleset);

    let output = run_drfw(root.path(), &["export", "web"]);
    assert!(output.status.success(), "{}", all_output(&output));
    assert_eq!(stdout_of(&output), format!("{}\n", ruleset.to_nft_text()));

    let output = run_drfw(root.path(), &["export", "web", "--format", "json"]);
    assert!(output.status.success(), "{}", all_output(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(json, ruleset.to_nftables_json());

    let output = run_drfw(root.path(), &["export", "missing"]);
    assert_eq!(output.status.code(), Some(1), "{}", all_output(&output));
}

/// Loading a profile from disk rebuilds the caches (they are not stored).
#[tokio::test]
async fn test_profile_load_rebuilds_caches() {
    let dirs = setup_temp_test_dirs();
    let ruleset = create_test_ruleset();
    write_profile(dirs.path(), "cached", &ruleset);
    let on_disk = std::fs::read_to_string(dirs.path().join("profiles/cached.json")).unwrap();
    assert!(!on_disk.contains("label_lowercase"), "caches are not saved");

    let loaded = drfw::core::profiles::load_profile("cached")
        .await
        .expect("load profile");
    assert_eq!(loaded.rules.len(), 1);
    let rule = &loaded.rules[0];
    assert_eq!(rule, &ruleset.rules[0], "caches rebuilt as on creation");
    assert_eq!(rule.label_lowercase, "test ssh");
    assert_eq!(rule.port_display, "22");
    assert_eq!(rule.protocol_lowercase, "tcp");
}

/// Save to System write path with the mock nft (`-c -f FILE` accepts files that
/// start with the DRFW shebang). Real-nft coverage is in `tests/real_nft.rs`.
/// Without the helper DRFW renders the payload itself: the file is exactly
/// `to_nft_text()`.
#[tokio::test]
async fn test_save_config_file_with_mock_nft() {
    use std::os::unix::fs::PermissionsExt;
    if !script_paths_usable() {
        return;
    }
    setup_mock_nft();

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("nftables.conf");
    let target_str = target.to_str().unwrap();
    let backup = dir.path().join("nftables.conf.drfw-bak");

    // No existing file: written, no backup reported
    let ruleset = create_test_ruleset();
    let text = ruleset.to_nft_text();
    let payload = SavePayload::of_ruleset(&ruleset);
    let output = drfw::core::system_config::write_config_file(&payload, target_str)
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), text);
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        drfw::core::system_config::backup_path_from_output(&output),
        None
    );
    assert!(!backup.exists());

    // Rejected content (the mock refuses `hook bogus`): original untouched,
    // no backup, no temp file left
    let output = drfw::core::system_config::write_config_file(&bogus_hook_payload(), target_str)
        .await
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), text);
    assert!(!backup.exists());
    assert!(!dir.path().join(".nftables.conf.drfw-tmp").exists());

    // Payloads for other tables are refused before anything runs
    let docker = r#"{"nftables":[{"delete":{"table":{"family":"inet","name":"docker"}}}]}"#;
    assert!(SavePayload::of_recorded_json(docker).is_err());

    // Second successful save backs up the previous file
    let output = drfw::core::system_config::write_config_file(&payload, target_str)
        .await
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        drfw::core::system_config::backup_path_from_output(&output),
        Some(backup.clone())
    );
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), text);
}

/// A payload DRFW's checks allow (only its own table) that nft rejects: a
/// chain with an unknown hook (`tests/mock_nft.sh` refuses `hook bogus` too).
fn bogus_hook_payload() -> SavePayload {
    let mut json = create_test_ruleset().to_nftables_json();
    json["nftables"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({ "add": { "chain": {
            "family": "inet", "table": "drfw", "name": "bogus",
            "type": "filter", "hook": "bogus", "prio": 0, "policy": "accept",
        } } }));
    SavePayload::of_recorded_json(&json.to_string()).unwrap()
}

/// Guarded apply with the mock nft: the real apply script and a real
/// (`setsid`) watcher, confirm/timeout/no-guard paths. Real-kernel revert
/// semantics are covered in `tests/real_nft.rs`.
#[tokio::test]
async fn test_guarded_apply_with_mock_nft() {
    use drfw::core::apply_guard::{ApplyError, GuardOutcome, OUTCOME_GRACE, apply_guarded};
    use drfw::core::confirmed::{ConfirmedRecord, RecordKind};
    if !script_paths_usable() {
        return;
    }
    setup_mock_nft();
    // A confirmed guard records the ruleset in the state directory: never
    // the user's real one
    let mut dirs = setup_temp_test_dirs();

    let dir = tempfile::tempdir().unwrap();
    let runtime_dir = dir.path().join("run");
    let state_dir = dir.path().join("guard");
    std::fs::create_dir(&runtime_dir).unwrap();
    // The token directory must be private, or DRFW does not use it
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Restored when `dirs` is dropped
    dirs.env.set("XDG_RUNTIME_DIR", &runtime_dir);
    dirs.env.set("DRFW_GUARD_STATE_DIR", &state_dir);
    let ruleset = create_test_ruleset();
    let json = ruleset.to_nftables_json();
    let record = || ConfirmedRecord::load_from_blocking(dirs.path());

    // No guard: just applied, and kept at once (the same record the GUI
    // keeps for an apply with auto-revert off)
    assert_eq!(apply_guarded(&json, 0, &ruleset).await, Ok(None));
    let kept = record().expect("recorded");
    assert_eq!(kept.kind(), RecordKind::Unguarded);
    assert!(kept.matches(&json));
    assert_eq!(
        kept.ruleset().map(|r| r.rules[0].id),
        Some(ruleset.rules[0].id)
    );

    // Confirmed before the timeout: the watcher reports it
    let handle = apply_guarded(&json, 30, &ruleset)
        .await
        .unwrap()
        .expect("guard");
    assert_eq!(
        record().map(|r| r.kind()),
        Some(RecordKind::Unguarded),
        "not kept until confirmed"
    );
    handle.confirm().unwrap();
    assert_eq!(
        handle.wait_outcome(OUTCOME_GRACE).await,
        Ok(GuardOutcome::Confirmed)
    );
    assert_eq!(record().map(|r| r.kind()), Some(RecordKind::Confirmed));
    // Tokens are cleaned up by the user side, never by the watcher
    assert_eq!(std::fs::read_dir(&runtime_dir).unwrap().count(), 0);
    // The token really went to the runtime dir: a watcher confirmed it there
    let handle = apply_guarded(&json, 30, &ruleset)
        .await
        .unwrap()
        .expect("guard");
    handle.confirm().unwrap();
    assert_eq!(std::fs::read_dir(&runtime_dir).unwrap().count(), 1);
    assert_eq!(
        handle.wait_outcome(OUTCOME_GRACE).await,
        Ok(GuardOutcome::Confirmed)
    );

    // Not confirmed: the watcher reverts on its own, the record stays
    let mut other = ruleset.clone();
    other.rules.push(create_test_rule("Other", Some(8080)));
    let handle = apply_guarded(&other.to_nftables_json(), 1, &other)
        .await
        .unwrap()
        .expect("guard");
    assert_eq!(
        handle.wait_for_timeout_outcome().await,
        Ok(GuardOutcome::Reverted)
    );
    assert!(record().expect("still recorded").matches(&json));

    // The script is killed right after the rules went live: DRFW cannot know
    // the outcome and says so, and the guard (started before the apply)
    // still reverts on time
    let reverted_count = || {
        std::fs::read_dir(&state_dir)
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry.file_name().to_string_lossy().starts_with("status-")
                    && std::fs::read_to_string(entry.path()).unwrap_or_default() == "reverted\n"
            })
            .count()
    };
    let before = reverted_count();
    std::fs::write(state_dir.join("mock-kill-apply"), "").unwrap();
    let error = apply_guarded(&json, 1, &ruleset).await.unwrap_err();
    assert!(
        matches!(error, ApplyError::StateUnknown(_)),
        "a killed apply script must not be reported as 'nothing changed': {error}"
    );
    assert!(error.rules_may_be_active());
    let mut reverted = false;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if reverted_count() == before + 1 {
            reverted = true;
            break;
        }
    }
    assert!(reverted, "the guard of the killed apply must revert");
}

// ============================================================================
// CLI binary tests (`drfw status`, `drfw check`)
// ============================================================================
//
// These run the real `drfw` binary. Each child gets its own environment
// (data/state dirs, mock nft), so they never race with the env-var users above.

/// The `drfw` binary against `root` with `nft` as `DRFW_NFT_COMMAND`, in a
/// hermetic environment: nothing of the runner's leaks in (its SSH session,
/// `DRFW_*` variables, `DISPLAY`, …), `HOME` is `root`, `PATH` has a fake
/// `systemctl` first (so the real systemd is never asked) and `/proc` is a
/// missing fixture dir (no SSH sessions). Only `TMPDIR` is kept, so nothing
/// is written outside it. Callers add or override variables.
fn drfw_command(root: &std::path::Path, nft: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    let fake_bin = root.join("fake-bin");
    if !fake_bin.join("systemctl").exists() {
        install_fake_systemctl(&fake_bin);
    }
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_drfw"));
    command
        .env_clear()
        .env("PATH", path_with(&fake_bin))
        .env("HOME", root)
        .env("DRFW_TEST_DATA_DIR", root)
        .env("DRFW_TEST_STATE_DIR", root)
        .env("DRFW_NFT_COMMAND", nft)
        .env("DRFW_TEST_PROC_DIR", root.join("no-proc"));
    if let Some(tmp) = env::var_os("TMPDIR") {
        command.env("TMPDIR", tmp);
    }
    command
}

/// Runs the `drfw` binary against `root` with `nft` as `DRFW_NFT_COMMAND`.
fn run_drfw_with_nft(root: &std::path::Path, nft: &str, args: &[&str]) -> std::process::Output {
    drfw_command(root, nft)
        .args(args)
        .output()
        .expect("run drfw")
}

/// Runs the `drfw` binary against `root` with the mock nft.
fn run_drfw(root: &std::path::Path, args: &[&str]) -> std::process::Output {
    run_drfw_with_nft(root, mock_nft_path().to_str().unwrap(), args)
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn all_output(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn test_cli_status_reports_profile_validity_and_does_not_claim_kernel_state() {
    let root = tempfile::tempdir().unwrap();
    let mut ruleset = create_test_ruleset();
    let mut broken = create_test_rule("Broken", Some(0)); // port 0 is invalid
    broken.enabled = false;
    ruleset.rules.push(broken);
    write_profile(root.path(), "default", &ruleset);

    let output = run_drfw(root.path(), &["status"]);
    let out = stdout_of(&output);
    assert!(output.status.success(), "{}", all_output(&output));
    assert!(
        out.contains("Active profile:") && out.contains("default"),
        "{out}"
    );
    assert!(out.contains("2 (1 enabled)"), "{out}");
    assert!(
        out.contains("Invalid rules:") && out.contains("1 (disabled or not applied)"),
        "{out}"
    );
    assert!(out.contains("Mode:") && out.contains("Desktop"), "{out}");
    assert!(out.contains("Auto-revert:"), "{out}");
    assert!(out.contains("Boot config:"), "{out}");
    // Honest about the kernel: it is not read, and the user is told how to
    assert!(
        out.contains("not checked") && out.contains("sudo nft list table inet drfw"),
        "{out}"
    );
}

#[test]
fn test_cli_status_flags_blocking_invalid_rules() {
    let root = tempfile::tempdir().unwrap();
    let mut ruleset = create_test_ruleset();
    ruleset.rules.push(create_test_rule("Broken", Some(0)));
    write_profile(root.path(), "default", &ruleset);

    let output = run_drfw(root.path(), &["status"]);
    let out = stdout_of(&output);
    assert!(output.status.success(), "{}", all_output(&output));
    assert!(out.contains("cannot be applied"), "{out}");
}

#[test]
fn test_cli_status_without_profile_still_succeeds() {
    let root = tempfile::tempdir().unwrap();
    let output = run_drfw(root.path(), &["status"]);
    let out = stdout_of(&output);
    assert!(output.status.success(), "{}", all_output(&output));
    assert!(out.contains("profile cannot be loaded"), "{out}");
}

#[test]
fn test_cli_check_valid_profile_exits_zero() {
    let root = tempfile::tempdir().unwrap();
    write_profile(root.path(), "web", &create_test_ruleset());

    let output = run_drfw(root.path(), &["check", "web"]);
    assert!(output.status.success(), "{}", all_output(&output));
    assert!(
        stdout_of(&output).contains("nft accepts"),
        "{}",
        all_output(&output)
    );
}

#[test]
fn test_cli_check_invalid_enabled_rule_fails_without_running_nft() {
    let root = tempfile::tempdir().unwrap();
    let mut ruleset = create_test_ruleset();
    ruleset.rules.push(create_test_rule("Broken", Some(0)));
    write_profile(root.path(), "web", &ruleset);

    // `false` as nft: if the check reached nft, the message would differ
    let output = run_drfw_with_nft(root.path(), "false", &["check", "web"]);
    let all = all_output(&output);
    assert_eq!(output.status.code(), Some(1), "{all}");
    assert!(
        all.contains("cannot be applied") && all.contains("Broken"),
        "{all}"
    );
    assert!(!all.contains("nft rejected"), "{all}");
}

#[test]
fn test_cli_check_invalid_disabled_rule_only_warns() {
    let root = tempfile::tempdir().unwrap();
    let mut ruleset = create_test_ruleset();
    let mut broken = create_test_rule("Broken", Some(0));
    broken.enabled = false;
    ruleset.rules.push(broken);
    write_profile(root.path(), "web", &ruleset);

    let output = run_drfw(root.path(), &["check", "web"]);
    let all = all_output(&output);
    assert!(output.status.success(), "{all}");
    assert!(all.contains("none of them would be applied"), "{all}");
}

#[test]
fn test_cli_check_nft_refusal_fails() {
    let root = tempfile::tempdir().unwrap();
    write_profile(root.path(), "web", &create_test_ruleset());

    let output = run_drfw_with_nft(root.path(), "false", &["check", "web"]);
    let all = all_output(&output);
    assert_eq!(output.status.code(), Some(1), "{all}");
    assert!(all.contains("nft rejected"), "{all}");
}

#[test]
fn test_cli_check_missing_profile_fails() {
    let root = tempfile::tempdir().unwrap();
    let output = run_drfw(root.path(), &["check", "nope"]);
    assert_eq!(output.status.code(), Some(1), "{}", all_output(&output));
}

// ============================================================================
// Boot persistence: fake `systemctl`, the save script's enable step, `drfw
// status` and `drfw print-service-unit`
// ============================================================================

/// A fake `systemctl` for the save script and the boot status query.
///
/// It appends its arguments to `<dir>/calls`. `is-enabled <unit>` prints the
/// content of `<dir>/state-<unit>` (else `not-found`), `is-active` prints
/// `inactive`, and `enable` succeeds unless `<dir>/enable-fails` exists.
const FAKE_SYSTEMCTL: &str = r#"#!/bin/sh
dir=$(dirname "$0")
printf '%s\n' "$*" >> "$dir/calls"
case $1 in
    enable)
        if [ -e "$dir/enable-fails" ]; then
            echo "Failed to enable unit: Unit $3 is masked." >&2
            exit 1
        fi
        exit 0 ;;
    is-enabled)
        if [ -e "$dir/state-$2" ]; then
            cat "$dir/state-$2"
        else
            echo not-found
        fi
        exit 1 ;;
    is-active)
        echo inactive
        exit 3 ;;
esac
exit 1
"#;

/// Writes the fake `systemctl` into `dir` (created if missing).
fn install_fake_systemctl(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join("systemctl");
    std::fs::write(&path, FAKE_SYSTEMCTL).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Creates a directory holding only the fake `systemctl`.
fn fake_systemctl_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    install_fake_systemctl(dir.path());
    dir
}

/// `PATH` with `dir` first, so `systemctl` resolves to the fake one.
fn path_with(dir: &std::path::Path) -> String {
    format!("{}:{}", dir.display(), env::var("PATH").unwrap_or_default())
}

/// The fake `systemctl`'s recorded calls, one per line.
fn systemctl_calls(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("calls"))
        .unwrap_or_default()
        .lines()
        .map(ToString::to_string)
        .collect()
}

/// Runs the save script (mock nft, unelevated) with the fake `systemctl` first
/// on the child's `PATH`. Only the child's environment is changed, so tests
/// running in parallel are not affected.
async fn run_save_script(
    content: &str,
    target: &str,
    service: Option<&str>,
    fake_bin: &std::path::Path,
) -> std::process::Output {
    use tokio::io::AsyncWriteExt;
    setup_mock_nft();
    let save = drfw::elevation::create_elevated_save_config_command(target, service).unwrap();
    // Without the helper the script reads the rendered text
    assert_eq!(save.input, drfw::elevation::SaveConfigInput::Text);
    let mut command = save.command;
    let mut child = command
        .env("PATH", path_with(fake_bin))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // The script exits without reading stdin when it rejects its arguments
    if let Err(e) = stdin.write_all(content.as_bytes()).await {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    drop(stdin);
    child.wait_with_output().await.unwrap()
}

#[tokio::test]
async fn test_save_script_enables_the_service_after_saving() {
    use drfw::core::system_config::{EnableOutcome, enable_outcome_from_output};
    if !script_paths_usable() {
        return;
    }

    let bin = fake_systemctl_dir();
    let dir = tempfile::tempdir().unwrap();
    // A missing directory (e.g. a custom DRFW_SYSTEM_NFT_PATH) is created
    let target = dir.path().join("etc-drfw").join("rules.nft");
    let target_str = target.to_str().unwrap();
    let text = create_test_ruleset().to_nft_text();

    let output = run_save_script(&text, target_str, Some("nftables.service"), bin.path()).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), text);
    assert_eq!(
        enable_outcome_from_output(&output),
        Some(EnableOutcome::Enabled)
    );
    // enable, never start (that would reload the rules mid-session)
    assert_eq!(systemctl_calls(bin.path()), ["enable -- nftables.service"]);

    // A failure to enable is a warning: the file is saved, exit status 0
    std::fs::write(bin.path().join("enable-fails"), "").unwrap();
    let output = run_save_script(&text, target_str, Some("nftables.service"), bin.path()).await;
    assert!(output.status.success());
    assert_eq!(
        enable_outcome_from_output(&output),
        Some(EnableOutcome::Failed(
            "Failed to enable unit: Unit nftables.service is masked.".to_string()
        ))
    );
    assert_eq!(
        drfw::core::system_config::backup_path_from_output(&output),
        Some(dir.path().join("etc-drfw").join("rules.nft.drfw-bak"))
    );
    assert_eq!(systemctl_calls(bin.path()).len(), 2);
}

#[tokio::test]
async fn test_save_script_skips_systemctl_without_a_service_or_a_save() {
    if !script_paths_usable() {
        return;
    }
    let bin = fake_systemctl_dir();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("nftables.conf");
    let target_str = target.to_str().unwrap();
    let text = create_test_ruleset().to_nft_text();

    // No service: saved, systemctl never called, no enable line
    let output = run_save_script(&text, target_str, None, bin.path()).await;
    assert!(output.status.success());
    assert_eq!(
        drfw::core::system_config::enable_outcome_from_output(&output),
        None
    );

    // nft rejects the file: nothing is enabled either
    let output = run_save_script(
        "not nft\n",
        target_str,
        Some("nftables.service"),
        bin.path(),
    )
    .await;
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), text);
    assert_eq!(systemctl_calls(bin.path()), Vec::<String>::new());
}

// ============================================================================
// Argument validation of the root scripts (run unelevated, nothing elevated)
// ============================================================================

/// Runs `script` as `/bin/sh -c <script> <name> <args…>` in `dir` with
/// `stdin`, `PATH` = `path`.
fn run_root_script(
    script: &str,
    name: &str,
    args: &[&str],
    dir: &std::path::Path,
    path: &str,
    stdin: &str,
) -> std::process::Output {
    use std::io::Write;
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .arg(name)
        .args(args)
        .current_dir(dir)
        .env("PATH", path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run /bin/sh");
    let mut input = child.stdin.take().expect("stdin");
    // The script exits without reading stdin when it rejects its arguments
    if let Err(e) = input.write_all(stdin.as_bytes()) {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    drop(input);
    child.wait_with_output().expect("wait for /bin/sh")
}

/// Everything under `dir` (relative paths, sorted).
fn tree(dir: &std::path::Path) -> Vec<String> {
    fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            out.push(path.strip_prefix(root).unwrap().display().to_string());
            if entry.file_type().unwrap().is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Asserts that the script refused its arguments: exit 1, `message` on
/// stderr, nothing created or changed under `dir`, no `systemctl` call.
fn assert_refused(
    output: &std::process::Output,
    message: &str,
    case: &str,
    dir: &std::path::Path,
    before: &[String],
) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{case}: {stderr}");
    assert!(
        stderr.contains(message),
        "{case}: expected {message:?}: {stderr}"
    );
    assert_eq!(tree(dir), before, "{case}: something was created");
}

/// `SAVE_CONFIG_SCRIPT` refuses every bad target, nft command and service
/// before touching anything (the target's directory would be created first
/// otherwise).
#[test]
fn test_save_script_rejects_bad_arguments_before_writing() {
    if !script_paths_usable() {
        return;
    }
    let bin = fake_systemctl_dir();
    let path = path_with(bin.path());
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let target = format!("{d}/sub/nftables.conf");
    let mock = mock_nft_path();
    let mock = mock.to_str().unwrap();
    let text = create_test_ruleset().to_nft_text();
    let before = tree(dir.path());

    let mut cases: Vec<([String; 3], &str)> = Vec::new();
    for bad in [
        "relative/nftables.conf".to_string(),
        String::new(),
        format!("{d}/sub/../nftables.conf"),
        format!("{d}/../nftables.conf"),
        format!("{d}/sub/a b.conf"),
        format!("{d}/sub/x$y.conf"),
        format!("{d}/sub/x;id"),
        format!("{d}/sub/x\nnftables.conf"),
    ] {
        cases.push(([bad, mock.into(), String::new()], "invalid target path"));
    }
    for bad in [
        "relative/nft".to_string(),
        String::new(),
        "nft;id".into(),
        "/usr/bin/n ft".into(),
        format!("{d}/../nft"),
        "/usr/sbin/nft$x".into(),
    ] {
        cases.push(([target.clone(), bad, String::new()], "invalid nft command"));
    }
    for bad in [
        "-nftables.service",
        ".nftables.service",
        "nftables",
        ".service",
        "nft;id.service",
        "nft tables.service",
        "nft$x.service",
        "nftables.socket",
        "../nftables.service",
    ] {
        cases.push((
            [target.clone(), mock.into(), bad.into()],
            "invalid service name",
        ));
    }

    for (args, message) in &cases {
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = run_root_script(
            drfw::elevation::SAVE_CONFIG_SCRIPT,
            "drfw-save-config",
            &argv,
            dir.path(),
            &path,
            &text,
        );
        assert_refused(&output, message, &format!("{argv:?}"), dir.path(), &before);
    }
    assert_eq!(systemctl_calls(bin.path()), Vec::<String>::new());

    // The valid arguments of the cases above do work
    let output = run_root_script(
        drfw::elevation::SAVE_CONFIG_SCRIPT,
        "drfw-save-config",
        &[&target, mock, ""],
        dir.path(),
        &path,
        &text,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), text);
}

/// Valid `APPLY_SCRIPT` arguments under `dir` (state dir `<dir>/state`),
/// nft = the mock.
fn valid_apply_args(dir: &str) -> [String; 7] {
    let uid = nix::unistd::getuid().as_raw();
    [
        format!("{dir}/state"),
        "1".into(),
        "0123456789abcdef0123456789abcdef".into(),
        format!("{dir}/confirm"),
        mock_nft_path().to_str().unwrap().into(),
        "setsid".into(),
        uid.to_string(),
    ]
}

/// `APPLY_SCRIPT` refuses every bad argument (exit 1, its message) before it
/// creates anything: no state dir, no lock, no guard.
#[test]
fn test_apply_script_rejects_bad_arguments_before_anything() {
    if !script_paths_usable() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let json = create_test_ruleset().to_nftables_json().to_string();
    let path = env::var("PATH").unwrap_or_default();
    let before = tree(dir.path());

    #[rustfmt::skip]
    let bad: &[(usize, &str, &str)] = &[
        (0, "relative/state", "invalid state directory"),
        (0, "", "invalid state directory"),
        (0, "{d}/a b", "invalid state directory"),
        (0, "{d}/x/../state", "invalid state directory"),
        (0, "{d}/$x", "invalid state directory"),
        (1, "", "invalid timeout"),
        (1, "1a", "invalid timeout"),
        (1, "-1", "invalid timeout"),
        (1, " 1", "invalid timeout"),
        (1, "3601", "timeout too long"),
        (1, "12345", "timeout too long"),
        (1, "00001", "timeout too long"),
        (2, "0123456789abcdef0123456789abcde", "invalid nonce"),
        (2, "0123456789abcdef0123456789abcdef0", "invalid nonce"),
        (2, "0123456789ABCDEF0123456789ABCDEF", "invalid nonce"),
        (2, "g123456789abcdef0123456789abcdef", "invalid nonce"),
        (2, "", "invalid nonce"),
        (3, "confirm", "invalid confirmation directory"),
        (3, "{d}/../confirm", "invalid confirmation directory"),
        (3, "{d}/c f", "invalid confirmation directory"),
        (4, "relative/nft", "invalid nft command"),
        (4, "nft;id", "invalid nft command"),
        (4, "/usr/bin/n ft", "invalid nft command"),
        (4, "{d}/../nft", "invalid nft command"),
        (4, "", "invalid nft command"),
        (5, "systemd", "invalid watcher launcher"),
        (5, "", "invalid watcher launcher"),
        (6, "", "invalid uid"),
        (6, "1a", "invalid uid"),
        (6, "-1", "invalid uid"),
        (6, "12345678901", "invalid uid"),
    ];
    for &(index, value, message) in bad {
        let mut owned = valid_apply_args(d);
        owned[index] = value.replace("{d}", d);
        let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
        let output = run_root_script(
            drfw::elevation::APPLY_SCRIPT,
            "drfw-apply",
            &argv,
            dir.path(),
            &path,
            &json,
        );
        assert_refused(&output, message, &format!("{argv:?}"), dir.path(), &before);
    }
}

/// `APPLY_SCRIPT` refuses a state dir that is not a real directory owned by
/// the caller and closed to others, before taking its lock or writing in it.
#[test]
fn test_apply_script_rejects_unsafe_state_dirs() {
    use std::os::unix::fs::PermissionsExt;
    if !script_paths_usable() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let json = create_test_ruleset().to_nftables_json().to_string();
    let path = env::var("PATH").unwrap_or_default();
    let refuse = |state: &str, message: &str| {
        let before = tree(dir.path());
        let mut owned = valid_apply_args(d);
        owned[0] = state.to_string();
        let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
        let output = run_root_script(
            drfw::elevation::APPLY_SCRIPT,
            "drfw-apply",
            &argv,
            dir.path(),
            &path,
            &json,
        );
        assert_refused(&output, message, state, dir.path(), &before);
    };
    let owned_only = "must be a directory owned by";

    let shared = dir.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    for mode in [0o775, 0o757, 0o777] {
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(mode)).unwrap();
        refuse(shared.to_str().unwrap(), owned_only);
    }
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    refuse(link.to_str().unwrap(), owned_only);
    let file = dir.path().join("file");
    std::fs::write(&file, "").unwrap();
    refuse(file.to_str().unwrap(), "cannot create");
    // Owned by someone else (root): refused before anything is written there
    // (as root, `/` would be accepted, so not as root)
    if !nix::unistd::getuid().is_root() {
        let before = tree(dir.path());
        let mut owned = valid_apply_args(d);
        owned[0] = "/".into();
        let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
        let output = run_root_script(
            drfw::elevation::APPLY_SCRIPT,
            "drfw-apply",
            &argv,
            dir.path(),
            &path,
            &json,
        );
        assert_refused(&output, owned_only, "/", dir.path(), &before);
    }
}

/// Runs `drfw status` with `path` as `PATH`.
fn run_drfw_status_with_path(root: &std::path::Path, path: &str) -> String {
    let output = drfw_command(root, mock_nft_path())
        .arg("status")
        .env("PATH", path)
        .output()
        .expect("run drfw");
    assert!(output.status.success(), "{}", all_output(&output));
    stdout_of(&output)
}

/// The "Boot persistence" line of `drfw status` output.
fn boot_persistence_line(out: &str) -> &str {
    out.lines()
        .find(|line| line.starts_with("Boot persistence:"))
        .unwrap_or_else(|| panic!("no boot persistence line in\n{out}"))
}

#[test]
fn test_cli_status_reports_boot_persistence() {
    let service = drfw::SYSTEM_NFT_SERVICE;
    let bundled = drfw::distro::BUNDLED_SERVICE;
    let root = tempfile::tempdir().unwrap();
    let bin = fake_systemctl_dir();
    let path = path_with(bin.path());
    let state = |unit: &str, value: &str| {
        std::fs::write(
            bin.path().join(format!("state-{unit}")),
            format!("{value}\n"),
        )
        .unwrap();
    };

    state(service, "disabled");
    let out = run_drfw_status_with_path(root.path(), &path);
    assert!(
        boot_persistence_line(&out).ends_with(&format!(
            "{service} is disabled: the rules will NOT load at boot"
        )),
        "{out}"
    );
    let calls = systemctl_calls(bin.path());
    assert!(
        calls.contains(&format!("is-enabled {service}")),
        "{calls:?}"
    );
    assert!(calls.contains(&format!("is-active {service}")), "{calls:?}");

    // drfw.service loads the same file: it counts when the service is not enabled
    if service != bundled {
        state(bundled, "enabled");
        let out = run_drfw_status_with_path(root.path(), &path);
        assert!(
            boot_persistence_line(&out).ends_with(&format!("Loaded at boot by {bundled}")),
            "{out}"
        );
    }

    state(service, "enabled");
    let out = run_drfw_status_with_path(root.path(), &path);
    assert!(
        boot_persistence_line(&out).ends_with(&format!("Loaded at boot by {service}")),
        "{out}"
    );

    if service != bundled {
        std::fs::remove_file(bin.path().join(format!("state-{bundled}"))).unwrap();
    }
    state(service, "masked");
    let out = run_drfw_status_with_path(root.path(), &path);
    assert!(boot_persistence_line(&out).contains("is masked"), "{out}");
}

#[test]
fn test_cli_status_without_systemctl() {
    let root = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let out = run_drfw_status_with_path(root.path(), empty.path().to_str().unwrap());
    assert!(
        boot_persistence_line(&out).contains("systemd is not available"),
        "{out}"
    );
}

#[test]
fn test_cli_print_service_unit() {
    // Runs at package time: prints the unit and creates no data directories
    let home = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_drfw"))
        .arg("print-service-unit")
        .env_remove("DRFW_TEST_DATA_DIR")
        .env_remove("DRFW_TEST_STATE_DIR")
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path().join("data"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .output()
        .expect("run drfw");
    assert!(output.status.success(), "{}", all_output(&output));
    let unit = stdout_of(&output);
    assert_eq!(unit, drfw::distro::service_unit());
    assert!(unit.contains(&format!(
        "ExecStart={} -f {}\n",
        drfw::distro::UNIT_NFT_PATH,
        drfw::SYSTEM_NFT_PATH
    )));
    assert!(
        !unit.contains("@SYSTEM_NFT_PATH@") && !unit.contains("@NFT_PATH@"),
        "placeholder left:\n{unit}"
    );
    assert_eq!(
        std::fs::read_dir(home.path()).unwrap().count(),
        0,
        "print-service-unit must not create data directories"
    );

    // Hidden from --help: it is for packagers
    let help = std::process::Command::new(env!("CARGO_BIN_EXE_drfw"))
        .arg("--help")
        .output()
        .expect("run drfw");
    assert!(!stdout_of(&help).contains("print-service-unit"));
}

// ============================================================================
// `drfw save`: CLI Save to System (mock nft, fake `systemctl`, temp target)
// ============================================================================

/// Runs `drfw save <args>` against `root` with the mock nft, the fake
/// `systemctl` first on `PATH`, stdin closed (not a terminal) and the target
/// redirected to `<root>/nftables.conf`.
fn run_drfw_save(
    root: &std::path::Path,
    fake_bin: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    run_drfw_save_with(root, fake_bin, args, &[])
}

/// [`run_drfw_save`] with extra environment variables for the child only.
fn run_drfw_save_with(
    root: &std::path::Path,
    fake_bin: &std::path::Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> std::process::Output {
    drfw_command(root, mock_nft_path())
        .arg("save")
        .args(args)
        .env("DRFW_TEST_SYSTEM_NFT_PATH", root.join("nftables.conf"))
        .env("PATH", path_with(fake_bin))
        .envs(env.iter().copied())
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run drfw")
}

/// A profile `web` under `root` and its ruleset.
fn save_fixture(root: &std::path::Path) -> FirewallRuleset {
    let ruleset = create_test_ruleset();
    write_profile(root, "web", &ruleset);
    ruleset
}

#[test]
fn test_cli_save_refuses_unconfirmed_rules_without_yes() {
    if !script_paths_usable() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let bin = fake_systemctl_dir();
    save_fixture(root.path());

    let output = run_drfw_save(root.path(), bin.path(), &["web"]);
    assert_eq!(output.status.code(), Some(7), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(out.contains("not the one last applied and kept"), "{out}");
    assert!(out.contains("WITHOUT a dead-man switch"), "{out}");
    assert!(out.contains("drfw apply web"), "{out}");
    assert!(!root.path().join("nftables.conf").exists());
    assert_eq!(systemctl_calls(bin.path()), Vec::<String>::new());
}

#[test]
fn test_cli_save_with_yes_saves_and_warns_about_boot() {
    if !script_paths_usable() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let bin = fake_systemctl_dir();
    let ruleset = save_fixture(root.path());
    std::fs::write(
        bin.path()
            .join(format!("state-{}", drfw::SYSTEM_NFT_SERVICE)),
        "disabled\n",
    )
    .unwrap();

    let output = run_drfw_save(root.path(), bin.path(), &["web", "--yes"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(
        out.contains("not the one last applied and kept"),
        "the warning is still shown: {out}"
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("nftables.conf")).unwrap(),
        ruleset.to_nft_text()
    );
    // Not asked to enable: warns that the rules will not load at boot
    assert!(out.contains("will NOT load at boot"), "{out}");
    assert!(out.contains("--enable-at-boot"), "{out}");
    assert!(
        !systemctl_calls(bin.path())
            .iter()
            .any(|c| c.starts_with("enable")),
        "{:?}",
        systemctl_calls(bin.path())
    );
}

#[test]
fn test_cli_save_enable_at_boot() {
    if !script_paths_usable() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let bin = fake_systemctl_dir();
    save_fixture(root.path());
    std::fs::write(
        bin.path()
            .join(format!("state-{}", drfw::SYSTEM_NFT_SERVICE)),
        "disabled\n",
    )
    .unwrap();

    let output = run_drfw_save(
        root.path(),
        bin.path(),
        &["web", "--yes", "--enable-at-boot"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    assert!(
        systemctl_calls(bin.path())
            .iter()
            .any(|c| *c == format!("enable -- {}", drfw::SYSTEM_NFT_SERVICE)),
        "{:?}",
        systemctl_calls(bin.path())
    );

    // Enabling fails: saved anyway, distinct exit code
    std::fs::write(bin.path().join("enable-fails"), "").unwrap();
    let output = run_drfw_save(
        root.path(),
        bin.path(),
        &["web", "--yes", "--enable-at-boot"],
    );
    assert_eq!(output.status.code(), Some(8), "{}", all_output(&output));
    assert!(all_output(&output).contains("was not enabled"));
    assert!(root.path().join("nftables.conf.drfw-bak").exists());
}

/// A ruleset confirmed under the guard, recorded by an older DRFW (the bare
/// nftables JSON; now written by `GuardHandle::wait_outcome` in the record
/// format), saves without --yes and without the warning.
#[test]
fn test_cli_save_confirmed_rules_need_no_yes() {
    if !script_paths_usable() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let bin = fake_systemctl_dir();
    let ruleset = save_fixture(root.path());
    std::fs::write(
        root.path().join("confirmed-ruleset.json"),
        serde_json::to_vec(&ruleset.to_nftables_json()).unwrap(),
    )
    .unwrap();

    let output = run_drfw_save(root.path(), bin.path(), &["web"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(out.contains("was applied and kept (confirmed)"), "{out}");
    assert!(out.contains("earlier session"), "no boot id: {out}");
    assert!(!out.contains("not the one last applied"), "{out}");
    assert!(root.path().join("nftables.conf").exists());

    // Any change to the profile makes it "not confirmed" again
    let mut changed = ruleset;
    changed.rules.push(create_test_rule("New", Some(8080)));
    write_profile(root.path(), "web", &changed);
    let output = run_drfw_save(root.path(), bin.path(), &["web"]);
    assert_eq!(output.status.code(), Some(7), "{}", all_output(&output));
}

/// Runs `drfw apply <args>` against `root` (mock nft, private runtime dir,
/// guard state under `root`, stdin closed: not a terminal).
fn run_drfw_apply(root: &std::path::Path, args: &[&str]) -> std::process::Output {
    run_drfw_apply_with(root, args, &[])
}

/// [`run_drfw_apply`] with extra environment variables for the child only.
fn run_drfw_apply_with(
    root: &std::path::Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> std::process::Output {
    use std::os::unix::fs::PermissionsExt;
    let runtime = root.join("run");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    drfw_command(root, mock_nft_path())
        .arg("apply")
        .args(args)
        .env("DRFW_GUARD_STATE_DIR", root.join("guard"))
        .env("XDG_RUNTIME_DIR", &runtime)
        .envs(env.iter().copied())
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run drfw")
}

/// A profile `web` with `count` rules under `root`.
fn web_profile_with(root: &std::path::Path, count: u16) -> FirewallRuleset {
    let mut ruleset = FirewallRuleset::new();
    for i in 0..count {
        ruleset
            .rules
            .push(create_test_rule(&format!("svc{i}"), Some(8000 + i)));
    }
    write_profile(root, "web", &ruleset);
    ruleset
}

/// `drfw apply --no-confirm` keeps the rules at once: it writes the record
/// (like the GUI with auto-revert off), so `drfw save` treats them as tested
/// and says how they were kept.
#[test]
fn test_cli_unguarded_apply_is_recorded_for_save() {
    if !script_paths_usable() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let bin = fake_systemctl_dir();
    let ruleset = web_profile_with(root.path(), 2);

    let output = run_drfw_apply(root.path(), &["web", "--no-confirm"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let record =
        drfw::core::confirmed::ConfirmedRecord::load_from_blocking(root.path()).expect("recorded");
    assert_eq!(record.kind(), drfw::core::confirmed::RecordKind::Unguarded);
    assert!(record.matches(&ruleset.to_nftables_json()));

    let output = run_drfw_save(root.path(), bin.path(), &["web"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(
        out.contains("applied and kept (without auto-revert)"),
        "{out}"
    );
    assert!(!out.contains("earlier session"), "same boot: {out}");
}

/// The retention guard: removing most of the kept rules needs --yes off a
/// terminal (exit 9, nothing applied); small changes pass.
#[test]
fn test_cli_apply_retention_guard() {
    if !script_paths_usable() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let original = web_profile_with(root.path(), 5);
    let output = run_drfw_apply(root.path(), &["web", "--no-confirm"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let kept_json = original.to_nftables_json();

    // 2 of 5 disabled: below the threshold
    let mut ruleset = original.clone();
    ruleset.rules[0].enabled = false;
    ruleset.rules[1].enabled = false;
    write_profile(root.path(), "web", &ruleset);
    let output = run_drfw_apply(root.path(), &["web", "--no-confirm"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    assert!(!all_output(&output).contains("big change"));

    // Back to the 5 kept (re-enabling is no removal), then 3 of 5 removed
    let mut ruleset = original;
    write_profile(root.path(), "web", &ruleset);
    let output = run_drfw_apply(root.path(), &["web", "--no-confirm"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    ruleset.rules.truncate(2);
    write_profile(root.path(), "web", &ruleset);
    let output = run_drfw_apply(root.path(), &["web", "--no-confirm"]);
    assert_eq!(output.status.code(), Some(9), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(out.contains("Removes 3 of the 5 enabled rules"), "{out}");
    assert!(out.contains("\"svc2\", \"svc3\", \"svc4\""), "{out}");
    assert!(out.contains("pass --yes"), "{out}");
    assert!(!out.contains("Applying ruleset"), "{out}");
    let record =
        drfw::core::confirmed::ConfirmedRecord::load_from_blocking(root.path()).expect("recorded");
    assert!(
        record.matches(&kept_json),
        "nothing applied, record unchanged"
    );

    let output = run_drfw_apply(root.path(), &["web", "--no-confirm", "--yes"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    assert!(all_output(&output).contains("big change"), "still shown");

    // Server mode needs a confirmation even without removals
    ruleset.advanced_security.egress_profile = drfw::core::firewall::EgressProfile::Server;
    write_profile(root.path(), "web", &ruleset);
    let output = run_drfw_apply(root.path(), &["web", "--no-confirm"]);
    assert_eq!(output.status.code(), Some(9), "{}", all_output(&output));
    assert!(all_output(&output).contains("Server Mode"));
}

/// `drfw save` shows the retention warning too; --yes covers it.
#[test]
fn test_cli_save_retention_guard() {
    if !script_paths_usable() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let bin = fake_systemctl_dir();
    let mut ruleset = web_profile_with(root.path(), 4);
    let output = run_drfw_apply(root.path(), &["web", "--no-confirm"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));

    ruleset.advanced_security.block_forwarding = true;
    ruleset.rules.truncate(1);
    write_profile(root.path(), "web", &ruleset);
    let output = run_drfw_save(root.path(), bin.path(), &["web"]);
    assert_eq!(output.status.code(), Some(7), "{}", all_output(&output));
    assert!(!root.path().join("nftables.conf").exists());

    let output = run_drfw_save(root.path(), bin.path(), &["web", "--yes"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(out.contains("Removes 3 of the 4 enabled rules"), "{out}");
    assert!(out.contains("Blocks forwarded traffic"), "{out}");
    assert!(root.path().join("nftables.conf").exists());
}

// ============================================================================
// SSH lockout check and `drfw exposure` (SSH_CONNECTION and the /proc
// fixture are set on the child only)
// ============================================================================

/// An SSH session from 10.0.0.5 to port 22 of 10.0.0.1.
const SSH_SESSION: (&str, &str) = ("SSH_CONNECTION", "10.0.0.5 50000 10.0.0.1 22");

/// `drfw apply` from an SSH session refuses rules that would block a new
/// connection from the session's client: exit 9 off a terminal, nothing
/// applied; --yes goes ahead; a rule for SSH needs no confirmation.
#[test]
fn test_cli_apply_lockout_check() {
    if !script_paths_usable() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ruleset = web_profile_with(root.path(), 2);
    let output = run_drfw_apply_with(root.path(), &["web", "--no-confirm"], &[SSH_SESSION]);
    assert_eq!(output.status.code(), Some(9), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(out.contains("could lock you out of SSH"), "{out}");
    assert!(
        out.contains("You are connected from 10.0.0.5 to port 22"),
        "{out}"
    );
    assert!(out.contains("BLOCKED: rejected by"), "{out}");
    assert!(out.contains("Open sessions stay connected"), "{out}");
    assert!(out.contains("not applied: pass --yes"), "{out}");
    assert!(!out.contains("Applying ruleset"), "{out}");
    assert!(
        drfw::core::confirmed::ConfirmedRecord::load_from_blocking(root.path()).is_none(),
        "nothing applied"
    );

    let output = run_drfw_apply_with(
        root.path(),
        &["web", "--no-confirm", "--yes"],
        &[SSH_SESSION],
    );
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    assert!(all_output(&output).contains("could lock you out of SSH"));
    let record =
        drfw::core::confirmed::ConfirmedRecord::load_from_blocking(root.path()).expect("applied");
    assert!(record.matches(&ruleset.to_nftables_json()));

    // Allowing SSH: no question
    let mut with_ssh = ruleset.clone();
    with_ssh.rules.push(create_test_rule("SSH", Some(22)));
    write_profile(root.path(), "web", &with_ssh);
    let output = run_drfw_apply_with(root.path(), &["web", "--no-confirm"], &[SSH_SESSION]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    assert!(!all_output(&output).contains("lock you out"));

    // Without a session (and no /proc sessions) there is nothing to check
    write_profile(root.path(), "web", &ruleset);
    let output = run_drfw_apply(root.path(), &["web", "--no-confirm"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    assert!(!all_output(&output).contains("lock you out"));
}

/// A rate-limited SSH accept (the recommended setup) is a note: printed,
/// no question, no exit 9, applied; `drfw save` is the same.
#[test]
fn test_cli_limited_ssh_is_a_note() {
    if !script_paths_usable() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut ruleset = FirewallRuleset::new();
    let mut ssh = create_test_rule("SSH", Some(22));
    ssh.rate_limit = Some(drfw::core::firewall::RateLimit {
        count: 3,
        unit: drfw::core::firewall::TimeUnit::Minute,
        burst: None,
        per_source: true,
    });
    ruleset.rules.push(ssh);
    write_profile(root.path(), "web", &ruleset);

    let output = run_drfw_apply_with(root.path(), &["web", "--no-confirm"], &[SSH_SESSION]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(
        out.contains("New SSH connections are limited by these rules:"),
        "{out}"
    );
    assert!(
        out.contains(
            "new connections from 10.0.0.5 would be accepted up to 3/minute per source by \
             rule \"SSH\"; more are turned away"
        ),
        "{out}"
    );
    assert!(!out.contains("lock you out"), "{out}");
    assert!(!out.contains("--yes"), "{out}");
    assert!(
        drfw::core::confirmed::ConfirmedRecord::load_from_blocking(root.path()).is_some(),
        "applied"
    );

    let bin = fake_systemctl_dir();
    let output = run_drfw_save_with(root.path(), bin.path(), &["web"], &[SSH_SESSION]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    assert!(all_output(&output).contains("New SSH connections are limited"));
    assert!(root.path().join("nftables.conf").exists());
}

/// "SSH on eth0 only": the session's server address (10.0.0.1) on eth0
/// allows it without a question; on another interface it is blocked (exit
/// 9, the guess named); with no interface having it, "blocked in some
/// cases" (exit 9). The interface addresses come from the fixture file in
/// `DRFW_TEST_PROC_DIR`, never from the machine.
#[test]
fn test_cli_interface_bound_ssh_uses_the_session_interface() {
    if !script_paths_usable() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut ruleset = FirewallRuleset::new();
    let mut ssh = create_test_rule("SSH on eth0", Some(22));
    ssh.interface = Some("eth0".into());
    ruleset.rules.push(ssh);
    write_profile(root.path(), "web", &ruleset);
    let proc = root.path().join("addrs");
    std::fs::create_dir_all(&proc).unwrap();
    let addresses = proc.join(drfw::core::lockout::TEST_ADDRESSES_FILE);
    let proc_env = ("DRFW_TEST_PROC_DIR", proc.to_str().unwrap());

    std::fs::write(
        &addresses,
        "lo 127.0.0.1\neth0 10.0.0.1\nwlan0 192.168.1.20\n",
    )
    .unwrap();
    let output = run_drfw_apply_with(
        root.path(),
        &["web", "--no-confirm"],
        &[SSH_SESSION, proc_env],
    );
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(!out.contains("lock you out"), "{out}");
    assert!(!out.contains("New SSH connections are limited"), "{out}");

    std::fs::write(&addresses, "eth0 192.168.1.20\nwlan0 10.0.0.1\n").unwrap();
    let output = run_drfw_apply_with(
        root.path(),
        &["web", "--no-confirm"],
        &[SSH_SESSION, proc_env],
    );
    assert_eq!(output.status.code(), Some(9), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(out.contains("could lock you out of SSH"), "{out}");
    assert!(out.contains("BLOCKED: rejected by"), "{out}");
    assert!(
        out.contains("(assuming they arrive on wlan0, the interface that has 10.0.0.1)"),
        "{out}"
    );

    // Ambiguous (two interfaces have it): unknown, blocked in some cases
    std::fs::write(&addresses, "eth0 10.0.0.1\nbr0 10.0.0.1\n").unwrap();
    let output = run_drfw_apply_with(
        root.path(),
        &["web", "--no-confirm"],
        &[SSH_SESSION, proc_env],
    );
    assert_eq!(output.status.code(), Some(9), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(out.contains("blocked in some cases"), "{out}");
    assert!(!out.contains("assuming they arrive"), "{out}");
}

/// `drfw save` runs the same check (the saved rules load at the next boot).
#[test]
fn test_cli_save_lockout_check() {
    if !script_paths_usable() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let bin = fake_systemctl_dir();
    web_profile_with(root.path(), 1);
    // Applied and kept (so the save is "tested"), from outside the session
    let output = run_drfw_apply(root.path(), &["web", "--no-confirm"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));

    let output = run_drfw_save_with(root.path(), bin.path(), &["web"], &[SSH_SESSION]);
    assert_eq!(output.status.code(), Some(9), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(out.contains("could lock you out of SSH"), "{out}");
    assert!(out.contains("not saved: pass --yes"), "{out}");
    assert!(!root.path().join("nftables.conf").exists());

    let output = run_drfw_save_with(root.path(), bin.path(), &["web", "--yes"], &[SSH_SESSION]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    assert!(root.path().join("nftables.conf").exists());
}

/// Runs `drfw <args>` with `proc` as `/proc` and extra environment.
fn run_drfw_in_proc(
    root: &std::path::Path,
    proc: &std::path::Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> std::process::Output {
    drfw_command(root, mock_nft_path())
        .args(args)
        .env("DRFW_TEST_PROC_DIR", proc)
        .envs(env.iter().copied())
        .output()
        .expect("run drfw")
}

/// A `/proc` fixture: root's server listening on TCP 22 with an established
/// connection from 10.0.0.5, and nginx (pid 4242, readable) on TCP 8080.
/// Addresses in host byte order (little-endian).
fn proc_fixture(dir: &std::path::Path) {
    use std::os::unix::fs::symlink;
    let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 900001 1 0 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 900002 1 0 100 0 0 10 0
   2: 0100000A:0016 0500000A:C350 01 00000000:00000000 02:000A7E2F 00000000     0        0 900003 2 0 20 4 29 10 -1
";
    std::fs::create_dir_all(dir.join("net")).unwrap();
    std::fs::write(dir.join("net/tcp"), tcp).unwrap();
    std::fs::create_dir_all(dir.join("4242/fd")).unwrap();
    std::fs::write(dir.join("4242/comm"), "nginx\n").unwrap();
    symlink("socket:[900002]", dir.join("4242/fd/5")).unwrap();
}

/// A profile `web` allowing TCP 8080 from everyone.
fn exposure_profile(root: &std::path::Path) {
    let mut ruleset = FirewallRuleset::new();
    ruleset.rules.push(create_test_rule("Web", Some(8080)));
    write_profile(root, "web", &ruleset);
}

#[cfg(target_endian = "little")]
#[test]
fn test_cli_exposure_table() {
    let root = tempfile::tempdir().unwrap();
    let proc = root.path().join("proc");
    proc_fixture(&proc);
    exposure_profile(root.path());

    let output = run_drfw_in_proc(root.path(), &proc, &["exposure", "web"], &[]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let out = stdout_of(&output);
    assert!(out.contains("profile 'web'"), "{out}");
    let lines: Vec<&str> = out.lines().collect();
    let header = lines
        .iter()
        .position(|l| l.starts_with("PORT"))
        .expect("header");
    for column in ["FAMILY", "PROCESS", "BIND", "REACHABLE FROM", "DECIDED BY"] {
        assert!(lines[header].contains(column), "{out}");
    }
    // Open to everyone first, marked in text, no escape codes off a terminal
    let web = lines[header + 1];
    assert!(web.starts_with("TCP 8080"), "{out}");
    assert!(web.contains("nginx"), "{out}");
    assert!(web.contains("OPEN TO EVERYONE: everyone"), "{out}");
    assert!(web.ends_with("rule \"Web\""), "{out}");
    let ssh = lines[header + 2];
    assert!(ssh.starts_with("TCP 22"), "{out}");
    assert!(ssh.contains("nobody"), "{out}");
    assert!(
        ssh.contains("built-in rule \"rate-limited reject\""),
        "{out}"
    );
    assert!(
        out.contains("2 listening sockets, 1 open to everyone."),
        "{out}"
    );
    // The established connection to root's port 22 is assumed SSH
    assert!(
        out.contains("SSH: a connection (assumed SSH) from 10.0.0.5 to port 22"),
        "{out}"
    );
    assert!(!out.contains('\x1b'), "{out}");

    // Missing profile: error, exit 1
    let output = run_drfw_in_proc(root.path(), &proc, &["exposure", "missing"], &[]);
    assert_eq!(output.status.code(), Some(1), "{}", all_output(&output));
    // Unreadable /proc: error, exit 1
    let output = run_drfw_in_proc(
        root.path(),
        &root.path().join("none"),
        &["exposure", "web"],
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "{}", all_output(&output));
    assert!(all_output(&output).contains("cannot read the listening sockets"));
}

#[cfg(target_endian = "little")]
#[test]
fn test_cli_exposure_json() {
    let root = tempfile::tempdir().unwrap();
    let proc = root.path().join("proc");
    proc_fixture(&proc);
    exposure_profile(root.path());
    // No name: the active profile
    std::fs::write(
        root.path().join("config.json"),
        r#"{"active_profile": "web"}"#,
    )
    .unwrap();

    let output = run_drfw_in_proc(root.path(), &proc, &["exposure", "--json"], &[SSH_SESSION]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(json["profile"], "web");
    let sockets = json["sockets"].as_array().unwrap();
    assert_eq!(sockets.len(), 2);
    let web = &sockets[0];
    for key in [
        "transport",
        "port",
        "families",
        "bind",
        "bind_display",
        "local_only",
        "uid",
        "process",
        "processes",
        "reachable_from",
        "open_to_everyone",
        "nobody",
        "decided_by",
        "decided_by_rule_id",
    ] {
        assert!(web.get(key).is_some(), "{key} missing: {web}");
    }
    assert_eq!(web["transport"], "tcp");
    assert_eq!(web["port"], 8080);
    assert_eq!(web["families"], serde_json::json!(["ipv4"]));
    assert_eq!(web["process"], "nginx");
    assert_eq!(web["processes"][0]["pid"], 4242);
    assert_eq!(web["open_to_everyone"], true);
    assert_eq!(web["decided_by"], "rule \"Web\"");
    assert_eq!(sockets[1]["port"], 22);
    assert_eq!(sockets[1]["nobody"], true);
    assert!(sockets[1]["decided_by_rule_id"].is_null());

    // The SSH_CONNECTION session and the one in /proc are the same session
    let sessions = json["ssh_sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    assert_eq!(sessions[0]["client"], "10.0.0.5");
    assert_eq!(sessions[0]["client_port"], 50000);
    assert_eq!(sessions[0]["server"], "10.0.0.1");
    assert_eq!(sessions[0]["server_port"], 22);
    assert_eq!(sessions[0]["source"], "environment");
    assert_eq!(sessions[0]["new_connections"], "blocked");
    assert!(
        sessions[0]["outcome"]
            .as_str()
            .unwrap()
            .starts_with("BLOCKED")
    );
}

/// Writes `contents` to `file` under the `/proc` fixture `dir`.
fn proc_file(dir: &std::path::Path, file: &str, contents: &[u8]) {
    let path = dir.join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// S3: Docker's published ports (from `docker-proxy` command lines in
/// `/proc`) replace the verdict in `drfw exposure` and its JSON; the
/// forwarding and container-network notices are printed when they apply.
#[cfg(target_endian = "little")]
#[test]
fn test_cli_exposure_marks_docker_published_ports() {
    let root = tempfile::tempdir().unwrap();
    let proc = root.path().join("proc");
    proc_fixture(&proc);
    exposure_profile(root.path());
    proc_file(
        &proc,
        "5000/cmdline",
        [
            "/usr/bin/docker-proxy",
            "-proto",
            "tcp",
            "-host-ip",
            "0.0.0.0",
            "-host-port",
            "8080",
            "-container-ip",
            "172.17.0.2",
            "-container-port",
            "80",
        ]
        .join("\0")
        .as_bytes(),
    );
    proc_file(&proc, "sys/net/ipv4/ip_forward", b"1\n");
    let docker_row = |out: &str| -> String {
        out.lines()
            .find(|l| l.starts_with("TCP 8080"))
            .unwrap_or_else(|| panic!("{out}"))
            .to_string()
    };

    // Not root's: a user's program named docker-proxy and a user's socket
    // must not relabel the port
    let output = run_drfw_in_proc(root.path(), &proc, &["exposure", "web"], &[]);
    assert!(
        docker_row(&stdout_of(&output)).contains("OPEN TO EVERYONE"),
        "{}",
        all_output(&output)
    );
    proc_file(
        &proc,
        "5000/status",
        b"Name:\tdocker-proxy\nUid:\t0\t0\t0\t0\n",
    );
    let output = run_drfw_in_proc(root.path(), &proc, &["exposure", "web"], &[]);
    assert!(
        docker_row(&stdout_of(&output)).contains("OPEN TO EVERYONE"),
        "a user's socket on the port: {}",
        all_output(&output)
    );
    // Docker's proxy runs as root and owns the socket
    let tcp = std::fs::read_to_string(proc.join("net/tcp")).unwrap();
    let root_owned = tcp
        .lines()
        .map(|line| {
            if line.contains(":1F90 ") {
                line.replacen("  1000  ", "     0  ", 1)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    proc_file(&proc, "net/tcp", format!("{root_owned}\n").as_bytes());

    let output = run_drfw_in_proc(root.path(), &proc, &["exposure", "web"], &[]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let out = stdout_of(&output);
    let web = docker_row(&out);
    assert!(
        web.contains("published by Docker: not filtered by DRFW's rules"),
        "{out}"
    );
    assert!(!web.contains("OPEN TO EVERYONE"), "{out}");
    assert!(
        !web.contains("rule \"Web\""),
        "not decided by a rule: {out}"
    );
    assert!(
        out.contains("2 listening sockets, 0 open to everyone, 1 published by Docker."),
        "{out}"
    );
    assert!(
        out.contains(drfw::core::host_facts::FORWARDING_WARNING),
        "{out}"
    );
    assert!(
        !out.contains(drfw::core::host_facts::CONTAINER_NETWORKS_NOTE),
        "a proxy was found: {out}"
    );

    let output = run_drfw_in_proc(root.path(), &proc, &["exposure", "web", "--json"], &[]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let web = &json["sockets"][0];
    assert_eq!(web["port"], 8080);
    assert_eq!(web["published_by_docker"], true);
    assert_eq!(web["docker_forward_filtered"], false);
    assert_eq!(web["open_to_everyone"], false);
    assert!(web["decided_by"].is_null());
    assert_eq!(json["sockets"][1]["published_by_docker"], false);
    assert_eq!(json["forwarding"]["ipv4"], true);
    assert_eq!(json["forwarding"]["filtered"], false);
    assert_eq!(
        json["notes"],
        serde_json::json!([drfw::core::host_facts::FORWARDING_WARNING])
    );

    // With "Block forwarded traffic" the Forwarded rules decide it
    let mut blocking = FirewallRuleset::new();
    blocking.rules.push(create_test_rule("Web", Some(8080)));
    blocking.advanced_security.block_forwarding = true;
    write_profile(root.path(), "blocking", &blocking);
    let output = run_drfw_in_proc(root.path(), &proc, &["exposure", "blocking"], &[]);
    let out = stdout_of(&output);
    assert!(
        docker_row(&out).contains(drfw::core::host_facts::DOCKER_PUBLISHED_FORWARD_FILTERED),
        "{out}"
    );
    assert!(
        out.contains("1 published by Docker (decided by your Forwarded rules)."),
        "{out}"
    );
    let output = run_drfw_in_proc(root.path(), &proc, &["exposure", "blocking", "--json"], &[]);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(json["sockets"][0]["published_by_docker"], true);
    assert_eq!(json["sockets"][0]["docker_forward_filtered"], true);
    assert_eq!(
        json["sockets"][0]["reachable_from"],
        drfw::core::host_facts::DOCKER_PUBLISHED_FORWARD_FILTERED
    );

    // No proxy, but a Docker bridge: the general note; forwarding off
    std::fs::remove_dir_all(proc.join("5000")).unwrap();
    proc_file(&proc, "sys/net/ipv4/ip_forward", b"0\n");
    proc_file(
        &proc,
        "net/dev",
        b"Inter-|   Receive\n face |bytes\n    lo: 0 0\ndocker0: 0 0\n",
    );
    let output = run_drfw_in_proc(root.path(), &proc, &["exposure", "web"], &[]);
    let out = stdout_of(&output);
    assert!(out.contains("OPEN TO EVERYONE: everyone"), "{out}");
    assert!(
        out.contains(drfw::core::host_facts::CONTAINER_NETWORKS_NOTE),
        "{out}"
    );
    assert!(
        !out.contains(drfw::core::host_facts::FORWARDING_WARNING),
        "{out}"
    );
    let output = run_drfw_in_proc(root.path(), &proc, &["exposure", "blocking"], &[]);
    assert!(
        stdout_of(&output)
            .contains(drfw::core::host_facts::CONTAINER_NETWORKS_NOTE_FORWARD_FILTERED),
        "{}",
        all_output(&output)
    );
}

/// `--confirm` outside 5..=120 seconds is a usage error (exit 2), not
/// silently clamped; nothing is verified or applied.
#[test]
fn test_cli_apply_confirm_range() {
    let root = tempfile::tempdir().unwrap();
    write_profile(root.path(), "web", &create_test_ruleset());
    for seconds in ["0", "4", "121", "3600"] {
        let output = run_drfw(root.path(), &["apply", "web", "--confirm", seconds]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{seconds}: {}",
            all_output(&output)
        );
        let out = all_output(&output);
        assert!(out.contains("5..=120"), "{seconds}: {out}");
        assert!(!out.contains("Verifying"), "{seconds}: {out}");
    }
}

/// `drfw status`, `drfw exposure` and `drfw list` with stdout a closed pipe
/// (`drfw status | head`): no panic (exit 101), the command finishes as
/// usual.
#[cfg(target_endian = "little")]
#[test]
fn test_cli_closed_stdout_does_not_panic() {
    let root = tempfile::tempdir().unwrap();
    let proc = root.path().join("proc");
    proc_fixture(&proc);
    exposure_profile(root.path());
    write_profile(root.path(), "default", &create_test_ruleset());
    for args in [
        &["status"][..],
        &["exposure", "web"],
        &["exposure", "web", "--json"],
        &["list"],
    ] {
        let (reader, writer) = std::io::pipe().expect("pipe");
        drop(reader);
        let output = drfw_command(root.path(), mock_nft_path())
            .env("DRFW_TEST_PROC_DIR", &proc)
            .args(args)
            .stdout(writer)
            .output()
            .expect("run drfw");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{args:?}: {stderr}");
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
    }
}

/// S3: `drfw status` has a "Forwarding" line: off, the forwarding notice,
/// or that the profile blocks forwarded traffic.
#[test]
fn test_cli_status_forwarding_line() {
    let root = tempfile::tempdir().unwrap();
    let mut ruleset = create_test_ruleset();
    write_profile(root.path(), "default", &ruleset);
    let proc = root.path().join("proc");
    std::fs::create_dir_all(&proc).unwrap();
    let forwarding_line = |out: &str| -> String {
        out.lines()
            .find(|l| l.starts_with("Forwarding:"))
            .unwrap_or_else(|| panic!("no Forwarding line: {out}"))
            .to_string()
    };

    let output = run_drfw_in_proc(root.path(), &proc, &["status"], &[]);
    assert!(output.status.success(), "{}", all_output(&output));
    assert!(
        forwarding_line(&stdout_of(&output)).ends_with("IP forwarding is off"),
        "{}",
        stdout_of(&output)
    );

    proc_file(&proc, "sys/net/ipv6/conf/all/forwarding", b"1\n");
    let output = run_drfw_in_proc(root.path(), &proc, &["status"], &[]);
    let line = forwarding_line(&stdout_of(&output));
    assert!(
        line.ends_with(drfw::core::host_facts::FORWARDING_WARNING),
        "{line}"
    );

    ruleset.advanced_security.block_forwarding = true;
    write_profile(root.path(), "default", &ruleset);
    let output = run_drfw_in_proc(root.path(), &proc, &["status"], &[]);
    let line = forwarding_line(&stdout_of(&output));
    assert!(
        line.contains("this profile blocks forwarded traffic"),
        "{line}"
    );
}

/// `drfw status` says whether the SSH session's client could reconnect.
#[test]
fn test_cli_status_ssh_line() {
    let root = tempfile::tempdir().unwrap();
    let mut ruleset = create_test_ruleset(); // allows TCP 22
    write_profile(root.path(), "default", &ruleset);
    let no_proc = root.path().join("no-proc");

    let output = run_drfw_in_proc(root.path(), &no_proc, &["status"], &[SSH_SESSION]);
    assert!(output.status.success(), "{}", all_output(&output));
    let out = stdout_of(&output);
    let line = out
        .lines()
        .find(|l| l.starts_with("SSH:"))
        .unwrap_or_else(|| panic!("no SSH line: {out}"));
    assert!(
        line.contains(
            "you are connected from 10.0.0.5 to port 22; new connections from 10.0.0.5 would be accepted by rule \"Test SSH\""
        ),
        "{line}"
    );

    ruleset.rules.clear();
    write_profile(root.path(), "default", &ruleset);
    let output = run_drfw_in_proc(root.path(), &no_proc, &["status"], &[SSH_SESSION]);
    let out = stdout_of(&output);
    assert!(out.contains("would be BLOCKED: rejected by"), "{out}");

    let output = run_drfw_in_proc(root.path(), &no_proc, &["status"], &[]);
    let out = stdout_of(&output);
    assert!(
        out.contains("SSH:              no SSH session into this computer found"),
        "{out}"
    );
}

#[test]
fn test_cli_save_refuses_invalid_and_missing_profiles() {
    if !script_paths_usable() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let bin = fake_systemctl_dir();
    let mut ruleset = create_test_ruleset();
    ruleset.rules.push(create_test_rule("Broken", Some(0)));
    write_profile(root.path(), "bad", &ruleset);

    for name in ["bad", "missing"] {
        let output = run_drfw_save(root.path(), bin.path(), &[name, "--yes"]);
        assert_eq!(output.status.code(), Some(1), "{}", all_output(&output));
        assert!(!root.path().join("nftables.conf").exists());
    }
}

/// The exit codes are documented in `--help`.
#[test]
fn test_cli_help_lists_exit_codes() {
    let help = std::process::Command::new(env!("CARGO_BIN_EXE_drfw"))
        .arg("--help")
        .output()
        .expect("run drfw");
    let help = stdout_of(&help);
    assert!(help.contains("Exit codes:"), "{help}");
    for code in [
        "  3  apply",
        "  6  apply",
        "  7  save",
        "  8  save",
        "  9  apply/save",
    ] {
        assert!(help.contains(code), "{code:?} missing:\n{help}");
    }
    assert!(help.contains("save"), "{help}");
}
