//! Integration tests for DRFW
//!
//! These tests verify end-to-end functionality including apply/revert flows,
//! error handling, CLI operations, and verification with mock nft.
//!
//! **Test Organization:**
//! - Verification tests with mock nft are here (authoritative)
//! - Guarded apply plumbing (tokens, watcher, status) with mock nft is here;
//!   real-kernel revert behavior is in `tests/real_nft.rs`
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
//!
//! # Note on Helper Functions
//!
//! This file has its own copies of helper functions (`create_test_rule`, etc.)
//! because integration tests are compiled as a separate crate and cannot access
//! `#[cfg(test)]` modules from the library. The library's `test_helpers` module
//! is for unit tests within the library crate only.

use std::env;
use std::path::PathBuf;
use std::sync::Once;

use drfw::core::firewall::{Action, FirewallRuleset, PortEntry, Protocol, RejectType, Rule};
use drfw::core::verify;
use uuid::Uuid;

/// One-time initialization flag for mock nft setup
static MOCK_NFT_INIT: Once = Once::new();

/// Get the path to the mock nft script
fn get_mock_nft_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("mock_nft.sh");
    path
}

/// Set up environment to use mock nft
///
/// Sets `DRFW_NFT_COMMAND` to the mock script path. This is called once
/// and applies to all subsequent nft operations in the test suite.
fn setup_mock_nft() {
    MOCK_NFT_INIT.call_once(|| {
        let mock_path = get_mock_nft_path();
        unsafe {
            env::set_var("DRFW_NFT_COMMAND", mock_path.to_str().unwrap());
        }
    });
}

/// Set up a temp directory for tests that access profile/config directories.
///
/// This prevents tests from creating or modifying the user's real data.
/// Returns a `TempDir` that will be automatically cleaned up when dropped.
fn setup_temp_test_dirs() -> tempfile::TempDir {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    unsafe {
        env::set_var("DRFW_TEST_DATA_DIR", temp_dir.path());
        env::set_var("DRFW_TEST_STATE_DIR", temp_dir.path());
    }
    temp_dir
}

/// Create a basic test ruleset with one SSH rule
fn create_test_ruleset() -> FirewallRuleset {
    let mut ruleset = FirewallRuleset::new();
    ruleset.rules.push(create_test_rule("Test SSH", Some(22)));
    ruleset
}

/// Create a test rule with label and optional port
fn create_test_rule(label: &str, port: Option<u16>) -> Rule {
    let mut rule = Rule {
        id: Uuid::new_v4(),
        label: label.to_string(),
        protocol: Protocol::Tcp,
        ports: port.map_or_default(|p| vec![PortEntry::Single(p)]),
        sources: vec![],
        destinations: vec![],
        interface: None,
        output_interface: None,
        chain: drfw::core::firewall::Chain::Input,
        enabled: true,
        tags: vec![],
        created_at: jiff::Timestamp::now(),
        action: Action::Accept,
        reject_type: RejectType::Default,
        rate_limit: None,
        connection_limit: 0,
        connection_limit_per_source: false,
        log_enabled: false,
        // Cached fields
        label_lowercase: String::new(),
        interface_lowercase: None,
        output_interface_lowercase: None,
        tags_lowercase: Vec::new(),
        protocol_lowercase: "",
        port_display: String::new(),
        sources_display: String::new(),
        destinations_display: String::new(),
        rate_limit_display: None,
        action_display: String::new(),
        interface_display: String::new(),
        log_prefix: String::new(),
        tags_truncated: Vec::new(),
        badge_display: String::new(),
    };
    rule.rebuild_caches();
    rule
}

/// Create a test rule with full configuration options
fn create_full_test_rule(
    label: &str,
    protocol: Protocol,
    port: Option<u16>,
    source: Option<&str>,
    interface: Option<&str>,
) -> Rule {
    let mut rule = Rule {
        id: Uuid::new_v4(),
        label: label.to_string(),
        protocol,
        ports: port.map_or_default(|p| vec![PortEntry::Single(p)]),
        sources: source
            .and_then(|s| s.parse().ok())
            .map_or_default(|ip| vec![ip]),
        destinations: vec![],
        interface: interface.map(String::from),
        output_interface: None,
        chain: drfw::core::firewall::Chain::Input,
        enabled: true,
        tags: vec![],
        created_at: jiff::Timestamp::now(),
        action: Action::Accept,
        reject_type: RejectType::Default,
        rate_limit: None,
        connection_limit: 0,
        connection_limit_per_source: false,
        log_enabled: false,
        // Cached fields
        label_lowercase: String::new(),
        interface_lowercase: None,
        output_interface_lowercase: None,
        tags_lowercase: Vec::new(),
        protocol_lowercase: "",
        port_display: String::new(),
        sources_display: String::new(),
        destinations_display: String::new(),
        rate_limit_display: None,
        action_display: String::new(),
        interface_display: String::new(),
        log_prefix: String::new(),
        tags_truncated: Vec::new(),
        badge_display: String::new(),
    };
    rule.rebuild_caches();
    rule
}

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
}

#[tokio::test]
async fn test_empty_ruleset_verification() {
    setup_mock_nft();

    let ruleset = FirewallRuleset::new();
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
        "Empty ruleset verification should succeed: {:?}",
        verify_result.issues
    );
}

#[tokio::test]
async fn test_multiple_rules_verification() {
    setup_mock_nft();

    let mut ruleset = FirewallRuleset::new();

    // Add multiple rules
    for i in 0..5 {
        ruleset
            .rules
            .push(create_test_rule(&format!("Test Rule {i}"), Some(8000 + i)));
    }

    let json = ruleset.to_nftables_json();
    let result = verify::verify_ruleset(json).await;
    assert!(result.is_ok(), "Multi-rule verification should succeed");
}

#[test]
fn test_json_generation_deterministic() {
    let ruleset = create_test_ruleset();

    let json1 = ruleset.to_nftables_json();
    let json2 = ruleset.to_nftables_json();

    let str1 = serde_json::to_string(&json1).unwrap();
    let str2 = serde_json::to_string(&json2).unwrap();

    assert_eq!(str1, str2, "JSON generation should be deterministic");
}

#[tokio::test]
async fn test_audit_logging_doesnt_panic() {
    // Test that audit logging functions don't panic
    // Pass enable_event_log=false to avoid writing to real user's audit log

    drfw::audit::log_apply(false, 5, 3, true, None).await;
    drfw::audit::log_apply(false, 5, 3, false, Some("Test error".to_string())).await;
    drfw::audit::log_revert(false, true, None).await;
    drfw::audit::log_revert(false, false, Some("Revert failed".to_string())).await;

    // If we reach here without panicking, test passes
}

// NOTE: test_all_protocol_types_generate_valid_json removed - see src/core/tests.rs
// for the authoritative test_json_generation_with_all_protocol_types

#[test]
fn test_complex_rule_configurations() {
    let mut ruleset = FirewallRuleset::new();

    // Rule with source filter
    ruleset.rules.push(create_full_test_rule(
        "With Source",
        Protocol::Tcp,
        Some(22),
        Some("10.0.0.0/8"),
        None,
    ));

    // Rule with interface filter
    ruleset.rules.push(create_full_test_rule(
        "With Interface",
        Protocol::Tcp,
        Some(80),
        None,
        Some("eth0"),
    ));

    // Rule with port range (needs custom construction)
    let mut port_range_rule = create_full_test_rule("Port Range", Protocol::Tcp, None, None, None);
    port_range_rule.ports = vec![PortEntry::Range {
        start: 8000,
        end: 8999,
    }];
    port_range_rule.rebuild_caches();
    ruleset.rules.push(port_range_rule);

    // Rule with everything
    ruleset.rules.push(create_full_test_rule(
        "Everything",
        Protocol::Udp,
        Some(53),
        Some("8.8.8.8/32"),
        Some("wlan0"),
    ));

    let json = ruleset.to_nftables_json();
    assert!(
        json["nftables"].as_array().is_some_and(|a| !a.is_empty()),
        "Complex configurations should produce an nftables command list"
    );

    // Verify JSON is valid
    let json_str = serde_json::to_string(&json);
    assert!(json_str.is_ok());
}

#[test]
fn test_mock_nft_script_exists() {
    let mock_path = get_mock_nft_path();
    assert!(
        mock_path.exists(),
        "Mock nft script should exist at {mock_path:?}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&mock_path).unwrap();
        let permissions = metadata.permissions();
        assert!(
            permissions.mode() & 0o111 != 0,
            "Mock script should be executable"
        );
    }
}

// ============================================================================
// CLI Command Integration Tests
// ============================================================================
//
// These tests verify the core functionality used by CLI commands without
// requiring the actual binary to be executed. They test the same code paths
// that handle_cli() in main.rs uses.

#[tokio::test]
async fn test_cli_list_profiles() {
    // Test the profile listing functionality used by `drfw list`
    // Uses temp directory to avoid touching user's real profile directory
    use drfw::core::profiles;

    let _temp_dir = setup_temp_test_dirs();

    // With a fresh temp dir, should return empty list or handle gracefully
    let result = profiles::list_profiles().await;
    assert!(result.is_ok(), "list_profiles() should not fail");

    let profiles = result.unwrap();
    // Empty temp dir should result in empty list (no default created by list)
    assert!(
        profiles.is_empty(),
        "Fresh temp dir should have no profiles"
    );
}

#[test]
fn test_cli_export_nft_format() {
    // Test the export functionality used by `drfw export --format nft`
    let ruleset = create_test_ruleset();
    let nft_text = ruleset.to_nft_text();

    // Verify nft format output structure
    assert!(
        nft_text.contains("table inet drfw"),
        "Should have table declaration"
    );
    assert!(nft_text.contains("chain input"), "Should have input chain");
    assert!(
        nft_text.contains("policy drop"),
        "Should have default policy"
    );
    assert!(nft_text.contains("Test SSH"), "Should include rule comment");
    assert!(
        nft_text.contains("tcp dport 22"),
        "Should include port rule"
    );
}

#[test]
fn test_cli_export_json_format() {
    // Test the export functionality used by `drfw export --format json`
    let ruleset = create_test_ruleset();
    let json = ruleset.to_nftables_json();

    // Verify JSON format structure
    assert!(json["nftables"].is_array(), "Should have nftables array");

    let json_str = serde_json::to_string_pretty(&json).unwrap();
    assert!(
        json_str.contains("\"table\""),
        "Should have table declaration"
    );
    assert!(
        json_str.contains("\"chain\""),
        "Should have chain declaration"
    );
    assert!(
        json_str.contains("\"rule\""),
        "Should have rule declaration"
    );
}

// NOTE: test_cli_verify_before_apply removed - exact duplicate of test_verify_with_mock

#[test]
fn test_cli_profile_load_and_rebuild_caches() {
    // Test that profile loading rebuilds caches (important for CLI performance)
    // We'll create a ruleset, serialize it to JSON, then deserialize and check caches

    let mut ruleset = create_test_ruleset();

    // Clear caches to simulate fresh load from disk
    for rule in &mut ruleset.rules {
        rule.label_lowercase = String::new();
        rule.port_display = String::new();
        rule.protocol_lowercase = "";
    }

    // Serialize to JSON (simulating save to disk)
    let json = serde_json::to_string(&ruleset).unwrap();

    // Deserialize and rebuild caches (simulating load from disk)
    let mut loaded: FirewallRuleset = serde_json::from_str(&json).unwrap();
    for rule in &mut loaded.rules {
        rule.rebuild_caches();
    }

    // Verify caches are rebuilt
    assert_eq!(loaded.rules.len(), 1);
    let rule = &loaded.rules[0];

    // These should be populated by rebuild_caches()
    assert!(
        !rule.label_lowercase.is_empty(),
        "Label cache should be rebuilt"
    );
    assert!(
        !rule.port_display.is_empty(),
        "Port display cache should be rebuilt"
    );
    assert_eq!(
        rule.protocol_lowercase, "tcp",
        "Protocol cache should be rebuilt"
    );
}

#[tokio::test]
async fn test_cli_invalid_profile_name() {
    // Test profile name validation (CLI error handling)
    // Note: Invalid names fail validation before any filesystem access,
    // so no temp directory setup is needed here.
    use drfw::core::profiles;

    // These should fail validation
    let invalid_names = vec![
        "../etc/passwd".to_string(), // Path traversal
        ".".to_string(),             // Special directory
        "..".to_string(),            // Parent directory
        "test/profile".to_string(),  // Contains slash
        "test profile".to_string(),  // Contains space
        "a".repeat(65),              // Too long
    ];

    for name in invalid_names {
        let result = profiles::load_profile(&name).await;
        assert!(
            result.is_err(),
            "Should reject invalid profile name: {name}"
        );
    }
}

#[tokio::test]
async fn test_cli_profile_not_found() {
    // Test CLI error handling for missing profiles
    // Uses temp directory to avoid touching user's real profile directory
    use drfw::core::profiles;

    let _temp_dir = setup_temp_test_dirs();

    // Use a short but valid profile name that doesn't exist
    let result = profiles::load_profile("nonexistent_abc").await;
    assert!(result.is_err(), "Should error when profile doesn't exist");

    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(
            err_msg.contains("not found") || err_msg.contains("NotFound"),
            "Error should indicate profile not found: {err_msg}"
        );
    }
}

/// Save to System write path with the mock nft (`-c -f FILE` accepts files that
/// start with the DRFW shebang). Real-nft coverage is in `tests/real_nft.rs`.
#[tokio::test]
async fn test_save_config_file_with_mock_nft() {
    use std::os::unix::fs::PermissionsExt;
    setup_mock_nft();

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("nftables.conf");
    let target_str = target.to_str().unwrap();
    let backup = dir.path().join("nftables.conf.drfw-bak");

    // No existing file: written, no backup reported
    let text = create_test_ruleset().to_nft_text();
    let output = drfw::core::system_config::write_config_file(&text, target_str)
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

    // Rejected content: original untouched, no backup, no temp file left
    let output = drfw::core::system_config::write_config_file("not nft\n", target_str)
        .await
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), text);
    assert!(!backup.exists());
    assert!(!dir.path().join(".nftables.conf.drfw-tmp").exists());

    // Second successful save backs up the previous file
    let output = drfw::core::system_config::write_config_file(&text, target_str)
        .await
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        drfw::core::system_config::backup_path_from_output(&output),
        Some(backup.clone())
    );
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), text);
}

/// Guarded apply with the mock nft: the real apply script and a real
/// (`setsid`) watcher, confirm/timeout/no-guard paths. Real-kernel revert
/// semantics are covered in `tests/real_nft.rs`.
#[tokio::test]
async fn test_guarded_apply_with_mock_nft() {
    use drfw::core::apply_guard::{ApplyError, GuardOutcome, OUTCOME_GRACE, apply_guarded};
    setup_mock_nft();
    // A confirmed guard records the ruleset in the state directory: never
    // the user's real one
    let _dirs = setup_temp_test_dirs();

    let dir = tempfile::tempdir().unwrap();
    let runtime_dir = dir.path().join("run");
    let state_dir = dir.path().join("guard");
    std::fs::create_dir(&runtime_dir).unwrap();
    // The token directory must be private, or DRFW does not use it
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // SAFETY: only this test reads these variables
    unsafe {
        env::set_var("XDG_RUNTIME_DIR", &runtime_dir);
        env::set_var("DRFW_GUARD_STATE_DIR", &state_dir);
    }
    let json = create_test_ruleset().to_nftables_json();

    // No guard: just applied
    assert_eq!(apply_guarded(&json, 0).await, Ok(None));

    // Confirmed before the timeout: the watcher reports it
    let handle = apply_guarded(&json, 30).await.unwrap().expect("guard");
    handle.confirm().unwrap();
    assert_eq!(
        handle.wait_outcome(OUTCOME_GRACE).await,
        Ok(GuardOutcome::Confirmed)
    );
    // Tokens are cleaned up by the user side, never by the watcher
    assert_eq!(std::fs::read_dir(&runtime_dir).unwrap().count(), 0);
    // The token really went to the runtime dir: a watcher confirmed it there
    let handle = apply_guarded(&json, 30).await.unwrap().expect("guard");
    handle.confirm().unwrap();
    assert_eq!(std::fs::read_dir(&runtime_dir).unwrap().count(), 1);
    assert_eq!(
        handle.wait_outcome(OUTCOME_GRACE).await,
        Ok(GuardOutcome::Confirmed)
    );

    // Not confirmed: the watcher reverts on its own
    let handle = apply_guarded(&json, 1).await.unwrap().expect("guard");
    assert_eq!(
        handle.wait_for_timeout_outcome().await,
        Ok(GuardOutcome::Reverted)
    );

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
    let error = apply_guarded(&json, 1).await.unwrap_err();
    assert!(
        matches!(error, ApplyError::StateUnknown(_)),
        "a killed apply script must not be reported as 'nothing changed': {error}"
    );
    assert!(error.rules_may_be_active());
    let reverted = (0..100).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(100));
        reverted_count() == before + 1
    });
    assert!(reverted, "the guard of the killed apply must revert");
}

// ============================================================================
// CLI binary tests (`drfw status`, `drfw check`)
// ============================================================================
//
// These run the real `drfw` binary. Each child gets its own environment
// (data/state dirs, mock nft), so they never race with the env-var users above.

/// Writes `ruleset` as profile `name` (current on-disk format) under `root`.
fn write_profile(root: &std::path::Path, name: &str, ruleset: &FirewallRuleset) {
    let dir = root.join("profiles");
    std::fs::create_dir_all(&dir).unwrap();
    let mut json = serde_json::to_value(ruleset).unwrap();
    json["version"] = serde_json::json!(drfw::core::profiles::PROFILE_FORMAT_VERSION);
    std::fs::write(
        dir.join(format!("{name}.json")),
        serde_json::to_vec_pretty(&json).unwrap(),
    )
    .unwrap();
}

/// Runs the `drfw` binary against `root` with `nft` as `DRFW_NFT_COMMAND`.
fn run_drfw_with_nft(root: &std::path::Path, nft: &str, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_drfw"))
        .args(args)
        .env("DRFW_TEST_DATA_DIR", root)
        .env("DRFW_TEST_STATE_DIR", root)
        .env("DRFW_NFT_COMMAND", nft)
        .output()
        .expect("run drfw")
}

/// Runs the `drfw` binary against `root` with the mock nft.
fn run_drfw(root: &std::path::Path, args: &[&str]) -> std::process::Output {
    run_drfw_with_nft(root, get_mock_nft_path().to_str().unwrap(), args)
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

/// Creates a directory holding only the fake `systemctl`.
fn fake_systemctl_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("systemctl");
    std::fs::write(&path, FAKE_SYSTEMCTL).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
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
    let mut child = drfw::elevation::create_elevated_save_config_command(target, service)
        .unwrap()
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

#[tokio::test]
async fn test_save_script_rejects_bad_arguments_before_writing() {
    let bin = fake_systemctl_dir();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("nftables.conf");
    let target_str = target.to_str().unwrap();
    let text = create_test_ruleset().to_nft_text();

    for service in [
        "-nftables.service",
        ".nftables.service",
        "nftables",
        ".service",
        "nft;id.service",
        "nft tables.service",
        "nft$x.service",
        "nftables.socket",
    ] {
        let output = run_save_script(&text, target_str, Some(service), bin.path()).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{service}: {stderr}");
        assert!(
            stderr.contains("invalid service name"),
            "{service}: {stderr}"
        );
    }
    let output = run_save_script(&text, "relative/nftables.conf", None, bin.path()).await;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid target path"));

    assert!(!target.exists(), "nothing may be written");
    assert_eq!(systemctl_calls(bin.path()), Vec::<String>::new());
}

/// Runs `drfw status` with `path` as `PATH`.
fn run_drfw_status_with_path(root: &std::path::Path, path: &str) -> String {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_drfw"))
        .arg("status")
        .env("DRFW_TEST_DATA_DIR", root)
        .env("DRFW_TEST_STATE_DIR", root)
        .env("DRFW_NFT_COMMAND", get_mock_nft_path())
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
    std::process::Command::new(env!("CARGO_BIN_EXE_drfw"))
        .arg("save")
        .args(args)
        .env("DRFW_TEST_DATA_DIR", root)
        .env("DRFW_TEST_STATE_DIR", root)
        .env("DRFW_NFT_COMMAND", get_mock_nft_path())
        .env("DRFW_TEST_SYSTEM_NFT_PATH", root.join("nftables.conf"))
        .env("PATH", path_with(fake_bin))
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
    let root = tempfile::tempdir().unwrap();
    let bin = fake_systemctl_dir();
    save_fixture(root.path());

    let output = run_drfw_save(root.path(), bin.path(), &["web"]);
    assert_eq!(output.status.code(), Some(7), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(out.contains("never confirmed"), "{out}");
    assert!(out.contains("WITHOUT a dead-man switch"), "{out}");
    assert!(out.contains("drfw apply web"), "{out}");
    assert!(!root.path().join("nftables.conf").exists());
    assert_eq!(systemctl_calls(bin.path()), Vec::<String>::new());
}

#[test]
fn test_cli_save_with_yes_saves_and_warns_about_boot() {
    let root = tempfile::tempdir().unwrap();
    let bin = fake_systemctl_dir();
    let ruleset = save_fixture(root.path());
    std::fs::write(bin.path().join("state-nftables.service"), "disabled\n").unwrap();

    let output = run_drfw_save(root.path(), bin.path(), &["web", "--yes"]);
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    let out = all_output(&output);
    assert!(
        out.contains("never confirmed"),
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
    let root = tempfile::tempdir().unwrap();
    let bin = fake_systemctl_dir();
    save_fixture(root.path());
    std::fs::write(bin.path().join("state-nftables.service"), "disabled\n").unwrap();

    let output = run_drfw_save(
        root.path(),
        bin.path(),
        &["web", "--yes", "--enable-at-boot"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", all_output(&output));
    assert!(
        systemctl_calls(bin.path())
            .iter()
            .any(|c| c == "enable -- nftables.service"),
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

/// A ruleset confirmed under the guard (recorded by `GuardHandle::wait_outcome`)
/// saves without --yes and without the warning.
#[test]
fn test_cli_save_confirmed_rules_need_no_yes() {
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
    assert!(out.contains("applied and confirmed"), "{out}");
    assert!(!out.contains("never confirmed"), "{out}");
    assert!(root.path().join("nftables.conf").exists());

    // Any change to the profile makes it "not confirmed" again
    let mut changed = ruleset;
    changed.rules.push(create_test_rule("New", Some(8080)));
    write_profile(root.path(), "web", &changed);
    let output = run_drfw_save(root.path(), bin.path(), &["web"]);
    assert_eq!(output.status.code(), Some(7), "{}", all_output(&output));
}

#[test]
fn test_cli_save_refuses_invalid_and_missing_profiles() {
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
    for code in ["  3  apply", "  6  apply", "  7  save", "  8  save"] {
        assert!(help.contains(code), "{code:?} missing:\n{help}");
    }
    assert!(help.contains("save"), "{help}");
}
