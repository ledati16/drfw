//! Integration tests for DRFW
//!
//! These tests verify end-to-end functionality including apply/revert flows,
//! error handling, CLI operations, and verification with mock nft.
//!
//! **Test Organization:**
//! - Snapshot validation tests are in `src/core/nft_json.rs` (authoritative)
//! - Verification tests with mock nft are here
//! - CLI command integration tests are here
//! - Profile operations are here
//!
//! # Running Tests
//!
//! All tests use the mock nft script automatically - no privileges needed:
//! ```bash
//! cargo test --test integration_tests
//! ```
//!
//! The mock script (`tests/mock_nft.sh`) simulates nft behavior for testing.

#![allow(clippy::uninlined_format_args)]

use drfw::core::firewall::{Action, FirewallRuleset, PortEntry, Protocol, RejectType, Rule};
use drfw::core::nft_json;
use drfw::core::verify;
use std::env;
use std::path::PathBuf;
use std::sync::Once;
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
        ports: port.map(|p| vec![PortEntry::Single(p)]).unwrap_or_default(),
        sources: vec![],
        destinations: vec![],
        interface: None,
        output_interface: None,
        chain: drfw::core::firewall::Chain::Input,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
        action: Action::Accept,
        reject_type: RejectType::Default,
        rate_limit: None,
        connection_limit: 0,
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
        ports: port.map(|p| vec![PortEntry::Single(p)]).unwrap_or_default(),
        sources: source
            .and_then(|s| s.parse().ok())
            .map(|ip| vec![ip])
            .unwrap_or_default(),
        destinations: vec![],
        interface: interface.map(String::from),
        output_interface: None,
        chain: drfw::core::firewall::Chain::Input,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
        action: Action::Accept,
        reject_type: RejectType::Default,
        rate_limit: None,
        connection_limit: 0,
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

    assert!(result.is_ok(), "verify_ruleset should succeed with mock: {:?}", result.err());

    let verify_result = result.unwrap();
    assert!(
        verify_result.success,
        "Mock verification should succeed: {:?}",
        verify_result.errors
    );
}

#[tokio::test]
async fn test_empty_ruleset_verification() {
    setup_mock_nft();

    let ruleset = FirewallRuleset::new();
    let json = ruleset.to_nftables_json();
    let result = verify::verify_ruleset(json).await;

    assert!(result.is_ok(), "verify_ruleset should succeed with mock: {:?}", result.err());

    let verify_result = result.unwrap();
    assert!(
        verify_result.success,
        "Empty ruleset verification should succeed: {:?}",
        verify_result.errors
    );
}

#[tokio::test]
async fn test_multiple_rules_verification() {
    setup_mock_nft();

    let mut ruleset = FirewallRuleset::new();

    // Add multiple rules
    for i in 0..5 {
        ruleset.rules.push(create_test_rule(
            &format!("Test Rule {}", i),
            Some(8000 + i),
        ));
    }

    let json = ruleset.to_nftables_json();
    let result = verify::verify_ruleset(json).await;
    assert!(result.is_ok(), "Multi-rule verification should succeed");
}

// ============================================================================
// NOTE: Snapshot validation and checksum tests are in src/core/nft_json.rs
// These tests were removed to avoid duplication. See nft_json.rs for:
// - test_validate_snapshot_*
// - test_compute_checksum_*
// - test_emergency_default_*
// ============================================================================

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

#[test]
fn test_all_protocol_types_generate_valid_json() {
    let mut ruleset = FirewallRuleset::new();

    ruleset.rules.push(create_full_test_rule(
        "TCP",
        Protocol::Tcp,
        Some(80),
        None,
        None,
    ));
    ruleset.rules.push(create_full_test_rule(
        "UDP",
        Protocol::Udp,
        Some(53),
        None,
        None,
    ));
    ruleset.rules.push(create_full_test_rule(
        "ICMP",
        Protocol::Icmp,
        None,
        None,
        None,
    ));
    ruleset.rules.push(create_full_test_rule(
        "Any",
        Protocol::Any,
        None,
        Some("192.168.1.0/24"),
        None,
    ));

    let json = ruleset.to_nftables_json();

    // Should be valid and serializable
    let json_str = serde_json::to_string(&json);
    assert!(json_str.is_ok(), "JSON should serialize");

    // Should validate
    let validation = nft_json::validate_snapshot(&json);
    assert!(validation.is_ok(), "All protocol types should validate");
}

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
    let validation = nft_json::validate_snapshot(&json);
    assert!(validation.is_ok(), "Complex configurations should validate");

    // Verify JSON is valid
    let json_str = serde_json::to_string(&json);
    assert!(json_str.is_ok());
}

#[test]
fn test_mock_nft_script_exists() {
    let mock_path = get_mock_nft_path();
    assert!(
        mock_path.exists(),
        "Mock nft script should exist at {:?}",
        mock_path
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

#[tokio::test]
async fn test_cli_verify_before_apply() {
    // Test the verification step used by `drfw apply`
    setup_mock_nft();

    let ruleset = create_test_ruleset();
    let json = ruleset.to_nftables_json();

    // Verify the ruleset before applying (as CLI does)
    let result = verify::verify_ruleset(json).await;

    assert!(result.is_ok(), "verify_ruleset should succeed with mock: {:?}", result.err());

    let verify_result = result.unwrap();
    assert!(
        verify_result.success,
        "Valid ruleset should verify successfully: {:?}",
        verify_result.errors
    );
    assert!(
        verify_result.errors.is_empty(),
        "Valid ruleset should have no errors"
    );
}

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
            "Should reject invalid profile name: {}",
            name
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
            "Error should indicate profile not found: {}",
            err_msg
        );
    }
}
