//! Integration tests for DRFW
//!
//! These tests verify end-to-end functionality including apply/revert flows,
//! error handling, CLI operations, and verification with mock nft.
//!
//! **Test Organization:**
//! - Snapshot validation tests are in `src/core/nft_json.rs` (authoritative)
//! - Verification tests with mock/real nft are here
//! - CLI command integration tests are here
//! - Profile operations are here
//!
//! # Running with Mock
//!
//! By default, these tests use the mock nft script which doesn't require privileges:
//! ```bash
//! cargo test --test integration_tests
//! ```
//!
//! # Running with Real nftables
//!
//! To test against real nftables (requires elevated privileges):
//! ```bash
//! sudo -E DRFW_USE_REAL_NFT=1 cargo test --test integration_tests
//! ```

#![allow(clippy::uninlined_format_args)]

use drfw::core::firewall::{Action, FirewallRuleset, PortRange, Protocol, Rule};
use drfw::core::nft_json;
use drfw::core::verify;
use std::env;
use std::path::PathBuf;
use uuid::Uuid;

/// Get the path to the mock nft script
fn get_mock_nft_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("mock_nft.sh");
    path
}

/// Set up environment to use mock nft
fn setup_mock_nft() {
    if env::var("DRFW_USE_REAL_NFT").is_ok() {
        // User wants to test with real nft, don't override PATH
        return;
    }

    let mock_dir = get_mock_nft_path().parent().unwrap().to_path_buf();
    let current_path = env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", mock_dir.display(), current_path);
    unsafe {
        env::set_var("PATH", new_path);
        env::set_var("DRFW_TEST_NO_ELEVATION", "1");
    }
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
        ports: port.map(PortRange::single),
        source: None,
        interface: None,
        chain: drfw::core::firewall::Chain::Input,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
        destination: None,
        action: Action::Accept,
        rate_limit: None,
        connection_limit: 0,
        // Cached fields
        label_lowercase: String::new(),
        interface_lowercase: None,
        tags_lowercase: Vec::new(),
        protocol_lowercase: "",
        port_display: String::new(),
        source_string: None,
        destination_string: None,
        rate_limit_display: None,
        action_display: String::new(),
        interface_display: String::new(),
    };
    rule.rebuild_caches();
    rule
}

/// Helper to check if verification result indicates permission issues
fn is_permission_error(errors: &[String]) -> bool {
    errors.iter().any(|e| {
        e.contains("Operation not permitted")
            || e.contains("Permission denied")
            || e.contains("cache initialization")
    })
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
        ports: port.map(PortRange::single),
        source: source.and_then(|s| s.parse().ok()),
        interface: interface.map(String::from),
        chain: drfw::core::firewall::Chain::Input,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
        destination: None,
        action: Action::Accept,
        rate_limit: None,
        connection_limit: 0,
        // Cached fields
        label_lowercase: String::new(),
        interface_lowercase: None,
        tags_lowercase: Vec::new(),
        protocol_lowercase: "",
        port_display: String::new(),
        source_string: None,
        destination_string: None,
        rate_limit_display: None,
        action_display: String::new(),
        interface_display: String::new(),
    };
    rule.rebuild_caches();
    rule
}

#[tokio::test]
async fn test_verify_with_mock() {
    // Skip if real nft is not available or not in mock mode
    // This test is mainly for documentation of how mocking should work
    // In practice, use the mock_nft.sh script manually for local testing
    if env::var("DRFW_USE_REAL_NFT").is_ok() {
        eprintln!("Skipping mock test: DRFW_USE_REAL_NFT is set");
        return;
    }

    setup_mock_nft();

    let ruleset = create_test_ruleset();
    let json = ruleset.to_nftables_json();
    let result = verify::verify_ruleset(json).await;

    // If nft is not available, skip the test
    if result.is_err() {
        eprintln!("Skipping test: nft not available");
        return;
    }

    let verify_result = result.unwrap();

    // Skip if we hit permission errors (real nft being used)
    if !verify_result.success
        && verify_result
            .errors
            .iter()
            .any(|e| e.contains("Operation not permitted") || e.contains("cache initialization"))
    {
        eprintln!("Skipping test: appears to be using real nft which requires privileges");
        return;
    }

    assert!(
        verify_result.success,
        "Mock verification should succeed: {:?}",
        verify_result.errors
    );
}

#[tokio::test]
async fn test_verify_fails_with_permission_error() {
    setup_mock_nft();
    unsafe {
        env::set_var("MOCK_NFT_FAIL_PERMS", "1");
    }

    let ruleset = create_test_ruleset();
    let json = ruleset.to_nftables_json();
    let result = verify::verify_ruleset(json).await;

    // Should succeed in running but report permission error
    assert!(result.is_ok());
    let verify_result = result.unwrap();
    assert!(!verify_result.success, "Should fail with permission error");
    assert!(
        verify_result
            .errors
            .iter()
            .any(|e| e.contains("Operation not permitted")),
        "Should have permission error: {:?}",
        verify_result.errors
    );

    unsafe {
        env::remove_var("MOCK_NFT_FAIL_PERMS");
    }
}

#[tokio::test]
async fn test_empty_ruleset_verification() {
    setup_mock_nft();

    let ruleset = FirewallRuleset::new();
    let json = ruleset.to_nftables_json();
    let result = verify::verify_ruleset(json).await;

    // Skip if nft is not available
    if result.is_err() {
        eprintln!("Skipping test: nft not available");
        return;
    }

    let verify_result = result.unwrap();

    // Skip if we hit permission errors
    if !verify_result.success
        && verify_result
            .errors
            .iter()
            .any(|e| e.contains("Operation not permitted") || e.contains("cache initialization"))
    {
        eprintln!("Skipping test: requires elevated privileges or mock nft");
        return;
    }

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
        ruleset.rules.push(Rule {
            id: Uuid::new_v4(),
            label: format!("Test Rule {}", i),
            protocol: Protocol::Tcp,
            ports: Some(PortRange::single(8000 + i)),
            source: None,
            interface: None,
            chain: drfw::core::firewall::Chain::Input,
            enabled: true,
            tags: vec![],
            created_at: chrono::Utc::now(),
            destination: None,
            action: Action::Accept,
            rate_limit: None,
            connection_limit: 0,
            // Cached fields
            label_lowercase: String::new(),
            interface_lowercase: None,
            tags_lowercase: Vec::new(),
            protocol_lowercase: "",
            port_display: String::new(),
            source_string: None,
            destination_string: None,
            rate_limit_display: None,
            action_display: String::new(),
            interface_display: String::new(),
        });
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
    // (we can't easily verify file contents without mocking filesystem)

    drfw::audit::log_apply(true, 5, 3, true, None).await;
    drfw::audit::log_apply(true, 5, 3, false, Some("Test error".to_string())).await;
    drfw::audit::log_revert(true, true, None).await;
    drfw::audit::log_revert(true, false, Some("Revert failed".to_string())).await;

    // If we reach here without panicking, test passes
}

#[test]
fn test_all_protocol_types_generate_valid_json() {
    let mut ruleset = FirewallRuleset::new();

    ruleset
        .rules
        .push(create_full_test_rule("TCP", Protocol::Tcp, Some(80), None, None));
    ruleset
        .rules
        .push(create_full_test_rule("UDP", Protocol::Udp, Some(53), None, None));
    ruleset
        .rules
        .push(create_full_test_rule("ICMP", Protocol::Icmp, None, None, None));
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
    port_range_rule.ports = Some(PortRange {
        start: 8000,
        end: 8999,
    });
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
    // This tests that list_profiles() can handle the actual profiles directory
    use drfw::core::profiles;

    // Just verify that list_profiles() doesn't panic and returns a vec
    let result = profiles::list_profiles().await;
    assert!(result.is_ok(), "list_profiles() should not fail");

    let profiles = result.unwrap();
    // Should at least have default profile (created by app if missing)
    assert!(
        profiles.iter().any(|p| p == "default") || profiles.is_empty(),
        "Should handle profiles directory correctly"
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

    if let Ok(verify_result) = result {
        // With mock or real nft available
        if verify_result.success {
            assert!(
                verify_result.errors.is_empty(),
                "Valid ruleset should have no errors"
            );
        } else if !is_permission_error(&verify_result.errors) {
            panic!(
                "Verification failed unexpectedly: {:?}",
                verify_result.errors
            );
        }
        // Permission errors are expected in unprivileged environments
    }
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
    use drfw::core::profiles;

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
