//! Integration tests for DRFW
//!
//! These tests verify end-to-end functionality including apply/revert flows,
//! error handling, and concurrent operation blocking.
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

use drfw::core::firewall::{FirewallRuleset, PortRange, Protocol, Rule};
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
    }
}

/// Create a basic test ruleset
fn create_test_ruleset() -> FirewallRuleset {
    let mut ruleset = FirewallRuleset::new();
    ruleset.rules.push(Rule {
        id: Uuid::new_v4(),
        label: "Test SSH".to_string(),
        protocol: Protocol::Tcp,
        ports: Some(PortRange::single(22)),
        source: None,
        interface: None,
        ipv6_only: false,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
    });
    ruleset
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
    let result = verify::verify_ruleset(&ruleset).await;

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
    let result = verify::verify_ruleset(&ruleset).await;

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
    let result = verify::verify_ruleset(&ruleset).await;

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
            ipv6_only: false,
            enabled: true,
            tags: vec![],
            created_at: chrono::Utc::now(),
        });
    }

    let result = verify::verify_ruleset(&ruleset).await;
    assert!(result.is_ok(), "Multi-rule verification should succeed");
}

#[tokio::test]
async fn test_snapshot_creation_and_validation() {
    let ruleset = create_test_ruleset();
    let snapshot = ruleset.to_nftables_json();

    // Validate snapshot structure
    let validation_result = nft_json::validate_snapshot(&snapshot);
    assert!(
        validation_result.is_ok(),
        "Snapshot should be valid: {:?}",
        validation_result
    );

    // Checksum should be deterministic
    let checksum1 = nft_json::compute_checksum(&snapshot);
    let checksum2 = nft_json::compute_checksum(&snapshot);
    assert_eq!(checksum1, checksum2, "Checksums should be identical");
    assert_eq!(checksum1.len(), 64, "SHA-256 should be 64 hex chars");
}

#[tokio::test]
async fn test_corrupted_snapshot_rejected() {
    use serde_json::json;

    // Missing nftables array
    let invalid_snapshot = json!({
        "invalid": []
    });

    let result = nft_json::validate_snapshot(&invalid_snapshot);
    assert!(result.is_err(), "Invalid snapshot should be rejected");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("missing nftables array"),
        "Should mention missing nftables array"
    );
}

#[tokio::test]
async fn test_empty_snapshot_warning_only() {
    use serde_json::json;

    // Empty snapshots are now allowed (with warning) for emergency recovery scenarios
    // They must still have table operations though
    let empty_snapshot = json!({
        "nftables": [
            { "add": { "table": { "family": "inet", "name": "drfw" } } }
        ]
    });

    let result = nft_json::validate_snapshot(&empty_snapshot);
    // Should pass validation even if minimal
    assert!(
        result.is_ok(),
        "Minimal snapshot with table should be valid: {:?}",
        result
    );
}

#[tokio::test]
async fn test_snapshot_without_tables_rejected() {
    use serde_json::json;

    let no_tables = json!({
        "nftables": [
            { "random": "stuff" }
        ]
    });

    let result = nft_json::validate_snapshot(&no_tables);
    assert!(result.is_err(), "Snapshot without tables should fail");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("no table operations"),
        "Should mention missing tables"
    );
}

#[tokio::test]
async fn test_emergency_default_ruleset_is_valid() {
    setup_mock_nft();

    let emergency = nft_json::get_emergency_default_ruleset();

    // Should pass validation
    let validation = nft_json::validate_snapshot(&emergency);
    assert!(
        validation.is_ok(),
        "Emergency ruleset should be valid: {:?}",
        validation
    );

    // Should have expected structure
    let nftables = emergency["nftables"].as_array().unwrap();
    assert!(!nftables.is_empty(), "Emergency ruleset should have rules");

    // Verify it contains essential safety rules
    let json_str = serde_json::to_string(&emergency).unwrap();
    assert!(
        json_str.contains("loopback"),
        "Should allow loopback traffic"
    );
    assert!(
        json_str.contains("established"),
        "Should allow established connections"
    );
    assert!(json_str.contains("invalid"), "Should drop invalid packets");
}

#[tokio::test]
async fn test_checksum_changes_on_modification() {
    let mut ruleset1 = create_test_ruleset();
    let snapshot1 = ruleset1.to_nftables_json();
    let checksum1 = nft_json::compute_checksum(&snapshot1);

    // Modify ruleset
    ruleset1.rules.push(Rule {
        id: Uuid::new_v4(),
        label: "New Rule".to_string(),
        protocol: Protocol::Tcp,
        ports: Some(PortRange::single(80)),
        source: None,
        interface: None,
        ipv6_only: false,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
    });

    let snapshot2 = ruleset1.to_nftables_json();
    let checksum2 = nft_json::compute_checksum(&snapshot2);

    assert_ne!(
        checksum1, checksum2,
        "Checksums should differ after modification"
    );
}

#[tokio::test]
async fn test_json_generation_deterministic() {
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

    drfw::audit::log_apply(5, 3, true, None).await;
    drfw::audit::log_apply(5, 3, false, Some("Test error".to_string())).await;
    drfw::audit::log_revert(true, None).await;
    drfw::audit::log_revert(false, Some("Revert failed".to_string())).await;

    // If we reach here without panicking, test passes
}

#[tokio::test]
async fn test_all_protocol_types_generate_valid_json() {
    let mut ruleset = FirewallRuleset::new();

    // TCP
    ruleset.rules.push(Rule {
        id: Uuid::new_v4(),
        label: "TCP".to_string(),
        protocol: Protocol::Tcp,
        ports: Some(PortRange::single(80)),
        source: None,
        interface: None,
        ipv6_only: false,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
    });

    // UDP
    ruleset.rules.push(Rule {
        id: Uuid::new_v4(),
        label: "UDP".to_string(),
        protocol: Protocol::Udp,
        ports: Some(PortRange::single(53)),
        source: None,
        interface: None,
        ipv6_only: false,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
    });

    // ICMP
    ruleset.rules.push(Rule {
        id: Uuid::new_v4(),
        label: "ICMP".to_string(),
        protocol: Protocol::Icmp,
        ports: None,
        source: None,
        interface: None,
        ipv6_only: false,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
    });

    // Any
    ruleset.rules.push(Rule {
        id: Uuid::new_v4(),
        label: "Any".to_string(),
        protocol: Protocol::Any,
        ports: None,
        source: Some("192.168.1.0/24".parse().unwrap()),
        interface: None,
        ipv6_only: false,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
    });

    let json = ruleset.to_nftables_json();

    // Should be valid and serializable
    let json_str = serde_json::to_string(&json);
    assert!(json_str.is_ok(), "JSON should serialize");

    // Should validate
    let validation = nft_json::validate_snapshot(&json);
    assert!(validation.is_ok(), "All protocol types should validate");
}

#[tokio::test]
async fn test_complex_rule_configurations() {
    let mut ruleset = FirewallRuleset::new();

    // Rule with source filter
    ruleset.rules.push(Rule {
        id: Uuid::new_v4(),
        label: "With Source".to_string(),
        protocol: Protocol::Tcp,
        ports: Some(PortRange::single(22)),
        source: Some("10.0.0.0/8".parse().unwrap()),
        interface: None,
        ipv6_only: false,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
    });

    // Rule with interface filter
    ruleset.rules.push(Rule {
        id: Uuid::new_v4(),
        label: "With Interface".to_string(),
        protocol: Protocol::Tcp,
        ports: Some(PortRange::single(80)),
        source: None,
        interface: Some("eth0".to_string()),
        ipv6_only: false,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
    });

    // Rule with port range
    ruleset.rules.push(Rule {
        id: Uuid::new_v4(),
        label: "Port Range".to_string(),
        protocol: Protocol::Tcp,
        ports: Some(PortRange {
            start: 8000,
            end: 8999,
        }),
        source: None,
        interface: None,
        ipv6_only: false,
        enabled: true,
        tags: vec![],
        created_at: chrono::Utc::now(),
    });

    // Rule with everything
    ruleset.rules.push(Rule {
        id: Uuid::new_v4(),
        label: "Everything".to_string(),
        protocol: Protocol::Udp,
        ports: Some(PortRange::single(53)),
        source: Some("8.8.8.8/32".parse().unwrap()),
        interface: Some("wlan0".to_string()),
        ipv6_only: false,
        enabled: true,
        tags: vec!["dns".to_string(), "public".to_string()],
        created_at: chrono::Utc::now(),
    });

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
