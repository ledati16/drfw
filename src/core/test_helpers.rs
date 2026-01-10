//! Shared test utilities for core module tests
//!
//! Provides common test helpers to avoid duplication across test suites.
//! This module is only compiled in test mode.

use crate::core::firewall::{
    Action, Chain, FirewallRuleset, PortEntry, Protocol, RejectType, Rule,
};
use chrono::Utc;
use std::sync::{Mutex, Once};
use uuid::Uuid;

/// Mutex for tests that need exclusive access to environment variables.
///
/// Use this when your test needs to:
/// 1. Temporarily change env vars to different values
/// 2. Restore env vars after the test
/// 3. Test behavior when env vars are absent
///
/// For tests that just need mock nft, use `setup_mock_nft()` instead -
/// it's simpler and doesn't require holding a guard.
///
/// # Example
///
/// ```ignore
/// let _guard = ENV_VAR_MUTEX.lock().unwrap();
/// unsafe {
///     std::env::remove_var("DRFW_NFT_COMMAND");
///     std::env::set_var("DRFW_ELEVATION_METHOD", "sudo");
/// }
/// // ... test with custom env state ...
/// unsafe {
///     std::env::remove_var("DRFW_ELEVATION_METHOD");
/// }
/// ```
pub static ENV_VAR_MUTEX: Mutex<()> = Mutex::new(());

/// One-time initialization flag for mock nft setup
static MOCK_NFT_INIT: Once = Once::new();

/// Sets up the mock nft script for testing.
///
/// Sets `DRFW_NFT_COMMAND` to the mock script path (`tests/mock_nft.sh`),
/// which causes all nft operations to use the mock instead of real nftables.
///
/// This is the preferred way to set up testing:
/// - Thread-safe and can be called multiple times (initialization happens once)
/// - No guard to hold, so no `await_holding_lock` issues in async tests
/// - Simple one-liner at the start of your test
/// - Tests never touch real nftables or require elevation
///
/// For tests that need to temporarily change env vars or test different
/// elevation methods, use `ENV_VAR_MUTEX` directly instead.
///
/// # Example
///
/// ```ignore
/// #[tokio::test]
/// async fn test_something() {
///     setup_mock_nft();
///     // ... test code, can use .await freely ...
///     // All nft operations use the mock script
/// }
/// ```
pub fn setup_mock_nft() {
    MOCK_NFT_INIT.call_once(|| {
        let mock_path = format!("{}/tests/mock_nft.sh", env!("CARGO_MANIFEST_DIR"));
        // SAFETY: This is only called once due to Once, and only in test code.
        // Test binaries typically run before any concurrent test threads start.
        unsafe {
            std::env::set_var("DRFW_NFT_COMMAND", &mock_path);
        }
    });
}

/// Creates a basic test ruleset with one SSH rule.
///
/// This is the canonical helper for creating test rulesets.
/// Use this instead of creating rulesets manually in tests.
#[allow(dead_code)] // Available for library tests; integration_tests.rs has its own copy
pub fn create_test_ruleset() -> FirewallRuleset {
    let mut ruleset = FirewallRuleset::new();
    ruleset.rules.push(create_test_rule("Test SSH", Some(22)));
    ruleset
}

/// Creates a test rule with customizable label and port.
///
/// # Arguments
///
/// * `label` - The rule label/comment
/// * `port` - Optional port number (None for no port filtering)
pub fn create_test_rule(label: &str, port: Option<u16>) -> Rule {
    let mut rule = Rule {
        id: Uuid::new_v4(),
        label: label.to_string(),
        protocol: Protocol::Tcp,
        ports: port.map(|p| vec![PortEntry::Single(p)]).unwrap_or_default(),
        sources: vec![],
        destinations: vec![],
        interface: None,
        output_interface: None,
        chain: Chain::Input,
        enabled: true,
        tags: Vec::new(),
        created_at: Utc::now(),
        action: Action::Accept,
        reject_type: RejectType::Default,
        rate_limit: None,
        connection_limit: 0,
        log_enabled: false,
        // Cached fields - will be populated by rebuild_caches()
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

/// Creates a test rule with all fields populated for comprehensive testing.
///
/// # Arguments
///
/// * `label` - The rule label/comment
/// * `protocol` - Protocol type
/// * `port` - Optional port number
/// * `source` - Optional source IP/CIDR as string
/// * `interface` - Optional interface name
pub fn create_full_test_rule(
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
        chain: Chain::Input,
        enabled: true,
        tags: Vec::new(),
        created_at: Utc::now(),
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

/// Checks if nft is available in the system PATH.
///
/// Returns `true` if `nft --version` succeeds, `false` otherwise.
/// This is a synchronous check suitable for test setup.
#[allow(dead_code)] // Available for tests that need sync nft detection
pub fn is_nft_installed() -> bool {
    std::process::Command::new("nft")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
