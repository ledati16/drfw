//! Shared test utilities for core module tests
//!
//! Provides common test helpers to avoid duplication across test suites.
//! This module is only compiled in test mode.

#![cfg(test)]

use crate::core::firewall::{
    Action, Chain, FirewallRuleset, PortEntry, Protocol, RejectType, Rule,
};
use chrono::Utc;
use uuid::Uuid;

/// Creates a basic test ruleset with one SSH rule.
///
/// This is the canonical helper for creating test rulesets.
/// Use this instead of creating rulesets manually in tests.
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

/// Sets up the test environment for elevation bypass.
///
/// This sets `DRFW_TEST_NO_ELEVATION=1` which causes `create_elevated_nft_command()`
/// to skip pkexec/sudo/run0 and call nft directly.
///
/// # Safety
///
/// Uses `unsafe` because `set_var` is not thread-safe. Tests using this should
/// not run in parallel with other tests that depend on environment variables.
pub fn setup_test_elevation_bypass() {
    // SAFETY: Tests are typically run with --test-threads=1 or this env var
    // is set before any concurrent test execution begins.
    unsafe {
        std::env::set_var("DRFW_TEST_NO_ELEVATION", "1");
    }
}

/// Cleans up the test environment after elevation bypass tests.
///
/// # Safety
///
/// Uses `unsafe` because `remove_var` is not thread-safe.
#[allow(dead_code)]
pub fn cleanup_test_elevation_bypass() {
    // SAFETY: Called at end of test, no concurrent access expected.
    unsafe {
        std::env::remove_var("DRFW_TEST_NO_ELEVATION");
    }
}
