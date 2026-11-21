//! Shared test utilities for core module tests
//!
//! Provides common test helpers to avoid duplication across test suites.
//! This module is only compiled in test mode.

use std::sync::Once;

use jiff::Timestamp;
use uuid::Uuid;

use crate::core::firewall::{Chain, FirewallRuleset, PortEntry, Protocol, Rule};

/// Timestamps exactly as earlier, chrono-based DRFW builds wrote them (and as
/// hand-edited files may contain them), with their Unix time in nanoseconds.
///
/// chrono 0.4 serialized `DateTime<Utc>` as RFC 3339 with `Z` and 0, 3, 6 or 9
/// fractional digits (whichever is exact). Its deserializer also accepted any
/// offset, so `+00:00` and non-UTC offsets are covered too. Used by the
/// `Rule.created_at` and `AuditEvent.timestamp` compatibility tests.
pub const CHRONO_TIMESTAMPS: &[(&str, i128)] = &[
    // Utc::now() as written by chrono (nanosecond precision)
    ("2026-11-20T22:39:15.366180715Z", 1_795_214_355_366_180_715),
    ("2026-11-20T22:39:15.000000001Z", 1_795_214_355_000_000_001),
    // Microsecond and millisecond precision (trailing zeros dropped in groups)
    ("2026-11-20T22:39:15.366180Z", 1_795_214_355_366_180_000),
    ("2026-11-20T22:39:15.366Z", 1_795_214_355_366_000_000),
    // Whole seconds
    ("2026-11-20T22:39:15Z", 1_795_214_355_000_000_000),
    ("1970-01-01T00:00:00Z", 0),
    // Explicit offsets (to_rfc3339(), hand edits)
    ("2026-11-20T22:39:15+00:00", 1_795_214_355_000_000_000),
    (
        "2026-11-20T22:39:15.366180715+00:00",
        1_795_214_355_366_180_715,
    ),
    ("2026-11-20T23:39:15.5+01:00", 1_795_214_355_500_000_000),
    ("2026-11-20T17:39:15-05:00", 1_795_214_355_000_000_000),
];

/// One-time initialization flag for mock nft setup
static MOCK_NFT_INIT: Once = Once::new();

/// Sets up the mock nft script for testing.
///
/// Sets `DRFW_NFT_COMMAND` to the mock script path (`tests/mock_nft.sh`),
/// which causes all nft operations to use the mock instead of real nftables.
///
/// - Thread-safe and can be called multiple times (initialization happens once)
/// - No guard to hold, so no `await_holding_lock` issues in async tests
///
/// This is the only change any lib test makes to the process environment,
/// and the variable is never removed again, so a test can never see it unset
/// once it has called this. (Elevation is tested through pure functions; an
/// accidental elevation or use of the real data/state directories panics in
/// lib tests.)
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
        // SAFETY: set once, never removed; no lib test changes the
        // environment otherwise
        unsafe {
            std::env::set_var("DRFW_NFT_COMMAND", &mock_path);
        }
    });
}

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
    create_full_test_rule(label, Protocol::Tcp, port, None, None)
}

/// Creates a test rule with all fields populated for comprehensive testing.
///
/// Built on [`Rule::with_caches`] (caches rebuilt), so a new `Rule` field
/// only has to be added there.
///
/// # Arguments
///
/// * `label` - The rule label/comment
/// * `protocol` - Protocol type
/// * `port` - Optional port number
/// * `source` - Optional source IP/CIDR as string
/// * `interface` - Optional interface name
///
/// # Panics
///
/// If `source` is not a valid IP/CIDR (a typo must not silently drop it).
pub fn create_full_test_rule(
    label: &str,
    protocol: Protocol,
    port: Option<u16>,
    source: Option<&str>,
    interface: Option<&str>,
) -> Rule {
    Rule::with_caches(
        Uuid::new_v4(),
        label.to_string(),
        protocol,
        port.map_or_default(|p| vec![PortEntry::Single(p)]),
        source.map_or_default(|s| vec![s.parse().expect("valid test source")]),
        interface.map(String::from),
        Chain::Input,
        true,
        Timestamp::now(),
        Vec::new(),
    )
}
