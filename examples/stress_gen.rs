//! Stress Test Profile Generator for DRFW
//!
//! Generates profiles with comprehensive rule variations for testing:
//! - All protocol, action, chain, and reject type combinations
//! - Edge cases: special characters in labels, semantic mismatches
//! - Boundary values: port limits, CIDR ranges
//!
//! # Usage
//!
//! ```bash
//! # Generate 100 rules with good coverage
//! cargo run --example stress_gen -- -o profiles/stress-test.json
//!
//! # Generate 500 rules with edge cases
//! cargo run --example stress_gen -- --count 500 --edge-cases -o profiles/edge-cases.json
//!
//! # Reproducible generation for bug reports
//! cargo run --example stress_gen -- --count 200 --seed 12345 -o /tmp/repro.json
//!
//! # Generate and verify with nft --check
//! cargo run --example stress_gen -- --count 100 --verify -o /tmp/verified.json
//!
//! # Use predefined scenarios
//! cargo run --example stress_gen -- --scenario chaos -o /tmp/chaos.json
//!
//! # Dry run to preview without writing files
//! cargo run --example stress_gen -- --scenario enterprise --dry-run
//! ```
//!
//! The generator automatically creates a `.sha256` checksum file alongside the JSON.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use chrono::{TimeZone, Utc};
use clap::{Parser, ValueEnum};
use drfw::core::firewall::{
    Action, AdvancedSecuritySettings, Chain, EgressProfile, FirewallRuleset, PortEntry, Protocol,
    RateLimit, RejectType, Rule, TimeUnit,
};
use drfw::core::rule_constraints::{
    available_reject_types_for_protocol, chain_uses_input_interface, protocol_requires_ipv4,
    protocol_requires_ipv6, protocol_supports_ports,
};
use drfw::validators::{
    MAX_CONNECTION_LIMIT, MAX_LABEL_LENGTH, MAX_RATE_LIMIT_PER_MINUTE, MAX_RATE_LIMIT_PER_SECOND,
};
use ipnetwork::IpNetwork;
use rand::prelude::*;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════
// CLI Arguments
// ═══════════════════════════════════════════════════════════════════════════

/// DRFW Stress Test Profile Generator
#[derive(Parser)]
#[command(name = "stress_gen")]
#[command(about = "Generate stress-test profiles for DRFW development and testing")]
struct Args {
    /// Number of rules to generate (overridden by --scenario)
    #[arg(short, long, default_value = "100")]
    count: usize,

    /// Output file path (will also create .sha256 checksum)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Include edge cases: special characters, semantic mismatches, boundary values
    #[arg(long)]
    edge_cases: bool,

    /// Random seed for reproducible generation (useful for bug reports)
    #[arg(long)]
    seed: Option<u64>,

    /// Print coverage report showing distribution of generated variants
    #[arg(long)]
    report: bool,

    /// Verify generated rules pass `nft --json --check` (requires nft installed)
    #[arg(long)]
    verify: bool,

    /// Use a predefined scenario (overrides --count and --edge-cases)
    #[arg(long, value_enum)]
    scenario: Option<Scenario>,

    /// Preview generation without writing files
    #[arg(long)]
    dry_run: bool,
}

/// Predefined generation scenarios
#[derive(Clone, Copy, ValueEnum)]
enum Scenario {
    /// 10 rules, basic coverage of all variants
    Minimal,
    /// 50 rules, realistic home/small office setup
    Typical,
    /// 200 rules, complex corporate setup with many tags/interfaces
    Enterprise,
    /// 1000 rules with ALL edge cases and semantic mismatches
    Chaos,
}

impl Scenario {
    const fn count(self) -> usize {
        match self {
            Scenario::Minimal => 10,
            Scenario::Typical => 50,
            Scenario::Enterprise => 200,
            Scenario::Chaos => 1000,
        }
    }

    const fn edge_cases(self) -> bool {
        match self {
            Scenario::Minimal | Scenario::Typical => false,
            Scenario::Enterprise | Scenario::Chaos => true,
        }
    }

    const fn edge_case_probability(self) -> f64 {
        match self {
            Scenario::Minimal | Scenario::Typical => 0.0,
            Scenario::Enterprise => 0.10,
            Scenario::Chaos => 0.40,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Scenario::Minimal => "minimal",
            Scenario::Typical => "typical",
            Scenario::Enterprise => "enterprise",
            Scenario::Chaos => "chaos",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Coverage Tracking
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks coverage of enum variants for reporting
#[derive(Default)]
struct CoverageTracker {
    protocols: HashMap<&'static str, usize>,
    actions: HashMap<&'static str, usize>,
    chains: HashMap<&'static str, usize>,
    reject_types: HashMap<&'static str, usize>,
    time_units: HashMap<&'static str, usize>,
    with_rate_limit: usize,
    with_connection_limit: usize,
    with_logging: usize,
    with_sources: usize,
    with_destinations: usize,
    with_interface: usize,
    with_output_interface: usize,
    with_tags: usize,
    disabled: usize,
    edge_cases: usize,
}

impl CoverageTracker {
    fn record_rule(&mut self, rule: &Rule, is_edge_case: bool) {
        *self.protocols.entry(rule.protocol.as_str()).or_insert(0) += 1;
        *self.actions.entry(rule.action.as_str()).or_insert(0) += 1;
        *self
            .chains
            .entry(match rule.chain {
                Chain::Input => "input",
                Chain::Output => "output",
            })
            .or_insert(0) += 1;

        if rule.action == Action::Reject {
            *self
                .reject_types
                .entry(rule.reject_type.display_name())
                .or_insert(0) += 1;
        }

        if let Some(ref rl) = rule.rate_limit {
            self.with_rate_limit += 1;
            *self
                .time_units
                .entry(match rl.unit {
                    TimeUnit::Second => "second",
                    TimeUnit::Minute => "minute",
                    TimeUnit::Hour => "hour",
                    TimeUnit::Day => "day",
                })
                .or_insert(0) += 1;
        }

        if rule.connection_limit > 0 {
            self.with_connection_limit += 1;
        }
        if rule.log_enabled {
            self.with_logging += 1;
        }
        if !rule.sources.is_empty() {
            self.with_sources += 1;
        }
        if !rule.destinations.is_empty() {
            self.with_destinations += 1;
        }
        if rule.interface.is_some() {
            self.with_interface += 1;
        }
        if rule.output_interface.is_some() {
            self.with_output_interface += 1;
        }
        if !rule.tags.is_empty() {
            self.with_tags += 1;
        }
        if !rule.enabled {
            self.disabled += 1;
        }
        if is_edge_case {
            self.edge_cases += 1;
        }
    }

    fn print_report(&self, total: usize) {
        println!("\n=== Coverage Report ===\n");
        println!("Generated {total} rules:\n");

        // Helper to print sorted hashmap
        fn print_sorted(name: &str, map: &HashMap<&'static str, usize>) {
            println!("{name}:");
            let mut items: Vec<_> = map.iter().collect();
            items.sort_by_key(|(k, _)| *k);
            for (key, count) in items {
                println!("  {key}: {count}");
            }
        }

        print_sorted("Protocols", &self.protocols);
        print_sorted("\nActions", &self.actions);
        print_sorted("\nChains", &self.chains);

        if !self.reject_types.is_empty() {
            print_sorted("\nReject Types", &self.reject_types);
        }

        if !self.time_units.is_empty() {
            print_sorted("\nRate Limit Time Units", &self.time_units);
        }

        println!("\nFeature Usage:");
        println!("  Rate limited: {}", self.with_rate_limit);
        println!("  Connection limited: {}", self.with_connection_limit);
        println!("  Per-rule logging: {}", self.with_logging);
        println!("  With sources: {}", self.with_sources);
        println!("  With destinations: {}", self.with_destinations);
        println!("  With input interface: {}", self.with_interface);
        println!("  With output interface: {}", self.with_output_interface);
        println!("  With tags: {}", self.with_tags);
        println!("  Disabled rules: {}", self.disabled);
        println!("  Edge cases: {}", self.edge_cases);
    }

    /// Check coverage and report any missing variants
    fn check_coverage(&self) -> Vec<String> {
        let mut missing = Vec::new();

        // Check protocols
        for proto in PROTOCOLS {
            if !self.protocols.contains_key(proto.as_str()) {
                missing.push(format!("Protocol::{:?}", proto));
            }
        }

        // Check actions
        for action in ACTIONS {
            if !self.actions.contains_key(action.as_str()) {
                missing.push(format!("Action::{:?}", action));
            }
        }

        // Check chains
        if !self.chains.contains_key("input") {
            missing.push("Chain::Input".to_string());
        }
        if !self.chains.contains_key("output") {
            missing.push("Chain::Output".to_string());
        }

        // Check reject types (only if we have Reject actions)
        if self.actions.contains_key("reject") {
            for reject_type in REJECT_TYPES {
                if !self.reject_types.contains_key(reject_type.display_name()) {
                    missing.push(format!("RejectType::{:?}", reject_type));
                }
            }
        }

        missing
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

const PROTOCOLS: [Protocol; 7] = [
    Protocol::Any,
    Protocol::Tcp,
    Protocol::Udp,
    Protocol::TcpAndUdp,
    Protocol::Icmp,
    Protocol::Icmpv6,
    Protocol::IcmpBoth,
];

const ACTIONS: [Action; 3] = [Action::Accept, Action::Drop, Action::Reject];

const CHAINS: [Chain; 2] = [Chain::Input, Chain::Output];

const REJECT_TYPES: [RejectType; 5] = [
    RejectType::Default,
    RejectType::PortUnreachable,
    RejectType::HostUnreachable,
    RejectType::AdminProhibited,
    RejectType::TcpReset,
];

const TIME_UNITS: [TimeUnit; 4] = [
    TimeUnit::Second,
    TimeUnit::Minute,
    TimeUnit::Hour,
    TimeUnit::Day,
];

const INTERFACE_NAMES: [&str; 10] = [
    "eth0", "eth1", "enp3s0", "wlan0", "docker0", "br0", "lo", "tun0", "wg0", "veth0",
];

// Interface wildcards for edge cases
const INTERFACE_WILDCARDS: [&str; 5] = ["eth*", "docker*", "veth*", "enp*", "wlan*"];

const SERVICE_NAMES: [&str; 20] = [
    "SSH",
    "HTTP",
    "HTTPS",
    "DNS",
    "SMTP",
    "MySQL",
    "PostgreSQL",
    "Redis",
    "MongoDB",
    "Docker",
    "Kubernetes",
    "Prometheus",
    "Grafana",
    "Nginx",
    "Apache",
    "Git",
    "NFS",
    "SMB",
    "VNC",
    "RDP",
];

const TAGS: [&str; 15] = [
    "production",
    "staging",
    "development",
    "critical",
    "monitoring",
    "database",
    "web",
    "api",
    "internal",
    "external",
    "legacy",
    "temporary",
    "security",
    "backup",
    "logging",
];

// Common ports for realistic generation
const COMMON_PORTS: [u16; 20] = [
    22, 80, 443, 8080, 8443, 3000, 3306, 5432, 6379, 27017, 9090, 9100, 25, 587, 993, 143, 53, 123,
    1194, 51820,
];

// Minimum rules needed to guarantee all variants appear
const MIN_COVERAGE_COUNT: usize = 15; // 7 protocols + 3 actions + 5 reject types (worst case)

// ═══════════════════════════════════════════════════════════════════════════
// Rule Builder (DRY: extracts common Rule construction)
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for building a rule
struct RuleConfig {
    protocol: Protocol,
    action: Action,
    chain: Chain,
    reject_type: RejectType,
    label: String,
    ports: Vec<PortEntry>,
    sources: Vec<IpNetwork>,
    destinations: Vec<IpNetwork>,
    interface: Option<String>,
    output_interface: Option<String>,
    rate_limit: Option<RateLimit>,
    connection_limit: u32,
    log_enabled: bool,
    enabled: bool,
    tags: Vec<String>,
    timestamp: chrono::DateTime<Utc>,
}

impl RuleConfig {
    fn into_rule(self) -> Rule {
        let mut rule = Rule {
            id: Uuid::new_v4(),
            label: self.label,
            protocol: self.protocol,
            ports: self.ports,
            sources: self.sources,
            interface: self.interface,
            output_interface: self.output_interface,
            chain: self.chain,
            enabled: self.enabled,
            created_at: self.timestamp,
            tags: self.tags,
            destinations: self.destinations,
            action: self.action,
            reject_type: self.reject_type,
            rate_limit: self.rate_limit,
            connection_limit: self.connection_limit,
            log_enabled: self.log_enabled,
            // Cached fields (populated by rebuild_caches())
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
}

// ═══════════════════════════════════════════════════════════════════════════
// Random Value Generators
// ═══════════════════════════════════════════════════════════════════════════

fn random_protocol(rng: &mut impl Rng) -> Protocol {
    *PROTOCOLS.choose(rng).unwrap()
}

fn random_action(rng: &mut impl Rng) -> Action {
    // Weight towards Accept (more common in real rulesets)
    let weights = [60, 25, 15]; // Accept, Drop, Reject
    let dist = rand::distributions::WeightedIndex::new(weights).unwrap();
    ACTIONS[dist.sample(rng)]
}

fn random_reject_type(rng: &mut impl Rng, protocol: Protocol) -> RejectType {
    // Use centralized constraint logic for valid reject types
    let valid_types = available_reject_types_for_protocol(protocol);
    *valid_types.choose(rng).unwrap()
}

fn random_chain(rng: &mut impl Rng) -> Chain {
    // Weight towards Input (more common)
    if rng.gen_bool(0.7) {
        Chain::Input
    } else {
        Chain::Output
    }
}

fn random_ports(rng: &mut impl Rng, protocol: Protocol) -> Vec<PortEntry> {
    // Use centralized constraint logic for port support
    if !protocol_supports_ports(protocol) {
        return Vec::new();
    }

    // Sometimes no port filter (all ports)
    if rng.gen_bool(0.15) {
        return Vec::new();
    }

    let count = rng.gen_range(1..=3);
    let mut ports = Vec::with_capacity(count);

    for _ in 0..count {
        if rng.gen_bool(0.8) {
            // Single port (more common)
            let port = if rng.gen_bool(0.7) {
                // Common port
                *COMMON_PORTS.choose(rng).unwrap()
            } else {
                // Random port
                rng.gen_range(1..=65535)
            };
            ports.push(PortEntry::Single(port));
        } else {
            // Port range
            let start = rng.gen_range(1..=65000);
            let end = rng.gen_range(start..=65535);
            ports.push(PortEntry::Range { start, end });
        }
    }

    ports
}

fn random_ipv4(rng: &mut impl Rng) -> IpNetwork {
    let ip = std::net::Ipv4Addr::new(
        rng.gen_range(1..=223),
        rng.gen_range(0..=255),
        rng.gen_range(0..=255),
        rng.gen_range(1..=254),
    );
    let prefix = *[8, 16, 24, 32].choose(rng).unwrap();
    IpNetwork::new(std::net::IpAddr::V4(ip), prefix).unwrap()
}

fn random_ipv6(rng: &mut impl Rng) -> IpNetwork {
    // Generate realistic IPv6 prefixes
    let prefixes = ["2001:db8::", "fd00::", "fe80::", "2607:f8b0::"];
    let prefix_str = *prefixes.choose(rng).unwrap();
    let suffix: u16 = rng.gen_range(0..=65535);
    let addr_str = format!("{prefix_str}{suffix:x}");
    let addr: std::net::Ipv6Addr = addr_str.parse().unwrap_or_else(|_| {
        // Fallback to simple address
        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, rng.gen_range(0..=65535))
    });
    let prefix_len = *[48, 64, 128].choose(rng).unwrap();
    IpNetwork::new(std::net::IpAddr::V6(addr), prefix_len).unwrap()
}

fn random_sources(rng: &mut impl Rng, protocol: Protocol) -> Vec<IpNetwork> {
    if rng.gen_bool(0.4) {
        return Vec::new(); // No source filter
    }

    let count = rng.gen_range(1..=4);
    let mut sources = Vec::with_capacity(count);

    for _ in 0..count {
        // Use centralized constraint for IP version compatibility
        let ip = if protocol_requires_ipv4(protocol) {
            // ICMP (v4) only works with IPv4
            random_ipv4(rng)
        } else if protocol_requires_ipv6(protocol) {
            // ICMPv6 only works with IPv6
            random_ipv6(rng)
        } else if rng.gen_bool(0.7) {
            // Other protocols: prefer IPv4 but allow IPv6
            random_ipv4(rng)
        } else {
            random_ipv6(rng)
        };
        sources.push(ip);
    }

    sources
}

fn random_destinations(rng: &mut impl Rng, protocol: Protocol) -> Vec<IpNetwork> {
    if rng.gen_bool(0.6) {
        return Vec::new(); // Less common to have destination filters
    }

    let count = rng.gen_range(1..=3);
    let mut dests = Vec::with_capacity(count);

    for _ in 0..count {
        // Use centralized constraint for IP version compatibility
        let ip = if protocol_requires_ipv4(protocol) {
            // ICMP (v4) only works with IPv4
            random_ipv4(rng)
        } else if protocol_requires_ipv6(protocol) {
            // ICMPv6 only works with IPv6
            random_ipv6(rng)
        } else if rng.gen_bool(0.7) {
            // Other protocols: prefer IPv4 but allow IPv6
            random_ipv4(rng)
        } else {
            random_ipv6(rng)
        };
        dests.push(ip);
    }

    dests
}

fn random_interface(rng: &mut impl Rng) -> Option<String> {
    if rng.gen_bool(0.7) {
        None
    } else {
        Some(INTERFACE_NAMES.choose(rng).unwrap().to_string())
    }
}

fn random_rate_limit(rng: &mut impl Rng) -> Option<RateLimit> {
    if rng.gen_bool(0.75) {
        return None;
    }

    let unit = *TIME_UNITS.choose(rng).unwrap();
    // Use typical values (well below validator maximums)
    let count = match unit {
        TimeUnit::Second => rng.gen_range(1..=100),
        TimeUnit::Minute => rng.gen_range(1..=1000),
        TimeUnit::Hour => rng.gen_range(1..=5000),
        TimeUnit::Day => rng.gen_range(1..=10000),
    };

    let burst = if rng.gen_bool(0.5) {
        Some(rng.gen_range(count..=count * 3))
    } else {
        None
    };

    Some(RateLimit { count, unit, burst })
}

fn random_connection_limit(rng: &mut impl Rng) -> u32 {
    if rng.gen_bool(0.8) {
        0 // Disabled
    } else {
        rng.gen_range(1..=100)
    }
}

fn random_tags(rng: &mut impl Rng) -> Vec<String> {
    if rng.gen_bool(0.5) {
        return Vec::new();
    }

    let count = rng.gen_range(1..=3);
    TAGS.choose_multiple(rng, count)
        .map(|s| (*s).to_string())
        .collect()
}

fn random_label(rng: &mut impl Rng, index: usize) -> String {
    let service = *SERVICE_NAMES.choose(rng).unwrap();
    let suffix = ["Rule", "Access", "Allow", "Block", "Filter"];
    let chosen_suffix = *suffix.choose(rng).unwrap();
    format!("{} {} #{}", service, chosen_suffix, index)
}

fn random_timestamp(rng: &mut impl Rng, vary: bool) -> chrono::DateTime<Utc> {
    if vary {
        // Vary timestamps: past year to now
        let now = Utc::now().timestamp();
        let year_ago = now - 365 * 24 * 3600;
        let random_ts = rng.gen_range(year_ago..=now);
        Utc.timestamp_opt(random_ts, 0).unwrap()
    } else {
        Utc::now()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge Case Generators
// ═══════════════════════════════════════════════════════════════════════════

fn edge_case_label(rng: &mut impl Rng, index: usize) -> String {
    // All edge case labels use only valid characters per sanitize_label():
    // ASCII alphanumeric, space, dash, underscore, dot, colon
    let edge_cases = [
        // Issue reference style (# is not valid, use colon instead)
        format!("Bug {:03} - Critical", index),
        format!("Issue-{}-{}-{}", index, index + 1, index + 2),
        // Path-like with valid separators
        format!("Path.to.rule.{}", index),
        format!("Path_to_rule_{}", index),
        // Unicode label names (will be sanitized to ASCII-only)
        format!("Unicode-Rule-{}", index),
        format!("Intl-Rule-{}", index),
        // Max length - exactly at boundary (use validator constant)
        {
            let base = format!("-{}", index);
            let padding = MAX_LABEL_LENGTH - base.len();
            format!("{}{}", "A".repeat(padding), base)
        },
        // Near max length (one less than max)
        {
            let base = format!("-{}", index);
            let padding = MAX_LABEL_LENGTH - 1 - base.len();
            format!("{}{}", "B".repeat(padding), base)
        },
        // Colon separator (valid for labels)
        format!("Service:Port:{}", index),
        // Multiple spaces (valid)
        format!("Spaced  Rule  {}", index),
        // Short label
        format!("R{}", index),
        // Mixed case
        format!("MixedCase-RULE-{}", index),
        // Dots and dashes
        format!("rule.v2-beta_{}", index),
    ];

    edge_cases.choose(rng).unwrap().clone()
}

fn edge_case_ports(rng: &mut impl Rng) -> Vec<PortEntry> {
    let cases: Vec<Vec<PortEntry>> = vec![
        // Boundary: port 1
        vec![PortEntry::Single(1)],
        // Boundary: port 65535
        vec![PortEntry::Single(65535)],
        // Full range
        vec![PortEntry::Range {
            start: 1,
            end: 65535,
        }],
        // Many ports
        vec![
            PortEntry::Single(22),
            PortEntry::Single(80),
            PortEntry::Single(443),
            PortEntry::Single(8080),
            PortEntry::Single(8443),
        ],
        // Mixed ranges and singles
        vec![
            PortEntry::Single(22),
            PortEntry::Range {
                start: 80,
                end: 90,
            },
            PortEntry::Single(443),
        ],
        // Single port as range (80-80)
        vec![PortEntry::Range {
            start: 80,
            end: 80,
        }],
        // Duplicate ports
        vec![
            PortEntry::Single(80),
            PortEntry::Single(80),
            PortEntry::Single(443),
        ],
        // Overlapping ranges
        vec![
            PortEntry::Range {
                start: 80,
                end: 100,
            },
            PortEntry::Range {
                start: 90,
                end: 110,
            },
        ],
        // Adjacent ranges
        vec![
            PortEntry::Range {
                start: 80,
                end: 89,
            },
            PortEntry::Range {
                start: 90,
                end: 99,
            },
        ],
    ];

    cases.choose(rng).unwrap().clone()
}

fn edge_case_sources(rng: &mut impl Rng, protocol: Protocol) -> Vec<IpNetwork> {
    // Use centralized constraint for IP version compatibility
    let ipv4_cases: Vec<Vec<IpNetwork>> = vec![
        // Any IPv4 (0.0.0.0/0)
        vec!["0.0.0.0/0".parse().unwrap()],
        // Single host IPv4 (/32)
        vec!["192.168.1.1/32".parse().unwrap()],
        // Link-local IPv4
        vec!["169.254.0.0/16".parse().unwrap()],
        // Loopback
        vec!["127.0.0.0/8".parse().unwrap()],
        // Mix of specific networks
        vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
        ],
    ];

    let ipv6_cases: Vec<Vec<IpNetwork>> = vec![
        // Any IPv6 (::/0)
        vec!["::/0".parse().unwrap()],
        // Single host IPv6 (/128)
        vec!["2001:db8::1/128".parse().unwrap()],
        // Link-local IPv6
        vec!["fe80::/10".parse().unwrap()],
        // IPv6 loopback
        vec!["::1/128".parse().unwrap()],
    ];

    // Select appropriate cases based on protocol constraints
    if protocol_requires_ipv4(protocol) {
        ipv4_cases.choose(rng).unwrap().clone()
    } else if protocol_requires_ipv6(protocol) {
        ipv6_cases.choose(rng).unwrap().clone()
    } else {
        // Other protocols: mix of both (can include mixed cases)
        let mixed_cases: Vec<Vec<IpNetwork>> = vec![
            vec!["0.0.0.0/0".parse().unwrap()],
            vec!["::/0".parse().unwrap()],
            vec!["192.168.1.1/32".parse().unwrap()],
            vec!["2001:db8::1/128".parse().unwrap()],
            // Mix of any-IP and specific (valid for non-ICMP protocols)
            vec![
                "0.0.0.0/0".parse().unwrap(),
                "192.168.1.0/24".parse().unwrap(),
            ],
        ];
        mixed_cases.choose(rng).unwrap().clone()
    }
}

fn edge_case_interface(rng: &mut impl Rng) -> Option<String> {
    let cases = [
        // Normal interfaces
        Some("eth0".to_string()),
        Some("lo".to_string()),
        // Wildcards
        Some(INTERFACE_WILDCARDS.choose(rng).unwrap().to_string()),
        // Long interface name (max 15 chars for Linux)
        Some("abcdefghijklmno".to_string()),
        // None
        None,
    ];

    cases.choose(rng).unwrap().clone()
}

fn edge_case_tags(rng: &mut impl Rng) -> Vec<String> {
    let cases: Vec<Vec<String>> = vec![
        // Empty
        vec![],
        // Many tags (10+)
        (0..12).map(|i| format!("tag{}", i)).collect(),
        // Tags with special characters (valid per sanitize_label)
        vec![
            "tag-with-dash".to_string(),
            "tag_underscore".to_string(),
            "tag.dot".to_string(),
        ],
        // Single character tags
        vec!["a".to_string(), "b".to_string(), "c".to_string()],
        // Max length tag (same as label limit, use validator constant)
        vec!["a".repeat(MAX_LABEL_LENGTH)],
    ];

    cases.choose(rng).unwrap().clone()
}

fn edge_case_rate_limit(rng: &mut impl Rng) -> Option<RateLimit> {
    // Use validator constants for edge case limits
    let cases = [
        // High rate at validator limit
        Some(RateLimit {
            count: MAX_RATE_LIMIT_PER_SECOND,
            unit: TimeUnit::Second,
            burst: None,
        }),
        // Very low rate
        Some(RateLimit {
            count: 1,
            unit: TimeUnit::Day,
            burst: None,
        }),
        // Large burst
        Some(RateLimit {
            count: 10,
            unit: TimeUnit::Minute,
            burst: Some(1000),
        }),
        // High minute rate at validator limit
        Some(RateLimit {
            count: MAX_RATE_LIMIT_PER_MINUTE,
            unit: TimeUnit::Minute,
            burst: None,
        }),
        // None
        None,
    ];

    *cases.choose(rng).unwrap()
}

fn edge_case_connection_limit(rng: &mut impl Rng) -> u32 {
    // Use validator constant for kernel maximum
    let cases = [
        0,                    // Disabled
        1,                    // Minimum
        100,                  // Normal
        MAX_CONNECTION_LIMIT, // Maximum (kernel limit)
    ];

    *cases.choose(rng).unwrap()
}

fn edge_case_timestamp(rng: &mut impl Rng) -> chrono::DateTime<Utc> {
    let cases = [
        // Unix epoch
        Utc.timestamp_opt(0, 0).unwrap(),
        // Very old (Y2K)
        Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap(),
        // Future (next year)
        Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
        // Now
        Utc::now(),
    ];

    *cases.choose(rng).unwrap()
}

fn generate_edge_case_rule(rng: &mut impl Rng, index: usize) -> Rule {
    let protocol = random_protocol(rng);
    let action = random_action(rng);
    let chain = random_chain(rng);

    // Intentionally create some semantic mismatches for testing
    let (interface, output_interface) = if rng.gen_bool(0.3) {
        // Semantic mismatch: opposite interface for chain (tests display/handling)
        if chain_uses_input_interface(chain) {
            (None, edge_case_interface(rng))
        } else {
            // OUTPUT chain with input interface
            (edge_case_interface(rng), None)
        }
    } else {
        // Normal: appropriate interface for chain
        if chain_uses_input_interface(chain) {
            (edge_case_interface(rng), None)
        } else {
            (None, edge_case_interface(rng))
        }
    };

    // Use centralized constraint for port support
    let ports = if !protocol_supports_ports(protocol) {
        // Edge case: non-port protocol with ports specified (should be ignored by nft)
        if rng.gen_bool(0.3) {
            vec![PortEntry::Single(22)] // Will be stripped when converting to nft
        } else {
            Vec::new()
        }
    } else {
        edge_case_ports(rng)
    };

    RuleConfig {
        protocol,
        action,
        chain,
        reject_type: if action == Action::Reject {
            random_reject_type(rng, protocol)
        } else {
            RejectType::Default
        },
        label: edge_case_label(rng, index),
        ports,
        sources: if rng.gen_bool(0.5) {
            edge_case_sources(rng, protocol)
        } else {
            random_sources(rng, protocol)
        },
        destinations: if rng.gen_bool(0.4) {
            edge_case_sources(rng, protocol) // Reuse edge case sources for destinations
        } else {
            random_destinations(rng, protocol)
        },
        interface,
        output_interface,
        rate_limit: edge_case_rate_limit(rng),
        connection_limit: edge_case_connection_limit(rng),
        log_enabled: rng.gen_bool(0.3),
        enabled: rng.gen_bool(0.85),
        tags: edge_case_tags(rng),
        timestamp: edge_case_timestamp(rng),
    }
    .into_rule()
}

// ═══════════════════════════════════════════════════════════════════════════
// Main Generation Logic
// ═══════════════════════════════════════════════════════════════════════════

fn generate_rule(rng: &mut impl Rng, index: usize, vary_timestamps: bool) -> Rule {
    let protocol = random_protocol(rng);
    let action = random_action(rng);
    let chain = random_chain(rng);

    // Use centralized constraint logic for interface-chain relationship
    let (interface, output_interface) = if chain_uses_input_interface(chain) {
        (random_interface(rng), None)
    } else {
        (None, random_interface(rng))
    };

    RuleConfig {
        protocol,
        action,
        chain,
        reject_type: if action == Action::Reject {
            random_reject_type(rng, protocol)
        } else {
            RejectType::Default
        },
        label: random_label(rng, index),
        ports: random_ports(rng, protocol),
        sources: random_sources(rng, protocol),
        destinations: random_destinations(rng, protocol),
        interface,
        output_interface,
        rate_limit: random_rate_limit(rng),
        connection_limit: random_connection_limit(rng),
        log_enabled: rng.gen_bool(0.1),
        enabled: rng.gen_bool(0.95),
        tags: random_tags(rng),
        timestamp: random_timestamp(rng, vary_timestamps),
    }
    .into_rule()
}

/// Generate a rule with specific forced variants for coverage guarantee
fn generate_coverage_rule(
    rng: &mut impl Rng,
    index: usize,
    protocol: Protocol,
    action: Action,
    chain: Chain,
    reject_type: Option<RejectType>,
    time_unit: Option<TimeUnit>,
) -> Rule {
    // Use centralized constraint logic for interface-chain relationship
    let (interface, output_interface) = if chain_uses_input_interface(chain) {
        (random_interface(rng), None)
    } else {
        (None, random_interface(rng))
    };

    // Use centralized constraint logic for port support
    let ports = if !protocol_supports_ports(protocol) {
        Vec::new()
    } else {
        random_ports(rng, protocol)
    };

    // Force rate limit if time_unit is specified
    let rate_limit = if let Some(unit) = time_unit {
        let count = match unit {
            TimeUnit::Second => rng.gen_range(1..=100),
            TimeUnit::Minute => rng.gen_range(1..=1000),
            TimeUnit::Hour => rng.gen_range(1..=5000),
            TimeUnit::Day => rng.gen_range(1..=10000),
        };
        Some(RateLimit {
            count,
            unit,
            burst: if rng.gen_bool(0.5) {
                Some(rng.gen_range(count..=count * 3))
            } else {
                None
            },
        })
    } else {
        random_rate_limit(rng)
    };

    RuleConfig {
        protocol,
        action,
        chain,
        reject_type: reject_type.unwrap_or(RejectType::Default),
        label: random_label(rng, index),
        ports,
        sources: random_sources(rng, protocol),
        destinations: random_destinations(rng, protocol),
        interface,
        output_interface,
        rate_limit,
        connection_limit: random_connection_limit(rng),
        log_enabled: rng.gen_bool(0.1),
        enabled: rng.gen_bool(0.95),
        tags: random_tags(rng),
        timestamp: Utc::now(),
    }
    .into_rule()
}

fn generate_ruleset(
    rng: &mut impl Rng,
    count: usize,
    edge_cases: bool,
    edge_case_prob: f64,
) -> (FirewallRuleset, CoverageTracker) {
    let mut rules = Vec::with_capacity(count);
    let mut tracker = CoverageTracker::default();
    let mut rule_index = 0;

    // Phase 1: Guarantee all variants appear
    // Generate rules to cover all Protocol variants
    for protocol in PROTOCOLS {
        if rule_index >= count {
            break;
        }
        let action = random_action(rng);
        let chain = random_chain(rng);
        let rule = generate_coverage_rule(
            rng,
            rule_index + 1,
            protocol,
            action,
            chain,
            None,
            None,
        );
        tracker.record_rule(&rule, false);
        rules.push(rule);
        rule_index += 1;
    }

    // Generate rules to cover all Action variants (especially Reject for reject types)
    for action in ACTIONS {
        if rule_index >= count {
            break;
        }
        // Skip if we might have already covered this action
        if rules.iter().any(|r| r.action == action) {
            continue;
        }
        let protocol = if action == Action::Reject {
            Protocol::Tcp // TCP for reject types
        } else {
            random_protocol(rng)
        };
        let chain = random_chain(rng);
        let rule = generate_coverage_rule(
            rng,
            rule_index + 1,
            protocol,
            action,
            chain,
            None,
            None,
        );
        tracker.record_rule(&rule, false);
        rules.push(rule);
        rule_index += 1;
    }

    // Generate rules to cover all Chain variants
    for chain in CHAINS {
        if rule_index >= count {
            break;
        }
        if rules.iter().any(|r| r.chain == chain) {
            continue;
        }
        let protocol = random_protocol(rng);
        let action = random_action(rng);
        let rule = generate_coverage_rule(
            rng,
            rule_index + 1,
            protocol,
            action,
            chain,
            None,
            None,
        );
        tracker.record_rule(&rule, false);
        rules.push(rule);
        rule_index += 1;
    }

    // Generate rules to cover all RejectType variants
    for reject_type in REJECT_TYPES {
        if rule_index >= count {
            break;
        }
        // Use TCP for all reject types (TcpReset specifically requires it)
        let protocol = Protocol::Tcp;
        let chain = random_chain(rng);
        let rule = generate_coverage_rule(
            rng,
            rule_index + 1,
            protocol,
            Action::Reject,
            chain,
            Some(reject_type),
            None,
        );
        tracker.record_rule(&rule, false);
        rules.push(rule);
        rule_index += 1;
    }

    // Generate rules to cover all TimeUnit variants
    for time_unit in TIME_UNITS {
        if rule_index >= count {
            break;
        }
        let protocol = random_protocol(rng);
        let action = random_action(rng);
        let chain = random_chain(rng);
        let rule = generate_coverage_rule(
            rng,
            rule_index + 1,
            protocol,
            action,
            chain,
            None,
            Some(time_unit),
        );
        tracker.record_rule(&rule, false);
        rules.push(rule);
        rule_index += 1;
    }

    // Phase 2: Generate remaining rules randomly
    let vary_timestamps = edge_cases; // Vary timestamps when edge cases enabled
    for i in rule_index..count {
        let (rule, is_edge_case) = if edge_cases && rng.gen_bool(edge_case_prob) {
            (generate_edge_case_rule(rng, i + 1), true)
        } else {
            (generate_rule(rng, i + 1, vary_timestamps), false)
        };

        tracker.record_rule(&rule, is_edge_case);
        rules.push(rule);
    }

    // Randomize advanced security settings
    let advanced_security = AdvancedSecuritySettings {
        strict_icmp: rng.gen_bool(0.3),
        icmp_rate_limit: if rng.gen_bool(0.4) {
            rng.gen_range(1..=50)
        } else {
            0
        },
        enable_rpf: rng.gen_bool(0.2),
        log_dropped: rng.gen_bool(0.3),
        log_rate_per_minute: rng.gen_range(1..=20),
        log_prefix: "DRFW-DROP: ".to_string(),
        egress_profile: if rng.gen_bool(0.7) {
            EgressProfile::Desktop
        } else {
            EgressProfile::Server
        },
    };

    (
        FirewallRuleset {
            rules,
            advanced_security,
        },
        tracker,
    )
}

fn verify_with_nft(ruleset: &FirewallRuleset) -> bool {
    let json = ruleset.to_nftables_json();
    let json_str = serde_json::to_string(&json).expect("Failed to serialize JSON");

    let output = Command::new("nft")
        .args(["--json", "--check", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(json_str.as_bytes())?;
            child.wait_with_output()
        });

    match output {
        Ok(output) => {
            if output.status.success() {
                println!("  nft --check: PASSED");
                true
            } else {
                println!("  nft --check: FAILED");
                println!("  stderr: {}", String::from_utf8_lossy(&output.stderr));
                false
            }
        }
        Err(e) => {
            println!("  nft --check: SKIPPED (nft not available: {})", e);
            true // Don't fail if nft isn't installed
        }
    }
}

fn main() {
    let args = Args::parse();

    // Determine effective count and edge_cases from scenario or args
    let (count, edge_cases, edge_case_prob, scenario_name) = if let Some(scenario) = args.scenario {
        (
            scenario.count(),
            scenario.edge_cases(),
            scenario.edge_case_probability(),
            Some(scenario.name()),
        )
    } else {
        (args.count, args.edge_cases, 0.15, None)
    };

    // Validate count
    if count < MIN_COVERAGE_COUNT {
        eprintln!(
            "Warning: count {} is less than minimum for full coverage ({}). \
             Not all enum variants may appear.",
            count, MIN_COVERAGE_COUNT
        );
    }

    // Check output path for non-dry-run
    if !args.dry_run && args.output.is_none() {
        eprintln!("Error: --output is required (or use --dry-run)");
        std::process::exit(1);
    }

    // Initialize RNG
    let mut rng: Box<dyn RngCore> = match args.seed {
        Some(seed) => {
            println!("Using seed: {}", seed);
            Box::new(rand::rngs::StdRng::seed_from_u64(seed))
        }
        None => Box::new(rand::thread_rng()),
    };

    // Print generation info
    if let Some(name) = scenario_name {
        println!("Scenario: {}", name);
    }
    println!(
        "Generating {} rules{}...",
        count,
        if edge_cases {
            format!(" (with edge cases, {}% probability)", (edge_case_prob * 100.0) as u32)
        } else {
            String::new()
        }
    );

    // Generate ruleset
    let (ruleset, tracker) = generate_ruleset(&mut rng, count, edge_cases, edge_case_prob);

    // Check coverage
    let missing = tracker.check_coverage();
    if !missing.is_empty() {
        eprintln!("\nWarning: Missing coverage for: {:?}", missing);
    }

    // Dry run: just show stats
    if args.dry_run {
        println!("\n[DRY RUN] Would generate {} rules", ruleset.rules.len());
        if args.report {
            tracker.print_report(count);
        }

        // Verification in dry-run mode
        if args.verify {
            println!("\nVerifying with nft...");
            verify_with_nft(&ruleset);
        }

        println!("\nDry run complete. No files written.");
        return;
    }

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&ruleset).expect("Failed to serialize ruleset");

    // Calculate checksum
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let checksum = format!("{:x}", hasher.finalize());

    // Write JSON file
    let output_path = args.output.as_ref().unwrap();
    std::fs::write(output_path, &json).expect("Failed to write JSON file");
    println!("Wrote: {}", output_path.display());

    // Write checksum file
    let checksum_path = output_path.with_extension("json.sha256");
    std::fs::write(&checksum_path, &checksum).expect("Failed to write checksum file");
    println!("Wrote: {}", checksum_path.display());

    // Verification
    if args.verify {
        println!("\nVerifying with nft...");
        verify_with_nft(&ruleset);
    }

    // Coverage report
    if args.report {
        tracker.print_report(count);
    }

    println!("\nDone! Profile ready for testing.");
}
