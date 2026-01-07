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
//! ```
//!
//! The generator automatically creates a `.sha256` checksum file alongside the JSON.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use chrono::Utc;
use clap::Parser;
use drfw::core::firewall::{
    Action, AdvancedSecuritySettings, Chain, EgressProfile, FirewallRuleset, PortEntry,
    Protocol, RateLimit, RejectType, Rule, TimeUnit,
};
use ipnetwork::IpNetwork;
use rand::prelude::*;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// DRFW Stress Test Profile Generator
#[derive(Parser)]
#[command(name = "stress_gen")]
#[command(about = "Generate stress-test profiles for DRFW development and testing")]
struct Args {
    /// Number of rules to generate
    #[arg(short, long, default_value = "100")]
    count: usize,

    /// Output file path (will also create .sha256 checksum)
    #[arg(short, long)]
    output: PathBuf,

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
}

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

        println!("Protocols:");
        for (name, count) in &self.protocols {
            println!("  {name}: {count}");
        }

        println!("\nActions:");
        for (name, count) in &self.actions {
            println!("  {name}: {count}");
        }

        println!("\nChains:");
        for (name, count) in &self.chains {
            println!("  {name}: {count}");
        }

        if !self.reject_types.is_empty() {
            println!("\nReject Types:");
            for (name, count) in &self.reject_types {
                println!("  {name}: {count}");
            }
        }

        if !self.time_units.is_empty() {
            println!("\nRate Limit Time Units:");
            for (name, count) in &self.time_units {
                println!("  {name}: {count}");
            }
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
}

// ═══════════════════════════════════════════════════════════════════════════
// Random Value Generators
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
    // TcpReset only valid for TCP
    if matches!(protocol, Protocol::Tcp | Protocol::TcpAndUdp) {
        *REJECT_TYPES.choose(rng).unwrap()
    } else {
        // Exclude TcpReset for non-TCP protocols
        *REJECT_TYPES[..4].choose(rng).unwrap()
    }
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
    // ICMP protocols don't use ports
    if matches!(
        protocol,
        Protocol::Icmp | Protocol::Icmpv6 | Protocol::IcmpBoth
    ) {
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

fn random_sources(rng: &mut impl Rng) -> Vec<IpNetwork> {
    if rng.gen_bool(0.4) {
        return Vec::new(); // No source filter
    }

    let count = rng.gen_range(1..=4);
    let mut sources = Vec::with_capacity(count);

    for _ in 0..count {
        if rng.gen_bool(0.7) {
            sources.push(random_ipv4(rng));
        } else {
            sources.push(random_ipv6(rng));
        }
    }

    sources
}

fn random_destinations(rng: &mut impl Rng) -> Vec<IpNetwork> {
    if rng.gen_bool(0.6) {
        return Vec::new(); // Less common to have destination filters
    }

    let count = rng.gen_range(1..=3);
    let mut dests = Vec::with_capacity(count);

    for _ in 0..count {
        if rng.gen_bool(0.7) {
            dests.push(random_ipv4(rng));
        } else {
            dests.push(random_ipv6(rng));
        }
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

// ═══════════════════════════════════════════════════════════════════════════
// Edge Case Generators
// ═══════════════════════════════════════════════════════════════════════════

fn edge_case_label(rng: &mut impl Rng, index: usize) -> String {
    let edge_cases = [
        // Contains # (the bug we found!)
        format!("Bug #{} - Critical", index),
        format!("Issue #{}#{}#{}", index, index + 1, index + 2),
        // Contains quotes
        format!("Rule with \"quotes\" #{}", index),
        // Contains backslash
        format!("Path\\to\\rule #{}", index),
        // Unicode (should be sanitized)
        format!("Unicode 日本語 #{}", index),
        format!("Emoji 🔥🛡️ #{}", index),
        // Max length (64 chars)
        "A".repeat(60) + &format!("#{}", index % 1000),
        // Special ASCII
        format!("Special!@$%^&*() #{}", index),
        // Empty-ish
        format!("  Spaces  #{}", index),
    ];

    edge_cases.choose(rng).unwrap().clone()
}

fn edge_case_ports(rng: &mut impl Rng) -> Vec<PortEntry> {
    let cases = [
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
    ];

    cases.choose(rng).unwrap().clone()
}

fn generate_edge_case_rule(rng: &mut impl Rng, index: usize) -> Rule {
    let protocol = random_protocol(rng);
    let action = random_action(rng);
    let chain = random_chain(rng);

    // Intentionally create some semantic mismatches
    let (interface, output_interface) = if rng.gen_bool(0.3) {
        // Semantic mismatch: INPUT chain with output_interface
        if chain == Chain::Input {
            (None, random_interface(rng))
        } else {
            // OUTPUT chain with input interface
            (random_interface(rng), None)
        }
    } else {
        // Normal: appropriate interface for chain
        if chain == Chain::Input {
            (random_interface(rng), None)
        } else {
            (None, random_interface(rng))
        }
    };

    // Edge case ports (unless ICMP)
    let ports = if matches!(
        protocol,
        Protocol::Icmp | Protocol::Icmpv6 | Protocol::IcmpBoth
    ) {
        // Edge case: ICMP with ports specified (should be ignored)
        if rng.gen_bool(0.3) {
            vec![PortEntry::Single(22)] // Should be ignored
        } else {
            Vec::new()
        }
    } else {
        edge_case_ports(rng)
    };

    Rule {
        id: Uuid::new_v4(),
        label: edge_case_label(rng, index),
        protocol,
        ports,
        sources: random_sources(rng),
        interface,
        output_interface,
        chain,
        enabled: rng.gen_bool(0.9),
        created_at: Utc::now(),
        tags: random_tags(rng),
        destinations: random_destinations(rng),
        action,
        reject_type: if action == Action::Reject {
            random_reject_type(rng, protocol)
        } else {
            RejectType::Default
        },
        rate_limit: random_rate_limit(rng),
        connection_limit: random_connection_limit(rng),
        log_enabled: rng.gen_bool(0.2),
        // Cached fields are populated by rebuild_caches()
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
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Main Generation Logic
// ═══════════════════════════════════════════════════════════════════════════

fn generate_rule(rng: &mut impl Rng, index: usize) -> Rule {
    let protocol = random_protocol(rng);
    let action = random_action(rng);
    let chain = random_chain(rng);

    // Appropriate interface for chain direction
    let (interface, output_interface) = if chain == Chain::Input {
        (random_interface(rng), None)
    } else {
        (None, random_interface(rng))
    };

    Rule {
        id: Uuid::new_v4(),
        label: random_label(rng, index),
        protocol,
        ports: random_ports(rng, protocol),
        sources: random_sources(rng),
        interface,
        output_interface,
        chain,
        enabled: rng.gen_bool(0.95), // Most rules enabled
        created_at: Utc::now(),
        tags: random_tags(rng),
        destinations: random_destinations(rng),
        action,
        reject_type: if action == Action::Reject {
            random_reject_type(rng, protocol)
        } else {
            RejectType::Default
        },
        rate_limit: random_rate_limit(rng),
        connection_limit: random_connection_limit(rng),
        log_enabled: rng.gen_bool(0.1),
        // Cached fields are populated by rebuild_caches()
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
    }
}

fn generate_ruleset(rng: &mut impl Rng, count: usize, edge_cases: bool) -> (FirewallRuleset, CoverageTracker) {
    let mut rules = Vec::with_capacity(count);
    let mut tracker = CoverageTracker::default();

    // Ensure at least one of each variant is generated (coverage guarantee)
    let mut ensure_variants = true;
    let mut variant_index = 0;

    for i in 0..count {
        let (rule, is_edge_case) = if edge_cases && rng.gen_bool(0.15) {
            // 15% edge cases when enabled
            (generate_edge_case_rule(rng, i + 1), true)
        } else if ensure_variants && variant_index < PROTOCOLS.len() {
            // Ensure each protocol appears at least once
            let mut rule = generate_rule(rng, i + 1);
            rule.protocol = PROTOCOLS[variant_index];
            // Ensure ports are appropriate for protocol
            if matches!(
                rule.protocol,
                Protocol::Icmp | Protocol::Icmpv6 | Protocol::IcmpBoth
            ) {
                rule.ports.clear();
            }
            variant_index += 1;
            if variant_index >= PROTOCOLS.len() {
                ensure_variants = false;
            }
            (rule, false)
        } else {
            (generate_rule(rng, i + 1), false)
        };

        tracker.record_rule(&rule, is_edge_case);
        rules.push(rule);
    }

    // Rebuild caches for all rules
    for rule in &mut rules {
        rule.rebuild_caches();
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
                println!(
                    "  stderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
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

    // Initialize RNG
    let mut rng: Box<dyn RngCore> = match args.seed {
        Some(seed) => {
            println!("Using seed: {}", seed);
            Box::new(rand::rngs::StdRng::seed_from_u64(seed))
        }
        None => Box::new(rand::thread_rng()),
    };

    println!(
        "Generating {} rules{}...",
        args.count,
        if args.edge_cases {
            " (with edge cases)"
        } else {
            ""
        }
    );

    // Generate ruleset
    let (ruleset, tracker) = generate_ruleset(&mut rng, args.count, args.edge_cases);

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&ruleset).expect("Failed to serialize ruleset");

    // Calculate checksum
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let checksum = format!("{:x}", hasher.finalize());

    // Write JSON file
    std::fs::write(&args.output, &json).expect("Failed to write JSON file");
    println!("Wrote: {}", args.output.display());

    // Write checksum file
    let checksum_path = args.output.with_extension("json.sha256");
    std::fs::write(&checksum_path, &checksum).expect("Failed to write checksum file");
    println!("Wrote: {}", checksum_path.display());

    // Verification
    if args.verify {
        println!("\nVerifying with nft...");
        verify_with_nft(&ruleset);
    }

    // Coverage report
    if args.report {
        tracker.print_report(args.count);
    }

    println!("\nDone! Profile ready for testing.");
}
