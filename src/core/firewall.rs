//! Firewall rule data structures and nftables code generation
//!
//! This module defines the core data structures for representing firewall rules
//! and provides functionality to convert them into nftables configuration format.
//!
//! # Rule Structure
//!
//! A [`Rule`] represents a single firewall rule with:
//! - Protocol filtering (TCP, UDP, TCP+UDP, ICMP, etc.)
//! - Port ranges for applicable protocols
//! - Source IP/network filtering
//! - Network interface filtering
//! - Chain direction (Input/Output) - only relevant in Server Mode
//! - Enable/disable state
//! - Tags for organization
//! - Advanced options: destination IP, action (Accept/Drop/Reject), rate limiting, connection limiting
//!
//! # Limits
//!
//! Profiles are limited to [`MAX_RULES`] rules to prevent memory exhaustion.
//!
//! # Example
//!
//! ```
//! use drfw::core::firewall::{Rule, Protocol, PortRange, Chain};
//! use uuid::Uuid;
//!
//! let mut rule = Rule {
//!     id: Uuid::new_v4(),
//!     label: "Allow SSH".to_string(),
//!     protocol: Protocol::Tcp,
//!     ports: Some(PortRange::single(22)),
//!     source: None,
//!     interface: None,
//!     chain: Chain::Input,
//!     enabled: true,
//!     created_at: chrono::Utc::now(),
//!     tags: vec![],
//!     // Advanced options
//!     destination: None,
//!     action: drfw::core::firewall::Action::Accept,
//!     rate_limit: None,
//!     connection_limit: 0,
//!     // Cached fields (populated by rebuild_caches())
//!     label_lowercase: String::new(),
//!     interface_lowercase: None,
//!     tags_lowercase: Vec::new(),
//!     protocol_lowercase: "",
//!     port_display: String::new(),
//!     source_string: None,
//!     destination_string: None,
//!     rate_limit_display: None,
//!     action_display: String::new(),
//!     interface_display: String::new(),
//! };
//! rule.rebuild_caches();
//! ```

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Maximum number of rules allowed in a single ruleset
///
/// Limit prevents memory exhaustion from malformed/malicious profiles.
/// 1000 rules is well beyond typical use cases (most users have <50).
pub const MAX_RULES: usize = 1000;

/// Network protocol type for firewall rules
///
/// Supports common protocols used in nftables filtering.
/// `Copy` trait allows efficient passing by value for this small enum.
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::AsRefStr,
)]
pub enum Protocol {
    /// Match all protocols
    #[strum(serialize = "any")]
    Any,
    /// Transmission Control Protocol
    #[strum(serialize = "tcp")]
    Tcp,
    /// User Datagram Protocol
    #[strum(serialize = "udp")]
    Udp,
    /// Both TCP and UDP (common for services like DNS, VPNs, game servers)
    #[strum(serialize = "tcp+udp")]
    TcpAndUdp,
    /// Internet Control Message Protocol (IPv4)
    #[strum(serialize = "icmp")]
    Icmp,
    /// Internet Control Message Protocol version 6
    #[strum(serialize = "icmpv6")]
    Icmpv6,
    /// Both ICMP and `ICMPv6` (dual-stack support, recommended default)
    #[strum(serialize = "icmp (both)")]
    IcmpBoth,
}

impl Protocol {
    /// Returns lowercase protocol name as static string for efficient search filtering (Issue #9)
    pub const fn as_str(self) -> &'static str {
        match self {
            Protocol::Any => "any",
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::TcpAndUdp => "tcp+udp",
            Protocol::Icmp => "icmp",
            Protocol::Icmpv6 => "icmpv6",
            Protocol::IcmpBoth => "icmp (both)",
        }
    }

    /// Returns display name for UI rendering (Issue #16)
    pub const fn display_name(self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::TcpAndUdp => "TCP+UDP",
            Protocol::Any => "ANY",
            Protocol::Icmp => "ICMP (v4)",
            Protocol::Icmpv6 => "ICMPv6",
            Protocol::IcmpBoth => "ICMP (Both)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    #[allow(dead_code)]
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// Rule action (Accept, Drop, or Reject)
///
/// Controls what happens when a packet matches this rule.
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Default,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::AsRefStr,
)]
pub enum Action {
    /// Accept the packet (allow it through)
    #[default]
    #[strum(serialize = "accept")]
    Accept,
    /// Drop the packet silently (no response sent)
    #[strum(serialize = "drop")]
    Drop,
    /// Reject the packet and send ICMP unreachable response
    #[strum(serialize = "reject")]
    Reject,
}

impl Action {
    /// Returns lowercase action name for UI rendering
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Accept => "accept",
            Action::Drop => "drop",
            Action::Reject => "reject",
        }
    }

    /// Returns display name for UI rendering
    pub const fn display_name(self) -> &'static str {
        match self {
            Action::Accept => "Accept",
            Action::Drop => "Drop",
            Action::Reject => "Reject",
        }
    }

    /// Returns single-character abbreviation for compact UI display
    /// Used in action badges (Phase 2.3 optimization)
    pub const fn as_char(self) -> &'static str {
        match self {
            Action::Accept => "A",
            Action::Drop => "D",
            Action::Reject => "R",
        }
    }
}

/// Time unit for rate limiting
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::AsRefStr,
)]
pub enum TimeUnit {
    #[strum(serialize = "second")]
    Second,
    #[strum(serialize = "minute")]
    Minute,
    #[strum(serialize = "hour")]
    Hour,
    #[strum(serialize = "day")]
    Day,
}

impl TimeUnit {
    /// Returns nftables time unit string
    pub const fn as_str(self) -> &'static str {
        match self {
            TimeUnit::Second => "second",
            TimeUnit::Minute => "minute",
            TimeUnit::Hour => "hour",
            TimeUnit::Day => "day",
        }
    }

    /// Returns display name for UI rendering
    pub const fn display_name(self) -> &'static str {
        match self {
            TimeUnit::Second => "Second",
            TimeUnit::Minute => "Minute",
            TimeUnit::Hour => "Hour",
            TimeUnit::Day => "Day",
        }
    }
}

/// Rate limiting configuration
///
/// Limits the rate at which packets can match this rule.
/// Useful for preventing brute force attacks.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimit {
    pub count: u32,
    pub unit: TimeUnit,
}

impl fmt::Display for RateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.count, self.unit)
    }
}

/// Firewall chain for rule direction (only relevant in Server Mode)
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Default,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::AsRefStr,
)]
pub enum Chain {
    /// Incoming traffic (default for desktop users)
    #[default]
    #[strum(serialize = "input")]
    Input,
    /// Outgoing traffic (only useful in Server Mode with OUTPUT DROP policy)
    #[strum(serialize = "output")]
    Output,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub id: Uuid,
    pub label: String,
    pub protocol: Protocol,
    pub ports: Option<PortRange>,
    pub source: Option<IpNetwork>,
    pub interface: Option<String>,
    /// Chain direction (Input/Output) - only relevant in Server Mode
    #[serde(default)]
    pub chain: Chain,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Tags for organizing and filtering rules
    #[serde(default)]
    pub tags: Vec<String>,

    // Advanced options
    /// Destination IP/network filtering (for outbound traffic control)
    #[serde(default)]
    pub destination: Option<IpNetwork>,
    /// Action to take when packet matches (Accept/Drop/Reject)
    #[serde(default)]
    pub action: Action,
    /// Rate limiting configuration (prevent brute force)
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
    /// Connection limit (max simultaneous connections, 0 = disabled)
    #[serde(default)]
    pub connection_limit: u32,

    // Cached lowercase fields for search performance (Issue #1)
    /// Cached lowercase version of `label` for fast search filtering
    #[serde(skip)]
    pub label_lowercase: String,
    /// Cached lowercase version of `interface` for fast search filtering
    #[serde(skip)]
    pub interface_lowercase: Option<String>,
    /// Cached lowercase versions of all tags for fast search filtering
    #[serde(skip)]
    pub tags_lowercase: Vec<String>,
    /// Cached lowercase protocol name for fast search filtering (Issue #3)
    #[serde(skip)]
    pub protocol_lowercase: &'static str,
    /// Cached port display string for efficient view rendering (Issue #5)
    #[serde(skip)]
    pub port_display: String,
    /// Cached source IP network string for efficient JSON generation (Issue #10)
    #[serde(skip)]
    pub source_string: Option<String>,
    /// Cached destination IP network string for efficient JSON generation
    #[serde(skip)]
    pub destination_string: Option<String>,
    /// Cached rate limit display string for efficient view rendering (e.g., "5/m", "10/s")
    #[serde(skip)]
    pub rate_limit_display: Option<String>,
    /// Cached action display string for efficient view rendering (e.g., "A", "D (5/s)", "R")
    /// Combines action character with rate limit if present (Phase 2.3 optimization)
    #[serde(skip)]
    pub action_display: String,
    /// Cached interface display string for efficient view rendering (e.g., "@eth0", "Any")
    /// (Phase 2.3 optimization)
    #[serde(skip)]
    pub interface_display: String,
}

impl Rule {
    /// Rebuilds all cached lowercase fields for search performance
    /// Must be called after deserialization or any field modification
    pub fn rebuild_caches(&mut self) {
        self.label_lowercase = self.label.to_lowercase();
        self.interface_lowercase = self.interface.as_ref().map(|i| i.to_lowercase());
        self.tags_lowercase = self.tags.iter().map(|t| t.to_lowercase()).collect();
        self.protocol_lowercase = self.protocol.as_str();
        // Issue #5: Cache port display string for efficient view rendering
        self.port_display = self.ports.as_ref().map_or_else(
            || "All".to_string(),
            |p| {
                if p.start == p.end {
                    p.start.to_string()
                } else {
                    format!("{}-{}", p.start, p.end)
                }
            },
        );
        // Issue #10: Cache source IP string for efficient JSON generation
        self.source_string = self.source.map(|s| s.to_string());
        // Cache destination IP string for efficient JSON generation
        self.destination_string = self.destination.map(|d| d.to_string());
        // Cache rate limit display string for efficient view rendering
        self.rate_limit_display = self.rate_limit.map(|rl| {
            let unit_abbrev = match rl.unit {
                TimeUnit::Second => "s",
                TimeUnit::Minute => "m",
                TimeUnit::Hour => "h",
                TimeUnit::Day => "d",
            };
            format!("{}/{}", rl.count, unit_abbrev)
        });
        // Phase 2.3: Cache action display string (combines action + rate limit)
        self.action_display = if let Some(ref rate_limit) = self.rate_limit_display {
            format!("{} ({})", self.action.as_char(), rate_limit)
        } else {
            self.action.as_char().to_string()
        };
        // Phase 2.3: Cache interface display string
        self.interface_display = if let Some(ref iface) = self.interface {
            format!("@{iface}")
        } else {
            "Any".to_string()
        };
    }

    /// Updates label and its cached lowercase version
    pub fn set_label(&mut self, label: String) {
        self.label_lowercase = label.to_lowercase();
        self.label = label;
    }

    /// Updates interface and its cached lowercase version
    pub fn set_interface(&mut self, interface: Option<String>) {
        self.interface_lowercase = interface.as_ref().map(|i| i.to_lowercase());
        self.interface = interface;
    }

    /// Updates protocol and its cached lowercase version
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.protocol_lowercase = protocol.as_str();
        self.protocol = protocol;
    }

    /// Adds a tag and updates the cached lowercase tags
    pub fn add_tag(&mut self, tag: String) {
        let tag_lowercase = tag.to_lowercase();
        self.tags.push(tag);
        self.tags_lowercase.push(tag_lowercase);
    }

    /// Removes a tag and updates the cached lowercase tags
    pub fn remove_tag(&mut self, tag: &str) {
        if let Some(pos) = self.tags.iter().position(|t| t == tag) {
            self.tags.remove(pos);
            self.tags_lowercase.remove(pos);
        }
    }

    /// Sets all tags and updates the cached lowercase tags
    pub fn set_tags(&mut self, tags: Vec<String>) {
        self.tags_lowercase = tags.iter().map(|t| t.to_lowercase()).collect();
        self.tags = tags;
    }

    /// Creates a Rule with specified fields and auto-initializes caches.
    /// Useful for tests and manual rule creation.
    /// Advanced options (destination, action, `rate_limit`, `connection_limit`) use defaults.
    #[allow(clippy::too_many_arguments)]
    pub fn with_caches(
        id: Uuid,
        label: String,
        protocol: Protocol,
        ports: Option<PortRange>,
        source: Option<IpNetwork>,
        interface: Option<String>,
        chain: Chain,
        enabled: bool,
        created_at: chrono::DateTime<chrono::Utc>,
        tags: Vec<String>,
    ) -> Self {
        let mut rule = Self {
            id,
            label,
            protocol,
            ports,
            source,
            interface,
            chain,
            enabled,
            created_at,
            tags,
            // Advanced options - use defaults
            destination: None,
            action: Action::default(),
            rate_limit: None,
            connection_limit: 0,
            // Initialize with empty caches - will be rebuilt next
            label_lowercase: String::new(),
            interface_lowercase: None,
            tags_lowercase: Vec::new(),
            protocol_lowercase: "",
            port_display: String::new(), // Issue #5: Will be populated by rebuild_caches()
            source_string: None,         // Issue #10: Will be populated by rebuild_caches()
            destination_string: None,
            rate_limit_display: None, // Will be populated by rebuild_caches()
            action_display: String::new(), // Phase 2.3: Will be populated by rebuild_caches()
            interface_display: String::new(), // Phase 2.3: Will be populated by rebuild_caches()
        };
        rule.rebuild_caches();
        rule
    }
}

fn default_true() -> bool {
    true
}

// ServicePreset removed - presets dropdown removed from UI for simplicity
/// Egress filtering profile
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Default,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::AsRefStr,
)]
pub enum EgressProfile {
    /// Desktop mode: Allow all outbound connections (OUTPUT ACCEPT)
    #[default]
    #[strum(serialize = "desktop")]
    Desktop,
    /// Server mode: Deny all outbound by default, require explicit rules (OUTPUT DROP)
    #[strum(serialize = "server")]
    Server,
}

/// Optional advanced security settings (all OFF/disabled by default for desktop compatibility)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdvancedSecuritySettings {
    /// Restrict ICMP to only essential types (may break network tools and games)
    #[serde(default)]
    pub strict_icmp: bool,

    /// ICMP rate limit in packets/second (0 = disabled)
    #[serde(default)]
    pub icmp_rate_limit: u32,

    /// Enable anti-spoofing via reverse path filtering (breaks Docker/VPNs)
    #[serde(default)]
    pub enable_rpf: bool,

    /// Enable dropped packet logging
    #[serde(default)]
    pub log_dropped: bool,

    /// Dropped packet log rate in logs/minute (default: 5)
    #[serde(default = "default_log_rate")]
    pub log_rate_per_minute: u32,

    /// Log prefix for dropped packets (default: "DRFW-DROP: ")
    #[serde(default = "default_log_prefix")]
    pub log_prefix: String,

    /// Egress filtering profile (Desktop vs Server)
    #[serde(default)]
    pub egress_profile: EgressProfile,
}

fn default_log_rate() -> u32 {
    5
}

fn default_log_prefix() -> String {
    "DRFW-DROP: ".to_string()
}

impl Default for AdvancedSecuritySettings {
    fn default() -> Self {
        Self {
            strict_icmp: false,
            icmp_rate_limit: 0,
            enable_rpf: false,
            log_dropped: false,
            log_rate_per_minute: default_log_rate(),
            log_prefix: default_log_prefix(),
            egress_profile: EgressProfile::Desktop,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleset {
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub advanced_security: AdvancedSecuritySettings,
}

impl Default for FirewallRuleset {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallRuleset {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            advanced_security: AdvancedSecuritySettings::default(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // JSON Helper Functions (DRY consolidation)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Creates a match expression for nft meta keys (l4proto, iifname, oifname, etc.)
    fn meta_match(key: &str, value: impl serde::Serialize) -> serde_json::Value {
        serde_json::json!({
            "match": {
                "left": { "meta": { "key": key } },
                "op": "==",
                "right": value
            }
        })
    }

    /// Creates a rate limit expression
    fn rate_limit(rate: u32, per: &str) -> serde_json::Value {
        serde_json::json!({ "limit": { "rate": rate, "per": per } })
    }

    /// Creates a rule add wrapper with the standard drfw table structure
    fn rule_add(chain: &str, expr: &[serde_json::Value], comment: &str) -> serde_json::Value {
        serde_json::json!({
            "add": {
                "rule": {
                    "family": "inet",
                    "table": "drfw",
                    "chain": chain,
                    "expr": expr,
                    "comment": comment
                }
            }
        })
    }

    // ═══════════════════════════════════════════════════════════════════════════

    /// Generates the nftables JSON representation of the ruleset.
    /// Follows the spec in Section 4 of `PLAN_DRFW.md`.
    pub fn to_nftables_json(&self) -> serde_json::Value {
        use serde_json::json;

        // Issue #11: Pre-allocate Vec with estimated capacity
        // Base rules: ~15, user rules: N, termination: ~5
        let estimated_capacity = 20 + self.rules.len();
        let mut nft_rules = Vec::with_capacity(estimated_capacity);

        // 1. Setup Table & Flush
        nft_rules.push(json!({ "add": { "table": { "family": "inet", "name": "drfw" } } }));
        nft_rules.push(json!({ "flush": { "table": { "family": "inet", "name": "drfw" } } }));

        // 2. Base Chains
        Self::add_base_chains(&mut nft_rules, &self.advanced_security);

        // 3. Base Rules
        Self::add_base_rules(&mut nft_rules, &self.advanced_security);

        // 4. User Rules
        for rule in &self.rules {
            if !rule.enabled {
                continue; // Skip disabled rules
            }

            // Skip OUTPUT rules in Desktop Mode (policy is ACCEPT, rules are redundant)
            if self.advanced_security.egress_profile == EgressProfile::Desktop
                && rule.chain == Chain::Output
            {
                continue;
            }

            Self::add_user_rule(&mut nft_rules, rule);
        }

        // 5. Termination Rules
        Self::add_termination_rules(&mut nft_rules, &self.advanced_security);

        json!({ "nftables": nft_rules })
    }

    fn add_base_chains(
        nft_rules: &mut Vec<serde_json::Value>,
        advanced: &AdvancedSecuritySettings,
    ) {
        use serde_json::json;

        // OUTPUT policy depends on egress filtering profile
        let output_policy = match advanced.egress_profile {
            EgressProfile::Desktop => "accept",
            EgressProfile::Server => "drop",
        };

        let chains = [
            ("input", "drop", -10),
            ("forward", "drop", -10),
            ("output", output_policy, -10),
        ];

        for (name, policy, priority) in chains {
            nft_rules.push(json!({
                "add": {
                    "chain": {
                        "family": "inet",
                        "table": "drfw",
                        "name": name,
                        "type": "filter",
                        "hook": name,
                        "prio": priority,
                        "policy": policy
                    }
                }
            }));
        }
    }

    fn add_base_rules(nft_rules: &mut Vec<serde_json::Value>, advanced: &AdvancedSecuritySettings) {
        use serde_json::json;

        // Rule ordering matters for performance and correctness:
        // 0. [OPTIONAL] Anti-spoofing (RPF) - must be first to check all packets
        // 1. Loopback - most common, should bypass all checks
        // 2. Drop invalid early - avoid wasting cycles on malformed packets
        // 3. Established/related - most traffic will match here
        // 4. Block ICMP redirects - prevent MITM attacks
        // 5. [OPTIONAL] ICMP rate limiting
        // 6. ICMP - needed for network diagnostics (strict mode or general allow)

        // Optional: Anti-spoofing (RPF) - WARNING: Breaks Docker/VPNs
        if advanced.enable_rpf {
            nft_rules.push(json!({
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "drfw",
                        "chain": "input",
                        "expr": [
                            { "match": {
                                "left": { "fib": { "flags": ["saddr", "iif"], "result": "oif" } },
                                "op": "==",
                                "right": false
                            } },
                            { "drop": null },
                        ],
                        "comment": "drop packets with spoofed source addresses (RPF)"
                    }
                }
            }));
        }

        // Standard rules (always enabled)
        let standard_rules = [
            (
                "allow from loopback",
                vec![
                    json!({ "match": { "left": { "meta": { "key": "iifname" } }, "op": "==", "right": "lo" } }),
                    json!({ "accept": null }),
                ],
            ),
            (
                "early drop of invalid connections",
                vec![
                    json!({ "match": { "left": { "ct": { "key": "state" } }, "op": "==", "right": ["invalid"] } }),
                    json!({ "drop": null }),
                ],
            ),
            (
                "allow tracked connections",
                vec![
                    json!({ "match": { "left": { "ct": { "key": "state" } }, "op": "==", "right": {"set": ["established", "related"]} } }),
                    json!({ "accept": null }),
                ],
            ),
            (
                "drop icmp redirects",
                vec![
                    json!({ "match": { "left": { "meta": { "key": "l4proto" } }, "op": "==", "right": "icmp" } }),
                    json!({ "match": { "left": { "payload": { "protocol": "icmp", "field": "type" } }, "op": "==", "right": "redirect" } }),
                    json!({ "drop": null }),
                ],
            ),
            (
                "drop icmpv6 redirects",
                vec![
                    json!({ "match": { "left": { "meta": { "key": "l4proto" } }, "op": "==", "right": "ipv6-icmp" } }),
                    json!({ "match": { "left": { "payload": { "protocol": "icmpv6", "field": "type" } }, "op": "==", "right": "nd-redirect" } }),
                    json!({ "drop": null }),
                ],
            ),
        ];

        for (comment, expr) in standard_rules {
            nft_rules.push(json!({
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "drfw",
                        "chain": "input",
                        "expr": expr,
                        "comment": comment
                    }
                }
            }));
        }

        // ICMP handling: rate limiting (optional) + strict mode OR general allow
        Self::add_icmp_rules(nft_rules, advanced);
    }

    fn add_icmp_rules(nft_rules: &mut Vec<serde_json::Value>, advanced: &AdvancedSecuritySettings) {
        use serde_json::json;

        // Helper to build ICMP rule expressions with optional rate limiting
        let build_icmp_rule = |protocol: &str,
                               type_filter: Option<serde_json::Value>,
                               rate_limit: u32|
         -> Vec<serde_json::Value> {
            let mut expr = vec![Self::meta_match("l4proto", protocol)];

            if let Some(filter) = type_filter {
                expr.push(filter);
            }

            if rate_limit > 0 {
                expr.push(Self::rate_limit(rate_limit, "second"));
            }

            expr.push(json!({ "accept": null }));
            expr
        };

        if advanced.strict_icmp {
            // Strict ICMP mode: Only allow essential types

            // IPv4 ICMP - essential types only
            let ipv4_types = json!({ "match": {
                "left": { "payload": { "protocol": "icmp", "field": "type" } },
                "op": "==",
                "right": {"set": [
                    "echo-reply",              // Type 0: ping responses
                    "destination-unreachable", // Type 3: path MTU discovery
                    "echo-request",            // Type 8: allow being pinged
                    "time-exceeded"            // Type 11: traceroute
                ]}
            }});

            let ipv4_expr = build_icmp_rule("icmp", Some(ipv4_types), advanced.icmp_rate_limit);
            nft_rules.push(Self::rule_add(
                "input",
                &ipv4_expr,
                "allow essential icmp (strict mode)",
            ));

            // IPv6 ICMP - essential types only (more types required for IPv6 to function)
            let ipv6_types = json!({ "match": {
                "left": { "payload": { "protocol": "icmpv6", "field": "type" } },
                "op": "==",
                "right": {"set": [
                    "destination-unreachable", // Type 1
                    "packet-too-big",          // Type 2: path MTU (CRITICAL for IPv6)
                    "time-exceeded",           // Type 3
                    "echo-request",            // Type 128
                    "echo-reply",              // Type 129
                    "nd-neighbor-solicit",     // Type 135 (CRITICAL for IPv6)
                    "nd-neighbor-advert"       // Type 136 (CRITICAL for IPv6)
                ]}
            }});

            let ipv6_expr =
                build_icmp_rule("ipv6-icmp", Some(ipv6_types), advanced.icmp_rate_limit);
            nft_rules.push(Self::rule_add(
                "input",
                &ipv6_expr,
                "allow essential icmpv6 (strict mode)",
            ));
        } else {
            // Default mode: Allow all ICMP (except redirects which are already blocked)

            let ipv4_expr = build_icmp_rule("icmp", None, advanced.icmp_rate_limit);
            nft_rules.push(Self::rule_add("input", &ipv4_expr, "allow icmp"));

            let ipv6_expr = build_icmp_rule("ipv6-icmp", None, advanced.icmp_rate_limit);
            nft_rules.push(Self::rule_add("input", &ipv6_expr, "allow icmp v6"));
        }
    }

    fn add_user_rule(nft_rules: &mut Vec<serde_json::Value>, rule: &Rule) {
        use serde_json::json;
        // Issue #11: Pre-allocate with typical max size (protocol + ports + src + interface + state + comment + action)
        let mut expressions = Vec::with_capacity(8);

        // Issue #9: Protocol matching using meta_match helper (static strings, no allocation)
        match rule.protocol {
            Protocol::Any => {}
            Protocol::Tcp | Protocol::Udp => {
                expressions.push(Self::meta_match("l4proto", rule.protocol.as_str()));
            }
            Protocol::TcpAndUdp => {
                // Match both TCP and UDP using nftables set syntax
                expressions.push(Self::meta_match("l4proto", json!({"set": ["tcp", "udp"]})));
            }
            Protocol::Icmp => {
                expressions.push(Self::meta_match("l4proto", "icmp"));
            }
            Protocol::Icmpv6 => {
                expressions.push(Self::meta_match("l4proto", "ipv6-icmp"));
            }
            Protocol::IcmpBoth => {
                // Match both ICMP and ICMPv6 for dual-stack support
                expressions.push(Self::meta_match(
                    "l4proto",
                    json!({"set": ["icmp", "ipv6-icmp"]}),
                ));
            }
        }

        if let Some(src) = rule.source {
            // Issue #10: Use cached source string (falls back to to_string() if cache not populated)
            let src_string;
            let src_str = if let Some(ref cached) = rule.source_string {
                cached.as_str()
            } else {
                src_string = src.to_string();
                &src_string
            };
            expressions.push(json!({
                "match": {
                    "left": { "payload": { "protocol": if src.is_ipv6() { "ip6" } else { "ip" }, "field": "saddr" } },
                    "op": "==",
                    "right": src_str
                }
            }));
        }

        if let Some(ref iface) = rule.interface {
            expressions.push(Self::meta_match("iifname", iface));
        }

        if let Some(ref ports) = rule.ports
            && matches!(
                rule.protocol,
                Protocol::Tcp | Protocol::Udp | Protocol::TcpAndUdp
            )
        {
            let port_val = if ports.start == ports.end {
                json!(ports.start)
            } else {
                json!({ "range": [ports.start, ports.end] })
            };

            // For TcpAndUdp, we need to match ports using th (transport header) instead of specific protocol
            if matches!(rule.protocol, Protocol::TcpAndUdp) {
                expressions.push(json!({
                    "match": {
                        "left": { "payload": { "protocol": "th", "field": "dport" } },
                        "op": "==",
                        "right": port_val
                    }
                }));
            } else {
                expressions.push(json!({
                    "match": {
                        // Issue #9: Use as_str() for static string (no allocation)
                        "left": { "payload": { "protocol": rule.protocol.as_str(), "field": "dport" } },
                        "op": "==",
                        "right": port_val
                    }
                }));
            }
        }

        // Advanced options: destination IP filtering
        if let Some(dest) = rule.destination {
            let dest_string;
            let dest_str = if let Some(ref cached) = rule.destination_string {
                cached.as_str()
            } else {
                dest_string = dest.to_string();
                &dest_string
            };
            expressions.push(json!({
                "match": {
                    "left": { "payload": { "protocol": if dest.is_ipv6() { "ip6" } else { "ip" }, "field": "daddr" } },
                    "op": "==",
                    "right": dest_str
                }
            }));
        }

        // Advanced options: rate limiting
        if let Some(rate_limit) = rule.rate_limit {
            expressions.push(json!({
                "limit": {
                    "rate": rate_limit.count,
                    "per": rate_limit.unit.as_str()
                }
            }));
        }

        // Advanced options: connection limiting
        if rule.connection_limit > 0 {
            expressions.push(json!({
                "match": {
                    "left": { "ct": { "key": "count" } },
                    "op": "<=",
                    "right": rule.connection_limit
                }
            }));
        }

        // Action (Accept/Drop/Reject)
        match rule.action {
            Action::Accept => expressions.push(json!({ "accept": null })),
            Action::Drop => expressions.push(json!({ "drop": null })),
            Action::Reject => expressions.push(json!({ "reject": null })),
        }

        nft_rules.push(json!({
            "add": {
                "rule": {
                    "family": "inet",
                    "table": "drfw",
                    "chain": rule.chain.as_ref(),
                    "expr": expressions,
                    "comment": if rule.label.is_empty() { None } else { Some(&rule.label) }
                }
            }
        }));
    }

    fn add_termination_rules(
        nft_rules: &mut Vec<serde_json::Value>,
        advanced: &AdvancedSecuritySettings,
    ) {
        use serde_json::json;

        // Optional: Log dropped packets before rejection
        if advanced.log_dropped {
            nft_rules.push(json!({
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "drfw",
                        "chain": "input",
                        "expr": [
                            { "limit": { "rate": advanced.log_rate_per_minute, "per": "minute" } },
                            { "log": {
                                "prefix": &advanced.log_prefix,
                                "level": "info"
                            } },
                        ],
                        "comment": "log dropped packets (rate limited)"
                    }
                }
            }));
        }

        // Rate-limited reject (prevents port scanning)
        nft_rules.push(json!({
            "add": {
                "rule": {
                    "family": "inet",
                    "table": "drfw",
                    "chain": "input",
                    "expr": [
                        { "match": { "left": { "meta": { "key": "pkttype" } }, "op": "==", "right": "host" } },
                        { "limit": { "rate": 5, "per": "second" } },
                        { "counter": null },
                        { "reject": { "type": "icmpx", "expr": "admin-prohibited" } }
                    ]
                }
            }
        }));

        // Final counter (catches all remaining drops from chain policy)
        nft_rules.push(json!({
            "add": {
                "rule": {
                    "family": "inet",
                    "table": "drfw",
                    "chain": "input",
                    "expr": [ { "counter": null } ]
                }
            }
        }));
    }

    /// Generates human-readable .nft text for preview.
    pub fn to_nft_text(&self) -> String {
        use std::fmt::Write;

        let mut out = String::new();

        let _ = writeln!(out, "table inet drfw {{");

        let _ = writeln!(out, "    chain input {{");

        let _ = writeln!(
            out,
            "        type filter hook input priority -10; policy drop;\n"
        );

        Self::write_base_rules_text(&mut out, &self.advanced_security);

        if !self.rules.is_empty() {
            self.write_user_rules_text(&mut out);
        }

        let _ = writeln!(out, "        # --- Rejects (End of Chain) ---");

        if self.advanced_security.log_dropped {
            let _ = writeln!(
                out,
                "        limit rate {}/minute log prefix \"{}\" level info",
                self.advanced_security.log_rate_per_minute, self.advanced_security.log_prefix
            );
        }

        let _ = writeln!(
            out,
            "        pkttype host limit rate 5/second counter reject with icmpx type admin-prohibited"
        );

        let _ = writeln!(out, "        counter");

        let _ = writeln!(out, "    }}\n");

        let _ = writeln!(out, "    chain forward {{");

        let _ = writeln!(
            out,
            "        type filter hook forward priority -10; policy drop;"
        );

        let _ = writeln!(out, "    }}\n");

        let _ = writeln!(out, "    chain output {{");

        let output_policy = match self.advanced_security.egress_profile {
            EgressProfile::Desktop => "accept",
            EgressProfile::Server => "drop",
        };

        let _ = writeln!(
            out,
            "        type filter hook output priority -10; policy {output_policy};"
        );

        let _ = writeln!(out, "    }}\n");

        let _ = writeln!(out, "}}");

        out
    }

    fn write_base_rules_text(out: &mut String, advanced: &AdvancedSecuritySettings) {
        use std::fmt::Write;

        let _ = writeln!(out, "        # --- Base Rules ---");

        let _ = writeln!(
            out,
            "        # Rule ordering: loopback → invalid drop → established → block redirects → ICMP"
        );

        // Optional: Anti-spoofing (RPF)
        if advanced.enable_rpf {
            let _ = writeln!(out, "        # [OPTIONAL: Anti-Spoofing Enabled]");
            let _ = writeln!(
                out,
                "        fib saddr . iif oif eq 0 drop comment \"drop packets with spoofed source addresses (RPF)\"\n"
            );
        }

        let _ = writeln!(
            out,
            "        iifname \"lo\" accept comment \"allow from loopback\""
        );

        let _ = writeln!(
            out,
            "        ct state invalid drop comment \"early drop of invalid connections\""
        );

        let _ = writeln!(
            out,
            "        ct state established,related accept comment \"allow tracked connections\"\n"
        );

        let _ = writeln!(out, "        # --- Security Rules ---");

        let _ = writeln!(
            out,
            "        ip protocol icmp icmp type redirect drop comment \"drop icmp redirects\""
        );

        let _ = writeln!(
            out,
            "        meta l4proto ipv6-icmp icmpv6 type nd-redirect drop comment \"drop icmpv6 redirects\"\n"
        );

        let _ = writeln!(out, "        # --- Standard Protocols ---");

        // ICMP rules (strict mode or general allow, with optional rate limiting)
        if advanced.strict_icmp {
            let _ = writeln!(out, "        # [STRICT ICMP MODE ENABLED]");
            if advanced.icmp_rate_limit > 0 {
                let _ = writeln!(
                    out,
                    "        ip protocol icmp icmp type {{ echo-reply, destination-unreachable, echo-request, time-exceeded }} limit rate {}/second accept comment \"allow essential icmp (strict mode, rate limited)\"",
                    advanced.icmp_rate_limit
                );
                let _ = writeln!(
                    out,
                    "        meta l4proto ipv6-icmp icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, echo-request, echo-reply, nd-neighbor-solicit, nd-neighbor-advert }} limit rate {}/second accept comment \"allow essential icmpv6 (strict mode, rate limited)\"\n",
                    advanced.icmp_rate_limit
                );
            } else {
                let _ = writeln!(
                    out,
                    "        ip protocol icmp icmp type {{ echo-reply, destination-unreachable, echo-request, time-exceeded }} accept comment \"allow essential icmp (strict mode)\""
                );
                let _ = writeln!(
                    out,
                    "        meta l4proto ipv6-icmp icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, echo-request, echo-reply, nd-neighbor-solicit, nd-neighbor-advert }} accept comment \"allow essential icmpv6 (strict mode)\"\n"
                );
            }
        } else {
            // Default: Allow all ICMP (except redirects)
            if advanced.icmp_rate_limit > 0 {
                let _ = writeln!(
                    out,
                    "        # [ICMP RATE LIMITING: {}/second]",
                    advanced.icmp_rate_limit
                );
                let _ = writeln!(
                    out,
                    "        ip protocol icmp limit rate {}/second accept comment \"allow icmp (rate limited)\"",
                    advanced.icmp_rate_limit
                );
                let _ = writeln!(
                    out,
                    "        meta l4proto ipv6-icmp limit rate {}/second accept comment \"allow icmp v6 (rate limited)\"\n",
                    advanced.icmp_rate_limit
                );
            } else {
                let _ = writeln!(
                    out,
                    "        ip protocol icmp accept comment \"allow icmp\""
                );
                let _ = writeln!(
                    out,
                    "        meta l4proto ipv6-icmp accept comment \"allow icmp v6\"\n"
                );
            }
        }
    }

    fn write_user_rules_text(&self, out: &mut String) {
        use std::fmt::Write;
        let _ = writeln!(out, "        # --- User Defined Rules ---");
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            // Skip OUTPUT rules in Desktop Mode (policy is ACCEPT, rules are redundant)
            if self.advanced_security.egress_profile == EgressProfile::Desktop
                && rule.chain == Chain::Output
            {
                continue;
            }
            let _ = write!(out, "        ");
            if let Some(src) = rule.source {
                let _ = write!(
                    out,
                    "{} saddr {src} ",
                    if src.is_ipv4() { "ip" } else { "ip6" }
                );
            }
            if let Some(dest) = rule.destination {
                let _ = write!(
                    out,
                    "{} daddr {dest} ",
                    if dest.is_ipv4() { "ip" } else { "ip6" }
                );
            }
            if let Some(ref iface) = rule.interface {
                let _ = write!(out, "iifname \"{iface}\" ");
            }
            match rule.protocol {
                Protocol::Any => {} // No-op
                Protocol::Tcp | Protocol::Udp => {
                    let _ = write!(out, "{}", rule.protocol);
                    if let Some(ref ports) = rule.ports {
                        let _ = write!(out, " dport {ports} ");
                    }
                }
                Protocol::TcpAndUdp => {
                    let _ = write!(out, "meta l4proto {{ tcp, udp }}");
                    if let Some(ref ports) = rule.ports {
                        let _ = write!(out, " th dport {ports} ");
                    }
                }
                Protocol::Icmp => {
                    let _ = write!(out, "icmp ");
                }
                Protocol::Icmpv6 => {
                    let _ = write!(out, "icmpv6 ");
                }
                Protocol::IcmpBoth => {
                    // Match both ICMP and ICMPv6 for dual-stack support
                    let _ = write!(out, "meta l4proto {{ icmp, ipv6-icmp }} ");
                }
            }
            // Advanced options: rate limiting
            if let Some(rate_limit) = rule.rate_limit {
                let _ = write!(out, "limit rate {}/{} ", rate_limit.count, rate_limit.unit);
            }
            // Advanced options: connection limiting
            if rule.connection_limit > 0 {
                let _ = write!(out, "ct count <= {} ", rule.connection_limit);
            }
            // Action
            let _ = write!(out, "{}", rule.action);
            if !rule.label.is_empty() {
                let _ = write!(out, " comment \"{}\"", rule.label);
            }
            let _ = writeln!(out);
        }
        let _ = writeln!(out);
    }
}
