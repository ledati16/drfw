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
//!     // Cached fields (populated by rebuild_caches())
//!     label_lowercase: String::new(),
//!     interface_lowercase: None,
//!     tags_lowercase: Vec::new(),
//!     protocol_lowercase: "",
//!     port_display: String::new(),
//!     source_string: None,
//! };
//! rule.rebuild_caches();
//! ```

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Network protocol type for firewall rules
///
/// Supports common protocols used in nftables filtering.
/// `Copy` trait allows efficient passing by value for this small enum.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Protocol {
    /// Match all protocols
    Any,
    /// Transmission Control Protocol
    Tcp,
    /// User Datagram Protocol
    Udp,
    /// Both TCP and UDP (common for services like DNS, VPNs, game servers)
    TcpAndUdp,
    /// Internet Control Message Protocol (IPv4)
    Icmp,
    /// Internet Control Message Protocol version 6
    Icmpv6,
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
        }
    }

    /// Returns display name for UI rendering (Issue #16)
    pub const fn display_name(self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::TcpAndUdp => "TCP+UDP",
            Protocol::Any => "ANY",
            Protocol::Icmp => "ICMP",
            Protocol::Icmpv6 => "ICMPv6",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Any => write!(f, "any"),
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::TcpAndUdp => write!(f, "tcp+udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Icmpv6 => write!(f, "icmpv6"),
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

/// Firewall chain for rule direction (only relevant in Server Mode)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum Chain {
    /// Incoming traffic (default for desktop users)
    #[default]
    Input,
    /// Outgoing traffic (only useful in Server Mode with OUTPUT DROP policy)
    Output,
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Chain::Input => write!(f, "input"),
            Chain::Output => write!(f, "output"),
        }
    }
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
            // Initialize with empty caches - will be rebuilt next
            label_lowercase: String::new(),
            interface_lowercase: None,
            tags_lowercase: Vec::new(),
            protocol_lowercase: "",
            port_display: String::new(), // Issue #5: Will be populated by rebuild_caches()
            source_string: None,         // Issue #10: Will be populated by rebuild_caches()
        };
        rule.rebuild_caches();
        rule
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServicePreset {
    pub name: &'static str,
    pub protocol: Protocol,
    pub port: u16,
}

pub const PRESETS: &[ServicePreset] = &[
    // Remote Access
    ServicePreset {
        name: "SSH",
        protocol: Protocol::Tcp,
        port: 22,
    },
    ServicePreset {
        name: "RDP (Remote Desktop)",
        protocol: Protocol::Tcp,
        port: 3389,
    },
    ServicePreset {
        name: "VNC",
        protocol: Protocol::Tcp,
        port: 5900,
    },
    ServicePreset {
        name: "TeamViewer",
        protocol: Protocol::Tcp,
        port: 5938,
    },
    // Web Services
    ServicePreset {
        name: "HTTP",
        protocol: Protocol::Tcp,
        port: 80,
    },
    ServicePreset {
        name: "HTTPS",
        protocol: Protocol::Tcp,
        port: 443,
    },
    ServicePreset {
        name: "HTTP Alt (8080)",
        protocol: Protocol::Tcp,
        port: 8080,
    },
    ServicePreset {
        name: "HTTPS Alt (8443)",
        protocol: Protocol::Tcp,
        port: 8443,
    },
    // DNS
    ServicePreset {
        name: "DNS (UDP)",
        protocol: Protocol::Udp,
        port: 53,
    },
    ServicePreset {
        name: "DNS (TCP)",
        protocol: Protocol::Tcp,
        port: 53,
    },
    ServicePreset {
        name: "DNS over TLS",
        protocol: Protocol::Tcp,
        port: 853,
    },
    // Database Services
    ServicePreset {
        name: "PostgreSQL",
        protocol: Protocol::Tcp,
        port: 5432,
    },
    ServicePreset {
        name: "MySQL/MariaDB",
        protocol: Protocol::Tcp,
        port: 3306,
    },
    ServicePreset {
        name: "MongoDB",
        protocol: Protocol::Tcp,
        port: 27017,
    },
    ServicePreset {
        name: "Redis",
        protocol: Protocol::Tcp,
        port: 6379,
    },
    // Mail Services
    ServicePreset {
        name: "SMTP",
        protocol: Protocol::Tcp,
        port: 25,
    },
    ServicePreset {
        name: "SMTP (Submission)",
        protocol: Protocol::Tcp,
        port: 587,
    },
    ServicePreset {
        name: "SMTPS",
        protocol: Protocol::Tcp,
        port: 465,
    },
    ServicePreset {
        name: "IMAP",
        protocol: Protocol::Tcp,
        port: 143,
    },
    ServicePreset {
        name: "IMAPS",
        protocol: Protocol::Tcp,
        port: 993,
    },
    ServicePreset {
        name: "POP3",
        protocol: Protocol::Tcp,
        port: 110,
    },
    ServicePreset {
        name: "POP3S",
        protocol: Protocol::Tcp,
        port: 995,
    },
    // File Sharing
    ServicePreset {
        name: "FTP",
        protocol: Protocol::Tcp,
        port: 21,
    },
    ServicePreset {
        name: "SFTP/SSH File Transfer",
        protocol: Protocol::Tcp,
        port: 22,
    },
    ServicePreset {
        name: "Samba (SMB)",
        protocol: Protocol::Tcp,
        port: 445,
    },
    ServicePreset {
        name: "NFS",
        protocol: Protocol::Tcp,
        port: 2049,
    },
    ServicePreset {
        name: "Rsync",
        protocol: Protocol::Tcp,
        port: 873,
    },
    ServicePreset {
        name: "Syncthing",
        protocol: Protocol::Tcp,
        port: 22000,
    },
    // VPN Services
    ServicePreset {
        name: "WireGuard",
        protocol: Protocol::Udp,
        port: 51820,
    },
    ServicePreset {
        name: "OpenVPN (UDP)",
        protocol: Protocol::Udp,
        port: 1194,
    },
    ServicePreset {
        name: "OpenVPN (TCP)",
        protocol: Protocol::Tcp,
        port: 1194,
    },
    ServicePreset {
        name: "IPSec (IKE)",
        protocol: Protocol::Udp,
        port: 500,
    },
    ServicePreset {
        name: "IPSec (NAT-T)",
        protocol: Protocol::Udp,
        port: 4500,
    },
    // Media Servers
    ServicePreset {
        name: "Plex",
        protocol: Protocol::Tcp,
        port: 32400,
    },
    ServicePreset {
        name: "Jellyfin",
        protocol: Protocol::Tcp,
        port: 8096,
    },
    ServicePreset {
        name: "Emby",
        protocol: Protocol::Tcp,
        port: 8096,
    },
    ServicePreset {
        name: "Transmission (Web)",
        protocol: Protocol::Tcp,
        port: 9091,
    },
    ServicePreset {
        name: "qBittorrent (Web)",
        protocol: Protocol::Tcp,
        port: 8080,
    },
    // Gaming
    ServicePreset {
        name: "Minecraft",
        protocol: Protocol::Tcp,
        port: 25565,
    },
    ServicePreset {
        name: "Steam",
        protocol: Protocol::Udp,
        port: 27015,
    },
    ServicePreset {
        name: "TeamSpeak",
        protocol: Protocol::Udp,
        port: 9987,
    },
    ServicePreset {
        name: "Mumble",
        protocol: Protocol::Udp,
        port: 64738,
    },
    ServicePreset {
        name: "Discord Voice",
        protocol: Protocol::Udp,
        port: 50000,
    },
    // Development
    ServicePreset {
        name: "Node.js (3000)",
        protocol: Protocol::Tcp,
        port: 3000,
    },
    ServicePreset {
        name: "Django Dev Server",
        protocol: Protocol::Tcp,
        port: 8000,
    },
    ServicePreset {
        name: "Rails Dev Server",
        protocol: Protocol::Tcp,
        port: 3000,
    },
    ServicePreset {
        name: "React Dev Server",
        protocol: Protocol::Tcp,
        port: 3000,
    },
    // Container/Orchestration
    ServicePreset {
        name: "Docker API",
        protocol: Protocol::Tcp,
        port: 2375,
    },
    ServicePreset {
        name: "Docker API (TLS)",
        protocol: Protocol::Tcp,
        port: 2376,
    },
    ServicePreset {
        name: "Kubernetes API",
        protocol: Protocol::Tcp,
        port: 6443,
    },
    ServicePreset {
        name: "Portainer",
        protocol: Protocol::Tcp,
        port: 9000,
    },
    // Monitoring
    ServicePreset {
        name: "Prometheus",
        protocol: Protocol::Tcp,
        port: 9090,
    },
    ServicePreset {
        name: "Grafana",
        protocol: Protocol::Tcp,
        port: 3000,
    },
    ServicePreset {
        name: "InfluxDB",
        protocol: Protocol::Tcp,
        port: 8086,
    },
    ServicePreset {
        name: "Node Exporter",
        protocol: Protocol::Tcp,
        port: 9100,
    },
    // Home Automation
    ServicePreset {
        name: "Home Assistant",
        protocol: Protocol::Tcp,
        port: 8123,
    },
    ServicePreset {
        name: "MQTT",
        protocol: Protocol::Tcp,
        port: 1883,
    },
    ServicePreset {
        name: "MQTTS",
        protocol: Protocol::Tcp,
        port: 8883,
    },
];

impl std::fmt::Display for ServicePreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({} {})", self.name, self.protocol, self.port)
    }
}

/// Egress filtering profile
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum EgressProfile {
    /// Desktop mode: Allow all outbound connections (OUTPUT ACCEPT)
    #[default]
    Desktop,
    /// Server mode: Deny all outbound by default, require explicit rules (OUTPUT DROP)
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
                    json!({ "match": { "left": { "ct": { "key": "state" } }, "op": "in", "right": ["established", "related"] } }),
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

        if advanced.strict_icmp {
            // Strict ICMP mode: Only allow essential types

            // IPv4 ICMP - essential types only
            let mut ipv4_expr = vec![
                json!({ "match": { "left": { "meta": { "key": "l4proto" } }, "op": "==", "right": "icmp" } }),
                json!({ "match": { "left": { "payload": { "protocol": "icmp", "field": "type" } }, "op": "in", "right": [
                    "echo-reply",           // Type 0: ping responses
                    "destination-unreachable", // Type 3: path MTU discovery
                    "echo-request",         // Type 8: allow being pinged
                    "time-exceeded"         // Type 11: traceroute
                ] } }),
            ];

            // Optional: Add rate limiting
            if advanced.icmp_rate_limit > 0 {
                ipv4_expr.insert(
                    2,
                    json!({ "limit": { "rate": advanced.icmp_rate_limit, "per": "second" } }),
                );
            }

            ipv4_expr.push(json!({ "accept": null }));

            nft_rules.push(json!({
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "drfw",
                        "chain": "input",
                        "expr": ipv4_expr,
                        "comment": "allow essential icmp (strict mode)"
                    }
                }
            }));

            // IPv6 ICMP - essential types only (more types required for IPv6 to function)
            let mut ipv6_expr = vec![
                json!({ "match": { "left": { "meta": { "key": "l4proto" } }, "op": "==", "right": "ipv6-icmp" } }),
                json!({ "match": { "left": { "payload": { "protocol": "icmpv6", "field": "type" } }, "op": "in", "right": [
                    "destination-unreachable", // Type 1
                    "packet-too-big",         // Type 2: path MTU (CRITICAL for IPv6)
                    "time-exceeded",          // Type 3
                    "echo-request",           // Type 128
                    "echo-reply",             // Type 129
                    "nd-neighbor-solicit",    // Type 135 (CRITICAL for IPv6)
                    "nd-neighbor-advert"      // Type 136 (CRITICAL for IPv6)
                ] } }),
            ];

            if advanced.icmp_rate_limit > 0 {
                ipv6_expr.insert(
                    2,
                    json!({ "limit": { "rate": advanced.icmp_rate_limit, "per": "second" } }),
                );
            }

            ipv6_expr.push(json!({ "accept": null }));

            nft_rules.push(json!({
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "drfw",
                        "chain": "input",
                        "expr": ipv6_expr,
                        "comment": "allow essential icmpv6 (strict mode)"
                    }
                }
            }));
        } else {
            // Default mode: Allow all ICMP (except redirects which are already blocked)

            // IPv4 ICMP
            let mut ipv4_expr = vec![
                json!({ "match": { "left": { "meta": { "key": "l4proto" } }, "op": "==", "right": "icmp" } }),
            ];

            if advanced.icmp_rate_limit > 0 {
                ipv4_expr.push(
                    json!({ "limit": { "rate": advanced.icmp_rate_limit, "per": "second" } }),
                );
            }

            ipv4_expr.push(json!({ "accept": null }));

            nft_rules.push(json!({
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "drfw",
                        "chain": "input",
                        "expr": ipv4_expr,
                        "comment": "allow icmp"
                    }
                }
            }));

            // IPv6 ICMP
            let mut ipv6_expr = vec![
                json!({ "match": { "left": { "meta": { "key": "l4proto" } }, "op": "==", "right": "ipv6-icmp" } }),
            ];

            if advanced.icmp_rate_limit > 0 {
                ipv6_expr.push(
                    json!({ "limit": { "rate": advanced.icmp_rate_limit, "per": "second" } }),
                );
            }

            ipv6_expr.push(json!({ "accept": null }));

            nft_rules.push(json!({
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "drfw",
                        "chain": "input",
                        "expr": ipv6_expr,
                        "comment": "allow icmp v6"
                    }
                }
            }));
        }
    }

    fn add_user_rule(nft_rules: &mut Vec<serde_json::Value>, rule: &Rule) {
        use serde_json::json;
        // Issue #11: Pre-allocate with typical max size (protocol + ports + src + interface + state + comment + action)
        let mut expressions = Vec::with_capacity(8);

        match rule.protocol {
            Protocol::Any => {}
            Protocol::Tcp | Protocol::Udp => {
                // Issue #9: Use as_str() for static string (no allocation)
                expressions.push(json!({ "match": { "left": { "meta": { "key": "l4proto" } }, "op": "==", "right": rule.protocol.as_str() } }));
            }
            Protocol::TcpAndUdp => {
                // Match both TCP and UDP using nftables set syntax
                expressions.push(json!({ "match": { "left": { "meta": { "key": "l4proto" } }, "op": "in", "right": ["tcp", "udp"] } }));
            }
            Protocol::Icmp => {
                expressions.push(json!({ "match": { "left": { "meta": { "key": "l4proto" } }, "op": "==", "right": "icmp" } }));
            }
            Protocol::Icmpv6 => {
                expressions.push(json!({ "match": { "left": { "meta": { "key": "l4proto" } }, "op": "==", "right": "ipv6-icmp" } }));
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
            expressions.push(json!({
                "match": { "left": { "meta": { "key": "iifname" } }, "op": "==", "right": iface }
            }));
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

        expressions.push(json!({ "accept": null }));

        nft_rules.push(json!({
            "add": {
                "rule": {
                    "family": "inet",
                    "table": "drfw",
                    "chain": rule.chain.to_string(),
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
                                "prefix": advanced.log_prefix.clone(),
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
            }
            let _ = write!(out, "accept");
            if !rule.label.is_empty() {
                let _ = write!(out, " comment \"{}\"", rule.label);
            }
            let _ = writeln!(out);
        }
        let _ = writeln!(out);
    }
}
