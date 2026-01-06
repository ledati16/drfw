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
//! use drfw::core::firewall::{Rule, Protocol, PortEntry, Chain};
//! use uuid::Uuid;
//!
//! let mut rule = Rule {
//!     id: Uuid::new_v4(),
//!     label: "Allow SSH".to_string(),
//!     protocol: Protocol::Tcp,
//!     ports: vec![PortEntry::single(22)],  // Single port, or vec![22.into()]
//!     sources: vec![],  // Empty = any source. Can mix IPv4/IPv6
//!     interface: None,
//!     output_interface: None,
//!     chain: Chain::Input,
//!     enabled: true,
//!     created_at: chrono::Utc::now(),
//!     tags: vec![],
//!     // Advanced options
//!     destinations: vec![],  // Empty = any destination. Can mix IPv4/IPv6
//!     action: drfw::core::firewall::Action::Accept,
//!     reject_type: drfw::core::firewall::RejectType::Default,
//!     rate_limit: None,
//!     connection_limit: 0,
//!     log_enabled: false,
//!     // Cached fields (populated by rebuild_caches())
//!     label_lowercase: String::new(),
//!     interface_lowercase: None,
//!     output_interface_lowercase: None,
//!     tags_lowercase: Vec::new(),
//!     protocol_lowercase: "",
//!     port_display: String::new(),
//!     sources_display: String::new(),
//!     destinations_display: String::new(),
//!     rate_limit_display: None,
//!     action_display: String::new(),
//!     interface_display: String::new(),
//!     log_prefix: String::new(),
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

/// A port range with start and end values.
///
/// Used within [`PortEntry`] for representing port ranges.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// Creates a single-port range (start == end)
    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// Creates a port range
    pub const fn range(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    /// Returns true if this is a single port (not a range)
    pub const fn is_single(&self) -> bool {
        self.start == self.end
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

/// A port entry that can be a single port or a range.
///
/// Used in [`Rule::ports`] to support multiple ports and ranges per rule.
///
/// # Examples
///
/// ```
/// use drfw::core::firewall::PortEntry;
///
/// // Single ports
/// let ssh = PortEntry::single(22);
/// let http = PortEntry::single(80);
///
/// // Port ranges
/// let high_ports = PortEntry::range(8000, 8080);
///
/// // Display
/// assert_eq!(ssh.to_string(), "22");
/// assert_eq!(high_ports.to_string(), "8000-8080");
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PortEntry {
    /// A single port
    Single(u16),
    /// A port range (inclusive)
    Range { start: u16, end: u16 },
}

impl PortEntry {
    /// Creates a single port entry
    pub const fn single(port: u16) -> Self {
        Self::Single(port)
    }

    /// Creates a port range entry
    pub const fn range(start: u16, end: u16) -> Self {
        Self::Range { start, end }
    }

    /// Converts from legacy PortRange to PortEntry
    pub const fn from_port_range(pr: PortRange) -> Self {
        if pr.start == pr.end {
            Self::Single(pr.start)
        } else {
            Self::Range {
                start: pr.start,
                end: pr.end,
            }
        }
    }

    /// Returns the start port (for single port, this is the port itself)
    pub const fn start(&self) -> u16 {
        match self {
            Self::Single(p) => *p,
            Self::Range { start, .. } => *start,
        }
    }

    /// Returns the end port (for single port, this is the port itself)
    pub const fn end(&self) -> u16 {
        match self {
            Self::Single(p) => *p,
            Self::Range { end, .. } => *end,
        }
    }

    /// Returns true if this is a single port (not a range)
    pub const fn is_single(&self) -> bool {
        matches!(self, Self::Single(_))
    }

    /// Converts to nftables JSON value
    pub fn to_nft_json(self) -> serde_json::Value {
        use serde_json::json;
        match self {
            Self::Single(p) => json!(p),
            Self::Range { start, end } => json!({ "range": [start, end] }),
        }
    }
}

impl fmt::Display for PortEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(p) => write!(f, "{p}"),
            Self::Range { start, end } => write!(f, "{start}-{end}"),
        }
    }
}

impl From<u16> for PortEntry {
    fn from(port: u16) -> Self {
        Self::Single(port)
    }
}

impl From<PortRange> for PortEntry {
    fn from(pr: PortRange) -> Self {
        Self::from_port_range(pr)
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

/// Reject type for ICMP response selection
///
/// Controls what ICMP response is sent when rejecting a packet.
/// Only applies when [`Action::Reject`] is selected.
///
/// **Note:** `TcpReset` is only valid for TCP protocol rules.
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
pub enum RejectType {
    /// System default (port-unreachable)
    #[default]
    #[strum(serialize = "default")]
    Default,
    /// ICMP port unreachable - appears as "closed port"
    #[strum(serialize = "port-unreachable")]
    PortUnreachable,
    /// ICMP host unreachable - appears as "host offline"
    #[strum(serialize = "host-unreachable")]
    HostUnreachable,
    /// ICMP admin prohibited - explicit firewall block
    #[strum(serialize = "admin-prohibited")]
    AdminProhibited,
    /// TCP RST - clean TCP connection close (TCP only!)
    #[strum(serialize = "tcp-reset")]
    TcpReset,
}

impl RejectType {
    /// Returns display name for UI rendering
    pub const fn display_name(self) -> &'static str {
        match self {
            RejectType::Default => "Default",
            RejectType::PortUnreachable => "Port Unreachable",
            RejectType::HostUnreachable => "Host Unreachable",
            RejectType::AdminProhibited => "Admin Prohibited",
            RejectType::TcpReset => "TCP Reset",
        }
    }

    /// Returns true if this reject type is only valid for TCP protocol
    pub const fn requires_tcp(self) -> bool {
        matches!(self, RejectType::TcpReset)
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
///
/// # Burst
/// The optional `burst` field allows short bursts beyond the rate limit.
/// For example, rate 5/minute with burst 10 allows up to 10 connections
/// quickly, then enforces 5/minute average.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimit {
    pub count: u32,
    pub unit: TimeUnit,
    /// Optional burst allowance (0 or None = no burst)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
}

impl fmt::Display for RateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(burst) = self.burst {
            write!(f, "{}/{} burst {}", self.count, self.unit, burst)
        } else {
            write!(f, "{}/{}", self.count, self.unit)
        }
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
    /// Port entries (single ports or ranges). Empty = all ports.
    /// Multiple entries create nftables anonymous sets: `dport { 22, 80, 443 }`
    #[serde(default)]
    pub ports: Vec<PortEntry>,
    /// Source IP/network filters. Empty = any source.
    /// IPv4 and IPv6 addresses can be mixed; DRFW splits them into separate nft rules.
    #[serde(default)]
    pub sources: Vec<IpNetwork>,
    /// Input interface filter (iifname). Supports wildcards (e.g., "eth*")
    pub interface: Option<String>,
    /// Output interface filter (oifname). Only for OUTPUT chain in Server Mode.
    /// Supports wildcards (e.g., "eth*")
    #[serde(default)]
    pub output_interface: Option<String>,
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
    /// Destination IP/network filters. Empty = any destination.
    /// IPv4 and IPv6 addresses can be mixed; DRFW splits them into separate nft rules.
    #[serde(default)]
    pub destinations: Vec<IpNetwork>,
    /// Action to take when packet matches (Accept/Drop/Reject)
    #[serde(default)]
    pub action: Action,
    /// Reject type selection (only used when action == Reject)
    /// Controls the ICMP response type sent when rejecting packets
    #[serde(default)]
    pub reject_type: RejectType,
    /// Rate limiting configuration (prevent brute force)
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
    /// Connection limit (max simultaneous connections, 0 = disabled)
    #[serde(default)]
    pub connection_limit: u32,
    /// Enable per-rule logging (logs matched packets before action)
    /// Prefix is auto-generated from sanitized label: "DRFW-{label}: "
    #[serde(default)]
    pub log_enabled: bool,

    // Cached lowercase fields for search performance (Issue #1)
    /// Cached lowercase version of `label` for fast search filtering
    #[serde(skip)]
    pub label_lowercase: String,
    /// Cached lowercase version of `interface` for fast search filtering
    #[serde(skip)]
    pub interface_lowercase: Option<String>,
    /// Cached lowercase version of `output_interface` for fast search filtering
    #[serde(skip)]
    pub output_interface_lowercase: Option<String>,
    /// Cached lowercase versions of all tags for fast search filtering
    #[serde(skip)]
    pub tags_lowercase: Vec<String>,
    /// Cached lowercase protocol name for fast search filtering (Issue #3)
    #[serde(skip)]
    pub protocol_lowercase: &'static str,
    /// Cached port display string for efficient view rendering (Issue #5)
    #[serde(skip)]
    pub port_display: String,
    /// Cached source IPs display string for efficient view rendering
    #[serde(skip)]
    pub sources_display: String,
    /// Cached destination IPs display string for efficient view rendering
    #[serde(skip)]
    pub destinations_display: String,
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
    /// Cached sanitized log prefix for nftables log expression
    /// Format: "DRFW-{sanitized_label}: " (max 64 chars)
    #[serde(skip)]
    pub log_prefix: String,
}

impl Rule {
    /// Rebuilds all cached lowercase fields for search performance
    /// Must be called after deserialization or any field modification
    pub fn rebuild_caches(&mut self) {
        self.label_lowercase = self.label.to_lowercase();
        self.interface_lowercase = self.interface.as_ref().map(|i| i.to_lowercase());
        self.output_interface_lowercase = self.output_interface.as_ref().map(|i| i.to_lowercase());
        self.tags_lowercase = self.tags.iter().map(|t| t.to_lowercase()).collect();
        self.protocol_lowercase = self.protocol.as_str();
        // Issue #5: Cache port display string for efficient view rendering
        self.port_display = if self.ports.is_empty() {
            "All".to_string()
        } else if self.ports.len() == 1 {
            self.ports[0].to_string()
        } else {
            // Multiple ports - show count or abbreviated list
            if self.ports.len() <= 3 {
                self.ports
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                format!("{} ports", self.ports.len())
            }
        };
        // Cache source IPs display string for efficient view rendering
        self.sources_display = if self.sources.is_empty() {
            "Any".to_string()
        } else if self.sources.len() == 1 {
            self.sources[0].to_string()
        } else if self.sources.len() <= 2 {
            self.sources
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            format!("{} addresses", self.sources.len())
        };
        // Cache destination IPs display string for efficient view rendering
        self.destinations_display = if self.destinations.is_empty() {
            "Any".to_string()
        } else if self.destinations.len() == 1 {
            self.destinations[0].to_string()
        } else if self.destinations.len() <= 2 {
            self.destinations
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            format!("{} addresses", self.destinations.len())
        };
        // Cache rate limit display string for efficient view rendering
        self.rate_limit_display = self.rate_limit.map(|rl| {
            let unit_abbrev = match rl.unit {
                TimeUnit::Second => "s",
                TimeUnit::Minute => "m",
                TimeUnit::Hour => "h",
                TimeUnit::Day => "d",
            };
            if let Some(burst) = rl.burst {
                format!("{}/{} b{}", rl.count, unit_abbrev, burst)
            } else {
                format!("{}/{}", rl.count, unit_abbrev)
            }
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
        // Cache sanitized log prefix for nftables log expression
        self.log_prefix = Self::sanitize_log_prefix(&self.label);
    }

    /// Sanitizes a label for use as nftables log prefix.
    /// Format: "DRFW-{sanitized_label}: " (max 64 chars total)
    fn sanitize_log_prefix(label: &str) -> String {
        let sanitized: String = label
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            .take(50) // Leave room for "DRFW-" prefix and ": " suffix
            .collect();

        if sanitized.is_empty() {
            "DRFW-rule: ".to_string()
        } else {
            format!("DRFW-{sanitized}: ")
        }
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
    /// Advanced options (destinations, action, `rate_limit`, `connection_limit`) use defaults.
    #[allow(clippy::too_many_arguments)]
    pub fn with_caches(
        id: Uuid,
        label: String,
        protocol: Protocol,
        ports: Vec<PortEntry>,
        sources: Vec<IpNetwork>,
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
            sources,
            interface,
            output_interface: None,
            chain,
            enabled,
            created_at,
            tags,
            // Advanced options - use defaults
            destinations: Vec::new(),
            action: Action::default(),
            reject_type: RejectType::default(),
            rate_limit: None,
            connection_limit: 0,
            log_enabled: false,
            // Initialize with empty caches - will be rebuilt next
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
                    json!({ "match": { "left": { "ct": { "key": "state" } }, "op": "==", "right": "invalid" } }),
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

    /// Adds user rule(s) to the nft_rules vector.
    /// May generate multiple nftables rules if the DRFW rule has mixed IPv4/IPv6 addresses.
    ///
    /// nftables requires separate rules for IPv4 and IPv6:
    /// - `ip saddr` only matches IPv4 addresses
    /// - `ip6 saddr` only matches IPv6 addresses
    ///
    /// So if a user specifies both IPv4 and IPv6 sources, we generate two nft rules.
    fn add_user_rule(nft_rules: &mut Vec<serde_json::Value>, rule: &Rule) {
        // Split sources and destinations by IP version
        let ipv4_sources: Vec<_> = rule.sources.iter().filter(|s| s.is_ipv4()).collect();
        let ipv6_sources: Vec<_> = rule.sources.iter().filter(|s| s.is_ipv6()).collect();
        let ipv4_dests: Vec<_> = rule.destinations.iter().filter(|d| d.is_ipv4()).collect();
        let ipv6_dests: Vec<_> = rule.destinations.iter().filter(|d| d.is_ipv6()).collect();

        // For rules with no IP filtering, generate a single rule
        if rule.sources.is_empty() && rule.destinations.is_empty() {
            Self::add_single_rule(nft_rules, rule, &[], &[]);
            return;
        }

        // Generate IPv4 rule if we have IPv4 sources or destinations
        if !ipv4_sources.is_empty() || !ipv4_dests.is_empty() {
            Self::add_single_rule(nft_rules, rule, &ipv4_sources, &ipv4_dests);
        }

        // Generate IPv6 rule if we have IPv6 sources or destinations
        if !ipv6_sources.is_empty() || !ipv6_dests.is_empty() {
            Self::add_single_rule(nft_rules, rule, &ipv6_sources, &ipv6_dests);
        }
    }

    /// Generates a single nftables rule with the given sources and destinations.
    fn add_single_rule(
        nft_rules: &mut Vec<serde_json::Value>,
        rule: &Rule,
        sources: &[&IpNetwork],
        destinations: &[&IpNetwork],
    ) {
        use serde_json::json;

        let mut expressions = Vec::with_capacity(8);

        // Protocol matching
        match rule.protocol {
            Protocol::Any => {}
            Protocol::Tcp | Protocol::Udp => {
                expressions.push(Self::meta_match("l4proto", rule.protocol.as_str()));
            }
            Protocol::TcpAndUdp => {
                expressions.push(Self::meta_match("l4proto", json!({"set": ["tcp", "udp"]})));
            }
            Protocol::Icmp => {
                expressions.push(Self::meta_match("l4proto", "icmp"));
            }
            Protocol::Icmpv6 => {
                expressions.push(Self::meta_match("l4proto", "ipv6-icmp"));
            }
            Protocol::IcmpBoth => {
                expressions.push(Self::meta_match(
                    "l4proto",
                    json!({"set": ["icmp", "ipv6-icmp"]}),
                ));
            }
        }

        // Source IP filtering (all sources should be same IP version)
        if !sources.is_empty() {
            let is_ipv6 = sources[0].is_ipv6();
            let protocol = if is_ipv6 { "ip6" } else { "ip" };

            let src_val = if sources.len() == 1 {
                json!(sources[0].to_string())
            } else {
                let src_set: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
                json!({ "set": src_set })
            };

            expressions.push(json!({
                "match": {
                    "left": { "payload": { "protocol": protocol, "field": "saddr" } },
                    "op": "==",
                    "right": src_val
                }
            }));
        }

        // Input interface
        if let Some(ref iface) = rule.interface {
            expressions.push(Self::meta_match("iifname", iface));
        }

        // Output interface
        if let Some(ref oiface) = rule.output_interface {
            expressions.push(Self::meta_match("oifname", oiface));
        }

        // Port filtering
        if !rule.ports.is_empty()
            && matches!(
                rule.protocol,
                Protocol::Tcp | Protocol::Udp | Protocol::TcpAndUdp
            )
        {
            let port_val = if rule.ports.len() == 1 {
                rule.ports[0].to_nft_json()
            } else {
                let port_set: Vec<serde_json::Value> = rule
                    .ports
                    .iter()
                    .copied()
                    .map(PortEntry::to_nft_json)
                    .collect();
                json!({ "set": port_set })
            };

            let protocol_key = if matches!(rule.protocol, Protocol::TcpAndUdp) {
                "th"
            } else {
                rule.protocol.as_str()
            };

            expressions.push(json!({
                "match": {
                    "left": { "payload": { "protocol": protocol_key, "field": "dport" } },
                    "op": "==",
                    "right": port_val
                }
            }));
        }

        // Destination IP filtering (all destinations should be same IP version)
        if !destinations.is_empty() {
            let is_ipv6 = destinations[0].is_ipv6();
            let protocol = if is_ipv6 { "ip6" } else { "ip" };

            let dest_val = if destinations.len() == 1 {
                json!(destinations[0].to_string())
            } else {
                let dest_set: Vec<String> = destinations.iter().map(|d| d.to_string()).collect();
                json!({ "set": dest_set })
            };

            expressions.push(json!({
                "match": {
                    "left": { "payload": { "protocol": protocol, "field": "daddr" } },
                    "op": "==",
                    "right": dest_val
                }
            }));
        }

        // Advanced options: rate limiting (with optional burst)
        if let Some(rate_limit) = rule.rate_limit {
            let mut limit_obj = json!({
                "rate": rate_limit.count,
                "per": rate_limit.unit.as_str()
            });
            if let Some(burst) = rate_limit.burst.filter(|&b| b > 0) {
                limit_obj["burst"] = json!(burst);
            }
            expressions.push(json!({ "limit": limit_obj }));
        }

        // Advanced options: connection limiting
        if rule.connection_limit > 0 {
            expressions.push(json!({
                "ct count": { "val": rule.connection_limit }
            }));
        }

        // Per-rule logging (before action, so log happens even if action is accept)
        if rule.log_enabled {
            expressions.push(json!({
                "log": {
                    "prefix": &rule.log_prefix,
                    "level": "info"
                }
            }));
        }

        // Action (Accept/Drop/Reject with optional reject type)
        match rule.action {
            Action::Accept => expressions.push(json!({ "accept": null })),
            Action::Drop => expressions.push(json!({ "drop": null })),
            Action::Reject => {
                let reject_expr = match rule.reject_type {
                    RejectType::Default => json!({ "reject": null }),
                    RejectType::PortUnreachable => {
                        json!({ "reject": { "type": "icmpx", "expr": "port-unreachable" } })
                    }
                    RejectType::HostUnreachable => {
                        json!({ "reject": { "type": "icmpx", "expr": "host-unreachable" } })
                    }
                    RejectType::AdminProhibited => {
                        json!({ "reject": { "type": "icmpx", "expr": "admin-prohibited" } })
                    }
                    RejectType::TcpReset => json!({ "reject": { "type": "tcp reset" } }),
                };
                expressions.push(reject_expr);
            }
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
            "        meta pkttype host limit rate 5/second counter reject with icmpx type admin-prohibited"
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
            "        meta l4proto icmp icmp type redirect drop comment \"drop icmp redirects\""
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
                    "        meta l4proto icmp icmp type {{ echo-reply, destination-unreachable, echo-request, time-exceeded }} limit rate {}/second accept comment \"allow essential icmp (strict mode, rate limited)\"",
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
                    "        meta l4proto icmp icmp type {{ echo-reply, destination-unreachable, echo-request, time-exceeded }} accept comment \"allow essential icmp (strict mode)\""
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
                    "        meta l4proto icmp limit rate {}/second accept comment \"allow icmp (rate limited)\"",
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
                    "        meta l4proto icmp accept comment \"allow icmp\""
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
            // Source IP filtering - show all sources (may be mixed IPv4/IPv6)
            // Note: JSON generation splits by IP version, text preview shows simplified
            if !rule.sources.is_empty() {
                let ipv4_sources: Vec<_> = rule.sources.iter().filter(|s| s.is_ipv4()).collect();
                let ipv6_sources: Vec<_> = rule.sources.iter().filter(|s| s.is_ipv6()).collect();

                if !ipv4_sources.is_empty() {
                    if ipv4_sources.len() == 1 {
                        let _ = write!(out, "ip saddr {} ", ipv4_sources[0]);
                    } else {
                        let addrs = ipv4_sources
                            .iter()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        let _ = write!(out, "ip saddr {{ {addrs} }} ");
                    }
                }
                if !ipv6_sources.is_empty() {
                    if ipv6_sources.len() == 1 {
                        let _ = write!(out, "ip6 saddr {} ", ipv6_sources[0]);
                    } else {
                        let addrs = ipv6_sources
                            .iter()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        let _ = write!(out, "ip6 saddr {{ {addrs} }} ");
                    }
                }
            }
            // Destination IP filtering - show all destinations
            if !rule.destinations.is_empty() {
                let ipv4_dests: Vec<_> = rule.destinations.iter().filter(|d| d.is_ipv4()).collect();
                let ipv6_dests: Vec<_> = rule.destinations.iter().filter(|d| d.is_ipv6()).collect();

                if !ipv4_dests.is_empty() {
                    if ipv4_dests.len() == 1 {
                        let _ = write!(out, "ip daddr {} ", ipv4_dests[0]);
                    } else {
                        let addrs = ipv4_dests
                            .iter()
                            .map(|d| d.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        let _ = write!(out, "ip daddr {{ {addrs} }} ");
                    }
                }
                if !ipv6_dests.is_empty() {
                    if ipv6_dests.len() == 1 {
                        let _ = write!(out, "ip6 daddr {} ", ipv6_dests[0]);
                    } else {
                        let addrs = ipv6_dests
                            .iter()
                            .map(|d| d.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        let _ = write!(out, "ip6 daddr {{ {addrs} }} ");
                    }
                }
            }
            if let Some(ref iface) = rule.interface {
                let _ = write!(out, "iifname \"{iface}\" ");
            }
            if let Some(ref oiface) = rule.output_interface {
                let _ = write!(out, "oifname \"{oiface}\" ");
            }
            match rule.protocol {
                Protocol::Any => {} // No-op
                Protocol::Tcp | Protocol::Udp => {
                    let _ = write!(out, "{}", rule.protocol);
                    if !rule.ports.is_empty() {
                        if rule.ports.len() == 1 {
                            let _ = write!(out, " dport {} ", rule.ports[0]);
                        } else {
                            // Multiple ports - use set syntax
                            let ports_str = rule
                                .ports
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ");
                            let _ = write!(out, " dport {{ {ports_str} }} ");
                        }
                    }
                }
                Protocol::TcpAndUdp => {
                    let _ = write!(out, "meta l4proto {{ tcp, udp }}");
                    if !rule.ports.is_empty() {
                        if rule.ports.len() == 1 {
                            let _ = write!(out, " th dport {} ", rule.ports[0]);
                        } else {
                            let ports_str = rule
                                .ports
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ");
                            let _ = write!(out, " th dport {{ {ports_str} }} ");
                        }
                    }
                }
                Protocol::Icmp => {
                    let _ = write!(out, "meta l4proto icmp ");
                }
                Protocol::Icmpv6 => {
                    let _ = write!(out, "meta l4proto ipv6-icmp ");
                }
                Protocol::IcmpBoth => {
                    // Match both ICMP and ICMPv6 for dual-stack support
                    let _ = write!(out, "meta l4proto {{ icmp, ipv6-icmp }} ");
                }
            }
            // Advanced options: rate limiting (with optional burst)
            if let Some(rate_limit) = rule.rate_limit {
                if let Some(burst) = rate_limit.burst {
                    let _ = write!(
                        out,
                        "limit rate {}/{} burst {} packets ",
                        rate_limit.count, rate_limit.unit, burst
                    );
                } else {
                    let _ = write!(out, "limit rate {}/{} ", rate_limit.count, rate_limit.unit);
                }
            }
            // Advanced options: connection limiting
            if rule.connection_limit > 0 {
                let _ = write!(out, "ct count {} ", rule.connection_limit);
            }
            // Per-rule logging (before action)
            if rule.log_enabled {
                let _ = write!(out, "log prefix \"{}\" level info ", rule.log_prefix);
            }
            // Action (with optional reject type)
            match rule.action {
                Action::Accept => {
                    let _ = write!(out, "accept");
                }
                Action::Drop => {
                    let _ = write!(out, "drop");
                }
                Action::Reject => match rule.reject_type {
                    RejectType::Default => {
                        let _ = write!(out, "reject");
                    }
                    RejectType::PortUnreachable => {
                        let _ = write!(out, "reject with icmpx type port-unreachable");
                    }
                    RejectType::HostUnreachable => {
                        let _ = write!(out, "reject with icmpx type host-unreachable");
                    }
                    RejectType::AdminProhibited => {
                        let _ = write!(out, "reject with icmpx type admin-prohibited");
                    }
                    RejectType::TcpReset => {
                        let _ = write!(out, "reject with tcp reset");
                    }
                },
            }
            if !rule.label.is_empty() {
                let _ = write!(out, " comment \"{}\"", rule.label);
            }
            let _ = writeln!(out);
        }
        let _ = writeln!(out);
    }
}
