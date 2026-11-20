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
//!     tags_truncated: Vec::new(),
//!     badge_display: String::new(),
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
/// 5000 rules allows stress testing while remaining practical.
/// Most users have <50 rules; enterprise setups rarely exceed 500.
pub const MAX_RULES: usize = 5000;

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

    /// Converts from legacy `PortRange` to `PortEntry`
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

    /// Cached truncated tags for efficient view rendering (max 16 chars + ellipsis)
    /// Avoids format!() allocation every frame in sidebar rule cards
    #[serde(skip)]
    pub tags_truncated: Vec<String>,

    /// Cached badge display string for sidebar rule cards
    /// Format: `"{protocol}: {port_display}"` (e.g., "TCP: 22" or "UDP: 53, 5353")
    /// Avoids format!() allocation every frame
    #[serde(skip)]
    pub badge_display: String,
}

impl Rule {
    /// Rebuilds all cached lowercase fields for search performance
    /// Must be called after deserialization or any field modification
    pub fn rebuild_caches(&mut self) {
        // Sanitize label to remove control characters (newlines, tabs, etc.)
        // that may have been introduced via JSON import or malformed data
        self.label = crate::validators::sanitize_label(&self.label);
        self.label_lowercase = self.label.to_lowercase();
        self.interface_lowercase = self.interface.as_ref().map(|i| i.to_lowercase());
        self.output_interface_lowercase = self.output_interface.as_ref().map(|i| i.to_lowercase());
        // Tags get the same allowlist sanitization as the tag input form. Profiles
        // imported from disk bypass the form, and later code (display truncation,
        // tag cloud) relies on tags being short ASCII.
        self.tags = std::mem::take(&mut self.tags)
            .into_iter()
            .map(|t| crate::validators::sanitize_label(&t))
            .filter(|t| !t.is_empty())
            .collect();
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

        // Cache truncated tags for efficient view rendering (avoids format! every frame)
        self.tags_truncated = self
            .tags
            .iter()
            .map(|t| {
                // Count chars, not bytes: slicing a byte range can split a
                // multi-byte character and panic.
                if t.chars().count() > 16 {
                    let head: String = t.chars().take(15).collect();
                    format!("{head}…")
                } else {
                    t.clone()
                }
            })
            .collect();

        // Cache badge display string for sidebar rule cards (avoids format! every frame)
        // Format: "{protocol}: {port_display}"
        self.badge_display = format!("{}: {}", self.protocol.display_name(), self.port_display);
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
            tags_truncated: Vec::new(),
            badge_display: String::new(),
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

    /// Block forwarded (routed) traffic: forward chain policy drop.
    ///
    /// Off by default: the kernel does not forward unless IP forwarding is
    /// enabled, and hosts that do forward (Docker, libvirt, `WireGuard`,
    /// Tailscale) need it. Only routers that want a default-deny forward
    /// policy should turn this on.
    #[serde(default)]
    pub block_forwarding: bool,
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
            block_forwarding: false,
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

    /// Generates the nftables JSON command list for this ruleset.
    ///
    /// This is the authoritative representation: it is what gets verified and
    /// applied. [`Self::to_nft_text`] renders the very same command list as
    /// `nft -f` text, so preview, export and Save to System cannot diverge from
    /// what is applied.
    ///
    /// Rule ordering (per chain):
    /// 1. Base rules (optional RPF, loopback, invalid drop, established/related,
    ///    `DHCPv6` client replies)
    /// 2. ICMP redirect drops and ICMP allow rules
    /// 3. User rules, in profile order
    /// 4. End of input chain: optional drop logging, rate-limited reject, counter
    pub fn to_nftables_json(&self) -> serde_json::Value {
        let commands: Vec<serde_json::Value> = self
            .build_commands()
            .into_iter()
            .map(|command| command.value)
            .collect();
        serde_json::json!({ "nftables": commands })
    }

    /// Renders the ruleset as a standalone `nft -f` file.
    ///
    /// The text is derived from [`Self::to_nftables_json`]'s command list (see
    /// [`crate::core::nft_text`]), so it always describes exactly what is
    /// applied. It starts with a shebang and the idempotent
    /// `table … / delete table … / table … { … }` idiom, so loading it twice
    /// replaces the table instead of duplicating rules. Section comments are
    /// added for readability.
    pub fn to_nft_text(&self) -> String {
        crate::core::nft_text::render(&self.build_commands())
    }

    /// Builds the annotated command list shared by the JSON and text outputs.
    pub(crate) fn build_commands(&self) -> Vec<NftCommand> {
        use serde_json::json;

        let advanced = &self.advanced_security;
        // Base: table, flush, 3 chains, ~20 base rules; user rules: N (or 2N when dual-stack)
        let mut cmds = CommandList::with_capacity(32 + self.rules.len());

        cmds.push(json!({ "add": { "table": { "family": NFT_FAMILY, "name": NFT_TABLE } } }));
        cmds.push(json!({ "flush": { "table": { "family": NFT_FAMILY, "name": NFT_TABLE } } }));

        Self::add_base_chains(&mut cmds, advanced);
        Self::add_base_rules(&mut cmds, advanced);

        cmds.section = SECTION_USER;
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            // OUTPUT rules only matter in Server Mode (Desktop output policy is accept)
            if advanced.egress_profile == EgressProfile::Desktop && rule.chain == Chain::Output {
                continue;
            }
            Self::add_user_rule(&mut cmds, rule);
        }

        Self::add_termination_rules(&mut cmds, advanced);

        cmds.commands
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // JSON Helper Functions (DRY consolidation)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Creates an equality match expression `left == right`.
    fn match_eq(left: serde_json::Value, right: impl Serialize) -> serde_json::Value {
        let mut expr = serde_json::json!({ "match": { "op": "==", "right": right } });
        expr["match"]["left"] = left;
        expr
    }

    /// Creates a match on an nft meta key (`l4proto`, `iifname`, `oifname`, ...).
    fn meta_match(key: &str, right: impl Serialize) -> serde_json::Value {
        Self::match_eq(serde_json::json!({ "meta": { "key": key } }), right)
    }

    /// Creates a match on a conntrack key (`state`, ...).
    fn ct_match(key: &str, right: impl Serialize) -> serde_json::Value {
        Self::match_eq(serde_json::json!({ "ct": { "key": key } }), right)
    }

    /// Creates a match on a packet header field (`ip saddr`, `tcp dport`, ...).
    fn payload_match(protocol: &str, field: &str, right: impl Serialize) -> serde_json::Value {
        Self::match_eq(
            serde_json::json!({ "payload": { "protocol": protocol, "field": field } }),
            right,
        )
    }

    /// `ct state { established, related }`
    fn ct_established() -> serde_json::Value {
        Self::ct_match(
            "state",
            serde_json::json!({ "set": ["established", "related"] }),
        )
    }

    /// Creates a rate limit expression (no burst, not inverted).
    fn rate_limit(rate: u32, per: &str) -> serde_json::Value {
        serde_json::json!({ "limit": { "rate": rate, "per": per } })
    }

    /// Wraps a list of values in an anonymous set, or returns the single value.
    fn value_or_set(mut values: Vec<serde_json::Value>) -> serde_json::Value {
        if values.len() == 1 {
            values.swap_remove(0)
        } else {
            serde_json::json!({ "set": values })
        }
    }

    /// Converts an `IpNetwork` to nftables JSON format.
    ///
    /// Per libnftables-json(5):
    /// - Single host (/32 IPv4, /128 IPv6): Plain IP string expression
    /// - Network prefix (any other CIDR): `{ "prefix": { "addr": "...", "len": N } }`
    ///
    /// For network prefixes, we use `.network()` to get the canonical network address.
    /// This handles edge cases where users enter non-canonical CIDRs like "192.168.1.50/24"
    /// which should be normalized to the network address "192.168.1.0".
    fn ip_to_nft_json(ip: &IpNetwork) -> serde_json::Value {
        let is_single_host = match ip {
            IpNetwork::V4(v4) => v4.prefix() == 32,
            IpNetwork::V6(v6) => v6.prefix() == 128,
        };

        if is_single_host {
            serde_json::json!(ip.ip().to_string())
        } else {
            serde_json::json!({
                "prefix": {
                    "addr": ip.network().to_string(),
                    "len": ip.prefix()
                }
            })
        }
    }

    /// Creates an `add rule` command in the drfw table.
    ///
    /// The comment is sanitized for nft quoted strings and omitted when empty.
    fn rule_add(chain: &str, expr: Vec<serde_json::Value>, comment: &str) -> serde_json::Value {
        let mut rule = serde_json::json!({
            "family": NFT_FAMILY,
            "table": NFT_TABLE,
            "chain": chain,
        });
        rule["expr"] = serde_json::Value::Array(expr);
        let comment = crate::validators::sanitize_nft_quoted(comment);
        if !comment.is_empty() {
            rule["comment"] = serde_json::json!(comment);
        }
        let mut command = serde_json::json!({ "add": {} });
        command["add"]["rule"] = rule;
        command
    }

    // ═══════════════════════════════════════════════════════════════════════════

    fn add_base_chains(cmds: &mut CommandList, advanced: &AdvancedSecuritySettings) {
        use serde_json::json;

        let output_policy = match advanced.egress_profile {
            EgressProfile::Desktop => "accept",
            EgressProfile::Server => "drop",
        };
        // Forwarding is left alone by default: the kernel only forwards when IP
        // forwarding is enabled, and then it is usually Docker/libvirt/VPNs that
        // need it (their own tables accepting is not enough, a drop here wins).
        let forward_policy = if advanced.block_forwarding {
            "drop"
        } else {
            "accept"
        };

        let chains = [
            ("input", "drop"),
            ("forward", forward_policy),
            ("output", output_policy),
        ];

        for (name, policy) in chains {
            cmds.push(json!({
                "add": {
                    "chain": {
                        "family": NFT_FAMILY,
                        "table": NFT_TABLE,
                        "name": name,
                        "type": "filter",
                        "hook": name,
                        "prio": CHAIN_PRIORITY,
                        "policy": policy
                    }
                }
            }));
        }
    }

    fn add_base_rules(cmds: &mut CommandList, advanced: &AdvancedSecuritySettings) {
        use serde_json::json;

        // Rule ordering matters for performance and correctness:
        // 0. [OPTIONAL] Anti-spoofing (RPF) - must be first to check all packets
        // 1. Loopback - most common, should bypass all checks
        // 2. Drop invalid early - avoid wasting cycles on malformed packets
        // 3. Established/related - most traffic will match here
        // 4. DHCPv6 client replies (not tracked: the request went to multicast)
        // 5. Block ICMP redirects - prevent MITM attacks
        // 6. ICMP - needed for network diagnostics (strict mode or general allow)
        cmds.section = SECTION_BASE;

        // Optional: Anti-spoofing (RPF) - WARNING: Breaks Docker/VPNs
        if advanced.enable_rpf {
            cmds.push(Self::rule_add(
                "input",
                vec![
                    Self::match_eq(
                        json!({ "fib": { "flags": ["saddr", "iif"], "result": "oif" } }),
                        false,
                    ),
                    json!({ "drop": null }),
                ],
                "drop packets with spoofed source addresses (RPF)",
            ));
        }

        cmds.push(Self::rule_add(
            "input",
            vec![Self::meta_match("iifname", "lo"), json!({ "accept": null })],
            "allow from loopback",
        ));
        cmds.push(Self::rule_add(
            "input",
            vec![Self::ct_match("state", "invalid"), json!({ "drop": null })],
            "early drop of invalid connections",
        ));
        cmds.push(Self::rule_add(
            "input",
            vec![Self::ct_established(), json!({ "accept": null })],
            "allow tracked connections",
        ));
        // DHCPv6 replies come from the server's link-local address to ours; the
        // request went to a multicast group so conntrack cannot associate them.
        cmds.push(Self::rule_add(
            "input",
            vec![
                Self::payload_match(
                    "ip6",
                    "saddr",
                    json!({ "prefix": { "addr": "fe80::", "len": 10 } }),
                ),
                Self::payload_match("udp", "sport", 547),
                Self::payload_match("udp", "dport", 546),
                json!({ "accept": null }),
            ],
            "allow dhcpv6 client replies",
        ));

        if advanced.block_forwarding {
            cmds.push(Self::rule_add(
                "forward",
                vec![Self::ct_match("state", "invalid"), json!({ "drop": null })],
                "drop invalid forwarded connections",
            ));
            cmds.push(Self::rule_add(
                "forward",
                vec![Self::ct_established(), json!({ "accept": null })],
                "allow tracked forwarded connections",
            ));
        }

        if advanced.egress_profile == EgressProfile::Server {
            Self::add_server_output_base_rules(cmds);
        }

        cmds.section = SECTION_SECURITY;
        cmds.push(Self::rule_add(
            "input",
            vec![
                Self::meta_match("l4proto", "icmp"),
                Self::payload_match("icmp", "type", "redirect"),
                json!({ "drop": null }),
            ],
            "drop icmp redirects",
        ));
        cmds.push(Self::rule_add(
            "input",
            vec![
                Self::meta_match("l4proto", "ipv6-icmp"),
                Self::payload_match("icmpv6", "type", "nd-redirect"),
                json!({ "drop": null }),
            ],
            "drop icmpv6 redirects",
        ));

        cmds.section = SECTION_ICMP;
        Self::add_icmp_rules(cmds, advanced);
    }

    /// Base rules for the output chain in Server Mode (policy drop).
    ///
    /// Without these, a default-deny output policy drops loopback traffic,
    /// replies to accepted inbound connections and IPv6 neighbor discovery,
    /// which locks the machine out of its own network.
    fn add_server_output_base_rules(cmds: &mut CommandList) {
        use serde_json::json;

        cmds.push(Self::rule_add(
            "output",
            vec![Self::meta_match("oifname", "lo"), json!({ "accept": null })],
            "allow to loopback",
        ));
        cmds.push(Self::rule_add(
            "output",
            vec![Self::ct_match("state", "invalid"), json!({ "drop": null })],
            "early drop of invalid outbound connections",
        ));
        cmds.push(Self::rule_add(
            "output",
            vec![Self::ct_established(), json!({ "accept": null })],
            "allow outbound tracked connections",
        ));
        // Neighbor discovery and MLD are not connection-tracked (untracked), so the
        // established rule above does not cover them; IPv6 breaks without them.
        cmds.push(Self::rule_add(
            "output",
            vec![
                Self::meta_match("l4proto", "ipv6-icmp"),
                Self::payload_match(
                    "icmpv6",
                    "type",
                    json!({ "set": [
                        "nd-router-solicit",
                        "nd-neighbor-solicit",
                        "nd-neighbor-advert",
                        "mld-listener-report",
                        "mld2-listener-report"
                    ] }),
                ),
                json!({ "accept": null }),
            ],
            "allow outbound ipv6 neighbor discovery",
        ));
    }

    fn add_icmp_rules(cmds: &mut CommandList, advanced: &AdvancedSecuritySettings) {
        use serde_json::json;

        // Builds an ICMP accept rule with optional type filter and rate limit
        let build_icmp_rule = |protocol: &str, type_filter: Option<serde_json::Value>| {
            let mut expr = vec![Self::meta_match("l4proto", protocol)];
            if let Some(filter) = type_filter {
                expr.push(filter);
            }
            if advanced.icmp_rate_limit > 0 {
                expr.push(Self::rate_limit(advanced.icmp_rate_limit, "second"));
            }
            expr.push(json!({ "accept": null }));
            expr
        };

        if advanced.strict_icmp {
            // IPv4 ICMP - essential types only
            let ipv4_types = Self::payload_match(
                "icmp",
                "type",
                json!({ "set": [
                    "echo-reply",              // Type 0: ping responses
                    "destination-unreachable", // Type 3: path MTU discovery
                    "echo-request",            // Type 8: allow being pinged
                    "time-exceeded",           // Type 11: traceroute
                    "parameter-problem"        // Type 12: header errors
                ] }),
            );
            cmds.push(Self::rule_add(
                "input",
                build_icmp_rule("icmp", Some(ipv4_types)),
                "allow essential icmp (strict mode)",
            ));

            // IPv6 ICMP - essential types only (more types required for IPv6 to function)
            let ipv6_types = Self::payload_match(
                "icmpv6",
                "type",
                json!({ "set": [
                    "destination-unreachable", // Type 1
                    "packet-too-big",          // Type 2: path MTU (CRITICAL for IPv6)
                    "time-exceeded",           // Type 3
                    "parameter-problem",       // Type 4
                    "echo-request",            // Type 128
                    "echo-reply",              // Type 129
                    "mld-listener-query",      // Type 130: multicast listener discovery
                    "nd-router-advert",        // Type 134: SLAAC / default route
                    "nd-neighbor-solicit",     // Type 135 (CRITICAL for IPv6)
                    "nd-neighbor-advert"       // Type 136 (CRITICAL for IPv6)
                ] }),
            );
            cmds.push(Self::rule_add(
                "input",
                build_icmp_rule("ipv6-icmp", Some(ipv6_types)),
                "allow essential icmpv6 (strict mode)",
            ));
        } else {
            // Default mode: Allow all ICMP (except redirects which are already blocked)
            cmds.push(Self::rule_add(
                "input",
                build_icmp_rule("icmp", None),
                "allow icmp",
            ));
            cmds.push(Self::rule_add(
                "input",
                build_icmp_rule("ipv6-icmp", None),
                "allow icmp v6",
            ));
        }
    }

    /// Adds the nft rule(s) for one user rule.
    ///
    /// nftables matches IPv4 and IPv6 addresses with different expressions
    /// (`ip saddr` vs `ip6 saddr`), and one rule cannot match both. A rule with
    /// mixed address families is therefore emitted once per family, and a
    /// family-specific copy is only emitted when **every** non-empty address
    /// list (sources, destinations) has an address of that family. Otherwise
    /// the copy would silently drop a list and match more than the user asked
    /// for (e.g. sources `[v4, v6]` with destinations `[v4]` must not produce an
    /// IPv6 rule that matches any destination).
    ///
    /// Rules that cannot be expressed without widening are skipped with a
    /// warning: no family satisfies both address lists, or an interface name
    /// is empty after sanitization.
    fn add_user_rule(cmds: &mut CommandList, rule: &Rule) {
        let iif = rule
            .interface
            .as_deref()
            .map(crate::validators::sanitize_nft_quoted);
        let oif = rule
            .output_interface
            .as_deref()
            .map(crate::validators::sanitize_nft_quoted);
        if iif.as_deref().is_some_and(str::is_empty) || oif.as_deref().is_some_and(str::is_empty) {
            tracing::warn!(
                "Skipping rule '{}': interface name is empty after sanitization",
                rule.label
            );
            return;
        }
        let ifaces = (iif.as_deref(), oif.as_deref());

        if rule.sources.is_empty() && rule.destinations.is_empty() {
            Self::add_single_rule(cmds, rule, ifaces, &AddressMatch::default());
            return;
        }

        let mut emitted = false;
        for (family, is_v6) in [("ip", false), ("ip6", true)] {
            let sources: Vec<&IpNetwork> = rule
                .sources
                .iter()
                .filter(|n| n.is_ipv6() == is_v6)
                .collect();
            let destinations: Vec<&IpNetwork> = rule
                .destinations
                .iter()
                .filter(|n| n.is_ipv6() == is_v6)
                .collect();
            let sources_ok = rule.sources.is_empty() || !sources.is_empty();
            let destinations_ok = rule.destinations.is_empty() || !destinations.is_empty();
            if sources_ok && destinations_ok {
                let addresses = AddressMatch {
                    family,
                    sources,
                    destinations,
                };
                Self::add_single_rule(cmds, rule, ifaces, &addresses);
                emitted = true;
            }
        }

        if !emitted {
            tracing::warn!(
                "Skipping rule '{}': sources and destinations have no IP family in common",
                rule.label
            );
        }
    }

    /// Generates a single nftables rule for one address family.
    fn add_single_rule(
        cmds: &mut CommandList,
        rule: &Rule,
        (iif, oif): (Option<&str>, Option<&str>),
        addresses: &AddressMatch<'_>,
    ) {
        use serde_json::json;

        let mut expressions = Vec::with_capacity(10);

        // Protocol matching. Ports only make sense for TCP/UDP: a port list on
        // "Any" means TCP+UDP (never silently drop the ports, that would widen
        // the rule to every port); on ICMP they are meaningless and ignored.
        let has_ports = !rule.ports.is_empty();
        let port_protocol = match rule.protocol {
            Protocol::Any => {
                if has_ports {
                    expressions.push(Self::meta_match("l4proto", json!({"set": ["tcp", "udp"]})));
                    Some("th")
                } else {
                    None
                }
            }
            Protocol::Tcp => {
                expressions.push(Self::meta_match("l4proto", "tcp"));
                Some("tcp")
            }
            Protocol::Udp => {
                expressions.push(Self::meta_match("l4proto", "udp"));
                Some("udp")
            }
            Protocol::TcpAndUdp => {
                expressions.push(Self::meta_match("l4proto", json!({"set": ["tcp", "udp"]})));
                Some("th")
            }
            Protocol::Icmp => {
                expressions.push(Self::meta_match("l4proto", "icmp"));
                None
            }
            Protocol::Icmpv6 => {
                expressions.push(Self::meta_match("l4proto", "ipv6-icmp"));
                None
            }
            Protocol::IcmpBoth => {
                expressions.push(Self::meta_match(
                    "l4proto",
                    json!({"set": ["icmp", "ipv6-icmp"]}),
                ));
                None
            }
        };

        if let Some(iface) = iif {
            expressions.push(Self::meta_match("iifname", iface));
        }
        if let Some(iface) = oif {
            expressions.push(Self::meta_match("oifname", iface));
        }

        if !addresses.sources.is_empty() {
            let value = Self::value_or_set(
                addresses
                    .sources
                    .iter()
                    .map(|ip| Self::ip_to_nft_json(ip))
                    .collect(),
            );
            expressions.push(Self::payload_match(addresses.family, "saddr", value));
        }
        if !addresses.destinations.is_empty() {
            let value = Self::value_or_set(
                addresses
                    .destinations
                    .iter()
                    .map(|ip| Self::ip_to_nft_json(ip))
                    .collect(),
            );
            expressions.push(Self::payload_match(addresses.family, "daddr", value));
        }

        if has_ports && let Some(protocol) = port_protocol {
            let value = Self::value_or_set(
                rule.ports
                    .iter()
                    .copied()
                    .map(PortEntry::to_nft_json)
                    .collect(),
            );
            expressions.push(Self::payload_match(protocol, "dport", value));
        }

        // Limits: for Accept the rule matches while UNDER the limit ("accept up
        // to N/s"). For Drop/Reject the intent is "drop when OVER the limit", so
        // the limit is inverted; a plain limit would drop exactly the traffic
        // that stays within it.
        let inverted = rule.action != Action::Accept;

        if let Some(rate_limit) = rule.rate_limit {
            let mut limit = json!({
                "rate": rate_limit.count,
                "per": rate_limit.unit.as_str()
            });
            // nft rejects "burst 0 packets"; 0 means "no burst"
            if let Some(burst) = rate_limit.burst.filter(|&b| b > 0) {
                limit["burst"] = json!(burst);
            }
            if inverted {
                limit["inv"] = json!(true);
            }
            expressions.push(json!({ "limit": limit }));
        }

        if rule.connection_limit > 0 {
            let mut count = json!({ "val": rule.connection_limit });
            if inverted {
                count["inv"] = json!(true);
            }
            expressions.push(json!({ "ct count": count }));
        }

        // Per-rule logging (before action, so log happens even if action is accept)
        if rule.log_enabled {
            let prefix = if rule.log_prefix.is_empty() {
                Rule::sanitize_log_prefix(&rule.label)
            } else {
                crate::validators::sanitize_nft_quoted(&rule.log_prefix).into_owned()
            };
            expressions.push(json!({ "log": { "prefix": prefix, "level": "info" } }));
        }

        expressions.push(match rule.action {
            Action::Accept => json!({ "accept": null }),
            Action::Drop => json!({ "drop": null }),
            Action::Reject => match rule.reject_type {
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
            },
        });

        cmds.push(Self::rule_add(
            rule.chain.as_ref(),
            expressions,
            &rule.label,
        ));
    }

    fn add_termination_rules(cmds: &mut CommandList, advanced: &AdvancedSecuritySettings) {
        use serde_json::json;

        cmds.section = SECTION_END;

        // Optional: Log dropped packets before rejection
        if advanced.log_dropped {
            let prefix = crate::validators::sanitize_nft_quoted(&advanced.log_prefix);
            cmds.push(Self::rule_add(
                "input",
                vec![
                    Self::rate_limit(advanced.log_rate_per_minute, "minute"),
                    json!({ "log": { "prefix": prefix, "level": "info" } }),
                ],
                "log dropped packets (rate limited)",
            ));
        }

        // Rate-limited reject (prevents port scanning)
        cmds.push(Self::rule_add(
            "input",
            vec![
                Self::meta_match("pkttype", "host"),
                Self::rate_limit(5, "second"),
                json!({ "counter": null }),
                json!({ "reject": { "type": "icmpx", "expr": "admin-prohibited" } }),
            ],
            "",
        ));

        // Final counter (catches all remaining drops from chain policy)
        cmds.push(Self::rule_add(
            "input",
            vec![json!({ "counter": null })],
            "",
        ));
    }
}

/// nftables address family of the drfw table.
const NFT_FAMILY: &str = "inet";
/// Name of the drfw table.
const NFT_TABLE: &str = "drfw";
/// Priority of drfw's base chains (runs just before the default filter priority 0).
const CHAIN_PRIORITY: i32 = -10;

// Preview section headings (text output only; see `NftCommand::section`).
const SECTION_SETUP: &str = "Setup";
const SECTION_BASE: &str = "Base rules";
const SECTION_SECURITY: &str = "Security";
const SECTION_ICMP: &str = "ICMP";
const SECTION_USER: &str = "User rules";
const SECTION_END: &str = "End of chain";

/// One nftables JSON command plus the preview section it belongs to.
///
/// The section is presentation-only: the JSON output ignores it, and the text
/// renderer prints it as a `# --- … ---` heading when it changes within a chain.
#[derive(Debug, Clone)]
pub(crate) struct NftCommand {
    pub section: &'static str,
    pub value: serde_json::Value,
}

/// Accumulates [`NftCommand`]s, tagging each with the current section.
struct CommandList {
    commands: Vec<NftCommand>,
    section: &'static str,
}

impl CommandList {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            commands: Vec::with_capacity(capacity),
            section: SECTION_SETUP,
        }
    }

    fn push(&mut self, value: serde_json::Value) {
        self.commands.push(NftCommand {
            section: self.section,
            value,
        });
    }
}

/// Address matches for one family-specific copy of a user rule.
struct AddressMatch<'a> {
    /// Payload protocol for address matches: `ip` or `ip6`
    family: &'static str,
    sources: Vec<&'a IpNetwork>,
    destinations: Vec<&'a IpNetwork>,
}

impl Default for AddressMatch<'_> {
    fn default() -> Self {
        Self {
            family: "ip",
            sources: Vec::new(),
            destinations: Vec::new(),
        }
    }
}
