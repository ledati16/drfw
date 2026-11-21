//! Rule evaluator: what the generated input chain does with a new connection
//!
//! [`evaluate_inbound`] answers "is a new TCP/UDP connection to this port
//! accepted, and which rule decides?" for a [`FirewallRuleset`], without nft
//! and without privileges. It is used by the Exposure view (and the
//! `exposure` rows of [`crate::core::exposure`]) to explain who can reach the
//! services listening on this computer.
//!
//! # Model
//!
//! The evaluator walks a model of the input chain that
//! [`FirewallRuleset::to_nftables_json`] generates, in this order:
//!
//! 1. optional anti-spoofing (RPF) drop
//! 2. loopback accept (`iifname "lo"`)
//! 3. `ct state invalid` drop and `ct state established,related` accept:
//!    never match a **new** connection, so they are not modelled
//! 4. `DHCPv6` client replies accept (UDP 547 → 546 from `fe80::/10`)
//! 5. ICMP redirect drops
//! 6. **user rules**, in profile order
//! 7. ICMP accepts
//! 8. the rate-limited `reject` of unicast packets, then the chain's drop policy
//!
//! The ICMP sections (5, 7) never match TCP or UDP, so for the probes this
//! evaluator answers their position relative to the user rules does not
//! change any verdict.
//!
//! A user rule is modelled the way the generator emits it: disabled rules and
//! OUTPUT rules are skipped (Server/Desktop mode only changes the output
//! chain), a rule is split into one copy per address family when it has
//! addresses or a per-source limit, a copy is only made for a family that
//! every non-empty address list has, and rules that cannot be expressed
//! (interface empty after sanitizing, no common family) are skipped. Ports on
//! "Any" mean TCP and UDP. For Drop/Reject rules with both a rate and a
//! connection limit, each limit is its own rule ("drop when over either").
//!
//! # Limits and conditions
//!
//! Some rules only decide under a condition the probe cannot settle: a rate or
//! connection limit (whether it is reached depends on traffic), an interface
//! or destination address the probe leaves open, the RPF check, the source
//! port of `DHCPv6` replies, or "unicast" for the final reject. Such a rule
//! yields [`Verdict::Limited`]: what it does while the conditions hold, and
//! what happens otherwise (evaluation continues). An Accept rule with a limit
//! accepts *up to* the limit; packets over it fall through to later rules. A
//! Drop/Reject rule with a limit drops only *over* the limit.
//!
//! # Unknown sources
//!
//! With [`ProbeSource::Unknown`] the answer is a set: [`Reachability`]. It is
//! computed exactly over source addresses (CIDR set arithmetic: accepting
//! rules add their sources, earlier unconditional drops subtract theirs), with
//! these documented approximations:
//!
//! - An earlier **conditional** drop (a limited Drop rule, or one bound to an
//!   interface or destination the probe leaves open) is *not* subtracted: it
//!   only drops some packets. The result then over-states reachability (the
//!   safe direction for an exposure report) and [`Reachability::exact`] is
//!   `false`, with the rules named in [`Reachability::caveats`].
//! - Conditional accepts are reported separately
//!   ([`Reachability::conditional`]) with their conditions.
//! - The probe's interface, when not given, is some non-loopback interface;
//!   the loopback accept does not apply.
//! - Broadcast and multicast are not modelled (only "unicast" as a condition
//!   of the final reject).

use std::fmt;
use std::net::IpAddr;

use ipnetwork::IpNetwork;
use uuid::Uuid;

use super::addr_set::AddrSet;
use super::firewall::{Action, Chain, FirewallRuleset, Protocol, RateLimit, Rule, TimeUnit};
use super::rule_constraints::{protocol_requires_ipv4, protocol_requires_ipv6};

/// Comment of the generated anti-spoofing rule.
pub const BASE_RPF: &str = "drop packets with spoofed source addresses (RPF)";
/// Comment of the generated loopback accept.
pub const BASE_LOOPBACK: &str = "allow from loopback";
/// Comment of the generated `DHCPv6` client replies accept.
pub const BASE_DHCPV6: &str = "allow dhcpv6 client replies";
/// Name of the generated rate-limited reject at the end of the input chain
/// (it has no comment in the ruleset).
pub const BASE_FINAL_REJECT: &str = "rate-limited reject";

/// Rate of the final reject (`limit rate 5/second`); over it, the policy drops.
const FINAL_REJECT_RATE: u32 = 5;
/// `DHCPv6` server port (source port of the replies the base rule accepts).
const DHCPV6_SERVER_PORT: u16 = 547;
/// `DHCPv6` client port.
const DHCPV6_CLIENT_PORT: u16 = 546;
/// Name of the loopback interface.
const LOOPBACK_INTERFACE: &str = "lo";

/// Transport protocol of a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    /// "TCP" / "UDP"
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

/// IP address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    /// The family of `addr` (IPv4-mapped IPv6 addresses are IPv4).
    pub fn of(addr: IpAddr) -> Self {
        match addr.to_canonical() {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }

    /// "IPv4" / "IPv6"
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }

    const fn is_v6(self) -> bool {
        matches!(self, Self::V6)
    }
}

/// Where a probe comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeSource {
    /// One source address. Its family decides the probe's family
    /// (IPv4-mapped IPv6 addresses count as IPv4).
    Addr(IpAddr),
    /// A new connection from an arbitrary source: the verdict is the set of
    /// sources that can connect ([`Verdict::Reachable`]).
    Unknown,
}

/// A new inbound connection (TCP SYN or first UDP datagram) to evaluate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub transport: Transport,
    /// Destination port
    pub port: u16,
    /// Address family; ignored for [`ProbeSource::Addr`], whose address decides
    pub family: IpFamily,
    /// Input interface name; `None` = some non-loopback interface (rules bound
    /// to an interface then decide only conditionally)
    pub interface: Option<String>,
    /// Destination (local) address; `None` = any address of this computer
    /// (rules with destinations then decide only conditionally)
    pub destination: Option<IpAddr>,
    pub source: ProbeSource,
}

/// What decided a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decider {
    /// A user rule, by id and label
    UserRule { id: Uuid, label: String },
    /// A rule DRFW generates itself, by its comment (see the `BASE_*` constants)
    BaseRule(&'static str),
    /// The input chain's drop policy
    Policy,
}

impl Decider {
    /// The id of the user rule, if a user rule decided.
    pub fn rule_id(&self) -> Option<Uuid> {
        match self {
            Self::UserRule { id, .. } => Some(*id),
            _ => None,
        }
    }
}

impl fmt::Display for Decider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserRule { label, .. } if label.is_empty() => {
                f.write_str("rule (no description)")
            }
            Self::UserRule { label, .. } => write!(f, "rule \"{label}\""),
            Self::BaseRule(comment) => write!(f, "built-in rule \"{comment}\""),
            Self::Policy => f.write_str("the input chain policy (drop)"),
        }
    }
}

/// A condition under which a rule decides (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// The packet is within (`over == false`) or over a rate limit
    Rate { limit: RateLimit, over: bool },
    /// The source has at most (`over == false`) or more than `max` connections
    Connections {
        max: u32,
        per_source: bool,
        over: bool,
    },
    /// The packet arrives on an interface matching this name (`*` suffix =
    /// prefix match); only when the probe has no interface
    Interface(String),
    /// The packet is addressed to one of these networks; only when the probe
    /// has no destination
    Destination(Vec<IpNetwork>),
    /// The packet comes from this source port (probes have none)
    SourcePort(u16),
    /// The source fails the reverse-path check (it would not be routed back
    /// through the input interface)
    ReversePathFails,
    /// The packet is addressed to this host (not broadcast/multicast)
    Unicast,
}

impl Condition {
    /// `true` for "within a limit" conditions (an Accept rule's limits).
    const fn is_within_limit(&self) -> bool {
        matches!(
            self,
            Self::Rate { over: false, .. } | Self::Connections { over: false, .. }
        )
    }

    /// `true` for rate and connection limits (either side).
    pub const fn is_limit(&self) -> bool {
        matches!(self, Self::Rate { .. } | Self::Connections { .. })
    }

    /// Whether the condition holds for the **first** packet of a fresh
    /// ruleset, from an ephemeral source port, unicast, with a source that
    /// passes the reverse-path check; `None` if that does not settle it
    /// (interface, destination).
    const fn holds_for_first_packet(&self) -> Option<bool> {
        match self {
            // A fresh budget: within every limit
            Self::Rate { over, .. } | Self::Connections { over, .. } => Some(!*over),
            Self::SourcePort(_) | Self::ReversePathFails => Some(false),
            Self::Unicast => Some(true),
            Self::Interface(_) | Self::Destination(_) => None,
        }
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rate { limit, over } => {
                write!(
                    f,
                    "{} {}/{}",
                    if *over { "over" } else { "up to" },
                    limit.count,
                    limit.unit.as_str()
                )?;
                if let Some(burst) = limit.burst.filter(|&b| b > 0) {
                    write!(f, " (burst {burst})")?;
                }
                if limit.per_source {
                    f.write_str(" per source")?;
                }
                Ok(())
            }
            Self::Connections {
                max,
                per_source,
                over,
            } => {
                let plural = if *max == 1 { "" } else { "s" };
                write!(
                    f,
                    "{} {max} connection{plural}",
                    if *over { "over" } else { "up to" }
                )?;
                if *per_source {
                    f.write_str(" per source")?;
                }
                Ok(())
            }
            Self::Interface(name) => write!(f, "on interface {name}"),
            Self::Destination(networks) => {
                f.write_str("to ")?;
                write_networks(f, networks)
            }
            Self::SourcePort(port) => write!(f, "from source port {port}"),
            Self::ReversePathFails => f.write_str("failing the reverse-path check"),
            Self::Unicast => f.write_str("unicast"),
        }
    }
}

/// Writes networks comma-separated (single hosts without the prefix length).
fn write_networks(f: &mut fmt::Formatter<'_>, networks: &[IpNetwork]) -> fmt::Result {
    for (i, network) in networks.iter().enumerate() {
        if i > 0 {
            f.write_str(", ")?;
        }
        let host = (network.is_ipv4() && network.prefix() == 32)
            || (network.is_ipv6() && network.prefix() == 128);
        if host {
            write!(f, "{}", network.ip())?;
        } else {
            write!(f, "{network}")?;
        }
    }
    Ok(())
}

/// Joins conditions with " and ".
fn write_conditions(f: &mut fmt::Formatter<'_>, conditions: &[Condition]) -> fmt::Result {
    for (i, condition) in conditions.iter().enumerate() {
        if i > 0 {
            f.write_str(" and ")?;
        }
        write!(f, "{condition}")?;
    }
    Ok(())
}

/// Past-tense verb of an action ("accepted").
const fn action_verb(action: Action) -> &'static str {
    match action {
        Action::Accept => "accepted",
        Action::Drop => "dropped",
        Action::Reject => "rejected",
    }
}

/// What happens to a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accepted(Decider),
    Dropped(Decider),
    Rejected(Decider),
    /// `by` does `action` only while every condition in `when` holds (e.g.
    /// "accepted up to 5/minute"); otherwise `otherwise` applies.
    Limited {
        by: Decider,
        action: Action,
        when: Vec<Condition>,
        otherwise: Box<Verdict>,
    },
    /// The answer for [`ProbeSource::Unknown`]: who can connect
    Reachable(Reachability),
}

impl Verdict {
    fn decided(action: Action, by: Decider) -> Self {
        match action {
            Action::Accept => Self::Accepted(by),
            Action::Drop => Self::Dropped(by),
            Action::Reject => Self::Rejected(by),
        }
    }

    /// What happens to the **first** packet after the ruleset is applied
    /// (limits not reached yet), from an ephemeral source port, unicast, with
    /// a source that passes the reverse-path check: the action and its
    /// decider. `None` for [`Verdict::Reachable`] or when a condition does not
    /// settle (an interface or destination the probe left open).
    pub fn first_packet(&self) -> Option<(Action, &Decider)> {
        match self {
            Self::Accepted(by) => Some((Action::Accept, by)),
            Self::Dropped(by) => Some((Action::Drop, by)),
            Self::Rejected(by) => Some((Action::Reject, by)),
            Self::Limited {
                by,
                action,
                when,
                otherwise,
            } => {
                let mut all_hold = true;
                for condition in when {
                    all_hold &= condition.holds_for_first_packet()?;
                }
                if all_hold {
                    Some((*action, by))
                } else {
                    otherwise.first_packet()
                }
            }
            Self::Reachable(_) => None,
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted(by) | Self::Dropped(by) | Self::Rejected(by) => {
                let action = match self {
                    Self::Accepted(_) => Action::Accept,
                    Self::Dropped(_) => Action::Drop,
                    _ => Action::Reject,
                };
                write!(f, "{} by {by}", action_verb(action))
            }
            Self::Limited {
                by,
                action,
                when,
                otherwise,
            } => {
                write!(f, "{} ", action_verb(*action))?;
                write_conditions(f, when)?;
                write!(f, " by {by}")?;
                if when.iter().all(Condition::is_within_limit) {
                    write!(f, ", then {otherwise}")
                } else {
                    write!(f, "; otherwise {otherwise}")
                }
            }
            Self::Reachable(reach) => write!(f, "reachable from {reach}"),
        }
    }
}

/// A set of source addresses, as shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// Every address of the family
    Everyone,
    /// Every address except these networks
    AllExcept(Vec<IpNetwork>),
    /// Exactly these networks
    Sources(Vec<IpNetwork>),
    Nobody,
}

impl Reach {
    /// `true` if `addr` is in the set. The set is of one family (that of the
    /// [`Reachability`] it belongs to); `Everyone` contains any address.
    pub fn contains(&self, addr: IpAddr) -> bool {
        let addr = addr.to_canonical();
        match self {
            Self::Everyone => true,
            Self::AllExcept(networks) => !networks.iter().any(|n| n.contains(addr)),
            Self::Sources(networks) => networks.iter().any(|n| n.contains(addr)),
            Self::Nobody => false,
        }
    }

    /// The shortest description of `set`: the networks, or "all except" the
    /// complement's networks when that is shorter.
    fn from_set(set: &AddrSet) -> Self {
        if set.is_empty() {
            return Self::Nobody;
        }
        if set.is_full() {
            return Self::Everyone;
        }
        let included = set.to_networks();
        let excluded = set.complement().to_networks();
        if excluded.len() < included.len() {
            Self::AllExcept(excluded)
        } else {
            Self::Sources(included)
        }
    }
}

impl fmt::Display for Reach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Everyone => f.write_str("everyone"),
            Self::AllExcept(networks) => {
                f.write_str("everyone except ")?;
                write_networks(f, networks)
            }
            Self::Sources(networks) => write_networks(f, networks),
            Self::Nobody => f.write_str("nobody"),
        }
    }
}

/// Sources accepted only under conditions (a limit, an interface, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalAccess {
    pub sources: Reach,
    pub by: Decider,
    pub when: Vec<Condition>,
}

/// Who can open a new connection to a port (the answer for
/// [`ProbeSource::Unknown`]; see the module docs for the approximations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reachability {
    pub family: IpFamily,
    /// Sources accepted without conditions
    pub open: Reach,
    /// Further sources accepted only under conditions, in rule order
    pub conditional: Vec<ConditionalAccess>,
    /// Rules that accept some of the `open` sources, in rule order
    pub accepted_by: Vec<Decider>,
    /// What turns the remaining sources away: the rule after which no source
    /// was left, or the final reject (then the policy). `None` when every
    /// source is accepted.
    pub blocked_by: Option<Decider>,
    /// `false` when earlier conditional drops were not subtracted (the sets
    /// are then upper bounds); see `caveats`
    pub exact: bool,
    /// Rules that may drop some of the reported sources, with their conditions
    pub caveats: Vec<ConditionalAccess>,
}

impl Reachability {
    /// `true` when every address of the family can connect, at least under
    /// some condition (a limit, an interface).
    pub fn open_to_everyone(&self) -> bool {
        self.open == Reach::Everyone
            || self
                .conditional
                .iter()
                .any(|access| access.sources == Reach::Everyone)
    }

    /// `true` when no source can connect, not even conditionally.
    pub fn nobody(&self) -> bool {
        self.open == Reach::Nobody && self.conditional.is_empty()
    }

    /// The rule that matters most for this answer: the first rule accepting
    /// without conditions, else the first conditional accept, else what
    /// blocks.
    pub fn deciding(&self) -> Option<&Decider> {
        self.accepted_by
            .first()
            .or_else(|| self.conditional.first().map(|access| &access.by))
            .or(self.blocked_by.as_ref())
    }
}

impl fmt::Display for Reachability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.nobody() {
            return f.write_str("nobody");
        }
        let mut first = true;
        if self.open != Reach::Nobody {
            write!(f, "{}", self.open)?;
            first = false;
        }
        for access in &self.conditional {
            if !first {
                f.write_str("; ")?;
            }
            first = false;
            write!(f, "{} (", access.sources)?;
            write_conditions(f, &access.when)?;
            f.write_str(")")?;
        }
        if !self.exact {
            f.write_str(" (at most)")?;
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Chain model
// ═══════════════════════════════════════════════════════════════════════════

/// Which transport protocols a node matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtoMatch {
    /// No protocol match (`Any` without ports)
    All,
    /// `meta l4proto { tcp, udp }`
    TcpUdp,
    Tcp,
    Udp,
    /// ICMP / `ICMPv6`: never a TCP or UDP probe
    Icmp,
}

impl ProtoMatch {
    const fn matches(self, transport: Transport) -> bool {
        match self {
            Self::All | Self::TcpUdp => true,
            Self::Tcp => matches!(transport, Transport::Tcp),
            Self::Udp => matches!(transport, Transport::Udp),
            Self::Icmp => false,
        }
    }
}

/// An `iifname` match.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InterfaceMatch {
    /// The name as written (shown in conditions)
    pattern: String,
    /// `eth*`: prefix match on `eth`
    wildcard: bool,
}

impl InterfaceMatch {
    fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
            wildcard: pattern.ends_with('*'),
        }
    }

    /// `true` for exactly `lo`.
    fn matches_only_loopback(&self) -> bool {
        !self.wildcard && self.pattern == LOOPBACK_INTERFACE
    }

    fn matches(&self, name: &str) -> bool {
        if self.wildcard {
            name.starts_with(&self.pattern[..self.pattern.len() - 1])
        } else {
            name == self.pattern
        }
    }
}

/// One rule of the modelled input chain (see the module docs).
#[derive(Debug, Clone)]
struct Node {
    decider: Decider,
    /// `None`: both families
    family: Option<IpFamily>,
    protocols: ProtoMatch,
    /// Destination port ranges (inclusive); empty = any port
    ports: Vec<(u16, u16)>,
    interface: Option<InterfaceMatch>,
    /// The rule can never match on the input hook (an `oifname` match)
    never: bool,
    /// Source networks (`None` = any); only with a `family`
    sources: Option<AddrSet>,
    /// Destination networks (`None` = any); only with a `family`
    destinations: Option<(Vec<IpNetwork>, AddrSet)>,
    /// Required source port (`DHCPv6` replies)
    source_port: Option<u16>,
    /// Limits and other conditions the probe cannot settle
    conditions: Vec<Condition>,
    action: Action,
}

impl Node {
    fn base(decider: &'static str, action: Action) -> Self {
        Self {
            decider: Decider::BaseRule(decider),
            family: None,
            protocols: ProtoMatch::All,
            ports: Vec::new(),
            interface: None,
            never: false,
            sources: None,
            destinations: None,
            source_port: None,
            conditions: Vec::new(),
            action,
        }
    }

    /// Whether the node matches the probe's fixed fields (everything but the
    /// source): `None` if not, else the conditions it still depends on.
    fn matches(&self, probe: &Probe, family: IpFamily) -> Option<Vec<Condition>> {
        if self.never
            || self.family.is_some_and(|f| f != family)
            || !self.protocols.matches(probe.transport)
            || (!self.ports.is_empty()
                && !self
                    .ports
                    .iter()
                    .any(|&(start, end)| (start..=end).contains(&probe.port)))
        {
            return None;
        }
        let mut conditions = Vec::new();
        if let Some(interface) = &self.interface {
            match &probe.interface {
                Some(name) if interface.matches(name) => {}
                Some(_) => return None,
                // An unknown interface is not loopback
                None if interface.matches_only_loopback() => return None,
                None => conditions.push(Condition::Interface(interface.pattern.clone())),
            }
        }
        if let Some((networks, set)) = &self.destinations {
            match probe.destination {
                Some(addr) if set.contains(addr.to_canonical()) => {}
                Some(_) => return None,
                None => conditions.push(Condition::Destination(networks.clone())),
            }
        }
        if let Some(port) = self.source_port {
            conditions.push(Condition::SourcePort(port));
        }
        conditions.extend(self.conditions.iter().cloned());
        Some(conditions)
    }
}

/// The modelled input chain of a ruleset, built once and evaluated for many
/// probes (see the module docs for what is modelled).
#[derive(Debug, Clone)]
pub struct InputChain {
    nodes: Vec<Node>,
}

impl InputChain {
    /// Models the input chain [`FirewallRuleset::to_nftables_json`] generates.
    pub fn new(ruleset: &FirewallRuleset) -> Self {
        let advanced = &ruleset.advanced_security;
        let mut nodes = Vec::with_capacity(8 + ruleset.rules.len());

        if advanced.enable_rpf {
            let mut rpf = Node::base(BASE_RPF, Action::Drop);
            rpf.conditions.push(Condition::ReversePathFails);
            nodes.push(rpf);
        }
        let mut loopback = Node::base(BASE_LOOPBACK, Action::Accept);
        loopback.interface = Some(InterfaceMatch::new(LOOPBACK_INTERFACE));
        nodes.push(loopback);
        // (ct state invalid drop / established accept: never a new connection)
        let mut dhcpv6 = Node::base(BASE_DHCPV6, Action::Accept);
        dhcpv6.family = Some(IpFamily::V6);
        dhcpv6.protocols = ProtoMatch::Udp;
        dhcpv6.ports = vec![(DHCPV6_CLIENT_PORT, DHCPV6_CLIENT_PORT)];
        dhcpv6.source_port = Some(DHCPV6_SERVER_PORT);
        let link_local =
            ipnetwork::Ipv6Network::new(std::net::Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 0), 10)
                .map(IpNetwork::V6);
        dhcpv6.sources = Some(AddrSet::from_networks(true, link_local.as_ref().ok()));
        nodes.push(dhcpv6);
        // (ICMP redirect drops: never TCP/UDP)

        for rule in &ruleset.rules {
            push_user_rule(&mut nodes, rule);
        }

        // (ICMP accepts: never TCP/UDP)
        let mut reject = Node::base(BASE_FINAL_REJECT, Action::Reject);
        reject.conditions = vec![
            Condition::Unicast,
            Condition::Rate {
                limit: RateLimit {
                    count: FINAL_REJECT_RATE,
                    unit: TimeUnit::Second,
                    burst: None,
                    per_source: false,
                },
                over: false,
            },
        ];
        nodes.push(reject);

        Self { nodes }
    }

    /// Evaluates a new inbound connection (see [`evaluate_inbound`]).
    pub fn evaluate(&self, probe: &Probe) -> Verdict {
        match probe.source {
            ProbeSource::Addr(addr) => self.evaluate_source(probe, addr.to_canonical()),
            ProbeSource::Unknown => Verdict::Reachable(self.reachability(probe)),
        }
    }

    /// The verdict for one source address: the first node that matches
    /// without conditions decides; conditional matches on the way become
    /// [`Verdict::Limited`] layers.
    fn evaluate_source(&self, probe: &Probe, source: IpAddr) -> Verdict {
        let family = IpFamily::of(source);
        let mut layers: Vec<(&Node, Vec<Condition>)> = Vec::new();
        let mut verdict = Verdict::Dropped(Decider::Policy);
        for node in &self.nodes {
            let Some(conditions) = node.matches(probe, family) else {
                continue;
            };
            if node.sources.as_ref().is_some_and(|s| !s.contains(source)) {
                continue;
            }
            if conditions.is_empty() {
                verdict = Verdict::decided(node.action, node.decider.clone());
                break;
            }
            layers.push((node, conditions));
        }
        for (node, when) in layers.into_iter().rev() {
            verdict = Verdict::Limited {
                by: node.decider.clone(),
                action: node.action,
                when,
                otherwise: Box::new(verdict),
            };
        }
        verdict
    }

    /// Who can connect (see [`Reachability`] and the module docs).
    fn reachability(&self, probe: &Probe) -> Reachability {
        let v6 = probe.family.is_v6();
        let mut remaining = AddrSet::full(v6);
        let mut open = AddrSet::empty(v6);
        let mut accepted_by: Vec<Decider> = Vec::new();
        let mut conditional: Vec<(AddrSet, Decider, Vec<Condition>)> = Vec::new();
        // Earlier conditional drops, checked against every later accept
        let mut conditional_drops: Vec<(AddrSet, Decider, Vec<Condition>)> = Vec::new();
        let mut caveats: Vec<ConditionalAccess> = Vec::new();
        let mut blocked_by = None;

        for node in &self.nodes {
            if remaining.is_empty() {
                break;
            }
            let Some(conditions) = node.matches(probe, probe.family) else {
                continue;
            };
            let matched = match &node.sources {
                Some(sources) => sources.intersection(&remaining),
                None => remaining.clone(),
            };
            if matched.is_empty() {
                continue;
            }
            if node.action == Action::Accept {
                // An accept behind a conditional drop may not reach everyone
                for (dropped, by, when) in &conditional_drops {
                    let overlap = dropped.intersection(&matched);
                    if !overlap.is_empty() && !caveats.iter().any(|c| c.by == *by) {
                        caveats.push(ConditionalAccess {
                            sources: Reach::from_set(&overlap),
                            by: by.clone(),
                            when: when.clone(),
                        });
                    }
                }
            }
            match (conditions.is_empty(), node.action) {
                (true, Action::Accept) => {
                    open = open.union(&matched);
                    remaining = remaining.difference(&matched);
                    if !accepted_by.contains(&node.decider) {
                        accepted_by.push(node.decider.clone());
                    }
                }
                (true, _) => {
                    remaining = remaining.difference(&matched);
                    if remaining.is_empty() {
                        blocked_by = Some(node.decider.clone());
                    }
                }
                (false, Action::Accept) => {
                    conditional.push((matched, node.decider.clone(), conditions));
                }
                (false, _) => conditional_drops.push((matched, node.decider.clone(), conditions)),
            }
        }
        if !remaining.is_empty() {
            blocked_by = Some(Decider::BaseRule(BASE_FINAL_REJECT));
        }

        // A source accepted unconditionally later is not "conditional"
        let conditional = conditional
            .into_iter()
            .filter_map(|(sources, by, when)| {
                let sources = sources.difference(&open);
                (!sources.is_empty()).then(|| ConditionalAccess {
                    sources: Reach::from_set(&sources),
                    by,
                    when,
                })
            })
            .collect();

        Reachability {
            family: probe.family,
            open: Reach::from_set(&open),
            conditional,
            accepted_by,
            blocked_by,
            exact: caveats.is_empty(),
            caveats,
        }
    }
}

/// Adds the nodes for one user rule, mirroring the generator's
/// `add_user_rule` (family copies, skipped rules).
fn push_user_rule(nodes: &mut Vec<Node>, rule: &Rule) {
    // Output rules never see inbound packets (and are skipped in Desktop mode)
    if !rule.enabled || rule.chain != Chain::Input {
        return;
    }
    let sanitize = |name: &Option<String>| {
        name.as_deref()
            .map(|n| crate::validators::sanitize_nft_quoted(n).into_owned())
    };
    let interface = sanitize(&rule.interface);
    let output_interface = sanitize(&rule.output_interface);
    if interface.as_deref().is_some_and(str::is_empty)
        || output_interface.as_deref().is_some_and(str::is_empty)
    {
        return; // the generator skips the rule
    }

    let per_source = rule.has_per_source_limit();
    if rule.sources.is_empty() && rule.destinations.is_empty() && !per_source {
        push_rule_copy(
            nodes,
            rule,
            interface.as_deref(),
            output_interface.is_some(),
            None,
        );
        return;
    }
    for family in [IpFamily::V4, IpFamily::V6] {
        let v6 = family.is_v6();
        let protocol_family_ok = if v6 {
            !protocol_requires_ipv4(rule.protocol)
        } else {
            !protocol_requires_ipv6(rule.protocol)
        };
        if per_source && !protocol_family_ok {
            continue;
        }
        let has = |list: &[IpNetwork]| list.is_empty() || list.iter().any(|n| n.is_ipv6() == v6);
        if has(&rule.sources) && has(&rule.destinations) {
            push_rule_copy(
                nodes,
                rule,
                interface.as_deref(),
                output_interface.is_some(),
                Some(family),
            );
        }
    }
}

/// Adds the node(s) of one family copy of a user rule.
fn push_rule_copy(
    nodes: &mut Vec<Node>,
    rule: &Rule,
    interface: Option<&str>,
    has_output_interface: bool,
    family: Option<IpFamily>,
) {
    let has_ports = !rule.ports.is_empty();
    let protocols = match rule.protocol {
        Protocol::Any if has_ports => ProtoMatch::TcpUdp,
        Protocol::Any => ProtoMatch::All,
        Protocol::Tcp => ProtoMatch::Tcp,
        Protocol::Udp => ProtoMatch::Udp,
        Protocol::TcpAndUdp => ProtoMatch::TcpUdp,
        Protocol::Icmp | Protocol::Icmpv6 | Protocol::IcmpBoth => ProtoMatch::Icmp,
    };
    let ports = if protocols == ProtoMatch::Icmp {
        Vec::new()
    } else {
        rule.ports.iter().map(|p| (p.start(), p.end())).collect()
    };
    let (sources, destinations) = match family {
        None => (None, None),
        Some(family) => {
            let v6 = family.is_v6();
            let sources =
                (!rule.sources.is_empty()).then(|| AddrSet::from_networks(v6, &rule.sources));
            let destinations = (!rule.destinations.is_empty()).then(|| {
                let list: Vec<IpNetwork> = rule
                    .destinations
                    .iter()
                    .filter(|n| n.is_ipv6() == v6)
                    .copied()
                    .collect();
                let set = AddrSet::from_networks(v6, &list);
                (list, set)
            });
            (sources, destinations)
        }
    };
    let template = Node {
        decider: Decider::UserRule {
            id: rule.id,
            label: rule.label.clone(),
        },
        family,
        protocols,
        ports,
        interface: interface.map(InterfaceMatch::new),
        // `oifname` is not set on the input hook: such a rule never matches
        never: has_output_interface,
        sources,
        destinations,
        source_port: None,
        conditions: Vec::new(),
        action: rule.action,
    };

    let rate = rule.rate_limit;
    let connections = (rule.connection_limit > 0).then_some(rule.connection_limit);
    let over = rule.action != Action::Accept;
    let rate_condition = rate.map(|limit| Condition::Rate { limit, over });
    let connection_condition = connections.map(|max| Condition::Connections {
        max,
        per_source: rule.connection_limit_per_source,
        over,
    });

    if over && rate_condition.is_some() && connection_condition.is_some() {
        // Drop/Reject with both limits: one rule per limit, "over either"
        for condition in [rate_condition, connection_condition].into_iter().flatten() {
            let mut node = template.clone();
            node.conditions.push(condition);
            nodes.push(node);
        }
        return;
    }
    let mut node = template;
    node.conditions.extend(rate_condition);
    node.conditions.extend(connection_condition);
    nodes.push(node);
}

/// What the input chain generated for `ruleset` does with a new inbound
/// TCP/UDP connection.
///
/// For a [`ProbeSource::Addr`] the verdict is [`Verdict::Accepted`],
/// [`Verdict::Dropped`], [`Verdict::Rejected`] (with the deciding rule) or
/// [`Verdict::Limited`] when a limit or an open condition is involved. For
/// [`ProbeSource::Unknown`] it is [`Verdict::Reachable`] with the set of
/// sources that can connect.
///
/// To evaluate many probes against one ruleset, build an [`InputChain`] once.
///
/// # Example
///
/// ```
/// use drfw::core::evaluate::{IpFamily, Probe, ProbeSource, Transport, evaluate_inbound};
/// use drfw::core::firewall::{Chain, FirewallRuleset, PortEntry, Protocol, Rule};
///
/// let mut ruleset = FirewallRuleset::new();
/// ruleset.rules.push(Rule::with_caches(
///     uuid::Uuid::new_v4(),
///     "SSH".into(),
///     Protocol::Tcp,
///     vec![PortEntry::Single(22)],
///     vec!["192.168.1.0/24".parse().unwrap()],
///     None,
///     Chain::Input,
///     true,
///     jiff::Timestamp::now(),
///     vec![],
/// ));
/// let probe = Probe {
///     transport: Transport::Tcp,
///     port: 22,
///     family: IpFamily::V4,
///     interface: None,
///     destination: None,
///     source: ProbeSource::Unknown,
/// };
/// let verdict = evaluate_inbound(&ruleset, &probe);
/// assert_eq!(verdict.to_string(), "reachable from 192.168.1.0/24");
/// ```
pub fn evaluate_inbound(ruleset: &FirewallRuleset, probe: &Probe) -> Verdict {
    InputChain::new(ruleset).evaluate(probe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::firewall::{AdvancedSecuritySettings, PortEntry};
    use crate::core::test_helpers::create_test_rule;

    fn ruleset(rules: Vec<Rule>) -> FirewallRuleset {
        FirewallRuleset {
            rules,
            advanced_security: AdvancedSecuritySettings::default(),
        }
    }

    fn rule(label: &str, protocol: Protocol, ports: &[u16], sources: &[&str]) -> Rule {
        let mut r = create_test_rule(label, None);
        r.protocol = protocol;
        r.ports = ports.iter().copied().map(PortEntry::Single).collect();
        r.sources = sources.iter().map(|s| s.parse().unwrap()).collect();
        r.rebuild_caches();
        r
    }

    fn probe(transport: Transport, port: u16, source: &str) -> Probe {
        let addr: IpAddr = source.parse().unwrap();
        Probe {
            transport,
            port,
            family: IpFamily::of(addr),
            interface: Some("eth0".into()),
            destination: None,
            source: ProbeSource::Addr(addr),
        }
    }

    fn unknown(transport: Transport, port: u16, family: IpFamily) -> Probe {
        Probe {
            transport,
            port,
            family,
            interface: None,
            destination: None,
            source: ProbeSource::Unknown,
        }
    }

    fn reach(ruleset: &FirewallRuleset, probe: &Probe) -> Reachability {
        match evaluate_inbound(ruleset, probe) {
            Verdict::Reachable(r) => r,
            other => panic!("expected a set, got {other:?}"),
        }
    }

    fn first(verdict: &Verdict) -> Action {
        verdict.first_packet().expect("settled").0
    }

    #[test]
    fn test_empty_ruleset_rejects_then_drops() {
        let v = evaluate_inbound(&ruleset(vec![]), &probe(Transport::Tcp, 22, "10.0.0.1"));
        assert_eq!(first(&v), Action::Reject);
        assert_eq!(
            v.to_string(),
            "rejected unicast and up to 5/second by built-in rule \"rate-limited reject\"; \
             otherwise dropped by the input chain policy (drop)"
        );
        let r = reach(&ruleset(vec![]), &unknown(Transport::Tcp, 22, IpFamily::V4));
        assert!(r.nobody());
        assert_eq!(r.blocked_by, Some(Decider::BaseRule(BASE_FINAL_REJECT)));
    }

    #[test]
    fn test_accept_rule_matches_protocol_port_and_source() {
        let ssh = rule("SSH", Protocol::Tcp, &[22], &["192.168.1.0/24"]);
        let id = ssh.id;
        let rs = ruleset(vec![ssh]);
        let v = evaluate_inbound(&rs, &probe(Transport::Tcp, 22, "192.168.1.9"));
        assert_eq!(
            v,
            Verdict::Accepted(Decider::UserRule {
                id,
                label: "SSH".into()
            })
        );
        for p in [
            probe(Transport::Udp, 22, "192.168.1.9"),
            probe(Transport::Tcp, 23, "192.168.1.9"),
            probe(Transport::Tcp, 22, "192.168.2.9"),
            probe(Transport::Tcp, 22, "fe80::1"),
        ] {
            assert_eq!(first(&evaluate_inbound(&rs, &p)), Action::Reject, "{p:?}");
        }
    }

    #[test]
    fn test_protocol_variants() {
        let cases = [
            (Protocol::Any, &[][..], Transport::Udp, 9, true),
            (Protocol::Any, &[53][..], Transport::Udp, 53, true),
            (Protocol::Any, &[53][..], Transport::Tcp, 54, false),
            (Protocol::TcpAndUdp, &[53][..], Transport::Tcp, 53, true),
            (Protocol::Udp, &[53][..], Transport::Tcp, 53, false),
            (Protocol::Icmp, &[][..], Transport::Tcp, 53, false),
            (Protocol::IcmpBoth, &[][..], Transport::Udp, 53, false),
        ];
        for (protocol, ports, transport, port, accepted) in cases {
            let rs = ruleset(vec![rule("r", protocol, ports, &[])]);
            let got = first(&evaluate_inbound(&rs, &probe(transport, port, "10.0.0.1")));
            assert_eq!(
                got == Action::Accept,
                accepted,
                "{protocol:?} {transport:?}"
            );
        }
        // Port ranges are inclusive
        let mut r = rule("range", Protocol::Tcp, &[], &[]);
        r.ports = vec![PortEntry::range(1000, 2000)];
        let rs = ruleset(vec![r]);
        for (port, ok) in [(999, false), (1000, true), (2000, true), (2001, false)] {
            let got = first(&evaluate_inbound(
                &rs,
                &probe(Transport::Tcp, port, "10.0.0.1"),
            ));
            assert_eq!(got == Action::Accept, ok, "port {port}");
        }
    }

    #[test]
    fn test_first_match_wins_and_disabled_or_output_rules_are_skipped() {
        let mut drop = rule("block", Protocol::Tcp, &[22], &["10.0.0.0/8"]);
        drop.action = Action::Drop;
        let allow = rule("allow", Protocol::Tcp, &[22], &[]);
        let rs = ruleset(vec![drop.clone(), allow.clone()]);
        assert_eq!(
            first(&evaluate_inbound(
                &rs,
                &probe(Transport::Tcp, 22, "10.1.1.1")
            )),
            Action::Drop
        );
        assert_eq!(
            first(&evaluate_inbound(
                &rs,
                &probe(Transport::Tcp, 22, "11.1.1.1")
            )),
            Action::Accept
        );

        let mut disabled = drop.clone();
        disabled.enabled = false;
        let mut output = drop;
        output.chain = Chain::Output;
        let rs = ruleset(vec![disabled, output, allow]);
        assert_eq!(
            first(&evaluate_inbound(
                &rs,
                &probe(Transport::Tcp, 22, "10.1.1.1")
            )),
            Action::Accept
        );
    }

    #[test]
    fn test_reachability_subtracts_earlier_drops() {
        let mut drop = rule("block", Protocol::Tcp, &[22], &["10.0.0.0/8"]);
        drop.action = Action::Reject;
        let allow = rule("allow", Protocol::Tcp, &[22], &[]);
        let rs = ruleset(vec![drop, allow.clone()]);
        let r = reach(&rs, &unknown(Transport::Tcp, 22, IpFamily::V4));
        assert_eq!(
            r.open,
            Reach::AllExcept(vec!["10.0.0.0/8".parse().unwrap()])
        );
        assert!(r.exact);
        assert!(!r.open_to_everyone());
        assert_eq!(r.to_string(), "everyone except 10.0.0.0/8");
        // IPv6 is not affected by an IPv4 drop
        let r6 = reach(&rs, &unknown(Transport::Tcp, 22, IpFamily::V6));
        assert_eq!(r6.open, Reach::Everyone);
        assert!(r6.open_to_everyone());
        assert_eq!(r6.deciding().and_then(Decider::rule_id), Some(allow.id));
    }

    #[test]
    fn test_reachability_unions_accepting_rules() {
        let a = rule("a", Protocol::Tcp, &[80], &["10.0.0.0/24", "fd00::/8"]);
        let b = rule("b", Protocol::TcpAndUdp, &[80], &["10.0.1.0/24"]);
        let rs = ruleset(vec![a, b]);
        let r = reach(&rs, &unknown(Transport::Tcp, 80, IpFamily::V4));
        assert_eq!(r.open, Reach::Sources(vec!["10.0.0.0/23".parse().unwrap()]));
        assert_eq!(r.accepted_by.len(), 2);
        assert_eq!(r.blocked_by, Some(Decider::BaseRule(BASE_FINAL_REJECT)));
        let r6 = reach(&rs, &unknown(Transport::Tcp, 80, IpFamily::V6));
        assert_eq!(r6.to_string(), "fd00::/8");
        assert!(reach(&rs, &unknown(Transport::Udp, 81, IpFamily::V4)).nobody());
    }

    #[test]
    fn test_accept_with_rate_limit_falls_through_over_the_limit() {
        let mut limited = rule("ssh", Protocol::Tcp, &[22], &[]);
        limited.rate_limit = Some(RateLimit {
            count: 3,
            unit: TimeUnit::Minute,
            burst: None,
            per_source: true,
        });
        let rs = ruleset(vec![limited]);
        let v = evaluate_inbound(&rs, &probe(Transport::Tcp, 22, "10.0.0.1"));
        assert_eq!(first(&v), Action::Accept);
        assert!(
            v.to_string()
                .starts_with("accepted up to 3/minute per source by rule \"ssh\", then rejected"),
            "{v}"
        );
        let r = reach(&rs, &unknown(Transport::Tcp, 22, IpFamily::V4));
        assert_eq!(r.open, Reach::Nobody);
        assert_eq!(r.conditional.len(), 1);
        assert!(r.open_to_everyone(), "everyone, if rate limited");
        assert_eq!(r.to_string(), "everyone (up to 3/minute per source)");
    }

    #[test]
    fn test_drop_with_limits_only_over_the_limit_and_split() {
        let mut flood = rule("flood", Protocol::Udp, &[53], &[]);
        flood.action = Action::Drop;
        flood.rate_limit = Some(RateLimit {
            count: 10,
            unit: TimeUnit::Second,
            burst: Some(20),
            per_source: false,
        });
        flood.connection_limit = 4;
        let allow = rule("dns", Protocol::Udp, &[53], &[]);
        let rs = ruleset(vec![flood, allow]);
        let v = evaluate_inbound(&rs, &probe(Transport::Udp, 53, "10.0.0.1"));
        assert_eq!(first(&v), Action::Accept);
        let Verdict::Limited {
            when, otherwise, ..
        } = &v
        else {
            panic!("{v:?}");
        };
        assert_eq!(when.len(), 1, "one limit per rule");
        assert!(matches!(**otherwise, Verdict::Limited { .. }));
        // The conditional drop is not subtracted; the answer says so
        let r = reach(&rs, &unknown(Transport::Udp, 53, IpFamily::V4));
        assert_eq!(r.open, Reach::Everyone);
        assert!(!r.exact);
        assert_eq!(r.caveats.len(), 1);
        assert!(r.to_string().ends_with("(at most)"));
    }

    #[test]
    fn test_interface_exact_wildcard_and_unknown() {
        let mut r = rule("wg", Protocol::Udp, &[51820], &[]);
        r.interface = Some("wg*".into());
        let rs = ruleset(vec![r]);
        let mut p = probe(Transport::Udp, 51820, "10.0.0.1");
        p.interface = Some("wg0".into());
        assert_eq!(first(&evaluate_inbound(&rs, &p)), Action::Accept);
        p.interface = Some("eth0".into());
        assert_eq!(first(&evaluate_inbound(&rs, &p)), Action::Reject);
        p.interface = None;
        assert_eq!(evaluate_inbound(&rs, &p).first_packet(), None, "unsettled");
        let r = reach(&rs, &unknown(Transport::Udp, 51820, IpFamily::V6));
        assert_eq!(r.to_string(), "everyone (on interface wg*)");

        // Loopback is accepted by the base rule
        let mut lo = probe(Transport::Tcp, 1, "127.0.0.1");
        lo.interface = Some("lo".into());
        assert_eq!(
            evaluate_inbound(&rs, &lo),
            Verdict::Accepted(Decider::BaseRule(BASE_LOOPBACK))
        );
    }

    #[test]
    fn test_destinations_and_family_copies() {
        let mut r = rule("web", Protocol::Tcp, &[443], &["10.0.0.0/8", "fd00::/8"]);
        r.destinations = vec!["192.168.1.10".parse().unwrap()];
        let rs = ruleset(vec![r]);
        // Only an IPv4 copy exists (the destination list has no IPv6)
        assert!(reach(&rs, &unknown(Transport::Tcp, 443, IpFamily::V6)).nobody());
        let r4 = reach(&rs, &unknown(Transport::Tcp, 443, IpFamily::V4));
        assert_eq!(r4.to_string(), "10.0.0.0/8 (to 192.168.1.10)");
        let mut p = probe(Transport::Tcp, 443, "10.2.3.4");
        p.destination = Some("192.168.1.10".parse().unwrap());
        assert_eq!(first(&evaluate_inbound(&rs, &p)), Action::Accept);
        p.destination = Some("192.168.1.11".parse().unwrap());
        assert_eq!(first(&evaluate_inbound(&rs, &p)), Action::Reject);

        // No common family: the generator skips the rule entirely
        let mut never = rule("never", Protocol::Tcp, &[443], &["fd00::/8"]);
        never.destinations = vec!["192.168.1.10".parse().unwrap()];
        let rs = ruleset(vec![never]);
        for family in [IpFamily::V4, IpFamily::V6] {
            assert!(reach(&rs, &unknown(Transport::Tcp, 443, family)).nobody());
        }
    }

    #[test]
    fn test_output_interface_on_input_never_matches_and_empty_interface_skips() {
        let mut r = rule("odd", Protocol::Tcp, &[22], &[]);
        r.output_interface = Some("eth0".into());
        let mut r2 = rule("quote", Protocol::Tcp, &[22], &[]);
        r2.interface = Some("\"".into());
        let rs = ruleset(vec![r, r2]);
        assert_eq!(
            first(&evaluate_inbound(
                &rs,
                &probe(Transport::Tcp, 22, "10.0.0.1")
            )),
            Action::Reject
        );
    }

    #[test]
    fn test_dhcpv6_and_rpf_base_rules_are_conditional() {
        let mut rs = ruleset(vec![]);
        let r = reach(&rs, &unknown(Transport::Udp, 546, IpFamily::V6));
        assert_eq!(r.to_string(), "fe80::/10 (from source port 547)");
        assert_eq!(
            r.deciding(),
            Some(&Decider::BaseRule(BASE_DHCPV6)),
            "the base rule decides"
        );
        rs.advanced_security.enable_rpf = true;
        rs.rules.push(rule("all", Protocol::Any, &[], &[]));
        let v = evaluate_inbound(&rs, &probe(Transport::Tcp, 80, "10.0.0.1"));
        assert_eq!(first(&v), Action::Accept, "RPF passes for the first packet");
        assert!(
            v.to_string()
                .starts_with("dropped failing the reverse-path check")
        );
        let r = reach(&rs, &unknown(Transport::Tcp, 80, IpFamily::V4));
        assert!(!r.exact, "the RPF drop is not subtracted");
    }

    #[test]
    fn test_conditional_accept_then_unconditional_accept() {
        let mut limited = rule("limited", Protocol::Tcp, &[22], &["10.0.0.0/8"]);
        limited.connection_limit = 2;
        let allow = rule("lan", Protocol::Tcp, &[22], &["10.1.0.0/16"]);
        let rs = ruleset(vec![limited, allow]);
        let r = reach(&rs, &unknown(Transport::Tcp, 22, IpFamily::V4));
        assert_eq!(r.open.to_string(), "10.1.0.0/16");
        assert_eq!(r.conditional.len(), 1);
        assert_eq!(
            r.conditional[0].when,
            [Condition::Connections {
                max: 2,
                per_source: false,
                over: false
            }]
        );
        // The conditional part excludes the unconditionally open /16
        assert!(matches!(&r.conditional[0].sources, Reach::Sources(n) if n.len() > 1));
    }

    #[test]
    fn test_mapped_source_is_ipv4() {
        let rs = ruleset(vec![rule("a", Protocol::Tcp, &[22], &["10.0.0.0/8"])]);
        let mut p = probe(Transport::Tcp, 22, "::ffff:10.0.0.1");
        p.family = IpFamily::V6;
        assert_eq!(first(&evaluate_inbound(&rs, &p)), Action::Accept);
    }

    /// The base rules named by the evaluator exist in the generated ruleset
    /// (guards against the generator renaming them).
    #[test]
    fn test_base_rule_names_match_the_generator() {
        let mut rs = ruleset(vec![]);
        rs.advanced_security.enable_rpf = true;
        let text = rs.to_nft_text();
        for comment in [BASE_RPF, BASE_LOOPBACK, BASE_DHCPV6] {
            assert!(text.contains(comment), "{comment} missing:\n{text}");
        }
        assert!(text.contains("limit rate 5/second"), "{text}");
        let origins: Vec<_> = rs.build_commands().into_iter().map(|c| c.origin).collect();
        assert!(
            origins.contains(&crate::core::firewall::CommandOrigin::BaseRule(
                BASE_FINAL_REJECT
            ))
        );
    }
}
