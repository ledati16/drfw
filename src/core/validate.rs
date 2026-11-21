//! Semantic validation of rules and rulesets
//!
//! This is the **single** source of truth for "is this rule something nft can
//! apply, and does it do what the user sees?". It is used by:
//!
//! - the GUI rule form ([`crate::app`]'s `RuleForm::validate` builds a candidate
//!   [`Rule`] and delegates here, so the form and the loader can never disagree),
//! - the GUI sidebar (invalid rules are flagged, with the reason in a tooltip),
//! - the apply / Save to System paths, which must refuse to run while
//!   [`FirewallRuleset::validate_for_apply`] returns an error.
//!
//! # Policy
//!
//! Profiles may *contain* invalid rules: loading never drops data. Invalid
//! rules are only a problem when they would be sent to the kernel, i.e. when
//! they are enabled (and, for OUTPUT rules, when Server Mode is on). Ruleset-level
//! problems (too many rules, duplicate ids, broken advanced settings) always
//! block applying.
//!
//! Field checks reuse [`crate::validators`] and [`crate::core::rule_constraints`];
//! this module only decides which combinations are errors.

use std::fmt;

use uuid::Uuid;

use super::firewall::{
    Action, AdvancedSecuritySettings, Chain, FirewallRuleset, MAX_RULES, PortEntry, Rule,
};
use super::rule_constraints::{
    ip_compatible_with_protocol, protocol_is_icmp, reject_type_valid_for_protocol,
};

/// Why a per-source limit is refused on a Drop/Reject rule.
pub const PER_SOURCE_ACCEPT_ONLY: &str = "Per-source limits only work with the Accept action \
     (when the tracking table is full, a Drop/Reject rule would let new sources through)";

/// The rule field an issue is about (lets the form show it next to the input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleField {
    Label,
    Tags,
    Ports,
    Sources,
    Destinations,
    Interface,
    OutputInterface,
    RejectType,
    RateLimit,
    ConnectionLimit,
}

/// One problem with one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleIssue {
    /// Which field the problem is about
    pub field: RuleField,
    /// User-facing explanation (no internal details)
    pub message: String,
}

impl RuleIssue {
    fn new(field: RuleField, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }
}

impl fmt::Display for RuleIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// All issues of one rule inside a ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleProblem {
    pub rule_id: Uuid,
    pub label: String,
    /// `true` when the rule would be sent to the kernel on apply (enabled, and
    /// not an OUTPUT rule in Desktop mode). Only such rules block applying.
    pub applies: bool,
    pub issues: Vec<RuleIssue>,
}

/// A problem with the ruleset as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulesetIssue {
    /// More rules than [`MAX_RULES`]
    TooManyRules { count: usize, limit: usize },
    /// Two or more rules share this id (undo/redo, editing and deletion would
    /// act on the wrong rule)
    DuplicateId(Uuid),
    /// An advanced security setting is out of range
    AdvancedSetting(String),
}

impl fmt::Display for RulesetIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyRules { count, limit } => {
                write!(f, "Profile has {count} rules (maximum {limit})")
            }
            Self::DuplicateId(id) => write!(f, "Several rules share the id {id}"),
            Self::AdvancedSetting(msg) => f.write_str(msg),
        }
    }
}

/// Result of validating a whole ruleset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationReport {
    /// Rules with at least one issue, in profile order
    pub rules: Vec<RuleProblem>,
    /// Ruleset-level issues
    pub ruleset: Vec<RulesetIssue>,
}

impl ValidationReport {
    /// `true` when there is nothing to report.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.ruleset.is_empty()
    }

    /// `true` when applying (or saving to the system) must be refused: a
    /// ruleset-level issue, or an issue in a rule that would be applied.
    pub fn blocks_apply(&self) -> bool {
        !self.ruleset.is_empty() || self.rules.iter().any(|r| r.applies)
    }

    /// Keeps only what blocks applying (ruleset issues and applied rules).
    fn into_blocking(mut self) -> Self {
        self.rules.retain(|r| r.applies);
        self
    }

    /// One-line, user-facing summary suitable for a banner, or `None` if the
    /// report does not block applying.
    ///
    /// # Example
    ///
    /// ```
    /// use drfw::core::firewall::{Chain, FirewallRuleset, PortEntry, Protocol, Rule};
    ///
    /// let mut ruleset = FirewallRuleset::new();
    /// ruleset.rules.push(Rule::with_caches(
    ///     uuid::Uuid::new_v4(),
    ///     "Bad".into(),
    ///     Protocol::Tcp,
    ///     vec![PortEntry::single(0)],
    ///     vec![],
    ///     None,
    ///     Chain::Input,
    ///     true,
    ///     jiff::Timestamp::now(),
    ///     vec![],
    /// ));
    /// let report = ruleset.validate().unwrap_err();
    /// assert!(report.blocking_summary().unwrap().contains("Bad"));
    /// ```
    pub fn blocking_summary(&self) -> Option<String> {
        if let Some(issue) = self.ruleset.first() {
            return Some(format!("Cannot apply: {issue}."));
        }
        let blocking: Vec<&RuleProblem> = self.rules.iter().filter(|r| r.applies).collect();
        let first = blocking.first()?;
        let reason = first.issues.first().map_or("", |i| i.message.as_str());
        let name = display_label(&first.label);
        Some(if blocking.len() == 1 {
            format!("Cannot apply: rule '{name}' is invalid ({reason}). Fix or disable it first.")
        } else {
            format!(
                "Cannot apply: {} enabled rules are invalid (first: '{name}': {reason}). \
                 Fix or disable them first.",
                blocking.len()
            )
        })
    }
}

fn display_label(label: &str) -> &str {
    if label.is_empty() {
        "Unnamed Rule"
    } else {
        label
    }
}

impl fmt::Display for ValidationReport {
    /// Multi-line description (one line per issue), for the CLI and logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut line = |f: &mut fmt::Formatter<'_>, args: fmt::Arguments<'_>| {
            if !first {
                writeln!(f)?;
            }
            first = false;
            f.write_fmt(args)
        };
        for issue in &self.ruleset {
            line(f, format_args!("{issue}"))?;
        }
        for problem in &self.rules {
            for issue in &problem.issues {
                line(
                    f,
                    format_args!("Rule '{}': {issue}", display_label(&problem.label)),
                )?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for ValidationReport {}

impl Rule {
    /// Checks this rule on its own (no ruleset context).
    ///
    /// Detects every combination that nft would reject, or that would make the
    /// generated rule differ from what the rule shows: port 0, reversed ranges,
    /// ports on ICMP rules, a zero rate/burst, `TcpReset` on non-TCP rules,
    /// interfaces on the wrong chain or with invalid names, sources and
    /// destinations without a common IP family, and so on.
    ///
    /// # Errors
    ///
    /// Returns every issue found (never an empty `Vec`).
    pub fn validate(&self) -> Result<(), Vec<RuleIssue>> {
        let mut issues = Vec::new();
        self.check_text(&mut issues);
        self.check_ports(&mut issues);
        self.check_addresses(&mut issues);
        self.check_interfaces(&mut issues);
        self.check_action(&mut issues);
        self.check_limits(&mut issues);
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    fn check_text(&self, issues: &mut Vec<RuleIssue>) {
        if self.label != crate::validators::sanitize_label(&self.label) {
            issues.push(RuleIssue::new(
                RuleField::Label,
                "Description contains characters that are not allowed",
            ));
        }
        if self
            .tags
            .iter()
            .any(|t| t.is_empty() || *t != crate::validators::sanitize_label(t))
        {
            issues.push(RuleIssue::new(
                RuleField::Tags,
                "A tag is empty or contains characters that are not allowed",
            ));
        }
    }

    fn check_ports(&self, issues: &mut Vec<RuleIssue>) {
        if self.ports.is_empty() {
            return;
        }
        // Ports on ICMP would be silently ignored by the generator, widening the
        // rule to all ICMP traffic. ("Any" with ports means TCP+UDP; see the
        // generator.)
        if protocol_is_icmp(self.protocol) {
            issues.push(RuleIssue::new(
                RuleField::Ports,
                format!(
                    "{} rules cannot match ports; remove the ports",
                    self.protocol.display_name()
                ),
            ));
            return;
        }
        for port in &self.ports {
            let problem = match *port {
                PortEntry::Single(0) => Some("Port 0 is not a valid port".to_string()),
                PortEntry::Range { start, end } if start == 0 || end == 0 => {
                    Some(format!("Port range {start}-{end} includes port 0"))
                }
                PortEntry::Range { start, end } if start > end => {
                    Some(format!("Port range {start}-{end} is reversed"))
                }
                _ => None,
            };
            if let Some(message) = problem {
                issues.push(RuleIssue::new(RuleField::Ports, message));
                return;
            }
        }
    }

    fn check_addresses(&self, issues: &mut Vec<RuleIssue>) {
        let icmp_family_message = |protocol: crate::core::firewall::Protocol| {
            if protocol == crate::core::firewall::Protocol::Icmp {
                "ICMP (v4) cannot be used with IPv6 addresses"
            } else {
                "ICMPv6 cannot be used with IPv4 addresses"
            }
        };
        if self
            .sources
            .iter()
            .any(|ip| !ip_compatible_with_protocol(ip, self.protocol))
        {
            issues.push(RuleIssue::new(
                RuleField::Sources,
                icmp_family_message(self.protocol),
            ));
        }
        if self
            .destinations
            .iter()
            .any(|ip| !ip_compatible_with_protocol(ip, self.protocol))
        {
            issues.push(RuleIssue::new(
                RuleField::Destinations,
                icmp_family_message(self.protocol),
            ));
        }

        // The generator emits one nft rule per IP family that both lists can
        // satisfy; with no common family it emits nothing at all.
        if !self.sources.is_empty() && !self.destinations.is_empty() {
            let has =
                |list: &[ipnetwork::IpNetwork], v6: bool| list.iter().any(|n| n.is_ipv6() == v6);
            let common_v4 = has(&self.sources, false) && has(&self.destinations, false);
            let common_v6 = has(&self.sources, true) && has(&self.destinations, true);
            if !common_v4 && !common_v6 {
                issues.push(RuleIssue::new(
                    RuleField::Destinations,
                    "Sources and destinations have no IP version in common (IPv4 vs IPv6), \
                     so the rule could never match",
                ));
            }
        }
    }

    fn check_interfaces(&self, issues: &mut Vec<RuleIssue>) {
        for (value, field, label) in [
            (&self.interface, RuleField::Interface, "Interface"),
            (
                &self.output_interface,
                RuleField::OutputInterface,
                "Output interface",
            ),
        ] {
            let Some(name) = value else { continue };
            if name.is_empty() {
                issues.push(RuleIssue::new(field, format!("{label} name is empty")));
            } else if let Err(msg) = crate::validators::validate_interface(name) {
                issues.push(RuleIssue::new(field, msg));
            }
        }

        // nftables only sets iifname on input and oifname on output; the other
        // one would make the rule never match. Forwarded packets have both.
        if self.interface.is_some() && self.chain == Chain::Output {
            issues.push(RuleIssue::new(
                RuleField::Interface,
                "Input interface not available for OUTPUT rules",
            ));
        }
        if self.output_interface.is_some() && self.chain == Chain::Input {
            issues.push(RuleIssue::new(
                RuleField::OutputInterface,
                "Output interface not available for INPUT rules",
            ));
        }
    }

    fn check_action(&self, issues: &mut Vec<RuleIssue>) {
        if self.action == Action::Reject
            && !reject_type_valid_for_protocol(self.reject_type, self.protocol)
        {
            issues.push(RuleIssue::new(
                RuleField::RejectType,
                "TCP Reset is only available for TCP protocol",
            ));
        }
    }

    fn check_limits(&self, issues: &mut Vec<RuleIssue>) {
        if let Some(rate) = self.rate_limit {
            if rate.count == 0 {
                issues.push(RuleIssue::new(
                    RuleField::RateLimit,
                    "Rate limit must be at least 1",
                ));
            } else if let Err(msg) = crate::validators::validate_rate_limit(rate.count, rate.unit) {
                issues.push(RuleIssue::new(RuleField::RateLimit, msg));
            }
            if rate.burst == Some(0) {
                issues.push(RuleIssue::new(
                    RuleField::RateLimit,
                    "Burst must be at least 1 (leave it empty for no burst)",
                ));
            }
        }
        if let Err(msg) = crate::validators::validate_connection_limit(self.connection_limit) {
            issues.push(RuleIssue::new(RuleField::ConnectionLimit, msg));
        }
        // (A per-source rate limit cannot exist without a rate: the flag is
        // part of the rate limit itself.)
        if self.connection_limit_per_source && self.connection_limit == 0 {
            issues.push(RuleIssue::new(
                RuleField::ConnectionLimit,
                "Set a connection limit to count connections per source address",
            ));
        }
        // Per-source state lives in a bounded set; once it is full, new
        // sources are not tracked. For Accept that fails closed, for
        // Drop/Reject ("drop sources over the limit") it would fail open.
        if self.action != Action::Accept {
            if self.rate_limit.is_some_and(|rate| rate.per_source) {
                issues.push(RuleIssue::new(RuleField::RateLimit, PER_SOURCE_ACCEPT_ONLY));
            }
            if self.connection_limit_per_source {
                issues.push(RuleIssue::new(
                    RuleField::ConnectionLimit,
                    PER_SOURCE_ACCEPT_ONLY,
                ));
            }
        }
    }
}

impl AdvancedSecuritySettings {
    /// Checks the advanced settings that end up in the generated ruleset.
    ///
    /// # Errors
    ///
    /// Returns a user-facing message per problem.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut issues = Vec::new();
        if self.log_dropped {
            if let Err(msg) = crate::validators::validate_log_rate(self.log_rate_per_minute) {
                issues.push(format!("Dropped-packet logging: {msg}"));
            }
            match crate::validators::validate_log_prefix(&self.log_prefix) {
                Ok(clean) if clean == self.log_prefix => {}
                Ok(_) => issues.push(
                    "Dropped-packet log prefix contains characters that are not allowed \
                     (quotes, newlines, ...)"
                        .to_string(),
                ),
                Err(msg) => issues.push(format!("Dropped-packet logging: {msg}")),
            }
        }
        if self.icmp_rate_limit > crate::validators::MAX_RATE_LIMIT_PER_SECOND {
            issues.push(format!(
                "ICMP rate limit exceeds max {}/second",
                crate::validators::MAX_RATE_LIMIT_PER_SECOND
            ));
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }
}

impl FirewallRuleset {
    /// Validates every rule and the ruleset as a whole.
    ///
    /// Reports issues in *all* rules, including disabled ones, so the GUI can
    /// flag them. Use [`ValidationReport::blocks_apply`] (or
    /// [`Self::validate_for_apply`]) to decide whether applying is allowed.
    ///
    /// # Errors
    ///
    /// Returns the full report when anything is wrong.
    pub fn validate(&self) -> Result<(), ValidationReport> {
        let mut report = ValidationReport::default();

        if self.rules.len() > MAX_RULES {
            report.ruleset.push(RulesetIssue::TooManyRules {
                count: self.rules.len(),
                limit: MAX_RULES,
            });
        }

        let mut seen = std::collections::HashSet::with_capacity(self.rules.len());
        let mut reported = std::collections::HashSet::new();
        for rule in &self.rules {
            if !seen.insert(rule.id) && reported.insert(rule.id) {
                report.ruleset.push(RulesetIssue::DuplicateId(rule.id));
            }
            if let Err(issues) = rule.validate() {
                report.rules.push(RuleProblem {
                    rule_id: rule.id,
                    label: rule.label.clone(),
                    applies: rule.takes_effect(&self.advanced_security),
                    issues,
                });
            }
        }

        if let Err(messages) = self.advanced_security.validate() {
            report
                .ruleset
                .extend(messages.into_iter().map(RulesetIssue::AdvancedSetting));
        }

        if report.is_empty() {
            Ok(())
        } else {
            Err(report)
        }
    }

    /// Gate for every path that sends this ruleset to the kernel or the system
    /// configuration (GUI Apply, GUI Save to System, CLI `apply`).
    ///
    /// Invalid rules may live in a profile (nothing is lost on load), but no
    /// ruleset may be applied while an **applied** rule (enabled, and not an
    /// OUTPUT rule in Desktop mode) is invalid, or while a ruleset-level issue
    /// exists. Call this before `to_nftables_json()` in those paths.
    ///
    /// # Errors
    ///
    /// Returns a report holding only the blocking issues. Its `Display` is a
    /// multi-line list (CLI); [`ValidationReport::blocking_summary`] is a
    /// one-line banner text (GUI).
    ///
    /// # Example
    ///
    /// ```
    /// use drfw::core::firewall::FirewallRuleset;
    ///
    /// let ruleset = FirewallRuleset::new();
    /// assert!(ruleset.validate_for_apply().is_ok());
    /// ```
    pub fn validate_for_apply(&self) -> Result<(), ValidationReport> {
        match self.validate() {
            Ok(()) => Ok(()),
            Err(report) if report.blocks_apply() => Err(report.into_blocking()),
            Err(_) => Ok(()),
        }
    }

    /// Repairs what can be repaired without changing meaning, after loading
    /// a profile from disk:
    ///
    /// - later rules whose id duplicates an earlier one get a fresh id,
    /// - labels and tags are sanitized like the rule form does (allowlist,
    ///   length limit, empty and duplicate tags removed),
    /// - display caches are rebuilt.
    ///
    /// Returns how many ids were regenerated (callers log it).
    pub fn normalize_loaded(&mut self) -> usize {
        let mut seen = std::collections::HashSet::with_capacity(self.rules.len());
        let mut regenerated = 0;
        for rule in &mut self.rules {
            while !seen.insert(rule.id) {
                let old = rule.id;
                rule.id = Uuid::new_v4();
                regenerated += 1;
                tracing::warn!(
                    "Rule '{}' had duplicate id {old}; assigned new id {}",
                    rule.label,
                    rule.id
                );
            }
            // rebuild_caches() sanitizes label and tags; drop duplicate tags too
            rule.rebuild_caches();
            let before = rule.tags.len();
            let mut unique = std::collections::HashSet::with_capacity(before);
            rule.tags.retain(|t| unique.insert(t.clone()));
            if rule.tags.len() != before {
                rule.rebuild_caches();
            }
        }
        regenerated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::firewall::{EgressProfile, Protocol, RateLimit, RejectType, TimeUnit};
    use crate::core::test_helpers::create_test_rule;

    fn base_rule() -> Rule {
        create_test_rule("Test", Some(22))
    }

    fn fields(rule: &Rule) -> Vec<RuleField> {
        rule.validate()
            .err()
            .unwrap_or_default()
            .into_iter()
            .map(|i| i.field)
            .collect()
    }

    #[test]
    fn test_valid_rule_passes() {
        assert!(base_rule().validate().is_ok());
    }

    #[test]
    fn test_port_zero() {
        let mut rule = base_rule();
        rule.ports = vec![PortEntry::single(0)];
        assert_eq!(fields(&rule), vec![RuleField::Ports]);
        rule.ports = vec![PortEntry::range(0, 10)];
        assert_eq!(fields(&rule), vec![RuleField::Ports]);
    }

    #[test]
    fn test_reversed_range() {
        let mut rule = base_rule();
        rule.ports = vec![PortEntry::range(9000, 8000)];
        let issues = rule.validate().unwrap_err();
        assert!(issues[0].message.contains("reversed"));
    }

    #[test]
    fn test_ports_on_icmp() {
        let mut rule = base_rule();
        rule.protocol = Protocol::IcmpBoth;
        assert_eq!(fields(&rule), vec![RuleField::Ports]);
        // "Any" with ports is TCP+UDP in the generator: allowed
        rule.protocol = Protocol::Any;
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_rate_limit_zero_and_burst_zero() {
        let mut rule = base_rule();
        rule.rate_limit = Some(RateLimit {
            count: 0,
            unit: TimeUnit::Second,
            burst: None,
            per_source: false,
        });
        assert_eq!(fields(&rule), vec![RuleField::RateLimit]);
        rule.rate_limit = Some(RateLimit {
            count: 5,
            unit: TimeUnit::Second,
            burst: Some(0),
            per_source: false,
        });
        assert_eq!(fields(&rule), vec![RuleField::RateLimit]);
        rule.rate_limit = Some(RateLimit {
            count: 5,
            unit: TimeUnit::Second,
            burst: Some(10),
            per_source: false,
        });
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_rate_limit_over_max() {
        let mut rule = base_rule();
        rule.rate_limit = Some(RateLimit {
            count: crate::validators::MAX_RATE_LIMIT_PER_SECOND + 1,
            unit: TimeUnit::Second,
            burst: None,
            per_source: false,
        });
        assert_eq!(fields(&rule), vec![RuleField::RateLimit]);
    }

    #[test]
    fn test_connection_limit_over_max() {
        let mut rule = base_rule();
        rule.connection_limit = crate::validators::MAX_CONNECTION_LIMIT + 1;
        assert_eq!(fields(&rule), vec![RuleField::ConnectionLimit]);
    }

    #[test]
    fn test_per_source_needs_a_limit() {
        let mut rule = base_rule();
        rule.connection_limit_per_source = true;
        assert_eq!(fields(&rule), vec![RuleField::ConnectionLimit]);
        rule.connection_limit = 3;
        assert!(rule.validate().is_ok());
        rule.rate_limit = Some(RateLimit {
            count: 3,
            unit: TimeUnit::Minute,
            burst: None,
            per_source: true,
        });
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_per_source_only_with_accept() {
        let mut rule = base_rule();
        rule.rate_limit = Some(RateLimit {
            count: 3,
            unit: TimeUnit::Minute,
            burst: None,
            per_source: true,
        });
        rule.connection_limit = 3;
        rule.connection_limit_per_source = true;
        assert!(rule.validate().is_ok());
        for action in [Action::Drop, Action::Reject] {
            rule.action = action;
            let issues = rule.validate().unwrap_err();
            assert_eq!(
                issues.iter().map(|i| i.field).collect::<Vec<_>>(),
                vec![RuleField::RateLimit, RuleField::ConnectionLimit],
                "{action:?}"
            );
            assert!(issues.iter().all(|i| i.message == PER_SOURCE_ACCEPT_ONLY));
        }
        // Plain (global) limits stay allowed on Drop/Reject
        rule.rate_limit = rule.rate_limit.map(|r| RateLimit {
            per_source: false,
            ..r
        });
        rule.connection_limit_per_source = false;
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_tcp_reset_requires_tcp() {
        let mut rule = base_rule();
        rule.action = Action::Reject;
        rule.reject_type = RejectType::TcpReset;
        assert!(rule.validate().is_ok());
        rule.protocol = Protocol::TcpAndUdp;
        assert_eq!(fields(&rule), vec![RuleField::RejectType]);
        // Reject type is irrelevant unless the action is Reject
        rule.action = Action::Drop;
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_interface_chain_mismatch() {
        let mut rule = base_rule();
        rule.output_interface = Some("eth0".into());
        assert_eq!(fields(&rule), vec![RuleField::OutputInterface]);
        rule.output_interface = None;
        rule.chain = Chain::Output;
        rule.interface = Some("eth0".into());
        assert_eq!(fields(&rule), vec![RuleField::Interface]);
        // Forwarded packets have both an input and an output interface
        rule.chain = Chain::Forward;
        rule.output_interface = Some("veth*".into());
        assert!(rule.validate().is_ok());
    }

    /// Forward rules only take part in the applied ruleset (and only block
    /// applying when invalid) with "Block forwarding" on.
    #[test]
    fn test_forward_rules_apply_only_with_block_forwarding() {
        let mut rule = base_rule();
        rule.chain = Chain::Forward;
        rule.ports = vec![PortEntry::Single(0)];
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(rule);
        assert!(ruleset.validate().is_err(), "reported");
        assert!(ruleset.validate_for_apply().is_ok(), "not applied");
        ruleset.advanced_security.block_forwarding = true;
        assert!(ruleset.validate_for_apply().is_err());
    }

    #[test]
    fn test_interface_names() {
        let mut rule = base_rule();
        rule.interface = Some("eth0\"; drop".into());
        assert_eq!(fields(&rule), vec![RuleField::Interface]);
        rule.interface = Some("a".repeat(16));
        assert_eq!(fields(&rule), vec![RuleField::Interface]);
        rule.interface = Some(String::new());
        assert_eq!(fields(&rule), vec![RuleField::Interface]);
        rule.interface = Some("eth*".into());
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_icmp_address_family() {
        let mut rule = base_rule();
        rule.ports.clear();
        rule.protocol = Protocol::Icmp;
        rule.sources = vec!["2001:db8::/32".parse().unwrap()];
        assert_eq!(fields(&rule), vec![RuleField::Sources]);
        rule.sources.clear();
        rule.protocol = Protocol::Icmpv6;
        rule.destinations = vec!["10.0.0.1/32".parse().unwrap()];
        assert_eq!(fields(&rule), vec![RuleField::Destinations]);
    }

    #[test]
    fn test_no_common_family() {
        let mut rule = base_rule();
        rule.sources = vec!["10.0.0.0/8".parse().unwrap()];
        rule.destinations = vec!["2001:db8::/32".parse().unwrap()];
        assert_eq!(fields(&rule), vec![RuleField::Destinations]);
        // One family in common is enough
        rule.sources.push("fd00::/8".parse().unwrap());
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_label_and_tags_must_be_sanitized() {
        let mut rule = base_rule();
        rule.label = "a\nb".into();
        rule.tags = vec!["ok".into(), "bad\"".into()];
        assert_eq!(fields(&rule), vec![RuleField::Label, RuleField::Tags]);
    }

    #[test]
    fn test_ruleset_duplicate_ids_and_disabled_rules() {
        let mut ruleset = FirewallRuleset::new();
        let rule = base_rule();
        ruleset.rules.push(rule.clone());
        ruleset.rules.push(rule.clone());
        ruleset.rules.push(rule);
        let report = ruleset.validate().unwrap_err();
        assert_eq!(report.ruleset.len(), 1, "one entry per duplicated id");
        assert!(matches!(report.ruleset[0], RulesetIssue::DuplicateId(_)));
        assert!(report.blocks_apply());

        // A disabled invalid rule is reported but does not block apply
        let mut ruleset = FirewallRuleset::new();
        let mut bad = base_rule();
        bad.ports = vec![PortEntry::single(0)];
        bad.enabled = false;
        ruleset.rules.push(bad);
        let report = ruleset.validate().unwrap_err();
        assert_eq!(report.rules.len(), 1);
        assert!(!report.rules[0].applies);
        assert!(!report.blocks_apply());
        assert!(report.blocking_summary().is_none());
        assert!(ruleset.validate_for_apply().is_ok());

        ruleset.rules[0].enabled = true;
        let blocking = ruleset.validate_for_apply().unwrap_err();
        assert!(blocking.blocking_summary().unwrap().contains("Test"));
        assert!(blocking.to_string().contains("Port 0"));
    }

    #[test]
    fn test_output_rule_ignored_in_desktop_mode() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = base_rule();
        rule.chain = Chain::Output;
        rule.interface = Some("eth0".into());
        ruleset.rules.push(rule);
        assert!(ruleset.validate().is_err());
        assert!(ruleset.validate_for_apply().is_ok());
        ruleset.advanced_security.egress_profile = EgressProfile::Server;
        assert!(ruleset.validate_for_apply().is_err());
    }

    #[test]
    fn test_too_many_rules() {
        let mut ruleset = FirewallRuleset::new();
        for _ in 0..=MAX_RULES {
            ruleset.rules.push(base_rule());
        }
        let report = ruleset.validate().unwrap_err();
        assert!(
            report
                .ruleset
                .iter()
                .any(|i| matches!(i, RulesetIssue::TooManyRules { .. }))
        );
    }

    #[test]
    fn test_advanced_settings() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.advanced_security.log_rate_per_minute = 0;
        // Unused while logging is off
        assert!(ruleset.validate().is_ok());
        ruleset.advanced_security.log_dropped = true;
        assert!(ruleset.validate_for_apply().is_err());
        ruleset.advanced_security.log_rate_per_minute = 5;
        assert!(ruleset.validate().is_ok());
        ruleset.advanced_security.log_prefix = "DROP\" accept\n".into();
        assert!(ruleset.validate_for_apply().is_err());
        ruleset.advanced_security.log_prefix = "DRFW-DROP: ".into();
        ruleset.advanced_security.icmp_rate_limit = u32::MAX;
        assert!(ruleset.validate_for_apply().is_err());
    }

    #[test]
    fn test_normalize_loaded_regenerates_later_duplicates() {
        let mut ruleset = FirewallRuleset::new();
        let rule = base_rule();
        let first_id = rule.id;
        ruleset.rules.push(rule.clone());
        ruleset.rules.push(rule);
        ruleset.rules[1].tags = vec!["web".into(), "web".into(), "bad\n".into()];
        assert_eq!(ruleset.normalize_loaded(), 1);
        assert_eq!(ruleset.rules[0].id, first_id);
        assert_ne!(ruleset.rules[1].id, first_id);
        assert_eq!(
            ruleset.rules[1].tags,
            vec!["web".to_string(), "bad".to_string()]
        );
        assert!(ruleset.validate().is_ok());
    }

    /// Profiles saved before labels were trimmed are fixed on load: the
    /// stray spaces go, and tags that only differed by them merge.
    #[test]
    fn test_normalize_loaded_trims_labels_and_tags() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = base_rule();
        rule.label = "Tailscale Interface ".into();
        rule.tags = vec!["vpn".into(), " vpn ".into(), "home  lan".into()];
        ruleset.rules.push(rule);
        assert_eq!(ruleset.normalize_loaded(), 0);
        let rule = &ruleset.rules[0];
        assert_eq!(rule.label, "Tailscale Interface");
        assert_eq!(rule.label_lowercase, "tailscale interface");
        assert_eq!(rule.tags, vec!["vpn".to_string(), "home lan".to_string()]);
        assert!(ruleset.validate().is_ok());
    }
}

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;

    use super::*;
    use crate::core::firewall::{Protocol, RateLimit, RejectType, TimeUnit};
    use crate::core::rule_constraints::{
        available_reject_types_for_protocol, protocol_supports_ports,
    };

    const PROTOCOLS: [Protocol; 7] = [
        Protocol::Any,
        Protocol::Tcp,
        Protocol::Udp,
        Protocol::TcpAndUdp,
        Protocol::Icmp,
        Protocol::Icmpv6,
        Protocol::IcmpBoth,
    ];

    prop_compose! {
        fn valid_port()(start in 1u16..=65535, len in 0u16..100) -> PortEntry {
            let end = start.saturating_add(len);
            if end == start { PortEntry::single(start) } else { PortEntry::range(start, end) }
        }
    }

    prop_compose! {
        /// Rules built only from values the validators accept, combined the
        /// way the constraints allow.
        fn valid_rule()(
            protocol_idx in 0usize..PROTOCOLS.len(),
            ports in prop::collection::vec(valid_port(), 0..5),
            label in "[A-Za-z0-9 _.:-]{0,64}",
            tags in prop::collection::vec("[a-z0-9]{1,16}", 0..4),
            v4_sources in prop::collection::vec((any::<[u8; 4]>(), 0u8..=32), 0..3),
            iface in prop::option::of("[a-z][a-z0-9]{0,10}\\*?"),
            output in any::<bool>(),
            action_idx in 0usize..3,
            reject_idx in 0usize..8,
            rate in prop::option::of((1u32..=1000, prop::option::of(1u32..=100))),
            conn in 0u32..=crate::validators::MAX_CONNECTION_LIMIT,
            per_source in any::<(bool, bool)>(),
            enabled in any::<bool>(),
        ) -> Rule {
            let protocol = PROTOCOLS[protocol_idx];
            let ports = if protocol_supports_ports(protocol) { ports } else { Vec::new() };
            // ICMPv6 is IPv6-only: give it no IPv4 sources
            let sources = if protocol == Protocol::Icmpv6 {
                Vec::new()
            } else {
                v4_sources
                    .into_iter()
                    .map(|(octets, prefix)| {
                        ipnetwork::IpNetwork::new(std::net::IpAddr::from(octets), prefix)
                            .expect("prefix <= 32")
                    })
                    .collect()
            };
            let chain = if output { Chain::Output } else { Chain::Input };
            let reject_types = available_reject_types_for_protocol(protocol);
            let mut rule = Rule::with_caches(
                Uuid::new_v4(), label, protocol, ports, sources, None, chain, enabled,
                jiff::Timestamp::now(), tags,
            );
            if output {
                rule.output_interface = iface;
            } else {
                rule.interface = iface;
            }
            rule.action = [Action::Accept, Action::Drop, Action::Reject][action_idx];
            rule.reject_type = reject_types[reject_idx % reject_types.len()];
            // Per-source limits only on Accept rules
            let accept = rule.action == Action::Accept;
            rule.rate_limit = rate.map(|(count, burst)| RateLimit { count, unit: TimeUnit::Minute, burst, per_source: per_source.0 && accept });
            rule.connection_limit = conn;
            rule.connection_limit_per_source = per_source.1 && conn > 0 && accept;
            rule.rebuild_caches();
            rule
        }
    }

    proptest! {
        #[test]
        fn test_generated_valid_rules_validate(rule in valid_rule()) {
            prop_assert_eq!(rule.validate(), Ok(()));
        }

        #[test]
        fn test_ruleset_of_valid_rules_is_applicable(rules in prop::collection::vec(valid_rule(), 0..20)) {
            let mut ruleset = FirewallRuleset::new();
            ruleset.rules = rules;
            prop_assert!(ruleset.validate().is_ok());
            prop_assert!(ruleset.validate_for_apply().is_ok());
        }

        #[test]
        fn test_any_zero_port_is_rejected(rule in valid_rule(), position in 0usize..4) {
            let mut rule = rule;
            prop_assume!(protocol_supports_ports(rule.protocol));
            let at = position.min(rule.ports.len());
            rule.ports.insert(at, PortEntry::single(0));
            prop_assert!(rule.validate().is_err());
        }

        #[test]
        fn test_tcp_reset_rejected_off_tcp(rule in valid_rule()) {
            let mut rule = rule;
            rule.action = Action::Reject;
            rule.reject_type = RejectType::TcpReset;
            // Per-source limits are Accept-only; keep this about the reject type
            if let Some(rate) = rule.rate_limit.as_mut() {
                rate.per_source = false;
            }
            rule.connection_limit_per_source = false;
            prop_assert_eq!(rule.validate().is_ok(), rule.protocol == Protocol::Tcp);
        }
    }
}
