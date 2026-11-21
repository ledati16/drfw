//! Rule form validation
//!
//! Handles validation of firewall rule form inputs with detailed error reporting.
//! Supports multi-value fields (ports, IPs) with helper modal editing pattern.
//!
//! The form only checks what is specific to text input (numbers that don't
//! parse, an enabled rate limit without a rate). Everything else is decided by
//! the core validator: [`RuleForm::validate`] builds the candidate [`Rule`] and
//! calls [`Rule::validate`], so the form and the profile loader can never
//! disagree about what is valid.

use ipnetwork::IpNetwork;

use crate::core::firewall::{PortEntry, Protocol, RateLimit, RejectType, Rule};
use crate::core::validate::RuleField;

/// Form validation errors for individual fields
#[derive(Debug, Clone, Default)]
pub struct FormErrors {
    pub port: Option<String>,
    pub source: Option<String>,
    pub interface: Option<String>,
    pub output_interface: Option<String>,
    pub destination: Option<String>,
    pub rate_limit: Option<String>,
    pub connection_limit: Option<String>,
    pub reject_type: Option<String>,
    /// Problems without a dedicated field in the form (label, tags, rule limit)
    pub general: Option<String>,
}

impl FormErrors {
    /// Stores `message` on the form field for `field` (first message wins).
    fn set(&mut self, field: RuleField, message: String) {
        let slot = match field {
            RuleField::Ports => &mut self.port,
            RuleField::Sources => &mut self.source,
            RuleField::Destinations => &mut self.destination,
            RuleField::Interface => &mut self.interface,
            RuleField::OutputInterface => &mut self.output_interface,
            RuleField::RejectType => &mut self.reject_type,
            RuleField::RateLimit => &mut self.rate_limit,
            RuleField::ConnectionLimit => &mut self.connection_limit,
            RuleField::Label | RuleField::Tags => &mut self.general,
        };
        if slot.is_none() {
            *slot = Some(message);
        }
    }

    fn is_empty(&self) -> bool {
        self.port.is_none()
            && self.source.is_none()
            && self.interface.is_none()
            && self.output_interface.is_none()
            && self.destination.is_none()
            && self.rate_limit.is_none()
            && self.connection_limit.is_none()
            && self.reject_type.is_none()
            && self.general.is_none()
    }
}

/// Helper modal types for multi-value field editing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperType {
    Ports,
    SourceAddresses,
    DestinationAddresses,
    Tags,
}

/// Helper modal state for editing multi-value fields
///
/// The helper operates directly on `RuleForm`'s Vec fields.
/// This struct only holds UI state (input field, error message).
#[derive(Debug, Clone, Default)]
pub struct RuleFormHelper {
    pub helper_type: Option<HelperType>,
    pub input: String,
    pub error: Option<String>,
}

/// Rule form state with validation
///
/// Supports multi-value fields via helper modals:
/// - `ports`: Multiple port entries (single or range)
/// - `sources`: Multiple source IP/CIDR addresses
/// - `destinations`: Multiple destination IP/CIDR addresses
/// - `tags`: Multiple organizational tags
#[derive(Debug, Clone)]
pub struct RuleForm {
    pub id: Option<uuid::Uuid>,
    pub label: String,
    pub protocol: Protocol,

    // Multi-value fields (edited via helper modals)
    pub ports: Vec<PortEntry>,
    pub sources: Vec<IpNetwork>,
    pub destinations: Vec<IpNetwork>,
    pub tags: Vec<String>,

    // Single-value fields
    pub interface: String,
    pub output_interface: String,
    pub chain: crate::core::firewall::Chain,
    pub action: crate::core::firewall::Action,
    pub reject_type: RejectType,

    // Rate limiting
    pub rate_limit_enabled: bool,
    pub rate_limit_count: String,
    pub rate_limit_unit: crate::core::firewall::TimeUnit,
    pub rate_limit_burst: String,

    // Connection limiting
    pub connection_limit: String,

    // Per-rule logging
    pub log_enabled: bool,

    // UI state
    pub show_advanced: bool,
}

impl Default for RuleForm {
    fn default() -> Self {
        Self {
            id: None,
            label: String::new(),
            protocol: Protocol::Tcp,
            ports: Vec::new(),
            sources: Vec::new(),
            destinations: Vec::new(),
            tags: Vec::new(),
            interface: String::new(),
            output_interface: String::new(),
            chain: crate::core::firewall::Chain::Input,
            action: crate::core::firewall::Action::Accept,
            reject_type: RejectType::Default,
            rate_limit_enabled: false,
            rate_limit_count: String::new(),
            rate_limit_unit: crate::core::firewall::TimeUnit::Second,
            rate_limit_burst: String::new(),
            connection_limit: String::new(),
            log_enabled: false,
            show_advanced: false,
        }
    }
}

impl RuleForm {
    /// Builds a form pre-filled from an existing rule (for editing).
    pub fn from_rule(rule: &Rule) -> Self {
        use crate::core::firewall::Action;
        let has_advanced = !rule.destinations.is_empty()
            || rule.action != Action::Accept
            || rule.rate_limit.is_some()
            || rule.connection_limit > 0
            || rule.output_interface.is_some()
            || rule.reject_type != RejectType::Default
            || rule.log_enabled;

        Self {
            id: Some(rule.id),
            label: rule.label.clone(),
            protocol: rule.protocol,
            ports: rule.ports.clone(),
            sources: rule.sources.clone(),
            destinations: rule.destinations.clone(),
            tags: rule.tags.clone(),
            interface: rule.interface.clone().unwrap_or_default(),
            output_interface: rule.output_interface.clone().unwrap_or_default(),
            chain: rule.chain,
            action: rule.action,
            reject_type: rule.reject_type,
            rate_limit_enabled: rule.rate_limit.is_some(),
            rate_limit_count: rule
                .rate_limit
                .map_or_else(String::new, |rl| rl.count.to_string()),
            rate_limit_unit: rule
                .rate_limit
                .map_or(crate::core::firewall::TimeUnit::Second, |rl| rl.unit),
            rate_limit_burst: rule
                .rate_limit
                .and_then(|rl| rl.burst)
                .map_or_else(String::new, |b| b.to_string()),
            connection_limit: if rule.connection_limit > 0 {
                rule.connection_limit.to_string()
            } else {
                String::new()
            },
            log_enabled: rule.log_enabled,
            show_advanced: has_advanced,
        }
    }

    /// Parses the free-text numeric fields, recording form-specific errors.
    ///
    /// Returns the rate limit (if enabled and parseable) and the connection
    /// limit (0 when empty or unparseable). Range checks are left to the core
    /// validator.
    fn parse_numbers(&self, errors: &mut FormErrors) -> (Option<RateLimit>, u32) {
        let rate_limit = if self.rate_limit_enabled {
            let count = self.rate_limit_count.trim();
            let burst = self.rate_limit_burst.trim();
            let parsed_burst = if burst.is_empty() {
                Ok(None)
            } else {
                burst.parse::<u32>().map(Some)
            };
            if parsed_burst.is_err() {
                errors.rate_limit = Some("Invalid burst number".to_string());
            }
            if count.is_empty() {
                errors.rate_limit =
                    Some("Enter a rate (at least 1), or turn rate limiting off".into());
                None
            } else if let Ok(count) = count.parse::<u32>() {
                Some(RateLimit {
                    count,
                    unit: self.rate_limit_unit,
                    burst: parsed_burst.unwrap_or(None),
                })
            } else {
                errors.rate_limit = Some("Invalid rate limit number".to_string());
                None
            }
        } else {
            None
        };

        let connection_limit = match self.connection_limit.trim() {
            "" => 0,
            text => text.parse::<u32>().unwrap_or_else(|_| {
                errors.connection_limit = Some("Invalid connection limit number".to_string());
                0
            }),
        };

        (rate_limit, connection_limit)
    }

    /// Builds the rule this form describes.
    ///
    /// `id`, `enabled` and `created_at` come from the caller: a new rule gets
    /// fresh values, an edited rule keeps its own (editing must not re-enable a
    /// disabled rule or reset its creation time). Unparseable numbers are
    /// left out; call [`Self::validate`] first.
    pub fn to_rule(&self, id: uuid::Uuid, enabled: bool, created_at: jiff::Timestamp) -> Rule {
        let (rate_limit, connection_limit) = self.parse_numbers(&mut FormErrors::default());
        self.build_rule(id, enabled, created_at, rate_limit, connection_limit)
    }

    fn build_rule(
        &self,
        id: uuid::Uuid,
        enabled: bool,
        created_at: jiff::Timestamp,
        rate_limit: Option<RateLimit>,
        connection_limit: u32,
    ) -> Rule {
        let non_empty = |s: &str| {
            let trimmed = s.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        };
        let mut rule = Rule::with_caches(
            id,
            crate::validators::sanitize_label(&self.label),
            self.protocol,
            self.ports.clone(),
            self.sources.clone(),
            non_empty(&self.interface),
            self.chain,
            enabled,
            created_at,
            self.tags.clone(),
        );
        rule.output_interface = non_empty(&self.output_interface);
        rule.destinations.clone_from(&self.destinations);
        rule.action = self.action;
        rule.reject_type = self.reject_type;
        rule.rate_limit = rate_limit;
        rule.connection_limit = connection_limit;
        rule.log_enabled = self.log_enabled;
        rule.rebuild_caches();
        rule
    }

    /// Validates all form fields.
    ///
    /// Text-input problems are reported first; then the candidate rule is
    /// checked with [`Rule::validate`] (the same check the loader and the
    /// apply path use) and each issue is shown on its field.
    ///
    /// Returns `None` if validation passed.
    pub fn validate(&self) -> Option<FormErrors> {
        let mut errors = FormErrors::default();
        let (rate_limit, connection_limit) = self.parse_numbers(&mut errors);
        let candidate = self.build_rule(
            uuid::Uuid::nil(),
            true,
            jiff::Timestamp::UNIX_EPOCH,
            rate_limit,
            connection_limit,
        );
        if let Err(issues) = candidate.validate() {
            for issue in issues {
                errors.set(issue.field, issue.message);
            }
        }

        if errors.is_empty() {
            None
        } else {
            Some(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::firewall::{Action, Chain, TimeUnit};

    fn tcp_form() -> RuleForm {
        RuleForm {
            label: "SSH".into(),
            ports: vec![PortEntry::single(22)],
            ..RuleForm::default()
        }
    }

    #[test]
    fn test_valid_form_passes() {
        assert!(tcp_form().validate().is_none());
    }

    #[test]
    fn test_rate_limit_enabled_needs_count() {
        let mut form = tcp_form();
        form.rate_limit_enabled = true;
        let errors = form.validate().expect("empty rate must fail");
        assert!(errors.rate_limit.is_some());

        form.rate_limit_count = "0".into();
        assert!(form.validate().unwrap().rate_limit.is_some());

        form.rate_limit_count = "5".into();
        assert!(form.validate().is_none());

        form.rate_limit_burst = "0".into();
        assert!(form.validate().unwrap().rate_limit.is_some());
        form.rate_limit_burst = "x".into();
        assert!(form.validate().unwrap().rate_limit.is_some());
        form.rate_limit_burst = "10".into();
        assert!(form.validate().is_none());
        let rule = form.to_rule(uuid::Uuid::nil(), true, jiff::Timestamp::now());
        assert_eq!(
            rule.rate_limit,
            Some(RateLimit {
                count: 5,
                unit: TimeUnit::Second,
                burst: Some(10)
            })
        );
    }

    #[test]
    fn test_ip_family_mismatch_reported() {
        let mut form = tcp_form();
        form.sources = vec!["10.0.0.0/8".parse().unwrap()];
        form.destinations = vec!["2001:db8::/32".parse().unwrap()];
        assert!(form.validate().unwrap().destination.is_some());
    }

    #[test]
    fn test_tcp_reset_on_tcp_udp_reported() {
        let mut form = tcp_form();
        form.action = Action::Reject;
        form.reject_type = RejectType::TcpReset;
        assert!(form.validate().is_none());
        form.protocol = Protocol::TcpAndUdp;
        assert!(form.validate().unwrap().reject_type.is_some());
    }

    #[test]
    fn test_ports_on_icmp_reported() {
        let mut form = tcp_form();
        form.protocol = Protocol::IcmpBoth;
        assert!(form.validate().unwrap().port.is_some());
    }

    #[test]
    fn test_output_interface_on_input_chain() {
        let mut form = tcp_form();
        form.output_interface = "eth0".into();
        assert!(form.validate().unwrap().output_interface.is_some());
        form.chain = Chain::Output;
        assert!(form.validate().is_none());
    }

    #[test]
    fn test_from_rule_round_trip() {
        let mut rule = crate::core::test_helpers::create_test_rule("Web", Some(443));
        rule.enabled = false;
        rule.rate_limit = Some(RateLimit {
            count: 3,
            unit: TimeUnit::Minute,
            burst: Some(6),
        });
        rule.connection_limit = 10;
        rule.rebuild_caches();
        let form = RuleForm::from_rule(&rule);
        assert!(form.show_advanced);
        let rebuilt = form.to_rule(rule.id, rule.enabled, rule.created_at);
        assert_eq!(rebuilt, rule);
    }
}

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;

    use super::*;
    use crate::core::firewall::{Action, Chain, TimeUnit};

    const PROTOCOLS: [Protocol; 7] = [
        Protocol::Any,
        Protocol::Tcp,
        Protocol::Udp,
        Protocol::TcpAndUdp,
        Protocol::Icmp,
        Protocol::Icmpv6,
        Protocol::IcmpBoth,
    ];
    const REJECT_TYPES: [RejectType; 5] = [
        RejectType::Default,
        RejectType::PortUnreachable,
        RejectType::HostUnreachable,
        RejectType::AdminProhibited,
        RejectType::TcpReset,
    ];

    prop_compose! {
        /// Arbitrary (often invalid) form contents.
        fn any_form()(
            protocol in 0usize..PROTOCOLS.len(),
            ports in prop::collection::vec((any::<u16>(), any::<u16>()), 0..3),
            v6_source in any::<bool>(),
            v6_dest in prop::option::of(any::<bool>()),
            interface in prop::option::of("[a-z0-9\"*]{0,18}"),
            output_interface in prop::option::of("[a-z0-9*]{0,18}"),
            output in any::<bool>(),
            action in 0usize..3,
            reject in 0usize..REJECT_TYPES.len(),
            rate in prop::option::of(("[0-9]{0,6}", "[0-9]{0,3}")),
            conn in "[0-9]{0,6}",
        ) -> RuleForm {
            let source: IpNetwork = if v6_source { "fd00::/8".parse().unwrap() } else { "10.0.0.0/8".parse().unwrap() };
            RuleForm {
                label: "x".into(),
                protocol: PROTOCOLS[protocol],
                ports: ports.into_iter().map(|(a, b)| if a == b { PortEntry::single(a) } else { PortEntry::range(a, b) }).collect(),
                sources: vec![source],
                destinations: v6_dest.map(|v6| if v6 { "2001:db8::/32".parse().unwrap() } else { "192.0.2.0/24".parse().unwrap() }).into_iter().collect(),
                interface: interface.unwrap_or_default(),
                output_interface: output_interface.unwrap_or_default(),
                chain: if output { Chain::Output } else { Chain::Input },
                action: [Action::Accept, Action::Drop, Action::Reject][action],
                reject_type: REJECT_TYPES[reject],
                rate_limit_enabled: rate.is_some(),
                rate_limit_count: rate.as_ref().map_or_default(|r| r.0.clone()),
                rate_limit_burst: rate.map_or_default(|r| r.1),
                rate_limit_unit: TimeUnit::Minute,
                connection_limit: conn,
                ..RuleForm::default()
            }
        }
    }

    proptest! {
        /// The form and the core validator never disagree: a form that passes
        /// produces a rule the loader/apply path accepts, and a rule the core
        /// rejects is never accepted by the form.
        #[test]
        fn test_form_agrees_with_core(form in any_form()) {
            let rule = form.to_rule(uuid::Uuid::new_v4(), true, jiff::Timestamp::now());
            let core_ok = rule.validate().is_ok();
            let form_ok = form.validate().is_none();
            if form_ok {
                prop_assert!(core_ok, "form accepted a rule the core rejects: {:?}", rule.validate());
            }
            if !core_ok {
                prop_assert!(!form_ok);
            }
        }
    }
}
