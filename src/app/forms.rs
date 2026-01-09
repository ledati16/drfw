//! Rule form validation
//!
//! Handles validation of firewall rule form inputs with detailed error reporting.
//! Supports multi-value fields (ports, IPs) with helper modal editing pattern.

use crate::core::firewall::{PortEntry, Protocol, RejectType};
use crate::core::rule_constraints::{
    ip_compatible_with_protocol, protocol_supports_ports, reject_type_valid_for_protocol,
};
use ipnetwork::IpNetwork;

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
    /// Validates all form fields
    ///
    /// Multi-value fields (ports, sources, destinations) are validated as Vec
    /// and returned directly since they're already parsed during helper modal input.
    ///
    /// Returns Option<FormErrors> - None if validation passed
    pub fn validate(&self) -> Option<FormErrors> {
        let mut errors = FormErrors::default();
        let mut has_errors = false;

        self.validate_ports(&mut errors, &mut has_errors);
        self.validate_sources(&mut errors, &mut has_errors);
        self.validate_destinations(&mut errors, &mut has_errors);
        self.validate_interface(&mut errors, &mut has_errors);
        self.validate_output_interface(&mut errors, &mut has_errors);
        self.validate_interface_chain_compat(&mut errors, &mut has_errors);
        self.validate_reject_type(&mut errors, &mut has_errors);
        self.validate_rate_limit(&mut errors, &mut has_errors);
        self.validate_connection_limit(&mut errors, &mut has_errors);

        if has_errors { Some(errors) } else { None }
    }

    fn validate_ports(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        // Use centralized constraint for port support
        if !protocol_supports_ports(self.protocol) {
            return;
        }

        // Multi-value ports are already validated when added via helper
        // Just check for any obvious issues
        for port in &self.ports {
            match port {
                PortEntry::Single(p) if *p == 0 => {
                    errors.port = Some("Port cannot be 0".to_string());
                    *has_errors = true;
                    return;
                }
                PortEntry::Range { start, end } if start > end => {
                    errors.port = Some("Port range start must be <= end".to_string());
                    *has_errors = true;
                    return;
                }
                _ => {}
            }
        }
    }

    fn validate_sources(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        // Use centralized constraint for ICMP/IP version compatibility
        for ip in &self.sources {
            if !ip_compatible_with_protocol(ip, self.protocol) {
                let msg = if ip.is_ipv6() {
                    "ICMP (v4) cannot be used with IPv6 addresses"
                } else {
                    "ICMPv6 cannot be used with IPv4 addresses"
                };
                errors.source = Some(msg.to_string());
                *has_errors = true;
                return;
            }
        }
    }

    fn validate_destinations(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        // Use centralized constraint for ICMP/IP version compatibility
        for ip in &self.destinations {
            if !ip_compatible_with_protocol(ip, self.protocol) {
                let msg = if ip.is_ipv6() {
                    "ICMP (v4) cannot be used with IPv6 addresses"
                } else {
                    "ICMPv6 cannot be used with IPv4 addresses"
                };
                errors.destination = Some(msg.to_string());
                *has_errors = true;
                return;
            }
        }
    }

    fn validate_interface(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        if !self.interface.is_empty()
            && let Err(msg) = crate::validators::validate_interface(&self.interface)
        {
            errors.interface = Some(msg.to_string());
            *has_errors = true;
        }
    }

    fn validate_output_interface(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        if !self.output_interface.is_empty()
            && let Err(msg) = crate::validators::validate_interface(&self.output_interface)
        {
            errors.output_interface = Some(msg.to_string());
            *has_errors = true;
        }
    }

    /// Validates interface/chain compatibility.
    ///
    /// nftables only sets certain meta keys for specific hooks:
    /// - `iifname`: Only available in INPUT and FORWARD (not OUTPUT)
    /// - `oifname`: Only available in OUTPUT and FORWARD (not INPUT)
    ///
    /// Using the wrong interface for a chain results in rules that never match.
    fn validate_interface_chain_compat(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        use crate::core::firewall::Chain;

        // Input interface on OUTPUT chain won't match (packets originate locally)
        if !self.interface.is_empty() && self.chain == Chain::Output {
            errors.interface = Some("Input interface not available for OUTPUT rules".to_string());
            *has_errors = true;
        }

        // Output interface on INPUT chain won't match (packets not routed yet)
        if !self.output_interface.is_empty() && self.chain == Chain::Input {
            errors.output_interface =
                Some("Output interface not available for INPUT rules".to_string());
            *has_errors = true;
        }
    }

    fn validate_reject_type(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        // Use centralized constraint for reject type validity
        if !reject_type_valid_for_protocol(self.reject_type, self.protocol) {
            errors.reject_type = Some("TCP Reset is only available for TCP protocol".to_string());
            *has_errors = true;
        }
    }

    fn validate_rate_limit(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        if !self.rate_limit_enabled {
            return;
        }

        if let Ok(count) = self.rate_limit_count.parse::<u32>() {
            // Ignore warnings (Ok result), only handle errors
            if let Err(msg) = crate::validators::validate_rate_limit(count, self.rate_limit_unit) {
                errors.rate_limit = Some(msg);
                *has_errors = true;
            }
        } else if !self.rate_limit_count.is_empty() {
            errors.rate_limit = Some("Invalid rate limit number".to_string());
            *has_errors = true;
        }

        // Validate burst if provided
        if !self.rate_limit_burst.is_empty() && self.rate_limit_burst.parse::<u32>().is_err() {
            errors.rate_limit = Some("Invalid burst number".to_string());
            *has_errors = true;
        }
    }

    fn validate_connection_limit(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        if self.connection_limit.is_empty() {
            return;
        }

        if let Ok(limit) = self.connection_limit.parse::<u32>() {
            // Ignore warnings (Ok result), only handle errors
            if let Err(msg) = crate::validators::validate_connection_limit(limit) {
                errors.connection_limit = Some(msg);
                *has_errors = true;
            }
        } else {
            errors.connection_limit = Some("Invalid connection limit number".to_string());
            *has_errors = true;
        }
    }
}
