//! Rule form validation
//!
//! Handles validation of firewall rule form inputs with detailed error reporting.

use crate::core::firewall::Protocol;

/// Form validation errors for individual fields
#[derive(Debug, Clone, Default)]
pub struct FormErrors {
    pub port: Option<String>,
    pub source: Option<String>,
    pub interface: Option<String>,
    pub destination: Option<String>,
    pub rate_limit: Option<String>,
    pub connection_limit: Option<String>,
}

/// Rule form state with validation
#[derive(Debug, Clone)]
pub struct RuleForm {
    pub id: Option<uuid::Uuid>,
    pub label: String,
    pub protocol: Protocol,
    pub port_start: String,
    pub port_end: String,
    pub source: String,
    pub interface: String,
    pub chain: crate::core::firewall::Chain,
    pub tags: Vec<String>,
    pub tag_input: String,
    pub show_advanced: bool,
    pub destination: String,
    pub action: crate::core::firewall::Action,
    pub rate_limit_enabled: bool,
    pub rate_limit_count: String,
    pub rate_limit_unit: crate::core::firewall::TimeUnit,
    pub connection_limit: String,
}

impl Default for RuleForm {
    fn default() -> Self {
        Self {
            id: None,
            label: String::new(),
            protocol: Protocol::Tcp,
            port_start: String::new(),
            port_end: String::new(),
            source: String::new(),
            interface: String::new(),
            chain: crate::core::firewall::Chain::Input,
            tags: Vec::new(),
            tag_input: String::new(),
            show_advanced: false,
            destination: String::new(),
            action: crate::core::firewall::Action::Accept,
            rate_limit_enabled: false,
            rate_limit_count: String::new(),
            rate_limit_unit: crate::core::firewall::TimeUnit::Second,
            connection_limit: String::new(),
        }
    }
}

impl RuleForm {
    /// Validates all form fields
    ///
    /// Returns (ports, source, errors) tuple where:
    /// - ports: Validated port range if applicable
    /// - source: Validated source IP/network if provided
    /// - errors: Form errors if validation failed
    pub fn validate(
        &self,
    ) -> (
        Option<crate::core::firewall::PortRange>,
        Option<ipnetwork::IpNetwork>,
        Option<FormErrors>,
    ) {
        let mut errors = FormErrors::default();
        let mut has_errors = false;

        let ports = self.validate_ports(&mut errors, &mut has_errors);
        let source = self.validate_source(&mut errors, &mut has_errors);
        self.validate_interface(&mut errors, &mut has_errors);
        self.validate_destination(&mut errors, &mut has_errors);
        self.validate_rate_limit(&mut errors, &mut has_errors);
        self.validate_connection_limit(&mut errors, &mut has_errors);

        if has_errors {
            (None, None, Some(errors))
        } else {
            (ports, source, None)
        }
    }

    fn validate_ports(
        &self,
        errors: &mut FormErrors,
        has_errors: &mut bool,
    ) -> Option<crate::core::firewall::PortRange> {
        if !matches!(
            self.protocol,
            Protocol::Tcp | Protocol::Udp | Protocol::TcpAndUdp
        ) {
            return None;
        }

        let port_start = self.port_start.parse::<u16>();
        let port_end = if self.port_end.is_empty() {
            port_start.clone() // Clone is necessary: Result doesn't implement Copy
        } else {
            self.port_end.parse::<u16>()
        };

        if let (Ok(s), Ok(e)) = (port_start, port_end) {
            match crate::validators::validate_port_range(s, e) {
                Ok((start, end)) => Some(crate::core::firewall::PortRange { start, end }),
                Err(msg) => {
                    errors.port = Some(msg.to_string());
                    *has_errors = true;
                    None
                }
            }
        } else {
            errors.port = Some("Invalid port number".to_string());
            *has_errors = true;
            None
        }
    }

    fn validate_source(
        &self,
        errors: &mut FormErrors,
        has_errors: &mut bool,
    ) -> Option<ipnetwork::IpNetwork> {
        let source = if self.source.is_empty() {
            return None;
        } else if let Ok(ip) = self.source.parse::<ipnetwork::IpNetwork>() {
            Some(ip)
        } else {
            errors.source = Some("Invalid IP address or CIDR (e.g. 192.168.1.0/24)".to_string());
            *has_errors = true;
            return None;
        };

        // Check protocol/IP version compatibility
        if let Some(src) = source {
            if self.protocol == Protocol::Icmp && src.is_ipv6() {
                errors.source = Some("ICMP (v4) selected with IPv6 source".to_string());
                *has_errors = true;
            } else if self.protocol == Protocol::Icmpv6 && src.is_ipv4() {
                errors.source = Some("ICMPv6 selected with IPv4 source".to_string());
                *has_errors = true;
            }
        }

        source
    }

    fn validate_interface(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        if !self.interface.is_empty()
            && let Err(msg) = crate::validators::validate_interface(&self.interface)
        {
            errors.interface = Some(msg.to_string());
            *has_errors = true;
        }
    }

    fn validate_destination(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        if !self.destination.is_empty() && self.destination.parse::<ipnetwork::IpNetwork>().is_err()
        {
            errors.destination =
                Some("Invalid destination IP or CIDR (domains not supported)".to_string());
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
