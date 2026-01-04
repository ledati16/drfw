//! Shared test utilities for handler modules
//!
//! Provides common test helpers to avoid duplication across handler test suites.

#[cfg(test)]
pub fn create_test_state() -> crate::app::State {
    crate::app::State::new().0
}

#[cfg(test)]
#[allow(dead_code)]
pub fn create_test_rule(label: &str) -> crate::core::firewall::Rule {
    use crate::core::firewall::{Chain, Protocol, Rule};
    use chrono::Utc;
    use uuid::Uuid;

    let mut rule = Rule {
        id: Uuid::new_v4(),
        label: label.to_string(),
        protocol: Protocol::Tcp,
        ports: None,
        source: None,
        interface: None,
        chain: Chain::Input,
        enabled: true,
        created_at: Utc::now(),
        tags: Vec::new(),
        destination: None,
        action: crate::core::firewall::Action::Accept,
        rate_limit: None,
        connection_limit: 0,
        label_lowercase: String::new(),
        interface_lowercase: None,
        tags_lowercase: Vec::new(),
        protocol_lowercase: "",
        port_display: String::new(),
        source_string: None,
        destination_string: None,
        rate_limit_display: None,
    };
    rule.rebuild_caches();
    rule
}
