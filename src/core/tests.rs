#[cfg(test)]
mod tests_impl {
    use crate::core::firewall::{Action, FirewallRuleset, PortEntry, Protocol, RejectType, Rule};
    use chrono::Utc;
    use uuid::Uuid;

    /// Helper to create a minimal test rule with sensible defaults
    fn test_rule(label: &str, protocol: Protocol, ports: Vec<PortEntry>) -> Rule {
        Rule {
            id: Uuid::nil(),
            label: label.to_string(),
            protocol,
            ports,
            sources: vec![],
            destinations: vec![],
            interface: None,
            output_interface: None,
            chain: crate::core::firewall::Chain::Input,
            enabled: true,
            tags: Vec::new(),
            created_at: Utc::now(),
            action: Action::Accept,
            reject_type: RejectType::Default,
            rate_limit: None,
            connection_limit: 0,
            log_enabled: false,
            // Cached fields
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
        }
    }

    #[test]
    fn test_empty_ruleset_json() {
        let ruleset = FirewallRuleset::new();
        let json = ruleset.to_nftables_json();

        // Assert basic structure
        assert!(json["nftables"].is_array());
        let nft = json["nftables"].as_array().unwrap();

        // table(1) + flush(1) + chains(3) + base(8: lo, invalid, ct, dhcpv6, icmp_redir, icmpv6_redir, icmp, icmpv6) + rejection(1) + counter(1) = 15
        assert_eq!(nft.len(), 15);

        assert_eq!(nft[0]["add"]["table"]["name"], "drfw");
        assert!(nft[1].get("flush").is_some());
    }
    #[test]
    fn test_single_rule_json() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(test_rule(
            "Allow SSH",
            Protocol::Tcp,
            vec![PortEntry::Single(22)],
        ));

        let json = ruleset.to_nftables_json();
        let nft = json["nftables"].as_array().unwrap();

        // 15 base + 1 user rule = 16
        assert_eq!(nft.len(), 16);

        let user_rule = &nft[13]["add"]["rule"];
        assert_eq!(user_rule["chain"], "input");
        assert_eq!(user_rule["table"], "drfw");
        assert_eq!(user_rule["comment"], "Allow SSH");

        let expr = user_rule["expr"].as_array().unwrap();
        // Should have protocol match, port match, and accept
        assert_eq!(expr.len(), 3);
        assert_eq!(expr[1]["match"]["right"], 22);
        assert!(expr[2].get("accept").is_some());
    }

    #[test]
    fn test_nft_text_output() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(test_rule(
            "Allow HTTP",
            Protocol::Tcp,
            vec![PortEntry::Single(80)],
        ));

        let text = ruleset.to_nft_text();
        assert!(text.contains("tcp dport 80 accept comment \"Allow HTTP\""));
        assert!(text.contains("policy drop"));
    }

    #[test]
    fn test_any_protocol_rule_json() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = test_rule(
            "Allow All LAN",
            Protocol::Any,
            vec![PortEntry::Single(80)], // Ports on "Any" mean TCP+UDP
        );
        rule.sources = vec!["192.168.1.0/24".parse().unwrap()];
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let nft = json["nftables"].as_array().unwrap();

        // 15 base + 1 user rule = 16
        assert_eq!(nft.len(), 16);

        let user_rule = &nft[13]["add"]["rule"];
        let expr = user_rule["expr"].as_array().unwrap();

        // l4proto {tcp, udp} + source + th dport + accept. The port must never be
        // dropped silently: that would turn "port 80 from LAN" into "everything from LAN".
        assert_eq!(expr.len(), 4);
        assert_eq!(
            expr[0]["match"]["right"],
            serde_json::json!({ "set": ["tcp", "udp"] })
        );

        // Check source match - should use prefix object format per libnftables-json(5)
        let right = &expr[1]["match"]["right"];
        assert_eq!(right["prefix"]["addr"], "192.168.1.0");
        assert_eq!(right["prefix"]["len"], 24);

        assert_eq!(expr[2]["match"]["left"]["payload"]["protocol"], "th");
        assert_eq!(expr[2]["match"]["right"], 80);
    }

    #[test]
    fn test_any_protocol_without_ports_has_no_protocol_match() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = test_rule("All From LAN", Protocol::Any, vec![]);
        rule.sources = vec!["192.168.1.0/24".parse().unwrap()];
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let user_rule = &json["nftables"][13]["add"]["rule"];
        let json_str = serde_json::to_string(user_rule).unwrap();
        assert!(!json_str.contains("l4proto"));
        assert!(!json_str.contains("dport"));
    }

    #[test]
    fn test_icmp_ports_are_ignored() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(test_rule(
            "Ping",
            Protocol::Icmp,
            vec![PortEntry::Single(22)],
        ));
        let json = ruleset.to_nftables_json();
        let expr = json["nftables"][13]["add"]["rule"]["expr"]
            .as_array()
            .unwrap()
            .clone();
        // meta l4proto icmp + accept; no dport (meaningless for ICMP)
        assert_eq!(expr.len(), 2);
        assert_eq!(expr[0]["match"]["right"], "icmp");
    }

    #[test]
    fn test_base_rule_ordering() {
        // Verify that base rules are in the correct order for performance and correctness
        let ruleset = FirewallRuleset::new();
        let json = ruleset.to_nftables_json();
        let nft = json["nftables"].as_array().unwrap();

        // Get the base rule comments
        let mut rule_comments = Vec::new();
        for item in nft {
            if let Some(rule) = item.get("add").and_then(|a| a.get("rule"))
                && let Some(comment) = rule.get("comment").and_then(|c| c.as_str())
            {
                rule_comments.push(comment);
            }
        }

        // Verify correct ordering (loopback → invalid → established → dhcpv6 → drop redirects → icmp → icmpv6)
        assert_eq!(rule_comments[0], "allow from loopback");
        assert_eq!(rule_comments[1], "early drop of invalid connections");
        assert_eq!(rule_comments[2], "allow tracked connections");
        assert_eq!(rule_comments[3], "allow dhcpv6 client replies");
        assert_eq!(rule_comments[4], "drop icmp redirects");
        assert_eq!(rule_comments[5], "drop icmpv6 redirects");
        assert_eq!(rule_comments[6], "allow icmp");
        assert_eq!(rule_comments[7], "allow icmp v6");
    }

    #[test]
    fn test_text_json_ordering_match() {
        // Verify that text and JSON generation produce the same rule order
        let ruleset = FirewallRuleset::new();
        let text = ruleset.to_nft_text();
        let json = ruleset.to_nftables_json();

        // Extract rule order from text
        assert!(text.contains("iifname \"lo\" accept comment \"allow from loopback\""));
        let lo_pos = text.find("allow from loopback").unwrap();
        let invalid_pos = text.find("early drop of invalid connections").unwrap();
        let est_pos = text.find("allow tracked connections").unwrap();

        // Verify order in text
        assert!(lo_pos < invalid_pos);
        assert!(invalid_pos < est_pos);

        // Extract from JSON
        let nft = json["nftables"].as_array().unwrap();
        let mut comments = Vec::new();
        for item in nft {
            if let Some(rule) = item.get("add").and_then(|a| a.get("rule"))
                && let Some(comment) = rule.get("comment").and_then(|c| c.as_str())
            {
                comments.push(comment);
            }
        }

        // Verify JSON has same order
        assert_eq!(comments[0], "allow from loopback");
        assert_eq!(comments[1], "early drop of invalid connections");
        assert_eq!(comments[2], "allow tracked connections");
    }

    #[test]
    fn test_text_json_complete_consistency() {
        // Comprehensive test: verify ALL rules appear in same order in both formats
        let mut ruleset = FirewallRuleset::new();

        // Add several user rules with different configurations
        let mut rule1 = test_rule("SSH Access", Protocol::Tcp, vec![PortEntry::Single(22)]);
        rule1.id = Uuid::new_v4();
        rule1.tags = vec!["secure".to_string()];
        ruleset.rules.push(rule1);

        let mut rule2 = test_rule(
            "Web Server",
            Protocol::Tcp,
            vec![PortEntry::Range {
                start: 80,
                end: 443,
            }],
        );
        rule2.id = Uuid::new_v4();
        rule2.sources = vec!["0.0.0.0/0".parse().unwrap()];
        rule2.interface = Some("eth0".to_string());
        ruleset.rules.push(rule2);

        let mut rule3 = test_rule("DNS", Protocol::Udp, vec![PortEntry::Single(53)]);
        rule3.id = Uuid::new_v4();
        ruleset.rules.push(rule3);

        let text = ruleset.to_nft_text();
        let json = ruleset.to_nftables_json();

        // Extract all rule comments from JSON (in order)
        let nft = json["nftables"].as_array().unwrap();
        let mut json_comments = Vec::new();
        for item in nft {
            if let Some(rule) = item.get("add").and_then(|a| a.get("rule"))
                && let Some(comment) = rule.get("comment").and_then(|c| c.as_str())
            {
                json_comments.push(comment);
            }
        }

        // Verify text contains all comments in the same relative order
        let mut last_pos = 0;
        for comment in &json_comments {
            if let Some(pos) = text.find(comment) {
                assert!(
                    pos > last_pos,
                    "Comment '{comment}' appears out of order in text output. Expected after position {last_pos}, found at {pos}"
                );
                last_pos = pos;
            } else {
                panic!("Comment '{comment}' found in JSON but not in text output");
            }
        }

        // Verify all expected rules are present
        assert_eq!(
            json_comments.len(),
            11,
            "Should have 8 base rules + 3 user rules"
        );
        assert_eq!(json_comments[8], "SSH Access");
        assert_eq!(json_comments[9], "Web Server");
        assert_eq!(json_comments[10], "DNS");
    }

    #[test]
    fn test_user_rule_ordering_preserved() {
        // Test that user rules maintain their insertion order in both formats
        let mut ruleset = FirewallRuleset::new();

        let rule_labels = vec![
            "First Rule",
            "Second Rule",
            "Third Rule",
            "Fourth Rule",
            "Fifth Rule",
        ];

        for (i, label) in rule_labels.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)] // i is 0..5, always fits in u16
            let port = 8000 + i as u16;
            let mut rule = test_rule(label, Protocol::Tcp, vec![PortEntry::Single(port)]);
            rule.id = Uuid::new_v4();
            ruleset.rules.push(rule);
        }

        let text = ruleset.to_nft_text();
        let json = ruleset.to_nftables_json();

        // Extract user rule comments from JSON (skip base rules)
        let nft = json["nftables"].as_array().unwrap();
        let mut json_user_rules = Vec::new();
        for item in nft.iter().skip(12) {
            // Skip table, flush, chains, base rules
            if let Some(rule) = item.get("add").and_then(|a| a.get("rule"))
                && let Some(comment) = rule.get("comment").and_then(|c| c.as_str())
                && !comment.starts_with("allow")  // Skip base rule comments
                && !comment.starts_with("drop")
                && !comment.starts_with("early")
            {
                json_user_rules.push(comment);
            }
        }

        // Verify order in JSON
        assert_eq!(json_user_rules, rule_labels);

        // Verify same order in text
        let mut last_pos = 0;
        for label in &rule_labels {
            let pos = text.find(label).unwrap_or_else(|| {
                panic!("User rule '{label}' not found in text output");
            });
            assert!(
                pos > last_pos,
                "User rule '{label}' appears out of order in text"
            );
            last_pos = pos;
        }
    }

    #[test]
    fn test_disabled_rules_excluded_from_both_formats() {
        // Verify that disabled rules are excluded from both text and JSON
        let mut ruleset = FirewallRuleset::new();

        let mut rule1 = test_rule("Enabled Rule", Protocol::Tcp, vec![PortEntry::Single(80)]);
        rule1.id = Uuid::new_v4();
        ruleset.rules.push(rule1);

        let mut rule2 = test_rule("Disabled Rule", Protocol::Tcp, vec![PortEntry::Single(443)]);
        rule2.id = Uuid::new_v4();
        rule2.enabled = false; // DISABLED
        ruleset.rules.push(rule2);

        let mut rule3 = test_rule(
            "Another Enabled",
            Protocol::Tcp,
            vec![PortEntry::Single(22)],
        );
        rule3.id = Uuid::new_v4();
        ruleset.rules.push(rule3);

        let text = ruleset.to_nft_text();
        let json = ruleset.to_nftables_json();

        // Verify text excludes disabled rule
        assert!(text.contains("Enabled Rule"));
        assert!(!text.contains("Disabled Rule"));
        assert!(text.contains("Another Enabled"));

        // Verify JSON excludes disabled rule
        let nft = json["nftables"].as_array().unwrap();
        let mut comments = Vec::new();
        for item in nft {
            if let Some(rule) = item.get("add").and_then(|a| a.get("rule"))
                && let Some(comment) = rule.get("comment").and_then(|c| c.as_str())
            {
                comments.push(comment);
            }
        }

        let comments_str = comments.join(", ");
        assert!(comments_str.contains("Enabled Rule"));
        assert!(!comments_str.contains("Disabled Rule"));
        assert!(comments_str.contains("Another Enabled"));
    }

    #[test]
    fn test_protocol_representation_consistency() {
        // Verify protocol matching is consistent between text and JSON
        let mut ruleset = FirewallRuleset::new();

        // Add rules for each protocol type
        let mut rule1 = test_rule("TCP Rule", Protocol::Tcp, vec![PortEntry::Single(80)]);
        rule1.id = Uuid::new_v4();
        ruleset.rules.push(rule1);

        let mut rule2 = test_rule("UDP Rule", Protocol::Udp, vec![PortEntry::Single(53)]);
        rule2.id = Uuid::new_v4();
        ruleset.rules.push(rule2);

        let mut rule3 = test_rule("Any Protocol", Protocol::Any, vec![]);
        rule3.id = Uuid::new_v4();
        rule3.sources = vec!["192.168.0.0/16".parse().unwrap()];
        ruleset.rules.push(rule3);

        let text = ruleset.to_nft_text();
        let json = ruleset.to_nftables_json();

        // Verify text has correct protocol syntax
        assert!(
            text.contains("tcp dport 80"),
            "Text should specify TCP protocol"
        );
        assert!(
            text.contains("udp dport 53"),
            "Text should specify UDP protocol"
        );

        // For "Any" protocol, should not have protocol match
        let any_rule_section = text.split("Any Protocol").nth(1).unwrap();
        assert!(!any_rule_section.contains("tcp dport"));
        assert!(!any_rule_section.contains("udp dport"));

        // Verify JSON has correct protocol matches
        let _nft = json["nftables"].as_array().unwrap();
        let json_str = serde_json::to_string(&json).unwrap();

        // TCP rule should have l4proto match
        assert!(json_str.contains(r#""l4proto""#));
        assert!(json_str.contains(r#""tcp""#));

        // UDP rule should have l4proto match
        assert!(json_str.contains(r#""udp""#));
    }
}

#[cfg(test)]
mod property_tests {
    use crate::core::firewall::{
        Action, FirewallRuleset, PortEntry, PortRange, Protocol, RejectType, Rule,
    };
    use chrono::Utc;
    use proptest::prelude::*;
    use uuid::Uuid;

    prop_compose! {
        fn arb_port()(port in 1u16..=65535) -> u16 {
            port
        }
    }

    prop_compose! {
        fn arb_port_range()(start in arb_port(), end in arb_port()) -> PortRange {
            PortRange {
                start: start.min(end),
                end: start.max(end),
            }
        }
    }

    prop_compose! {
        fn arb_port_entry()(start in arb_port(), end in arb_port()) -> Vec<PortEntry> {
            let s = start.min(end);
            let e = start.max(end);
            if s == e {
                vec![PortEntry::Single(s)]
            } else {
                vec![PortEntry::Range { start: s, end: e }]
            }
        }
    }

    /// Addresses of both families, single hosts and prefixes (incl. non-canonical)
    fn arb_ip() -> impl Strategy<Value = ipnetwork::IpNetwork> {
        prop_oneof![
            (any::<[u8; 4]>(), 0u8..=32).prop_map(|(o, len)| {
                ipnetwork::IpNetwork::V4(
                    ipnetwork::Ipv4Network::new(std::net::Ipv4Addr::from(o), len).unwrap(),
                )
            }),
            (any::<[u16; 8]>(), 0u8..=128).prop_map(|(s, len)| {
                ipnetwork::IpNetwork::V6(
                    ipnetwork::Ipv6Network::new(
                        std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]),
                        len,
                    )
                    .unwrap(),
                )
            }),
        ]
    }

    fn arb_interface() -> impl Strategy<Value = Option<String>> {
        proptest::option::of(prop_oneof![
            Just("eth0".to_string()),
            Just("wg*".to_string()),
            Just("br-lan.10".to_string()),
            // Hostile names: quotes, newlines, backslashes must never escape the string
            Just("eth0\" accept\n accept #".to_string()),
            Just("x\\y".to_string()),
        ])
    }

    fn arb_protocol() -> impl Strategy<Value = Protocol> {
        prop_oneof![
            Just(Protocol::Any),
            Just(Protocol::Tcp),
            Just(Protocol::Udp),
            Just(Protocol::TcpAndUdp),
            Just(Protocol::Icmp),
            Just(Protocol::Icmpv6),
            Just(Protocol::IcmpBoth),
        ]
    }

    prop_compose! {
        fn arb_rule()(
            label in "\\PC{0,40}",
            protocol in arb_protocol(),
            ports in prop::collection::vec(arb_port_entry(), 0..4),
            sources in prop::collection::vec(arb_ip(), 0..3),
            destinations in prop::collection::vec(arb_ip(), 0..3),
            interface in arb_interface(),
            output_interface in arb_interface(),
            output_chain in any::<bool>(),
            action in prop_oneof![Just(Action::Accept), Just(Action::Drop), Just(Action::Reject)],
            reject_type in prop_oneof![
                Just(RejectType::Default),
                Just(RejectType::PortUnreachable),
                Just(RejectType::HostUnreachable),
                Just(RejectType::AdminProhibited),
                Just(RejectType::TcpReset),
            ],
            rate_limit in proptest::option::of((1u32..1000, 0usize..4, proptest::option::of(0u32..50))),
            connection_limit in prop_oneof![Just(0u32), 1u32..1000],
            log_enabled in any::<bool>(),
            tags in prop::collection::vec("\\PC{0,24}", 0..3),
        ) -> Rule {
            use crate::core::firewall::{Chain, RateLimit, TimeUnit};
            let units = [TimeUnit::Second, TimeUnit::Minute, TimeUnit::Hour, TimeUnit::Day];
            let mut rule = Rule::with_caches(
                Uuid::new_v4(),
                label,
                protocol,
                ports.into_iter().flatten().collect(),
                sources,
                interface,
                if output_chain { Chain::Output } else { Chain::Input },
                true,
                Utc::now(),
                tags,
            );
            rule.destinations = destinations;
            rule.output_interface = output_interface;
            rule.action = action;
            // TCP reset is only valid for pure TCP (enforced by the GUI)
            rule.reject_type = if reject_type == RejectType::TcpReset && protocol != Protocol::Tcp {
                RejectType::Default
            } else {
                reject_type
            };
            rule.rate_limit = rate_limit.map(|(count, unit, burst)| RateLimit {
                count,
                unit: units[unit],
                burst,
            });
            rule.connection_limit = connection_limit;
            rule.log_enabled = log_enabled;
            rule.rebuild_caches();
            rule
        }
    }

    proptest! {
        #[test]
        fn test_rule_json_roundtrip_never_panics(rule in arb_rule()) {
            let mut ruleset = FirewallRuleset::new();
            ruleset.rules.push(rule);

            let json = ruleset.to_nftables_json();

            // Should be valid JSON structure
            prop_assert!(json.is_object());
            prop_assert!(json["nftables"].is_array());
        }

        #[test]
        fn test_rule_text_generation_never_panics(rule in arb_rule()) {
            let mut ruleset = FirewallRuleset::new();
            ruleset.rules.push(rule);

            let text = ruleset.to_nft_text();

            // Should contain basic structure
            prop_assert!(text.contains("table inet drfw"));
            prop_assert!(text.contains("chain input"));
        }

        /// A generated nft rule must never match more than the DRFW rule says:
        /// every non-empty address list and every port list (for port-capable
        /// protocols) must appear in each emitted copy.
        #[test]
        fn test_user_rules_never_widen(rule in arb_rule()) {
            let mut ruleset = FirewallRuleset::new();
            ruleset.advanced_security.egress_profile = crate::core::firewall::EgressProfile::Server;
            ruleset.rules.push(rule.clone());

            let user_rules: Vec<serde_json::Value> = ruleset
                .build_commands()
                .into_iter()
                .filter(|c| c.section == "User rules")
                .map(|c| c.value["add"]["rule"]["expr"].clone())
                .collect();

            for expr in &user_rules {
                let has_field = |field: &str| {
                    expr.as_array().unwrap().iter().any(|e| {
                        e["match"]["left"]["payload"]["field"].as_str() == Some(field)
                    })
                };
                if !rule.sources.is_empty() {
                    prop_assert!(has_field("saddr"), "sources dropped: {expr}");
                }
                if !rule.destinations.is_empty() {
                    prop_assert!(has_field("daddr"), "destinations dropped: {expr}");
                }
                let port_capable = !matches!(
                    rule.protocol,
                    Protocol::Icmp | Protocol::Icmpv6 | Protocol::IcmpBoth
                );
                if !rule.ports.is_empty() && port_capable {
                    prop_assert!(has_field("dport"), "ports dropped: {expr}");
                }
            }

            // At most one copy per address family
            prop_assert!(user_rules.len() <= 2);
        }

        /// Text output never contains a statement line that is not part of a
        /// rule we generated (no injection through quoted strings).
        #[test]
        fn test_text_quoted_strings_cannot_inject(rule in arb_rule()) {
            let mut ruleset = FirewallRuleset::new();
            ruleset.rules.push(rule);
            let text = ruleset.to_nft_text();
            for line in text.lines() {
                let quotes = line.matches('"').count();
                prop_assert!(quotes % 2 == 0, "unbalanced quotes in line: {line}");
                prop_assert!(line.trim() != "accept", "bare accept line: {line}");
            }
            prop_assert!(!text.contains("drfw-render-error"));
        }

        #[test]
        fn test_json_serialization_always_succeeds(rule in arb_rule()) {
            let mut ruleset = FirewallRuleset::new();
            ruleset.rules.push(rule);

            let json = ruleset.to_nftables_json();
            let json_str = serde_json::to_string(&json);

            prop_assert!(json_str.is_ok());
        }

        #[test]
        fn test_port_range_ordering_maintained(
            start in 1u16..=65535,
            end in 1u16..=65535
        ) {
            let range = PortRange {
                start: start.min(end),
                end: start.max(end),
            };

            prop_assert!(range.start <= range.end);
        }

        #[test]
        fn test_multiple_rules_json_generation(rules in prop::collection::vec(arb_rule(), 0..10)) {
            let mut ruleset = FirewallRuleset::new();
            ruleset.rules = rules;

            let json = ruleset.to_nftables_json();
            let nft_array = json["nftables"].as_array().unwrap();

            // Should have base rules (14) + user rules
            prop_assert!(nft_array.len() >= 15);
        }

        #[test]
        fn test_rate_limit_serialization_roundtrip(
            count in 1u32..1000,
            unit_idx in 0usize..4
        ) {
            use crate::core::firewall::{RateLimit, TimeUnit};

            let units = [TimeUnit::Second, TimeUnit::Minute, TimeUnit::Hour, TimeUnit::Day];
            let rate_limit = RateLimit { count, unit: units[unit_idx], burst: None };

            // Test serialization
            let json = serde_json::to_string(&rate_limit).unwrap();
            let parsed: RateLimit = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(rate_limit.count, parsed.count);
            prop_assert_eq!(rate_limit.unit, parsed.unit);
        }

        #[test]
        fn test_rate_limit_display_format(
            count in 1u32..1000,
            unit_idx in 0usize..4
        ) {
            use crate::core::firewall::{RateLimit, TimeUnit};

            let units = [TimeUnit::Second, TimeUnit::Minute, TimeUnit::Hour, TimeUnit::Day];
            let rate_limit = RateLimit { count, unit: units[unit_idx], burst: None };

            let display = rate_limit.to_string();

            // Display should contain count and unit abbreviation
            prop_assert!(display.contains(&count.to_string()));
            prop_assert!(display.contains('/'));
        }
    }
}

#[cfg(test)]
mod integration_tests {
    //! Integration tests for DRFW core JSON generation.
    //!
    //! **Note on test organization:**
    //! - Verification tests with mock nft are in `tests/integration_tests.rs` (authoritative)
    //! - Snapshot validation tests are in `nft_json.rs` (authoritative)
    //! - JSON generation tests are here (close to implementation)
    //!
    //! Tests that exercise the verification flow should be in `tests/integration_tests.rs`
    //! to avoid duplication.

    use crate::core::firewall::{FirewallRuleset, PortEntry, Protocol};
    use crate::core::test_helpers::{create_test_rule, setup_mock_nft};
    use crate::core::verify;

    #[tokio::test]
    async fn test_verify_port_range() {
        setup_mock_nft();

        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Test Port Range", Some(22));
        rule.ports = vec![PortEntry::Range {
            start: 1,
            end: 65535,
        }];
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let result = verify::verify_ruleset(json).await;

        assert!(
            result.is_ok(),
            "Port range ruleset should pass verification: {:?}",
            result.err()
        );
        let verify_result = result.unwrap();
        assert!(
            verify_result.success,
            "Port range should be valid: {:?}",
            verify_result.errors
        );
    }

    #[test]
    fn test_json_generation_with_all_protocol_types() {
        use crate::core::test_helpers::create_full_test_rule;

        let mut ruleset = FirewallRuleset::new();

        // TCP rule
        ruleset.rules.push(create_full_test_rule(
            "TCP Rule",
            Protocol::Tcp,
            Some(80),
            None,
            None,
        ));

        // UDP rule
        ruleset.rules.push(create_full_test_rule(
            "UDP Rule",
            Protocol::Udp,
            Some(53),
            None,
            None,
        ));

        // Any protocol rule with source
        ruleset.rules.push(create_full_test_rule(
            "Any Protocol",
            Protocol::Any,
            None,
            Some("192.168.1.0/24"),
            None,
        ));

        let json = ruleset.to_nftables_json();
        let nft_array = json["nftables"].as_array().unwrap();

        // Should have base rules (15) + 3 user rules
        assert_eq!(nft_array.len(), 18);

        // Verify JSON can be serialized
        let json_str = serde_json::to_string(&json);
        assert!(json_str.is_ok(), "JSON should serialize successfully");
    }

    #[test]
    fn test_connection_limit_json_generation() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Connection Limited", Some(22));
        rule.connection_limit = 5;
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let json_str = serde_json::to_string_pretty(&json).unwrap();

        // Verify the JSON contains the correct ct count syntax
        assert!(
            json_str.contains(r#""ct count""#),
            "JSON should contain 'ct count' key, got: {json_str}"
        );
        assert!(
            json_str.contains(r#""val": 5"#),
            "JSON should contain 'val': 5, got: {json_str}"
        );
        // Verify it does NOT contain the old wrong syntax
        assert!(
            !json_str.contains(r#""key": "count""#),
            "JSON should NOT contain old 'key': 'count' syntax"
        );
    }

    #[test]
    fn test_connection_limit_text_generation() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Connection Limited", Some(22));
        rule.connection_limit = 3;
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let text = ruleset.to_nft_text();

        // Verify the text contains correct ct count syntax (no <= operator)
        assert!(
            text.contains("ct count 3"),
            "Text should contain 'ct count 3', got: {text}"
        );
        // Verify it does NOT contain the old wrong syntax
        assert!(
            !text.contains("ct count <="),
            "Text should NOT contain 'ct count <=' syntax"
        );
    }

    /// Tests that mixed IPv4/IPv6 sources generate separate nftables rules.
    ///
    /// nftables requires separate rules for IPv4 (ip saddr) and IPv6 (ip6 saddr).
    /// When a DRFW rule has both IPv4 and IPv6 sources, it must generate 2 nft rules.
    #[test]
    fn test_mixed_ipv4_ipv6_sources_generates_two_rules() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Mixed IPs", Some(22));
        rule.sources = vec![
            "192.168.1.0/24".parse().unwrap(), // IPv4
            "10.0.0.0/8".parse().unwrap(),     // IPv4
            "fd00::/8".parse().unwrap(),       // IPv6
        ];
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let nft_array = json["nftables"].as_array().unwrap();

        // Count user rules (rules with comments)
        let user_rules: Vec<_> = nft_array
            .iter()
            .filter(|obj| {
                obj.get("add")
                    .and_then(|a| a.get("rule"))
                    .and_then(|r| r.get("comment"))
                    .and_then(|c| c.as_str())
                    .is_some_and(|s| s == "Mixed IPs")
            })
            .collect();

        // Should have 2 rules: one for IPv4 sources, one for IPv6 source
        assert_eq!(
            user_rules.len(),
            2,
            "Mixed IPv4/IPv6 sources should generate 2 nft rules"
        );

        // Verify one rule uses "ip" protocol (IPv4) and one uses "ip6" (IPv6)
        let json_str = serde_json::to_string_pretty(&json).unwrap();
        assert!(
            json_str.contains(r#""protocol": "ip""#),
            "Should have IPv4 rule with 'ip' protocol"
        );
        assert!(
            json_str.contains(r#""protocol": "ip6""#),
            "Should have IPv6 rule with 'ip6' protocol"
        );
    }

    /// Tests that IPv4-only sources generate a single rule.
    #[test]
    fn test_ipv4_only_sources_generates_one_rule() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("IPv4 Only", Some(80));
        rule.sources = vec![
            "192.168.1.0/24".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let nft_array = json["nftables"].as_array().unwrap();

        let user_rules: Vec<_> = nft_array
            .iter()
            .filter(|obj| {
                obj.get("add")
                    .and_then(|a| a.get("rule"))
                    .and_then(|r| r.get("comment"))
                    .and_then(|c| c.as_str())
                    .is_some_and(|s| s == "IPv4 Only")
            })
            .collect();

        assert_eq!(
            user_rules.len(),
            1,
            "IPv4-only sources should generate 1 nft rule"
        );

        // Verify it uses anonymous set for multiple sources
        let json_str = serde_json::to_string(&json).unwrap();
        assert!(
            json_str.contains(r#""set""#),
            "Multiple sources should use anonymous set"
        );
    }

    /// Tests IP address JSON format compliance with libnftables-json(5) spec.
    ///
    /// Per spec:
    /// - Single hosts (/32 IPv4, /128 IPv6): Plain IP string
    /// - Network prefixes: { "prefix": { "addr": "...", "len": N } }
    #[test]
    fn test_ip_json_format_single_host_ipv4() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Single IPv4 Host", Some(22));
        rule.sources = vec!["192.168.1.1".parse().unwrap()]; // Single host, /32
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let nft_array = json["nftables"].as_array().unwrap();

        // Find the user rule
        let user_rule = nft_array
            .iter()
            .find(|obj| {
                obj.get("add")
                    .and_then(|a| a.get("rule"))
                    .and_then(|r| r.get("comment"))
                    .and_then(|c| c.as_str())
                    .is_some_and(|s| s == "Single IPv4 Host")
            })
            .expect("Should find user rule");

        let expr = user_rule["add"]["rule"]["expr"].as_array().unwrap();
        // Find the saddr match (second match after l4proto)
        let src_match = expr
            .iter()
            .filter(|e| e.get("match").is_some())
            .find(|e| {
                e["match"]["left"]
                    .get("payload")
                    .and_then(|p| p.get("field"))
                    .and_then(|f| f.as_str())
                    .is_some_and(|s| s == "saddr")
            })
            .and_then(|e| e.get("match"))
            .expect("Should have saddr match");

        // Should be plain string, not prefix object
        assert_eq!(
            src_match["right"], "192.168.1.1",
            "Single IPv4 host should be plain string"
        );
    }

    #[test]
    fn test_ip_json_format_single_host_ipv6() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Single IPv6 Host", Some(22));
        rule.sources = vec!["2001:db8::1".parse().unwrap()]; // Single host, /128
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let nft_array = json["nftables"].as_array().unwrap();

        let user_rule = nft_array
            .iter()
            .find(|obj| {
                obj.get("add")
                    .and_then(|a| a.get("rule"))
                    .and_then(|r| r.get("comment"))
                    .and_then(|c| c.as_str())
                    .is_some_and(|s| s == "Single IPv6 Host")
            })
            .expect("Should find user rule");

        let expr = user_rule["add"]["rule"]["expr"].as_array().unwrap();
        let src_match = expr
            .iter()
            .filter(|e| e.get("match").is_some())
            .find(|e| {
                e["match"]["left"]
                    .get("payload")
                    .and_then(|p| p.get("field"))
                    .and_then(|f| f.as_str())
                    .is_some_and(|s| s == "saddr")
            })
            .and_then(|e| e.get("match"))
            .expect("Should have saddr match");

        assert_eq!(
            src_match["right"], "2001:db8::1",
            "Single IPv6 host should be plain string"
        );
    }

    #[test]
    fn test_ip_json_format_network_prefix_ipv4() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("IPv4 Network", Some(80));
        rule.sources = vec!["192.168.1.0/24".parse().unwrap()];
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let nft_array = json["nftables"].as_array().unwrap();

        let user_rule = nft_array
            .iter()
            .find(|obj| {
                obj.get("add")
                    .and_then(|a| a.get("rule"))
                    .and_then(|r| r.get("comment"))
                    .and_then(|c| c.as_str())
                    .is_some_and(|s| s == "IPv4 Network")
            })
            .expect("Should find user rule");

        let expr = user_rule["add"]["rule"]["expr"].as_array().unwrap();
        let src_match = expr
            .iter()
            .filter(|e| e.get("match").is_some())
            .find(|e| {
                e["match"]["left"]
                    .get("payload")
                    .and_then(|p| p.get("field"))
                    .and_then(|f| f.as_str())
                    .is_some_and(|s| s == "saddr")
            })
            .and_then(|e| e.get("match"))
            .expect("Should have saddr match");

        let right = &src_match["right"];
        assert_eq!(
            right["prefix"]["addr"], "192.168.1.0",
            "Should have network address"
        );
        assert_eq!(right["prefix"]["len"], 24, "Should have prefix length 24");
    }

    #[test]
    fn test_ip_json_format_network_prefix_ipv6() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("IPv6 Network", Some(443));
        rule.sources = vec!["2001:db8::/32".parse().unwrap()];
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let nft_array = json["nftables"].as_array().unwrap();

        let user_rule = nft_array
            .iter()
            .find(|obj| {
                obj.get("add")
                    .and_then(|a| a.get("rule"))
                    .and_then(|r| r.get("comment"))
                    .and_then(|c| c.as_str())
                    .is_some_and(|s| s == "IPv6 Network")
            })
            .expect("Should find user rule");

        let expr = user_rule["add"]["rule"]["expr"].as_array().unwrap();
        let src_match = expr
            .iter()
            .filter(|e| e.get("match").is_some())
            .find(|e| {
                e["match"]["left"]
                    .get("payload")
                    .and_then(|p| p.get("field"))
                    .and_then(|f| f.as_str())
                    .is_some_and(|s| s == "saddr")
            })
            .and_then(|e| e.get("match"))
            .expect("Should have saddr match");

        let right = &src_match["right"];
        assert_eq!(
            right["prefix"]["addr"], "2001:db8::",
            "Should have correct network address"
        );
        assert_eq!(right["prefix"]["len"], 32, "Should have prefix length 32");
    }

    /// Tests that non-canonical CIDR inputs are normalized to network address.
    #[test]
    fn test_ip_json_format_normalizes_non_canonical_cidr() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Non-Canonical CIDR", Some(22));
        // User enters host IP with /24 - should normalize to network address
        rule.sources = vec!["192.168.1.50/24".parse().unwrap()];
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let nft_array = json["nftables"].as_array().unwrap();

        let user_rule = nft_array
            .iter()
            .find(|obj| {
                obj.get("add")
                    .and_then(|a| a.get("rule"))
                    .and_then(|r| r.get("comment"))
                    .and_then(|c| c.as_str())
                    .is_some_and(|s| s == "Non-Canonical CIDR")
            })
            .expect("Should find user rule");

        let expr = user_rule["add"]["rule"]["expr"].as_array().unwrap();
        let src_match = expr
            .iter()
            .filter(|e| e.get("match").is_some())
            .find(|e| {
                e["match"]["left"]
                    .get("payload")
                    .and_then(|p| p.get("field"))
                    .and_then(|f| f.as_str())
                    .is_some_and(|s| s == "saddr")
            })
            .and_then(|e| e.get("match"))
            .expect("Should have saddr match");

        // Should normalize to 192.168.1.0, not keep 192.168.1.50
        let right = &src_match["right"];
        assert_eq!(
            right["prefix"]["addr"], "192.168.1.0",
            "Non-canonical CIDR should be normalized to network address"
        );
        assert_eq!(right["prefix"]["len"], 24);
    }

    /// Tests /0 prefix (any IP) generates correct format.
    #[test]
    fn test_ip_json_format_any_ipv4() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Any IPv4", Some(22));
        rule.sources = vec!["0.0.0.0/0".parse().unwrap()];
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let nft_array = json["nftables"].as_array().unwrap();

        let user_rule = nft_array
            .iter()
            .find(|obj| {
                obj.get("add")
                    .and_then(|a| a.get("rule"))
                    .and_then(|r| r.get("comment"))
                    .and_then(|c| c.as_str())
                    .is_some_and(|s| s == "Any IPv4")
            })
            .expect("Should find user rule");

        let expr = user_rule["add"]["rule"]["expr"].as_array().unwrap();
        let src_match = expr
            .iter()
            .filter(|e| e.get("match").is_some())
            .find(|e| {
                e["match"]["left"]
                    .get("payload")
                    .and_then(|p| p.get("field"))
                    .and_then(|f| f.as_str())
                    .is_some_and(|s| s == "saddr")
            })
            .and_then(|e| e.get("match"))
            .expect("Should have saddr match");

        let right = &src_match["right"];
        assert_eq!(
            right["prefix"]["addr"], "0.0.0.0",
            "Should have 0.0.0.0 address"
        );
        assert_eq!(right["prefix"]["len"], 0, "Should have prefix length 0");
    }

    /// Tests multiple IPs in a set all use correct format.
    #[test]
    fn test_ip_json_format_set_with_mixed_types() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Mixed IP Types", Some(80));
        rule.sources = vec![
            "192.168.1.1".parse().unwrap(),   // Single host - plain string
            "10.0.0.0/8".parse().unwrap(),    // Network - prefix object
            "172.16.0.0/12".parse().unwrap(), // Network - prefix object
        ];
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let nft_array = json["nftables"].as_array().unwrap();

        let user_rule = nft_array
            .iter()
            .find(|obj| {
                obj.get("add")
                    .and_then(|a| a.get("rule"))
                    .and_then(|r| r.get("comment"))
                    .and_then(|c| c.as_str())
                    .is_some_and(|s| s == "Mixed IP Types")
            })
            .expect("Should find user rule");

        let expr = user_rule["add"]["rule"]["expr"].as_array().unwrap();
        let src_match = expr
            .iter()
            .filter(|e| e.get("match").is_some())
            .find(|e| {
                e["match"]["left"]
                    .get("payload")
                    .and_then(|p| p.get("field"))
                    .and_then(|f| f.as_str())
                    .is_some_and(|s| s == "saddr")
            })
            .and_then(|e| e.get("match"))
            .expect("Should have saddr match");

        let right = &src_match["right"];
        let set = right["set"].as_array().expect("Should have set");

        // First element: single host as plain string
        assert_eq!(set[0], "192.168.1.1", "Single host should be plain string");

        // Second element: 10.0.0.0/8 as prefix object
        assert_eq!(set[1]["prefix"]["addr"], "10.0.0.0");
        assert_eq!(set[1]["prefix"]["len"], 8);

        // Third element: 172.16.0.0/12 as prefix object
        assert_eq!(set[2]["prefix"]["addr"], "172.16.0.0");
        assert_eq!(set[2]["prefix"]["len"], 12);
    }

    /// Tests that empty sources/destinations generate a single rule.
    #[test]
    fn test_no_ip_filtering_generates_one_rule() {
        let mut ruleset = FirewallRuleset::new();
        let rule = create_test_rule("No IP Filter", Some(443));
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let nft_array = json["nftables"].as_array().unwrap();

        let user_rules: Vec<_> = nft_array
            .iter()
            .filter(|obj| {
                obj.get("add")
                    .and_then(|a| a.get("rule"))
                    .and_then(|r| r.get("comment"))
                    .and_then(|c| c.as_str())
                    .is_some_and(|s| s == "No IP Filter")
            })
            .collect();

        assert_eq!(
            user_rules.len(),
            1,
            "No IP filtering should generate 1 nft rule"
        );
    }

    /// Tests rate limit with burst generates correct JSON.
    #[test]
    fn test_rate_limit_with_burst_json() {
        use crate::core::firewall::RateLimit;

        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Rate Limited", Some(22));
        rule.rate_limit = Some(RateLimit {
            count: 5,
            unit: crate::core::firewall::TimeUnit::Minute,
            burst: Some(10),
        });
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let json_str = serde_json::to_string_pretty(&json).unwrap();

        assert!(json_str.contains(r#""rate": 5"#), "Should have rate: 5");
        assert!(
            json_str.contains(r#""per": "minute""#),
            "Should have per: minute"
        );
        assert!(json_str.contains(r#""burst": 10"#), "Should have burst: 10");
    }

    /// Tests reject types generate correct JSON.
    #[test]
    fn test_reject_types_json() {
        use crate::core::firewall::{Action, RejectType};

        let mut ruleset = FirewallRuleset::new();

        // TCP Reset
        let mut rule1 = create_test_rule("TCP Reset", Some(23));
        rule1.action = Action::Reject;
        rule1.reject_type = RejectType::TcpReset;
        rule1.rebuild_caches();
        ruleset.rules.push(rule1);

        // Admin Prohibited
        let mut rule2 = create_test_rule("Admin Prohibited", Some(25));
        rule2.action = Action::Reject;
        rule2.reject_type = RejectType::AdminProhibited;
        rule2.rebuild_caches();
        ruleset.rules.push(rule2);

        let json = ruleset.to_nftables_json();
        let json_str = serde_json::to_string_pretty(&json).unwrap();

        assert!(
            json_str.contains(r#""type": "tcp reset""#),
            "Should have TCP reset reject type"
        );
        assert!(
            json_str.contains(r#""type": "icmpx""#),
            "Should have icmpx reject type"
        );
        assert!(
            json_str.contains(r#""expr": "admin-prohibited""#),
            "Should have admin-prohibited expression"
        );
    }

    /// Tests per-rule logging generates correct JSON.
    #[test]
    fn test_per_rule_logging_json() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Logged Rule", Some(22));
        rule.log_enabled = true;
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let json_str = serde_json::to_string_pretty(&json).unwrap();

        assert!(json_str.contains(r#""log""#), "Should have log statement");
        assert!(
            json_str.contains(r#""prefix": "DRFW-LoggedRule: ""#),
            "Should have sanitized log prefix (spaces removed)"
        );
        assert!(
            json_str.contains(r#""level": "info""#),
            "Should have info log level"
        );
    }

    /// Tests multiple ports generate correct JSON with anonymous set.
    #[test]
    fn test_multiple_ports_json() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Multi Port", None);
        rule.ports = vec![
            PortEntry::Single(22),
            PortEntry::Single(80),
            PortEntry::Single(443),
            PortEntry::Range {
                start: 8000,
                end: 8080,
            },
        ];
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let json_str = serde_json::to_string(&json).unwrap();

        // Should use anonymous set
        assert!(
            json_str.contains(r#""set""#),
            "Multiple ports should use set"
        );
        // Should have range syntax
        assert!(
            json_str.contains(r#""range""#),
            "Port range should use range syntax"
        );
        assert!(
            json_str.contains("8000") && json_str.contains("8080"),
            "Should have port range values"
        );
    }

    /// Tests output interface generates correct JSON.
    #[test]
    fn test_output_interface_json() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Output Iface", Some(443));
        rule.output_interface = Some("eth0".to_string());
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let json_str = serde_json::to_string_pretty(&json).unwrap();

        assert!(
            json_str.contains(r#""key": "oifname""#),
            "Should have oifname meta key"
        );
        assert!(
            json_str.contains(r#""right": "eth0""#),
            "Should match eth0 interface"
        );
    }
}

#[cfg(test)]
mod generation_semantics_tests {
    //! Semantic guarantees of the generator (no widening, lockout prevention,
    //! limit inversion). Real-kernel checks live in `tests/real_nft.rs`.

    use crate::core::firewall::{
        Action, Chain, EgressProfile, FirewallRuleset, NftCommand, PortEntry, Protocol, RateLimit,
        TimeUnit,
    };
    use crate::core::test_helpers::create_test_rule;

    fn rules_in_chain<'a>(cmds: &'a [NftCommand], chain: &str) -> Vec<&'a serde_json::Value> {
        cmds.iter()
            .filter_map(|c| c.value.get("add").and_then(|a| a.get("rule")))
            .filter(|r| r["chain"] == chain)
            .collect()
    }

    fn user_rule_exprs(ruleset: &FirewallRuleset) -> Vec<serde_json::Value> {
        ruleset
            .build_commands()
            .into_iter()
            .filter(|c| c.section == "User rules")
            .map(|c| c.value["add"]["rule"]["expr"].clone())
            .collect()
    }

    fn chain_policy(ruleset: &FirewallRuleset, chain: &str) -> String {
        ruleset
            .build_commands()
            .iter()
            .filter_map(|c| c.value.get("add").and_then(|a| a.get("chain")))
            .find(|c| c["name"] == chain)
            .and_then(|c| c["policy"].as_str())
            .unwrap()
            .to_string()
    }

    #[test]
    fn test_mixed_family_rule_does_not_widen() {
        // sources [v4, v6] + destinations [v4]: only the IPv4 copy can honour
        // both lists. An IPv6 copy would have no daddr match (any destination).
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Mixed", Some(22));
        rule.sources = vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()];
        rule.destinations = vec!["192.168.1.1".parse().unwrap()];
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let exprs = user_rule_exprs(&ruleset);
        assert_eq!(exprs.len(), 1);
        let text = exprs[0].to_string();
        assert!(text.contains(r#""protocol":"ip""#));
        assert!(!text.contains(r#""protocol":"ip6""#));
        assert!(text.contains("daddr"));
    }

    #[test]
    fn test_disjoint_families_emit_nothing() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Impossible", Some(22));
        rule.sources = vec!["fd00::1".parse().unwrap()];
        rule.destinations = vec!["192.168.1.1".parse().unwrap()];
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        assert_eq!(user_rule_exprs(&ruleset), Vec::<serde_json::Value>::new());
    }

    #[test]
    fn test_drop_and_reject_limits_are_inverted() {
        for (action, inverted) in [
            (Action::Accept, false),
            (Action::Drop, true),
            (Action::Reject, true),
        ] {
            let mut ruleset = FirewallRuleset::new();
            let mut rule = create_test_rule("Limited", Some(22));
            rule.action = action;
            rule.rate_limit = Some(RateLimit {
                count: 5,
                unit: TimeUnit::Minute,
                burst: Some(0),
            });
            rule.connection_limit = 3;
            rule.rebuild_caches();
            ruleset.rules.push(rule);

            let exprs = user_rule_exprs(&ruleset);
            let expr = exprs[0].as_array().unwrap();
            let limit = expr.iter().find_map(|e| e.get("limit")).unwrap();
            let count = expr.iter().find_map(|e| e.get("ct count")).unwrap();
            assert_eq!(limit.get("inv").is_some(), inverted, "{action:?}");
            assert_eq!(count.get("inv").is_some(), inverted, "{action:?}");
            // burst 0 means "no burst"; nft rejects "burst 0 packets"
            assert!(limit.get("burst").is_none());

            let text = ruleset.to_nft_text();
            assert_eq!(text.contains("limit rate over 5/minute"), inverted);
            assert_eq!(text.contains("ct count over 3"), inverted);
            assert!(!text.contains("burst 0"));
        }
    }

    #[test]
    fn test_server_mode_output_base_rules() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.advanced_security.egress_profile = EgressProfile::Server;
        let mut rule = create_test_rule("Outbound HTTPS", Some(443));
        rule.chain = Chain::Output;
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let cmds = ruleset.build_commands();
        let output = rules_in_chain(&cmds, "output");
        let comments: Vec<&str> = output
            .iter()
            .filter_map(|r| r["comment"].as_str())
            .collect();
        assert_eq!(
            comments,
            [
                "allow to loopback",
                "early drop of invalid outbound connections",
                "allow outbound tracked connections",
                "allow outbound ipv6 neighbor discovery",
                "Outbound HTTPS",
            ]
        );
        assert_eq!(chain_policy(&ruleset, "output"), "drop");

        // Desktop mode: no output rules at all (policy accept)
        ruleset.advanced_security.egress_profile = EgressProfile::Desktop;
        let cmds = ruleset.build_commands();
        assert_eq!(
            rules_in_chain(&cmds, "output"),
            Vec::<&serde_json::Value>::new()
        );
        assert_eq!(chain_policy(&ruleset, "output"), "accept");
    }

    #[test]
    fn test_forward_chain_policy() {
        let mut ruleset = FirewallRuleset::new();
        assert_eq!(chain_policy(&ruleset, "forward"), "accept");
        let cmds = ruleset.build_commands();
        assert_eq!(
            rules_in_chain(&cmds, "forward"),
            Vec::<&serde_json::Value>::new()
        );

        ruleset.advanced_security.block_forwarding = true;
        assert_eq!(chain_policy(&ruleset, "forward"), "drop");
        let cmds = ruleset.build_commands();
        let forward = rules_in_chain(&cmds, "forward");
        assert_eq!(forward.len(), 2);
        assert_eq!(forward[0]["expr"][0]["match"]["right"], "invalid");
    }

    #[test]
    fn test_block_forwarding_defaults_off_when_missing_from_profile() {
        let settings: crate::core::firewall::AdvancedSecuritySettings =
            serde_json::from_str("{}").unwrap();
        assert!(!settings.block_forwarding);
    }

    #[test]
    fn test_strict_icmp_types() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.advanced_security.strict_icmp = true;
        let text = ruleset.to_nft_text();
        for icmpv6_type in [
            "nd-router-advert",
            "mld-listener-query",
            "nd-neighbor-solicit",
            "packet-too-big",
        ] {
            assert!(text.contains(icmpv6_type), "missing {icmpv6_type}");
        }
        let icmp_line = text
            .lines()
            .find(|l| l.contains("allow essential icmp (strict mode)"))
            .unwrap();
        assert!(icmp_line.contains("parameter-problem"));
        let icmpv6_line = text
            .lines()
            .find(|l| l.contains("allow essential icmpv6 (strict mode)"))
            .unwrap();
        assert!(icmpv6_line.contains("parameter-problem"));
    }

    #[test]
    fn test_dhcpv6_client_rule_after_established() {
        let text = FirewallRuleset::new().to_nft_text();
        let established = text.find("allow tracked connections").unwrap();
        let dhcp = text
            .find("ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept")
            .unwrap();
        assert!(established < dhcp);
    }

    #[test]
    fn test_interface_names_sanitized_identically() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Evil", Some(22));
        rule.interface = Some("eth0\" accept\n accept #".to_string());
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let exprs = user_rule_exprs(&ruleset);
        let iif = exprs[0]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["match"]["left"]["meta"]["key"] == "iifname")
            .unwrap();
        assert_eq!(iif["match"]["right"], "eth0 accept accept #");

        let text = ruleset.to_nft_text();
        assert!(text.contains("iifname \"eth0 accept accept #\""));
        assert!(!text.lines().any(|l| l.trim() == "accept"));
    }

    #[test]
    fn test_empty_sanitized_interface_skips_rule() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Quote only", Some(22));
        rule.interface = Some("\"\"".to_string());
        rule.rebuild_caches();
        ruleset.rules.push(rule);
        assert_eq!(user_rule_exprs(&ruleset), Vec::<serde_json::Value>::new());
    }

    #[test]
    fn test_text_rules_land_in_their_chain() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.advanced_security.egress_profile = EgressProfile::Server;
        let mut rule = create_test_rule("Outbound DNS", Some(53));
        rule.protocol = Protocol::Udp;
        rule.chain = Chain::Output;
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let text = ruleset.to_nft_text();
        let output_chain = text.find("chain output {").unwrap();
        let rule_pos = text.find("Outbound DNS").unwrap();
        assert!(
            rule_pos > output_chain,
            "output rule rendered outside output chain"
        );
    }

    #[test]
    fn test_text_tcp_without_ports_is_valid_form() {
        // Old renderer produced bare "tcp accept" (syntax error)
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("All TCP", None);
        rule.ports = Vec::<PortEntry>::new();
        rule.rebuild_caches();
        ruleset.rules.push(rule);
        let text = ruleset.to_nft_text();
        assert!(text.contains("meta l4proto tcp accept comment \"All TCP\""));
    }

    #[test]
    fn test_text_header() {
        let text = FirewallRuleset::new().to_nft_text();
        assert!(text.starts_with("#!/usr/sbin/nft -f\n"));
        assert!(text.contains("\ntable inet drfw\ndelete table inet drfw\n"));
    }

    #[test]
    fn test_non_ascii_tags_do_not_panic() {
        let mut rule = create_test_rule("Tags", Some(22));
        rule.tags = vec![
            "ääääääääääääääääääää".to_string(),
            "日本語のタグはとても長いです".to_string(),
            "web-servers-production".to_string(),
        ];
        rule.rebuild_caches();
        // Non-ASCII is stripped by the tag allowlist; empty results are dropped
        assert_eq!(rule.tags, vec!["web-servers-production".to_string()]);
        assert_eq!(rule.tags_truncated, vec!["web-servers-pro…".to_string()]);
    }
}
