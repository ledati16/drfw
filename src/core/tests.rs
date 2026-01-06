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
        }
    }

    #[test]
    fn test_empty_ruleset_json() {
        let ruleset = FirewallRuleset::new();
        let json = ruleset.to_nftables_json();

        // Assert basic structure
        assert!(json["nftables"].is_array());
        let nft = json["nftables"].as_array().unwrap();

        // table(1) + flush(1) + chains(3) + base(7: lo, invalid, ct, icmp_redir, icmpv6_redir, icmp, icmpv6) + rejection(1) + counter(1) = 14
        assert_eq!(nft.len(), 14);

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

        // 14 base + 1 user rule = 15
        assert_eq!(nft.len(), 15);

        let user_rule = &nft[12]["add"]["rule"];
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
            vec![PortEntry::Single(80)], // Ports should be ignored
        );
        rule.sources = vec!["192.168.1.0/24".parse().unwrap()];
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let nft = json["nftables"].as_array().unwrap();

        // 14 base + 1 user rule = 15
        assert_eq!(nft.len(), 15);

        let user_rule = &nft[12]["add"]["rule"];
        let expr = user_rule["expr"].as_array().unwrap();

        // Should have source match (1) + accept (1) = 2
        // Protocol match and port match should be absent
        assert_eq!(expr.len(), 2);

        // Check source match - should use prefix object format per libnftables-json(5)
        let src_match = &expr[0]["match"];
        let right = &src_match["right"];
        assert_eq!(right["prefix"]["addr"], "192.168.1.0");
        assert_eq!(right["prefix"]["len"], 24);

        // Check for absence of meta l4proto
        let json_str = serde_json::to_string(user_rule).unwrap();
        assert!(!json_str.contains("l4proto"));
        assert!(!json_str.contains("dport"));
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

        // Verify correct ordering (loopback → invalid → established → drop redirects → icmp → icmpv6)
        assert_eq!(rule_comments[0], "allow from loopback");
        assert_eq!(rule_comments[1], "early drop of invalid connections");
        assert_eq!(rule_comments[2], "allow tracked connections");
        assert_eq!(rule_comments[3], "drop icmp redirects");
        assert_eq!(rule_comments[4], "drop icmpv6 redirects");
        assert_eq!(rule_comments[5], "allow icmp");
        assert_eq!(rule_comments[6], "allow icmp v6");
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
                    "Comment '{}' appears out of order in text output. Expected after position {}, found at {}",
                    comment,
                    last_pos,
                    pos
                );
                last_pos = pos;
            } else {
                panic!("Comment '{}' found in JSON but not in text output", comment);
            }
        }

        // Verify all expected rules are present
        assert_eq!(
            json_comments.len(),
            10,
            "Should have 7 base rules + 3 user rules"
        );
        assert_eq!(json_comments[7], "SSH Access");
        assert_eq!(json_comments[8], "Web Server");
        assert_eq!(json_comments[9], "DNS");
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
            let mut rule = test_rule(
                label,
                Protocol::Tcp,
                vec![PortEntry::Single(8000 + i as u16)],
            );
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
                panic!("User rule '{}' not found in text output", label);
            });
            assert!(
                pos > last_pos,
                "User rule '{}' appears out of order in text",
                label
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

    prop_compose! {
        fn arb_rule()(
            label in "[a-zA-Z0-9 ]{0,64}",
            protocol in prop_oneof![
                Just(Protocol::Tcp),
                Just(Protocol::Udp),
                Just(Protocol::Any),
            ],
            port_entries in proptest::option::of(arb_port_entry()),
        ) -> Rule {
            Rule {
                id: Uuid::new_v4(),
                label,
                protocol,
                ports: port_entries.unwrap_or_default(),
                sources: vec![],
                destinations: vec![],
                interface: None,
                output_interface: None,
                chain: crate::core::firewall::Chain::Input,
                enabled: true,
                tags: Vec::new(),
                created_at: Utc::now(),
                // Advanced options
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
            }
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
            prop_assert!(nft_array.len() >= 14);
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
    //! Integration tests for DRFW core functionality.
    //!
    //! **Note on privilege requirements:**
    //! Some tests require nftables to verify rulesets, which needs elevated privileges
    //! even with the `--check` flag. These tests will gracefully skip if:
    //! - `nft` is not installed
    //! - The test lacks necessary privileges
    //!
    //! To run the full integration test suite with verification:
    //! ```bash
    //! sudo -E cargo test integration_tests -- --nocapture
    //! ```
    //!
    //! **Note on test organization:**
    //! - Snapshot validation tests are in `nft_json.rs` (authoritative)
    //! - Verification tests that need nft binary are here
    //! - Checksum tests are in `nft_json.rs` (close to implementation)

    use crate::core::firewall::{FirewallRuleset, PortEntry, Protocol};
    use crate::core::test_helpers::{
        create_test_rule, create_test_ruleset, setup_test_elevation_bypass,
    };
    use crate::core::verify;

    /// Helper to check if nft is available and accessible (async version for tokio tests)
    async fn is_nft_available() -> bool {
        tokio::process::Command::new("nft")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Helper to check if verification result indicates permission issues
    fn is_permission_error(errors: &[String]) -> bool {
        errors.iter().any(|e| {
            e.contains("Operation not permitted")
                || e.contains("Cannot run program --action")
                || e.contains("cache initialization")
        })
    }

    #[tokio::test]
    async fn test_verify_valid_ruleset() {
        setup_test_elevation_bypass();
        if !is_nft_available().await {
            eprintln!("Skipping test: nft not available");
            return;
        }

        let ruleset = create_test_ruleset();
        let json = ruleset.to_nftables_json();
        let result = verify::verify_ruleset(json).await;

        assert!(
            result.is_ok(),
            "Valid ruleset should pass verification: {:?}",
            result.err()
        );
        let verify_result = result.unwrap();

        // Skip if we don't have privileges (expected in non-elevated test environment)
        if !verify_result.success && is_permission_error(&verify_result.errors) {
            eprintln!(
                "Skipping test: nft verification requires elevated privileges or nft is unavailable"
            );
            return;
        }

        assert!(
            verify_result.success,
            "Verification should succeed. Errors: {:?}",
            verify_result.errors
        );
        assert!(
            verify_result.errors.is_empty(),
            "Should have no errors: {:?}",
            verify_result.errors
        );
    }

    #[tokio::test]
    async fn test_verify_invalid_port_range() {
        setup_test_elevation_bypass();
        if !is_nft_available().await {
            eprintln!("Skipping test: nft not available");
            return;
        }

        let mut ruleset = FirewallRuleset::new();
        // This is actually valid since we create the port range correctly,
        // but let's test the verification anyway
        let mut rule = create_test_rule("Test Invalid", Some(22));
        rule.ports = vec![PortEntry::Range {
            start: 1,
            end: 65535,
        }];
        rule.rebuild_caches();
        ruleset.rules.push(rule);

        let json = ruleset.to_nftables_json();
        let result = verify::verify_ruleset(json).await;
        // This should actually succeed since it's a valid (though broad) range
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_audit_logging_integration() {
        // This test verifies that audit logging doesn't panic
        // We can't easily test the file contents without mocking
        let ruleset = create_test_ruleset();
        let rule_count = ruleset.rules.len();
        let enabled_count = ruleset.rules.iter().filter(|r| r.enabled).count();

        // These should not panic
        crate::audit::log_apply(true, rule_count, enabled_count, true, None).await;
        crate::audit::log_apply(
            true,
            rule_count,
            enabled_count,
            false,
            Some("Test error".to_string()),
        )
        .await;

        // Success if we reach here without panicking
    }

    #[tokio::test]
    async fn test_verify_empty_ruleset() {
        setup_test_elevation_bypass();
        if !is_nft_available().await {
            eprintln!("Skipping test: nft not available");
            return;
        }

        let ruleset = FirewallRuleset::new();
        let json = ruleset.to_nftables_json();
        let result = verify::verify_ruleset(json).await;

        assert!(
            result.is_ok(),
            "Empty ruleset should pass verification: {:?}",
            result.err()
        );
        let verify_result = result.unwrap();

        // Skip if we don't have privileges (expected in non-elevated test environment)
        if !verify_result.success && is_permission_error(&verify_result.errors) {
            eprintln!(
                "Skipping test: nft verification requires elevated privileges or nft is unavailable"
            );
            return;
        }

        assert!(
            verify_result.success,
            "Empty ruleset verification should succeed. Errors: {:?}",
            verify_result.errors
        );
    }

    #[tokio::test]
    async fn test_verify_multiple_rules() {
        use crate::core::test_helpers::create_test_rule;

        setup_test_elevation_bypass();
        if !is_nft_available().await {
            eprintln!("Skipping test: nft not available");
            return;
        }

        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(create_test_rule("Test SSH", Some(22)));
        ruleset.rules.push(create_test_rule("Test HTTP", Some(80)));
        ruleset
            .rules
            .push(create_test_rule("Test HTTPS", Some(443)));

        let json = ruleset.to_nftables_json();
        let result = verify::verify_ruleset(json).await;

        assert!(
            result.is_ok(),
            "Multiple rules should pass verification: {:?}",
            result.err()
        );
        let verify_result = result.unwrap();

        // Skip if we don't have privileges (expected in non-elevated test environment)
        if !verify_result.success && is_permission_error(&verify_result.errors) {
            eprintln!(
                "Skipping test: nft verification requires elevated privileges or nft is unavailable"
            );
            return;
        }

        assert!(
            verify_result.success,
            "Multi-rule verification should succeed. Errors: {:?}",
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

        // Should have base rules (14) + 3 user rules
        assert_eq!(nft_array.len(), 17);

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
            "JSON should contain 'ct count' key, got: {}",
            json_str
        );
        assert!(
            json_str.contains(r#""val": 5"#),
            "JSON should contain 'val': 5, got: {}",
            json_str
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
            "Text should contain 'ct count 3', got: {}",
            text
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
                    .map(|s| s == "Mixed IPs")
                    .unwrap_or(false)
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
                    .map(|s| s == "IPv4 Only")
                    .unwrap_or(false)
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
                    .map(|s| s == "Single IPv4 Host")
                    .unwrap_or(false)
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
                    .map(|s| s == "saddr")
                    .unwrap_or(false)
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
                    .map(|s| s == "Single IPv6 Host")
                    .unwrap_or(false)
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
                    .map(|s| s == "saddr")
                    .unwrap_or(false)
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
                    .map(|s| s == "IPv4 Network")
                    .unwrap_or(false)
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
                    .map(|s| s == "saddr")
                    .unwrap_or(false)
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
                    .map(|s| s == "IPv6 Network")
                    .unwrap_or(false)
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
                    .map(|s| s == "saddr")
                    .unwrap_or(false)
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
                    .map(|s| s == "Non-Canonical CIDR")
                    .unwrap_or(false)
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
                    .map(|s| s == "saddr")
                    .unwrap_or(false)
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
                    .map(|s| s == "Any IPv4")
                    .unwrap_or(false)
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
                    .map(|s| s == "saddr")
                    .unwrap_or(false)
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
                    .map(|s| s == "Mixed IP Types")
                    .unwrap_or(false)
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
                    .map(|s| s == "saddr")
                    .unwrap_or(false)
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
                    .map(|s| s == "No IP Filter")
                    .unwrap_or(false)
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
