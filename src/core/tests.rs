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

        // Check source match
        let src_match = &expr[0]["match"];
        assert_eq!(src_match["right"], "192.168.1.0/24");

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
}
