#[cfg(test)]
mod tests_impl {
    use crate::core::firewall::{FirewallRuleset, PortRange, Protocol, Rule};
    use chrono::Utc;
    use uuid::Uuid;

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
        ruleset.rules.push(Rule {
            id: Uuid::nil(),
            label: "Allow SSH".to_string(),
            protocol: Protocol::Tcp,
            ports: Some(PortRange::single(22)),
            source: None,
            interface: None,
            ipv6_only: false,
            enabled: true,
            created_at: Utc::now(),
        });

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
        ruleset.rules.push(Rule {
            id: Uuid::nil(),
            label: "Allow HTTP".to_string(),
            protocol: Protocol::Tcp,
            ports: Some(PortRange::single(80)),
            source: None,
            interface: None,
            ipv6_only: false,
            enabled: true,
            created_at: Utc::now(),
        });

        let text = ruleset.to_nft_text();
        assert!(text.contains("tcp dport 80 accept comment \"Allow HTTP\""));
        assert!(text.contains("policy drop"));
    }

    #[test]
    fn test_any_protocol_rule_json() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(Rule {
            id: Uuid::nil(),
            label: "Allow All LAN".to_string(),
            protocol: Protocol::Any,
            ports: Some(PortRange::single(80)), // Ports should be ignored
            source: Some("192.168.1.0/24".parse().unwrap()),
            interface: None,
            ipv6_only: false,
            enabled: true,
            created_at: Utc::now(),
        });

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
        for item in nft.iter() {
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
        for item in nft.iter() {
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
}

#[cfg(test)]
mod property_tests {
    use crate::core::firewall::{FirewallRuleset, PortRange, Protocol, Rule};
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
        fn arb_rule()(
            label in "[a-zA-Z0-9 ]{0,64}",
            protocol in prop_oneof![
                Just(Protocol::Tcp),
                Just(Protocol::Udp),
                Just(Protocol::Any),
            ],
            port_range in proptest::option::of(arb_port_range()),
        ) -> Rule {
            Rule {
                id: Uuid::new_v4(),
                label,
                protocol,
                ports: port_range,
                source: None,
                interface: None,
                ipv6_only: false,
                enabled: true,
                created_at: Utc::now(),
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
    //! Without elevated privileges, verification tests will skip but other
    //! integration tests (checksums, audit logging, JSON generation) will run.

    use crate::core::firewall::{FirewallRuleset, PortRange, Protocol, Rule};
    use crate::core::nft_json;
    use crate::core::verify;
    use chrono::Utc;
    use uuid::Uuid;

    /// Helper to check if nft is available and accessible
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

    /// Helper to create a simple test ruleset
    fn create_test_ruleset() -> FirewallRuleset {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(Rule {
            id: Uuid::new_v4(),
            label: "Test SSH".to_string(),
            protocol: Protocol::Tcp,
            ports: Some(PortRange::single(22)),
            source: None,
            interface: None,
            ipv6_only: false,
            enabled: true,
            created_at: Utc::now(),
        });
        ruleset
    }

    #[tokio::test]
    async fn test_verify_valid_ruleset() {
        if !is_nft_available().await {
            eprintln!("Skipping test: nft not available");
            return;
        }

        let ruleset = create_test_ruleset();
        let result = verify::verify_ruleset(&ruleset).await;

        assert!(
            result.is_ok(),
            "Valid ruleset should pass verification: {:?}",
            result.err()
        );
        let verify_result = result.unwrap();

        // Skip if we don't have privileges (expected in non-elevated test environment)
        if !verify_result.success
            && verify_result
                .errors
                .iter()
                .any(|e| e.contains("Operation not permitted"))
        {
            eprintln!("Skipping test: nft verification requires elevated privileges");
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
        if !is_nft_available().await {
            eprintln!("Skipping test: nft not available");
            return;
        }

        let mut ruleset = FirewallRuleset::new();
        // This is actually valid since we create the PortRange correctly,
        // but let's test the verification anyway
        ruleset.rules.push(Rule {
            id: Uuid::new_v4(),
            label: "Test Invalid".to_string(),
            protocol: Protocol::Tcp,
            ports: Some(PortRange {
                start: 1,
                end: 65535,
            }),
            source: None,
            interface: None,
            ipv6_only: false,
            enabled: true,
            created_at: Utc::now(),
        });

        let result = verify::verify_ruleset(&ruleset).await;
        // This should actually succeed since it's a valid (though broad) range
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_snapshot_checksum_consistency() {
        let ruleset = create_test_ruleset();
        let json = ruleset.to_nftables_json();

        let checksum1 = nft_json::compute_checksum(&json);
        let checksum2 = nft_json::compute_checksum(&json);

        assert_eq!(checksum1, checksum2, "Checksums should be deterministic");
        assert_eq!(checksum1.len(), 64, "SHA-256 hex should be 64 chars");
    }

    #[tokio::test]
    async fn test_snapshot_checksum_changes_on_modification() {
        let mut ruleset1 = create_test_ruleset();
        let json1 = ruleset1.to_nftables_json();
        let checksum1 = nft_json::compute_checksum(&json1);

        // Modify the ruleset
        ruleset1.rules.push(Rule {
            id: Uuid::new_v4(),
            label: "Test HTTP".to_string(),
            protocol: Protocol::Tcp,
            ports: Some(PortRange::single(80)),
            source: None,
            interface: None,
            ipv6_only: false,
            enabled: true,
            created_at: Utc::now(),
        });

        let json2 = ruleset1.to_nftables_json();
        let checksum2 = nft_json::compute_checksum(&json2);

        assert_ne!(
            checksum1, checksum2,
            "Checksums should differ for different rulesets"
        );
    }

    #[tokio::test]
    async fn test_audit_logging_integration() {
        // This test verifies that audit logging doesn't panic
        // We can't easily test the file contents without mocking
        let ruleset = create_test_ruleset();
        let rule_count = ruleset.rules.len();
        let enabled_count = ruleset.rules.iter().filter(|r| r.enabled).count();

        // This should not panic
        crate::audit::log_apply(rule_count, enabled_count, true, None).await;
        crate::audit::log_apply(
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
        if !is_nft_available().await {
            eprintln!("Skipping test: nft not available");
            return;
        }

        let ruleset = FirewallRuleset::new();
        let result = verify::verify_ruleset(&ruleset).await;

        assert!(
            result.is_ok(),
            "Empty ruleset should pass verification: {:?}",
            result.err()
        );
        let verify_result = result.unwrap();

        // Skip if we don't have privileges (expected in non-elevated test environment)
        if !verify_result.success
            && verify_result
                .errors
                .iter()
                .any(|e| e.contains("Operation not permitted"))
        {
            eprintln!("Skipping test: nft verification requires elevated privileges");
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
        if !is_nft_available().await {
            eprintln!("Skipping test: nft not available");
            return;
        }

        let mut ruleset = FirewallRuleset::new();

        // Add multiple rules
        ruleset.rules.push(Rule {
            id: Uuid::new_v4(),
            label: "Test SSH".to_string(),
            protocol: Protocol::Tcp,
            ports: Some(PortRange::single(22)),
            source: None,
            interface: None,
            ipv6_only: false,
            enabled: true,
            created_at: Utc::now(),
        });

        ruleset.rules.push(Rule {
            id: Uuid::new_v4(),
            label: "Test HTTP".to_string(),
            protocol: Protocol::Tcp,
            ports: Some(PortRange::single(80)),
            source: None,
            interface: None,
            ipv6_only: false,
            enabled: true,
            created_at: Utc::now(),
        });

        ruleset.rules.push(Rule {
            id: Uuid::new_v4(),
            label: "Test HTTPS".to_string(),
            protocol: Protocol::Tcp,
            ports: Some(PortRange::single(443)),
            source: None,
            interface: None,
            ipv6_only: false,
            enabled: true,
            created_at: Utc::now(),
        });

        let result = verify::verify_ruleset(&ruleset).await;

        assert!(
            result.is_ok(),
            "Multiple rules should pass verification: {:?}",
            result.err()
        );
        let verify_result = result.unwrap();

        // Skip if we don't have privileges (expected in non-elevated test environment)
        if !verify_result.success
            && verify_result
                .errors
                .iter()
                .any(|e| e.contains("Operation not permitted"))
        {
            eprintln!("Skipping test: nft verification requires elevated privileges");
            return;
        }

        assert!(
            verify_result.success,
            "Multi-rule verification should succeed. Errors: {:?}",
            verify_result.errors
        );
    }

    #[tokio::test]
    async fn test_json_generation_with_all_protocol_types() {
        let mut ruleset = FirewallRuleset::new();

        // TCP rule
        ruleset.rules.push(Rule {
            id: Uuid::new_v4(),
            label: "TCP Rule".to_string(),
            protocol: Protocol::Tcp,
            ports: Some(PortRange::single(80)),
            source: None,
            interface: None,
            ipv6_only: false,
            enabled: true,
            created_at: Utc::now(),
        });

        // UDP rule
        ruleset.rules.push(Rule {
            id: Uuid::new_v4(),
            label: "UDP Rule".to_string(),
            protocol: Protocol::Udp,
            ports: Some(PortRange::single(53)),
            source: None,
            interface: None,
            ipv6_only: false,
            enabled: true,
            created_at: Utc::now(),
        });

        // Any protocol rule
        ruleset.rules.push(Rule {
            id: Uuid::new_v4(),
            label: "Any Protocol".to_string(),
            protocol: Protocol::Any,
            ports: None,
            source: Some("192.168.1.0/24".parse().unwrap()),
            interface: None,
            ipv6_only: false,
            enabled: true,
            created_at: Utc::now(),
        });

        let json = ruleset.to_nftables_json();
        let nft_array = json["nftables"].as_array().unwrap();

        // Should have base rules (14) + 3 user rules
        assert_eq!(nft_array.len(), 17);

        // Verify JSON can be serialized
        let json_str = serde_json::to_string(&json);
        assert!(json_str.is_ok(), "JSON should serialize successfully");
    }
}
