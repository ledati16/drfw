#[cfg(test)]
mod tests_impl {
    use jiff::Timestamp;
    use uuid::Uuid;

    use crate::core::firewall::{Action, FirewallRuleset, PortEntry, Protocol, RejectType, Rule};

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
            created_at: Timestamp::now(),
            action: Action::Accept,
            reject_type: RejectType::Default,
            rate_limit: None,
            connection_limit: 0,
            connection_limit_per_source: false,
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

        // table(3: add, delete, add) + chains(3) + base(9: lo, invalid, icmp_redir,
        // icmpv6_redir, ct, loopback src, loopback dst, dhcp, dhcpv6) + local(1: igmp)
        // + icmp(2) + rejection(1) + counter(1) = 20
        assert_eq!(nft.len(), 20);

        assert_eq!(nft[0]["add"]["table"]["name"], "drfw");
        assert_eq!(nft[1]["delete"]["table"]["name"], "drfw");
        assert_eq!(nft[2]["add"]["table"]["name"], "drfw");
    }
    /// Index of the first user rule in a default ruleset: table setup (3),
    /// chains (3), loopback, invalid, two redirect drops, established, two
    /// loopback-address drops, DHCP, `DHCPv6`. The IGMP and ICMP allow rules
    /// follow the user rules.
    const FIRST_USER_RULE: usize = 15;

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

        // 20 base + 1 user rule = 21
        assert_eq!(nft.len(), 21);

        let user_rule = &nft[FIRST_USER_RULE]["add"]["rule"];
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

        // 20 base + 1 user rule = 21
        assert_eq!(nft.len(), 21);

        let user_rule = &nft[FIRST_USER_RULE]["add"]["rule"];
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
        let user_rule = &json["nftables"][FIRST_USER_RULE]["add"]["rule"];
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
        let expr = json["nftables"][FIRST_USER_RULE]["add"]["rule"]["expr"]
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

        // Redirect drops before the established/related accept (a redirect
        // quoting one of our connections is `related`); checks of new
        // packets after it; IGMP and ICMP after the (no) user rules
        assert_eq!(
            rule_comments,
            [
                "allow from loopback",
                "early drop of invalid connections",
                "drop icmp redirects",
                "drop icmpv6 redirects",
                "allow tracked connections",
                "drop loopback source addresses from the network",
                "drop loopback destination addresses from the network",
                "allow dhcp client replies",
                "allow dhcpv6 client replies",
                "allow igmp (multicast group membership)",
                "allow icmp",
                "allow icmp v6",
                "rate-limited reject",
                "final counter",
            ]
        );
        let text = ruleset.to_nft_text();
        for line in [
            "icmp type redirect drop comment \"drop icmp redirects\"",
            "iifname != \"lo\" ip saddr 127.0.0.0/8 drop comment",
            "iifname != \"lo\" ip daddr 127.0.0.0/8 drop comment",
            "udp sport 67 udp dport 68 accept comment \"allow dhcp client replies\"",
            "ip protocol igmp accept comment \"allow igmp (multicast group membership)\"",
            "pkttype host limit rate 5/second burst 5 packets counter reject with icmpx type admin-prohibited",
        ] {
            assert!(text.contains(line), "{line} missing:\n{text}");
        }
    }

    /// The ICMP rate limit drops echo requests over the limit, before the
    /// established accept (every echo request of a running ping is
    /// `established`); the ICMP accepts carry no limit, so neighbor
    /// discovery, router advertisements and MLD are never limited.
    #[test]
    fn test_icmp_rate_limit_limits_echo_requests_before_established() {
        for strict in [false, true] {
            let mut ruleset = FirewallRuleset::new();
            ruleset.advanced_security.strict_icmp = strict;
            ruleset.advanced_security.icmp_rate_limit = 10;
            let json = ruleset.to_nftables_json();
            let comments: Vec<&str> = json["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|item| item["add"]["rule"]["comment"].as_str())
                .collect();
            let at = |c: &str| comments.iter().position(|x| *x == c).unwrap();
            assert!(at("drop icmpv6 redirects") < at("limit incoming pings"));
            assert!(at("limit incoming pings (ipv6)") < at("allow tracked connections"));
            let text = ruleset.to_nft_text();
            for line in [
                "meta l4proto icmp icmp type echo-request limit rate over 10/second burst 5 packets drop comment \"limit incoming pings\"",
                "meta l4proto ipv6-icmp icmpv6 type echo-request limit rate over 10/second burst 5 packets drop comment \"limit incoming pings (ipv6)\"",
            ] {
                assert!(text.contains(line), "{line} missing:\n{text}");
            }
            assert_eq!(
                text.matches("limit rate").count(),
                3,
                "pings + final reject:\n{text}"
            );
            assert!(!text.contains("neighbor discovery (not rate limited)"));
        }
        let text = FirewallRuleset::new().to_nft_text();
        assert!(!text.contains("echo-request limit"), "{text}");
    }

    /// Strict `ICMPv6` accepts the types RFC 4890 4.4.1 says must not be
    /// dropped, including router solicitations and MLD reports (hosts that
    /// act as a router for VMs or a hotspot receive them).
    #[test]
    fn test_strict_icmpv6_types() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.advanced_security.strict_icmp = true;
        let text = ruleset.to_nft_text();
        assert!(
            text.contains(
                "meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, \
                 time-exceeded, parameter-problem, echo-request, echo-reply, mld-listener-query, \
                 mld-listener-report, mld-listener-done, nd-router-solicit, nd-router-advert, \
                 nd-neighbor-solicit, nd-neighbor-advert, mld2-listener-report } accept \
                 comment \"allow essential icmpv6 (strict mode)\""
            ),
            "{text}"
        );
        assert!(text.contains(
            "meta l4proto icmp icmp type { echo-reply, destination-unreachable, echo-request, \
             time-exceeded, parameter-problem } accept comment \"allow essential icmp (strict mode)\""
        ));
    }

    /// User rules sit between the redirect drops and the ICMP allow rules,
    /// in strict and default ICMP mode, so a user Drop rule also stops ICMP.
    #[test]
    fn test_user_rules_come_before_icmp_allow_rules() {
        for strict in [false, true] {
            let mut ruleset = FirewallRuleset::new();
            ruleset.advanced_security.strict_icmp = strict;
            let mut rule = test_rule("Drop peer", Protocol::Any, vec![]);
            rule.action = Action::Drop;
            rule.sources = vec!["192.0.2.7".parse().unwrap()];
            ruleset.rules.push(rule);
            let json = ruleset.to_nftables_json();
            let comments: Vec<&str> = json["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|item| item["add"]["rule"]["comment"].as_str())
                .collect();
            let user = comments.iter().position(|c| *c == "Drop peer").unwrap();
            let redirects = comments
                .iter()
                .position(|c| *c == "drop icmpv6 redirects")
                .unwrap();
            let first_icmp_allow = comments
                .iter()
                .position(|c| c.starts_with("allow") && c.contains("icmp"))
                .unwrap();
            assert!(redirects < user && user < first_icmp_allow, "{comments:?}");
            // The text form keeps the order (and a section heading per part)
            let text = ruleset.to_nft_text();
            let pos = |needle: &str| text.find(needle).unwrap();
            assert!(pos("\"Drop peer\"") < pos("# --- ICMP ---"), "{text}");
        }
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
        assert_eq!(comments[4], "allow tracked connections");
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
            17,
            "Should have 14 base rules + 3 user rules"
        );
        // 9 base rules, the user rules, then IGMP and the 2 ICMP allow rules
        assert_eq!(json_comments[9], "SSH Access");
        assert_eq!(json_comments[10], "Web Server");
        assert_eq!(json_comments[11], "DNS");
        assert_eq!(json_comments[12], "allow igmp (multicast group membership)");
        assert_eq!(json_comments[13], "allow icmp");
        assert_eq!(json_comments[14], "allow icmp v6");
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
            let port = 8000 + u16::try_from(i).unwrap();
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
            // Skip table setup, chains, base rules
            if let Some(rule) = item.get("add").and_then(|a| a.get("rule"))
                && let Some(comment) = rule.get("comment").and_then(|c| c.as_str())
                && !comment.starts_with("allow")  // Skip base rule comments
                && !comment.starts_with("drop")
                && !comment.starts_with("early")
                && !["rate-limited reject", "final counter"].contains(&comment)
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
    use jiff::Timestamp;
    use proptest::prelude::*;
    use uuid::Uuid;

    use crate::core::firewall::{
        Action, FirewallRuleset, PortEntry, PortRange, Protocol, RejectType, Rule,
    };

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
            // Generated: any control character, quotes, backslashes, nft syntax
            HOSTILE_TEXT.prop_map(|s| s.chars().take(15).collect()),
        ])
    }

    /// Text with control characters (newline, CR, tab, NUL, ESC, DEL), quotes,
    /// backslashes and nft syntax mixed into printable text: `\PC` alone never
    /// generates control characters, so injection by newline would go untested.
    const HOSTILE_TEXT: &str = "(\\PC|[\\x00-\\x1f\\x7f\"\\\\#;{}])*";

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
            label in HOSTILE_TEXT.prop_map(|s| s.chars().take(40).collect::<String>()),
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
            tags in prop::collection::vec(
                HOSTILE_TEXT.prop_map(|s| s.chars().take(24).collect::<String>()),
                0..3,
            ),
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
                Timestamp::now(),
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
                per_source: false,
            });
            rule.connection_limit = connection_limit;
            rule.log_enabled = log_enabled;
            rule.rebuild_caches();
            rule
        }
    }

    proptest! {
        #[test]
        fn test_rule_json_generation_never_panics(rule in arb_rule()) {
            let mut ruleset = FirewallRuleset::new();
            ruleset.rules.push(rule);

            let json = ruleset.to_nftables_json();

            // Should be valid JSON structure
            prop_assert!(json.is_object());
            prop_assert!(json["nftables"].is_array());
        }

        /// A rule survives the profile format (serde JSON) unchanged once its
        /// caches are rebuilt, as on every profile load.
        #[test]
        fn test_rule_serde_roundtrip(rule in arb_rule()) {
            let json = serde_json::to_string(&rule).expect("serialize rule");
            let mut parsed: Rule = serde_json::from_str(&json).expect("parse rule");
            parsed.rebuild_caches();
            prop_assert_eq!(&parsed, &rule);
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

            // At most one copy per address family, or two (one per limit)
            // for a Drop/Reject rule with both a rate and a connection limit
            let split = rule.action != Action::Accept
                && rule.rate_limit.is_some()
                && rule.connection_limit > 0;
            let max_copies = if split { 4 } else { 2 };
            prop_assert!(user_rules.len() <= max_copies, "{} copies", user_rules.len());
        }

        /// Whatever the rules and settings, DRFW's output passes the root
        /// helper's table check, and the save payload root renders is
        /// exactly the preview text.
        #[test]
        fn test_generated_rulesets_pass_the_root_payload_check(
            rules in prop::collection::vec(
                (arb_rule(), any::<bool>(), any::<bool>(), any::<bool>()),
                0..6,
            ),
            settings in any::<[bool; 7]>(),
        ) {
            use crate::core::firewall::{Chain, EgressProfile};
            use crate::core::root_payload::{SavePayload, check_ruleset_json};
            let mut ruleset = FirewallRuleset::new();
            for (mut rule, per_source, conn_per_source, forward) in rules {
                if let Some(limit) = &mut rule.rate_limit {
                    limit.per_source = per_source;
                }
                rule.connection_limit_per_source = conn_per_source;
                if forward {
                    rule.chain = Chain::Forward;
                }
                rule.rebuild_caches();
                ruleset.rules.push(rule);
            }
            let [strict_icmp, icmp_limit, rpf, log_dropped, server, block_forwarding, discovery] =
                settings;
            let advanced = &mut ruleset.advanced_security;
            advanced.strict_icmp = strict_icmp;
            advanced.icmp_rate_limit = if icmp_limit { 10 } else { 0 };
            advanced.enable_rpf = rpf;
            advanced.log_dropped = log_dropped;
            advanced.egress_profile = if server { EgressProfile::Server } else { EgressProfile::Desktop };
            advanced.block_forwarding = block_forwarding;
            advanced.local_discovery = discovery;

            let json = serde_json::to_vec(&ruleset.to_nftables_json()).expect("json");
            prop_assert_eq!(check_ruleset_json(&json), Ok(()));
            prop_assert_eq!(crate::helper::check_payload(&json), Ok(()));
            let rendered = SavePayload::of_ruleset(&ruleset).render();
            prop_assert_eq!(rendered, Ok(ruleset.to_nft_text()));
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
        fn test_multiple_rules_json_generation(rules in prop::collection::vec(arb_rule(), 0..10)) {
            let mut ruleset = FirewallRuleset::new();
            ruleset.rules = rules;

            let json = ruleset.to_nftables_json();
            let nft_array = json["nftables"].as_array().unwrap();

            // At least the commands of an empty ruleset (table, chains, base
            // rules); user rules only add to them
            let base = FirewallRuleset::new().to_nftables_json();
            prop_assert!(nft_array.len() >= base["nftables"].as_array().unwrap().len());
        }

        #[test]
        fn test_rate_limit_serialization_roundtrip(
            count in 1u32..1000,
            unit_idx in 0usize..4
        ) {
            use crate::core::firewall::{RateLimit, TimeUnit};

            let units = [TimeUnit::Second, TimeUnit::Minute, TimeUnit::Hour, TimeUnit::Day];
            let rate_limit = RateLimit { count, unit: units[unit_idx], burst: None, per_source: false };

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
            let rate_limit = RateLimit { count, unit: units[unit_idx], burst: None, per_source: false };

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
    //! - JSON generation tests are here (close to implementation)
    //!
    //! Tests that exercise the verification flow should be in `tests/integration_tests.rs`
    //! to avoid duplication.

    use crate::core::firewall::{FirewallRuleset, PortEntry, Protocol};
    use crate::core::test_helpers::create_test_rule;

    /// Every filter of every rule (source, interface, port range) reaches
    /// the generated text.
    #[test]
    fn test_rule_filters_reach_generated_text() {
        use crate::core::test_helpers::create_full_test_rule;
        let mut ruleset = FirewallRuleset::new();

        // Rule with source filter
        ruleset.rules.push(create_full_test_rule(
            "With Source",
            Protocol::Tcp,
            Some(22),
            Some("10.0.0.0/8"),
            None,
        ));

        // Rule with interface filter
        ruleset.rules.push(create_full_test_rule(
            "With Interface",
            Protocol::Tcp,
            Some(80),
            None,
            Some("eth0"),
        ));

        // Rule with port range (needs custom construction)
        let mut port_range_rule =
            create_full_test_rule("Port Range", Protocol::Tcp, None, None, None);
        port_range_rule.ports = vec![PortEntry::Range {
            start: 8000,
            end: 8999,
        }];
        port_range_rule.rebuild_caches();
        ruleset.rules.push(port_range_rule);

        // Rule with everything
        ruleset.rules.push(create_full_test_rule(
            "Everything",
            Protocol::Udp,
            Some(53),
            Some("8.8.8.8/32"),
            Some("wlan0"),
        ));

        // Every filter of every rule reaches the generated rules
        let text = ruleset.to_nft_text();
        for expected in [
            "ip saddr 10.0.0.0/8 tcp dport 22",
            "iifname \"eth0\" tcp dport 80",
            "tcp dport 8000-8999",
            "iifname \"wlan0\" ip saddr 8.8.8.8 udp dport 53",
        ] {
            assert!(text.contains(expected), "{expected:?} missing:\n{text}");
        }
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

        // Should have base rules (20) + 3 user rules
        assert_eq!(nft_array.len(), 23);

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
            per_source: false,
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
        Action, Chain, CommandOrigin, EgressProfile, FirewallRuleset, NftCommand, PortEntry,
        Protocol, RateLimit, TimeUnit,
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
                per_source: false,
            });
            rule.connection_limit = 3;
            rule.rebuild_caches();
            ruleset.rules.push(rule);

            let exprs = user_rule_exprs(&ruleset);
            let find = |key: &str| {
                exprs
                    .iter()
                    .flat_map(|e| e.as_array().unwrap())
                    .find_map(|e| e.get(key))
                    .unwrap()
                    .clone()
            };
            let (limit, count) = (find("limit"), find("ct count"));
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

    /// "Over the rate OR over the count" for Drop/Reject: two rules with the
    /// same matches, one limit each. A single rule would AND them, and since
    /// `limit` stops evaluation, `ct count` would only see over-rate packets.
    /// Accept keeps one rule ("under the rate AND under the count").
    #[test]
    fn test_inverted_rate_and_connection_limits_are_separate_rules() {
        for (action, rules) in [(Action::Accept, 1), (Action::Drop, 2), (Action::Reject, 2)] {
            let mut ruleset = FirewallRuleset::new();
            let mut rule = create_test_rule("Both", Some(22));
            rule.action = action;
            rule.sources = vec!["10.0.0.0/8".parse().unwrap()];
            rule.rate_limit = Some(RateLimit {
                count: 5,
                unit: TimeUnit::Second,
                burst: Some(10),
                per_source: false,
            });
            rule.connection_limit = 3;
            rule.log_enabled = true;
            rule.rebuild_caches();
            let id = rule.id;
            ruleset.rules.push(rule);

            let cmds = ruleset.build_commands();
            let user: Vec<&NftCommand> = cmds
                .iter()
                .filter(|c| c.origin == CommandOrigin::UserRule(id))
                .collect();
            assert_eq!(user.len(), rules, "{action:?}");
            let exprs: Vec<&Vec<serde_json::Value>> = user
                .iter()
                .map(|c| c.value["add"]["rule"]["expr"].as_array().unwrap())
                .collect();
            let has = |e: &[serde_json::Value], key: &str| e.iter().any(|x| x.get(key).is_some());
            if rules == 1 {
                assert!(has(exprs[0], "limit") && has(exprs[0], "ct count"));
                continue;
            }
            assert!(has(exprs[0], "limit") && !has(exprs[0], "ct count"));
            assert!(!has(exprs[1], "limit") && has(exprs[1], "ct count"));
            // Same matches (protocol, source, port), log and action in both
            let strip = |e: &[serde_json::Value]| -> Vec<serde_json::Value> {
                e.iter()
                    .filter(|x| x.get("limit").is_none() && x.get("ct count").is_none())
                    .cloned()
                    .collect()
            };
            assert_eq!(strip(exprs[0]), strip(exprs[1]), "{action:?}");
            assert!(has(exprs[0], "log") && has(exprs[1], "log"));

            let text = ruleset.to_nft_text();
            assert!(
                text.contains("limit rate over 5/second burst 10 packets log"),
                "{text}"
            );
            assert!(text.contains("ct count over 3 log"), "{text}");
            assert!(!text.contains("limit rate over 5/second burst 10 packets ct count"));
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
                "allow outbound igmp (multicast group membership)",
                "allow outbound dhcp client requests",
                "allow outbound dhcpv6 client requests",
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
        assert!(!settings.local_discovery, "existing profiles do not change");
    }

    /// Forward rules go into the forward chain, after its base rules, only
    /// with "Block forwarded traffic" on; both interfaces are matched.
    #[test]
    fn test_forward_user_rules() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Routed web", Some(8080));
        rule.chain = Chain::Forward;
        rule.interface = Some("veth-a".into());
        rule.output_interface = Some("veth-b".into());
        rule.rebuild_caches();
        ruleset.rules.push(rule);
        let text = ruleset.to_nft_text();
        assert!(
            !text.contains("Routed web"),
            "forward policy accepts: {text}"
        );

        ruleset.advanced_security.block_forwarding = true;
        let cmds = ruleset.build_commands();
        let comments: Vec<&str> = rules_in_chain(&cmds, "forward")
            .iter()
            .filter_map(|r| r["comment"].as_str())
            .collect();
        assert_eq!(
            comments,
            [
                "drop invalid forwarded connections",
                "allow tracked forwarded connections",
                "Routed web"
            ]
        );
        assert!(
            rules_in_chain(&cmds, "input")
                .iter()
                .all(|r| r["comment"] != "Routed web")
        );
        let text = ruleset.to_nft_text();
        assert!(
            text.contains(
                "meta l4proto tcp iifname \"veth-a\" oifname \"veth-b\" tcp dport 8080 accept \
                 comment \"Routed web\""
            ),
            "{text}"
        );
        // Serialized as "Forward"
        let json = serde_json::to_value(&ruleset.rules[0]).unwrap();
        assert_eq!(json["chain"], "Forward");
    }

    /// Anti-spoofing: strict reverse-path check keyed with the mark (policy
    /// routing by fwmark), after the established accept and the loopback
    /// accept, before the DHCP replies and user rules.
    #[test]
    fn test_rpf_after_established_with_mark() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.advanced_security.enable_rpf = true;
        let cmds = ruleset.build_commands();
        let comments: Vec<&str> = rules_in_chain(&cmds, "input")
            .iter()
            .filter_map(|r| r["comment"].as_str())
            .collect();
        let at = |c: &str| comments.iter().position(|x| *x == c).unwrap();
        let rpf = at("drop new packets with spoofed source addresses (RPF)");
        assert!(at("allow from loopback") < rpf);
        assert!(at("allow tracked connections") < rpf);
        assert!(rpf < at("allow dhcp client replies"));
        let text = ruleset.to_nft_text();
        assert!(text.contains(
            "fib saddr . mark . iif oif missing drop comment \
             \"drop new packets with spoofed source addresses (RPF)\""
        ));
    }

    /// Local discovery: the set, the output rule that fills it, and the
    /// input accepts after the user rules and IGMP, before ICMP; Desktop
    /// mode only.
    #[test]
    fn test_local_discovery_rules() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(create_test_rule("User", Some(22)));
        ruleset.advanced_security.local_discovery = true;
        let text = ruleset.to_nft_text();
        let set = "    set discovery_reply {\n        type inet_service\n        flags dynamic,timeout\n        timeout 10s\n        size 1024\n    }";
        assert!(text.contains(set), "{text}");
        let input = [
            "ip protocol igmp accept comment \"allow igmp (multicast group membership)\"",
            "ip daddr 224.0.0.251 udp dport 5353 accept comment \"allow mdns\"",
            "ip6 daddr ff02::fb udp dport 5353 accept comment \"allow mdns (ipv6)\"",
            "ip daddr 239.255.255.250 udp dport { 1900, 3702 } accept comment \"allow ssdp and ws-discovery\"",
            "ip6 daddr { ff02::c, ff05::c } udp dport { 1900, 3702 } accept comment \"allow ssdp and ws-discovery (ipv6)\"",
            "pkttype host ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } udp dport @discovery_reply accept comment \"allow replies to our discovery queries\"",
            "pkttype host ip6 saddr { fe80::/10, fc00::/7 } udp dport @discovery_reply accept comment \"allow replies to our discovery queries (ipv6)\"",
        ];
        let mut last = text.find("comment \"User\"").unwrap();
        for line in input {
            let at = text
                .find(line)
                .unwrap_or_else(|| panic!("{line} missing:\n{text}"));
            assert!(at > last, "{line} out of order");
            last = at;
        }
        assert!(last < text.find("# --- ICMP ---").unwrap());
        // Only genuine queries fill the set: each protocol's group and port
        // (NetBIOS: broadcast to the name service port)
        let output = &text[text.find("chain output").unwrap()..];
        let update = "update @discovery_reply { udp sport } comment";
        for line in [
            "ip daddr 239.255.255.250 udp dport { 1900, 3702 }",
            "ip6 daddr { ff02::c, ff05::c } udp dport { 1900, 3702 }",
            "ip daddr 224.0.0.251 udp dport 5353",
            "ip6 daddr ff02::fb udp dport 5353",
            "ip daddr 224.0.0.252 udp dport 5355",
            "ip6 daddr ff02::1:3 udp dport 5355",
            "fib daddr type broadcast udp dport 137",
        ] {
            assert!(
                output.contains(&format!("{line} {update}")),
                "{line}:\n{output}"
            );
        }
        assert_eq!(output.matches("@discovery_reply").count(), 7, "{output}");
        assert!(!output.contains("multicast }"), "no catch-all: {output}");
        // ... and their ports are the ones Exposure knows
        let mut ports: Vec<u16> = Vec::new();
        for command in ruleset.to_nftables_json()["nftables"].as_array().unwrap() {
            let rule = &command["add"]["rule"];
            if rule["chain"] != "output" {
                continue;
            }
            for expr in rule["expr"].as_array().unwrap() {
                let m = &expr["match"];
                if m["left"]["payload"]["field"] == "dport" {
                    let port = |v: &serde_json::Value| u16::try_from(v.as_u64().unwrap()).unwrap();
                    match m["right"]["set"].as_array() {
                        Some(set) => ports.extend(set.iter().map(port)),
                        None => ports.push(port(&m["right"])),
                    }
                }
            }
        }
        ports.sort_unstable();
        ports.dedup();
        let mut known = crate::core::firewall::DISCOVERY_QUERY_PORTS.to_vec();
        known.sort_unstable();
        assert_eq!(ports, known);
        // The output policy stays accept: the rule only records ports
        assert_eq!(chain_policy(&ruleset, "output"), "accept");

        // Off, or in Server Mode: none of it (IGMP stays)
        for (on, egress) in [
            (false, EgressProfile::Desktop),
            (true, EgressProfile::Server),
        ] {
            ruleset.advanced_security.local_discovery = on;
            ruleset.advanced_security.egress_profile = egress;
            let text = ruleset.to_nft_text();
            assert!(!text.contains("discovery_reply"), "{egress:?}: {text}");
            assert!(!text.contains("discovery queries"), "{egress:?}: {text}");
            assert!(!text.contains("mdns"));
            assert!(text.contains("ip protocol igmp accept"));
        }
    }

    /// Server Mode lets IGMP membership reports and MLD "done" messages out.
    #[test]
    fn test_server_mode_multicast_membership_out() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.advanced_security.egress_profile = EgressProfile::Server;
        let text = ruleset.to_nft_text();
        let output = &text[text.find("chain output").unwrap()..];
        assert!(
            output.contains(
                "meta l4proto ipv6-icmp icmpv6 type { nd-router-solicit, nd-neighbor-solicit, \
             nd-neighbor-advert, mld-listener-report, mld-listener-done, mld2-listener-report } \
             accept comment \"allow outbound ipv6 neighbor discovery\""
            ),
            "{output}"
        );
        assert!(output.contains(
            "ip protocol igmp accept comment \"allow outbound igmp (multicast group membership)\""
        ));
    }

    /// Drop logging only logs unicast packets (like the reject after it).
    #[test]
    fn test_drop_log_is_unicast_only() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.advanced_security.log_dropped = true;
        let text = ruleset.to_nft_text();
        assert!(
            text.contains(
                "pkttype host limit rate 5/minute burst 5 packets log prefix \"DRFW-DROP: \" level info"
            ),
            "{text}"
        );
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
        // The shebang follows the compile-time nft path (DRFW_NFT_PATH)
        assert!(text.starts_with(&format!("#!{} -f\n", crate::distro::UNIT_NFT_PATH)));
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

#[cfg(test)]
mod timestamp_compat_tests {
    //! `Rule.created_at` must stay readable in both directions across the
    //! chrono -> jiff migration: old profiles load, and what we write loads in
    //! older (chrono-based) DRFW builds.

    use crate::core::firewall::Rule;
    use crate::core::test_helpers::{CHRONO_TIMESTAMPS, create_test_rule};

    /// A rule as an older DRFW build saved it, with `created_at` = `stamp`.
    fn legacy_rule_json(stamp: &str) -> String {
        format!(
            r#"{{"id":"6f1c0f5e-2b9e-4a7c-9f5d-111111111111","label":"SSH",
                "protocol":"Tcp","ports":[22],"interface":null,"chain":"Input",
                "enabled":true,"created_at":"{stamp}","tags":[]}}"#
        )
    }

    #[test]
    fn test_rule_created_at_reads_chrono_strings() {
        for &(stamp, nanos) in CHRONO_TIMESTAMPS {
            let rule: Rule = serde_json::from_str(&legacy_rule_json(stamp))
                .unwrap_or_else(|e| panic!("{stamp}: {e}"));
            assert_eq!(rule.created_at.as_nanosecond(), nanos, "{stamp}");
        }
    }

    #[test]
    fn test_rule_created_at_writes_rfc3339_utc() {
        // chrono's deserializer (older builds) reads RFC 3339 with a `Z` or an
        // offset and 0-9 fractional digits; jiff writes exactly that subset.
        for &(stamp, nanos) in CHRONO_TIMESTAMPS {
            let mut rule = create_test_rule("SSH", Some(22));
            rule.created_at = jiff::Timestamp::from_nanosecond(nanos).unwrap();
            let json = serde_json::to_value(&rule).unwrap();
            let written = json["created_at"].as_str().unwrap();
            assert!(written.ends_with('Z'), "{stamp} -> {written}");
            assert!(written.contains('T') && written.len() >= 20, "{written}");
            // Round trip is lossless
            let back: Rule = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(back.created_at.as_nanosecond(), nanos);
        }
        // The common case is byte-identical to what chrono wrote
        let mut rule = create_test_rule("SSH", Some(22));
        rule.created_at = "2026-11-20T22:39:15.366180715Z".parse().unwrap();
        assert_eq!(
            serde_json::to_value(&rule).unwrap()["created_at"],
            "2026-11-20T22:39:15.366180715Z"
        );
        rule.created_at = "2026-11-20T22:39:15Z".parse().unwrap();
        assert_eq!(
            serde_json::to_value(&rule).unwrap()["created_at"],
            "2026-11-20T22:39:15Z"
        );
    }

    #[test]
    fn test_rule_created_at_rejects_garbage() {
        for bad in ["", "yesterday", "2026-13-01T00:00:00Z", "1795214355"] {
            let json = legacy_rule_json(bad);
            assert!(serde_json::from_str::<Rule>(&json).is_err(), "{bad:?}");
        }
    }
}

#[cfg(test)]
mod per_source_tests {
    //! JSON shape and text rendering of per-source rate and connection limits
    //! (named dynamic sets). Kernel behaviour is tested in `tests/real_nft.rs`.

    use serde_json::{Value, json};

    use crate::core::firewall::{Action, FirewallRuleset, Protocol, RateLimit, Rule, TimeUnit};
    use crate::core::test_helpers::create_test_rule;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn per_source_rule(action: Action, rate: Option<RateLimit>, conn: u32) -> Rule {
        let mut rule = create_test_rule("SSH", Some(22));
        rule.id = ID.parse().unwrap();
        rule.action = action;
        rule.rate_limit = rate;
        rule.connection_limit = conn;
        rule.connection_limit_per_source = conn > 0;
        rule.rebuild_caches();
        rule
    }

    fn rate(count: u32, unit: TimeUnit, burst: Option<u32>) -> RateLimit {
        RateLimit {
            count,
            unit,
            burst,
            per_source: true,
        }
    }

    fn commands(rule: Rule) -> Vec<Value> {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(rule);
        ruleset.to_nftables_json()["nftables"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn sets(cmds: &[Value]) -> Vec<&Value> {
        cmds.iter().filter_map(|c| c["add"].get("set")).collect()
    }

    fn user_rules(cmds: &[Value]) -> Vec<&Value> {
        cmds.iter()
            .filter_map(|c| c["add"].get("rule"))
            .filter(|r| r["comment"] == "SSH")
            .collect()
    }

    /// The set statements of a rule
    fn set_statements(rule: &Value) -> Vec<&Value> {
        rule["expr"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e.get("set").filter(|s| s.get("op").is_some()))
            .collect()
    }

    #[test]
    fn test_accept_rate_limit_emits_one_set_and_rule_per_family() {
        let cmds = commands(per_source_rule(
            Action::Accept,
            Some(rate(2, TimeUnit::Minute, Some(2))),
            0,
        ));

        let sets = sets(&cmds);
        assert_eq!(sets.len(), 2);
        assert_eq!(
            *sets[0],
            json!({
                "family": "inet", "table": "drfw", "name": "rl4_0123456789ab",
                "type": "ipv4_addr", "size": 65535,
                "flags": ["dynamic", "timeout"], "timeout": 120
            })
        );
        assert_eq!(sets[1]["name"], "rl6_0123456789ab");
        assert_eq!(sets[1]["type"], "ipv6_addr");

        let rules = user_rules(&cmds);
        assert_eq!(rules.len(), 2, "one rule per family");
        let v4 = set_statements(rules[0]);
        assert_eq!(
            *v4[0],
            json!({
                "op": "update",
                "elem": { "payload": { "protocol": "ip", "field": "saddr" } },
                "set": "@rl4_0123456789ab",
                "stmt": [{ "limit": { "rate": 2, "per": "minute", "burst": 2 } }]
            })
        );
        let v6 = set_statements(rules[1]);
        assert_eq!(
            v6[0]["elem"],
            json!({ "&": [
                { "payload": { "protocol": "ip6", "field": "saddr" } },
                "ffff:ffff:ffff:ffff::"
            ] })
        );
        assert_eq!(v6[0]["set"], "@rl6_0123456789ab");
        // No global limit statement next to the per-source one
        let expr = rules[0]["expr"].to_string();
        assert_eq!(expr.matches("\"limit\"").count(), 1);

        // Every set is created before the first rule that references it
        let position = |pred: &dyn Fn(&Value) -> bool| cmds.iter().position(pred).unwrap();
        let set_at = position(&|c| c["add"]["set"]["name"] == "rl6_0123456789ab");
        let rule_at = position(&|c| c["add"]["rule"]["expr"].to_string().contains("@rl6_"));
        assert!(set_at < rule_at);
    }

    #[test]
    fn test_rate_and_connection_sets_in_one_rule_and_ct_count_uses_add() {
        let cmds = commands(per_source_rule(
            Action::Accept,
            Some(rate(5, TimeUnit::Second, None)),
            3,
        ));
        let rules = user_rules(&cmds);
        assert_eq!(rules.len(), 2, "one rule per family");
        let stmts = set_statements(rules[0]);
        assert_eq!(stmts.len(), 2, "rate and connection sets");
        assert_eq!(
            stmts[0]["stmt"],
            json!([{ "limit": { "rate": 5, "per": "second" } }])
        );
        assert_eq!(stmts[1]["op"], "add");
        assert_eq!(stmts[1]["set"], "@cl4_0123456789ab");
        assert_eq!(stmts[1]["stmt"], json!([{ "ct count": { "val": 3 } }]));

        let conn_set = sets(&cmds)
            .into_iter()
            .find(|s| s["name"] == "cl4_0123456789ab")
            .expect("connection set");
        assert_eq!(conn_set["flags"], json!(["dynamic"]));
        assert!(
            conn_set.get("timeout").is_none(),
            "ct count elements expire with their connections"
        );
    }

    #[test]
    fn test_families_follow_addresses_and_protocol() {
        // IPv4 sources: IPv4 copy only
        let mut rule = per_source_rule(Action::Accept, Some(rate(3, TimeUnit::Minute, None)), 0);
        rule.sources = vec!["192.0.2.0/24".parse().unwrap()];
        let cmds = commands(rule);
        let names: Vec<_> = sets(&cmds).iter().map(|s| s["name"].clone()).collect();
        assert_eq!(names, vec![json!("rl4_0123456789ab")]);
        assert_eq!(user_rules(&cmds).len(), 1);

        // ICMPv6 without addresses: IPv6 copy only
        let mut rule = per_source_rule(Action::Accept, Some(rate(3, TimeUnit::Minute, None)), 0);
        rule.protocol = Protocol::Icmpv6;
        rule.ports = Vec::new();
        let cmds = commands(rule);
        let names: Vec<_> = sets(&cmds).iter().map(|s| s["name"].clone()).collect();
        assert_eq!(names, vec![json!("rl6_0123456789ab")]);

        // A global limit keeps the single family-less rule and creates no set
        let mut rule = per_source_rule(Action::Accept, Some(rate(3, TimeUnit::Minute, None)), 0);
        rule.rate_limit.as_mut().unwrap().per_source = false;
        let cmds = commands(rule);
        assert_eq!(sets(&cmds), [] as [&Value; 0]);
        assert_eq!(user_rules(&cmds).len(), 1);

        // A per-source flag without a connection limit does nothing
        let mut rule = per_source_rule(Action::Accept, None, 0);
        rule.connection_limit_per_source = true;
        let cmds = commands(rule);
        assert_eq!(sets(&cmds), [] as [&Value; 0]);
        assert_eq!(user_rules(&cmds).len(), 1);
    }

    #[test]
    fn test_rate_set_timeout_covers_the_bucket_refill_time() {
        let timeout = |rate_limit: Option<RateLimit>| {
            sets(&commands(per_source_rule(Action::Accept, rate_limit, 0)))[0]["timeout"].clone()
        };
        // At least two periods
        assert_eq!(timeout(Some(rate(2, TimeUnit::Minute, Some(2)))), 120);
        assert_eq!(timeout(Some(rate(10, TimeUnit::Second, None))), 2);
        assert_eq!(timeout(Some(rate(100, TimeUnit::Hour, Some(50)))), 7_200);
        // Bucket refill time plus one period: burst 10 at 1/minute refills in
        // 10 minutes; no burst means the kernel default of 5 packets
        assert_eq!(timeout(Some(rate(1, TimeUnit::Minute, Some(10)))), 660);
        assert_eq!(timeout(Some(rate(1, TimeUnit::Minute, None))), 360);
        assert_eq!(timeout(Some(rate(3, TimeUnit::Minute, Some(7)))), 240);
        // Capped at a week
        assert_eq!(timeout(Some(rate(1, TimeUnit::Day, Some(1000)))), 604_800);
    }

    #[test]
    fn test_set_names_never_collide() {
        let mut ruleset = FirewallRuleset::new();
        // Same first 12 hex digits, different ids
        for id in [ID, "0123456789abffffffffffffffffffff"] {
            let mut rule =
                per_source_rule(Action::Accept, Some(rate(3, TimeUnit::Minute, None)), 0);
            rule.id = id.parse().unwrap();
            rule.sources = vec!["192.0.2.1/32".parse().unwrap()];
            ruleset.rules.push(rule);
        }
        let json = ruleset.to_nftables_json();
        let cmds = json["nftables"].as_array().unwrap();
        let names: Vec<_> = sets(cmds).iter().map(|s| s["name"].clone()).collect();
        assert_eq!(
            names,
            vec![json!("rl4_0123456789ab"), json!("rl4_0123456789ab_2")]
        );
        assert!(json.to_string().contains("\"@rl4_0123456789ab_2\""));
    }

    #[test]
    fn test_text_renders_sets_and_set_statements() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(per_source_rule(
            Action::Accept,
            Some(rate(2, TimeUnit::Minute, Some(2))),
            4,
        ));
        let text = ruleset.to_nft_text();

        let set_block = "    set rl4_0123456789ab {\n        type ipv4_addr\n        \
                         flags dynamic,timeout\n        timeout 120s\n        size 65535\n    }\n";
        assert!(text.contains(set_block), "set block missing:\n{text}");
        assert!(
            text.contains("    set cl6_0123456789ab {\n        type ipv6_addr\n        flags dynamic\n        size 65535\n    }\n"),
            "connection set block missing:\n{text}"
        );
        // Sets are declared before the chains that use them
        assert!(text.find("set rl4_").unwrap() < text.find("chain input").unwrap());
        assert!(
            text.contains(
                "meta l4proto tcp tcp dport 22 \
             update @rl4_0123456789ab { ip saddr limit rate 2/minute burst 2 packets } \
             add @cl4_0123456789ab { ip saddr ct count 4 } accept comment \"SSH\""
            ),
            "{text}"
        );
        assert!(text.contains(
            "update @rl6_0123456789ab { ip6 saddr & ffff:ffff:ffff:ffff:: limit rate 2/minute burst 2 packets }"
        ), "{text}");
        assert!(!text.contains("drfw-render-error"));
        // The table is replaced, never just flushed
        assert_eq!(text.matches("\ntable inet drfw\n").count(), 1);
        assert!(text.contains("\ndelete table inet drfw\n"));
    }

    #[test]
    fn test_per_source_flags_serde() {
        // Old profiles (no flags) load with the flags off
        let old: RateLimit = serde_json::from_str(r#"{"count":5,"unit":"Minute"}"#).unwrap();
        assert!(!old.per_source);
        // Off is not written, so profiles without per-source limits are unchanged
        let rule = create_test_rule("x", Some(22));
        let value = serde_json::to_value(&rule).unwrap();
        assert!(value.get("connection_limit_per_source").is_none());
        let mut limited = per_source_rule(Action::Accept, Some(rate(5, TimeUnit::Minute, None)), 2);
        let value = serde_json::to_value(&limited).unwrap();
        assert_eq!(value["rate_limit"]["per_source"], true);
        assert_eq!(value["connection_limit_per_source"], true);
        let mut back: Rule = serde_json::from_value(value).unwrap();
        back.rebuild_caches();
        limited.rebuild_caches();
        assert_eq!(back, limited);
    }

    #[test]
    fn test_badge_marks_per_source_rules() {
        let rule = per_source_rule(Action::Accept, Some(rate(5, TimeUnit::Minute, None)), 0);
        assert_eq!(rule.badge_display, "TCP: 22 · per-src");
        let mut rule = create_test_rule("x", Some(22));
        rule.connection_limit_per_source = true; // no limit: not per source
        rule.rebuild_caches();
        assert_eq!(rule.badge_display, "TCP: 22");
    }
}

#[cfg(test)]
mod command_origin_tests {
    //! Every generated command records what produced it (`CommandOrigin`);
    //! error attribution relies on it.

    use std::collections::HashMap;

    use uuid::Uuid;

    use crate::core::firewall::{
        Chain, CommandOrigin, EgressProfile, FirewallRuleset, Protocol, RateLimit, TimeUnit,
    };
    use crate::core::test_helpers::create_test_rule;

    fn varied_ruleset() -> FirewallRuleset {
        let mut ruleset = FirewallRuleset::new();
        let mut dual = create_test_rule("dual stack", Some(443));
        dual.sources = vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()];
        // Per-source limits without addresses: one copy and two sets per family
        let mut per_source = create_test_rule("per source", Some(22));
        per_source.rate_limit = Some(RateLimit {
            count: 3,
            unit: TimeUnit::Minute,
            burst: None,
            per_source: true,
        });
        per_source.connection_limit = 4;
        per_source.connection_limit_per_source = true;
        let mut icmp = create_test_rule("icmp per source", None);
        icmp.protocol = Protocol::Icmp;
        icmp.rate_limit = per_source.rate_limit;
        let mut output = create_test_rule("output", Some(53));
        output.chain = Chain::Output;
        let mut disabled = create_test_rule("disabled", Some(25));
        disabled.enabled = false;
        ruleset.rules = vec![
            create_test_rule("ssh", Some(22)),
            dual,
            per_source,
            icmp,
            output,
            disabled,
        ];
        for rule in &mut ruleset.rules {
            rule.rebuild_caches();
        }
        ruleset.advanced_security.egress_profile = EgressProfile::Server;
        ruleset.advanced_security.log_dropped = true;
        ruleset.advanced_security.enable_rpf = true;
        ruleset.advanced_security.block_forwarding = true;
        ruleset
    }

    /// The JSON values of `ruleset`'s commands whose origin is `rule_id`.
    fn commands_of(ruleset: &FirewallRuleset, rule_id: Uuid) -> Vec<serde_json::Value> {
        ruleset
            .build_commands()
            .into_iter()
            .filter(|c| c.origin == CommandOrigin::UserRule(rule_id))
            .map(|c| c.value)
            .collect()
    }

    #[test]
    fn test_user_rule_commands_carry_the_rule_id() {
        let ruleset = varied_ruleset();
        let commands = ruleset.build_commands();
        let mut base = ruleset.clone();
        base.rules.clear();
        let base_commands = base.build_commands();

        // Without the user rules' commands, exactly the base ruleset remains
        let non_user: Vec<_> = commands
            .iter()
            .filter(|c| !matches!(c.origin, CommandOrigin::UserRule(_)))
            .map(|c| (c.origin, &c.value))
            .collect();
        let expected: Vec<_> = base_commands.iter().map(|c| (c.origin, &c.value)).collect();
        assert_eq!(non_user, expected);

        let mut per_rule: HashMap<Uuid, usize> = HashMap::new();
        for command in &commands {
            let CommandOrigin::UserRule(id) = command.origin else {
                assert!(
                    command.value["add"].get("set").is_none(),
                    "set without a rule: {}",
                    command.value
                );
                continue;
            };
            let rule = ruleset.rules.iter().find(|r| r.id == id).expect("known id");
            assert!(rule.enabled);
            let add = &command.value["add"];
            if let Some(set) = add.get("set") {
                let mut buf = Uuid::encode_buffer();
                let hex = id.simple().encode_lower(&mut buf);
                let name = set["name"].as_str().unwrap();
                assert!(name.contains(&hex[..12]), "{name} is not {}'s", rule.label);
            } else {
                assert_eq!(add["rule"]["comment"], rule.label.as_str());
            }
            *per_rule.entry(id).or_default() += 1;
        }

        // Each rule's commands are the ones it produces on its own
        for rule in ruleset.rules.iter().filter(|r| r.enabled) {
            let mut single = base.clone();
            single.rules.push(rule.clone());
            assert_eq!(
                commands_of(&ruleset, rule.id),
                commands_of(&single, rule.id),
                "{}",
                rule.label
            );
        }
        let counts = |label: &str| {
            let id = ruleset.rules.iter().find(|r| r.label == label).unwrap().id;
            per_rule.get(&id).copied().unwrap_or(0)
        };
        assert_eq!(counts("ssh"), 1);
        assert_eq!(counts("dual stack"), 2);
        // Two family copies, each with a rate set and a connection set
        assert_eq!(counts("per source"), 6);
        // ICMP (v4 only): one copy with its rate set
        assert_eq!(counts("icmp per source"), 2);
        assert_eq!(counts("output"), 1);
        assert_eq!(counts("disabled"), 0);
    }

    #[test]
    fn test_base_commands_are_named() {
        let ruleset = varied_ruleset();
        for command in ruleset.build_commands() {
            let add = &command.value["add"];
            match command.origin {
                CommandOrigin::Setup => {
                    let verb = command.value.as_object().and_then(|o| o.keys().next());
                    let table = &command.value[verb.map_or("", String::as_str)]["table"];
                    assert_eq!(table["name"], "drfw", "{}", command.value);
                }
                CommandOrigin::Chain(name) => assert_eq!(add["chain"]["name"], name),
                CommandOrigin::BaseRule(name) => {
                    assert_ne!(name, "");
                    if let Some(comment) = add["rule"]["comment"].as_str() {
                        assert_eq!(comment, name);
                    }
                }
                CommandOrigin::UserRule(_) => {}
            }
        }
    }
}
