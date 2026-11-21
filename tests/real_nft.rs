//! Tests against the real `nft` binary and kernel, in a private namespace
//!
//! Every test runs `nft` inside `unshare -rn`: a fresh unprivileged user +
//! network namespace. Rulesets are loaded, listed and compared there without
//! root and without touching the host firewall.
//!
//! If `unshare`/`nft` are missing or the namespace cannot be created (e.g.
//! unprivileged user namespaces disabled), the tests print a skip notice and
//! pass, unless `DRFW_REQUIRE_REAL_NFT=1` is set (CI sets it), in which case
//! they fail.
//!
//! What is covered:
//! - The text output of varied rulesets passes `nft -c -f` and loads.
//! - **Differential**: applying the JSON and applying the text produce
//!   identical kernel rulesets (proptest over generated rulesets).
//! - Loading the text twice does not duplicate rules.
//! - Mixed IPv4/IPv6 rules never widen.
//! - Server Mode keeps loopback working.
//! - Behaviour in two network namespaces: per-source limits keep clients
//!   apart; a user "Drop Any from X" rule blocks X's ping.
//! - The interface validator's length limit matches nft's.
//! - The Save to System script, end to end, with the real `nft -c`.
//! - The revert guard (apply script + detached watcher): timeout after a
//!   first apply removes the table, an existing table is restored exactly,
//!   confirm/revert tokens (only the applying uid's), superseding applies,
//!   rejected rulesets, and SIGHUP/SIGINT/SIGTERM/SIGKILL right after the
//!   new rules went live.
//! - The root helper `drfw-helper` (debug-build test mode): apply with
//!   confirm and timeout, Save to System and the check through it, and
//!   refused requests (foreign state dir, foreign uid, `include` payloads)
//!   that change nothing.
//!
//! The probe, the `nft` binary (the one the library runs unprivileged, put
//! first on the scripts' `PATH`) and the rule builder come from
//! `tests/common/mod.rs`.

mod common;

use std::path::Path;
use std::process::{Command, Output};

use drfw::core::firewall::{
    Action, Chain, EgressProfile, FirewallRuleset, PortEntry, Protocol, RateLimit, RejectType,
    Rule, TimeUnit,
};
use ipnetwork::IpNetwork;
use proptest::prelude::*;

use crate::common::{real_nft_available, rule, unshare};

// ============================================================================
// Namespace helpers
// ============================================================================

/// Runs a `/bin/sh` script in a fresh user + network namespace, in `dir`.
fn run_in_netns(dir: &Path, script: &str) -> Output {
    unshare()
        .args(["-rn", "/bin/sh", "-c", script])
        .current_dir(dir)
        .output()
        .expect("failed to spawn unshare")
}

/// Like [`run_in_netns`] but panics with the script's stderr on failure.
fn run_in_netns_ok(dir: &Path, script: &str) -> Output {
    let output = run_in_netns(dir, script);
    assert!(
        output.status.success(),
        "script failed: {script}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Writes the JSON and text forms of a ruleset into `dir`.
fn write_ruleset(dir: &Path, ruleset: &FirewallRuleset) {
    std::fs::write(
        dir.join("rules.json"),
        serde_json::to_string(&ruleset.to_nftables_json()).expect("serialize JSON"),
    )
    .expect("write rules.json");
    std::fs::write(dir.join("rules.nft"), ruleset.to_nft_text()).expect("write rules.nft");
}

/// Parses `nft -j list` output and strips run-specific data (handles, metainfo).
fn normalize_listing(raw: &[u8]) -> serde_json::Value {
    fn strip_handles(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                map.remove("handle");
                map.values_mut().for_each(strip_handles);
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(strip_handles),
            _ => {}
        }
    }
    let mut value: serde_json::Value = serde_json::from_slice(raw).expect("nft -j list output");
    let items = value["nftables"]
        .as_array_mut()
        .expect("nftables array in listing");
    items.retain(|item| item.get("metainfo").is_none());
    strip_handles(&mut value);
    value
}

/// Rules (as listed by the kernel) of the drfw table.
fn listed_rules(listing: &serde_json::Value) -> Vec<&serde_json::Value> {
    listing["nftables"]
        .as_array()
        .expect("nftables array")
        .iter()
        .filter_map(|item| item.get("rule"))
        .collect()
}

/// Applies JSON, lists; flushes; applies text, lists. Returns both listings.
fn apply_both_forms(
    dir: &Path,
    ruleset: &FirewallRuleset,
) -> (serde_json::Value, serde_json::Value) {
    write_ruleset(dir, ruleset);
    run_in_netns_ok(
        dir,
        "nft -j -f rules.json && nft -j list table inet drfw > from_json.out \
         && nft flush ruleset \
         && nft -f rules.nft && nft -j list table inet drfw > from_text.out",
    );
    let from_json = normalize_listing(&std::fs::read(dir.join("from_json.out")).expect("read"));
    let from_text = normalize_listing(&std::fs::read(dir.join("from_text.out")).expect("read"));
    (from_json, from_text)
}

/// Describes the first difference between two normalized listings, if any.
fn listing_difference(a: &serde_json::Value, b: &serde_json::Value) -> Option<String> {
    let empty = Vec::new();
    let a_items = a["nftables"].as_array().unwrap_or(&empty);
    let b_items = b["nftables"].as_array().unwrap_or(&empty);
    for (i, (x, y)) in a_items.iter().zip(b_items).enumerate() {
        if x != y {
            return Some(format!("item {i} differs:\n json: {x}\n text: {y}"));
        }
    }
    (a_items.len() != b_items.len()).then(|| {
        format!(
            "item count differs: json {} vs text {}",
            a_items.len(),
            b_items.len()
        )
    })
}

/// A temporary working directory for one test.
fn work_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("create temp dir")
}

// ============================================================================
// Rule helpers
// ============================================================================

fn nets(addrs: &[&str]) -> Vec<IpNetwork> {
    addrs
        .iter()
        .map(|a| a.parse().expect("valid test address"))
        .collect()
}

/// A ruleset exercising every feature the generator supports.
fn kitchen_sink_rules() -> Vec<Rule> {
    let mut rules = Vec::new();

    for protocol in [
        Protocol::Any,
        Protocol::Tcp,
        Protocol::Udp,
        Protocol::TcpAndUdp,
        Protocol::Icmp,
        Protocol::Icmpv6,
        Protocol::IcmpBoth,
    ] {
        // Without ports (old text renderer emitted bare "tcp accept")
        rules.push(rule(&format!("{protocol:?} no ports"), protocol, vec![]));
        // With a port set incl. a range (ignored for ICMP, TCP+UDP for Any)
        rules.push(rule(
            &format!("{protocol:?} ports"),
            protocol,
            vec![PortEntry::Single(22), PortEntry::range(8000, 8080)],
        ));
    }

    let mut r = rule("Single port", Protocol::Tcp, vec![PortEntry::Single(443)]);
    r.sources = nets(&["192.168.1.0/24"]);
    rules.push(r);

    let mut r = rule("Mixed families", Protocol::Tcp, vec![PortEntry::Single(22)]);
    r.sources = nets(&["10.0.0.0/8", "192.168.1.50/24", "fd00::/8", "2001:db8::1"]);
    r.destinations = nets(&["10.1.1.1", "fe80::1"]);
    rules.push(r);

    let mut r = rule("V6 only dest", Protocol::Udp, vec![PortEntry::Single(53)]);
    r.destinations = nets(&["::1"]);
    rules.push(r);

    let mut r = rule("Interface", Protocol::Tcp, vec![PortEntry::Single(80)]);
    r.interface = Some("eth0".to_string());
    rules.push(r);

    let mut r = rule(
        "Wildcard iface",
        Protocol::Udp,
        vec![PortEntry::Single(51820)],
    );
    r.interface = Some("wg*".to_string());
    rules.push(r);

    let mut r = rule("Hostile iface", Protocol::Tcp, vec![PortEntry::Single(81)]);
    r.interface = Some("x\" accept #".to_string());
    rules.push(r);

    for (i, (action, burst)) in [
        (Action::Accept, None),
        (Action::Accept, Some(10)),
        (Action::Drop, Some(0)),
        (Action::Reject, Some(5)),
    ]
    .into_iter()
    .enumerate()
    {
        let mut r = rule(
            &format!("Rate {i}"),
            Protocol::Tcp,
            vec![PortEntry::Single(22)],
        );
        r.action = action;
        r.rate_limit = Some(RateLimit {
            count: 5,
            unit: [
                TimeUnit::Second,
                TimeUnit::Minute,
                TimeUnit::Hour,
                TimeUnit::Day,
            ][i],
            burst,
            per_source: false,
        });
        rules.push(r);
    }

    // Regression: nft 1.1.7 rejects `limit rate over N/unit reject with tcp reset
    // comment ".."` when no burst is spelled out (found by the differential proptest)
    let mut r = rule("Rate reset", Protocol::Tcp, vec![PortEntry::Single(23)]);
    r.action = Action::Reject;
    r.reject_type = RejectType::TcpReset;
    r.rate_limit = Some(RateLimit {
        count: 1,
        unit: TimeUnit::Second,
        burst: None,
        per_source: false,
    });
    rules.push(r);

    // Rate AND connection limit: one rule for Accept, two rules (one per
    // limit) for Drop/Reject
    for action in [Action::Accept, Action::Drop, Action::Reject] {
        let mut r = rule(
            &format!("Rate+ct {action:?}"),
            Protocol::Tcp,
            vec![PortEntry::Single(26)],
        );
        r.action = action;
        r.rate_limit = Some(RateLimit {
            count: 4,
            unit: TimeUnit::Second,
            burst: Some(8),
            per_source: false,
        });
        r.connection_limit = 6;
        r.log_enabled = action == Action::Drop;
        rules.push(r);
    }

    for action in [Action::Accept, Action::Drop] {
        let mut r = rule(
            &format!("Ct {action:?}"),
            Protocol::Tcp,
            vec![PortEntry::Single(25)],
        );
        r.action = action;
        r.connection_limit = 10;
        r.log_enabled = true;
        rules.push(r);
    }

    for reject_type in [
        RejectType::Default,
        RejectType::PortUnreachable,
        RejectType::HostUnreachable,
        RejectType::AdminProhibited,
        RejectType::TcpReset,
    ] {
        let mut r = rule(
            &format!("Reject {reject_type:?}"),
            Protocol::Tcp,
            vec![PortEntry::Single(23)],
        );
        r.action = Action::Reject;
        r.reject_type = reject_type;
        rules.push(r);
    }

    rules.extend(per_source_rules());

    let mut r = rule("Outbound DNS", Protocol::Udp, vec![PortEntry::Single(53)]);
    r.chain = Chain::Output;
    r.output_interface = Some("eth*".to_string());
    rules.push(r);

    // Forward rules (generated with "Block forwarding" only): both interfaces
    let mut r = rule("Routed web", Protocol::Tcp, vec![PortEntry::Single(8080)]);
    r.chain = Chain::Forward;
    r.interface = Some("veth-a".to_string());
    r.output_interface = Some("br-*".to_string());
    r.sources = nets(&["10.0.0.0/8", "fd00::/8"]);
    r.log_enabled = true;
    rules.push(r);
    let mut r = rule(
        "Routed limited",
        Protocol::Udp,
        vec![PortEntry::Single(51820)],
    );
    r.chain = Chain::Forward;
    r.rate_limit = Some(per_source_rate(10, TimeUnit::Second, None));
    rules.push(r);

    let mut r = rule("Disabled", Protocol::Tcp, vec![PortEntry::Single(9)]);
    r.enabled = false;
    rules.push(r);

    for r in &mut rules {
        r.rebuild_caches();
    }
    rules
}

/// A per-source rate limit (`burst: None` = nft's default).
fn per_source_rate(count: u32, unit: TimeUnit, burst: Option<u32>) -> RateLimit {
    RateLimit {
        count,
        unit,
        burst,
        per_source: true,
    }
}

/// Every shape of per-source limit (Accept only; validation refuses them on
/// Drop/Reject): both families, pinned families, rate + connection sets on
/// one rule, ICMP, OUTPUT chain.
fn per_source_rules() -> Vec<Rule> {
    let mut rules = Vec::new();

    let mut r = rule("PS accept", Protocol::Tcp, vec![PortEntry::Single(22)]);
    r.rate_limit = Some(per_source_rate(2, TimeUnit::Minute, Some(2)));
    rules.push(r);

    let mut r = rule("PS mixed", Protocol::Tcp, vec![PortEntry::Single(80)]);
    r.sources = nets(&["192.0.2.0/24", "2001:db8::/48"]);
    r.rate_limit = Some(per_source_rate(20, TimeUnit::Second, None));
    rules.push(r);

    let mut r = rule("PS both", Protocol::Tcp, vec![PortEntry::Single(2222)]);
    r.rate_limit = Some(per_source_rate(1, TimeUnit::Hour, Some(10)));
    r.connection_limit = 3;
    r.connection_limit_per_source = true;
    rules.push(r);

    let mut r = rule("PS conn only", Protocol::Any, vec![]);
    r.destinations = nets(&["fd00::1"]);
    r.connection_limit = 50;
    r.connection_limit_per_source = true;
    r.log_enabled = true;
    rules.push(r);

    let mut r = rule(
        "PS conn tcp+udp",
        Protocol::TcpAndUdp,
        vec![PortEntry::Single(53)],
    );
    r.connection_limit = 8;
    r.connection_limit_per_source = true;
    rules.push(r);

    let mut r = rule("PS icmp", Protocol::Icmp, vec![]);
    r.rate_limit = Some(per_source_rate(10, TimeUnit::Second, Some(20)));
    rules.push(r);

    let mut r = rule("PS icmp both", Protocol::IcmpBoth, vec![]);
    r.rate_limit = Some(per_source_rate(5, TimeUnit::Day, None));
    rules.push(r);

    let mut r = rule("PS out", Protocol::Tcp, vec![PortEntry::Single(25)]);
    r.chain = Chain::Output;
    r.rate_limit = Some(per_source_rate(1, TimeUnit::Day, Some(1000)));
    rules.push(r);

    rules
}

/// Every combination of the global settings, each with the kitchen-sink rules.
fn varied_rulesets() -> Vec<(String, FirewallRuleset)> {
    let mut out = Vec::new();
    for bits in 0u8..64 {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules = kitchen_sink_rules();
        let adv = &mut ruleset.advanced_security;
        adv.strict_icmp = bits & 1 != 0;
        adv.enable_rpf = bits & 2 != 0;
        adv.block_forwarding = bits & 4 != 0;
        adv.log_dropped = bits & 8 != 0;
        adv.egress_profile = if bits & 16 != 0 {
            EgressProfile::Server
        } else {
            EgressProfile::Desktop
        };
        adv.local_discovery = bits & 32 != 0;
        adv.icmp_rate_limit = if bits % 3 == 0 { 10 } else { 0 };
        out.push((format!("settings {bits:06b}"), ruleset));
    }
    out.push(("empty".to_string(), FirewallRuleset::new()));
    out
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn test_text_output_passes_nft_check_and_loads() {
    if !real_nft_available() {
        return;
    }
    let dir = work_dir();
    for (name, ruleset) in varied_rulesets() {
        write_ruleset(dir.path(), &ruleset);
        let output = run_in_netns(dir.path(), "nft -c -f rules.nft && nft -f rules.nft");
        assert!(
            output.status.success(),
            "{name}: nft rejected the text output:\n{}\n--- text ---\n{}",
            String::from_utf8_lossy(&output.stderr),
            ruleset.to_nft_text()
        );
    }
}

#[test]
fn test_varied_rulesets_json_and_text_are_identical_in_kernel() {
    if !real_nft_available() {
        return;
    }
    let dir = work_dir();
    for (name, ruleset) in varied_rulesets() {
        let (from_json, from_text) = apply_both_forms(dir.path(), &ruleset);
        if let Some(diff) = listing_difference(&from_json, &from_text) {
            panic!("{name}: JSON and text differ in kernel: {diff}");
        }
    }
}

/// Every rule template (and Server Mode's essentials) loads in the kernel,
/// as JSON, as the ruleset's text and as the text rendered from the recorded
/// JSON (what "Save the last kept rules" writes), all three identical; with
/// and without Server Mode, local discovery and "Block forwarded traffic".
#[test]
fn test_templates_and_essentials_load_in_kernel() {
    use drfw::core::templates::{
        server_essentials, tailscale_direct, trust_interface, vm_guest_dhcp_dns,
    };
    if !real_nft_available() {
        return;
    }
    let dir = work_dir();
    let mut rules = server_essentials();
    rules.extend(vm_guest_dhcp_dns("virbr0"));
    rules.push(tailscale_direct());
    rules.push(trust_interface("tailscale0"));
    for (server, discovery, block_forwarding) in [(true, false, true), (false, true, false)] {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.clone_from(&rules);
        let adv = &mut ruleset.advanced_security;
        adv.egress_profile = if server {
            EgressProfile::Server
        } else {
            EgressProfile::Desktop
        };
        adv.local_discovery = discovery;
        adv.block_forwarding = block_forwarding;
        assert!(ruleset.validate_for_apply().is_ok(), "templates are valid");
        let (from_json, from_text) = apply_both_forms(dir.path(), &ruleset);
        if let Some(diff) = listing_difference(&from_json, &from_text) {
            panic!("server {server}: JSON and text differ in kernel: {diff}");
        }
        let recorded = serde_json::to_string(&ruleset.to_nftables_json()).expect("JSON");
        let text = drfw::core::nft_text::render_json(&recorded).expect("renders");
        std::fs::write(dir.path().join("recorded.nft"), text).expect("write");
        run_in_netns_ok(
            dir.path(),
            "nft -c -f recorded.nft && nft -f recorded.nft \
             && nft -j list table inet drfw > from_record.out",
        );
        let from_record =
            normalize_listing(&std::fs::read(dir.path().join("from_record.out")).expect("read"));
        if let Some(diff) = listing_difference(&from_json, &from_record) {
            panic!("server {server}: recorded-JSON text differs in kernel: {diff}");
        }
    }
}

#[test]
fn test_loading_text_twice_does_not_duplicate_rules() {
    if !real_nft_available() {
        return;
    }
    let dir = work_dir();
    let mut ruleset = FirewallRuleset::new();
    ruleset.rules = kitchen_sink_rules();
    write_ruleset(dir.path(), &ruleset);

    run_in_netns_ok(
        dir.path(),
        "nft -f rules.nft && nft -j list table inet drfw > once.out \
         && nft -f rules.nft && nft -j list table inet drfw > twice.out",
    );
    let once = normalize_listing(&std::fs::read(dir.path().join("once.out")).expect("read"));
    let twice = normalize_listing(&std::fs::read(dir.path().join("twice.out")).expect("read"));
    let rule_count = listed_rules(&once).len();
    assert!(
        rule_count > 10,
        "expected the kitchen-sink rules, got {rule_count}"
    );
    assert_eq!(rule_count, listed_rules(&twice).len());
    assert_eq!(once, twice);
}

#[test]
fn test_mixed_family_rule_never_widens_in_kernel() {
    if !real_nft_available() {
        return;
    }
    let dir = work_dir();
    let mut ruleset = FirewallRuleset::new();
    let mut r = rule("Mixed", Protocol::Tcp, vec![PortEntry::Single(22)]);
    // Only IPv4 destinations: an IPv6 copy would have no daddr match
    r.sources = nets(&["10.0.0.0/8", "fd00::/8"]);
    r.destinations = nets(&["192.168.1.1"]);
    r.rebuild_caches();
    ruleset.rules.push(r);

    let (from_json, from_text) = apply_both_forms(dir.path(), &ruleset);
    assert_eq!(listing_difference(&from_json, &from_text), None);

    let mixed: Vec<_> = listed_rules(&from_text)
        .into_iter()
        .filter(|r| r["comment"] == "Mixed")
        .collect();
    assert_eq!(mixed.len(), 1, "exactly one (IPv4) copy expected");
    let expr = mixed[0]["expr"].to_string();
    assert!(expr.contains("\"daddr\""), "daddr match missing: {expr}");
    assert!(expr.contains("\"saddr\""), "saddr match missing: {expr}");
    assert!(
        !expr.contains("\"ip6\""),
        "IPv6 copy must not exist: {expr}"
    );
}

/// Applying the JSON replaces the table: per-source state starts fresh and the
/// sets of removed rules disappear (`flush table` would keep both).
#[test]
fn test_apply_replaces_per_source_sets() {
    if !real_nft_available() {
        return;
    }
    let dir = work_dir();
    let mut ruleset = FirewallRuleset::new();
    let mut r = rule("PS", Protocol::Tcp, vec![PortEntry::Single(22)]);
    r.id = "0123456789abcdef0123456789abcdef".parse().expect("uuid");
    r.rate_limit = Some(per_source_rate(2, TimeUnit::Minute, Some(2)));
    ruleset.rules.push(r);
    write_json(dir.path(), "with.json", &ruleset);
    write_json(dir.path(), "without.json", &FirewallRuleset::new());

    let output = run_in_netns_ok(
        dir.path(),
        "nft -j -f with.json \
         && nft add element inet drfw rl4_0123456789ab '{ 192.0.2.7 }' \
         && nft list set inet drfw rl4_0123456789ab > before.out \
         && nft -j -f with.json \
         && nft list set inet drfw rl4_0123456789ab > again.out \
         && nft -j -f without.json \
         && nft list table inet drfw",
    );
    assert!(read(dir.path(), "before.out").contains("192.0.2.7"));
    let again = read(dir.path(), "again.out");
    assert!(
        !again.contains("192.0.2.7"),
        "re-applying must reset per-source state:\n{again}"
    );
    assert!(again.contains("timeout 2m"), "set definition:\n{again}");
    let table = String::from_utf8_lossy(&output.stdout);
    assert!(
        !table.contains("set "),
        "the set of a removed rule must not linger:\n{table}"
    );
}

/// Behaviour in the kernel: two clients behind a veth pair share one port, and
/// exhausting one client's budget leaves the other's intact.
///
/// Uses two network namespaces (the test namespace and a child holding the
/// client end of the veth pair). TCP connects come from bash `/dev/tcp`; the
/// source address is chosen with a `/32` route's `src`. Nothing listens on the
/// port, so a connect the firewall *accepted* fails with "Connection refused"
/// (the kernel's RST), while a blocked one fails otherwise (drfw's final
/// `reject with icmpx admin-prohibited`, or a timeout).
#[test]
fn test_per_source_rate_limit_keeps_clients_apart() {
    if !real_nft_available() {
        return;
    }
    let missing = common::missing_tools(&["bash", "ip", "nsenter", "timeout"]);
    if !missing.is_empty() {
        common::skip("per-source behaviour test", &format!("missing {missing:?}"));
        return;
    }

    let dir = work_dir();
    let mut ruleset = FirewallRuleset::new();
    let mut r = rule("PS ssh", Protocol::Tcp, vec![PortEntry::Single(2222)]);
    r.id = "0123456789abcdef0123456789abcdef".parse().expect("uuid");
    r.rate_limit = Some(per_source_rate(2, TimeUnit::Minute, Some(2)));
    ruleset.rules.push(r);
    // A per-source connection limit too, so the revert check below also
    // reloads a populated `ct count` set
    let mut r = rule("PS conn", Protocol::Tcp, vec![PortEntry::Single(2223)]);
    r.id = "fedcba9876543210fedcba9876543210".parse().expect("uuid");
    r.connection_limit = 5;
    r.connection_limit_per_source = true;
    ruleset.rules.push(r);
    write_json(dir.path(), "rules.json", &ruleset);

    let script = r#"
set -eu
unshare -n sleep 60 &
client=$!
trap 'kill $client 2>/dev/null' EXIT
i=0
while [ "$(readlink /proc/$client/ns/net)" = "$(readlink /proc/self/ns/net)" ]; do
    i=$((i + 1)); [ $i -lt 100 ] || { echo "client namespace not ready" >&2; exit 1; }
    sleep 0.05
done
ip link set lo up
ip link add v0 type veth peer name v1 netns "$client"
ip addr add 10.9.0.1/24 dev v0
ip link set v0 up
nsenter -t "$client" -n sh -c 'ip link set lo up && ip addr add 10.9.0.2/24 dev v1 \
    && ip addr add 10.9.0.3/24 dev v1 && ip link set v1 up'
nft -j -f rules.json
attempt() { # source port
    nsenter -t "$client" -n ip route replace 10.9.0.1/32 dev v1 src "$1"
    if out=$(nsenter -t "$client" -n timeout 3 bash -c "exec 3<>/dev/tcp/10.9.0.1/$2" 2>&1); then
        echo "$1 connected"
    else
        case $out in
            *refused*) echo "$1 accepted" ;;
            *) echo "$1 blocked" ;;
        esac
    fi
}
for src in 10.9.0.2 10.9.0.2 10.9.0.2 10.9.0.3 10.9.0.3 10.9.0.3; do
    attempt "$src" 2222
done
attempt 10.9.0.2 2223 > /dev/null
nft list set inet drfw rl4_0123456789ab > rate_set.out
nft list set inet drfw cl4_fedcba987654 > conn_set.out
# The revert guard restores `nft list table` output: it must reload with the
# dynamic sets populated
{ printf 'add table inet drfw\ndelete table inet drfw\n'; nft list table inet drfw; } > revert.nft
nft -f revert.nft
"#;
    let output = unshare()
        .args(["-rn", "bash", "-c", script])
        .current_dir(dir.path())
        .output()
        .expect("failed to spawn unshare");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "behaviour script failed:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let outcomes: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        outcomes,
        [
            "10.9.0.2 accepted",
            "10.9.0.2 accepted",
            "10.9.0.2 blocked",
            // The first client's exhausted budget does not affect the second
            "10.9.0.3 accepted",
            "10.9.0.3 accepted",
            "10.9.0.3 blocked",
        ],
        "burst 2 per source"
    );
    let rate_set = read(dir.path(), "rate_set.out");
    for element in [
        "10.9.0.2 limit rate 2/minute",
        "10.9.0.3 limit rate 2/minute",
    ] {
        assert!(rate_set.contains(element), "{element} missing:\n{rate_set}");
    }
    let conn_set = read(dir.path(), "conn_set.out");
    assert!(conn_set.contains("flags dynamic"), "{conn_set}");
}

/// The interface validator accepts exactly the names nft accepts: at most
/// 15 characters, a trailing `*` included.
#[test]
fn test_interface_length_limit_matches_nft() {
    if !real_nft_available() {
        return;
    }
    let names = [
        "eth*".to_string(),
        "a".repeat(15),
        "a".repeat(16),
        format!("{}*", "a".repeat(14)),
        format!("{}*", "a".repeat(15)),
    ];
    for name in names {
        let dir = work_dir();
        let mut r = rule("Iface", Protocol::Tcp, vec![PortEntry::Single(22)]);
        r.interface = Some(name.clone());
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(r);
        write_json(dir.path(), "rules.json", &ruleset);
        let loaded = run_in_netns(dir.path(), "nft -j -f rules.json")
            .status
            .success();
        assert_eq!(
            drfw::validators::validate_interface(&name).is_ok(),
            loaded,
            "{name:?} ({} chars): validator and nft disagree",
            name.len()
        );
    }
}

/// Behaviour: a user "Drop Any from <peer>" rule also stops the peer's ICMP
/// (ping) in the default (non-strict) mode: user rules come before the
/// "allow icmp" base rules. Without the rule the peer can ping.
///
/// Two network namespaces joined by a veth pair; the peer pings from its own
/// namespace.
#[test]
fn test_user_drop_rule_blocks_ping() {
    if !real_nft_available() {
        return;
    }
    let missing = common::missing_tools(&["ip", "nsenter", "ping"]);
    if !missing.is_empty() {
        common::skip("ping behaviour test", &format!("missing {missing:?}"));
        return;
    }

    let dir = work_dir();
    write_json(dir.path(), "open.json", &FirewallRuleset::new());
    let mut drop_peer = FirewallRuleset::new();
    let mut r = rule("Drop peer", Protocol::Any, vec![]);
    r.action = Action::Drop;
    r.sources = nets(&["10.9.0.2", "fd09::2"]);
    drop_peer.rules.push(r);
    write_json(dir.path(), "drop.json", &drop_peer);

    let script = r#"
set -eu
unshare -n sleep 60 &
peer=$!
trap 'kill $peer 2>/dev/null' EXIT
i=0
while [ "$(readlink /proc/$peer/ns/net)" = "$(readlink /proc/self/ns/net)" ]; do
    i=$((i + 1)); [ $i -lt 100 ] || { echo "peer namespace not ready" >&2; exit 1; }
    sleep 0.05
done
ip link set lo up
ip link add v0 type veth peer name v1 netns "$peer"
ip addr add 10.9.0.1/24 dev v0
ip -6 addr add fd09::1/64 dev v0 nodad
ip link set v0 up
nsenter -t "$peer" -n sh -c 'ip link set lo up && ip addr add 10.9.0.2/24 dev v1     && ip -6 addr add fd09::2/64 dev v1 nodad && ip link set v1 up'
ping_from_peer() {
    if nsenter -t "$peer" -n ping -c1 -W1 "$1" >/dev/null 2>&1; then echo "$2 $1 ok"; else echo "$2 $1 blocked"; fi
}
nft -j -f open.json
ping_from_peer 10.9.0.1 open
ping_from_peer fd09::1 open
nft -j -f drop.json
ping_from_peer 10.9.0.1 drop
ping_from_peer fd09::1 drop
"#;
    let output = unshare()
        .args(["-rn", "sh", "-c", script])
        .current_dir(dir.path())
        .output()
        .expect("failed to spawn unshare");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "ping script failed:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        [
            "open 10.9.0.1 ok",
            "open fd09::1 ok",
            "drop 10.9.0.1 blocked",
            "drop fd09::1 blocked",
        ]
    );
}

#[test]
fn test_server_mode_keeps_loopback_working() {
    if !real_nft_available() {
        return;
    }
    if Command::new("ping").arg("-V").output().is_err() {
        eprintln!("SKIPPING loopback ping test: ping not installed");
        return;
    }
    let dir = work_dir();

    // Control: a bare output policy drop must break loopback ping, otherwise
    // this test could not detect a lockout.
    let control = run_in_netns(
        dir.path(),
        "ip link set lo up && nft add table inet t \
         && nft add chain inet t o '{ type filter hook output priority 0; policy drop; }' \
         && ping -c1 -W1 127.0.0.1",
    );
    if control.status.success() {
        eprintln!("SKIPPING loopback ping test: ping not filtered in this namespace");
        return;
    }

    let mut ruleset = FirewallRuleset::new();
    ruleset.advanced_security.egress_profile = EgressProfile::Server;
    ruleset.advanced_security.strict_icmp = true;
    write_ruleset(dir.path(), &ruleset);
    run_in_netns_ok(
        dir.path(),
        "ip link set lo up && nft -f rules.nft \
         && ping -c1 -W1 127.0.0.1 && ping -c1 -W1 ::1",
    );
}

#[test]
fn test_save_config_script_with_real_nft() {
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    let target = dir.path().join("nftables.conf");
    let backup = dir.path().join("nftables.conf.drfw-bak");
    let tmp = dir.path().join(".nftables.conf.drfw-tmp");

    // nft wrapper: the save script's `nft -c` runs inside a private namespace,
    // with the nft the library uses
    let wrapper = dir.path().join("nft-wrapper.sh");
    std::fs::write(
        &wrapper,
        format!("#!/bin/sh\nexec unshare -rn {} \"$@\"\n", common::nft()),
    )
    .expect("write wrapper");
    set_mode(&wrapper, 0o755);

    std::fs::write(&target, "# old config\n").expect("write old config");
    set_mode(&target, 0o600);

    // The only test in this binary that sets DRFW_NFT_COMMAND (after the
    // probe above, which refuses it): restored when the guard drops
    let mut env = common::EnvVarGuard::lock();
    env.set("DRFW_NFT_COMMAND", &wrapper);
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let target_str = target.to_str().expect("utf-8 temp path");

    // 1. Valid content: installed, old file backed up with its permissions
    let mut ruleset = FirewallRuleset::new();
    ruleset.rules = kitchen_sink_rules();
    let text = ruleset.to_nft_text();
    let output = runtime
        .block_on(drfw::core::system_config::write_config_file(
            &text, target_str,
        ))
        .expect("run save script");
    assert!(
        output.status.success(),
        "save failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&target).expect("read target"), text);
    assert_eq!(mode_of(&target), 0o644);
    assert_eq!(
        std::fs::read_to_string(&backup).expect("read backup"),
        "# old config\n"
    );
    assert_eq!(
        mode_of(&backup),
        0o600,
        "backup must keep original permissions"
    );
    assert_eq!(
        drfw::core::system_config::backup_path_from_output(&output),
        Some(backup.clone())
    );
    assert!(!tmp.exists());

    // 2. Invalid content: rejected by nft -c, target and backup untouched
    let output = runtime
        .block_on(drfw::core::system_config::write_config_file(
            "table inet drfw { chain input { bogus } }\n",
            target_str,
        ))
        .expect("run save script");
    assert_eq!(output.status.code(), Some(3), "nft rejection exit code");
    assert_eq!(std::fs::read_to_string(&target).expect("read target"), text);
    assert_eq!(
        std::fs::read_to_string(&backup).expect("read backup"),
        "# old config\n"
    );
    assert!(!tmp.exists(), "temp file must be removed on failure");

    // 3. A second valid save: .drfw-bak holds the previous save, while
    //    .drfw-orig keeps the very first (pre-DRFW) config forever
    let orig = dir.path().join("nftables.conf.drfw-orig");
    let mut second = FirewallRuleset::new();
    second.advanced_security.egress_profile = EgressProfile::Server;
    let second_text = second.to_nft_text();
    let output = runtime
        .block_on(drfw::core::system_config::write_config_file(
            &second_text,
            target_str,
        ))
        .expect("run save script");
    drop(env);
    assert!(
        output.status.success(),
        "second save failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("read target"),
        second_text
    );
    assert_eq!(std::fs::read_to_string(&backup).expect("read backup"), text);
    assert_eq!(
        std::fs::read_to_string(&orig).expect("read orig"),
        "# old config\n",
        ".drfw-orig must never be overwritten"
    );
    assert_eq!(mode_of(&orig), 0o600);
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

// ============================================================================
// Revert guard (APPLY_SCRIPT + watcher) against the real kernel
// ============================================================================
//
// Each test runs the apply script, its detached (`setsid`) watcher and all
// checks inside ONE `unshare -rn` session, so the watcher acts on the same
// private network namespace the test inspects. The script runs unelevated with
// the real `nft`, exactly as with `DRFW_NFT_COMMAND`.

/// Shell helpers available to every guard session:
/// - `guard_apply FILE TIMEOUT NONCE`: runs `APPLY_SCRIPT` with FILE on stdin
/// - `wait_status NONCE`: waits (max 30 s, a generous bound for a loaded
///   machine; it returns as soon as the status exists) for the watcher's
///   status and prints it
/// - `wait_watcher_exit APPLY_OUTPUT`: waits (max 30 s) until the `setsid`
///   watcher named in an apply's output (`watcher=setsid:<pid>`) has exited:
///   from then on nothing can change the rules any more
const GUARD_HELPERS: &str = r#"
set -u
mkdir -p confirm
guard_apply() {
    sh -c "$DRFW_APPLY_SCRIPT" drfw-apply "$PWD/state" "$2" "$3" "$PWD/confirm" nft setsid \
        "$(id -u)" < "$1"
}
wait_status() {
    i=0
    while [ ! -e "state/status-$1" ] && [ "$i" -lt 300 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    cat "state/status-$1"
}
wait_watcher_exit() {
    pid=$(sed -n 's/^watcher=setsid://p' "$1")
    [ -n "$pid" ] || { echo "no setsid watcher in $1" >&2; return 1; }
    i=0
    while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 300 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    ! kill -0 "$pid" 2>/dev/null
}
"#;

/// Guard timeout for tests that must observe the new rules while the guard
/// is still pending: long enough that a loaded machine cannot revert them
/// before the test looks (the tests wait for the outcome, not for this).
const PENDING_TIMEOUT_SECS: u32 = 4;

const NONCE_A: &str = "0123456789abcdef0123456789abcdef";
const NONCE_B: &str = "fedcba9876543210fedcba9876543210";

/// Runs `body` (after [`GUARD_HELPERS`]) in one private namespace session.
fn run_guard_session(dir: &Path, body: &str) -> Output {
    let script = format!("{GUARD_HELPERS}\n{body}");
    let output = unshare()
        .args(["-rn", "/bin/sh", "-c", &script])
        .env("DRFW_APPLY_SCRIPT", drfw::elevation::APPLY_SCRIPT)
        .current_dir(dir)
        .output()
        .expect("failed to spawn unshare");
    assert!(
        output.status.success(),
        "guard session failed: {body}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Reads a file the session wrote into `dir`.
fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// Normalized `nft -j list` output the session wrote into `dir`.
fn listing(dir: &Path, name: &str) -> serde_json::Value {
    normalize_listing(&std::fs::read(dir.join(name)).expect("read listing"))
}

/// Writes `ruleset`'s JSON into `dir/name`.
fn write_json(dir: &Path, name: &str, ruleset: &FirewallRuleset) {
    std::fs::write(
        dir.join(name),
        serde_json::to_string(&ruleset.to_nftables_json()).expect("serialize JSON"),
    )
    .expect("write JSON");
}

/// A ruleset that differs visibly from [`kitchen_sink_rules`].
fn other_ruleset() -> FirewallRuleset {
    let mut ruleset = FirewallRuleset::new();
    ruleset.rules = vec![rule(
        "Only HTTPS",
        Protocol::Tcp,
        vec![PortEntry::Single(443)],
    )];
    ruleset.advanced_security.egress_profile = EgressProfile::Server;
    ruleset
}

fn kitchen_sink_ruleset() -> FirewallRuleset {
    let mut ruleset = FirewallRuleset::new();
    ruleset.rules = kitchen_sink_rules();
    ruleset
}

/// The old lockout bug: the very first apply (no drfw table yet) timing out
/// must remove the table, not leave empty drop-policy chains behind.
#[test]
fn test_guard_first_apply_timeout_removes_table() {
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    write_json(dir.path(), "new.json", &kitchen_sink_ruleset());
    let out = run_guard_session(
        dir.path(),
        &format!(
            "guard_apply new.json {PENDING_TIMEOUT_SECS} {NONCE_A} > apply.out
             nft list tables > during.out
             wait_status {NONCE_A} > status.out
             nft list tables > after.out"
        ),
    );
    let apply_out = read(dir.path(), "apply.out");
    assert!(
        apply_out.contains("watcher=setsid:"),
        "apply output: {apply_out}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(read(dir.path(), "during.out").contains("table inet drfw"));
    assert_eq!(read(dir.path(), "status.out"), "reverted\n");
    assert!(
        !read(dir.path(), "after.out").contains("table inet drfw"),
        "the drfw table must be gone after reverting a first apply"
    );
    // The watcher cleans up after itself
    assert!(
        !dir.path()
            .join(format!("state/revert-{NONCE_A}.nft"))
            .exists()
    );
    assert!(
        !dir.path()
            .join(format!("state/watcher-{NONCE_A}.sh"))
            .exists()
    );
    assert!(!dir.path().join("state/active").exists());
}

/// An existing drfw table is restored exactly when the guard times out.
#[test]
fn test_guard_timeout_restores_previous_ruleset_exactly() {
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    write_json(dir.path(), "old.json", &kitchen_sink_ruleset());
    write_json(dir.path(), "new.json", &other_ruleset());
    run_guard_session(
        dir.path(),
        &format!(
            "nft -j -f old.json
             nft -j list table inet drfw > before.json
             guard_apply new.json {PENDING_TIMEOUT_SECS} {NONCE_A} > /dev/null
             nft -j list table inet drfw > during.json
             wait_status {NONCE_A} > status.out
             nft -j list table inet drfw > after.json"
        ),
    );
    assert_eq!(read(dir.path(), "status.out"), "reverted\n");
    let before = listing(dir.path(), "before.json");
    let during = listing(dir.path(), "during.json");
    let after = listing(dir.path(), "after.json");
    assert_ne!(before, during, "the new ruleset must have been applied");
    assert!(
        listing_difference(&before, &after).is_none(),
        "revert must restore exactly the previous table: {}",
        listing_difference(&before, &after).unwrap_or_default()
    );
}

/// A confirm token before the timeout keeps the new rules.
#[test]
fn test_guard_confirm_token_keeps_new_rules() {
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    write_json(dir.path(), "old.json", &other_ruleset());
    write_json(dir.path(), "new.json", &kitchen_sink_ruleset());
    run_guard_session(
        dir.path(),
        &format!(
            "nft -j -f old.json
             guard_apply new.json {PENDING_TIMEOUT_SECS} {NONCE_A} > apply.out
             nft -j list table inet drfw > during.json
             touch confirm/drfw-confirm-{NONCE_A}
             wait_status {NONCE_A} > status.out
             wait_watcher_exit apply.out
             nft -j list table inet drfw > after.json"
        ),
    );
    assert_eq!(read(dir.path(), "status.out"), "confirmed\n");
    assert_eq!(
        listing(dir.path(), "during.json"),
        listing(dir.path(), "after.json"),
        "confirmed rules must stay: the watcher exited without reverting"
    );
    // The watcher never deletes (or otherwise touches) the user's token
    assert!(
        dir.path()
            .join(format!("confirm/drfw-confirm-{NONCE_A}"))
            .exists()
    );
}

/// Only tokens owned by the applying user count: a confirm token owned by
/// anyone else is ignored and the rules revert. (The namespace maps a single
/// uid, so the guard is told that a different uid applied.)
#[test]
fn test_guard_ignores_tokens_of_other_users() {
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    write_json(dir.path(), "new.json", &kitchen_sink_ruleset());
    run_guard_session(
        dir.path(),
        &format!(
            r#"sh -c "$DRFW_APPLY_SCRIPT" drfw-apply "$PWD/state" 2 {NONCE_A} "$PWD/confirm" nft \
                 setsid "$(( $(id -u) + 1 ))" < new.json > /dev/null
             touch confirm/drfw-confirm-{NONCE_A}
             wait_status {NONCE_A} > status.out
             nft list tables > after.out"#
        ),
    );
    assert_eq!(read(dir.path(), "status.out"), "reverted\n");
    assert!(!read(dir.path(), "after.out").contains("table inet drfw"));
}

/// A revert token reverts immediately, long before the timeout.
#[test]
fn test_guard_revert_token_reverts_immediately() {
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    write_json(dir.path(), "new.json", &kitchen_sink_ruleset());
    let start = std::time::Instant::now();
    run_guard_session(
        dir.path(),
        &format!(
            "guard_apply new.json 60 {NONCE_A} > /dev/null
             touch confirm/drfw-revert-{NONCE_A}
             wait_status {NONCE_A} > status.out
             nft list tables > after.out"
        ),
    );
    assert_eq!(read(dir.path(), "status.out"), "reverted\n");
    assert!(!read(dir.path(), "after.out").contains("table inet drfw"));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(15),
        "revert token must not wait for the 60 s timeout"
    );
}

/// A second apply supersedes the first guard and inherits its baseline: if
/// the second one times out, the state from before the FIRST (unconfirmed)
/// apply comes back.
#[test]
fn test_guard_second_apply_supersedes_first() {
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    let mut base = FirewallRuleset::new();
    base.rules = vec![rule("SSH", Protocol::Tcp, vec![PortEntry::Single(22)])];
    write_json(dir.path(), "base.json", &base);
    write_json(dir.path(), "first.json", &kitchen_sink_ruleset());
    write_json(dir.path(), "second.json", &other_ruleset());
    run_guard_session(
        dir.path(),
        &format!(
            "nft -j -f base.json
             nft -j list table inet drfw > before.json
             guard_apply first.json 60 {NONCE_A} > apply_a.out
             guard_apply second.json 1 {NONCE_B} > /dev/null
             wait_status {NONCE_A} > status_a.out
             wait_status {NONCE_B} > status_b.out
             wait_watcher_exit apply_a.out
             cat state/status-{NONCE_A} > status_a_later.out
             nft -j list table inet drfw > after.json"
        ),
    );
    assert_eq!(read(dir.path(), "status_a.out"), "superseded\n");
    assert_eq!(read(dir.path(), "status_b.out"), "reverted\n");
    assert_eq!(
        read(dir.path(), "status_a_later.out"),
        "superseded\n",
        "the superseded watcher exited without acting"
    );
    let before = listing(dir.path(), "before.json");
    let after = listing(dir.path(), "after.json");
    assert!(
        listing_difference(&before, &after).is_none(),
        "must return to the last confirmed state: {}",
        listing_difference(&before, &after).unwrap_or_default()
    );
}

/// An invalid ruleset is rejected with exit 3; nothing changes, and the
/// watcher (started before the apply) exits without reverting.
#[test]
fn test_guard_invalid_ruleset_exits_3_without_watcher() {
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    std::fs::write(
        dir.path().join("bad.json"),
        r#"{"nftables":[{"add":{"table":{"family":"inet","name":"drfw"}}},{"add":{"rule":{"family":"inet","table":"drfw","chain":"nope","expr":[{"accept":null}]}}}]}"#,
    )
    .expect("write bad.json");
    write_json(dir.path(), "old.json", &other_ruleset());
    run_guard_session(
        dir.path(),
        &format!(
            "nft -j -f old.json
             nft -j list table inet drfw > before.json
             rc=0
             guard_apply bad.json 1 {NONCE_A} > apply.out 2> apply.err || rc=$?
             echo $rc > rc.out
             # Past the 1 s deadline: a watcher that wrongly reverted would
             # have done so (it prints no pid to wait for on this path)
             sleep 2
             ls -A state > state.ls
             cat state/status-{NONCE_A} > status.out
             nft -j list table inet drfw > after.json"
        ),
    );
    assert_eq!(
        read(dir.path(), "rc.out"),
        "3\n",
        "stderr: {}",
        read(dir.path(), "apply.err")
    );
    assert!(read(dir.path(), "apply.err").contains("nft rejected the ruleset"));
    let state = read(dir.path(), "state.ls");
    assert!(
        !state.contains("watcher-")
            && !state.contains("revert-")
            && !state.contains("armed-")
            && !state.contains("active"),
        "no guard may be left behind: {state}"
    );
    assert_eq!(read(dir.path(), "status.out"), "not-applied\n");
    assert_eq!(
        listing(dir.path(), "before.json"),
        listing(dir.path(), "after.json")
    );
}

/// Unguarded apply (timeout 0) just applies and starts nothing.
#[test]
fn test_guard_timeout_zero_just_applies() {
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    write_json(dir.path(), "new.json", &other_ruleset());
    run_guard_session(
        dir.path(),
        &format!(
            "guard_apply new.json 0 {NONCE_A} > apply.out
             ls -A state > state.ls
             nft list tables > after.out"
        ),
    );
    assert_eq!(
        read(dir.path(), "apply.out"),
        "drfw-apply-started\nwatcher=none\n"
    );
    assert!(read(dir.path(), "after.out").contains("table inet drfw"));
    assert!(!read(dir.path(), "state.ls").contains(NONCE_A));
}

/// An nft wrapper for the signal tests: for the apply itself
/// (`nft --json -f -`) it applies, creates `applied.flag` and then keeps
/// running for 3 s, so the test can signal the apply script while the new
/// rules are already live but the script has not finished.
const SLOW_APPLY_NFT: &str = r#"#!/bin/sh
if [ "$1" = --json ] && [ "$2" = -f ] && [ "$3" = - ]; then
    nft "$@" || exit $?
    : > applied.flag
    sleep 3
    exit 0
fi
exec nft "$@"
"#;

/// Starts `APPLY_SCRIPT` in the background with [`SLOW_APPLY_NFT`] and a 4 s
/// guard, sends it `signal` as soon as the new rules are live and records
/// what happens. Returns how long the session took: the revert must come on
/// time (the wrapper's 3 s, the 4 s guard, polling), not only eventually.
fn guard_signal_session(dir: &Path, signal: &str) -> std::time::Duration {
    let start = std::time::Instant::now();
    std::fs::write(dir.join("nft-slow.sh"), SLOW_APPLY_NFT).expect("write wrapper");
    set_mode(&dir.join("nft-slow.sh"), 0o755);
    write_json(dir, "new.json", &kitchen_sink_ruleset());
    run_guard_session(
        dir,
        &format!(
            r#"sh -c "$DRFW_APPLY_SCRIPT" drfw-apply "$PWD/state" 4 {NONCE_A} "$PWD/confirm" \
                 "$PWD/nft-slow.sh" setsid "$(id -u)" < new.json > apply.out 2> apply.err &
             pid=$!
             i=0
             while [ ! -e applied.flag ] && [ "$i" -lt 100 ]; do sleep 0.05; i=$((i + 1)); done
             nft list tables > during.out
             kill -{signal} "$pid"
             rc=0
             wait "$pid" || rc=$?
             echo "$rc" > rc.out
             wait_status {NONCE_A} > status.out
             nft list tables > after.out"#
        ),
    );
    start.elapsed()
}

/// Upper bound for [`guard_signal_session`]: 3 s wrapper + 4 s guard + 1 s
/// poll (about 8 s), plus generous slack for a loaded machine. Below the
/// 30 s that `wait_status` waits, so a late revert fails here, by name.
const SIGNAL_SESSION_MAX: std::time::Duration = std::time::Duration::from_secs(20);

/// The signal window: a SIGHUP (SSH drop), SIGINT (Ctrl-C after the
/// password) or SIGTERM while the new rules are live must not leave them
/// without a guard. The script ignores those signals and finishes.
fn check_ignored_signal_still_reverts(signal: &str) {
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    let took = guard_signal_session(dir.path(), signal);
    assert!(
        took < SIGNAL_SESSION_MAX,
        "SIG{signal}: revert took {took:?}"
    );
    assert!(
        read(dir.path(), "during.out").contains("table inet drfw"),
        "SIG{signal}: the new rules must have been live when the signal came"
    );
    assert_eq!(
        read(dir.path(), "status.out"),
        "reverted\n",
        "SIG{signal}: rc {} stderr: {}",
        read(dir.path(), "rc.out"),
        read(dir.path(), "apply.err")
    );
    assert_eq!(read(dir.path(), "rc.out"), "0\n", "SIG{signal} is ignored");
    assert!(
        !read(dir.path(), "after.out").contains("table inet drfw"),
        "SIG{signal}: the revert must remove the first apply's table"
    );
}

/// SIGHUP: the SSH connection dropped.
#[test]
fn test_guard_sighup_after_apply_still_reverts() {
    check_ignored_signal_still_reverts("HUP");
}

/// SIGINT: Ctrl-C after the password.
#[test]
fn test_guard_sigint_after_apply_still_reverts() {
    check_ignored_signal_still_reverts("INT");
}

/// SIGTERM: the elevation tool or session was terminated.
#[test]
fn test_guard_sigterm_after_apply_still_reverts() {
    check_ignored_signal_still_reverts("TERM");
}

/// Even SIGKILL (which cannot be ignored) right after the rules went live
/// leaves a guard: the watcher is started before the ruleset is applied.
#[test]
fn test_guard_sigkill_after_apply_still_reverts() {
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    let took = guard_signal_session(dir.path(), "KILL");
    assert!(took < SIGNAL_SESSION_MAX, "revert took {took:?}");
    assert!(read(dir.path(), "during.out").contains("table inet drfw"));
    assert_eq!(
        read(dir.path(), "status.out"),
        "reverted\n",
        "stderr: {}",
        read(dir.path(), "apply.err")
    );
    assert!(!read(dir.path(), "after.out").contains("table inet drfw"));
}

/// A watcher that is terminated (`systemctl stop`, `kill`, shutdown) before
/// the rules are confirmed reverts them at once, long before its deadline.
/// The revert file and the watcher script are readable by root only; the
/// status and `active` are world-readable.
#[test]
fn test_guard_terminated_watcher_reverts() {
    use std::os::unix::fs::PermissionsExt;
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    write_json(dir.path(), "new.json", &kitchen_sink_ruleset());
    let start = std::time::Instant::now();
    run_guard_session(
        dir.path(),
        &format!(
            "guard_apply new.json 120 {NONCE_A} > apply.out
             stat -c '%n %a' state state/active state/revert-{NONCE_A}.nft \
                 state/watcher-{NONCE_A}.sh > modes.out
             nft list tables > during.out
             kill -TERM \"$(sed -n 's/^watcher=setsid://p' apply.out)\"
             wait_status {NONCE_A} > status.out
             stat -c '%a' state/status-{NONCE_A} > status_mode.out
             nft list tables > after.out"
        ),
    );
    let took = start.elapsed();
    assert!(read(dir.path(), "during.out").contains("table inet drfw"));
    assert_eq!(read(dir.path(), "status.out"), "reverted\n");
    assert!(
        took < std::time::Duration::from_secs(30),
        "reverted on the signal, not at the 120 s deadline: {took:?}"
    );
    assert!(!read(dir.path(), "after.out").contains("table inet drfw"));
    let modes = read(dir.path(), "modes.out");
    for (file, mode) in [
        ("state", "755"),
        ("state/active", "644"),
        ("revert-", "600"),
        ("watcher-", "600"),
    ] {
        assert!(
            modes
                .lines()
                .any(|l| l.contains(file) && l.ends_with(&format!(" {mode}"))),
            "{file} must be mode {mode}: {modes}"
        );
    }
    assert_eq!(read(dir.path(), "status_mode.out"), "644\n");
    let state = dir.path().join("state");
    let mode = std::fs::metadata(&state).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
}

/// A watcher killed with `SIGKILL` (no outcome) is reported as lost by
/// `pending_guard`, not as a pending revert; while it runs it is pending.
#[test]
fn test_guard_killed_watcher_is_reported_lost() {
    use drfw::core::apply_guard::{WatcherState, pending_guard};
    if !real_nft_available() || !common::script_paths_usable() {
        return;
    }
    let dir = work_dir();
    write_json(dir.path(), "new.json", &kitchen_sink_ruleset());
    // The session ends with the watcher still running (120 s guard)
    run_guard_session(
        dir.path(),
        &format!("guard_apply new.json 120 {NONCE_A} > apply.out"),
    );
    let apply = read(dir.path(), "apply.out");
    let pid = apply
        .lines()
        .find_map(|l| l.strip_prefix("watcher=setsid:"))
        .expect("setsid watcher")
        .to_string();
    let state = dir.path().join("state");
    let pending = pending_guard(&state).unwrap().expect("pending");
    assert_eq!(pending.watcher, WatcherState::Running, "{apply}");
    let killed = Command::new("kill")
        .args(["-KILL", &pid])
        .status()
        .expect("run kill");
    assert!(killed.success());
    let mut watcher = WatcherState::Running;
    for _ in 0..100 {
        watcher = pending_guard(&state)
            .unwrap()
            .expect("still no outcome")
            .watcher;
        if watcher != WatcherState::Running {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(watcher, WatcherState::Gone);
}

// ============================================================================
// The root helper (`drfw-helper`) in test mode, against the real kernel
// ============================================================================
//
// The helper runs as root of the namespace (`unshare -rn`), in its debug-build
// test mode (`DRFW_HELPER_TEST_MODE=1`): the state directory, config file and
// nft come from `DRFW_HELPER_TEST_*` instead of this build's fixed paths, the
// watcher is started with `setsid`, and the caller uid is the namespace's 0.
// Everything else is the production path: argv validation, the payload check,
// the cleared environment, then `exec` of the same fixed script.

/// The helper binary built with these tests.
const HELPER: &str = env!("CARGO_BIN_EXE_drfw-helper");

/// Shell helpers for helper sessions (after [`GUARD_HELPERS`]):
/// - `helper ARGS…`: runs `drfw-helper` in test mode
/// - `helper_apply FILE TIMEOUT NONCE`: `helper apply` with FILE on stdin and
///   exactly the arguments DRFW builds
/// - `helper_save FILE`: `helper save-config` of FILE to `$PWD/nftables.conf`
const HELPER_HELPERS: &str = r#"
helper() {
    env DRFW_HELPER_TEST_MODE=1 DRFW_HELPER_TEST_STATE_DIR="$PWD/state" \
        DRFW_HELPER_TEST_TARGET="$PWD/nftables.conf" DRFW_HELPER_TEST_NFT="$DRFW_NFT" \
        "$DRFW_HELPER" "$@"
}
helper_apply() {
    helper apply "$PWD/state" "$2" "$3" "$PWD/confirm" "$DRFW_NFT" setsid "$(id -u)" < "$1"
}
helper_save() {
    helper save-config "$PWD/nftables.conf" "$DRFW_NFT" "" < "$1"
}
"#;

/// The helper's test mode exists only in debug builds (`cargo test`).
fn helper_test_mode_available() -> bool {
    if cfg!(debug_assertions) {
        return true;
    }
    eprintln!("SKIPPING drfw-helper namespace test: release build (no test mode)");
    false
}

/// Runs `body` (after [`GUARD_HELPERS`] and [`HELPER_HELPERS`]) in one
/// private namespace session.
fn run_helper_session(dir: &Path, body: &str) -> Output {
    let script = format!("{GUARD_HELPERS}\n{HELPER_HELPERS}\n{body}");
    let output = unshare()
        .args(["-rn", "/bin/sh", "-c", &script])
        .env("DRFW_HELPER", HELPER)
        .env("DRFW_NFT", common::nft())
        .current_dir(dir)
        .output()
        .expect("failed to spawn unshare");
    assert!(
        output.status.success(),
        "helper session failed: {body}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// The `nft` path must be absolute for the helper's test override.
fn nft_is_absolute() -> bool {
    if Path::new(common::nft()).is_absolute() {
        return true;
    }
    common::skip(
        "drfw-helper namespace test",
        "nft was not found at an absolute path",
    )
}

/// Apply through the helper: the guard works exactly as with the script.
/// A confirmed apply stays; a second apply that times out returns to it.
#[test]
fn test_helper_apply_confirm_then_timeout() {
    if !helper_test_mode_available()
        || !real_nft_available()
        || !common::script_paths_usable()
        || !nft_is_absolute()
    {
        return;
    }
    let dir = work_dir();
    write_json(dir.path(), "first.json", &kitchen_sink_ruleset());
    write_json(dir.path(), "second.json", &other_ruleset());
    run_helper_session(
        dir.path(),
        &format!(
            "helper_apply first.json {PENDING_TIMEOUT_SECS} {NONCE_A} > apply_a.out
             echo $? > rc_a.out
             nft -j list table inet drfw > kept.json
             touch confirm/drfw-confirm-{NONCE_A}
             wait_status {NONCE_A} > status_a.out
             wait_watcher_exit apply_a.out
             helper_apply second.json 1 {NONCE_B} > apply_b.out
             echo $? > rc_b.out
             wait_status {NONCE_B} > status_b.out
             wait_watcher_exit apply_b.out
             nft -j list table inet drfw > after.json"
        ),
    );
    assert_eq!(read(dir.path(), "rc_a.out"), "0\n");
    assert_eq!(read(dir.path(), "rc_b.out"), "0\n");
    let apply_a = read(dir.path(), "apply_a.out");
    assert!(
        apply_a.starts_with("drfw-apply-started\n") && apply_a.contains("watcher=setsid:"),
        "{apply_a}"
    );
    assert_eq!(read(dir.path(), "status_a.out"), "confirmed\n");
    assert_eq!(read(dir.path(), "status_b.out"), "reverted\n");
    let kept = listing(dir.path(), "kept.json");
    let after = listing(dir.path(), "after.json");
    assert!(
        listing_difference(&kept, &after).is_none(),
        "the timed-out apply must return to the confirmed rules: {}",
        listing_difference(&kept, &after).unwrap_or_default()
    );
}

/// Refused requests change nothing: a foreign state directory, a uid that is
/// not the caller's, and an `include` payload (which root nft would follow:
/// the session first shows that plain `nft -j -c` echoes the file's content).
#[test]
fn test_helper_refusals_change_nothing() {
    if !helper_test_mode_available()
        || !real_nft_available()
        || !common::script_paths_usable()
        || !nft_is_absolute()
    {
        return;
    }
    let dir = work_dir();
    write_json(dir.path(), "new.json", &kitchen_sink_ruleset());
    std::fs::write(dir.path().join("secret"), "TOPSECRET-CONTENT\n").expect("write secret");
    run_helper_session(
        dir.path(),
        &format!(
            r#"printf 'include "%s"\n' "$PWD/secret" > include.payload
             "$DRFW_NFT" -j -c -f - < include.payload > plain_nft.out 2>&1
             helper check < include.payload > check.out 2> check.err
             echo $? > rc_check.out
             helper_apply include.payload 4 {NONCE_A} > apply_include.out 2> apply_include.err
             echo $? > rc_include.out
             helper apply "$PWD/elsewhere" 4 {NONCE_A} "$PWD/confirm" "$DRFW_NFT" setsid \
                 "$(id -u)" < new.json > apply_dir.out 2> apply_dir.err
             echo $? > rc_dir.out
             helper apply "$PWD/state" 4 {NONCE_A} "$PWD/confirm" "$DRFW_NFT" setsid \
                 "$(( $(id -u) + 1 ))" < new.json > apply_uid.out 2> apply_uid.err
             echo $? > rc_uid.out
             nft list tables > tables.out
             ls -A > files.out"#
        ),
    );
    // Without the helper, root nft would have shown the file
    assert!(
        read(dir.path(), "plain_nft.out").contains("TOPSECRET-CONTENT"),
        "plain nft did not follow the include; the test would prove nothing"
    );
    for (rc, err, reason) in [
        ("rc_check.out", "check.err", "include statement"),
        ("rc_include.out", "apply_include.err", "include statement"),
        ("rc_dir.out", "apply_dir.err", "the state directory must be"),
        (
            "rc_uid.out",
            "apply_uid.err",
            "the uid must be the caller's",
        ),
    ] {
        assert_eq!(
            read(dir.path(), rc),
            "1\n",
            "{err}: {}",
            read(dir.path(), err)
        );
        let err_text = read(dir.path(), err);
        assert!(err_text.contains(reason), "{err}: {err_text}");
        assert!(!err_text.contains("TOPSECRET"), "{err}: {err_text}");
    }
    assert_eq!(read(dir.path(), "check.out"), "");
    assert_eq!(read(dir.path(), "apply_include.out"), "");
    assert!(
        !read(dir.path(), "tables.out").contains("table inet drfw"),
        "a refused apply changed the ruleset"
    );
    let files = read(dir.path(), "files.out");
    assert!(
        !files.lines().any(|f| f == "state" || f == "elsewhere"),
        "a refused apply created its state directory: {files}"
    );
}

/// Save to System through the helper: installs a valid config (backup
/// kept), rejects an invalid one with exit 3 and an `include` with exit 1,
/// both leaving the file untouched.
#[test]
fn test_helper_save_config_and_check() {
    if !helper_test_mode_available()
        || !real_nft_available()
        || !common::script_paths_usable()
        || !nft_is_absolute()
    {
        return;
    }
    let dir = work_dir();
    let text = kitchen_sink_ruleset().to_nft_text();
    std::fs::write(dir.path().join("good.nft"), &text).expect("write good");
    std::fs::write(
        dir.path().join("bad.nft"),
        "table inet drfw { chain input { bogus } }\n",
    )
    .expect("write bad");
    std::fs::write(
        dir.path().join("include.nft"),
        format!("{text}include \"/etc/hostname\"\n"),
    )
    .expect("write include");
    std::fs::write(dir.path().join("nftables.conf"), "# old config\n").expect("write old");
    write_json(dir.path(), "good.json", &kitchen_sink_ruleset());
    std::fs::write(
        dir.path().join("bad.json"),
        r#"{"nftables":[{"add":{"bogus":{}}}]}"#,
    )
    .expect("write bad json");
    run_helper_session(
        dir.path(),
        "helper_save good.nft > save_good.out 2>&1; echo $? > rc_good.out
         cp nftables.conf after_good.conf
         helper_save bad.nft > save_bad.out 2>&1; echo $? > rc_bad.out
         helper_save include.nft > save_include.out 2>&1; echo $? > rc_include.out
         helper check < good.json > check_good.out 2>&1; echo $? > rc_check_good.out
         helper check < bad.json > check_bad.out 2>&1; echo $? > rc_check_bad.out
         nft list tables > tables.out",
    );
    assert_eq!(
        read(dir.path(), "rc_good.out"),
        "0\n",
        "{}",
        read(dir.path(), "save_good.out")
    );
    assert_eq!(read(dir.path(), "after_good.conf"), text);
    assert_eq!(read(dir.path(), "nftables.conf.drfw-bak"), "# old config\n");
    assert!(
        read(dir.path(), "save_good.out").contains("backup="),
        "{}",
        read(dir.path(), "save_good.out")
    );
    assert_eq!(read(dir.path(), "rc_bad.out"), "3\n");
    assert_eq!(read(dir.path(), "rc_include.out"), "1\n");
    assert!(read(dir.path(), "save_include.out").contains("include statement"));
    // Neither failure touched the installed file
    assert_eq!(read(dir.path(), "nftables.conf"), text);
    assert_eq!(read(dir.path(), "rc_check_good.out"), "0\n");
    assert_ne!(read(dir.path(), "rc_check_bad.out"), "0\n");
    // A check never changes the ruleset
    assert!(!read(dir.path(), "tables.out").contains("table inet drfw"));
}

// ============================================================================
// Differential property test
// ============================================================================

fn arb_ip() -> impl Strategy<Value = IpNetwork> {
    prop_oneof![
        (any::<[u8; 4]>(), 0u8..=32).prop_map(|(o, len)| IpNetwork::V4(
            ipnetwork::Ipv4Network::new(std::net::Ipv4Addr::from(o), len).expect("valid prefix")
        )),
        (any::<[u16; 8]>(), 0u8..=128).prop_map(|(s, len)| IpNetwork::V6(
            ipnetwork::Ipv6Network::new(
                std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]),
                len
            )
            .expect("valid prefix")
        )),
    ]
}

fn arb_port_entry() -> impl Strategy<Value = PortEntry> {
    (1u16..=65535, 1u16..=65535).prop_map(|(a, b)| {
        if a == b {
            PortEntry::Single(a)
        } else {
            PortEntry::range(a.min(b), a.max(b))
        }
    })
}

fn arb_interface() -> impl Strategy<Value = Option<String>> {
    proptest::option::of(prop_oneof![
        Just("eth0".to_string()),
        Just("wg*".to_string()),
        Just("br-lan.10".to_string()),
        Just("x\" accept #".to_string()),
        Just("a\\b\nc".to_string()),
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
        label in "\\PC{0,30}",
        protocol in arb_protocol(),
        ports in prop::collection::vec(arb_port_entry(), 0..4),
        sources in prop::collection::vec(arb_ip(), 0..3),
        destinations in prop::collection::vec(arb_ip(), 0..3),
        interface in arb_interface(),
        output_interface in arb_interface(),
        chain in prop_oneof![Just(Chain::Input), Just(Chain::Output), Just(Chain::Forward)],
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
        per_source in any::<(bool, bool)>(),
        log_enabled in any::<bool>(),
        tags in prop::collection::vec("\\PC{0,24}", 0..3),
    ) -> Rule {
        let mut r = Rule::with_caches(
            uuid::Uuid::new_v4(),
            label,
            protocol,
            ports,
            sources,
            interface,
            chain,
            true,
            jiff::Timestamp::now(),
            tags,
        );
        r.destinations = destinations;
        r.output_interface = output_interface;
        r.action = action;
        // TCP reset is only valid for pure TCP (the GUI enforces this)
        r.reject_type = if reject_type == RejectType::TcpReset && protocol != Protocol::Tcp {
            RejectType::Default
        } else {
            reject_type
        };
        r.rate_limit = rate_limit.map(|(count, unit, burst)| RateLimit {
            count,
            unit: [TimeUnit::Second, TimeUnit::Minute, TimeUnit::Hour, TimeUnit::Day][unit],
            burst,
            per_source: per_source.0,
        });
        r.connection_limit = connection_limit;
        r.connection_limit_per_source = per_source.1;
        r.log_enabled = log_enabled;
        r.rebuild_caches();
        r
    }
}

prop_compose! {
    fn arb_ruleset()(
        rules in prop::collection::vec(arb_rule(), 0..8),
        settings in any::<[bool; 6]>(),
        icmp_rate in prop_oneof![Just(0u32), 1u32..50],
    ) -> FirewallRuleset {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules = rules;
        let adv = &mut ruleset.advanced_security;
        adv.strict_icmp = settings[0];
        adv.enable_rpf = settings[1];
        adv.block_forwarding = settings[2];
        adv.log_dropped = settings[3];
        adv.egress_profile = if settings[4] { EgressProfile::Server } else { EgressProfile::Desktop };
        adv.local_discovery = settings[5];
        adv.icmp_rate_limit = icmp_rate;
        ruleset
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: common::proptest_cases(48),
        failure_persistence: Some(common::proptest_persistence("tests/real_nft.proptest-regressions")),
        ..ProptestConfig::default()
    })]

    /// The text file and the JSON must load into byte-identical kernel rulesets.
    #[test]
    fn prop_json_and_text_are_identical_in_kernel(ruleset in arb_ruleset()) {
        if !real_nft_available() {
            return Ok(());
        }
        let dir = work_dir();
        let (from_json, from_text) = apply_both_forms(dir.path(), &ruleset);
        let diff = listing_difference(&from_json, &from_text);
        prop_assert!(diff.is_none(), "JSON and text differ in kernel: {}", diff.unwrap_or_default());
    }
}
