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
//! - The Save to System script, end to end, with the real `nft -c`.
//! - The revert guard (apply script + detached watcher): timeout after a
//!   first apply removes the table, an existing table is restored exactly,
//!   confirm/revert tokens, superseding applies, rejected rulesets.
//!
//! This file has its own rule helpers: integration tests cannot see the
//! library's `#[cfg(test)]` helpers.

use std::path::Path;
use std::process::{Command, Output};
use std::sync::OnceLock;

use drfw::core::firewall::{
    Action, Chain, EgressProfile, FirewallRuleset, PortEntry, Protocol, RateLimit, RejectType,
    Rule, TimeUnit,
};
use ipnetwork::IpNetwork;
use proptest::prelude::*;

// ============================================================================
// Namespace helpers
// ============================================================================

/// Returns true when real nft tests can run; prints a skip notice otherwise.
///
/// Panics instead of skipping when `DRFW_REQUIRE_REAL_NFT=1`.
fn real_nft_available() -> bool {
    static AVAILABLE: OnceLock<Result<(), String>> = OnceLock::new();
    let status = AVAILABLE.get_or_init(|| {
        let output = Command::new("unshare")
            .args(["-rn", "nft", "list", "ruleset"])
            .output()
            .map_err(|e| format!("cannot run unshare: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "`unshare -rn nft list ruleset` failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    });
    match status {
        Ok(()) => true,
        Err(reason) => {
            assert!(
                std::env::var("DRFW_REQUIRE_REAL_NFT").as_deref() != Ok("1"),
                "DRFW_REQUIRE_REAL_NFT=1 but real nft is unavailable: {reason}"
            );
            eprintln!("SKIPPING real nft test: {reason}");
            false
        }
    }
}

/// Runs a `/bin/sh` script in a fresh user + network namespace, in `dir`.
fn run_in_netns(dir: &Path, script: &str) -> Output {
    Command::new("unshare")
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

fn rule(label: &str, protocol: Protocol, ports: Vec<PortEntry>) -> Rule {
    Rule::with_caches(
        uuid::Uuid::new_v4(),
        label.to_string(),
        protocol,
        ports,
        Vec::new(),
        None,
        Chain::Input,
        true,
        jiff::Timestamp::now(),
        Vec::new(),
    )
}

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
    });
    rules.push(r);

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

    let mut r = rule("Outbound DNS", Protocol::Udp, vec![PortEntry::Single(53)]);
    r.chain = Chain::Output;
    r.output_interface = Some("eth*".to_string());
    rules.push(r);

    let mut r = rule("Disabled", Protocol::Tcp, vec![PortEntry::Single(9)]);
    r.enabled = false;
    rules.push(r);

    for r in &mut rules {
        r.rebuild_caches();
    }
    rules
}

/// Every combination of the global settings, each with the kitchen-sink rules.
fn varied_rulesets() -> Vec<(String, FirewallRuleset)> {
    let mut out = Vec::new();
    for bits in 0u8..32 {
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
        adv.icmp_rate_limit = if bits % 3 == 0 { 10 } else { 0 };
        out.push((format!("settings {bits:05b}"), ruleset));
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
    if !real_nft_available() {
        return;
    }
    let dir = work_dir();
    let target = dir.path().join("nftables.conf");
    let backup = dir.path().join("nftables.conf.drfw-bak");
    let tmp = dir.path().join(".nftables.conf.drfw-tmp");

    // nft wrapper: the save script's `nft -c` runs inside a private namespace
    let wrapper = dir.path().join("nft-wrapper.sh");
    std::fs::write(&wrapper, "#!/bin/sh\nexec unshare -rn nft \"$@\"\n").expect("write wrapper");
    set_mode(&wrapper, 0o755);

    std::fs::write(&target, "# old config\n").expect("write old config");
    set_mode(&target, 0o600);

    // SAFETY: this is the only test in this binary that touches DRFW_NFT_COMMAND,
    // and it does so before spawning any task that reads it.
    unsafe {
        std::env::set_var("DRFW_NFT_COMMAND", &wrapper);
    }
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
    unsafe {
        std::env::remove_var("DRFW_NFT_COMMAND");
    }
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
/// - `wait_status NONCE`: waits (max 10 s) for the watcher's status and prints it
const GUARD_HELPERS: &str = r#"
set -u
mkdir -p confirm
guard_apply() {
    sh -c "$DRFW_APPLY_SCRIPT" drfw-apply "$PWD/state" "$2" "$3" "$PWD/confirm" nft setsid < "$1"
}
wait_status() {
    i=0
    while [ ! -e "state/status-$1" ] && [ "$i" -lt 100 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    cat "state/status-$1"
}
"#;

const NONCE_A: &str = "0123456789abcdef0123456789abcdef";
const NONCE_B: &str = "fedcba9876543210fedcba9876543210";

/// Runs `body` (after [`GUARD_HELPERS`]) in one private namespace session.
fn run_guard_session(dir: &Path, body: &str) -> Output {
    let script = format!("{GUARD_HELPERS}\n{body}");
    let output = Command::new("unshare")
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
    if !real_nft_available() {
        return;
    }
    let dir = work_dir();
    write_json(dir.path(), "new.json", &kitchen_sink_ruleset());
    let out = run_guard_session(
        dir.path(),
        &format!(
            "guard_apply new.json 1 {NONCE_A} > apply.out
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
    if !real_nft_available() {
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
             guard_apply new.json 1 {NONCE_A} > /dev/null
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
    if !real_nft_available() {
        return;
    }
    let dir = work_dir();
    write_json(dir.path(), "old.json", &other_ruleset());
    write_json(dir.path(), "new.json", &kitchen_sink_ruleset());
    run_guard_session(
        dir.path(),
        &format!(
            "nft -j -f old.json
             guard_apply new.json 3 {NONCE_A} > /dev/null
             nft -j list table inet drfw > during.json
             touch confirm/drfw-confirm-{NONCE_A}
             wait_status {NONCE_A} > status.out
             sleep 3
             nft -j list table inet drfw > after.json"
        ),
    );
    assert_eq!(read(dir.path(), "status.out"), "confirmed\n");
    assert_eq!(
        listing(dir.path(), "during.json"),
        listing(dir.path(), "after.json"),
        "confirmed rules must stay after the timeout would have passed"
    );
    // The watcher never deletes (or otherwise touches) the user's token
    assert!(
        dir.path()
            .join(format!("confirm/drfw-confirm-{NONCE_A}"))
            .exists()
    );
}

/// A revert token reverts immediately, long before the timeout.
#[test]
fn test_guard_revert_token_reverts_immediately() {
    if !real_nft_available() {
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
    if !real_nft_available() {
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
             guard_apply first.json 60 {NONCE_A} > /dev/null
             guard_apply second.json 1 {NONCE_B} > /dev/null
             wait_status {NONCE_A} > status_a.out
             wait_status {NONCE_B} > status_b.out
             sleep 2
             cat state/status-{NONCE_A} > status_a_later.out
             nft -j list table inet drfw > after.json"
        ),
    );
    assert_eq!(read(dir.path(), "status_a.out"), "superseded\n");
    assert_eq!(read(dir.path(), "status_b.out"), "reverted\n");
    assert_eq!(
        read(dir.path(), "status_a_later.out"),
        "superseded\n",
        "the superseded watcher must not act any more"
    );
    let before = listing(dir.path(), "before.json");
    let after = listing(dir.path(), "after.json");
    assert!(
        listing_difference(&before, &after).is_none(),
        "must return to the last confirmed state: {}",
        listing_difference(&before, &after).unwrap_or_default()
    );
}

/// An invalid ruleset is rejected with exit 3; nothing changes and no
/// watcher is started.
#[test]
fn test_guard_invalid_ruleset_exits_3_without_watcher() {
    if !real_nft_available() {
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
             sleep 2
             ls -A state > state.ls
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
        !state.contains("watcher-") && !state.contains("status-") && !state.contains("revert-"),
        "no guard may be left behind: {state}"
    );
    assert_eq!(
        listing(dir.path(), "before.json"),
        listing(dir.path(), "after.json")
    );
}

/// Unguarded apply (timeout 0) just applies and starts nothing.
#[test]
fn test_guard_timeout_zero_just_applies() {
    if !real_nft_available() {
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
    assert_eq!(read(dir.path(), "apply.out"), "watcher=none\n");
    assert!(read(dir.path(), "after.out").contains("table inet drfw"));
    assert!(!read(dir.path(), "state.ls").contains(NONCE_A));
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
        let mut r = Rule::with_caches(
            uuid::Uuid::new_v4(),
            label,
            protocol,
            ports,
            sources,
            interface,
            if output_chain { Chain::Output } else { Chain::Input },
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
        });
        r.connection_limit = connection_limit;
        r.log_enabled = log_enabled;
        r.rebuild_caches();
        r
    }
}

prop_compose! {
    fn arb_ruleset()(
        rules in prop::collection::vec(arb_rule(), 0..8),
        settings in any::<[bool; 5]>(),
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
        adv.icmp_rate_limit = icmp_rate;
        ruleset
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

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
