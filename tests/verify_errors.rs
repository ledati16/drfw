//! Readable verification errors, mapped to the rules that caused them
//!
//! - Against the real `nft` (in `unshare -rn`, no root): a ruleset nft
//!   rejects is checked, and every located error must name the rule that
//!   caused it. These tests skip without `unshare`/`nft` unless
//!   `DRFW_REQUIRE_REAL_NFT=1` is set, in which case they fail.
//! - The CLI (`drfw check`) with a scripted nft: mapped errors are printed as
//!   `rule "<label>": <message>` plus the source and caret lines, and piped
//!   output never contains color escape codes.
//!
//! The rejected rulesets bypass `validate()` on purpose: validation catches
//! everything nft is known to reject, so the only way to make nft refuse a
//! ruleset is to hand it one that validation would have stopped.

use std::process::Command;
use std::sync::OnceLock;

use drfw::core::firewall::{Chain, FirewallRuleset, PortEntry, Protocol, Rule};
use drfw::core::verify::{self, ErrorOrigin, VerifyIssue, VerifyResult};

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

/// Checks `ruleset` without privileges and maps the errors.
async fn check_and_locate(ruleset: &FirewallRuleset) -> VerifyResult {
    let result = verify::verify_ruleset_unprivileged(&ruleset.to_nftables_json())
        .await
        .expect("the unprivileged check runs");
    assert!(!result.success, "nft must reject this ruleset");
    verify::locate_errors(ruleset, result).await
}

/// The user rule ids the located issues point at.
fn rule_ids(result: &VerifyResult) -> Vec<uuid::Uuid> {
    result
        .issues
        .iter()
        .filter_map(VerifyIssue::rule_id)
        .collect()
}

#[tokio::test]
async fn test_real_rejection_names_the_rule() {
    if !real_nft_available() {
        return;
    }
    let mut ruleset = FirewallRuleset::new();
    ruleset
        .rules
        .push(rule("ssh", Protocol::Tcp, vec![PortEntry::single(22)]));
    // A reversed range: nft says "Range negative size"
    let broken = rule(
        "reversed",
        Protocol::Tcp,
        vec![PortEntry::range(9000, 8000)],
    );
    let broken_id = broken.id;
    ruleset.rules.push(broken);
    ruleset
        .rules
        .push(rule("web", Protocol::Tcp, vec![PortEntry::single(80)]));
    assert!(ruleset.validate().is_err(), "validation would stop it");

    let result = check_and_locate(&ruleset).await;
    assert_eq!(rule_ids(&result), vec![broken_id], "{:#?}", result.issues);
    let issue = &result.issues[0];
    assert_eq!(
        issue.origin,
        Some(ErrorOrigin::UserRule {
            id: broken_id,
            label: "reversed".into()
        })
    );
    assert!(
        issue.message.contains("Range negative size"),
        "{}",
        issue.message
    );
    let source = issue.source_line.as_deref().expect("source line");
    let caret = issue.caret.as_deref().expect("caret line");
    assert!(source.contains("9000-8000"), "{source}");
    // The caret sits under the offending range
    let at = caret.find('^').expect("a caret");
    assert!(source[at..].starts_with("9000-8000"), "{source}\n{caret}");
    assert_eq!(issue.to_string(), "rule \"reversed\": Range negative size");
}

#[tokio::test]
async fn test_real_rejection_maps_every_broken_rule() {
    if !real_nft_available() {
        return;
    }
    let mut ruleset = FirewallRuleset::new();
    let mut long_iface = rule("long interface", Protocol::Tcp, vec![PortEntry::single(22)]);
    long_iface.interface = Some("a".repeat(31));
    long_iface.rebuild_caches();
    // IPv4 + IPv6 sources: rendered as two nft rules, both broken
    let mut dual = rule("dual stack", Protocol::Udp, vec![PortEntry::range(60, 50)]);
    dual.sources = vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()];
    dual.rebuild_caches();
    let ok = rule("fine", Protocol::Tcp, vec![PortEntry::single(443)]);
    let (long_id, dual_id, ok_id) = (long_iface.id, dual.id, ok.id);
    ruleset.rules.extend([long_iface, ok, dual]);

    let result = check_and_locate(&ruleset).await;
    let ids = rule_ids(&result);
    assert!(ids.contains(&long_id), "{:#?}", result.issues);
    assert_eq!(
        ids.iter().filter(|id| **id == dual_id).count(),
        2,
        "{:#?}",
        result.issues
    );
    assert!(!ids.contains(&ok_id), "the valid rule is not blamed");
    assert_eq!(result.rejected_count(), 2);
}

/// Per-source limits add `add set` commands next to their rule; attribution
/// must still name the right rule (not drop the name, not blame a neighbour).
#[tokio::test]
async fn test_real_rejection_with_per_source_sets_names_the_rule() {
    use drfw::core::firewall::{RateLimit, TimeUnit};

    if !real_nft_available() {
        return;
    }
    let per_source = |label: &str, port: u16| {
        let mut r = rule(label, Protocol::Tcp, vec![PortEntry::single(port)]);
        r.rate_limit = Some(RateLimit {
            count: 3,
            unit: TimeUnit::Minute,
            burst: None,
            per_source: true,
        });
        r.connection_limit = 4;
        r.connection_limit_per_source = true;
        r
    };
    let before = per_source("ssh limited", 22);
    let mut broken = per_source("broken limited", 2222);
    broken.interface = Some("b".repeat(31));
    let after = per_source("web limited", 443);
    let broken_id = broken.id;
    let mut ruleset = FirewallRuleset::new();
    ruleset.rules = vec![before, broken, after];
    for r in &mut ruleset.rules {
        r.rebuild_caches();
    }

    let result = check_and_locate(&ruleset).await;
    let ids = rule_ids(&result);
    assert!(
        !ids.is_empty(),
        "attribution was dropped: {:#?}",
        result.issues
    );
    assert!(
        ids.iter().all(|id| *id == broken_id),
        "only the broken rule may be blamed: {:#?}",
        result.issues
    );
}

// ============================================================================
// CLI
// ============================================================================

/// A scripted nft: refuses JSON without a location (like nft does), and
/// for the text check reports an error on the line of the rule commented
/// "web", quoting it with a caret under `80`.
const SCRIPTED_NFT: &str = r#"#!/bin/sh
case "$1" in
    --json)
        cat > /dev/null
        echo "internal:0:0-0: Error: Service out of range" >&2
        echo >&2
        exit 1
        ;;
    -c)
        input=$(cat)
        line=$(printf '%s\n' "$input" | grep -n 'comment "web"' | cut -d: -f1)
        source=$(printf '%s\n' "$input" | sed -n "${line}p")
        echo "/dev/stdin:${line}:19-20: Error: Service out of range" >&2
        printf '%s\n' "$source" >&2
        echo "                  ^^" >&2
        exit 1
        ;;
esac
echo "Error: unexpected arguments: $*" >&2
exit 1
"#;

/// Writes `ruleset` as profile `name` (current on-disk format) under `root`.
fn write_profile(root: &std::path::Path, name: &str, ruleset: &FirewallRuleset) {
    let dir = root.join("profiles");
    std::fs::create_dir_all(&dir).unwrap();
    let mut json = serde_json::to_value(ruleset).unwrap();
    json["version"] = serde_json::json!(drfw::core::profiles::PROFILE_FORMAT_VERSION);
    std::fs::write(
        dir.join(format!("{name}.json")),
        serde_json::to_vec_pretty(&json).unwrap(),
    )
    .unwrap();
}

/// Runs `drfw <args>` against `root` with the scripted nft; stdout and
/// stderr are pipes, not terminals.
fn run_drfw(root: &std::path::Path, args: &[&str]) -> std::process::Output {
    use std::os::unix::fs::PermissionsExt;

    let nft = root.join("scripted-nft.sh");
    std::fs::write(&nft, SCRIPTED_NFT).unwrap();
    std::fs::set_permissions(&nft, std::fs::Permissions::from_mode(0o755)).unwrap();
    Command::new(env!("CARGO_BIN_EXE_drfw"))
        .args(args)
        .env("DRFW_TEST_DATA_DIR", root)
        .env("DRFW_TEST_STATE_DIR", root)
        .env("DRFW_NFT_COMMAND", &nft)
        .env_remove("SSH_CONNECTION")
        .env("DRFW_TEST_PROC_DIR", root.join("no-proc"))
        .output()
        .expect("run drfw")
}

#[test]
fn test_cli_check_prints_mapped_errors_without_colors() {
    let root = tempfile::tempdir().unwrap();
    let mut ruleset = FirewallRuleset::new();
    ruleset
        .rules
        .push(rule("ssh", Protocol::Tcp, vec![PortEntry::single(22)]));
    ruleset
        .rules
        .push(rule("web", Protocol::Tcp, vec![PortEntry::single(80)]));
    write_profile(root.path(), "site", &ruleset);

    let output = run_drfw(root.path(), &["check", "site"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stdout}{stderr}");
    assert!(
        stdout.contains("✓ All rules are valid."),
        "status marks are plain text: {stdout}"
    );
    assert!(
        stdout.contains("✗ nft rejected the generated ruleset:"),
        "{stdout}"
    );
    let lines: Vec<&str> = stderr.lines().collect();
    let at = lines
        .iter()
        .position(|l| *l == "  rule \"web\": Service out of range")
        .unwrap_or_else(|| panic!("no mapped error in:\n{stderr}"));
    // The offending line, dedented under the message, then the caret
    let source = lines[at + 1];
    assert!(
        source.starts_with("      ") && !source.starts_with("       "),
        "{stderr}"
    );
    assert!(
        source.contains("dport 80") && source.ends_with("comment \"web\""),
        "{stderr}"
    );
    // nft's caret at column 19, minus the 8 columns of indentation removed
    assert_eq!(
        lines[at + 2],
        format!("      {}^^", " ".repeat(10)),
        "{stderr}"
    );
    // Piped output: no escape codes anywhere
    assert!(!stdout.contains('\x1b'), "{stdout:?}");
    assert!(!stderr.contains('\x1b'), "{stderr:?}");
}
