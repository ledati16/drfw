//! Integration tests for profile and config storage (no nft involved).
//!
//! Each test points `DRFW_TEST_DATA_DIR` at its own temp directory. The
//! variable is process-wide, so the tests in this binary are serialized with
//! [`LOCK`]; this file is its own test binary, so it cannot race with the
//! env-var users in `integration_tests.rs`.
//!
//! Covers: unreadable profiles are reported and copied aside (never silently
//! replaced), newer-version refusal, duplicate-id repair, invalid rules kept,
//! no-replace create/rename, profile listing hygiene, file modes, and the
//! config recovery path.

#![allow(clippy::uninlined_format_args)]

use drfw::core::profiles::{self, ProfileError};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Points the data/state dirs at a fresh temp dir; keep the guard and the
/// `TempDir` alive for the whole test.
async fn isolated() -> (tokio::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
    let guard = LOCK.lock().await;
    let dir = tempfile::tempdir().expect("temp dir");
    // SAFETY: tests in this binary are serialized by LOCK
    unsafe {
        std::env::set_var("DRFW_TEST_DATA_DIR", dir.path());
        std::env::set_var("DRFW_TEST_STATE_DIR", dir.path());
    }
    (guard, dir)
}

fn profiles_dir(root: &Path) -> PathBuf {
    let dir = root.join("profiles");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Files in `dir` whose name starts with `prefix`.
fn files_starting_with(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(prefix))
        .collect()
}

const RULE_TEMPLATE: &str = r#"{ "id": "ID", "label": "LABEL", "protocol": "Tcp",
    "ports": [PORT], "interface": null, "created_at": "2026-01-01T00:00:00Z" }"#;

fn rule_json(id: &str, label: &str, port: u16) -> String {
    RULE_TEMPLATE
        .replace("ID", id)
        .replace("LABEL", label)
        .replace("PORT", &port.to_string())
}

#[tokio::test]
async fn test_corrupt_profile_is_copied_aside_and_never_replaced() {
    let (_guard, root) = isolated().await;
    let dir = profiles_dir(root.path());
    let path = dir.join("broken.json");
    std::fs::write(&path, b"{ \"rules\": [ this is not json").unwrap();

    let err = profiles::load_profile("broken").await.unwrap_err();
    assert!(matches!(err, ProfileError::Corrupt { .. }), "{err:?}");
    assert!(err.is_unreadable_content());

    let issue = profiles::load_profile_or_preserve("broken")
        .await
        .unwrap_err();
    let backup = issue.backup.clone().expect("a copy must be made");
    assert_eq!(
        std::fs::read(&backup).unwrap(),
        b"{ \"rules\": [ this is not json"
    );
    assert_eq!(mode(&backup), 0o600);
    assert!(
        backup
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("broken.json.corrupt-")
    );
    assert!(issue.user_message().contains(&backup.display().to_string()));
    // The original is untouched and the copy is not offered as a profile
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"{ \"rules\": [ this is not json"
    );
    assert_eq!(profiles::list_profiles().await.unwrap(), vec!["broken"]);
}

#[tokio::test]
async fn test_newer_version_profile_is_refused_with_clear_message() {
    let (_guard, root) = isolated().await;
    let dir = profiles_dir(root.path());
    std::fs::write(
        dir.join("future.json"),
        r#"{ "version": 7, "rules": [], "new_feature": { "x": 1 } }"#,
    )
    .unwrap();

    let err = profiles::load_profile("future").await.unwrap_err();
    assert!(
        matches!(err, ProfileError::UnsupportedVersion { found: 7, .. }),
        "{err:?}"
    );
    assert!(err.to_string().contains("newer version of DRFW"));

    let issue = profiles::load_profile_or_preserve("future")
        .await
        .unwrap_err();
    assert!(issue.backup.is_some());
}

#[tokio::test]
async fn test_chrono_era_profile_loads_and_saves_compatibly() {
    // created_at strings exactly as chrono-based DRFW builds wrote them
    // (nanoseconds, whole seconds) plus offset forms from hand edits
    let (_guard, root) = isolated().await;
    let dir = profiles_dir(root.path());
    let stamps = [
        (
            "2026-11-20T22:39:15.366180715Z",
            1_795_214_355_366_180_715_i128,
        ),
        ("2026-11-20T22:39:15Z", 1_795_214_355_000_000_000),
        ("2026-11-20T22:39:15.366+00:00", 1_795_214_355_366_000_000),
        ("2026-11-20T23:39:15+01:00", 1_795_214_355_000_000_000),
    ];
    let rules: Vec<String> = stamps
        .iter()
        .enumerate()
        .map(|(i, (stamp, _))| {
            rule_json(&format!("00000000-0000-4000-8000-00000000000{i}"), "R", 22)
                .replace("2026-01-01T00:00:00Z", stamp)
        })
        .collect();
    // Version-less file, as written before the format version existed
    std::fs::write(
        dir.join("old.json"),
        format!(r#"{{ "rules": [{}] }}"#, rules.join(",")),
    )
    .unwrap();

    let ruleset = profiles::load_profile("old")
        .await
        .expect("old profile loads");
    let loaded: Vec<i128> = ruleset
        .rules
        .iter()
        .map(|r| r.created_at.as_nanosecond())
        .collect();
    let expected: Vec<i128> = stamps.iter().map(|(_, n)| *n).collect();
    assert_eq!(loaded, expected);

    // Saved back as RFC 3339 UTC, which chrono-based builds read
    profiles::save_profile("old", &ruleset).await.unwrap();
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("old.json")).unwrap()).unwrap();
    let written: Vec<&str> = saved["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["created_at"].as_str().unwrap())
        .collect();
    assert_eq!(
        written,
        [
            "2026-11-20T22:39:15.366180715Z",
            "2026-11-20T22:39:15Z",
            "2026-11-20T22:39:15.366Z",
            "2026-11-20T22:39:15Z",
        ]
    );
}

#[tokio::test]
async fn test_oversized_profile_is_refused() {
    let (_guard, root) = isolated().await;
    let dir = profiles_dir(root.path());
    let file = std::fs::File::create(dir.join("huge.json")).unwrap();
    // Sparse: no real disk use
    file.set_len(profiles::MAX_PROFILE_BYTES + 1).unwrap();

    let err = profiles::load_profile("huge").await.unwrap_err();
    assert!(matches!(err, ProfileError::TooLarge { .. }), "{err:?}");
    assert!(err.is_unreadable_content());
}

#[tokio::test]
async fn test_missing_profile_is_the_normal_default_path() {
    let (_guard, _root) = isolated().await;
    let ruleset = profiles::load_profile_or_preserve("nothere")
        .await
        .expect("missing profile loads as empty");
    assert_eq!(ruleset.rules.len(), 0);
}

#[tokio::test]
async fn test_duplicate_ids_regenerated_and_invalid_rules_kept() {
    let (_guard, root) = isolated().await;
    let dir = profiles_dir(root.path());
    let id = "11111111-1111-1111-1111-111111111111";
    let json = format!(
        r#"{{ "rules": [{}, {}, {}] }}"#,
        rule_json(id, "First", 22),
        rule_json(id, "Second", 80),
        // Invalid (port 0) but must not be dropped
        rule_json("22222222-2222-2222-2222-222222222222", "Zero", 0),
    );
    std::fs::write(dir.join("dups.json"), json).unwrap();

    let ruleset = profiles::load_profile("dups").await.unwrap();
    assert_eq!(ruleset.rules.len(), 3);
    assert_eq!(ruleset.rules[0].id.to_string(), id, "first keeps its id");
    assert_ne!(ruleset.rules[1].id.to_string(), id, "later one regenerated");
    assert_eq!(ruleset.rules[1].label, "Second");

    let report = ruleset.validate().unwrap_err();
    assert_eq!(report.rules.len(), 1);
    assert_eq!(report.rules[0].label, "Zero");
    assert!(ruleset.validate_for_apply().is_err());
}

#[tokio::test]
async fn test_save_writes_version_mode_and_removes_legacy_checksum() {
    let (_guard, root) = isolated().await;
    let dir = profiles_dir(root.path());
    let checksum = dir.join("p.json.sha256");
    std::fs::write(&checksum, "deadbeef").unwrap();

    profiles::save_profile("p", &drfw::core::firewall::FirewallRuleset::new())
        .await
        .unwrap();

    let path = dir.join("p.json");
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(value["version"], profiles::PROFILE_FORMAT_VERSION);
    assert_eq!(mode(&path), 0o600);
    assert!(!checksum.exists(), "stale checksum must be removed");
    assert_eq!(
        files_starting_with(&dir, ".drfw-").len(),
        0,
        "no temp files"
    );
}

#[tokio::test]
async fn test_create_profile_never_replaces_existing() {
    let (_guard, _root) = isolated().await;
    let mut ruleset = drfw::core::firewall::FirewallRuleset::new();
    ruleset.advanced_security.strict_icmp = true;
    profiles::save_profile("Work", &ruleset).await.unwrap();

    for name in ["Work", "work", "WORK"] {
        let err = profiles::create_profile(name, &drfw::core::firewall::FirewallRuleset::new())
            .await
            .unwrap_err();
        assert!(matches!(err, ProfileError::AlreadyExists(_)), "{err:?}");
    }
    let kept = profiles::load_profile("Work").await.unwrap();
    assert!(
        kept.advanced_security.strict_icmp,
        "existing profile untouched"
    );

    profiles::create_profile("home", &drfw::core::firewall::FirewallRuleset::new())
        .await
        .unwrap();
    assert_eq!(
        profiles::list_profiles().await.unwrap(),
        vec!["Work".to_string(), "home".to_string()]
    );
}

#[tokio::test]
async fn test_rename_never_replaces_existing_profile() {
    let (_guard, root) = isolated().await;
    let dir = profiles_dir(root.path());
    let mut alpha = drfw::core::firewall::FirewallRuleset::new();
    alpha.advanced_security.icmp_rate_limit = 1;
    let mut beta = drfw::core::firewall::FirewallRuleset::new();
    beta.advanced_security.icmp_rate_limit = 2;
    profiles::save_profile("alpha", &alpha).await.unwrap();
    profiles::save_profile("beta", &beta).await.unwrap();

    for target in ["beta", "BETA"] {
        let err = profiles::rename_profile("alpha", target).await.unwrap_err();
        assert!(matches!(err, ProfileError::AlreadyExists(_)), "{err:?}");
    }
    assert_eq!(
        profiles::load_profile("alpha")
            .await
            .unwrap()
            .advanced_security
            .icmp_rate_limit,
        1
    );
    assert_eq!(
        profiles::load_profile("beta")
            .await
            .unwrap()
            .advanced_security
            .icmp_rate_limit,
        2
    );

    // Case-only rename of the same profile is allowed
    profiles::rename_profile("alpha", "Alpha").await.unwrap();
    profiles::rename_profile("Alpha", "gamma").await.unwrap();
    assert!(!dir.join("Alpha.json").exists());
    assert_eq!(
        profiles::load_profile("gamma")
            .await
            .unwrap()
            .advanced_security
            .icmp_rate_limit,
        1
    );
}

#[tokio::test]
async fn test_list_profiles_skips_invalid_names() {
    let (_guard, root) = isolated().await;
    let dir = profiles_dir(root.path());
    for file in [
        "good.json",
        "has space.json",
        "dot.name.json",
        "good.json.corrupt-20260101T000000Z",
    ] {
        std::fs::write(dir.join(file), r#"{ "rules": [] }"#).unwrap();
    }
    assert_eq!(profiles::list_profiles().await.unwrap(), vec!["good"]);
}

#[tokio::test]
async fn test_ensure_profile_exists_removes_legacy_checksums() {
    let (_guard, root) = isolated().await;
    let dir = profiles_dir(root.path());
    std::fs::write(dir.join("old.json.sha256"), "x").unwrap();
    profiles::ensure_profile_exists().await.unwrap();
    assert!(dir.join("default.json").exists());
    assert!(!dir.join("old.json.sha256").exists());
}

#[tokio::test]
async fn test_corrupt_config_is_backed_up_and_not_overwritten() {
    let (_guard, root) = isolated().await;
    let path = root.path().join("config.json");
    let original = r#"{ "active_profile": "work", "theme_choice": "ThemeFromTheFuture" }"#;
    std::fs::write(&path, original).unwrap();

    let loaded = drfw::config::load_config_checked().await;
    let problem = loaded.problem.expect("problem must be reported");
    assert!(problem.contains("config.json.corrupt-"), "{problem}");
    assert_eq!(
        loaded.config.active_profile, "work",
        "active profile salvaged"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    assert_eq!(
        files_starting_with(root.path(), "config.json.corrupt-").len(),
        1
    );
}

#[tokio::test]
async fn test_missing_config_is_not_a_problem() {
    let (_guard, _root) = isolated().await;
    let loaded = drfw::config::load_config_checked().await;
    assert!(loaded.problem.is_none());
    assert_eq!(loaded.config.active_profile, profiles::DEFAULT_PROFILE_NAME);
}

#[tokio::test]
async fn test_config_save_is_private_and_round_trips() {
    let (_guard, root) = isolated().await;
    let config = drfw::config::AppConfig {
        active_profile: "work".to_string(),
        ..Default::default()
    };
    drfw::config::save_config(&config).await.unwrap();
    let path = root.path().join("config.json");
    assert_eq!(mode(&path), 0o600);
    let loaded = drfw::config::load_config_checked().await;
    assert!(loaded.problem.is_none());
    assert_eq!(loaded.config.active_profile, "work");
}
