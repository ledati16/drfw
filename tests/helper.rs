//! The root helper binary `drfw-helper`, run as the test user
//!
//! The helper refuses to run unless it is root and was started by pkexec,
//! sudo or run0. Debug builds (what `cargo test` builds) have a test mode
//! (`DRFW_HELPER_TEST_MODE=1`, see `drfw::helper`) that lets these tests run
//! it unprivileged with `tests/env_nft.sh` standing in for `nft`; release
//! builds have none, which is checked too.
//!
//! What is covered here (the namespace tests with the real `nft`, apply and
//! save-config end to end, are in `tests/real_nft.rs`):
//! - refusal without root, and of test mode under an elevation tool;
//! - the child's environment: only the fixed `PATH`, working directory `/`;
//! - a table of bad requests (every subcommand) and an `include` payload are
//!   refused before anything runs, with exit status 1 (never 126/127);
//! - payloads for other tables or in text form are refused for every
//!   request; save-config hands the script the text it rendered;
//! - `drfw print-polkit-policy`: the action file for this build.

mod common;

use std::io::Write;
use std::process::{Command, Output, Stdio};

const HELPER: &str = env!("CARGO_BIN_EXE_drfw-helper");

/// `tests/env_nft.sh`: prints its arguments, directory, environment, stdin.
fn env_nft() -> String {
    format!("{}/tests/env_nft.sh", env!("CARGO_MANIFEST_DIR"))
}

/// Runs the helper with exactly `env` (nothing inherited), `args` and
/// `stdin`.
fn run_helper(args: &[&str], env: &[(&str, &str)], stdin: &[u8]) -> Output {
    let mut child = Command::new(HELPER)
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start drfw-helper");
    if let Some(mut input) = child.stdin.take() {
        // A refused request exits without reading stdin
        let _ = input.write_all(stdin);
    }
    child.wait_with_output().expect("wait for drfw-helper")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Asserts a refusal: exit 1 (never 126/127, which DRFW reads as
/// authentication failures), the helper's message, and nothing ran.
fn assert_refused(output: &Output, reason: &str, context: &str) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "{context}: {}",
        stderr(output)
    );
    let message = stderr(output);
    assert!(
        message.starts_with("drfw: drfw-helper: ") && message.contains(reason),
        "{context}: expected {reason:?} in {message:?}"
    );
    assert!(
        output.stdout.is_empty(),
        "{context}: the child ran: {}",
        stdout(output)
    );
}

/// The smallest payload the helper accepts: `add table inet drfw`.
const DRFW_TABLE: &[u8] = br#"{"nftables":[{"add":{"table":{"family":"inet","name":"drfw"}}}]}"#;

fn running_as_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Test mode exists only in debug builds; prints a notice otherwise.
fn test_mode_available() -> bool {
    if cfg!(debug_assertions) {
        return true;
    }
    eprintln!("SKIPPING drfw-helper test mode test: release build (no test mode)");
    false
}

#[test]
fn test_refuses_to_run_without_root() {
    if running_as_root() {
        eprintln!("SKIPPING: the tests run as root");
        return;
    }
    // Whatever the elevation variables claim: uid and euid must be 0
    for env in [
        &[][..],
        &[("PKEXEC_UID", "1000")][..],
        &[("SUDO_UID", "1000")][..],
    ] {
        let output = run_helper(&["check"], env, b"{}");
        assert_refused(&output, "must run as root", &format!("{env:?}"));
    }
}

/// Release builds ignore the test-mode variables entirely.
#[test]
fn test_release_build_has_no_test_mode() {
    if cfg!(debug_assertions) || running_as_root() {
        return;
    }
    let output = run_helper(
        &["check"],
        &[
            ("DRFW_HELPER_TEST_MODE", "1"),
            ("DRFW_HELPER_TEST_NFT", &env_nft()),
        ],
        b"{}",
    );
    assert_refused(
        &output,
        "must run as root",
        "release build, test mode asked",
    );
}

/// Test mode is refused when an elevation tool started the helper.
#[test]
fn test_test_mode_refused_under_an_elevation_tool() {
    if !test_mode_available() {
        return;
    }
    for var in ["PKEXEC_UID", "SUDO_UID"] {
        let output = run_helper(
            &["check"],
            &[("DRFW_HELPER_TEST_MODE", "1"), (var, "1000")],
            b"{}",
        );
        assert_refused(&output, "test mode is refused", var);
    }
}

/// The child gets only the fixed `PATH` (none of the caller's variables,
/// not even its `PATH`), runs in `/`, and reads the payload on stdin.
#[test]
fn test_child_environment_is_sanitized() {
    if !test_mode_available() || !common::script_paths_usable() {
        return;
    }
    let nft = env_nft();
    let payload = DRFW_TABLE;
    let output = run_helper(
        &["check"],
        &[
            ("DRFW_HELPER_TEST_MODE", "1"),
            ("DRFW_HELPER_TEST_NFT", &nft),
            ("PATH", "/nonexistent/evil:/usr/bin:/bin"),
            ("BASH_ENV", "/nonexistent/bash_env"),
            ("ENV", "/nonexistent/env"),
            ("IFS", "x"),
            ("SHELLOPTS", "xtrace"),
            ("LD_LIBRARY_PATH", "/nonexistent/lib"),
            ("HOME", "/nonexistent/home"),
            ("DRFW_SECRET", "must-not-reach-root"),
        ],
        payload,
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("args=--json --check -f -\n"), "{out}");
    assert!(out.contains("pwd=/\n"), "{out}");
    assert!(
        out.ends_with(&format!("stdin={}", String::from_utf8_lossy(payload))),
        "{out}"
    );
    let env: Vec<&str> = out
        .lines()
        .filter_map(|line| line.strip_prefix("env="))
        .collect();
    assert!(
        env.contains(&format!("PATH={}", drfw::helper::SAFE_PATH).as_str()),
        "{env:?}"
    );
    // Only what the shell running the stand-in adds by itself
    for var in &env {
        let name = var.split('=').next().unwrap_or_default();
        assert!(
            matches!(name, "PATH" | "PWD" | "OLDPWD" | "SHLVL" | "_"),
            "unexpected variable in the child: {var} (all: {env:?})"
        );
    }
}

/// Every subcommand with a bad argument, and unknown requests, are refused
/// before anything runs; the valid `check` runs the stand-in.
#[test]
fn test_bad_requests_are_refused() {
    if !test_mode_available() || !common::script_paths_usable() {
        return;
    }
    let nft = env_nft();
    let state = "/nonexistent/drfw-state";
    let target = "/nonexistent/nftables.conf";
    let env = [
        ("DRFW_HELPER_TEST_MODE", "1"),
        ("DRFW_HELPER_TEST_NFT", nft.as_str()),
        ("DRFW_HELPER_TEST_STATE_DIR", state),
        ("DRFW_HELPER_TEST_TARGET", target),
    ];
    let uid = nix::unistd::getuid().as_raw().to_string();
    let nonce = "0123456789abcdef0123456789abcdef";
    let apply = |index: usize, value: &str| {
        let mut args = vec![
            "apply",
            state,
            "30",
            nonce,
            "/run/user/1000",
            nft.as_str(),
            "setsid",
            uid.as_str(),
        ];
        args[index] = value;
        args.into_iter().map(String::from).collect::<Vec<_>>()
    };
    let other_uid = (nix::unistd::getuid().as_raw() + 1).to_string();
    let cases: Vec<(Vec<String>, &str)> = vec![
        (apply(1, "/run/drfw"), "the state directory must be"),
        (apply(2, "3601"), "invalid timeout"),
        (
            apply(3, "0123456789ABCDEF0123456789ABCDEF"),
            "invalid nonce",
        ),
        (apply(4, "/run/user/../0"), "invalid confirmation directory"),
        (apply(5, "/usr/bin/nft-other"), "nft must be"),
        (apply(6, "auto"), "the watcher launcher must be"),
        (apply(7, &other_uid), "the uid must be the caller's"),
        (apply(0, "apply")[..5].to_vec(), "apply takes 7 arguments"),
        (
            ["save-config", "/etc/passwd", nft.as_str(), ""]
                .map(String::from)
                .to_vec(),
            "the target must be",
        ),
        (
            ["save-config", target, nft.as_str(), "sshd.service"]
                .map(String::from)
                .to_vec(),
            "the service must be",
        ),
        (
            ["save-config", target].map(String::from).to_vec(),
            "save-config takes 3 arguments",
        ),
        (
            ["check", "/etc/shadow"].map(String::from).to_vec(),
            "check takes 0 arguments",
        ),
        (Vec::new(), "missing request"),
        (
            ["sh", "-c", "id"].map(String::from).to_vec(),
            "unknown request",
        ),
    ];
    for (args, reason) in cases {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = run_helper(&args, &env, b"{}");
        assert_refused(&output, reason, &format!("{args:?}"));
    }
    // The same environment runs a valid request
    let output = run_helper(&["check"], &env, DRFW_TABLE);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).starts_with("args=--json --check -f -\n"));
}

/// A payload with an `include` (root nft would read that file and echo it)
/// is refused for every request, before anything runs.
#[test]
fn test_include_payload_is_refused() {
    if !test_mode_available() || !common::script_paths_usable() {
        return;
    }
    let nft = env_nft();
    let env = [
        ("DRFW_HELPER_TEST_MODE", "1"),
        ("DRFW_HELPER_TEST_NFT", nft.as_str()),
    ];
    for payload in [
        &b"include \"/etc/shadow\"\n"[..],
        b"{\"nftables\": []}\ninclude \"/etc/shadow\"\n",
        b"include \\\n\"/etc/shadow\"\n",
    ] {
        let output = run_helper(&["check"], &env, payload);
        assert_refused(&output, "the ruleset", &String::from_utf8_lossy(payload));
    }
}

/// Payloads for other tables, the whole ruleset or in text form are refused
/// for every request before anything runs; a valid save payload reaches the
/// script as the text the helper rendered (`tests/env_nft.sh` stands in for
/// `nft`, so the script's `nft -c` passes and the file is installed).
#[test]
fn test_payloads_outside_the_drfw_table_are_refused() {
    if !test_mode_available() || !common::script_paths_usable() {
        return;
    }
    let nft = env_nft();
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("nftables.conf");
    let target = target.to_str().expect("utf-8 path");
    let state = dir.path().join("state");
    let state = state.to_str().expect("utf-8 path");
    let env = [
        ("DRFW_HELPER_TEST_MODE", "1"),
        ("DRFW_HELPER_TEST_NFT", nft.as_str()),
        ("DRFW_HELPER_TEST_TARGET", target),
        ("DRFW_HELPER_TEST_STATE_DIR", state),
    ];
    let uid = nix::unistd::getuid().as_raw().to_string();
    let nonce = "0123456789abcdef0123456789abcdef";
    let requests: [Vec<&str>; 3] = [
        vec!["check"],
        vec![
            "apply",
            state,
            "30",
            nonce,
            "/run/user/1000",
            nft.as_str(),
            "setsid",
            uid.as_str(),
        ],
        vec!["save-config", target, nft.as_str(), ""],
    ];
    let ruleset = drfw::core::firewall::FirewallRuleset::new();
    let with = |extra: serde_json::Value| {
        let mut json = ruleset.to_nftables_json();
        json["nftables"]
            .as_array_mut()
            .expect("command list")
            .push(extra);
        json.to_string().into_bytes()
    };
    let refused: Vec<(Vec<u8>, &str)> = vec![
        (
            with(serde_json::json!({ "flush": { "ruleset": null } })),
            "is not allowed",
        ),
        (
            with(
                serde_json::json!({ "delete": { "table": { "family": "inet", "name": "docker" } } }),
            ),
            "is not allowed",
        ),
        (
            with(
                serde_json::json!({ "delete": { "table": { "family": "ip", "name": "filter" } } }),
            ),
            "is not allowed",
        ),
        (
            with(serde_json::json!({ "add": { "chain": {
                "family": "inet", "table": "docker", "name": "x",
            } } })),
            "is not allowed",
        ),
        (
            b"flush ruleset
"
            .to_vec(),
            "not JSON",
        ),
        (ruleset.to_nft_text().into_bytes(), "not JSON"),
    ];
    for request in &requests {
        for (payload, reason) in &refused {
            let output = run_helper(request, &env, payload);
            assert_refused(
                &output,
                reason,
                &format!("{request:?} {}", String::from_utf8_lossy(payload)),
            );
        }
    }
    assert!(
        !std::path::Path::new(target).exists() && !std::path::Path::new(state).exists(),
        "a refused request wrote something"
    );

    // A valid save: the script gets the rendered text (the preview)
    let payload = drfw::core::root_payload::SavePayload::of_ruleset(&ruleset);
    let output = run_helper(&requests[2], &env, payload.as_bytes());
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        std::fs::read_to_string(target).expect("saved file"),
        ruleset.to_nft_text()
    );
}

#[test]
fn test_cli_print_polkit_policy() {
    // Runs at package time: prints the action file, creates no data directories
    let home = tempfile::tempdir().expect("tempdir");
    let output = Command::new(env!("CARGO_BIN_EXE_drfw"))
        .arg("print-polkit-policy")
        .env_remove("DRFW_TEST_DATA_DIR")
        .env_remove("DRFW_TEST_STATE_DIR")
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path().join("data"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .output()
        .expect("run drfw");
    assert!(output.status.success(), "{}", stderr(&output));
    let policy = stdout(&output);
    assert_eq!(policy, drfw::distro::polkit_policy());
    assert!(policy.contains(&format!(
        "<annotate key=\"org.freedesktop.policykit.exec.path\">{}</annotate>",
        drfw::distro::HELPER_PATH
    )));
    assert!(policy.contains("<allow_active>auth_admin_keep</allow_active>"));
    assert_eq!(
        std::fs::read_dir(home.path()).expect("read home").count(),
        0,
        "print-polkit-policy must not create data directories"
    );

    // Well-formed XML for a real parser too, where one is installed
    if common::missing_tools(&["xmllint"]).is_empty() {
        let file = home.path().join("org.drfw.helper.policy");
        std::fs::write(&file, &policy).expect("write policy");
        let mut lint = Command::new("xmllint");
        lint.args(["--noout", "--nonet"]);
        // Valid against polkit's own DTD, where polkit is installed
        let dtd = std::path::Path::new("/usr/share/polkit-1/policyconfig-1.dtd");
        if dtd.is_file() {
            lint.arg("--dtdvalid").arg(dtd);
        }
        let lint = lint.arg(&file).output().expect("run xmllint");
        assert!(lint.status.success(), "xmllint: {}", stderr(&lint));
    } else {
        eprintln!("NOTE: xmllint not installed; only the built-in well-formedness test ran");
    }

    // Hidden from --help: it is for packagers
    let help = Command::new(env!("CARGO_BIN_EXE_drfw"))
        .arg("--help")
        .output()
        .expect("run drfw");
    assert!(!stdout(&help).contains("print-polkit-policy"));
}
