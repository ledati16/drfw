//! Root end-to-end helpers for the disposable test kit (`tools/e2e/run.sh`)
//!
//! Every test here is `#[ignore]`d and additionally does nothing unless
//! `DRFW_E2E_DISPOSABLE=1` is set, so `cargo test -- --ignored` on a
//! workstation never touches the system. The kit runs this binary inside a
//! throwaway container or VM to drive what the CLI cannot: Save to System
//! ([`drfw::core::system_config::write_config_file`], the exact code path of
//! the GUI's handler) through the real elevation tool and the real `nft -c`.
//!
//! The kit does the system-level assertions (backups, `nft -c -f`, loading
//! twice, boot persistence); these tests assert what only the library sees
//! (exit codes, the written bytes) and print `E2E key=value` lines for it.
//!
//! Environment:
//! - `DRFW_E2E_DISPOSABLE=1`: required for anything that writes; it must also
//!   run in a VM or container (`systemd-detect-virt`) unless
//!   `DRFW_E2E_ALLOW_BARE_METAL=1` (set by `run.sh --i-know-this-is-not-my-workstation`)
//! - `DRFW_E2E_SAVE_PROFILE`: profile to save (loaded from `DRFW_TEST_DATA_DIR`)
//! - `DRFW_E2E_SAVE_TARGET`: file to replace (default [`drfw::SYSTEM_NFT_PATH`])
//! - `DRFW_E2E_APPLY_PROFILES`: comma-separated profiles that
//!   `e2e_gui_applies_in_one_process` applies one after the other, in this one
//!   process, the way the GUI does (`pkexec`, no auto-revert)
//!
//! `DRFW_NFT_COMMAND` must NOT be set: it would bypass elevation and the real
//! `nft`, which is what these tests exist to exercise.

use std::path::Path;

/// True when the kit asked for real system changes; prints a skip notice otherwise.
fn disposable() -> bool {
    if std::env::var("DRFW_E2E_DISPOSABLE").as_deref() != Ok("1") {
        eprintln!("SKIPPING root e2e helper: DRFW_E2E_DISPOSABLE=1 is not set");
        return false;
    }
    assert!(
        drfw::elevation::test_nft_command().is_none(),
        "DRFW_NFT_COMMAND must not be set for the root e2e kit"
    );
    // Second guard, like run.sh: only in a VM/container unless the kit was
    // explicitly told otherwise (--i-know-this-is-not-my-workstation)
    if std::env::var("DRFW_E2E_ALLOW_BARE_METAL").as_deref() != Ok("1") {
        let virt = std::process::Command::new("systemd-detect-virt")
            .output()
            .map_or_default(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        assert!(
            !virt.is_empty() && virt != "none",
            "refusing to write system files: systemd-detect-virt reports {virt:?} (not a VM or container)"
        );
    }
    true
}

fn save_target() -> String {
    std::env::var("DRFW_E2E_SAVE_TARGET").unwrap_or_else(|_| drfw::SYSTEM_NFT_PATH.to_string())
}

async fn profile_text() -> String {
    let name = std::env::var("DRFW_E2E_SAVE_PROFILE").expect("DRFW_E2E_SAVE_PROFILE is not set");
    let ruleset = drfw::core::profiles::load_profile(&name)
        .await
        .unwrap_or_else(|e| panic!("cannot load profile {name}: {e}"));
    ruleset.to_nft_text()
}

fn print_output(output: &std::process::Output) {
    println!(
        "E2E exit={}",
        output
            .status
            .code()
            .map_or_else(|| "signal".to_string(), |c| c.to_string())
    );
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        println!("E2E stdout={line}");
    }
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        println!("E2E stderr={line}");
    }
}

/// The temporary file the save script writes next to the target.
fn temp_path(target: &str) -> std::path::PathBuf {
    let path = Path::new(target);
    let name = path.file_name().expect("target has a file name");
    path.with_file_name(format!(".{}.drfw-tmp", name.to_string_lossy()))
}

/// Prints the compiled-in paths so the kit tests the paths this build uses.
#[test]
#[ignore = "root e2e kit helper (tools/e2e/run.sh)"]
fn e2e_print_paths() {
    println!("E2E SYSTEM_NFT_PATH={}", drfw::SYSTEM_NFT_PATH);
    println!("E2E SYSTEM_NFT_SERVICE={}", drfw::SYSTEM_NFT_SERVICE);
    println!("E2E GUARD_STATE_DIR={}", drfw::elevation::GUARD_STATE_DIR);
    println!("E2E HELPER_PATH={}", drfw::distro::HELPER_PATH);
}

/// Applies `DRFW_E2E_APPLY_PROFILES` one after the other from this single
/// process, through the GUI's elevation (`pkexec`) and code path
/// (`apply_guarded`, auto-revert off): the kit counts how often the polkit
/// agent asked for a password (once, with the helper's `auth_admin_keep`).
#[tokio::test]
#[ignore = "root e2e kit helper (tools/e2e/run.sh); applies firewall rules"]
async fn e2e_gui_applies_in_one_process() {
    if !disposable() {
        return;
    }
    drfw::elevation::set_context(drfw::elevation::ElevationContext::Gui);
    let names =
        std::env::var("DRFW_E2E_APPLY_PROFILES").expect("DRFW_E2E_APPLY_PROFILES is not set");
    for name in names.split(',') {
        let ruleset = drfw::core::profiles::load_profile(name)
            .await
            .unwrap_or_else(|e| panic!("cannot load profile {name}: {e}"));
        let started = std::time::Instant::now();
        let result =
            drfw::core::apply_guard::apply_guarded(&ruleset.to_nftables_json(), 0, &ruleset).await;
        println!(
            "E2E applied={name} result={} seconds={}",
            result
                .as_ref()
                .map_or_else(ToString::to_string, |_| "ok".to_string()),
            started.elapsed().as_secs()
        );
        assert!(result.is_ok(), "apply of {name} failed");
    }
}

/// Save to System with a valid profile: succeeds and writes exactly the text.
#[tokio::test]
#[ignore = "root e2e kit helper (tools/e2e/run.sh); writes the system nftables config"]
async fn e2e_save_profile() {
    if !disposable() {
        return;
    }
    let target = save_target();
    let text = profile_text().await;
    let output = drfw::core::system_config::write_config_file(&text, &target)
        .await
        .expect("cannot run the save script");
    print_output(&output);
    if let Some(backup) = drfw::core::system_config::backup_path_from_output(&output) {
        println!("E2E backup={}", backup.display());
    }
    assert_eq!(output.status.code(), Some(0), "save failed");
    let written = std::fs::read_to_string(&target).expect("cannot read the saved file");
    assert_eq!(written, text, "the saved file differs from to_nft_text()");
    assert!(!temp_path(&target).exists(), "temporary file left behind");
}

/// Save to System with content nft rejects: exit 3, target untouched.
#[tokio::test]
#[ignore = "root e2e kit helper (tools/e2e/run.sh); attempts a broken system config save"]
async fn e2e_save_broken_is_rejected() {
    if !disposable() {
        return;
    }
    let target = save_target();
    let before = std::fs::read(&target).ok();
    // A real header and table, then a line nft cannot parse
    let text = format!(
        "{}\nthis is not an nftables statement {{\n",
        profile_text().await
    );
    let output = drfw::core::system_config::write_config_file(&text, &target)
        .await
        .expect("cannot run the save script");
    print_output(&output);
    assert_eq!(
        output.status.code(),
        Some(3),
        "a broken config must be rejected by nft -c (exit 3)"
    );
    assert_eq!(
        std::fs::read(&target).ok(),
        before,
        "a rejected save changed the target"
    );
    assert!(!temp_path(&target).exists(), "temporary file left behind");
}
