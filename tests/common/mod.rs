//! Helpers shared by the integration test crates (`mod common;`)
//!
//! Every file in `tests/` is its own crate and cannot see the library's
//! `#[cfg(test)]` helpers, but it can include this module:
//!
//! - real-nft probes: [`real_nft_available`] runs the same `nft` the library
//!   runs ([`nft`]), and [`unshare`] puts it first on `PATH` for scripts
//! - [`script_paths_usable`]: whether this checkout and `TMPDIR` can be passed
//!   to the root scripts at all
//! - rule builders on [`Rule::with_caches`], [`write_profile`]
//! - [`EnvVarGuard`]: process-wide env changes, serialized and restored
//!
//! Each crate uses only some of the helpers, hence the `dead_code` allow.

// Each test crate compiles this module and uses a different subset of it
#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use drfw::core::firewall::{Chain, FirewallRuleset, PortEntry, Protocol, Rule};

// ============================================================================
// Real nft
// ============================================================================

/// The `nft` the library runs without privileges (`DRFW_NFT_PATH`, else the
/// first of `/usr/sbin`, `/sbin`, `/usr/bin` that has it, else `PATH`).
pub fn nft() -> &'static str {
    drfw::distro::unprivileged_nft()
}

/// `PATH` with [`nft`]'s directory first, so scripts that call plain `nft`
/// run the very binary the library uses. Unchanged when [`nft`] is not an
/// absolute path named `nft`.
pub fn path_with_nft() -> OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let nft = Path::new(nft());
    let (Some(dir), Some("nft")) = (nft.parent(), nft.file_name().and_then(OsStr::to_str)) else {
        return path;
    };
    if !nft.is_absolute() {
        return path;
    }
    std::env::join_paths(std::iter::once(dir.to_path_buf()).chain(std::env::split_paths(&path)))
        .unwrap_or(path)
}

/// `unshare` with [`path_with_nft`] as `PATH`.
pub fn unshare() -> Command {
    let mut command = Command::new("unshare");
    command.env("PATH", path_with_nft());
    command
}

/// Skips a test (returns `false` after a notice), or fails it when
/// `DRFW_REQUIRE_REAL_NFT=1` (CI: a skip there would hide a broken setup).
pub fn skip(what: &str, reason: &str) -> bool {
    assert!(
        std::env::var("DRFW_REQUIRE_REAL_NFT").as_deref() != Ok("1"),
        "DRFW_REQUIRE_REAL_NFT=1 but the {what} cannot run: {reason}"
    );
    eprintln!("SKIPPING {what}: {reason}");
    false
}

/// Why the real-nft tests cannot run here, if they cannot (checked once).
fn real_nft_problem() -> Option<&'static str> {
    static PROBLEM: OnceLock<Option<String>> = OnceLock::new();
    PROBLEM
        .get_or_init(|| {
            // The library would run it instead of the real nft
            if let Some(command) = std::env::var_os("DRFW_NFT_COMMAND") {
                return Some(format!(
                    "DRFW_NFT_COMMAND is set ({}); the real-nft tests need the real nft, unset it",
                    command.to_string_lossy()
                ));
            }
            let output = match unshare().args(["-rn", nft(), "list", "ruleset"]).output() {
                Ok(output) => output,
                Err(e) => return Some(format!("cannot run unshare: {e}")),
            };
            (!output.status.success()).then(|| {
                format!(
                    "`unshare -rn {} list ruleset` failed: {}",
                    nft(),
                    String::from_utf8_lossy(&output.stderr).trim()
                )
            })
        })
        .as_deref()
}

/// True when real nft tests can run; prints a skip notice otherwise.
///
/// Panics instead of skipping when `DRFW_REQUIRE_REAL_NFT=1`.
pub fn real_nft_available() -> bool {
    match real_nft_problem() {
        None => true,
        Some(reason) => skip("real nft test", reason),
    }
}

/// The tools in `tools` that `sh -c 'command -v …'` cannot find.
pub fn missing_tools<'a>(tools: &[&'a str]) -> Vec<&'a str> {
    tools
        .iter()
        .copied()
        .filter(|tool| {
            Command::new("sh")
                .args(["-c", &format!("command -v {tool}")])
                .output()
                .map_or(true, |o| !o.status.success())
        })
        .collect()
}

// ============================================================================
// Paths for the root scripts
// ============================================================================

/// The mock nft (`tests/mock_nft.sh`).
pub fn mock_nft_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mock_nft.sh")
}

/// True when the paths tests hand to the root scripts (the mock nft and
/// temp dirs under `TMPDIR`) pass the scripts' `safe_path`
/// ([`drfw::distro::is_script_path`]); otherwise prints a skip notice. A
/// checkout or `TMPDIR` with a space (e.g. a makepkg `srcdir`) cannot work:
/// the scripts refuse such paths by design.
pub fn script_paths_usable() -> bool {
    static PROBLEM: OnceLock<Option<String>> = OnceLock::new();
    let problem = PROBLEM.get_or_init(|| {
        let temp = std::env::temp_dir();
        [mock_nft_path(), temp].into_iter().find_map(|path| {
            let usable = path.to_str().is_some_and(drfw::distro::is_script_path);
            (!usable).then(|| {
                format!(
                    "{} has characters the root scripts refuse (allowed: A-Z a-z 0-9 / . _ @ + -, \
                     no `..`); use a checkout and TMPDIR without them",
                    path.display()
                )
            })
        })
    });
    match problem {
        None => true,
        Some(reason) => {
            eprintln!("SKIPPING root script test: {reason}");
            false
        }
    }
}

// ============================================================================
// Rules and profiles
// ============================================================================

/// A TCP/UDP/… input rule with caches built ([`Rule::with_caches`]: a new
/// `Rule` field never has to be added to the tests).
pub fn rule(label: &str, protocol: Protocol, ports: Vec<PortEntry>) -> Rule {
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

/// A TCP rule with label and optional port.
pub fn create_test_rule(label: &str, port: Option<u16>) -> Rule {
    rule(
        label,
        Protocol::Tcp,
        port.map_or_default(|p| vec![PortEntry::Single(p)]),
    )
}

/// A rule with protocol, port, source and interface.
///
/// # Panics
///
/// If `source` is not a valid IP/CIDR (a typo must not silently drop it).
pub fn create_full_test_rule(
    label: &str,
    protocol: Protocol,
    port: Option<u16>,
    source: Option<&str>,
    interface: Option<&str>,
) -> Rule {
    let mut rule = rule(
        label,
        protocol,
        port.map_or_default(|p| vec![PortEntry::Single(p)]),
    );
    rule.sources = source.map_or_default(|s| vec![s.parse().expect("valid test source")]);
    rule.interface = interface.map(String::from);
    rule.rebuild_caches();
    rule
}

/// A ruleset with one SSH rule.
pub fn create_test_ruleset() -> FirewallRuleset {
    let mut ruleset = FirewallRuleset::new();
    ruleset.rules.push(create_test_rule("Test SSH", Some(22)));
    ruleset
}

/// Writes `ruleset` as profile `name` (current on-disk format) under `root`
/// (a `DRFW_TEST_DATA_DIR`).
pub fn write_profile(root: &Path, name: &str, ruleset: &FirewallRuleset) {
    let dir = root.join("profiles");
    std::fs::create_dir_all(&dir).expect("create profiles dir");
    let mut json = serde_json::to_value(ruleset).expect("serialize profile");
    json["version"] = serde_json::json!(drfw::core::profiles::PROFILE_FORMAT_VERSION);
    std::fs::write(
        dir.join(format!("{name}.json")),
        serde_json::to_vec_pretty(&json).expect("serialize profile"),
    )
    .expect("write profile");
}

// ============================================================================
// Environment
// ============================================================================

/// Serializes the tests of one crate that change the process environment.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Exclusive use of the process environment: every variable changed through
/// it gets its previous value back (or is removed again) when it is dropped,
/// also when the test panics. Locking tolerates poisoning.
///
/// Prefer setting variables on a child `Command`; this is for the library's
/// own reads (data/state dirs, the guard's runtime dir).
pub struct EnvVarGuard {
    saved: Vec<(&'static str, Option<OsString>)>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    /// Waits for the other env users of this crate.
    pub fn lock() -> Self {
        Self {
            saved: Vec::new(),
            _lock: ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner),
        }
    }

    /// Sets `name` until the guard is dropped.
    pub fn set(&mut self, name: &'static str, value: impl AsRef<OsStr>) {
        if !self.saved.iter().any(|(saved, _)| *saved == name) {
            self.saved.push((name, std::env::var_os(name)));
        }
        // SAFETY: env changes in this crate hold ENV_LOCK
        unsafe { std::env::set_var(name, value) };
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (name, value) in self.saved.drain(..).rev() {
            // SAFETY: still holding ENV_LOCK (released after this)
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}
