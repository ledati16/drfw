//! The root helper `drfw-helper` (binary: `src/helper_main.rs`)
//!
//! When it is installed at [`crate::distro::HELPER_PATH`] (owned by root, see
//! [`crate::elevation`]), DRFW elevates this program instead of `/bin/sh`:
//! `pkexec <helper> apply …`. polkit can then remember the authorization
//! (`auth_admin_keep` on the action `org.drfw.helper`, see
//! [`crate::distro::polkit_policy`]) without that meaning "any root shell".
//!
//! # What it does
//!
//! Exactly what DRFW already elevated, nothing else. Three requests, each the
//! same argv DRFW passed to the fixed scripts before, payload on stdin:
//!
//! | Request | Runs |
//! |---------|------|
//! | `apply <state_dir> <timeout> <nonce> <confirm_dir> <nft> <launcher> <uid>` | [`crate::elevation::APPLY_SCRIPT`] |
//! | `save-config <target> <nft> <service or "">` | [`crate::elevation::SAVE_CONFIG_SCRIPT`] |
//! | `check` | `<nft> --json --check -f -` |
//!
//! The scripts are the audited text compiled into this binary; the helper
//! `exec`s `/bin/sh -c <script> <name> <validated args…>`, so the process
//! tree, signal handling and exit codes are the scripts' own.
//!
//! # What it refuses (exit 1, `drfw: drfw-helper: …` on stderr)
//!
//! - Not running as root (uid and euid 0), or not started by `pkexec`, `sudo`
//!   or `run0` (`PKEXEC_UID` / `SUDO_UID` name the user who asked).
//! - Any other subcommand, a wrong number of arguments, non-UTF-8 arguments.
//! - Arguments that differ from this build's fixed values: the state
//!   directory ([`crate::elevation::GUARD_STATE_DIR`]), `nft`
//!   ([`crate::distro::NFT_COMMAND`]), the watcher launcher (`auto`), the
//!   config file ([`crate::SYSTEM_NFT_PATH`]) and the service
//!   ([`crate::SYSTEM_NFT_SERVICE`], or none). Only the timeout (≤ 3600 s),
//!   the nonce (32 lowercase hex digits), the token directory (a path the
//!   scripts' `safe_path` accepts) and the uid (must be the caller's) vary.
//! - A payload over [`MAX_PAYLOAD_BYTES`], or one in which nft could see an
//!   `include` statement ([`check_payload`]): root `nft` would read any file
//!   named there and echo its lines in error messages. This also applies to
//!   the JSON requests: `nft --json -f` parses input that is not valid JSON
//!   as nftables text.
//!
//! The environment is never passed on: the child gets `PATH=`[`SAFE_PATH`]
//! and nothing else, and runs in `/`. Nothing from argv or stdin is ever put
//! into script text.
//!
//! # Test mode (debug builds only)
//!
//! `cargo test` runs the helper without root: in a debug build (where
//! `debug_assertions` is on; release builds do not even read these
//! variables), `DRFW_HELPER_TEST_MODE=1` replaces the root check and the fixed
//! values with `DRFW_HELPER_TEST_STATE_DIR`, `DRFW_HELPER_TEST_TARGET`,
//! `DRFW_HELPER_TEST_NFT`, `DRFW_HELPER_TEST_SERVICE` and
//! `DRFW_HELPER_TEST_PATH` (each optional, validated like the real values),
//! the watcher launcher `setsid` and the caller uid `getuid()`. Test mode
//! refuses to run when `PKEXEC_UID` or `SUDO_UID` is set (started through an
//! elevation tool) or as root of the initial user namespace (real root); as
//! root of a private namespace (`unshare -rn`) it runs. pkexec clears the
//! environment anyway, so the variables could not reach an installed helper
//! through it.

use std::ffi::OsString;
use std::io::{Read, Seek, Write};
use std::process::{Command, ExitCode};

use crate::elevation::{
    APPLY_SCRIPT, APPLY_SCRIPT_NAME, NFT_JSON_CHECK_ARGS, SAVE_CONFIG_SCRIPT,
    SAVE_CONFIG_SCRIPT_NAME, SHELL_PATH, WatcherLauncher,
};

/// The only `PATH` the helper's child gets, whatever the elevation tool set.
pub const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Largest payload the helper accepts on stdin (a 1000-rule ruleset is well
/// under 2 MiB).
pub const MAX_PAYLOAD_BYTES: usize = 64 << 20;

/// Subcommand: apply a ruleset and arm the revert guard.
pub const APPLY: &str = "apply";
/// Subcommand: Save to System.
pub const SAVE_CONFIG: &str = "save-config";
/// Subcommand: `nft --json --check` of a ruleset.
pub const CHECK: &str = "check";

/// Exit status of every refusal (the scripts' "failed, nothing changed").
pub const EXIT_REFUSED: u8 = 1;

/// Why the helper refused a request (printed as `drfw: drfw-helper: …`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Refusal(String);

impl Refusal {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// The fixed values a request must use, and what the child gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperConfig {
    /// The only state directory `apply` accepts
    pub state_dir: String,
    /// The only `nft` (`nft` or an absolute path)
    pub nft: String,
    /// The only watcher launcher `apply` accepts
    pub launcher: WatcherLauncher,
    /// The only file `save-config` writes
    pub save_target: String,
    /// The only service `save-config` enables (or none)
    pub service: String,
    /// The child's `PATH`
    pub path: String,
    /// The user who asked; `apply`'s uid argument must be this one
    pub caller_uid: u32,
}

impl HelperConfig {
    /// This build's values ([`crate::distro`], [`crate::elevation::GUARD_STATE_DIR`]).
    pub fn production(caller_uid: u32) -> Self {
        Self {
            state_dir: crate::elevation::GUARD_STATE_DIR.to_string(),
            nft: crate::distro::NFT_COMMAND.to_string(),
            launcher: WatcherLauncher::Auto,
            save_target: crate::distro::SYSTEM_NFT_PATH.to_string(),
            service: crate::distro::SYSTEM_NFT_SERVICE.to_string(),
            path: SAFE_PATH.to_string(),
            caller_uid,
        }
    }
}

/// Test-mode overrides (debug builds only, see the module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestOverrides {
    /// `DRFW_HELPER_TEST_STATE_DIR`
    pub state_dir: Option<String>,
    /// `DRFW_HELPER_TEST_TARGET`
    pub save_target: Option<String>,
    /// `DRFW_HELPER_TEST_NFT`
    pub nft: Option<String>,
    /// `DRFW_HELPER_TEST_SERVICE`
    pub service: Option<String>,
    /// `DRFW_HELPER_TEST_PATH`
    pub path: Option<String>,
}

/// Everything about the process the configuration depends on;
/// [`Invocation::from_process`] reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Invocation {
    /// Real uid
    pub uid: u32,
    /// Effective uid
    pub euid: u32,
    /// `PKEXEC_UID` (set by pkexec)
    pub pkexec_uid: Option<String>,
    /// `SUDO_UID` (set by sudo and run0)
    pub sudo_uid: Option<String>,
    /// Test mode was asked for (always `None` in release builds)
    pub test: Option<TestOverrides>,
    /// The process is in the initial user namespace with the identity uid
    /// map, i.e. uid 0 here is real root (true when it cannot be read)
    pub initial_user_namespace: bool,
}

impl Invocation {
    /// Reads the uids, the elevation tool's variables, the test-mode
    /// variables (debug builds only) and the user namespace.
    pub fn from_process() -> Self {
        let var =
            |name: &str| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned());
        Self {
            uid: nix::unistd::getuid().as_raw(),
            euid: nix::unistd::geteuid().as_raw(),
            pkexec_uid: var("PKEXEC_UID"),
            sudo_uid: var("SUDO_UID"),
            test: test_overrides_from_env(&var),
            initial_user_namespace: std::fs::read_to_string("/proc/self/uid_map")
                .map_or(true, |map| is_identity_uid_map(&map)),
        }
    }
}

/// The test-mode variables, if `DRFW_HELPER_TEST_MODE=1` (debug builds).
#[cfg(debug_assertions)]
fn test_overrides_from_env(var: &dyn Fn(&str) -> Option<String>) -> Option<TestOverrides> {
    (var("DRFW_HELPER_TEST_MODE").as_deref() == Some("1")).then(|| TestOverrides {
        state_dir: var("DRFW_HELPER_TEST_STATE_DIR"),
        save_target: var("DRFW_HELPER_TEST_TARGET"),
        nft: var("DRFW_HELPER_TEST_NFT"),
        service: var("DRFW_HELPER_TEST_SERVICE"),
        path: var("DRFW_HELPER_TEST_PATH"),
    })
}

/// Release builds have no test mode: the variables are not even read.
#[cfg(not(debug_assertions))]
fn test_overrides_from_env(_var: &dyn Fn(&str) -> Option<String>) -> Option<TestOverrides> {
    None
}

/// True if `uid_map` (the content of `/proc/self/uid_map`) maps the whole
/// uid range onto itself: the initial user namespace.
fn is_identity_uid_map(uid_map: &str) -> bool {
    uid_map
        .lines()
        .any(|line| line.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"])
}

/// Parses a uid the way the scripts accept it: decimal digits only, at most
/// 10 of them, in range, and written canonically (no leading zeros).
fn parse_uid(value: &str) -> Option<u32> {
    if value.is_empty() || value.len() > 10 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let uid: u32 = value.parse().ok()?;
    (uid.to_string() == value).then_some(uid)
}

/// The configuration for this invocation, or why the helper must not run.
///
/// # Errors
///
/// A [`Refusal`] when not root (uid and euid 0), when neither `PKEXEC_UID`
/// nor `SUDO_UID` names a valid uid, or, in test mode, when started through
/// an elevation tool, as real root, or with an invalid override.
pub fn resolve_config(invocation: &Invocation) -> Result<HelperConfig, Refusal> {
    if cfg!(debug_assertions)
        && let Some(test) = &invocation.test
    {
        return test_config(invocation, test);
    }
    if invocation.uid != 0 || invocation.euid != 0 {
        return Err(Refusal::new(
            "must run as root (started by pkexec, sudo or run0); it is not meant to be run directly",
        ));
    }
    let caller = match (&invocation.pkexec_uid, &invocation.sudo_uid) {
        (Some(uid), _) | (None, Some(uid)) => {
            parse_uid(uid).ok_or_else(|| Refusal::new(format!("invalid caller uid {uid:?}")))?
        }
        (None, None) => {
            return Err(Refusal::new(
                "must be started by pkexec, sudo or run0 (no PKEXEC_UID or SUDO_UID)",
            ));
        }
    };
    Ok(HelperConfig::production(caller))
}

/// The test-mode configuration (see the module docs).
fn test_config(invocation: &Invocation, test: &TestOverrides) -> Result<HelperConfig, Refusal> {
    if invocation.pkexec_uid.is_some() || invocation.sudo_uid.is_some() {
        return Err(Refusal::new(
            "test mode is refused when started by pkexec, sudo or run0",
        ));
    }
    if invocation.euid == 0 && invocation.initial_user_namespace {
        return Err(Refusal::new(
            "test mode is refused as real root (use a private user namespace)",
        ));
    }
    let mut config = HelperConfig::production(invocation.uid);
    config.launcher = WatcherLauncher::Setsid;
    let path_override = |value: &Option<String>, name: &str| -> Result<Option<String>, Refusal> {
        match value {
            Some(path) if crate::distro::is_script_path(path) => Ok(Some(path.clone())),
            Some(path) => Err(Refusal::new(format!("invalid test {name} {path:?}"))),
            None => Ok(None),
        }
    };
    if let Some(dir) = path_override(&test.state_dir, "state directory")? {
        config.state_dir = dir;
    }
    if let Some(target) = path_override(&test.save_target, "target")? {
        config.save_target = target;
    }
    if let Some(nft) = &test.nft {
        if !is_nft_arg(nft) {
            return Err(Refusal::new(format!("invalid test nft {nft:?}")));
        }
        config.nft.clone_from(nft);
    }
    if let Some(service) = &test.service {
        if !crate::distro::is_valid_service_name(service) {
            return Err(Refusal::new(format!("invalid test service {service:?}")));
        }
        config.service.clone_from(service);
    }
    if let Some(path) = &test.path {
        if path.is_empty() || !path.split(':').all(crate::distro::is_script_path) {
            return Err(Refusal::new(format!("invalid test PATH {path:?}")));
        }
        config.path.clone_from(path);
    }
    Ok(config)
}

/// The scripts' rule for their nft argument: `nft` or a `safe_path`.
fn is_nft_arg(nft: &str) -> bool {
    nft == "nft" || crate::distro::is_script_path(nft)
}

/// A validated request; the slices are the script's arguments, unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request<'a> {
    /// The seven [`crate::elevation::APPLY_SCRIPT`] arguments
    Apply(&'a [String]),
    /// The three [`crate::elevation::SAVE_CONFIG_SCRIPT`] arguments
    SaveConfig(&'a [String]),
    /// `nft --json --check -f -`
    Check,
}

/// Fails unless `value` is exactly `expected`.
fn expect_fixed(what: &str, value: &str, expected: &str) -> Result<(), Refusal> {
    if value == expected {
        Ok(())
    } else {
        Err(Refusal::new(format!(
            "{what} must be {expected:?}, not {value:?}"
        )))
    }
}

/// Validates the helper's argv (without the program name).
///
/// # Errors
///
/// A [`Refusal`] naming the first argument that is not acceptable (see the
/// module docs for the rules).
pub fn parse_request<'a>(
    args: &'a [String],
    config: &HelperConfig,
) -> Result<Request<'a>, Refusal> {
    let Some((subcommand, rest)) = args.split_first() else {
        return Err(Refusal::new(format!(
            "missing request (one of {APPLY}, {SAVE_CONFIG}, {CHECK})"
        )));
    };
    let arity = |n: usize| {
        Refusal::new(format!(
            "{subcommand} takes {n} arguments, got {}",
            rest.len()
        ))
    };
    match subcommand.as_str() {
        APPLY => {
            let [state_dir, timeout, nonce, confirm_dir, nft, launcher, uid] = rest else {
                return Err(arity(7));
            };
            expect_fixed("the state directory", state_dir, &config.state_dir)?;
            if timeout.is_empty()
                || timeout.len() > 4
                || !timeout.bytes().all(|b| b.is_ascii_digit())
                || timeout.parse::<u32>().map_or(true, |t| t > 3600)
            {
                return Err(Refusal::new(format!("invalid timeout {timeout:?}")));
            }
            if nonce.len() != 32
                || !nonce
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(Refusal::new(format!("invalid nonce {nonce:?}")));
            }
            if !crate::distro::is_script_path(confirm_dir) {
                return Err(Refusal::new(format!(
                    "invalid confirmation directory {confirm_dir:?}"
                )));
            }
            expect_fixed("nft", nft, &config.nft)?;
            expect_fixed("the watcher launcher", launcher, config.launcher.as_arg())?;
            if parse_uid(uid) != Some(config.caller_uid) {
                return Err(Refusal::new(format!(
                    "the uid must be the caller's ({}), not {uid:?}",
                    config.caller_uid
                )));
            }
            Ok(Request::Apply(rest))
        }
        SAVE_CONFIG => {
            let [target, nft, service] = rest else {
                return Err(arity(3));
            };
            expect_fixed("the target", target, &config.save_target)?;
            expect_fixed("nft", nft, &config.nft)?;
            if !service.is_empty() {
                expect_fixed("the service", service, &config.service)?;
            }
            Ok(Request::SaveConfig(rest))
        }
        CHECK if rest.is_empty() => Ok(Request::Check),
        CHECK => Err(arity(0)),
        other => Err(Refusal::new(format!(
            "unknown request {other:?} (one of {APPLY}, {SAVE_CONFIG}, {CHECK})"
        ))),
    }
}

/// Refuses a payload in which nft could see an `include` statement.
///
/// nft reads the file an `include "<path>"` names, as root, and prints its
/// lines in error messages: a file-read primitive. DRFW never writes
/// `include`, so the helper refuses any payload where the word could be
/// outside an nft string. The check holds whatever nft's lexer does beyond
/// two facts (both true of nft 1.x): a quoted string runs from `"` to the
/// next `"`, and outside one, `\` can join lines. So:
///
/// - any `\` is refused (no line continuation, no escapes);
/// - every `"` that opens a string must be closed on the same line;
/// - outside those strings, `include` in any letter case is refused, on
///   comment lines too (nft ignoring a comment can only hide text from
///   nft, never show it more than this check sees).
///
/// Under these rules nft and this check agree on where every string starts
/// and ends, line by line, so nft cannot find an `include` keyword that this
/// check missed. It applies to JSON too: `nft --json -f` parses input that is
/// not valid JSON as text. DRFW's own JSON and text pass: every string it
/// generates has `"`, `\` and control characters removed
/// ([`crate::validators::sanitize_nft_quoted`]).
///
/// # Errors
///
/// A [`Refusal`] saying which rule the payload broke.
pub fn check_payload(payload: &[u8]) -> Result<(), Refusal> {
    if payload.contains(&b'\\') {
        return Err(Refusal::new(
            "the ruleset contains a backslash, which DRFW never writes",
        ));
    }
    for (number, line) in payload.split(|&b| b == b'\n').enumerate() {
        let mut outside = Vec::with_capacity(line.len());
        let mut rest = line;
        while let Some(open) = rest.iter().position(|&b| b == b'"') {
            outside.extend_from_slice(&rest[..open]);
            outside.push(b' ');
            let after = &rest[open + 1..];
            let Some(close) = after.iter().position(|&b| b == b'"') else {
                return Err(Refusal::new(format!(
                    "line {} of the ruleset has an unterminated string",
                    number + 1
                )));
            };
            rest = &after[close + 1..];
        }
        outside.extend_from_slice(rest);
        if outside
            .windows(b"include".len())
            .any(|w| w.eq_ignore_ascii_case(b"include"))
        {
            return Err(Refusal::new(format!(
                "line {} of the ruleset has an include statement, which DRFW never writes",
                number + 1
            )));
        }
    }
    Ok(())
}

/// The child the helper becomes: the script with its arguments, or `nft`.
/// Its environment is only `PATH` (the config's), its directory `/`.
pub fn command_for(request: Request<'_>, config: &HelperConfig) -> Command {
    let mut command = match request {
        Request::Apply(args) => {
            let mut command = Command::new(SHELL_PATH);
            command
                .args(["-c", APPLY_SCRIPT, APPLY_SCRIPT_NAME])
                .args(args);
            command
        }
        Request::SaveConfig(args) => {
            let mut command = Command::new(SHELL_PATH);
            command
                .args(["-c", SAVE_CONFIG_SCRIPT, SAVE_CONFIG_SCRIPT_NAME])
                .args(args);
            command
        }
        Request::Check => {
            let mut command = Command::new(&config.nft);
            command.args(NFT_JSON_CHECK_ARGS);
            command
        }
    };
    command
        .env_clear()
        .env("PATH", &config.path)
        .current_dir("/");
    command
}

/// Reads stdin up to [`MAX_PAYLOAD_BYTES`].
fn read_payload(mut input: impl Read) -> Result<Vec<u8>, Refusal> {
    let mut payload = Vec::new();
    input
        .by_ref()
        .take(MAX_PAYLOAD_BYTES as u64 + 1)
        .read_to_end(&mut payload)
        .map_err(|e| Refusal::new(format!("cannot read the ruleset from stdin: {e}")))?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Refusal::new(format!(
            "the ruleset is larger than {MAX_PAYLOAD_BYTES} bytes"
        )));
    }
    Ok(payload)
}

/// The checked payload in an anonymous in-memory file, at offset 0: the
/// child's stdin (`nft -f -` and `install /dev/stdin` both read it whole).
fn payload_stdin(payload: &[u8]) -> Result<std::fs::File, Refusal> {
    use nix::sys::memfd::{MFdFlags, memfd_create};
    let fail = |e: &dyn std::fmt::Display| Refusal::new(format!("cannot buffer the ruleset: {e}"));
    let fd = memfd_create(c"drfw-payload", MFdFlags::MFD_CLOEXEC).map_err(|e| fail(&e))?;
    let mut file = std::fs::File::from(fd);
    file.write_all(payload).map_err(|e| fail(&e))?;
    file.rewind().map_err(|e| fail(&e))?;
    Ok(file)
}

/// Converts argv (without the program name) to UTF-8 strings.
fn utf8_args(args: impl Iterator<Item = OsString>) -> Result<Vec<String>, Refusal> {
    args.map(|arg| {
        arg.into_string()
            .map_err(|_| Refusal::new("arguments must be UTF-8"))
    })
    .collect()
}

/// Validates everything, then replaces the process with the child. Returns
/// only on a refusal or when `exec` fails.
fn exec_request() -> Refusal {
    use std::os::unix::process::CommandExt;

    let config = match resolve_config(&Invocation::from_process()) {
        Ok(config) => config,
        Err(refusal) => return refusal,
    };
    let args = match utf8_args(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(refusal) => return refusal,
    };
    let request = match parse_request(&args, &config) {
        Ok(request) => request,
        Err(refusal) => return refusal,
    };
    let stdin = match read_payload(std::io::stdin().lock())
        .and_then(|payload| check_payload(&payload).map(|()| payload))
        .and_then(|payload| payload_stdin(&payload))
    {
        Ok(stdin) => stdin,
        Err(refusal) => return refusal,
    };
    let mut command = command_for(request, &config);
    command.stdin(stdin);
    let error = command.exec();
    Refusal::new(format!(
        "cannot run {}: {error}",
        command.get_program().to_string_lossy()
    ))
}

/// The helper's `main`: never returns on success (the process becomes the
/// script or `nft`); on a refusal prints `drfw: drfw-helper: <reason>` and
/// exits with [`EXIT_REFUSED`] (never 126/127, which callers read as
/// authentication failures).
pub fn main() -> ExitCode {
    let refusal = exec_request();
    eprintln!("drfw: drfw-helper: {refusal}");
    ExitCode::from(EXIT_REFUSED)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(ToString::to_string).collect()
    }

    fn production() -> HelperConfig {
        HelperConfig::production(1000)
    }

    /// The `apply` argv DRFW builds for `config`, with one argument replaced.
    fn apply_args(config: &HelperConfig, index: usize, value: &str) -> Vec<String> {
        let mut args = strings(&[
            APPLY,
            &config.state_dir,
            "30",
            NONCE,
            "/run/user/1000",
            &config.nft,
            config.launcher.as_arg(),
            &config.caller_uid.to_string(),
        ]);
        if index > 0 {
            args[index] = value.to_string();
        }
        args
    }

    fn verdict(args: &[String], config: &HelperConfig) -> String {
        match parse_request(args, config) {
            Ok(Request::Apply(rest)) => format!("apply {}", rest.len()),
            Ok(Request::SaveConfig(rest)) => format!("save-config {}", rest.len()),
            Ok(Request::Check) => "check".to_string(),
            Err(refusal) => format!("refused: {refusal}"),
        }
    }

    #[test]
    fn test_parse_request_table() {
        let config = production();
        let target = config.save_target.clone();
        let nft = config.nft.clone();
        let service = config.service.clone();
        // (argv, accepted)
        let cases: Vec<(Vec<String>, bool)> = vec![
            // apply: exactly what DRFW builds
            (apply_args(&config, 0, ""), true),
            (apply_args(&config, 2, "0"), true),
            (apply_args(&config, 2, "3600"), true),
            (apply_args(&config, 4, "/home/u/.local/state/drfw/"), true),
            // apply: every argument has its bad case
            (apply_args(&config, 1, "/tmp/drfw"), false),
            (apply_args(&config, 1, "/run/drfw/"), false),
            (apply_args(&config, 2, "3601"), false),
            (apply_args(&config, 2, "10000"), false),
            (apply_args(&config, 2, ""), false),
            (apply_args(&config, 2, "-1"), false),
            (apply_args(&config, 2, "1e3"), false),
            (apply_args(&config, 3, &NONCE.to_uppercase()), false),
            (apply_args(&config, 3, &NONCE[1..]), false),
            (apply_args(&config, 3, &format!("{NONCE}0")), false),
            (
                apply_args(&config, 3, "../../../../etc/passwd0123456789a"),
                false,
            ),
            (apply_args(&config, 4, "relative/dir"), false),
            (apply_args(&config, 4, "/run/user/../0"), false),
            (apply_args(&config, 4, "/home/John Doe"), false),
            (apply_args(&config, 4, "/x;reboot"), false),
            (apply_args(&config, 5, "/tmp/evil-nft"), false),
            (apply_args(&config, 5, "nft2"), false),
            (apply_args(&config, 6, "setsid"), false),
            (apply_args(&config, 6, "systemd"), false),
            (apply_args(&config, 7, "0"), false),
            (apply_args(&config, 7, "01000"), false),
            (apply_args(&config, 7, "1001"), false),
            (apply_args(&config, 7, "99999999999"), false),
            // apply: arity
            (apply_args(&config, 0, "")[..7].to_vec(), false),
            (
                [apply_args(&config, 0, ""), strings(&["extra"])].concat(),
                false,
            ),
            // save-config: with and without the service
            (strings(&[SAVE_CONFIG, &target, &nft, &service]), true),
            (strings(&[SAVE_CONFIG, &target, &nft, ""]), true),
            (strings(&[SAVE_CONFIG, "/etc/passwd", &nft, ""]), false),
            (
                strings(&[SAVE_CONFIG, &format!("{target}.x"), &nft, ""]),
                false,
            ),
            (strings(&[SAVE_CONFIG, &target, "/tmp/nft", ""]), false),
            (
                strings(&[SAVE_CONFIG, &target, &nft, "sshd.service"]),
                false,
            ),
            (strings(&[SAVE_CONFIG, &target, &nft, "-x.service"]), false),
            (strings(&[SAVE_CONFIG, &target, &nft]), false),
            (strings(&[SAVE_CONFIG, &target, &nft, "", ""]), false),
            // check: no arguments; never a file from argv
            (strings(&[CHECK]), true),
            (strings(&[CHECK, "/etc/shadow"]), false),
            (strings(&[CHECK, "-f", "/etc/shadow"]), false),
            // anything else
            (strings(&[]), false),
            (strings(&[""]), false),
            (strings(&["sh"]), false),
            (strings(&["APPLY"]), false),
            (strings(&["--help"]), false),
            (strings(&["list", "ruleset"]), false),
        ];
        for (args, accepted) in cases {
            let verdict = verdict(&args, &config);
            assert_eq!(
                !verdict.starts_with("refused"),
                accepted,
                "{args:?}: {verdict}"
            );
        }
    }

    #[test]
    fn test_parse_request_returns_the_script_arguments_unchanged() {
        let config = production();
        let args = apply_args(&config, 0, "");
        assert_eq!(
            parse_request(&args, &config),
            Ok(Request::Apply(&args[1..]))
        );
        let args = strings(&[SAVE_CONFIG, &config.save_target, &config.nft, ""]);
        assert_eq!(
            parse_request(&args, &config),
            Ok(Request::SaveConfig(&args[1..]))
        );
    }

    /// What DRFW's command builders pass is what the helper accepts, for
    /// this build's paths.
    #[test]
    fn test_production_config_is_this_build() {
        let config = production();
        assert_eq!(config.state_dir, crate::elevation::GUARD_STATE_DIR);
        assert_eq!(config.nft, crate::distro::NFT_COMMAND);
        assert_eq!(config.launcher, WatcherLauncher::Auto);
        assert_eq!(config.save_target, crate::SYSTEM_NFT_PATH);
        assert_eq!(config.service, crate::SYSTEM_NFT_SERVICE);
        assert_eq!(config.path, SAFE_PATH);
    }

    fn root_via(pkexec: Option<&str>, sudo: Option<&str>) -> Invocation {
        Invocation {
            uid: 0,
            euid: 0,
            pkexec_uid: pkexec.map(str::to_string),
            sudo_uid: sudo.map(str::to_string),
            test: None,
            initial_user_namespace: true,
        }
    }

    #[test]
    fn test_resolve_config_requires_root_and_an_elevation_tool() {
        let ok = |inv: &Invocation| resolve_config(inv).map(|c| c.caller_uid);
        assert_eq!(ok(&root_via(Some("1000"), None)), Ok(1000));
        assert_eq!(ok(&root_via(None, Some("1001"))), Ok(1001));
        // pkexec's variable wins (pkexec clears the environment it is given)
        assert_eq!(ok(&root_via(Some("1000"), Some("0"))), Ok(1000));
        assert!(ok(&root_via(None, None)).is_err());
        for bad in ["", "abc", "-1", "1000 ", "01000", "4294967296", "1e3"] {
            assert!(ok(&root_via(Some(bad), None)).is_err(), "{bad:?}");
            assert!(ok(&root_via(None, Some(bad))).is_err(), "{bad:?}");
        }
        // Not root: refused, whatever the environment says
        for (uid, euid) in [(1000, 1000), (1000, 0), (0, 1000)] {
            let invocation = Invocation {
                uid,
                euid,
                ..root_via(Some("1000"), None)
            };
            let refusal = resolve_config(&invocation).expect_err("not root");
            assert!(refusal.0.contains("must run as root"), "{refusal}");
        }
    }

    #[test]
    fn test_test_mode_rules() {
        let base = Invocation {
            uid: 1000,
            euid: 1000,
            test: Some(TestOverrides::default()),
            ..Invocation::default()
        };
        // Unprivileged: test values, setsid, the real uid as the caller
        let config = resolve_config(&base).expect("test mode");
        assert_eq!(config.launcher, WatcherLauncher::Setsid);
        assert_eq!(config.caller_uid, 1000);
        // Root of a private user namespace (unshare -rn): allowed
        let ns_root = Invocation {
            uid: 0,
            euid: 0,
            initial_user_namespace: false,
            ..base.clone()
        };
        assert_eq!(resolve_config(&ns_root).map(|c| c.caller_uid), Ok(0));
        // Real root, or started through an elevation tool: refused
        let real_root = Invocation {
            initial_user_namespace: true,
            ..ns_root.clone()
        };
        assert!(resolve_config(&real_root).is_err());
        for (pkexec, sudo) in [(Some("1000"), None), (None, Some("1000"))] {
            let elevated = Invocation {
                pkexec_uid: pkexec.map(str::to_string),
                sudo_uid: sudo.map(str::to_string),
                ..base.clone()
            };
            assert!(resolve_config(&elevated).is_err());
        }
        // Overrides are validated like the real values
        let with = |test: TestOverrides| {
            resolve_config(&Invocation {
                test: Some(test),
                ..base.clone()
            })
        };
        let good = with(TestOverrides {
            state_dir: Some("/t/state".into()),
            save_target: Some("/t/nftables.conf".into()),
            nft: Some("/t/nft".into()),
            service: Some("drfw-test.service".into()),
            path: Some("/t/bin:/usr/bin".into()),
        })
        .expect("valid overrides");
        assert_eq!(
            (good.state_dir.as_str(), good.save_target.as_str()),
            ("/t/state", "/t/nftables.conf")
        );
        assert_eq!(
            (good.nft.as_str(), good.path.as_str()),
            ("/t/nft", "/t/bin:/usr/bin")
        );
        for bad in [
            TestOverrides {
                state_dir: Some("t/state".into()),
                ..TestOverrides::default()
            },
            TestOverrides {
                save_target: Some("/t/a b".into()),
                ..TestOverrides::default()
            },
            TestOverrides {
                nft: Some("nft2".into()),
                ..TestOverrides::default()
            },
            TestOverrides {
                service: Some("x".into()),
                ..TestOverrides::default()
            },
            TestOverrides {
                path: Some("/usr/bin::.".into()),
                ..TestOverrides::default()
            },
            TestOverrides {
                path: Some(String::new()),
                ..TestOverrides::default()
            },
        ] {
            assert!(with(bad.clone()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_identity_uid_map() {
        assert!(is_identity_uid_map("         0          0 4294967295\n"));
        assert!(!is_identity_uid_map("         0       1000          1\n"));
        assert!(!is_identity_uid_map(""));
    }

    /// The child's environment is cleared, then only `PATH` is set, and it
    /// runs in `/` (the helper binary's integration test runs it).
    #[test]
    fn test_command_environment_is_only_path() {
        let config = production();
        for request in [
            Request::Check,
            Request::Apply(&[]),
            Request::SaveConfig(&[]),
        ] {
            let command = command_for(request, &config);
            let envs: Vec<_> = command.get_envs().collect();
            assert_eq!(
                envs,
                [(
                    std::ffi::OsStr::new("PATH"),
                    Some(std::ffi::OsStr::new(SAFE_PATH))
                )]
            );
            assert_eq!(command.get_current_dir(), Some(std::path::Path::new("/")));
            // `env_clear` has no getter; std's Debug output shows it as `env -i`
            let debug = format!("{command:?}");
            assert!(debug.contains("env -i "), "{debug}");
        }
    }

    #[test]
    fn test_command_for_runs_the_fixed_scripts() {
        let config = production();
        let split = |command: &Command| {
            (
                command.get_program().to_string_lossy().into_owned(),
                command
                    .get_args()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect::<Vec<_>>(),
            )
        };
        let args = apply_args(&config, 0, "");
        let (program, got) = split(&command_for(Request::Apply(&args[1..]), &config));
        assert_eq!(program, SHELL_PATH);
        assert_eq!(&got[..3], ["-c", APPLY_SCRIPT, APPLY_SCRIPT_NAME]);
        assert_eq!(&got[3..], &args[1..]);

        let args = strings(&[SAVE_CONFIG, &config.save_target, &config.nft, ""]);
        let (program, got) = split(&command_for(Request::SaveConfig(&args[1..]), &config));
        assert_eq!(program, SHELL_PATH);
        assert_eq!(
            &got[..3],
            ["-c", SAVE_CONFIG_SCRIPT, SAVE_CONFIG_SCRIPT_NAME]
        );
        assert_eq!(&got[3..], &args[1..]);

        let (program, got) = split(&command_for(Request::Check, &config));
        assert_eq!(program, config.nft);
        assert_eq!(got, NFT_JSON_CHECK_ARGS);
    }

    #[test]
    fn test_check_payload_refuses_include() {
        let refused = [
            "include \"/etc/shadow\"\n",
            "table inet drfw {}\ninclude \"/etc/shadow\"\n",
            "  INCLUDE \"/etc/shadow\"",
            "table inet x { comment \"a\" ; } include \"/etc/shadow\"",
            // A comment line counts too
            "# include \"/etc/shadow\"",
            // Line continuation and escapes: no backslash at all
            "include \\\n\"/etc/shadow\"",
            "comment \"a\\\"b\"",
            // A string must end on its line (nft's may span lines)
            "\"\n\" include \"/etc/shadow\"",
            "# it's \"\ninclude \"/etc/shadow\" #\"",
            "x \"unterminated",
            // JSON that is not valid JSON is parsed as text by nft
            "{\"nftables\": []}\ninclude \"/etc/shadow\"",
            "includes",
        ];
        for payload in refused {
            assert!(check_payload(payload.as_bytes()).is_err(), "{payload:?}");
        }
        let accepted = [
            "",
            "table inet drfw {\n  chain input { comment \"include printers\" accept }\n}\n",
            "# Loading this file replaces the whole \"inet drfw\" table.\n",
            "{\"nftables\":[{\"add\":{\"rule\":{\"comment\":\"Include LAN\"}}}]}",
            "comment \"a # b\"",
            "comment 'it is'",
        ];
        for payload in accepted {
            assert_eq!(check_payload(payload.as_bytes()), Ok(()), "{payload:?}");
        }
    }

    /// DRFW's own output always passes, for every rule shape the generator
    /// knows (the stress generator's corpus is in the integration tests).
    #[test]
    fn test_check_payload_accepts_drfw_output() {
        use crate::core::firewall::Protocol;
        use crate::core::test_helpers::{create_full_test_rule, create_test_ruleset};
        let mut ruleset = create_test_ruleset();
        ruleset.rules.push(create_full_test_rule(
            "include \"x\" \\ ' # \n",
            Protocol::Tcp,
            Some(22),
            Some("10.0.0.0/8"),
            Some("eth\"0\\"),
        ));
        let json = serde_json::to_vec(&ruleset.to_nftables_json()).expect("json");
        assert_eq!(check_payload(&json), Ok(()));
        assert_eq!(check_payload(ruleset.to_nft_text().as_bytes()), Ok(()));
    }

    #[test]
    fn test_read_payload_limit() {
        let big = vec![b'x'; MAX_PAYLOAD_BYTES + 1];
        assert!(read_payload(big.as_slice()).is_err());
        assert_eq!(read_payload(&b"abc"[..]), Ok(b"abc".to_vec()));
    }

    #[test]
    fn test_payload_stdin_holds_the_payload_from_the_start() {
        let mut file = payload_stdin(b"payload\n").expect("memfd");
        let mut read_back = String::new();
        file.read_to_string(&mut read_back).expect("read");
        assert_eq!(read_back, "payload\n");
    }
}
