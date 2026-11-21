//! Privilege elevation for system operations
//!
//! DRFW runs as an unprivileged user and elevates for exactly three things:
//!
//! - **apply**: the fixed [`APPLY_SCRIPT`] applies a ruleset and arms the
//!   root-side revert guard ([`WATCHER_SCRIPT`]); see [`crate::core::apply_guard`]
//! - **save-config**: the fixed [`SAVE_CONFIG_SCRIPT`] verifies and atomically
//!   writes the system nftables configuration (Save to System), optionally
//!   followed by `systemctl enable` of the boot service
//! - **check**: `nft --json --check -f -` ([`NFT_JSON_CHECK_ARGS`]), only when
//!   the unprivileged namespace check is inconclusive
//!
//! `nft` is [`crate::distro::NFT_COMMAND`]: the packager's `DRFW_NFT_PATH`, or
//! plain `nft` resolved by the elevation tool.
//!
//! # What is elevated: the helper, else `/bin/sh`
//!
//! When the root helper `drfw-helper` ([`crate::helper`]) is installed at
//! [`crate::distro::HELPER_PATH`] as a regular file owned by root, with no
//! group- or world-writable file or directory on the way, DRFW elevates it:
//! `pkexec <helper> apply|save-config|check …`. The helper validates the
//! request again as root (this build's fixed paths, nonce, uid, payload: only
//! DRFW's JSON for the `inet drfw` table, see [`crate::core::root_payload`])
//! and then runs the same fixed script, or `nft` for the check. For
//! save-config it gets the JSON and renders the file itself. Otherwise
//! (development builds, `cargo run`), DRFW elevates `/bin/sh -c <script>`
//! and `nft` directly, exactly as before the helper existed.
//!
//! # Elevation Strategy
//!
//! The front end declares its [`ElevationContext`] once at startup
//! ([`set_context`]); the method follows from it:
//!
//! - **GUI** ([`ElevationContext::Gui`]): always `pkexec` (a graphical polkit
//!   dialog), even when the GUI was started from a terminal: `run0` or `sudo`
//!   would ask for the password in that terminal, invisibly. Without `pkexec`
//!   elevation fails with [`ElevationError::PkexecNotFound`].
//! - **CLI** ([`ElevationContext::Cli`]), or no context declared: with a TTY on
//!   stdin, `run0` (systemd v256+, no SUID) if installed, else `sudo`; without
//!   one, `pkexec`.
//!
//! `DRFW_ELEVATION_METHOD` overrides both. Already root: nothing is elevated
//! and the scripts run directly (never the helper, which insists on being
//! started by `pkexec`, `sudo` or `run0`).
//!
//! # Prompts
//!
//! With the helper installed, the polkit action `org.drfw.helper`
//! ([`crate::distro::polkit_policy`]) has `auth_admin_keep` for an active
//! local session: the first apply, save or elevated check asks for the
//! password, and polkit remembers it for about five minutes **for that DRFW
//! process only** (the subject is the process that ran `pkexec`). Remote and
//! inactive sessions get `auth_admin` and are asked every time. The dialog says "Authentication is required
//! to change the firewall rules". `sudo` uses its own timestamp. Without the
//! helper every elevated operation asks: polkit cannot safely remember an
//! authorization for `/bin/sh` (that would be any root command) or for `nft`
//! (root `nft -c -f <file>` reads any file).
//!
//! # Environment Variables
//!
//! - `DRFW_NFT_COMMAND`: Path to nft binary or mock script. When set, uses this path
//!   directly without elevation (and without the helper). Used for testing with mock nft.
//!   The lib tests set it themselves (`setup_mock_nft()`); the real-nft
//!   integration tests need it unset.
//!
//! - `DRFW_ELEVATION_METHOD`: Force a specific elevation method (`sudo`, `run0`, or `pkexec`),
//!   e.g. `sudo` where `run0` is installed but not usable. It changes only which tool asks
//!   for the password. There is deliberately no unattended (password-less) mode: without
//!   the helper the elevated program is `/bin/sh`, so a sudoers `NOPASSWD` rule for it
//!   would grant unrestricted root. Automation that already runs as root can run `drfw` as
//!   root (it then elevates nothing), or load `drfw export` output with `nft -f`.
//!
//! # Security
//!
//! - Only fixed programs are elevated: the helper, or `nft` and `/bin/sh`
//!   with a fixed script; the `create_elevated_*` functions are the only
//!   builders
//! - Every elevated child is spawned with `kill_on_drop(true)`, so a timed-out or
//!   abandoned call does not leave an orphaned authentication dialog behind
//! - All inputs are validated before elevation, and again as root
//! - Commands are constructed safely without shell interpolation
//! - Audit logging tracks all privileged operations (via caller)
//! - The elevation tool is checked for availability before use; the target
//!   program is resolved by the elevation tool (root's `PATH`) unless the
//!   packager set an absolute `DRFW_NFT_PATH`
//!
//! # Example
//!
//! ```no_run
//! use drfw::elevation::create_elevated_check_command;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut cmd = create_elevated_check_command()?;
//! cmd.stdin(std::process::Stdio::piped());
//! # Ok(())
//! # }
//! ```

use std::io;
use std::sync::OnceLock;

use tokio::process::Command;

/// Which front end is asking for elevation; selects the method (see the
/// module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationContext {
    /// The iced GUI: always `pkexec`
    Gui,
    /// The command line: `run0`/`sudo` with a TTY, else `pkexec`
    Cli,
}

static CONTEXT: OnceLock<ElevationContext> = OnceLock::new();

/// Declares the front end, once, at startup ([`crate::run_gui`] and the CLI's
/// `main`). Later calls are ignored: the context never changes mid-process.
pub fn set_context(context: ElevationContext) {
    if CONTEXT.set(context).is_err() && CONTEXT.get() != Some(&context) {
        tracing::warn!("Elevation context already set; ignoring {context:?}");
    }
}

/// The declared context; [`ElevationContext::Cli`] (TTY detection) if none.
fn context() -> ElevationContext {
    CONTEXT.get().copied().unwrap_or(ElevationContext::Cli)
}

/// Error type for privilege elevation operations
#[derive(Debug, thiserror::Error)]
pub enum ElevationError {
    /// pkexec binary not found in PATH
    #[error("pkexec not found - please install PolicyKit")]
    PkexecNotFound,

    /// Requested elevation method is not available (binary not found)
    #[error("Elevation method '{0}' is not available (binary not found)")]
    MethodNotAvailable(String),

    /// Invalid value for `DRFW_ELEVATION_METHOD`
    #[error("Invalid DRFW_ELEVATION_METHOD '{0}'. Valid options: sudo, run0, pkexec")]
    InvalidMethod(String),

    /// Generic I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Why an elevated command failed before the target program could run.
///
/// Derived from the elevation tool's exit status ([`auth_failure_from_exit`]),
/// never from free-form error text alone. DRFW's own scripts never exit with
/// 126 or 127, so these codes unambiguously come from `pkexec`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// The user dismissed the authentication dialog (`pkexec` exit 126)
    #[error("Authentication was cancelled")]
    Cancelled,

    /// No polkit authentication agent is running, so nobody can be asked
    #[error(
        "No polkit authentication agent is running. Start one (most desktops do this automatically) and try again"
    )]
    NoAgent,

    /// Authorization was refused or could not be obtained (`pkexec` exit 127)
    #[error("Authentication failed: {0}")]
    Failed(String),

    /// No elevation method is available on this system
    #[error("Privilege escalation unavailable: {0}")]
    Unavailable(String),

    /// The elevated command did not finish in time (typically: the
    /// authentication dialog was left open)
    #[error("Timed out after {0} seconds waiting for authentication")]
    TimedOut(u64),
}

/// `pkexec` exit status when the authentication dialog was dismissed.
pub const EXIT_AUTH_CANCELLED: i32 = 126;
/// `pkexec` exit status when authorization could not be obtained.
pub const EXIT_AUTH_FAILED: i32 = 127;

/// Classifies an elevated command's exit status as an authentication failure.
///
/// Returns `None` when the status is not one of the elevation tool's own
/// failure codes, i.e. the target program ran and its exit status is its own.
/// `pkexec` documents 126 (dialog dismissed) and 127 (not authorized, no agent,
/// or another error before the program ran). For 127, `pkexec`'s stderr is
/// consulted only to tell "no authentication agent" apart from other refusals.
pub fn auth_failure_from_exit(code: Option<i32>, stderr: &str) -> Option<AuthError> {
    match code? {
        EXIT_AUTH_CANCELLED => Some(AuthError::Cancelled),
        EXIT_AUTH_FAILED => {
            let stderr = stderr.trim();
            if stderr.contains("No authentication agent") {
                Some(AuthError::NoAgent)
            } else if stderr.is_empty() {
                Some(AuthError::Failed("not authorized".to_string()))
            } else {
                Some(AuthError::Failed(stderr.to_string()))
            }
        }
        _ => None,
    }
}

/// Checks if a binary exists in PATH
///
/// # Arguments
///
/// * `name` - Binary name to search for (e.g., "pkexec", "nft")
///
/// # Returns
///
/// `true` if the binary is found in PATH, `false` otherwise
fn binary_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths).find_map(|dir| {
                let full_path = dir.join(name);
                if full_path.is_file() {
                    Some(full_path)
                } else {
                    None
                }
            })
        })
        .is_some()
}

/// How a program that needs root is started.
///
/// Private on purpose: only the `create_elevated_*` functions build elevated
/// commands, so only approved programs (the helper, or `nft` and `/bin/sh`
/// with a fixed script) are ever elevated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Elevation {
    /// Already root: run the program itself (no prompt)
    Direct,
    /// `run0 <program>` (systemd v256+, no SUID)
    Run0,
    /// `sudo <program>`
    Sudo,
    /// `pkexec --disable-internal-agent <program>` (graphical polkit dialog)
    Pkexec,
}

impl Elevation {
    /// The elevation tool's binary (`None` for [`Self::Direct`]).
    const fn tool(self) -> Option<&'static str> {
        match self {
            Self::Direct => None,
            Self::Run0 => Some("run0"),
            Self::Sudo => Some("sudo"),
            Self::Pkexec => Some("pkexec"),
        }
    }

    /// Builds the command that runs `program args…` this way. The child is
    /// killed when its handle is dropped (e.g. on timeout), so an abandoned
    /// call leaves no authentication dialog behind.
    fn command(self, program: &str, args: &[&str]) -> Command {
        let mut cmd = match self.tool() {
            None => Command::new(program),
            Some(tool) => {
                let mut cmd = Command::new(tool);
                if self == Self::Pkexec {
                    cmd.arg("--disable-internal-agent");
                }
                cmd.arg(program);
                cmd
            }
        };
        cmd.args(args).kill_on_drop(true);
        cmd
    }
}

/// Everything the choice of [`Elevation`] depends on (see the module docs);
/// [`current_elevation`] reads them from the process.
struct ElevationInputs<'a> {
    /// Running as root: nothing to elevate
    is_root: bool,
    /// `DRFW_ELEVATION_METHOD`, if set
    method: Option<&'a str>,
    /// The declared front end
    context: ElevationContext,
    /// stdin is a terminal (only the CLI asks on one)
    stdin_is_tty: bool,
    /// Whether an elevation tool is installed (looked up in `PATH`)
    available: &'a dyn Fn(&str) -> bool,
    /// The root helper is installed and trusted ([`helper_is_trusted`])
    helper_installed: bool,
}

/// How a root operation runs: with which tool, and whether through the
/// helper ([`crate::distro::HELPER_PATH`]) or `/bin/sh`/`nft` directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ElevationPlan {
    /// The elevation tool (or none)
    elevation: Elevation,
    /// Elevate the helper instead of `/bin/sh -c <script>` / `nft`
    helper: bool,
}

impl ElevationPlan {
    /// Today's behaviour without the helper (also: test mode, root).
    const fn direct() -> Self {
        Self {
            elevation: Elevation::Direct,
            helper: false,
        }
    }

    /// The command for one of the fixed scripts: `<tool> <helper> <request>
    /// <args…>`, or `<tool> /bin/sh -c <script> <name> <args…>`.
    fn script_command(
        self,
        request: &str,
        script: &str,
        script_name: &str,
        args: &[&str],
    ) -> Command {
        if self.helper {
            let mut helper_args = Vec::with_capacity(args.len() + 1);
            helper_args.push(request);
            helper_args.extend_from_slice(args);
            return self
                .elevation
                .command(crate::distro::HELPER_PATH, &helper_args);
        }
        let mut shell_args = Vec::with_capacity(args.len() + 3);
        shell_args.extend_from_slice(&["-c", script, script_name]);
        shell_args.extend_from_slice(args);
        self.elevation.command(SHELL_PATH, &shell_args)
    }

    /// The elevated `nft --json --check -f -`: `<tool> <helper> check`, or
    /// `<tool> <nft> --json --check -f -`.
    fn check_command(self) -> Command {
        if self.helper {
            self.elevation
                .command(crate::distro::HELPER_PATH, &[crate::helper::CHECK])
        } else {
            self.elevation
                .command(crate::distro::NFT_COMMAND, &NFT_JSON_CHECK_ARGS)
        }
    }
}

/// Arguments of the check-only `nft` run that reads JSON from stdin (the
/// unprivileged check, the elevated fallback and the helper's `check`).
pub const NFT_JSON_CHECK_ARGS: [&str; 4] = ["--json", "--check", "-f", "-"];

/// True if a directory entry with this owner and mode may be trusted as part
/// of the helper's path: owned by root and not writable by group or others;
/// the helper itself must also be a regular executable file.
const fn trusted_entry(is_helper: bool, is_file: bool, is_dir: bool, uid: u32, mode: u32) -> bool {
    let kind_ok = if is_helper {
        is_file && mode & 0o111 != 0
    } else {
        is_dir
    };
    kind_ok && uid == 0 && mode & 0o022 == 0
}

/// Whether the helper at `path` is installed the way a package installs it:
/// a regular executable file (not a symlink) owned by root, in directories
/// owned by root, none of them group- or world-writable. Anything else (not
/// installed, a development copy, a tampered permission) means DRFW does not
/// elevate it and falls back to `/bin/sh`.
fn helper_is_trusted(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !trusted_entry(
        true,
        meta.file_type().is_file(),
        false,
        meta.uid(),
        meta.mode(),
    ) {
        return false;
    }
    path.ancestors().skip(1).all(|dir| {
        std::fs::metadata(dir)
            .is_ok_and(|meta| trusted_entry(false, false, meta.is_dir(), meta.uid(), meta.mode()))
    })
}

/// Chooses how to elevate: root needs nothing; `DRFW_ELEVATION_METHOD`
/// (case-insensitive, empty = unset) overrides the front end's choice; the
/// CLI on a terminal uses `run0`, else `sudo`; the GUI, or no terminal,
/// `pkexec`. Whatever the tool, the installed helper is elevated instead of
/// `/bin/sh`/`nft` (never when already root). Pure, so every combination is
/// tested.
///
/// # Errors
///
/// - [`ElevationError::InvalidMethod`]: the method is not `sudo`, `run0` or `pkexec`
/// - [`ElevationError::MethodNotAvailable`]: the requested tool (or, on a
///   terminal, both `run0` and `sudo`) is not installed
/// - [`ElevationError::PkexecNotFound`]: `pkexec` is needed but not installed
fn select_elevation(inputs: &ElevationInputs<'_>) -> Result<ElevationPlan, ElevationError> {
    let elevation = select_tool(inputs)?;
    Ok(ElevationPlan {
        elevation,
        helper: inputs.helper_installed && elevation != Elevation::Direct,
    })
}

/// The tool part of [`select_elevation`].
fn select_tool(inputs: &ElevationInputs<'_>) -> Result<Elevation, ElevationError> {
    if inputs.is_root {
        return Ok(Elevation::Direct);
    }

    if let Some(method) = inputs
        .method
        .map(str::to_lowercase)
        .filter(|m| !m.is_empty())
    {
        let elevation = match method.as_str() {
            "sudo" => Elevation::Sudo,
            "run0" => Elevation::Run0,
            "pkexec" => Elevation::Pkexec,
            _ => return Err(ElevationError::InvalidMethod(method)),
        };
        if !(inputs.available)(&method) {
            return Err(ElevationError::MethodNotAvailable(method));
        }
        return Ok(elevation);
    }

    // The GUI always uses pkexec: even when it was started from a terminal,
    // run0/sudo would prompt in that terminal, which nobody is looking at.
    // The CLI uses run0/sudo on a TTY (works over SSH).
    if inputs.context == ElevationContext::Cli && inputs.stdin_is_tty {
        if (inputs.available)("run0") {
            return Ok(Elevation::Run0);
        }
        if (inputs.available)("sudo") {
            return Ok(Elevation::Sudo);
        }
        return Err(ElevationError::MethodNotAvailable("run0 or sudo".into()));
    }
    if (inputs.available)("pkexec") {
        return Ok(Elevation::Pkexec);
    }
    Err(ElevationError::PkexecNotFound)
}

/// [`select_elevation`] for this process (uid, `DRFW_ELEVATION_METHOD`,
/// context, stdin, `PATH`, the helper at [`crate::distro::HELPER_PATH`]).
///
/// # Panics
///
/// In the library's own unit tests, always: they must never elevate (nor run
/// anything as root). Tests use `DRFW_NFT_COMMAND` (`setup_mock_nft()`) or the
/// pure functions.
fn current_elevation() -> Result<ElevationPlan, ElevationError> {
    use std::os::fd::AsFd;

    crate::utils::deny_in_lib_tests(
        "tried to elevate; use setup_mock_nft() or the pure command builders",
    );
    let method = std::env::var("DRFW_ELEVATION_METHOD").ok();
    select_elevation(&ElevationInputs {
        is_root: nix::unistd::getuid().is_root(),
        method: method.as_deref(),
        context: context(),
        stdin_is_tty: nix::unistd::isatty(std::io::stdin().as_fd()).unwrap_or(false),
        available: &binary_exists,
        helper_installed: helper_is_trusted(std::path::Path::new(crate::distro::HELPER_PATH)),
    })
}

/// Creates the elevated `nft --json --check -f -` (the authoritative check,
/// used when the unprivileged namespace check is inconclusive).
///
/// The caller writes the nftables JSON to the command's stdin. With the
/// helper installed this is `<tool> <helper> check` (the helper runs exactly
/// that `nft` command, reading stdin only); otherwise `<tool> <nft> --json
/// --check -f -`.
///
/// # Elevation Strategy
///
/// 1. **Custom command**: If `DRFW_NFT_COMMAND` is set, runs that path directly (no elevation)
/// 2. **Already root**: runs `nft` directly
/// 3. `DRFW_ELEVATION_METHOD`, else by [`ElevationContext`]: the GUI uses
///    `pkexec`; the CLI uses `run0` (else `sudo`) with a TTY and `pkexec`
///    without one
///
/// # Errors
///
/// - [`ElevationError::PkexecNotFound`] - GUI (or no TTY) and `pkexec` is not installed
/// - [`ElevationError::MethodNotAvailable`] - `DRFW_ELEVATION_METHOD` names a tool that is not
///   installed, or the CLI on a TTY finds neither `run0` nor `sudo`
/// - [`ElevationError::InvalidMethod`] - `DRFW_ELEVATION_METHOD` is not `sudo`, `run0` or `pkexec`
///
/// # Testing
///
/// Set `DRFW_NFT_COMMAND` to a mock script path (e.g., `tests/mock_nft.sh`) to use
/// a mock nft for testing without requiring root privileges.
pub fn create_elevated_check_command() -> Result<Command, ElevationError> {
    check_command(test_nft_command().as_deref(), current_elevation)
}

/// [`create_elevated_check_command`] with the `DRFW_NFT_COMMAND` override and
/// the elevation choice passed in; `elevation` is only asked without an
/// override.
fn check_command(
    test_nft: Option<&str>,
    elevation: impl FnOnce() -> Result<ElevationPlan, ElevationError>,
) -> Result<Command, ElevationError> {
    // Explicit nft command override (tests, with the mock): no elevation
    if let Some(nft_path) = test_nft {
        return Ok(Elevation::Direct.command(nft_path, &NFT_JSON_CHECK_ARGS));
    }
    Ok(elevation()?.check_command())
}

/// Returns `DRFW_NFT_COMMAND` when set and non-empty (test mode: no elevation).
pub fn test_nft_command() -> Option<String> {
    std::env::var("DRFW_NFT_COMMAND")
        .ok()
        .filter(|path| !path.is_empty())
}

/// Shell function shared by [`SAVE_CONFIG_SCRIPT`] and [`APPLY_SCRIPT`]: true if
/// `$1` is an absolute path of `[A-Za-z0-9/._@+-]` characters without a `..`
/// component: exactly [`crate::distro::is_script_path`] (a differential test
/// keeps the two in step). The compile-time paths pass the stricter
/// [`crate::distro::is_valid_absolute_path`].
macro_rules! safe_path_fn {
    () => {
        r"safe_path() {
    case $1 in
        /*) ;;
        *) return 1 ;;
    esac
    case $1 in
        *[!A-Za-z0-9/._@+-]*) return 1 ;;
    esac
    case /$1/ in
        */../*) return 1 ;;
    esac
    return 0
}
"
    };
}

/// [`safe_path_fn`]'s text, for the differential test against the Rust
/// predicate.
#[cfg(test)]
const SAFE_PATH_FN: &str = safe_path_fn!();

/// Fixed shell script run (elevated) by Save to System.
///
/// Arguments: `$1` = target path, `$2` = nft command (`nft` or an absolute
/// path), `$3` = service to enable at boot (optional; empty = do not enable).
/// The new file content arrives on stdin. No user-controlled data is ever
/// interpolated into the script text; the target path and the service are
/// compile-time constants ([`crate::SYSTEM_NFT_PATH`],
/// [`crate::SYSTEM_NFT_SERVICE`]) in the GUI and are only ever passed as argv.
/// All three are checked against allowlists first (paths: absolute,
/// `[A-Za-z0-9/._@+-]`, no `..` component; service: `[A-Za-z0-9:_.@-]+.service`, not starting
/// with `-` or `.`).
///
/// Steps:
/// 1. Create the target's directory (mode 755) if it is missing.
/// 2. Write stdin to `<dir>/.<name>.drfw-tmp` (mode 644) in the target's own
///    directory, so the final rename is atomic (same filesystem).
/// 3. `nft -c -f` that temp file: the authoritative check of the exact bytes
///    that will be installed.
/// 4. Copy the existing target (if any) to `<target>.drfw-bak`, preserving
///    mode/owner/timestamps. Done after the check so a rejected file never
///    overwrites a good backup.
///    The first time DRFW replaces a file, it is also copied once to
///    `<target>.drfw-orig`, which is never overwritten, so the distribution's or
///    user's original config can always be recovered (`.drfw-bak` only holds the
///    previous save).
/// 5. Flush the temp file to disk, then `mv -f` it over the target (atomic
///    rename), so a crash cannot leave an empty or truncated config.
/// 6. With a service: `systemctl enable <service>` (never `start`: that would
///    reload the rules in the middle of the session). `systemctl` is called by
///    name, through the `PATH` the elevation tool sets for root. A failure
///    here is reported, not fatal: the file was saved.
///
/// The script ignores `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGTERM` and `SIGPIPE`,
/// so a dropped SSH session or Ctrl-C after the password cannot stop it
/// between the steps. Any failure before step 6 removes the temp file and
/// leaves the original untouched. On success, prints `key=value` lines on stdout:
/// `backup=<path>` when a backup was made, and with a service either
/// `enable=ok` or `enable=failed: <systemctl output on one line>`.
///
/// Exit codes: 0 success (even if enabling failed), 3 nft rejected the file,
/// 1 other failures. 126/127 are deliberately never used: callers interpret
/// those as authentication errors from pkexec/sudo/run0.
pub const SAVE_CONFIG_SCRIPT: &str = concat!(
    r#"trap '' HUP INT QUIT TERM PIPE
set -u
umask 022
target=$1
nft=$2
service=${3-}
tmp=
fail() {
    if [ -n "$tmp" ]; then
        rm -f -- "$tmp"
    fi
    printf 'drfw: %s\n' "$1" >&2
    exit "$2"
}
"#,
    safe_path_fn!(),
    r#"safe_path "$target" || fail "invalid target path" 1
case $nft in
    nft) ;;
    *) safe_path "$nft" || fail "invalid nft command" 1 ;;
esac
if [ -n "$service" ]; then
    case $service in
        -*|.*|*[!A-Za-z0-9:_.@-]*) fail "invalid service name" 1 ;;
    esac
    case $service in
        ?*.service) ;;
        *) fail "invalid service name" 1 ;;
    esac
fi
dir=$(dirname -- "$target") || exit 1
name=$(basename -- "$target") || exit 1
backup="$target.drfw-bak"
orig="$target.drfw-orig"
if [ ! -d "$dir" ]; then
    # shellcheck disable=SC2174 # parents get 755 from the umask anyway
    mkdir -p -m 755 -- "$dir" || fail "cannot create $dir" 1
fi
tmp="$dir/.$name.drfw-tmp"
rm -f -- "$tmp" || fail "cannot remove stale temporary file $tmp" 1
install -m 644 /dev/stdin "$tmp" || fail "cannot write $tmp" 1
if ! check_output=$("$nft" -c -f "$tmp" 2>&1); then
    fail "nft rejected the configuration; $target left unchanged: $check_output" 3
fi
if [ -e "$target" ]; then
    if [ ! -e "$orig" ]; then
        cp -p -- "$target" "$orig" || fail "cannot back up $target to $orig" 1
    fi
    cp -p -- "$target" "$backup" || fail "cannot back up $target to $backup" 1
    made_backup=1
else
    made_backup=0
fi
sync -- "$tmp" 2>/dev/null || sync
mv -f -- "$tmp" "$target" || fail "cannot replace $target" 1
tmp=
if [ "$made_backup" = 1 ]; then
    printf 'backup=%s\n' "$backup"
fi
if [ -n "$service" ]; then
    if out=$(systemctl enable -- "$service" 2>&1); then
        printf 'enable=ok\n'
    else
        out=$(printf '%s' "$out" | tr '\n' ' ')
        printf 'enable=failed: %s\n' "${out:-systemctl enable failed}"
    fi
fi
exit 0
"#
);

/// `$0` for [`SAVE_CONFIG_SCRIPT`] (shows up in `ps` and in shell error messages).
pub(crate) const SAVE_CONFIG_SCRIPT_NAME: &str = "drfw-save-config";

/// Absolute shell path: elevation tools must not resolve `sh` through `PATH`.
pub(crate) const SHELL_PATH: &str = "/bin/sh";

/// What a save-config command reads on stdin ([`SaveConfigCommand::input`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveConfigInput {
    /// The root helper: the JSON [`SavePayload`] itself; the helper checks
    /// it (only the `inet drfw` table) and renders the file as root
    ///
    /// [`SavePayload`]: crate::core::root_payload::SavePayload
    Payload,
    /// [`SAVE_CONFIG_SCRIPT`] without the helper: the `nft -f` text,
    /// rendered by DRFW from the same payload ([`SavePayload::render`])
    ///
    /// [`SavePayload::render`]: crate::core::root_payload::SavePayload::render
    Text,
}

/// The save-config command and what to write to its stdin.
#[derive(Debug)]
pub struct SaveConfigCommand {
    /// The (elevated) command
    pub command: Command,
    /// What it reads on stdin
    pub input: SaveConfigInput,
}

/// Creates the (elevated) command that installs a new system nftables config.
///
/// Runs [`SAVE_CONFIG_SCRIPT`] with a single elevation prompt: through the
/// helper (`<helper> save-config <target> <nft> <service>`) when it is
/// installed, else with `/bin/sh`. The caller writes [`SaveConfigCommand::input`]
/// to the command's stdin: the JSON save payload for the helper (which renders
/// the file itself, and only for the `inet drfw` table), the rendered text for
/// the script. The helper accepts only this build's target and service.
///
/// # Arguments
///
/// * `target` - Path of the file to replace (normally [`crate::SYSTEM_NFT_PATH`])
/// * `enable_service` - Unit to `systemctl enable` after a successful save
///   (normally [`crate::SYSTEM_NFT_SERVICE`]), or `None`
///
/// # Testing
///
/// When `DRFW_NFT_COMMAND` is set, the script runs **without elevation** and
/// uses that command for the `nft -c` check, mirroring
/// [`create_elevated_check_command`]. Tests point `target` at a temporary
/// directory and put a fake `systemctl` first on the child's `PATH`.
///
/// # Errors
///
/// Returns `Err(ElevationError)` if no elevation method is available.
///
/// # Example
///
/// ```no_run
/// use drfw::elevation::create_elevated_save_config_command;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut save =
///     create_elevated_save_config_command(drfw::SYSTEM_NFT_PATH, Some(drfw::SYSTEM_NFT_SERVICE))?;
/// save.command.stdin(std::process::Stdio::piped());
/// # Ok(())
/// # }
/// ```
pub fn create_elevated_save_config_command(
    target: &str,
    enable_service: Option<&str>,
) -> Result<SaveConfigCommand, ElevationError> {
    save_config_command(
        test_nft_command().as_deref(),
        target,
        enable_service,
        current_elevation,
    )
}

/// [`create_elevated_save_config_command`] with the `DRFW_NFT_COMMAND`
/// override and the elevation choice passed in; `elevation` is only asked
/// without an override.
fn save_config_command(
    test_nft: Option<&str>,
    target: &str,
    enable_service: Option<&str>,
    elevation: impl FnOnce() -> Result<ElevationPlan, ElevationError>,
) -> Result<SaveConfigCommand, ElevationError> {
    let service = enable_service.unwrap_or_default();
    let (plan, nft) = match test_nft {
        Some(nft) => (ElevationPlan::direct(), nft),
        None => (elevation()?, crate::distro::NFT_COMMAND),
    };
    Ok(SaveConfigCommand {
        command: plan.script_command(
            crate::helper::SAVE_CONFIG,
            SAVE_CONFIG_SCRIPT,
            SAVE_CONFIG_SCRIPT_NAME,
            &[target, nft, service],
        ),
        input: if plan.helper {
            SaveConfigInput::Payload
        } else {
            SaveConfigInput::Text
        },
    })
}

// ============================================================================
// Apply with a root-side revert guard
// ============================================================================

/// Root-owned directory where [`APPLY_SCRIPT`] keeps the revert file, the
/// watcher script and the outcome (`status-<nonce>`) of every guarded apply.
///
/// It lives on tmpfs (`/run`), so nothing survives a reboot, which is correct:
/// the kernel ruleset does not survive one either.
pub const GUARD_STATE_DIR: &str = "/run/drfw";

/// Text of [`WATCHER_SCRIPT`]; a macro so [`APPLY_SCRIPT`] can embed it with
/// `concat!` (it is written verbatim through a quoted here-document).
macro_rules! watcher_script {
    () => {
        r#"set -u
umask 077
LC_ALL=C
export LC_ALL
state_dir=$1
timeout=$2
nonce=$3
confirm_dir=$4
nft=$5
uid=$6
launcher=$7
revert_file="$state_dir/revert-$nonce.nft"
status_file="$state_dir/status-$nonce"
armed_file="$state_dir/armed-$nonce"
active_file="$state_dir/active"
watcher_file="$state_dir/watcher-$nonce.sh"

# Monotonic time in centiseconds (immune to wall-clock changes)
now_cs() {
    read -r up _ < /proc/uptime
    secs=${up%%.*}
    frac=${up#*.}
    echo $(( secs * 100 + 1$frac - 100 ))
}

# To the journal: stderr under systemd-run, else syslog if logger exists
log() {
    if [ "$launcher" = systemd ]; then
        printf 'drfw revert guard %s: %s\n' "$nonce" "$1" >&2
    elif command -v logger >/dev/null 2>&1; then
        logger -t drfw -- "revert guard $nonce: $1" >/dev/null 2>&1
    fi
    return 0
}

# A hung user directory (NFS, FUSE) must not stall the watcher forever
if command -v timeout >/dev/null 2>&1; then
    bounded() { timeout -k 1 2 "$@"; }
else
    bounded() { "$@"; }
fi

# True if the user (uid $uid) created token $1 in confirm_dir. confirm_dir
# belongs to the user, so it is only ever listed (readdir via find, which
# never follows symlinks; -user uses lstat); nothing in it is opened, created
# or followed.
token_present() {
    [ -n "$(bounded find "$confirm_dir/" -maxdepth 1 -name "$1" -user "$uid" -print 2>/dev/null)" ]
}

# Serializes with applies. Waits for an apply that is still running (it holds
# the lock until its outcome is recorded). Once this guard is armed, a lock
# held for more than 60 s no longer blocks it: reverting matters more.
lock() {
    command -v flock >/dev/null 2>&1 || return 0
    if ! ( : >> "$state_dir/lock" ) 2>/dev/null; then
        log "cannot open $state_dir/lock; going ahead without the lock"
        return 0
    fi
    exec 9>>"$state_dir/lock"
    while ! flock -w 60 9; do
        if [ -e "$armed_file" ]; then
            log "the lock is still held after 60 s; going ahead without it"
            return 0
        fi
        log "the apply has not finished after 60 s; still waiting for it"
    done
    return 0
}

finish() {
    tmp="$state_dir/.status-$nonce.tmp"
    printf '%s\n' "$1" > "$tmp" && chmod 644 "$tmp" && mv -f -- "$tmp" "$status_file"
    rm -f -- "$revert_file" "$watcher_file" "$armed_file"
    if [ -f "$active_file" ]; then
        active_nonce=
        read -r active_nonce _ < "$active_file" || true
        if [ "$active_nonce" = "$nonce" ]; then
            rm -f -- "$active_file"
        fi
    fi
    exit 0
}

revert() {
    lock
    # Superseded by a newer apply, or this apply failed (nothing to undo)
    if [ -e "$status_file" ]; then
        exit 0
    fi
    if [ ! -e "$armed_file" ]; then
        # The apply ended without recording an outcome (killed): its rules may
        # be live. Restoring the saved state is right either way.
        log "the apply was interrupted; restoring the previous rules"
    fi
    if err=$("$nft" -f "$revert_file" 2>&1 >/dev/null); then
        finish reverted
    fi
    err=$(printf '%s' "$err" | tr '\n' ' ')
    # Last resort: drop the drfw table so drfw cannot keep anyone locked out
    if printf 'add table inet drfw\ndelete table inet drfw\n' | "$nft" -f - >/dev/null 2>&1; then
        log "restoring failed ($err); removed table inet drfw instead"
        finish "removed: $err"
    fi
    log "restoring failed and table inet drfw could not be removed: $err"
    finish "revert-failed: $err"
}

confirm() {
    lock
    if [ -e "$status_file" ]; then
        exit 0
    fi
    finish confirmed
}

# Stopped from outside (`systemctl stop`, `kill`, shutdown). The apply script
# writes the status before it stops a guard it supersedes or that failed, so
# that is a quiet exit; anything else means the rules were never confirmed:
# revert them rather than leave them live without a guard
on_signal() {
    trap '' HUP INT TERM
    if [ -e "$status_file" ]; then
        exit 0
    fi
    log "stopped before the rules were confirmed; reverting"
    revert
}
trap on_signal HUP INT TERM

# Counted from now until the apply arms the guard, then afresh from that
# moment, so the user gets the full timeout once the new rules are live
deadline=$(( $(now_cs) + timeout * 100 ))
armed=0
while :; do
    if [ -e "$status_file" ]; then
        exit 0
    fi
    if [ "$armed" = 0 ] && [ -e "$armed_file" ]; then
        armed=1
        deadline=$(( $(now_cs) + timeout * 100 ))
    fi
    # The deadline first: nothing in the user's directory can delay a revert
    if [ "$(now_cs)" -ge "$deadline" ]; then
        revert
    fi
    # Tokens only count once the apply succeeded
    if [ "$armed" = 1 ]; then
        if token_present "drfw-confirm-$nonce"; then
            confirm
        fi
        if token_present "drfw-revert-$nonce"; then
            revert
        fi
    fi
    sleep 1
done
"#
    };
}

/// Fixed shell script run as root, detached, to revert an unconfirmed apply.
///
/// Arguments: `$1` state dir, `$2` timeout in seconds, `$3` nonce, `$4`
/// confirmation dir, `$5` nft command, `$6` uid of the user who may confirm,
/// `$7` how it was started (`systemd` or `setsid`; only selects where it
/// logs). Started by [`APPLY_SCRIPT`] (via `systemd-run` or `setsid`) **before** the
/// new ruleset is applied, never by DRFW directly.
///
/// The timeout is measured on `/proc/uptime` (clock changes do not matter):
/// from the watcher's start until the guard is armed, then afresh from the
/// moment it sees the `armed` marker, so the user gets the whole timeout once
/// the new rules are live. Once per second, in this order:
/// 1. its status file exists: the apply failed (`not-applied`) or a newer
///    apply superseded it: exit silently;
/// 2. the deadline has passed: revert;
/// 3. only once `<state_dir>/armed-<nonce>` exists (written by the apply
///    script after the new rules went live):
///    `<confirm_dir>/drfw-confirm-<nonce>` owned by `uid` exists: write
///    status `confirmed`, exit; `<confirm_dir>/drfw-revert-<nonce>` exists:
///    revert now.
///
/// Revert = `nft -f <state_dir>/revert-<nonce>.nft` (one atomic batch that
/// recreates exactly the pre-apply `inet drfw` table, or removes it if there
/// was none). If that fails it deletes the `inet drfw` table instead (status
/// `removed: <error>`), so DRFW never keeps a host locked out; only if even
/// that fails is the status `revert-failed: <error>`. Status files are written
/// atomically (temp + rename), mode 644, as `<state_dir>/status-<nonce>`.
///
/// A revert first takes the state dir's lock, so it waits for an apply that
/// is still running. If the apply script died without an outcome (no `armed`
/// marker, no status: e.g. `SIGKILL`), the watcher reverts anyway: the revert
/// file holds the state from before the apply, so restoring it is correct
/// whether or not the new rules went live. Problems are logged to the journal
/// (stderr under systemd, else `logger -t drfw`).
///
/// `SIGTERM`, `SIGHUP` or `SIGINT` (`systemctl stop`, `kill`, shutdown) end
/// the guard like the deadline: it reverts, unless its status already
/// exists (the apply script writes `superseded` or `not-applied` before it
/// stops a watcher). Only `SIGKILL` (or a crash) ends it without an outcome;
/// [`crate::core::apply_guard::pending_guard`] then reports the guard lost.
/// It runs with umask 077: only the status files (and the apply script's
/// `active`) are made world-readable, never the revert file, which holds the
/// previous `inet drfw` table.
///
/// # Trust boundary
///
/// `confirm_dir` is the user's `$XDG_RUNTIME_DIR` (or DRFW's state dir),
/// which DRFW only uses when it is owned by the user and not accessible to
/// anyone else. It is user-controlled, so the watcher only ever lists it with
/// `find -maxdepth 1 -name … -user <uid>` (readdir and lstat, no symlinks
/// followed), bounded by `timeout 2` where available. It never writes,
/// creates, opens or follows anything there: root writing to a user directory
/// would invite a symlink attack, and even `test -e` would follow a planted
/// symlink and leak whether a root-only path exists.
///
/// The nonce is **not** a secret: it is visible to every local user (in
/// `ps`, in the `drfw-revert-<nonce>` unit name and in the world-readable
/// `/run/drfw/active`). What protects the guard is ownership: only files
/// owned by `uid` count as tokens, in a directory only that user can write.
/// Any process of that user can create the confirm token. That is not an
/// escalation: all it does is keep rules that the user just authenticated to
/// apply. A fresh nonce for every apply keeps stale tokens from matching a
/// later guard.
pub const WATCHER_SCRIPT: &str = watcher_script!();

/// True if `haystack` contains `needle` (usable in constants).
pub(crate) const fn const_contains(haystack: &str, needle: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    let mut start = 0;
    while start + n.len() <= h.len() {
        let mut i = 0;
        while i < n.len() && h[start + i] == n[i] {
            i += 1;
        }
        if i == n.len() {
            return true;
        }
        start += 1;
    }
    false
}

// APPLY_SCRIPT writes the watcher through a here-document ending at a line
// `DRFW_WATCHER_EOF`; the watcher text must never contain that line.
const _: () = assert!(
    !const_contains(WATCHER_SCRIPT, "\nDRFW_WATCHER_EOF")
        && matches!(WATCHER_SCRIPT.as_bytes().last(), Some(b'\n')),
    "WATCHER_SCRIPT would break APPLY_SCRIPT's here-document"
);

/// Fixed shell script that applies a ruleset and arms the revert guard, with a
/// single elevation.
///
/// Arguments: `$1` state dir ([`GUARD_STATE_DIR`]), `$2` timeout in seconds
/// (0 = no guard, just apply), `$3` nonce (32 lowercase hex digits), `$4`
/// confirmation dir, `$5` nft command, `$6` watcher launcher (`auto` or
/// `setsid`; tests force `setsid`), `$7` uid of the user who may confirm.
/// The nftables JSON arrives on stdin. No argument is ever interpolated into
/// script text, and every argument is validated against an allowlist first
/// (paths: absolute, `[A-Za-z0-9/._@+-]`, no `..` component; they also
/// travel through `systemd-run`, which would expand `$`).
///
/// The script ignores `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGTERM` and `SIGPIPE`
/// (an SSH drop, Ctrl-C after the password or a killed elevation tool must not
/// stop it halfway), and the watcher is started **before** the new rules go
/// live, so even `SIGKILL` cannot leave them without a guard. A `setsid`
/// watcher gets the default signal handling back (it reverts when
/// terminated). It runs with umask 077: the revert file (the previous
/// `inet drfw` table, which listing normally needs `CAP_NET_ADMIN` for), the
/// watcher script and the lock are readable by root only; the state
/// directory (755), the `status-*` files and `active` (644) are
/// world-readable, for [`crate::core::apply_guard`].
///
/// Steps:
/// 1. Print `drfw-apply-started` (DRFW then knows authentication succeeded).
/// 2. Validate the arguments. Create `<state_dir>` (mode 755) and require it
///    to be a real directory (not a symlink) owned by the caller (root) and
///    not group/world-writable. Take `flock` on `<state_dir>/lock` when
///    available, so watchers and concurrent applies serialize; it is held
///    (also by nft) until the outcome is recorded.
/// 3. With a guard: write `<state_dir>/revert-<nonce>.nft`, a complete atomic
///    batch: `add table inet drfw`, `delete table inet drfw`, then
///    `nft list table inet drfw` (stdout only) if that table exists. If the
///    table did not exist, the revert therefore removes it. If an earlier
///    guard is still pending (never confirmed), its revert file is inherited
///    instead: a timeout must go back to the last *confirmed* state, not to
///    rules that were themselves on probation.
/// 4. With a guard: write the watcher to `<state_dir>/watcher-<nonce>.sh` and
///    start it detached: `systemd-run --unit=drfw-revert-<nonce> --collect` when
///    systemd is PID 1 (required under `run0`, whose transient unit would kill
///    leftover children), else `setsid` with stdio on `/dev/null`. It cannot
///    act on tokens yet (not armed). If it cannot be started: exit 4, nothing
///    changed.
/// 5. `nft --json -f -` the new ruleset. On failure: write the new guard's
///    status `not-applied` (its watcher exits without reverting), exit 3;
///    nothing changed and any earlier guard keeps running.
/// 6. Supersede the earlier guard: write its status `superseded` (its watcher
///    exits on the next poll) and `systemctl stop` its unit if it had one.
/// 7. With a guard: create `<state_dir>/armed-<nonce>` (from now on the
///    watcher accepts confirm/revert tokens) and record the guard in
///    `<state_dir>/active` (`<nonce> <systemd|setsid> <pid|->`, mode 644;
///    the pid of a `setsid` watcher, `-` for a systemd unit). Without one:
///    remove `active`.
/// 8. Print `revert_file=<path>` and `watcher=<systemd:unit|setsid:pid|none>`.
///
/// Exit codes: 0 success; 1 failure before anything changed; 3 nft rejected
/// the ruleset (nothing changed); 4 the guard could not be started (nothing
/// changed); 5 the rules were applied but the guard could not be armed: they
/// revert at the deadline and cannot be confirmed. 126/127 are never used:
/// callers read those as authentication errors from pkexec.
pub const APPLY_SCRIPT: &str = concat!(
    r#"trap '' HUP INT QUIT TERM PIPE
set -u
umask 077
LC_ALL=C
export LC_ALL
printf 'drfw-apply-started\n'
state_dir=$1
timeout=$2
nonce=$3
confirm_dir=$4
nft=$5
launcher=$6
uid=$7
fail() {
    printf 'drfw: %s\n' "$1" >&2
    exit "$2"
}
"#,
    safe_path_fn!(),
    r#"safe_path "$state_dir" || fail "invalid state directory" 1
safe_path "$confirm_dir" || fail "invalid confirmation directory" 1
case $nft in
    nft) ;;
    *) safe_path "$nft" || fail "invalid nft command" 1 ;;
esac
case $nonce in
    *[!0-9a-f]*) fail "invalid nonce" 1 ;;
esac
[ "${#nonce}" -eq 32 ] || fail "invalid nonce" 1
case $timeout in
    ''|*[!0-9]*) fail "invalid timeout" 1 ;;
esac
[ "${#timeout}" -le 4 ] && [ "$timeout" -le 3600 ] || fail "timeout too long" 1
case $launcher in
    auto|setsid) ;;
    *) fail "invalid watcher launcher" 1 ;;
esac
case $uid in
    ''|*[!0-9]*) fail "invalid uid" 1 ;;
esac
[ "${#uid}" -le 10 ] || fail "invalid uid" 1

# shellcheck disable=SC2174 # only the last component is new (/run exists)
mkdir -p -m 755 -- "$state_dir" || fail "cannot create $state_dir" 1
if [ -L "$state_dir" ] || [ ! -d "$state_dir" ] || [ -z "$(find "$state_dir" -prune \
        -user "$(id -u)" ! -perm -0020 ! -perm -0002 -print)" ]; then
    fail "$state_dir must be a directory owned by $(id -un) and writable only by it" 1
fi
if command -v flock >/dev/null 2>&1; then
    exec 9>"$state_dir/lock" || fail "cannot open $state_dir/lock" 1
    flock -w 60 9 || fail "another drfw apply is still running" 1
fi

# Forget outcomes and leftovers older than a day (guards last at most an hour)
find "$state_dir/" -maxdepth 1 -type f \( -name 'status-*' -o -name 'revert-*' \
    -o -name 'watcher-*' -o -name 'armed-*' -o -name '.*.tmp' \) -mmin +1440 \
    -exec rm -f -- {} + 2>/dev/null

active_file="$state_dir/active"
revert_file="$state_dir/revert-$nonce.nft"
watcher_file="$state_dir/watcher-$nonce.sh"
armed_file="$state_dir/armed-$nonce"

# Atomically writes status $2 for nonce $1
write_status() {
    tmp="$state_dir/.status-$1.tmp"
    printf '%s\n' "$2" > "$tmp" && chmod 644 "$tmp" && mv -f -- "$tmp" "$state_dir/status-$1"
}

# An earlier guard that has not finished yet (no status file)
prev_nonce=
prev_launcher=
if [ -f "$active_file" ]; then
    read -r prev_nonce prev_launcher _ < "$active_file" || true
    case $prev_nonce in
        *[!0-9a-f]*) prev_nonce= ;;
    esac
    if [ "${#prev_nonce}" -ne 32 ] || [ -e "$state_dir/status-$prev_nonce" ]; then
        prev_nonce=
    fi
fi

if [ "$timeout" -gt 0 ]; then
    tmp="$state_dir/.revert-$nonce.tmp"
    if [ -n "$prev_nonce" ] && [ -f "$state_dir/revert-$prev_nonce.nft" ]; then
        cp -- "$state_dir/revert-$prev_nonce.nft" "$tmp" \
            || fail "cannot copy the pending revert file" 1
    else
        # stdout only: nft's warnings or errors must never end up in the batch
        tables=$("$nft" list tables) || fail "cannot list nftables tables" 1
        current=
        if printf '%s\n' "$tables" | grep -qx 'table inet drfw'; then
            current=$("$nft" list table inet drfw) \
                || fail "cannot save the current drfw table" 1
        fi
        printf 'add table inet drfw\ndelete table inet drfw\n%s\n' "$current" > "$tmp" \
            || { rm -f -- "$tmp"; fail "cannot write the revert file" 1; }
    fi
    mv -f -- "$tmp" "$revert_file" || { rm -f -- "$tmp"; fail "cannot write $revert_file" 1; }

    not_started() {
        rm -f -- "$revert_file" "$watcher_file"
        fail "could not start the revert guard ($1); nothing was changed" 4
    }

    cat > "$watcher_file" <<'DRFW_WATCHER_EOF' || not_started "cannot write $watcher_file"
"#,
    watcher_script!(),
    r#"DRFW_WATCHER_EOF

    if [ "$launcher" = auto ] && [ -d /run/systemd/system ]; then
        unit="drfw-revert-$nonce"
        if ! out=$(systemd-run --unit="$unit" --collect --quiet --service-type=exec \
                --description="drfw: revert firewall rules unless confirmed" \
                /bin/sh "$watcher_file" "$state_dir" "$timeout" "$nonce" "$confirm_dir" \
                "$nft" "$uid" systemd 2>&1); then
            not_started "systemd-run failed: $out"
        fi
        launched=systemd
        watcher_pid=-
        watcher="systemd:$unit.service"
    else
        command -v setsid >/dev/null 2>&1 || not_started "setsid not found"
        # Default signal handling for the watcher (this script ignores them):
        # it reverts when it is terminated
        (
            trap - HUP INT QUIT TERM PIPE
            exec setsid /bin/sh "$watcher_file" "$state_dir" "$timeout" "$nonce" \
                "$confirm_dir" "$nft" "$uid" setsid </dev/null >/dev/null 2>&1 9>&-
        ) &
        pid=$!
        kill -0 "$pid" 2>/dev/null || not_started "setsid failed"
        launched=setsid
        watcher_pid=$pid
        watcher="setsid:$pid"
    fi
fi

if ! apply_err=$("$nft" --json -f - 2>&1 >/dev/null); then
    if [ "$timeout" -gt 0 ]; then
        # The new watcher exits without reverting
        write_status "$nonce" not-applied
        rm -f -- "$revert_file" "$watcher_file"
        if [ "$launched" = systemd ]; then
            systemctl stop --no-block "drfw-revert-$nonce.service" >/dev/null 2>&1
        fi
    fi
    fail "nft rejected the ruleset: $apply_err" 3
fi

# The new rules are live: retire the earlier guard
if [ -n "$prev_nonce" ]; then
    write_status "$prev_nonce" superseded
    if [ "$prev_launcher" = systemd ]; then
        systemctl stop --no-block "drfw-revert-$prev_nonce.service" >/dev/null 2>&1
    fi
    rm -f -- "$state_dir/revert-$prev_nonce.nft" "$state_dir/watcher-$prev_nonce.sh" \
        "$state_dir/armed-$prev_nonce"
fi

if [ "$timeout" -eq 0 ]; then
    rm -f -- "$active_file"
    printf 'watcher=none\n'
    exit 0
fi

if ! : > "$armed_file"; then
    rm -f -- "$active_file"
    fail "the new rules are active, but the revert guard could not be armed: they revert in $timeout seconds and cannot be confirmed" 5
fi
printf '%s %s %s\n' "$nonce" "$launched" "$watcher_pid" > "$active_file.tmp" \
    && chmod 644 "$active_file.tmp" && mv -f -- "$active_file.tmp" "$active_file"
printf 'revert_file=%s\nwatcher=%s\n' "$revert_file" "$watcher"
exit 0
"#
);

/// `$0` for [`APPLY_SCRIPT`] (shows up in `ps` and in shell error messages).
pub(crate) const APPLY_SCRIPT_NAME: &str = "drfw-apply";

/// How [`APPLY_SCRIPT`] starts its watcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatcherLauncher {
    /// `systemd-run` when systemd is PID 1, else `setsid` (production)
    Auto,
    /// Always `setsid` (tests: never assume systemd inside a namespace)
    Setsid,
}

impl WatcherLauncher {
    /// The script argument for this launcher.
    pub const fn as_arg(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Setsid => "setsid",
        }
    }
}

/// Creates the (elevated) command that applies a ruleset with a revert guard.
///
/// Runs [`APPLY_SCRIPT`] with a single elevation prompt, through the helper
/// (`<helper> apply <args…>`) when it is installed, else with `/bin/sh`; the
/// caller writes the nftables JSON to the command's stdin. Returns the command
/// and the state directory whose `status-<nonce>` file will hold the outcome.
///
/// # Arguments
///
/// * `timeout_secs` - Seconds until the watcher reverts (0 = no guard)
/// * `nonce` - 32 lowercase hex digits, fresh for every apply
/// * `confirm_dir` - User directory where confirm/revert tokens are created
/// * `uid` - The user whose tokens count (owner of `confirm_dir`)
///
/// # Testing
///
/// When `DRFW_NFT_COMMAND` is set, the script runs **without elevation**, uses
/// that command as nft, keeps its state in `DRFW_GUARD_STATE_DIR` (default
/// `<DRFW state dir>/guard`) and always starts the watcher with `setsid`.
///
/// # Errors
///
/// Returns `Err(ElevationError)` if no elevation method is available.
pub fn create_elevated_apply_command(
    timeout_secs: u64,
    nonce: &str,
    confirm_dir: &str,
    uid: u32,
) -> Result<(Command, std::path::PathBuf), ElevationError> {
    let timeout = timeout_secs.to_string();
    let uid = uid.to_string();

    if let Some(nft_path) = test_nft_command() {
        let state_dir = std::env::var_os("DRFW_GUARD_STATE_DIR")
            .map(std::path::PathBuf::from)
            .or_else(|| crate::utils::get_state_dir().map(|dir| dir.join("guard")))
            .ok_or_else(|| {
                ElevationError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no state directory for the test guard",
                ))
            })?;
        let state_str = state_dir.to_string_lossy().into_owned();
        let cmd = apply_command(
            ElevationPlan::direct(),
            &state_str,
            &timeout,
            nonce,
            confirm_dir,
            &nft_path,
            WatcherLauncher::Setsid,
            &uid,
        );
        return Ok((cmd, state_dir));
    }

    let cmd = apply_command(
        current_elevation()?,
        GUARD_STATE_DIR,
        &timeout,
        nonce,
        confirm_dir,
        crate::distro::NFT_COMMAND,
        WatcherLauncher::Auto,
        &uid,
    );
    Ok((cmd, std::path::PathBuf::from(GUARD_STATE_DIR)))
}

/// The [`APPLY_SCRIPT`] command for `plan`, with the script's arguments in
/// order (the helper receives the same ones).
fn apply_command(
    plan: ElevationPlan,
    state_dir: &str,
    timeout: &str,
    nonce: &str,
    confirm_dir: &str,
    nft: &str,
    launcher: WatcherLauncher,
    uid: &str,
) -> Command {
    plan.script_command(
        crate::helper::APPLY,
        APPLY_SCRIPT,
        APPLY_SCRIPT_NAME,
        &[
            state_dir,
            timeout,
            nonce,
            confirm_dir,
            nft,
            launcher.as_arg(),
            uid,
        ],
    )
}

#[cfg(test)]
mod tests {
    //! No test here changes the process environment: the elevation choice and
    //! the commands are built by pure functions with their inputs passed in.

    use super::*;

    const MOCK_NFT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/mock_nft.sh");

    /// Runs the root scripts' shell `safe_path` on every path (one `/bin/sh`
    /// for all of them), with `LC_ALL` set to `locale` if given; true for each
    /// path it accepts.
    fn shell_safe_path(paths: &[String], locale: Option<&str>) -> Vec<bool> {
        let script = format!(
            "{SAFE_PATH_FN}for p; do if safe_path \"$p\"; then printf 1; else printf 0; fi; done"
        );
        let mut cmd = std::process::Command::new(SHELL_PATH);
        cmd.arg("-c").arg(&script).arg("drfw-safe-path").args(paths);
        if let Some(locale) = locale {
            cmd.env("LC_ALL", locale);
        }
        let output = cmd.output().expect("run /bin/sh");
        assert!(output.status.success(), "{output:?}");
        let verdicts: Vec<bool> = output.stdout.iter().map(|b| *b == b'1').collect();
        assert_eq!(verdicts.len(), paths.len(), "{output:?}");
        verdicts
    }

    /// The shell `safe_path` accepts exactly what `distro::is_script_path`
    /// accepts (in the inherited, the C and a UTF-8 locale), every
    /// compile-time-valid path, and only allowlisted bytes.
    fn check_safe_path_agrees(paths: &[String]) -> Result<(), String> {
        use crate::distro::{is_safe_path_byte, is_script_path, is_valid_absolute_path};
        for locale in [None, Some("C"), Some("C.UTF-8")] {
            for (path, shell) in paths.iter().zip(shell_safe_path(paths, locale)) {
                let context = format!("{path:?} (LC_ALL={locale:?}): shell says {shell}");
                if shell != is_script_path(path) {
                    return Err(format!("{context}, is_script_path disagrees"));
                }
                if is_valid_absolute_path(path) && !shell {
                    return Err(format!("{context}, but it is a valid compile-time path"));
                }
                if shell && !path.bytes().all(is_safe_path_byte) {
                    return Err(format!("{context}, but it has unsafe bytes"));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_shell_safe_path_corpus() {
        let corpus = [
            "",
            "/",
            "//",
            "/.",
            "/..",
            "/../",
            "/a/..",
            "/a/../b",
            "/../a",
            "/a/..b",
            "/a/b..",
            "/a/.../b",
            "/..a",
            "/a/./b",
            "/a/",
            "/a//b",
            "/etc/nftables.conf",
            "/run/user/1000",
            "/usr/sbin/nft",
            "/a-b_c@d+e.f",
            "relative",
            "./x",
            "../x",
            "-/x",
            "/a b",
            "/a\tb",
            "/a\nb",
            "/a$b",
            "/a*",
            "/a?",
            "/[a]",
            "/a!",
            "/a\\b",
            "/a'b",
            "/a\"b",
            "/a`b",
            "/a;b",
            "/~",
            "/caf\u{e9}",
            "/a\u{2215}b",
            "/%n",
        ]
        .map(String::from);
        check_safe_path_agrees(&corpus).unwrap_or_else(|e| panic!("{e}"));
    }

    fn arb_path() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::*;
        let piece = prop_oneof![
            6 => proptest::sample::select(&["/", ".", "..", "a", "Z9", "_", "@", "+", "-", "x.y"][..])
                .prop_map(str::to_string),
            2 => proptest::sample::select(
                &[" ", "$", "*", "?", "[", "]", "!", "\n", "\t", "\\", "'", "\"", "`", ";", "~",
                  "\u{e9}", "\u{2215}", "%", "=", ",", "\u{7f}"][..]
            )
            .prop_map(str::to_string),
            // argv cannot hold NUL
            1 => any::<char>().prop_filter("no NUL", |c| *c != '\0').prop_map(String::from),
        ];
        (any::<bool>(), proptest::collection::vec(piece, 0..8)).prop_map(|(absolute, parts)| {
            let path = parts.concat();
            if absolute { format!("/{path}") } else { path }
        })
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(
            crate::core::test_helpers::proptest_cases(64)
        ))]

        /// Differential: shell `safe_path` vs the Rust predicates.
        #[test]
        fn prop_shell_safe_path_matches_rust(paths in proptest::collection::vec(arb_path(), 32)) {
            if let Err(e) = check_safe_path_agrees(&paths) {
                proptest::prop_assert!(false, "{}", e);
            }
        }
    }

    #[test]
    fn test_binary_exists() {
        // sh should exist on all Unix systems
        assert!(binary_exists("sh"));
        // This should not exist
        assert!(!binary_exists("drfw_nonexistent_binary_xyz"));
    }

    /// Runs [`select_elevation`] with the tools in `installed` available.
    fn select(
        is_root: bool,
        method: Option<&str>,
        context: ElevationContext,
        stdin_is_tty: bool,
        installed: &[&str],
        helper_installed: bool,
    ) -> Result<ElevationPlan, ElevationError> {
        select_elevation(&ElevationInputs {
            is_root,
            method,
            context,
            stdin_is_tty,
            available: &|tool| installed.contains(&tool),
            helper_installed,
        })
    }

    /// What a selection result is, for comparing (`ElevationError` holds an
    /// `io::Error` and has no `PartialEq`): `Pkexec`, or `Pkexec+helper`.
    fn outcome(result: Result<ElevationPlan, ElevationError>) -> String {
        match result {
            Ok(ElevationPlan {
                elevation,
                helper: false,
            }) => format!("{elevation:?}"),
            Ok(ElevationPlan {
                elevation,
                helper: true,
            }) => format!("{elevation:?}+helper"),
            Err(ElevationError::InvalidMethod(m)) => format!("invalid {m}"),
            Err(ElevationError::MethodNotAvailable(m)) => format!("unavailable {m}"),
            Err(ElevationError::PkexecNotFound) => "no pkexec".to_string(),
            Err(e) => format!("other {e}"),
        }
    }

    #[test]
    fn test_select_elevation_table() {
        use ElevationContext::{Cli, Gui};
        const ALL: &[&str] = &["run0", "sudo", "pkexec"];
        /// root, `DRFW_ELEVATION_METHOD`, context, TTY, installed tools, outcome
        type Case<'a> = (
            bool,
            Option<&'a str>,
            ElevationContext,
            bool,
            &'a [&'a str],
            &'a str,
        );
        #[rustfmt::skip]
        let cases: &[Case<'_>] = &[
            // Root never elevates, whatever the method (even an invalid one)
            (true, None, Cli, true, ALL, "Direct"),
            (true, None, Gui, false, &[], "Direct"),
            (true, Some("invalid_method"), Cli, true, ALL, "Direct"),
            // DRFW_ELEVATION_METHOD overrides the context, case-insensitively
            (false, Some("sudo"), Gui, false, ALL, "Sudo"),
            (false, Some("SUDO"), Cli, true, ALL, "Sudo"),
            (false, Some("Run0"), Gui, false, ALL, "Run0"),
            (false, Some("pkexec"), Cli, true, ALL, "Pkexec"),
            (false, Some("sudo"), Cli, true, &["run0", "pkexec"], "unavailable sudo"),
            (false, Some("RUN0"), Cli, true, &["sudo"], "unavailable run0"),
            (false, Some("pkexec"), Gui, false, &["sudo"], "unavailable pkexec"),
            (false, Some("Invalid_Method"), Cli, true, ALL, "invalid invalid_method"),
            (false, Some("doas"), Cli, true, ALL, "invalid doas"),
            // An empty method counts as unset
            (false, Some(""), Cli, true, ALL, "Run0"),
            // CLI on a terminal: run0, else sudo
            (false, None, Cli, true, ALL, "Run0"),
            (false, None, Cli, true, &["sudo", "pkexec"], "Sudo"),
            (false, None, Cli, true, &["pkexec"], "unavailable run0 or sudo"),
            // CLI without a terminal: pkexec only
            (false, None, Cli, false, ALL, "Pkexec"),
            (false, None, Cli, false, &["run0", "sudo"], "no pkexec"),
            // GUI: pkexec, even when started from a terminal
            (false, None, Gui, true, ALL, "Pkexec"),
            (false, None, Gui, false, ALL, "Pkexec"),
            (false, None, Gui, true, &["run0", "sudo"], "no pkexec"),
        ];
        for &(is_root, method, context, tty, installed, expected) in cases {
            assert_eq!(
                outcome(select(is_root, method, context, tty, installed, false)),
                expected,
                "root={is_root} method={method:?} {context:?} tty={tty} installed={installed:?}"
            );
            // With the helper installed: the same tool (or error), elevating
            // the helper; root still runs the scripts directly
            let with_helper = match expected {
                "Direct" => "Direct".to_string(),
                "Run0" | "Sudo" | "Pkexec" => format!("{expected}+helper"),
                error => error.to_string(),
            };
            assert_eq!(
                outcome(select(is_root, method, context, tty, installed, true)),
                with_helper,
                "helper installed: root={is_root} method={method:?} {context:?} tty={tty} \
                 installed={installed:?}"
            );
        }
    }

    #[test]
    fn test_trusted_entry_table() {
        // (helper?, file?, dir?, uid, mode, trusted)
        #[rustfmt::skip]
        let cases = [
            // The helper: root-owned regular executable, not group/world-writable
            (true, true, false, 0, 0o100_755, true),
            (true, true, false, 0, 0o100_700, true),
            (true, true, false, 0, 0o104_755, true),
            (true, true, false, 1000, 0o100_755, false),
            (true, true, false, 0, 0o100_775, false),
            (true, true, false, 0, 0o100_757, false),
            (true, true, false, 0, 0o100_644, false),
            (true, false, false, 0, 0o120_777, false),
            (true, false, true, 0, 0o040_755, false),
            // Its directories: root-owned, not group/world-writable
            (false, false, true, 0, 0o040_755, true),
            (false, false, true, 0, 0o041_777, false),
            (false, false, true, 0, 0o040_775, false),
            (false, false, true, 1000, 0o040_755, false),
            (false, true, false, 0, 0o100_755, false),
        ];
        for (helper, file, dir, uid, mode, trusted) in cases {
            assert_eq!(
                trusted_entry(helper, file, dir, uid, mode),
                trusted,
                "helper={helper} file={file} dir={dir} uid={uid} mode={mode:o}"
            );
        }
    }

    #[test]
    fn test_helper_is_trusted_on_real_files() {
        use std::os::unix::fs::MetadataExt;
        assert!(!helper_is_trusted(std::path::Path::new(
            "/nonexistent/drfw-helper"
        )));
        // A copy owned by the user running the tests (a development build)
        let dir = tempfile::tempdir().expect("tempdir");
        let copy = dir.path().join("drfw-helper");
        std::fs::write(&copy, "#!/bin/sh\n").expect("write");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        if !nix::unistd::getuid().is_root() {
            assert!(!helper_is_trusted(&copy));
        }
        // A root-owned system binary in root-owned directories passes
        let system = std::path::Path::new("/usr/bin/env");
        if std::fs::symlink_metadata(system).is_ok_and(|m| m.is_file() && m.uid() == 0) {
            assert!(helper_is_trusted(system));
        }
    }

    /// Program and arguments of a built command.
    fn argv(cmd: &Command) -> (String, Vec<String>) {
        let std_cmd = cmd.as_std();
        (
            std_cmd.get_program().to_string_lossy().into_owned(),
            std_cmd
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect(),
        )
    }

    #[test]
    fn test_elevation_commands() {
        let args = ["list", "ruleset"];
        let built = |elevation: Elevation| argv(&elevation.command("nft", &args));
        assert_eq!(
            built(Elevation::Direct),
            ("nft".into(), vec!["list".into(), "ruleset".into()])
        );
        for (elevation, tool) in [(Elevation::Run0, "run0"), (Elevation::Sudo, "sudo")] {
            assert_eq!(
                built(elevation),
                (
                    tool.into(),
                    vec!["nft".into(), "list".into(), "ruleset".into()]
                )
            );
        }
        assert_eq!(
            built(Elevation::Pkexec),
            (
                "pkexec".into(),
                vec![
                    "--disable-internal-agent".into(),
                    "nft".into(),
                    "list".into(),
                    "ruleset".into()
                ]
            )
        );
    }

    /// `DRFW_NFT_COMMAND` runs that command directly: the elevation choice is
    /// never even made (an invalid `DRFW_ELEVATION_METHOD` cannot matter).
    #[test]
    fn test_check_command_override_skips_elevation() {
        let cmd = check_command(Some(MOCK_NFT), || panic!("the override must not elevate"))
            .expect("override");
        assert_eq!(
            argv(&cmd),
            (
                MOCK_NFT.into(),
                NFT_JSON_CHECK_ARGS.map(String::from).to_vec()
            )
        );

        let sudo = |helper| {
            move || {
                Ok(ElevationPlan {
                    elevation: Elevation::Sudo,
                    helper,
                })
            }
        };
        let cmd = check_command(None, sudo(false)).expect("elevated");
        let mut expected = vec![crate::distro::NFT_COMMAND.to_string()];
        expected.extend(NFT_JSON_CHECK_ARGS.map(String::from));
        assert_eq!(argv(&cmd), ("sudo".into(), expected));
        // The helper's `check`: no nft arguments, never a file from argv
        let cmd = check_command(None, sudo(true)).expect("helper");
        assert_eq!(
            argv(&cmd),
            (
                "sudo".into(),
                vec![crate::distro::HELPER_PATH.into(), "check".into()]
            )
        );
        let error = check_command(None, || Err(ElevationError::InvalidMethod("x".into())));
        assert!(matches!(error, Err(ElevationError::InvalidMethod(_))));
    }

    /// With the helper, the request carries the scripts' arguments unchanged,
    /// and the helper accepts what DRFW builds (production values).
    #[test]
    fn test_helper_commands_are_accepted_by_the_helper() {
        let pkexec_helper = ElevationPlan {
            elevation: Elevation::Pkexec,
            helper: true,
        };
        let config = crate::helper::HelperConfig::production(1000);
        let helper_args = |cmd: &Command| {
            let (program, args) = argv(cmd);
            assert_eq!(program, "pkexec");
            assert_eq!(
                &args[..2],
                ["--disable-internal-agent", crate::distro::HELPER_PATH]
            );
            args[2..].to_vec()
        };

        let cmd = apply_command(
            pkexec_helper,
            GUARD_STATE_DIR,
            "30",
            "0123456789abcdef0123456789abcdef",
            "/run/user/1000",
            crate::distro::NFT_COMMAND,
            WatcherLauncher::Auto,
            "1000",
        );
        let args = helper_args(&cmd);
        assert_eq!(args[0], "apply");
        assert!(matches!(
            crate::helper::parse_request(&args, &config),
            Ok(crate::helper::Request::Apply(_))
        ));

        for service in [Some(crate::SYSTEM_NFT_SERVICE), None] {
            let save =
                save_config_command(None, crate::SYSTEM_NFT_PATH, service, || Ok(pkexec_helper))
                    .expect("helper");
            // The helper renders the file itself: it gets the JSON payload
            assert_eq!(save.input, SaveConfigInput::Payload);
            let args = helper_args(&save.command);
            assert_eq!(
                args,
                [
                    "save-config",
                    crate::SYSTEM_NFT_PATH,
                    crate::distro::NFT_COMMAND,
                    service.unwrap_or_default()
                ]
            );
            assert!(matches!(
                crate::helper::parse_request(&args, &config),
                Ok(crate::helper::Request::SaveConfig(_))
            ));
        }

        let args = helper_args(&pkexec_helper.check_command());
        assert_eq!(
            crate::helper::parse_request(&args, &config),
            Ok(crate::helper::Request::Check)
        );
    }

    /// Without the helper (development builds): exactly the pre-helper
    /// commands, `/bin/sh -c <script>` through the tool.
    #[test]
    fn test_apply_command_without_helper_runs_the_script() {
        let cmd = apply_command(
            ElevationPlan {
                elevation: Elevation::Run0,
                helper: false,
            },
            GUARD_STATE_DIR,
            "30",
            "0123456789abcdef0123456789abcdef",
            "/run/user/1000",
            "nft",
            WatcherLauncher::Auto,
            "1000",
        );
        let (program, args) = argv(&cmd);
        assert_eq!(program, "run0");
        assert_eq!(
            args,
            [
                SHELL_PATH,
                "-c",
                APPLY_SCRIPT,
                APPLY_SCRIPT_NAME,
                GUARD_STATE_DIR,
                "30",
                "0123456789abcdef0123456789abcdef",
                "/run/user/1000",
                "nft",
                "auto",
                "1000"
            ]
        );
    }

    #[test]
    fn test_save_config_command_with_mock_skips_elevation() {
        let cmd = save_config_command(
            Some(MOCK_NFT),
            "/nonexistent/nftables.conf",
            Some("nftables.service"),
            || panic!("mock mode never needs elevation"),
        )
        .expect("mock mode");
        // The script reads the text DRFW rendered
        assert_eq!(cmd.input, SaveConfigInput::Text);
        let (program, args) = argv(&cmd.command);
        assert_eq!(program, SHELL_PATH);
        // Fixed script, then $0, target and nft command as separate argv entries
        assert_eq!(
            args,
            [
                "-c",
                SAVE_CONFIG_SCRIPT,
                SAVE_CONFIG_SCRIPT_NAME,
                "/nonexistent/nftables.conf",
                MOCK_NFT,
                "nftables.service"
            ]
        );

        // Elevated: the script through the tool, with the build's nft
        let cmd = save_config_command(None, "/etc/x.conf", None, || {
            Ok(ElevationPlan {
                elevation: Elevation::Pkexec,
                helper: false,
            })
        })
        .expect("elevated");
        assert_eq!(cmd.input, SaveConfigInput::Text);
        let (program, args) = argv(&cmd.command);
        assert_eq!(program, "pkexec");
        assert_eq!(
            args,
            [
                "--disable-internal-agent",
                SHELL_PATH,
                "-c",
                SAVE_CONFIG_SCRIPT,
                SAVE_CONFIG_SCRIPT_NAME,
                "/etc/x.conf",
                crate::distro::NFT_COMMAND,
                ""
            ]
        );
    }
}
