//! Privilege elevation for system operations
//!
//! This module provides controlled privilege escalation to execute commands
//! with root privileges. DRFW runs as an unprivileged user and only elevates for
//! specific operations:
//!
//! - **nft**: Firewall rule verification and application
//! - **/bin/sh** running the fixed [`SAVE_CONFIG_SCRIPT`]: verified, atomic writes of
//!   the system nftables configuration (Save to System), optionally followed by
//!   `systemctl enable` of the boot service
//!
//! `nft` is [`crate::distro::NFT_COMMAND`]: the packager's `DRFW_NFT_PATH`, or
//! plain `nft` resolved by the elevation tool.
//! - **/bin/sh** running the fixed [`APPLY_SCRIPT`]: applies a ruleset and arms the
//!   root-side revert guard ([`WATCHER_SCRIPT`]); see [`crate::core::apply_guard`]
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
//! `DRFW_ELEVATION_METHOD` overrides both.
//!
//! # Prompts
//!
//! Every elevated operation asks once: Apply and Save to System each run one
//! fixed `/bin/sh` script (see [`APPLY_SCRIPT`], [`SAVE_CONFIG_SCRIPT`]), and
//! the rare elevated `nft --check` fallback asks too. DRFW ships no polkit rule
//! that caches authorizations: caching `/bin/sh` would allow arbitrary root
//! commands, and caching `nft` would make root `nft` (which can read any file
//! via `nft -c -f <file>`) available to anything that can drive the DRFW
//! process, just to save a prompt in a fallback path.
//!
//! # Environment Variables
//!
//! - `DRFW_NFT_COMMAND`: Path to nft binary or mock script. When set, uses this path
//!   directly without elevation. Used for testing with mock nft.
//!   Example: `DRFW_NFT_COMMAND=tests/mock_nft.sh cargo test`
//!
//! - `DRFW_ELEVATION_METHOD`: Force a specific elevation method (`sudo`, `run0`, or `pkexec`),
//!   e.g. `sudo` where `run0` is installed but not usable. It changes only which tool asks
//!   for the password. There is deliberately no unattended (password-less) mode: the
//!   elevated program is `/bin/sh`, so a sudoers `NOPASSWD` rule for it would grant
//!   unrestricted root. Automation that already runs as root can run `drfw` as root
//!   (it then elevates nothing), or load `drfw export` output with `nft -f`.
//!
//! # Security
//!
//! - Only specific programs can be elevated (nft, and `/bin/sh` with a fixed script)
//! - Every elevated child is spawned with `kill_on_drop(true)`, so a timed-out or
//!   abandoned call does not leave an orphaned authentication dialog behind
//! - All inputs are validated before elevation
//! - Commands are constructed safely without shell interpolation
//! - Audit logging tracks all privileged operations (via caller)
//! - The elevation tool is checked for availability before use; the target
//!   program is resolved by the elevation tool (root's `PATH`) unless the
//!   packager set an absolute `DRFW_NFT_PATH`
//!
//! # Example
//!
//! ```no_run
//! use drfw::elevation::create_elevated_nft_command;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut cmd = create_elevated_nft_command(&["--json", "list", "ruleset"])?;
//! let output = cmd.output().await?;
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

/// Internal helper to build an elevated command for a specific program.
///
/// This is not exposed publicly - callers must use the specific functions
/// (`create_elevated_nft_command`, `create_elevated_save_config_command`,
/// `create_elevated_apply_command`) to ensure only approved binaries can be
/// elevated. The child is killed when its handle is dropped (e.g. on timeout).
fn build_elevated_command(program: &str, args: &[&str]) -> Result<Command, ElevationError> {
    let mut cmd = build_elevated_command_inner(program, args)?;
    cmd.kill_on_drop(true);
    Ok(cmd)
}

/// Builds an unelevated command (test mode or already root), killed on drop.
fn unelevated_command(program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args).kill_on_drop(true);
    cmd
}

fn build_elevated_command_inner(program: &str, args: &[&str]) -> Result<Command, ElevationError> {
    use std::os::fd::AsFd;

    // 1. Direct Root Execution (No prompt needed)
    let is_root = nix::unistd::getuid().is_root();
    if is_root {
        return Ok(unelevated_command(program, args));
    }

    // 2. Explicit elevation method override
    if let Ok(method) = std::env::var("DRFW_ELEVATION_METHOD") {
        let method = method.to_lowercase();
        if !method.is_empty() {
            return match method.as_str() {
                "sudo" => {
                    if !binary_exists("sudo") {
                        return Err(ElevationError::MethodNotAvailable("sudo".into()));
                    }
                    let mut cmd = Command::new("sudo");
                    cmd.arg(program).args(args);
                    Ok(cmd)
                }
                "run0" => {
                    if !binary_exists("run0") {
                        return Err(ElevationError::MethodNotAvailable("run0".into()));
                    }
                    let mut cmd = Command::new("run0");
                    cmd.arg(program).args(args);
                    Ok(cmd)
                }
                "pkexec" => {
                    if !binary_exists("pkexec") {
                        return Err(ElevationError::MethodNotAvailable("pkexec".into()));
                    }
                    let mut cmd = Command::new("pkexec");
                    cmd.args(["--disable-internal-agent", program]).args(args);
                    Ok(cmd)
                }
                _ => Err(ElevationError::InvalidMethod(method)),
            };
        }
    }

    // 3. From the front end. The GUI always uses pkexec: even when it was
    // started from a terminal, run0/sudo would prompt in that terminal, which
    // nobody is looking at. The CLI uses run0/sudo on a TTY (works over SSH).
    let is_atty = context() == ElevationContext::Cli
        && nix::unistd::isatty(std::io::stdin().as_fd()).unwrap_or(false);

    if is_atty {
        // CLI environment: prefer run0 (modern, no SUID), fallback to sudo
        if binary_exists("run0") {
            let mut cmd = Command::new("run0");
            cmd.arg(program).args(args);
            return Ok(cmd);
        }
        if !binary_exists("sudo") {
            return Err(ElevationError::MethodNotAvailable("run0 or sudo".into()));
        }
        let mut cmd = Command::new("sudo");
        cmd.arg(program).args(args);
        Ok(cmd)
    } else {
        // GUI, or no terminal to ask on: pkexec only
        if binary_exists("pkexec") {
            let mut cmd = Command::new("pkexec");
            cmd.args(["--disable-internal-agent", program]).args(args);
            return Ok(cmd);
        }
        Err(ElevationError::PkexecNotFound)
    }
}

/// Creates an elevated `nft` command with the specified arguments
///
/// This function constructs a command that will execute `nft` with root privileges.
/// The arguments are passed directly without shell interpretation, preventing
/// command injection.
///
/// # Elevation Strategy
///
/// 1. **Custom command**: If `DRFW_NFT_COMMAND` is set, uses that path directly (no elevation)
/// 2. **Already root**: runs `nft` directly
/// 3. `DRFW_ELEVATION_METHOD`, else by [`ElevationContext`]: the GUI uses
///    `pkexec nft`; the CLI uses `run0 nft` (else `sudo nft`) with a TTY and
///    `pkexec nft` without one
///
/// # Arguments
///
/// * `args` - Command-line arguments to pass to `nft`
///
/// # Returns
///
/// A configured tokio `Command`, ready to spawn.
///
/// # Errors
///
/// - [`ElevationError::PkexecNotFound`] - GUI (or no TTY) and `pkexec` is not installed
/// - [`ElevationError::MethodNotAvailable`] - `DRFW_ELEVATION_METHOD` names a tool that is not
///   installed, or the CLI on a TTY finds neither `run0` nor `sudo`
/// - [`ElevationError::InvalidMethod`] - `DRFW_ELEVATION_METHOD` is not `sudo`, `run0` or `pkexec`
///
/// # Example
///
/// ```no_run
/// use drfw::elevation::create_elevated_nft_command;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // List current ruleset
/// let mut cmd = create_elevated_nft_command(&["list", "ruleset"])?;
/// let output = cmd.output().await?;
///
/// // Apply rules from stdin
/// let mut cmd = create_elevated_nft_command(&["--json", "-f", "-"])?;
/// cmd.stdin(std::process::Stdio::piped());
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// Arguments are passed directly to `nft` without shell interpretation.
/// Callers must ensure arguments are properly validated before calling this function.
/// See CLAUDE.md Section 5 for input validation guidelines.
///
/// # Testing
///
/// Set `DRFW_NFT_COMMAND` to a mock script path (e.g., `tests/mock_nft.sh`) to use
/// a mock nft for testing without requiring root privileges.
pub fn create_elevated_nft_command(args: &[&str]) -> Result<Command, ElevationError> {
    // Check for explicit nft command override (for testing with mock)
    if let Some(nft_path) = test_nft_command() {
        return Ok(unelevated_command(&nft_path, args));
    }

    build_elevated_command(crate::distro::NFT_COMMAND, args)
}

/// Returns `DRFW_NFT_COMMAND` when set and non-empty (test mode: no elevation).
pub fn test_nft_command() -> Option<String> {
    std::env::var("DRFW_NFT_COMMAND")
        .ok()
        .filter(|path| !path.is_empty())
}

/// Shell function shared by [`SAVE_CONFIG_SCRIPT`] and [`APPLY_SCRIPT`]: true if
/// `$1` is an absolute path of `[A-Za-z0-9/._@+-]` characters. The same
/// allowlist as [`crate::distro::is_safe_path_byte`], which checks the
/// compile-time paths.
macro_rules! safe_path_fn {
    () => {
        r#"safe_path() {
    case $1 in
        /*) ;;
        *) return 1 ;;
    esac
    case $1 in
        *[!A-Za-z0-9/._@+-]*) return 1 ;;
    esac
    return 0
}
"#
    };
}

/// Fixed shell script run (elevated) by Save to System.
///
/// Arguments: `$1` = target path, `$2` = nft command (`nft` or an absolute
/// path), `$3` = service to enable at boot (optional; empty = do not enable).
/// The new file content arrives on stdin. No user-controlled data is ever
/// interpolated into the script text; the target path and the service are
/// compile-time constants ([`crate::SYSTEM_NFT_PATH`],
/// [`crate::SYSTEM_NFT_SERVICE`]) in the GUI and are only ever passed as argv.
/// All three are checked against allowlists first (paths: absolute,
/// `[A-Za-z0-9/._@+-]`; service: `[A-Za-z0-9:_.@-]+.service`, not starting
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
const SAVE_CONFIG_SCRIPT_NAME: &str = "drfw-save-config";

/// Absolute shell path: elevation tools must not resolve `sh` through `PATH`.
const SHELL_PATH: &str = "/bin/sh";

/// Creates the (elevated) command that installs a new system nftables config.
///
/// Runs [`SAVE_CONFIG_SCRIPT`] with `/bin/sh` and a single elevation prompt.
/// The caller writes the file content to the command's stdin.
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
/// [`create_elevated_nft_command`]. Tests point `target` at a temporary
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
/// let mut cmd =
///     create_elevated_save_config_command(drfw::SYSTEM_NFT_PATH, Some(drfw::SYSTEM_NFT_SERVICE))?;
/// cmd.stdin(std::process::Stdio::piped());
/// # Ok(())
/// # }
/// ```
pub fn create_elevated_save_config_command(
    target: &str,
    enable_service: Option<&str>,
) -> Result<Command, ElevationError> {
    let service = enable_service.unwrap_or_default();
    if let Some(nft_path) = test_nft_command() {
        return Ok(unelevated_command(
            SHELL_PATH,
            &[
                "-c",
                SAVE_CONFIG_SCRIPT,
                SAVE_CONFIG_SCRIPT_NAME,
                target,
                &nft_path,
                service,
            ],
        ));
    }

    build_elevated_command(
        SHELL_PATH,
        &[
            "-c",
            SAVE_CONFIG_SCRIPT,
            SAVE_CONFIG_SCRIPT_NAME,
            target,
            crate::distro::NFT_COMMAND,
            service,
        ],
    )
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
umask 022
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
/// (paths: absolute, `[A-Za-z0-9/._@+-]`; they also travel through
/// `systemd-run`, which would expand `$`).
///
/// The script ignores `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGTERM` and `SIGPIPE`
/// (an SSH drop, Ctrl-C after the password or a killed elevation tool must not
/// stop it halfway), and the watcher is started **before** the new rules go
/// live, so even `SIGKILL` cannot leave them without a guard.
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
///    `<state_dir>/active` (`<nonce> <systemd|setsid>`). Without one: remove
///    `active`.
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
umask 022
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
        watcher="systemd:$unit.service"
    else
        command -v setsid >/dev/null 2>&1 || not_started "setsid not found"
        setsid /bin/sh "$watcher_file" "$state_dir" "$timeout" "$nonce" "$confirm_dir" \
            "$nft" "$uid" setsid </dev/null >/dev/null 2>&1 9>&- &
        pid=$!
        kill -0 "$pid" 2>/dev/null || not_started "setsid failed"
        launched=setsid
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
printf '%s %s\n' "$nonce" "$launched" > "$active_file.tmp" \
    && mv -f -- "$active_file.tmp" "$active_file"
printf 'revert_file=%s\nwatcher=%s\n' "$revert_file" "$watcher"
exit 0
"#
);

/// `$0` for [`APPLY_SCRIPT`] (shows up in `ps` and in shell error messages).
const APPLY_SCRIPT_NAME: &str = "drfw-apply";

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
/// Runs [`APPLY_SCRIPT`] with `/bin/sh` and a single elevation prompt; the
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
        let cmd = unelevated_command(
            SHELL_PATH,
            &[
                "-c",
                APPLY_SCRIPT,
                APPLY_SCRIPT_NAME,
                &state_str,
                &timeout,
                nonce,
                confirm_dir,
                &nft_path,
                WatcherLauncher::Setsid.as_arg(),
                &uid,
            ],
        );
        return Ok((cmd, state_dir));
    }

    let cmd = build_elevated_command(
        SHELL_PATH,
        &[
            "-c",
            APPLY_SCRIPT,
            APPLY_SCRIPT_NAME,
            GUARD_STATE_DIR,
            &timeout,
            nonce,
            confirm_dir,
            crate::distro::NFT_COMMAND,
            WatcherLauncher::Auto.as_arg(),
            &uid,
        ],
    )?;
    Ok((cmd, std::path::PathBuf::from(GUARD_STATE_DIR)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_helpers::ENV_VAR_MUTEX;

    /// Get absolute path to `mock_nft.sh` for testing
    fn get_mock_nft_path() -> String {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        format!("{manifest_dir}/tests/mock_nft.sh")
    }

    #[test]
    fn test_binary_exists() {
        // sh should exist on all Unix systems
        assert!(binary_exists("sh"));
        // This should not exist
        assert!(!binary_exists("drfw_nonexistent_binary_xyz"));
    }

    #[test]
    fn test_create_nft_command_with_mock() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        // Use DRFW_NFT_COMMAND to specify mock nft
        let mock_path = get_mock_nft_path();
        unsafe {
            std::env::set_var("DRFW_NFT_COMMAND", &mock_path);
        }

        let cmd = create_elevated_nft_command(&["list", "ruleset"]);
        assert!(cmd.is_ok(), "Should create command with mock nft");

        // Clean up
        unsafe {
            std::env::remove_var("DRFW_NFT_COMMAND");
        }
    }

    #[test]
    fn test_save_config_command_with_mock_skips_elevation() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        let mock_path = get_mock_nft_path();
        unsafe {
            std::env::set_var("DRFW_NFT_COMMAND", &mock_path);
        }
        let cmd = create_elevated_save_config_command(
            "/nonexistent/nftables.conf",
            Some("nftables.service"),
        );
        unsafe {
            std::env::remove_var("DRFW_NFT_COMMAND");
        }

        let cmd = cmd.expect("mock mode never needs elevation");
        let std_cmd = cmd.as_std();
        assert_eq!(std_cmd.get_program(), SHELL_PATH);
        let args: Vec<_> = std_cmd.get_args().collect();
        // Fixed script, then $0, target and nft command as separate argv entries
        assert_eq!(args[1], SAVE_CONFIG_SCRIPT);
        assert_eq!(args[3], "/nonexistent/nftables.conf");
        assert_eq!(args[4], mock_path.as_str());
        assert_eq!(args[5], "nftables.service");
    }

    #[test]
    fn test_invalid_elevation_method() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        // Clear custom command and set invalid method
        unsafe {
            std::env::remove_var("DRFW_NFT_COMMAND");
            std::env::set_var("DRFW_ELEVATION_METHOD", "invalid_method");
        }

        let result = create_elevated_nft_command(&["list", "ruleset"]);

        // Clean up
        unsafe {
            std::env::remove_var("DRFW_ELEVATION_METHOD");
        }

        assert!(matches!(result, Err(ElevationError::InvalidMethod(_))));
    }

    #[test]
    fn test_elevation_method_case_insensitive() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        // Clear custom command and test case insensitivity with SUDO (uppercase)
        unsafe {
            std::env::remove_var("DRFW_NFT_COMMAND");
            std::env::set_var("DRFW_ELEVATION_METHOD", "SUDO");
        }

        let result = create_elevated_nft_command(&["list", "ruleset"]);

        // Clean up
        unsafe {
            std::env::remove_var("DRFW_ELEVATION_METHOD");
        }

        // Should succeed (sudo exists) or fail with MethodNotAvailable (sudo doesn't exist)
        // but NOT InvalidMethod - that would mean case sensitivity is broken
        assert!(!matches!(result, Err(ElevationError::InvalidMethod(_))));
    }

    #[test]
    fn test_drfw_nft_command_takes_precedence() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        // Even with elevation method set, DRFW_NFT_COMMAND should take precedence
        let mock_path = get_mock_nft_path();
        unsafe {
            std::env::set_var("DRFW_NFT_COMMAND", &mock_path);
            std::env::set_var("DRFW_ELEVATION_METHOD", "invalid_method");
        }

        let result = create_elevated_nft_command(&["list", "ruleset"]);

        // Clean up
        unsafe {
            std::env::remove_var("DRFW_NFT_COMMAND");
            std::env::remove_var("DRFW_ELEVATION_METHOD");
        }

        // Should succeed because DRFW_NFT_COMMAND bypasses elevation entirely
        assert!(
            result.is_ok(),
            "DRFW_NFT_COMMAND should take precedence over DRFW_ELEVATION_METHOD"
        );
    }
}
