//! Apply with a root-side revert guard (the dead-man switch)
//!
//! [`apply_guarded`] runs the fixed [`APPLY_SCRIPT`] with a single elevation.
//! As root, the script saves the current `inet drfw` table as a complete,
//! atomic revert batch, starts a detached watcher ([`WATCHER_SCRIPT`]) and
//! only then applies the new ruleset. The watcher restores the saved table
//! when the timeout expires unless it is told otherwise. The script ignores
//! hang-up, interrupt and terminate signals, and because the watcher exists
//! before the new rules go live, not even `SIGKILL` can leave them unguarded.
//!
//! The watcher does not depend on DRFW staying alive: closing the GUI, a GUI
//! crash, the terminal closing or the SSH session dropping all lead to the
//! revert. It also needs no second authentication, so it works exactly when
//! the user has locked themselves out.
//!
//! Talking to the watcher needs no privileges either. The user side only
//! creates empty token files in its own runtime directory
//! ([`GuardHandle::confirm`], [`GuardHandle::revert_now`]); the watcher, polling
//! once per second, only checks whether they exist and writes the outcome to a
//! root-owned status file that [`GuardHandle::wait_outcome`] reads.
//!
//! # Trust model
//!
//! Tokens live in a directory that must be owned by the user and closed to
//! everyone else (`$XDG_RUNTIME_DIR`, else DRFW's state dir; see
//! `confirm_dir`), and the watcher only counts tokens owned by the user's
//! uid. The nonce is not a secret (other local users can see it in `ps`, in
//! the unit name and in `/run/drfw/active`); ownership is the check. Any
//! process running as the same user can create the confirm token. That is not
//! an escalation: it can only keep rules that the user just authenticated to
//! apply. Every apply uses a fresh random 128-bit nonce, so stale tokens never
//! match a later guard. The watcher never writes to or follows anything in
//! the user's directory (see [`WATCHER_SCRIPT`]).
//!
//! [`APPLY_SCRIPT`]: crate::elevation::APPLY_SCRIPT
//! [`WATCHER_SCRIPT`]: crate::elevation::WATCHER_SCRIPT

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::core::confirmed::{ConfirmedRecord, RecordKind};
use crate::core::firewall::FirewallRuleset;
use crate::elevation::AuthError;

/// Upper bound for the authentication step of an elevated apply: from
/// spawning the elevation tool until the script reports that it started.
/// If it runs out, nothing was changed.
pub const APPLY_TIMEOUT: Duration = Duration::from_secs(120);

/// Upper bound for the script itself once it has started (as root). It
/// normally takes well under a second, but may wait up to 60 s for the lock
/// of a concurrent apply. If this runs out, the state is unknown: the script
/// is root and cannot be killed by DRFW.
pub const SCRIPT_TIMEOUT: Duration = Duration::from_secs(90);

/// First line the apply script prints, before it changes anything.
const STARTED_MARKER: &str = "drfw-apply-started";

/// Longest revert timeout the apply script accepts.
pub const MAX_GUARD_TIMEOUT_SECS: u64 = 3600;

/// How long to wait for the watcher's verdict after a confirm/revert request
/// or after the countdown ended. The watcher polls once per second.
pub const OUTCOME_GRACE: Duration = Duration::from_secs(10);

/// How often [`GuardHandle::wait_outcome`] checks the status file.
const OUTCOME_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Exit codes of [`crate::elevation::APPLY_SCRIPT`].
const EXIT_FAILED: i32 = 1;
const EXIT_REJECTED: i32 = 3;
const EXIT_GUARD_NOT_STARTED: i32 = 4;
const EXIT_GUARD_NOT_ARMED: i32 = 5;

/// Why a guarded apply failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplyError {
    /// Elevation failed or was cancelled; nothing was changed
    #[error("{0}")]
    Auth(#[from] AuthError),

    /// nft rejected the ruleset (script exit 3); nothing was changed
    #[error("nftables rejected the ruleset; nothing was changed: {0}")]
    Rejected(String),

    /// The watcher could not be started, so nothing was applied (script
    /// exit 4)
    #[error("The revert guard could not be started; nothing was changed: {0}")]
    GuardNotStarted(String),

    /// The script started (as root) but its outcome is unknown: it was killed
    /// by a signal, exited with an unexpected status, did not finish in
    /// time, or applied the rules without being able to arm the guard
    /// (script exit 5). The new rules may be active.
    #[error("Firewall state unknown: the new rules MAY BE ACTIVE. {0}")]
    StateUnknown(String),

    /// Any other failure (script exit 1, I/O errors, the elevation tool's own
    /// errors); nothing was changed
    #[error("Apply failed: {0}")]
    Failed(String),
}

impl ApplyError {
    /// True when the new rules may be live despite the error.
    pub fn rules_may_be_active(&self) -> bool {
        matches!(self, Self::StateUnknown(_))
    }
}

/// What the watcher did, as reported in its root-owned status file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardOutcome {
    /// The confirm token was seen in time: the new rules stay
    Confirmed,
    /// The previous `inet drfw` table was restored (or removed, if there was none)
    Reverted,
    /// Restoring the previous table failed, so the `inet drfw` table was
    /// deleted instead: DRFW is no longer filtering anything
    Removed(String),
    /// The revert failed: the new rules are STILL ACTIVE
    RevertFailed(String),
    /// A newer apply replaced this guard before it finished
    Superseded,
}

impl GuardOutcome {
    /// Parses the first line of a status file.
    fn parse(status: &str) -> Self {
        let line = status.lines().next().unwrap_or_default().trim();
        if let Some(err) = line.strip_prefix("revert-failed:") {
            return Self::RevertFailed(err.trim().to_string());
        }
        if let Some(err) = line.strip_prefix("removed:") {
            return Self::Removed(err.trim().to_string());
        }
        match line {
            "confirmed" => Self::Confirmed,
            "reverted" => Self::Reverted,
            "superseded" => Self::Superseded,
            other => Self::RevertFailed(format!("unrecognized guard status: {other:?}")),
        }
    }
}

/// Why the outcome of a guard could not be determined.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuardError {
    /// Creating the confirm/revert token failed
    #[error("Cannot signal the revert guard: {0}")]
    Token(String),
    /// The watcher did not report in time; the firewall state is unknown
    #[error(
        "The revert guard did not report an outcome within {0} seconds; the firewall state is unknown"
    )]
    NoOutcome(u64),
}

/// Handle to a running revert guard, returned by [`apply_guarded`].
///
/// Two handles are equal when they name the same guard (same nonce,
/// directories and deadline).
#[derive(Debug, Clone)]
pub struct GuardHandle {
    nonce: String,
    confirm_dir: PathBuf,
    state_dir: PathBuf,
    timeout: Duration,
    deadline: Instant,
    /// What was applied (exactly the bytes nft read), written to
    /// `record_dir` once the guard reports a confirmation
    record: Arc<ConfirmedRecord>,
    /// Where to record it: DRFW's state directory when the apply started
    /// (`None`: do not record)
    record_dir: Option<PathBuf>,
}

impl PartialEq for GuardHandle {
    fn eq(&self, other: &Self) -> bool {
        self.nonce == other.nonce
            && self.confirm_dir == other.confirm_dir
            && self.state_dir == other.state_dir
            && self.timeout == other.timeout
            && self.deadline == other.deadline
            && self.record_dir == other.record_dir
            && Arc::ptr_eq(&self.record, &other.record)
    }
}

impl Eq for GuardHandle {}

impl GuardHandle {
    /// A handle for unit tests: nonce `0123…cdef`, tokens in `dir/confirm`,
    /// status in `dir/state`, deadline `timeout` from now.
    #[cfg(test)]
    pub(crate) fn new_for_testing(dir: &Path, timeout: Duration) -> Self {
        Self {
            nonce: "0123456789abcdef0123456789abcdef".to_string(),
            confirm_dir: dir.join("confirm"),
            state_dir: dir.join("state"),
            timeout,
            deadline: Instant::now() + timeout,
            record: Arc::new(
                ConfirmedRecord::new(
                    &serde_json::json!({}),
                    &FirewallRuleset::new(),
                    RecordKind::Confirmed,
                )
                .expect("serializable"),
            ),
            record_dir: None,
        }
    }

    /// The configured revert timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// When the watcher reverts, measured on the monotonic clock. Taken when
    /// the apply returned; the watcher restarts its own countdown when it
    /// notices that the guard was armed (just before the apply returned, and
    /// it polls once per second), so its deadline is at most milliseconds
    /// earlier than this one, and up to a second later. The UI must still
    /// wait for [`Self::wait_outcome`] for the actual outcome.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Time left until [`Self::deadline`] (zero once it passed).
    pub fn remaining(&self, now: Instant) -> Duration {
        self.deadline.saturating_duration_since(now)
    }

    /// Whole seconds left, rounded up (so the display reads N … 1, then 0).
    pub fn remaining_secs(&self, now: Instant) -> u64 {
        ceil_secs(self.remaining(now))
    }

    /// Tells the watcher to keep the new rules. Needs no privileges.
    ///
    /// # Errors
    ///
    /// Returns [`GuardError::Token`] if the token file cannot be created.
    pub fn confirm(&self) -> Result<(), GuardError> {
        create_token(&self.token_path("drfw-confirm-"))
    }

    /// Tells the watcher to revert now. Needs no privileges.
    ///
    /// # Errors
    ///
    /// Returns [`GuardError::Token`] if the token file cannot be created.
    pub fn revert_now(&self) -> Result<(), GuardError> {
        create_token(&self.token_path("drfw-revert-"))
    }

    /// Returns the watcher's verdict if it has written one.
    pub fn read_outcome(&self) -> Option<GuardOutcome> {
        let path = self.state_dir.join(format!("status-{}", self.nonce));
        std::fs::read_to_string(path)
            .ok()
            .map(|s| GuardOutcome::parse(&s))
    }

    /// Waits until the watcher reports an outcome, at most `max_wait`.
    ///
    /// Removes this guard's tokens once an outcome is known. A confirmed
    /// ruleset is recorded as the last one applied and kept (see
    /// [`crate::core::confirmed`]).
    ///
    /// # Errors
    ///
    /// Returns [`GuardError::NoOutcome`] if no status appears in time.
    pub async fn wait_outcome(&self, max_wait: Duration) -> Result<GuardOutcome, GuardError> {
        let give_up = Instant::now() + max_wait;
        loop {
            if let Some(outcome) = self.read_outcome() {
                self.remove_tokens();
                info!("Revert guard {} finished: {outcome:?}", self.nonce);
                if outcome == GuardOutcome::Confirmed
                    && let Some(dir) = &self.record_dir
                {
                    self.record.save_in(dir).await;
                }
                return Ok(outcome);
            }
            if Instant::now() >= give_up {
                warn!("Revert guard {} did not report an outcome", self.nonce);
                return Err(GuardError::NoOutcome(ceil_secs(max_wait)));
            }
            tokio::time::sleep(OUTCOME_POLL_INTERVAL).await;
        }
    }

    /// Waits for the watcher after the countdown ran out (deadline + grace).
    ///
    /// # Errors
    ///
    /// Returns [`GuardError::NoOutcome`] if the watcher never reports.
    pub async fn wait_for_timeout_outcome(&self) -> Result<GuardOutcome, GuardError> {
        let wait = self.remaining(Instant::now()) + OUTCOME_GRACE;
        self.wait_outcome(wait).await
    }

    fn token_path(&self, prefix: &str) -> PathBuf {
        self.confirm_dir.join(format!("{prefix}{}", self.nonce))
    }

    fn remove_tokens(&self) {
        for prefix in ["drfw-confirm-", "drfw-revert-"] {
            let _ = std::fs::remove_file(self.token_path(prefix));
        }
    }
}

/// Rounds a duration up to whole seconds.
fn ceil_secs(d: Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0)
}

/// Creates an empty token file (0600, never following an existing symlink).
fn create_token(path: &Path) -> Result<(), GuardError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    cfg_select! {
        unix => {
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        }
        _ => {}
    }
    match options.open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(GuardError::Token(format!("{}: {e}", path.display()))),
    }
}

/// True if the apply script accepts `path` as a path argument
/// ([`crate::distro::is_script_path`]: absolute, `[A-Za-z0-9/._@+-]`, no `..`
/// component): they are also passed through `systemd-run`.
fn is_script_safe_path(path: &Path) -> bool {
    path.to_str().is_some_and(crate::distro::is_script_path)
}

/// Why `dir` cannot hold confirm/revert tokens, or `None` if it can: it
/// must be a real directory (not a symlink) owned by `uid` with no access for
/// group or others (mode 0700 or stricter), and its path must pass
/// [`is_script_safe_path`]. Otherwise another user could plant or remove
/// tokens.
fn confirm_dir_problem(dir: &Path, uid: u32) -> Option<String> {
    if !is_script_safe_path(dir) {
        return Some(format!(
            "{} contains characters the apply script refuses",
            dir.display()
        ));
    }
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(e) => return Some(format!("{}: {e}", dir.display())),
    };
    if !meta.is_dir() {
        return Some(format!("{} is not a directory", dir.display()));
    }
    cfg_select! {
        unix => {
            let owner = std::os::unix::fs::MetadataExt::uid(&meta);
            let mode = std::os::unix::fs::MetadataExt::mode(&meta);
            if owner != uid {
                return Some(format!(
                    "{} is owned by uid {owner}, not by you (uid {uid})",
                    dir.display()
                ));
            }
            if mode & 0o077 != 0 {
                return Some(format!(
                    "{} is accessible to other users (mode {:o}; needs 0700)",
                    dir.display(),
                    mode & 0o777
                ));
            }
        }
        _ => {
            let _ = uid;
        }
    }
    None
}

/// Directory for confirm/revert tokens: `$XDG_RUNTIME_DIR` (per-user tmpfs,
/// mode 0700), else DRFW's state directory, whichever is owned by `uid` and
/// closed to everyone else (see [`confirm_dir_problem`]).
///
/// # Errors
///
/// [`ApplyError::Failed`] (before anything is elevated) if neither qualifies.
fn confirm_dir(uid: u32) -> Result<PathBuf, ApplyError> {
    let mut problems = Vec::with_capacity(2);
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        match confirm_dir_problem(&dir, uid) {
            None => return Ok(dir),
            Some(problem) => {
                warn!("Not using XDG_RUNTIME_DIR for the revert guard: {problem}");
                problems.push(format!("XDG_RUNTIME_DIR: {problem}"));
            }
        }
    }
    crate::utils::ensure_dirs().map_err(|e| ApplyError::Failed(e.to_string()))?;
    if let Some(dir) = crate::utils::get_state_dir() {
        match confirm_dir_problem(&dir, uid) {
            None => return Ok(dir),
            Some(problem) => problems.push(format!("state directory: {problem}")),
        }
    }
    Err(ApplyError::Failed(format!(
        "no safe directory for the confirmation token ({})",
        if problems.is_empty() {
            "set XDG_RUNTIME_DIR".to_string()
        } else {
            problems.join("; ")
        }
    )))
}

/// A fresh random 128-bit nonce as 32 lowercase hex digits.
fn new_nonce() -> Result<String, ApplyError> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| ApplyError::Failed(format!("cannot read /dev/urandom: {e}")))?;
    Ok(bytes.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    }))
}

/// Maps the apply script's exit status to a result.
///
/// `started`: the script printed its start marker, i.e. authentication
/// succeeded and the script ran as root. Without it nothing was changed,
/// whatever the status (the elevation tool failed, or was killed before the
/// script ran). With it, a status the script never uses (a signal, a shell
/// error) means the script stopped at an unknown step: the state is unknown.
fn classify_apply_exit(code: Option<i32>, stderr: &str, started: bool) -> Result<(), ApplyError> {
    if code == Some(0) {
        return Ok(());
    }
    if let Some(auth) = crate::elevation::auth_failure_from_exit(code, stderr) {
        return Err(ApplyError::Auth(auth));
    }
    let message = stderr
        .lines()
        .map(|line| line.trim().trim_start_matches("drfw: "))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    let message = if message.is_empty() {
        code.map_or_else(
            || "terminated by a signal".to_string(),
            |c| format!("exit code {c}"),
        )
    } else {
        message
    };
    if !started {
        return Err(ApplyError::Failed(message));
    }
    Err(match code {
        Some(EXIT_FAILED) => ApplyError::Failed(message),
        Some(EXIT_REJECTED) => ApplyError::Rejected(message),
        Some(EXIT_GUARD_NOT_STARTED) => ApplyError::GuardNotStarted(message),
        Some(EXIT_GUARD_NOT_ARMED) => ApplyError::StateUnknown(message),
        _ => ApplyError::StateUnknown(format!(
            "The apply script was interrupted ({message}). If the rules were applied with \
             auto-revert, they revert on their own when the countdown ends."
        )),
    })
}

/// A revert guard that has been armed but has not finished yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingGuard {
    /// When the guarded apply armed it (modification time of the `active` file)
    pub armed_at: Option<std::time::SystemTime>,
    /// How the watcher was started (`systemd` or `setsid`)
    pub launcher: String,
    /// Whether its watcher still runs
    pub watcher: WatcherState,
}

/// Whether the watcher of a [`PendingGuard`] still runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatcherState {
    /// It runs: the rules revert at the deadline unless they are confirmed
    Running,
    /// It ended without an outcome (killed with `SIGKILL`, crashed): the
    /// rules stay as they are and will not revert by themselves
    Gone,
    /// It could not be checked: `/proc` hides other users' processes
    /// (`hidepid`), no systemd cgroup hierarchy is mounted, or `active` was
    /// written by an older DRFW (no pid)
    Unknown,
}

/// The cgroup file system, where a systemd unit's processes are listed
/// (world-readable).
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Looks for an unfinished revert guard in `state_dir` (normally
/// [`crate::elevation::GUARD_STATE_DIR`]) and checks that its watcher still
/// runs. Needs no privileges: the apply script keeps the directory and its
/// `active`/`status-*` files world-readable, the watcher's process is found
/// in `/proc` ([`crate::core::exposure::proc_root`]) or, for a
/// `drfw-revert-<nonce>` unit, in its cgroup.
///
/// A guard is pending while `active` names a nonce that has no `status-<nonce>`
/// outcome yet (see [`crate::elevation::APPLY_SCRIPT`]).
///
/// # Errors
///
/// Returns `Err` if `active` exists but cannot be read.
pub fn pending_guard(state_dir: &Path) -> std::io::Result<Option<PendingGuard>> {
    pending_guard_in(
        state_dir,
        &crate::core::exposure::proc_root(),
        Path::new(CGROUP_ROOT),
    )
}

/// [`pending_guard`] with `proc_root` read as `/proc` and `cgroup_root` as
/// `/sys/fs/cgroup`.
fn pending_guard_in(
    state_dir: &Path,
    proc_root: &Path,
    cgroup_root: &Path,
) -> std::io::Result<Option<PendingGuard>> {
    let active = state_dir.join("active");
    let content = match std::fs::read_to_string(&active) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut fields = content.split_whitespace();
    let nonce = fields.next().unwrap_or_default();
    let valid_nonce = nonce.len() == 32
        && nonce
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !valid_nonce || state_dir.join(format!("status-{nonce}")).exists() {
        return Ok(None);
    }
    let launcher = fields.next().unwrap_or("unknown");
    let watcher = match launcher {
        "systemd" => unit_state(nonce, cgroup_root),
        "setsid" => process_state(nonce, fields.next(), proc_root),
        _ => WatcherState::Unknown,
    };
    // An outcome written while we looked (the watcher just finished)
    if watcher == WatcherState::Gone && state_dir.join(format!("status-{nonce}")).exists() {
        return Ok(None);
    }
    Ok(Some(PendingGuard {
        armed_at: std::fs::metadata(&active).and_then(|m| m.modified()).ok(),
        launcher: launcher.to_string(),
        watcher,
    }))
}

/// The `drfw-revert-<nonce>` unit still has processes: its cgroup (cgroup
/// v2, or v1's `systemd` hierarchy) lists some. A unit started with
/// `--collect` loses its cgroup when its process ends.
fn unit_state(nonce: &str, cgroup_root: &Path) -> WatcherState {
    let slices = [
        cgroup_root.join("system.slice"),
        cgroup_root.join("systemd/system.slice"),
    ];
    let Some(slice) = slices.iter().find(|dir| dir.is_dir()) else {
        return WatcherState::Unknown;
    };
    let procs = slice
        .join(format!("drfw-revert-{nonce}.service"))
        .join("cgroup.procs");
    match std::fs::read_to_string(procs) {
        Ok(pids) if pids.split_whitespace().next().is_some() => WatcherState::Running,
        Ok(_) => WatcherState::Gone,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => WatcherState::Gone,
        Err(_) => WatcherState::Unknown,
    }
}

/// The `setsid` watcher `pid` still runs: `/proc/<pid>/cmdline` names its
/// script (`watcher-<nonce>.sh`; another program means the pid was reused).
fn process_state(nonce: &str, pid: Option<&str>, proc_root: &Path) -> WatcherState {
    let Some(pid) = pid.filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) else {
        return WatcherState::Unknown;
    };
    // With `hidepid`, other users' processes (init's too) are invisible
    if !proc_root.join("1").exists() {
        return WatcherState::Unknown;
    }
    let script = format!("watcher-{nonce}.sh");
    match std::fs::read(proc_root.join(pid).join("cmdline")) {
        Ok(cmdline) if cmdline.is_empty() => WatcherState::Gone, // a zombie
        Ok(cmdline) => {
            let names_script = cmdline
                .split(|&b| b == 0)
                .any(|arg| arg.ends_with(script.as_bytes()));
            if names_script {
                WatcherState::Running
            } else {
                WatcherState::Gone
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => WatcherState::Gone,
        Err(_) => WatcherState::Unknown,
    }
}

/// Applies `json` (generated from `ruleset`) with one elevation and, if
/// `timeout_secs > 0`, arms the root-side revert guard.
///
/// Returns `Ok(None)` for an unguarded apply (`timeout_secs == 0`), otherwise
/// the handle used to confirm, revert or wait for the outcome. Dropping the
/// handle does not stop the guard: without a confirmation the rules revert.
///
/// A successful unguarded apply is recorded at once as the last ruleset
/// applied and kept ([`RecordKind::Unguarded`]); a guarded one when it is
/// confirmed ([`GuardHandle::wait_outcome`]). See [`crate::core::confirmed`].
///
/// Authentication may take up to [`APPLY_TIMEOUT`]; once the script reports
/// that it started (as root), it gets another [`SCRIPT_TIMEOUT`].
///
/// # Errors
///
/// - [`ApplyError::Auth`]: elevation unavailable, cancelled, refused or timed
///   out before the script started (nothing changed)
/// - [`ApplyError::Rejected`]: nft rejected the ruleset (nothing changed)
/// - [`ApplyError::GuardNotStarted`]: the watcher could not be started
///   (nothing changed)
/// - [`ApplyError::StateUnknown`]: the script started but was interrupted,
///   exited unexpectedly or did not finish in time, or could not arm the
///   guard: the new rules may be active
/// - [`ApplyError::Failed`]: anything else; nothing was changed
pub async fn apply_guarded(
    json: &serde_json::Value,
    timeout_secs: u64,
    ruleset: &FirewallRuleset,
) -> Result<Option<GuardHandle>, ApplyError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let timeout_secs = timeout_secs.min(MAX_GUARD_TIMEOUT_SECS);
    let kind = if timeout_secs == 0 {
        RecordKind::Unguarded
    } else {
        RecordKind::Confirmed
    };
    // The record holds exactly the bytes nft reads
    let record = Arc::new(
        ConfirmedRecord::new(json, ruleset, kind).map_err(|e| ApplyError::Failed(e.to_string()))?,
    );
    let nonce = new_nonce()?;
    let uid = nix::unistd::getuid().as_raw();
    let confirm_dir = confirm_dir(uid)?;
    let confirm_dir_str = confirm_dir.to_string_lossy().into_owned();

    let (mut command, state_dir) = crate::elevation::create_elevated_apply_command(
        timeout_secs,
        &nonce,
        &confirm_dir_str,
        uid,
    )
    .map_err(|e| ApplyError::Auth(AuthError::Unavailable(e.to_string())))?;

    info!("Applying ruleset (revert guard: {timeout_secs}s)");
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| ApplyError::Failed(format!("cannot start the apply script: {e}")))?;

    // stdin, stdout and stderr are served concurrently: the payload may not
    // fit into the pipe before nft reads it, and the start marker must be
    // seen while the script runs.
    let stdin = child.stdin.take();
    let stdin_payload = Arc::clone(record.nftables_text());
    let stdin_task = tokio::spawn(async move {
        if let Some(mut stdin) = stdin {
            // A script that exits before reading (failed authentication,
            // rejected arguments) closes the pipe; its exit status says why
            if let Err(e) = stdin.write_all(stdin_payload.as_bytes()).await {
                tracing::debug!("apply script stdin: {e}");
            }
            // Dropping stdin closes the pipe so nft sees EOF
        }
    });
    let (started_tx, mut started_rx) = tokio::sync::oneshot::channel();
    let stdout = child.stdout.take();
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::with_capacity(256);
        let mut started_tx = Some(started_tx);
        if let Some(mut stdout) = stdout {
            let mut chunk = [0u8; 256];
            while let Ok(n) = stdout.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if started_tx.is_some() && contains_started_marker(&buf) {
                    let _ = started_tx.take().map(|tx| tx.send(()));
                }
            }
        }
        buf
    });
    let stderr = child.stderr.take();
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut stderr) = stderr {
            let _ = stderr.read_to_end(&mut buf).await;
        }
        buf
    });

    let status = {
        let wait = child.wait();
        tokio::pin!(wait);
        // Authentication: until the script starts (or the tool gives up)
        let first = tokio::time::timeout(APPLY_TIMEOUT, async {
            tokio::select! {
                status = &mut wait => Some(status),
                Ok(()) = &mut started_rx => None,
            }
        })
        .await;
        match first {
            Ok(Some(status)) => status,
            Ok(None) => {
                // Authenticated: the script runs as root and cannot be killed
                // from here, so running out of time leaves the state unknown
                let Ok(status) = tokio::time::timeout(SCRIPT_TIMEOUT, &mut wait).await else {
                    stdin_task.abort();
                    warn!("The apply script did not finish in time");
                    return Err(ApplyError::StateUnknown(format!(
                        "The apply script (running as root) did not finish within {} seconds. \
                         If the rules were applied with auto-revert, they revert on their own \
                         when the countdown ends.",
                        SCRIPT_TIMEOUT.as_secs()
                    )));
                };
                status
            }
            Err(_) => {
                stdin_task.abort();
                return Err(ApplyError::Auth(AuthError::TimedOut(
                    APPLY_TIMEOUT.as_secs(),
                )));
            }
        }
    }
    .map_err(|e| ApplyError::Failed(format!("apply script I/O: {e}")))?;

    let _ = stdin_task.await;
    let stdout = stdout_task.await.unwrap_or_default();
    let stderr = stderr_task.await.unwrap_or_default();
    let started = contains_started_marker(&stdout);
    let stderr = String::from_utf8_lossy(&stderr);
    classify_apply_exit(status.code(), &stderr, started)?;
    info!(
        "Apply succeeded: {}",
        String::from_utf8_lossy(&stdout).trim()
    );

    let record_dir = crate::utils::get_state_dir();
    if timeout_secs == 0 {
        // No safety net by choice: these rules are kept as of now
        if let Some(dir) = &record_dir {
            record.save_in(dir).await;
        }
        return Ok(None);
    }
    let timeout = Duration::from_secs(timeout_secs);
    Ok(Some(GuardHandle {
        nonce,
        confirm_dir,
        state_dir,
        timeout,
        deadline: Instant::now() + timeout,
        record,
        record_dir,
    }))
}

/// True if the apply script's stdout so far contains its start marker line.
fn contains_started_marker(stdout: &[u8]) -> bool {
    String::from_utf8_lossy(stdout)
        .lines()
        .any(|line| line.trim() == STARTED_MARKER)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle_in(dir: &Path, timeout: Duration) -> GuardHandle {
        GuardHandle::new_for_testing(dir, timeout)
    }

    #[test]
    fn test_outcome_parse() {
        assert_eq!(GuardOutcome::parse("confirmed\n"), GuardOutcome::Confirmed);
        assert_eq!(GuardOutcome::parse("reverted\n"), GuardOutcome::Reverted);
        assert_eq!(GuardOutcome::parse("superseded"), GuardOutcome::Superseded);
        assert_eq!(
            GuardOutcome::parse("revert-failed: Error: boom \n"),
            GuardOutcome::RevertFailed("Error: boom".to_string())
        );
        assert_eq!(
            GuardOutcome::parse("removed: bad file"),
            GuardOutcome::Removed("bad file".to_string())
        );
        // Anything unexpected must never be read as "reverted"
        assert!(matches!(
            GuardOutcome::parse("garbage"),
            GuardOutcome::RevertFailed(_)
        ));
    }

    #[test]
    fn test_pending_guard() {
        let dir = tempfile::tempdir().unwrap();
        let nonce = "0123456789abcdef0123456789abcdef";
        // No active file: nothing pending
        assert_eq!(pending_guard(dir.path()).unwrap(), None);

        std::fs::write(dir.path().join("active"), format!("{nonce} systemd -\n")).unwrap();
        let pending = pending_guard(dir.path()).unwrap().expect("pending");
        assert_eq!(pending.launcher, "systemd");
        assert!(pending.armed_at.is_some());

        // An outcome for that nonce means the guard has finished
        std::fs::write(dir.path().join(format!("status-{nonce}")), "confirmed\n").unwrap();
        assert_eq!(pending_guard(dir.path()).unwrap(), None);

        // A malformed active file is never reported as pending
        std::fs::write(dir.path().join("active"), "../../etc/passwd setsid\n").unwrap();
        assert_eq!(pending_guard(dir.path()).unwrap(), None);
    }

    /// The watcher's liveness: a `systemd` unit by its cgroup, a `setsid`
    /// watcher by its pid and command line.
    #[test]
    fn test_pending_guard_checks_the_watcher() {
        let dir = tempfile::tempdir().unwrap();
        let (state, proc, cgroup) = (
            dir.path().join("state"),
            dir.path().join("proc"),
            dir.path().join("cgroup"),
        );
        std::fs::create_dir_all(&state).unwrap();
        let nonce = "0123456789abcdef0123456789abcdef";
        let check = |active: &str| {
            std::fs::write(state.join("active"), active).unwrap();
            pending_guard_in(&state, &proc, &cgroup)
                .unwrap()
                .expect("pending")
                .watcher
        };
        let write = |path: PathBuf, contents: &[u8]| {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        };

        // systemd: no cgroup hierarchy, then the unit's cgroup
        let systemd = format!("{nonce} systemd -\n");
        assert_eq!(check(&systemd), WatcherState::Unknown);
        std::fs::create_dir_all(cgroup.join("system.slice")).unwrap();
        assert_eq!(check(&systemd), WatcherState::Gone, "no unit");
        let procs = cgroup
            .join("system.slice")
            .join(format!("drfw-revert-{nonce}.service/cgroup.procs"));
        write(procs.clone(), b"4242\n");
        assert_eq!(check(&systemd), WatcherState::Running);
        write(procs, b"");
        assert_eq!(check(&systemd), WatcherState::Gone, "no process left");

        // setsid: /proc hidden, the watcher, a reused pid, no process
        let setsid = format!("{nonce} setsid 4242\n");
        assert_eq!(check(&setsid), WatcherState::Unknown, "hidepid");
        write(proc.join("1/cmdline"), b"/sbin/init\0");
        assert_eq!(check(&setsid), WatcherState::Gone);
        let cmdline = format!("/bin/sh\0/run/drfw/watcher-{nonce}.sh\0/run/drfw\0");
        write(proc.join("4242/cmdline"), cmdline.as_bytes());
        assert_eq!(check(&setsid), WatcherState::Running);
        write(proc.join("4242/cmdline"), b"/usr/bin/vim\0");
        assert_eq!(check(&setsid), WatcherState::Gone, "pid reused");
        // An older DRFW recorded no pid
        assert_eq!(check(&format!("{nonce} setsid\n")), WatcherState::Unknown);
        // A finished guard is not pending, whatever its watcher does
        std::fs::write(state.join(format!("status-{nonce}")), "reverted\n").unwrap();
        std::fs::write(state.join("active"), &setsid).unwrap();
        assert_eq!(pending_guard_in(&state, &proc, &cgroup).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn test_classify_apply_exit() {
        let started = |code, stderr| classify_apply_exit(code, stderr, true);
        assert_eq!(started(Some(0), ""), Ok(()));
        assert_eq!(
            started(Some(126), ""),
            Err(ApplyError::Auth(AuthError::Cancelled))
        );
        assert_eq!(
            classify_apply_exit(
                Some(127),
                "Error executing command as another user: No authentication agent found.",
                false
            ),
            Err(ApplyError::Auth(AuthError::NoAgent))
        );
        assert!(matches!(
            classify_apply_exit(Some(127), "Not authorized", false),
            Err(ApplyError::Auth(AuthError::Failed(_)))
        ));
        assert_eq!(
            started(Some(3), "drfw: nft rejected the ruleset: Error: x\n"),
            Err(ApplyError::Rejected(
                "nft rejected the ruleset: Error: x".to_string()
            ))
        );
        let not_started = started(Some(4), "drfw: could not start").unwrap_err();
        assert!(matches!(not_started, ApplyError::GuardNotStarted(_)));
        assert!(!not_started.rules_may_be_active());
        let unarmed = started(Some(5), "drfw: could not be armed").unwrap_err();
        assert!(matches!(unarmed, ApplyError::StateUnknown(_)));
        assert!(unarmed.rules_may_be_active());
        // A message containing "nftables" must not be mistaken for anything special
        assert_eq!(
            started(Some(1), "drfw: cannot list nftables tables"),
            Err(ApplyError::Failed(
                "cannot list nftables tables".to_string()
            ))
        );
        assert_eq!(
            started(Some(1), ""),
            Err(ApplyError::Failed("exit code 1".to_string()))
        );
        // Killed or an unexpected status once the script ran: state unknown
        for code in [None, Some(2), Some(129)] {
            let error = started(code, "").unwrap_err();
            assert!(matches!(error, ApplyError::StateUnknown(_)), "{code:?}");
            assert!(error.rules_may_be_active());
        }
        // The script never started (e.g. sudo's wrong password, exit 1; a
        // killed elevation tool): nothing was changed, whatever the status
        for code in [None, Some(1), Some(2), Some(5)] {
            let error = classify_apply_exit(code, "sudo: 3 incorrect password attempts", false)
                .unwrap_err();
            assert!(matches!(error, ApplyError::Failed(_)), "{code:?}: {error}");
            assert!(!error.rules_may_be_active());
        }
    }

    #[test]
    fn test_started_marker() {
        assert!(contains_started_marker(b"drfw-apply-started\n"));
        assert!(contains_started_marker(
            b"drfw-apply-started\r\nwatcher=none\n"
        ));
        assert!(!contains_started_marker(b"drfw-apply-star"));
        assert!(!contains_started_marker(b""));
    }

    #[cfg(unix)]
    #[test]
    fn test_confirm_dir_must_be_private_and_owned() {
        use std::os::unix::fs::PermissionsExt;
        let uid = nix::unistd::getuid().as_raw();
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(confirm_dir_problem(&private, uid), None);

        // Readable or writable by others: refused
        for mode in [0o755, 0o770, 0o701, 0o777] {
            std::fs::set_permissions(&private, std::fs::Permissions::from_mode(mode)).unwrap();
            let problem = confirm_dir_problem(&private, uid).expect("refused");
            assert!(problem.contains("other users"), "{mode:o}: {problem}");
        }
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Someone else's directory
        let problem = confirm_dir_problem(&private, uid.wrapping_add(1)).expect("refused");
        assert!(problem.contains("owned by"), "{problem}");
        // A symlink to a good directory is not good enough
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&private, &link).unwrap();
        assert!(confirm_dir_problem(&link, uid).is_some());
        // Missing, or a path the script refuses
        assert!(confirm_dir_problem(&dir.path().join("missing"), uid).is_some());
        assert!(confirm_dir_problem(Path::new("relative"), uid).is_some());
    }

    #[test]
    fn test_remaining_secs_rounds_up_and_saturates() {
        let dir = tempfile::tempdir().unwrap();
        let handle = handle_in(dir.path(), Duration::from_secs(15));
        let start = handle
            .deadline()
            .checked_sub(Duration::from_secs(15))
            .unwrap();
        assert_eq!(handle.remaining_secs(start), 15);
        assert_eq!(
            handle.remaining_secs(start + Duration::from_millis(100)),
            15
        );
        assert_eq!(handle.remaining_secs(start + Duration::from_secs(1)), 14);
        assert_eq!(
            handle.remaining_secs(start + Duration::from_millis(14_001)),
            1
        );
        assert_eq!(handle.remaining_secs(handle.deadline()), 0);
        assert_eq!(
            handle.remaining_secs(handle.deadline() + Duration::from_secs(5)),
            0
        );
    }

    #[test]
    fn test_nonce_is_128_bit_hex() {
        let a = new_nonce().unwrap();
        let b = new_nonce().unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
        assert_ne!(a, b);
    }

    #[test]
    fn test_script_safe_path() {
        assert!(is_script_safe_path(Path::new("/run/user/1000")));
        assert!(is_script_safe_path(Path::new(
            "/home/a.b/.local/state/drfw"
        )));
        assert!(!is_script_safe_path(Path::new("relative/dir")));
        assert!(!is_script_safe_path(Path::new("/home/John Doe")));
        assert!(!is_script_safe_path(Path::new("/tmp/$HOME")));
        assert!(!is_script_safe_path(Path::new("/tmp/%n")));
        // The script refuses `..` components (but not names with dots)
        assert!(!is_script_safe_path(Path::new("/run/user/../0")));
        assert!(is_script_safe_path(Path::new("/run/user/..1000")));
    }

    #[tokio::test]
    async fn test_tokens_and_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let handle = handle_in(dir.path(), Duration::from_secs(5));
        std::fs::create_dir_all(dir.path().join("confirm")).unwrap();
        std::fs::create_dir_all(dir.path().join("state")).unwrap();

        // Tokens are plain files named after the nonce; creating one twice is fine
        handle.confirm().unwrap();
        handle.confirm().unwrap();
        handle.revert_now().unwrap();
        let confirm_token = dir
            .path()
            .join("confirm/drfw-confirm-0123456789abcdef0123456789abcdef");
        assert!(confirm_token.is_file());

        // No status yet: wait gives up
        assert_eq!(
            handle.wait_outcome(Duration::from_millis(250)).await,
            Err(GuardError::NoOutcome(1))
        );

        // The watcher's verdict is read and the tokens are cleaned up
        std::fs::write(
            dir.path()
                .join("state/status-0123456789abcdef0123456789abcdef"),
            "confirmed\n",
        )
        .unwrap();
        assert_eq!(
            handle.wait_outcome(Duration::from_secs(1)).await,
            Ok(GuardOutcome::Confirmed)
        );
        assert!(!confirm_token.exists());
    }

    /// A confirmed outcome records the applied JSON and ruleset; other
    /// outcomes do not.
    #[tokio::test]
    async fn test_confirmed_ruleset_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("state")).unwrap();
        let record_dir = dir.path().join("record");
        std::fs::create_dir_all(&record_dir).unwrap();
        let ruleset = crate::core::test_helpers::create_test_ruleset();
        let json = ruleset.to_nftables_json();
        let mut handle = handle_in(dir.path(), Duration::from_secs(5));
        handle.record =
            Arc::new(ConfirmedRecord::new(&json, &ruleset, RecordKind::Confirmed).unwrap());
        handle.record_dir = Some(record_dir.clone());
        let status = dir
            .path()
            .join("state/status-0123456789abcdef0123456789abcdef");

        std::fs::write(&status, "reverted\n").unwrap();
        let _ = handle.wait_outcome(Duration::from_secs(1)).await;
        assert!(ConfirmedRecord::load_from(&record_dir).await.is_none());

        std::fs::write(&status, "confirmed\n").unwrap();
        let _ = handle.wait_outcome(Duration::from_secs(1)).await;
        let record = ConfirmedRecord::load_from(&record_dir)
            .await
            .expect("recorded");
        assert!(record.matches(&json));
        assert!(!record.matches(&serde_json::json!({})));
        assert_eq!(record.kind(), RecordKind::Confirmed);
        assert_eq!(
            record.ruleset().map(|r| r.rules[0].id),
            Some(ruleset.rules[0].id)
        );
    }

    #[test]
    fn test_token_in_missing_dir_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let handle = handle_in(&dir.path().join("missing"), Duration::from_secs(5));
        assert!(matches!(handle.confirm(), Err(GuardError::Token(_))));
    }
}
