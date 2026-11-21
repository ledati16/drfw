//! Apply with a root-side revert guard (the dead-man switch)
//!
//! [`apply_guarded`] runs the fixed [`APPLY_SCRIPT`] with a single elevation.
//! As root, the script saves the current `inet drfw` table as a complete,
//! atomic revert batch, applies the new ruleset and starts a detached watcher
//! ([`WATCHER_SCRIPT`]) that restores the saved table when the timeout expires
//! unless it is told otherwise.
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
//! Any process running as the same user can create the confirm token. That is
//! not an escalation: it can only keep rules that the user just authenticated
//! to apply. Every apply uses a fresh random 128-bit nonce, so stale tokens
//! never match a later guard. The watcher never writes to or follows anything
//! in the user's directory (see [`WATCHER_SCRIPT`]).
//!
//! [`APPLY_SCRIPT`]: crate::elevation::APPLY_SCRIPT
//! [`WATCHER_SCRIPT`]: crate::elevation::WATCHER_SCRIPT

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::elevation::AuthError;

/// Upper bound for the whole elevated apply, including the time the user
/// spends in the authentication dialog. The script itself takes well under a
/// second once authenticated.
pub const APPLY_TIMEOUT: Duration = Duration::from_secs(120);

/// Longest revert timeout the apply script accepts.
pub const MAX_GUARD_TIMEOUT_SECS: u64 = 3600;

/// How long to wait for the watcher's verdict after a confirm/revert request
/// or after the countdown ended. The watcher polls once per second.
pub const OUTCOME_GRACE: Duration = Duration::from_secs(10);

/// How often [`GuardHandle::wait_outcome`] checks the status file.
const OUTCOME_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Exit codes of [`crate::elevation::APPLY_SCRIPT`].
const EXIT_REJECTED: i32 = 3;
const EXIT_GUARD_FAILED_REVERTED: i32 = 4;
const EXIT_GUARD_FAILED_RULES_ACTIVE: i32 = 5;

/// Why a guarded apply failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplyError {
    /// Elevation failed or was cancelled; nothing was changed
    #[error("{0}")]
    Auth(#[from] AuthError),

    /// nft rejected the ruleset (script exit 3); nothing was changed
    #[error("nftables rejected the ruleset; nothing was changed: {0}")]
    Rejected(String),

    /// The rules were applied but the watcher could not be started, so the
    /// script rolled them back (script exit 4)
    #[error("The revert guard could not be started, so the change was rolled back: {0}")]
    GuardFailedRolledBack(String),

    /// The watcher could not be started and the rollback failed too: the new
    /// rules are still active (script exit 5)
    #[error(
        "The new rules are STILL ACTIVE: the revert guard could not be started and the rollback failed: {0}"
    )]
    GuardFailedRulesActive(String),

    /// Any other failure (script exit 1, I/O errors); nothing was changed
    #[error("Apply failed: {0}")]
    Failed(String),
}

impl ApplyError {
    /// True when the new rules may be live despite the error.
    pub fn rules_may_be_active(&self) -> bool {
        matches!(self, Self::GuardFailedRulesActive(_))
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardHandle {
    nonce: String,
    confirm_dir: PathBuf,
    state_dir: PathBuf,
    timeout: Duration,
    deadline: Instant,
}

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
        }
    }

    /// The configured revert timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// When the watcher reverts, measured on the monotonic clock. Taken when
    /// the apply returned, so it is never earlier than the watcher's own
    /// deadline: the UI must still wait for [`Self::wait_outcome`].
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
    /// Removes this guard's tokens once an outcome is known.
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

/// True if `path` only uses characters the apply script accepts in paths
/// (absolute, `[A-Za-z0-9/._@+-]`): they are also passed through `systemd-run`.
fn is_script_safe_path(path: &Path) -> bool {
    let Some(s) = path.to_str() else {
        return false;
    };
    s.starts_with('/')
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'@' | b'+' | b'-')
        })
}

/// Directory for confirm/revert tokens: `$XDG_RUNTIME_DIR` (per-user tmpfs,
/// mode 0700), else DRFW's state directory.
fn confirm_dir() -> Result<PathBuf, ApplyError> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|dir| dir.is_dir() && is_script_safe_path(dir));
    if let Some(dir) = runtime {
        return Ok(dir);
    }
    crate::utils::ensure_dirs().map_err(|e| ApplyError::Failed(e.to_string()))?;
    crate::utils::get_state_dir()
        .filter(|dir| is_script_safe_path(dir))
        .ok_or_else(|| {
            ApplyError::Failed(
                "no usable directory for the confirmation token (set XDG_RUNTIME_DIR)".to_string(),
            )
        })
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
fn classify_apply_exit(code: Option<i32>, stderr: &str) -> Result<(), ApplyError> {
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
    Err(match code {
        Some(EXIT_REJECTED) => ApplyError::Rejected(message),
        Some(EXIT_GUARD_FAILED_REVERTED) => ApplyError::GuardFailedRolledBack(message),
        Some(EXIT_GUARD_FAILED_RULES_ACTIVE) => ApplyError::GuardFailedRulesActive(message),
        _ => ApplyError::Failed(message),
    })
}

/// A revert guard that has been armed but has not finished yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingGuard {
    /// When the guarded apply armed it (modification time of the `active` file)
    pub armed_at: Option<std::time::SystemTime>,
    /// How the watcher was started (`systemd` or `setsid`)
    pub launcher: String,
}

/// Looks for an unfinished revert guard in `state_dir` (normally
/// [`crate::elevation::GUARD_STATE_DIR`]). Needs no privileges: the apply
/// script keeps the directory and its `active`/`status-*` files
/// world-readable.
///
/// A guard is pending while `active` names a nonce that has no `status-<nonce>`
/// outcome yet (see [`crate::elevation::APPLY_SCRIPT`]).
///
/// # Errors
///
/// Returns `Err` if `active` exists but cannot be read.
pub fn pending_guard(state_dir: &Path) -> std::io::Result<Option<PendingGuard>> {
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
    Ok(Some(PendingGuard {
        armed_at: std::fs::metadata(&active).and_then(|m| m.modified()).ok(),
        launcher: fields.next().unwrap_or("unknown").to_string(),
    }))
}

/// Applies `json` with one elevation and, if `timeout_secs > 0`, arms the
/// root-side revert guard.
///
/// Returns `Ok(None)` for an unguarded apply (`timeout_secs == 0`), otherwise
/// the handle used to confirm, revert or wait for the outcome. Dropping the
/// handle does not stop the guard: without a confirmation the rules revert.
///
/// # Errors
///
/// - [`ApplyError::Auth`]: elevation unavailable, cancelled, refused or timed out
/// - [`ApplyError::Rejected`]: nft rejected the ruleset (nothing changed)
/// - [`ApplyError::GuardFailedRolledBack`] / [`ApplyError::GuardFailedRulesActive`]:
///   the watcher could not be started (see their docs)
/// - [`ApplyError::Failed`]: anything else; nothing was changed
pub async fn apply_guarded(
    json: &serde_json::Value,
    timeout_secs: u64,
) -> Result<Option<GuardHandle>, ApplyError> {
    use tokio::io::AsyncWriteExt;

    let timeout_secs = timeout_secs.min(MAX_GUARD_TIMEOUT_SECS);
    let payload = serde_json::to_vec(json).map_err(|e| ApplyError::Failed(e.to_string()))?;
    let nonce = new_nonce()?;
    let confirm_dir = confirm_dir()?;
    let confirm_dir_str = confirm_dir.to_string_lossy().into_owned();

    let (mut command, state_dir) =
        crate::elevation::create_elevated_apply_command(timeout_secs, &nonce, &confirm_dir_str)
            .map_err(|e| ApplyError::Auth(AuthError::Unavailable(e.to_string())))?;

    info!("Applying ruleset (revert guard: {timeout_secs}s)");
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| ApplyError::Failed(format!("cannot start the apply script: {e}")))?;

    let work = async {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&payload).await?;
            // Dropping stdin closes the pipe so nft sees EOF
        }
        child.wait_with_output().await
    };
    let output = match tokio::time::timeout(APPLY_TIMEOUT, work).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => return Err(ApplyError::Failed(format!("apply script I/O: {e}"))),
        Err(_) => {
            return Err(ApplyError::Auth(AuthError::TimedOut(
                APPLY_TIMEOUT.as_secs(),
            )));
        }
    };

    let stderr = String::from_utf8_lossy(&output.stderr);
    classify_apply_exit(output.status.code(), &stderr)?;
    info!(
        "Apply succeeded: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );

    if timeout_secs == 0 {
        return Ok(None);
    }
    let timeout = Duration::from_secs(timeout_secs);
    Ok(Some(GuardHandle {
        nonce,
        confirm_dir,
        state_dir,
        timeout,
        deadline: Instant::now() + timeout,
    }))
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

        std::fs::write(dir.path().join("active"), format!("{nonce} systemd\n")).unwrap();
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

    #[cfg(unix)]
    #[test]
    fn test_classify_apply_exit() {
        assert_eq!(classify_apply_exit(Some(0), ""), Ok(()));
        assert_eq!(
            classify_apply_exit(Some(126), ""),
            Err(ApplyError::Auth(AuthError::Cancelled))
        );
        assert_eq!(
            classify_apply_exit(
                Some(127),
                "Error executing command as another user: No authentication agent found."
            ),
            Err(ApplyError::Auth(AuthError::NoAgent))
        );
        assert!(matches!(
            classify_apply_exit(Some(127), "Not authorized"),
            Err(ApplyError::Auth(AuthError::Failed(_)))
        ));
        assert_eq!(
            classify_apply_exit(Some(3), "drfw: nft rejected the ruleset: Error: x\n"),
            Err(ApplyError::Rejected(
                "nft rejected the ruleset: Error: x".to_string()
            ))
        );
        assert!(matches!(
            classify_apply_exit(Some(4), "drfw: could not start"),
            Err(ApplyError::GuardFailedRolledBack(_))
        ));
        let active = classify_apply_exit(Some(5), "drfw: STILL ACTIVE").unwrap_err();
        assert!(active.rules_may_be_active());
        // A message containing "nftables" must not be mistaken for anything special
        assert_eq!(
            classify_apply_exit(Some(1), "drfw: cannot list nftables tables"),
            Err(ApplyError::Failed(
                "cannot list nftables tables".to_string()
            ))
        );
        assert_eq!(
            classify_apply_exit(Some(1), ""),
            Err(ApplyError::Failed("exit code 1".to_string()))
        );
        assert_eq!(
            classify_apply_exit(None, ""),
            Err(ApplyError::Failed("terminated by a signal".to_string()))
        );
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

    #[test]
    fn test_token_in_missing_dir_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let handle = handle_in(&dir.path().join("missing"), Duration::from_secs(5));
        assert!(matches!(handle.confirm(), Err(GuardError::Token(_))));
    }
}
