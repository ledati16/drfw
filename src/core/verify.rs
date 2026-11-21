//! Verification of rulesets before they are applied
//!
//! [`verify_ruleset`] runs `nft --json --check` on the generated JSON. It first
//! tries **without privileges**, in a private user + network namespace
//! (`unshare -rn`): if the kernel accepts the batch there, it is valid and no
//! authentication prompt is needed. A failure there is only *inconclusive*
//! (e.g. kernel modules cannot be autoloaded from a user namespace, or
//! unprivileged user namespaces are disabled), so it falls back to the elevated
//! check, whose verdict is authoritative.
//!
//! nft's errors for JSON input carry no location. When a check fails,
//! [`locate_errors`] checks the same ruleset in its text form (unprivileged,
//! diagnostics only) and maps each error to the rule that caused it (see
//! [`crate::core::nft_errors`]).

use std::time::Duration;

use tracing::{info, warn};

use crate::core::firewall::FirewallRuleset;
use crate::core::nft_errors::{AnnotatedText, unlocated_issues};
pub use crate::core::nft_errors::{ErrorOrigin, VerifyIssue};
use crate::elevation::AuthError;

/// Timeout for the unprivileged check (no prompt involved; nft is near-instant).
const UNPRIVILEGED_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for the elevated check, including time spent in the
/// authentication dialog.
const ELEVATED_CHECK_TIMEOUT: Duration = Duration::from_secs(120);

/// Arguments for a check-only run of nft reading JSON from stdin.
const CHECK_ARGS: [&str; 4] = ["--json", "--check", "-f", "-"];

/// Arguments for a check-only run of nft reading the text form from stdin
/// (only used to locate errors, see [`locate_errors`]).
const TEXT_CHECK_ARGS: [&str; 3] = ["-c", "-f", "-"];

/// Result of a ruleset verification operation
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub success: bool,
    /// nft's errors when `success` is false (may be empty if nft printed
    /// nothing). Mapped to rules only after [`locate_errors`].
    pub issues: Vec<VerifyIssue>,
}

impl VerifyResult {
    /// Creates a successful verification result
    pub fn success() -> Self {
        Self {
            success: true,
            issues: Vec::new(),
        }
    }

    /// Creates a failed verification result with errors
    pub fn failure(issues: Vec<VerifyIssue>) -> Self {
        Self {
            success: false,
            issues,
        }
    }

    /// Number of distinct rules (user or built-in), chains or header parts
    /// the issues point at; 0 when none could be located.
    pub fn rejected_count(&self) -> usize {
        let mut seen: Vec<&ErrorOrigin> = Vec::new();
        for origin in self.issues.iter().filter_map(|i| i.origin.as_ref()) {
            if !seen.contains(&origin) {
                seen.push(origin);
            }
        }
        seen.len()
    }

    /// All issues on one line, `; `-separated (audit log).
    pub fn summary(&self) -> String {
        self.issues
            .iter()
            .map(|issue| issue.to_string().replace('\n', " "))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Why a ruleset could not be verified at all (as opposed to being invalid,
/// which is a successful verification with [`VerifyResult::success`] false).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// Elevation for the authoritative check failed or was cancelled
    #[error("{0}")]
    Auth(#[from] AuthError),
    /// nft could not be run or its output not read
    #[error("Verification could not run: {0}")]
    Failed(String),
}

/// Runs `command` (already set up with [`CHECK_ARGS`]) with `payload` on stdin.
async fn run_check(
    mut command: tokio::process::Command,
    payload: &[u8],
    timeout: Duration,
) -> Result<Option<std::process::Output>, VerifyError> {
    use tokio::io::AsyncWriteExt;

    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| VerifyError::Failed(format!("cannot start nft: {e}")))?;

    let work = async {
        if let Some(mut stdin) = child.stdin.take() {
            // nft may exit before reading all of its input (e.g. an option
            // error); its exit status and stderr are the verdict, not EPIPE
            if let Err(e) = stdin.write_all(payload).await
                && e.kind() != std::io::ErrorKind::BrokenPipe
            {
                return Err(e);
            }
        }
        child.wait_with_output().await
    };
    match tokio::time::timeout(timeout, work).await {
        Ok(Ok(output)) => Ok(Some(output)),
        Ok(Err(e)) => Err(VerifyError::Failed(format!("nft I/O: {e}"))),
        Err(_) => Ok(None),
    }
}

/// Interprets an authoritative check's output.
fn check_verdict(
    output: &std::process::Output,
    elevated: bool,
) -> Result<VerifyResult, VerifyError> {
    if output.status.success() {
        info!("Ruleset verification passed");
        return Ok(VerifyResult::success());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if elevated
        && let Some(auth) = crate::elevation::auth_failure_from_exit(output.status.code(), &stderr)
    {
        return Err(VerifyError::Auth(auth));
    }
    warn!("Ruleset verification failed: {stderr}");
    Ok(VerifyResult::failure(unlocated_issues(&stderr)))
}

/// Outcome of the check in a private namespace.
enum UnprivilegedCheck {
    /// nft accepted the ruleset: it is valid
    Passed,
    /// nft refused it (its stderr). Usually a real error, but it can also
    /// mean that a kernel module could not be loaded from the namespace.
    Refused(String),
    /// The check could not run (no `unshare`/`nft`, user namespaces
    /// disabled, timeout)
    Unavailable(String),
}

/// Runs `unshare -rn nft <args>` with `payload` on stdin: no privileges, no
/// prompt.
async fn unprivileged_check(args: &[&str], payload: &[u8]) -> UnprivilegedCheck {
    // The packager's nft (`DRFW_NFT_PATH`) if set, else found in sbin/bin
    let nft = crate::distro::unprivileged_nft();
    let mut command = tokio::process::Command::new("unshare");
    command.arg("-rn").arg(nft).args(args);
    match run_check(command, payload, UNPRIVILEGED_CHECK_TIMEOUT).await {
        Ok(Some(output)) if output.status.success() => UnprivilegedCheck::Passed,
        Ok(Some(output)) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            // unshare itself failing (EPERM: user namespaces disabled) is not nft's verdict
            if stderr.starts_with("unshare:") {
                UnprivilegedCheck::Unavailable(stderr)
            } else {
                UnprivilegedCheck::Refused(stderr)
            }
        }
        Ok(None) => UnprivilegedCheck::Unavailable("timed out".to_string()),
        Err(e) => UnprivilegedCheck::Unavailable(e.to_string()),
    }
}

/// Tries the check without privileges in a private namespace.
///
/// Returns `true` only if nft accepted the ruleset there; every other outcome
/// is inconclusive.
async fn unprivileged_check_passes(payload: &[u8]) -> bool {
    match unprivileged_check(&CHECK_ARGS, payload).await {
        UnprivilegedCheck::Passed => true,
        UnprivilegedCheck::Refused(stderr) => {
            info!("Unprivileged check inconclusive, falling back to elevated check: {stderr}");
            false
        }
        UnprivilegedCheck::Unavailable(reason) => {
            info!("Unprivileged check unavailable ({reason}), falling back to elevated check");
            false
        }
    }
}

/// Verifies a ruleset **without privileges and without any prompt**
/// (`drfw check`): `nft --json --check` in a private user + network
/// namespace. With `DRFW_NFT_COMMAND` set (tests), that command is used.
///
/// Unlike [`verify_ruleset`], a refusal is reported as-is
/// ([`VerifyResult::success`] false). It is nearly always a real error, but
/// in rare setups a kernel module that cannot be loaded from the namespace
/// also causes one; only the elevated check is authoritative.
///
/// # Errors
///
/// [`VerifyError::Failed`] if the check cannot run (no `unshare` or `nft`,
/// unprivileged user namespaces disabled, timeout).
pub async fn verify_ruleset_unprivileged(
    json_payload: &serde_json::Value,
) -> Result<VerifyResult, VerifyError> {
    let payload =
        serde_json::to_vec(json_payload).map_err(|e| VerifyError::Failed(e.to_string()))?;

    if let Some(nft) = crate::elevation::test_nft_command() {
        let mut command = tokio::process::Command::new(nft);
        command.args(CHECK_ARGS);
        let Some(output) = run_check(command, &payload, UNPRIVILEGED_CHECK_TIMEOUT).await? else {
            return Err(VerifyError::Failed("nft --check timed out".to_string()));
        };
        return check_verdict(&output, false);
    }

    match unprivileged_check(&CHECK_ARGS, &payload).await {
        UnprivilegedCheck::Passed => Ok(VerifyResult::success()),
        UnprivilegedCheck::Refused(stderr) => Ok(VerifyResult::failure(unlocated_issues(&stderr))),
        UnprivilegedCheck::Unavailable(reason) => Err(VerifyError::Failed(format!(
            "the unprivileged check (unshare -rn nft) is not available: {reason}"
        ))),
    }
}

/// Verifies a ruleset without applying it using `nft --json --check`.
///
/// Tries an unprivileged check in a private namespace first (no prompt); if
/// that does not pass, runs the elevated check, which is authoritative.
/// With `DRFW_NFT_COMMAND` set (tests), only that command is used.
///
/// # Errors
///
/// - [`VerifyError::Auth`] if the elevated check could not authenticate
///   (cancelled, refused, no agent, timed out)
/// - [`VerifyError::Failed`] if nft cannot be run or JSON serialization fails
///
/// An invalid ruleset is **not** an error: it yields `Ok` with
/// [`VerifyResult::success`] false and nft's messages.
pub async fn verify_ruleset(json_payload: serde_json::Value) -> Result<VerifyResult, VerifyError> {
    let payload =
        serde_json::to_vec(&json_payload).map_err(|e| VerifyError::Failed(e.to_string()))?;

    if crate::elevation::test_nft_command().is_none() && unprivileged_check_passes(&payload).await {
        info!("Ruleset verification passed (unprivileged namespace check)");
        return Ok(VerifyResult::success());
    }

    info!("Verifying ruleset via nft --json --check (elevated)");
    let command = crate::elevation::create_elevated_nft_command(&CHECK_ARGS)
        .map_err(|e| VerifyError::Auth(AuthError::Unavailable(e.to_string())))?;
    let elevated = crate::elevation::test_nft_command().is_none();
    let Some(output) = run_check(command, &payload, ELEVATED_CHECK_TIMEOUT).await? else {
        warn!("Elevated nft --check timed out");
        return Err(VerifyError::Auth(AuthError::TimedOut(
            ELEVATED_CHECK_TIMEOUT.as_secs(),
        )));
    };
    check_verdict(&output, elevated)
}

/// Maps a failed check's errors to the rules that caused them.
///
/// nft's errors for JSON input have no location, so this checks `ruleset`'s
/// text form (the same commands, see [`FirewallRuleset::to_nft_text`]) with
/// `unshare -rn nft -c -f -`: no privileges, never a prompt. Each located
/// error is traced back to its rule, chain or the header.
///
/// `result` is returned unchanged when it succeeded, or when the text check
/// cannot help: it is unavailable (no `unshare`, user namespaces disabled),
/// it passes (the JSON failure is then not reproducible as text), or none of
/// its errors could be located. With `DRFW_NFT_COMMAND` set (tests), that
/// command runs the text check.
pub async fn locate_errors(ruleset: &FirewallRuleset, result: VerifyResult) -> VerifyResult {
    if result.success {
        return result;
    }
    let annotated = AnnotatedText::new(ruleset);
    let payload = annotated.text().as_bytes();

    let check = if let Some(nft) = crate::elevation::test_nft_command() {
        let mut command = tokio::process::Command::new(nft);
        command.args(TEXT_CHECK_ARGS);
        match run_check(command, payload, UNPRIVILEGED_CHECK_TIMEOUT).await {
            Ok(Some(output)) if output.status.success() => UnprivilegedCheck::Passed,
            Ok(Some(output)) => {
                UnprivilegedCheck::Refused(String::from_utf8_lossy(&output.stderr).into_owned())
            }
            Ok(None) => UnprivilegedCheck::Unavailable("timed out".to_string()),
            Err(e) => UnprivilegedCheck::Unavailable(e.to_string()),
        }
    } else {
        unprivileged_check(&TEXT_CHECK_ARGS, payload).await
    };

    let stderr = match check {
        UnprivilegedCheck::Refused(stderr) => stderr,
        UnprivilegedCheck::Passed => {
            info!("Text form passes nft -c; showing the JSON check's errors unmapped");
            return result;
        }
        UnprivilegedCheck::Unavailable(reason) => {
            info!("Cannot locate nft errors ({reason}); showing them unmapped");
            return result;
        }
    };
    let issues = annotated.issues(&stderr);
    if issues.iter().any(|issue| issue.origin.is_some()) {
        VerifyResult::failure(issues)
    } else {
        info!("nft -c gave no usable locations; showing the JSON check's errors unmapped");
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn output(code: i32, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_check_verdict_classifies_by_exit_code() {
        assert!(check_verdict(&output(0, ""), true).unwrap().success);
        assert_eq!(
            check_verdict(&output(126, ""), true).unwrap_err(),
            VerifyError::Auth(AuthError::Cancelled)
        );
        assert_eq!(
            check_verdict(&output(127, "No authentication agent found."), true).unwrap_err(),
            VerifyError::Auth(AuthError::NoAgent)
        );
        // nft's own failure (exit 1) is an invalid ruleset, not an error
        let invalid = check_verdict(&output(1, "Error: syntax error\n"), true).unwrap();
        assert!(!invalid.success);
        assert_eq!(invalid.issues, vec![VerifyIssue::unlocated("syntax error")]);
        // Unelevated (test mode): 126/127 are nft's own statuses
        assert!(!check_verdict(&output(126, "x"), false).unwrap().success);
    }

    #[test]
    fn test_verify_result_success() {
        let result = VerifyResult::success();
        assert!(result.success);
        assert_eq!(result.issues, Vec::new());
        assert_eq!(result.rejected_count(), 0);
    }

    #[test]
    fn test_verify_result_failure_counts_and_summary() {
        let rule = |label: &str, id| {
            Some(ErrorOrigin::UserRule {
                id,
                label: label.to_string(),
            })
        };
        let ssh = uuid::Uuid::new_v4();
        let issue = |origin, message: &str| VerifyIssue {
            origin,
            message: message.to_string(),
            source_line: None,
            caret: None,
        };
        let result = VerifyResult::failure(vec![
            issue(rule("ssh", ssh), "first"),
            issue(rule("ssh", ssh), "second\nline"),
            issue(rule("web", uuid::Uuid::new_v4()), "third"),
            VerifyIssue::unlocated("loose"),
        ]);
        assert!(!result.success);
        assert_eq!(result.rejected_count(), 2);
        assert_eq!(
            result.summary(),
            "rule \"ssh\": first; rule \"ssh\": second line; rule \"web\": third; loose"
        );
    }

    /// The mock nft cannot check text: the JSON errors are kept unmapped.
    #[tokio::test]
    async fn test_locate_errors_falls_back_to_raw_errors() {
        crate::core::test_helpers::setup_mock_nft();
        let ruleset = crate::core::test_helpers::create_test_ruleset();
        let failed = VerifyResult::failure(vec![VerifyIssue::unlocated("raw")]);
        let located = locate_errors(&ruleset, failed).await;
        assert!(!located.success);
        assert_eq!(located.issues, vec![VerifyIssue::unlocated("raw")]);
        let ok = locate_errors(&ruleset, VerifyResult::success()).await;
        assert!(ok.success);
    }
}
