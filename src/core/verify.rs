//! Verification of rulesets before they are applied
//!
//! [`verify_ruleset`] runs `nft --json --check` on the generated JSON. It first
//! tries **without privileges**, in a private user + network namespace
//! (`unshare -rn`): if the kernel accepts the batch there, it is valid and no
//! authentication prompt is needed. A failure there is only *inconclusive*
//! (e.g. kernel modules cannot be autoloaded from a user namespace, or
//! unprivileged user namespaces are disabled), so it falls back to the elevated
//! check, whose verdict is authoritative.

use crate::elevation::AuthError;
use std::time::Duration;
use tracing::{info, warn};

/// Timeout for the unprivileged check (no prompt involved; nft is near-instant).
const UNPRIVILEGED_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for the elevated check, including time spent in the
/// authentication dialog.
const ELEVATED_CHECK_TIMEOUT: Duration = Duration::from_secs(120);

/// Arguments for a check-only run of nft reading JSON from stdin.
const CHECK_ARGS: [&str; 4] = ["--json", "--check", "-f", "-"];

/// Result of a ruleset verification operation
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub success: bool,
    pub errors: Vec<String>,
}

impl VerifyResult {
    /// Creates a successful verification result
    pub fn success() -> Self {
        Self {
            success: true,
            errors: Vec::new(),
        }
    }

    /// Creates a failed verification result with errors
    pub fn failure(errors: Vec<String>) -> Self {
        Self {
            success: false,
            errors,
        }
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
            stdin.write_all(payload).await?;
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
    Ok(VerifyResult::failure(parse_nft_errors(&stderr)))
}

/// Tries the check without privileges in a private namespace.
///
/// Returns `true` only if nft accepted the ruleset there; every other outcome
/// is inconclusive.
async fn unprivileged_check_passes(payload: &[u8]) -> bool {
    // nft usually lives in sbin, which is not on every user's PATH (Debian)
    let nft = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .unwrap_or("nft");
    let mut command = tokio::process::Command::new("unshare");
    command.arg("-rn").arg(nft).args(CHECK_ARGS);
    match run_check(command, payload, UNPRIVILEGED_CHECK_TIMEOUT).await {
        Ok(Some(output)) if output.status.success() => true,
        Ok(Some(output)) => {
            info!(
                "Unprivileged check inconclusive, falling back to elevated check: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            false
        }
        Ok(None) => {
            info!("Unprivileged check timed out, falling back to elevated check");
            false
        }
        Err(e) => {
            info!("Unprivileged check unavailable ({e}), falling back to elevated check");
            false
        }
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

/// Parses nft error output into user-friendly messages
///
/// Attempts to extract meaningful error information from nft's
/// stderr output, falling back to raw output if parsing fails.
fn parse_nft_errors(stderr: &str) -> Vec<String> {
    // Try to parse JSON error format first
    if let Ok(json_err) = serde_json::from_str::<serde_json::Value>(stderr)
        && let Some(errors) = json_err.get("errors").and_then(|e| e.as_array())
    {
        return errors
            .iter()
            .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
            .map(String::from)
            .collect();
    }

    // Fall back to line-by-line parsing
    stderr
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            // Clean up common nft error prefixes
            line.trim()
                .trim_start_matches("Error: ")
                .trim_start_matches("nft: ")
                .to_string()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nft_errors_plain_text() {
        let stderr = "Error: syntax error, unexpected $end\nError: invalid expression\n";
        let errors = parse_nft_errors(stderr);

        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0], "syntax error, unexpected $end");
        assert_eq!(errors[1], "invalid expression");
    }

    #[test]
    fn test_parse_nft_errors_empty() {
        let stderr = "";
        let errors = parse_nft_errors(stderr);

        assert_eq!(errors, Vec::<String>::new());
    }

    #[test]
    fn test_parse_nft_errors_with_nft_prefix() {
        let stderr = "nft: syntax error\n";
        let errors = parse_nft_errors(stderr);

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0], "syntax error");
    }

    #[test]
    fn test_parse_nft_errors_permission_denied() {
        // Test that permission errors are correctly parsed
        let stderr = "Error: Operation not permitted\n";
        let errors = parse_nft_errors(stderr);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("Operation not permitted"));
    }

    #[test]
    fn test_parse_nft_errors_permission_denied_verbose() {
        // Test multi-line permission error output
        let stderr =
            "nft: Operation not permitted\nError: Could not process rule: Permission denied\n";
        let errors = parse_nft_errors(stderr);

        assert_eq!(errors.len(), 2);
        assert!(errors[0].contains("Operation not permitted"));
        assert!(errors[1].contains("Permission denied"));
    }

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
        assert_eq!(invalid.errors, vec!["syntax error".to_string()]);
        // Unelevated (test mode): 126/127 are nft's own statuses
        assert!(!check_verdict(&output(126, "x"), false).unwrap().success);
    }

    #[test]
    fn test_verify_result_success() {
        let result = VerifyResult::success();
        assert!(result.success);
        assert_eq!(result.errors, Vec::<String>::new());
    }

    #[test]
    fn test_verify_result_failure() {
        let errors = vec!["error 1".to_string(), "error 2".to_string()];
        let result = VerifyResult::failure(errors.clone());

        assert!(!result.success);
        assert_eq!(result.errors, errors);
    }
}
