/// Verification module for nftables rulesets
///
/// This module provides validation of rulesets before they are applied,
/// helping prevent broken firewall configurations.
use crate::core::error::{Error, Result};
use tracing::{info, warn};

/// Result of a ruleset verification operation
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub success: bool,
    #[allow(dead_code)]
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl VerifyResult {
    /// Creates a successful verification result
    pub fn success() -> Self {
        Self {
            success: true,
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Creates a failed verification result with errors
    pub fn failure(errors: Vec<String>) -> Self {
        Self {
            success: false,
            warnings: Vec::new(),
            errors,
        }
    }
}

/// Verifies a ruleset without applying it using `nft --json --check`
/// Phase 1 Optimization: Takes JSON directly to avoid cloning ruleset
///
/// # Errors
///
/// Returns `Err` if:
/// - nft command cannot be executed
/// - JSON serialization fails
/// - Communication with nft process fails
pub async fn verify_ruleset(json_payload: serde_json::Value) -> Result<VerifyResult> {
    let json_string = serde_json::to_string(&json_payload)?;

    info!("Verifying ruleset via nft --json --check (elevated)");

    let mut child =
        crate::elevation::create_elevated_nft_command(&["--json", "--check", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Internal(format!("Failed to spawn nft: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(json_string.as_bytes())
            .await
            .map_err(|e| Error::Internal(format!("Failed to write to nft stdin: {e}")))?;
    }

    let output = child.wait_with_output().await?;

    if output.status.success() {
        info!("Ruleset verification passed");
        Ok(VerifyResult::success())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Ruleset verification failed: {}", stderr);

        let errors = parse_nft_errors(&stderr);

        Ok(VerifyResult::failure(errors))
    }
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

        assert!(errors.is_empty());
    }

    #[test]
    fn test_parse_nft_errors_with_nft_prefix() {
        let stderr = "nft: syntax error\n";
        let errors = parse_nft_errors(stderr);

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0], "syntax error");
    }

    #[test]
    fn test_verify_result_success() {
        let result = VerifyResult::success();
        assert!(result.success);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_verify_result_failure() {
        let errors = vec!["error 1".to_string(), "error 2".to_string()];
        let result = VerifyResult::failure(errors.clone());

        assert!(!result.success);
        assert_eq!(result.errors, errors);
    }
}
