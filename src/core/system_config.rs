//! Save to System: verified, atomic replacement of the system nftables config
//!
//! The GUI's "Save to System" writes [`FirewallRuleset::to_nft_text`] to
//! [`crate::SYSTEM_NFT_PATH`] so the rules survive a reboot. The write runs as
//! one elevated invocation of the fixed
//! [`SAVE_CONFIG_SCRIPT`](crate::elevation::SAVE_CONFIG_SCRIPT): content on
//! stdin, target path as argv, `nft -c` on the exact bytes, backup of the old
//! file, atomic rename and, if asked, `systemctl enable` of the boot service
//! in the same prompt. See the script's docs for the exact steps.
//!
//! [`FirewallRuleset::to_nft_text`]: crate::core::firewall::FirewallRuleset::to_nft_text

use std::path::PathBuf;
use std::time::Duration;

use crate::core::error::{Error, Result};

/// Maximum time for the whole save, including the authentication dialog.
const SAVE_TIMEOUT: Duration = Duration::from_secs(120);

/// Stdout marker printed by the save script when it backed up the old file.
const BACKUP_MARKER: &str = "backup=";

/// Stdout marker printed by the save script after `systemctl enable`.
const ENABLE_MARKER: &str = "enable=";

/// What the save script reported for `systemctl enable <service>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnableOutcome {
    /// `systemctl enable` succeeded
    Enabled,
    /// `systemctl enable` failed (its output); the file was saved anyway
    Failed(String),
}

/// Runs the save script for `target` with `content` on stdin.
///
/// Returns the raw process output; callers interpret the exit status (the
/// elevation tools use 126/127 for cancelled/failed authentication, the
/// script itself uses 3 for "nft rejected the file" and 1 otherwise). Use
/// [`backup_path_from_output`] to find out whether a backup was made.
///
/// # Arguments
///
/// * `content` - Complete file content (normally `FirewallRuleset::to_nft_text()`)
/// * `target` - Path to replace (normally [`crate::SYSTEM_NFT_PATH`])
///
/// # Errors
///
/// - [`Error::Elevation`] if no elevation method is available
/// - [`Error::Io`] if the process cannot be spawned or its stdin written
/// - [`Error::Internal`] if the operation times out (e.g. the authentication
///   dialog was left open)
///
/// # Testing
///
/// With `DRFW_NFT_COMMAND` set, runs unelevated and uses that command for the
/// syntax check (see [`crate::elevation::create_elevated_save_config_command`]).
pub async fn write_config_file(content: &str, target: &str) -> Result<std::process::Output> {
    write_config_file_and_enable(content, target, None).await
}

/// [`write_config_file`], then (as root, in the same prompt) `systemctl
/// enable <enable_service>` if the file was installed.
///
/// A failure to enable does not fail the save (exit status 0): read it with
/// [`enable_outcome_from_output`].
///
/// # Errors
///
/// The same as [`write_config_file`].
pub async fn write_config_file_and_enable(
    content: &str,
    target: &str,
    enable_service: Option<&str>,
) -> Result<std::process::Output> {
    use tokio::io::AsyncWriteExt;

    let mut child = crate::elevation::create_elevated_save_config_command(target, enable_service)
        .map_err(|e| Error::Elevation(e.to_string()))?
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let work = async {
        if let Some(mut stdin) = child.stdin.take() {
            // A script that exits before reading (rejected arguments, failed
            // authentication) closes the pipe: its exit status and stderr
            // explain why, not the broken pipe
            if let Err(e) = stdin.write_all(content.as_bytes()).await
                && e.kind() != std::io::ErrorKind::BrokenPipe
            {
                return Err(e);
            }
            // Dropping stdin closes the pipe so `install` sees EOF
        }
        child.wait_with_output().await
    };

    match tokio::time::timeout(SAVE_TIMEOUT, work).await {
        Ok(result) => Ok(result?),
        Err(_) => Err(Error::Internal(
            "Save timed out (authentication dialog expired?)".to_string(),
        )),
    }
}

/// Extracts the backup path reported by a successful save, if one was made.
///
/// Returns `None` when the target did not exist before (nothing to back up).
pub fn backup_path_from_output(output: &std::process::Output) -> Option<PathBuf> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix(BACKUP_MARKER))
        .map(PathBuf::from)
}

/// Extracts the result of `systemctl enable` from a successful save.
///
/// Returns `None` when no service was to be enabled (or the script ended
/// before that step).
pub fn enable_outcome_from_output(output: &std::process::Output) -> Option<EnableOutcome> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix(ENABLE_MARKER))
        .map(|value| match value.strip_prefix("failed:") {
            Some(error) => EnableOutcome::Failed(error.trim().to_string()),
            None if value.trim() == "ok" => EnableOutcome::Enabled,
            None => EnableOutcome::Failed(value.trim().to_string()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn test_backup_path_from_output() {
        use std::os::unix::process::ExitStatusExt;
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"backup=/etc/nftables.conf.drfw-bak\n".to_vec(),
            stderr: Vec::new(),
        };
        assert_eq!(
            backup_path_from_output(&output),
            Some(PathBuf::from("/etc/nftables.conf.drfw-bak"))
        );

        let output = std::process::Output {
            stdout: Vec::new(),
            ..output
        };
        assert_eq!(backup_path_from_output(&output), None);
    }

    #[cfg(unix)]
    #[test]
    fn test_enable_outcome_from_output() {
        use std::os::unix::process::ExitStatusExt;
        let output = |stdout: &str| std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        };
        assert_eq!(enable_outcome_from_output(&output("")), None);
        assert_eq!(
            enable_outcome_from_output(&output("backup=/etc/nftables.conf.drfw-bak\n")),
            None
        );
        assert_eq!(
            enable_outcome_from_output(&output("backup=/x.drfw-bak\nenable=ok\n")),
            Some(EnableOutcome::Enabled)
        );
        assert_eq!(
            enable_outcome_from_output(&output(
                "enable=failed: Failed to enable unit: Unit file x.service is masked. \n"
            )),
            Some(EnableOutcome::Failed(
                "Failed to enable unit: Unit file x.service is masked.".to_string()
            ))
        );
        assert_eq!(
            enable_outcome_from_output(&output("enable=weird\n")),
            Some(EnableOutcome::Failed("weird".to_string()))
        );
    }
}
