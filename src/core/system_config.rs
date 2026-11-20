//! Save to System: verified, atomic replacement of the system nftables config
//!
//! The GUI's "Save to System" writes [`FirewallRuleset::to_nft_text`] to
//! [`crate::SYSTEM_NFT_PATH`] so the rules survive a reboot. The write runs as
//! one elevated invocation of the fixed
//! [`SAVE_CONFIG_SCRIPT`](crate::elevation::SAVE_CONFIG_SCRIPT): content on
//! stdin, target path as argv, `nft -c` on the exact bytes, backup of the old
//! file, atomic rename. See the script's docs for the exact steps.
//!
//! [`FirewallRuleset::to_nft_text`]: crate::core::firewall::FirewallRuleset::to_nft_text

use crate::core::error::{Error, Result};
use std::path::PathBuf;
use std::time::Duration;

/// Maximum time for the whole save, including the authentication dialog.
const SAVE_TIMEOUT: Duration = Duration::from_secs(120);

/// Stdout marker printed by the save script when it backed up the old file.
const BACKUP_MARKER: &str = "backup=";

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
    use tokio::io::AsyncWriteExt;

    let mut child = crate::elevation::create_elevated_save_config_command(target)
        .map_err(|e| Error::Elevation(e.to_string()))?
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let work = async {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(content.as_bytes()).await?;
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
}
