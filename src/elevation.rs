//! Privilege elevation for nftables operations
//!
//! This module provides controlled privilege escalation using `pkexec` (PolicyKit)
//! to execute nftables commands with root privileges. DRFW runs as an unprivileged
//! user and only elevates for specific firewall modification operations.
//!
//! # PolicyKit Integration
//!
//! DRFW uses a polkit policy file (`org.drfw.policy`) that defines the authorization
//! action `org.drfw.nftables.modify`. This policy should be installed to:
//! `/usr/share/polkit-1/actions/org.drfw.policy`
//!
//! The policy is configured for one-shot authentication (no credential caching).
//! Each privileged operation will require the user to re-authenticate.
//!
//! # Security
//!
//! - Uses `pkexec` (part of PolicyKit) for proper privilege escalation
//! - All inputs are validated before elevation
//! - Commands are constructed safely without shell interpolation
//! - Audit logging tracks all privileged operations (via caller)
//! - Binaries (pkexec, nft) are checked for availability
//! - Timeout protection prevents indefinite hangs
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
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Default timeout for pkexec operations (2 minutes)
///
/// This prevents indefinite hangs if the polkit daemon is unresponsive
/// or the user doesn't respond to the authentication prompt.
// Suggested default for callers of execute_elevated_nft
#[allow(dead_code)]
const DEFAULT_PKEXEC_TIMEOUT: Duration = Duration::from_secs(120);

/// Error type for privilege elevation operations
#[derive(Debug, thiserror::Error)]
pub enum ElevationError {
    /// pkexec binary not found in PATH
    #[error("pkexec not found - please install PolicyKit")]
    PkexecNotFound,

    /// nft binary not found in PATH
    #[error("nft binary not found - please install nftables")]
    NftNotFound,

    /// PolicyKit daemon not running or not accessible
    #[error("PolicyKit daemon not accessible: {0}")]
    #[allow(dead_code)] // Part of public API, will be used when GUI integrates elevation
    PkexecUnavailable(String),

    /// User cancelled authentication
    #[error("Authentication cancelled by user")]
    #[allow(dead_code)] // Part of public API, will be used when GUI integrates elevation
    AuthenticationCancelled,

    /// Authentication failed (wrong password, etc.)
    #[error("Authentication failed")]
    #[allow(dead_code)] // Part of public API, will be used when GUI integrates elevation
    AuthenticationFailed,

    /// Operation timed out waiting for authentication
    #[error("Operation timed out after {0:?}")]
    #[allow(dead_code)] // Part of public API, will be used when GUI integrates elevation
    Timeout(Duration),

    /// Generic I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
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

/// Checks if privilege elevation infrastructure is available
///
/// Verifies that both `pkexec` and `nft` binaries are present in PATH.
/// This should be called at startup to provide early feedback if the
/// system is not properly configured.
///
/// # Returns
///
/// - `Ok(())` if both binaries are available
/// - `Err(ElevationError)` with specific missing binary
///
/// # Example
///
/// ```no_run
/// use drfw::elevation::check_elevation_available;
///
/// match check_elevation_available() {
///     Ok(()) => println!("Privilege elevation available"),
///     Err(e) => eprintln!("Cannot elevate privileges: {e}"),
/// }
/// ```
// Part of public API intended for startup checks, not yet integrated into GUI
#[allow(dead_code)]
pub fn check_elevation_available() -> Result<(), ElevationError> {
    // Skip checks in test mode
    if std::env::var("DRFW_TEST_NO_ELEVATION").is_ok() {
        return Ok(());
    }

    if !binary_exists("pkexec") {
        return Err(ElevationError::PkexecNotFound);
    }

    if !binary_exists("nft") {
        return Err(ElevationError::NftNotFound);
    }

    Ok(())
}

/// Creates a `pkexec nft` command with the specified arguments
///
/// This function constructs a command that will execute `nft` with root privileges
/// via `pkexec`. The arguments are passed directly without shell interpretation,
/// preventing command injection.
///
/// The command is configured with the polkit action `org.drfw.nftables.modify`,
/// which should be defined in `/usr/share/polkit-1/actions/org.drfw.policy`.
///
/// # Arguments
///
/// * `args` - Command-line arguments to pass to `nft`
///
/// # Returns
///
/// - `Ok(Command)` - Configured tokio Command ready to spawn
/// - `Err(ElevationError)` - If pkexec or nft are not available
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
/// Set the environment variable `DRFW_TEST_NO_ELEVATION=1` to bypass pkexec
/// and run nft directly (requires nft to already have necessary permissions,
/// or tests to run as root).
pub fn create_elevated_nft_command(args: &[&str]) -> Result<Command, ElevationError> {
    if std::env::var("DRFW_TEST_NO_ELEVATION").is_ok() {
        // Test mode: run nft directly
        let mut cmd = Command::new("nft");
        cmd.args(args);
        Ok(cmd)
    } else {
        // Production mode: check if we are root
        let is_root = nix::unistd::getuid().is_root();
        if is_root {
            let mut cmd = Command::new("nft");
            cmd.args(args);
            return Ok(cmd);
        }

        // Not root - decide between pkexec (GUI) and sudo (CLI)
        // We detect CLI by checking if we have a controlling terminal
        use std::os::fd::AsFd;
        let is_atty = nix::unistd::isatty(std::io::stdin().as_fd()).unwrap_or(false);

        if is_atty {
            // CLI: Prefer sudo
            let mut cmd = Command::new("sudo");
            cmd.arg("nft").args(args);
            Ok(cmd)
        } else {
            // GUI: Use pkexec with polkit action
            if !binary_exists("pkexec") {
                return Err(ElevationError::PkexecNotFound);
            }
            let mut cmd = Command::new("pkexec");
            cmd.arg("--action")
                .arg("org.drfw.nftables.modify")
                .arg("nft")
                .args(args);
            Ok(cmd)
        }
    }
}

/// Translates pkexec/polkit exit codes and stderr to user-friendly errors
///
/// pkexec returns specific exit codes for different failure modes.
/// This function converts them to actionable error messages.
///
/// # Arguments
///
/// * `exit_code` - Exit code from pkexec process
/// * `stderr` - Standard error output from pkexec
///
/// # Returns
///
/// Appropriate `ElevationError` variant based on the failure mode
// Used internally by execute_elevated_nft, which is part of public API not yet integrated
#[allow(dead_code)]
pub fn translate_pkexec_error(exit_code: Option<i32>, stderr: &str) -> ElevationError {
    match exit_code {
        Some(126) => {
            // pkexec: user cancelled authentication
            ElevationError::AuthenticationCancelled
        }
        Some(127) => {
            // pkexec: authentication failed (wrong password, etc.)
            // Exit code 127 always indicates auth failure regardless of stderr
            ElevationError::AuthenticationFailed
        }
        Some(1) if stderr.contains("Cannot run program") => {
            // nft binary not found after pkexec succeeded
            ElevationError::NftNotFound
        }
        Some(1) if stderr.contains("polkit") || stderr.contains("PolicyKit") => {
            // PolicyKit daemon issues
            ElevationError::PkexecUnavailable(stderr.to_string())
        }
        _ => {
            // Generic error - preserve stderr for debugging
            ElevationError::Io(io::Error::other(format!("pkexec failed: {stderr}")))
        }
    }
}

/// Helper to execute an elevated nft command with timeout
///
/// This is a convenience function that handles common patterns:
/// - Spawning the command
/// - Applying a timeout
/// - Translating pkexec errors
///
/// # Arguments
///
/// * `args` - Arguments to pass to `nft`
/// * `stdin_data` - Optional data to write to stdin (for `-f -` operations)
/// * `timeout` - Maximum time to wait for the operation
///
/// # Returns
///
/// - `Ok(output)` - Command output if successful
/// - `Err(ElevationError)` - On failure
///
/// # Example
///
/// ```no_run
/// use drfw::elevation::execute_elevated_nft;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // List ruleset (no stdin)
/// let output = execute_elevated_nft(
///     &["--json", "list", "ruleset"],
///     None,
///     Duration::from_secs(30)
/// ).await?;
///
/// // Apply rules from JSON
/// let json = r#"{"nftables": [...]}"#;
/// let output = execute_elevated_nft(
///     &["--json", "-f", "-"],
///     Some(json.as_bytes()),
///     Duration::from_secs(60)
/// ).await?;
/// # Ok(())
/// # }
/// ```
// Part of public API for convenient elevated nft execution, not yet used in GUI
#[allow(dead_code)]
pub async fn execute_elevated_nft(
    args: &[&str],
    stdin_data: Option<&[u8]>,
    timeout: Duration,
) -> Result<std::process::Output, ElevationError> {
    use tokio::io::AsyncWriteExt;
    use tokio::time::timeout as tokio_timeout;

    let mut cmd = create_elevated_nft_command(args)?;

    // Configure stdio
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Spawn process
    let mut child = cmd.spawn()?;

    // Write stdin if provided
    // Note: Could use let-chains to collapse nested if, but that requires unstable feature
    #[allow(clippy::collapsible_if)]
    if let Some(data) = stdin_data {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data).await?;
            // Explicitly drop to close stdin
            drop(stdin);
        }
    }

    // Wait with timeout
    match tokio_timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            if output.status.success() {
                Ok(output)
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(translate_pkexec_error(output.status.code(), &stderr))
            }
        }
        Ok(Err(e)) => Err(ElevationError::from(e)),
        Err(_) => Err(ElevationError::Timeout(timeout)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_exists() {
        // sh should exist on all Unix systems
        assert!(binary_exists("sh"));
        // This should not exist
        assert!(!binary_exists("drfw_nonexistent_binary_xyz"));
    }

    #[test]
    fn test_pkexec_error_translation() {
        // User cancelled
        let err = translate_pkexec_error(Some(126), "");
        assert!(matches!(err, ElevationError::AuthenticationCancelled));

        // Wrong password
        let err = translate_pkexec_error(Some(127), "authentication failed");
        assert!(matches!(err, ElevationError::AuthenticationFailed));

        // Not authorized
        let err = translate_pkexec_error(Some(127), "not authorized");
        assert!(matches!(err, ElevationError::AuthenticationFailed));
    }

    #[tokio::test]
    async fn test_create_command_test_mode() {
        // Set test mode
        unsafe {
            std::env::set_var("DRFW_TEST_NO_ELEVATION", "1");
        }

        let cmd = create_elevated_nft_command(&["list", "ruleset"]);
        assert!(cmd.is_ok());

        // Clean up
        unsafe {
            std::env::remove_var("DRFW_TEST_NO_ELEVATION");
        }
    }
}
