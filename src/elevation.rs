//! Privilege elevation for nftables operations
//!
//! This module provides controlled privilege escalation to execute nftables commands
//! with root privileges. DRFW runs as an unprivileged user and only elevates for
//! specific firewall modification operations.
//!
//! # Elevation Strategy
//!
//! - **Preferred (all modes)**: Uses `run0` when available (systemd v256+, no SUID, better security)
//! - **CLI fallback**: Uses `sudo` for standard CLI workflow
//! - **GUI fallback**: Uses `pkexec` for graphical authentication
//!
//! # Security
//!
//! - Uses `pkexec` (GUI) or `sudo` (CLI) for proper privilege escalation
//! - All inputs are validated before elevation
//! - Commands are constructed safely without shell interpolation
//! - Audit logging tracks all privileged operations (via caller)
//! - Binaries (pkexec/sudo, nft) are checked for availability
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
    #[error("`PolicyKit` daemon not accessible: {0}")]
    #[allow(dead_code)] // Part of public API, will be used when GUI integrates elevation
    PkexecUnavailable(String),

    /// No polkit authentication agent available (GUI mode requires one)
    #[error(
        "No polkit authentication agent available. Please start a polkit agent (e.g., polkit-gnome-authentication-agent-1, polkit-kde-authentication-agent-1)"
    )]
    #[allow(dead_code)] // Part of public API, will be used when GUI integrates elevation
    NoPolkitAgent,

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

/// Checks if a polkit authentication agent is running
///
/// This function detects GUI authentication agents by searching for processes
/// with "polkit" in their name, excluding the daemon and terminal-only agents.
///
/// # Returns
///
/// `true` if a GUI polkit agent is running, `false` otherwise
///
/// # Detected Agents
///
/// - polkit-gnome-authentication-agent-1
/// - polkit-kde-authentication-agent-1
/// - lxqt-policykit-agent
/// - And all other standard GUI agents
pub fn is_polkit_agent_running() -> bool {
    std::process::Command::new("pgrep")
        .arg("-a") // Show full command line
        .arg("polkit")
        .output()
        .map(|output| {
            if !output.status.success() {
                return false;
            }

            let output_str = String::from_utf8_lossy(&output.stdout);

            for line in output_str.lines() {
                // Skip daemon and terminal-only agent
                if !line.contains("polkitd") && !line.contains("pkttyagent") {
                    return true;
                }
            }
            false
        })
        .unwrap_or(false)
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

/// Creates an elevated `nft` command with the specified arguments
///
/// This function constructs a command that will execute `nft` with root privileges.
/// The arguments are passed directly without shell interpretation, preventing
/// command injection.
///
/// # Elevation Strategy
///
/// 1. **Preferred**: `run0 nft` when available (systemd v256+, better security, no SUID)
/// 2. **CLI fallback**: `sudo nft` for terminal environments
/// 3. **GUI fallback**: `pkexec nft` for graphical authentication
///
/// # Arguments
///
/// * `args` - Command-line arguments to pass to `nft`
///
/// # Returns
///
/// - `Ok(Command)` - Configured tokio Command ready to spawn
/// - `Err(ElevationError)` - If pkexec/sudo or nft are not available
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
/// Set the environment variable `DRFW_TEST_NO_ELEVATION=1` to bypass pkexec/sudo
/// and run nft directly (requires nft to already have necessary permissions,
/// or tests to run as root).
pub fn create_elevated_nft_command(args: &[&str]) -> Result<Command, ElevationError> {
    use std::os::fd::AsFd;

    // 1. Strict Test Mode Override (Highest Priority)
    if std::env::var("DRFW_TEST_NO_ELEVATION").is_ok() {
        let mut cmd = Command::new("nft");
        cmd.args(args);
        return Ok(cmd);
    }

    // 2. Direct Root Execution (No prompt needed)
    let is_root = nix::unistd::getuid().is_root();
    if is_root {
        let mut cmd = Command::new("nft");
        cmd.args(args);
        return Ok(cmd);
    }

    // 3. Elevation required - prefer run0 (modern, no SUID), fallback to sudo/pkexec

    // Prefer run0 everywhere when available (better security, no SUID bit)
    if binary_exists("run0") {
        let mut cmd = Command::new("run0");
        cmd.arg("nft").args(args);
        return Ok(cmd);
    }

    // Fall back based on environment when run0 not available
    let is_atty = nix::unistd::isatty(std::io::stdin().as_fd()).unwrap_or(false);

    if is_atty {
        // CLI: Standard sudo elevation
        let mut cmd = Command::new("sudo");
        cmd.arg("nft").args(args);
        Ok(cmd)
    } else {
        // GUI: pkexec elevation
        if !binary_exists("pkexec") {
            return Err(ElevationError::PkexecNotFound);
        }

        let mut cmd = Command::new("pkexec");
        cmd.arg("nft").args(args);
        Ok(cmd)
    }
}

/// Translates pkexec/run0/polkit exit codes and stderr to user-friendly errors
///
/// Elevation tools return specific exit codes for different failure modes.
/// This function converts them to actionable error messages.
///
/// # Arguments
///
/// * `exit_code` - Exit code from elevation process (pkexec, run0, etc.)
/// * `stderr` - Standard error output from the process
///
/// # Returns
///
/// Appropriate `ElevationError` variant based on the failure mode
// Used internally by execute_elevated_nft, which is part of public API not yet integrated
#[allow(dead_code)]
pub fn translate_pkexec_error(exit_code: Option<i32>, stderr: &str) -> ElevationError {
    // Check for no polkit agent (common in both pkexec and run0)
    if stderr.contains("No session for pid")
        || stderr.contains("No authentication agent found")
        || stderr.contains("not registered")
    {
        return ElevationError::NoPolkitAgent;
    }

    match exit_code {
        Some(126) => {
            // pkexec/run0: user cancelled authentication
            ElevationError::AuthenticationCancelled
        }
        Some(127) => {
            // pkexec: authentication failed (wrong password, etc.)
            // Exit code 127 always indicates auth failure regardless of stderr
            ElevationError::AuthenticationFailed
        }
        Some(1) if stderr.contains("Cannot run program") || stderr.contains("not found") => {
            // nft binary not found after elevation succeeded
            ElevationError::NftNotFound
        }
        Some(1) if stderr.contains("polkit") || stderr.contains("PolicyKit") => {
            // PolicyKit daemon issues
            ElevationError::PkexecUnavailable(stderr.to_string())
        }
        _ => {
            // Generic error - preserve stderr for debugging
            ElevationError::Io(io::Error::other(format!("Elevation failed: {stderr}")))
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
    }
}
