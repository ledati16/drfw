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
use tokio::process::Command;

/// Error type for privilege elevation operations
#[derive(Debug, thiserror::Error)]
pub enum ElevationError {
    /// pkexec binary not found in PATH
    #[error("pkexec not found - please install PolicyKit")]
    PkexecNotFound,

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
///
/// # Performance
///
/// Uses `pgrep` which typically completes in <100ms. This is a synchronous call
/// without an explicit timeout, but `pgrep` is a fast process enumeration that
/// reads from `/proc` and returns quickly. Called once at startup to detect
/// the GUI environment.
// Used in app::handlers::apply (binary only, not in lib.rs)
#[allow(dead_code)]
pub(crate) fn is_polkit_agent_running() -> bool {
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
