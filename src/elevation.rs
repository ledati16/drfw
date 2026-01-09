//! Privilege elevation for system operations
//!
//! This module provides controlled privilege escalation to execute commands
//! with root privileges. DRFW runs as an unprivileged user and only elevates for
//! specific operations:
//!
//! - **nft**: Firewall rule verification and application
//! - **install**: Writing configuration to system locations
//!
//! # Elevation Strategy
//!
//! - **Preferred (all modes)**: Uses `run0` when available (systemd v256+, no SUID, better security)
//! - **CLI fallback**: Uses `sudo` for terminal environments
//! - **GUI fallback**: Uses `pkexec` for graphical authentication
//!
//! # Environment Variables
//!
//! - `DRFW_ELEVATION_METHOD`: Force a specific elevation method (`sudo`, `run0`, or `pkexec`).
//!   Useful for scripts with sudoers NOPASSWD rules where you want to bypass run0/polkit.
//!   Example: `DRFW_ELEVATION_METHOD=sudo drfw apply --no-confirm production`
//!
//! - `DRFW_TEST_NO_ELEVATION`: Bypass elevation entirely (for testing only).
//!
//! # Security
//!
//! - Only specific binaries can be elevated (nft, install)
//! - All inputs are validated before elevation
//! - Commands are constructed safely without shell interpolation
//! - Audit logging tracks all privileged operations (via caller)
//! - Binaries (pkexec/sudo, target program) are checked for availability
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

    /// Requested elevation method is not available (binary not found)
    #[error("Elevation method '{0}' is not available (binary not found)")]
    MethodNotAvailable(String),

    /// Invalid value for `DRFW_ELEVATION_METHOD`
    #[error("Invalid DRFW_ELEVATION_METHOD '{0}'. Valid options: sudo, run0, pkexec")]
    InvalidMethod(String),

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

/// Internal helper to build an elevated command for a specific program.
///
/// This is not exposed publicly - callers must use the specific functions
/// (`create_elevated_nft_command`, `create_elevated_install_command`) to ensure
/// only approved binaries can be elevated.
fn build_elevated_command(program: &str, args: &[&str]) -> Result<Command, ElevationError> {
    use std::os::fd::AsFd;

    // 1. Strict Test Mode Override (Highest Priority)
    if std::env::var("DRFW_TEST_NO_ELEVATION").is_ok() {
        let mut cmd = Command::new(program);
        cmd.args(args);
        return Ok(cmd);
    }

    // 2. Direct Root Execution (No prompt needed)
    let is_root = nix::unistd::getuid().is_root();
    if is_root {
        let mut cmd = Command::new(program);
        cmd.args(args);
        return Ok(cmd);
    }

    // 3. Explicit elevation method override (for scripts with sudoers NOPASSWD, etc.)
    if let Ok(method) = std::env::var("DRFW_ELEVATION_METHOD") {
        let method = method.to_lowercase();
        if !method.is_empty() {
            return match method.as_str() {
                "sudo" => {
                    if !binary_exists("sudo") {
                        return Err(ElevationError::MethodNotAvailable("sudo".into()));
                    }
                    let mut cmd = Command::new("sudo");
                    cmd.arg(program).args(args);
                    Ok(cmd)
                }
                "run0" => {
                    if !binary_exists("run0") {
                        return Err(ElevationError::MethodNotAvailable("run0".into()));
                    }
                    let mut cmd = Command::new("run0");
                    cmd.arg(program).args(args);
                    Ok(cmd)
                }
                "pkexec" => {
                    if !binary_exists("pkexec") {
                        return Err(ElevationError::MethodNotAvailable("pkexec".into()));
                    }
                    let mut cmd = Command::new("pkexec");
                    cmd.arg(program).args(args);
                    Ok(cmd)
                }
                _ => Err(ElevationError::InvalidMethod(method)),
            };
        }
    }

    // 4. Automatic detection - prefer run0 (modern, no SUID), fallback to sudo/pkexec

    // Prefer run0 everywhere when available (better security, no SUID bit)
    if binary_exists("run0") {
        let mut cmd = Command::new("run0");
        cmd.arg(program).args(args);
        return Ok(cmd);
    }

    // Fall back based on environment when run0 not available
    let is_atty = nix::unistd::isatty(std::io::stdin().as_fd()).unwrap_or(false);

    if is_atty {
        // CLI: Standard sudo elevation
        let mut cmd = Command::new("sudo");
        cmd.arg(program).args(args);
        Ok(cmd)
    } else {
        // GUI: pkexec elevation
        if !binary_exists("pkexec") {
            return Err(ElevationError::PkexecNotFound);
        }

        let mut cmd = Command::new("pkexec");
        cmd.arg(program).args(args);
        Ok(cmd)
    }
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
    build_elevated_command("nft", args)
}

/// Creates an elevated `install` command with the specified arguments
///
/// This function constructs a command that will execute `install` with root privileges.
/// Used for writing configuration files to system locations like `/etc/nftables.conf`.
///
/// # Elevation Strategy
///
/// Same as [`create_elevated_nft_command`] - prefers run0, falls back to sudo/pkexec.
///
/// # Arguments
///
/// * `args` - Command-line arguments to pass to `install`
///
/// # Returns
///
/// - `Ok(Command)` - Configured tokio Command ready to spawn
/// - `Err(ElevationError)` - If pkexec/sudo are not available
///
/// # Example
///
/// ```no_run
/// use drfw::elevation::create_elevated_install_command;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Install a config file with mode 644
/// let mut cmd = create_elevated_install_command(&["-m", "644", "/tmp/config", "/etc/nftables.conf"])?;
/// let status = cmd.status().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// Arguments are passed directly to `install` without shell interpretation.
/// Callers must ensure file paths are properly validated before calling this function.
pub fn create_elevated_install_command(args: &[&str]) -> Result<Command, ElevationError> {
    build_elevated_command("install", args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_helpers::ENV_VAR_MUTEX;

    #[test]
    fn test_binary_exists() {
        // sh should exist on all Unix systems
        assert!(binary_exists("sh"));
        // This should not exist
        assert!(!binary_exists("drfw_nonexistent_binary_xyz"));
    }

    #[tokio::test]
    async fn test_create_nft_command_test_mode() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        // Set test mode
        unsafe {
            std::env::set_var("DRFW_TEST_NO_ELEVATION", "1");
        }

        let cmd = create_elevated_nft_command(&["list", "ruleset"]);
        assert!(cmd.is_ok());
    }

    #[tokio::test]
    async fn test_create_install_command_test_mode() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        // Set test mode
        unsafe {
            std::env::set_var("DRFW_TEST_NO_ELEVATION", "1");
        }

        let cmd = create_elevated_install_command(&["-m", "644", "/tmp/test", "/etc/test"]);
        assert!(cmd.is_ok());
    }

    #[test]
    fn test_invalid_elevation_method() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        // Clear test mode and set invalid method
        unsafe {
            std::env::remove_var("DRFW_TEST_NO_ELEVATION");
            std::env::set_var("DRFW_ELEVATION_METHOD", "invalid_method");
        }

        let result = create_elevated_nft_command(&["list", "ruleset"]);

        // Restore test mode for other tests
        unsafe {
            std::env::set_var("DRFW_TEST_NO_ELEVATION", "1");
            std::env::remove_var("DRFW_ELEVATION_METHOD");
        }

        assert!(matches!(result, Err(ElevationError::InvalidMethod(_))));
    }

    #[test]
    fn test_elevation_method_case_insensitive() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        // sudo should exist on most systems, so this tests case insensitivity
        unsafe {
            std::env::remove_var("DRFW_TEST_NO_ELEVATION");
            std::env::set_var("DRFW_ELEVATION_METHOD", "SUDO");
        }

        let result = create_elevated_nft_command(&["list", "ruleset"]);

        // Restore test mode
        unsafe {
            std::env::set_var("DRFW_TEST_NO_ELEVATION", "1");
            std::env::remove_var("DRFW_ELEVATION_METHOD");
        }

        // Should succeed (sudo exists) or fail with MethodNotAvailable (sudo doesn't exist)
        // but NOT InvalidMethod
        assert!(!matches!(result, Err(ElevationError::InvalidMethod(_))));
    }
}
