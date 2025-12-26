//! Privilege elevation for nftables operations
//!
//! This module provides controlled privilege escalation using `pkexec` to execute
//! nftables commands with root privileges. DRFW runs as an unprivileged user and
//! only elevates for specific firewall modification operations.
//!
//! # Security
//!
//! - Uses `pkexec` (part of polkit) for proper privilege escalation
//! - All inputs are validated before elevation
//! - Commands are constructed safely without shell interpolation
//! - Audit logging tracks all privileged operations
//!
//! # Example
//!
//! ```no_run
//! use drfw::elevation::create_elevated_nft_command;
//!
//! let cmd = create_elevated_nft_command(&["--json", "list", "ruleset"]);
//! // Execute cmd through async runtime
//! ```

/// Creates a `pkexec nft` command with the specified arguments
///
/// This function constructs a command that will execute `nft` with root privileges
/// via `pkexec`. The arguments are passed directly without shell interpretation,
/// preventing command injection.
///
/// # Arguments
///
/// * `args` - Command-line arguments to pass to `nft`
///
/// # Example
///
/// ```no_run
/// use drfw::elevation::create_elevated_nft_command;
///
/// // List current ruleset
/// let cmd = create_elevated_nft_command(&["list", "ruleset"]);
///
/// // Apply rules from stdin
/// let cmd = create_elevated_nft_command(&["--json", "-f", "-"]);
/// ```
///
/// # Security
///
/// Arguments are passed directly to `nft` without shell interpretation.
/// Callers must ensure arguments are properly validated before calling this function.
pub fn create_elevated_nft_command(args: &[&str]) -> tokio::process::Command {
    if std::env::var("DRFW_TEST_NO_ELEVATION").is_ok() {
        let mut cmd = tokio::process::Command::new("nft");
        cmd.args(args);
        cmd
    } else {
        let mut cmd = tokio::process::Command::new("pkexec");
        cmd.arg("nft").args(args);
        cmd
    }
}
