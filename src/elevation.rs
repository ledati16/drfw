//! Privilege elevation for system operations
//!
//! This module provides controlled privilege escalation to execute commands
//! with root privileges. DRFW runs as an unprivileged user and only elevates for
//! specific operations:
//!
//! - **nft**: Firewall rule verification and application
//! - **/bin/sh** running the fixed [`SAVE_CONFIG_SCRIPT`]: verified, atomic writes of
//!   the system nftables configuration (Save to System)
//!
//! # Elevation Strategy
//!
//! Elevation method is chosen based on environment:
//!
//! - **CLI (TTY present)**: Prefers `run0` (systemd v256+, no SUID), falls back to `sudo`
//! - **GUI (no TTY)**: Prefers `pkexec` (proper credential caching), falls back to `run0`
//!
//! This distinction matters because `run0` uses TTY-based session binding for credential
//! caching. When launched from a GUI without a TTY, `run0` creates a new PTY for each
//! invocation, breaking caching.
//!
//! # Credential Caching (pkexec)
//!
//! With the polkit rules file (`contrib/50-drfw.rules`), pkexec enables `AUTH_ADMIN_KEEP`
//! which caches credentials **per-process (PID)**, not per-desktop-session:
//!
//! - Once DRFW authenticates for nft, all subsequent pkexec calls from that process
//!   are authorized without re-prompting
//! - Cache expires after ~5 minutes OR when DRFW exits (whichever comes first)
//! - Restarting DRFW requires reauthentication (new PID = new polkit subject)
//!
//! # Environment Variables
//!
//! - `DRFW_NFT_COMMAND`: Path to nft binary or mock script. When set, uses this path
//!   directly without elevation. Used for testing with mock nft.
//!   Example: `DRFW_NFT_COMMAND=tests/mock_nft.sh cargo test`
//!
//! - `DRFW_ELEVATION_METHOD`: Force a specific elevation method (`sudo`, `run0`, or `pkexec`).
//!   Useful for scripts with sudoers NOPASSWD rules where you want to bypass run0/polkit.
//!   Example: `DRFW_ELEVATION_METHOD=sudo drfw apply --no-confirm production`
//!
//! # Security
//!
//! - Only specific programs can be elevated (nft, and `/bin/sh` with a fixed script)
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
/// (`create_elevated_nft_command`, `create_elevated_save_config_command`) to ensure
/// only approved binaries can be elevated.
fn build_elevated_command(program: &str, args: &[&str]) -> Result<Command, ElevationError> {
    use std::os::fd::AsFd;

    // 1. Direct Root Execution (No prompt needed)
    let is_root = nix::unistd::getuid().is_root();
    if is_root {
        let mut cmd = Command::new(program);
        cmd.args(args);
        return Ok(cmd);
    }

    // 2. Explicit elevation method override (for scripts with sudoers NOPASSWD, etc.)
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
                    cmd.args(["--disable-internal-agent", program]).args(args);
                    Ok(cmd)
                }
                _ => Err(ElevationError::InvalidMethod(method)),
            };
        }
    }

    // 3. Automatic detection based on environment
    //
    // Run0 uses TTY-based session binding for credential caching. When launched
    // from a GUI (no TTY), run0 creates a new PTY for each invocation, breaking
    // caching. Pkexec uses D-Bus/XDG session identification which persists across
    // the desktop session, making it better suited for GUI applications.
    let is_atty = nix::unistd::isatty(std::io::stdin().as_fd()).unwrap_or(false);

    if is_atty {
        // CLI environment: prefer run0 (modern, no SUID), fallback to sudo
        if binary_exists("run0") {
            let mut cmd = Command::new("run0");
            cmd.arg(program).args(args);
            return Ok(cmd);
        }
        let mut cmd = Command::new("sudo");
        cmd.arg(program).args(args);
        Ok(cmd)
    } else {
        // GUI environment: pkexec only (run0/sudo use terminal auth which can't work in GUI)
        if binary_exists("pkexec") {
            let mut cmd = Command::new("pkexec");
            cmd.args(["--disable-internal-agent", program]).args(args);
            return Ok(cmd);
        }
        Err(ElevationError::PkexecNotFound)
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
/// 1. **Custom command**: If `DRFW_NFT_COMMAND` is set, uses that path directly (no elevation)
/// 2. **CLI (TTY present)**: `run0 nft` preferred, falls back to `sudo nft`
/// 3. **GUI (no TTY)**: `pkexec nft` preferred (proper session caching), falls back to `run0 nft`
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
/// Set `DRFW_NFT_COMMAND` to a mock script path (e.g., `tests/mock_nft.sh`) to use
/// a mock nft for testing without requiring root privileges.
pub fn create_elevated_nft_command(args: &[&str]) -> Result<Command, ElevationError> {
    // Check for explicit nft command override (for testing with mock)
    if let Ok(nft_path) = std::env::var("DRFW_NFT_COMMAND")
        && !nft_path.is_empty()
    {
        let mut cmd = Command::new(&nft_path);
        cmd.args(args);
        return Ok(cmd);
    }

    build_elevated_command("nft", args)
}

/// Fixed shell script run (elevated) by Save to System.
///
/// Arguments: `$1` = target path, `$2` = nft command. The new file content
/// arrives on stdin. No user-controlled data is ever interpolated into the
/// script text; the target path is a compile-time constant
/// ([`crate::SYSTEM_NFT_PATH`]) in the GUI and is only ever passed as argv.
///
/// Steps:
/// 1. Write stdin to `<dir>/.<name>.drfw-tmp` (mode 644) in the target's own
///    directory, so the final rename is atomic (same filesystem).
/// 2. `nft -c -f` that temp file: the authoritative check of the exact bytes
///    that will be installed.
/// 3. Copy the existing target (if any) to `<target>.drfw-bak`, preserving
///    mode/owner/timestamps. Done after the check so a rejected file never
///    overwrites a good backup.
/// 4. `mv -f` the temp file over the target (atomic rename).
///
/// Any failure removes the temp file and leaves the original untouched. On
/// success, prints `backup=<path>` on stdout when a backup was made.
///
/// Exit codes: 0 success, 3 nft rejected the file, 1 other failures. 126/127
/// are deliberately never used: callers interpret those as authentication
/// errors from pkexec/sudo/run0.
pub const SAVE_CONFIG_SCRIPT: &str = r#"set -u
target=$1
nft=$2
dir=$(dirname -- "$target") || exit 1
name=$(basename -- "$target") || exit 1
tmp="$dir/.$name.drfw-tmp"
backup="$target.drfw-bak"
fail() {
    rm -f -- "$tmp"
    printf 'drfw: %s\n' "$1" >&2
    exit "$2"
}
rm -f -- "$tmp" || fail "cannot remove stale temporary file $tmp" 1
install -m 644 /dev/stdin "$tmp" || fail "cannot write $tmp" 1
if ! check_output=$("$nft" -c -f "$tmp" 2>&1); then
    fail "nft rejected the configuration; $target left unchanged: $check_output" 3
fi
if [ -e "$target" ]; then
    cp -p -- "$target" "$backup" || fail "cannot back up $target to $backup" 1
    made_backup=1
else
    made_backup=0
fi
mv -f -- "$tmp" "$target" || fail "cannot replace $target" 1
if [ "$made_backup" = 1 ]; then
    printf 'backup=%s\n' "$backup"
fi
exit 0
"#;

/// `$0` for [`SAVE_CONFIG_SCRIPT`] (shows up in `ps` and in shell error messages).
const SAVE_CONFIG_SCRIPT_NAME: &str = "drfw-save-config";

/// Absolute shell path: elevation tools must not resolve `sh` through `PATH`.
const SHELL_PATH: &str = "/bin/sh";

/// Creates the (elevated) command that installs a new system nftables config.
///
/// Runs [`SAVE_CONFIG_SCRIPT`] with `/bin/sh` and a single elevation prompt.
/// The caller writes the file content to the command's stdin.
///
/// # Arguments
///
/// * `target` - Path of the file to replace (normally [`crate::SYSTEM_NFT_PATH`])
///
/// # Testing
///
/// When `DRFW_NFT_COMMAND` is set, the script runs **without elevation** and
/// uses that command for the `nft -c` check, mirroring
/// [`create_elevated_nft_command`]. Tests point `target` at a temporary directory.
///
/// # Errors
///
/// Returns `Err(ElevationError)` if no elevation method is available.
///
/// # Example
///
/// ```no_run
/// use drfw::elevation::create_elevated_save_config_command;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut cmd = create_elevated_save_config_command(drfw::SYSTEM_NFT_PATH)?;
/// cmd.stdin(std::process::Stdio::piped());
/// # Ok(())
/// # }
/// ```
pub fn create_elevated_save_config_command(target: &str) -> Result<Command, ElevationError> {
    if let Ok(nft_path) = std::env::var("DRFW_NFT_COMMAND")
        && !nft_path.is_empty()
    {
        let mut cmd = Command::new(SHELL_PATH);
        cmd.args([
            "-c",
            SAVE_CONFIG_SCRIPT,
            SAVE_CONFIG_SCRIPT_NAME,
            target,
            &nft_path,
        ]);
        return Ok(cmd);
    }

    build_elevated_command(
        SHELL_PATH,
        &[
            "-c",
            SAVE_CONFIG_SCRIPT,
            SAVE_CONFIG_SCRIPT_NAME,
            target,
            "nft",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_helpers::ENV_VAR_MUTEX;

    /// Get absolute path to `mock_nft.sh` for testing
    fn get_mock_nft_path() -> String {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        format!("{manifest_dir}/tests/mock_nft.sh")
    }

    #[test]
    fn test_binary_exists() {
        // sh should exist on all Unix systems
        assert!(binary_exists("sh"));
        // This should not exist
        assert!(!binary_exists("drfw_nonexistent_binary_xyz"));
    }

    #[test]
    fn test_create_nft_command_with_mock() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        // Use DRFW_NFT_COMMAND to specify mock nft
        let mock_path = get_mock_nft_path();
        unsafe {
            std::env::set_var("DRFW_NFT_COMMAND", &mock_path);
        }

        let cmd = create_elevated_nft_command(&["list", "ruleset"]);
        assert!(cmd.is_ok(), "Should create command with mock nft");

        // Clean up
        unsafe {
            std::env::remove_var("DRFW_NFT_COMMAND");
        }
    }

    #[test]
    fn test_save_config_command_with_mock_skips_elevation() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        let mock_path = get_mock_nft_path();
        unsafe {
            std::env::set_var("DRFW_NFT_COMMAND", &mock_path);
        }
        let cmd = create_elevated_save_config_command("/nonexistent/nftables.conf");
        unsafe {
            std::env::remove_var("DRFW_NFT_COMMAND");
        }

        let cmd = cmd.expect("mock mode never needs elevation");
        let std_cmd = cmd.as_std();
        assert_eq!(std_cmd.get_program(), SHELL_PATH);
        let args: Vec<_> = std_cmd.get_args().collect();
        // Fixed script, then $0, target and nft command as separate argv entries
        assert_eq!(args[1], SAVE_CONFIG_SCRIPT);
        assert_eq!(args[3], "/nonexistent/nftables.conf");
        assert_eq!(args[4], mock_path.as_str());
    }

    #[test]
    fn test_invalid_elevation_method() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        // Clear custom command and set invalid method
        unsafe {
            std::env::remove_var("DRFW_NFT_COMMAND");
            std::env::set_var("DRFW_ELEVATION_METHOD", "invalid_method");
        }

        let result = create_elevated_nft_command(&["list", "ruleset"]);

        // Clean up
        unsafe {
            std::env::remove_var("DRFW_ELEVATION_METHOD");
        }

        assert!(matches!(result, Err(ElevationError::InvalidMethod(_))));
    }

    #[test]
    fn test_elevation_method_case_insensitive() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        // Clear custom command and test case insensitivity with SUDO (uppercase)
        unsafe {
            std::env::remove_var("DRFW_NFT_COMMAND");
            std::env::set_var("DRFW_ELEVATION_METHOD", "SUDO");
        }

        let result = create_elevated_nft_command(&["list", "ruleset"]);

        // Clean up
        unsafe {
            std::env::remove_var("DRFW_ELEVATION_METHOD");
        }

        // Should succeed (sudo exists) or fail with MethodNotAvailable (sudo doesn't exist)
        // but NOT InvalidMethod - that would mean case sensitivity is broken
        assert!(!matches!(result, Err(ElevationError::InvalidMethod(_))));
    }

    #[test]
    fn test_drfw_nft_command_takes_precedence() {
        let _guard = ENV_VAR_MUTEX.lock().unwrap();

        // Even with elevation method set, DRFW_NFT_COMMAND should take precedence
        let mock_path = get_mock_nft_path();
        unsafe {
            std::env::set_var("DRFW_NFT_COMMAND", &mock_path);
            std::env::set_var("DRFW_ELEVATION_METHOD", "invalid_method");
        }

        let result = create_elevated_nft_command(&["list", "ruleset"]);

        // Clean up
        unsafe {
            std::env::remove_var("DRFW_NFT_COMMAND");
            std::env::remove_var("DRFW_ELEVATION_METHOD");
        }

        // Should succeed because DRFW_NFT_COMMAND bypasses elevation entirely
        assert!(
            result.is_ok(),
            "DRFW_NFT_COMMAND should take precedence over DRFW_ELEVATION_METHOD"
        );
    }
}
