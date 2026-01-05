//! Utility functions for directory management and system integration
//!
//! This module provides helper functions following the XDG Base Directory specification
//! for portable configuration and data storage across Linux distributions.
//!
//! # Directory Structure
//!
//! - Config: `~/.config/drfw/` - User configuration files
//! - Data: `~/.local/share/drfw/` - Application data (saved rulesets)
//! - State: `~/.local/state/drfw/` - Runtime state (snapshots, audit logs)
//!
//! # Example
//!
//! ```
//! use drfw::utils::{get_data_dir, get_state_dir, ensure_dirs};
//!
//! // Ensure directories exist before use
//! ensure_dirs().expect("Failed to create directories");
//!
//! if let Some(data_path) = get_data_dir() {
//!     // Load configuration from data_path
//! }
//! ```

use directories::ProjectDirs;
use std::path::PathBuf;

pub fn get_data_dir() -> Option<PathBuf> {
    ProjectDirs::from("com", "drfw", "drfw").map(|pd| pd.data_dir().to_path_buf())
}

pub fn get_state_dir() -> Option<PathBuf> {
    ProjectDirs::from("com", "drfw", "drfw")
        .and_then(|pd| pd.state_dir().map(std::path::Path::to_path_buf))
}

pub fn ensure_dirs() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = DirBuilder::new();
        builder.mode(0o700); // User read/write/execute only
        builder.recursive(true);

        if let Some(dir) = get_data_dir() {
            builder.create(dir)?;
        }
        if let Some(dir) = get_state_dir() {
            builder.create(dir)?;
        }
    }

    #[cfg(not(unix))]
    {
        if let Some(dir) = get_data_dir() {
            std::fs::create_dir_all(dir)?;
        }
        if let Some(dir) = get_state_dir() {
            std::fs::create_dir_all(dir)?;
        }
    }

    Ok(())
}

/// Lists available network interfaces on the system
///
/// Uses the `network-interface` crate for robust cross-platform interface discovery.
/// Filters out the loopback interface (`lo`) since base firewall rules already handle it.
///
/// # Returns
///
/// A sorted vector of interface names (e.g., `["eth0", "wlan0"]`)
pub fn list_interfaces() -> Vec<String> {
    use network_interface::{NetworkInterface, NetworkInterfaceConfig};

    let mut interfaces: Vec<String> = NetworkInterface::show()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|iface| {
            // Filter out loopback (already handled by base rules)
            if iface.name != "lo" {
                Some(iface.name)
            } else {
                None
            }
        })
        .collect();

    interfaces.sort();
    interfaces
}

/// Executes an async function in a blocking context.
///
/// This is a utility wrapper for running async code from synchronous contexts,
/// typically during application startup before the main async runtime is available.
///
/// # Behavior
///
/// - **If called within a Tokio runtime context:** Uses the current runtime's handle
/// - **Otherwise:** Creates a temporary runtime (shouldn't happen in practice)
///
/// # Panics
///
/// Panics if unable to create a Tokio runtime (extremely rare, indicates system
/// resource exhaustion).
///
/// # Usage
///
/// This should **only** be used in synchronous wrapper functions like
/// `load_config_blocking()`, `load_profile_blocking()`, etc. All other code
/// should use async/await directly.
///
/// # Example
///
/// ```no_run
/// use drfw::utils::block_on_async;
///
/// async fn fetch_data() -> String {
///     // ... async operations ...
///     String::from("data")
/// }
///
/// pub fn fetch_data_blocking() -> String {
///     block_on_async(fetch_data())
/// }
/// ```
pub fn block_on_async<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.block_on(future)
    } else {
        // Fallback: create temporary runtime (shouldn't happen in practice)
        tokio::runtime::Runtime::new()
            .expect("Failed to create Tokio runtime")
            .block_on(future)
    }
}
