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

/// Returns the application data directory.
///
/// Normally returns `~/.local/share/drfw/` (XDG Base Directory spec).
///
/// # Test Override
///
/// Set `DRFW_TEST_DATA_DIR` environment variable to override the data directory
/// for testing. This allows tests to use a temporary directory instead of
/// the user's real data directory.
pub fn get_data_dir() -> Option<PathBuf> {
    // Allow tests to override data directory
    if let Ok(test_dir) = std::env::var("DRFW_TEST_DATA_DIR") {
        return Some(PathBuf::from(test_dir));
    }
    ProjectDirs::from("com", "drfw", "drfw").map(|pd| pd.data_dir().to_path_buf())
}

/// Returns the application state directory.
///
/// Normally returns `~/.local/state/drfw/` (XDG Base Directory spec).
///
/// # Test Override
///
/// Set `DRFW_TEST_STATE_DIR` environment variable to override the state directory
/// for testing. This allows tests to use a temporary directory instead of
/// the user's real state directory.
pub fn get_state_dir() -> Option<PathBuf> {
    // Allow tests to override state directory
    if let Ok(test_dir) = std::env::var("DRFW_TEST_STATE_DIR") {
        return Some(PathBuf::from(test_dir));
    }
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
/// Lists available network interfaces on the system (excluding loopback).
pub fn list_interfaces() -> Vec<String> {
    use network_interface::{NetworkInterface, NetworkInterfaceConfig};

    let mut interfaces: Vec<String> = NetworkInterface::show()
        .unwrap_or_default()
        .into_iter()
        // Filter out loopback (already handled by base rules)
        .filter(|iface| iface.name != "lo")
        .map(|iface| iface.name)
        .collect();

    interfaces.sort();
    interfaces
}

/// Builds interface suggestions for `combo_box` autocomplete.
///
/// Returns a list containing:
/// 1. System interfaces (from `list_interfaces()`)
/// 2. Wildcards for interface families that exist on the system
///
/// Wildcards are only added when matching interfaces are present.
pub fn build_interface_suggestions() -> Vec<String> {
    let mut suggestions = list_interfaces();

    // Common interface prefixes for wildcard matching
    let wildcard_prefixes = [
        "eth", "enp", "ens", "wlan", "wlp", "docker", "veth", "br", "virbr", "wg", "tun", "tap",
    ];

    // Only add wildcards for interface families that actually exist on the system
    for prefix in wildcard_prefixes {
        let has_matching = suggestions.iter().any(|s| s.starts_with(prefix));
        if has_matching {
            suggestions.push(format!("{prefix}*"));
        }
    }

    suggestions
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
