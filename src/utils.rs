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

/// Opens a native save file dialog
///
/// Returns the chosen path, or `None` if user cancelled the dialog.
///
/// # Arguments
///
/// * `default_name` - Default filename to suggest
/// * `extension` - File extension (e.g., "json", "nft")
///
/// # Example
///
/// ```no_run
/// use drfw::utils::pick_save_path;
///
/// if let Some(path) = pick_save_path("rules.json", "json") {
///     // User selected a path
/// } else {
///     // User cancelled dialog
/// }
/// ```
pub fn pick_save_path(default_name: &str, extension: &str) -> Option<std::path::PathBuf> {
    rfd::FileDialog::new()
        .set_file_name(default_name)
        .add_filter(extension, &[extension])
        .save_file()
}

/// Truncates a string to a maximum length and adds an ellipsis if needed
#[allow(dead_code)]
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Find the nearest character boundary to avoid splitting multi-byte characters
        let end = s
            .char_indices()
            .map(|(idx, _)| idx)
            .take_while(|&idx| idx <= max_len.saturating_sub(3))
            .last()
            .unwrap_or(0);
        format!("{}...", &s[..end])
    }
}
