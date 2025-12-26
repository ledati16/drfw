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

pub fn list_interfaces() -> Vec<String> {
    let mut interfaces = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                // Ignore loopback usually, but maybe keep it as an option?
                // Most users don't need to add rules for 'lo' since we have a base rule.
                if name != "lo" {
                    interfaces.push(name);
                }
            }
        }
    }
    interfaces.sort();
    interfaces
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
