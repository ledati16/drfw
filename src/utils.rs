//! Utility functions for directory management and system integration
//!
//! This module provides helper functions following the XDG Base Directory specification
//! for portable configuration and data storage across Linux distributions.
//!
//! # Directory Structure
//!
//! - Config: `~/.config/drfw/` - User configuration files
//! - Data: `~/.local/share/drfw/` - Application data (saved rulesets)
//! - State: `~/.local/state/drfw/` - Runtime state (audit logs, GUI log)
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
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    cfg_select! {
        unix => {
            // User read/write/execute only
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        }
        _ => {}
    }

    if let Some(dir) = get_data_dir() {
        builder.create(dir)?;
    }
    if let Some(dir) = get_state_dir() {
        builder.create(dir)?;
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

/// Returns the lowercase hexadecimal SHA-256 digest of `data`.
///
/// Produces the same 64-character lowercase hex string that `sha2` 0.10's
/// `format!("{:x}", hasher.finalize())` did, so existing `.sha256` checksum
/// files on disk remain valid.
///
/// # Example
///
/// ```
/// use drfw::utils::sha256_hex;
///
/// assert_eq!(
///     sha256_hex(b"abc"),
///     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
/// );
/// ```
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;

    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in &digest {
        // Writing to a `String` cannot fail
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Truncates `s` to at most `max_bytes` bytes without splitting a UTF-8 character.
///
/// Slicing a `&str` at an arbitrary byte index panics when the index falls inside
/// a multibyte character (e.g. `é`, `日`, emoji). This rounds the cut point down
/// to the nearest character boundary instead, so the result may be slightly
/// shorter than `max_bytes`. Strings already within the limit are returned whole.
///
/// The limit is in bytes (not characters) so the result is never longer than the
/// space reserved for it; callers append their own ellipsis.
///
/// # Example
///
/// ```
/// use drfw::utils::truncate_str;
///
/// assert_eq!(truncate_str("firewall", 4), "fire");
/// assert_eq!(truncate_str("short", 64), "short");
/// // "é" is 2 bytes; cutting at byte 2 would split it, so the cut moves back
/// assert_eq!(truncate_str("aé", 2), "a");
/// ```
pub fn truncate_str(s: &str, max_bytes: usize) -> &str {
    &s[..s.floor_char_boundary(max_bytes)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_truncate_str_ascii() {
        assert_eq!(truncate_str("hello world", 5), "hello");
        assert_eq!(truncate_str("hello", 5), "hello");
        assert_eq!(truncate_str("hello", 100), "hello");
        assert_eq!(truncate_str("hello", 0), "");
        assert_eq!(truncate_str("", 10), "");
    }

    #[test]
    fn test_truncate_str_multibyte_never_splits() {
        // 'é' = 2 bytes, '日' = 3 bytes, '🔥' = 4 bytes
        let s = "aé日🔥b";
        assert_eq!(s.len(), 11);
        let expected = [
            "",
            "a",
            "a",
            "aé",
            "aé",
            "aé",
            "aé日",
            "aé日",
            "aé日",
            "aé日",
            "aé日🔥",
        ];
        for (max, want) in expected.iter().enumerate() {
            assert_eq!(truncate_str(s, max), *want, "max_bytes = {max}");
        }
        assert_eq!(truncate_str(s, 11), s);
    }

    #[test]
    fn test_truncate_str_all_cut_points_valid() {
        let s = "Ошибка: нет доступа 🚫 — ファイアウォール";
        for max in 0..=s.len() + 2 {
            let out = truncate_str(s, max);
            assert!(out.len() <= max);
            assert!(s.starts_with(out));
        }
    }
}
