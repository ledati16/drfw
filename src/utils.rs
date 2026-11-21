//! Utility functions for directory management and system integration
//!
//! This module provides helper functions following the XDG Base Directory specification
//! for portable configuration and data storage across Linux distributions.
//!
//! # Directory Structure
//!
//! - Data: `~/.local/share/drfw/` - `config.json` and `profiles/` (0700)
//! - State: `~/.local/state/drfw/` - Runtime state (audit log, `drfw.log`) (0700)
//!
//! # Example
//!
//! ```no_run
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

/// Creates the application's data, state and profiles directories as private
/// (0700) directories, and tightens the mode of directories that already exist
/// (older versions created `profiles/` with the umask default, usually 0755).
///
/// # Errors
///
/// Returns `Err` if a directory cannot be created. Failing to tighten the
/// mode of an existing directory (e.g. not its owner) is only logged.
pub fn ensure_dirs() -> std::io::Result<()> {
    if let Some(dir) = get_data_dir() {
        ensure_private_dir(&dir)?;
        ensure_private_dir(&dir.join("profiles"))?;
    }
    if let Some(dir) = get_state_dir() {
        ensure_private_dir(&dir)?;
    }
    Ok(())
}

/// Creates `dir` (and missing parents) with mode 0700 and resets an existing
/// `dir` to 0700 if it is more permissive.
///
/// # Errors
///
/// Returns `Err` if the directory cannot be created.
pub fn ensure_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    cfg_select! {
        unix => {
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        }
        _ => {}
    }
    builder.create(dir)?;

    cfg_select! {
        unix => {
            let mode = std::os::unix::fs::PermissionsExt::mode(
                &std::fs::metadata(dir)?.permissions(),
            ) & 0o777;
            if mode != 0o700
                && let Err(e) = std::fs::set_permissions(
                    dir,
                    <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
                )
            {
                tracing::warn!("Could not restrict {} to 0700: {e}", dir.display());
            }
        }
        _ => {}
    }
    Ok(())
}

/// Atomically replaces `path` with `data`; the file is created with mode 0600.
///
/// Writes to a uniquely named temporary file in the same directory, syncs it
/// and renames it over `path`, so a crash or a full disk never leaves a
/// half-written file, and concurrent writers never share a temp file.
///
/// Blocking: call [`write_atomic_private_async`] from async code.
///
/// # Errors
///
/// Returns `Err` if the temp file cannot be created, written or renamed. A full
/// disk is reported as `StorageFull` with a user-readable message.
pub fn write_atomic_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    // NamedTempFile is created with 0600 on Unix before any data is written
    let mut temp = tempfile::Builder::new()
        .prefix(".drfw-")
        .suffix(".tmp")
        .tempfile_in(dir)?;
    let result = temp
        .write_all(data)
        .and_then(|()| temp.as_file().sync_all())
        .and_then(|()| temp.persist(path).map(|_| ()).map_err(|e| e.error));
    result.map_err(|e| {
        if e.kind() == std::io::ErrorKind::StorageFull {
            std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "Disk full. Free up space and try again.",
            )
        } else {
            e
        }
    })
}

/// Async wrapper for [`write_atomic_private`] (runs on the blocking pool).
///
/// # Errors
///
/// Same as [`write_atomic_private`].
pub async fn write_atomic_private_async(path: PathBuf, data: Vec<u8>) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || write_atomic_private(&path, &data))
        .await
        .map_err(std::io::Error::other)?
}

/// Copies an unreadable file (corrupt, from a newer version, too large) to
/// `<file>.corrupt-<UTC timestamp>` with mode 0600, never overwriting an
/// existing copy, and returns the copy's path.
///
/// Used before the app falls back to defaults, so the original content can
/// always be recovered even if the original file is later overwritten.
///
/// # Errors
///
/// Returns `Err` if the file cannot be read or the copy cannot be written.
pub fn preserve_unreadable_file(path: &std::path::Path) -> std::io::Result<PathBuf> {
    // Streamed, not read into memory: the file may be one rejected as too large
    let mut source = std::fs::File::open(path)?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let file_name = path
        .file_name()
        .map_or_default(|n| n.to_string_lossy().into_owned());

    for attempt in 0..100u32 {
        let suffix = if attempt == 0 {
            format!("{file_name}.corrupt-{stamp}")
        } else {
            format!("{file_name}.corrupt-{stamp}-{attempt}")
        };
        let target = path.with_file_name(suffix);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        cfg_select! {
            unix => {
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            }
            _ => {}
        }
        match options.open(&target) {
            Ok(mut file) => {
                std::io::copy(&mut source, &mut file)?;
                file.sync_all()?;
                return Ok(target);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "too many backup copies with the same timestamp",
    ))
}

/// Opens the application log file for appending, mode 0600.
///
/// If the file is larger than `max_bytes`, it is first renamed to `<file>.1`
/// (replacing an older `.1`), so at most one old log is kept. An existing log
/// with looser permissions (older versions used the umask) is tightened.
///
/// # Errors
///
/// Returns `Err` if the file cannot be opened.
pub fn open_private_log(path: &std::path::Path, max_bytes: u64) -> std::io::Result<std::fs::File> {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > max_bytes) {
        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        if let Err(e) = std::fs::rename(path, &rotated) {
            eprintln!("Failed to rotate {}: {e}", path.display());
        }
    }

    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    cfg_select! {
        unix => {
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        }
        _ => {}
    }
    let file = options.open(path)?;
    cfg_select! {
        unix => {
            let mode = std::os::unix::fs::PermissionsExt::mode(&file.metadata()?.permissions());
            if mode & 0o777 != 0o600 {
                file.set_permissions(
                    <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
                )?;
            }
        }
        _ => {}
    }
    Ok(file)
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
/// `load_config_checked_blocking()`, `load_profile_or_preserve_blocking()`, etc. All other code
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
/// `format!("{:x}", hasher.finalize())` did, so existing snapshot checksums
/// remain valid.
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

    #[cfg(unix)]
    fn mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_private_dir_creates_and_fixes_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("a").join("b");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn test_write_atomic_private_mode_and_replace() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("x.json");
        write_atomic_private(&path, b"one").unwrap();
        write_atomic_private(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(mode(&path), 0o600);
        // No temp files left behind
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn test_preserve_unreadable_file_never_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("p.json");
        std::fs::write(&path, b"{broken").unwrap();
        let first = preserve_unreadable_file(&path).unwrap();
        let second = preserve_unreadable_file(&path).unwrap();
        assert_ne!(first, second);
        for copy in [&first, &second] {
            assert_eq!(std::fs::read(copy).unwrap(), b"{broken");
            assert_eq!(mode(copy), 0o600);
            let name = copy.file_name().unwrap().to_string_lossy().into_owned();
            assert!(name.starts_with("p.json.corrupt-"), "{name}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_open_private_log_appends_rotates_and_fixes_mode() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("drfw.log");
        std::fs::write(&path, b"old line\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mut file = open_private_log(&path, 1024).unwrap();
        file.write_all(b"new line\n").unwrap();
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), b"old line\nnew line\n");
        assert_eq!(mode(&path), 0o600);

        // Over the limit: moved to .1, fresh file started
        let file = open_private_log(&path, 4).unwrap();
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        assert_eq!(
            std::fs::read(tmp.path().join("drfw.log.1")).unwrap(),
            b"old line\nnew line\n"
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
