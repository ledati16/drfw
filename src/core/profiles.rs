//! Firewall profile management
//!
//! Profiles are standalone JSON files containing a `FirewallRuleset` plus a
//! format `version`. They are stored in the application's data directory under
//! `profiles/` (mode 0700; files 0600).
//!
//! # Safety of user data
//!
//! - Saves are atomic (unique temp file + rename) and serialized within the
//!   process, so a crash, a full disk or two overlapping saves never leave a
//!   half-written profile.
//! - Create and rename never replace an existing profile (names are compared
//!   case-insensitively, and the rename itself uses no-replace semantics).
//! - A profile that cannot be read (corrupt, written by a newer DRFW, too
//!   large) is reported with a specific [`ProfileError`]; the GUI copies it
//!   aside with [`preserve_unreadable_profile`] before doing anything else.
//!
//! # Concurrent Access
//!
//! Profile functions are **not** safe for concurrent access from multiple processes.
//! Running multiple DRFW instances simultaneously may cause data loss.

use crate::core::firewall::{FirewallRuleset, MAX_RULES};
use crate::utils::get_data_dir;
use std::path::PathBuf;

/// The canonical name for the initial/fallback profile.
/// This profile is protected from deletion and renaming to ensure the system
/// always has at least one valid policy file to load.
pub const DEFAULT_PROFILE_NAME: &str = "default";

/// Profile format version written by this build.
///
/// Version 1 is the original format (files without a `version` field are
/// version 1). Bump this when a change makes older builds misread new files.
pub const PROFILE_FORMAT_VERSION: u32 = 1;

/// Largest profile file accepted, in bytes. [`MAX_RULES`] fully-featured rules
/// fit comfortably; anything larger is not a profile DRFW wrote.
pub const MAX_PROFILE_BYTES: u64 = 32 * 1024 * 1024;

/// Serializes profile writes within this process so that an older snapshot
/// can never be renamed over a newer one (e.g. autosave vs. "save & switch").
static SAVE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Error type for profile operations
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("Invalid profile name: {0}")]
    InvalidName(String),

    #[error("Profile not found: {0}")]
    NotFound(String),

    #[error("A profile named '{0}' already exists")]
    AlreadyExists(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The file exists but is not a valid profile (JSON syntax error, wrong
    /// field types, unknown values).
    #[error("Profile '{name}' is damaged and cannot be read ({reason})")]
    Corrupt { name: String, reason: String },

    /// The file was written by a newer DRFW with a format this build does not know.
    #[error(
        "Profile '{name}' was saved by a newer version of DRFW (format {found}; this version supports up to {supported}). Update DRFW to open it."
    )]
    UnsupportedVersion {
        name: String,
        found: u32,
        supported: u32,
    },

    #[error("Profile '{name}' is too large ({bytes} bytes, maximum {limit})")]
    TooLarge {
        name: String,
        bytes: u64,
        limit: u64,
    },

    #[error("Data directory not available")]
    DataDirUnavailable,

    #[error("Rule limit exceeded: {current} rules (maximum: {limit})")]
    RuleLimitExceeded { current: usize, limit: usize },
}

impl ProfileError {
    /// `true` when the profile file exists but its content cannot be used
    /// (corrupt, newer version, too large, too many rules). Such a file must
    /// never be overwritten by an empty default; see
    /// [`preserve_unreadable_profile`].
    pub fn is_unreadable_content(&self) -> bool {
        matches!(
            self,
            Self::Corrupt { .. }
                | Self::UnsupportedVersion { .. }
                | Self::TooLarge { .. }
                | Self::RuleLimitExceeded { .. }
        )
    }
}

/// Validates a profile name for filesystem safety.
///
/// Constraints:
/// - Alphanumeric, underscores, and hyphens only: Prevents shell injection and
///   cross-platform filename issues.
/// - Max 20 chars: Allows descriptive names while staying reasonable for UI display.
/// - Rejects "." and "..": Critical path traversal protection.
///
/// # Errors
///
/// Returns [`ProfileError::InvalidName`] (with the reason) if any constraint
/// is violated.
pub fn validate_profile_name(name: &str) -> Result<(), ProfileError> {
    if name.is_empty() {
        return Err(ProfileError::InvalidName("Name cannot be empty".into()));
    }

    if name.len() > 20 {
        return Err(ProfileError::InvalidName(
            "Name too long (max 20 chars)".into(),
        ));
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ProfileError::InvalidName(
            "Name contains invalid characters (use only a-z, 0-9, _, -)".into(),
        ));
    }

    // Prevent path traversal
    if name == "." || name == ".." {
        return Err(ProfileError::InvalidName("Invalid name".into()));
    }

    Ok(())
}

/// Returns the existing profile whose name equals `name` ignoring ASCII case,
/// skipping `except` (the profile being renamed, so "Work" → "work" is allowed).
///
/// Profile names are case-sensitive on Linux, but two profiles that differ only
/// in case are confusing and collide on case-insensitive filesystems.
///
/// # Example
///
/// ```
/// use drfw::core::profiles::find_name_conflict;
///
/// let existing = vec!["default".to_string(), "Work".to_string()];
/// assert_eq!(find_name_conflict(&existing, "work", None), Some("Work"));
/// assert_eq!(find_name_conflict(&existing, "work", Some("Work")), None);
/// assert_eq!(find_name_conflict(&existing, "home", None), None);
/// ```
pub fn find_name_conflict<'a>(
    existing: &'a [String],
    name: &str,
    except: Option<&str>,
) -> Option<&'a str> {
    existing
        .iter()
        .map(String::as_str)
        .filter(|e| Some(*e) != except)
        .find(|e| e.eq_ignore_ascii_case(name))
}

/// Gets the directory where profiles are stored, creating it (mode 0700) if
/// it doesn't exist.
///
/// # Async
/// Uses `tokio::fs` for non-blocking I/O.
///
/// # Errors
///
/// Returns [`ProfileError::DataDirUnavailable`] if there is no data directory,
/// or [`ProfileError::Io`] if the directory cannot be checked or created.
pub async fn get_profiles_dir() -> Result<PathBuf, ProfileError> {
    let mut path = get_data_dir().ok_or(ProfileError::DataDirUnavailable)?;
    path.push("profiles");

    if !tokio::fs::try_exists(&path).await? {
        let mut builder = tokio::fs::DirBuilder::new();
        builder.recursive(true);
        cfg_select! {
            unix => {
                builder.mode(0o700);
            }
            _ => {}
        }
        builder.create(&path).await?;
    }

    Ok(path)
}

/// Returns the path to a specific profile file.
/// Validates the name first to prevent directory traversal attacks before file access.
///
/// # Async
/// Uses `tokio::fs` for non-blocking directory operations.
///
/// # Errors
///
/// Returns [`ProfileError::InvalidName`] for an invalid `name`, or the errors
/// of [`get_profiles_dir`].
pub async fn get_profile_path(name: &str) -> Result<PathBuf, ProfileError> {
    validate_profile_name(name)?;
    let mut path = get_profiles_dir().await?;
    path.push(format!("{name}.json"));
    Ok(path)
}

/// Lists all available profile names, sorted.
///
/// Files whose stem is not a valid profile name (e.g. `my profile.json`) are
/// skipped with a warning: they could never be loaded, so offering them would
/// only produce a selection that silently does nothing.
///
/// # Async
/// Uses `tokio::fs` for non-blocking directory scanning.
///
/// # Errors
///
/// Returns the errors of [`get_profiles_dir`], or [`ProfileError::Io`] if
/// the directory cannot be read.
pub async fn list_profiles() -> Result<Vec<String>, ProfileError> {
    let dir = get_profiles_dir().await?;
    let mut profiles = Vec::new();

    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();

        if path.is_file()
            && path.extension().and_then(|s| s.to_str()) == Some("json")
            && let Some(name) = path.file_stem().and_then(|s| s.to_str())
        {
            if let Err(e) = validate_profile_name(name) {
                tracing::warn!("Ignoring profile file '{}': {e}", path.display());
                continue;
            }
            profiles.push(name.to_string());
        }
    }

    profiles.sort();
    Ok(profiles)
}

/// Only the `version` field, read before the full parse so a newer profile is
/// reported as "newer" even when it also contains values this build can't parse.
#[derive(serde::Deserialize)]
struct VersionProbe {
    #[serde(default = "default_version")]
    version: u32,
}

fn default_version() -> u32 {
    1
}

/// On-disk form written by [`save_profile`]: the ruleset plus its format version.
#[derive(serde::Serialize)]
struct ProfileFileRef<'a> {
    version: u32,
    #[serde(flatten)]
    ruleset: &'a FirewallRuleset,
}

/// Parses profile JSON (`name` is only used in error messages).
///
/// Checks the format version first, then the content, then the rule count, and
/// finally normalizes the result (see [`FirewallRuleset::normalize_loaded`]).
///
/// # Errors
///
/// [`ProfileError::UnsupportedVersion`], [`ProfileError::Corrupt`] or
/// [`ProfileError::RuleLimitExceeded`].
pub fn parse_profile(name: &str, json: &str) -> Result<FirewallRuleset, ProfileError> {
    let corrupt = |e: serde_json::Error| ProfileError::Corrupt {
        name: name.to_string(),
        reason: e.to_string(),
    };

    let probe: VersionProbe = serde_json::from_str(json).map_err(corrupt)?;
    if probe.version > PROFILE_FORMAT_VERSION {
        return Err(ProfileError::UnsupportedVersion {
            name: name.to_string(),
            found: probe.version,
            supported: PROFILE_FORMAT_VERSION,
        });
    }

    let mut ruleset: FirewallRuleset = serde_json::from_str(json).map_err(corrupt)?;

    // Validate rule count to prevent memory exhaustion
    if ruleset.rules.len() > MAX_RULES {
        return Err(ProfileError::RuleLimitExceeded {
            current: ruleset.rules.len(),
            limit: MAX_RULES,
        });
    }

    let regenerated = ruleset.normalize_loaded();
    if regenerated > 0 {
        tracing::warn!("Profile '{name}': regenerated {regenerated} duplicate rule id(s)");
    }

    Ok(ruleset)
}

/// Loads a profile by name.
///
/// Invalid rules are kept (nothing is dropped); use
/// [`FirewallRuleset::validate`] to find them. Duplicate rule ids are
/// regenerated, labels and tags are sanitized, and caches are rebuilt.
///
/// # Errors
///
/// - [`ProfileError::NotFound`] if the file does not exist,
/// - [`ProfileError::TooLarge`], [`ProfileError::Corrupt`],
///   [`ProfileError::UnsupportedVersion`], [`ProfileError::RuleLimitExceeded`]
///   if it exists but cannot be used ([`ProfileError::is_unreadable_content`]),
/// - [`ProfileError::Io`] / [`ProfileError::InvalidName`] otherwise.
///
/// # Async
/// Uses `tokio::fs` for non-blocking file I/O.
pub async fn load_profile(name: &str) -> Result<FirewallRuleset, ProfileError> {
    let path = get_profile_path(name).await?;

    let metadata = match tokio::fs::metadata(&path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ProfileError::NotFound(name.to_string()));
        }
        Err(e) => return Err(e.into()),
    };
    if metadata.len() > MAX_PROFILE_BYTES {
        return Err(ProfileError::TooLarge {
            name: name.to_string(),
            bytes: metadata.len(),
            limit: MAX_PROFILE_BYTES,
        });
    }

    let bytes = tokio::fs::read(&path).await?;
    let json = String::from_utf8(bytes).map_err(|e| ProfileError::Corrupt {
        name: name.to_string(),
        reason: e.to_string(),
    })?;
    parse_profile(name, &json)
}

/// Copies an unreadable profile to `<name>.json.corrupt-<UTC timestamp>`
/// (mode 0600, never overwriting) and returns the copy's path.
///
/// Call this before falling back to an empty ruleset for a profile whose load
/// failed with [`ProfileError::is_unreadable_content`], so the user's data
/// survives any later save. The copy's name does not end in `.json`, so it is
/// not listed as a profile.
///
/// # Errors
///
/// Returns `Err` if the profile cannot be read or the copy cannot be written.
pub async fn preserve_unreadable_profile(name: &str) -> Result<PathBuf, ProfileError> {
    let path = get_profile_path(name).await?;
    let copy = tokio::task::spawn_blocking(move || crate::utils::preserve_unreadable_file(&path))
        .await
        .map_err(std::io::Error::other)??;
    Ok(copy)
}

/// Removes a `<profile>.json.sha256` file left behind by older versions
/// (profile checksums were removed; they provided no protection).
async fn remove_legacy_checksum(path: &std::path::Path) {
    let mut checksum = path.as_os_str().to_owned();
    checksum.push(".sha256");
    match tokio::fs::remove_file(&checksum).await {
        Ok(()) => tracing::debug!("Removed legacy checksum {:?}", checksum),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("Failed to remove legacy checksum {:?}: {e}", checksum),
    }
}

/// Serializes `ruleset` in the on-disk profile format (with `version`).
fn profile_json(ruleset: &FirewallRuleset) -> Result<Vec<u8>, ProfileError> {
    Ok(serde_json::to_vec_pretty(&ProfileFileRef {
        version: PROFILE_FORMAT_VERSION,
        ruleset,
    })?)
}

/// Saves a profile atomically, replacing any existing file with that name.
///
/// Uses a unique temporary file + rename so a crash or a full disk never
/// corrupts the profile; saves within the process are serialized so an older
/// snapshot can never overwrite a newer one. Writes the current
/// [`PROFILE_FORMAT_VERSION`] and removes a stale legacy `.sha256` file.
///
/// # Security
///
/// On Unix systems, files are created with mode 0o600 (user read/write only).
/// On Windows, files inherit directory permissions. Users should ensure the
/// profiles directory has appropriate ACLs: `%LOCALAPPDATA%\drfw\drfw\data\profiles`
///
/// # Errors
///
/// Returns `Err` on invalid names, serialization or I/O failure (a full disk
/// is reported with a readable message).
pub async fn save_profile(name: &str, ruleset: &FirewallRuleset) -> Result<(), ProfileError> {
    let path = get_profile_path(name).await?;
    let json = profile_json(ruleset)?;

    let _guard = SAVE_LOCK.lock().await;
    crate::utils::write_atomic_private_async(path.clone(), json).await?;
    remove_legacy_checksum(&path).await;
    Ok(())
}

/// Creates a new profile; never replaces an existing one.
///
/// # Errors
///
/// [`ProfileError::AlreadyExists`] if a profile with the same name (ignoring
/// case) exists, plus the errors of [`save_profile`].
pub async fn create_profile(name: &str, ruleset: &FirewallRuleset) -> Result<(), ProfileError> {
    let path = get_profile_path(name).await?;
    let existing = list_profiles().await?;
    if let Some(conflict) = find_name_conflict(&existing, name, None) {
        return Err(ProfileError::AlreadyExists(conflict.to_string()));
    }
    let json = profile_json(ruleset)?;
    let name_owned = name.to_string();

    let _guard = SAVE_LOCK.lock().await;
    tokio::task::spawn_blocking(move || -> Result<(), ProfileError> {
        use std::io::Write;
        let dir = path
            .parent()
            .ok_or_else(|| std::io::Error::other("profile path has no parent"))?;
        let mut temp = tempfile::Builder::new()
            .prefix(".drfw-")
            .suffix(".tmp")
            .tempfile_in(dir)?;
        temp.write_all(&json)?;
        temp.as_file().sync_all()?;
        // persist_noclobber fails instead of replacing an existing file
        temp.persist_noclobber(&path).map_err(|e| {
            if e.error.kind() == std::io::ErrorKind::AlreadyExists {
                ProfileError::AlreadyExists(name_owned)
            } else {
                e.error.into()
            }
        })?;
        Ok(())
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Deletes a profile.
///
/// # Business Logic Validation
///
/// This function only performs the file deletion. The caller is responsible for:
/// - Ensuring this isn't the last profile (system must have ≥1 profile)
/// - Ensuring this isn't the currently active profile (must switch first)
/// - Updating application state after deletion
///
/// # Errors
///
/// [`ProfileError::NotFound`] if the profile does not exist, or an I/O error.
pub async fn delete_profile(name: &str) -> Result<(), ProfileError> {
    let path = get_profile_path(name).await?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ProfileError::NotFound(name.to_string()));
        }
        Err(e) => return Err(e.into()),
    }
    remove_legacy_checksum(&path).await;
    Ok(())
}

/// Renames `old` to `new` without ever replacing an existing file.
///
/// Uses `renameat2(RENAME_NOREPLACE)` on Linux; where that is unavailable
/// (other platforms, filesystems without support), falls back to hard-link +
/// unlink, which also fails if the target exists.
fn rename_no_replace(old: &std::path::Path, new: &std::path::Path) -> std::io::Result<()> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        use nix::errno::Errno;
        use nix::fcntl::{AT_FDCWD, RenameFlags, renameat2};
        match renameat2(AT_FDCWD, old, AT_FDCWD, new, RenameFlags::RENAME_NOREPLACE) {
            Ok(()) => return Ok(()),
            // Not supported by this kernel/filesystem: use the fallback
            Err(Errno::EINVAL | Errno::ENOSYS | Errno::EOPNOTSUPP) => {}
            Err(e) => return Err(e.into()),
        }
    }
    std::fs::hard_link(old, new)?;
    std::fs::remove_file(old)
}

/// Renames a profile.
///
/// # Errors
///
/// - [`ProfileError::InvalidName`] for an invalid new name,
/// - [`ProfileError::NotFound`] if `old_name` does not exist,
/// - [`ProfileError::AlreadyExists`] if another profile already has the new
///   name (ignoring case); the existing profile is never replaced.
///
/// # Business Logic Validation
///
/// The caller is responsible for:
/// - Updating config if renaming the active profile
/// - Updating UI state after rename
pub async fn rename_profile(old_name: &str, new_name: &str) -> Result<(), ProfileError> {
    validate_profile_name(new_name)?;

    let old_path = get_profile_path(old_name).await?;
    let new_path = get_profile_path(new_name).await?;

    if !tokio::fs::try_exists(&old_path).await? {
        return Err(ProfileError::NotFound(old_name.to_string()));
    }
    let existing = list_profiles().await?;
    if let Some(conflict) = find_name_conflict(&existing, new_name, Some(old_name)) {
        return Err(ProfileError::AlreadyExists(conflict.to_string()));
    }

    let _guard = SAVE_LOCK.lock().await;
    let (from, to) = (old_path.clone(), new_path);
    tokio::task::spawn_blocking(move || rename_no_replace(&from, &to))
        .await
        .map_err(std::io::Error::other)?
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                ProfileError::AlreadyExists(new_name.to_string())
            } else {
                e.into()
            }
        })?;
    remove_legacy_checksum(&old_path).await;
    Ok(())
}

/// Ensures at least one profile exists, creating a default if none found, and
/// removes legacy `.sha256` profile checksum files.
///
/// This is a defensive measure for:
/// - First run (no profiles directory yet)
/// - Manual deletion of all profiles
///
/// # Async
/// Uses `tokio::fs` for non-blocking file I/O.
///
/// # Errors
///
/// Returns the errors of [`list_profiles`], or of [`save_profile`] when the
/// default profile has to be created. A failed legacy-checksum cleanup is
/// only logged.
pub async fn ensure_profile_exists() -> Result<(), ProfileError> {
    let profiles = list_profiles().await?;

    if profiles.is_empty() {
        tracing::warn!("No profiles found, creating default profile");
        save_profile(DEFAULT_PROFILE_NAME, &FirewallRuleset::default()).await?;
    }

    if let Err(e) = remove_legacy_checksums().await {
        tracing::warn!("Failed to clean up legacy profile checksums: {e}");
    }

    Ok(())
}

/// Removes every `*.json.sha256` file in the profiles directory (written by
/// versions that had profile checksums).
async fn remove_legacy_checksums() -> Result<usize, ProfileError> {
    let dir = get_profiles_dir().await?;
    let mut entries = tokio::fs::read_dir(&dir).await?;
    let mut removed = 0;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".json.sha256"))
        {
            tokio::fs::remove_file(&path).await?;
            removed += 1;
        }
    }
    if removed > 0 {
        tracing::info!("Removed {removed} legacy profile checksum file(s)");
    }
    Ok(removed)
}

/// A profile that exists but could not be loaded.
///
/// Returned by [`load_profile_or_preserve`]; the GUI opens such a profile
/// read-only (empty, autosave disabled) until the user switches profile or
/// chooses "start fresh".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableProfile {
    /// Profile name
    pub name: String,
    /// Why it could not be loaded (user-facing)
    pub reason: String,
    /// Where the original was copied to, if the copy succeeded
    pub backup: Option<PathBuf>,
}

impl UnreadableProfile {
    /// User-facing explanation for the error banner and the read-only notice.
    pub fn user_message(&self) -> String {
        let copy = match &self.backup {
            Some(path) => format!("A copy of the file was saved to {}.", path.display()),
            None => "The file was left untouched (a backup copy could not be made).".to_string(),
        };
        format!(
            "{} {copy} The profile is open read-only: switch profiles, or choose \
             \"Start fresh\" to replace it with an empty profile.",
            self.reason
        )
    }
}

/// Loads a profile for editing, protecting the file if it cannot be read.
///
/// - Loads normally when possible.
/// - A missing profile is the normal default path: returns an empty ruleset.
/// - Any other failure returns [`UnreadableProfile`]; if the content is
///   unreadable ([`ProfileError::is_unreadable_content`]), the file is first
///   copied aside with [`preserve_unreadable_profile`]. The caller must not
///   save over that profile until the user explicitly agrees.
///
/// # Errors
///
/// Returns [`UnreadableProfile`] for every failure except "not found".
pub async fn load_profile_or_preserve(name: &str) -> Result<FirewallRuleset, UnreadableProfile> {
    match load_profile(name).await {
        Ok(ruleset) => Ok(ruleset),
        Err(ProfileError::NotFound(_)) => Ok(FirewallRuleset::default()),
        Err(e) => {
            tracing::error!("Failed to load profile '{name}': {e}");
            let backup = if e.is_unreadable_content() {
                match preserve_unreadable_profile(name).await {
                    Ok(path) => {
                        tracing::warn!("Copied unreadable profile '{name}' to {}", path.display());
                        Some(path)
                    }
                    Err(copy_err) => {
                        tracing::error!("Could not copy unreadable profile '{name}': {copy_err}");
                        None
                    }
                }
            } else {
                None
            };
            Err(UnreadableProfile {
                name: name.to_string(),
                reason: e.to_string(),
                backup,
            })
        }
    }
}

/// Synchronous wrapper for `ensure_profile_exists()` for use during startup initialization.
///
/// This blocks the current thread and should only be used in `State::new()` where
/// async initialization isn't possible.
///
/// # Errors
///
/// Same as [`ensure_profile_exists`].
pub fn ensure_profile_exists_blocking() -> Result<(), ProfileError> {
    crate::utils::block_on_async(ensure_profile_exists())
}

/// Synchronous wrapper for `list_profiles()` for use during startup initialization.
///
/// This blocks the current thread and should only be used in `State::new()` where
/// async initialization isn't possible. Everywhere else should use async `list_profiles()`.
///
/// # Errors
///
/// Same as [`list_profiles`].
pub fn list_profiles_blocking() -> Result<Vec<String>, ProfileError> {
    crate::utils::block_on_async(list_profiles())
}

/// Synchronous wrapper for [`load_profile_or_preserve`] for use during startup
/// initialization (`State::new()`).
///
/// # Errors
///
/// See [`load_profile_or_preserve`].
pub fn load_profile_or_preserve_blocking(name: &str) -> Result<FirewallRuleset, UnreadableProfile> {
    crate::utils::block_on_async(load_profile_or_preserve(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_profile_without_version_is_v1() {
        let json = r#"{ "rules": [] }"#;
        assert_eq!(parse_profile("p", json).unwrap().rules.len(), 0);
    }

    #[test]
    fn test_parse_profile_newer_version_refused_even_if_unparseable() {
        // A newer version may also contain values this build can't parse;
        // the version message must win over the generic "corrupt" one.
        let json = r#"{ "version": 99, "rules": [{"protocol": "Sctp"}] }"#;
        let err = parse_profile("p", json).unwrap_err();
        assert!(
            matches!(err, ProfileError::UnsupportedVersion { found: 99, .. }),
            "{err:?}"
        );
        assert!(err.is_unreadable_content());
        assert!(err.to_string().contains("newer version"));
    }

    #[test]
    fn test_parse_profile_corrupt() {
        let err = parse_profile("p", "{ not json").unwrap_err();
        assert!(matches!(err, ProfileError::Corrupt { .. }));
        assert!(err.is_unreadable_content());
        // An unknown enum value at the current version is corrupt, not "newer"
        let err = parse_profile(
            "p",
            r#"{ "rules": [{ "id": "00000000-0000-0000-0000-000000000001", "label": "x",
                 "protocol": "Sctp", "interface": null,
                 "created_at": "2026-01-01T00:00:00Z" }] }"#,
        )
        .unwrap_err();
        assert!(matches!(err, ProfileError::Corrupt { .. }), "{err:?}");
    }

    #[test]
    fn test_profile_json_round_trip_writes_version() {
        let ruleset = crate::core::test_helpers::create_test_ruleset();
        let json = String::from_utf8(profile_json(&ruleset).unwrap()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["version"], PROFILE_FORMAT_VERSION);
        let loaded = parse_profile("p", &json).unwrap();
        assert_eq!(loaded.rules, ruleset.rules);
    }

    #[test]
    fn test_rename_no_replace_keeps_existing_target() {
        let tmp = tempfile::tempdir().unwrap();
        let alpha = tmp.path().join("alpha.json");
        let beta = tmp.path().join("beta.json");
        std::fs::write(&alpha, "alpha").unwrap();
        std::fs::write(&beta, "beta").unwrap();

        let err = rename_no_replace(&alpha, &beta).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&alpha).unwrap(), "alpha");
        assert_eq!(std::fs::read_to_string(&beta).unwrap(), "beta");

        let gamma = tmp.path().join("gamma.json");
        rename_no_replace(&alpha, &gamma).unwrap();
        assert!(!alpha.exists());
        assert_eq!(std::fs::read_to_string(&gamma).unwrap(), "alpha");
    }

    #[test]
    fn test_unreadable_profile_message_mentions_copy() {
        let issue = UnreadableProfile {
            name: "p".into(),
            reason: "Profile 'p' is damaged".into(),
            backup: Some(PathBuf::from("/x/p.json.corrupt-1")),
        };
        let msg = issue.user_message();
        assert!(msg.contains("/x/p.json.corrupt-1"));
        assert!(msg.contains("read-only"));
    }
}
