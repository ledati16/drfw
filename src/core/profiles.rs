//! Firewall profile management
//!
//! Profiles are standalone JSON files containing a `FirewallRuleset`.
//! They are stored in the application's data directory under `profiles/`.

use crate::core::firewall::FirewallRuleset;
use crate::utils::get_data_dir;
use std::path::PathBuf;

/// The canonical name for the initial/fallback profile.
/// This profile is protected from deletion and renaming to ensure the system
/// always has at least one valid policy file to load.
pub const DEFAULT_PROFILE_NAME: &str = "default";

/// Error type for profile operations
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("Invalid profile name: {0}")]
    InvalidName(String),

    #[error("Profile not found: {0}")]
    NotFound(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Data directory not available")]
    DataDirUnavailable,
}

/// Validates a profile name for filesystem safety.
///
/// Constraints:
/// - Alphanumeric, underscores, and hyphens only: Prevents shell injection and
///   cross-platform filename issues.
/// - Max 64 chars: Ensures filenames stay within system limits (typically 255)
///   while allowing descriptive names.
/// - Rejects "." and "..": Critical path traversal protection.
pub fn validate_profile_name(name: &str) -> Result<(), ProfileError> {
    if name.is_empty() {
        return Err(ProfileError::InvalidName("Name cannot be empty".into()));
    }

    if name.len() > 64 {
        return Err(ProfileError::InvalidName(
            "Name too long (max 64 chars)".into(),
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

/// Gets the directory where profiles are stored.
/// Creates the directory if it doesn't exist to ensure subsequent file operations succeed.
///
/// # Async
/// Uses `tokio::fs` for non-blocking I/O.
pub async fn get_profiles_dir() -> Result<PathBuf, ProfileError> {
    let mut path = get_data_dir().ok_or(ProfileError::DataDirUnavailable)?;
    path.push("profiles");

    if !tokio::fs::try_exists(&path).await? {
        tokio::fs::create_dir_all(&path).await?;
    }

    Ok(path)
}

/// Returns the path to a specific profile file.
/// Validates the name first to prevent directory traversal attacks before file access.
///
/// # Async
/// Uses `tokio::fs` for non-blocking directory operations.
pub async fn get_profile_path(name: &str) -> Result<PathBuf, ProfileError> {
    validate_profile_name(name)?;
    let mut path = get_profiles_dir().await?;
    path.push(format!("{name}.json"));
    Ok(path)
}

/// Lists all available profile names.
/// Scans the profiles directory for .json files and extracts their stems.
///
/// # Async
/// Uses `tokio::fs` for non-blocking directory scanning.
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
            profiles.push(name.to_string());
        }
    }

    profiles.sort();
    Ok(profiles)
}

/// Loads a profile by name.
/// Rebuilds rule caches after deserialization to ensure UI search and rendering
/// are performant immediately after load.
///
/// # Async
/// Uses `tokio::fs` for non-blocking file I/O.
pub async fn load_profile(name: &str) -> Result<FirewallRuleset, ProfileError> {
    let path = get_profile_path(name).await?;

    if !tokio::fs::try_exists(&path).await? {
        return Err(ProfileError::NotFound(name.to_string()));
    }

    let json = tokio::fs::read_to_string(&path).await?;

    // Verify checksum if present (warns but doesn't fail for manually edited profiles)
    let mut checksum_path = path.clone();
    checksum_path.set_extension("json.sha256");

    if let Ok(expected_checksum) = tokio::fs::read_to_string(&checksum_path).await {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        let actual_checksum = format!("{:x}", hasher.finalize());

        if expected_checksum.trim() != actual_checksum {
            tracing::warn!(
                "Profile '{}' checksum mismatch (expected: {}, got: {})",
                name,
                expected_checksum.trim(),
                actual_checksum
            );
            // Don't fail - just warn (profile might be manually edited)
        }
    }

    let mut ruleset: FirewallRuleset = serde_json::from_str(&json)?;

    // Validate rule count to prevent memory exhaustion
    if ruleset.rules.len() > crate::core::firewall::MAX_RULES {
        return Err(ProfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Profile '{}' contains {} rules (max: {})",
                name,
                ruleset.rules.len(),
                crate::core::firewall::MAX_RULES
            ),
        )));
    }

    // Rebuild caches for each rule to ensure performant UI rendering/filtering
    for rule in &mut ruleset.rules {
        rule.rebuild_caches();
    }

    Ok(ruleset)
}

/// Saves a profile atomically.
/// Uses a temporary file + rename pattern to prevent data corruption if the
/// process crashes or the disk fills up during write.
///
/// # Async
/// Uses `tokio::fs` for non-blocking file I/O.
pub async fn save_profile(name: &str, ruleset: &FirewallRuleset) -> Result<(), ProfileError> {
    let path = get_profile_path(name).await?;
    let json = serde_json::to_string_pretty(ruleset)?;

    let mut temp_path = path.clone();
    temp_path.set_extension("json.tmp");

    #[cfg(unix)]
    {
        use tokio::fs::OpenOptions;
        use tokio::io::AsyncWriteExt;

        // Set restrictive permissions (0o600) BEFORE writing sensitive firewall rules
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)
            .await?;

        file.write_all(json.as_bytes()).await?;
        file.sync_all().await?; // Ensure bits are on the platter before renaming
    }

    #[cfg(not(unix))]
    {
        tokio::fs::write(&temp_path, json).await?;
    }

    tokio::fs::rename(temp_path, &path).await?;

    // Calculate and save checksum for integrity verification
    let checksum = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        format!("{:x}", hasher.finalize())
    };

    let mut checksum_path = path.clone();
    checksum_path.set_extension("json.sha256");
    tokio::fs::write(checksum_path, checksum).await?;

    Ok(())
}

/// Deletes a profile.
/// Protects the default profile from deletion to prevent the app from
/// entering an invalid "no-profile" state.
///
/// # Async
/// Uses `tokio::fs` for non-blocking file I/O.
pub async fn delete_profile(name: &str) -> Result<(), ProfileError> {
    if name == DEFAULT_PROFILE_NAME {
        return Err(ProfileError::InvalidName(
            "Cannot delete default profile".into(),
        ));
    }

    let path = get_profile_path(name).await?;
    if tokio::fs::try_exists(&path).await? {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
}

/// Renames a profile.
/// Ensures the new name is valid and doesn't conflict with existing profiles.
/// Protects the default profile from being renamed to maintain system consistency.
///
/// # Async
/// Uses `tokio::fs` for non-blocking file I/O.
pub async fn rename_profile(old_name: &str, new_name: &str) -> Result<(), ProfileError> {
    validate_profile_name(new_name)?;

    if old_name == DEFAULT_PROFILE_NAME {
        return Err(ProfileError::InvalidName(
            "Cannot rename default profile".into(),
        ));
    }

    let old_path = get_profile_path(old_name).await?;
    let new_path = get_profile_path(new_name).await?;

    if !tokio::fs::try_exists(&old_path).await? {
        return Err(ProfileError::NotFound(old_name.to_string()));
    }

    // Rename and handle collision atomically (removes TOCTOU race)
    match tokio::fs::rename(old_path, new_path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(ProfileError::InvalidName(
            "Profile with new name already exists".into(),
        )),
        Err(e) => Err(e.into()),
    }
}

/// Synchronous wrapper for `list_profiles()` for use during startup initialization.
///
/// This blocks the current thread and should only be used in `State::new()` where
/// async initialization isn't possible. Everywhere else should use async `list_profiles()`.
pub fn list_profiles_blocking() -> Result<Vec<String>, ProfileError> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.block_on(list_profiles())
    } else {
        tokio::runtime::Runtime::new()
            .expect("Failed to create runtime")
            .block_on(list_profiles())
    }
}

/// Synchronous wrapper for `load_profile()` for use during startup initialization.
///
/// This blocks the current thread and should only be used in `State::new()` where
/// async initialization isn't possible. Everywhere else should use async `load_profile()`.
pub fn load_profile_blocking(name: &str) -> Result<FirewallRuleset, ProfileError> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.block_on(load_profile(name))
    } else {
        tokio::runtime::Runtime::new()
            .expect("Failed to create runtime")
            .block_on(load_profile(name))
    }
}
