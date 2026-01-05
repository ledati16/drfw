//! Firewall profile management
//!
//! Profiles are standalone JSON files containing a `FirewallRuleset`.
//! They are stored in the application's data directory under `profiles/`.
//!
//! # Concurrent Access
//!
//! Profile functions are **not** safe for concurrent access from multiple processes.
//! Running multiple DRFW instances simultaneously may cause data loss.
//! Use file locking or a single daemon if concurrent access is required.

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

    #[error("Rule limit exceeded: {current} rules (maximum: {limit})")]
    RuleLimitExceeded { current: usize, limit: usize },
}

/// Validates a profile name for filesystem safety.
///
/// Constraints:
/// - Alphanumeric, underscores, and hyphens only: Prevents shell injection and
///   cross-platform filename issues.
/// - Max 20 chars: Allows descriptive names while staying reasonable for UI display.
/// - Rejects "." and "..": Critical path traversal protection.
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
        return Err(ProfileError::RuleLimitExceeded {
            current: ruleset.rules.len(),
            limit: crate::core::firewall::MAX_RULES,
        });
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
/// # Security
///
/// On Unix systems, files are created with mode 0o600 (user read/write only).
/// On Windows, files inherit directory permissions. Users should ensure the
/// profiles directory has appropriate ACLs: `%LOCALAPPDATA%\drfw\drfw\data\profiles`
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

    tokio::fs::rename(temp_path, &path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::StorageFull {
            std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "Disk full: cannot save profile. Free up space and try again.",
            )
        } else {
            e
        }
    })?;

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

/// Deletes a profile and its associated checksum file.
///
/// # Business Logic Validation
///
/// This function only performs the file deletion. The caller is responsible for:
/// - Ensuring this isn't the last profile (system must have ≥1 profile)
/// - Ensuring this isn't the currently active profile (must switch first)
/// - Updating application state after deletion
///
/// # Async
/// Uses `tokio::fs` for non-blocking file I/O.
pub async fn delete_profile(name: &str) -> Result<(), ProfileError> {
    let path = get_profile_path(name).await?;
    if tokio::fs::try_exists(&path).await? {
        tokio::fs::remove_file(&path).await?;

        // Also delete checksum file if it exists (best-effort)
        let mut checksum_path = path.clone();
        checksum_path.set_extension("json.sha256");
        if tokio::fs::try_exists(&checksum_path).await?
            && let Err(e) = tokio::fs::remove_file(&checksum_path).await
        {
            tracing::warn!("Failed to delete checksum file for '{}': {}", name, e);
        }
    }
    Ok(())
}

/// Renames a profile and its associated checksum file.
/// Ensures the new name is valid and doesn't conflict with existing profiles.
///
/// # Business Logic Validation
///
/// The caller is responsible for:
/// - Updating config if renaming the active profile
/// - Updating UI state after rename
///
/// # Async
/// Uses `tokio::fs` for non-blocking file I/O.
pub async fn rename_profile(old_name: &str, new_name: &str) -> Result<(), ProfileError> {
    validate_profile_name(new_name)?;

    let old_path = get_profile_path(old_name).await?;
    let new_path = get_profile_path(new_name).await?;

    if !tokio::fs::try_exists(&old_path).await? {
        return Err(ProfileError::NotFound(old_name.to_string()));
    }

    // Rename JSON file atomically (removes TOCTOU race)
    match tokio::fs::rename(&old_path, &new_path).await {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ProfileError::InvalidName(
                "Profile with new name already exists".into(),
            ));
        }
        Err(e) => return Err(e.into()),
    }

    // Rename checksum file if it exists (best-effort)
    // Checksum content remains valid since JSON content didn't change
    let mut old_checksum = old_path.clone();
    old_checksum.set_extension("json.sha256");
    let mut new_checksum = new_path.clone();
    new_checksum.set_extension("json.sha256");

    if tokio::fs::try_exists(&old_checksum).await?
        && let Err(e) = tokio::fs::rename(&old_checksum, &new_checksum).await
    {
        tracing::warn!(
            "Failed to rename checksum file for '{}': {}. New checksum will be created on save.",
            old_name,
            e
        );
    }

    Ok(())
}

/// Ensures at least one profile exists, creating a default if none found.
///
/// This is a defensive measure for:
/// - First run (no profiles directory yet)
/// - Manual deletion of all profiles
/// - Filesystem corruption
///
/// If no profiles exist, creates "default" profile with default FirewallRuleset.
/// Also performs cleanup of orphaned checksum files.
///
/// # Async
/// Uses `tokio::fs` for non-blocking file I/O.
pub async fn ensure_profile_exists() -> Result<(), ProfileError> {
    let profiles = list_profiles().await?;

    if profiles.is_empty() {
        tracing::warn!("No profiles found, creating default profile");
        save_profile(DEFAULT_PROFILE_NAME, &FirewallRuleset::default()).await?;
    }

    // Clean up orphaned checksums from old operations (self-healing)
    // This is fast (1-5ms typical) and prevents long-term directory pollution
    if let Ok(count) = cleanup_orphaned_checksums().await
        && count > 0
    {
        tracing::info!("Cleaned up {} orphaned checksum files", count);
    }

    Ok(())
}

/// Removes orphaned checksum files (checksums without corresponding profile JSON).
///
/// This cleans up artifacts from:
/// - Old bugs in delete/rename operations (pre-fix)
/// - Manual file deletions
/// - Incomplete operations (crashes, disk full, etc.)
///
/// Called automatically during `ensure_profile_exists()` at startup for self-healing.
/// Performance: ~1-5ms typical, up to ~50ms if many orphans exist (one-time cost).
///
/// # Async
/// Uses `tokio::fs` for non-blocking file I/O.
async fn cleanup_orphaned_checksums() -> Result<usize, ProfileError> {
    let dir = get_profiles_dir().await?;
    let mut entries = tokio::fs::read_dir(&dir).await?;
    let mut removed_count = 0;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();

        // Only check .sha256 files (early exit for .json files)
        if path.extension().and_then(|s| s.to_str()) != Some("sha256") {
            continue;
        }

        // Extract profile name from "name.json.sha256"
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            && let Some(profile_name) = stem.strip_suffix(".json")
        {
            // Check if corresponding .json exists
            let json_path = dir.join(format!("{}.json", profile_name));

            if !tokio::fs::try_exists(&json_path).await? {
                // Orphaned checksum - delete it
                tracing::debug!("Removing orphaned checksum: {}.json.sha256", profile_name);
                tokio::fs::remove_file(&path).await?;
                removed_count += 1;
            }
        }
    }

    Ok(removed_count)
}

/// Synchronous wrapper for `ensure_profile_exists()` for use during startup initialization.
///
/// This blocks the current thread and should only be used in `State::new()` where
/// async initialization isn't possible.
pub fn ensure_profile_exists_blocking() -> Result<(), ProfileError> {
    crate::utils::block_on_async(ensure_profile_exists())
}

/// Synchronous wrapper for `list_profiles()` for use during startup initialization.
///
/// This blocks the current thread and should only be used in `State::new()` where
/// async initialization isn't possible. Everywhere else should use async `list_profiles()`.
pub fn list_profiles_blocking() -> Result<Vec<String>, ProfileError> {
    crate::utils::block_on_async(list_profiles())
}

/// Synchronous wrapper for `load_profile()` for use during startup initialization.
///
/// This blocks the current thread and should only be used in `State::new()` where
/// async initialization isn't possible. Everywhere else should use async `load_profile()`.
pub fn load_profile_blocking(name: &str) -> Result<FirewallRuleset, ProfileError> {
    crate::utils::block_on_async(load_profile(name))
}
