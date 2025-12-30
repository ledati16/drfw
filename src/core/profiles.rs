//! Firewall profile management
//!
//! Profiles are standalone JSON files containing a `FirewallRuleset`.
//! They are stored in the application's data directory under `profiles/`.

use crate::core::firewall::FirewallRuleset;
use crate::utils::get_data_dir;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

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
/// Allows only alphanumeric characters, underscores, and hyphens.
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
pub fn get_profiles_dir() -> Result<PathBuf, ProfileError> {
    let mut path = get_data_dir().ok_or(ProfileError::DataDirUnavailable)?;
    path.push("profiles");

    if !path.exists() {
        fs::create_dir_all(&path)?;
    }

    Ok(path)
}

/// Returns the path to a specific profile file.
pub fn get_profile_path(name: &str) -> Result<PathBuf, ProfileError> {
    validate_profile_name(name)?;
    let mut path = get_profiles_dir()?;
    path.push(format!("{}.json", name));
    Ok(path)
}

/// Lists all available profile names.
pub fn list_profiles() -> Result<Vec<String>, ProfileError> {
    let dir = get_profiles_dir()?;
    let mut profiles = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
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
pub fn load_profile(name: &str) -> Result<FirewallRuleset, ProfileError> {
    let path = get_profile_path(name)?;

    if !path.exists() {
        return Err(ProfileError::NotFound(name.to_string()));
    }

    let json = fs::read_to_string(path)?;
    let mut ruleset: FirewallRuleset = serde_json::from_str(&json)?;

    // Rebuild caches for each rule
    for rule in &mut ruleset.rules {
        rule.rebuild_caches();
    }

    Ok(ruleset)
}

/// Saves a profile atomically.
pub fn save_profile(name: &str, ruleset: &FirewallRuleset) -> Result<(), ProfileError> {
    let path = get_profile_path(name)?;
    let json = serde_json::to_string_pretty(ruleset)?;

    let mut temp_path = path.clone();
    temp_path.set_extension("json.tmp");

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)?;

        file.write_all(json.as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        fs::write(&temp_path, json)?;
    }

    fs::rename(temp_path, path)?;
    Ok(())
}

/// Deletes a profile.
pub fn delete_profile(name: &str) -> Result<(), ProfileError> {
    if name == DEFAULT_PROFILE_NAME {
        return Err(ProfileError::InvalidName(
            "Cannot delete default profile".into(),
        ));
    }

    let path = get_profile_path(name)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Renames a profile.
pub fn rename_profile(old_name: &str, new_name: &str) -> Result<(), ProfileError> {
    validate_profile_name(new_name)?;

    if old_name == DEFAULT_PROFILE_NAME {
        return Err(ProfileError::InvalidName(
            "Cannot rename default profile".into(),
        ));
    }

    let old_path = get_profile_path(old_name)?;
    let new_path = get_profile_path(new_name)?;

    if !old_path.exists() {
        return Err(ProfileError::NotFound(old_name.to_string()));
    }

    if new_path.exists() {
        return Err(ProfileError::InvalidName(
            "Profile with new name already exists".into(),
        ));
    }

    fs::rename(old_path, new_path)?;
    Ok(())
}
