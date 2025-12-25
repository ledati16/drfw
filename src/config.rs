use crate::core::firewall::FirewallRuleset;
use crate::utils::get_data_dir;
use std::fs;
use std::io::Write;

/// Saves the ruleset to disk using an atomic write pattern.
/// 1. Writes to a temporary file.
/// 2. Sets restrictive permissions (0o600).
/// 3. Atomically renames to the target path.
pub fn save_ruleset(ruleset: &FirewallRuleset) -> std::io::Result<()> {
    if let Some(mut path) = get_data_dir() {
        let json = serde_json::to_string_pretty(ruleset)?;

        let mut temp_path = path.clone();
        temp_path.push("ruleset.json.tmp");

        path.push("ruleset.json");

        // Create file with restrictive permissions from the start to prevent
        // race condition where file is briefly world-readable
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600) // Set permissions BEFORE any data is written
                .open(&temp_path)?;

            file.write_all(json.as_bytes())?;
            file.sync_all()?; // Ensure data is flushed to physical media
        }

        #[cfg(not(unix))]
        {
            let mut file = fs::File::create(&temp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }

        // Atomic rename
        fs::rename(temp_path, path)?;
    }
    Ok(())
}

pub fn load_ruleset() -> FirewallRuleset {
    if let Some(mut path) = get_data_dir() {
        path.push("ruleset.json");
        if let Ok(rs) = fs::read_to_string(path).and_then(|json| {
            serde_json::from_str::<FirewallRuleset>(&json).map_err(std::io::Error::other)
        }) {
            return rs;
        }
    }
    FirewallRuleset::new()
}
