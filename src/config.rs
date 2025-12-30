use crate::core::profiles::DEFAULT_PROFILE_NAME;
use crate::utils::get_data_dir;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;

/// Complete application configuration including UI settings and current profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_profile")]
    pub active_profile: String,
    #[serde(default)]
    pub theme_choice: crate::theme::ThemeChoice,
    #[serde(default)]
    pub regular_font: crate::fonts::RegularFontChoice,
    #[serde(default)]
    pub mono_font: crate::fonts::MonoFontChoice,
    #[serde(default = "default_true")]
    pub show_diff: bool,
    #[serde(default = "default_true")]
    pub show_zebra_striping: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            active_profile: default_profile(),
            theme_choice: crate::theme::ThemeChoice::default(),
            regular_font: crate::fonts::RegularFontChoice::default(),
            mono_font: crate::fonts::MonoFontChoice::default(),
            show_diff: true,
            show_zebra_striping: true,
        }
    }
}

fn default_profile() -> String {
    DEFAULT_PROFILE_NAME.to_string()
}

fn default_true() -> bool {
    true
}

/// Saves the complete app config to disk using an atomic write pattern.
/// 1. Writes to a temporary file.
/// 2. Sets restrictive permissions (0o600).
/// 3. Atomically renames to the target path.
pub fn save_config(config: &AppConfig) -> std::io::Result<()> {
    if let Some(mut path) = get_data_dir() {
        let json = serde_json::to_string_pretty(config)?;

        let mut temp_path = path.clone();
        temp_path.push("config.json.tmp");

        path.push("config.json");

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

pub fn load_config() -> AppConfig {
    if let Some(mut path) = get_data_dir() {
        path.push("config.json");
        if let Ok(config) = fs::read_to_string(&path).and_then(|json| {
            serde_json::from_str::<AppConfig>(&json).map_err(std::io::Error::other)
        }) {
            return config;
        }
    }
    AppConfig::default()
}
