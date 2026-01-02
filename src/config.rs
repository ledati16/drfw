use crate::core::profiles::DEFAULT_PROFILE_NAME;
use crate::utils::get_data_dir;
use serde::{Deserialize, Serialize};

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
    /// Enable auto-revert countdown when applying rules (GUI only, CLI is always safe)
    #[serde(default)]
    pub auto_revert_enabled: bool,
    /// Timeout in seconds for auto-revert countdown (default: 15s, max: 3600s)
    ///
    /// Clamped to 3600 seconds (1 hour) to prevent integer overflow in countdown calculations.
    #[serde(default = "default_auto_revert_timeout")]
    pub auto_revert_timeout_secs: u64,
    /// Enable event logging for Diagnostics tab (opt-in, disabled by default)
    #[serde(default)]
    pub enable_event_log: bool,
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
            auto_revert_enabled: false, // OFF by default for GUI (desktop context)
            auto_revert_timeout_secs: 15,
            enable_event_log: false, // Opt-in only for privacy/disk space
        }
    }
}

fn default_profile() -> String {
    DEFAULT_PROFILE_NAME.to_string()
}

fn default_true() -> bool {
    true
}

fn default_auto_revert_timeout() -> u64 {
    15
}

/// Saves the complete app config to disk using an atomic write pattern.
/// 1. Writes to a temporary file.
/// 2. Sets restrictive permissions (0o600).
/// 3. Atomically renames to the target path.
///
/// # Security
///
/// On Unix systems, files are created with mode 0o600 (user read/write only).
/// On Windows, files inherit directory permissions. Users should ensure the
/// config directory has appropriate ACLs: `%LOCALAPPDATA%\drfw\drfw\config`
///
/// # Async
/// Uses `tokio::fs` for non-blocking I/O to avoid blocking the event loop.
pub async fn save_config(config: &AppConfig) -> std::io::Result<()> {
    if let Some(mut path) = get_data_dir() {
        let json = serde_json::to_string_pretty(config)?;

        let mut temp_path = path.clone();
        temp_path.push("config.json.tmp");

        path.push("config.json");

        // Create file with restrictive permissions from the start to prevent
        // race condition where file is briefly world-readable
        #[cfg(unix)]
        {
            use tokio::fs::OpenOptions;
            use tokio::io::AsyncWriteExt;

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600) // Set permissions BEFORE any data is written
                .open(&temp_path)
                .await?;

            file.write_all(json.as_bytes()).await?;
            file.sync_all().await?; // Ensure data is flushed to physical media
        }

        #[cfg(not(unix))]
        {
            use tokio::io::AsyncWriteExt;

            let mut file = tokio::fs::File::create(&temp_path).await?;
            file.write_all(json.as_bytes()).await?;
            file.sync_all().await?;
        }

        // Atomic rename
        tokio::fs::rename(temp_path, path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::StorageFull {
                std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "Disk full: cannot save configuration. Free up space and try again.",
                )
            } else {
                e
            }
        })?;
    }
    Ok(())
}

/// Loads the app config from disk, or returns default if not found.
///
/// # Async
/// Uses `tokio::fs` for non-blocking I/O to avoid blocking the event loop.
pub async fn load_config() -> AppConfig {
    if let Some(mut path) = get_data_dir() {
        path.push("config.json");
        if let Ok(json) = tokio::fs::read_to_string(&path).await
            && let Ok(config) = serde_json::from_str::<AppConfig>(&json)
        {
            return config;
        }
    }
    AppConfig::default()
}

/// Synchronous wrapper for `load_config()` for use during startup initialization.
///
/// This blocks the current thread and should only be used in `State::new()` where
/// async initialization isn't possible. Everywhere else should use async `load_config()`.
pub fn load_config_blocking() -> AppConfig {
    // Use Handle::current() if available (we're in a Tokio context),
    // otherwise create a temporary runtime
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.block_on(load_config())
    } else {
        // Fallback: create temporary runtime (shouldn't happen in practice)
        tokio::runtime::Runtime::new()
            .expect("Failed to create runtime")
            .block_on(load_config())
    }
}
