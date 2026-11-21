use serde::{Deserialize, Serialize};

use crate::core::profiles::DEFAULT_PROFILE_NAME;
use crate::utils::get_data_dir;

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
    /// Enable auto-revert countdown when applying rules (GUI; the CLI uses
    /// `--confirm`/`--no-confirm`). On by default: an unconfirmed apply is
    /// reverted by a root-side guard, which protects against lockouts.
    /// Configs written before this default changed keep their explicit value.
    #[serde(default = "default_true")]
    pub auto_revert_enabled: bool,
    /// The GUI's one-time "Auto-revert is off" notice was answered (or the
    /// user changed auto-revert themselves). Configs from before the default
    /// changed hold `auto_revert_enabled: false` without the user ever
    /// having chosen it; the notice asks once instead of flipping the saved
    /// value. Missing in older configs: `false`.
    #[serde(default)]
    pub auto_revert_notice_shown: bool,
    /// Timeout in seconds for auto-revert countdown (default: 15s, max: 3600s)
    ///
    /// Clamped to 3600 seconds (1 hour) to prevent integer overflow in countdown calculations.
    #[serde(default = "default_auto_revert_timeout")]
    pub auto_revert_timeout_secs: u64,
    /// Enable event logging for Diagnostics tab
    #[serde(default = "default_true")]
    pub enable_event_log: bool,
    /// Reduce syntax highlighting colors (accessibility feature)
    ///
    /// When enabled, collapses syntax colors to 2 levels (primary/muted) instead of 6,
    /// reducing visual noise while preserving the theme's overall feel.
    #[serde(default)]
    pub reduced_colors: bool,
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
            auto_revert_enabled: true, // Lockout protection on by default
            auto_revert_notice_shown: false,
            auto_revert_timeout_secs: 15,
            enable_event_log: true, // Useful for troubleshooting, local-only so no privacy concern
            reduced_colors: false,  // Full syntax highlighting by default
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

/// Returns the path of `config.json` (in the data directory, e.g.
/// `~/.local/share/drfw/config.json`).
fn config_path() -> Option<std::path::PathBuf> {
    get_data_dir().map(|dir| dir.join("config.json"))
}

/// Saves the complete app config to disk atomically (unique temp file, mode
/// 0600, sync, rename).
///
/// # Security
///
/// On Unix systems, files are created with mode 0o600 (user read/write only).
/// On Windows, files inherit directory permissions. Users should ensure the
/// data directory has appropriate ACLs: `%LOCALAPPDATA%\drfw\drfw\data`
///
/// # Errors
///
/// Returns `Err` if the config cannot be serialized or written (a full disk is
/// reported with a readable message).
pub async fn save_config(config: &AppConfig) -> std::io::Result<()> {
    let Some(path) = config_path() else {
        return Ok(());
    };
    let json = serde_json::to_vec_pretty(config)?;
    crate::utils::write_atomic_private_async(path, json).await
}

/// Result of [`load_config_checked`].
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// The config to use (defaults when the file was unreadable)
    pub config: AppConfig,
    /// User-facing explanation when `config.json` existed but could not be
    /// used; `None` when it loaded fine or simply did not exist.
    pub problem: Option<String>,
}

/// Loads the app config for the GUI without ever losing the user's file.
///
/// - Missing file: defaults, no problem (first run).
/// - Unreadable file (bad JSON, values from a newer version): the file is
///   copied to `config.json.corrupt-<UTC timestamp>` (0600), defaults are used
///   (keeping `active_profile` if it can still be read), and `problem`
///   explains what happened. The original file is not touched; it is only
///   replaced when the user next changes a setting.
///
/// # Async
/// Uses `tokio::fs`; the backup copy runs on the blocking pool.
pub async fn load_config_checked() -> LoadedConfig {
    let Some(path) = config_path() else {
        return LoadedConfig {
            config: AppConfig::default(),
            problem: None,
        };
    };
    let json = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return LoadedConfig {
                config: AppConfig::default(),
                problem: None,
            };
        }
        Err(e) => {
            tracing::error!("Failed to read configuration: {e}");
            return LoadedConfig {
                config: AppConfig::default(),
                problem: Some(format!(
                    "Settings could not be read ({e}); using defaults for this session."
                )),
            };
        }
    };

    match serde_json::from_slice::<AppConfig>(&json) {
        Ok(config) => LoadedConfig {
            config,
            problem: None,
        },
        Err(e) => {
            tracing::error!("Configuration file is unreadable: {e}");
            let mut config = AppConfig::default();
            if let Some(name) = salvage_active_profile(&json) {
                config.active_profile = name;
            }
            let copy_path = path.clone();
            let copy = tokio::task::spawn_blocking(move || {
                crate::utils::preserve_unreadable_file(&copy_path)
            })
            .await;
            let copy_note = match copy {
                Ok(Ok(backup)) => format!("A copy was saved to {}.", backup.display()),
                Ok(Err(err)) => {
                    tracing::error!("Could not back up configuration: {err}");
                    "A backup copy could not be made.".to_string()
                }
                Err(err) => {
                    tracing::error!("Could not back up configuration: {err}");
                    "A backup copy could not be made.".to_string()
                }
            };
            LoadedConfig {
                config,
                problem: Some(format!(
                    "Settings file could not be read ({e}). {copy_note} Default settings are \
                     in use; the file is only replaced when you change a setting."
                )),
            }
        }
    }
}

/// Reads `active_profile` from an otherwise unreadable config, so a broken
/// setting elsewhere does not also switch the user to another profile.
fn salvage_active_profile(json: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(json).ok()?;
    let name = value.get("active_profile")?.as_str()?;
    crate::core::profiles::validate_profile_name(name).ok()?;
    Some(name.to_string())
}

/// Loads the app config from disk, or returns defaults if it is missing or
/// unreadable (used by the CLI, which never writes the config).
///
/// # Async
/// Uses `tokio::fs` for non-blocking I/O to avoid blocking the event loop.
pub async fn load_config() -> AppConfig {
    if let Some(path) = config_path()
        && let Ok(json) = tokio::fs::read(&path).await
    {
        match serde_json::from_slice::<AppConfig>(&json) {
            Ok(config) => return config,
            Err(e) => {
                tracing::warn!("Configuration file is unreadable, using defaults: {e}");
                let mut config = AppConfig::default();
                if let Some(name) = salvage_active_profile(&json) {
                    config.active_profile = name;
                }
                return config;
            }
        }
    }
    AppConfig::default()
}

/// Synchronous wrapper for [`load_config_checked`] for use during startup
/// initialization (`State::new()`).
pub fn load_config_checked_blocking() -> LoadedConfig {
    crate::utils::block_on_async(load_config_checked())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config saved before auto-revert defaulted to on keeps its value,
    /// and has not seen the notice.
    #[test]
    fn test_old_config_keeps_auto_revert_off_and_has_no_notice() {
        let old: AppConfig =
            serde_json::from_str(r#"{ "active_profile": "home", "auto_revert_enabled": false }"#)
                .unwrap();
        assert!(!old.auto_revert_enabled);
        assert!(!old.auto_revert_notice_shown);
        let mut answered = old;
        answered.auto_revert_notice_shown = true;
        let round_trip: AppConfig =
            serde_json::from_slice(&serde_json::to_vec(&answered).unwrap()).unwrap();
        assert!(round_trip.auto_revert_notice_shown);
        assert!(!round_trip.auto_revert_enabled);
    }

    #[test]
    fn test_salvage_active_profile() {
        let json = br#"{ "active_profile": "work", "theme_choice": "FromTheFuture" }"#;
        assert!(serde_json::from_slice::<AppConfig>(json).is_err());
        assert_eq!(salvage_active_profile(json), Some("work".to_string()));
        assert_eq!(
            salvage_active_profile(br#"{ "active_profile": "../x" }"#),
            None
        );
        assert_eq!(salvage_active_profile(b"{ broken"), None);
    }
}
