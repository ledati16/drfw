use iced::Font;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Represents a font choice, either a system preset or a specific system font family
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FontChoice {
    #[default]
    SystemDefault,
    SystemMonospace,
    Specific {
        name: String,
        #[serde(skip)]
        handle: Option<Font>,
        #[serde(skip)]
        name_lowercase: String,
    },
}

impl FontChoice {
    pub fn name(&self) -> String {
        match self {
            Self::SystemDefault => "System Default".to_string(),
            Self::SystemMonospace => "System Monospace".to_string(),
            Self::Specific { name, .. } => name.clone(),
        }
    }

    /// Returns the lowercase version of the font name (cached for performance)
    pub fn name_lowercase(&self) -> &str {
        match self {
            Self::SystemDefault => "system default",
            Self::SystemMonospace => "system monospace",
            Self::Specific { name_lowercase, .. } => name_lowercase.as_str(),
        }
    }

    pub fn to_font(&self) -> Font {
        match self {
            Self::SystemDefault => Font::DEFAULT,
            Self::SystemMonospace => Font::MONOSPACE,
            Self::Specific { handle, .. } => handle.unwrap_or(Font::DEFAULT),
        }
    }

    /// Returns true if this font is monospaced (fixed-width)
    pub fn is_monospace(&self) -> bool {
        match self {
            Self::SystemDefault => false,
            Self::SystemMonospace => true,
            Self::Specific { name_lowercase, .. } => {
                // Heuristic: Check if name contains common monospace indicators
                // Use cached lowercase version for performance
                name_lowercase.contains("mono")
                    || name_lowercase.contains("code")
                    || name_lowercase.contains("console")
                    || name_lowercase.contains("courier")
                    || name_lowercase.contains("terminal")
                    || name_lowercase.contains("fixed")
                    || name_lowercase.contains("source code")
                    || name_lowercase.contains("jetbrains")
                    || name_lowercase.contains("fira code")
                    || name_lowercase.contains("inconsolata")
                    || name_lowercase.contains("hack")
                    || name_lowercase.contains("menlo")
                    || name_lowercase.contains("consolas")
                    || name_lowercase.contains("roboto mono")
                    || name_lowercase.contains("ubuntu mono")
                    || name_lowercase.contains("dejavu sans mono")
                    || name_lowercase.contains("liberation mono")
                    || name_lowercase.contains("noto mono")
                    || name_lowercase.contains("cascadia")
                    || name_lowercase.contains("iosevka")
            }
        }
    }

    /// Resolves a font choice by populating its handle from the system cache if missing.
    /// Used when loading from configuration.
    pub fn resolve(&mut self, is_mono: bool) {
        if let Self::Specific {
            name,
            handle,
            name_lowercase,
        } = self
        {
            // Populate name_lowercase if empty (deserialized from old config)
            if name_lowercase.is_empty() {
                *name_lowercase = name.to_lowercase();
            }

            // Populate handle if missing
            if handle.is_none() {
                let mut found_handle = None;
                // Find matching font in system cache
                for option in all_options() {
                    if let Self::Specific {
                        name: system_name,
                        handle: system_handle,
                        ..
                    } = option
                        && system_name == name
                    {
                        found_handle = *system_handle;
                        break;
                    }
                }

                if let Some(h) = found_handle {
                    *handle = Some(h);
                } else {
                    // Font was deleted from system, fall back to appropriate default
                    tracing::warn!(
                        "Font '{}' not found on system, falling back to default.",
                        name
                    );
                    *self = if is_mono {
                        Self::SystemMonospace
                    } else {
                        Self::SystemDefault
                    };
                }
            }
        }
    }
}

impl std::fmt::Display for FontChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Global cache of system font families
static SYSTEM_FONTS: OnceLock<Vec<FontChoice>> = OnceLock::new();

/// Centralized storage for font names (Phase 2: Fix memory leak)
/// Instead of leaking each font name individually, we leak one Vec
/// This is still a leak, but bounds memory to `O(n_fonts)` instead of unbounded growth
static FONT_NAMES_STORAGE: OnceLock<&'static [String]> = OnceLock::new();

/// Returns all available font choices for the UI, cached
pub fn all_options() -> &'static [FontChoice] {
    SYSTEM_FONTS.get_or_init(|| {
        let mut db = fontdb::Database::new();
        db.load_system_fonts();

        let mut families: Vec<String> = db
            .faces()
            .filter_map(|face| face.families.first().map(|(name, _)| name.clone()))
            .collect();

        families.sort();
        families.dedup();

        // Store all font names in centralized static storage (one-time controlled leak)
        // Box::leak gives us 'static access to the Vec's contents
        let font_names: &'static [String] =
            FONT_NAMES_STORAGE.get_or_init(|| Box::leak(families.into_boxed_slice()));

        let mut options = vec![FontChoice::SystemDefault, FontChoice::SystemMonospace];

        // Reference strings from the centralized storage
        for name in font_names {
            options.push(FontChoice::Specific {
                name: name.clone(),
                handle: Some(Font::with_name(name.as_str())),
                name_lowercase: name.to_lowercase(),
            });
        }
        options
    })
}

// Re-export old types as aliases for compatibility
pub type RegularFontChoice = FontChoice;
pub type MonoFontChoice = FontChoice;
