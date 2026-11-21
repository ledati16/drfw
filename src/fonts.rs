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
        /// fontdb reports a fixed-pitch face for this family (`post` table)
        #[serde(skip)]
        monospaced: bool,
    },
}

impl FontChoice {
    /// Display name of the font (no allocation; safe to call from `view()`).
    pub fn name(&self) -> &str {
        match self {
            Self::SystemDefault => "System Default",
            Self::SystemMonospace => "System Monospace",
            Self::Specific { name, .. } => name,
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

    /// Returns true if this font is monospaced (fixed-width).
    ///
    /// For system fonts this is what the font itself declares (fontdb reads
    /// the `post` table's fixed-pitch flag), not a guess from the name: a
    /// name heuristic listed display fonts such as "Monoton" and missed
    /// monospaced fonts without "mono" in their name.
    pub fn is_monospace(&self) -> bool {
        match self {
            Self::SystemDefault => false,
            Self::SystemMonospace => true,
            Self::Specific { monospaced, .. } => *monospaced,
        }
    }

    /// Gives a configured font a usable handle before the system font list
    /// has loaded, so the UI starts in the right font.
    ///
    /// iced resolves fonts by family name, so this needs no font scan. The
    /// name is leaked to get the `&'static str` iced requires; this happens
    /// at most once per configured font at startup. [`Self::resolve`] later
    /// swaps in the system list's handle (or falls back if the font is gone).
    pub fn set_provisional_handle(&mut self) {
        if let Self::Specific {
            name,
            handle,
            name_lowercase,
            ..
        } = self
        {
            if name_lowercase.is_empty() {
                *name_lowercase = name.to_lowercase();
            }
            if handle.is_none() {
                let leaked: &'static str = Box::leak(name.clone().into_boxed_str());
                *handle = Some(Font::with_name(leaked));
            }
        }
    }

    /// Resolves a configured font against the loaded system font list:
    /// takes its handle and monospace flag from there, or falls back to the
    /// system default (monospace if `is_mono`) when the font is not installed.
    ///
    /// Returns `true` if the choice changed to the fallback.
    pub fn resolve(&mut self, system_fonts: &[FontChoice], is_mono: bool) -> bool {
        let Self::Specific { name, .. } = self else {
            return false;
        };
        let found = system_fonts.iter().find(|option| {
            matches!(option, Self::Specific { name: system_name, .. } if system_name == name)
        });
        if let Some(system_choice) = found {
            *self = system_choice.clone();
            return false;
        }
        // Font was deleted from system, fall back to appropriate default
        tracing::warn!("Font '{name}' not found on system, falling back to default.");
        *self = if is_mono {
            Self::SystemMonospace
        } else {
            Self::SystemDefault
        };
        true
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

/// Returns all available font choices for the UI, cached.
///
/// The first call scans and parses every installed font file, which can take
/// a noticeable time: call it off the UI thread (the GUI does so with
/// `spawn_blocking` at startup).
pub fn all_options() -> &'static [FontChoice] {
    SYSTEM_FONTS.get_or_init(|| {
        let mut db = fontdb::Database::new();
        db.load_system_fonts();

        // Family name -> any face of the family declares fixed pitch
        let mut families: std::collections::BTreeMap<String, bool> =
            std::collections::BTreeMap::new();
        for face in db.faces() {
            if let Some((name, _)) = face.families.first() {
                *families.entry(name.clone()).or_default() |= face.monospaced;
            }
        }
        let (names, monospaced): (Vec<String>, Vec<bool>) = families.into_iter().unzip();

        // Store all font names in centralized static storage (one-time controlled leak)
        // Box::leak gives us 'static access to the Vec's contents
        let font_names: &'static [String] =
            FONT_NAMES_STORAGE.get_or_init(|| Box::leak(names.into_boxed_slice()));

        let mut options = Vec::with_capacity(font_names.len() + 2);
        options.push(FontChoice::SystemDefault);
        options.push(FontChoice::SystemMonospace);

        // Reference strings from the centralized storage
        for (name, monospaced) in font_names.iter().zip(monospaced) {
            options.push(FontChoice::Specific {
                name: name.clone(),
                handle: Some(Font::with_name(name.as_str())),
                name_lowercase: name.to_lowercase(),
                monospaced,
            });
        }
        options
    })
}

// Re-export old types as aliases for compatibility
pub type RegularFontChoice = FontChoice;
pub type MonoFontChoice = FontChoice;

#[cfg(test)]
mod tests {
    use super::*;

    fn specific(name: &str, monospaced: bool) -> FontChoice {
        FontChoice::Specific {
            name: name.to_string(),
            handle: Some(Font::with_name("Test")),
            name_lowercase: name.to_lowercase(),
            monospaced,
        }
    }

    #[test]
    fn test_monospace_comes_from_the_font_not_its_name() {
        assert!(!specific("Monoton", false).is_monospace());
        assert!(specific("Iosevka Term", true).is_monospace());
        assert!(FontChoice::SystemMonospace.is_monospace());
        assert!(!FontChoice::SystemDefault.is_monospace());
    }

    #[test]
    fn test_resolve_takes_system_entry_or_falls_back() {
        let system = [specific("Fira Code", true)];
        let mut configured = FontChoice::Specific {
            name: "Fira Code".to_string(),
            handle: None,
            name_lowercase: String::new(),
            monospaced: false,
        };
        configured.set_provisional_handle();
        assert!(configured.to_font() != Font::DEFAULT);
        assert!(!configured.resolve(&system, true));
        assert!(
            configured.is_monospace(),
            "flag copied from the system list"
        );

        let mut missing = specific("Gone Font", false);
        assert!(missing.resolve(&system, true));
        assert_eq!(missing, FontChoice::SystemMonospace);
    }
}
