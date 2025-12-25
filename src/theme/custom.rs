use super::AppTheme;
use iced::Color;
use serde::Deserialize;
use std::path::PathBuf;

/// TOML-friendly theme definition for custom themes
#[derive(Debug, Deserialize)]
pub struct ThemeToml {
    pub theme: ThemeMetadata,
    pub colors: ThemeColors,
}

#[derive(Debug, Deserialize)]
pub struct ThemeMetadata {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct ThemeColors {
    // Backgrounds
    pub bg_base: String,
    pub bg_sidebar: String,
    pub bg_surface: String,
    pub bg_elevated: String,
    pub bg_hover: String,
    pub bg_active: String,

    // Foregrounds
    pub fg_primary: String,
    pub fg_secondary: String,
    pub fg_muted: String,
    pub fg_on_accent: String,

    // Semantic
    pub accent: String,
    pub accent_hover: String,
    pub success: String,
    pub warning: String,
    pub danger: String,
    pub info: String,

    // Borders
    pub border: String,
    pub border_strong: String,
    pub divider: String,

    // Syntax
    pub syntax_keyword: String,
    pub syntax_type: String,
    pub syntax_string: String,
    pub syntax_number: String,
    pub syntax_comment: String,
    pub syntax_operator: String,
}

impl ThemeToml {
    /// Load a custom theme from a TOML file
    pub fn load(path: &PathBuf) -> Result<AppTheme, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read theme file: {}", e))?;

        let toml: ThemeToml =
            toml::from_str(&content).map_err(|e| format!("Failed to parse theme TOML: {}", e))?;

        toml.into_app_theme()
    }

    /// Convert TOML theme to AppTheme
    fn into_app_theme(self) -> Result<AppTheme, String> {
        Ok(AppTheme {
            name: self.theme.name,
            bg_base: parse_color(&self.colors.bg_base)?,
            bg_sidebar: parse_color(&self.colors.bg_sidebar)?,
            bg_surface: parse_color(&self.colors.bg_surface)?,
            bg_elevated: parse_color(&self.colors.bg_elevated)?,
            bg_hover: parse_color(&self.colors.bg_hover)?,
            bg_active: parse_color(&self.colors.bg_active)?,
            fg_primary: parse_color(&self.colors.fg_primary)?,
            fg_secondary: parse_color(&self.colors.fg_secondary)?,
            fg_muted: parse_color(&self.colors.fg_muted)?,
            fg_on_accent: parse_color(&self.colors.fg_on_accent)?,
            accent: parse_color(&self.colors.accent)?,
            accent_hover: parse_color(&self.colors.accent_hover)?,
            success: parse_color(&self.colors.success)?,
            warning: parse_color(&self.colors.warning)?,
            danger: parse_color(&self.colors.danger)?,
            info: parse_color(&self.colors.info)?,
            border: parse_color(&self.colors.border)?,
            border_strong: parse_color(&self.colors.border_strong)?,
            divider: parse_color(&self.colors.divider)?,
            syntax_keyword: parse_color(&self.colors.syntax_keyword)?,
            syntax_type: parse_color(&self.colors.syntax_type)?,
            syntax_string: parse_color(&self.colors.syntax_string)?,
            syntax_number: parse_color(&self.colors.syntax_number)?,
            syntax_comment: parse_color(&self.colors.syntax_comment)?,
            syntax_operator: parse_color(&self.colors.syntax_operator)?,
            shadow_color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            shadow_strong: Color::from_rgba(0.0, 0.0, 0.0, 0.8),
        })
    }
}

/// Parse hex color string (#RRGGBB) to iced Color
fn parse_color(hex: &str) -> Result<Color, String> {
    let hex = hex.trim_start_matches('#');

    if hex.len() != 6 {
        return Err(format!("Invalid color format: {}, expected #RRGGBB", hex));
    }

    let r = u8::from_str_radix(&hex[0..2], 16)
        .map_err(|_| format!("Invalid red component in color: {}", hex))?;
    let g = u8::from_str_radix(&hex[2..4], 16)
        .map_err(|_| format!("Invalid green component in color: {}", hex))?;
    let b = u8::from_str_radix(&hex[4..6], 16)
        .map_err(|_| format!("Invalid blue component in color: {}", hex))?;

    Ok(Color::from_rgb(
        f32::from(r) / 255.0,
        f32::from(g) / 255.0,
        f32::from(b) / 255.0,
    ))
}

/// Scan for custom themes in the config directory
pub fn load_custom_themes() -> Vec<AppTheme> {
    let mut themes = Vec::new();

    if let Some(mut config_dir) = crate::utils::get_data_dir() {
        config_dir.push("themes");

        if !config_dir.exists() {
            // Create themes directory if it doesn't exist
            let _ = std::fs::create_dir_all(&config_dir);
            return themes;
        }

        if let Ok(entries) = std::fs::read_dir(&config_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                    match ThemeToml::load(&path) {
                        Ok(theme) => {
                            tracing::info!("Loaded custom theme: {}", theme.name);
                            themes.push(theme);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to load theme from {:?}: {}", path, e);
                        }
                    }
                }
            }
        }
    }

    themes
}

/// Create an example custom theme file in the themes directory
pub fn create_example_theme() -> Result<PathBuf, String> {
    let mut config_dir =
        crate::utils::get_data_dir().ok_or_else(|| "Failed to get config directory".to_string())?;

    config_dir.push("themes");
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create themes directory: {}", e))?;

    config_dir.push("example.toml");

    if config_dir.exists() {
        return Ok(config_dir); // Don't overwrite existing example
    }

    let example = r##"# DRFW Custom Theme Example
# Copy this file and customize the colors to create your own theme
# Color format: "#RRGGBB" (hex RGB)

[theme]
name = "My Custom Theme"

[colors]
# Background layers (darkest to lightest)
bg_base = "#1e1e1e"
bg_sidebar = "#181818"
bg_surface = "#252525"
bg_elevated = "#2d2d2d"
bg_hover = "#353535"
bg_active = "#404040"

# Text colors
fg_primary = "#e0e0e0"
fg_secondary = "#b0b0b0"
fg_muted = "#707070"
fg_on_accent = "#1e1e1e"

# Semantic colors
accent = "#569cd6"
accent_hover = "#669de6"
success = "#4ec9b0"
warning = "#dcdcaa"
danger = "#f48771"
info = "#9cdcfe"

# Borders and dividers
border = "#2d2d2d"
border_strong = "#569cd6"
divider = "#252525"

# Syntax highlighting (for nftables preview)
syntax_keyword = "#c586c0"
syntax_type = "#569cd6"
syntax_string = "#ce9178"
syntax_number = "#b5cea8"
syntax_comment = "#6a9955"
syntax_operator = "#d4d4d4"
"##;

    std::fs::write(&config_dir, example)
        .map_err(|e| format!("Failed to write example theme: {}", e))?;

    Ok(config_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_color() {
        let color = parse_color("#FF0000").unwrap();
        assert_eq!(color.r, 1.0);
        assert_eq!(color.g, 0.0);
        assert_eq!(color.b, 0.0);

        let color = parse_color("#00FF00").unwrap();
        assert_eq!(color.r, 0.0);
        assert_eq!(color.g, 1.0);
        assert_eq!(color.b, 0.0);

        let color = parse_color("#0000FF").unwrap();
        assert_eq!(color.r, 0.0);
        assert_eq!(color.g, 0.0);
        assert_eq!(color.b, 1.0);
    }

    #[test]
    fn test_parse_color_invalid() {
        assert!(parse_color("#FF").is_err());
        assert!(parse_color("FFFF").is_err()); // Too short even after removing #
        assert!(parse_color("#GGGGGG").is_err());
    }
}
