pub mod custom;
pub mod presets;

use iced::Color;
use serde::{Deserialize, Serialize};

/// Complete theme definition with semantic color naming
#[derive(Debug, Clone, PartialEq)]
pub struct AppTheme {
    pub name: String,

    // === Background Layers (progressive depth) ===
    pub bg_base: Color,     // App background (deepest)
    pub bg_sidebar: Color,  // Sidebar background
    pub bg_surface: Color,  // Cards, containers
    pub bg_elevated: Color, // Inputs, buttons
    pub bg_hover: Color,    // Hover states
    pub bg_active: Color,   // Active/selected states

    // === Foreground/Text ===
    pub fg_primary: Color,   // Main text
    pub fg_secondary: Color, // Less important text
    pub fg_muted: Color,     // Disabled/placeholder text
    pub fg_on_accent: Color, // Text on accent colors

    // === Semantic Colors ===
    pub accent: Color,       // Brand/primary actions
    pub accent_hover: Color, // Hovered accent
    pub success: Color,      // Positive actions/states
    pub warning: Color,      // Warnings
    pub danger: Color,       // Destructive actions
    pub info: Color,         // Informational

    // === Borders & Dividers ===
    pub border: Color,        // Default borders
    pub border_strong: Color, // Emphasized borders
    pub divider: Color,       // Separators

    // === Syntax Highlighting (for nftables preview) ===
    pub syntax_keyword: Color,  // Keywords (table, chain, etc.)
    pub syntax_type: Color,     // Types (filter, nat, etc.)
    pub syntax_string: Color,   // Strings, comments
    pub syntax_number: Color,   // Numbers, ports
    pub syntax_comment: Color,  // Comments
    pub syntax_operator: Color, // Operators, punctuation

    // === Shadows ===
    pub shadow_color: Color,  // Shadow color (transparent black usually)
    pub shadow_strong: Color, // Stronger shadow for modals
}

impl AppTheme {
    /// Creates a theme from RGB hex values for easier definition
    #[allow(clippy::too_many_arguments)]
    pub fn from_hex(
        name: &str,
        bg_base: u32,
        bg_sidebar: u32,
        bg_surface: u32,
        bg_elevated: u32,
        bg_hover: u32,
        bg_active: u32,
        fg_primary: u32,
        fg_secondary: u32,
        fg_muted: u32,
        fg_on_accent: u32,
        accent: u32,
        accent_hover: u32,
        success: u32,
        warning: u32,
        danger: u32,
        info: u32,
        border: u32,
        border_strong: u32,
        divider: u32,
        syntax_keyword: u32,
        syntax_type: u32,
        syntax_string: u32,
        syntax_number: u32,
        syntax_comment: u32,
        syntax_operator: u32,
    ) -> Self {
        Self {
            name: name.to_string(),
            bg_base: hex_to_color(bg_base),
            bg_sidebar: hex_to_color(bg_sidebar),
            bg_surface: hex_to_color(bg_surface),
            bg_elevated: hex_to_color(bg_elevated),
            bg_hover: hex_to_color(bg_hover),
            bg_active: hex_to_color(bg_active),
            fg_primary: hex_to_color(fg_primary),
            fg_secondary: hex_to_color(fg_secondary),
            fg_muted: hex_to_color(fg_muted),
            fg_on_accent: hex_to_color(fg_on_accent),
            accent: hex_to_color(accent),
            accent_hover: hex_to_color(accent_hover),
            success: hex_to_color(success),
            warning: hex_to_color(warning),
            danger: hex_to_color(danger),
            info: hex_to_color(info),
            border: hex_to_color(border),
            border_strong: hex_to_color(border_strong),
            divider: hex_to_color(divider),
            syntax_keyword: hex_to_color(syntax_keyword),
            syntax_type: hex_to_color(syntax_type),
            syntax_string: hex_to_color(syntax_string),
            syntax_number: hex_to_color(syntax_number),
            syntax_comment: hex_to_color(syntax_comment),
            syntax_operator: hex_to_color(syntax_operator),
            shadow_color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            shadow_strong: Color::from_rgba(0.0, 0.0, 0.0, 0.8),
        }
    }
}

/// Converts hex color (0xRRGGBB) to iced Color
#[allow(clippy::cast_precision_loss)]
fn hex_to_color(hex: u32) -> Color {
    Color::from_rgb(
        ((hex >> 16) & 0xFF) as f32 / 255.0,
        ((hex >> 8) & 0xFF) as f32 / 255.0,
        (hex & 0xFF) as f32 / 255.0,
    )
}

/// All available built-in themes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ThemeChoice {
    #[default]
    Nord,
    Gruvbox,
    Dracula,
    Monokai,
    Everforest,
    TokyoNight,
    CatppuccinMocha,
    OneDark,
    SolarizedDark,
    Custom(usize), // Index into custom themes list
}

impl ThemeChoice {
    pub fn all_builtin() -> &'static [Self] {
        &[
            Self::Nord,
            Self::Gruvbox,
            Self::Dracula,
            Self::Monokai,
            Self::Everforest,
            Self::TokyoNight,
            Self::CatppuccinMocha,
            Self::OneDark,
            Self::SolarizedDark,
        ]
    }

    pub fn name(&self) -> String {
        match self {
            Self::Nord => "Nord".to_string(),
            Self::Gruvbox => "Gruvbox".to_string(),
            Self::Dracula => "Dracula".to_string(),
            Self::Monokai => "Monokai".to_string(),
            Self::Everforest => "Everforest".to_string(),
            Self::TokyoNight => "Tokyo Night".to_string(),
            Self::CatppuccinMocha => "Catppuccin Mocha".to_string(),
            Self::OneDark => "One Dark".to_string(),
            Self::SolarizedDark => "Solarized Dark".to_string(),
            Self::Custom(idx) => format!("Custom {idx}"),
        }
    }

    // Each match arm intentionally calls a different theme function
    // The Custom variant temporarily falls back to Nord until custom theme loading is implemented
    #[allow(clippy::match_same_arms)]
    pub fn to_theme(self) -> AppTheme {
        match self {
            Self::Nord => presets::nord(),
            Self::Gruvbox => presets::gruvbox(),
            Self::Dracula => presets::dracula(),
            Self::Monokai => presets::monokai(),
            Self::Everforest => presets::everforest(),
            Self::TokyoNight => presets::tokyo_night(),
            Self::CatppuccinMocha => presets::catppuccin_mocha(),
            Self::OneDark => presets::one_dark(),
            Self::SolarizedDark => presets::solarized_dark(),
            Self::Custom(_) => presets::nord(), // Will be replaced with custom theme
        }
    }
}

impl std::fmt::Display for ThemeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name())
    }
}
