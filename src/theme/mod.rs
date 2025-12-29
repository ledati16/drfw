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

    // === Zebra Striping ===
    /// Pre-calculated subtle background for even rows in code preview (1.5% difference from `bg_surface`)
    pub zebra_stripe: Color,
}

impl AppTheme {
    /// Creates a theme from RGB hex values for easier definition
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
        let bg_base_color = hex_to_color(bg_base);

        // Calculate if theme is light based on background luminance
        let is_light = color_luminance(&bg_base_color) > 0.5;

        // Set shadow colors appropriate for theme type
        let (shadow_color, shadow_strong) = if is_light {
            // Light themes: crisp and visible without muddiness (35%)
            (
                Color::from_rgba(0.0, 0.0, 0.0, 0.35),
                Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            )
        } else {
            // Dark themes: stronger for pixel-perfect depth (60%)
            (
                Color::from_rgba(0.0, 0.0, 0.0, 0.6),
                Color::from_rgba(0.0, 0.0, 0.0, 0.85),
            )
        };

        // Calculate zebra stripe color (1.5% difference from bg_surface) once per theme
        let bg_surface_color = hex_to_color(bg_surface);
        let zebra_stripe = if is_light {
            // Light themes: slightly darker
            Color {
                r: (bg_surface_color.r * 0.985).max(0.0),
                g: (bg_surface_color.g * 0.985).max(0.0),
                b: (bg_surface_color.b * 0.985).max(0.0),
                ..bg_surface_color
            }
        } else {
            // Dark themes: slightly lighter
            Color {
                r: (bg_surface_color.r * 1.015 + 0.005).min(1.0),
                g: (bg_surface_color.g * 1.015 + 0.005).min(1.0),
                b: (bg_surface_color.b * 1.015 + 0.005).min(1.0),
                ..bg_surface_color
            }
        };

        Self {
            name: name.to_string(),
            bg_base: bg_base_color,
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
            shadow_color,
            shadow_strong,
            zebra_stripe,
        }
    }

    /// Returns `true` if this is a light theme
    pub fn is_light(&self) -> bool {
        color_luminance(&self.bg_base) > 0.5
    }
}

/// Converts hex color (0xRRGGBB) to iced Color
#[allow(clippy::cast_precision_loss)] // RGB components (0-255) fit perfectly in f32 mantissa
fn hex_to_color(hex: u32) -> Color {
    Color::from_rgb(
        ((hex >> 16) & 0xFF) as f32 / 255.0,
        ((hex >> 8) & 0xFF) as f32 / 255.0,
        (hex & 0xFF) as f32 / 255.0,
    )
}

/// Calculates relative luminance using WCAG formula
/// Returns value between 0.0 (black) and 1.0 (white)
fn color_luminance(color: &Color) -> f32 {
    // Apply gamma correction
    let r = if color.r <= 0.03928 {
        color.r / 12.92
    } else {
        ((color.r + 0.055) / 1.055).powf(2.4)
    };
    let g = if color.g <= 0.03928 {
        color.g / 12.92
    } else {
        ((color.g + 0.055) / 1.055).powf(2.4)
    };
    let b = if color.b <= 0.03928 {
        color.b / 12.92
    } else {
        ((color.b + 0.055) / 1.055).powf(2.4)
    };

    // WCAG luminance formula
    0.2126 * r + 0.7152 * g + 0.0722 * b
}

/// All available built-in themes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ThemeChoice {
    // ═══════════════════════════════════════════════════
    // CUSTOM THEMES (Project Defaults)
    // ═══════════════════════════════════════════════════
    #[default]
    Oxide,
    Aethel,

    // ═══════════════════════════════════════════════════
    // POPULAR DARK THEMES (by downloads/rating)
    // ═══════════════════════════════════════════════════
    Dracula,     // 7.5M - Iconic purple/pink
    OneDark,     // 7.2M - VSCode favorite
    Monokai,     // 2M+ - Classic warm
    NightOwl,    // 1.9M
    SynthWave84, // 1.3M - Retro cyberpunk

    // ═══════════════════════════════════════════════════
    // MODERN DARK THEMES
    // ═══════════════════════════════════════════════════
    TokyoNight,
    CatppuccinMocha,
    RosePine,

    // ═══════════════════════════════════════════════════
    // NATURE/ATMOSPHERIC DARK THEMES
    // ═══════════════════════════════════════════════════
    Nord,
    Gruvbox,
    Everforest,
    AyuDark,

    // ═══════════════════════════════════════════════════
    // LIGHT THEMES
    // ═══════════════════════════════════════════════════
    GruvboxLight,
    CatppuccinLatte,
    RosePineDawn,
    EverforestLight,
    OxideLight,
    OneLight,
    SolarizedLight,
}

impl ThemeChoice {
    /// Returns all available themes
    pub fn all() -> &'static [Self] {
        &[
            // Custom themes
            Self::Oxide,
            Self::Aethel,
            // Popular dark themes
            Self::Dracula,
            Self::OneDark,
            Self::Monokai,
            Self::NightOwl,
            Self::SynthWave84,
            // Modern dark themes
            Self::TokyoNight,
            Self::CatppuccinMocha,
            Self::RosePine,
            // Nature/atmospheric dark themes
            Self::Nord,
            Self::Gruvbox,
            Self::Everforest,
            Self::AyuDark,
            // Light themes
            Self::GruvboxLight,
            Self::CatppuccinLatte,
            Self::RosePineDawn,
            Self::EverforestLight,
            Self::OxideLight,
            Self::OneLight,
            Self::SolarizedLight,
        ]
    }

    pub fn name(self) -> String {
        match self {
            // Custom themes
            Self::Oxide => "Oxide".to_string(),
            Self::Aethel => "Aethel".to_string(),
            // Popular dark themes
            Self::Dracula => "Dracula".to_string(),
            Self::OneDark => "One Dark".to_string(),
            Self::Monokai => "Monokai".to_string(),
            Self::NightOwl => "Night Owl".to_string(),
            Self::SynthWave84 => "SynthWave '84".to_string(),
            // Modern dark themes
            Self::TokyoNight => "Tokyo Night".to_string(),
            Self::CatppuccinMocha => "Catppuccin Mocha".to_string(),
            Self::RosePine => "Rosé Pine".to_string(),
            // Nature/atmospheric dark themes
            Self::Nord => "Nord".to_string(),
            Self::Gruvbox => "Gruvbox Dark".to_string(),
            Self::Everforest => "Everforest Dark".to_string(),
            Self::AyuDark => "Ayu Dark".to_string(),
            // Light themes
            Self::GruvboxLight => "Gruvbox Light".to_string(),
            Self::CatppuccinLatte => "Catppuccin Latte".to_string(),
            Self::RosePineDawn => "Rosé Pine Dawn".to_string(),
            Self::EverforestLight => "Everforest Light".to_string(),
            Self::OxideLight => "Oxide Light".to_string(),
            Self::OneLight => "One Light".to_string(),
            Self::SolarizedLight => "Solarized Light".to_string(),
        }
    }

    /// Converts theme choice to actual theme
    pub fn to_theme(self) -> AppTheme {
        match self {
            // Custom themes
            Self::Oxide => presets::oxide(),
            Self::Aethel => presets::aethel(),
            // Popular dark themes
            Self::Dracula => presets::dracula(),
            Self::OneDark => presets::one_dark(),
            Self::Monokai => presets::monokai(),
            Self::NightOwl => presets::night_owl(),
            Self::SynthWave84 => presets::synthwave_84(),
            // Modern dark themes
            Self::TokyoNight => presets::tokyo_night(),
            Self::CatppuccinMocha => presets::catppuccin_mocha(),
            Self::RosePine => presets::rose_pine(),
            // Nature/atmospheric dark themes
            Self::Nord => presets::nord(),
            Self::Gruvbox => presets::gruvbox(),
            Self::Everforest => presets::everforest(),
            Self::AyuDark => presets::ayu_dark(),
            // Light themes
            Self::GruvboxLight => presets::gruvbox_light(),
            Self::CatppuccinLatte => presets::catppuccin_latte(),
            Self::RosePineDawn => presets::rose_pine_dawn(),
            Self::EverforestLight => presets::everforest_light(),
            Self::OxideLight => presets::oxide_light(),
            Self::OneLight => presets::one_light(),
            Self::SolarizedLight => presets::solarized_light(),
        }
    }
}

impl std::fmt::Display for ThemeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name())
    }
}
