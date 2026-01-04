pub mod presets;

use iced::Color;
use serde::{Deserialize, Serialize};

// Shadow alpha values for depth perception
// These constants define the opacity of drop shadows for different theme types
const SHADOW_LIGHT_ALPHA: f32 = 0.35; // Light themes: crisp and visible
const SHADOW_LIGHT_STRONG_ALPHA: f32 = 0.5; // Light themes: emphasized depth
const SHADOW_DARK_ALPHA: f32 = 0.6; // Dark themes: visible against dark backgrounds
const SHADOW_DARK_STRONG_ALPHA: f32 = 0.85; // Dark themes: maximum depth

/// Complete theme definition with semantic color naming
#[derive(Debug, Clone, PartialEq)]
pub struct AppTheme {
    pub name: &'static str, // Issue #8: Static string to avoid heap allocation

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
        name: &'static str, // Issue #8: Static string (no allocation)
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
            (
                Color::from_rgba(0.0, 0.0, 0.0, SHADOW_LIGHT_ALPHA),
                Color::from_rgba(0.0, 0.0, 0.0, SHADOW_LIGHT_STRONG_ALPHA),
            )
        } else {
            (
                Color::from_rgba(0.0, 0.0, 0.0, SHADOW_DARK_ALPHA),
                Color::from_rgba(0.0, 0.0, 0.0, SHADOW_DARK_STRONG_ALPHA),
            )
        };

        // Calculate zebra stripe color (2-3% difference from bg_surface) once per theme
        let bg_surface_color = hex_to_color(bg_surface);
        let zebra_stripe = if is_light {
            // Light themes: slightly darker (2%)
            Color {
                r: (bg_surface_color.r * 0.98).max(0.0),
                g: (bg_surface_color.g * 0.98).max(0.0),
                b: (bg_surface_color.b * 0.98).max(0.0),
                ..bg_surface_color
            }
        } else {
            // Dark themes: slightly lighter (2% + 1% boost = 3%)
            Color {
                r: (bg_surface_color.r * 1.02 + 0.01).min(1.0),
                g: (bg_surface_color.g * 1.02 + 0.01).min(1.0),
                b: (bg_surface_color.b * 1.02 + 0.01).min(1.0),
                ..bg_surface_color
            }
        };

        Self {
            name, // Issue #8: Use static str directly (no allocation)
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
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    strum::EnumString,
    strum::EnumIter,
    strum::AsRefStr,
)]
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
    GitHubDark,       // 17.9M - #1 most popular globally
    Dracula,          // 7.5M - Iconic purple/pink
    OneDark,          // 7.2M - VSCode favorite
    Monokai,          // 2M+ - Classic warm
    MaterialPalenight, // 2.46M - Purple-blue professional
    NightOwl,         // 1.9M - Accessible dark navy
    SynthWave84,      // 1.3M - Retro cyberpunk
    MinDark,          // 551K - Minimal aesthetic

    // ═══════════════════════════════════════════════════
    // MODERN DARK THEMES
    // ═══════════════════════════════════════════════════
    TokyoNight,
    CatppuccinMocha,
    RosePine,
    Poimandres, // 141K - Semantic minimalist
    Pnevma,     // High-contrast neutral with desaturated earth tones

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
    GitHubLight,
    GruvboxLight,
    CatppuccinLatte,
    RosePineDawn,
    EverforestLight,
    OxideLight,
    OneLight,
    SolarizedLight,
}

impl ThemeChoice {
    pub fn name(self) -> &'static str {
        // Issue #8: Return static strings (no allocation)
        match self {
            // Custom themes
            Self::Oxide => "Oxide",
            Self::Aethel => "Aethel",
            // Popular dark themes
            Self::GitHubDark => "GitHub Dark",
            Self::Dracula => "Dracula",
            Self::OneDark => "One Dark",
            Self::Monokai => "Monokai",
            Self::MaterialPalenight => "Material Palenight",
            Self::NightOwl => "Night Owl",
            Self::SynthWave84 => "SynthWave '84",
            Self::MinDark => "Min Dark",
            // Modern dark themes
            Self::TokyoNight => "Tokyo Night",
            Self::CatppuccinMocha => "Catppuccin Mocha",
            Self::RosePine => "Rosé Pine",
            Self::Poimandres => "Poimandres",
            Self::Pnevma => "Pnevma",
            // Nature/atmospheric dark themes
            Self::Nord => "Nord",
            Self::Gruvbox => "Gruvbox Dark",
            Self::Everforest => "Everforest Dark",
            Self::AyuDark => "Ayu Dark",
            // Light themes
            Self::GitHubLight => "GitHub Light",
            Self::GruvboxLight => "Gruvbox Light",
            Self::CatppuccinLatte => "Catppuccin Latte",
            Self::RosePineDawn => "Rosé Pine Dawn",
            Self::EverforestLight => "Everforest Light",
            Self::OxideLight => "Oxide Light",
            Self::OneLight => "One Light",
            Self::SolarizedLight => "Solarized Light",
        }
    }

    /// Converts theme choice to actual theme
    pub fn to_theme(self) -> AppTheme {
        match self {
            // Custom themes
            Self::Oxide => presets::oxide(),
            Self::Aethel => presets::aethel(),
            // Popular dark themes
            Self::GitHubDark => presets::github_dark(),
            Self::Dracula => presets::dracula(),
            Self::OneDark => presets::one_dark(),
            Self::Monokai => presets::monokai(),
            Self::MaterialPalenight => presets::material_palenight(),
            Self::NightOwl => presets::night_owl(),
            Self::SynthWave84 => presets::synthwave_84(),
            Self::MinDark => presets::min_dark(),
            // Modern dark themes
            Self::TokyoNight => presets::tokyo_night(),
            Self::CatppuccinMocha => presets::catppuccin_mocha(),
            Self::RosePine => presets::rose_pine(),
            Self::Poimandres => presets::poimandres(),
            Self::Pnevma => presets::pnevma(),
            // Nature/atmospheric dark themes
            Self::Nord => presets::nord(),
            Self::Gruvbox => presets::gruvbox(),
            Self::Everforest => presets::everforest(),
            Self::AyuDark => presets::ayu_dark(),
            // Light themes
            Self::GitHubLight => presets::github_light(),
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
        f.write_str(self.name())
    }
}
