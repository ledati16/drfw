/// New theme-aware UI components
/// These provide helper functions to get colors from the current theme

use crate::theme::AppTheme;
use iced::Color;

/// Get colors from theme for use in view code
pub struct ThemeColors {
    // Backgrounds
    pub bg_base: Color,
    pub bg_sidebar: Color,
    pub bg_surface: Color,
    pub bg_elevated: Color,
    pub bg_hover: Color,
    pub bg_active: Color,

    // Foregrounds
    pub fg_primary: Color,
    pub fg_secondary: Color,
    pub fg_muted: Color,
    pub fg_on_accent: Color,

    // Semantic
    pub accent: Color,
    pub accent_hover: Color,
    pub success: Color,
    pub warning: Color,
    pub danger: Color,
    pub info: Color,

    // Borders
    pub border: Color,
    pub border_strong: Color,
    pub divider: Color,

    // Syntax
    pub syntax_keyword: Color,
    pub syntax_type: Color,
    pub syntax_string: Color,
    pub syntax_number: Color,
    pub syntax_comment: Color,
    pub syntax_operator: Color,

    // Shadows
    pub shadow_color: Color,
    pub shadow_strong: Color,
}

impl From<&AppTheme> for ThemeColors {
    fn from(theme: &AppTheme) -> Self {
        Self {
            bg_base: theme.bg_base,
            bg_sidebar: theme.bg_sidebar,
            bg_surface: theme.bg_surface,
            bg_elevated: theme.bg_elevated,
            bg_hover: theme.bg_hover,
            bg_active: theme.bg_active,
            fg_primary: theme.fg_primary,
            fg_secondary: theme.fg_secondary,
            fg_muted: theme.fg_muted,
            fg_on_accent: theme.fg_on_accent,
            accent: theme.accent,
            accent_hover: theme.accent_hover,
            success: theme.success,
            warning: theme.warning,
            danger: theme.danger,
            info: theme.info,
            border: theme.border,
            border_strong: theme.border_strong,
            divider: theme.divider,
            syntax_keyword: theme.syntax_keyword,
            syntax_type: theme.syntax_type,
            syntax_string: theme.syntax_string,
            syntax_number: theme.syntax_number,
            syntax_comment: theme.syntax_comment,
            syntax_operator: theme.syntax_operator,
            shadow_color: theme.shadow_color,
            shadow_strong: theme.shadow_strong,
        }
    }
}
