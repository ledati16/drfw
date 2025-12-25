use crate::theme::AppTheme;
use iced::widget::{button, container};
use iced::{Border, Color, Shadow, Theme, Vector};

// Re-export legacy constants for backward compatibility during migration
// These will be removed once all view code is updated
pub use legacy::*;

/// Main container style
pub fn main_container(theme: &AppTheme, _t: &Theme) -> container::Style {
    container::Style {
        background: Some(theme.bg_base.into()),
        text_color: Some(theme.fg_primary),
        ..Default::default()
    }
}

/// Sidebar container style
pub fn sidebar_container(theme: &AppTheme) -> impl Fn(&Theme) -> container::Style {
    let bg = theme.bg_sidebar;
    let border_color = theme.border;
    move |_t| container::Style {
        background: Some(bg.into()),
        border: Border {
            color: border_color,
            width: 0.0,
            radius: 0.0.into(),
        },
        ..Default::default()
    }
}

/// Card container style
pub fn card_container(theme: &AppTheme) -> impl Fn(&Theme) -> container::Style {
    let bg = theme.bg_surface;
    let border_color = theme.border;
    let shadow_color = theme.shadow_color;
    move |_t| container::Style {
        background: Some(bg.into()),
        border: Border {
            color: border_color,
            width: 1.0,
            radius: 8.0.into(),
        },
        shadow: Shadow {
            color: shadow_color,
            offset: Vector::new(0.0, 2.0),
            blur_radius: 4.0,
        },
        ..Default::default()
    }
}

/// Active/selected card container style
pub fn active_card_container(theme: &AppTheme) -> impl Fn(&Theme) -> container::Style {
    let bg = theme.bg_active;
    let border_color = theme.accent;
    let fg = theme.fg_primary;
    move |_t| container::Style {
        background: Some(bg.into()),
        text_color: Some(fg),
        border: Border {
            color: border_color,
            width: 1.0,
            radius: 8.0.into(),
        },
        ..Default::default()
    }
}

/// Hovered card container style
pub fn hovered_card_container(theme: &AppTheme) -> impl Fn(&Theme) -> container::Style {
    let bg = theme.bg_hover;
    let border_color = theme.border;
    let shadow_color = theme.shadow_color;
    move |_t| container::Style {
        background: Some(bg.into()),
        border: Border {
            color: border_color,
            width: 1.0,
            radius: 8.0.into(),
        },
        shadow: Shadow {
            color: shadow_color,
            offset: Vector::new(0.0, 3.0),
            blur_radius: 6.0,
        },
        ..Default::default()
    }
}

/// Section header container style
pub fn section_header_container(theme: &AppTheme) -> impl Fn(&Theme) -> container::Style {
    let bg = theme.bg_elevated;
    move |_t| container::Style {
        background: Some(bg.into()),
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Pill-shaped container style
pub fn pill_container(theme: &AppTheme) -> impl Fn(&Theme) -> container::Style {
    let bg = theme.bg_elevated;
    move |_t| container::Style {
        background: Some(bg.into()),
        border: Border {
            radius: 20.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Primary button style
pub fn primary_button(theme: &AppTheme) -> impl Fn(&Theme, button::Status) -> button::Style {
    let accent = theme.accent;
    let accent_hover = theme.accent_hover;
    let fg_on_accent = theme.fg_on_accent;

    move |_t, status| {
        let base = button::Style {
            background: Some(accent.into()),
            text_color: fg_on_accent,
            border: Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        };

        match status {
            button::Status::Hovered => button::Style {
                background: Some(accent_hover.into()),
                ..base
            },
            button::Status::Pressed => button::Style {
                background: Some(darken(accent, 0.2).into()),
                ..base
            },
            _ => base,
        }
    }
}

/// Dirty/unsaved changes button style (glowing effect)
pub fn dirty_button(theme: &AppTheme) -> impl Fn(&Theme, button::Status) -> button::Style {
    let accent = theme.accent;
    let accent_hover = theme.accent_hover;
    let warning = theme.warning;
    let fg_on_accent = theme.fg_on_accent;

    move |_t, status| {
        let mut style = button::Style {
            background: Some(accent.into()),
            text_color: fg_on_accent,
            border: Border {
                color: warning,
                width: 2.0,
                radius: 4.0.into(),
            },
            shadow: Shadow {
                color: Color::from_rgba(warning.r, warning.g, warning.b, 0.2),
                offset: Vector::new(0.0, 0.0),
                blur_radius: 8.0,
            },
            ..Default::default()
        };

        if status == button::Status::Hovered {
            style.background = Some(accent_hover.into());
        }

        style
    }
}

/// Danger/destructive action button style
pub fn danger_button(theme: &AppTheme) -> impl Fn(&Theme, button::Status) -> button::Style {
    let danger = theme.danger;
    let fg_primary = theme.fg_primary;

    move |_t, status| {
        let base = button::Style {
            background: Some(danger.into()),
            text_color: fg_primary,
            border: Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        };

        match status {
            button::Status::Hovered => button::Style {
                background: Some(lighten(danger, 0.1).into()),
                ..base
            },
            _ => base,
        }
    }
}

/// Card-style button (inherits card container styling)
pub fn card_button(theme: &AppTheme) -> impl Fn(&Theme, button::Status) -> button::Style {
    let bg = theme.bg_surface;
    let border_color = theme.border;
    let shadow_color = theme.shadow_color;
    let fg = theme.fg_primary;

    move |_t, _status| {
        button::Style {
            background: Some(bg.into()),
            text_color: fg,
            border: Border {
                color: border_color,
                width: 1.0,
                radius: 8.0.into(),
            },
            shadow: Shadow {
                color: shadow_color,
                offset: Vector::new(0.0, 2.0),
                blur_radius: 4.0,
            },
        }
    }
}

/// Hovered card button style
pub fn hovered_card_button(theme: &AppTheme) -> impl Fn(&Theme, button::Status) -> button::Style {
    let bg = theme.bg_hover;
    let border_color = theme.border;
    let shadow_color = theme.shadow_color;
    let fg = theme.fg_primary;

    move |_t, _status| {
        button::Style {
            background: Some(bg.into()),
            text_color: fg,
            border: Border {
                color: border_color,
                width: 1.0,
                radius: 8.0.into(),
            },
            shadow: Shadow {
                color: shadow_color,
                offset: Vector::new(0.0, 3.0),
                blur_radius: 6.0,
            },
        }
    }
}

/// Active/selected card button style
pub fn active_card_button(theme: &AppTheme) -> impl Fn(&Theme, button::Status) -> button::Style {
    let bg = theme.bg_active;
    let border_color = theme.accent;
    let fg = theme.fg_primary;

    move |_t, _status| {
        button::Style {
            background: Some(bg.into()),
            text_color: fg,
            border: Border {
                color: border_color,
                width: 1.0,
                radius: 8.0.into(),
            },
            shadow: Shadow::default(),
        }
    }
}

/// Active tab button style
pub fn active_tab_button(theme: &AppTheme) -> impl Fn(&Theme, button::Status) -> button::Style {
    let bg = theme.bg_active;
    let fg = theme.fg_primary;

    move |_t, _status| {
        button::Style {
            background: Some(bg.into()),
            text_color: fg,
            border: Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

/// Helper: darken a color
fn darken(color: Color, amount: f32) -> Color {
    Color::from_rgb(
        (color.r * (1.0 - amount)).max(0.0),
        (color.g * (1.0 - amount)).max(0.0),
        (color.b * (1.0 - amount)).max(0.0),
    )
}

/// Helper: lighten a color
fn lighten(color: Color, amount: f32) -> Color {
    Color::from_rgb(
        (color.r + (1.0 - color.r) * amount).min(1.0),
        (color.g + (1.0 - color.g) * amount).min(1.0),
        (color.b + (1.0 - color.b) * amount).min(1.0),
    )
}

/// Legacy module for backward compatibility
/// These exports use hardcoded Gruvbox colors and will be phased out
mod legacy {
    use super::*;

    // Gruvbox Dark Palette (for legacy compatibility)
    pub const GRUV_BG0: Color = Color::from_rgb(0.157, 0.157, 0.157);
    pub const GRUV_BG1: Color = Color::from_rgb(0.235, 0.219, 0.212);
    pub const GRUV_BG2: Color = Color::from_rgb(0.314, 0.286, 0.271);
    pub const GRUV_FG0: Color = Color::from_rgb(0.984, 0.945, 0.780);
    pub const GRUV_FG4: Color = Color::from_rgb(0.659, 0.600, 0.518);

    pub const GRUV_RED: Color = Color::from_rgb(0.800, 0.141, 0.114);
    pub const GRUV_GREEN: Color = Color::from_rgb(0.596, 0.592, 0.102);
    pub const GRUV_YELLOW: Color = Color::from_rgb(0.839, 0.514, 0.086);
    pub const GRUV_BLUE: Color = Color::from_rgb(0.271, 0.447, 0.475);
    pub const GRUV_PURPLE: Color = Color::from_rgb(0.690, 0.384, 0.525);
    pub const GRUV_AQUA: Color = Color::from_rgb(0.424, 0.588, 0.522);
    pub const GRUV_ORANGE: Color = Color::from_rgb(0.839, 0.302, 0.051);

    pub const ACCENT: Color = GRUV_YELLOW;
    pub const SUCCESS: Color = GRUV_GREEN;
    pub const DANGER: Color = GRUV_RED;
    pub const TEXT_BRIGHT: Color = GRUV_FG0;
    pub const TEXT_DIM: Color = GRUV_FG4;
}
