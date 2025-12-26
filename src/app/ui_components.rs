use crate::theme::AppTheme;
use iced::widget::{button, container};
use iced::{Border, Color, Shadow, Vector};

pub fn main_container(theme: &AppTheme) -> container::Style {
    container::Style {
        background: Some(theme.bg_base.into()),
        text_color: Some(theme.fg_primary),
        ..Default::default()
    }
}

pub fn sidebar_container(theme: &AppTheme) -> container::Style {
    container::Style {
        background: Some(theme.bg_sidebar.into()),
        border: Border {
            color: theme.border,
            width: 0.0,
            radius: 0.0.into(),
        },
        ..Default::default()
    }
}

pub fn card_container(theme: &AppTheme) -> container::Style {
    container::Style {
        background: Some(theme.bg_surface.into()),
        border: Border {
            color: theme.border,
            width: 1.0,
            radius: 8.0.into(),
        },
        shadow: Shadow {
            color: theme.shadow_color,
            offset: Vector::new(0.0, 2.0),
            blur_radius: 4.0,
        },
        ..Default::default()
    }
}

pub fn active_card_container(theme: &AppTheme) -> container::Style {
    container::Style {
        background: Some(theme.bg_active.into()),
        border: Border {
            color: theme.accent,
            width: 1.0,
            radius: 8.0.into(),
        },
        ..Default::default()
    }
}

pub fn section_header_container(theme: &AppTheme) -> container::Style {
    container::Style {
        background: Some(
            Color {
                a: 0.02,
                ..theme.fg_primary
            }
            .into(),
        ),
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn pill_container(theme: &AppTheme) -> container::Style {
    container::Style {
        background: Some(
            Color {
                a: 0.05,
                ..theme.fg_primary
            }
            .into(),
        ),
        border: Border {
            radius: 20.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn primary_button(theme: &AppTheme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(theme.accent.into()),
        text_color: theme.fg_on_accent,
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(theme.accent_hover.into()),
            ..base
        },
        button::Status::Pressed => button::Style {
            background: Some(theme.accent.into()),
            ..base
        },
        _ => base,
    }
}

pub fn dirty_button(theme: &AppTheme, status: button::Status) -> button::Style {
    let mut style = primary_button(theme, status);
    style.shadow = Shadow {
        color: Color::from_rgba(theme.warning.r, theme.warning.g, theme.warning.b, 0.2),
        offset: Vector::new(0.0, 0.0),
        blur_radius: 8.0,
    };
    style.border.width = 2.0;
    style.border.color = theme.warning;
    style
}

pub fn danger_button(theme: &AppTheme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(theme.danger.into()),
        text_color: theme.fg_on_accent,
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(
                Color {
                    r: (theme.danger.r * 1.1).min(1.0),
                    g: (theme.danger.g * 1.1).min(1.0),
                    b: (theme.danger.b * 1.1).min(1.0),
                    ..theme.danger
                }
                .into(),
            ),
            ..base
        },
        _ => base,
    }
}

pub fn card_button(theme: &AppTheme, _status: button::Status) -> button::Style {
    let c = card_container(theme);
    button::Style {
        background: c.background,
        text_color: theme.fg_primary,
        border: c.border,
        shadow: c.shadow,
        snap: true,
    }
}

pub fn active_card_button(theme: &AppTheme, _status: button::Status) -> button::Style {
    let c = active_card_container(theme);
    button::Style {
        background: c.background,
        text_color: theme.fg_primary,
        border: c.border,
        shadow: c.shadow,
        snap: true,
    }
}

pub fn active_tab_button(app_theme: &AppTheme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(app_theme.bg_elevated.into()),
        text_color: app_theme.fg_primary,
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(app_theme.bg_hover.into()),
            ..base
        },
        _ => base,
    }
}
