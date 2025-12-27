use crate::theme::AppTheme;
use iced::widget::{
    button, checkbox, container, pick_list, rule, scrollable, slider, text_input, toggler,
};
use iced::{Border, Color, Gradient, Shadow, Vector};

pub fn main_container(theme: &AppTheme) -> container::Style {
    container::Style {
        background: Some(theme.bg_base.into()),
        text_color: Some(theme.fg_primary),
        ..Default::default()
    }
}

pub fn sidebar_container(theme: &AppTheme) -> container::Style {
    // Theme-aware gradient: light themes darken, dark themes lighten more dramatically
    let multiplier = if theme.is_light() { 0.80 } else { 1.40 };

    let gradient = Gradient::Linear(iced::gradient::Linear::new(0.0)
        .add_stop(0.0, theme.bg_sidebar)
        .add_stop(1.0, Color {
            r: (theme.bg_sidebar.r * multiplier).min(1.0),
            g: (theme.bg_sidebar.g * multiplier).min(1.0),
            b: (theme.bg_sidebar.b * multiplier).min(1.0),
            ..theme.bg_sidebar
        }));

    container::Style {
        background: Some(gradient.into()),
        border: Border {
            color: theme.border,
            width: 1.0,
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
            blur_radius: 3.0,
        },
        ..Default::default()
    }
}

/// Elevated card container for main content areas (nftables/json/settings)
/// Larger shadow for more visual hierarchy
pub fn elevated_card_container(theme: &AppTheme) -> container::Style {
    container::Style {
        background: Some(theme.bg_surface.into()),
        border: Border {
            color: theme.border,
            width: 1.0,
            radius: 8.0.into(),
        },
        shadow: Shadow {
            color: theme.shadow_color,
            offset: Vector::new(0.0, 4.0),
            blur_radius: 6.0,
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

pub fn primary_button(theme: &AppTheme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(theme.accent.into()),
        text_color: theme.fg_on_accent,
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        shadow: Shadow {
            color: theme.shadow_color,
            offset: Vector::new(0.0, 2.0),
            blur_radius: 3.0,
        },
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(
                Color {
                    r: (theme.accent.r * 1.08).min(1.0),
                    g: (theme.accent.g * 1.08).min(1.0),
                    b: (theme.accent.b * 1.08).min(1.0),
                    ..theme.accent
                }
                .into(),
            ),
            shadow: Shadow {
                color: theme.shadow_color,
                offset: Vector::new(0.0, 2.5),
                blur_radius: 4.0,
            },
            ..base
        },
        button::Status::Pressed => button::Style {
            background: Some(
                Color {
                    r: (theme.accent.r * 0.95).min(1.0),
                    g: (theme.accent.g * 0.95).min(1.0),
                    b: (theme.accent.b * 0.95).min(1.0),
                    ..theme.accent
                }
                .into(),
            ),
            shadow: Shadow {
                color: theme.shadow_color,
                offset: Vector::new(0.0, 0.5),
                blur_radius: 1.5,
            },
            ..base
        },
        button::Status::Disabled => button::Style {
            background: Some(
                Color {
                    a: 0.5,
                    ..theme.accent
                }
                .into(),
            ),
            text_color: Color {
                a: 0.5,
                ..theme.fg_on_accent
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 0.0),
                blur_radius: 0.0,
            },
            ..base
        },
        button::Status::Active => base,
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
        shadow: Shadow {
            color: theme.shadow_color,
            offset: Vector::new(0.0, 2.0),
            blur_radius: 3.0,
        },
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(
                Color {
                    r: (theme.danger.r * 1.08).min(1.0),
                    g: (theme.danger.g * 1.08).min(1.0),
                    b: (theme.danger.b * 1.08).min(1.0),
                    ..theme.danger
                }
                .into(),
            ),
            shadow: Shadow {
                color: theme.shadow_color,
                offset: Vector::new(0.0, 2.5),
                blur_radius: 4.0,
            },
            ..base
        },
        button::Status::Pressed => button::Style {
            background: Some(
                Color {
                    r: (theme.danger.r * 0.95).min(1.0),
                    g: (theme.danger.g * 0.95).min(1.0),
                    b: (theme.danger.b * 0.95).min(1.0),
                    ..theme.danger
                }
                .into(),
            ),
            shadow: Shadow {
                color: theme.shadow_color,
                offset: Vector::new(0.0, 0.5),
                blur_radius: 1.5,
            },
            ..base
        },
        button::Status::Disabled => button::Style {
            background: Some(
                Color {
                    a: 0.5,
                    ..theme.danger
                }
                .into(),
            ),
            text_color: Color {
                a: 0.5,
                ..theme.fg_on_accent
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 0.0),
                blur_radius: 0.0,
            },
            ..base
        },
        button::Status::Active => base,
    }
}

pub fn card_button(theme: &AppTheme, status: button::Status) -> button::Style {
    let c = card_container(theme);
    let base = button::Style {
        background: c.background,
        text_color: theme.fg_primary,
        border: c.border,
        shadow: c.shadow,
        snap: true,
    };

    match status {
        button::Status::Hovered => button::Style {
            shadow: Shadow {
                color: theme.shadow_color,
                offset: Vector::new(0.0, 3.0),
                blur_radius: 6.0,
            },
            ..base
        },
        button::Status::Pressed => button::Style {
            shadow: Shadow {
                color: theme.shadow_color,
                offset: Vector::new(0.0, 1.0),
                blur_radius: 2.0,
            },
            ..base
        },
        button::Status::Active | button::Status::Disabled => base,
    }
}

pub fn active_card_button(theme: &AppTheme, status: button::Status) -> button::Style {
    let c = active_card_container(theme);
    let base = button::Style {
        background: c.background,
        text_color: theme.fg_primary,
        border: c.border,
        shadow: Shadow {
            color: theme.shadow_color,
            offset: Vector::new(0.0, 2.0),
            blur_radius: 4.0,
        },
        snap: true,
    };

    match status {
        button::Status::Hovered => button::Style {
            shadow: Shadow {
                color: theme.shadow_color,
                offset: Vector::new(0.0, 3.0),
                blur_radius: 6.0,
            },
            ..base
        },
        button::Status::Pressed => button::Style {
            shadow: Shadow {
                color: theme.shadow_color,
                offset: Vector::new(0.0, 1.0),
                blur_radius: 2.0,
            },
            ..base
        },
        _ => base,
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
        shadow: Shadow {
            color: app_theme.shadow_color,
            offset: Vector::new(0.0, 2.0),
            blur_radius: 4.0,
        },
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(app_theme.bg_hover.into()),
            shadow: Shadow {
                color: app_theme.shadow_color,
                offset: Vector::new(0.0, 3.0),
                blur_radius: 6.0,
            },
            ..base
        },
        button::Status::Pressed => button::Style {
            background: Some(app_theme.bg_elevated.into()),
            shadow: Shadow {
                color: app_theme.shadow_color,
                offset: Vector::new(0.0, 1.0),
                blur_radius: 2.0,
            },
            ..base
        },
        _ => base,
    }
}

pub fn secondary_button(theme: &AppTheme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(theme.bg_surface.into()),
        text_color: theme.fg_primary,
        border: Border {
            color: theme.border,
            width: 1.0,
            radius: 4.0.into(),
        },
        shadow: Shadow {
            color: theme.shadow_color,
            offset: Vector::new(0.0, 2.0),
            blur_radius: 3.0,
        },
        ..Default::default()
    };

    match status {
        button::Status::Hovered => button::Style {
            background: Some(
                Color {
                    r: (theme.bg_surface.r * 1.08).min(1.0),
                    g: (theme.bg_surface.g * 1.08).min(1.0),
                    b: (theme.bg_surface.b * 1.08).min(1.0),
                    ..theme.bg_surface
                }
                .into(),
            ),
            shadow: Shadow {
                color: theme.shadow_color,
                offset: Vector::new(0.0, 2.5),
                blur_radius: 4.0,
            },
            ..base
        },
        button::Status::Pressed => button::Style {
            background: Some(
                Color {
                    r: (theme.bg_surface.r * 0.95).min(1.0),
                    g: (theme.bg_surface.g * 0.95).min(1.0),
                    b: (theme.bg_surface.b * 0.95).min(1.0),
                    ..theme.bg_surface
                }
                .into(),
            ),
            shadow: Shadow {
                color: theme.shadow_color,
                offset: Vector::new(0.0, 0.5),
                blur_radius: 1.5,
            },
            ..base
        },
        button::Status::Disabled => button::Style {
            background: Some(
                Color {
                    a: 0.5,
                    ..theme.bg_surface
                }
                .into(),
            ),
            text_color: theme.fg_muted,
            border: Border {
                color: Color {
                    a: 0.3,
                    ..theme.border
                },
                width: 1.0,
                radius: 4.0.into(),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 0.0),
                blur_radius: 0.0,
            },
            ..Default::default()
        },
        button::Status::Active => base,
    }
}

/// Text input styling with theme-aware colors
pub fn themed_text_input(theme: &AppTheme, status: text_input::Status) -> text_input::Style {
    match status {
        text_input::Status::Active => text_input::Style {
            background: theme.bg_elevated.into(),
            border: Border {
                color: theme.border,
                width: 1.0,
                radius: 4.0.into(),
            },
            icon: theme.fg_muted,
            placeholder: theme.fg_muted,
            value: theme.fg_primary,
            selection: theme.accent,
        },
        text_input::Status::Hovered => text_input::Style {
            background: theme.bg_hover.into(),
            border: Border {
                color: theme.border_strong,
                width: 1.0,
                radius: 4.0.into(),
            },
            icon: theme.fg_secondary,
            placeholder: theme.fg_muted,
            value: theme.fg_primary,
            selection: theme.accent,
        },
        text_input::Status::Focused { .. } => text_input::Style {
            background: theme.bg_elevated.into(),
            border: Border {
                color: theme.accent,
                width: 2.0,
                radius: 4.0.into(),
            },
            icon: theme.accent,
            placeholder: theme.fg_muted,
            value: theme.fg_primary,
            selection: theme.accent,
        },
        text_input::Status::Disabled => text_input::Style {
            background: Color { a: 0.5, ..theme.bg_elevated }.into(),
            border: Border {
                color: Color { a: 0.3, ..theme.border },
                width: 1.0,
                radius: 4.0.into(),
            },
            icon: theme.fg_muted,
            placeholder: theme.fg_muted,
            value: theme.fg_muted,
            selection: theme.accent,
        },
    }
}

/// Pick list (dropdown) styling with theme-aware colors
pub fn themed_pick_list(theme: &AppTheme, status: pick_list::Status) -> pick_list::Style {
    match status {
        pick_list::Status::Active => pick_list::Style {
            background: theme.bg_elevated.into(),
            border: Border {
                color: theme.border,
                width: 1.0,
                radius: 4.0.into(),
            },
            handle_color: theme.fg_secondary,
            placeholder_color: theme.fg_muted,
            text_color: theme.fg_primary,
        },
        pick_list::Status::Hovered => pick_list::Style {
            background: theme.bg_hover.into(),
            border: Border {
                color: theme.border_strong,
                width: 1.0,
                radius: 4.0.into(),
            },
            handle_color: theme.fg_primary,
            placeholder_color: theme.fg_muted,
            text_color: theme.fg_primary,
        },
        pick_list::Status::Opened { .. } => pick_list::Style {
            background: theme.bg_elevated.into(),
            border: Border {
                color: theme.accent,
                width: 2.0,
                radius: 4.0.into(),
            },
            handle_color: theme.accent,
            placeholder_color: theme.fg_muted,
            text_color: theme.fg_primary,
        },
    }
}

/// Pick list menu styling (the dropdown menu itself)
pub fn themed_pick_list_menu(theme: &AppTheme) -> iced::overlay::menu::Style {
    iced::overlay::menu::Style {
        background: theme.bg_surface.into(),
        border: Border {
            color: theme.border_strong,
            width: 1.0,
            radius: 4.0.into(),
        },
        shadow: Shadow {
            color: theme.shadow_color,
            offset: Vector::new(0.0, 4.0),
            blur_radius: 8.0,
        },
        text_color: theme.fg_primary,
        selected_background: theme.bg_hover.into(),
        selected_text_color: theme.fg_primary,
    }
}

/// Slider styling with theme-aware colors
pub fn themed_slider(theme: &AppTheme, status: slider::Status) -> slider::Style {
    let rail = slider::Rail {
        backgrounds: (theme.bg_hover.into(), theme.accent.into()),
        width: 4.0,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 2.0.into(),
        },
    };

    let handle = slider::Handle {
        shape: slider::HandleShape::Circle { radius: 8.0 },
        background: theme.accent.into(),
        border_color: theme.bg_elevated,
        border_width: 2.0,
    };

    match status {
        slider::Status::Active => slider::Style { rail, handle },
        slider::Status::Hovered => slider::Style {
            rail,
            handle: slider::Handle {
                background: theme.accent_hover.into(),
                ..handle
            },
        },
        slider::Status::Dragged => slider::Style {
            rail: slider::Rail {
                backgrounds: (theme.bg_hover.into(), theme.accent_hover.into()),
                ..rail
            },
            handle: slider::Handle {
                background: theme.accent_hover.into(),
                border_width: 3.0,
                ..handle
            },
        },
    }
}

/// Checkbox styling with theme-aware colors
pub fn themed_checkbox(theme: &AppTheme, status: checkbox::Status) -> checkbox::Style {
    let base = checkbox::Style {
        background: theme.bg_elevated.into(),
        icon_color: theme.fg_on_accent,
        border: Border {
            color: theme.border,
            width: 1.0,
            radius: 3.0.into(),
        },
        text_color: Some(theme.fg_primary),
    };

    match status {
        checkbox::Status::Active { is_checked } => {
            if is_checked {
                checkbox::Style {
                    background: theme.accent.into(),
                    border: Border {
                        color: theme.accent,
                        width: 1.0,
                        radius: 3.0.into(),
                    },
                    ..base
                }
            } else {
                base
            }
        }
        checkbox::Status::Hovered { is_checked } => {
            if is_checked {
                checkbox::Style {
                    background: theme.accent_hover.into(),
                    border: Border {
                        color: theme.accent_hover,
                        width: 1.0,
                        radius: 3.0.into(),
                    },
                    ..base
                }
            } else {
                checkbox::Style {
                    background: theme.bg_hover.into(),
                    border: Border {
                        color: theme.border_strong,
                        width: 1.0,
                        radius: 3.0.into(),
                    },
                    ..base
                }
            }
        }
        checkbox::Status::Disabled { .. } => checkbox::Style {
            background: Color {
                a: 0.5,
                ..theme.bg_elevated
            }
            .into(),
            border: Border {
                color: Color {
                    a: 0.3,
                    ..theme.border
                },
                width: 1.0,
                radius: 3.0.into(),
            },
            text_color: Some(theme.fg_muted),
            ..base
        },
    }
}

/// Toggler styling with theme-aware colors
pub fn themed_toggler(theme: &AppTheme, status: toggler::Status) -> toggler::Style {
    let base = toggler::Style {
        background: theme.bg_elevated.into(),
        background_border_width: 1.0,
        background_border_color: theme.border,
        border_radius: Some(10.0.into()),
        foreground: theme.fg_muted.into(),
        foreground_border_width: 0.0,
        foreground_border_color: Color::TRANSPARENT,
        padding_ratio: 0.5,
        text_color: Some(theme.fg_primary),
    };

    match status {
        toggler::Status::Active { is_toggled } => {
            if is_toggled {
                toggler::Style {
                    background: theme.accent.into(),
                    background_border_color: theme.accent,
                    foreground: theme.fg_on_accent.into(),
                    ..base
                }
            } else {
                base
            }
        }
        toggler::Status::Hovered { is_toggled } => {
            if is_toggled {
                toggler::Style {
                    background: theme.accent_hover.into(),
                    background_border_color: theme.accent_hover,
                    foreground: theme.fg_on_accent.into(),
                    ..base
                }
            } else {
                toggler::Style {
                    background: theme.bg_hover.into(),
                    background_border_color: theme.border_strong,
                    ..base
                }
            }
        }
        toggler::Status::Disabled { .. } => toggler::Style {
            background: Color {
                a: 0.5,
                ..theme.bg_elevated
            }
            .into(),
            background_border_color: Color {
                a: 0.3,
                ..theme.border
            },
            foreground: theme.fg_muted.into(),
            ..base
        },
    }
}

/// Semi-transparent modal backdrop that works with both light and dark themes
pub fn modal_backdrop(theme: &AppTheme) -> container::Style {
    container::Style {
        background: Some(
            Color {
                a: 0.85,
                ..theme.bg_base
            }
            .into(),
        ),
        ..Default::default()
    }
}

/// Themed horizontal rule (separator line)
pub fn themed_horizontal_rule(theme: &AppTheme) -> rule::Style {
    rule::Style {
        color: theme.border,
        radius: 0.0.into(),
        fill_mode: rule::FillMode::Full,
        snap: true,
    }
}

/// Themed vertical rule (separator line)
#[allow(dead_code)] // Available for future use
pub fn themed_vertical_rule(theme: &AppTheme) -> rule::Style {
    rule::Style {
        color: theme.border,
        radius: 0.0.into(),
        fill_mode: rule::FillMode::Full,
        snap: true,
    }
}

/// Themed scrollable with visible scrollbars
pub fn themed_scrollable(theme: &AppTheme, status: scrollable::Status) -> scrollable::Style {
    let rail = scrollable::Rail {
        background: Some(theme.bg_elevated.into()),
        border: Border {
            color: theme.border,
            width: 0.0,
            radius: 4.0.into(),
        },
        scroller: scrollable::Scroller {
            background: theme.fg_muted.into(),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 4.0.into(),
            },
        },
    };

    let auto_scroll = scrollable::AutoScroll {
        background: theme.bg_surface.into(),
        border: Border {
            color: theme.border,
            width: 1.0,
            radius: 4.0.into(),
        },
        shadow: iced::Shadow {
            color: theme.shadow_color,
            offset: iced::Vector::new(0.0, 2.0),
            blur_radius: 4.0,
        },
        icon: theme.fg_primary,
    };

    match status {
        scrollable::Status::Active { .. } => scrollable::Style {
            container: container::Style::default(),
            vertical_rail: rail,
            horizontal_rail: rail,
            gap: None,
            auto_scroll,
        },
        scrollable::Status::Hovered {
            is_horizontal_scrollbar_hovered,
            is_vertical_scrollbar_hovered,
            ..
        } => {
            // Change color when either scrollbar is hovered
            let is_any_hovered = is_horizontal_scrollbar_hovered || is_vertical_scrollbar_hovered;
            let hovered_rail = scrollable::Rail {
                scroller: scrollable::Scroller {
                    background: if is_any_hovered {
                        theme.fg_secondary.into()
                    } else {
                        theme.fg_muted.into()
                    },
                    border: Border {
                        color: Color::TRANSPARENT,
                        width: 0.0,
                        radius: 4.0.into(),
                    },
                },
                ..rail
            };

            scrollable::Style {
                container: container::Style::default(),
                vertical_rail: hovered_rail,
                horizontal_rail: hovered_rail,
                gap: None,
                auto_scroll,
            }
        }
        scrollable::Status::Dragged { .. } => {
            let dragged_rail = scrollable::Rail {
                scroller: scrollable::Scroller {
                    background: theme.accent.into(),
                    border: Border {
                        color: Color::TRANSPARENT,
                        width: 0.0,
                        radius: 4.0.into(),
                    },
                },
                ..rail
            };

            scrollable::Style {
                container: container::Style::default(),
                vertical_rail: dragged_rail,
                horizontal_rail: dragged_rail,
                gap: None,
                auto_scroll,
            }
        }
    }
}
