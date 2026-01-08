use crate::theme::AppTheme;
use iced::widget::{
    button, checkbox, container, pick_list, rule, scrollable, slider, text_input, toggler,
};
use iced::{Border, Color, Gradient, Shadow, Vector};

// =============================================================================
// BUTTON STYLING SYSTEM (Phase 2.1-2.2 refactor)
// =============================================================================

/// Configuration for button styling variations
#[derive(Debug, Clone, Copy)]
struct ButtonStyleConfig {
    /// Base background color source
    base_color: ButtonColorSource,

    /// Text color
    text_color: ButtonTextColor,

    /// Border configuration
    border_width: f32,
    border_radius: f32,
    use_theme_border_color: bool,

    /// Shadow configuration
    shadow_offset: (f32, f32),
    shadow_blur: f32,

    /// Hover state multiplier (1.0 = no change)
    hover_brightness: f32,
    hover_shadow_offset: (f32, f32),
    hover_shadow_blur: f32,

    /// Pressed state multiplier (1.0 = no change)
    pressed_brightness: f32,
    pressed_shadow_offset: (f32, f32),
    pressed_shadow_blur: f32,

    /// Whether to handle disabled state
    has_disabled_state: bool,

    /// Whether to enable snap behavior
    snap: bool,
}

#[derive(Debug, Clone, Copy)]
enum ButtonColorSource {
    Accent,
    Danger,
    Surface,
    /// For tabs: use pre-defined `accent_hover` on hover
    AccentWithHoverColor,
    /// For dirty button: pre-shift warning color
    ShiftedWarning,
    /// For card buttons: use container styling
    CardContainer,
    ActiveCardContainer,
}

#[derive(Debug, Clone, Copy)]
enum ButtonTextColor {
    OnAccent,
    Primary,
}

impl ButtonStyleConfig {
    const PRIMARY: Self = Self {
        base_color: ButtonColorSource::Accent,
        text_color: ButtonTextColor::OnAccent,
        border_width: 0.0,
        border_radius: 4.0,
        use_theme_border_color: false,
        shadow_offset: (0.0, 2.0),
        shadow_blur: 3.0,
        hover_brightness: 1.08,
        hover_shadow_offset: (0.0, 2.5),
        hover_shadow_blur: 4.0,
        pressed_brightness: 0.95,
        pressed_shadow_offset: (0.0, 0.5),
        pressed_shadow_blur: 1.5,
        has_disabled_state: true,
        snap: false,
    };

    const DANGER: Self = Self {
        base_color: ButtonColorSource::Danger,
        text_color: ButtonTextColor::OnAccent,
        border_width: 0.0,
        border_radius: 4.0,
        use_theme_border_color: false,
        shadow_offset: (0.0, 2.0),
        shadow_blur: 3.0,
        hover_brightness: 1.08,
        hover_shadow_offset: (0.0, 2.5),
        hover_shadow_blur: 4.0,
        pressed_brightness: 0.95,
        pressed_shadow_offset: (0.0, 0.5),
        pressed_shadow_blur: 1.5,
        has_disabled_state: true,
        snap: false,
    };

    const DIRTY: Self = Self {
        base_color: ButtonColorSource::ShiftedWarning,
        text_color: ButtonTextColor::OnAccent,
        border_width: 0.0,
        border_radius: 4.0,
        use_theme_border_color: false,
        shadow_offset: (0.0, 2.0),
        shadow_blur: 3.0,
        hover_brightness: 1.08,
        hover_shadow_offset: (0.0, 2.5),
        hover_shadow_blur: 4.0,
        pressed_brightness: 0.95,
        pressed_shadow_offset: (0.0, 0.5),
        pressed_shadow_blur: 1.5,
        has_disabled_state: false,
        snap: false,
    };

    const SECONDARY: Self = Self {
        base_color: ButtonColorSource::Surface,
        text_color: ButtonTextColor::Primary,
        border_width: 1.0,
        border_radius: 4.0,
        use_theme_border_color: true,
        shadow_offset: (0.0, 2.0),
        shadow_blur: 3.0,
        hover_brightness: 1.08,
        hover_shadow_offset: (0.0, 2.5),
        hover_shadow_blur: 4.0,
        pressed_brightness: 0.95,
        pressed_shadow_offset: (0.0, 0.5),
        pressed_shadow_blur: 1.5,
        has_disabled_state: true,
        snap: false,
    };

    const CARD: Self = Self {
        base_color: ButtonColorSource::CardContainer,
        text_color: ButtonTextColor::Primary,
        border_width: 0.0,  // Container handles border
        border_radius: 0.0, // Container handles radius
        use_theme_border_color: false,
        shadow_offset: (0.0, 2.0),
        shadow_blur: 3.0,
        hover_brightness: 1.0, // No color change
        hover_shadow_offset: (0.0, 3.0),
        hover_shadow_blur: 6.0,
        pressed_brightness: 1.0, // No color change
        pressed_shadow_offset: (0.0, 1.0),
        pressed_shadow_blur: 2.0,
        has_disabled_state: false,
        snap: true,
    };

    const ACTIVE_CARD: Self = Self {
        base_color: ButtonColorSource::ActiveCardContainer,
        text_color: ButtonTextColor::Primary,
        border_width: 0.0,  // Container handles border
        border_radius: 0.0, // Container handles radius
        use_theme_border_color: false,
        shadow_offset: (0.0, 2.0),
        shadow_blur: 4.0,
        hover_brightness: 1.0, // No color change
        hover_shadow_offset: (0.0, 3.0),
        hover_shadow_blur: 6.0,
        pressed_brightness: 1.0, // No color change
        pressed_shadow_offset: (0.0, 1.0),
        pressed_shadow_blur: 2.0,
        has_disabled_state: false,
        snap: true,
    };

    const ACTIVE_TAB: Self = Self {
        base_color: ButtonColorSource::AccentWithHoverColor,
        text_color: ButtonTextColor::OnAccent,
        border_width: 0.0,
        border_radius: 4.0,
        use_theme_border_color: false,
        shadow_offset: (0.0, 2.0),
        shadow_blur: 4.0,
        hover_brightness: 1.0, // Uses accent_hover color instead
        hover_shadow_offset: (0.0, 3.0),
        hover_shadow_blur: 6.0,
        pressed_brightness: 1.0, // Return to base accent
        pressed_shadow_offset: (0.0, 1.0),
        pressed_shadow_blur: 2.0,
        has_disabled_state: false,
        snap: false,
    };

    const INACTIVE_TAB: Self = Self {
        base_color: ButtonColorSource::Surface,
        text_color: ButtonTextColor::Primary,
        border_width: 1.0,
        border_radius: 4.0,
        use_theme_border_color: true,
        shadow_offset: (0.0, 2.0),
        shadow_blur: 3.0,
        hover_brightness: 1.08,
        hover_shadow_offset: (0.0, 2.5),
        hover_shadow_blur: 4.0,
        pressed_brightness: 1.0, // No darkening on press
        pressed_shadow_offset: (0.0, 1.0),
        pressed_shadow_blur: 2.0,
        has_disabled_state: false,
        snap: false,
    };

    /// Tag chip button (inactive) - minimal shadows to avoid clipping in scrollables
    const TAG_INACTIVE: Self = Self {
        base_color: ButtonColorSource::Surface,
        text_color: ButtonTextColor::Primary,
        border_width: 1.0,
        border_radius: 4.0,
        use_theme_border_color: true,
        shadow_offset: (0.0, 0.5),
        shadow_blur: 1.0,
        hover_brightness: 1.08,
        hover_shadow_offset: (0.0, 0.5),
        hover_shadow_blur: 1.0,
        pressed_brightness: 1.0,
        pressed_shadow_offset: (0.0, 0.5),
        pressed_shadow_blur: 1.0,
        has_disabled_state: false,
        snap: false,
    };

    /// Tag chip button (active/selected) - minimal shadows to avoid clipping in scrollables
    const TAG_ACTIVE: Self = Self {
        base_color: ButtonColorSource::AccentWithHoverColor,
        text_color: ButtonTextColor::OnAccent,
        border_width: 0.0,
        border_radius: 4.0,
        use_theme_border_color: false,
        shadow_offset: (0.0, 0.5),
        shadow_blur: 1.5,
        hover_brightness: 1.0, // Uses accent_hover color instead
        hover_shadow_offset: (0.0, 0.5),
        hover_shadow_blur: 1.5,
        pressed_brightness: 1.0,
        pressed_shadow_offset: (0.0, 0.5),
        pressed_shadow_blur: 1.0,
        has_disabled_state: false,
        snap: false,
    };
}

/// Adjusts color brightness for hover/pressed states
/// Handles light/dark theme differences
fn adjust_brightness(base: Color, factor: f32, is_light_theme: bool) -> Color {
    if factor == 1.0 {
        return base; // No adjustment needed
    }

    if is_light_theme {
        // Light themes: multiply only (darken)
        Color {
            r: (base.r * factor).min(1.0),
            g: (base.g * factor).min(1.0),
            b: (base.b * factor).min(1.0),
            ..base
        }
    } else {
        // Dark themes: multiply + boost (brighten)
        Color {
            r: ((base.r * factor) + 0.03).min(1.0),
            g: ((base.g * factor) + 0.03).min(1.0),
            b: ((base.b * factor) + 0.03).min(1.0),
            ..base
        }
    }
}

/// Unified button styling function
/// All button variants use this internally
fn build_button_style(
    theme: &AppTheme,
    status: button::Status,
    config: ButtonStyleConfig,
) -> button::Style {
    // Resolve base color
    let base_color = match config.base_color {
        ButtonColorSource::Accent | ButtonColorSource::AccentWithHoverColor => theme.accent,
        ButtonColorSource::Danger => theme.danger,
        ButtonColorSource::Surface => theme.bg_surface,
        ButtonColorSource::ShiftedWarning => {
            // Special: shift warning color by 20% (dirty button)
            if theme.is_light() {
                Color {
                    r: (theme.warning.r * 0.80).max(0.0),
                    g: (theme.warning.g * 0.80).max(0.0),
                    b: (theme.warning.b * 0.80).max(0.0),
                    ..theme.warning
                }
            } else {
                Color {
                    r: (theme.warning.r * 1.20).min(1.0),
                    g: (theme.warning.g * 1.20).min(1.0),
                    b: (theme.warning.b * 1.20).min(1.0),
                    ..theme.warning
                }
            }
        }
        ButtonColorSource::CardContainer => {
            // Use card container background
            return build_card_button_style(theme, status, &config, false);
        }
        ButtonColorSource::ActiveCardContainer => {
            // Use active card container background
            return build_card_button_style(theme, status, &config, true);
        }
    };

    // Resolve text color
    let text_color = match config.text_color {
        ButtonTextColor::OnAccent => theme.fg_on_accent,
        ButtonTextColor::Primary => theme.fg_primary,
    };

    // Build border
    let border = if config.border_width > 0.0 {
        Border {
            color: if config.use_theme_border_color {
                theme.border
            } else {
                Color::TRANSPARENT
            },
            width: config.border_width,
            radius: config.border_radius.into(),
        }
    } else {
        Border {
            radius: config.border_radius.into(),
            ..Default::default()
        }
    };

    // Build base shadow
    let shadow = Shadow {
        color: theme.shadow_color,
        offset: Vector::new(config.shadow_offset.0, config.shadow_offset.1),
        blur_radius: config.shadow_blur,
    };

    // Base style
    let base = button::Style {
        background: Some(base_color.into()),
        text_color,
        border,
        shadow,
        snap: config.snap,
    };

    // Apply status-specific modifications
    match status {
        button::Status::Active => base,

        button::Status::Hovered => {
            let hover_color =
                if matches!(config.base_color, ButtonColorSource::AccentWithHoverColor) {
                    // Special case: active tab uses pre-defined hover color
                    theme.accent_hover
                } else {
                    adjust_brightness(base_color, config.hover_brightness, theme.is_light())
                };

            button::Style {
                background: Some(hover_color.into()),
                shadow: Shadow {
                    color: theme.shadow_color,
                    offset: Vector::new(config.hover_shadow_offset.0, config.hover_shadow_offset.1),
                    blur_radius: config.hover_shadow_blur,
                },
                ..base
            }
        }

        button::Status::Pressed => {
            let pressed_color =
                adjust_brightness(base_color, config.pressed_brightness, theme.is_light());

            button::Style {
                background: Some(pressed_color.into()),
                shadow: Shadow {
                    color: theme.shadow_color,
                    offset: Vector::new(
                        config.pressed_shadow_offset.0,
                        config.pressed_shadow_offset.1,
                    ),
                    blur_radius: config.pressed_shadow_blur,
                },
                ..base
            }
        }

        button::Status::Disabled => {
            if !config.has_disabled_state {
                return base; // Some buttons don't have disabled state
            }

            // Handle different disabled styles
            let (disabled_bg, disabled_text, disabled_border) = match config.base_color {
                ButtonColorSource::Surface => {
                    // Secondary button has special disabled styling
                    (
                        Color {
                            a: 0.5,
                            ..base_color
                        },
                        theme.fg_muted,
                        Border {
                            color: Color {
                                a: 0.3,
                                ..theme.border
                            },
                            width: 1.0,
                            radius: config.border_radius.into(),
                        },
                    )
                }
                _ => {
                    // Standard disabled styling
                    (
                        Color {
                            a: 0.5,
                            ..base_color
                        },
                        Color {
                            a: 0.5,
                            ..text_color
                        },
                        border,
                    )
                }
            };

            button::Style {
                background: Some(disabled_bg.into()),
                text_color: disabled_text,
                border: disabled_border,
                shadow: Shadow {
                    color: Color::TRANSPARENT,
                    offset: Vector::new(0.0, 0.0),
                    blur_radius: 0.0,
                },
                ..base
            }
        }
    }
}

/// Helper for card button styling (uses container styling)
fn build_card_button_style(
    theme: &AppTheme,
    status: button::Status,
    config: &ButtonStyleConfig,
    active: bool,
) -> button::Style {
    let container_style = if active {
        active_card_container(theme)
    } else {
        card_container(theme)
    };

    let base = button::Style {
        background: container_style.background,
        text_color: theme.fg_primary,
        border: container_style.border,
        shadow: container_style.shadow,
        snap: config.snap,
    };

    match status {
        button::Status::Hovered => button::Style {
            shadow: Shadow {
                color: theme.shadow_color,
                offset: Vector::new(config.hover_shadow_offset.0, config.hover_shadow_offset.1),
                blur_radius: config.hover_shadow_blur,
            },
            ..base
        },
        button::Status::Pressed => button::Style {
            shadow: Shadow {
                color: theme.shadow_color,
                offset: Vector::new(
                    config.pressed_shadow_offset.0,
                    config.pressed_shadow_offset.1,
                ),
                blur_radius: config.pressed_shadow_blur,
            },
            ..base
        },
        _ => base,
    }
}

// =============================================================================
// PUBLIC BUTTON STYLING FUNCTIONS
// =============================================================================

pub fn main_container(theme: &AppTheme) -> container::Style {
    container::Style {
        background: Some(theme.bg_base.into()),
        text_color: Some(theme.fg_primary),
        ..Default::default()
    }
}

pub fn sidebar_container(theme: &AppTheme) -> container::Style {
    // Theme-aware gradient: both light and dark go from darker → lighter (bottom to top)
    let gradient_end = if theme.is_light() {
        // Light themes: subtle darkening at bottom (10% darker)
        Color {
            r: (theme.bg_sidebar.r * 0.90).max(0.0),
            g: (theme.bg_sidebar.g * 0.90).max(0.0),
            b: (theme.bg_sidebar.b * 0.90).max(0.0),
            ..theme.bg_sidebar
        }
    } else {
        // Dark themes: hybrid (multiply + add boost for very dark themes)
        Color {
            r: (theme.bg_sidebar.r * 1.30 + 0.05).min(1.0),
            g: (theme.bg_sidebar.g * 1.30 + 0.05).min(1.0),
            b: (theme.bg_sidebar.b * 1.30 + 0.05).min(1.0),
            ..theme.bg_sidebar
        }
    };

    // Light themes: swap gradient direction to match dark themes (darker bottom → lighter top)
    let gradient = if theme.is_light() {
        Gradient::Linear(
            iced::gradient::Linear::new(0.0)
                .add_stop(0.0, gradient_end) // Darker at bottom
                .add_stop(1.0, theme.bg_sidebar), // Lighter at top
        )
    } else {
        Gradient::Linear(
            iced::gradient::Linear::new(0.0)
                .add_stop(0.0, theme.bg_sidebar)
                .add_stop(1.0, gradient_end),
        )
    };

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
                a: 0.05, // Increased from 0.02 for better visibility
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

pub fn popup_container(theme: &AppTheme) -> container::Style {
    let popup_bg = if theme.is_light() {
        // Light themes: slightly brighter/whiter
        Color {
            r: (theme.bg_elevated.r * 1.02).min(1.0),
            g: (theme.bg_elevated.g * 1.02).min(1.0),
            b: (theme.bg_elevated.b * 1.02).min(1.0),
            ..theme.bg_elevated
        }
    } else {
        // Dark themes: noticeably lighter than surface
        Color {
            r: (theme.bg_elevated.r * 1.1 + 0.05).min(1.0),
            g: (theme.bg_elevated.g * 1.1 + 0.05).min(1.0),
            b: (theme.bg_elevated.b * 1.1 + 0.05).min(1.0),
            ..theme.bg_elevated
        }
    };

    container::Style {
        background: Some(popup_bg.into()),
        border: Border {
            color: Color {
                a: 0.15,
                ..theme.border
            },
            width: 1.0,
            radius: 6.0.into(),
        },
        shadow: Shadow {
            color: theme.shadow_color,
            offset: Vector::new(0.0, 2.0),
            blur_radius: 3.0,
        },
        ..Default::default()
    }
}

pub fn primary_button(theme: &AppTheme, status: button::Status) -> button::Style {
    build_button_style(theme, status, ButtonStyleConfig::PRIMARY)
}

pub fn dirty_button(theme: &AppTheme, status: button::Status) -> button::Style {
    build_button_style(theme, status, ButtonStyleConfig::DIRTY)
}

pub fn danger_button(theme: &AppTheme, status: button::Status) -> button::Style {
    build_button_style(theme, status, ButtonStyleConfig::DANGER)
}

pub fn card_button(theme: &AppTheme, status: button::Status) -> button::Style {
    build_button_style(theme, status, ButtonStyleConfig::CARD)
}

pub fn active_card_button(theme: &AppTheme, status: button::Status) -> button::Style {
    build_button_style(theme, status, ButtonStyleConfig::ACTIVE_CARD)
}

pub fn active_tab_button(theme: &AppTheme, status: button::Status) -> button::Style {
    build_button_style(theme, status, ButtonStyleConfig::ACTIVE_TAB)
}

pub fn inactive_tab_button(theme: &AppTheme, status: button::Status) -> button::Style {
    build_button_style(theme, status, ButtonStyleConfig::INACTIVE_TAB)
}

pub fn secondary_button(theme: &AppTheme, status: button::Status) -> button::Style {
    build_button_style(theme, status, ButtonStyleConfig::SECONDARY)
}

/// Tag chip button (inactive) - minimal shadows for use in scrollable containers
pub fn tag_button(theme: &AppTheme, status: button::Status) -> button::Style {
    build_button_style(theme, status, ButtonStyleConfig::TAG_INACTIVE)
}

/// Tag chip button (active/selected) - minimal shadows for use in scrollable containers
pub fn active_tag_button(theme: &AppTheme, status: button::Status) -> button::Style {
    build_button_style(theme, status, ButtonStyleConfig::TAG_ACTIVE)
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
            background: theme.bg_base.into(), // Dimmed to deepest layer for depressed look
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0, // No border when opened - menu shadow provides definition
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
    // Calculate brighter menu background to distinguish from input controls
    let menu_bg = if theme.is_light() {
        // Light themes: brighten toward white
        Color {
            r: (theme.bg_elevated.r * 0.97 + 0.03).min(1.0),
            g: (theme.bg_elevated.g * 0.97 + 0.03).min(1.0),
            b: (theme.bg_elevated.b * 0.97 + 0.03).min(1.0),
            ..theme.bg_elevated
        }
    } else {
        // Dark themes: hybrid brighten (multiply + boost)
        Color {
            r: (theme.bg_elevated.r * 1.15 + 0.04).min(1.0),
            g: (theme.bg_elevated.g * 1.15 + 0.04).min(1.0),
            b: (theme.bg_elevated.b * 1.15 + 0.04).min(1.0),
            ..theme.bg_elevated
        }
    };

    iced::overlay::menu::Style {
        background: menu_bg.into(),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 4.0.into(),
        },
        shadow: Shadow {
            color: theme.shadow_color,
            offset: Vector::new(0.0, 2.0), // Crisp shadow matching modal style
            blur_radius: 3.0,
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

/// Renders an in-app notification banner
///
/// Banners appear at the top of the content area with appropriate coloring based on severity.
/// Uses shadow for depth and semantic colors from the theme.
/// Supports click-to-dismiss functionality.
pub fn notification_banner<'a>(
    banner: &'a crate::app::NotificationBanner,
    theme: &'a crate::theme::AppTheme,
    index: usize,
) -> iced::Element<'a, crate::app::Message> {
    use iced::widget::{container, mouse_area, row, text};
    use iced::{Background, Border, Shadow};

    // Determine colors based on severity
    let (bg_color, fg_color, icon) = match banner.severity {
        crate::app::BannerSeverity::Success => (theme.success, theme.fg_on_accent, "✓"),
        crate::app::BannerSeverity::Info => (theme.info, theme.fg_on_accent, "ℹ"),
        crate::app::BannerSeverity::Warning => (theme.warning, theme.fg_on_accent, "⚠"),
        crate::app::BannerSeverity::Error => (theme.danger, theme.fg_on_accent, "✖"),
    };

    let content = row![
        text(icon).size(16).color(fg_color),
        text(&banner.message).size(14).color(fg_color),
    ]
    .spacing(12)
    .padding([8, 16]);

    let styled_container =
        container(content)
            .max_width(450)
            .style(move |_theme| container::Style {
                background: Some(Background::Color(bg_color)),
                border: Border {
                    radius: 6.0.into(),
                    ..Default::default()
                },
                shadow: Shadow {
                    color: theme.shadow_color,
                    offset: iced::Vector::new(0.0, 2.0),
                    blur_radius: 8.0,
                },
                ..Default::default()
            });

    // Wrap in mouse_area for click-to-dismiss
    mouse_area(styled_container)
        .on_press(crate::app::Message::DismissBanner(index))
        .into()
}
