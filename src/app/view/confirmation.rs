//! Apply confirmation dialogs and countdown modals

use crate::app::ui_components::{
    card_container, danger_button, primary_button, secondary_button, section_header_container,
};
use crate::app::{AppStatus, Message};
use iced::widget::{button, column, container, progress_bar, row, text};
use iced::{Alignment, Background, Border, Color, Element, Gradient, Padding, Shadow};

// ============================================================================
// Helper Functions - Build modal body content
// ============================================================================

/// Build the body content for `AwaitingApply` state
fn build_awaiting_body(
    auto_revert_enabled: bool,
    auto_revert_timeout: u64,
    theme: &crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'_, Message> {
    let description_row = if auto_revert_enabled {
        let timeout_val = auto_revert_timeout.min(120);
        container(row![
            text("Applying will activate a ")
                .size(14)
                .font(font)
                .color(theme.fg_muted),
            text(format!("{timeout_val}"))
                .size(14)
                .font(iced::Font {
                    weight: iced::font::Weight::Bold,
                    ..font
                })
                .color(theme.fg_muted),
            text(" second safety timer.")
                .size(14)
                .font(font)
                .color(theme.fg_muted),
        ])
        .width(360)
        .align_x(Alignment::Center)
    } else {
        container(
            text("Changes will take effect immediately (no auto-revert).")
                .size(14)
                .font(font)
                .color(theme.fg_muted),
        )
        .width(360)
        .align_x(Alignment::Center)
    };

    column![
        text("✓ Rules verified.")
            .size(14)
            .font(font)
            .color(theme.success)
            .width(360)
            .align_x(Alignment::Center),
        description_row,
    ]
    .spacing(5)
    .into()
}

/// Build the buttons for `AwaitingApply` state
fn build_awaiting_buttons(
    auto_revert_enabled: bool,
    theme: &crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'_, Message> {
    let button_text = if auto_revert_enabled {
        "Apply & Start Timer"
    } else {
        "Apply Now"
    };

    row![
        button(text("Discard").size(14).font(font))
            .on_press(Message::CancelRuleForm)
            .padding([10, 20])
            .style(move |_, status| secondary_button(theme, status)),
        button(text(button_text).size(14).font(font))
            .on_press(Message::ProceedToApply)
            .padding([10, 24])
            .style(move |_, status| primary_button(theme, status)),
    ]
    .spacing(16)
    .into()
}

/// Build the body content for Applying state (new!)
fn build_applying_body(theme: &crate::theme::AppTheme, font: iced::Font) -> Element<'_, Message> {
    text("Updating firewall configuration...")
        .size(14)
        .font(font)
        .color(theme.fg_muted)
        .width(360)
        .align_x(Alignment::Center)
        .into()
}

/// Build the buttons for Applying state (disabled versions)
fn build_applying_buttons(
    auto_revert_enabled: bool,
    theme: &crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'_, Message> {
    let button_text = if auto_revert_enabled {
        "Apply & Start Timer"
    } else {
        "Apply Now"
    };

    row![
        button(text("Discard").size(14).font(font))
            .padding([10, 20])
            .style(move |_, status| secondary_button(theme, status)),
        button(text(button_text).size(14).font(font))
            .padding([10, 24])
            .style(move |_, status| secondary_button(theme, status)),
    ]
    .spacing(16)
    .into()
}

/// Build the body content for `PendingConfirmation` state
fn build_confirmation_body(
    remaining: u32,
    animated_progress: f32,
    theme: &crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'_, Message> {
    let progress = animated_progress;

    column![
        text("✓ Firewall updated.")
            .size(14)
            .font(font)
            .color(theme.success)
            .width(360)
            .align_x(Alignment::Center),
        container(row![
            text("Automatic rollback in ")
                .size(14)
                .font(font)
                .color(theme.accent),
            text(format!("{remaining}"))
                .size(14)
                .font(iced::Font {
                    weight: iced::font::Weight::Bold,
                    ..font
                })
                .color(theme.accent),
            text(" seconds if not confirmed.")
                .size(14)
                .font(font)
                .color(theme.accent),
        ])
        .width(360)
        .align_x(Alignment::Center),
        // Progress bar showing time remaining (inset/recessed style)
        container(
            progress_bar(0.0..=1.0, progress)
                .length(iced::Length::Fill)
                .girth(18)
                .style(move |_| {
                    use iced::widget::progress_bar;

                    // Use darkened accent for inset appearance (recessed elements are darker)
                    let base_color = if remaining <= 5 {
                        theme.danger
                    } else {
                        theme.accent
                    };

                    let bar_color = if theme.is_light() {
                        if remaining <= 5 {
                            // Light themes at 5s: subtly darker gray for urgency
                            Color {
                                r: theme.bg_surface.r * 0.65, // Subtle darkening at 5 seconds
                                g: theme.bg_surface.g * 0.65,
                                b: theme.bg_surface.b * 0.65,
                                a: 1.0,
                            }
                        } else {
                            // Light themes: gray (desaturated), darker than empty track for inset depth
                            Color {
                                r: theme.bg_surface.r * 0.70, // 30% darker gray (darker than empty track)
                                g: theme.bg_surface.g * 0.70,
                                b: theme.bg_surface.b * 0.70,
                                a: 1.0,
                            }
                        }
                    } else {
                        // Dark themes: 15% darker accent color (PERFECT)
                        Color {
                            r: base_color.r * 0.85,
                            g: base_color.g * 0.85,
                            b: base_color.b * 0.85,
                            a: 1.0,
                        }
                    };

                    // Gradient: straight top shadow with sharper transition (crisp like buttons)
                    let gradient_multiplier = if theme.is_light() {
                        0.92 // Light themes: subtle 8% darker at top
                    } else {
                        0.65 // Dark themes: strong 35% darker for depth
                    };

                    let bar_gradient = Gradient::Linear(
                        iced::gradient::Linear::new(std::f32::consts::PI)
                            .add_stop(
                                0.0,
                                Color {
                                    r: bar_color.r * gradient_multiplier,
                                    g: bar_color.g * gradient_multiplier,
                                    b: bar_color.b * gradient_multiplier,
                                    a: bar_color.a,
                                },
                            )
                            .add_stop(0.15, bar_color) // Extended to 15% for slightly more coverage
                            .add_stop(1.0, bar_color),
                    ); // Full fill color for rest

                    progress_bar::Style {
                        background: Color {
                            r: theme.bg_surface.r * 0.85, // 15% darker empty track (same for both themes)
                            g: theme.bg_surface.g * 0.85,
                            b: theme.bg_surface.b * 0.85,
                            a: theme.bg_surface.a,
                        }
                        .into(),
                        bar: Background::Gradient(bar_gradient),
                        border: Border {
                            radius: 6.0.into(),
                            ..Default::default()
                        },
                    }
                })
        )
        .width(360)
        .padding(Padding {
            top: 2.5, // Slightly thicker top rim (sweet spot)
            right: 2.0,
            bottom: 1.0, // Thinner bottom rim
            left: 2.0,
        })
        .style(move |_| {
            let (rim_top, rim_bottom) = if theme.is_light() {
                // Light themes: strong top shadow, very subtle bottom
                (0.5, 0.95) // 50% darker top, 5% darker bottom
            } else {
                // Dark themes: strong inset shadow (PERFECT)
                (0.5, 0.88) // 50% darker top, 12% darker bottom
            };

            container::Style {
                background: Some(Background::Gradient(Gradient::Linear(
                    iced::gradient::Linear::new(std::f32::consts::PI) // Vertical gradient
                        .add_stop(
                            0.0,
                            Color {
                                r: theme.bg_surface.r * rim_top,
                                g: theme.bg_surface.g * rim_top,
                                b: theme.bg_surface.b * rim_top,
                                a: theme.bg_surface.a,
                            },
                        )
                        .add_stop(
                            1.0,
                            Color {
                                r: theme.bg_surface.r * rim_bottom,
                                g: theme.bg_surface.g * rim_bottom,
                                b: theme.bg_surface.b * rim_bottom,
                                a: theme.bg_surface.a,
                            },
                        ),
                ))),
                border: Border {
                    color: Color {
                        r: theme.bg_surface.r * 0.75, // Lighter 25% darkening for border
                        g: theme.bg_surface.g * 0.75,
                        b: theme.bg_surface.b * 0.75,
                        a: theme.bg_surface.a,
                    },
                    width: 1.0,
                    radius: 8.0.into(),
                },
                shadow: Shadow {
                    // Inner shadow effect (inverted offset for recess illusion)
                    color: Color {
                        r: theme.bg_surface.r * 0.5, // Even darker for shadow depth
                        g: theme.bg_surface.g * 0.5,
                        b: theme.bg_surface.b * 0.5,
                        a: 0.9, // Less transparent for sharper definition
                    },
                    offset: iced::Vector::new(0.0, -1.0), // Negative Y = top shadow
                    blur_radius: 1.0,                     // Crisp shadow matching button precision
                },
                ..Default::default()
            }
        }),
    ]
    .spacing(20)
    .into()
}

/// Build the buttons for `PendingConfirmation` state
fn build_confirmation_buttons(
    theme: &crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'_, Message> {
    row![
        button(text("Rollback").size(14).font(font))
            .on_press(Message::RevertClicked)
            .padding([10, 20])
            .style(move |_, status| danger_button(theme, status)),
        button(text("Confirm & Stay").size(14).font(font))
            .on_press(Message::ConfirmClicked)
            .padding([10, 24])
            .style(move |_, status| primary_button(theme, status)),
    ]
    .spacing(16)
    .into()
}

// ============================================================================
// Unified Modal Function
// ============================================================================

/// Unified apply flow modal that handles all three states:
/// - `AwaitingApply`: "Commit Changes?" with enabled buttons
/// - `Applying`: "Applying Rules..." with disabled buttons (no flash!)
/// - `PendingConfirmation`: Countdown timer with progress bar
pub fn view_apply_flow_modal<'a>(
    status: &'a AppStatus,
    auto_revert_enabled: bool,
    auto_revert_timeout: u64,
    countdown_remaining: u32,
    animated_progress: f32,
    theme: &'a crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'a, Message> {
    // Determine content based on current status
    let (icon, title_text, body, buttons) = match status {
        AppStatus::AwaitingApply => (
            text("🛡️").size(36),
            "Commit Changes?",
            build_awaiting_body(auto_revert_enabled, auto_revert_timeout, theme, font),
            build_awaiting_buttons(auto_revert_enabled, theme, font),
        ),
        AppStatus::Applying => (
            text("⏳").size(36),
            "Applying Rules...",
            build_applying_body(theme, font),
            build_applying_buttons(auto_revert_enabled, theme, font),
        ),
        AppStatus::PendingConfirmation { .. } => (
            text("⏳").size(36),
            "Confirm Safety",
            build_confirmation_body(countdown_remaining, animated_progress, theme, font),
            build_confirmation_buttons(theme, font),
        ),
        _ => {
            // Shouldn't be called with other statuses, but handle gracefully
            return container(text("Invalid modal state").size(14).color(theme.fg_muted)).into();
        }
    };

    // Single shared card structure (no duplication!)
    container(
        column![
            icon,
            container(text(title_text).size(24).font(font).color(theme.fg_primary))
                .padding([4, 8])
                .style(move |_| section_header_container(theme)),
            body,
            buttons,
        ]
        .spacing(20)
        .padding(32)
        .align_x(Alignment::Center),
    )
    .style(move |_| card_container(theme))
    .into()
}

// ============================================================================
// Save to System Modal
// ============================================================================

/// Modal for confirming the Save to System operation.
/// Shows when `AppStatus::AwaitingSaveToSystem` is active.
pub fn view_save_to_system_modal(
    theme: &crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'_, Message> {
    let body = column![
        text("✓ Rules verified.")
            .size(14)
            .font(font)
            .color(theme.success)
            .width(400)
            .align_x(Alignment::Center),
        text(format!(
            "Save current configuration to {}?",
            drfw::SYSTEM_NFT_PATH
        ))
        .size(14)
        .font(font)
        .color(theme.fg_primary)
        .width(400)
        .align_x(Alignment::Center),
        text("This will overwrite the system default configuration.")
            .size(12)
            .font(font)
            .color(theme.fg_muted)
            .width(400)
            .align_x(Alignment::Center),
    ]
    .spacing(5);

    let buttons = row![
        button(text("Cancel").size(14).font(font))
            .on_press(Message::SaveToSystemCancelled)
            .padding([10, 20])
            .style(move |_, status| secondary_button(theme, status)),
        button(text("Save").size(14).font(font))
            .on_press(Message::SaveToSystemConfirmed)
            .padding([10, 24])
            .style(move |_, status| primary_button(theme, status)),
    ]
    .spacing(16);

    container(
        column![
            text("💾").size(36),
            container(
                text("Save to System")
                    .size(24)
                    .font(font)
                    .color(theme.fg_primary)
            )
            .padding([4, 8])
            .style(move |_| section_header_container(theme)),
            body,
            buttons,
        ]
        .spacing(20)
        .padding(32)
        .align_x(Alignment::Center),
    )
    .style(move |_| card_container(theme))
    .into()
}
