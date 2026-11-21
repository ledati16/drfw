//! Apply confirmation dialogs and countdown modals

use iced::widget::{button, checkbox, column, container, progress_bar, row, text};
use iced::{Alignment, Background, Border, Color, Element, Gradient, Padding, Shadow};

use crate::app::handlers::SaveTested;
use crate::app::ui_components::{
    card_container, danger_button, inset_container_bordered, primary_button, secondary_button,
    section_header_container, themed_checkbox,
};
use crate::app::{AppStatus, Message, SaveSource};
use crate::core::lockout::LockoutWarning;
use crate::core::retention::RetentionWarning;

/// Heading of the retention guard's warning in both dialogs.
const RETENTION_HEADING: &str = "This is a big change. Check it before you continue:";

/// A warning that needs an explicit confirmation (retention guard, SSH
/// lockout check), or a note that does not (`heading_color` tells them
/// apart): a heading and its lines, all prepared in `update()`.
fn warning_block<'a>(
    heading: &'a str,
    heading_color: Color,
    lines: &'a [String],
    width: f32,
    theme: &'a crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'a, Message> {
    let lines = lines.iter().map(|line| {
        text(line)
            .size(13)
            .font(font)
            .color(theme.fg_primary)
            .into()
    });
    container(
        column![
            text(heading)
                .size(13)
                .font(iced::Font {
                    weight: iced::font::Weight::Bold,
                    ..font
                })
                .color(heading_color),
        ]
        .extend(lines)
        .spacing(6),
    )
    .padding(12)
    .width(width)
    .style(move |_| inset_container_bordered(theme))
    .into()
}

/// The blocks for the warnings that are present (retention guard first),
/// then the lockout check's note (info style: it needs no confirmation).
fn confirmation_blocks<'a>(
    retention: Option<&'a RetentionWarning>,
    lockout: Option<&'a LockoutWarning>,
    theme: &'a crate::theme::AppTheme,
    font: iced::Font,
) -> Vec<Element<'a, Message>> {
    let mut blocks = Vec::with_capacity(3);
    if let Some(warning) = retention {
        blocks.push(warning_block(
            RETENTION_HEADING,
            theme.danger,
            &warning.lines,
            400.0,
            theme,
            font,
        ));
    }
    if let Some(warning) = lockout.filter(|l| l.needs_confirmation()) {
        blocks.push(warning_block(
            LockoutWarning::HEADING,
            theme.danger,
            &warning.lines,
            400.0,
            theme,
            font,
        ));
    }
    if let Some(note) = lockout.filter(|l| !l.notes.is_empty()) {
        blocks.push(warning_block(
            LockoutWarning::NOTE_HEADING,
            theme.info,
            &note.notes,
            400.0,
            theme,
            font,
        ));
    }
    blocks
}

// ============================================================================
// Helper Functions - Build modal body content
// ============================================================================

/// The "Commit Changes?" line when auto-revert is off.
pub(crate) const NO_AUTO_REVERT_NOTE: &str =
    "No auto-revert: these rules stay until you change them.";

/// Build the body content for `AwaitingApply` state
fn build_awaiting_body<'a>(
    auto_revert_enabled: bool,
    timer_secs: &'a str,
    theme: &'a crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'a, Message> {
    let description_row = if auto_revert_enabled {
        container(row![
            text("Applying will activate a ")
                .size(14)
                .font(font)
                .color(theme.fg_muted),
            text(timer_secs)
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
            text(NO_AUTO_REVERT_NOTE)
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

/// Build the buttons for `AwaitingApply` state. With a warning (retention
/// guard, lockout check) the apply button is "Apply anyway" (danger style,
/// click only: Enter is refused)
fn build_awaiting_buttons(
    auto_revert_enabled: bool,
    needs_confirmation: bool,
    theme: &crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'_, Message> {
    let apply = if needs_confirmation {
        button(text("Apply anyway").size(14).font(font))
            .on_press(Message::ProceedToApplyAnyway)
            .padding([10, 24])
            .style(move |_, status| danger_button(theme, status))
    } else {
        let button_text = if auto_revert_enabled {
            "Apply & Start Timer"
        } else {
            "Apply Now"
        };
        button(text(button_text).size(14).font(font))
            .on_press(Message::ProceedToApply)
            .padding([10, 24])
            .style(move |_, status| primary_button(theme, status))
    };

    // Cancel closes the dialog without applying; the edits stay
    row![
        button(text("Cancel").size(14).font(font))
            .on_press(Message::CancelApply)
            .padding([10, 20])
            .style(move |_, status| secondary_button(theme, status)),
        apply,
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
        button(text("Cancel").size(14).font(font))
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
fn build_confirmation_body<'a>(
    remaining_text: &'a str,
    remaining: u32,
    animated_progress: f32,
    theme: &'a crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'a, Message> {
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
            text(remaining_text)
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
        text("Closing DRFW or losing the connection is safe: the rules still revert on time.")
            .size(12)
            .font(font)
            .color(theme.fg_muted)
            .width(360)
            .align_x(Alignment::Center),
        text("Keyboard: Ctrl+Enter confirms.")
            .size(12)
            .font(font)
            .color(theme.fg_muted)
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
///
/// `timer_secs` and `countdown_text` are the timer length and the remaining
/// seconds, formatted in `update()`; `session` holds the warnings for this
/// apply (retention guard, lockout check), computed in `update()`.
pub fn view_apply_flow_modal<'a>(
    status: &'a AppStatus,
    session: Option<&'a crate::app::handlers::ApplySession>,
    auto_revert_enabled: bool,
    timer_secs: &'a str,
    countdown_text: &'a str,
    countdown_remaining: u32,
    animated_progress: f32,
    theme: &'a crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'a, Message> {
    // Determine content based on current status
    let (title_text, body, buttons) = match status {
        AppStatus::AwaitingApply => {
            let body = build_awaiting_body(auto_revert_enabled, timer_secs, theme, font);
            let blocks = confirmation_blocks(
                session.and_then(crate::app::handlers::ApplySession::retention),
                session.and_then(crate::app::handlers::ApplySession::lockout),
                theme,
                font,
            );
            let body = if blocks.is_empty() {
                body
            } else {
                column![body]
                    .extend(blocks)
                    .spacing(16)
                    .align_x(Alignment::Center)
                    .into()
            };
            let needs_confirmation =
                session.is_some_and(crate::app::handlers::ApplySession::needs_confirmation);
            (
                "Commit Changes?",
                body,
                build_awaiting_buttons(auto_revert_enabled, needs_confirmation, theme, font),
            )
        }
        AppStatus::Applying => (
            "Applying Rules...",
            build_applying_body(theme, font),
            build_applying_buttons(auto_revert_enabled, theme, font),
        ),
        AppStatus::PendingConfirmation { .. } => (
            "Confirm Safety",
            build_confirmation_body(
                countdown_text,
                countdown_remaining,
                animated_progress,
                theme,
                font,
            ),
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

/// Question shown in the Save to System modal (built once; the path is a
/// compile-time constant but not a literal, so `concat!` cannot be used).
static SAVE_TO_SYSTEM_QUESTION: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!("Save current configuration to {}?", crate::SYSTEM_NFT_PATH)
});

/// Explanation shown in the Save to System modal (built once).
static SAVE_TO_SYSTEM_DETAILS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        "The file is checked with nft before it replaces the current one, which is \
         kept as {}.drfw-bak.",
        crate::SYSTEM_NFT_PATH
    )
});

/// Label of the "enable at boot" checkbox (built once).
static ENABLE_AT_BOOT_LABEL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| format!("Also enable {} at boot", crate::SYSTEM_NFT_SERVICE));

/// Modal for confirming the Save to System operation.
/// Shows when `AppStatus::AwaitingSaveToSystem` is active.
///
/// `dialog` holds the boot persistence line and the "Also enable at boot"
/// checkbox, both prepared in `update()` from an unprivileged `systemctl`
/// query.
pub fn view_save_to_system_modal<'a>(
    dialog: &'a crate::app::handlers::SaveToSystemDialog,
    theme: &'a crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'a, Message> {
    let boot_color = if dialog.boot.is_none() {
        theme.fg_muted
    } else if dialog.boot_warning {
        theme.warning
    } else {
        theme.success
    };
    let mut body = column![
        text("✓ Rules verified.")
            .size(14)
            .font(font)
            .color(theme.success)
            .width(400)
            .align_x(Alignment::Center),
        text(SAVE_TO_SYSTEM_QUESTION.as_str())
            .size(14)
            .font(font)
            .color(theme.fg_primary)
            .width(400)
            .align_x(Alignment::Center),
        text(SAVE_TO_SYSTEM_DETAILS.as_str())
            .size(12)
            .font(font)
            .color(theme.fg_muted)
            .width(400)
            .align_x(Alignment::Center),
        text(dialog.boot_text.as_str())
            .size(12)
            .font(font)
            .color(boot_color)
            .width(400)
            .align_x(Alignment::Center),
    ]
    .spacing(5)
    .align_x(Alignment::Center);

    if dialog.offer_enable {
        body = body.push(
            container(
                checkbox(dialog.enable_at_boot)
                    .label(ENABLE_AT_BOOT_LABEL.as_str())
                    .on_toggle(Message::SaveToSystemEnableToggled)
                    .size(16)
                    .spacing(8)
                    .text_size(12)
                    .font(font)
                    .style(move |_, status| themed_checkbox(theme, status)),
            )
            .padding([6, 0]),
        );
    }

    // The kept rules may not be what runs now (applied before a reboot)
    if let Some(note) = dialog.earlier_session {
        body = body.push(
            text(note)
                .size(12)
                .font(font)
                .color(theme.warning)
                .width(400)
                .align_x(Alignment::Center),
        );
    }

    // Untested rules take effect at boot without the auto-revert safety net
    if let Some(warning) = dialog.tested.warning() {
        body = body.push(
            container(
                text(warning)
                    .size(13)
                    .font(font)
                    .color(theme.danger)
                    .width(400)
                    .align_x(Alignment::Center),
            )
            .padding([6, 0]),
        );
    }

    let cancel = button(text("Cancel").size(14).font(font))
        .on_press(Message::SaveToSystemCancelled)
        .padding([10, 20])
        .style(move |_, status| secondary_button(theme, status));
    // Saving the editor's rules despite the retention guard or the lockout
    // check takes a click
    body = body.extend(confirmation_blocks(
        dialog.retention.as_ref(),
        dialog.lockout.as_ref(),
        theme,
        font,
    ));

    let buttons = match dialog.tested {
        SaveTested::Tested if dialog.editor_needs_confirmation() => row![
            cancel,
            button(text("Save anyway").size(14).font(font))
                .on_press(Message::SaveToSystemConfirmed(SaveSource::Editor))
                .padding([10, 24])
                .style(move |_, status| danger_button(theme, status)),
        ],
        SaveTested::Tested => row![
            cancel,
            button(text("Save").size(14).font(font))
                .on_press(Message::SaveToSystemConfirmed(SaveSource::Editor))
                .padding([10, 24])
                .style(move |_, status| primary_button(theme, status)),
        ],
        SaveTested::Differs => row![
            cancel,
            button(text("Save untested rules").size(14).font(font))
                .on_press(Message::SaveToSystemConfirmed(SaveSource::Editor))
                .padding([10, 20])
                .style(move |_, status| danger_button(theme, status)),
            button(text("Save the last applied rules").size(14).font(font))
                .on_press(Message::SaveToSystemConfirmed(SaveSource::LastConfirmed))
                .padding([10, 24])
                .style(move |_, status| primary_button(theme, status)),
        ],
        SaveTested::NothingApplied => row![
            cancel,
            button(text("Save untested rules").size(14).font(font))
                .on_press(Message::SaveToSystemConfirmed(SaveSource::Editor))
                .padding([10, 20])
                .style(move |_, status| danger_button(theme, status)),
        ],
    }
    .spacing(16);

    container(
        column![
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
