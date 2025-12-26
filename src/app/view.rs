use crate::app::ui_components::{
    active_card_button, active_card_container, active_tab_button, card_button, card_container,
    danger_button, dirty_button, main_container, primary_button,
    section_header_container, sidebar_container,
};
use crate::app::{
    AppStatus, FONT_MONO, FONT_REGULAR, Message, PendingWarning, RuleForm,
    State, WorkspaceTab,
};
use crate::core::firewall::{PRESETS, Protocol};
use iced::widget::{
    button, checkbox, column, container, mouse_area, pick_list, row, rule, scrollable, stack, text, text_input,
    toggler, tooltip,
};
use iced::widget::text::Wrapping;
use iced::{Alignment, Border, Color, Element, Length, Theme};

#[allow(clippy::too_many_lines)]
pub fn view(state: &State) -> Element<'_, Message> {
    let theme = &state.theme;
    let sidebar = view_sidebar(state);

    // Compute diff if needed (before match to extend lifetime)
    let diff_text = if state.show_diff && state.active_tab == WorkspaceTab::Nftables {
        state.compute_diff()
    } else {
        None
    };

    let preview_content: Element<'_, Message> = match state.active_tab {
        WorkspaceTab::Nftables => {
            if let Some(ref diff) = diff_text {
                container(view_diff_text(diff, theme))
                    .width(Length::Fill)
                    .into()
            } else {
                container(view_highlighted_nft(&state.cached_nft_text, theme))
                    .width(Length::Fill)
                    .into()
            }
        }
        WorkspaceTab::Json => {
            // Use cached JSON to avoid regenerating on every frame
            container(view_highlighted_json(&state.cached_json_text, theme))
                .width(Length::Fill)
                .into()
        }
        WorkspaceTab::Settings => container(view_settings(state))
            .width(Length::Fill)
            .into(),
    };

    let workspace = view_workspace(state, preview_content);

    let content = row![sidebar, workspace];

    let overlay = if let Some(warning) = &state.pending_warning {
        Some(
            container(view_warning_modal(warning, theme))
                .style(|_| container::Style {
                    background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.9).into()),
                    ..Default::default()
                })
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill),
        )
    } else if let Some(form) = &state.rule_form {
        Some(
            container(view_rule_form(
                form,
                state.form_errors.as_ref(),
                &state.interfaces,
                theme,
            ))
            .style(|_| container::Style {
                background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.9).into()),
                ..Default::default()
            })
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill),
        )
    } else {
        match &state.status {
            AppStatus::AwaitingApply => Some(
                container(view_awaiting_apply(theme))
                    .style(|_| container::Style {
                        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.9).into()),
                        ..Default::default()
                    })
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill),
            ),
            AppStatus::PendingConfirmation { .. } => Some(
                container(view_pending_confirmation(state.countdown_remaining, theme))
                    .style(|_| container::Style {
                        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.95).into()),
                        ..Default::default()
                    })
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill),
            ),
            _ => None,
        }
    };

    let base = container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |_| main_container(theme));

    let with_overlay = if let Some(overlay) = overlay {
        stack![base, overlay].into()
    } else {
        base.into()
    };

    // Diagnostics modal overlay
    let with_diagnostics = if state.show_diagnostics {
        stack![
            with_overlay,
            container(view_diagnostics_modal(theme))
                .style(|_| container::Style {
                    background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.9).into()),
                    ..Default::default()
                })
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
        ]
        .into()
    } else {
        with_overlay
    };

    // Export modal overlay
    let with_export = if state.show_export_modal {
        stack![
            with_diagnostics,
            container(view_export_modal(theme))
                .style(|_| container::Style {
                    background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.9).into()),
                    ..Default::default()
                })
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
        ]
        .into()
    } else {
        with_diagnostics
    };

    // Keyboard shortcuts help overlay
    if state.show_shortcuts_help {
        stack![
            with_export,
            container(view_shortcuts_help(theme))
                .style(|_| container::Style {
                    background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.9).into()),
                    ..Default::default()
                })
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
        ]
        .into()
    } else {
        with_export
    }
}

#[allow(clippy::too_many_lines)]
fn view_sidebar(state: &State) -> Element<'_, Message> {
    let theme = &state.theme;
    let branding = container(column![
        row![
            container(text("🛡️").size(28).color(theme.accent)).padding(4),
            column![
                text("DRFW").size(24).font(FONT_REGULAR).color(theme.accent),
                text("DUMB RUST FIREWALL")
                    .size(9)
                    .color(theme.fg_muted)
                    .font(FONT_MONO),
            ]
            .spacing(0)
        ]
        .spacing(12)
        .align_y(Alignment::Center)
    ])
    .padding(iced::Padding::new(0.0).bottom(10.0));

    let search_bar = column![
        text_input("Search rules...", &state.rule_search)
            .on_input(Message::RuleSearchChanged)
            .padding(10)
            .size(13),
    ]
    .spacing(4);

    let add_button = button(
        row![text("+").size(18), text("Add Access Rule").size(14)]
            .spacing(10)
            .align_y(Alignment::Center),
    )
    .width(Length::Fill)
    .padding(12)
    .style(move |_, status| primary_button(theme, status))
    .on_press(Message::AddRuleClicked);

    let filtered_rules: Vec<_> = state
        .ruleset
        .rules
        .iter()
        .filter(|r| {
            // Text search filter
            let search_term = state.rule_search.to_lowercase();
            let matches_search = state.rule_search.is_empty()
                || r.label.to_lowercase().contains(&search_term)
                || r.protocol.to_string().to_lowercase().contains(&search_term)
                || r.interface.as_ref().is_some_and(|i| i.to_lowercase().contains(&search_term))
                || r.tags.iter().any(|tag| tag.to_lowercase().contains(&search_term));

            // Tag filter
            let matches_tag = if let Some(ref filter_tag) = state.filter_tag {
                r.tags.contains(filter_tag)
            } else {
                true
            };

            matches_search && matches_tag
        })
        .collect();

    let metrics = row![
        text(format!(
            "Showing {} of {}",
            filtered_rules.len(),
            state.ruleset.rules.len()
        ))
        .size(10)
        .color(theme.fg_muted)
        .font(FONT_MONO),
    ]
    .width(Length::Fill)
    .align_y(Alignment::Center);

    let rule_list: Element<'_, Message> = if filtered_rules.is_empty() {
        container(
            column![
                text("No matching rules.")
                    .size(13)
                    .color(theme.fg_muted)
                    .font(FONT_REGULAR),
                if state.ruleset.rules.is_empty() {
                    text("Click '+' to add your first rule.")
                        .size(11)
                        .color(theme.fg_muted)
                } else {
                    text("")
                }
            ]
            .spacing(10)
            .align_x(Alignment::Center),
        )
        .width(Length::Fill)
        .padding(40)
        .center_x(Length::Fill)
        .into()
    } else {
        filtered_rules
            .into_iter()
            .fold(column![].spacing(8), |col, rule| {
                let is_editing = state.rule_form.as_ref().and_then(|f| f.id) == Some(rule.id);
                let is_deleting = state.deleting_id == Some(rule.id);
                let is_being_dragged = state.dragged_rule_id == Some(rule.id);
                let any_drag_active = state.dragged_rule_id.is_some();
                let is_hover_target = state.hovered_drop_target_id == Some(rule.id);

                let card_content: Element<'_, Message> = if is_deleting {
                    row![
                        text("Delete?")
                            .size(12)
                            .color(theme.danger)
                            .width(Length::Fill),
                        button(text("No").size(11))
                            .on_press(Message::CancelDelete)
                            .padding(6)
                            .style(button::secondary),
                        button(text("Yes").size(11))
                            .on_press(Message::DeleteRule(rule.id))
                            .padding(6)
                            .style(move |_, status| danger_button(theme, status)),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center)
                    .padding(iced::Padding::new(10.0))
                    .into()
                } else {
                    let handle_action = if any_drag_active {
                        Message::RuleDropped(rule.id)
                    } else {
                        Message::RuleDragStart(rule.id)
                    };

                    let handle_color = if is_being_dragged {
                        theme.accent
                    } else if any_drag_active {
                        theme.success
                    } else {
                        theme.fg_muted
                    };

                    // Compact card design, REVERTED truncation/icons
                    row![
                        // Drag Handle (Button) with tooltip
                        tooltip(
                            button(
                                container(text("::").size(12).color(handle_color))
                                    .width(Length::Fixed(20.0))
                                    .center_x(Length::Fixed(20.0))
                            )
                            .on_press(handle_action)
                            .padding([0, 2])
                            .style(button::text),
                            container(
                                text(if any_drag_active && !is_being_dragged {
                                    "Click to move here"
                                } else {
                                    "Click to move rule"
                                })
                                .size(11)
                            )
                            .padding(6)
                            .style(move |_| container::Style {
                                background: Some(Color::from_rgb(0.15, 0.15, 0.15).into()),
                                border: Border {
                                    color: theme.border,
                                    width: 1.0,
                                    radius: 4.0.into(),
                                },
                                shadow: iced::Shadow {
                                    color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
                                    offset: iced::Vector::new(0.0, 2.0),
                                    blur_radius: 4.0,
                                },
                                ..Default::default()
                            }),
                            tooltip::Position::Right
                        ),

                        // Status Strip
                        container(column![])
                            .width(Length::Fixed(3.0))
                            .height(Length::Fixed(24.0))
                            .style(move |_| container::Style {
                                background: Some(
                                    (if rule.enabled {
                                        theme.info
                                    } else {
                                        theme.fg_muted
                                    })
                                    .into()
                                ),
                                border: Border {
                                    radius: 2.0.into(),
                                    ..Default::default()
                                },
                                ..Default::default()
                            }),

                        // Toggle - make non-interactive when drag is active
                        {
                            let toggle = toggler(rule.enabled)
                                .size(12)
                                .width(Length::Shrink)
                                .spacing(0);

                            if any_drag_active && !is_being_dragged {
                                toggle  // No on_toggle handler when drag active
                            } else {
                                toggle.on_toggle(move |_| Message::ToggleRuleEnabled(rule.id))
                            }
                        },

                        // Protocol Badge + Port (vertical stack)
                        column![
                            container(
                                text(match rule.protocol {
                                    Protocol::Tcp => "TCP",
                                    Protocol::Udp => "UDP",
                                    Protocol::Any => "ANY",
                                    _ => "PROTO",
                                })
                                .size(9)
                                .font(FONT_MONO)
                                .color(if rule.enabled {
                                    theme.syntax_type
                                } else {
                                    theme.fg_muted
                                })
                            )
                            .padding([2, 4])
                            .style(move |_| container::Style {
                                background: Some(theme.bg_base.into()),
                                border: Border {
                                    radius: 4.0.into(),
                                    color: theme.border,
                                    width: 1.0,
                                },
                                ..Default::default()
                            }),

                            // Port number below protocol - split range if too long
                            container({
                                let port_display = rule.ports.as_ref().map_or_else(
                                    || column![text("All").size(8).color(theme.fg_muted).font(FONT_MONO)],
                                    |p| if p.start == p.end {
                                        // Single port
                                        column![text(p.start.to_string()).size(8).color(theme.fg_muted).font(FONT_MONO)]
                                    } else {
                                        // Port range - check if it needs wrapping
                                        let range_str = format!("{}-{}", p.start, p.end);
                                        if range_str.len() > 8 {
                                            // Split across two lines for long ranges
                                            column![
                                                text(p.start.to_string()).size(8).color(theme.fg_muted).font(FONT_MONO),
                                                text(p.end.to_string()).size(8).color(theme.fg_muted).font(FONT_MONO),
                                            ]
                                            .spacing(0)
                                            .align_x(Alignment::Center)
                                        } else {
                                            // Fits on one line
                                            column![text(range_str).size(8).color(theme.fg_muted).font(FONT_MONO)]
                                        }
                                    }
                                );
                                port_display.align_x(Alignment::Center)
                            })
                            .width(Length::Fixed(50.0))  // Fixed width prevents alignment shift
                            .center_x(Length::Fixed(50.0)),
                        ]
                        .spacing(2)
                        .align_x(Alignment::Center),  // Center the column contents

                        // Info Column - make non-interactive when drag is active
                        {
                            // Build tag badges - no limit, just let them flow and clip naturally
                            let mut tag_items = vec![];

                            for tag in rule.tags.iter() {
                                let tag_theme = theme.clone();
                                tag_items.push(
                                    container(
                                        container(
                                            text(tag)
                                                .size(8)
                                                .color(theme.fg_on_accent)
                                                .wrapping(Wrapping::None)
                                        )
                                        .max_width(80)  // Max width for tag text, but shrinks to fit
                                        .clip(true)  // Clip text at badge edge if over max
                                    )
                                    .padding([1, 4])
                                    .style(move |_| container::Style {
                                        background: Some(tag_theme.accent.into()),
                                        border: Border {
                                            radius: 3.0.into(),
                                            ..Default::default()
                                        },
                                        ..Default::default()
                                    })
                                    .into()
                                );
                            }

                            let content = column![
                                // Row 1: Label
                                container(
                                    text(if rule.label.is_empty() {
                                        "Unnamed Rule"
                                    } else {
                                        &rule.label
                                    })
                                    .size(12)
                                    .font(FONT_REGULAR)
                                    .wrapping(Wrapping::None)
                                    .color(if rule.enabled {
                                        theme.fg_primary
                                    } else {
                                        theme.fg_muted
                                    })
                                )
                                .width(Length::Fill)
                                .clip(true),

                                // Row 2: Tags only (port is now under protocol badge)
                                row(tag_items)
                                    .spacing(4)
                                    .align_y(Alignment::Center),
                            ]
                            .spacing(4)
                            .width(Length::Fill);

                            let btn = button(content)
                                .padding(0)
                                .style(button::text);

                            if any_drag_active && !is_being_dragged {
                                btn  // No on_press when drag active
                            } else {
                                btn.on_press(Message::EditRuleClicked(rule.id))
                            }
                        },

                        // Actions - make non-interactive when drag is active
                        {
                            let btn = button(text("×").size(14).color(theme.fg_muted))
                                .padding(4)
                                .style(button::text);

                            if any_drag_active && !is_being_dragged {
                                btn  // No on_press when drag active
                            } else {
                                btn.on_press(Message::DeleteRuleRequested(rule.id))
                            }
                        },
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center)
                    .padding(iced::Padding {
                        top: 6.0,
                        right: 8.0,
                        bottom: 6.0,
                        left: 4.0,
                    })
                    .into()
                };

                // Wrap card in mouse_area when dragging to detect hover
                let card = container(card_content)
                    .style(move |_| if is_editing {
                        active_card_container(theme)
                    } else if is_being_dragged {
                        container::Style {
                            background: Some(theme.bg_active.into()),
                            border: Border {
                                color: theme.accent,
                                width: 2.0,
                                radius: 8.0.into(),
                            },
                            ..Default::default()
                        }
                    } else if is_hover_target {
                        container::Style {
                            background: Some(theme.bg_surface.into()),
                            border: Border {
                                color: theme.success,
                                width: 2.0,
                                radius: 8.0.into(),
                            },
                            ..Default::default()
                        }
                    } else {
                        card_container(theme)
                    });

                let card_element: Element<'_, Message> = if any_drag_active && !is_being_dragged {
                    // Make entire card clickable and hoverable when drag is active
                    mouse_area(card)
                        .on_enter(Message::RuleHoverStart(rule.id))
                        .on_exit(Message::RuleHoverEnd)
                        .on_press(Message::RuleDropped(rule.id))
                        .into()
                } else {
                    card.into()
                };

                col.push(card_element)
            })
            .into()
    };

    container(
        column![
            branding,
            text("NETWORK ACCESS")
                .size(10)
                .color(theme.fg_muted)
                .font(FONT_REGULAR),
            search_bar,
            metrics,
            container(
                scrollable(container(rule_list).height(Length::Shrink))
                    .height(Length::Fill)
            )
            .max_height(800),
            add_button,
        ]
        .spacing(20)
        .padding(24),
    )
    .width(Length::Fixed(320.0))
    .height(Length::Fill)
    .style(move |_| sidebar_container(theme))
    .into()
}

#[allow(clippy::too_many_lines)]
fn view_workspace<'a>(
    state: &'a State,
    preview_content: Element<'a, Message>,
) -> Element<'a, Message> {
    let theme = &state.theme;
    let tab_bar = row![
        view_tab_button(
            "nftables.conf",
            WorkspaceTab::Nftables,
            state.active_tab,
            theme
        ),
        view_tab_button("JSON Payload", WorkspaceTab::Json, state.active_tab, theme),
        view_tab_button("Settings", WorkspaceTab::Settings, state.active_tab, theme),
    ]
    .spacing(2);

    let mut preview_header_row = row![
        column![
            text(match state.active_tab {
                WorkspaceTab::Nftables => "Active Configuration",
                WorkspaceTab::Json => "JSON Export",
                WorkspaceTab::Settings => "Advanced Security",
            })
            .size(20)
            .font(FONT_REGULAR)
            .color(theme.warning),
            text(match state.active_tab {
                WorkspaceTab::Nftables => "Current nftables ruleset generated from your rules.",
                WorkspaceTab::Json => "Low-level JSON representation for debugging or automation.",
                WorkspaceTab::Settings =>
                    "Optional security features for advanced users and server deployments.",
            })
            .size(12)
            .color(theme.fg_muted),
        ]
        .spacing(4)
        .width(Length::Fill),
    ];

    // Add diff toggle when on Nftables tab and we have a previous version
    if state.active_tab == WorkspaceTab::Nftables && state.last_applied_ruleset.is_some() {
        preview_header_row = preview_header_row.push(
            checkbox(state.show_diff)
                .label("Show diff")
                .on_toggle(Message::ToggleDiff)
                .size(16)
                .text_size(13)
                .spacing(8),
        );
    }

    let preview_header = preview_header_row.push(tab_bar).align_y(Alignment::Center);

    let editor = container(
        scrollable(
            container(preview_content)
                .padding(24)
                .width(Length::Fill)
                .height(Length::Shrink)
        )
        .width(Length::Fill)
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(|_| container::Style {
        background: Some(Color::from_rgb(0.11, 0.11, 0.11).into()),
        border: Border {
            radius: 12.0.into(),
            color: theme.border,
            width: 1.0,
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.4),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 10.0,
        },
        ..Default::default()
    });

    let save_to_system = if state.status == AppStatus::Confirmed {
        button(text("Permanently Save to System").font(FONT_REGULAR))
            .style(move |_, status| primary_button(theme, status))
            .padding([12, 24])
            .on_press(Message::SaveToSystemClicked)
    } else {
        button(text("Save to /etc/nftables.conf").font(FONT_REGULAR))
            .padding([12, 24])
            .style(button::secondary)
    };

    let is_dirty = state.is_dirty();
    let apply_button = {
        let is_busy = matches!(
            state.status,
            AppStatus::Verifying
                | AppStatus::Applying
                | AppStatus::PendingConfirmation { .. }
                | AppStatus::Reverting
        );
        let button_text = if matches!(state.status, AppStatus::Verifying) {
            "Verifying..."
        } else if is_busy {
            "Processing..."
        } else if is_dirty {
            "Apply Changes*"
        } else {
            "Apply Changes"
        };
        let mut btn = button(text(button_text).font(FONT_REGULAR)).padding([12, 32]);

        if is_dirty && !is_busy {
            btn = btn.style(move |_, status| dirty_button(theme, status));
        } else {
            btn = btn.style(move |_, status| primary_button(theme, status));
        }

        if !is_busy {
            btn = btn.on_press(Message::ApplyClicked);
        }
        btn
    };

    // Undo/Redo buttons
    let undo_button = {
        let mut btn = button(text("↶ Undo").font(FONT_REGULAR))
            .padding([12, 20])
            .style(button::secondary);
        if state.command_history.can_undo() {
            btn = btn.on_press(Message::Undo);
        }
        btn
    };

    let redo_button = {
        let mut btn = button(text("↷ Redo").font(FONT_REGULAR))
            .padding([12, 20])
            .style(button::secondary);
        if state.command_history.can_redo() {
            btn = btn.on_press(Message::Redo);
        }
        btn
    };

    let footer = row![
        button("Export")
            .on_press(Message::ExportClicked)
            .padding([12, 20])
            .style(button::secondary),
        button("Diagnostics")
            .on_press(Message::ToggleDiagnostics(true))
            .padding([12, 20])
            .style(button::secondary),
        undo_button,
        redo_button,
        save_to_system,
        rule::horizontal(1),
        if let Some(ref err) = state.last_error {
            view_error_display(err, theme)
        } else {
            row![].into()
        },
        rule::horizontal(1),
        apply_button,
    ]
    .spacing(16)
    .align_y(Alignment::Center);

    container(
        column![preview_header, editor, footer]
            .spacing(24)
            .padding(32),
    )
    .width(Length::Fill)
    .into()
}

fn view_tab_button<'a>(
    label: &'static str,
    tab: WorkspaceTab,
    active_tab: WorkspaceTab,
    theme: &'a crate::theme::AppTheme,
) -> Element<'a, Message> {
    let is_active = tab == active_tab;
    button(text(label).size(13))
        .padding([8, 16])
        .style(move |_, status| {
            if is_active {
                active_tab_button(theme, status)
            } else {
                button::secondary(&Theme::Dark, status)
            }
        })
        .on_press(Message::TabChanged(tab))
        .into()
}

#[allow(clippy::too_many_lines)]
fn view_highlighted_json(
    content: &str,
    theme: &crate::theme::AppTheme,
) -> iced::widget::Column<'static, Message> {
    let mut lines = column![].spacing(2);

    for (i, line) in content.lines().enumerate() {
        let mut row_content = row![].spacing(0);

        // Line number
        row_content = row_content.push(
            container(
                text(format!("{:3} ", i + 1))
                    .font(FONT_MONO)
                    .size(11)
                    .color(Color::from_rgb(0.4, 0.4, 0.4)),
            )
            .padding(iced::Padding::new(0.0).right(10.0)),
        );

        row_content = row_content.push(rule::vertical(1));

        // Preserve indentation
        let trimmed = line.trim_start();
        let indent = line.len().saturating_sub(trimmed.len()).min(32);
        if !line.is_empty() {
            if indent > 0 {
                // Use a static string for common indentation levels (up to 32 spaces)
                const SPACES: &str = "                                ";
                let spaces = &SPACES[..indent];
                row_content = row_content
                    .push(text("  ").font(FONT_MONO).size(13))
                    .push(text(spaces).font(FONT_MONO).size(13));
            } else {
                row_content = row_content.push(text("  ").font(FONT_MONO).size(13));
            }
        }

        // Syntax highlight JSON tokens
        let mut chars = trimmed.chars().peekable();
        let mut current_token = String::new();

        while let Some(ch) = chars.next() {
            match ch {
                '"' => {
                    if !current_token.is_empty() {
                        let token = std::mem::take(&mut current_token);
                        row_content = row_content
                            .push(text(token).font(FONT_MONO).size(13).color(theme.fg_primary));
                    }

                    // Read the full string
                    let mut string_content = String::from('"');
                    while let Some(&next_ch) = chars.peek() {
                        chars.next();
                        string_content.push(next_ch);
                        if next_ch == '"' && !string_content.ends_with("\\\"") {
                            break;
                        }
                    }

                    // Check if this is a key (followed by colon)
                    let mut temp_chars = chars.clone();
                    let mut is_key = false;
                    while let Some(&next_ch) = temp_chars.peek() {
                        if next_ch.is_whitespace() {
                            temp_chars.next();
                        } else {
                            is_key = next_ch == ':';
                            break;
                        }
                    }

                    let color = if is_key {
                        theme.syntax_type
                    } else {
                        theme.syntax_string
                    };
                    row_content = row_content
                        .push(text(string_content).font(FONT_MONO).size(13).color(color));
                }
                ':' | ',' => {
                    if !current_token.is_empty() {
                        let token = std::mem::take(&mut current_token);
                        row_content = row_content
                            .push(text(token).font(FONT_MONO).size(13).color(theme.fg_primary));
                    }
                    let ch_str = if ch == ':' { ":" } else { "," };
                    row_content = row_content.push(
                        text(ch_str)
                            .font(FONT_MONO)
                            .size(13)
                            .color(theme.fg_primary),
                    );
                }
                '{' | '}' | '[' | ']' => {
                    if !current_token.is_empty() {
                        let token = std::mem::take(&mut current_token);
                        row_content = row_content
                            .push(text(token).font(FONT_MONO).size(13).color(theme.fg_primary));
                    }
                    let ch_str = match ch {
                        '{' => "{",
                        '}' => "}",
                        '[' => "[",
                        ']' => "]",
                        _ => unreachable!(),
                    };
                    row_content = row_content
                        .push(text(ch_str).font(FONT_MONO).size(13).color(theme.info));
                }
                _ => {
                    current_token.push(ch);
                }
            }
        }

        // Flush remaining token
        if !current_token.is_empty() {
            let token_trimmed = current_token.trim();
            let color = match token_trimmed {
                "true" | "false" | "null" => theme.syntax_keyword,
                _ if token_trimmed.parse::<f64>().is_ok() => theme.warning,
                _ => theme.fg_primary,
            };
            row_content = row_content
                .push(text(current_token).font(FONT_MONO).size(13).color(color));
        }

        lines = lines.push(row_content);
    }
    lines
}

fn view_highlighted_nft(
    content: &str,
    theme: &crate::theme::AppTheme,
) -> iced::widget::Column<'static, Message> {
    let mut lines = column![].spacing(2);

    for (i, line) in content.lines().enumerate() {
        let mut row_content = row![].spacing(0);

        // Line number
        row_content = row_content.push(
            container(
                text(format!("{:3} ", i + 1))
                    .font(FONT_MONO)
                    .size(11)
                    .color(Color::from_rgb(0.4, 0.4, 0.4)),
            )
            .padding(iced::Padding::new(0.0).right(10.0)),
        );

        row_content = row_content.push(rule::vertical(1));

        // Preserve indentation
        let trimmed = line.trim_start();
        let indent = line.len().saturating_sub(trimmed.len()).min(32);
        if !line.is_empty() {
            if indent > 0 {
                const SPACES: &str = "                                ";
                let spaces = &SPACES[..indent];
                row_content = row_content
                    .push(text("  ").font(FONT_MONO).size(13))
                    .push(text(spaces).font(FONT_MONO).size(13));
            } else {
                row_content = row_content.push(text("  ").font(FONT_MONO).size(13));
            }
        }

        // Syntax highlight nftables tokens
        let words: Vec<String> = trimmed.split_whitespace().map(String::from).collect();

        for (idx, word) in words.into_iter().enumerate() {
            // Add space between words (except first word)
            if idx > 0 {
                row_content = row_content.push(text(" ").font(FONT_MONO).size(13));
            }

            // Determine color based on token type
            let color = if matches!(
                word.as_str(),
                "table" | "chain" | "type" | "hook" | "priority" | "policy"
                | "counter" | "accept" | "drop" | "reject" | "jump" | "goto"
                | "meta" | "iif" | "oif" | "saddr" | "daddr" | "sport" | "dport"
                | "tcp" | "udp" | "icmp" | "icmpv6" | "ip" | "ip6" | "inet"
                | "filter" | "nat" | "route" | "input" | "output" | "forward"
                | "prerouting" | "postrouting" | "ct" | "state" | "established"
                | "related" | "invalid" | "new"
            ) {
                theme.syntax_keyword
            } else if word.starts_with('"') || word.ends_with('"') {
                theme.syntax_string
            } else if word.parse::<u16>().is_ok() || word.contains('.') || word.contains(':') {
                theme.warning // Numbers, IPs
            } else if matches!(word.as_str(), "{" | "}" | "(" | ")") {
                theme.info
            } else if word.starts_with('#') {
                theme.fg_muted // Comments
            } else {
                theme.fg_primary
            };

            row_content = row_content.push(
                text(word)
                    .font(FONT_MONO)
                    .size(13)
                    .color(color)
            );
        }

        lines = lines.push(row_content);
    }

    lines
}

fn view_diff_text(
    diff_content: &str,
    theme: &crate::theme::AppTheme,
) -> iced::widget::Column<'static, Message> {
    let mut lines = column![].spacing(2);

    for (i, line) in diff_content.lines().enumerate() {
        let mut row_content = row![].spacing(0);

        // Line number
        row_content = row_content.push(
            container(
                text(format!("{:3} ", i + 1))
                    .font(FONT_MONO)
                    .size(11)
                    .color(Color::from_rgb(0.4, 0.4, 0.4)),
            )
            .padding(iced::Padding::new(0.0).right(10.0)),
        );

        row_content = row_content.push(rule::vertical(1));

        // Determine if this is an added, removed, or unchanged line
        let (diff_prefix, content_line) = if let Some(content) = line.strip_prefix("+ ") {
            ("+", content)
        } else if let Some(content) = line.strip_prefix("- ") {
            ("-", content)
        } else if let Some(content) = line.strip_prefix("  ") {
            (" ", content)
        } else {
            // Fallback for lines without any prefix
            (" ", line)
        };

        // Preserve indentation (matching regular view structure)
        let trimmed = content_line.trim_start();
        let indent = content_line.len().saturating_sub(trimmed.len()).min(32);
        if !content_line.is_empty() {
            // Add diff indicator as the base spacing
            let diff_color = match diff_prefix {
                "+" => theme.success,
                "-" => theme.danger,
                _ => theme.fg_muted,
            };
            row_content = row_content.push(
                text(format!("{diff_prefix} "))
                    .font(FONT_MONO)
                    .size(13)
                    .color(diff_color),
            );

            // Add additional indentation if needed
            if indent > 0 {
                const SPACES: &str = "                                ";
                let spaces = &SPACES[..indent];
                row_content = row_content.push(text(spaces).font(FONT_MONO).size(13));
            }
        }

        // Syntax highlight nftables tokens with slight tinting based on diff status
        let words: Vec<String> = trimmed.split_whitespace().map(String::from).collect();

        for (idx, word) in words.into_iter().enumerate() {
            // Add space between words (except first word)
            if idx > 0 {
                row_content = row_content.push(text(" ").font(FONT_MONO).size(13));
            }

            // Determine base color based on token type
            let base_color = if matches!(
                word.as_str(),
                "table" | "chain" | "type" | "hook" | "priority" | "policy"
                | "counter" | "accept" | "drop" | "reject" | "jump" | "goto"
                | "meta" | "iif" | "oif" | "saddr" | "daddr" | "sport" | "dport"
                | "tcp" | "udp" | "icmp" | "icmpv6" | "ip" | "ip6" | "inet"
                | "filter" | "nat" | "route" | "input" | "output" | "forward"
                | "prerouting" | "postrouting" | "ct" | "state" | "established"
                | "related" | "invalid" | "new"
            ) {
                theme.syntax_keyword
            } else if word.starts_with('"') || word.ends_with('"') {
                theme.syntax_string
            } else if word.parse::<u16>().is_ok() || word.contains('.') || word.contains(':') {
                theme.warning
            } else if matches!(word.as_str(), "{" | "}" | "(" | ")") {
                theme.info
            } else if word.starts_with('#') {
                theme.fg_muted
            } else {
                theme.fg_primary
            };

            // Tint the color based on diff status
            let color = match diff_prefix {
                "+" => Color {
                    g: (base_color.g * 1.2).min(1.0),
                    ..base_color
                },
                "-" => Color {
                    r: (base_color.r * 1.2).min(1.0),
                    ..base_color
                },
                _ => base_color,
            };

            row_content = row_content.push(
                text(word)
                    .font(FONT_MONO)
                    .size(13)
                    .color(color)
            );
        }

        lines = lines.push(row_content);
    }

    lines
}

#[allow(clippy::too_many_lines)]
fn view_rule_form<'a>(
    form: &'a RuleForm,
    errors: Option<&'a crate::app::FormErrors>,
    interfaces: &'a [String],
    theme: &'a crate::theme::AppTheme,
) -> Element<'a, Message> {
    let title_text = if form.id.is_some() {
        "Edit Rule"
    } else {
        "New Access Rule"
    };
    let button_text = if form.id.is_some() {
        "Update"
    } else {
        "Create"
    };
    let port_error = errors.and_then(|e| e.port.as_ref());
    let source_error = errors.and_then(|e| e.source.as_ref());
    let mut iface_options = vec!["Any".to_string()];
    iface_options.extend(interfaces.iter().cloned());

    let form_box = column![
        column![
            text(title_text)
                .size(22)
                .font(FONT_REGULAR)
                .color(theme.info),
            text("Define allowed traffic patterns.")
                .size(12)
                .color(theme.fg_muted)
        ]
        .spacing(4),
        column![
            container(text("BASIC INFO").size(10).color(theme.fg_primary))
                .padding([4, 8])
                .style(move |_| section_header_container(theme)),
            column![
                text("DESCRIPTION").size(10).color(theme.fg_muted),
                text_input("e.g. Local Web Server", &form.label)
                    .on_input(Message::RuleFormLabelChanged)
                    .padding(10)
            ]
            .spacing(6),
            column![
                text("SERVICE PRESET").size(10).color(theme.fg_muted),
                pick_list(
                    PRESETS,
                    form.selected_preset.clone(),
                    Message::RuleFormPresetSelected
                )
                .placeholder("Select a common service...")
                .width(Length::Fill)
                .padding(10)
            ]
            .spacing(6),
        ]
        .spacing(12),
        column![
            container(text("TECHNICAL DETAILS").size(10).color(theme.fg_primary))
                .padding([4, 8])
                .style(move |_| section_header_container(theme)),
            row![
                column![
                    text("PROTOCOL").size(10).color(theme.fg_muted),
                    pick_list(
                        vec![
                            Protocol::Any,
                            Protocol::Tcp,
                            Protocol::Udp,
                            Protocol::Icmp,
                            Protocol::Icmpv6
                        ],
                        Some(form.protocol),
                        Message::RuleFormProtocolChanged
                    )
                    .width(Length::Fill)
                    .padding(10)
                ]
                .spacing(6)
                .width(Length::Fill),
                column![
                    text("PORT RANGE").size(10).color(theme.fg_muted),
                    view_port_inputs(form, port_error, theme),
                    if let Some(err) = port_error {
                        text(err).size(11).color(theme.danger)
                    } else {
                        text("")
                    }
                ]
                .spacing(6)
                .width(Length::Fill),
            ]
            .spacing(16),
        ]
        .spacing(12),
        column![
            container(text("CONTEXT").size(10).color(theme.fg_primary))
                .padding([4, 8])
                .style(move |_| section_header_container(theme)),
            column![
                text("SOURCE ADDRESS (OPTIONAL)")
                    .size(10)
                    .color(theme.fg_muted),
                text_input("e.g. 192.168.1.0/24 or specific IP", &form.source)
                    .on_input(Message::RuleFormSourceChanged)
                    .padding(10),
                if let Some(err) = source_error {
                    text(err).size(11).color(theme.danger)
                } else {
                    text("")
                }
            ]
            .spacing(6),
            column![
                text("INTERFACE (OPTIONAL)").size(10).color(theme.fg_muted),
                pick_list(
                    iface_options,
                    Some(if form.interface.is_empty() {
                        "Any".to_string()
                    } else {
                        form.interface.clone()
                    }),
                    |s| if s == "Any" {
                        Message::RuleFormInterfaceChanged(String::new())
                    } else {
                        Message::RuleFormInterfaceChanged(s)
                    }
                )
                .width(Length::Fill)
                .padding(10)
            ]
            .spacing(6),
        ]
        .spacing(12),
        column![
            container(text("ORGANIZATION").size(10).color(theme.fg_primary))
                .padding([4, 8])
                .style(move |_| section_header_container(theme)),
            column![
                text("TAGS").size(10).color(theme.fg_muted),
                row![
                    text_input("Add a tag...", &form.tag_input)
                        .on_input(Message::RuleFormTagInputChanged)
                        .on_submit(Message::RuleFormAddTag)
                        .padding(10),
                    button(text("+").size(16))
                        .on_press(Message::RuleFormAddTag)
                        .padding([8, 16])
                        .style(move |_, status| primary_button(theme, status)),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
                if form.tags.is_empty() {
                    row(std::iter::empty()).spacing(8).wrap()
                } else {
                    row(form.tags.iter().map(|tag| {
                        let tag_theme = theme.clone();
                        container(
                            row![
                                text(tag).size(12).color(theme.fg_on_accent),
                                button(text("×").size(14))
                                    .on_press(Message::RuleFormRemoveTag(tag.clone()))
                                    .padding([2, 6])
                                    .style(button::text),
                            ]
                            .spacing(6)
                            .align_y(Alignment::Center),
                        )
                        .padding([4, 10])
                        .style(move |t| {
                            let mut style = container::rounded_box(t);
                            style.background = Some(tag_theme.accent.into());
                            style
                        })
                        .into()
                    }))
                    .spacing(8)
                    .wrap()
                },
            ]
            .spacing(8),
        ]
        .spacing(12),
        row![
            button(text("Cancel").size(14))
                .on_press(Message::CancelRuleForm)
                .padding([10, 20])
                .style(button::secondary),
            rule::horizontal(1),
            button(text(button_text).size(14))
                .on_press(Message::SaveRuleForm)
                .padding([10, 24])
                .style(move |_, status| primary_button(theme, status)),
        ]
        .spacing(16)
        .align_y(Alignment::Center)
    ]
    .spacing(20)
    .padding(32);
    container(form_box)
        .max_width(520)
        .style(move |_| card_container(theme))
        .into()
}

fn view_port_inputs<'a>(
    form: &RuleForm,
    _has_error: Option<&String>,
    theme: &'a crate::theme::AppTheme,
) -> Element<'a, Message> {
    if matches!(form.protocol, Protocol::Tcp | Protocol::Udp) {
        row![
            text_input("80", &form.port_start)
                .on_input(Message::RuleFormPortStartChanged)
                .padding(10)
                .width(Length::Fill),
            text("-").size(16).color(theme.fg_muted),
            text_input("80", &form.port_end)
                .on_input(Message::RuleFormPortEndChanged)
                .padding(10)
                .width(Length::Fill),
        ]
        .spacing(6)
        .align_y(Alignment::Center)
        .into()
    } else {
        container(
            text("Not applicable")
                .size(12)
                .color(theme.fg_muted)
                .font(FONT_MONO),
        )
        .padding(10)
        .width(Length::Fill)
        .height(40)
        .align_y(iced::alignment::Vertical::Center)
        .into()
    }
}

fn view_awaiting_apply(app_theme: &crate::theme::AppTheme) -> Element<'_, Message> {
    container(column![text("🛡️").size(36), text("Commit Changes?").size(24).font(FONT_REGULAR).color(app_theme.fg_primary),
                      text("Rules verified. Applying will take effect immediately with a 15s safety rollback window.").size(14).color(app_theme.fg_muted).width(360).align_x(Alignment::Center),
                      row![button(text("Discard").size(14)).on_press(Message::CancelRuleForm).padding([10, 20]).style(button::secondary),
                           button(text("Apply & Start Timer").size(14)).on_press(Message::ProceedToApply).padding([10, 24]).style(move |_, status| primary_button(app_theme, status)),
                      ].spacing(16)
    ].spacing(20).padding(32).align_x(Alignment::Center))
    .style(move |_| { let mut style = card_container(app_theme); style.shadow = iced::Shadow { color: Color::from_rgba(0.0, 0.0, 0.0, 0.8), offset: iced::Vector::new(0.0, 10.0), blur_radius: 20.0 }; style }).into()
}

fn view_pending_confirmation(
    remaining: u32,
    app_theme: &crate::theme::AppTheme,
) -> Element<'_, Message> {
    container(
        column![
            text("⏳").size(36),
            text("Confirm Safety")
                .size(24)
                .font(FONT_REGULAR)
                .color(app_theme.fg_primary),
            text(format!(
                "Firewall updated. Automatic rollback in {remaining} seconds if not confirmed."
            ))
            .size(14)
            .color(app_theme.accent)
            .width(360)
            .align_x(Alignment::Center),
            row![
                button(text("Rollback").size(14))
                    .on_press(Message::RevertClicked)
                    .padding([10, 20])
                    .style(move |_, status| danger_button(app_theme, status)),
                button(text("Confirm & Stay").size(14))
                    .on_press(Message::ConfirmClicked)
                    .padding([10, 24])
                    .style(move |_, status| primary_button(app_theme, status)),
            ]
            .spacing(16)
        ]
        .spacing(20)
        .padding(32)
        .align_x(Alignment::Center),
    )
    .style(move |_| {
        let mut style = card_container(app_theme);
        style.shadow = iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.8),
            offset: iced::Vector::new(0.0, 10.0),
            blur_radius: 20.0,
        };
        style
    })
    .into()
}

#[allow(clippy::too_many_lines)]
fn view_settings(state: &State) -> Element<'_, Message> {
    use iced::widget::slider;

    let theme = &state.theme;
    let advanced = &state.ruleset.advanced_security;

    column![
            // Header
            text("Settings")
                .size(24)
                .color(theme.fg_primary),

            // Theme Selector
            row![
                column![
                    text("Theme").size(16).color(theme.fg_primary),
                    text("Choose your preferred color scheme")
                        .size(13)
                        .color(theme.fg_muted),
                ]
                .width(Length::Fill),
                pick_list(
                    crate::theme::ThemeChoice::all_builtin(),
                    Some(state.current_theme),
                    Message::ThemeChanged,
                )
                .width(200)
                .text_size(14),
            ]
            .spacing(16)
            .align_y(Alignment::Center),

            rule::horizontal(1),

            // Advanced Security Header
            text("Advanced Security Settings")
                .size(20)
                .color(theme.fg_primary),
            text("⚠️  These settings may break common applications. Defaults are suitable for most users.")
                .size(14)
                .color(theme.syntax_string),
            rule::horizontal(1),
            // Strict ICMP Mode
            row![
                toggler(advanced.strict_icmp)
                    .on_toggle(Message::ToggleStrictIcmp)
                    .width(40),
                column![
                    text("Strict ICMP filtering").size(16).color(theme.fg_primary),
                    text("Only allow essential ICMP types")
                        .size(13)
                        .color(theme.fg_muted),
                    text("ℹ️  May break network tools and games")
                        .size(12)
                        .color(theme.info),
                ]
                .spacing(4),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            // ICMP Rate Limiting
            row![
                toggler(advanced.icmp_rate_limit > 0)
                    .on_toggle(|enabled| {
                        Message::IcmpRateLimitChanged(if enabled { 10 } else { 0 })
                    })
                    .width(40),
                column![
                    text("ICMP rate limiting").size(16).color(theme.fg_primary),
                    row![
                        text("Rate:").size(13).color(theme.fg_muted),
                        slider(
                            0..=50, advanced.icmp_rate_limit, Message::IcmpRateLimitChanged
                        )
                        .width(200),
                        text(format!("{}/sec", advanced.icmp_rate_limit))
                            .size(13)
                            .color(theme.fg_primary),
                        text("(0 = disabled)").size(12).color(theme.fg_muted),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                    text("ℹ️  May interfere with monitoring tools")
                        .size(12)
                        .color(theme.info),
                ]
                .spacing(4),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            // Anti-spoofing (RPF)
            row![
                toggler(advanced.enable_rpf)
                    .on_toggle(Message::ToggleRpfRequested)
                    .width(40),
                column![
                    text("Anti-spoofing (RPF)").size(16).color(theme.fg_primary),
                    text("Reverse path filtering via FIB lookup")
                        .size(13)
                        .color(theme.fg_muted),
                    text("⚠️  WILL BREAK: Docker, VPNs, cloud instances")
                        .size(12)
                        .color(theme.danger),
                ]
                .spacing(4),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            // Dropped Packet Logging
            row![
                toggler(advanced.log_dropped)
                    .on_toggle(Message::ToggleDroppedLogging)
                    .width(40),
                column![
                    text("Log dropped packets").size(16).color(theme.fg_primary),
                    row![
                        text("Rate:").size(13).color(theme.fg_muted),
                        slider(
                            1..=100, advanced.log_rate_per_minute, Message::LogRateChanged
                        )
                        .width(200),
                        text(format!("{}/min", advanced.log_rate_per_minute))
                            .size(13)
                            .color(theme.fg_primary),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                    row![
                        text("Prefix:").size(13).color(theme.fg_muted),
                        text_input("DRFW-DROP: ", &advanced.log_prefix)
                            .on_input(Message::LogPrefixChanged)
                            .width(200),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                    text("ℹ️  Privacy: Logs network activity")
                        .size(12)
                        .color(theme.info),
                ]
                .spacing(4),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            // Egress Profile
            column![
                text("Egress Filtering Profile")
                    .size(16)
                    .color(theme.fg_primary),
                row![
                    button(
                        text(if advanced.egress_profile
                            == crate::core::firewall::EgressProfile::Desktop
                        {
                            "● Desktop"
                        } else {
                            "○ Desktop"
                        })
                        .size(14)
                    )
                    .on_press(Message::EgressProfileRequested(
                        crate::core::firewall::EgressProfile::Desktop
                    ))
                    .style(move |_, status| if advanced.egress_profile
                        == crate::core::firewall::EgressProfile::Desktop
                    {
                        active_card_button(&state.theme, status)
                    } else {
                        card_button(&state.theme, status)
                    }),
                    button(
                        text(if advanced.egress_profile
                            == crate::core::firewall::EgressProfile::Server
                        {
                            "● Server"
                        } else {
                            "○ Server"
                        })
                        .size(14)
                    )
                    .on_press(Message::EgressProfileRequested(
                        crate::core::firewall::EgressProfile::Server
                    ))
                    .style(move |_, status| if advanced.egress_profile
                        == crate::core::firewall::EgressProfile::Server
                    {
                        active_card_button(&state.theme, status)
                    } else {
                        card_button(&state.theme, status)
                    }),
                ]
                .spacing(12),
                text(if advanced.egress_profile
                    == crate::core::firewall::EgressProfile::Desktop
                {
                    "Allow all outbound connections (default)"
                } else {
                    "⚠️  Deny all outbound by default (server mode)"
                })
                .size(13)
                .color(if advanced.egress_profile
                    == crate::core::firewall::EgressProfile::Desktop
                {
                    theme.fg_muted
                } else {
                    theme.danger
                }),
            ]
            .spacing(8),
        ]
        .spacing(20)
        .padding(20)
        .into()
}

fn view_warning_modal<'a>(
    warning: &'a PendingWarning,
    theme: &'a crate::theme::AppTheme,
) -> Element<'a, Message> {
    let (title, message, confirm_msg) = match warning {
        PendingWarning::EnableRpf => (
            "⚠️ WARNING: Anti-Spoofing Mode",
            "Enabling this feature may break:\n\n    • Docker containers\n    • VPN connections (WireGuard, OpenVPN)\n    • Multi-homed systems\n    • AWS/GCP cloud instances\n\nOnly enable if:\n    ✓ You don't use Docker or VPNs\n    ✓ This is a single-interface server\n    ✓ You understand reverse path filtering\n\nAlternative: Use kernel RPF instead:\n  \n      sudo sysctl net.ipv4.conf.all.rp_filter=1",
            Message::ConfirmEnableRpf,
        ),
        PendingWarning::EnableServerMode => (
            "⚠️ Server Mode: Egress Filtering",
            "This will BLOCK all outbound connections by default.\n\nYou'll need to explicitly allow:\n    • Web browsing (HTTP/HTTPS)\n    • DNS queries\n    • Software updates\n    • Any services your applications use\n\nThis mode is designed for servers, not desktop use.",
            Message::ConfirmServerMode,
        ),
    };

    container(
        column![
            text(title).size(20).color(theme.danger),
            text(message)
                .size(14)
                .color(theme.fg_primary)
                .font(FONT_MONO),
            row![
                button(text("Cancel").size(14))
                    .on_press(Message::CancelWarning)
                    .padding(12)
                    .style(move |_, status| card_button(theme, status)),
                button(text("Yes, I understand").size(14))
                    .on_press(confirm_msg)
                    .padding(12)
                    .style(move |_, status| danger_button(theme, status)),
            ]
            .spacing(12),
        ]
        .spacing(20)
        .padding(30)
        .max_width(600),
    )
    .style(move |_| {
        let mut style = card_container(theme);
        style.shadow = iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.8),
            offset: iced::Vector::new(0.0, 10.0),
            blur_radius: 20.0,
        };
        style.border = Border {
            color: theme.danger,
            width: 2.0,
            ..Default::default()
        };
        style
    })
    .into()
}

fn view_error_display<'a>(
    err: &'a crate::core::error::ErrorInfo,
    theme: &'a crate::theme::AppTheme,
) -> Element<'a, Message> {
    let mut elements: Vec<Element<'_, Message>> = vec![
        row![
            text("⚠️").size(16),
            text(&err.message)
                .size(13)
                .color(theme.danger)
                .font(FONT_REGULAR),
            button("Copy Details")
                .on_press(Message::CopyErrorClicked)
                .padding([4, 10])
                .style(move |_, status| danger_button(theme, status))
        ]
        .spacing(12)
        .align_y(Alignment::Center)
        .into(),
    ];

    // Add suggestions if available
    for suggestion in &err.suggestions {
        elements.push(
            row![
                text("→").size(12).color(theme.info),
                text(suggestion)
                    .size(12)
                    .color(theme.fg_primary)
                    .font(FONT_MONO),
            ]
            .spacing(6)
            .into(),
        );
    }

    column(elements).spacing(6).into()
}

#[allow(clippy::too_many_lines)]
fn view_diagnostics_modal(theme: &crate::theme::AppTheme) -> Element<'_, Message> {
    // Read recent audit log entries
    let audit_entries = std::fs::read_to_string(
        crate::utils::get_data_dir()
            .map(|mut p| {
                p.push("audit.log");
                p
            })
            .unwrap_or_default(),
    )
    .unwrap_or_default();

    // Collect entries as owned Strings
    let recent_entries: Vec<String> = audit_entries
        .lines()
        .rev()
        .take(10)
        .map(std::string::ToString::to_string)
        .collect();

    // Get recovery commands as owned strings
    let state_dir = crate::utils::get_data_dir().map_or_else(
        || "~/.local/state/drfw".to_string(),
        |p| p.to_string_lossy().to_string(),
    );

    let recovery_cmd = "sudo nft flush ruleset".to_string();
    let snapshot_restore_cmd = format!("sudo nft --json -f {state_dir}/snapshot-*.json");

    container(
        column![
            row![
                text("📊 Diagnostics & Logs")
                    .size(24)
                    .font(FONT_REGULAR)
                    .color(theme.warning),
                rule::horizontal(0),
            ]
            .spacing(12)
            .align_y(Alignment::Center)
            .width(Length::Fill),
            // Audit log section
            column![
                text("Recent Audit Log Entries:")
                    .size(14)
                    .color(theme.fg_primary),
                container(scrollable(
                    column(if recent_entries.is_empty() {
                        vec![
                            text("No audit entries found")
                                .size(12)
                                .color(theme.fg_muted)
                                .into(),
                        ]
                    } else {
                        recent_entries
                            .into_iter()
                            .map(|entry| {
                                text(entry)
                                    .size(11)
                                    .font(FONT_MONO)
                                    .color(theme.fg_primary)
                                    .into()
                            })
                            .collect()
                    })
                    .spacing(4)
                ))
                .height(200)
                .style(move |_| container::Style {
                    background: Some(theme.bg_elevated.into()),
                    border: Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                })
                .padding(12),
            ]
            .spacing(8),
            // Recovery commands section
            column![
                text("Manual Recovery Commands:")
                    .size(14)
                    .color(theme.fg_primary),
                container(
                    column![
                        text("Emergency flush (removes all rules):")
                            .size(12)
                            .color(theme.fg_muted),
                        text(recovery_cmd)
                            .size(12)
                            .font(FONT_MONO)
                            .color(theme.warning),
                        text("Restore from snapshot:")
                            .size(12)
                            .color(theme.fg_muted),
                        text(snapshot_restore_cmd)
                            .size(12)
                            .font(FONT_MONO)
                            .color(theme.warning),
                    ]
                    .spacing(6)
                )
                .style(move |_| container::Style {
                    background: Some(theme.bg_elevated.into()),
                    border: Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                })
                .padding(12),
            ]
            .spacing(8),
            // Action buttons
            row![
                button(text("Open Logs Folder").size(14))
                    .on_press(Message::OpenLogsFolder)
                    .padding([10, 20])
                    .style(move |_, status| primary_button(theme, status)),
                button(text("Close").size(14))
                    .on_press(Message::ToggleDiagnostics(false))
                    .padding([10, 20])
                    .style(move |_, status| card_button(theme, status)),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        ]
        .spacing(20)
        .padding(32)
        .max_width(700),
    )
    .style(move |_| section_header_container(theme))
    .into()
}

fn view_export_modal(theme: &crate::theme::AppTheme) -> Element<'_, Message> {
    container(
        column![
            text("📤 Export Rules")
                .size(24)
                .font(FONT_REGULAR)
                .color(theme.warning),
            text("Choose the export format:")
                .size(14)
                .color(theme.fg_muted),
            column![
                button(
                    row![
                        text("📄").size(20),
                        column![
                            text("Export as JSON")
                                .size(16)
                                .font(FONT_REGULAR)
                                .color(theme.fg_primary),
                            text("Structured data format for automation and backup")
                                .size(12)
                                .color(theme.fg_muted),
                        ]
                        .spacing(4),
                    ]
                    .spacing(12)
                    .align_y(Alignment::Center)
                    .padding(16)
                )
                .on_press(Message::ExportAsJson)
                .style(move |_, status| card_button(theme, status))
                .width(Length::Fill),
                button(
                    row![
                        text("📝").size(20),
                        column![
                            text("Export as nftables text")
                                .size(16)
                                .font(FONT_REGULAR)
                                .color(theme.fg_primary),
                            text("Human-readable .nft format for manual editing")
                                .size(12)
                                .color(theme.fg_muted),
                        ]
                        .spacing(4),
                    ]
                    .spacing(12)
                    .align_y(Alignment::Center)
                    .padding(16)
                )
                .on_press(Message::ExportAsNft)
                .style(move |_, status| card_button(theme, status))
                .width(Length::Fill),
            ]
            .spacing(12),
            text("Files will be saved to ~/Downloads/ or your data directory")
                .size(11)
                .color(theme.fg_muted),
            button(text("Cancel").size(14))
                .on_press(Message::ExportClicked) // Toggle to close
                .padding([10, 20])
                .style(button::secondary),
        ]
        .spacing(20)
        .padding(32)
        .max_width(500)
        .align_x(Alignment::Center),
    )
    .style(move |_| section_header_container(theme))
    .into()
}

#[allow(clippy::too_many_lines)]
fn view_shortcuts_help(theme: &crate::theme::AppTheme) -> Element<'_, Message> {
    container(
        column![
            text("⌨️ Keyboard Shortcuts")
                .size(24)
                .font(FONT_REGULAR)
                .color(theme.warning),
            column![
                text("General").size(16).color(theme.fg_primary),
                row![
                    container(text("F1").size(13).font(FONT_MONO).color(theme.warning))
                        .width(150)
                        .padding([4, 8])
                        .style(move |_| container::Style {
                            background: Some(theme.bg_elevated.into()),
                            border: Border {
                                radius: 4.0.into(),
                                ..Default::default()
                            },
                            ..Default::default()
                        }),
                    text("Show this help").size(13).color(theme.fg_primary)
                ]
                .spacing(16),
                row![
                    container(text("Esc").size(13).font(FONT_MONO).color(theme.warning))
                        .width(150)
                        .padding([4, 8])
                        .style(move |_| container::Style {
                            background: Some(theme.bg_elevated.into()),
                            border: Border {
                                radius: 4.0.into(),
                                ..Default::default()
                            },
                            ..Default::default()
                        }),
                    text("Close any modal or form").size(13).color(theme.fg_primary)
                ]
                .spacing(16),
            ]
            .spacing(12),
            column![
                text("Rules").size(16).color(theme.fg_primary),
                row![
                    container(
                        text("Ctrl + N")
                            .size(13)
                            .font(FONT_MONO)
                            .color(theme.warning)
                    )
                    .width(150)
                    .padding([4, 8])
                    .style(move |_| container::Style {
                        background: Some(theme.bg_elevated.into()),
                        border: Border {
                            radius: 4.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                    text("Add new rule").size(13).color(theme.fg_primary)
                ]
                .spacing(16),
                row![
                    container(
                        text("Ctrl + S")
                            .size(13)
                            .font(FONT_MONO)
                            .color(theme.warning)
                    )
                    .width(150)
                    .padding([4, 8])
                    .style(move |_| container::Style {
                        background: Some(theme.bg_elevated.into()),
                        border: Border {
                            radius: 4.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                    text("Apply changes").size(13).color(theme.fg_primary)
                ]
                .spacing(16),
                row![
                    container(
                        text("Ctrl + Z")
                            .size(13)
                            .font(FONT_MONO)
                            .color(theme.warning)
                    )
                    .width(150)
                    .padding([4, 8])
                    .style(move |_| container::Style {
                        background: Some(theme.bg_elevated.into()),
                        border: Border {
                            radius: 4.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                    text("Undo last modification").size(13).color(theme.fg_primary)
                ]
                .spacing(16),
                row![
                    container(
                        text("Ctrl + Shift + Z")
                            .size(13)
                            .font(FONT_MONO)
                            .color(theme.warning)
                    )
                    .width(150)
                    .padding([4, 8])
                    .style(move |_| container::Style {
                        background: Some(theme.bg_elevated.into()),
                        border: Border {
                            radius: 4.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                    text("Redo last undone modification")
                        .size(13)
                        .color(theme.fg_primary)
                ]
                .spacing(16),
            ]
            .spacing(12),
            column![
                text("Workspace").size(16).color(theme.fg_primary),
                row![
                    container(
                        text("Ctrl + E")
                            .size(13)
                            .font(FONT_MONO)
                            .color(theme.warning)
                    )
                    .width(150)
                    .padding([4, 8])
                    .style(move |_| container::Style {
                        background: Some(theme.bg_elevated.into()),
                        border: Border {
                            radius: 4.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                    text("Export rules").size(13).color(theme.fg_primary)
                ]
                .spacing(16),
            ]
            .spacing(12),
            button(text("Close").size(14))
                .on_press(Message::ToggleShortcutsHelp(false))
                .padding([10, 20])
                .style(move |_, status| card_button(theme, status)),
        ]
        .spacing(24)
        .padding(32)
        .max_width(600),
    )
    .style(move |_| section_header_container(theme))
    .into()
}