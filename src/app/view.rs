use crate::app::ui_components::{
    active_card_button, active_card_container, active_tab_button, card_button, card_container,
    danger_button, dirty_button, elevated_card_container, main_container, modal_backdrop,
    primary_button, secondary_button, section_header_container, sidebar_container,
    themed_checkbox, themed_horizontal_rule, themed_pick_list, themed_pick_list_menu,
    themed_scrollable, themed_slider, themed_text_input, themed_toggler,
};
use crate::app::{
    AppStatus, FontPickerTarget, Message, PendingWarning, RuleForm, State, WorkspaceTab,
};
use crate::core::firewall::{PRESETS, Protocol};
use iced::widget::text::Wrapping;
use iced::widget::{
    button, checkbox, column, container, mouse_area, pick_list, row, rule, scrollable, stack, text,
    text_input, toggler,
};
use iced::{Alignment, Border, Color, Element, Length};

pub fn view(state: &State) -> Element<'_, Message> {
    let theme = &state.theme;
    let sidebar = view_sidebar(state);

    let preview_content: Element<'_, Message> = match state.active_tab {
        WorkspaceTab::Nftables => {
            // Phase 1 Optimized: Use pre-cached diff tokens (no computation in view!)
            if state.show_diff {
                if let Some(ref diff_tokens) = state.cached_diff_tokens {
                    container(view_from_cached_diff_tokens(
                        diff_tokens,
                        theme,
                        state.font_mono,
                    ))
                    .width(Length::Fill)
                    .into()
                } else {
                    // No changes - show normal view
                    container(view_from_cached_nft_tokens(
                        &state.cached_nft_tokens,
                        theme,
                        state.font_mono,
                    ))
                    .width(Length::Fill)
                    .into()
                }
            } else {
                // Diff disabled - use pre-tokenized cache (60-80% CPU savings)
                container(view_from_cached_nft_tokens(
                    &state.cached_nft_tokens,
                    theme,
                    state.font_mono,
                ))
                .width(Length::Fill)
                .into()
            }
        }
        WorkspaceTab::Json => {
            // Phase 1: Use pre-tokenized cache (60-80% CPU savings)
            container(view_from_cached_json_tokens(
                &state.cached_json_tokens,
                theme,
                state.font_mono,
            ))
            .width(Length::Fill)
            .into()
        }
        WorkspaceTab::Settings => container(view_settings(state)).width(Length::Fill).into(),
    };

    let workspace = view_workspace(state, preview_content);

    let content = row![sidebar, workspace];

    let overlay = if let Some(warning) = &state.pending_warning {
        Some(
            container(view_warning_modal(
                warning,
                theme,
                state.font_regular,
                state.font_mono,
            ))
            .style(move |_| modal_backdrop(theme))
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
                state.font_regular,
                state.font_mono,
            ))
            .style(move |_| modal_backdrop(theme))
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill),
        )
    } else {
        match &state.status {
            AppStatus::AwaitingApply => Some(
                container(view_awaiting_apply(theme, state.font_regular))
                    .style(move |_| modal_backdrop(theme))
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill),
            ),
            AppStatus::PendingConfirmation { .. } => Some(
                container(view_pending_confirmation(
                    state.countdown_remaining,
                    theme,
                    state.font_regular,
                ))
                .style(move |_| modal_backdrop(theme))
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
            container(view_diagnostics_modal(
                theme,
                state.font_regular,
                state.font_mono
            ))
            .style(move |_| modal_backdrop(theme))
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Alignment::Center)
            .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_overlay
    };

    // Export modal overlay
    let with_export = if state.show_export_modal {
        stack![
            with_diagnostics,
            container(view_export_modal(theme, state.font_regular))
                .style(move |_| modal_backdrop(theme))
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_diagnostics
    };

    // Font picker modal overlay
    let with_font_picker = if let Some(ref picker_state) = state.font_picker {
        stack![
            with_export,
            container(view_font_picker(state, picker_state))
                .style(move |_| modal_backdrop(theme))
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_export
    };

    // Keyboard shortcuts help overlay
    if state.show_shortcuts_help {
        stack![
            with_font_picker,
            container(view_shortcuts_help(
                theme,
                state.font_regular,
                state.font_mono
            ))
            .style(move |_| modal_backdrop(theme))
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Alignment::Center)
            .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_font_picker
    }
}

fn view_sidebar(state: &State) -> Element<'_, Message> {
    let theme = &state.theme;

    // 1. Branding Header
    let branding = container(column![
        row![
            container(text("🛡️").size(28).color(theme.accent)).padding(4),
            column![
                text("DRFW")
                    .size(24)
                    .font(state.font_regular)
                    .color(theme.accent),
                text("DUMB RUST FIREWALL")
                    .size(9)
                    .color(theme.fg_muted)
                    .font(state.font_mono),
            ]
            .spacing(0)
        ]
        .spacing(12)
        .align_y(Alignment::Center)
    ])
    .padding(iced::Padding::new(0.0).bottom(10.0));

    // 2. Filter Logic & Tag Collection (Phase 3: Use cached tags, Phase 1: Use cached filtered indices)
    let all_tags = &state.cached_all_tags;

    // Phase 1 Optimization: Use pre-filtered rule indices (updated in update(), not every frame!)
    let filtered_rules: Vec<_> = state
        .cached_filtered_rule_indices
        .iter()
        .map(|&idx| &state.ruleset.rules[idx])
        .collect();

    // 3. Search and Filters Section
    let tag_cloud: Element<'_, Message> = if all_tags.is_empty() {
        column![].into()
    } else {
        let mut tag_elements: Vec<Element<'_, Message>> = vec![
            button(text("All").size(10))
                .on_press(Message::FilterByTag(None))
                .padding([4, 8])
                .style(move |_, status| {
                    if state.filter_tag.is_none() {
                        active_tab_button(theme, status)
                    } else {
                        secondary_button(theme, status)
                    }
                })
                .into(),
        ];

        for tag in all_tags {
            let is_selected = state.filter_tag.as_ref() == Some(tag);
            tag_elements.push(
                button(text(tag).size(10))
                    .on_press(Message::FilterByTag(Some(tag.clone())))
                    .padding([4, 8])
                    .style(move |_, status| {
                        if is_selected {
                            active_tab_button(theme, status)
                        } else {
                            secondary_button(theme, status)
                        }
                    })
                    .into(),
            );
        }

        let tags_row = row(tag_elements).spacing(6).wrap();

        column![
            text("FILTERS")
                .size(9)
                .font(state.font_mono)
                .color(theme.fg_muted),
            container(tags_row).width(Length::Fill).max_height(120)
        ]
        .spacing(8)
        .into()
    };

    let search_area = column![
        text_input("Search rules...", &state.rule_search)
            .on_input(Message::RuleSearchChanged)
            .padding(10)
            .size(13)
            .style(move |_, status| themed_text_input(theme, status)),
        tag_cloud,
    ]
    .spacing(16);

    // 4. Rule List Header
    let list_header = row![
        text("RULES")
            .size(9)
            .font(state.font_mono)
            .color(theme.fg_muted),
        container(row![]).width(Length::Fill),
        text(format!(
            "{}/{}",
            filtered_rules.len(),
            state.ruleset.rules.len()
        ))
        .size(9)
        .font(state.font_mono)
        .color(theme.fg_muted),
    ]
    .align_y(Alignment::Center)
    .padding([0, 4]);

    // 5. Rule List (Scrollable)
    let rule_list: Element<'_, Message> = if filtered_rules.is_empty() {
        container(
            column![
                text("No matching rules.")
                    .size(13)
                    .color(theme.fg_muted)
                    .font(state.font_regular),
            ]
            .padding(40)
            .align_x(Alignment::Center),
        )
        .width(Length::Fill)
        .center_x(Length::Fill)
        .into()
    } else {
        // Phase 5: Pre-allocate Vec for better performance
        let mut rule_cards = Vec::with_capacity(filtered_rules.len());

        for rule in filtered_rules {
            // ... (Rule card logic remains the same)
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
                        .style(move |_, status| secondary_button(theme, status)),
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

                // Combined Protocol/Port pill
                let proto_text = match rule.protocol {
                    Protocol::Tcp => "TCP",
                    Protocol::Udp => "UDP",
                    Protocol::Any => "ANY",
                    Protocol::Icmp => "ICMP",
                    Protocol::Icmpv6 => "ICMPv6",
                };

                let port_text = rule.ports.as_ref().map_or_else(
                    || "All".to_string(),
                    |p| {
                        if p.start == p.end {
                            p.start.to_string()
                        } else {
                            format!("{}-{}", p.start, p.end)
                        }
                    },
                );

                let badge = container(
                    text(format!("{proto_text}: {port_text}"))
                        .size(9)
                        .font(state.font_mono)
                        .color(if rule.enabled {
                            theme.syntax_type
                        } else {
                            theme.fg_muted
                        }),
                )
                .padding([2, 6])
                .style(move |_| container::Style {
                    background: Some(theme.bg_base.into()),
                    border: Border {
                        radius: 4.0.into(),
                        color: theme.border,
                        width: 1.0,
                    },
                    ..Default::default()
                });

                // Main Content: Label + Tags
                let mut tag_items: Vec<Element<'_, Message>> = vec![];
                for tag in &rule.tags {
                    let tag_theme = theme.clone();
                    let is_enabled = rule.enabled;
                    tag_items.push(
                        container(
                            text(tag)
                                .size(8)
                                .color(if is_enabled {
                                    theme.fg_on_accent
                                } else {
                                    Color {
                                        a: 0.5,
                                        ..theme.fg_muted
                                    }
                                })
                                .wrapping(Wrapping::None),
                        )
                        .padding([1, 4])
                        .style(move |_: &_| container::Style {
                            background: Some(if is_enabled {
                                tag_theme.accent.into()
                            } else {
                                Color {
                                    a: 0.3,
                                    ..tag_theme.accent
                                }
                                .into()
                            }),
                            border: Border {
                                radius: 3.0.into(),
                                ..Default::default()
                            },
                            ..Default::default()
                        })
                        .clip(true)
                        .into(),
                    );
                }

                let main_info = column![
                    // Top row: Label (with clipping and fixed height)
                    container(
                        text(if rule.label.is_empty() {
                            "Unnamed Rule"
                        } else {
                            &rule.label
                        })
                        .size(13)
                        .font(state.font_regular)
                        .color(if rule.enabled {
                            theme.fg_primary
                        } else {
                            theme.fg_muted
                        })
                        .wrapping(Wrapping::None)
                    )
                    .width(Length::Fill)
                    .height(Length::Fixed(18.0))
                    .padding(iced::Padding::new(0.0).right(4.0))
                    .clip(true),
                    // Bottom row: Tags (clipped, fixed height) + Badge (priority)
                    row![
                        container(row(tag_items).spacing(4).align_y(Alignment::Center))
                            .width(Length::Fill)
                            .height(Length::Fixed(18.0))
                            .align_y(Alignment::Center)
                            .clip(true),
                        badge,
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center)
                ]
                .spacing(2)
                .width(Length::Fill);

                row![
                    // Drag Handle
                    button(
                        container(text("::").size(12).color(handle_color))
                            .center_x(Length::Fixed(20.0))
                    )
                    .on_press(handle_action)
                    .padding([0, 2])
                    .style(button::text),
                    // Status Strip
                    container(column![])
                        .width(Length::Fixed(3.0))
                        .height(Length::Fixed(24.0))
                        .style(move |_: &_| container::Style {
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
                    // Checkbox
                    checkbox(rule.enabled)
                        .on_toggle(move |_| Message::ToggleRuleEnabled(rule.id))
                        .size(16)
                        .spacing(0)
                        .style(move |_, status| themed_checkbox(theme, status)),
                    // Info Click Area
                    button(main_info)
                        .on_press(Message::EditRuleClicked(rule.id))
                        .padding(0)
                        .style(button::text)
                        .width(Length::Fill),
                    // Delete
                    button(text("×").size(14).color(theme.fg_muted))
                        .on_press(Message::DeleteRuleRequested(rule.id))
                        .padding(4)
                        .style(button::text),
                ]
                .spacing(8)
                .padding([6, 8])
                .align_y(Alignment::Center)
                .into()
            };

            let card = container(card_content).style(move |_| {
                let mut style = if is_editing {
                    active_card_container(theme)
                } else if is_being_dragged {
                    container::Style {
                        background: Some(theme.bg_active.into()),
                        border: Border {
                            color: theme.accent,
                            width: 2.0,
                            radius: 8.0.into(),
                        },
                        shadow: iced::Shadow {
                            color: theme.shadow_color,
                            offset: iced::Vector::new(0.0, 4.0),
                            blur_radius: 8.0,
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
                        shadow: iced::Shadow {
                            color: theme.shadow_color,
                            offset: iced::Vector::new(0.0, 3.0),
                            blur_radius: 6.0,
                        },
                        ..Default::default()
                    }
                } else {
                    card_container(theme)
                };

                // Dim the card if the rule is disabled
                if !rule.enabled && !is_editing && !is_being_dragged && !is_hover_target {
                    style.background = style.background.map(|b| match b {
                        iced::Background::Color(c) => {
                            iced::Background::Color(Color { a: 0.6, ..c })
                        }
                        iced::Background::Gradient(_) => b,
                    });
                }
                style
            });

            let card_element: Element<'_, Message> = if any_drag_active && !is_being_dragged {
                mouse_area(card)
                    .on_enter(Message::RuleHoverStart(rule.id))
                    .on_exit(Message::RuleHoverEnd)
                    .on_press(Message::RuleDropped(rule.id))
                    .into()
            } else {
                card.into()
            };

            rule_cards.push(card_element);
        }

        // Build column from pre-allocated Vec
        column(rule_cards).spacing(8).into()
    };

    // 6. Sidebar Footer (Pinned Action)
    // 6. Sidebar Footer (Pinned Action)
    let footer = column![
        container(row![])
            .height(Length::Fixed(1.0))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(theme.border.into()),
                ..Default::default()
            }),
        container(
            button(
                row![text("+").size(18), text("Add Access Rule").size(14)]
                    .spacing(10)
                    .align_y(Alignment::Center),
            )
            .width(Length::Fill)
            .padding(14)
            .style(move |_, status| primary_button(theme, status))
            .on_press(Message::AddRuleClicked)
        )
        .padding(iced::Padding::new(0.0).top(16.0))
    ];

    container(
        column![
            branding,
            search_area,
            column![
                list_header,
                scrollable(container(rule_list).padding([0, 2]))
                    .height(Length::Fill)
                    .style(move |_, status| themed_scrollable(theme, status)),
            ]
            .spacing(12)
            .height(Length::Fill),
            footer,
        ]
        .spacing(16)
        .padding(24),
    )
    .width(Length::Fixed(320.0))
    .height(Length::Fill)
    .style(move |_| sidebar_container(theme))
    .into()
}

fn view_workspace<'a>(
    state: &'a State,
    preview_content: Element<'a, Message>,
) -> Element<'a, Message> {
    let theme = &state.theme;

    // Header: Tab Strip (Left) and Global Tools (Right)
    let nav_row = row![
        // Unified Tab Strip
        container(
            row![
                view_tab_button(
                    "nftables.conf",
                    WorkspaceTab::Nftables,
                    state.active_tab,
                    theme
                ),
                view_tab_button("JSON Payload", WorkspaceTab::Json, state.active_tab, theme),
                view_tab_button("Settings", WorkspaceTab::Settings, state.active_tab, theme),
            ]
            .spacing(2)
        )
        .padding(2)
        .style(move |_| container::Style {
            background: Some(theme.bg_elevated.into()),
            border: Border {
                radius: 6.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }),
        container(row![]).width(Length::Fill),
        // Global Utility Tools
        row![
            button(row![text("📤").size(14), text("Export").size(13)].spacing(8))
                .on_press(Message::ToggleExportModal(true))
                .padding([8, 16])
                .style(move |_, status| secondary_button(theme, status)),
            button(row![text("📊").size(14), text("Diagnostics").size(13)].spacing(8))
                .on_press(Message::ToggleDiagnostics(true))
                .padding([8, 16])
                .style(move |_, status| secondary_button(theme, status)),
        ]
        .spacing(8)
    ]
    .align_y(Alignment::Center);

    // Title and description row with optional diff checkbox
    let mut title_row = row![
        column![
            text(match state.active_tab {
                WorkspaceTab::Nftables => "Active Configuration",
                WorkspaceTab::Json => "JSON Export",
                WorkspaceTab::Settings => "Settings",
            })
            .size(20)
            .font(state.font_regular)
            .color(theme.fg_primary),
            text(match state.active_tab {
                WorkspaceTab::Nftables => "Current nftables ruleset generated from your rules.",
                WorkspaceTab::Json => "Low-level JSON representation for debugging or automation.",
                WorkspaceTab::Settings =>
                    "Configure application appearance and advanced firewall security hardening.",
            })
            .size(12)
            .color(theme.fg_muted),
        ]
        .spacing(2)
        .width(Length::Fill),
    ];

    // Add diff toggle when on Nftables tab and we have a previous version
    if state.active_tab == WorkspaceTab::Nftables && state.last_applied_ruleset.is_some() {
        title_row = title_row.push(
            checkbox(state.show_diff)
                .label("Show diff")
                .on_toggle(Message::ToggleDiff)
                .size(16)
                .text_size(12)
                .spacing(6)
                .style(move |_, status| themed_checkbox(theme, status)),
        );
    }

    let preview_header = column![nav_row, title_row].spacing(20);

    let editor = container(
        scrollable(
            container(preview_content)
                .padding(24)
                .width(Length::Fill)
                .height(Length::Shrink),
        )
        .width(Length::Fill)
        .style(move |_, status| themed_scrollable(theme, status)),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(move |_| elevated_card_container(theme));

    // Zone: History (Left)
    let history_actions = container(
        row![
            button(text("↶").size(18))
                .on_press_maybe(state.command_history.can_undo().then_some(Message::Undo))
                .padding([10, 16])
                .style(move |_, status| secondary_button(theme, status)),
            button(text("↷").size(18))
                .on_press_maybe(state.command_history.can_redo().then_some(Message::Redo))
                .padding([10, 16])
                .style(move |_, status| secondary_button(theme, status)),
        ]
        .spacing(2),
    )
    .style(move |_| container::Style {
        background: Some(theme.bg_elevated.into()),
        border: Border {
            radius: 6.0.into(),
            ..Default::default()
        },
        ..Default::default()
    });

    // Zone: Status (Center)
    let status_area = container(if let Some(ref err) = state.last_error {
        view_error_display(err, theme, state.font_regular, state.font_mono)
    } else {
        row![].into()
    })
    .width(Length::Fill)
    .center_x(Length::Fill);

    // Zone: Commitment (Right)
    let save_to_system = if state.status == AppStatus::Confirmed {
        button(
            text("Permanently Save to System")
                .size(13)
                .font(state.font_regular),
        )
        .style(move |_, status| primary_button(theme, status))
        .padding([10, 20])
        .on_press(Message::SaveToSystemClicked)
    } else {
        button(text("Save to System").size(13).font(state.font_regular))
            .padding([10, 20])
            .style(move |_, status| secondary_button(theme, status))
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
        let mut btn = button(text(button_text).size(14).font(state.font_regular)).padding([10, 24]);

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

    let footer = row![
        history_actions,
        status_area,
        row![save_to_system, apply_button].spacing(12)
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
                secondary_button(theme, status)
            }
        })
        .on_press(Message::TabChanged(tab))
        .into()
}

/// Phase 1 Optimized: Build diff view from pre-tokenized cache (no parsing in view!)
fn view_from_cached_diff_tokens<'a>(
    diff_tokens: &'a [(
        crate::app::syntax_cache::DiffType,
        crate::app::syntax_cache::HighlightedLine,
    )],
    theme: &crate::theme::AppTheme,
    mono_font: iced::Font,
) -> iced::widget::Column<'a, Message> {
    const SPACES: &str = "                                ";
    let mut lines = column![].spacing(1);

    for (diff_type, highlighted_line) in diff_tokens {
        let mut row_content = row![].spacing(0);

        // Line number (same format as normal view - no extra diff indicator to prevent jumping)
        row_content = row_content.push(
            container(
                text(format!("{:4}", highlighted_line.line_number))
                    .font(mono_font)
                    .size(14)
                    .color(crate::app::syntax_cache::TokenColor::LineNumberNft.to_color(theme)),
            )
            .width(Length::Fixed(50.0))
            .padding(iced::Padding::new(0.0).right(8.0)),
        );

        // Indentation
        if highlighted_line.indent > 0 {
            let spaces = &SPACES[..highlighted_line.indent];
            row_content = row_content.push(text(spaces).font(mono_font).size(14));
        }

        // Tokens (already parsed - just build widgets!)
        for token in &highlighted_line.tokens {
            let color = token.color.to_color(theme);
            row_content = row_content.push(text(&token.text).font(mono_font).size(14).color(color));
        }

        // Add subtle background for added/removed lines
        let bg_color = match diff_type {
            crate::app::syntax_cache::DiffType::Added => Some(Color {
                a: 0.1,
                ..theme.success
            }),
            crate::app::syntax_cache::DiffType::Removed => Some(Color {
                a: 0.1,
                ..theme.danger
            }),
            crate::app::syntax_cache::DiffType::Unchanged => None,
        };

        lines = lines.push(container(row_content).width(Length::Fill).style(move |_| {
            container::Style {
                background: bg_color.map(Into::into),
                ..Default::default()
            }
        }));
    }

    lines
}

fn view_rule_form<'a>(
    form: &'a RuleForm,
    errors: Option<&'a crate::app::FormErrors>,
    interfaces: &'a [String],
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
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
        // Title Section
        column![
            text(title_text)
                .size(22)
                .font(regular_font)
                .color(theme.info),
            text("Define allowed traffic patterns.")
                .size(12)
                .color(theme.fg_muted)
        ]
        .spacing(4),
        // Basic Info Section
        column![
            container(text("BASIC INFO").size(10).color(theme.fg_primary))
                .padding([4, 8])
                .style(move |_| section_header_container(theme)),
            column![
                text("DESCRIPTION").size(10).color(theme.fg_muted),
                text_input("e.g. Local Web Server", &form.label)
                    .on_input(Message::RuleFormLabelChanged)
                    .padding(8)
                    .style(move |_, status| themed_text_input(theme, status))
            ]
            .spacing(4),
            column![
                text("SERVICE PRESET").size(10).color(theme.fg_muted),
                pick_list(
                    PRESETS,
                    form.selected_preset.clone(),
                    Message::RuleFormPresetSelected
                )
                .placeholder("Select a common service...")
                .width(Length::Fill)
                .padding(8)
                .style(move |_, status| themed_pick_list(theme, status))
                .menu_style(move |_| themed_pick_list_menu(theme))
            ]
            .spacing(4),
        ]
        .spacing(8),
        // Technical Details Section
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
                    .padding(8)
                    .style(move |_, status| themed_pick_list(theme, status))
                    .menu_style(move |_| themed_pick_list_menu(theme))
                ]
                .spacing(4)
                .width(Length::Fill),
                {
                    let mut port_col = column![
                        text("PORT RANGE").size(10).color(theme.fg_muted),
                        view_port_inputs(form, port_error, theme, mono_font),
                    ]
                    .spacing(4)
                    .width(Length::Fill);

                    if let Some(err) = port_error {
                        port_col = port_col.push(text(err).size(11).color(theme.danger));
                    }
                    port_col
                },
            ]
            .spacing(16),
        ]
        .spacing(8),
        // Context Section
        column![
            container(text("CONTEXT").size(10).color(theme.fg_primary))
                .padding([4, 8])
                .style(move |_| section_header_container(theme)),
            {
                let mut source_col = column![
                    text("SOURCE ADDRESS (OPTIONAL)")
                        .size(10)
                        .color(theme.fg_muted),
                    text_input("e.g. 192.168.1.0/24 or specific IP", &form.source)
                        .on_input(Message::RuleFormSourceChanged)
                        .padding(8)
                        .style(move |_, status| themed_text_input(theme, status)),
                ]
                .spacing(4);

                if let Some(err) = source_error {
                    source_col = source_col.push(text(err).size(11).color(theme.danger));
                }
                source_col
            },
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
                .padding(8)
                .style(move |_, status| themed_pick_list(theme, status))
                .menu_style(move |_| themed_pick_list_menu(theme))
            ]
            .spacing(4),
        ]
        .spacing(8),
        // Organization Section
        column![
            container(text("ORGANIZATION").size(10).color(theme.fg_primary))
                .padding([4, 8])
                .style(move |_| section_header_container(theme)),
            {
                let mut org_col = column![
                    text("TAGS").size(10).color(theme.fg_muted),
                    row![
                        text_input("Add a tag...", &form.tag_input)
                            .on_input(Message::RuleFormTagInputChanged)
                            .on_submit(Message::RuleFormAddTag)
                            .padding(8)
                            .style(move |_, status| themed_text_input(theme, status)),
                        button(text("+").size(16))
                            .on_press(Message::RuleFormAddTag)
                            .padding([8, 16])
                            .style(move |_, status| primary_button(theme, status)),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                ]
                .spacing(10);

                if !form.tags.is_empty() {
                    org_col = org_col.push(Element::from(
                        row(form.tags.iter().map(|tag| -> Element<'_, Message> {
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
                        .wrap(),
                    ));
                }
                org_col
            },
        ]
        .spacing(8),
        // Footer Actions
        row![
            button(text("Cancel").size(14))
                .on_press(Message::CancelRuleForm)
                .padding([10, 24])
                .style(move |_, status| secondary_button(theme, status)),
            container(row![]).width(Length::Fill),
            button(text(button_text).size(14))
                .on_press(Message::SaveRuleForm)
                .padding([10, 32])
                .style(move |_, status| primary_button(theme, status)),
        ]
        .spacing(16)
        .align_y(Alignment::Center)
    ]
    .spacing(12)
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
    mono_font: iced::Font,
) -> Element<'a, Message> {
    if matches!(form.protocol, Protocol::Tcp | Protocol::Udp) {
        row![
            text_input("80", &form.port_start)
                .on_input(Message::RuleFormPortStartChanged)
                .padding(8)
                .width(Length::Fill)
                .style(move |_, status| themed_text_input(theme, status)),
            text("-").size(16).color(theme.fg_muted),
            text_input("80", &form.port_end)
                .on_input(Message::RuleFormPortEndChanged)
                .padding(8)
                .width(Length::Fill)
                .style(move |_, status| themed_text_input(theme, status)),
        ]
        .spacing(6)
        .align_y(Alignment::Center)
        .into()
    } else {
        container(
            text("Not applicable")
                .size(12)
                .color(theme.fg_muted)
                .font(mono_font),
        )
        .padding(8)
        .width(Length::Fill)
        .height(36)
        .align_y(iced::alignment::Vertical::Center)
        .into()
    }
}

fn view_awaiting_apply(
    app_theme: &crate::theme::AppTheme,
    regular_font: iced::Font,
) -> Element<'_, Message> {
    container(column![text("🛡️").size(36), text("Commit Changes?").size(24).font(regular_font).color(app_theme.fg_primary),
                      text("Rules verified. Applying will take effect immediately with a 15s safety rollback window.").size(14).color(app_theme.fg_muted).width(360).align_x(Alignment::Center),
                      row![button(text("Discard").size(14)).on_press(Message::CancelRuleForm).padding([10, 20]).style(move |_, status| secondary_button(app_theme, status)),
                           button(text("Apply & Start Timer").size(14)).on_press(Message::ProceedToApply).padding([10, 24]).style(move |_, status| primary_button(app_theme, status)),
                      ].spacing(16)
    ].spacing(20).padding(32).align_x(Alignment::Center))
    .style(move |_| { let mut style = card_container(app_theme); style.shadow = iced::Shadow { color: app_theme.shadow_strong, offset: iced::Vector::new(0.0, 10.0), blur_radius: 20.0 }; style }).into()
}

fn view_pending_confirmation(
    remaining: u32,
    app_theme: &crate::theme::AppTheme,
    regular_font: iced::Font,
) -> Element<'_, Message> {
    container(
        column![
            text("⏳").size(36),
            text("Confirm Safety")
                .size(24)
                .font(regular_font)
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
            color: app_theme.shadow_strong,
            offset: iced::Vector::new(0.0, 10.0),
            blur_radius: 20.0,
        };
        style
    })
    .into()
}

fn view_settings(state: &State) -> Element<'_, Message> {
    use iced::widget::slider;

    let theme = &state.theme;
    let advanced = &state.ruleset.advanced_security;

    let appearance_card = container(column![
        container(
            row![
                text("🎨").size(18),
                text("APPEARANCE").size(12).font(state.font_regular)
            ]
            .spacing(8)
            .align_y(Alignment::Center)
        )
        .padding([8, 12])
        .width(Length::Fill)
        .style(move |_| section_header_container(theme)),
        column![
            render_settings_row(
                "Theme",
                "Choose your preferred color scheme",
                pick_list(
                    crate::theme::ThemeChoice::all(),
                    Some(state.current_theme),
                    Message::ThemeChanged,
                )
                .width(Length::Fill)
                .text_size(14)
                .style(move |_, status| themed_pick_list(theme, status))
                .menu_style(move |_| themed_pick_list_menu(theme))
                .into(),
                theme,
                state.font_regular,
            ),
            render_settings_row(
                "UI Font",
                "Font used for buttons, labels, and text",
                button(
                    row![
                        container(
                            text(state.regular_font_choice.name())
                                .size(13)
                                .wrapping(Wrapping::None)
                        )
                        .width(Length::Fill)
                        .clip(true),
                        text(" ▾").size(10).color(theme.fg_muted)
                    ]
                    .align_y(Alignment::Center)
                )
                .on_press(Message::OpenFontPicker(FontPickerTarget::Regular))
                .width(Length::Fill)
                .padding(8)
                .style(move |_, status| secondary_button(theme, status))
                .into(),
                theme,
                state.font_regular,
            ),
            render_settings_row(
                "Code Font",
                "Monospace font for configuration preview",
                button(
                    row![
                        container(
                            text(state.mono_font_choice.name())
                                .size(13)
                                .wrapping(Wrapping::None)
                        )
                        .width(Length::Fill)
                        .clip(true),
                        text(" ▾").size(10).color(theme.fg_muted)
                    ]
                    .align_y(Alignment::Center)
                )
                .on_press(Message::OpenFontPicker(FontPickerTarget::Mono))
                .width(Length::Fill)
                .padding(8)
                .style(move |_, status| secondary_button(theme, status))
                .into(),
                theme,
                state.font_regular,
            ),
        ]
        .spacing(16)
        .padding(16)
    ])
    .style(move |_| card_container(theme));

    let security_card = container(
        column![
            container(
                row![text("🛡️").size(18), text("ADVANCED SECURITY").size(12).font(state.font_regular)]
                    .spacing(8)
                    .align_y(Alignment::Center)
            )
            .padding([8, 12])
            .width(Length::Fill)
            .style(move |_| section_header_container(theme)),

            column![
                text("⚠️ These settings may break common applications. Defaults are suitable for most users.")
                    .size(13)
                    .color(theme.syntax_string),

                render_settings_row(
                    "Strict ICMP filtering",
                    "Only allow essential ICMP types (ping, MTU discovery)",
                    toggler(advanced.strict_icmp)
                        .on_toggle(Message::ToggleStrictIcmp)
                        .width(Length::Shrink)
                        .style(move |_, status| themed_toggler(theme, status))
                        .into(),
                    theme,
                    state.font_regular,
                ),

                render_settings_row(
                    "ICMP rate limiting",
                    "Limit incoming ICMP packets to prevent floods",
                    row![
                        slider(0..=50, advanced.icmp_rate_limit, Message::IcmpRateLimitChanged)
                            .width(Length::Fill)
                            .style(move |_, status| themed_slider(theme, status)),
                        text(format!("{}/s", advanced.icmp_rate_limit))
                            .size(12).font(state.font_mono).width(40).align_x(Alignment::End),
                    ].spacing(12).align_y(Alignment::Center).into(),
                    theme,
                    state.font_regular,
                ),

                render_settings_row(
                    "Anti-spoofing (RPF)",
                    "Drop packets with spoofed source addresses",
                    toggler(advanced.enable_rpf)
                        .on_toggle(Message::ToggleRpfRequested)
                        .width(Length::Shrink)
                        .style(move |_, status| themed_toggler(theme, status))
                        .into(),
                    theme,
                    state.font_regular,
                ),

                render_settings_row(
                    "Log dropped packets",
                    "Record filtered traffic to system logs",
                    toggler(advanced.log_dropped)
                        .on_toggle(Message::ToggleDroppedLogging)
                        .width(Length::Shrink)
                        .style(move |_, status| themed_toggler(theme, status))
                        .into(),
                    theme,
                    state.font_regular,
                ),

                if advanced.log_dropped {
                    Element::from(column![
                        render_settings_row(
                            "   └ Log Rate",
                            "Maximum log entries per minute",
                            row![
                                slider(1..=100, advanced.log_rate_per_minute, Message::LogRateChanged)
                                    .width(Length::Fill)
                                    .style(move |_, status| themed_slider(theme, status)),
                                text(format!("{}/m", advanced.log_rate_per_minute))
                                    .size(12).font(state.font_mono).width(40).align_x(Alignment::End),
                            ].spacing(12).align_y(Alignment::Center).into(),
                            theme,
                            state.font_regular,
                        ),
                        render_settings_row(
                            "   └ Log Prefix",
                            "Tag used in system journal",
                            text_input("DRFW-DROP: ", &advanced.log_prefix)
                                .on_input(Message::LogPrefixChanged)
                                .padding(8)
                                .size(13)
                                .style(move |_, status| themed_text_input(theme, status))
                                .into(),
                            theme,
                            state.font_regular,
                        ),
                    ].spacing(8))
                } else {
                    column![].into()
                },

                container(
                    rule::horizontal(1).style(move |_| themed_horizontal_rule(theme))
                )
                .padding([8, 0]),

                column![
                    text("Egress Filtering Profile").size(15).font(state.font_regular).color(theme.fg_primary),
                    text("Desktop allows all outbound; Server mode denies by default").size(12).color(theme.fg_muted),
                    row![
                        button(text(if advanced.egress_profile == crate::core::firewall::EgressProfile::Desktop { "● Desktop" } else { "○ Desktop" }).size(13))
                            .on_press(Message::EgressProfileRequested(crate::core::firewall::EgressProfile::Desktop))
                            .width(Length::Fill)
                            .style(move |_, status| if advanced.egress_profile == crate::core::firewall::EgressProfile::Desktop { active_card_button(theme, status) } else { card_button(theme, status) }),
                        button(text(if advanced.egress_profile == crate::core::firewall::EgressProfile::Server { "● Server" } else { "○ Server" }).size(13))
                            .on_press(Message::EgressProfileRequested(crate::core::firewall::EgressProfile::Server))
                            .width(Length::Fill)
                            .style(move |_, status| if advanced.egress_profile == crate::core::firewall::EgressProfile::Server { active_card_button(theme, status) } else { card_button(theme, status) }),
                    ].spacing(12).width(Length::Fill)
                ].spacing(8)
            ].spacing(16).padding(16)
        ]
    )
        .style(move |_| card_container(theme));

    column![appearance_card, security_card,]
        .spacing(24)
        .padding(8)
        .into()
}
fn render_settings_row<'a>(
    title: &'static str,
    desc: &'static str,
    control: Element<'a, Message>,
    theme: &crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'a, Message> {
    row![
        column![
            text(title).size(15).font(font).color(theme.fg_primary),
            text(desc).size(12).color(theme.fg_muted),
        ]
        .width(Length::Fill)
        .spacing(2),
        container(control)
            .width(Length::Fixed(250.0))
            .align_x(Alignment::End)
    ]
    .spacing(20)
    .align_y(Alignment::Center)
    .into()
}

fn view_warning_modal<'a>(
    warning: &'a PendingWarning,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
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
            text(title).size(20).font(regular_font).color(theme.danger),
            text(message)
                .size(14)
                .color(theme.fg_primary)
                .font(mono_font),
            row![
                button(text("Cancel").size(14).font(regular_font))
                    .on_press(Message::CancelWarning)
                    .padding(12)
                    .style(move |_, status| card_button(theme, status)),
                button(text("Yes, I understand").size(14).font(regular_font))
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
            color: theme.shadow_strong,
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
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    let mut elements: Vec<Element<'_, Message>> = vec![
        row![
            text("⚠️").size(16),
            text(&err.message)
                .size(13)
                .color(theme.danger)
                .font(regular_font),
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
                    .font(mono_font),
            ]
            .spacing(6)
            .into(),
        );
    }

    column(elements).spacing(6).into()
}

fn view_diagnostics_modal(
    theme: &crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'_, Message> {
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
                    .font(regular_font)
                    .color(theme.warning),
                rule::horizontal(0).style(move |_| themed_horizontal_rule(theme)),
            ]
            .spacing(12)
            .align_y(Alignment::Center)
            .width(Length::Fill),
            // Audit log section
            column![
                text("Recent Audit Log Entries:")
                    .size(14)
                    .color(theme.fg_primary),
                container(
                    scrollable(column(if recent_entries.is_empty() {
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
                                    .font(mono_font)
                                    .color(theme.fg_primary)
                                    .into()
                            })
                            .collect()
                    })
                    .spacing(4))
                    .style(move |_, status| themed_scrollable(theme, status))
                )
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
                            .font(mono_font)
                            .color(theme.warning),
                        text("Restore from snapshot:")
                            .size(12)
                            .color(theme.fg_muted),
                        text(snapshot_restore_cmd)
                            .size(12)
                            .font(mono_font)
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
        .padding(32),
    )
    .max_width(700)
    .style(move |_| card_container(theme))
    .into()
}

fn view_export_modal(
    theme: &crate::theme::AppTheme,
    regular_font: iced::Font,
) -> Element<'_, Message> {
    container(
        column![
            text("📤 Export Rules")
                .size(24)
                .font(regular_font)
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
                                .font(regular_font)
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
                                .font(regular_font)
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
                .on_press(Message::ToggleExportModal(false)) // Toggle to close
                .padding([10, 20])
                .style(move |_, status| secondary_button(theme, status)),
        ]
        .spacing(20)
        .padding(32)
        .align_x(Alignment::Center),
    )
    .max_width(500)
    .style(move |_| card_container(theme))
    .into()
}

fn view_font_picker<'a>(
    state: &'a State,
    picker: &'a crate::app::FontPickerState,
) -> Element<'a, Message> {
    let theme = &state.theme;
    // Phase 1: Use cached lowercase search term (avoid allocation every frame)
    let search_term = &picker.search_lowercase;

    // Phase 1: Filter by target (mono vs regular) AND search term
    let is_mono_picker = matches!(picker.target, crate::app::FontPickerTarget::Mono);
    let filtered_fonts: Vec<_> = state
        .available_fonts
        .iter()
        .filter(|f| {
            // Filter monospace fonts for code font picker
            if is_mono_picker && !f.is_monospace() {
                return false;
            }
            // Search filter (use cached lowercase, only lowercase font name once per font)
            search_term.is_empty() || f.name().to_lowercase().contains(search_term)
        })
        .collect();

    // Limit visible items to improve rendering performance if there are many matches
    // 30 is enough for a searchable list and keeps layout fast (reduced from 100)
    let font_list = column(filtered_fonts.into_iter().take(30).map(|f| {
        // Performance: Don't clone until button press (use index instead)
        let name = f.name();
        let preview_font = f.to_font(); // Cheap: just returns handle from FontChoice

        let is_selected = match picker.target {
            FontPickerTarget::Regular => &state.regular_font_choice == f,
            FontPickerTarget::Mono => &state.mono_font_choice == f,
        };

        // Clone ONLY when button is pressed, not on every render
        let f_for_message = f.clone();

        button(
            row![
                column![
                    text(name).size(13).color(theme.fg_primary),
                    // Performance: Simple preview text, no complex rendering
                    text("AaBbCc 123")
                        .size(11)
                        .font(preview_font)
                        .color(theme.fg_secondary),
                ]
                .spacing(2)
                .width(Length::Fill),
                if is_selected {
                    text("✓").size(14).color(theme.success)
                } else {
                    text("").size(14)
                }
            ]
            .align_y(Alignment::Center)
            .padding([6, 10]),
        )
        .width(Length::Fill)
        .on_press(match picker.target {
            FontPickerTarget::Regular => Message::RegularFontChanged(f_for_message),
            FontPickerTarget::Mono => Message::MonoFontChanged(f_for_message),
        })
        .style(move |_, status| {
            let mut style = if is_selected {
                active_card_button(theme, status)
            } else {
                card_button(theme, status)
            };

            // Clean list item look: no background or border unless hovered or selected
            let is_hovered = matches!(status, iced::widget::button::Status::Hovered);
            if !is_hovered && !is_selected {
                style.background = None;
                style.border.width = 0.0;
                style.shadow.color = Color::TRANSPARENT;
            } else if is_hovered && !is_selected {
                style.background = Some(theme.bg_hover.into());
                style.border.width = 0.0;
                style.shadow.color = Color::TRANSPARENT;
            }
            style
        })
        .into()
    }))
    .spacing(2);

    container(
        column![
            row![
                text(match picker.target {
                    FontPickerTarget::Regular => "Select UI Font",
                    FontPickerTarget::Mono => "Select Code Font",
                })
                .size(18)
                .font(state.font_regular)
                .color(theme.fg_primary),
                rule::horizontal(0).style(move |_| themed_horizontal_rule(theme)),
                button(text("×").size(20).color(theme.fg_muted))
                    .on_press(Message::CloseFontPicker)
                    .style(button::text),
            ]
            .align_y(Alignment::Center)
            .spacing(12),
            text_input("Search fonts...", &picker.search)
                .on_input(Message::FontPickerSearchChanged)
                .padding(10)
                .size(13)
                .style(move |_, status| themed_text_input(theme, status)),
            container(
                scrollable(container(font_list).padding(2))
                    .style(move |_, status| themed_scrollable(theme, status))
            )
            .height(Length::Fixed(400.0))
            .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(theme.bg_elevated.into()),
                    border: Border {
                        radius: 8.0.into(),
                        color: theme.border,
                        width: 1.0,
                    },
                    ..Default::default()
                }),
            row![
                text(format!("{} fonts found", state.available_fonts.len()))
                    .size(10)
                    .color(theme.fg_muted)
                    .font(state.font_mono),
                rule::horizontal(0).style(move |_| themed_horizontal_rule(theme)),
                button(text("Close").size(13))
                    .on_press(Message::CloseFontPicker)
                    .padding([8, 20])
                    .style(move |_, status| secondary_button(theme, status)),
            ]
            .align_y(Alignment::Center)
            .spacing(16)
        ]
        .spacing(16)
        .padding(24)
        .width(Length::Fixed(500.0)),
    )
    .style(move |_| {
        let mut style = card_container(theme);
        style.shadow = iced::Shadow {
            color: theme.shadow_strong,
            offset: iced::Vector::new(0.0, 10.0),
            blur_radius: 30.0,
        };
        style
    })
    .into()
}

fn view_shortcuts_help(
    theme: &crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'_, Message> {
    container(
        column![
            text("⌨️ Keyboard Shortcuts")
                .size(24)
                .font(regular_font)
                .color(theme.warning),
            column![
                text("General").size(16).color(theme.fg_primary),
                row![
                    container(text("F1").size(13).font(mono_font).color(theme.warning))
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
                    container(text("Esc").size(13).font(mono_font).color(theme.warning))
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
                    text("Close any modal or form")
                        .size(13)
                        .color(theme.fg_primary)
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
                            .font(mono_font)
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
                            .font(mono_font)
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
                            .font(mono_font)
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
                    text("Undo last modification")
                        .size(13)
                        .color(theme.fg_primary)
                ]
                .spacing(16),
                row![
                    container(
                        text("Ctrl + Shift + Z")
                            .size(13)
                            .font(mono_font)
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
                            .font(mono_font)
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
        .padding(32),
    )
    .max_width(600)
    .style(move |_| card_container(theme))
    .into()
}

/// Phase 1 Optimization: Build widgets from pre-tokenized JSON (cached in State)
/// This avoids expensive character-by-character parsing every frame
fn view_from_cached_json_tokens<'a>(
    tokens: &'a [crate::app::syntax_cache::HighlightedLine],
    theme: &crate::theme::AppTheme,
    mono_font: iced::Font,
) -> iced::widget::Column<'a, Message> {
    const SPACES: &str = "                                ";

    let mut lines = column![].spacing(2);

    for highlighted_line in tokens {
        let mut row_content = row![].spacing(0);

        // Line number
        row_content = row_content.push(
            container(
                text(format!("{:3} ", highlighted_line.line_number))
                    .font(mono_font)
                    .size(14)
                    .color(crate::app::syntax_cache::TokenColor::LineNumber.to_color(theme)),
            )
            .width(iced::Length::Fixed(50.0))
            .padding(iced::Padding::new(0.0).right(8.0)),
        );

        // Indentation
        if highlighted_line.indent > 0 {
            let spaces = &SPACES[..highlighted_line.indent];
            row_content = row_content
                .push(text("  ").font(mono_font).size(14))
                .push(text(spaces).font(mono_font).size(14));
        } else if !highlighted_line.tokens.is_empty() {
            row_content = row_content.push(text("  ").font(mono_font).size(14));
        }

        // Tokens (already parsed!)
        for token in &highlighted_line.tokens {
            row_content = row_content.push(
                text(&token.text)
                    .font(mono_font)
                    .size(14)
                    .color(token.color.to_color(theme)),
            );
        }

        lines = lines.push(row_content);
    }

    lines
}

/// Phase 1 Optimization: Build widgets from pre-tokenized NFT (cached in State)
fn view_from_cached_nft_tokens<'a>(
    tokens: &'a [crate::app::syntax_cache::HighlightedLine],
    theme: &crate::theme::AppTheme,
    mono_font: iced::Font,
) -> iced::widget::Column<'a, Message> {
    const SPACES: &str = "                                ";

    let mut lines = column![].spacing(1); // NFT uses tighter spacing than JSON

    for highlighted_line in tokens {
        let mut row_content = row![].spacing(0);

        // Line number (NFT uses darker gray and different format)
        row_content = row_content.push(
            container(
                text(format!("{:4}", highlighted_line.line_number))
                    .font(mono_font)
                    .size(14)
                    .color(crate::app::syntax_cache::TokenColor::LineNumberNft.to_color(theme)),
            )
            .width(iced::Length::Fixed(50.0))
            .padding(iced::Padding::new(0.0).right(8.0)),
        );

        // Indentation (NFT only uses actual indentation, no extra spacing)
        if highlighted_line.indent > 0 && !highlighted_line.tokens.is_empty() {
            let spaces = &SPACES[..highlighted_line.indent];
            row_content = row_content.push(text(spaces).font(mono_font).size(14));
        }

        // Tokens (already parsed!)
        for token in &highlighted_line.tokens {
            row_content = row_content.push(
                text(&token.text)
                    .font(mono_font)
                    .size(14)
                    .color(token.color.to_color(theme)),
            );
        }

        lines = lines.push(row_content);
    }

    lines
}
