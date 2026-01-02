use crate::app::ui_components::{
    active_card_button, active_card_container, active_tab_button, card_button, card_container,
    danger_button, dirty_button, inactive_tab_button, main_container, modal_backdrop,
    notification_banner, popup_container, primary_button, secondary_button,
    section_header_container, sidebar_container, themed_checkbox, themed_horizontal_rule,
    themed_pick_list, themed_pick_list_menu, themed_scrollable, themed_slider,
    themed_text_input, themed_toggler,
};
use crate::app::{
    AppStatus, FontPickerTarget, Message, PendingWarning, ProfileManagerState, RuleForm, State,
    ThemeFilter, ThemePickerState, WorkspaceTab,
};
use crate::core::firewall::Protocol;
use iced::widget::text::Wrapping;
use iced::widget::{
    Id, button, checkbox, column, container, keyed_column, mouse_area, pick_list, progress_bar,
    row, rule, scrollable, space, stack, text, text_input, toggler, tooltip,
};
use iced::{alignment, Alignment, Border, Color, Element, Length, Padding, Shadow};
use std::sync::Arc; // Issue #2: Arc for cheap pointer cloning
use strum::IntoEnumIterator; // For ThemeChoice::iter()

// Text input IDs for focus management
pub const FONT_SEARCH_INPUT_ID: &str = "font-search-input";

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
                        state.show_zebra_striping,
                        state.cached_diff_width_px, // Dynamic width for diff view
                    ))
                    .width(Length::Fill)
                    .into()
                } else {
                    // No changes - show normal view
                    container(view_from_cached_nft_tokens(
                        &state.cached_nft_tokens,
                        theme,
                        state.font_mono,
                        state.show_zebra_striping,
                        state.cached_nft_width_px, // Dynamic width for NFT view
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
                    state.show_zebra_striping,
                    state.cached_nft_width_px, // Dynamic width for NFT view
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
                state.show_zebra_striping,
                state.cached_json_width_px, // Dynamic width for JSON view
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
            container(view_warning_modal(warning, theme, state.font_regular))
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
                &state.interfaces_with_any, // Issue #4: Use cached list with "Any" prepended
                theme,
                state.font_regular,
                state.font_mono,
                state.ruleset.advanced_security.egress_profile
                    == crate::core::firewall::EgressProfile::Server,
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
                container(view_awaiting_apply(theme, state.font_regular, state.auto_revert_enabled, state.auto_revert_timeout_secs))
                    .style(move |_| modal_backdrop(theme))
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill),
            ),
            AppStatus::PendingConfirmation { .. } => Some(
                container(view_pending_confirmation(
                    state.countdown_remaining,
                    state.auto_revert_timeout_secs.min(120) as u32,
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

    // Modal overlay layer (fades base content)
    let with_overlay = if let Some(overlay) = overlay {
        stack![base, overlay].into()
    } else {
        base.into()
    };

    // Banner overlay layer (free-floating at top-right, ABOVE modal backdrop)
    let with_banners: Element<'_, Message> = if !state.banners.is_empty() {
        let banner_column = column(
            state
                .banners
                .iter()
                .take(2)
                .enumerate()
                .map(|(index, banner)| notification_banner(banner, theme, index))
                .collect::<Vec<_>>(),
        )
        .spacing(8)
        .width(Length::Shrink)
        .padding(16);

        stack![
            with_overlay,
            container(banner_column)
                .width(Length::Fill)
                .height(Length::Shrink)
                .align_x(alignment::Horizontal::Right)
                .align_y(alignment::Vertical::Top)
        ]
        .into()
    } else {
        with_overlay
    };

    // Diagnostics modal overlay (on top of everything)
    let with_diagnostics = if state.show_diagnostics {
        stack![
            with_banners,
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
        with_banners
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

    // Theme picker modal overlay
    let with_theme_picker = if let Some(ref picker_state) = state.theme_picker {
        stack![
            with_font_picker,
            container(view_theme_picker(state, picker_state))
                .style(move |_| modal_backdrop(theme))
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_font_picker
    };

    // Profile switch confirmation overlay
    let with_profile_confirm = if state.pending_profile_switch.is_some() {
        stack![
            with_theme_picker,
            container(view_profile_switch_confirm(theme, state.font_regular))
                .style(move |_| modal_backdrop(theme))
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_theme_picker
    };

    // Profile manager modal overlay
    let with_profile_manager = if let Some(ref mgr_state) = state.profile_manager {
        stack![
            with_profile_confirm,
            container(view_profile_manager(state, mgr_state))
                .style(move |_| modal_backdrop(theme))
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
        ]
        .into()
    } else {
        with_profile_confirm
    };

    // Keyboard shortcuts help overlay
    if state.show_shortcuts_help {
        stack![
            with_profile_manager,
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
        with_profile_manager
    }
}

fn view_sidebar(state: &State) -> Element<'_, Message> {
    let theme = &state.theme;

    // 1. Branding & Profile Header
    let is_dirty = state.is_profile_dirty();

    let profile_selector = column![
        row![
            container(
                text("PROFILE")
                    .size(9)
                    .font(state.font_mono)
                    .color(theme.fg_muted)
            )
            .padding([2, 6])
            .style(move |_| section_header_container(theme)),
            container(row![]).width(Length::Fill),
            if is_dirty {
                text("Unsaved Changes*")
                    .size(9)
                    .font(state.font_mono)
                    .color(theme.warning)
            } else {
                text("Saved")
                    .size(9)
                    .font(state.font_mono)
                    .color(theme.success)
            }
        ]
        .align_y(Alignment::Center),
        row![
            pick_list(
                &state.available_profiles[..],
                Some(state.active_profile_name.clone()),
                Message::ProfileSelected
            )
            .width(Length::Fill)
            .padding(8)
            .style(move |_, status| themed_pick_list(theme, status))
            .menu_style(move |_| themed_pick_list_menu(theme)),
            button(text("⚙").size(16))
                .on_press(Message::OpenProfileManager)
                .padding([8, 12])
                .style(move |_, status| secondary_button(theme, status)),
        ]
        .spacing(8)
    ]
    .spacing(4);

    let branding = container(
        column![
            row![
                container(text("🛡️").size(28).color(theme.accent)).padding(4),
                column![
                    text("DRFW")
                        .size(24)
                        .font(state.font_regular)
                        .color(theme.accent),
                    container(
                        text("DUMB RUST FIREWALL")
                            .size(9)
                            .color(theme.fg_muted)
                            .font(state.font_mono)
                    )
                    .padding([2, 6])
                    .style(move |_| section_header_container(theme)),
                ]
                .spacing(0)
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            // Branding Separator
            container(row![])
                .height(Length::Fixed(1.0))
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(theme.border.into()),
                    ..Default::default()
                }),
            profile_selector
        ]
        .spacing(16),
    )
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
                button(text(tag.as_str()).size(10))
                    // Issue #2: Arc::clone just copies pointer (cheap!), not string data
                    .on_press(Message::FilterByTag(Some(Arc::clone(tag))))
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
            container(
                text("FILTERS")
                    .size(9)
                    .font(state.font_mono)
                    .color(theme.fg_muted)
            )
            .padding([2, 6])
            .style(move |_| section_header_container(theme)),
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
        container(
            text("RULES")
                .size(9)
                .font(state.font_mono)
                .color(theme.fg_muted)
        )
        .padding([2, 6])
        .style(move |_| section_header_container(theme)),
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
    .align_y(Alignment::Center);

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
                    text("Delete this rule?")
                        .size(11)
                        .color(theme.danger)
                        .width(Length::Fill),
                    button(text("Cancel").size(11))
                        .on_press(Message::CancelDelete)
                        .padding([4, 10])
                        .style(move |_, status| secondary_button(theme, status)),
                    button(text("Delete").size(11))
                        .on_press(Message::DeleteRule(rule.id))
                        .padding([4, 10])
                        .style(move |_, status| danger_button(theme, status)),
                ]
                .spacing(8)
                .align_y(Alignment::Center)
                .padding(8.0)
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

                // Protocol/Port badge with chain arrow in Server Mode
                // Issue #16: Use display_name() method (no match expression)
                let proto_text = rule.protocol.display_name();
                // Issue #5: Use cached port display string - no allocation!
                let port_text = &rule.port_display;

                // Determine if we're in Server Mode
                let server_mode = state.ruleset.advanced_security.egress_profile
                    == crate::core::firewall::EgressProfile::Server;

                // Chain arrow: only show in Server Mode
                let chain_arrow = if server_mode {
                    match rule.chain {
                        crate::core::firewall::Chain::Input => "↓",
                        crate::core::firewall::Chain::Output => "↑",
                    }
                } else {
                    ""
                };

                let badge = container(
                    text(format!("{chain_arrow}{proto_text}: {port_text}"))
                        .size(9)
                        .font(state.font_mono)
                        .color(if rule.enabled {
                            theme.syntax_type
                        } else {
                            theme.fg_muted
                        })
                        .wrapping(Wrapping::None), // Never wrap - clip instead
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
                })
                .width(Length::Shrink) // Only take needed space
                .clip(true); // Clip if extreme edge case

                // Action badge (DROP/REJECT) - only if not Accept
                let action_badge = if rule.action == crate::core::firewall::Action::Accept {
                    None
                } else {
                    let action_char = match rule.action {
                        crate::core::firewall::Action::Drop => "D",
                        crate::core::firewall::Action::Reject => "R",
                        crate::core::firewall::Action::Accept => "", // unreachable
                    };

                    let action_text = if let Some(ref rate_limit) = rule.rate_limit_display {
                        format!("{action_char} ({rate_limit})")
                    } else {
                        action_char.to_string()
                    };

                    Some(
                        container(
                            text(action_text)
                                .size(9)
                                .font(state.font_mono)
                                .color(theme.fg_on_accent)
                                .wrapping(Wrapping::None),
                        )
                        .padding([2, 6])
                        .style(move |_| container::Style {
                            background: Some(theme.danger.into()),
                            border: Border {
                                radius: 4.0.into(),
                                color: theme.danger,
                                width: 1.0,
                            },
                            ..Default::default()
                        })
                        .width(Length::Shrink)
                        .clip(true),
                    )
                };

                // Main Content: Label + Tags
                // Issue #20: Pre-allocate tag items Vec with exact capacity
                let mut tag_items: Vec<Element<'_, Message>> = Vec::with_capacity(rule.tags.len());
                // Issue #15: Pre-compute all tag colors (enabled/disabled variants)
                let is_enabled = rule.enabled;
                let tag_text_color = if is_enabled {
                    theme.fg_on_accent
                } else {
                    Color {
                        a: 0.5,
                        ..theme.fg_muted
                    }
                };
                let tag_bg_color = if is_enabled {
                    theme.accent
                } else {
                    Color {
                        a: 0.3,
                        ..theme.accent
                    }
                };
                for tag in &rule.tags {
                    tag_items.push(
                        container(
                            text(tag)
                                .size(8)
                                .color(tag_text_color)
                                .wrapping(Wrapping::None),
                        )
                        .padding([1, 4])
                        .style(move |_: &_| container::Style {
                            background: Some(tag_bg_color.into()),
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

                // Row 1: Controls (Drag) + Label + Accent + Controls (Toggle, Delete)
                let top_row = row![
                    // Drag Handle (Between Checkbox and Label)
                    button(
                        container(
                            text(if is_being_dragged {
                                "●"
                            } else if any_drag_active {
                                if is_hover_target { "◎" } else { "○" }
                            } else {
                                "⠿"
                            })
                            .size(14)
                            .color(handle_color),
                        )
                        .center_x(Length::Fixed(20.0))
                    )
                    .on_press(handle_action)
                    .padding([0, 2])
                    .style(button::text),
                    // Label (Clickable area for editing with distinctive popup Tooltip)
                    button(
                        tooltip(
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
                            .max_width(140.0)
                            .padding([2, 8])
                            .style(move |_| section_header_container(theme))
                            .align_x(iced::alignment::Horizontal::Left)
                            .clip(true),
                            container(
                                text(if rule.label.is_empty() {
                                    "Unnamed Rule"
                                } else {
                                    &rule.label
                                })
                                .size(12)
                                .font(state.font_regular)
                                .color(theme.fg_primary)
                            )
                            .padding([6, 10])
                            .style(move |_| popup_container(theme)),
                            tooltip::Position::Bottom
                        )
                        .delay(std::time::Duration::from_millis(1000)),
                    )
                    .on_press(Message::EditRuleClicked(rule.id))
                    .padding(0)
                    .style(button::text),
                    // Accent Line (Absorbs all remaining space)
                    rule::horizontal(1).style(move |_| rule::Style {
                        color: Color {
                            a: 0.1,
                            ..theme.fg_muted
                        },
                        fill_mode: rule::FillMode::Full,
                        radius: 0.0.into(),
                        snap: true,
                    }),
                    // Management Cluster (Always stays on far right)
                    row![
                        // Checkbox
                        checkbox(rule.enabled)
                            .on_toggle(move |_| Message::ToggleRuleEnabled(rule.id))
                            .size(16)
                            .spacing(0)
                            .style(move |_, status| themed_checkbox(theme, status)),
                        // Delete
                        button(text("×").size(14).color(theme.fg_muted))
                            .on_press(Message::DeleteRuleRequested(rule.id))
                            .padding(6)
                            .style(button::text),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                ]
                .spacing(8)
                .padding([0, 8]) // Add horizontal padding to match other rows
                .align_y(Alignment::Center);

                // Row 2: Detail Row (Interface, Action, Protocol/Ports) - now full width
                // Re-build detail_items to ensure interface is far left and protocol is far right
                let mut detail_items: Vec<Element<'_, Message>> = Vec::with_capacity(4);

                // 1. Interface (Far Left)
                if let Some(ref iface) = rule.interface {
                    detail_items.push(
                        container(
                            text(format!("@{iface}"))
                                .size(9)
                                .font(state.font_mono)
                                .color(if rule.enabled {
                                    theme.fg_muted
                                } else {
                                    Color {
                                        a: 0.5,
                                        ..theme.fg_muted
                                    }
                                })
                                .wrapping(Wrapping::None),
                        )
                        .clip(true)
                        .into(),
                    );
                }

                // 2. Action badge (Next to interface)
                if let Some(action_badge_elem) = action_badge {
                    detail_items.push(action_badge_elem.into());
                }

                // 3. Spacer (Fills middle to push protocol to right)
                detail_items.push(container(column![]).width(Length::Fill).into());

                // 4. Protocol Badge (Far Right)
                detail_items.push(badge.into());

                let details_row = button(
                    container(row(detail_items).spacing(8).align_y(Alignment::Center))
                        .width(Length::Fill),
                )
                .on_press(Message::EditRuleClicked(rule.id))
                .padding([0, 8]) // Match outer padding
                .style(button::text)
                .width(Length::Fill);

                // Row 3: Tags (if present)
                let mut card_rows = vec![top_row.into(), details_row.into()];

                if !rule.tags.is_empty() {
                    let tag_row = button(
                        container(row(tag_items).spacing(4).align_y(Alignment::Center))
                            .width(Length::Fill),
                    )
                    .on_press(Message::EditRuleClicked(rule.id))
                    .padding([0, 8])
                    .style(button::text)
                    .width(Length::Fill);

                    card_rows.push(tag_row.into());
                }

                column(card_rows).spacing(2).padding([4, 0]).into()
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
                scrollable(rule_list)
                    .height(Length::Fill)
                    .style(move |_, status| themed_scrollable(theme, status)),
            ]
            .spacing(8)
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
        // Tab buttons - simple rounded buttons like Export/Diagnostics
        view_tab_button("Ruleset", WorkspaceTab::Nftables, state.active_tab, theme),
        view_tab_button("JSON", WorkspaceTab::Json, state.active_tab, theme),
        view_tab_button("Settings", WorkspaceTab::Settings, state.active_tab, theme),
        container(row![]).width(Length::Fill),
        // Global Utility Tools
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
    .align_y(Alignment::Center);

    // Title and description row with optional diff checkbox
    let mut title_row = row![
        column![
            text(match state.active_tab {
                WorkspaceTab::Nftables => "Firewall Ruleset",
                WorkspaceTab::Json => "JSON Export",
                WorkspaceTab::Settings => "Settings",
            })
            .size(20)
            .font(state.font_regular)
            .color(theme.fg_primary),
            text(match state.active_tab {
                WorkspaceTab::Nftables =>
                    "Current nftables configuration generated from your rules.",
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

    // Add checkboxes in a vertical column when on Nftables tab
    if state.active_tab == WorkspaceTab::Nftables {
        let mut checkboxes = column![].spacing(8);

        // Add diff toggle when we have a previous version
        if state.last_applied_ruleset.is_some() {
            checkboxes = checkboxes.push(
                checkbox(state.show_diff)
                    .label("Show diff")
                    .on_toggle(Message::ToggleDiff)
                    .size(16)
                    .text_size(12)
                    .spacing(6)
                    .style(move |_, status| themed_checkbox(theme, status)),
            );
        }

        // Always show zebra toggle on Nftables tab
        checkboxes = checkboxes.push(
            checkbox(state.show_zebra_striping)
                .label("Show zebra")
                .on_toggle(Message::ToggleZebraStriping)
                .size(16)
                .text_size(12)
                .spacing(6)
                .style(move |_, status| themed_checkbox(theme, status)),
        );

        title_row = title_row.push(checkboxes);
    }

    let preview_header = column![nav_row, title_row].spacing(20);

    // Settings tab only needs vertical scrolling, other tabs need both
    let scroll_direction = if matches!(state.active_tab, WorkspaceTab::Settings) {
        scrollable::Direction::Vertical(scrollable::Scrollbar::default())
    } else {
        scrollable::Direction::Both {
            vertical: scrollable::Scrollbar::default(),
            horizontal: scrollable::Scrollbar::default(),
        }
    };

    let editor = container(
        scrollable(
            container(preview_content)
                .padding(24)
                .width(Length::Fill)
                .height(Length::Fill),
        )
        .direction(scroll_direction)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |_, status| themed_scrollable(theme, status)),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(move |_| container::Style {
        background: Some(theme.bg_surface.into()),
        border: Border {
            color: theme.border,
            width: 1.0,
            radius: 8.0.into(),
        },
        shadow: Shadow {
            color: theme.shadow_color,
            offset: iced::Vector::new(0.0, 2.0),
            blur_radius: 3.0,
        },
        ..Default::default()
    });

    // Zone: History (Left)
    let history_actions = row![
        button(text("↶").size(18))
            .on_press_maybe(state.command_history.can_undo().then_some(Message::Undo))
            .padding([10, 16])
            .style(move |_, status| secondary_button(theme, status)),
        button(text("↷").size(18))
            .on_press_maybe(state.command_history.can_redo().then_some(Message::Redo))
            .padding([10, 16])
            .style(move |_, status| secondary_button(theme, status)),
    ]
    .spacing(12);

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
                inactive_tab_button(theme, status)
            }
        })
        .on_press(Message::TabChanged(tab))
        .into()
}

/// Phase 1 Optimized: Build diff view from pre-tokenized cache (no parsing in view!)
/// Uses `keyed_column` for efficient widget reconciliation during resize
fn view_from_cached_diff_tokens<'a>(
    diff_tokens: &'a [(
        crate::app::syntax_cache::DiffType,
        crate::app::syntax_cache::HighlightedLine,
    )],
    theme: &crate::theme::AppTheme,
    mono_font: iced::Font,
    show_zebra_striping: bool,
    content_width_px: f32,
) -> iced::widget::keyed::Column<'a, usize, Message> {
    const SPACES: &str = "                                ";

    // Use pre-computed zebra stripe color from theme (computed once, not every frame)
    let even_stripe = theme.zebra_stripe;

    // Issue #20: Pre-allocate with exact line count
    let mut lines = keyed_column(Vec::with_capacity(diff_tokens.len())).spacing(1);

    for (diff_type, highlighted_line) in diff_tokens {
        let line_number = highlighted_line.line_number;
        let mut row_content = row![].spacing(0);

        // Line number (same format as normal view - no extra diff indicator, pre-formatted to avoid allocation)
        row_content = row_content.push(
            container(
                text(&highlighted_line.formatted_line_number_nft)
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
            let font = iced::Font {
                weight: if token.bold {
                    iced::font::Weight::Bold
                } else {
                    iced::font::Weight::Normal
                },
                style: if token.italic {
                    iced::font::Style::Italic
                } else {
                    iced::font::Style::Normal
                },
                ..mono_font
            };
            row_content = row_content.push(text(&token.text).font(font).size(14).color(color));
        }

        // Background colors: diff colors for added/removed, zebra stripes for unchanged
        let bg_color = match diff_type {
            crate::app::syntax_cache::DiffType::Added => Some(Color {
                a: 0.1,
                ..theme.success
            }),
            crate::app::syntax_cache::DiffType::Removed => Some(Color {
                a: 0.1,
                ..theme.danger
            }),
            crate::app::syntax_cache::DiffType::Unchanged => {
                // Apply zebra striping to unchanged lines (if enabled)
                if show_zebra_striping {
                    let is_even = line_number % 2 == 0;
                    if is_even { Some(even_stripe) } else { None }
                } else {
                    None
                }
            }
        };

        lines = lines.push(
            line_number,
            container(row_content)
                .width(Length::Fixed(content_width_px))
                .style(move |_| container::Style {
                    background: bg_color.map(Into::into),
                    ..Default::default()
                }),
        );
    }

    // Add a spacer at the end to fill remaining vertical space with zebra background
    // Continue the zebra pattern: if last line_number is odd, next would be even
    let last_line_number = diff_tokens.last().map_or(0, |(_, hl)| hl.line_number);
    let spacer_bg = if show_zebra_striping {
        let is_even = (last_line_number + 1).is_multiple_of(2);
        if is_even { Some(even_stripe) } else { None }
    } else {
        None
    };

    lines = lines.push(
        usize::MAX,
        container(space().height(Length::Fill))
            .width(Length::Fixed(content_width_px))
            .style(move |_| container::Style {
                background: spacer_bg.map(Into::into),
                ..Default::default()
            }),
    );

    lines
}

fn view_rule_form<'a>(
    form: &'a RuleForm,
    errors: Option<&'a crate::app::FormErrors>,
    interfaces: &'a [String],
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
    server_mode: bool,
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
    let destination_error = errors.and_then(|e| e.destination.as_ref());
    let rate_limit_error = errors.and_then(|e| e.rate_limit.as_ref());
    let connection_limit_error = errors.and_then(|e| e.connection_limit.as_ref());
    // Issue #4: Use pre-cached interface list with "Any" - no allocation!
    let iface_options = interfaces;

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
            text("DESCRIPTION").size(10).color(theme.fg_muted),
            text_input("e.g. Local Web Server", &form.label)
                .on_input(Message::RuleFormLabelChanged)
                .padding(8)
                .style(move |_, status| themed_text_input(theme, status))
        ]
        .spacing(4),
        // Technical Details Section
        column![
            row![
                column![
                    container(text("PROTOCOL").size(10).color(theme.fg_muted))
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
                    pick_list(
                        {
                            let mut protocols = vec![
                                Protocol::Any,
                                Protocol::Tcp,
                                Protocol::Udp,
                                Protocol::TcpAndUdp,
                                Protocol::IcmpBoth,
                            ];
                            // Only show individual ICMP versions in advanced mode
                            if form.show_advanced {
                                protocols.push(Protocol::Icmp);
                                protocols.push(Protocol::Icmpv6);
                            }
                            protocols
                        },
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
                        container(text("PORT RANGE").size(10).color(theme.fg_muted))
                            .padding([2, 6])
                            .style(move |_| section_header_container(theme)),
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
            .spacing(8),
        ]
        .spacing(6),
        // Context Section
        {
            let mut context_col = column![
                {
                    let mut source_col = column![
                        container(
                            text("SOURCE ADDRESS (OPTIONAL)")
                                .size(10)
                                .color(theme.fg_muted)
                        )
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
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
                    container(text("INTERFACE (OPTIONAL)").size(10).color(theme.fg_muted))
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
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
            .spacing(6);

            // Chain selection (only visible in Server Mode)
            if server_mode {
                context_col = context_col.push(
                    column![
                        container(text("CHAIN DIRECTION").size(10).color(theme.fg_muted))
                            .padding([2, 6])
                            .style(move |_| section_header_container(theme)),
                        pick_list(
                            vec![
                                crate::core::firewall::Chain::Input,
                                crate::core::firewall::Chain::Output,
                            ],
                            Some(form.chain),
                            Message::RuleFormChainChanged
                        )
                        .width(Length::Fill)
                        .padding(8)
                        .style(move |_, status| themed_pick_list(theme, status))
                        .menu_style(move |_| themed_pick_list_menu(theme))
                    ]
                    .spacing(4),
                );
            }
            context_col
        },
        // Advanced Options Section
        {
            let mut adv_col = column![
                checkbox(form.show_advanced)
                    .label("Show Advanced Options")
                    .on_toggle(Message::RuleFormToggleAdvanced)
                    .size(16)
                    .spacing(8)
                    .text_size(12)
                    .style(move |_, status| themed_checkbox(theme, status)),
            ]
            .spacing(6);

            if form.show_advanced {
                adv_col = adv_col.push(
                    column![
                        // Destination IP
                        {
                            let mut dest_col = column![
                                container(
                                    text("DESTINATION ADDRESS (OPTIONAL)")
                                        .size(10)
                                        .color(theme.fg_muted)
                                )
                                .padding([2, 6])
                                .style(move |_| section_header_container(theme)),
                                text_input("e.g. 192.168.1.0/24 or specific IP", &form.destination)
                                    .on_input(Message::RuleFormDestinationChanged)
                                    .padding(8)
                                    .style(move |_, status| themed_text_input(theme, status)),
                            ]
                            .spacing(4);

                            if let Some(err) = destination_error {
                                dest_col = dest_col.push(text(err).size(11).color(theme.danger));
                            }
                            dest_col
                        },
                        // Action
                        column![
                            container(text("ACTION").size(10).color(theme.fg_muted))
                                .padding([2, 6])
                                .style(move |_| section_header_container(theme)),
                            pick_list(
                                vec![
                                    crate::core::firewall::Action::Accept,
                                    crate::core::firewall::Action::Drop,
                                    crate::core::firewall::Action::Reject,
                                ],
                                Some(form.action),
                                Message::RuleFormActionChanged
                            )
                            .width(Length::Fill)
                            .padding(8)
                            .style(move |_, status| themed_pick_list(theme, status))
                            .menu_style(move |_| themed_pick_list_menu(theme))
                        ]
                        .spacing(4),
                        // Rate Limiting
                        {
                            let mut rate_limit_col = column![
                                checkbox(form.rate_limit_enabled)
                                    .label("Enable Rate Limiting")
                                    .on_toggle(Message::RuleFormToggleRateLimit)
                                    .size(16)
                                    .spacing(8)
                                    .text_size(12)
                                    .style(move |_, status| themed_checkbox(theme, status)),
                            ]
                            .spacing(4);

                            if form.rate_limit_enabled {
                                rate_limit_col = rate_limit_col.push(
                                    row![
                                        column![
                                            container(text("COUNT").size(10).color(theme.fg_muted))
                                                .padding([2, 6])
                                                .style(move |_| section_header_container(theme)),
                                            text_input("e.g. 5", &form.rate_limit_count)
                                                .on_input(Message::RuleFormRateLimitCountChanged)
                                                .padding(8)
                                                .style(move |_, status| themed_text_input(
                                                    theme, status
                                                )),
                                        ]
                                        .spacing(4)
                                        .width(Length::Fill),
                                        column![
                                            container(text("PER").size(10).color(theme.fg_muted))
                                                .padding([2, 6])
                                                .style(move |_| section_header_container(theme)),
                                            pick_list(
                                                vec![
                                                    crate::core::firewall::TimeUnit::Second,
                                                    crate::core::firewall::TimeUnit::Minute,
                                                    crate::core::firewall::TimeUnit::Hour,
                                                    crate::core::firewall::TimeUnit::Day,
                                                ],
                                                Some(form.rate_limit_unit),
                                                Message::RuleFormRateLimitUnitChanged
                                            )
                                            .width(Length::Fill)
                                            .padding(8)
                                            .style(move |_, status| themed_pick_list(theme, status))
                                            .menu_style(move |_| themed_pick_list_menu(theme))
                                        ]
                                        .spacing(4)
                                        .width(Length::Fill),
                                    ]
                                    .spacing(8),
                                );
                            }

                            if let Some(err) = rate_limit_error {
                                rate_limit_col =
                                    rate_limit_col.push(text(err).size(11).color(theme.danger));
                            }
                            rate_limit_col
                        },
                        // Connection Limiting
                        {
                            let mut conn_col = column![
                                container(
                                    text("CONNECTION LIMIT (OPTIONAL)")
                                        .size(10)
                                        .color(theme.fg_muted)
                                )
                                .padding([2, 6])
                                .style(move |_| section_header_container(theme)),
                                text_input(
                                    "Max simultaneous connections (0 = unlimited)",
                                    &form.connection_limit
                                )
                                .on_input(Message::RuleFormConnectionLimitChanged)
                                .padding(8)
                                .style(move |_, status| themed_text_input(theme, status)),
                            ]
                            .spacing(4);

                            if let Some(err) = connection_limit_error {
                                conn_col = conn_col.push(text(err).size(11).color(theme.danger));
                            }
                            conn_col
                        },
                    ]
                    .spacing(6),
                );
            }
            adv_col
        },
        // Organization Section
        {
            let mut org_col = column![
                container(text("TAGS").size(10).color(theme.fg_muted))
                    .padding([2, 6])
                    .style(move |_| section_header_container(theme)),
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
            .spacing(4);

            if !form.tags.is_empty() {
                // Issue #6: Capture only needed colors instead of cloning entire theme
                let accent_color = theme.accent;
                let fg_on_accent = theme.fg_on_accent;
                org_col = org_col.push(
                    row(form.tags.iter().map(|tag| -> Element<'_, Message> {
                        container(
                            row![
                                text(tag).size(12).color(fg_on_accent),
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
                            style.background = Some(accent_color.into());
                            style
                        })
                        .into()
                    }))
                    .spacing(6)
                    .wrap(),
                );
            }
            org_col
        },
        // Footer Actions
        row![
            button(text("Cancel").size(14))
                .on_press(Message::CancelRuleForm)
                .padding([10, 20])
                .style(move |_, status| secondary_button(theme, status)),
            container(row![]).width(Length::Fill),
            button(text(button_text).size(14))
                .on_press(Message::SaveRuleForm)
                .padding([10, 24])
                .style(move |_, status| primary_button(theme, status)),
        ]
        .spacing(16)
        .align_y(Alignment::Center)
    ]
    .spacing(6)
    .padding(20);
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
    if matches!(
        form.protocol,
        Protocol::Tcp | Protocol::Udp | Protocol::TcpAndUdp
    ) {
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
    auto_revert_enabled: bool,
    auto_revert_timeout: u64,
) -> Element<'_, Message> {
    let description = if auto_revert_enabled {
        format!("Rules verified. Applying will activate a {}s safety rollback timer.", auto_revert_timeout.min(120))
    } else {
        "Rules verified. Changes will take effect immediately (no auto-revert).".to_string()
    };

    let button_text = if auto_revert_enabled {
        "Apply & Start Timer"
    } else {
        "Apply Now"
    };

    container(column![text("🛡️").size(36), container(text("Commit Changes?").size(24).font(regular_font).color(app_theme.fg_primary))
                          .padding([4, 8])
                          .style(move |_| section_header_container(app_theme)),
                      text(description).size(14).color(app_theme.fg_muted).width(360).align_x(Alignment::Center),
                      row![button(text("Discard").size(14)).on_press(Message::CancelRuleForm).padding([10, 20]).style(move |_, status| secondary_button(app_theme, status)),
                           button(text(button_text).size(14)).on_press(Message::ProceedToApply).padding([10, 24]).style(move |_, status| primary_button(app_theme, status)),
                      ].spacing(16)
    ].spacing(20).padding(32).align_x(Alignment::Center))
    .style(move |_| card_container(app_theme))
    .into()
}

fn view_pending_confirmation(
    remaining: u32,
    total_timeout: u32,
    app_theme: &crate::theme::AppTheme,
    regular_font: iced::Font,
) -> Element<'_, Message> {
    // Calculate progress (inverted: starts at 100%, goes to 0%)
    let progress = if total_timeout > 0 {
        (remaining as f32) / (total_timeout as f32)
    } else {
        0.0
    };

    container(
        column![
            text("⏳").size(36),
            container(
                text("Confirm Safety")
                    .size(24)
                    .font(regular_font)
                    .color(app_theme.fg_primary)
            )
            .padding([4, 8])
            .style(move |_| section_header_container(app_theme)),
            text(format!(
                "Firewall updated. Automatic rollback in {remaining} seconds if not confirmed."
            ))
            .size(14)
            .color(app_theme.accent)
            .width(360)
            .align_x(Alignment::Center),
            // Progress bar showing time remaining (inset/recessed style)
            container(
                progress_bar(0.0..=1.0, progress)
                    .length(Length::Fill)
                    .girth(18)
                    .style(move |_| {
                        use iced::widget::progress_bar;
                        use iced::{Gradient, Background};

                        // Use darkened accent for inset appearance (recessed elements are darker)
                        let base_color = if remaining <= 5 {
                            app_theme.danger
                        } else {
                            app_theme.accent
                        };

                        let bar_color = Color {
                            r: base_color.r * 0.85,  // 15% darker than raised buttons
                            g: base_color.g * 0.85,
                            b: base_color.b * 0.85,
                            a: base_color.a,
                        };

                        // Gradient: straight top shadow (light from above)
                        let bar_gradient = Gradient::Linear(iced::gradient::Linear::new(std::f32::consts::PI)
                            .add_stop(0.0, Color {
                                r: bar_color.r * 0.5,  // 50% darker shadow at top edge
                                g: bar_color.g * 0.5,
                                b: bar_color.b * 0.5,
                                a: bar_color.a,
                            })
                            .add_stop(0.08, bar_color)  // Quick transition at 8%
                            .add_stop(1.0, bar_color));  // Full fill color for rest

                        progress_bar::Style {
                            background: Color {
                                r: app_theme.bg_surface.r * 0.8,
                                g: app_theme.bg_surface.g * 0.8,
                                b: app_theme.bg_surface.b * 0.8,
                                a: app_theme.bg_surface.a,
                            }.into(),
                            bar: Background::Gradient(bar_gradient),
                            border: Border {
                                radius: 6.0.into(),
                                ..Default::default()
                            },
                        }
                    })
            )
            .width(360)
            .padding(2)  // Reduced from 3 for thinner edge
            .style(move |_| container::Style {
                background: Some(Color {
                    r: app_theme.bg_surface.r * 0.7,  // 30% darker using RGB multiplication
                    g: app_theme.bg_surface.g * 0.7,
                    b: app_theme.bg_surface.b * 0.7,
                    a: app_theme.bg_surface.a,
                }.into()),
                border: Border {
                    color: Color {
                        r: app_theme.bg_surface.r * 0.75,  // Lighter 25% darkening for border
                        g: app_theme.bg_surface.g * 0.75,
                        b: app_theme.bg_surface.b * 0.75,
                        a: app_theme.bg_surface.a,
                    }.into(),
                    width: 1.0,
                    radius: 8.0.into(),
                },
                shadow: Shadow {
                    // Inner shadow effect (inverted offset for recess illusion)
                    color: Color {
                        r: app_theme.bg_surface.r * 0.5,  // Even darker for shadow depth
                        g: app_theme.bg_surface.g * 0.5,
                        b: app_theme.bg_surface.b * 0.5,
                        a: 0.8,  // Slightly transparent for blend
                    },
                    offset: iced::Vector::new(0.0, -1.0),  // Negative Y = top shadow
                    blur_radius: 3.0,
                },
                ..Default::default()
            }),
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
    .style(move |_| card_container(app_theme))
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
                button(
                    row![
                        container(
                            text(state.current_theme.name())
                                .size(13)
                                .wrapping(Wrapping::None)
                        )
                        .width(Length::Fill)
                        .clip(true),
                        text(" ▾").size(10).color(theme.fg_muted)
                    ]
                    .align_y(Alignment::Center)
                )
                .on_press(Message::OpenThemePicker)
                .width(Length::Fill)
                .padding(8)
                .style(move |_, status| secondary_button(theme, status))
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

    let safety_card = container(column![
        container(
            row![
                text("⏱️").size(18),
                text("APPLY SAFETY").size(12).font(state.font_regular)
            ]
            .spacing(8)
            .align_y(Alignment::Center)
        )
        .padding([8, 12])
        .width(Length::Fill)
        .style(move |_| section_header_container(theme)),
        column![
            render_settings_row(
                "Auto-revert confirmation",
                "Require manual confirmation or automatically revert firewall changes after timeout",
                toggler(state.auto_revert_enabled)
                    .on_toggle(Message::ToggleAutoRevert)
                    .width(Length::Shrink)
                    .style(move |_, status| themed_toggler(theme, status))
                    .into(),
                theme,
                state.font_regular,
            ),
            if state.auto_revert_enabled {
                Element::from(render_settings_row(
                    "   └ Timeout",
                    "Seconds before automatic revert (5-120s)",
                    row![
                        slider(5.0..=120.0, state.auto_revert_timeout_secs as f64, |v| Message::AutoRevertTimeoutChanged(v as u64))
                            .width(Length::Fill)
                            .style(move |_, status| themed_slider(theme, status)),
                        text(format!("{}s", state.auto_revert_timeout_secs))
                            .size(12).font(state.font_mono).width(40).align_x(Alignment::End),
                    ].spacing(12).align_y(Alignment::Center).into(),
                    theme,
                    state.font_regular,
                ))
            } else {
                column![].into()
            },
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

                render_settings_row(
                    "Server Mode",
                    "Block all outbound connections by default (recommended for servers)",
                    toggler(advanced.egress_profile == crate::core::firewall::EgressProfile::Server)
                        .on_toggle(Message::ServerModeToggled)
                        .width(Length::Shrink)
                        .style(move |_, status| themed_toggler(theme, status))
                        .into(),
                    theme,
                    state.font_regular,
                )
            ].spacing(16).padding(16)
        ]
    )
        .style(move |_| card_container(theme));

    column![appearance_card, safety_card, security_card,]
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
                .font(regular_font),
            row![
                button(text("Cancel").size(14).font(regular_font))
                    .on_press(Message::CancelWarning)
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
                button(text("Yes, I understand").size(14).font(regular_font))
                    .on_press(confirm_msg)
                    .padding([10, 24])
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
        style.border = Border {
            color: theme.danger,
            width: 2.0,
            radius: 8.0.into(),
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
                    scrollable(
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
                                        .font(mono_font)
                                        .color(theme.fg_primary)
                                        .into()
                                })
                                .collect()
                        })
                        .spacing(4)
                    )
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
                    .style(move |_, status| secondary_button(theme, status)),
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
    // Phase 4: Use cached lowercase search term for fuzzy matching
    let search_term = &picker.search_lowercase;

    // Phase 4: Filter by target (mono vs regular) THEN fuzzy match
    let is_mono_picker = matches!(picker.target, crate::app::FontPickerTarget::Mono);
    let target_filtered = state.available_fonts.iter().filter(|f| {
        // Filter monospace fonts for code font picker
        !is_mono_picker || f.is_monospace()
    });

    // Phase 4: Apply fuzzy matching (returns fonts sorted by relevance)
    let filtered_fonts: Vec<_> = crate::app::fuzzy_filter_fonts(target_filtered, search_term)
        .into_iter()
        .map(|(font, _score)| font) // Discard scores, just use sorted order
        .collect();

    // Track counts for display
    let filtered_count = filtered_fonts.len();
    let display_limit = 30;
    let displayed_count = filtered_count.min(display_limit);

    // Limit visible items to improve rendering performance if there are many matches
    // 30 is enough for a searchable list and keeps layout fast (reduced from 100)
    let font_list = column(filtered_fonts.into_iter().take(display_limit).map(|f| {
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
                    // Contextual preview text: code sample for mono fonts, readable text for UI fonts
                    text(if is_mono_picker {
                        "fn main() { 0x123 }"
                    } else {
                        "The quick brown fox"
                    })
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
            container(
                text(match picker.target {
                    FontPickerTarget::Regular => "Select UI Font",
                    FontPickerTarget::Mono => "Select Code Font",
                })
                .size(18)
                .font(state.font_regular)
                .color(theme.fg_primary)
            )
            .padding([4, 8])
            .style(move |_| section_header_container(theme)),
            text_input("Search fonts...", &picker.search)
                .on_input(Message::FontPickerSearchChanged)
                .padding(10)
                .size(13)
                .id(Id::new(FONT_SEARCH_INPUT_ID))
                .style(move |_, status| themed_text_input(theme, status)),
            container(
                scrollable(
                    column![
                        container(font_list).padding(Padding {
                            top: 2.0,
                            right: 12.0,
                            bottom: 2.0,
                            left: 2.0,
                        }),
                        if filtered_count == 0 {
                            container(
                                text("No fonts found — try a different search")
                                    .size(11)
                                    .color(theme.fg_muted),
                            )
                            .padding(Padding {
                                top: 8.0,
                                right: 12.0,
                                bottom: 4.0,
                                left: 12.0,
                            })
                        } else if filtered_count > display_limit {
                            container(
                                text(format!(
                                    "Showing {displayed_count} of {filtered_count} fonts — search to find more"
                                ))
                                .size(11)
                                .color(theme.fg_muted),
                            )
                            .padding(Padding {
                                top: 8.0,
                                right: 12.0,
                                bottom: 4.0,
                                left: 12.0,
                            })
                        } else {
                            container(text(""))
                        },
                    ]
                    .spacing(0)
                )
                .style(move |_, status| themed_scrollable(theme, status))
            )
            .height(Length::Fixed(400.0))
            .width(Length::Fill)
            .style(move |_| container::Style {
                border: Border {
                    radius: 8.0.into(),
                    color: theme.border,
                    width: 1.0,
                },
                ..Default::default()
            }),
            row![
                container(
                    text(if filtered_count < state.available_fonts.len() {
                        format!("{filtered_count} fonts match")
                    } else {
                        format!("{filtered_count} fonts available")
                    })
                    .size(10)
                    .color(theme.fg_muted)
                    .font(state.font_mono)
                )
                .padding([2, 6])
                .style(move |_| section_header_container(theme)),
                space::Space::new().width(Length::Fill),
                button(text("Close").size(14))
                    .on_press(Message::CloseFontPicker)
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
            ]
            .align_y(Alignment::Center)
        ]
        .spacing(16)
        .padding(24)
        .width(Length::Fixed(500.0)),
    )
    .style(move |_| card_container(theme))
    .into()
}

fn view_theme_picker<'a>(state: &'a State, picker: &'a ThemePickerState) -> Element<'a, Message> {
    // Theme picker layout constants
    const CARD_WIDTH: f32 = 150.0;
    const CARD_SPACING: f32 = 16.0;
    const GRID_PADDING: f32 = 8.0; // Clean symmetric padding
    const MODAL_WIDTH: f32 = 556.0; // Fine-tuned for visual balance
    const GRADIENT_BAR_HEIGHT: f32 = 24.0;
    const COLOR_DOT_SIZE: f32 = 12.0;
    const STATUS_COLOR_SIZE: f32 = 14.0;

    let theme = &state.theme;
    let search_term = &picker.search_lowercase;

    // Phase 4: Filter by light/dark THEN fuzzy match
    let filter_passed = crate::theme::ThemeChoice::iter().filter(|choice| {
        let theme_instance = choice.to_theme();
        match picker.filter {
            ThemeFilter::All => true,
            ThemeFilter::Light => theme_instance.is_light(),
            ThemeFilter::Dark => !theme_instance.is_light(),
        }
    });

    // Phase 4: Apply fuzzy matching (returns themes sorted by relevance)
    // Cache to_theme() results to avoid duplicate calls (performance optimization)
    let filtered_themes: Vec<_> = crate::app::fuzzy_filter_themes(filter_passed, search_term)
        .into_iter()
        .map(|(choice, _score)| {
            // Cache theme instance to avoid duplicate to_theme() calls
            (choice, choice.to_theme())
        })
        .collect();

    // Track counts for display
    let filtered_count = filtered_themes.len();

    // Helper function for creating colored dot containers
    let make_color_dot = |color: Color, size: f32| {
        container(space::Space::new().width(size).height(size)).style(move |_| container::Style {
            background: Some(color.into()),
            border: Border {
                radius: (size / 2.0).into(),
                ..Default::default()
            },
            ..Default::default()
        })
    };

    // Pre-allocate theme card vector (show all themes, no limit)
    let mut theme_cards = Vec::with_capacity(filtered_count);

    for (choice, theme_preview) in &filtered_themes {
        let is_selected = state.current_theme == *choice;

        // Extract colors for use in closures (Color is Copy)
        let bg_base = theme_preview.bg_base;
        let bg_surface = theme_preview.bg_surface;
        let accent = theme_preview.accent;
        let success = theme_preview.success;
        let warning = theme_preview.warning;
        let danger = theme_preview.danger;

        theme_cards.push(
            button(
                column![
                    // Header: name only (no checkmark)
                    text(choice.name()).size(13).color(theme.fg_primary),
                    // Split visual preview: 70% bg gradient + 30% accent color (square)
                    row![
                        // Left: background gradient
                        container(space::Space::new())
                            .width(Length::FillPortion(7))
                            .height(Length::Fixed(GRADIENT_BAR_HEIGHT))
                            .style(move |_| container::Style {
                                background: Some(
                                    iced::gradient::Linear::new(0.0)
                                        .add_stop(0.0, bg_base)
                                        .add_stop(1.0, bg_surface)
                                        .into(),
                                ),
                                ..Default::default()
                            }),
                        // Right: accent color
                        container(space::Space::new())
                            .width(Length::FillPortion(3))
                            .height(Length::Fixed(GRADIENT_BAR_HEIGHT))
                            .style(move |_| container::Style {
                                background: Some(accent.into()),
                                ..Default::default()
                            }),
                    ],
                    // Color swatches (semantic colors)
                    row![
                        make_color_dot(accent, COLOR_DOT_SIZE),
                        make_color_dot(success, COLOR_DOT_SIZE),
                        make_color_dot(warning, COLOR_DOT_SIZE),
                        make_color_dot(danger, COLOR_DOT_SIZE),
                    ]
                    .spacing(4),
                ]
                .spacing(6)
                .padding(8),
            )
            .width(Length::Fixed(CARD_WIDTH))
            .on_press(Message::ThemePreview(*choice))
            .style(move |_, status| {
                let mut style = card_button(theme, status);
                if is_selected {
                    // Add accent border for selected theme
                    style.border = Border {
                        color: accent,
                        width: 2.0,
                        radius: 8.0.into(),
                    };
                }
                style
            })
            .into(),
        );
    }

    // Create grid layout (3 columns) - wrapped row with better spacing
    let theme_grid = row(theme_cards).spacing(CARD_SPACING).wrap();

    // Filter buttons (identical to tag filtering pattern)
    let filter_buttons = row![
        button(text("All").size(10))
            .padding([4, 8])
            .style(move |_, status| {
                if matches!(picker.filter, ThemeFilter::All) {
                    active_tab_button(theme, status)
                } else {
                    secondary_button(theme, status)
                }
            })
            .on_press(Message::ThemePickerFilterChanged(ThemeFilter::All)),
        button(text("Light").size(10))
            .padding([4, 8])
            .style(move |_, status| {
                if matches!(picker.filter, ThemeFilter::Light) {
                    active_tab_button(theme, status)
                } else {
                    secondary_button(theme, status)
                }
            })
            .on_press(Message::ThemePickerFilterChanged(ThemeFilter::Light)),
        button(text("Dark").size(10))
            .padding([4, 8])
            .style(move |_, status| {
                if matches!(picker.filter, ThemeFilter::Dark) {
                    active_tab_button(theme, status)
                } else {
                    secondary_button(theme, status)
                }
            })
            .on_press(Message::ThemePickerFilterChanged(ThemeFilter::Dark)),
    ]
    .spacing(6);

    // Preview panel showing currently selected theme (two-column layout)
    let preview_panel = container(
        column![
            row![
                container(
                    text("PREVIEW:")
                        .size(11)
                        .font(state.font_mono)
                        .color(theme.fg_muted)
                )
                .padding([2, 6])
                .style(move |_| section_header_container(theme)),
                text(state.current_theme.name())
                    .size(11)
                    .font(state.font_mono)
                    .color(theme.fg_muted),
                rule::horizontal(1).style(move |_| rule::Style {
                    color: Color {
                        a: 0.1,
                        ..theme.fg_muted
                    },
                    fill_mode: rule::FillMode::Full,
                    radius: 0.0.into(),
                    snap: true,
                }),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
            // Two-column layout: UI elements left, code right
            row![
                // Left column: Buttons, text hierarchy, status colors (45% width)
                column![
                    // Buttons in 2x2 grid (standard secondary style)
                    row![
                        button(text("Apply").size(12))
                            .padding([6, 12])
                            .on_press(Message::ThemePreviewButtonClick)
                            .style(move |_, status| primary_button(theme, status)),
                        button(text("Cancel").size(12))
                            .padding([6, 12])
                            .on_press(Message::ThemePreviewButtonClick)
                            .style(move |_, status| secondary_button(theme, status)),
                    ]
                    .spacing(6),
                    row![
                        button(text("Delete").size(12))
                            .padding([6, 12])
                            .on_press(Message::ThemePreviewButtonClick)
                            .style(move |_, status| danger_button(theme, status)),
                        button(text("Save").size(12))
                            .padding([6, 12])
                            .on_press(Message::ThemePreviewButtonClick)
                            .style(move |_, status| dirty_button(theme, status)),
                    ]
                    .spacing(6),
                    // Text hierarchy
                    column![
                        container(
                            text("Text Hierarchy")
                                .size(10)
                                .font(state.font_mono)
                                .color(theme.fg_muted)
                        )
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
                        row![
                            text("Primary").size(11).color(theme.fg_primary),
                            text("•").size(11).color(theme.fg_muted),
                            text("Secondary").size(11).color(theme.fg_secondary),
                            text("•").size(11).color(theme.fg_muted),
                            text("Muted").size(11).color(theme.fg_muted),
                        ]
                        .spacing(6),
                    ]
                    .spacing(4),
                    // Status colors
                    column![
                        container(
                            text("Status Colors")
                                .size(10)
                                .font(state.font_mono)
                                .color(theme.fg_muted)
                        )
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
                        row![
                            make_color_dot(theme.success, STATUS_COLOR_SIZE),
                            make_color_dot(theme.warning, STATUS_COLOR_SIZE),
                            make_color_dot(theme.danger, STATUS_COLOR_SIZE),
                            make_color_dot(theme.info, STATUS_COLOR_SIZE),
                        ]
                        .spacing(6),
                    ]
                    .spacing(4),
                ]
                .spacing(12)
                .width(Length::FillPortion(7)),
                // Right column: Taller code snippet (65% width) - Fills more space
                container(
                    column![
                        text("fn process_data(items: Vec<String>) -> u32 {")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_keyword),
                        text("    let mut count = 0;  // initialize")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_comment),
                        text("    for item in items.iter() {")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_keyword),
                        text("        if item.len() > 5 {")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_keyword),
                        text("            count += 1;")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_number),
                        text("            println!(\"Found: {}\", item);")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_string),
                        text("        }")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_keyword),
                        text("    }")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_keyword),
                        text("    count  // return value")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_comment),
                        text("}")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_keyword),
                    ]
                    .spacing(1)
                )
                .padding(12)
                .width(Length::FillPortion(13))
                .height(Length::Shrink)
                .style(move |_| container::Style {
                    background: Some(theme.bg_elevated.into()),
                    border: Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        ]
        .spacing(8)
        .padding(12),
    )
    .width(Length::Fill)
    .height(Length::Shrink)
    .style(move |_| container::Style {
        background: Some(theme.bg_surface.into()),
        border: Border {
            radius: 8.0.into(),
            color: theme.border,
            width: 1.0,
        },
        ..Default::default()
    });

    container(
        column![
            container(
                text("Select Theme")
                    .size(18)
                    .font(state.font_regular)
                    .color(theme.fg_primary)
            )
            .padding([4, 8])
            .style(move |_| section_header_container(theme)),
            text_input("Search themes...", &picker.search)
                .on_input(Message::ThemePickerSearchChanged)
                .padding(10)
                .size(13)
                .style(move |_, status| themed_text_input(theme, status)),
            filter_buttons,
            container(
                scrollable(column![if filtered_count == 0 {
                    container(
                        text("No themes found — try a different search")
                            .size(11)
                            .color(theme.fg_muted),
                    )
                    .padding(GRID_PADDING) // Symmetric - simple and maintainable
                } else {
                    container(theme_grid).padding(GRID_PADDING) // Symmetric - simple and maintainable
                }])
                .width(Length::Fill)
                .style(move |_, status| themed_scrollable(theme, status))
            )
            .height(Length::Fixed(320.0))
            .width(Length::Fill)
            .style(move |_| container::Style {
                border: Border {
                    radius: 8.0.into(),
                    color: theme.border,
                    width: 1.0,
                },
                ..Default::default()
            }),
            preview_panel,
            row![
                container(
                    text(
                        if filtered_count < crate::theme::ThemeChoice::iter().count() {
                            format!("{filtered_count} themes match")
                        } else {
                            format!("{filtered_count} themes available")
                        }
                    )
                    .size(10)
                    .color(theme.fg_muted)
                    .font(state.font_mono)
                )
                .padding([2, 6])
                .style(move |_| section_header_container(theme)),
                space::Space::new().width(Length::Fill),
                button(text("Cancel").size(14))
                    .on_press(Message::CancelThemePicker)
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
                button(text("Apply").size(14))
                    .on_press(Message::ApplyTheme)
                    .padding([10, 24])
                    .style(move |_, status| primary_button(theme, status)),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
        ]
        .spacing(16)
        .padding(24)
        .width(Length::Fixed(MODAL_WIDTH)),
    )
    .style(move |_| card_container(theme))
    .into()
}

fn view_shortcuts_help(
    theme: &crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'_, Message> {
    container(
        column![
            container(
                text("⌨️ Keyboard Shortcuts")
                    .size(24)
                    .font(regular_font)
                    .color(theme.warning)
            )
            .padding([4, 8])
            .style(move |_| section_header_container(theme)),
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
                .style(move |_, status| secondary_button(theme, status)),
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
/// Uses `keyed_column` for efficient widget reconciliation during resize
fn view_from_cached_json_tokens<'a>(
    tokens: &'a [crate::app::syntax_cache::HighlightedLine],
    theme: &crate::theme::AppTheme,
    mono_font: iced::Font,
    show_zebra_striping: bool,
    content_width_px: f32,
) -> iced::widget::keyed::Column<'a, usize, Message> {
    const SPACES: &str = "                                ";

    // Use pre-computed zebra stripe color from theme (computed once, not every frame)
    let even_stripe = theme.zebra_stripe;

    // Issue #20: Pre-allocate with exact line count
    let mut lines = keyed_column(Vec::with_capacity(tokens.len())).spacing(2);

    for highlighted_line in tokens {
        let line_number = highlighted_line.line_number;
        let mut row_content = row![].spacing(0);

        // Line number (pre-formatted to avoid allocation every frame)
        row_content = row_content.push(
            container(
                text(&highlighted_line.formatted_line_number_json)
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
            let font = iced::Font {
                weight: if token.bold {
                    iced::font::Weight::Bold
                } else {
                    iced::font::Weight::Normal
                },
                style: if token.italic {
                    iced::font::Style::Italic
                } else {
                    iced::font::Style::Normal
                },
                ..mono_font
            };
            row_content = row_content.push(
                text(&token.text)
                    .font(font)
                    .size(14)
                    .color(token.color.to_color(theme)),
            );
        }

        // Apply subtle zebra striping: even rows get background, odd rows transparent (if enabled)
        let bg = if show_zebra_striping {
            let is_even = line_number % 2 == 0;
            if is_even { Some(even_stripe) } else { None }
        } else {
            None
        };

        lines = lines.push(
            line_number,
            container(row_content)
                .width(Length::Fixed(content_width_px))
                .style(move |_| container::Style {
                    background: bg.map(Into::into),
                    ..Default::default()
                }),
        );
    }

    // Add a spacer at the end to fill remaining vertical space with zebra background
    // Continue the zebra pattern: if last line_number is odd, next would be even
    let last_line_number = tokens.last().map_or(0, |hl| hl.line_number);
    let spacer_bg = if show_zebra_striping {
        let is_even = (last_line_number + 1).is_multiple_of(2);
        if is_even { Some(even_stripe) } else { None }
    } else {
        None
    };

    lines = lines.push(
        usize::MAX,
        container(space().height(Length::Fill))
            .width(Length::Fixed(content_width_px))
            .style(move |_| container::Style {
                background: spacer_bg.map(Into::into),
                ..Default::default()
            }),
    );

    lines
}

/// Phase 1 Optimization: Build widgets from pre-tokenized NFT (cached in State)
/// Uses `keyed_column` for efficient widget reconciliation during resize
fn view_from_cached_nft_tokens<'a>(
    tokens: &'a [crate::app::syntax_cache::HighlightedLine],
    theme: &crate::theme::AppTheme,
    mono_font: iced::Font,
    show_zebra_striping: bool,
    content_width_px: f32,
) -> iced::widget::keyed::Column<'a, usize, Message> {
    const SPACES: &str = "                                ";

    // Use pre-computed zebra stripe color from theme (computed once, not every frame)
    let even_stripe = theme.zebra_stripe;

    // Issue #20: Pre-allocate with exact line count
    let mut lines = keyed_column(Vec::with_capacity(tokens.len())).spacing(1); // NFT uses tighter spacing than JSON

    for highlighted_line in tokens {
        let line_number = highlighted_line.line_number;
        let mut row_content = row![].spacing(0);

        // Line number (NFT uses darker gray and different format, pre-formatted to avoid allocation)
        row_content = row_content.push(
            container(
                text(&highlighted_line.formatted_line_number_nft)
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
            let font = iced::Font {
                weight: if token.bold {
                    iced::font::Weight::Bold
                } else {
                    iced::font::Weight::Normal
                },
                style: if token.italic {
                    iced::font::Style::Italic
                } else {
                    iced::font::Style::Normal
                },
                ..mono_font
            };
            row_content = row_content.push(
                text(&token.text)
                    .font(font)
                    .size(14)
                    .color(token.color.to_color(theme)),
            );
        }

        // Apply subtle zebra striping: even rows get background, odd rows transparent (if enabled)
        let bg = if show_zebra_striping {
            let is_even = line_number % 2 == 0;
            if is_even { Some(even_stripe) } else { None }
        } else {
            None
        };

        lines = lines.push(
            line_number,
            container(row_content)
                .width(Length::Fixed(content_width_px))
                .style(move |_| container::Style {
                    background: bg.map(Into::into),
                    ..Default::default()
                }),
        );
    }

    // Add a spacer at the end to fill remaining vertical space with zebra background
    // Continue the zebra pattern: if last line_number is odd, next would be even
    let last_line_number = tokens.last().map_or(0, |hl| hl.line_number);
    let spacer_bg = if show_zebra_striping {
        let is_even = (last_line_number + 1).is_multiple_of(2);
        if is_even { Some(even_stripe) } else { None }
    } else {
        None
    };

    lines = lines.push(
        usize::MAX,
        container(space().height(Length::Fill))
            .width(Length::Fixed(content_width_px))
            .style(move |_| container::Style {
                background: spacer_bg.map(Into::into),
                ..Default::default()
            }),
    );

    lines
}

fn view_profile_switch_confirm(
    theme: &crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'_, Message> {
    container(
        column![
            text("⚠️ Unsaved Changes")
                .size(20)
                .font(font)
                .color(theme.warning),
            text("You have unsaved changes in your current profile. What would you like to do?")
                .size(14)
                .color(theme.fg_primary),
            row![
                button(text("Cancel").size(14))
                    .on_press(Message::CancelProfileSwitch)
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
                button(text("Discard").size(14))
                    .on_press(Message::DiscardProfileSwitch)
                    .padding([10, 20])
                    .style(move |_, status| danger_button(theme, status)),
                button(text("Save & Switch").size(14))
                    .on_press(Message::ConfirmProfileSwitch)
                    .padding([10, 24])
                    .style(move |_, status| primary_button(theme, status)),
            ]
            .spacing(12),
        ]
        .spacing(20)
        .padding(30)
        .max_width(500),
    )
    .style(move |_| {
        let mut style = card_container(theme);
        style.border = Border {
            color: theme.danger,
            width: 2.0,
            radius: 8.0.into(),
        };
        style
    })
    .into()
}

fn view_profile_manager<'a>(
    state: &'a State,
    mgr: &'a ProfileManagerState,
) -> Element<'a, Message> {
    let theme = &state.theme;

    let profiles_list: Element<'_, Message> = if state.available_profiles.is_empty() {
        text("No profiles found.").color(theme.fg_muted).into()
    } else {
        let mut list = column![].spacing(8);
        for name in &state.available_profiles {
            let is_active = name == &state.active_profile_name;

            let mut row_content = row![
                text(name)
                    .size(14)
                    .color(if is_active {
                        theme.accent
                    } else {
                        theme.fg_primary
                    })
                    .width(Length::Fill),
            ]
            .spacing(12)
            .align_y(Alignment::Center);

            if let Some((old, current)) = &mgr.renaming_name
                && old == name
            {
                row_content = row![
                    text_input("New name...", current)
                        .on_input(Message::ProfileNewNameChanged)
                        .on_submit(Message::ConfirmRenameProfile)
                        .padding(8)
                        .style(move |_, status| themed_text_input(theme, status))
                        .width(Length::Fill),
                    button(text("OK").size(12))
                        .on_press(Message::ConfirmRenameProfile)
                        .style(move |_, status| primary_button(theme, status)),
                    button(text("Cancel").size(12))
                        .on_press(Message::CancelRenameProfile)
                        .style(move |_, status| secondary_button(theme, status)),
                ]
                .spacing(8)
                .align_y(Alignment::Center);
            } else if let Some(del_name) = &mgr.deleting_name
                && del_name == name
            {
                row_content = row![
                    text("Delete profile?")
                        .size(12)
                        .color(theme.danger)
                        .width(Length::Fill),
                    button(text("No").size(12))
                        .on_press(Message::CancelDeleteProfile)
                        .style(move |_, status| secondary_button(theme, status)),
                    button(text("Yes, Delete").size(12))
                        .on_press(Message::ConfirmDeleteProfile)
                        .style(move |_, status| danger_button(theme, status)),
                ]
                .spacing(8)
                .align_y(Alignment::Center);
            } else if !is_active {
                row_content = row_content
                    .push(
                        button(text("✎").size(14))
                            .on_press(Message::RenameProfileRequested(name.clone()))
                            .style(button::text),
                    )
                    .push(
                        button(text("🗑").size(14))
                            .on_press(Message::DeleteProfileRequested(name.clone()))
                            .style(button::text),
                    );
            } else {
                row_content = row_content.push(text("(Active)").size(11).color(theme.fg_muted));
            }

            list = list.push(
                container(row_content)
                    .padding(12)
                    .style(move |_| card_container(theme)),
            );
        }
        scrollable(list).height(Length::Fixed(300.0)).into()
    };

    container(
        column![
            row![
                text("🗂 Profile Manager")
                    .size(24)
                    .font(state.font_regular)
                    .color(theme.accent),
                container(row![]).width(Length::Fill),
                button(text("×").size(20))
                    .on_press(Message::CloseProfileManager)
                    .style(button::text),
            ]
            .align_y(Alignment::Center),
            profiles_list,
            if mgr.creating_new {
                container(
                    row![
                        text_input("New profile name...", &mgr.new_name_input)
                            .on_input(Message::NewProfileNameChanged)
                            .on_submit(Message::SaveProfileAs(mgr.new_name_input.clone()))
                            .padding(8)
                            .style(move |_, status| themed_text_input(theme, status))
                            .width(Length::Fill),
                        button(text("Save").size(12))
                            .on_press(Message::SaveProfileAs(mgr.new_name_input.clone()))
                            .style(move |_, status| primary_button(theme, status)),
                        button(text("Cancel").size(12))
                            .on_press(Message::CancelCreatingNewProfile)
                            .style(move |_, status| secondary_button(theme, status)),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                )
                .padding(12)
                .style(move |_| card_container(theme))
            } else {
                container(
                    button(text("+ Add Profile from Current Rules").size(13))
                        .on_press(Message::StartCreatingNewProfile)
                        .width(Length::Fill)
                        .padding(12)
                        .style(move |_, status| secondary_button(theme, status)),
                )
                .width(Length::Fill)
            },
            row![
                button(text("Save Current Profile").size(13))
                    .on_press(Message::SaveProfileClicked)
                    .padding([10, 20])
                    .style(move |_, status| primary_button(theme, status)),
                container(row![]).width(Length::Fill),
                button(text("Close").size(13))
                    .on_press(Message::CloseProfileManager)
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
            ]
            .spacing(12)
        ]
        .spacing(20)
        .padding(32)
        .width(Length::Fixed(600.0)),
    )
    .style(move |_| card_container(theme))
    .into()
}
