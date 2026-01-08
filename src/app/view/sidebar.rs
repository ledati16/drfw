//! Sidebar with profile selector and rule list

use crate::app::ui_components::{
    active_card_container, active_tag_button, card_container, danger_button, popup_container,
    primary_button, secondary_button, section_header_container, sidebar_container, tag_button,
    themed_checkbox, themed_scrollable, themed_text_input,
};
use crate::app::{Message, State};
use iced::widget::text::Wrapping;
use iced::widget::{
    button, checkbox, column, container, mouse_area, row, rule, scrollable, text, text_input,
    tooltip, Id,
};
use iced::{Alignment, Border, Color, Element, Length};
use std::sync::Arc;

pub fn view_sidebar(state: &State) -> Element<'_, Message> {
    let theme = &state.theme;

    // 1. Profile Header (replaces branding for cleaner layout)
    let is_dirty = state.is_profile_dirty() || state.config_dirty;

    let profile_header = column![
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
        button(
            row![
                container(
                    text(&state.active_profile_name)
                        .size(14)
                        .font(state.font_regular)
                        .wrapping(Wrapping::None)
                )
                .width(Length::Fill)
                .clip(true),
                text(" ⚙")
                    .size(14)
                    .font(state.font_regular)
                    .color(theme.fg_muted)
            ]
            .align_y(Alignment::Center)
        )
        .on_press(Message::OpenProfileManager)
        .width(Length::Fill)
        .padding(8)
        .style(move |_, status| secondary_button(theme, status)),
        // Separator line after profile section
        container(
            container(row![])
                .height(Length::Fixed(1.0))
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(theme.border.into()),
                    ..Default::default()
                })
        )
        .padding(iced::Padding::new(0.0).top(8.0)),
    ]
    .spacing(8);

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
            button(text("All").size(10).font(state.font_regular))
                .on_press(Message::FilterByTag(None))
                .padding([4, 8])
                .style(move |_, status| {
                    if state.filter_tag.is_none() {
                        active_tag_button(theme, status)
                    } else {
                        tag_button(theme, status)
                    }
                })
                .into(),
        ];

        for tag in all_tags {
            let is_selected = state.filter_tag.as_ref() == Some(tag);
            // Truncate long tags for display (full tag still used for filtering)
            let display_tag: std::borrow::Cow<'_, str> = if tag.len() > 16 {
                format!("{}…", &tag[..15]).into()
            } else {
                tag.as_str().into()
            };
            tag_elements.push(
                button(text(display_tag).size(10).font(state.font_regular))
                    // Arc::clone just copies pointer (cheap!), not string data
                    .on_press(Message::FilterByTag(Some(Arc::clone(tag))))
                    .padding([4, 8])
                    .style(move |_, status| {
                        if is_selected {
                            active_tag_button(theme, status)
                        } else {
                            tag_button(theme, status)
                        }
                    })
                    .into(),
            );
        }

        let tags_row = row(tag_elements).spacing(6).wrap();

        // Scrollable tag cloud with embedded scrollbar (STYLE.md Section 17)
        // Use Shrink height + max_height so it only takes needed space
        // Scrollbar::spacing(8) creates gap between content and scrollbar
        let scrollable_tags = scrollable(
            container(tags_row).width(Length::Fill),
        )
        .direction(scrollable::Direction::Vertical(
            scrollable::Scrollbar::new().spacing(8),
        ))
        .height(Length::Shrink)
        .style(move |_, status| themed_scrollable(theme, status));

        column![
            container(
                text("FILTERS")
                    .size(9)
                    .font(state.font_mono)
                    .color(theme.fg_muted)
            )
            .padding([2, 6])
            .style(move |_| section_header_container(theme)),
            container(scrollable_tags).max_height(120)
        ]
        .spacing(8)
        .into()
    };

    let search_area = column![
        text_input("Search rules...", &state.rule_search)
            .on_input(Message::RuleSearchChanged)
            .padding(10)
            .size(13)
            .font(state.font_regular)
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
                        .font(state.font_regular)
                        .color(theme.danger)
                        .width(Length::Fill),
                    button(text("Cancel").size(11).font(state.font_regular))
                        .on_press(Message::CancelDelete)
                        .padding([4, 10])
                        .style(move |_, status| secondary_button(theme, status)),
                    button(text("Delete").size(11).font(state.font_regular))
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
                    // Phase 2.3: Use cached action_display string (no allocation)
                    Some(
                        container(
                            text(&rule.action_display)
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
                                .font(state.font_regular)
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
                        button(
                            text("×")
                                .size(14)
                                .font(state.font_regular)
                                .color(theme.fg_muted)
                        )
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
                if rule.interface.is_some() {
                    // Phase 2.3: Use cached interface_display string (no allocation)
                    detail_items.push(
                        container(
                            text(&rule.interface_display)
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
                row![
                    text("+").size(18).font(state.font_regular),
                    text("Add Access Rule").size(14).font(state.font_regular)
                ]
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
            profile_header,
            search_area,
            column![
                list_header,
                scrollable(
                    container(rule_list)
                        .width(Length::Fill)
                        .padding(iced::Padding::new(0.0).bottom(4.0)),
                )
                .id(Id::new(super::SIDEBAR_SCROLLABLE_ID))
                .direction(scrollable::Direction::Vertical(
                    scrollable::Scrollbar::new().spacing(8),
                ))
                .height(Length::Fill)
                .style(move |_, status| themed_scrollable(theme, status)),
            ]
            .spacing(8)
            .height(Length::Fill),
            footer,
        ]
        .spacing(16)
        .padding(16),
    )
    .width(Length::Fixed(330.0))
    .height(Length::Fill)
    .style(move |_| sidebar_container(theme))
    .into()
}
