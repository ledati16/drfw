//! Sidebar with profile selector and rule list

use std::sync::Arc;

use iced::widget::text::Wrapping;
use iced::widget::{
    Id, button, checkbox, column, container, mouse_area, row, rule, scrollable, text, text_input,
    tooltip,
};
use iced::{Alignment, Border, Color, Element, Length};

use crate::app::ui_components::{
    active_card_container, active_tag_button, card_container, danger_button, inset_container,
    popup_container, primary_button, secondary_button, section_header_container, sidebar_container,
    tag_button, themed_checkbox, themed_horizontal_rule, themed_scrollable, themed_text_input,
};
use crate::app::{InactiveReason, Message, State};

/// Persistent notice for a profile that could not be loaded (read-only), with
/// the explanation and the "Start fresh" action. Empty when not read-only.
fn read_only_notice(state: &State) -> Element<'_, Message> {
    let theme = &state.theme;
    let Some(issue) = &state.unreadable_profile else {
        return column![].into();
    };
    container(
        column![
            text(&issue.reason)
                .size(11)
                .font(state.font_regular)
                .color(theme.danger),
            text(match &issue.backup {
                Some(_) =>
                    "A copy of the file was saved next to it (.corrupt-…). \
                            Editing is disabled until you switch profiles or start fresh.",
                None => "Editing is disabled until you switch profiles or start fresh.",
            })
            .size(11)
            .font(state.font_regular)
            .color(theme.fg_muted),
            button(text("Start fresh").size(12).font(state.font_regular))
                .on_press(Message::StartFreshProfile)
                .padding([6, 12])
                .style(move |_, status| danger_button(theme, status)),
        ]
        .spacing(6),
    )
    .padding(8)
    .width(Length::Fill)
    .style(move |_| inset_container(theme))
    .into()
}

/// Small "INVALID" badge whose tooltip lists why the rule can't be applied.
fn invalid_badge<'a>(state: &'a State, reasons: &'a str) -> Element<'a, Message> {
    let theme = &state.theme;
    tooltip(
        container(
            text("INVALID")
                .size(9)
                .font(state.font_mono)
                .color(theme.danger)
                .wrapping(Wrapping::None),
        )
        .padding([2, 6])
        .style(move |_| container::Style {
            border: Border {
                radius: 4.0.into(),
                color: theme.danger,
                width: 1.0,
            },
            ..Default::default()
        }),
        container(
            text(reasons)
                .size(12)
                .font(state.font_regular)
                .color(theme.fg_primary),
        )
        .padding([6, 10])
        .max_width(280.0)
        .style(move |_| popup_container(theme)),
        tooltip::Position::Bottom,
    )
    .into()
}

/// Explains why an Output-chain rule does nothing in Desktop mode.
const INACTIVE_OUTPUT_TOOLTIP: &str = "Desktop mode allows all outgoing traffic, so outbound \
     (Output chain) rules are not applied. Enable Server Mode in Settings to use them, \
     or edit the rule to make it inbound.";

/// Explains why a Forwarded rule does nothing while forwarding is not blocked.
const INACTIVE_FORWARD_TOOLTIP: &str = "Forwarded traffic is accepted while \"Block forwarded \
     traffic\" is off, so Forwarded rules are not applied. Turn it on in Settings to use them.";

/// Small "INACTIVE …" badge with a tooltip explaining why.
fn inactive_badge(state: &State, reason: InactiveReason) -> Element<'_, Message> {
    let theme = &state.theme;
    let (label, explanation) = match reason {
        InactiveReason::DesktopMode => ("INACTIVE IN DESKTOP MODE", INACTIVE_OUTPUT_TOOLTIP),
        InactiveReason::ForwardingNotBlocked => (
            "INACTIVE (FORWARDING NOT BLOCKED)",
            INACTIVE_FORWARD_TOOLTIP,
        ),
    };
    tooltip(
        container(
            text(label)
                .size(9)
                .font(state.font_mono)
                .color(theme.warning)
                .wrapping(Wrapping::None),
        )
        .padding([2, 6])
        .style(move |_| container::Style {
            border: Border {
                radius: 4.0.into(),
                color: theme.warning,
                width: 1.0,
            },
            ..Default::default()
        }),
        container(
            text(explanation)
                .size(12)
                .font(state.font_regular)
                .color(theme.fg_primary),
        )
        .padding([6, 10])
        .max_width(280.0)
        .style(move |_| popup_container(theme)),
        tooltip::Position::Bottom,
    )
    .into()
}

/// The "Add from template" menu: one button per template that applies to
/// this computer's interfaces (entries and their text built when the menu
/// opened), or a note that none does.
fn template_menu<'a>(
    state: &'a State,
    menu: &'a crate::app::templates::TemplateMenu,
    edits_locked: bool,
) -> Element<'a, Message> {
    let theme = &state.theme;
    let mut items = column![
        container(
            text("ADD FROM TEMPLATE")
                .size(9)
                .font(state.font_mono)
                .color(theme.fg_muted)
        )
        .padding([2, 6])
        .style(move |_| section_header_container(theme)),
    ]
    .spacing(6);
    if menu.entries.is_empty() {
        items = items.push(
            text(crate::app::templates::NO_TEMPLATES)
                .size(11)
                .font(state.font_regular)
                .color(theme.fg_muted),
        );
    }
    for (index, entry) in menu.entries.iter().enumerate() {
        let mut content = column![
            text(&entry.title).size(13).font(state.font_regular),
            text(entry.detail)
                .size(11)
                .font(state.font_regular)
                .color(theme.fg_muted),
        ]
        .spacing(2);
        for note in &entry.notes {
            content = content.push(
                text(note)
                    .size(11)
                    .font(state.font_regular)
                    .color(theme.warning),
            );
        }
        if entry.already_added {
            content = content.push(
                text(crate::app::templates::ALREADY_ADDED)
                    .size(11)
                    .font(state.font_regular)
                    .color(theme.fg_muted),
            );
        }
        items = items.push(
            button(content)
                .width(Length::Fill)
                .padding([8, 10])
                .style(move |_, status| secondary_button(theme, status))
                .on_press_maybe(
                    (!edits_locked && !entry.already_added).then_some(Message::AddTemplate(index)),
                ),
        );
    }
    container(items)
        .padding(8)
        .width(Length::Fill)
        .style(move |_| inset_container(theme))
        .into()
}

pub fn view_sidebar(state: &State) -> Element<'_, Message> {
    let theme = &state.theme;

    // 1. Profile Header (replaces branding for cleaner layout). Only the
    // profile counts: settings are saved separately and say so if they fail.
    let is_dirty = state.profile_dirty || state.is_profile_dirty();
    // The apply flow owns the ruleset: no form can be opened meanwhile
    let edits_locked = crate::app::handlers::edits_locked(state);

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
            if state.unreadable_profile.is_some() {
                text("Read-only")
                    .size(9)
                    .font(state.font_mono)
                    .color(theme.danger)
            } else if state.profile_save_error.is_some() {
                text("Save failed")
                    .size(9)
                    .font(state.font_mono)
                    .color(theme.danger)
            } else if is_dirty {
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
        read_only_notice(state),
        // Separator line after profile section
        container(rule::horizontal(1).style(move |_| themed_horizontal_rule(theme)))
            .padding(iced::Padding::new(0.0).top(8.0)),
    ]
    .spacing(8);

    // 2. Filter Logic & Tag Collection (cached tags and filtered indices)
    let all_tags = &state.cached_all_tags;

    // Pre-filtered rule indices (updated in update(), not every frame!)
    let filtered_rules = &state.cached_filtered_rule_indices;

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

        // Performance: Use cached truncated tags (avoids format! every frame)
        // Iterate both original tags (for filter message) and truncated (for display)
        for (tag, truncated) in all_tags.iter().zip(&state.cached_all_tags_truncated) {
            let is_selected = state.filter_tag.as_ref() == Some(tag);
            tag_elements.push(
                button(text(truncated).size(10).font(state.font_regular))
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
        let scrollable_tags = scrollable(container(tags_row).width(Length::Fill))
            .id(Id::new(super::SIDEBAR_TAGS_SCROLLABLE_ID))
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
            container(scrollable_tags)
                .max_height(120)
                .padding(6)
                .style(move |_| inset_container(theme))
        ]
        .spacing(8)
        .into()
    };

    let search_area = column![
        text_input("Search rules...", &state.rule_search)
            .id(crate::app::focus::RULE_SEARCH)
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
        // Performance: Use cached filter_count_display (avoids format! every frame)
        text(&state.filter_count_display)
            .size(9)
            .font(state.font_mono)
            .color(theme.fg_muted),
    ]
    .align_y(Alignment::Center);

    // Why the ruleset can't be applied right now (cached in update())
    let list_header: Element<'_, Message> = match &state.cached_validation_notice {
        Some(notice) => column![
            list_header,
            text(notice)
                .size(11)
                .font(state.font_regular)
                .color(theme.danger)
        ]
        .spacing(4)
        .into(),
        None => list_header.into(),
    };

    // 5. Rule List (Scrollable)
    let rule_list: Element<'_, Message> = if filtered_rules.is_empty() {
        container(
            column![
                text(if state.ruleset.rules.is_empty() {
                    "No rules yet. Add one with \"Add Access Rule\"."
                } else {
                    "No matching rules."
                })
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
        // Pre-allocate the Vec
        let mut rule_cards = Vec::with_capacity(filtered_rules.len());

        for &rule_index in filtered_rules {
            let Some(rule) = state.ruleset.rules.get(rule_index) else {
                continue;
            };
            // Listed but not applied (Output rule in Desktop mode): dimmed like
            // a disabled rule, with a badge explaining why
            let inactive = state.inactive_reason(rule);
            let is_inactive = inactive.is_some();
            let looks_enabled = rule.enabled && !is_inactive;
            let is_editing = state.rule_form.as_ref().and_then(|f| f.id) == Some(rule.id);
            let is_deleting = state.deleting_id == Some(rule.id);
            let is_being_dragged = state.dragged_rule_id == Some(rule.id);
            let any_drag_active = state.dragged_rule_id.is_some();
            let is_hover_target = state.hovered_drop_target_id == Some(rule.id);
            // When drag is active and this card is a potential drop target,
            // all click handlers should trigger RuleDropped instead of their normal action
            let is_drop_target = any_drag_active && !is_being_dragged;
            // Click on the card: drop during a drag, else edit (not while locked)
            let card_click = if is_drop_target {
                Some(Message::RuleDropped(rule.id))
            } else {
                (!edits_locked).then_some(Message::EditRuleClicked(rule.id))
            };

            let card_content: Element<'_, Message> = if is_deleting {
                row![
                    text("Delete this rule?")
                        .size(12)
                        .font(state.font_regular)
                        .color(theme.danger)
                        .width(Length::Fill),
                    button(text("Cancel").size(12).font(state.font_regular))
                        .on_press(Message::CancelDelete)
                        .padding([4, 10])
                        .style(move |_, status| secondary_button(theme, status)),
                    button(text("Delete").size(12).font(state.font_regular))
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

                // Protocol/Port badge (with chain arrow in Server Mode), cached in
                // update() so no format! runs per frame
                let badge_text = state
                    .cached_rule_badges
                    .get(rule_index)
                    .unwrap_or(&rule.badge_display);

                let badge = container(
                    text(badge_text)
                        .size(9)
                        .font(state.font_mono)
                        .color(if looks_enabled {
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
                    // Cached action_display string (no allocation)
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
                let is_enabled = looks_enabled;
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
                // Performance: Use cached tags_truncated (avoids format! every frame)
                // Note: Display-only tag badges use 3.0px radius (smaller than interactive
                // tag_button's 4.0px) for visual hierarchy - badges are compact indicators,
                // not clickable controls.
                for truncated_tag in &rule.tags_truncated {
                    tag_items.push(
                        container(
                            text(truncated_tag)
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
                    tooltip(
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
                        container(
                            text("Click to reorder")
                                .size(12)
                                .font(state.font_regular)
                                .color(theme.fg_primary)
                        )
                        .padding([6, 10])
                        .style(move |_| popup_container(theme)),
                        tooltip::Position::Top
                    )
                    .delay(std::time::Duration::from_millis(1000)),
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
                                .color(if looks_enabled {
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
                    .on_press_maybe(card_click.clone())
                    .padding(0)
                    .style(button::text),
                    // Accent Line (Absorbs all remaining space)
                    rule::horizontal(1).style(move |_| themed_horizontal_rule(theme)),
                    // Management Cluster (Always stays on far right)
                    {
                        // Checkbox: disable interaction during drag (clicks fall through to mouse_area)
                        let cb = checkbox(rule.enabled)
                            .size(16)
                            .spacing(0)
                            .style(move |_, status| themed_checkbox(theme, status));
                        let cb: Element<'_, Message> = if is_drop_target {
                            cb.into() // Non-interactive during drag
                        } else {
                            cb.on_toggle(move |_| Message::ToggleRuleEnabled(rule.id))
                                .into()
                        };

                        // Delete button: redirect to drop during drag
                        let delete_btn = button(
                            text("×")
                                .size(14)
                                .font(state.font_regular)
                                .color(theme.fg_muted),
                        )
                        .on_press(if is_drop_target {
                            Message::RuleDropped(rule.id)
                        } else {
                            Message::DeleteRuleRequested(rule.id)
                        })
                        .padding(6)
                        .style(button::text);

                        row![cb, delete_btn].spacing(8).align_y(Alignment::Center)
                    },
                ]
                .spacing(8)
                .padding([0, 8]) // Add horizontal padding to match other rows
                .align_y(Alignment::Center);

                // Row 2: Detail Row (Interface, Action, Protocol/Ports) - now full width
                // Re-build detail_items to ensure interface is far left and protocol is far right
                let mut detail_items: Vec<Element<'_, Message>> = Vec::with_capacity(4);

                // 1. Interface (Far Left)
                if rule.interface.is_some() {
                    // Cached interface_display string (no allocation)
                    detail_items.push(
                        container(
                            text(&rule.interface_display)
                                .size(9)
                                .font(state.font_mono)
                                .color(if looks_enabled {
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

                // Invalid-rule badge; reasons in the tooltip (cached in update())
                if let Some(reasons) = state.cached_rule_issues.get(&rule.id) {
                    detail_items.push(invalid_badge(state, reasons));
                }

                // Output rule in Desktop mode: listed but not applied
                if let Some(reason) = inactive {
                    detail_items.push(inactive_badge(state, reason));
                }

                // 3. Spacer (Fills middle to push protocol to right)
                detail_items.push(container(column![]).width(Length::Fill).into());

                // 4. Protocol Badge (Far Right)
                detail_items.push(badge.into());

                let details_row = button(
                    container(row(detail_items).spacing(8).align_y(Alignment::Center))
                        .width(Length::Fill),
                )
                .on_press_maybe(card_click.clone())
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
                    .on_press_maybe(card_click.clone())
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

                // Dim the card if the rule is disabled or inactive in this mode
                if !looks_enabled && !is_editing && !is_being_dragged && !is_hover_target {
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

    // 6. Sidebar Footer (Pinned Action), with the template menu above it
    let menu_open = state.template_menu.is_some();
    let mut footer = column![rule::horizontal(1).style(move |_| themed_horizontal_rule(theme))];
    if let Some(menu) = &state.template_menu {
        footer = footer.push(
            container(template_menu(state, menu, edits_locked))
                .padding(iced::Padding::new(0.0).top(12.0)),
        );
    }
    footer = footer.push(
        container(
            row![
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
                .on_press_maybe((!edits_locked).then_some(Message::AddRuleClicked)),
                tooltip(
                    button(
                        text(if menu_open { "▴" } else { "▾" })
                            .size(16)
                            .font(state.font_regular)
                    )
                    .padding([14, 12])
                    .style(move |_, status| secondary_button(theme, status))
                    // Closing always works (B.L4); opening only while edits are allowed
                    .on_press_maybe(
                        (menu_open || !edits_locked)
                            .then_some(Message::ToggleTemplateMenu(!menu_open))
                    ),
                    container(
                        text("Add from template")
                            .size(12)
                            .font(state.font_regular)
                            .color(theme.fg_primary)
                    )
                    .padding([6, 10])
                    .style(move |_| popup_container(theme)),
                    tooltip::Position::Top
                )
                .delay(std::time::Duration::from_millis(500)),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        )
        .padding(iced::Padding::new(0.0).top(16.0)),
    );

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
