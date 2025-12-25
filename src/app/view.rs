use crate::app::ui_components::{
    ACCENT, DANGER, GRUV_AQUA, GRUV_BG2, GRUV_BLUE, GRUV_FG0, GRUV_ORANGE, GRUV_PURPLE,
    GRUV_YELLOW, SUCCESS, TEXT_BRIGHT, TEXT_DIM, active_card_button, active_tab_button,
    card_button, card_container, danger_button, dirty_button, hovered_card_button, main_container,
    pill_container, primary_button, section_header_container, sidebar_container,
};
use crate::app::{
    AppStatus, FONT_MONO, FONT_REGULAR, Message, PendingWarning, PersistenceStatus, RuleForm,
    State, WorkspaceTab,
};
use crate::core::firewall::{PRESETS, Protocol};
use iced::widget::{
    button, checkbox, column, container, horizontal_rule, pick_list, row, scrollable, stack, text,
    text_input, toggler, vertical_rule,
};
use iced::{Alignment, Border, Color, Element, Length};

#[allow(clippy::too_many_lines)]
pub fn view(state: &State) -> Element<'_, Message> {
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
                view_diff_text(diff).into()
            } else {
                view_highlighted_nft(&state.cached_nft_text).into()
            }
        }
        WorkspaceTab::Json => {
            let json = serde_json::to_string_pretty(&state.ruleset.to_nftables_json())
                .unwrap_or_else(|e| e.to_string());
            text(json).font(FONT_MONO).size(13).color(GRUV_FG0).into()
        }
        WorkspaceTab::Settings => view_settings(state),
    };

    let workspace = view_workspace(state, preview_content);

    let content = row![sidebar, workspace];

    let overlay = if let Some(warning) = &state.pending_warning {
        Some(
            container(view_warning_modal(warning))
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
                container(view_awaiting_apply())
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
                container(view_pending_confirmation(state.countdown_remaining))
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
        .style(main_container);

    let with_overlay = if let Some(overlay) = overlay {
        stack![base, overlay].into()
    } else {
        base.into()
    };

    // Diagnostics modal overlay
    let with_diagnostics = if state.show_diagnostics {
        stack![
            with_overlay,
            container(view_diagnostics_modal())
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
            container(view_export_modal())
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
            container(view_shortcuts_help())
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
    let branding = container(column![
        row![
            container(text("🛡️").size(28).color(GRUV_PURPLE)).padding(4),
            column![
                text("DRFW").size(24).font(FONT_REGULAR).color(GRUV_PURPLE),
                text("DUMB RUST FIREWALL")
                    .size(9)
                    .color(TEXT_DIM)
                    .font(FONT_MONO),
            ]
            .spacing(0)
        ]
        .spacing(12)
        .align_y(Alignment::Center)
    ])
    .padding(iced::Padding::new(0.0).bottom(10.0));

    let system_health = container(
        column![
            text("SYSTEM STATUS")
                .size(10)
                .color(TEXT_DIM)
                .font(FONT_REGULAR),
            view_status_pill(&state.status),
            view_persistence_pill(state.persistence_status),
        ]
        .spacing(8),
    )
    .padding(16)
    .style(section_header_container);

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
    .style(primary_button)
    .on_press(Message::AddRuleClicked);

    let filtered_rules: Vec<_> = state
        .ruleset
        .rules
        .iter()
        .filter(|r| {
            state.rule_search.is_empty()
                || r.label
                    .to_lowercase()
                    .contains(&state.rule_search.to_lowercase())
                || r.protocol
                    .to_string()
                    .contains(&state.rule_search.to_lowercase())
        })
        .collect();

    let metrics = row![
        text(format!(
            "Showing {} of {}",
            filtered_rules.len(),
            state.ruleset.rules.len()
        ))
        .size(10)
        .color(TEXT_DIM)
        .font(FONT_MONO),
    ]
    .width(Length::Fill)
    .align_y(Alignment::Center);

    let rule_list: Element<'_, Message> = if filtered_rules.is_empty() {
        container(
            column![
                text("No matching rules.")
                    .size(13)
                    .color(TEXT_DIM)
                    .font(FONT_REGULAR),
                if state.ruleset.rules.is_empty() {
                    text("Click '+' to add your first rule.")
                        .size(11)
                        .color(TEXT_DIM)
                } else {
                    text("").size(0)
                }
            ]
            .spacing(10)
            .align_x(Alignment::Center),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
    } else {
        filtered_rules
            .into_iter()
            .fold(column![].spacing(12), |col, rule| {
                let is_editing = state.rule_form.as_ref().and_then(|f| f.id) == Some(rule.id);
                let is_deleting = state.deleting_id == Some(rule.id);

                let card_content: Element<'_, Message> = if is_deleting {
                    row![
                        text("Delete?").size(12).color(DANGER).width(Length::Fill),
                        button(text("No").size(11))
                            .on_press(Message::CancelDelete)
                            .padding(6)
                            .style(button::secondary),
                        button(text("Yes").size(11))
                            .on_press(Message::DeleteRule(rule.id))
                            .padding(6)
                            .style(danger_button),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center)
                    .padding(iced::Padding::new(10.0))
                    .into()
                } else {
                    row![
                        container(column![])
                            .width(Length::Fixed(4.0))
                            .height(Length::Fill)
                            .style(move |_| container::Style {
                                background: Some(
                                    (if rule.enabled { GRUV_AQUA } else { TEXT_DIM }).into()
                                ),
                                border: Border {
                                    radius: 2.0.into(),
                                    ..Default::default()
                                },
                                ..Default::default()
                            }),
                        toggler(rule.enabled)
                            .on_toggle(move |_| Message::ToggleRuleEnabled(rule.id))
                            .size(14)
                            .width(Length::Shrink),
                        button(
                            row![
                                container(
                                    text(match rule.protocol {
                                        Protocol::Tcp => "🌐",
                                        Protocol::Udp => "⚡",
                                        Protocol::Any => "🔗",
                                        _ => "🛠️",
                                    })
                                    .size(14)
                                    .color(if rule.enabled { GRUV_BLUE } else { TEXT_DIM })
                                )
                                .padding(6)
                                .style(|_| container::Style {
                                    background: Some(GRUV_BG2.into()),
                                    border: Border {
                                        radius: 6.0.into(),
                                        ..Default::default()
                                    },
                                    ..Default::default()
                                }),
                                column![
                                    text(if rule.label.is_empty() {
                                        "Unnamed Rule"
                                    } else {
                                        &rule.label
                                    })
                                    .size(13)
                                    .font(FONT_REGULAR)
                                    .color(if rule.enabled { GRUV_YELLOW } else { TEXT_DIM }),
                                    text(format!(
                                        "{}/{}",
                                        rule.protocol,
                                        rule.ports.as_ref().map_or_else(
                                            || "any".to_string(),
                                            std::string::ToString::to_string
                                        )
                                    ))
                                    .size(10)
                                    .color(TEXT_DIM)
                                    .font(FONT_MONO),
                                ]
                                .width(Length::Fill)
                                .spacing(1),
                            ]
                            .spacing(10)
                            .align_y(Alignment::Center)
                        )
                        .padding(0)
                        .style(button::text)
                        .on_press(Message::EditRuleClicked(rule.id)),
                        row![
                            column![
                                button(text("⏫").size(8))
                                    .on_press(Message::MoveRuleToTop(rule.id))
                                    .padding(2)
                                    .style(button::text),
                                button(text("▲").size(10))
                                    .on_press(Message::MoveRuleUp(rule.id))
                                    .padding(2)
                                    .style(button::text),
                            ]
                            .spacing(1),
                            column![
                                button(text("▼").size(10))
                                    .on_press(Message::MoveRuleDown(rule.id))
                                    .padding(2)
                                    .style(button::text),
                                button(text("⏬").size(8))
                                    .on_press(Message::MoveRuleToBottom(rule.id))
                                    .padding(2)
                                    .style(button::text),
                            ]
                            .spacing(1),
                        ]
                        .spacing(4),
                        button(text("×").size(14))
                            .on_press(Message::DeleteRuleRequested(rule.id))
                            .padding(4)
                            .style(button::text),
                    ]
                    .padding(iced::Padding {
                        top: 8.0,
                        right: 12.0,
                        bottom: 8.0,
                        left: 8.0,
                    })
                    .align_y(Alignment::Center)
                    .spacing(8)
                    .into()
                };

                col.push(
                    button(container(card_content))
                        .padding(0)
                        .style(move |theme, status| {
                            if is_editing {
                                active_card_button(theme, status)
                            } else if status == button::Status::Hovered {
                                hovered_card_button(theme, status)
                            } else {
                                card_button(theme, status)
                            }
                        })
                        .on_press(Message::EditRuleClicked(rule.id)),
                )
            })
            .into()
    };

    container(
        column![
            branding,
            system_health,
            horizontal_rule(1),
            text("NETWORK ACCESS")
                .size(10)
                .color(TEXT_DIM)
                .font(FONT_REGULAR),
            search_bar,
            metrics,
            scrollable(rule_list).height(Length::Fill),
            add_button,
        ]
        .spacing(20)
        .padding(24),
    )
    .width(Length::Fixed(320.0))
    .height(Length::Fill)
    .style(sidebar_container)
    .into()
}

#[allow(clippy::too_many_lines)]
fn view_workspace<'a>(
    state: &'a State,
    preview_content: Element<'a, Message>,
) -> Element<'a, Message> {
    let tab_bar = row![
        view_tab_button("nftables.conf", WorkspaceTab::Nftables, state.active_tab),
        view_tab_button("JSON Payload", WorkspaceTab::Json, state.active_tab),
        view_tab_button("Settings", WorkspaceTab::Settings, state.active_tab),
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
            .color(GRUV_ORANGE),
            text(match state.active_tab {
                WorkspaceTab::Nftables => "Current nftables ruleset generated from your rules.",
                WorkspaceTab::Json => "Low-level JSON representation for debugging or automation.",
                WorkspaceTab::Settings =>
                    "Optional security features for advanced users and server deployments.",
            })
            .size(12)
            .color(TEXT_DIM),
        ]
        .spacing(4)
        .width(Length::Fill),
    ];

    // Add diff toggle when on Nftables tab and we have a previous version
    if state.active_tab == WorkspaceTab::Nftables && state.last_applied_ruleset.is_some() {
        preview_header_row = preview_header_row.push(
            checkbox("Show diff", state.show_diff)
                .on_toggle(Message::ToggleDiff)
                .size(16)
                .text_size(13)
                .spacing(8),
        );
    }

    let preview_header = preview_header_row.push(tab_bar).align_y(Alignment::Center);

    let editor = container(scrollable(container(preview_content).padding(24)))
        .width(Length::Fill)
        .height(Length::Fill)
        .style(|_| container::Style {
            background: Some(Color::from_rgb(0.11, 0.11, 0.11).into()),
            border: Border {
                radius: 12.0.into(),
                color: GRUV_BG2,
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
            .style(primary_button)
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
            btn = btn.style(dirty_button);
        } else {
            btn = btn.style(primary_button);
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
        horizontal_rule(1),
        if let Some(ref err) = state.last_error {
            view_error_display(err)
        } else {
            row![].into()
        },
        horizontal_rule(1),
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
    .height(Length::Fill)
    .into()
}

fn view_tab_button(
    label: &str,
    tab: WorkspaceTab,
    active_tab: WorkspaceTab,
) -> Element<'_, Message> {
    let is_active = tab == active_tab;
    button(text(label).size(13))
        .padding([8, 16])
        .style(if is_active {
            active_tab_button
        } else {
            button::secondary
        })
        .on_press(Message::TabChanged(tab))
        .into()
}

fn view_highlighted_nft(content: &str) -> iced::widget::Column<'_, Message> {
    let mut lines = column![].spacing(2);
    for (i, line) in content.lines().enumerate() {
        let mut row_content = row![].spacing(0);

        row_content = row_content.push(
            container(
                text(format!("{:3} ", i + 1))
                    .font(FONT_MONO)
                    .size(11)
                    .color(Color::from_rgb(0.4, 0.4, 0.4)),
            )
            .padding(iced::Padding::new(0.0).right(10.0)),
        );

        row_content = row_content.push(vertical_rule(1));

        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if !line.is_empty() {
            row_content = row_content.push(
                text(format!("  {}", " ".repeat(indent)))
                    .font(FONT_MONO)
                    .size(13),
            );
        }

        if trimmed.starts_with('#') {
            row_content = row_content.push(text(trimmed).font(FONT_MONO).size(13).color(TEXT_DIM));
        } else {
            for word in trimmed.split_inclusive(' ') {
                let word_trim = word.trim();
                let color = match word_trim {
                    "table" | "chain" | "type" | "hook" | "priority" | "policy" => GRUV_AQUA,
                    "accept" => SUCCESS,
                    "drop" | "reject" => DANGER,
                    "ip" | "ip6" | "tcp" | "udp" | "icmp" | "icmpv6" | "meta" | "ct" | "inet" => {
                        GRUV_BLUE
                    }
                    "dport" | "saddr" | "iifname" | "state" | "comment" => GRUV_YELLOW,
                    _ if word_trim.contains('"')
                        || word_trim.parse::<u16>().is_ok()
                        || word_trim.contains('/') =>
                    {
                        GRUV_YELLOW
                    }
                    _ => GRUV_FG0,
                };
                let is_keyword =
                    matches!(word_trim, "table" | "chain" | "accept" | "drop" | "reject");
                row_content = row_content.push(
                    text(word)
                        .font(if is_keyword { FONT_REGULAR } else { FONT_MONO })
                        .size(13)
                        .color(color),
                );
            }
        }
        lines = lines.push(row_content);
    }
    lines
}

fn view_diff_text(diff_content: &str) -> iced::widget::Column<'static, Message> {
    let mut lines = column![].spacing(2);

    for (i, line) in diff_content.lines().enumerate() {
        let mut row_content = row![].spacing(0);

        // Line number
        let line_num = format!("{:3} ", i + 1);
        row_content = row_content.push(
            container(
                text(line_num)
                    .font(FONT_MONO)
                    .size(11)
                    .color(Color::from_rgb(0.4, 0.4, 0.4)),
            )
            .padding(iced::Padding::new(0.0).right(10.0)),
        );

        row_content = row_content.push(vertical_rule(1));

        // Determine color based on diff prefix and own the string
        let (color, content) = if line.starts_with("+ ") {
            (SUCCESS, line.to_string())  // Green for additions
        } else if line.starts_with("- ") {
            (DANGER, line.to_string())   // Red for deletions
        } else {
            (GRUV_FG0, line.to_string()) // Normal for unchanged
        };

        row_content = row_content.push(
            text(format!("  {}", content))
                .font(FONT_MONO)
                .size(13)
                .color(color),
        );

        lines = lines.push(row_content);
    }

    lines
}

fn view_pill<'a>(
    label: &'a str,
    color: Color,
    action: Option<(&'a str, Message)>,
) -> Element<'a, Message> {
    let content = row![
        container(column![]).width(8).height(8).style(move |_| {
            container::Style {
                background: Some(color.into()),
                border: Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }
        }),
        text(label).size(12).font(FONT_REGULAR).color(color),
    ]
    .spacing(10)
    .align_y(Alignment::Center);

    let pill = container(content).padding([6, 12]).style(pill_container);

    if let Some((action_label, msg)) = action {
        column![
            pill,
            button(text(action_label).size(11))
                .on_press(msg)
                .style(button::text)
        ]
        .spacing(4)
        .align_x(Alignment::Center)
        .into()
    } else {
        pill.into()
    }
}

fn view_status_pill(status: &AppStatus) -> Element<'_, Message> {
    let (label, color) = match status {
        AppStatus::Idle => ("System Protected", SUCCESS),
        AppStatus::Verifying => ("Verifying Rules...", ACCENT),
        AppStatus::Applying => ("Applying...", ACCENT),
        AppStatus::AwaitingApply => ("Ready to Commit", ACCENT),
        AppStatus::PendingConfirmation { .. } => ("Pending Verification", ACCENT),
        AppStatus::Error(_) => ("Error Detected", DANGER),
        _ => ("Operational", SUCCESS),
    };
    view_pill(label, color, None)
}

fn view_persistence_pill(status: PersistenceStatus) -> Element<'static, Message> {
    let (label, color, action) = match status {
        PersistenceStatus::Enabled => ("Boot Persistence: ON", SUCCESS, None),
        PersistenceStatus::Disabled => (
            "Boot Persistence: OFF",
            GRUV_ORANGE,
            Some(("Enable at Boot", Message::EnablePersistenceClicked)),
        ),
        PersistenceStatus::NotInstalled => ("nftables not found", DANGER, None),
        PersistenceStatus::Unknown => ("Checking Persistence...", TEXT_DIM, None),
    };
    view_pill(label, color, action)
}

#[allow(clippy::too_many_lines)]
fn view_rule_form<'a>(
    form: &'a RuleForm,
    errors: Option<&'a crate::app::FormErrors>,
    interfaces: &'a [String],
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
                .color(GRUV_AQUA),
            text("Define allowed traffic patterns.")
                .size(12)
                .color(TEXT_DIM)
        ]
        .spacing(4),
        column![
            container(text("BASIC INFO").size(10).color(TEXT_BRIGHT))
                .padding([4, 8])
                .style(section_header_container),
            column![
                text("DESCRIPTION").size(10).color(TEXT_DIM),
                text_input("e.g. Local Web Server", &form.label)
                    .on_input(Message::RuleFormLabelChanged)
                    .padding(10)
            ]
            .spacing(6),
            column![
                text("SERVICE PRESET").size(10).color(TEXT_DIM),
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
            container(text("TECHNICAL DETAILS").size(10).color(TEXT_BRIGHT))
                .padding([4, 8])
                .style(section_header_container),
            row![
                column![
                    text("PROTOCOL").size(10).color(TEXT_DIM),
                    pick_list(
                        vec![
                            Protocol::Any,
                            Protocol::Tcp,
                            Protocol::Udp,
                            Protocol::Icmp,
                            Protocol::Icmpv6
                        ],
                        Some(form.protocol.clone()),
                        Message::RuleFormProtocolChanged
                    )
                    .width(Length::Fill)
                    .padding(10)
                ]
                .spacing(6)
                .width(Length::Fill),
                column![
                    text("PORT RANGE").size(10).color(TEXT_DIM),
                    view_port_inputs(form, port_error),
                    if let Some(err) = port_error {
                        text(err).size(11).color(DANGER)
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
            container(text("CONTEXT").size(10).color(TEXT_BRIGHT))
                .padding([4, 8])
                .style(section_header_container),
            column![
                text("SOURCE ADDRESS (OPTIONAL)").size(10).color(TEXT_DIM),
                text_input("e.g. 192.168.1.0/24 or specific IP", &form.source)
                    .on_input(Message::RuleFormSourceChanged)
                    .padding(10),
                if let Some(err) = source_error {
                    text(err).size(11).color(DANGER)
                } else {
                    text("")
                }
            ]
            .spacing(6),
            column![
                text("INTERFACE (OPTIONAL)").size(10).color(TEXT_DIM),
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
        row![
            button(text("Cancel").size(14))
                .on_press(Message::CancelRuleForm)
                .padding([10, 20])
                .style(button::secondary),
            horizontal_rule(1),
            button(text(button_text).size(14))
                .on_press(Message::SaveRuleForm)
                .padding([10, 24])
                .style(primary_button),
        ]
        .spacing(16)
        .align_y(Alignment::Center)
    ]
    .spacing(20)
    .padding(32);
    container(form_box)
        .max_width(520)
        .style(card_container)
        .into()
}

fn view_port_inputs<'a>(form: &RuleForm, _has_error: Option<&String>) -> Element<'a, Message> {
    if matches!(form.protocol, Protocol::Tcp | Protocol::Udp) {
        row![
            text_input("80", &form.port_start)
                .on_input(Message::RuleFormPortStartChanged)
                .padding(10)
                .width(Length::Fill),
            text("-").size(16).color(TEXT_DIM),
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
                .color(TEXT_DIM)
                .font(FONT_MONO),
        )
        .padding(10)
        .width(Length::Fill)
        .height(40)
        .align_y(iced::alignment::Vertical::Center)
        .into()
    }
}

fn view_awaiting_apply() -> Element<'static, Message> {
    container(column![text("🛡️").size(36), text("Commit Changes?").size(24).font(FONT_REGULAR).color(TEXT_BRIGHT),
                      text("Rules verified. Applying will take effect immediately with a 15s safety rollback window.").size(14).color(TEXT_DIM).width(360).align_x(Alignment::Center),
                      row![button(text("Discard").size(14)).on_press(Message::CancelRuleForm).padding([10, 20]).style(button::secondary),
                           button(text("Apply & Start Timer").size(14)).on_press(Message::ProceedToApply).padding([10, 24]).style(primary_button),
                      ].spacing(16)
    ].spacing(20).padding(32).align_x(Alignment::Center))
    .style(|theme| { let mut style = card_container(theme); style.shadow = iced::Shadow { color: Color::from_rgba(0.0, 0.0, 0.0, 0.8), offset: iced::Vector::new(0.0, 10.0), blur_radius: 20.0 }; style }).into()
}

fn view_pending_confirmation(remaining: u32) -> Element<'static, Message> {
    container(
        column![
            text("⏳").size(36),
            text("Confirm Safety")
                .size(24)
                .font(FONT_REGULAR)
                .color(TEXT_BRIGHT),
            text(format!(
                "Firewall updated. Automatic rollback in {remaining} seconds if not confirmed."
            ))
            .size(14)
            .color(ACCENT)
            .width(360)
            .align_x(Alignment::Center),
            row![
                button(text("Rollback").size(14))
                    .on_press(Message::RevertClicked)
                    .padding([10, 20])
                    .style(danger_button),
                button(text("Confirm & Stay").size(14))
                    .on_press(Message::ConfirmClicked)
                    .padding([10, 24])
                    .style(primary_button),
            ]
            .spacing(16)
        ]
        .spacing(20)
        .padding(32)
        .align_x(Alignment::Center),
    )
    .style(|theme| {
        let mut style = card_container(theme);
        style.shadow = iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.8),
            offset: iced::Vector::new(0.0, 10.0),
            blur_radius: 20.0,
        };
        style
    })
    .into()
}

fn view_settings(state: &State) -> Element<'_, Message> {
    use iced::widget::slider;

    let advanced = &state.ruleset.advanced_security;

    let content = scrollable(
        column![
            // Header
            text("Advanced Security Settings")
                .size(24)
                .color(TEXT_BRIGHT),
            text("⚠️  These settings may break common applications. Defaults are suitable for most users.")
                .size(14)
                .color(GRUV_YELLOW),
            horizontal_rule(1),
            // Strict ICMP Mode
            row![
                toggler(advanced.strict_icmp)
                    .on_toggle(Message::ToggleStrictIcmp)
                    .width(40),
                column![
                    text("Strict ICMP filtering").size(16).color(TEXT_BRIGHT),
                    text("Only allow essential ICMP types")
                        .size(13)
                        .color(TEXT_DIM),
                    text("ℹ️  May break network tools and games")
                        .size(12)
                        .color(GRUV_AQUA),
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
                    text("ICMP rate limiting").size(16).color(TEXT_BRIGHT),
                    row![
                        text("Rate:").size(13).color(TEXT_DIM),
                        slider(
                            0..=50,
                            advanced.icmp_rate_limit,
                            Message::IcmpRateLimitChanged
                        )
                        .width(200),
                        text(format!("{}/sec", advanced.icmp_rate_limit))
                            .size(13)
                            .color(TEXT_BRIGHT),
                        text("(0 = disabled)").size(12).color(TEXT_DIM),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                    text("ℹ️  May interfere with monitoring tools")
                        .size(12)
                        .color(GRUV_AQUA),
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
                    text("Anti-spoofing (RPF)").size(16).color(TEXT_BRIGHT),
                    text("Reverse path filtering via FIB lookup")
                        .size(13)
                        .color(TEXT_DIM),
                    text("⚠️  WILL BREAK: Docker, VPNs, cloud instances")
                        .size(12)
                        .color(DANGER),
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
                    text("Log dropped packets").size(16).color(TEXT_BRIGHT),
                    row![
                        text("Rate:").size(13).color(TEXT_DIM),
                        slider(
                            1..=100,
                            advanced.log_rate_per_minute,
                            Message::LogRateChanged
                        )
                        .width(200),
                        text(format!("{}/min", advanced.log_rate_per_minute))
                            .size(13)
                            .color(TEXT_BRIGHT),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                    row![
                        text("Prefix:").size(13).color(TEXT_DIM),
                        text_input("DRFW-DROP: ", &advanced.log_prefix)
                            .on_input(Message::LogPrefixChanged)
                            .width(200),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                    text("ℹ️  Privacy: Logs network activity")
                        .size(12)
                        .color(GRUV_AQUA),
                ]
                .spacing(4),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            // Egress Profile
            column![
                text("Egress Filtering Profile")
                    .size(16)
                    .color(TEXT_BRIGHT),
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
                    .style(if advanced.egress_profile
                        == crate::core::firewall::EgressProfile::Desktop
                    {
                        active_card_button
                    } else {
                        card_button
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
                    .style(if advanced.egress_profile
                        == crate::core::firewall::EgressProfile::Server
                    {
                        active_card_button
                    } else {
                        card_button
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
                    TEXT_DIM
                } else {
                    DANGER
                }),
            ]
            .spacing(8),
        ]
        .spacing(20)
        .padding(20),
    );

    content.into()
}

fn view_warning_modal(warning: &PendingWarning) -> Element<'_, Message> {
    let (title, message, confirm_msg) = match warning {
        PendingWarning::EnableRpf => (
            "⚠️ WARNING: Anti-Spoofing Mode",
            "Enabling this feature may break:\n\
            • Docker containers\n\
            • VPN connections (WireGuard, OpenVPN)\n\
            • Multi-homed systems\n\
            • AWS/GCP cloud instances\n\n\
            Only enable if:\n\
            ✓ You don't use Docker or VPNs\n\
            ✓ This is a single-interface server\n\
            ✓ You understand reverse path filtering\n\n\
            Alternative: Use kernel RPF instead:\n  \
            sudo sysctl net.ipv4.conf.all.rp_filter=1",
            Message::ConfirmEnableRpf,
        ),
        PendingWarning::EnableServerMode => (
            "⚠️ Server Mode: Egress Filtering",
            "This will BLOCK all outbound connections by default.\n\n\
            You'll need to explicitly allow:\n\
            • Web browsing (HTTP/HTTPS)\n\
            • DNS queries\n\
            • Software updates\n\
            • Any services your applications use\n\n\
            This mode is designed for servers, not desktop use.",
            Message::ConfirmServerMode,
        ),
    };

    container(
        column![
            text(title).size(20).color(DANGER),
            text(message).size(14).color(TEXT_BRIGHT).font(FONT_MONO),
            row![
                button(text("Cancel").size(14))
                    .on_press(Message::CancelWarning)
                    .padding(12)
                    .style(card_button),
                button(text("Yes, I understand").size(14))
                    .on_press(confirm_msg)
                    .padding(12)
                    .style(danger_button),
            ]
            .spacing(12),
        ]
        .spacing(20)
        .padding(30)
        .max_width(600),
    )
    .style(|theme| {
        let mut style = card_container(theme);
        style.shadow = iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.8),
            offset: iced::Vector::new(0.0, 10.0),
            blur_radius: 20.0,
        };
        style.border = Border {
            color: DANGER,
            width: 2.0,
            ..Default::default()
        };
        style
    })
    .into()
}

fn view_error_display(err: &crate::core::error::ErrorInfo) -> Element<'_, Message> {
    let mut elements: Vec<Element<'_, Message>> = vec![
        row![
            text("⚠️").size(16),
            text(&err.message).size(13).color(DANGER).font(FONT_REGULAR),
            button("Copy Details")
                .on_press(Message::CopyErrorClicked)
                .padding([4, 10])
                .style(danger_button)
        ]
        .spacing(12)
        .align_y(Alignment::Center)
        .into(),
    ];

    // Add suggestions if available
    for suggestion in &err.suggestions {
        elements.push(
            row![
                text("→").size(12).color(GRUV_AQUA),
                text(suggestion).size(12).color(TEXT_BRIGHT).font(FONT_MONO),
            ]
            .spacing(6)
            .into(),
        );
    }

    column(elements).spacing(6).into()
}

fn view_diagnostics_modal() -> Element<'static, Message> {
    // Read recent audit log entries
    let audit_entries = std::fs::read_to_string(
        crate::utils::get_state_dir()
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
        .map(|s| s.to_string())
        .collect();

    // Get recovery commands as owned strings
    let state_dir = crate::utils::get_state_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "~/.local/state/drfw".to_string());

    let recovery_cmd = "sudo nft flush ruleset".to_string();
    let snapshot_restore_cmd = format!("sudo nft --json -f {}/snapshot-*.json", state_dir);

    container(
        column![
            row![
                text("📊 Diagnostics & Logs")
                    .size(24)
                    .font(FONT_REGULAR)
                    .color(GRUV_ORANGE),
                horizontal_rule(0),
            ]
            .spacing(12)
            .align_y(Alignment::Center)
            .width(Length::Fill),

            // Audit log section
            column![
                text("Recent Audit Log Entries:").size(14).color(TEXT_BRIGHT),
                container(
                    scrollable(
                        column(
                            if recent_entries.is_empty() {
                                vec![text("No audit entries found").size(12).color(TEXT_DIM).into()]
                            } else {
                                recent_entries
                                    .into_iter()
                                    .map(|entry| {
                                        text(entry)
                                            .size(11)
                                            .font(FONT_MONO)
                                            .color(GRUV_FG0)
                                            .into()
                                    })
                                    .collect()
                            }
                        )
                        .spacing(4)
                    )
                )
                .height(200)
                .style(|_| container::Style {
                    background: Some(GRUV_BG2.into()),
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
                text("Manual Recovery Commands:").size(14).color(TEXT_BRIGHT),
                container(
                    column![
                        text("Emergency flush (removes all rules):").size(12).color(TEXT_DIM),
                        text(recovery_cmd).size(12).font(FONT_MONO).color(GRUV_YELLOW),

                        text("Restore from snapshot:").size(12).color(TEXT_DIM),
                        text(snapshot_restore_cmd)
                            .size(12)
                            .font(FONT_MONO)
                            .color(GRUV_YELLOW),
                    ]
                    .spacing(6)
                )
                .style(|_| container::Style {
                    background: Some(GRUV_BG2.into()),
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
                    .style(primary_button),
                button(text("Close").size(14))
                    .on_press(Message::ToggleDiagnostics(false))
                    .padding([10, 20])
                    .style(card_button),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        ]
        .spacing(20)
        .padding(32)
        .max_width(700)
    )
    .style(section_header_container)
    .into()
}

fn view_export_modal() -> Element<'static, Message> {
    container(
        column![
            text("📤 Export Rules")
                .size(24)
                .font(FONT_REGULAR)
                .color(GRUV_ORANGE),

            text("Choose the export format:")
                .size(14)
                .color(TEXT_DIM),

            column![
                button(
                    row![
                        text("📄").size(20),
                        column![
                            text("Export as JSON")
                                .size(16)
                                .font(FONT_REGULAR)
                                .color(TEXT_BRIGHT),
                            text("Structured data format for automation and backup")
                                .size(12)
                                .color(TEXT_DIM),
                        ]
                        .spacing(4),
                    ]
                    .spacing(12)
                    .align_y(Alignment::Center)
                    .padding(16)
                )
                .on_press(Message::ExportAsJson)
                .style(card_button)
                .width(Length::Fill),

                button(
                    row![
                        text("📝").size(20),
                        column![
                            text("Export as nftables text")
                                .size(16)
                                .font(FONT_REGULAR)
                                .color(TEXT_BRIGHT),
                            text("Human-readable .nft format for manual editing")
                                .size(12)
                                .color(TEXT_DIM),
                        ]
                        .spacing(4),
                    ]
                    .spacing(12)
                    .align_y(Alignment::Center)
                    .padding(16)
                )
                .on_press(Message::ExportAsNft)
                .style(card_button)
                .width(Length::Fill),
            ]
            .spacing(12),

            text("Files will be saved to ~/Downloads/ or your data directory")
                .size(11)
                .color(TEXT_DIM),

            button(text("Cancel").size(14))
                .on_press(Message::ExportClicked) // Toggle to close
                .padding([10, 20])
                .style(button::secondary),
        ]
        .spacing(20)
        .padding(32)
        .max_width(500)
        .align_x(Alignment::Center)
    )
    .style(section_header_container)
    .into()
}

fn view_shortcuts_help() -> Element<'static, Message> {
    container(
        column![
            text("⌨️ Keyboard Shortcuts")
                .size(24)
                .font(FONT_REGULAR)
                .color(GRUV_ORANGE),

            column![
                text("General").size(16).color(TEXT_BRIGHT),
                row![
                    container(text("F1").size(13).font(FONT_MONO).color(GRUV_YELLOW))
                        .width(150)
                        .padding([4, 8])
                        .style(|_| container::Style {
                            background: Some(GRUV_BG2.into()),
                            border: Border { radius: 4.0.into(), ..Default::default() },
                            ..Default::default()
                        }),
                    text("Show this help").size(13).color(TEXT_BRIGHT)
                ]
                .spacing(16)
                .align_y(Alignment::Center),
                row![
                    container(text("Esc").size(13).font(FONT_MONO).color(GRUV_YELLOW))
                        .width(150)
                        .padding([4, 8])
                        .style(|_| container::Style {
                            background: Some(GRUV_BG2.into()),
                            border: Border { radius: 4.0.into(), ..Default::default() },
                            ..Default::default()
                        }),
                    text("Close modals / Cancel").size(13).color(TEXT_BRIGHT)
                ]
                .spacing(16)
                .align_y(Alignment::Center),
            ]
            .spacing(8),

            column![
                text("Rules").size(16).color(TEXT_BRIGHT),
                row![
                    container(text("Ctrl + N").size(13).font(FONT_MONO).color(GRUV_YELLOW))
                        .width(150)
                        .padding([4, 8])
                        .style(|_| container::Style {
                            background: Some(GRUV_BG2.into()),
                            border: Border { radius: 4.0.into(), ..Default::default() },
                            ..Default::default()
                        }),
                    text("Add new rule").size(13).color(TEXT_BRIGHT)
                ]
                .spacing(16)
                .align_y(Alignment::Center),
                row![
                    container(text("Enter").size(13).font(FONT_MONO).color(GRUV_YELLOW))
                        .width(150)
                        .padding([4, 8])
                        .style(|_| container::Style {
                            background: Some(GRUV_BG2.into()),
                            border: Border { radius: 4.0.into(), ..Default::default() },
                            ..Default::default()
                        }),
                    text("Save rule (when editing)").size(13).color(TEXT_BRIGHT)
                ]
                .spacing(16)
                .align_y(Alignment::Center),
            ]
            .spacing(8),

            column![
                text("Actions").size(16).color(TEXT_BRIGHT),
                row![
                    container(text("Ctrl + S").size(13).font(FONT_MONO).color(GRUV_YELLOW))
                        .width(150)
                        .padding([4, 8])
                        .style(|_| container::Style {
                            background: Some(GRUV_BG2.into()),
                            border: Border { radius: 4.0.into(), ..Default::default() },
                            ..Default::default()
                        }),
                    text("Apply changes").size(13).color(TEXT_BRIGHT)
                ]
                .spacing(16)
                .align_y(Alignment::Center),
                row![
                    container(text("Ctrl + E").size(13).font(FONT_MONO).color(GRUV_YELLOW))
                        .width(150)
                        .padding([4, 8])
                        .style(|_| container::Style {
                            background: Some(GRUV_BG2.into()),
                            border: Border { radius: 4.0.into(), ..Default::default() },
                            ..Default::default()
                        }),
                    text("Export rules").size(13).color(TEXT_BRIGHT)
                ]
                .spacing(16)
                .align_y(Alignment::Center),
            ]
            .spacing(8),

            column![
                text("Editing").size(16).color(TEXT_BRIGHT),
                row![
                    container(text("Ctrl + Z").size(13).font(FONT_MONO).color(GRUV_YELLOW))
                        .width(150)
                        .padding([4, 8])
                        .style(|_| container::Style {
                            background: Some(GRUV_BG2.into()),
                            border: Border { radius: 4.0.into(), ..Default::default() },
                            ..Default::default()
                        }),
                    text("Undo last change").size(13).color(TEXT_BRIGHT)
                ]
                .spacing(16)
                .align_y(Alignment::Center),
                row![
                    container(text("Ctrl + Y").size(13).font(FONT_MONO).color(GRUV_YELLOW))
                        .width(150)
                        .padding([4, 8])
                        .style(|_| container::Style {
                            background: Some(GRUV_BG2.into()),
                            border: Border { radius: 4.0.into(), ..Default::default() },
                            ..Default::default()
                        }),
                    text("Redo last undone change").size(13).color(TEXT_BRIGHT)
                ]
                .spacing(16)
                .align_y(Alignment::Center),
                row![
                    container(text("Ctrl + Shift + Z").size(13).font(FONT_MONO).color(GRUV_YELLOW))
                        .width(150)
                        .padding([4, 8])
                        .style(|_| container::Style {
                            background: Some(GRUV_BG2.into()),
                            border: Border { radius: 4.0.into(), ..Default::default() },
                            ..Default::default()
                        }),
                    text("Redo (alternative)").size(13).color(TEXT_BRIGHT)
                ]
                .spacing(16)
                .align_y(Alignment::Center),
            ]
            .spacing(8),

            text("💡 Tip: Most buttons can be clicked instead of using shortcuts")
                .size(11)
                .color(TEXT_DIM),

            button(text("Close").size(14))
                .on_press(Message::ToggleShortcutsHelp(false))
                .padding([10, 20])
                .style(primary_button),
        ]
        .spacing(20)
        .padding(32)
        .max_width(550)
        .align_x(Alignment::Center)
    )
    .style(section_header_container)
    .into()
}
