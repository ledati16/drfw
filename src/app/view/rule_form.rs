//! Rule editing form modal
//!
//! Uses summary buttons for multi-value fields that open helper modals.
//! Main form stays compact with advanced options in collapsible section.

use super::helper_modals;
use crate::app::ui_components::{
    card_container, primary_button, secondary_button, section_header_container, themed_checkbox,
    themed_pick_list, themed_pick_list_menu, themed_text_input,
};
use crate::app::{HelperType, Message, RuleForm};
use crate::core::firewall::{Protocol, RejectType};
use crate::core::rule_constraints::{available_reject_types_for_protocol, protocol_supports_ports};
use iced::widget::{
    Space, button, checkbox, column, combo_box, container, pick_list, row, text, text_input,
};
use iced::{Alignment, Element, Length};

pub fn view_rule_form<'a>(
    form: &'a RuleForm,
    errors: Option<&'a crate::app::FormErrors>,
    interface_combo: &'a combo_box::State<String>,
    output_interface_combo: &'a combo_box::State<String>,
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

    // Extract errors
    let port_error = errors.and_then(|e| e.port.as_ref());
    let source_error = errors.and_then(|e| e.source.as_ref());
    let destination_error = errors.and_then(|e| e.destination.as_ref());
    let rate_limit_error = errors.and_then(|e| e.rate_limit.as_ref());
    let connection_limit_error = errors.and_then(|e| e.connection_limit.as_ref());
    let reject_type_error = errors.and_then(|e| e.reject_type.as_ref());
    let output_interface_error = errors.and_then(|e| e.output_interface.as_ref());

    // Summary strings for multi-value fields
    let ports_summary = helper_modals::ports_summary(&form.ports);
    let sources_summary = helper_modals::addresses_summary(&form.sources);
    let destinations_summary = helper_modals::addresses_summary(&form.destinations);
    let tags_summary = helper_modals::tags_summary(&form.tags);

    let form_box = column![
        // Title Section
        column![
            text(title_text)
                .size(22)
                .font(regular_font)
                .color(theme.info),
            text("Define allowed traffic patterns.")
                .size(12)
                .font(regular_font)
                .color(theme.fg_muted)
        ]
        .spacing(4),
        // Basic Info Section
        column![
            container(
                text("DESCRIPTION")
                    .size(11)
                    .font(regular_font)
                    .color(theme.fg_muted)
            )
            .padding([2, 6])
            .style(move |_| section_header_container(theme)),
            text_input("e.g. Local Web Server", &form.label)
                .on_input(Message::RuleFormLabelChanged)
                .padding(8)
                .font(regular_font)
                .style(move |_, status| themed_text_input(theme, status))
        ]
        .spacing(4),
        // Protocol and Ports Section
        column![
            row![
                column![
                    container(
                        text("PROTOCOL")
                            .size(11)
                            .font(regular_font)
                            .color(theme.fg_muted)
                    )
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
                    .font(regular_font)
                    .style(move |_, status| themed_pick_list(theme, status))
                    .menu_style(move |_| themed_pick_list_menu(theme))
                ]
                .spacing(4)
                .width(Length::Fill),
                // Ports summary button
                {
                    let mut port_col = column![
                        container(
                            text("PORTS")
                                .size(11)
                                .font(regular_font)
                                .color(theme.fg_muted)
                        )
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
                        view_ports_summary(form, ports_summary.clone(), theme, regular_font),
                    ]
                    .spacing(4)
                    .width(Length::Fill);

                    if let Some(err) = port_error {
                        port_col = port_col
                            .push(text(err).size(12).font(regular_font).color(theme.danger));
                    }
                    port_col
                },
            ]
            .spacing(8),
        ]
        .spacing(6),
        // Source and Interface Section
        {
            let mut context_col = column![
                // Source addresses summary button
                {
                    let mut source_col = column![
                        container(
                            text("SOURCE ADDRESS")
                                .size(11)
                                .font(regular_font)
                                .color(theme.fg_muted)
                        )
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
                        view_summary_button(
                            sources_summary.clone(),
                            HelperType::SourceAddresses,
                            !form.sources.is_empty(),
                            theme,
                            regular_font,
                        ),
                    ]
                    .spacing(4);

                    if let Some(err) = source_error {
                        source_col = source_col
                            .push(text(err).size(12).font(regular_font).color(theme.danger));
                    }
                    source_col
                },
                // Interface combo_box(es) with autocomplete (supports wildcards like eth*, docker*)
                // In server mode: Input + Output interface side by side
                // Otherwise: just "INTERFACE" (input only)
                view_interface_fields(
                    form,
                    interface_combo,
                    output_interface_combo,
                    output_interface_error,
                    theme,
                    regular_font,
                    server_mode,
                ),
            ]
            .spacing(6);

            // Chain selection (only visible in Server Mode)
            if server_mode {
                context_col = context_col.push(
                    column![
                        container(
                            text("CHAIN DIRECTION")
                                .size(11)
                                .font(regular_font)
                                .color(theme.fg_muted)
                        )
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
                        .font(regular_font)
                        .style(move |_, status| themed_pick_list(theme, status))
                        .menu_style(move |_| themed_pick_list_menu(theme))
                    ]
                    .spacing(4),
                );
            }
            context_col
        },
        // Tags summary button
        column![
            container(
                text("TAGS")
                    .size(11)
                    .font(regular_font)
                    .color(theme.fg_muted)
            )
            .padding([2, 6])
            .style(move |_| section_header_container(theme)),
            view_summary_button(
                tags_summary.clone(),
                HelperType::Tags,
                !form.tags.is_empty(),
                theme,
                regular_font,
            ),
        ]
        .spacing(4),
        // Advanced Options Section
        view_advanced_section(
            form,
            destinations_summary,
            destination_error,
            rate_limit_error,
            connection_limit_error,
            reject_type_error,
            theme,
            regular_font,
            mono_font,
        ),
        // Footer Actions
        row![
            button(text("Cancel").size(14).font(regular_font))
                .on_press(Message::CancelRuleForm)
                .padding([10, 20])
                .style(move |_, status| secondary_button(theme, status)),
            Space::new().width(Length::Fill),
            button(text(button_text).size(14).font(regular_font))
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

/// Renders ports summary button or "Not applicable" for non-port protocols
fn view_ports_summary<'a>(
    form: &RuleForm,
    summary: String,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
) -> Element<'a, Message> {
    // Use centralized constraint logic for port support
    if protocol_supports_ports(form.protocol) {
        view_summary_button(
            summary,
            HelperType::Ports,
            !form.ports.is_empty(),
            theme,
            regular_font,
        )
    } else {
        container(
            text("Not applicable")
                .size(12)
                .color(theme.fg_muted)
                .font(regular_font),
        )
        .padding(8)
        .width(Length::Fill)
        .height(36)
        .align_y(iced::alignment::Vertical::Center)
        .into()
    }
}

/// Renders a summary button that opens a helper modal.
///
/// Takes ownership of `summary` String to avoid lifetime issues -
/// the string becomes part of the Element and is dropped with it.
fn view_summary_button(
    summary: String,
    helper_type: HelperType,
    has_values: bool,
    theme: &crate::theme::AppTheme,
    regular_font: iced::Font,
) -> Element<'_, Message> {
    let text_color = if has_values {
        theme.fg_primary
    } else {
        theme.fg_muted
    };

    button(
        row![
            text(summary).size(13).font(regular_font).color(text_color),
            Space::new().width(Length::Fill),
            text("→").size(14).font(regular_font).color(theme.fg_muted),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill),
    )
    .on_press(Message::OpenHelper(helper_type))
    .padding(8)
    .width(Length::Fill)
    .style(move |_, status| {
        let mut style = secondary_button(theme, status);
        // Make it look more like an input field
        style.border.radius = 4.0.into();
        style
    })
    .into()
}

/// Interface fields - single or side-by-side based on server mode
fn view_interface_fields<'a>(
    form: &'a RuleForm,
    interface_combo: &'a combo_box::State<String>,
    output_interface_combo: &'a combo_box::State<String>,
    output_interface_error: Option<&'a String>,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    server_mode: bool,
) -> Element<'a, Message> {
    let input_label = if server_mode {
        "INPUT INTERFACE"
    } else {
        "INTERFACE"
    };

    let input_iface_col = column![
        container(
            text(input_label)
                .size(11)
                .font(regular_font)
                .color(theme.fg_muted)
        )
        .padding([2, 6])
        .style(move |_| section_header_container(theme)),
        combo_box(
            interface_combo,
            "Any (type or select)",
            if form.interface.is_empty() {
                None
            } else {
                Some(&form.interface)
            },
            Message::RuleFormInterfaceChanged,
        )
        .on_input(Message::RuleFormInterfaceChanged)
        .padding(8)
        .font(regular_font)
        .width(Length::Fill)
        .input_style(move |_, status| themed_text_input(theme, status))
        .menu_style(move |_| themed_pick_list_menu(theme))
    ]
    .spacing(4)
    .width(Length::Fill);

    if server_mode {
        let mut output_iface_col = column![
            container(
                text("OUTPUT INTERFACE")
                    .size(11)
                    .font(regular_font)
                    .color(theme.fg_muted)
            )
            .padding([2, 6])
            .style(move |_| section_header_container(theme)),
            combo_box(
                output_interface_combo,
                "Any (type or select)",
                if form.output_interface.is_empty() {
                    None
                } else {
                    Some(&form.output_interface)
                },
                Message::RuleFormOutputInterfaceChanged,
            )
            .on_input(Message::RuleFormOutputInterfaceChanged)
            .padding(8)
            .font(regular_font)
            .width(Length::Fill)
            .input_style(move |_, status| themed_text_input(theme, status))
            .menu_style(move |_| themed_pick_list_menu(theme))
        ]
        .spacing(4)
        .width(Length::Fill);

        if let Some(err) = output_interface_error {
            output_iface_col =
                output_iface_col.push(text(err).size(12).font(regular_font).color(theme.danger));
        }

        row![input_iface_col, output_iface_col].spacing(12).into()
    } else {
        input_iface_col.into()
    }
}

/// Advanced options section with destination, action, reject type, rate limiting, etc.
fn view_advanced_section<'a>(
    form: &'a RuleForm,
    destinations_summary: String,
    destination_error: Option<&'a String>,
    rate_limit_error: Option<&'a String>,
    connection_limit_error: Option<&'a String>,
    reject_type_error: Option<&'a String>,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    let mut adv_col = column![
        checkbox(form.show_advanced)
            .label("Show Advanced Options")
            .on_toggle(Message::RuleFormToggleAdvanced)
            .size(16)
            .spacing(8)
            .text_size(12)
            .font(regular_font)
            .style(move |_, status| themed_checkbox(theme, status)),
    ]
    .spacing(6);

    if form.show_advanced {
        // Destination addresses
        let mut dest_col = column![
            container(
                text("DESTINATION ADDRESS")
                    .size(11)
                    .font(regular_font)
                    .color(theme.fg_muted)
            )
            .padding([2, 6])
            .style(move |_| section_header_container(theme)),
            view_summary_button(
                destinations_summary,
                HelperType::DestinationAddresses,
                !form.destinations.is_empty(),
                theme,
                regular_font,
            ),
        ]
        .spacing(4);
        if let Some(err) = destination_error {
            dest_col = dest_col.push(text(err).size(12).font(regular_font).color(theme.danger));
        }
        adv_col = adv_col.push(dest_col);

        // Action and Reject Type (side by side when Reject is selected)
        {
            let action_col = column![
                container(
                    text("ACTION")
                        .size(11)
                        .font(regular_font)
                        .color(theme.fg_muted)
                )
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
                .font(regular_font)
                .style(move |_, status| themed_pick_list(theme, status))
                .menu_style(move |_| themed_pick_list_menu(theme))
            ]
            .spacing(4)
            .width(Length::Fill);

            if form.action == crate::core::firewall::Action::Reject {
                // Use centralized constraint logic for available reject types
                let reject_options = available_reject_types_for_protocol(form.protocol);

                // If current reject type is not valid for protocol, reset to Default
                let selected = if reject_options.contains(&form.reject_type) {
                    form.reject_type
                } else {
                    RejectType::Default
                };

                let mut reject_col = column![
                    container(
                        text("REJECT TYPE")
                            .size(11)
                            .font(regular_font)
                            .color(theme.fg_muted)
                    )
                    .padding([2, 6])
                    .style(move |_| section_header_container(theme)),
                    pick_list(
                        reject_options,
                        Some(selected),
                        Message::RuleFormRejectTypeChanged
                    )
                    .width(Length::Fill)
                    .padding(8)
                    .font(regular_font)
                    .style(move |_, status| themed_pick_list(theme, status))
                    .menu_style(move |_| themed_pick_list_menu(theme))
                ]
                .spacing(4)
                .width(Length::Fill);

                if let Some(err) = reject_type_error {
                    reject_col =
                        reject_col.push(text(err).size(12).font(regular_font).color(theme.danger));
                }

                adv_col = adv_col.push(row![action_col, reject_col].spacing(12));
            } else {
                adv_col = adv_col.push(action_col);
            }
        }

        // Rate Limiting
        let mut rate_limit_col = column![
            checkbox(form.rate_limit_enabled)
                .label("Enable Rate Limiting")
                .on_toggle(Message::RuleFormToggleRateLimit)
                .size(16)
                .spacing(8)
                .text_size(12)
                .font(regular_font)
                .style(move |_, status| themed_checkbox(theme, status)),
        ]
        .spacing(4);
        if form.rate_limit_enabled {
            rate_limit_col = rate_limit_col.push(
                row![
                    column![
                        container(
                            text("COUNT")
                                .size(11)
                                .font(regular_font)
                                .color(theme.fg_muted)
                        )
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
                        text_input("e.g. 5", &form.rate_limit_count)
                            .on_input(Message::RuleFormRateLimitCountChanged)
                            .padding(8)
                            .font(mono_font)
                            .style(move |_, status| themed_text_input(theme, status)),
                    ]
                    .spacing(4)
                    .width(Length::Fill),
                    column![
                        container(
                            text("PER")
                                .size(11)
                                .font(regular_font)
                                .color(theme.fg_muted)
                        )
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
                        .font(regular_font)
                        .style(move |_, status| themed_pick_list(theme, status))
                        .menu_style(move |_| themed_pick_list_menu(theme))
                    ]
                    .spacing(4)
                    .width(Length::Fill),
                    column![
                        container(
                            text("BURST")
                                .size(11)
                                .font(regular_font)
                                .color(theme.fg_muted)
                        )
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
                        text_input("optional", &form.rate_limit_burst)
                            .on_input(Message::RuleFormRateLimitBurstChanged)
                            .padding(8)
                            .font(mono_font)
                            .style(move |_, status| themed_text_input(theme, status)),
                    ]
                    .spacing(4)
                    .width(Length::Fill),
                ]
                .spacing(8),
            );
        }
        if let Some(err) = rate_limit_error {
            rate_limit_col =
                rate_limit_col.push(text(err).size(12).font(regular_font).color(theme.danger));
        }
        adv_col = adv_col.push(rate_limit_col);

        // Connection Limiting
        let mut conn_col = column![
            container(
                text("CONNECTION LIMIT")
                    .size(11)
                    .font(regular_font)
                    .color(theme.fg_muted)
            )
            .padding([2, 6])
            .style(move |_| section_header_container(theme)),
            text_input("0 = unlimited", &form.connection_limit)
                .on_input(Message::RuleFormConnectionLimitChanged)
                .padding(8)
                .font(mono_font)
                .style(move |_, status| themed_text_input(theme, status)),
        ]
        .spacing(4);
        if let Some(err) = connection_limit_error {
            conn_col = conn_col.push(text(err).size(12).font(regular_font).color(theme.danger));
        }
        adv_col = adv_col.push(conn_col);

        // Per-rule logging
        adv_col = adv_col.push(
            checkbox(form.log_enabled)
                .label("Enable Per-Rule Logging")
                .on_toggle(Message::RuleFormLogEnabledToggled)
                .size(16)
                .spacing(8)
                .text_size(12)
                .font(regular_font)
                .style(move |_, status| themed_checkbox(theme, status)),
        );
    }

    adv_col.into()
}
