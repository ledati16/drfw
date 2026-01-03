//! Rule editing form modal

use crate::app::ui_components::{
    card_container, primary_button, secondary_button, section_header_container, themed_checkbox,
    themed_pick_list, themed_pick_list_menu, themed_text_input,
};
use crate::app::{Message, RuleForm};
use crate::core::firewall::Protocol;
use iced::widget::{button, checkbox, column, container, pick_list, row, text, text_input};
use iced::{Alignment, Element, Length};

pub fn view_rule_form<'a>(
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
                .font(regular_font)
                .color(theme.fg_muted)
        ]
        .spacing(4),
        // Basic Info Section
        column![
            text("DESCRIPTION")
                .size(10)
                .font(regular_font)
                .color(theme.fg_muted),
            text_input("e.g. Local Web Server", &form.label)
                .on_input(Message::RuleFormLabelChanged)
                .padding(8)
                .font(regular_font)
                .style(move |_, status| themed_text_input(theme, status))
        ]
        .spacing(4),
        // Technical Details Section
        column![
            row![
                column![
                    container(
                        text("PROTOCOL")
                            .size(10)
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
                {
                    let mut port_col = column![
                        container(
                            text("PORT RANGE")
                                .size(10)
                                .font(regular_font)
                                .color(theme.fg_muted)
                        )
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
                        view_port_inputs(form, port_error, theme, regular_font, mono_font),
                    ]
                    .spacing(4)
                    .width(Length::Fill);

                    if let Some(err) = port_error {
                        port_col = port_col
                            .push(text(err).size(11).font(regular_font).color(theme.danger));
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
                                .font(regular_font)
                                .color(theme.fg_muted)
                        )
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
                        text_input("e.g. 192.168.1.0/24 or specific IP", &form.source)
                            .on_input(Message::RuleFormSourceChanged)
                            .padding(8)
                            .font(regular_font)
                            .style(move |_, status| themed_text_input(theme, status)),
                    ]
                    .spacing(4);

                    if let Some(err) = source_error {
                        source_col = source_col
                            .push(text(err).size(11).font(regular_font).color(theme.danger));
                    }
                    source_col
                },
                column![
                    container(
                        text("INTERFACE (OPTIONAL)")
                            .size(10)
                            .font(regular_font)
                            .color(theme.fg_muted)
                    )
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
                    .font(regular_font)
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
                        container(
                            text("CHAIN DIRECTION")
                                .size(10)
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
        // Advanced Options Section
        {
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
                adv_col = adv_col.push(
                    column![
                        // Destination IP
                        {
                            let mut dest_col = column![
                                container(
                                    text("DESTINATION ADDRESS (OPTIONAL)")
                                        .size(10)
                                        .font(regular_font)
                                        .color(theme.fg_muted)
                                )
                                .padding([2, 6])
                                .style(move |_| section_header_container(theme)),
                                text_input("e.g. 192.168.1.0/24 or specific IP", &form.destination)
                                    .on_input(Message::RuleFormDestinationChanged)
                                    .padding(8)
                                    .font(regular_font)
                                    .style(move |_, status| themed_text_input(theme, status)),
                            ]
                            .spacing(4);

                            if let Some(err) = destination_error {
                                dest_col = dest_col.push(
                                    text(err).size(11).font(regular_font).color(theme.danger),
                                );
                            }
                            dest_col
                        },
                        // Action
                        column![
                            container(
                                text("ACTION")
                                    .size(10)
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
                                                    .size(10)
                                                    .font(regular_font)
                                                    .color(theme.fg_muted)
                                            )
                                            .padding([2, 6])
                                            .style(move |_| section_header_container(theme)),
                                            text_input("e.g. 5", &form.rate_limit_count)
                                                .on_input(Message::RuleFormRateLimitCountChanged)
                                                .padding(8)
                                                .font(regular_font)
                                                .style(move |_, status| themed_text_input(
                                                    theme, status
                                                )),
                                        ]
                                        .spacing(4)
                                        .width(Length::Fill),
                                        column![
                                            container(
                                                text("PER")
                                                    .size(10)
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
                                    ]
                                    .spacing(8),
                                );
                            }

                            if let Some(err) = rate_limit_error {
                                rate_limit_col = rate_limit_col.push(
                                    text(err).size(11).font(regular_font).color(theme.danger),
                                );
                            }
                            rate_limit_col
                        },
                        // Connection Limiting
                        {
                            let mut conn_col = column![
                                container(
                                    text("CONNECTION LIMIT (OPTIONAL)")
                                        .size(10)
                                        .font(regular_font)
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
                                .font(regular_font)
                                .style(move |_, status| themed_text_input(theme, status)),
                            ]
                            .spacing(4);

                            if let Some(err) = connection_limit_error {
                                conn_col = conn_col.push(
                                    text(err).size(11).font(regular_font).color(theme.danger),
                                );
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
                container(
                    text("TAGS")
                        .size(10)
                        .font(regular_font)
                        .color(theme.fg_muted)
                )
                .padding([2, 6])
                .style(move |_| section_header_container(theme)),
                row![
                    text_input("Add a tag...", &form.tag_input)
                        .on_input(Message::RuleFormTagInputChanged)
                        .on_submit(Message::RuleFormAddTag)
                        .padding(8)
                        .font(regular_font)
                        .style(move |_, status| themed_text_input(theme, status)),
                    button(text("+").size(16).font(regular_font))
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
                                text(tag).size(12).font(regular_font).color(fg_on_accent),
                                button(text("×").size(14).font(regular_font))
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
            button(text("Cancel").size(14).font(regular_font))
                .on_press(Message::CancelRuleForm)
                .padding([10, 20])
                .style(move |_, status| secondary_button(theme, status)),
            container(row![]).width(Length::Fill),
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

pub fn view_port_inputs<'a>(
    form: &RuleForm,
    _has_error: Option<&String>,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
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
                .font(mono_font)
                .style(move |_, status| themed_text_input(theme, status)),
            text("-").size(16).font(mono_font).color(theme.fg_muted),
            text_input("80", &form.port_end)
                .on_input(Message::RuleFormPortEndChanged)
                .padding(8)
                .width(Length::Fill)
                .font(mono_font)
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
                .font(regular_font),
        )
        .padding(8)
        .width(Length::Fill)
        .height(36)
        .align_y(iced::alignment::Vertical::Center)
        .into()
    }
}
