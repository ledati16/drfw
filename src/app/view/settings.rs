//! Settings tab UI

use iced::widget::text::Wrapping;
use iced::widget::{Column, button, column, container, row, slider, text, text_input, toggler};
use iced::{Alignment, Element, Length};

use crate::app::ui_components::{
    card_container, secondary_button, section_header_container, themed_slider, themed_text_input,
    themed_toggler,
};
use crate::app::{FontPickerTarget, Message, State};
use crate::core::firewall::EgressProfile;

/// Description of the "Local network discovery" row.
const LOCAL_DISCOVERY_DESC: &str = "Find and be found by printers, TVs, speakers and other \
     computers on your network (mDNS, UPnP). Turn off on networks you don't trust.";

/// The same row in Server Mode, where the setting is not used.
const LOCAL_DISCOVERY_SERVER_NOTE: &str = "Not available in Server Mode: outgoing \
     connections there only follow your Output rules. Switch to Desktop mode to use it.";

/// Description of the "Anti-spoofing (RPF)" row (new packets only, with the
/// routing mark: see CLAUDE.md §9, "Rule Ordering").
const RPF_DESC: &str = "Drop new connections whose source address could not have arrived on \
     that interface. Useful with rules that trust a source address. May block peers that \
     contact a full-tunnel VPN first.";

/// Description of the "Block forwarded traffic" row.
const BLOCK_FORWARDING_DESC: &str = "Drop routed traffic unless a Forwarded rule allows it. \
     Docker, VMs and VPN routing then need such rules; mainly for routers";

/// Description of the "Server Mode" row.
const SERVER_MODE_DESC: &str = "Block outgoing connections unless a rule allows them. For \
     locked-down servers; you must allow DNS, time sync and updates yourself.";

pub fn view_settings(state: &State) -> Element<'_, Message> {
    let theme = &state.theme;
    let advanced = &state.ruleset.advanced_security;

    let appearance_card = container(column![
        container(
            text("APPEARANCE")
                .size(12)
                .font(state.font_regular)
                .color(theme.fg_muted)
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
                                .font(state.font_regular)
                                .wrapping(Wrapping::None)
                        )
                        .width(Length::Fill)
                        .clip(true),
                        text(" ▾")
                            .size(10)
                            .font(state.font_regular)
                            .color(theme.fg_muted)
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
                                .font(state.font_regular)
                                .wrapping(Wrapping::None)
                        )
                        .width(Length::Fill)
                        .clip(true),
                        text(" ▾")
                            .size(10)
                            .font(state.font_regular)
                            .color(theme.fg_muted)
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
                                .font(state.font_regular)
                                .wrapping(Wrapping::None)
                        )
                        .width(Length::Fill)
                        .clip(true),
                        text(" ▾")
                            .size(10)
                            .font(state.font_regular)
                            .color(theme.fg_muted)
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
            render_settings_row(
                "Reduce syntax colors",
                "Simplify code highlighting to 2 levels (accessibility)",
                toggler(state.reduced_colors)
                    .on_toggle(Message::ToggleReducedColors)
                    .width(Length::Shrink)
                    .style(move |_, status| themed_toggler(theme, status))
                    .into(),
                theme,
                state.font_regular,
            ),
        ]
        .spacing(16)
        .padding(16)
    ])
    .style(move |_| card_container(theme));

    let behavior_card = {
        let mut behavior_items: Vec<Element<'_, Message>> = vec![render_settings_row(
            "Auto-revert confirmation",
            "Require manual confirmation or automatically revert firewall changes after timeout",
            toggler(state.auto_revert_enabled)
                .on_toggle(Message::ToggleAutoRevert)
                .width(Length::Shrink)
                .style(move |_, status| themed_toggler(theme, status))
                .into(),
            theme,
            state.font_regular,
        )];

        if state.auto_revert_enabled {
            // Precision loss acceptable: timeout is 5-120s, well within f64/u64 precision
            #[allow(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss
            )]
            behavior_items.push(render_settings_row(
                "   └ Timeout",
                "Seconds before automatic revert (5-120s)",
                row![
                    slider(5.0..=120.0, state.auto_revert_timeout_secs as f64, |v| {
                        Message::AutoRevertTimeoutChanged(v as u64)
                    })
                    .width(Length::Fill)
                    .style(move |_, status| themed_slider(theme, status)),
                    text(&state.settings_display.auto_revert_timeout)
                        .size(12)
                        .font(state.font_mono)
                        .width(40)
                        .align_x(Alignment::End),
                ]
                .spacing(12)
                .align_y(Alignment::Center)
                .into(),
                theme,
                state.font_regular,
            ));
        }

        behavior_items.push(render_settings_row(
            "Event logging",
            "Record firewall operations to the event log",
            toggler(state.enable_event_log)
                .on_toggle(Message::ToggleEventLog)
                .width(Length::Shrink)
                .style(move |_, status| themed_toggler(theme, status))
                .into(),
            theme,
            state.font_regular,
        ));

        container(column![
            container(
                text("BEHAVIOR")
                    .size(12)
                    .font(state.font_regular)
                    .color(theme.fg_muted)
            )
            .padding([8, 12])
            .width(Length::Fill)
            .style(move |_| section_header_container(theme)),
            Column::with_children(behavior_items)
                .spacing(16)
                .padding(16)
        ])
        .style(move |_| card_container(theme))
    };

    let network_card = {
        let server_mode = advanced.egress_profile == EgressProfile::Server;
        let mut discovery = toggler(advanced.local_discovery && !server_mode)
            .width(Length::Shrink)
            .style(move |_, status| themed_toggler(theme, status));
        if !server_mode {
            discovery = discovery.on_toggle(Message::ToggleLocalDiscovery);
        }
        container(column![
            container(
                text("NETWORK")
                    .size(12)
                    .font(state.font_regular)
                    .color(theme.fg_muted)
            )
            .padding([8, 12])
            .width(Length::Fill)
            .style(move |_| section_header_container(theme)),
            column![render_settings_row(
                "Local network discovery",
                if server_mode {
                    LOCAL_DISCOVERY_SERVER_NOTE
                } else {
                    LOCAL_DISCOVERY_DESC
                },
                discovery.into(),
                theme,
                state.font_regular,
            )]
            .spacing(16)
            .padding(16)
        ])
        .style(move |_| card_container(theme))
    };

    let security_card = {
        let mut security_items: Vec<Element<'_, Message>> = vec![
            text("These settings may break common applications. Defaults are suitable for most users.")
                .size(13)
                .font(state.font_regular)
                .color(theme.warning)
                .into(),
            render_settings_row(
                "Strict ICMP filtering",
                "Only allow the ICMP types networks need (ping, errors, MTU discovery, IPv6 neighbor and router discovery, MLD)",
                toggler(advanced.strict_icmp)
                    .on_toggle(Message::ToggleStrictIcmpRequested)
                    .width(Length::Shrink)
                    .style(move |_, status| themed_toggler(theme, status))
                    .into(),
                theme,
                state.font_regular,
            ),
            render_settings_row(
                "ICMP rate limiting",
                &state.settings_display.icmp_rate_desc,
                row![
                    slider(0..=50, advanced.icmp_rate_limit, Message::IcmpRateLimitChanged)
                        .width(Length::Fill)
                        .style(move |_, status| themed_slider(theme, status)),
                    text(&state.settings_display.icmp_rate)
                        .size(12).font(state.font_mono).width(40).align_x(Alignment::End),
                ].spacing(12).align_y(Alignment::Center).into(),
                theme,
                state.font_regular,
            ),
            render_settings_row(
                "Anti-spoofing (RPF)",
                RPF_DESC,
                toggler(advanced.enable_rpf)
                    .on_toggle(Message::ToggleRpfRequested)
                    .width(Length::Shrink)
                    .style(move |_, status| themed_toggler(theme, status))
                    .into(),
                theme,
                state.font_regular,
            ),
            render_settings_row(
                "Block forwarded traffic",
                BLOCK_FORWARDING_DESC,
                toggler(advanced.block_forwarding)
                    .on_toggle(Message::ToggleBlockForwarding)
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
        ];

        if advanced.log_dropped {
            security_items.push(
                column![
                    render_settings_row(
                        "   └ Log Rate",
                        "Maximum log entries per minute",
                        row![
                            slider(
                                1..=100,
                                advanced.log_rate_per_minute,
                                Message::LogRateChanged
                            )
                            .width(Length::Fill)
                            .style(move |_, status| themed_slider(theme, status)),
                            text(&state.settings_display.log_rate)
                                .size(12)
                                .font(state.font_mono)
                                .width(40)
                                .align_x(Alignment::End),
                        ]
                        .spacing(12)
                        .align_y(Alignment::Center)
                        .into(),
                        theme,
                        state.font_regular,
                    ),
                    render_settings_row(
                        "   └ Log Prefix",
                        "Tag used in system journal",
                        text_input("DRFW-DROP: ", &advanced.log_prefix)
                            .id(crate::app::focus::LOG_PREFIX)
                            .on_input(Message::LogPrefixChanged)
                            .padding(8)
                            .size(13)
                            .font(state.font_mono)
                            .style(move |_, status| themed_text_input(theme, status))
                            .into(),
                        theme,
                        state.font_regular,
                    ),
                ]
                .spacing(8)
                .into(),
            );
        }

        security_items.push(render_settings_row(
            "Server Mode",
            SERVER_MODE_DESC,
            toggler(advanced.egress_profile == EgressProfile::Server)
                .on_toggle(Message::ServerModeToggled)
                .width(Length::Shrink)
                .style(move |_, status| themed_toggler(theme, status))
                .into(),
            theme,
            state.font_regular,
        ));

        container(column![
            container(
                text("ADVANCED SECURITY")
                    .size(12)
                    .font(state.font_regular)
                    .color(theme.fg_muted)
            )
            .padding([8, 12])
            .width(Length::Fill)
            .style(move |_| section_header_container(theme)),
            Column::with_children(security_items)
                .spacing(16)
                .padding(16)
        ])
        .style(move |_| card_container(theme))
    };

    column![appearance_card, behavior_card, network_card, security_card,]
        .spacing(24)
        .into()
}

pub fn render_settings_row<'a>(
    title: &'static str,
    desc: &'a str,
    control: Element<'a, Message>,
    theme: &crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'a, Message> {
    row![
        column![
            text(title).size(15).font(font).color(theme.fg_primary),
            text(desc).size(12).font(font).color(theme.fg_muted),
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
