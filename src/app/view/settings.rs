//! Settings tab UI

use crate::app::ui_components::{
    card_container, secondary_button, section_header_container, themed_slider, themed_text_input,
    themed_toggler,
};
use crate::app::{FontPickerTarget, Message, State};
use crate::core::firewall::EgressProfile;
use iced::widget::text::Wrapping;
use iced::widget::{button, column, container, row, slider, text, text_input, toggler};
use iced::{Alignment, Element, Length};

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
        ]
        .spacing(16)
        .padding(16)
    ])
    .style(move |_| card_container(theme));

    let behavior_card = container(column![
        container(
            text("BEHAVIOR")
                .size(12)
                .font(state.font_regular)
                .color(theme.fg_muted)
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
                        // Precision loss acceptable: timeout is 5-120s, well within f64/u64 precision
                        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
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
            render_settings_row(
                "Event logging",
                "Record firewall operations to the event log",
                toggler(state.enable_event_log)
                    .on_toggle(Message::ToggleEventLog)
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

    let security_card = container(
        column![
            container(
                text("ADVANCED SECURITY")
                    .size(12)
                    .font(state.font_regular)
                    .color(theme.fg_muted)
            )
            .padding([8, 12])
            .width(Length::Fill)
            .style(move |_| section_header_container(theme)),

            column![
                text("These settings may break common applications. Defaults are suitable for most users.")
                    .size(13)
                    .font(state.font_regular)
                    .color(theme.warning),

                render_settings_row(
                    "Strict ICMP filtering",
                    "Only allow essential ICMP types (ping, MTU discovery)",
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
                                .font(state.font_mono)
                                .style(move |_, status| themed_text_input(theme, status))
                                .into(),
                            theme,
                            state.font_regular,
                        ),
                    ].spacing(8))
                } else {
                    column![].into()
                },

                render_settings_row(
                    "Server Mode",
                    "Block all outbound connections by default (recommended for servers)",
                    toggler(advanced.egress_profile == EgressProfile::Server)
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

    column![appearance_card, behavior_card, security_card,]
        .spacing(24)
        .into()
}

pub fn render_settings_row<'a>(
    title: &'static str,
    desc: &'static str,
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
