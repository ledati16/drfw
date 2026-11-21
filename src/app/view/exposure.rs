//! Exposure panel: listening sockets and who can reach them
//!
//! Every string comes from `app::exposure::ExposurePanel`, built in
//! `update()`; this view only borrows them.

use iced::widget::{Space, button, column, container, row, scrollable, text};
use iced::{Alignment, Color, Element, Length};

use crate::app::Message;
use crate::app::exposure::{
    AppliedState, ExposurePanel, ExposureRowView, Highlight, ReachTone, ReachView,
};
use crate::app::ui_components::{
    attention_card_container, card_container, danger_badge_container, info_notice_container,
    primary_button, secondary_button, section_header_container, themed_scrollable,
    warning_attention_card_container, warning_badge_container,
};
use crate::theme::AppTheme;

/// Height of the scrollable socket list.
const LIST_HEIGHT: f32 = 440.0;
/// Width of the port/protocol column.
const PORT_COLUMN_WIDTH: f32 = 110.0;
/// Width of the "Editor"/"Applied" label column.
const LABEL_COLUMN_WIDTH: f32 = 64.0;

/// Theme color of a reachability answer (always shown with its text).
fn tone_color(theme: &AppTheme, tone: ReachTone) -> Color {
    match tone {
        ReachTone::Open => theme.danger,
        ReachTone::OpenOnInterfaces | ReachTone::PublishedByDocker => theme.warning,
        ReachTone::Restricted | ReachTone::PublishedByDockerFiltered => theme.fg_primary,
        ReachTone::Closed => theme.success,
        ReachTone::LocalOnly => theme.fg_muted,
    }
}

/// One answer: badge, "Reachable from: …" and the deciding rule.
fn reach_line<'a>(
    label: &'static str,
    view: &'a ReachView,
    theme: &'a AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    let mut line = row![
        container(text(label).size(10).font(mono_font).color(theme.fg_muted))
            .width(LABEL_COLUMN_WIDTH),
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    if let Some(badge) = &view.badge {
        let warning = view.tone == ReachTone::OpenOnInterfaces || view.tone.is_docker();
        line = line.push(
            container(text(badge).size(10).font(mono_font))
                .padding([2, 8])
                .style(move |_| {
                    if warning {
                        warning_badge_container(theme)
                    } else {
                        danger_badge_container(theme)
                    }
                }),
        );
    }
    line = line.push(
        text(&view.text)
            .size(13)
            .font(regular_font)
            .color(tone_color(theme, view.tone))
            .width(Length::Fill),
    );
    if let Some(id) = view.edit_rule_id {
        line = line.push(
            button(text(&view.rule_text).size(12).font(regular_font))
                .on_press(Message::EditRuleClicked(id))
                .padding([4, 10])
                .style(move |_, status| secondary_button(theme, status)),
        );
    } else if !view.rule_text.is_empty() {
        line = line.push(
            text(&view.rule_text)
                .size(12)
                .font(regular_font)
                .color(theme.fg_muted),
        );
    }
    line.into()
}

/// One socket card.
fn socket_row<'a>(
    row_data: &'a ExposureRowView,
    applied: AppliedState,
    applied_label: &'static str,
    theme: &'a AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    let editor_label = match applied {
        AppliedState::Unknown | AppliedState::Differs => "EDITOR",
        AppliedState::SameAsEditor => "RULES",
    };
    let mut answers = column![reach_line(
        editor_label,
        &row_data.editor,
        theme,
        regular_font,
        mono_font
    )]
    .spacing(4);
    if let Some(applied_view) = &row_data.applied {
        answers = answers.push(reach_line(
            applied_label,
            applied_view,
            theme,
            regular_font,
            mono_font,
        ));
    }

    let header = row![
        column![
            text(&row_data.port_proto)
                .size(14)
                .font(mono_font)
                .color(theme.fg_primary),
            text(row_data.family)
                .size(11)
                .font(mono_font)
                .color(theme.fg_muted),
        ]
        .width(PORT_COLUMN_WIDTH),
        column![
            text(&row_data.process)
                .size(14)
                .font(regular_font)
                .color(theme.fg_primary),
            text(&row_data.bind)
                .size(11)
                .font(mono_font)
                .color(theme.fg_muted),
        ]
        .width(Length::Fill),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    let highlight = row_data.highlight;
    container(column![header, answers].spacing(8))
        .padding(12)
        .width(Length::Fill)
        .style(move |_| match highlight {
            Highlight::Everyone => attention_card_container(theme),
            Highlight::Interfaces => warning_attention_card_container(theme),
            Highlight::None => card_container(theme),
        })
        .into()
}

pub fn view_exposure_modal<'a>(
    panel: &'a ExposurePanel,
    theme: &'a AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    let mut body = column![
        container(
            text("Exposure")
                .size(18)
                .font(regular_font)
                .color(theme.fg_primary)
        )
        .padding([4, 8])
        .style(move |_| section_header_container(theme)),
        column![
            text(&panel.summary)
                .size(14)
                .font(regular_font)
                .color(theme.fg_primary),
            text(
                "Programs listening for connections, and who can open a new connection to \
                 them through the firewall."
            )
            .size(12)
            .font(regular_font)
            .color(theme.fg_muted),
            text(panel.applied_note)
                .size(12)
                .font(regular_font)
                .color(theme.fg_muted),
        ]
        .spacing(4),
    ]
    .spacing(16)
    .padding(24);

    // Whether the clients of the SSH sessions could reconnect (text first;
    // the color only repeats it)
    if !panel.ssh_lines.is_empty() {
        body = body.push(
            column(panel.ssh_lines.iter().map(|line| {
                text(&line.text)
                    .size(13)
                    .font(regular_font)
                    .color(if line.warning {
                        theme.danger
                    } else {
                        theme.fg_primary
                    })
                    .into()
            }))
            .spacing(4),
        );
    }

    // Forwarding and container networks: what the rows cannot show
    for note in &panel.notes {
        body = body.push(
            container(
                row![
                    text("INFO")
                        .size(10)
                        .font(iced::Font {
                            weight: iced::font::Weight::Bold,
                            ..mono_font
                        })
                        .color(theme.info),
                    text(*note)
                        .size(13)
                        .font(regular_font)
                        .color(theme.fg_primary)
                        .width(Length::Fill),
                ]
                .spacing(12)
                .align_y(Alignment::Center),
            )
            .padding([10, 16])
            .width(Length::Fill)
            .style(move |_| info_notice_container(theme)),
        );
    }

    if let Some(error) = &panel.error {
        body = body.push(text(error).size(13).font(regular_font).color(theme.danger));
    }

    let rows = column(panel.rows.iter().map(|r| {
        socket_row(
            r,
            panel.applied,
            panel.applied_label,
            theme,
            regular_font,
            mono_font,
        )
    }))
    .spacing(8);
    // Borderless scrollable (STYLE.md section 17, pattern 1)
    body = body.push(
        container(
            scrollable(container(rows).width(Length::Fill))
                .direction(scrollable::Direction::Vertical(
                    scrollable::Scrollbar::new().spacing(8),
                ))
                .style(move |_, status| themed_scrollable(theme, status)),
        )
        .width(Length::Fill)
        .max_height(LIST_HEIGHT),
    );

    let mut refresh = button(
        text(if panel.scanning {
            "Scanning…"
        } else {
            "Refresh"
        })
        .size(14)
        .font(regular_font),
    )
    .padding([10, 20])
    .style(move |_, status| secondary_button(theme, status));
    if !panel.scanning {
        refresh = refresh.on_press(Message::RefreshExposure);
    }
    body = body.push(
        row![
            text(
                "Process names of other users' sockets need root, which DRFW does not \
                 use for this."
            )
            .size(11)
            .font(regular_font)
            .color(theme.fg_muted)
            .width(Length::Fill),
            Space::new().width(12),
            refresh,
            button(text("Close").size(14).font(regular_font))
                .on_press(Message::ToggleExposure(false))
                .padding([10, 24])
                .style(move |_, status| primary_button(theme, status)),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    );

    container(body)
        .max_width(980)
        .style(move |_| card_container(theme))
        .into()
}
