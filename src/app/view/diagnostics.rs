//! Diagnostics modal and event log viewer
//!
//! Rows, filter results and the count label are prepared in `update()`
//! (`app::diagnostics::DiagnosticsLog`); this view only borrows them.

use iced::widget::{
    button, column, container, pick_list, row, scrollable, space, text, text_input,
};
use iced::{Alignment, Border, Element, Length, Padding};

use crate::app::diagnostics::{DiagnosticRow, RowTone};
use crate::app::ui_components::{
    card_container, danger_button, secondary_button, section_header_container, themed_pick_list,
    themed_pick_list_menu, themed_scrollable, themed_text_input,
};
use crate::app::{DiagnosticsFilter, Message, State};

/// Time column width for `HH:MM:SS` in the 12px mono font
const TIME_COLUMN_WIDTH: f32 = 64.0;
/// Time column width for `YYYY-MM-DD HH:MM:SS` in the 12px mono font
const DATED_TIME_COLUMN_WIDTH: f32 = 144.0;

const FILTERS: [DiagnosticsFilter; 5] = [
    DiagnosticsFilter::All,
    DiagnosticsFilter::Successes,
    DiagnosticsFilter::Errors,
    DiagnosticsFilter::ProfileChanges,
    DiagnosticsFilter::Settings,
];

/// One event log row: time, status dot, description
fn event_row<'a>(
    event: &'a DiagnosticRow,
    theme: &crate::theme::AppTheme,
    mono_font: iced::Font,
    time_width: f32,
) -> Element<'a, Message> {
    let status_color = match event.tone {
        RowTone::Success => theme.success,
        RowTone::Warning => theme.warning,
        RowTone::Danger => theme.danger,
        RowTone::Accent => theme.accent,
    };

    row![
        text(&event.time)
            .size(12)
            .font(mono_font)
            .color(theme.fg_muted)
            .width(Length::Fixed(time_width)),
        container(text(""))
            .width(Length::Fixed(8.0))
            .height(Length::Fixed(8.0))
            .style(move |_| container::Style {
                background: Some(status_color.into()),
                border: Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
        text(&event.description)
            .size(13)
            .font(mono_font)
            .color(theme.fg_primary),
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .width(Length::Fill)
    .into()
}

/// Bottom-right buttons: "Clear Log" + "Close", or the clear confirmation
fn action_buttons<'a>(
    state: &'a State,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
) -> Element<'a, Message> {
    let log = &state.diagnostics;
    if log.confirm_clear {
        return row![
            text("Clear the event log? This cannot be undone.")
                .size(13)
                .font(regular_font)
                .color(theme.fg_primary),
            button(text("Cancel").size(14).font(regular_font))
                .on_press(Message::ClearEventLogCancelled)
                .padding([10, 20])
                .style(move |_, status| secondary_button(theme, status)),
            button(text("Clear Log").size(14).font(regular_font))
                .on_press(Message::ClearEventLogConfirmed)
                .padding([10, 20])
                .style(move |_, status| danger_button(theme, status)),
        ]
        .spacing(8)
        .align_y(Alignment::Center)
        .into();
    }

    row![
        button(
            text(if log.clearing {
                "Clearing…"
            } else {
                "Clear Log"
            })
            .size(14)
            .font(regular_font)
        )
        .on_press_maybe((!log.clearing).then_some(Message::ClearEventLog))
        .padding([10, 20])
        .style(move |_, status| danger_button(theme, status)),
        button(text("Close").size(14).font(regular_font))
            .on_press(Message::ToggleDiagnostics(false))
            .padding([10, 20])
            .style(move |_, status| secondary_button(theme, status)),
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}

pub fn view_diagnostics_modal<'a>(
    state: &'a State,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    let log = &state.diagnostics;

    let entries: Vec<Element<'a, Message>> = if log.nothing_visible() {
        let message = if !state.enable_event_log {
            "Event logging is disabled. Enable it in Settings to track operations."
        } else if log.search.trim().is_empty() {
            "No events match the current filter"
        } else {
            "No events match the current filter and search"
        };
        vec![
            text(message)
                .size(12)
                .font(regular_font)
                .color(theme.fg_muted)
                .into(),
        ]
    } else {
        let time_width = if log.any_visible_dated {
            DATED_TIME_COLUMN_WIDTH
        } else {
            TIME_COLUMN_WIDTH
        };
        log.visible_rows()
            .map(|event| event_row(event, theme, mono_font, time_width))
            .collect()
    };

    container(
        column![
            container(
                text("Event Log")
                    .size(18)
                    .font(regular_font)
                    .color(theme.fg_primary)
            )
            .padding([4, 8])
            .style(move |_| section_header_container(theme)),
            // Filter and search
            row![
                text("Filter:")
                    .size(12)
                    .font(regular_font)
                    .color(theme.fg_muted),
                pick_list(
                    FILTERS,
                    Some(state.diagnostics_filter),
                    Message::DiagnosticsFilterChanged
                )
                .placeholder("Filter...")
                .padding(8)
                .font(regular_font)
                .style(move |_, status| themed_pick_list(theme, status))
                .menu_style(move |_| themed_pick_list_menu(theme)),
                text_input("Search events...", &log.search)
                    .on_input(Message::DiagnosticsSearchChanged)
                    .padding(8)
                    .size(13)
                    .font(regular_font)
                    .width(Length::Fill)
                    .style(move |_, status| themed_text_input(theme, status)),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            // Event log section
            container(
                scrollable(container(column(entries).spacing(4)).padding(Padding {
                    top: 8.0,
                    right: 8.0,
                    bottom: 8.0,
                    left: 8.0,
                }))
                .spacing(0) // Embedded mode prevents overlap
                .style(move |_, status| themed_scrollable(theme, status)),
            )
            .width(Length::Fill)
            .height(500)
            .style(move |_| container::Style {
                background: Some(theme.bg_elevated.into()),
                border: Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
            // Count and actions
            row![
                container(
                    text(&log.count_label)
                        .size(10)
                        .font(mono_font)
                        .color(theme.fg_muted)
                )
                .padding([2, 6])
                .style(move |_| section_header_container(theme)),
                space::Space::new().width(Length::Fill),
                action_buttons(state, theme, regular_font),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        ]
        .spacing(16)
        .padding(24),
    )
    .max_width(1000)
    .style(move |_| card_container(theme))
    .into()
}
