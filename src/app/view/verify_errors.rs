//! "Verification Errors" panel: what nft rejected, per rule
//!
//! Every string comes from `app::verify_errors::VerifyErrorsPanel`, built in
//! `update()` when a verification fails; this view only borrows them.

use iced::widget::{button, column, container, row, scrollable, space, text};
use iced::{Alignment, Element, Length};

use crate::app::Message;
use crate::app::ui_components::{
    card_container, inset_container, primary_button, secondary_button, section_header_container,
    themed_scrollable,
};
use crate::app::verify_errors::{VerifyErrorRow, VerifyErrorsPanel};

/// Height of the scrollable error list.
const LIST_HEIGHT: f32 = 420.0;

/// One error: what it points at, nft's message, the offending line.
fn error_row<'a>(
    row_data: &'a VerifyErrorRow,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    let mut header = row![
        text(&row_data.title)
            .size(14)
            .font(regular_font)
            .color(theme.fg_primary)
            .width(Length::Fill),
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    if let Some(id) = row_data.edit_rule_id() {
        header = header.push(
            button(text("Edit Rule").size(13).font(regular_font))
                .on_press(Message::EditRuleClicked(id))
                .padding([6, 12])
                .style(move |_, status| primary_button(theme, status)),
        );
    }

    let mut body = column![
        header,
        text(&row_data.message)
            .size(13)
            .font(regular_font)
            .color(theme.danger),
    ]
    .spacing(6);

    if let (Some(source), Some(caret)) = (&row_data.source_line, &row_data.caret) {
        let code = column![
            text(source)
                .size(12)
                .font(mono_font)
                .color(theme.fg_primary)
                .wrapping(text::Wrapping::None),
            text(caret)
                .size(12)
                .font(mono_font)
                .color(theme.danger)
                .wrapping(text::Wrapping::None),
        ];
        body = body.push(
            container(
                scrollable(container(code).padding(8))
                    .direction(scrollable::Direction::Horizontal(
                        scrollable::Scrollbar::new().spacing(0),
                    ))
                    .style(move |_, status| themed_scrollable(theme, status)),
            )
            .width(Length::Fill)
            .style(move |_| inset_container(theme)),
        );
    }

    container(body)
        .padding(12)
        .width(Length::Fill)
        .style(move |_| card_container(theme))
        .into()
}

pub fn view_verify_errors_modal<'a>(
    panel: &'a VerifyErrorsPanel,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    let rows = column(
        panel
            .rows
            .iter()
            .map(|r| error_row(r, theme, regular_font, mono_font)),
    )
    .spacing(8);

    container(
        column![
            container(
                text(panel.title)
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
                text(panel.next_step)
                    .size(12)
                    .font(regular_font)
                    .color(theme.fg_muted),
            ]
            .spacing(4),
            // Borderless scrollable (STYLE.md section 17, pattern 1)
            container(
                scrollable(container(rows).width(Length::Fill))
                    .direction(scrollable::Direction::Vertical(
                        scrollable::Scrollbar::new().spacing(8),
                    ))
                    .style(move |_, status| themed_scrollable(theme, status)),
            )
            .width(Length::Fill)
            .max_height(LIST_HEIGHT),
            row![
                space::Space::new().width(Length::Fill),
                button(text("Close").size(14).font(regular_font))
                    .on_press(Message::ToggleVerifyErrors(false))
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
            ]
            .align_y(Alignment::Center),
        ]
        .spacing(16)
        .padding(24),
    )
    .max_width(900)
    .style(move |_| card_container(theme))
    .into()
}
