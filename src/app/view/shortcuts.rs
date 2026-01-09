//! Keyboard shortcuts help modal

use crate::app::Message;
use crate::app::ui_components::{
    card_container, kbd_badge_container, secondary_button, section_header_container,
};
use iced::widget::{button, column, container, row, text};
use iced::Element;

pub fn view_shortcuts_help(
    theme: &crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'_, Message> {
    container(
        column![
            container(
                text("⌨️ Keyboard Shortcuts")
                    .size(24)
                    .font(regular_font)
                    .color(theme.warning)
            )
            .padding([4, 8])
            .style(move |_| section_header_container(theme)),
            column![
                text("General")
                    .size(16)
                    .font(regular_font)
                    .color(theme.fg_primary),
                row![
                    container(text("F1").size(13).font(mono_font).color(theme.warning))
                        .width(150)
                        .padding([4, 8])
                        .style(move |_| kbd_badge_container(theme)),
                    text("Show this help")
                        .size(13)
                        .font(regular_font)
                        .color(theme.fg_primary)
                ]
                .spacing(16),
                row![
                    container(text("Esc").size(13).font(mono_font).color(theme.warning))
                        .width(150)
                        .padding([4, 8])
                        .style(move |_| kbd_badge_container(theme)),
                    text("Close any modal or form")
                        .size(13)
                        .font(regular_font)
                        .color(theme.fg_primary)
                ]
                .spacing(16),
            ]
            .spacing(12),
            column![
                text("Rules")
                    .size(16)
                    .font(regular_font)
                    .color(theme.fg_primary),
                row![
                    container(
                        text("Ctrl + N")
                            .size(13)
                            .font(mono_font)
                            .color(theme.warning)
                    )
                    .width(150)
                    .padding([4, 8])
                    .style(move |_| kbd_badge_container(theme)),
                    text("Add new rule")
                        .size(13)
                        .font(regular_font)
                        .color(theme.fg_primary)
                ]
                .spacing(16),
                row![
                    container(
                        text("Ctrl + S")
                            .size(13)
                            .font(mono_font)
                            .color(theme.warning)
                    )
                    .width(150)
                    .padding([4, 8])
                    .style(move |_| kbd_badge_container(theme)),
                    text("Apply changes")
                        .size(13)
                        .font(regular_font)
                        .color(theme.fg_primary)
                ]
                .spacing(16),
                row![
                    container(
                        text("Ctrl + Z")
                            .size(13)
                            .font(mono_font)
                            .color(theme.warning)
                    )
                    .width(150)
                    .padding([4, 8])
                    .style(move |_| kbd_badge_container(theme)),
                    text("Undo last modification")
                        .size(13)
                        .font(regular_font)
                        .color(theme.fg_primary)
                ]
                .spacing(16),
                row![
                    container(
                        text("Ctrl + Shift + Z")
                            .size(13)
                            .font(mono_font)
                            .color(theme.warning)
                    )
                    .width(150)
                    .padding([4, 8])
                    .style(move |_| kbd_badge_container(theme)),
                    text("Redo last undone modification")
                        .size(13)
                        .font(regular_font)
                        .color(theme.fg_primary)
                ]
                .spacing(16),
            ]
            .spacing(12),
            column![
                text("Workspace")
                    .size(16)
                    .font(regular_font)
                    .color(theme.fg_primary),
                row![
                    container(
                        text("Ctrl + E")
                            .size(13)
                            .font(mono_font)
                            .color(theme.warning)
                    )
                    .width(150)
                    .padding([4, 8])
                    .style(move |_| kbd_badge_container(theme)),
                    text("Export rules")
                        .size(13)
                        .font(regular_font)
                        .color(theme.fg_primary)
                ]
                .spacing(16),
            ]
            .spacing(12),
            button(text("Close").size(14).font(regular_font))
                .on_press(Message::ToggleShortcutsHelp(false))
                .padding([10, 20])
                .style(move |_, status| secondary_button(theme, status)),
        ]
        .spacing(24)
        .padding(32),
    )
    .max_width(600)
    .style(move |_| card_container(theme))
    .into()
}
