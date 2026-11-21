//! Keyboard shortcuts help modal

use crate::app::Message;
use crate::app::ui_components::{
    card_container, kbd_badge_container, secondary_button, section_header_container,
};
use iced::Element;
use iced::widget::{button, column, container, row, text};

/// One "keys — description" row.
fn shortcut_row<'a>(
    keys: &'static str,
    description: &'static str,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    row![
        container(text(keys).size(13).font(mono_font).color(theme.warning))
            .width(150)
            .padding([4, 8])
            .style(move |_| kbd_badge_container(theme)),
        text(description)
            .size(13)
            .font(regular_font)
            .color(theme.fg_primary)
    ]
    .spacing(16)
    .into()
}

/// A titled group of shortcut rows.
fn shortcut_group<'a>(
    title: &'static str,
    rows: &[(&'static str, &'static str)],
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    let mut group = column![
        text(title)
            .size(16)
            .font(regular_font)
            .color(theme.fg_primary)
    ]
    .spacing(12);
    for &(keys, description) in rows {
        group = group.push(shortcut_row(
            keys,
            description,
            theme,
            regular_font,
            mono_font,
        ));
    }
    group.into()
}

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
            shortcut_group(
                "General",
                &[
                    ("F1", "Show this help"),
                    ("Esc", "Close the top-most dialog or form"),
                ],
                theme,
                regular_font,
                mono_font,
            ),
            shortcut_group(
                "Rules",
                &[
                    ("Ctrl + N", "Add new rule"),
                    ("Enter", "Save the open rule form"),
                    ("Ctrl + S", "Apply changes"),
                    ("Ctrl + Z", "Undo last modification"),
                    ("Ctrl + Y", "Redo last undone modification"),
                    ("Ctrl + Shift + Z", "Redo (alternative)"),
                ],
                theme,
                regular_font,
                mono_font,
            ),
            shortcut_group(
                "Workspace",
                &[("Ctrl + E", "Export rules")],
                theme,
                regular_font,
                mono_font,
            ),
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
