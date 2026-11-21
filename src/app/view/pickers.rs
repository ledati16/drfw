//! Theme and font picker modals

use iced::widget::{button, column, container, row, rule, scrollable, space, text, text_input};
use iced::{Alignment, Border, Color, Element, Length, Padding};

use crate::app::ui_components::{
    active_card_button, active_tab_button, card_button, card_container, danger_button,
    dirty_button, inset_container_bordered, primary_button, secondary_button,
    section_header_container, themed_horizontal_rule, themed_scrollable, themed_text_input,
};
use crate::app::{
    FONT_PICKER_DISPLAY_LIMIT, FontPickerState, FontPickerTarget, Message, State, ThemeFilter,
    ThemePickerState,
};

pub fn view_font_picker<'a>(state: &'a State, picker: &'a FontPickerState) -> Element<'a, Message> {
    let theme = &state.theme;
    let is_mono_picker = matches!(picker.target, FontPickerTarget::Mono);

    // Filtered and sorted in update() (FontPickerState::refilter), not per frame
    let filtered_fonts = picker
        .filtered
        .iter()
        .filter_map(|&index| state.available_fonts.get(index));

    // Limit visible items to keep layout fast with many matches
    let font_list = column(filtered_fonts.take(FONT_PICKER_DISPLAY_LIMIT).map(|f| {
        let name = f.name();
        let preview_font = f.to_font(); // Cheap: just returns handle from FontChoice

        let is_selected = match picker.target {
            FontPickerTarget::Regular => &state.regular_font_choice == f,
            FontPickerTarget::Mono => &state.mono_font_choice == f,
        };

        // Clone needed for on_press closure (cheap: just font name string)
        let f_for_message = f.clone();

        button(
            row![
                column![
                    text(name)
                        .size(13)
                        .font(state.font_regular)
                        .color(theme.fg_primary),
                    // Contextual preview text: code sample for mono fonts, readable text for UI fonts
                    text(if is_mono_picker {
                        "fn main() { 0x123 }"
                    } else {
                        "The quick brown fox"
                    })
                    .size(11)
                    .font(preview_font)
                    .color(theme.fg_secondary),
                ]
                .spacing(2)
                .width(Length::Fill),
                if is_selected {
                    text("✓").size(14).color(theme.success)
                } else {
                    text("").size(14)
                }
            ]
            .align_y(Alignment::Center)
            .padding([6, 10]),
        )
        .width(Length::Fill)
        .on_press(match picker.target {
            FontPickerTarget::Regular => Message::RegularFontChanged(f_for_message),
            FontPickerTarget::Mono => Message::MonoFontChanged(f_for_message),
        })
        .style(move |_, status| {
            let mut style = if is_selected {
                active_card_button(theme, status)
            } else {
                card_button(theme, status)
            };

            // Clean list item look: no background or border unless hovered or selected
            let is_hovered = matches!(status, iced::widget::button::Status::Hovered);
            if !is_hovered && !is_selected {
                style.background = None;
                style.border.width = 0.0;
                style.shadow.color = Color::TRANSPARENT;
            } else if is_hovered && !is_selected {
                style.background = Some(theme.bg_hover.into());
                style.border.width = 0.0;
                style.shadow.color = Color::TRANSPARENT;
            }
            style
        })
        .into()
    }))
    .spacing(2);

    container(
        column![
            container(
                text(match picker.target {
                    FontPickerTarget::Regular => "Select UI Font",
                    FontPickerTarget::Mono => "Select Code Font",
                })
                .size(18)
                .font(state.font_regular)
                .color(theme.fg_primary)
            )
            .padding([4, 8])
            .style(move |_| section_header_container(theme)),
            text_input("Search fonts...", &picker.search)
                .on_input(Message::FontPickerSearchChanged)
                .padding(10)
                .size(13)
                .font(state.font_regular)
                .id(crate::app::focus::FONT_SEARCH)
                .style(move |_, status| themed_text_input(theme, status)),
            container(
                scrollable(
                    column![
                        container(font_list).padding(8),
                        if picker.filtered.is_empty() && state.fonts_loaded {
                            container(
                                text("No fonts found — try a different search")
                                    .size(11)
                                    .font(state.font_regular)
                                    .color(theme.fg_muted),
                            )
                            .padding(Padding {
                                top: 8.0,
                                right: 8.0,
                                bottom: 4.0,
                                left: 8.0,
                            })
                        } else if let Some(overflow) = &picker.overflow_display {
                            container(
                                text(overflow)
                                    .size(11)
                                    .font(state.font_regular)
                                    .color(theme.fg_muted),
                            )
                            .padding(Padding {
                                top: 8.0,
                                right: 8.0,
                                bottom: 4.0,
                                left: 8.0,
                            })
                        } else {
                            container(text(""))
                        },
                    ]
                    .spacing(0)
                )
                .direction(scrollable::Direction::Vertical(
                    scrollable::Scrollbar::new().spacing(0),
                ))
                .style(move |_, status| themed_scrollable(theme, status))
            )
            .height(Length::Fixed(400.0))
            .width(Length::Fill)
            .style(move |_| inset_container_bordered(theme)),
            row![
                container(
                    text(&picker.count_display)
                        .size(10)
                        .color(theme.fg_muted)
                        .font(state.font_mono)
                )
                .padding([2, 6])
                .style(move |_| section_header_container(theme)),
                space::Space::new().width(Length::Fill),
                button(text("Close").size(14).font(state.font_regular))
                    .on_press(Message::CloseFontPicker)
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
            ]
            .align_y(Alignment::Center)
        ]
        .spacing(16)
        .padding(24)
        .width(Length::Fixed(500.0)),
    )
    .style(move |_| card_container(theme))
    .into()
}

pub fn view_theme_picker<'a>(
    state: &'a State,
    picker: &'a ThemePickerState,
) -> Element<'a, Message> {
    // Theme picker layout constants
    const CARD_WIDTH: f32 = 150.0;
    const CARD_SPACING: f32 = 10.0;
    const GRID_PADDING: f32 = 10.0; // Clean symmetric padding
    const MODAL_WIDTH: f32 = 548.0; // Fine-tuned for visual balance
    const GRADIENT_BAR_HEIGHT: f32 = 24.0;
    const COLOR_DOT_SIZE: f32 = 12.0;
    const STATUS_COLOR_SIZE: f32 = 14.0;

    let theme = &state.theme;

    // Filtered and sorted in update() (ThemePickerState::refilter), not per frame
    let filtered_themes = picker
        .filtered
        .iter()
        .filter_map(|&index| picker.cached_themes.get(index));
    let filtered_count = picker.filtered.len();

    // Helper function for creating colored dot containers
    let make_color_dot = |color: Color, size: f32| {
        container(space::Space::new().width(size).height(size)).style(move |_| container::Style {
            background: Some(color.into()),
            border: Border {
                radius: (size / 2.0).into(),
                ..Default::default()
            },
            ..Default::default()
        })
    };

    // Pre-allocate theme card vector (show all themes, no limit)
    let mut theme_cards = Vec::with_capacity(filtered_count);

    for (choice, theme_preview) in filtered_themes {
        let is_selected = state.current_theme == *choice;

        // Extract colors for use in closures (Color is Copy)
        let bg_base = theme_preview.bg_base;
        let bg_surface = theme_preview.bg_surface;
        let accent = theme_preview.accent;
        let success = theme_preview.success;
        let warning = theme_preview.warning;
        let danger = theme_preview.danger;

        theme_cards.push(
            button(
                column![
                    // Header: name only (no checkmark)
                    text(choice.name())
                        .size(13)
                        .font(state.font_regular)
                        .color(theme.fg_primary),
                    // Split visual preview: 70% bg gradient + 30% accent color (square)
                    row![
                        // Left: background gradient
                        container(space::Space::new())
                            .width(Length::FillPortion(7))
                            .height(Length::Fixed(GRADIENT_BAR_HEIGHT))
                            .style(move |_| container::Style {
                                background: Some(
                                    iced::gradient::Linear::new(0.0)
                                        .add_stop(0.0, bg_base)
                                        .add_stop(1.0, bg_surface)
                                        .into(),
                                ),
                                ..Default::default()
                            }),
                        // Right: accent color
                        container(space::Space::new())
                            .width(Length::FillPortion(3))
                            .height(Length::Fixed(GRADIENT_BAR_HEIGHT))
                            .style(move |_| container::Style {
                                background: Some(accent.into()),
                                ..Default::default()
                            }),
                    ],
                    // Color swatches (semantic colors)
                    row![
                        make_color_dot(accent, COLOR_DOT_SIZE),
                        make_color_dot(success, COLOR_DOT_SIZE),
                        make_color_dot(warning, COLOR_DOT_SIZE),
                        make_color_dot(danger, COLOR_DOT_SIZE),
                    ]
                    .spacing(4),
                ]
                .spacing(6)
                .padding(8),
            )
            .width(Length::Fixed(CARD_WIDTH))
            .on_press(Message::ThemePreview(*choice))
            .style(move |_, status| {
                let mut style = card_button(theme, status);
                if is_selected {
                    // Add accent border for selected theme
                    style.border = Border {
                        color: accent,
                        width: 2.0,
                        radius: 8.0.into(),
                    };
                }
                style
            })
            .into(),
        );
    }

    // Create grid layout (3 columns) - wrapped row with better spacing
    let theme_grid = row(theme_cards).spacing(CARD_SPACING).wrap();

    // Filter buttons (identical to tag filtering pattern)
    let filter_buttons = row![
        button(text("All").size(10).font(state.font_regular))
            .padding([4, 8])
            .style(move |_, status| {
                if matches!(picker.filter, ThemeFilter::All) {
                    active_tab_button(theme, status)
                } else {
                    secondary_button(theme, status)
                }
            })
            .on_press(Message::ThemePickerFilterChanged(ThemeFilter::All)),
        button(text("Light").size(10).font(state.font_regular))
            .padding([4, 8])
            .style(move |_, status| {
                if matches!(picker.filter, ThemeFilter::Light) {
                    active_tab_button(theme, status)
                } else {
                    secondary_button(theme, status)
                }
            })
            .on_press(Message::ThemePickerFilterChanged(ThemeFilter::Light)),
        button(text("Dark").size(10).font(state.font_regular))
            .padding([4, 8])
            .style(move |_, status| {
                if matches!(picker.filter, ThemeFilter::Dark) {
                    active_tab_button(theme, status)
                } else {
                    secondary_button(theme, status)
                }
            })
            .on_press(Message::ThemePickerFilterChanged(ThemeFilter::Dark)),
    ]
    .spacing(6);

    // Preview panel showing currently selected theme (two-column layout)
    let preview_panel = container(
        column![
            row![
                container(
                    text("PREVIEW:")
                        .size(11)
                        .font(state.font_mono)
                        .color(theme.fg_muted)
                )
                .padding([2, 6])
                .style(move |_| section_header_container(theme)),
                text(state.current_theme.name())
                    .size(11)
                    .font(state.font_mono)
                    .color(theme.fg_muted),
                rule::horizontal(1).style(move |_| themed_horizontal_rule(theme)),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
            // Two-column layout: UI elements left, code right
            row![
                // Left column: Buttons, text hierarchy, status colors (45% width)
                column![
                    // Buttons in 2x2 grid (standard secondary style)
                    row![
                        button(text("Apply").size(12).font(state.font_regular))
                            .padding([6, 12])
                            .on_press(Message::Noop)
                            .style(move |_, status| primary_button(theme, status)),
                        button(text("Cancel").size(12).font(state.font_regular))
                            .padding([6, 12])
                            .on_press(Message::Noop)
                            .style(move |_, status| secondary_button(theme, status)),
                    ]
                    .spacing(6),
                    row![
                        button(text("Delete").size(12).font(state.font_regular))
                            .padding([6, 12])
                            .on_press(Message::Noop)
                            .style(move |_, status| danger_button(theme, status)),
                        button(text("Save").size(12).font(state.font_regular))
                            .padding([6, 12])
                            .on_press(Message::Noop)
                            .style(move |_, status| dirty_button(theme, status)),
                    ]
                    .spacing(6),
                    // Text hierarchy
                    column![
                        container(
                            text("Text Hierarchy")
                                .size(10)
                                .font(state.font_mono)
                                .color(theme.fg_muted)
                        )
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
                        row![
                            text("Primary")
                                .size(11)
                                .font(state.font_regular)
                                .color(theme.fg_primary),
                            text("•")
                                .size(11)
                                .font(state.font_regular)
                                .color(theme.fg_muted),
                            text("Secondary")
                                .size(11)
                                .font(state.font_regular)
                                .color(theme.fg_secondary),
                            text("•")
                                .size(11)
                                .font(state.font_regular)
                                .color(theme.fg_muted),
                            text("Muted")
                                .size(11)
                                .font(state.font_regular)
                                .color(theme.fg_muted),
                        ]
                        .spacing(6),
                    ]
                    .spacing(4),
                    // Status colors
                    column![
                        container(
                            text("Status Colors")
                                .size(10)
                                .font(state.font_mono)
                                .color(theme.fg_muted)
                        )
                        .padding([2, 6])
                        .style(move |_| section_header_container(theme)),
                        row![
                            make_color_dot(theme.success, STATUS_COLOR_SIZE),
                            make_color_dot(theme.warning, STATUS_COLOR_SIZE),
                            make_color_dot(theme.danger, STATUS_COLOR_SIZE),
                            make_color_dot(theme.info, STATUS_COLOR_SIZE),
                        ]
                        .spacing(6),
                    ]
                    .spacing(4),
                ]
                .spacing(12)
                .width(Length::FillPortion(7)),
                // Right column: Taller code snippet (65% width) - Fills more space
                container(
                    column![
                        text("fn process_data(items: Vec<String>) -> u32 {")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_keyword),
                        text("    let mut count = 0;  // initialize")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_comment),
                        text("    for item in items.iter() {")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_keyword),
                        text("        if item.len() > 5 {")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_keyword),
                        text("            count += 1;")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_number),
                        text("            println!(\"Found: {}\", item);")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_string),
                        text("        }")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_keyword),
                        text("    }")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_keyword),
                        text("    count  // return value")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_comment),
                        text("}")
                            .size(10)
                            .font(state.font_mono)
                            .color(theme.syntax_keyword),
                    ]
                    .spacing(1)
                )
                .padding(12)
                .width(Length::FillPortion(13))
                .height(Length::Shrink)
                .style(move |_| container::Style {
                    background: Some(theme.bg_elevated.into()),
                    border: Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        ]
        .spacing(8)
        .padding(12),
    )
    .width(Length::Fill)
    .height(Length::Shrink)
    .style(move |_| container::Style {
        background: Some(theme.bg_surface.into()),
        border: Border {
            radius: 8.0.into(),
            color: theme.border,
            width: 1.0,
        },
        ..Default::default()
    });

    container(
        column![
            container(
                text("Select Theme")
                    .size(18)
                    .font(state.font_regular)
                    .color(theme.fg_primary)
            )
            .padding([4, 8])
            .style(move |_| section_header_container(theme)),
            text_input("Search themes...", &picker.search)
                .id(crate::app::focus::THEME_SEARCH)
                .on_input(Message::ThemePickerSearchChanged)
                .padding(10)
                .size(13)
                .font(state.font_regular)
                .style(move |_, status| themed_text_input(theme, status)),
            filter_buttons,
            container(
                scrollable(column![if filtered_count == 0 {
                    container(
                        text("No themes found — try a different search")
                            .size(11)
                            .font(state.font_regular)
                            .color(theme.fg_muted),
                    )
                    .padding(GRID_PADDING) // Symmetric - simple and maintainable
                } else {
                    container(theme_grid).padding(GRID_PADDING) // Symmetric - simple and maintainable
                }])
                .width(Length::Fill)
                .direction(scrollable::Direction::Vertical(
                    scrollable::Scrollbar::new().spacing(0),
                ))
                .style(move |_, status| themed_scrollable(theme, status))
            )
            .height(Length::Fixed(320.0))
            .width(Length::Fill)
            .style(move |_| inset_container_bordered(theme)),
            preview_panel,
            row![
                container(
                    text(&picker.count_display)
                        .size(10)
                        .color(theme.fg_muted)
                        .font(state.font_mono)
                )
                .padding([2, 6])
                .style(move |_| section_header_container(theme)),
                space::Space::new().width(Length::Fill),
                button(text("Cancel").size(14).font(state.font_regular))
                    .on_press(Message::CancelThemePicker)
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
                button(text("Apply").size(14).font(state.font_regular))
                    .on_press(Message::ApplyTheme)
                    .padding([10, 24])
                    .style(move |_, status| primary_button(theme, status)),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
        ]
        .spacing(16)
        .padding(24)
        .width(Length::Fixed(MODAL_WIDTH)),
    )
    .style(move |_| card_container(theme))
    .into()
}
