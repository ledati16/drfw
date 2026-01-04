//! Profile management UI components

use crate::app::ui_components::{
    card_button, card_container, danger_button, primary_button, secondary_button,
    section_header_container, themed_text_input,
};
use crate::app::{Message, ProfileManagerState, State};
use iced::widget::{button, column, container, row, scrollable, space, text, text_input};
use iced::{Alignment, Border, Element, Length, Padding};

pub fn view_profile_switch_confirm(
    theme: &crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'_, Message> {
    container(
        column![
            text("⚠️ Unsaved Changes")
                .size(20)
                .font(font)
                .color(theme.warning),
            text("You have unsaved changes in your current profile. What would you like to do?")
                .size(14)
                .font(font)
                .color(theme.fg_primary),
            row![
                button(text("Cancel").size(14).font(font))
                    .on_press(Message::CancelProfileSwitch)
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
                button(text("Discard").size(14).font(font))
                    .on_press(Message::DiscardProfileSwitch)
                    .padding([10, 20])
                    .style(move |_, status| danger_button(theme, status)),
                button(text("Save & Switch").size(14).font(font))
                    .on_press(Message::ConfirmProfileSwitch)
                    .padding([10, 24])
                    .style(move |_, status| primary_button(theme, status)),
            ]
            .spacing(12),
        ]
        .spacing(20)
        .padding(30)
        .max_width(500),
    )
    .style(move |_| {
        let mut style = card_container(theme);
        style.border = Border {
            color: theme.danger,
            width: 2.0,
            radius: 8.0.into(),
        };
        style
    })
    .into()
}

pub fn view_profile_manager<'a>(
    state: &'a State,
    mgr: &'a ProfileManagerState,
) -> Element<'a, Message> {
    let theme = &state.theme;

    let profiles_list: Element<'_, Message> = if state.available_profiles.is_empty() {
        text("No profiles found.")
            .font(state.font_regular)
            .color(theme.fg_muted)
            .into()
    } else {
        let mut list = column![].spacing(6);
        for name in &state.available_profiles {
            let is_active = name == &state.active_profile_name;

            let item: Element<'_, Message> = if let Some((old, current)) = &mgr.renaming_name
                && old == name
            {
                // Renaming mode: inline text input
                let is_valid_rename = crate::core::profiles::validate_profile_name(current).is_ok();
                let ok_button = if is_valid_rename {
                    button(text("OK").size(12).font(state.font_regular))
                        .on_press(Message::ConfirmRenameProfile)
                        .style(move |_, status| primary_button(theme, status))
                } else {
                    button(text("OK").size(12).font(state.font_regular))
                        .style(move |_, status| secondary_button(theme, status))
                };

                container(
                    row![
                        text_input("New name...", current)
                            .on_input(Message::ProfileNewNameChanged)
                            .on_submit(if is_valid_rename {
                                Message::ConfirmRenameProfile
                            } else {
                                Message::Noop
                            })
                            .padding(8)
                            .font(state.font_regular)
                            .style(move |_, status| themed_text_input(theme, status))
                            .width(Length::Fill),
                        ok_button,
                        button(text("Cancel").size(12).font(state.font_regular))
                            .on_press(Message::CancelRenameProfile)
                            .style(move |_, status| secondary_button(theme, status)),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center)
                    .padding([6, 10]),
                )
                .style(move |_| card_container(theme))
                .into()
            } else if let Some(del_name) = &mgr.deleting_name
                && del_name == name
            {
                // Delete confirmation mode
                container(
                    row![
                        text("Delete this profile?")
                            .size(11)
                            .font(state.font_regular)
                            .color(theme.danger)
                            .width(Length::Fill),
                        button(text("Cancel").size(11).font(state.font_regular))
                            .on_press(Message::CancelDeleteProfile)
                            .padding([4, 10])
                            .style(move |_, status| secondary_button(theme, status)),
                        button(text("Delete").size(11).font(state.font_regular))
                            .on_press(Message::ConfirmDeleteProfile)
                            .padding([4, 10])
                            .style(move |_, status| danger_button(theme, status)),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center)
                    .padding(8.0),
                )
                .style(move |_| card_container(theme))
                .into()
            } else {
                // Normal mode: clickable row
                button(
                    row![
                        text(name)
                            .size(13)
                            .font(state.font_regular)
                            .color(if is_active {
                                theme.accent
                            } else {
                                theme.fg_primary
                            })
                            .width(Length::Fill),
                        if is_active {
                            text("✓").size(14).color(theme.success)
                        } else {
                            text("").size(14)
                        },
                        button(text("✎").size(14).color(theme.fg_muted))
                            .on_press(Message::RenameProfileRequested(name.clone()))
                            .style(button::text),
                        // Hide delete button for active profile or last remaining profile
                        if !is_active && state.available_profiles.len() > 1 {
                            button(text("×").size(14).color(theme.fg_muted))
                                .on_press(Message::DeleteProfileRequested(name.clone()))
                                .padding(6)
                                .style(button::text)
                        } else {
                            button(text("").size(14)) // Placeholder for alignment
                                .style(button::text)
                        },
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center)
                    .padding([6, 10]),
                )
                .width(Length::Fill)
                .on_press(Message::ProfileSelected(name.clone()))
                .style(move |_, status| {
                    let mut style = card_button(theme, status);

                    // Active profile: accent border (like theme picker cards)
                    if is_active {
                        style.border = iced::Border {
                            color: theme.accent,
                            width: 2.0,
                            radius: 8.0.into(),
                        };
                    }

                    style
                })
                .into()
            };

            list = list.push(item);
        }

        // Wrap scrollable in bordered container
        container(
            scrollable(container(list).padding(Padding {
                top: 8.0,
                right: 8.0,
                bottom: 8.0,
                left: 8.0,
            }))
            .spacing(0) // Embedded mode prevents overlap, but adds tiny intrinsic space
            .style(move |_, status| {
                use crate::app::ui_components::themed_scrollable;
                themed_scrollable(theme, status)
            }),
        )
        .height(Length::Fixed(300.0))
        .width(Length::Fill)
        .style(move |_| container::Style {
            border: Border {
                radius: 8.0.into(),
                color: theme.border,
                width: 1.0,
            },
            ..Default::default()
        })
        .into()
    };

    container(
        column![
            container(
                text("Profiles")
                    .size(18)
                    .font(state.font_regular)
                    .color(theme.fg_primary)
            )
            .padding([4, 8])
            .style(move |_| section_header_container(theme)),
            profiles_list,
            if mgr.creating_new {
                let is_valid_name =
                    crate::core::profiles::validate_profile_name(&mgr.new_name_input).is_ok();
                let save_button = if is_valid_name {
                    button(text("Save").size(12).font(state.font_regular))
                        .on_press(Message::SaveProfileAs(mgr.new_name_input.clone()))
                        .style(move |_, status| primary_button(theme, status))
                } else {
                    button(text("Save").size(12).font(state.font_regular))
                        .style(move |_, status| secondary_button(theme, status))
                };

                container(
                    row![
                        text_input("New profile name...", &mgr.new_name_input)
                            .on_input(Message::NewProfileNameChanged)
                            .on_submit(if is_valid_name {
                                Message::SaveProfileAs(mgr.new_name_input.clone())
                            } else {
                                Message::Noop
                            })
                            .padding(8)
                            .font(state.font_regular)
                            .style(move |_, status| themed_text_input(theme, status))
                            .width(Length::Fill),
                        save_button,
                        button(text("Cancel").size(12).font(state.font_regular))
                            .on_press(Message::CancelCreatingNewProfile)
                            .style(move |_, status| secondary_button(theme, status)),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                )
                .padding(12)
                .style(move |_| card_container(theme))
            } else {
                container(
                    row![
                        button(text("+ New from Current").size(12).font(state.font_regular),)
                            .on_press(Message::StartCreatingNewProfile)
                            .padding([8, 12])
                            .style(move |_, status| primary_button(theme, status)),
                        button(text("+ New Empty").size(12).font(state.font_regular),)
                            .on_press(Message::CreateEmptyProfile)
                            .padding([8, 12])
                            .style(move |_, status| primary_button(theme, status)),
                    ]
                    .spacing(8),
                )
            },
            row![
                container(
                    text(format!("{} profiles", state.available_profiles.len()))
                        .size(10)
                        .font(state.font_mono)
                        .color(theme.fg_muted)
                )
                .padding([2, 6])
                .style(move |_| section_header_container(theme)),
                space::Space::new().width(Length::Fill),
                button(text("Close").size(14).font(state.font_regular))
                    .on_press(Message::CloseProfileManager)
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
            ]
            .align_y(Alignment::Center)
        ]
        .spacing(16)
        .padding(24)
        .width(Length::Fixed(550.0)), // Balanced width: spacious for 20-char names + scrollbar clearance
    )
    .style(move |_| card_container(theme))
    .into()
}
