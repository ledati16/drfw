//! Profile management UI components

use crate::app::ui_components::{
    card_container, danger_button, primary_button, secondary_button, themed_text_input,
};
use crate::app::{Message, ProfileManagerState, State};
use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Border, Element, Length};

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
        let mut list = column![].spacing(8);
        for name in &state.available_profiles {
            let is_active = name == &state.active_profile_name;

            let mut row_content = row![
                text(name)
                    .size(14)
                    .font(state.font_regular)
                    .color(if is_active {
                        theme.accent
                    } else {
                        theme.fg_primary
                    })
                    .width(Length::Fill),
            ]
            .spacing(12)
            .align_y(Alignment::Center);

            if let Some((old, current)) = &mgr.renaming_name
                && old == name
            {
                let is_valid_rename = crate::core::profiles::validate_profile_name(current).is_ok();
                let ok_button = if is_valid_rename {
                    button(text("OK").size(12).font(state.font_regular))
                        .on_press(Message::ConfirmRenameProfile)
                        .style(move |_, status| primary_button(theme, status))
                } else {
                    button(text("OK").size(12).font(state.font_regular))
                        .style(move |_, status| secondary_button(theme, status))
                };

                row_content = row![
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
                .align_y(Alignment::Center);
            } else if let Some(del_name) = &mgr.deleting_name
                && del_name == name
            {
                row_content = row![
                    text("Delete profile?")
                        .size(12)
                        .font(state.font_regular)
                        .color(theme.danger)
                        .width(Length::Fill),
                    button(text("No").size(12).font(state.font_regular))
                        .on_press(Message::CancelDeleteProfile)
                        .style(move |_, status| secondary_button(theme, status)),
                    button(text("Yes, Delete").size(12).font(state.font_regular))
                        .on_press(Message::ConfirmDeleteProfile)
                        .style(move |_, status| danger_button(theme, status)),
                ]
                .spacing(8)
                .align_y(Alignment::Center);
            } else if !is_active {
                row_content = row_content
                    .push(
                        button(text("Select").size(12).font(state.font_regular))
                            .on_press(Message::ProfileSelected(name.clone()))
                            .padding([4, 8])
                            .style(move |_, status| primary_button(theme, status)),
                    )
                    .push(
                        button(text("✎").size(14))
                            .on_press(Message::RenameProfileRequested(name.clone()))
                            .style(button::text),
                    )
                    .push(
                        button(text("🗑").size(14))
                            .on_press(Message::DeleteProfileRequested(name.clone()))
                            .style(button::text),
                    );
            } else {
                row_content = row_content.push(
                    text("(Active)")
                        .size(11)
                        .font(state.font_regular)
                        .color(theme.fg_muted),
                );
            }

            list = list.push(
                container(row_content)
                    .padding(12)
                    .style(move |_| card_container(theme)),
            );
        }
        scrollable(list).height(Length::Fixed(300.0)).into()
    };

    container(
        column![
            row![
                text("🗂 Profile Manager")
                    .size(24)
                    .font(state.font_regular)
                    .color(theme.accent),
                container(row![]).width(Length::Fill),
                button(text("×").size(20).font(state.font_regular))
                    .on_press(Message::CloseProfileManager)
                    .style(button::text),
            ]
            .align_y(Alignment::Center),
            profiles_list,
            if mgr.creating_new {
                let is_valid_name = crate::core::profiles::validate_profile_name(&mgr.new_name_input).is_ok();
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
                    button(
                        text("+ Add Profile from Current Rules")
                            .size(13)
                            .font(state.font_regular),
                    )
                    .on_press(Message::StartCreatingNewProfile)
                    .width(Length::Fill)
                    .padding(12)
                    .style(move |_, status| secondary_button(theme, status)),
                )
                .width(Length::Fill)
            },
            row![
                container(row![]).width(Length::Fill),
                button(text("Close").size(13).font(state.font_regular))
                    .on_press(Message::CloseProfileManager)
                    .padding([10, 20])
                    .style(move |_, status| primary_button(theme, status)),
            ]
            .spacing(12)
        ]
        .spacing(20)
        .padding(32)
        .width(Length::Fixed(600.0)),
    )
    .style(move |_| card_container(theme))
    .into()
}
