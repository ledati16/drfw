//! Helper modals for multi-value field editing
//!
//! Provides reusable modal components for editing Vec fields in rule forms:
//! - Ports: Single ports or ranges (e.g., "22", "8000-8080")
//! - Addresses: IP/CIDR addresses (e.g., "192.168.1.0/24", "`fd00::1`")
//! - Tags: Organizational labels

use iced::widget::{Space, button, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Element, Length};

use crate::app::ui_components::{
    card_container, inset_container_bordered, primary_button, section_header_container, tag_button,
    themed_scrollable, themed_text_input,
};
use crate::app::{HelperType, Message, RuleForm, RuleFormHelper};

/// The helper's feedback line: the error (danger color) or a neutral notice.
fn view_feedback<'a>(
    helper: &'a RuleFormHelper,
    theme: &crate::theme::AppTheme,
    regular_font: iced::Font,
) -> Element<'a, Message> {
    if let Some(err) = &helper.error {
        container(text(err).size(12).font(regular_font).color(theme.danger)).into()
    } else if let Some(notice) = &helper.notice {
        container(
            text(notice)
                .size(12)
                .font(regular_font)
                .color(theme.fg_muted),
        )
        .into()
    } else {
        container(Space::new()).into()
    }
}

/// One removable entry of a ports/addresses helper list.
fn view_list_item<'a>(
    index: usize,
    label: &'a str,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    row![
        text(label).size(13).font(mono_font).color(theme.fg_primary),
        Space::new().width(Length::Fill),
        button(text("×").size(14).font(regular_font).color(theme.danger))
            .on_press(Message::HelperRemoveValue(index))
            .padding(4)
            .style(button::text),
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}

/// Renders the helper modal based on current helper type
pub fn view_helper_modal<'a>(
    form: &'a RuleForm,
    helper: &'a RuleFormHelper,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    let Some(helper_type) = helper.helper_type else {
        return Space::new().into();
    };

    match helper_type {
        HelperType::Ports => view_ports_helper(form, helper, theme, regular_font, mono_font),
        HelperType::SourceAddresses => {
            view_addresses_helper(form, helper, theme, regular_font, mono_font, true)
        }
        HelperType::DestinationAddresses => {
            view_addresses_helper(form, helper, theme, regular_font, mono_font, false)
        }
        HelperType::Tags => view_tags_helper(form, helper, theme, regular_font, mono_font),
    }
}

/// Ports helper modal
fn view_ports_helper<'a>(
    form: &'a RuleForm,
    helper: &'a RuleFormHelper,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    let content = column![
        // Header
        text("Configure Ports")
            .size(18)
            .font(regular_font)
            .color(theme.info),
        text("Add single ports (22) or ranges (8000-8080)")
            .size(12)
            .font(regular_font)
            .color(theme.fg_muted),
        // Input row
        row![
            text_input("e.g. 22 or 8000-8080", &helper.input)
                .id(crate::app::focus::HELPER_INPUT)
                .on_input(Message::HelperInputChanged)
                .on_submit(Message::HelperAddValue)
                .padding(8)
                .width(Length::Fill)
                .font(mono_font)
                .style(move |_, status| themed_text_input(theme, status)),
            button(text("+").size(16).font(regular_font))
                .on_press(Message::HelperAddValue)
                .padding([8, 16])
                .style(move |_, status| primary_button(theme, status)),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        // Error or notice
        view_feedback(helper, theme, regular_font),
        // Current values list
        container(
            text("CONFIGURED PORTS")
                .size(9)
                .font(mono_font)
                .color(theme.fg_muted)
        )
        .padding([2, 6])
        .style(move |_| section_header_container(theme)),
        // STYLE.md Section 17, Pattern 2: Bordered scrollable
        container(
            scrollable(
                container(
                    column(form.display.port_items.iter().enumerate().map(|(i, port)| {
                        view_list_item(i, port, theme, regular_font, mono_font)
                    }))
                    .spacing(4),
                )
                .width(Length::Fill)
                .padding(8),
            )
            .direction(scrollable::Direction::Vertical(
                scrollable::Scrollbar::new().spacing(0),
            ))
            .style(move |_, status| themed_scrollable(theme, status)),
        )
        .height(Length::Fixed(150.0))
        .width(Length::Fill)
        .style(move |_| inset_container_bordered(theme)),
        // Footer
        row![
            button(text("Done").size(14).font(regular_font))
                .on_press(Message::CloseHelper)
                .padding([10, 24])
                .style(move |_, status| primary_button(theme, status)),
        ]
        .spacing(16)
        .align_y(Alignment::Center),
    ]
    .spacing(12)
    .padding(20);

    container(content)
        .max_width(400)
        .style(move |_| card_container(theme))
        .into()
}

/// Addresses helper modal (reused for source and destination)
fn view_addresses_helper<'a>(
    form: &'a RuleForm,
    helper: &'a RuleFormHelper,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
    is_source: bool,
) -> Element<'a, Message> {
    let title = if is_source {
        "Configure Source Addresses"
    } else {
        "Configure Destination Addresses"
    };
    let addresses = if is_source {
        &form.display.source_items
    } else {
        &form.display.destination_items
    };
    let header_text = if is_source {
        "SOURCE ADDRESSES"
    } else {
        "DESTINATION ADDRESSES"
    };

    let content = column![
        // Header
        text(title).size(18).font(regular_font).color(theme.info),
        text("Add IP addresses or CIDR blocks (e.g., 192.168.1.0/24)")
            .size(12)
            .font(regular_font)
            .color(theme.fg_muted),
        // Input row
        row![
            text_input("e.g. 192.168.1.0/24 or 10.0.0.1", &helper.input)
                .id(crate::app::focus::HELPER_INPUT)
                .on_input(Message::HelperInputChanged)
                .on_submit(Message::HelperAddValue)
                .padding(8)
                .width(Length::Fill)
                .font(mono_font)
                .style(move |_, status| themed_text_input(theme, status)),
            button(text("+").size(16).font(regular_font))
                .on_press(Message::HelperAddValue)
                .padding([8, 16])
                .style(move |_, status| primary_button(theme, status)),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        // Error or notice
        view_feedback(helper, theme, regular_font),
        // Current values list
        container(
            text(header_text)
                .size(9)
                .font(mono_font)
                .color(theme.fg_muted)
        )
        .padding([2, 6])
        .style(move |_| section_header_container(theme)),
        // STYLE.md Section 17, Pattern 2: Bordered scrollable
        container(
            scrollable(
                container(
                    column(addresses.iter().enumerate().map(|(i, addr)| {
                        view_list_item(i, addr, theme, regular_font, mono_font)
                    }))
                    .spacing(4),
                )
                .width(Length::Fill)
                .padding(8),
            )
            .direction(scrollable::Direction::Vertical(
                scrollable::Scrollbar::new().spacing(0),
            ))
            .style(move |_, status| themed_scrollable(theme, status)),
        )
        .height(Length::Fixed(150.0))
        .width(Length::Fill)
        .style(move |_| inset_container_bordered(theme)),
        // Footer
        row![
            button(text("Done").size(14).font(regular_font))
                .on_press(Message::CloseHelper)
                .padding([10, 24])
                .style(move |_, status| primary_button(theme, status)),
        ]
        .spacing(16)
        .align_y(Alignment::Center),
    ]
    .spacing(12)
    .padding(20);

    container(content)
        .max_width(400)
        .style(move |_| card_container(theme))
        .into()
}

/// Tags helper modal
fn view_tags_helper<'a>(
    form: &'a RuleForm,
    helper: &'a RuleFormHelper,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    _mono_font: iced::Font,
) -> Element<'a, Message> {
    let content = column![
        // Header
        text("Configure Tags")
            .size(18)
            .font(regular_font)
            .color(theme.info),
        text("Add organizational labels (max 10 tags; separate several with commas)")
            .size(12)
            .font(regular_font)
            .color(theme.fg_muted),
        // Input row
        row![
            text_input("e.g. web-server, production", &helper.input)
                .id(crate::app::focus::HELPER_INPUT)
                .on_input(Message::HelperInputChanged)
                .on_submit(Message::HelperAddValue)
                .padding(8)
                .width(Length::Fill)
                .font(regular_font)
                .style(move |_, status| themed_text_input(theme, status)),
            button(text("+").size(16).font(regular_font))
                .on_press(Message::HelperAddValue)
                .padding([8, 16])
                .style(move |_, status| primary_button(theme, status)),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        // Error or notice
        view_feedback(helper, theme, regular_font),
        // Section header (matches ports/addresses helpers)
        container(
            text("CONFIGURED TAGS")
                .size(9)
                .font(regular_font)
                .color(theme.fg_muted)
        )
        .padding([2, 6])
        .style(move |_| section_header_container(theme)),
        // Tag chips in scrollable container with background (matches sidebar tag cloud)
        container(
            scrollable(
                container({
                    let tag_content: Element<'_, Message> = if form.tags.is_empty() {
                        text("No tags configured")
                            .size(12)
                            .font(regular_font)
                            .color(theme.fg_muted)
                            .into()
                    } else {
                        row(form.display.tag_items.iter().enumerate().map(|(i, tag)| {
                            // Cut like the tag cloud (cached in the form)
                            button(
                                row![
                                    text(tag).size(10).font(regular_font),
                                    text("×").size(12).font(regular_font).color(theme.danger),
                                ]
                                .spacing(6)
                                .align_y(Alignment::Center),
                            )
                            .on_press(Message::HelperRemoveValue(i))
                            .padding([4, 8])
                            .style(move |_, status| tag_button(theme, status))
                            .into()
                        }))
                        .spacing(6)
                        .wrap()
                        .into()
                    };
                    tag_content
                })
                .width(Length::Fill)
                .padding(8),
            )
            .direction(scrollable::Direction::Vertical(
                scrollable::Scrollbar::new().spacing(0),
            ))
            .style(move |_, status| themed_scrollable(theme, status)),
        )
        .height(Length::Fixed(100.0))
        .width(Length::Fill)
        .style(move |_| inset_container_bordered(theme)),
        // Footer
        row![
            button(text("Done").size(14).font(regular_font))
                .on_press(Message::CloseHelper)
                .padding([10, 24])
                .style(move |_, status| primary_button(theme, status)),
        ]
        .spacing(16)
        .align_y(Alignment::Center),
    ]
    .spacing(12)
    .padding(20);

    container(content)
        .max_width(400)
        .style(move |_| card_container(theme))
        .into()
}
