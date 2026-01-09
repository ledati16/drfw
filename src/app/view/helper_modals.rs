//! Helper modals for multi-value field editing
//!
//! Provides reusable modal components for editing Vec fields in rule forms:
//! - Ports: Single ports or ranges (e.g., "22", "8000-8080")
//! - Addresses: IP/CIDR addresses (e.g., "192.168.1.0/24", "fd00::1")
//! - Tags: Organizational labels

use crate::app::ui_components::{
    card_container, primary_button, section_header_container, tag_button, themed_scrollable,
    themed_text_input,
};
use crate::app::{HelperType, Message, RuleForm, RuleFormHelper};
use crate::core::firewall::PortEntry;
use iced::widget::{Space, button, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Border, Color, Element, Length};

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
        // Error message
        {
            if let Some(err) = &helper.error {
                container(text(err).size(12).font(regular_font).color(theme.danger))
            } else {
                container(Space::new())
            }
        },
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
                    column(form.ports.iter().enumerate().map(|(i, port)| {
                        let port_text = match port {
                            PortEntry::Single(p) => p.to_string(),
                            PortEntry::Range { start, end } => format!("{}-{}", start, end),
                        };
                        row![
                            text(port_text)
                                .size(13)
                                .font(mono_font)
                                .color(theme.fg_primary),
                            Space::new().width(Length::Fill),
                            button(text("×").size(14).font(regular_font).color(theme.danger))
                                .on_press(Message::HelperRemoveValue(i))
                                .padding(4)
                                .style(button::text),
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center)
                        .into()
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
        .style(move |_| container::Style {
            border: Border {
                radius: 8.0.into(),
                color: theme.border,
                width: 1.0,
            },
            ..Default::default()
        }),
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
        &form.sources
    } else {
        &form.destinations
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
        // Error message
        {
            if let Some(err) = &helper.error {
                container(text(err).size(12).font(regular_font).color(theme.danger))
            } else {
                container(Space::new())
            }
        },
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
                        row![
                            text(addr.to_string())
                                .size(13)
                                .font(mono_font)
                                .color(theme.fg_primary),
                            Space::new().width(Length::Fill),
                            button(text("×").size(14).font(regular_font).color(theme.danger))
                                .on_press(Message::HelperRemoveValue(i))
                                .padding(4)
                                .style(button::text),
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center)
                        .into()
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
        .style(move |_| container::Style {
            border: Border {
                radius: 8.0.into(),
                color: theme.border,
                width: 1.0,
            },
            ..Default::default()
        }),
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
        text("Add organizational labels (max 10 tags)")
            .size(12)
            .font(regular_font)
            .color(theme.fg_muted),
        // Input row
        row![
            text_input("e.g. web-server, production", &helper.input)
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
        // Error message
        {
            if let Some(err) = &helper.error {
                container(text(err).size(12).font(regular_font).color(theme.danger))
            } else {
                container(Space::new())
            }
        },
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
                        row(form.tags.iter().enumerate().map(|(i, tag)| {
                            // Truncate long tags for display (same as tag cloud)
                            let display_tag: std::borrow::Cow<'_, str> = if tag.len() > 16 {
                                format!("{}…", &tag[..15]).into()
                            } else {
                                tag.as_str().into()
                            };
                            button(
                                row![
                                    text(display_tag).size(10).font(regular_font),
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
        .style(move |_| {
            // STYLE.md Section 10: Hybrid Darkening/Brightening for background
            let bg = if theme.is_light() {
                Color {
                    r: theme.bg_surface.r * 0.92,
                    g: theme.bg_surface.g * 0.92,
                    b: theme.bg_surface.b * 0.92,
                    ..theme.bg_surface
                }
            } else {
                Color {
                    r: (theme.bg_surface.r * 1.15 + 0.02).min(1.0),
                    g: (theme.bg_surface.g * 1.15 + 0.02).min(1.0),
                    b: (theme.bg_surface.b * 1.15 + 0.02).min(1.0),
                    ..theme.bg_surface
                }
            };
            container::Style {
                background: Some(bg.into()),
                border: Border {
                    radius: 8.0.into(),
                    color: theme.border,
                    width: 1.0,
                },
                ..Default::default()
            }
        }),
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

/// Returns a summary string for ports (used in main form)
pub fn ports_summary(ports: &[PortEntry]) -> String {
    if ports.is_empty() {
        "All ports".to_string()
    } else if ports.len() == 1 {
        match &ports[0] {
            PortEntry::Single(p) => format!("Port {}", p),
            PortEntry::Range { start, end } => format!("Ports {}-{}", start, end),
        }
    } else {
        format!("{} ports configured", ports.len())
    }
}

/// Returns a summary string for addresses (used in main form)
pub fn addresses_summary(addresses: &[ipnetwork::IpNetwork]) -> String {
    if addresses.is_empty() {
        "Any".to_string()
    } else if addresses.len() == 1 {
        addresses[0].to_string()
    } else {
        format!("{} addresses", addresses.len())
    }
}

/// Returns a summary string for tags (used in main form)
pub fn tags_summary(tags: &[String]) -> String {
    if tags.is_empty() {
        "No tags".to_string()
    } else if tags.len() == 1 {
        // Truncate long tags for display (same as tag cloud)
        if tags[0].len() > 16 {
            format!("{}…", &tags[0][..15])
        } else {
            tags[0].clone()
        }
    } else {
        format!("{} tags", tags.len())
    }
}
