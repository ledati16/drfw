//! Modal dialogs (warnings and export)

use crate::app::ui_components::{
    card_container, danger_button, primary_button, secondary_button, section_header_container,
};
use crate::app::{Message, PendingWarning};
use iced::widget::{button, column, container, row, space, text};
use iced::{Alignment, Border, Element, Length};

pub fn view_warning_modal<'a>(
    warning: &'a PendingWarning,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
) -> Element<'a, Message> {
    let (title, message, confirm_msg) = match warning {
        PendingWarning::EnableRpf => (
            "⚠️ WARNING: Anti-Spoofing Mode",
            "Enabling this feature may break:\n\n    • Docker containers\n    • VPN connections (WireGuard, OpenVPN)\n    • Multi-homed systems\n    • AWS/GCP cloud instances\n\nOnly enable if:\n    ✓ You don't use Docker or VPNs\n    ✓ This is a single-interface server\n    ✓ You understand reverse path filtering\n\nAlternative: Use kernel RPF instead:\n  \n      sudo sysctl net.ipv4.conf.all.rp_filter=1",
            Message::ConfirmEnableRpf,
        ),
        PendingWarning::EnableServerMode => (
            "⚠️ Server Mode: Egress Filtering",
            "This will BLOCK all outbound connections by default.\n\nYou'll need to explicitly allow:\n    • Web browsing (HTTP/HTTPS)\n    • DNS queries\n    • Software updates\n    • Any services your applications use\n\nThis mode is designed for servers, not desktop use.",
            Message::ConfirmServerMode,
        ),
    };

    container(
        column![
            text(title).size(20).font(regular_font).color(theme.danger),
            text(message)
                .size(14)
                .color(theme.fg_primary)
                .font(regular_font),
            row![
                button(text("Cancel").size(14).font(regular_font))
                    .on_press(Message::CancelWarning)
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
                button(text("Yes, I understand").size(14).font(regular_font))
                    .on_press(confirm_msg)
                    .padding([10, 24])
                    .style(move |_, status| danger_button(theme, status)),
            ]
            .spacing(12),
        ]
        .spacing(20)
        .padding(30)
        .max_width(600),
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

pub fn view_export_modal(
    theme: &crate::theme::AppTheme,
    regular_font: iced::Font,
) -> Element<'_, Message> {
    container(
        column![
            container(
                text("Export")
                    .size(18)
                    .font(regular_font)
                    .color(theme.fg_primary)
            )
            .padding([4, 8])
            .style(move |_| section_header_container(theme)),
            text("Choose export format:")
                .size(12)
                .font(regular_font)
                .color(theme.fg_muted),
            column![
                button(
                    column![
                        text("Export as JSON")
                            .size(14)
                            .font(regular_font)
                            .color(theme.fg_on_accent),
                        text("Structured data format for automation and backup")
                            .size(11)
                            .font(regular_font)
                            .color(theme.fg_on_accent),
                    ]
                    .spacing(4)
                    .padding(16)
                )
                .on_press(Message::ExportAsJson)
                .style(move |_, status| primary_button(theme, status))
                .width(Length::Fill),
                button(
                    column![
                        text("Export as nftables text")
                            .size(14)
                            .font(regular_font)
                            .color(theme.fg_on_accent),
                        text("Human-readable .nft format for manual editing")
                            .size(11)
                            .font(regular_font)
                            .color(theme.fg_on_accent),
                    ]
                    .spacing(4)
                    .padding(16)
                )
                .on_press(Message::ExportAsNft)
                .style(move |_, status| primary_button(theme, status))
                .width(Length::Fill),
            ]
            .spacing(12),
            row![
                space::Space::new().width(Length::Fill),
                button(text("Cancel").size(14).font(regular_font))
                    .on_press(Message::ToggleExportModal(false))
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
            ]
            .align_y(Alignment::Center),
        ]
        .spacing(16)
        .padding(24),
    )
    .max_width(500)
    .style(move |_| card_container(theme))
    .into()
}
