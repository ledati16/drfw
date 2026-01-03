//! Modal dialogs (warnings and export)

use crate::app::ui_components::{card_button, card_container, danger_button, secondary_button};
use crate::app::{Message, PendingWarning};
use iced::widget::{button, column, container, row, text};
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
            text("📤 Export Rules")
                .size(24)
                .font(regular_font)
                .color(theme.warning),
            text("Choose the export format:")
                .size(14)
                .font(regular_font)
                .color(theme.fg_muted),
            column![
                button(
                    row![
                        text("📄").size(20),
                        column![
                            text("Export as JSON")
                                .size(16)
                                .font(regular_font)
                                .color(theme.fg_primary),
                            text("Structured data format for automation and backup")
                                .size(12)
                                .font(regular_font)
                                .color(theme.fg_muted),
                        ]
                        .spacing(4),
                    ]
                    .spacing(12)
                    .align_y(Alignment::Center)
                    .padding(16)
                )
                .on_press(Message::ExportAsJson)
                .style(move |_, status| card_button(theme, status))
                .width(Length::Fill),
                button(
                    row![
                        text("📝").size(20),
                        column![
                            text("Export as nftables text")
                                .size(16)
                                .font(regular_font)
                                .color(theme.fg_primary),
                            text("Human-readable .nft format for manual editing")
                                .size(12)
                                .font(regular_font)
                                .color(theme.fg_muted),
                        ]
                        .spacing(4),
                    ]
                    .spacing(12)
                    .align_y(Alignment::Center)
                    .padding(16)
                )
                .on_press(Message::ExportAsNft)
                .style(move |_, status| card_button(theme, status))
                .width(Length::Fill),
            ]
            .spacing(12),
            text("Files will be saved to ~/Downloads/ or your data directory")
                .size(11)
                .font(regular_font)
                .color(theme.fg_muted),
            button(text("Cancel").size(14).font(regular_font))
                .on_press(Message::ToggleExportModal(false)) // Toggle to close
                .padding([10, 20])
                .style(move |_, status| secondary_button(theme, status)),
        ]
        .spacing(20)
        .padding(32)
        .align_x(Alignment::Center),
    )
    .max_width(500)
    .style(move |_| card_container(theme))
    .into()
}
