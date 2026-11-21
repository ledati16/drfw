//! Modal dialogs (warnings and export)

use iced::widget::{button, checkbox, column, container, row, space, text};
use iced::{Alignment, Border, Element, Length};

use crate::app::ui_components::{
    card_container, danger_button, primary_button, secondary_button, section_header_container,
    themed_checkbox,
};
use crate::app::{Message, PendingWarning};

/// The RPF warning (true of the strict reverse path check DRFW generates:
/// after established/related, so new packets only, keyed by the routing
/// mark; see README "Anti-spoofing").
const RPF_WARNING: &str = "Drop new connections whose source address could not have arrived \
on that interface (strict reverse path filtering). Useful with rules that trust a source \
address, such as \"SSH from 192.168.1.0/24 only\".\n\n\
Only new connections are checked, and the routing mark VPNs set is honoured, so Docker and \
libvirt bridges, split-tunnel VPNs and full-tunnel VPN clients (wg-quick, a Tailscale exit \
node) keep working.\n\n\
It may block:\n\n    \
• Peers that contact a full-tunnel VPN host first over its underlying network (not through \
the tunnel)\n    \
• Asymmetric routing: new connections from an address that arrive on another interface \
than the route back to it";

/// The Server Mode warning, above the essential-rule checkboxes.
const SERVER_MODE_WARNING: &str = "Outgoing connections are blocked unless a rule allows \
them. Replies to accepted connections, loopback, IPv6 neighbor discovery and DHCP keep \
working, so an open SSH session is not cut off.\n\n\
Without rules this computer can't look up names, set its clock or download updates. \
Add these Output rules now (ordinary rules you can edit or delete later):";

/// The Strict ICMP warning (the strict sets include IPv6 router
/// solicitations and the MLD reports, so nothing a network needs is lost).
const STRICT_ICMP_WARNING: &str = "This allows only the ICMP types networks need:\n\n    \
✓ Ping (echo-request/echo-reply)\n    \
✓ MTU discovery (packet-too-big)\n    \
✓ Error reporting (destination-unreachable, time-exceeded, parameter-problem)\n    \
✓ IPv6 neighbor and router discovery (SLAAC) and multicast listener (MLD) messages\n\n\
Ping, traceroute and MTU discovery keep working. Only rarely used types are blocked, such \
as timestamp and address-mask requests and other exotic ICMP.";

pub fn view_warning_modal<'a>(
    warning: &'a PendingWarning,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
) -> Element<'a, Message> {
    let (title, message, confirm_msg) = match warning {
        PendingWarning::EnableRpf => (
            "WARNING: Anti-Spoofing Mode",
            RPF_WARNING,
            Message::ConfirmEnableRpf,
        ),
        PendingWarning::EnableServerMode(_) => (
            "Server Mode: Egress Filtering",
            SERVER_MODE_WARNING,
            Message::ConfirmServerMode,
        ),
        PendingWarning::EnableStrictIcmp => (
            "Strict ICMP Mode",
            STRICT_ICMP_WARNING,
            Message::ConfirmStrictIcmp,
        ),
    };

    let mut content = column![
        text(title).size(20).font(regular_font).color(theme.danger),
        text(message)
            .size(14)
            .color(theme.fg_primary)
            .font(regular_font),
    ]
    .spacing(20);

    // Server Mode: the essential Output rules, pre-ticked (labels built
    // when the dialog opened)
    if let PendingWarning::EnableServerMode(essentials) = warning {
        content = content.push(
            column(
                essentials
                    .choices
                    .iter()
                    .enumerate()
                    .map(|(index, choice)| {
                        checkbox(choice.ticked)
                            .label(choice.label.as_str())
                            .on_toggle(move |ticked| Message::ServerEssentialToggled(index, ticked))
                            .size(16)
                            .text_size(14)
                            .font(regular_font)
                            .spacing(8)
                            .style(move |_, status| themed_checkbox(theme, status))
                            .into()
                    }),
            )
            .spacing(8)
            .padding([0, 16]),
        );
    }

    content = content.push(
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
    );

    container(content.padding(30).max_width(600))
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

/// Export dialog. While a file dialog is open (`in_progress`), the export
/// buttons are disabled so a second one can't be opened.
pub fn view_export_modal(
    theme: &crate::theme::AppTheme,
    regular_font: iced::Font,
    in_progress: bool,
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
                        text("nftables JSON for scripts and automation (cannot be imported back)")
                            .size(11)
                            .font(regular_font)
                            .color(theme.fg_on_accent),
                    ]
                    .spacing(4)
                    .padding(16)
                )
                .on_press_maybe((!in_progress).then_some(Message::ExportAsJson))
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
                .on_press_maybe((!in_progress).then_some(Message::ExportAsNft))
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

/// Dialog after saving on close failed: keep DRFW open (primary, Enter and
/// Escape) or close and lose the changes.
pub fn view_close_failed<'a>(
    message: &'a str,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
) -> Element<'a, Message> {
    container(
        column![
            text("Changes not saved")
                .size(20)
                .font(regular_font)
                .color(theme.danger),
            text(message)
                .size(14)
                .font(regular_font)
                .color(theme.fg_primary),
            row![
                button(text("Close anyway").size(14).font(regular_font))
                    .on_press(Message::CloseAnyway)
                    .padding([10, 20])
                    .style(move |_, status| danger_button(theme, status)),
                space::Space::new().width(Length::Fill),
                button(text("Keep DRFW open").size(14).font(regular_font))
                    .on_press(Message::CancelClose)
                    .padding([10, 24])
                    .style(move |_, status| primary_button(theme, status)),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        ]
        .spacing(20)
        .padding(30)
        .max_width(520),
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
