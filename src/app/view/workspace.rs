//! Workspace tab bar and content area

use crate::app::ui_components::{
    active_tab_button, dirty_button, inactive_tab_button, primary_button, secondary_button,
    themed_checkbox, themed_scrollable,
};
use crate::app::{AppStatus, Message, State, WorkspaceTab};
use iced::widget::{button, checkbox, column, container, row, scrollable, text, Id};
use iced::{Alignment, Border, Element, Length, Shadow};

pub fn view_workspace<'a>(
    state: &'a State,
    preview_content: Element<'a, Message>,
) -> Element<'a, Message> {
    let theme = &state.theme;

    // Header: Tab Strip (Left) and Global Tools (Right)
    let nav_row = row![
        // Tab buttons - simple rounded buttons like Export/Diagnostics
        view_tab_button("Ruleset", WorkspaceTab::Nftables, state.active_tab, theme),
        view_tab_button("Settings", WorkspaceTab::Settings, state.active_tab, theme),
        container(row![]).width(Length::Fill),
        // Global Utility Tools
        button(text("Export").size(13).font(state.font_regular))
            .on_press(Message::ToggleExportModal(true))
            .padding([8, 16])
            .style(move |_, status| secondary_button(theme, status)),
        button(text("Diagnostics").size(13).font(state.font_regular))
            .on_press(Message::ToggleDiagnostics(true))
            .padding([8, 16])
            .style(move |_, status| secondary_button(theme, status)),
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    // Title and description row with optional diff checkbox
    let mut title_row = row![
        column![
            text(match state.active_tab {
                WorkspaceTab::Nftables => "Firewall Ruleset",
                WorkspaceTab::Settings => "Settings",
            })
            .size(20)
            .font(state.font_regular)
            .color(theme.fg_primary),
            text(match state.active_tab {
                WorkspaceTab::Nftables =>
                    "Current nftables configuration generated from your rules.",
                WorkspaceTab::Settings =>
                    "Configure application appearance and advanced firewall security hardening.",
            })
            .size(12)
            .font(state.font_regular)
            .color(theme.fg_muted),
        ]
        .spacing(2)
        .width(Length::Fill),
    ];

    // Add checkboxes in a vertical column when on Nftables tab
    if state.active_tab == WorkspaceTab::Nftables {
        let mut checkboxes = column![].spacing(8);

        // Add diff toggle when we have a previous version
        if state.last_applied_ruleset.is_some() {
            checkboxes = checkboxes.push(
                checkbox(state.show_diff)
                    .label("Show diff")
                    .on_toggle(Message::ToggleDiff)
                    .size(16)
                    .text_size(12)
                    .font(state.font_regular)
                    .spacing(6)
                    .style(move |_, status| themed_checkbox(theme, status)),
            );
        }

        // Always show zebra toggle on Nftables tab
        checkboxes = checkboxes.push(
            checkbox(state.show_zebra_striping)
                .label("Show zebra")
                .on_toggle(Message::ToggleZebraStriping)
                .size(16)
                .text_size(12)
                .font(state.font_regular)
                .spacing(6)
                .style(move |_, status| themed_checkbox(theme, status)),
        );

        title_row = title_row.push(checkboxes);
    }

    let preview_header = column![nav_row, title_row].spacing(20);

    // Settings tab only needs vertical scrolling, other tabs need both
    let scroll_direction = if matches!(state.active_tab, WorkspaceTab::Settings) {
        scrollable::Direction::Vertical(scrollable::Scrollbar::default())
    } else {
        scrollable::Direction::Both {
            vertical: scrollable::Scrollbar::default(),
            horizontal: scrollable::Scrollbar::default(),
        }
    };

    let editor = container(
        scrollable(
            container(preview_content)
                .padding(24)
                .width(Length::Fill)
                .height(Length::Fill),
        )
        .id(Id::new(super::WORKSPACE_SCROLLABLE_ID))
        .direction(scroll_direction)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |_, status| themed_scrollable(theme, status)),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(move |_| container::Style {
        background: Some(theme.bg_surface.into()),
        border: Border {
            color: theme.border,
            width: 1.0,
            radius: 8.0.into(),
        },
        shadow: Shadow {
            color: theme.shadow_color,
            offset: iced::Vector::new(0.0, 2.0),
            blur_radius: 3.0,
        },
        ..Default::default()
    });

    // Zone: History (Left)
    let history_actions = row![
        button(text("↶").size(18))
            .on_press_maybe(state.command_history.can_undo().then_some(Message::Undo))
            .padding([10, 16])
            .style(move |_, status| secondary_button(theme, status)),
        button(text("↷").size(18))
            .on_press_maybe(state.command_history.can_redo().then_some(Message::Redo))
            .padding([10, 16])
            .style(move |_, status| secondary_button(theme, status)),
    ]
    .spacing(12);

    // Zone: Commitment (Right)
    let is_busy = state.is_busy();

    let save_to_system = {
        let mut btn = button(text("Save to System").size(13).font(state.font_regular))
            .padding([10, 20])
            .style(move |_, status| secondary_button(theme, status));

        if !is_busy {
            btn = btn.on_press(Message::SaveToSystemClicked);
        }
        btn
    };

    let is_dirty = state.is_dirty();
    let apply_button = {
        let button_text = if matches!(state.status, AppStatus::Verifying) {
            "Verifying..."
        } else if is_busy {
            "Processing..."
        } else if is_dirty {
            "Apply Changes*"
        } else {
            "Apply Changes"
        };
        let mut btn = button(text(button_text).size(14).font(state.font_regular)).padding([10, 24]);

        if is_dirty && !is_busy {
            btn = btn.style(move |_, status| dirty_button(theme, status));
        } else {
            btn = btn.style(move |_, status| primary_button(theme, status));
        }

        if !is_busy {
            btn = btn.on_press(Message::ApplyClicked);
        }
        btn
    };

    let footer = row![
        history_actions,
        container(row![]).width(Length::Fill), // Spacer
        row![save_to_system, apply_button].spacing(12)
    ]
    .spacing(16)
    .align_y(Alignment::Center);

    // Version info - subtle, bottom-right
    let version_text = container(
        text(crate::version_string())
            .size(9)
            .font(state.font_mono)
            .color(theme.fg_muted),
    )
    .width(Length::Fill)
    .align_x(Alignment::End);

    let footer_section = column![footer, version_text].spacing(12);

    container(
        column![preview_header, editor, footer_section]
            .spacing(24)
            .padding(32),
    )
    .width(Length::Fill)
    .into()
}

pub fn view_tab_button<'a>(
    label: &'static str,
    tab: WorkspaceTab,
    active_tab: WorkspaceTab,
    theme: &'a crate::theme::AppTheme,
) -> Element<'a, Message> {
    let is_active = tab == active_tab;
    button(text(label).size(13))
        .padding([8, 16])
        .style(move |_, status| {
            if is_active {
                active_tab_button(theme, status)
            } else {
                inactive_tab_button(theme, status)
            }
        })
        .on_press(Message::TabChanged(tab))
        .into()
}
