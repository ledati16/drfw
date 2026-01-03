//! Diagnostics modal and event log viewer

use crate::app::ui_components::{
    card_container, danger_button, primary_button, secondary_button, themed_horizontal_rule,
    themed_pick_list, themed_pick_list_menu, themed_scrollable,
};
use crate::app::{DiagnosticsFilter, Message, State};
use crate::audit::{AuditEvent, EventType};
use crate::utils::get_state_dir;
use iced::widget::{button, column, container, pick_list, row, rule, scrollable, text};
use iced::{Alignment, Border, Element, Length};

/// Formats an audit event for display in the Diagnostics modal
pub fn format_audit_event<'a>(
    event: &AuditEvent,
    theme: &crate::theme::AppTheme,
    font: iced::Font,
) -> Element<'a, Message> {
    // Format timestamp as HH:MM:SS
    let time = event.timestamp.format("%H:%M:%S").to_string();

    // Choose icon and color based on event type and success
    let (icon, icon_color, description) = match (&event.event_type, event.success) {
        (EventType::ApplyRules, true) => (
            "✓",
            theme.success,
            format!(
                "Applied {} rules ({} enabled)",
                event.details["rule_count"], event.details["enabled_count"]
            ),
        ),
        (EventType::ApplyRules, false) => (
            "✗",
            theme.danger,
            format!(
                "Failed to apply rules: {}",
                event.error.as_deref().unwrap_or("Unknown error")
            ),
        ),
        (EventType::RevertRules, true) => (
            "⟲",
            theme.warning,
            "Reverted to previous ruleset".to_string(),
        ),
        (EventType::RevertRules, false) => (
            "✗",
            theme.danger,
            format!(
                "Revert failed: {}",
                event.error.as_deref().unwrap_or("Unknown error")
            ),
        ),
        (EventType::VerifyRules, true) => (
            "✓",
            theme.success,
            "Rules verified successfully".to_string(),
        ),
        (EventType::VerifyRules, false) => (
            "✗",
            theme.danger,
            format!(
                "Verification failed: {} errors",
                event.details["error_count"]
            ),
        ),
        (EventType::ProfileCreated, _) => (
            "➕",
            theme.accent,
            format!("Created profile '{}'", event.details["profile_name"]),
        ),
        (EventType::ProfileDeleted, _) => (
            "➖",
            theme.accent,
            format!("Deleted profile '{}'", event.details["profile_name"]),
        ),
        (EventType::ProfileRenamed, _) => (
            "✎",
            theme.accent,
            format!(
                "Renamed profile '{}' → '{}'",
                event.details["old_name"], event.details["new_name"]
            ),
        ),
        (EventType::ProfileSwitched, _) => (
            "↔",
            theme.accent,
            format!(
                "Switched profile: '{}' → '{}'",
                event.details["from"], event.details["to"]
            ),
        ),
        (EventType::SettingsSaved, _) => (
            "⚙",
            theme.accent,
            event.details["description"]
                .as_str()
                .unwrap_or("Settings saved")
                .to_string(),
        ),
        (EventType::AutoRevertConfirmed, _) => (
            "✓",
            theme.success,
            format!(
                "Auto-revert confirmed ({}s timeout)",
                event.details["timeout_secs"]
            ),
        ),
        (EventType::AutoRevertTimedOut, _) => (
            "⏱",
            theme.warning,
            format!("Auto-revert timed out ({}s)", event.details["timeout_secs"]),
        ),
        (EventType::ElevationCancelled, _) => (
            "⚠",
            theme.warning,
            "Authentication cancelled by user".to_string(),
        ),
        (EventType::ElevationFailed, _) => (
            "✗",
            theme.danger,
            format!(
                "Authentication failed: {}",
                event.error.as_deref().unwrap_or("Unknown error")
            ),
        ),
        (EventType::RuleCreated, _) => (
            "➕",
            theme.success,
            format!(
                "Created rule '{}'{}",
                event.details["label"].as_str().unwrap_or(""),
                event.details["ports"]
                    .as_str()
                    .map(|p| format!(" ({})", p))
                    .unwrap_or_default()
            ),
        ),
        (EventType::RuleDeleted, _) => (
            "➖",
            theme.danger,
            format!(
                "Deleted rule '{}'",
                event.details["label"].as_str().unwrap_or("")
            ),
        ),
        (EventType::RuleModified, _) => (
            "✎",
            theme.accent,
            format!(
                "Modified rule '{}'{}",
                event.details["label"].as_str().unwrap_or(""),
                event.details["ports"]
                    .as_str()
                    .map(|p| format!(" ({})", p))
                    .unwrap_or_default()
            ),
        ),
        (EventType::RuleToggled, _) => (
            "⏻",
            theme.accent,
            format!(
                "Rule '{}' {}",
                event.details["label"].as_str().unwrap_or(""),
                if event.details["enabled"].as_bool().unwrap_or(false) {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
        ),
        (EventType::RulesReordered, _) => (
            "↕",
            theme.accent,
            format!(
                "Moved rule '{}' {}",
                event.details["label"].as_str().unwrap_or(""),
                event.details["direction"].as_str().unwrap_or("")
            ),
        ),
        (EventType::ExportCompleted, _) => (
            "📤",
            theme.success,
            format!(
                "Exported {} to {}",
                event.details["format"].as_str().unwrap_or("rules"),
                event.details["path"].as_str().unwrap_or("")
            ),
        ),
    };

    row![
        text(time).size(13).font(font).color(theme.fg_muted),
        text(icon).size(15).color(icon_color),
        text(description)
            .size(14)
            .font(font)
            .color(theme.fg_primary),
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .width(Length::Fill)
    .into()
}

pub fn view_diagnostics_modal<'a>(
    state: &'a State,
    theme: &'a crate::theme::AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    // Read and parse audit log entries
    let audit_entries = std::fs::read_to_string(
        get_state_dir()
            .map(|mut p| {
                p.push("audit.log");
                p
            })
            .unwrap_or_default(),
    )
    .unwrap_or_default();

    // Parse JSON Lines format and filter based on selection
    let parsed_events: Vec<AuditEvent> = audit_entries
        .lines()
        .rev()
        .take(100)
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    // Apply filter
    let filtered_events: Vec<&AuditEvent> = parsed_events
        .iter()
        .filter(|event| match state.diagnostics_filter {
            DiagnosticsFilter::All => true,
            DiagnosticsFilter::Successes => event.success,
            DiagnosticsFilter::Errors => !event.success,
            DiagnosticsFilter::ProfileChanges => matches!(
                event.event_type,
                EventType::ProfileCreated
                    | EventType::ProfileDeleted
                    | EventType::ProfileRenamed
                    | EventType::ProfileSwitched
            ),
            DiagnosticsFilter::Settings => matches!(event.event_type, EventType::SettingsSaved),
        })
        .collect();

    container(
        column![
            row![
                text("📊 Diagnostics & Logs")
                    .size(24)
                    .font(regular_font)
                    .color(theme.warning),
                rule::horizontal(0).style(move |_| themed_horizontal_rule(theme)),
            ]
            .spacing(12)
            .align_y(Alignment::Center)
            .width(Length::Fill),
            // Filter and count
            row![
                text(format!("Event Log ({} entries)", filtered_events.len()))
                    .size(14)
                    .font(regular_font)
                    .color(theme.fg_primary),
                pick_list(
                    vec![
                        DiagnosticsFilter::All,
                        DiagnosticsFilter::Successes,
                        DiagnosticsFilter::Errors,
                        DiagnosticsFilter::ProfileChanges,
                        DiagnosticsFilter::Settings,
                    ],
                    Some(state.diagnostics_filter),
                    Message::DiagnosticsFilterChanged
                )
                .placeholder("Filter...")
                .padding(8)
                .font(regular_font)
                .style(move |_, status| themed_pick_list(theme, status))
                .menu_style(move |_| themed_pick_list_menu(theme)),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            // Event log section
            container(
                scrollable(
                    column(if filtered_events.is_empty() {
                        vec![text(if state.enable_event_log {
                            "No events match the current filter"
                        } else {
                            "Event logging is disabled. Enable it in Settings to track operations."
                        })
                        .size(12)
                        .font(regular_font)
                        .color(theme.fg_muted)
                        .into()]
                    } else {
                        filtered_events
                            .into_iter()
                            .map(|event| format_audit_event(event, theme, mono_font))
                            .collect()
                    })
                    .spacing(8),
                )
                .style(move |_, status| themed_scrollable(theme, status)),
            )
            .width(Length::Fill)
            .height(500)
            .style(move |_| container::Style {
                background: Some(theme.bg_elevated.into()),
                border: Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            })
            .padding(12),
            // Action buttons
            row![
                button(text("Clear Log").size(14).font(regular_font))
                    .on_press(Message::ClearEventLog)
                    .padding([10, 20])
                    .style(move |_, status| danger_button(theme, status)),
                button(text("Open Logs Folder").size(14).font(regular_font))
                    .on_press(Message::OpenLogsFolder)
                    .padding([10, 20])
                    .style(move |_, status| primary_button(theme, status)),
                button(text("Close").size(14).font(regular_font))
                    .on_press(Message::ToggleDiagnostics(false))
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        ]
        .spacing(20)
        .padding(32),
    )
    .max_width(1000)
    .style(move |_| card_container(theme))
    .into()
}
