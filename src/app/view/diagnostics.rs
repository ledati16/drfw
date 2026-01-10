//! Diagnostics modal and event log viewer

use crate::app::ui_components::{
    card_container, danger_button, secondary_button, section_header_container, themed_pick_list,
    themed_pick_list_menu, themed_scrollable,
};
use crate::app::{DiagnosticsFilter, Message, State};
use crate::audit::{AuditEvent, EventType};
use crate::core::error::NftablesErrorPattern;
use iced::widget::{button, column, container, pick_list, row, scrollable, space, text};
use iced::{Alignment, Border, Element, Length, Padding};

/// Formats a raw error message into a verbose, user-friendly description.
/// Uses `NftablesErrorPattern` to provide helpful context and suggestions.
fn format_error_for_display(error: Option<&str>) -> String {
    match error {
        Some(e) if !e.is_empty() => {
            let translation = NftablesErrorPattern::match_error(e);
            if translation.suggestions.is_empty() {
                translation.user_message
            } else {
                format!(
                    "{} — {}",
                    translation.user_message,
                    translation.suggestions.join("; ")
                )
            }
        }
        _ => "No error details available".to_string(),
    }
}

/// Formats an audit event for display in the Diagnostics modal
pub fn format_audit_event<'a>(
    event: &AuditEvent,
    theme: &crate::theme::AppTheme,
    mono_font: iced::Font,
) -> Element<'a, Message> {
    // Format timestamp as HH:MM:SS
    let time = event.timestamp.format("%H:%M:%S").to_string();

    // Choose status color based on event type and success
    let (status_color, description) = match (&event.event_type, event.success) {
        (EventType::ApplyRules, true) => (
            theme.success,
            format!(
                "Applied {} rules ({} enabled)",
                event.details["rule_count"], event.details["enabled_count"]
            ),
        ),
        (EventType::ApplyRules, false) => (
            theme.danger,
            format!(
                "Failed to apply rules: {}",
                format_error_for_display(event.error.as_deref())
            ),
        ),
        (EventType::RevertRules, true) => {
            (theme.warning, "Reverted to previous ruleset".to_string())
        }
        (EventType::RevertRules, false) => (
            theme.danger,
            format!(
                "Revert failed: {}",
                format_error_for_display(event.error.as_deref())
            ),
        ),
        (EventType::VerifyRules, true) => {
            (theme.success, "Rules verified successfully".to_string())
        }
        (EventType::VerifyRules, false) => (
            theme.danger,
            if event.error.is_some() {
                format!(
                    "Verification failed: {}",
                    format_error_for_display(event.error.as_deref())
                )
            } else {
                format!(
                    "Verification failed: {} errors",
                    event.details["error_count"]
                )
            },
        ),
        (EventType::ProfileCreated, _) => (
            theme.accent,
            format!("Created profile '{}'", event.details["profile_name"]),
        ),
        (EventType::ProfileDeleted, _) => (
            theme.accent,
            format!("Deleted profile '{}'", event.details["profile_name"]),
        ),
        (EventType::ProfileRenamed, _) => (
            theme.accent,
            format!(
                "Renamed profile '{}' → '{}'",
                event.details["old_name"], event.details["new_name"]
            ),
        ),
        (EventType::ProfileSwitched, _) => (
            theme.accent,
            format!(
                "Switched profile: '{}' → '{}'",
                event.details["from"], event.details["to"]
            ),
        ),
        (EventType::SettingsSaved, _) => (
            theme.accent,
            event.details["description"]
                .as_str()
                .unwrap_or("Settings saved")
                .to_string(),
        ),
        (EventType::AutoRevertConfirmed, _) => (
            theme.success,
            format!(
                "Auto-revert confirmed ({}s timeout)",
                event.details["timeout_secs"]
            ),
        ),
        (EventType::AutoRevertTimedOut, _) => (
            theme.warning,
            format!("Auto-revert timed out ({}s)", event.details["timeout_secs"]),
        ),
        (EventType::ElevationCancelled, _) => (
            theme.warning,
            "Authentication cancelled by user".to_string(),
        ),
        (EventType::ElevationFailed, _) => (
            theme.danger,
            format!(
                "Authentication failed: {}",
                format_error_for_display(event.error.as_deref())
            ),
        ),
        (EventType::RuleCreated, _) => (
            theme.success,
            format!(
                "Created rule '{}'{}",
                event.details["label"].as_str().unwrap_or(""),
                event.details["ports"]
                    .as_str()
                    .map(|p| format!(" ({p})"))
                    .unwrap_or_default()
            ),
        ),
        (EventType::RuleDeleted, _) => (
            theme.danger,
            format!(
                "Deleted rule '{}'",
                event.details["label"].as_str().unwrap_or("")
            ),
        ),
        (EventType::RuleModified, _) => (
            theme.accent,
            format!(
                "Modified rule '{}'{}",
                event.details["label"].as_str().unwrap_or(""),
                event.details["ports"]
                    .as_str()
                    .map(|p| format!(" ({p})"))
                    .unwrap_or_default()
            ),
        ),
        (EventType::RuleToggled, _) => (
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
            theme.accent,
            format!(
                "Moved rule '{}' {}",
                event.details["label"].as_str().unwrap_or(""),
                event.details["direction"].as_str().unwrap_or("")
            ),
        ),
        (EventType::Undone, _) => (
            theme.warning,
            format!(
                "Undid: {}",
                event.details["description"]
                    .as_str()
                    .unwrap_or("unknown operation")
            ),
        ),
        (EventType::Redone, _) => (
            theme.accent,
            format!(
                "Redid: {}",
                event.details["description"]
                    .as_str()
                    .unwrap_or("unknown operation")
            ),
        ),
        (EventType::ExportCompleted, _) => (
            theme.success,
            format!(
                "Exported {} to {}",
                event.details["format"].as_str().unwrap_or("rules"),
                event.details["path"].as_str().unwrap_or("")
            ),
        ),
        (EventType::SaveToSystem, true) => (
            theme.success,
            format!(
                "Saved to {}",
                event.details["target_path"].as_str().unwrap_or("")
            ),
        ),
        (EventType::SaveToSystem, false) => (
            theme.danger,
            format!(
                "Failed to save: {}",
                format_error_for_display(event.error.as_deref())
            ),
        ),
        (EventType::SnapshotFailed, _) => (
            theme.warning,
            format!(
                "Snapshot failed: {}",
                format_error_for_display(event.error.as_deref())
            ),
        ),
        (EventType::ProfileDeleteFailed, _) => (
            theme.danger,
            format!(
                "Failed to delete profile '{}': {}",
                event.details["profile_name"].as_str().unwrap_or(""),
                format_error_for_display(event.error.as_deref())
            ),
        ),
        (EventType::ProfileRenameFailed, _) => (
            theme.danger,
            format!(
                "Failed to rename profile '{}': {}",
                event.details["profile_name"].as_str().unwrap_or(""),
                format_error_for_display(event.error.as_deref())
            ),
        ),
        (EventType::ExportFailed, _) => (
            theme.danger,
            format!(
                "Export failed: {}",
                format_error_for_display(event.error.as_deref())
            ),
        ),
        (EventType::GenericError, _) => (
            theme.danger,
            format!(
                "Error: {}",
                format_error_for_display(event.error.as_deref())
            ),
        ),
    };

    row![
        text(time).size(12).font(mono_font).color(theme.fg_muted),
        container(text(""))
            .width(Length::Fixed(8.0))
            .height(Length::Fixed(8.0))
            .style(move |_| container::Style {
                background: Some(status_color.into()),
                border: Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
        text(description)
            .size(13)
            .font(mono_font)
            .color(theme.fg_primary),
    ]
    .spacing(8)
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
    // Use cached audit entries (loaded asynchronously)
    // Events are already parsed and in reverse order (most recent first)
    let parsed_events: &[AuditEvent] = &state.cached_audit_entries;

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

    let event_count = filtered_events.len();

    container(
        column![
            container(
                text("Event Log")
                    .size(18)
                    .font(regular_font)
                    .color(theme.fg_primary)
            )
            .padding([4, 8])
            .style(move |_| section_header_container(theme)),
            // Filter
            row![
                text("Filter:")
                    .size(12)
                    .font(regular_font)
                    .color(theme.fg_muted),
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
            .spacing(8)
            .align_y(Alignment::Center),
            // Event log section
            container(
                scrollable(
                    container(
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
                        .spacing(4)
                    )
                    .padding(Padding {
                        top: 8.0,
                        right: 8.0,
                        bottom: 8.0,
                        left: 8.0,
                    })
                )
                .spacing(0)  // Embedded mode prevents overlap
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
            }),
            // Action buttons
            row![
                container(
                    text(format!("{event_count} events"))
                        .size(10)
                        .font(mono_font)
                        .color(theme.fg_muted)
                )
                .padding([2, 6])
                .style(move |_| section_header_container(theme)),
                space::Space::new().width(Length::Fill),
                button(text("Clear Log").size(14).font(regular_font))
                    .on_press(Message::ClearEventLog)
                    .padding([10, 20])
                    .style(move |_, status| danger_button(theme, status)),
                button(text("Open Logs Folder").size(14).font(regular_font))
                    .on_press(Message::OpenLogsFolder)
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
                button(text("Close").size(14).font(regular_font))
                    .on_press(Message::ToggleDiagnostics(false))
                    .padding([10, 20])
                    .style(move |_, status| secondary_button(theme, status)),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        ]
        .spacing(16)
        .padding(24),
    )
    .max_width(1000)
    .style(move |_| card_container(theme))
    .into()
}
