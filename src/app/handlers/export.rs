//! Export and audit log operations
//!
//! Handles:
//! - Exporting rules as JSON
//! - Exporting rules as nft text
//! - Diagnostics event log: change-checked reloads, search, clearing

use iced::Task;

use crate::app::{BannerSeverity, Message, State, diagnostics};
use crate::audit;

/// Handles exporting as JSON
///
/// One file dialog at a time: the export buttons are disabled while one is
/// open, and a second request is ignored.
pub(crate) fn handle_export_as_json(state: &mut State) -> Task<Message> {
    if std::mem::replace(&mut state.export_in_progress, true) {
        return Task::none();
    }
    let json = serde_json::to_string_pretty(&state.ruleset.to_nftables_json()).unwrap_or_default();
    Task::perform(
        async move {
            use rfd::AsyncFileDialog;
            let file = AsyncFileDialog::new()
                .set_file_name("firewall-rules.json")
                .add_filter("JSON", &["json"])
                .save_file()
                .await;

            if let Some(file) = file {
                tokio::fs::write(file.path(), json)
                    .await
                    .map(|()| file.path().display().to_string())
                    .map_err(|e| format!("Failed to write file: {e}"))
            } else {
                Err("Export cancelled".to_string())
            }
        },
        Message::ExportResult,
    )
}

/// Handles exporting as nft text (one file dialog at a time, see
/// [`handle_export_as_json`])
pub(crate) fn handle_export_as_nft(state: &mut State) -> Task<Message> {
    if std::mem::replace(&mut state.export_in_progress, true) {
        return Task::none();
    }
    let text = state.ruleset.to_nft_text();
    Task::perform(
        async move {
            use rfd::AsyncFileDialog;
            let file = AsyncFileDialog::new()
                .set_file_name("firewall-rules.nft")
                .add_filter("NFT", &["nft", "conf"])
                .save_file()
                .await;

            if let Some(file) = file {
                tokio::fs::write(file.path(), text)
                    .await
                    .map(|()| file.path().display().to_string())
                    .map_err(|e| format!("Failed to write file: {e}"))
            } else {
                Err("Export cancelled".to_string())
            }
        },
        Message::ExportResult,
    )
}

/// Handles export result
pub(crate) fn handle_export_result(
    state: &mut State,
    result: Result<String, String>,
) -> Task<Message> {
    state.show_export_modal = false;
    state.export_in_progress = false;
    match result {
        Ok(path) => {
            let msg = crate::app::helpers::truncate_path_smart(&path, 60);
            state.push_banner(format!("Exported to {msg}"), BannerSeverity::Success);
            Task::none()
        }
        Err(e) if e == "Export cancelled" => {
            // User cancelled - don't show error or log
            Task::none()
        }
        Err(e) => {
            let msg = if e.len() > 50 {
                format!("Export failed: {}...", crate::utils::truncate_str(&e, 47))
            } else {
                format!("Export failed: {e}")
            };
            state.push_banner(&msg, BannerSeverity::Error);
            let enable_event_log = state.enable_event_log;
            Task::perform(
                async move {
                    audit::log_export_failed(enable_event_log, e).await;
                },
                |()| Message::AuditLogWritten,
            )
        }
    }
}

/// Starts a diagnostics log reload unless one is running. The load stats the
/// log first and only re-reads it if its size or modification time changed.
pub(crate) fn refresh_audit_log(state: &mut State) -> Task<Message> {
    let today = diagnostics::local_today();
    let Some((generation, known)) = state.diagnostics.begin_load(today) else {
        return Task::none();
    };
    Task::perform(
        // The path is resolved when the load runs, not when it is scheduled
        async move { diagnostics::load_if_changed(audit::audit_log_path(), known, today).await },
        move |load| Message::AuditLogLoaded(generation, load),
    )
}

/// Handles a finished diagnostics log load (stale generations are dropped)
pub(crate) fn handle_audit_log_loaded(
    state: &mut State,
    generation: u64,
    load: diagnostics::AuditLoad,
) {
    state
        .diagnostics
        .finish_load(generation, load, state.diagnostics_filter);
}

/// Handles a change of the diagnostics search text
pub(crate) fn handle_diagnostics_search_changed(state: &mut State, search: String) {
    state
        .diagnostics
        .set_search(search, state.diagnostics_filter);
}

/// Handles "Clear Log": asks for confirmation first
pub(crate) fn handle_clear_event_log(state: &mut State) {
    if !state.diagnostics.clearing {
        state.diagnostics.confirm_clear = true;
    }
}

/// Handles cancelling the clear confirmation
pub(crate) fn handle_cancel_clear_event_log(state: &mut State) {
    state.diagnostics.confirm_clear = false;
}

/// Handles the confirmed clear: replaces the log off the UI thread with one
/// whose first line records the clearing (when event logging is enabled).
pub(crate) fn handle_confirm_clear_event_log(state: &mut State) -> Task<Message> {
    if state.diagnostics.clearing {
        return Task::none();
    }
    state.diagnostics.confirm_clear = false;
    state.diagnostics.clearing = true;
    // A load already running would show the log as it was before the clear
    state.diagnostics.invalidate();
    let enable_event_log = state.enable_event_log;
    Task::perform(
        async move {
            audit::clear_log(enable_event_log)
                .await
                .map_err(|e| e.to_string())
        },
        Message::EventLogCleared,
    )
}

/// Handles the end of a clear: reports the outcome and reloads the log
pub(crate) fn handle_event_log_cleared(
    state: &mut State,
    result: Result<(), String>,
) -> Task<Message> {
    state.diagnostics.clearing = false;
    match result {
        Ok(()) => state.push_banner("Event log cleared", BannerSeverity::Success),
        Err(e) => {
            tracing::error!("Failed to clear the event log: {e}");
            state.push_banner(
                format!("Could not clear the event log: {e}"),
                BannerSeverity::Error,
            );
        }
    }
    if state.show_diagnostics {
        refresh_audit_log(state)
    } else {
        Task::none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::handlers::test_utils::create_test_state;

    #[test]
    fn test_handle_export_result_success() {
        let mut state = create_test_state();
        let _ = handle_export_result(&mut state, Ok("/path/to/file.json".to_string()));
        assert!(!state.show_export_modal);
        assert!(!state.banners.is_empty());
    }

    #[test]
    fn test_clear_event_log_asks_first() {
        let mut state = create_test_state();
        handle_clear_event_log(&mut state);
        assert!(state.diagnostics.confirm_clear);
        assert!(!state.diagnostics.clearing);
        handle_cancel_clear_event_log(&mut state);
        assert!(!state.diagnostics.confirm_clear);
        assert!(!state.diagnostics.clearing);
    }

    #[test]
    fn test_confirmed_clear_supersedes_running_load() {
        let mut state = create_test_state();
        state.show_diagnostics = true;
        let _ = refresh_audit_log(&mut state); // a load is now in flight
        handle_clear_event_log(&mut state);
        let _ = handle_confirm_clear_event_log(&mut state);
        assert!(!state.diagnostics.confirm_clear);
        assert!(state.diagnostics.clearing);
        // No reloads while clearing, and a second confirm does nothing
        let today = crate::app::diagnostics::local_today();
        assert!(state.diagnostics.begin_load(today).is_none());
        let _ = handle_confirm_clear_event_log(&mut state);
        assert!(state.diagnostics.clearing);
    }

    #[test]
    fn test_clear_failure_is_reported() {
        let mut state = create_test_state();
        state.diagnostics.clearing = true;
        let _ = handle_event_log_cleared(&mut state, Err("Permission denied".to_string()));
        assert!(!state.diagnostics.clearing);
        let banner = state.banners.back().expect("an error banner");
        assert_eq!(banner.severity, BannerSeverity::Error);
        assert!(banner.message.contains("Permission denied"));
    }

    #[test]
    fn test_one_export_dialog_at_a_time() {
        let mut state = create_test_state();
        assert!(handle_export_as_json(&mut state).units() > 0);
        assert!(state.export_in_progress);
        assert_eq!(handle_export_as_nft(&mut state).units(), 0, "ignored");
        assert_eq!(handle_export_as_json(&mut state).units(), 0, "ignored");
        let _ = handle_export_result(&mut state, Err("Export cancelled".to_string()));
        assert!(!state.export_in_progress);
    }
}
