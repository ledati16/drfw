//! Export and audit log operations
//!
//! Handles:
//! - Exporting rules as JSON
//! - Exporting rules as nft text
//! - Clearing audit log
//! - Opening logs folder
//! - Loading audit entries

use crate::app::{BannerSeverity, Message, State};
use iced::Task;

/// Handles exporting as JSON
pub(crate) fn handle_export_as_json(state: &State) -> Task<Message> {
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

/// Handles exporting as nft text
pub(crate) fn handle_export_as_nft(state: &State) -> Task<Message> {
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
pub(crate) fn handle_export_result(state: &mut State, result: Result<String, String>) {
    state.show_export_modal = false;
    match result {
        Ok(path) => {
            let msg = crate::app::helpers::truncate_path_smart(&path, 60);
            state.push_banner(format!("Exported to {msg}"), BannerSeverity::Success, 5);
        }
        Err(e) if e == "Export cancelled" => {
            // User cancelled - don't show error
        }
        Err(e) => {
            let msg = if e.len() > 50 {
                format!("Export failed: {}...", &e[..47])
            } else {
                format!("Export failed: {e}")
            };
            state.push_banner(&msg, BannerSeverity::Error, 8);
        }
    }
}

/// Handles clearing event log
pub(crate) fn handle_clear_event_log(state: &mut State) {
    if let Some(mut path) = crate::utils::get_state_dir() {
        path.push("audit.log");
        let _ = std::fs::remove_file(path);
        state.audit_log_dirty = true; // Refresh after clearing
    }
}

/// Handles opening logs folder
pub(crate) fn handle_open_logs_folder() {
    if let Some(state_dir) = crate::utils::get_state_dir()
        && state_dir.exists()
        && state_dir.is_dir()
        && let Ok(canonical) = state_dir.canonicalize()
    {
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("xdg-open")
                .arg(canonical.as_os_str())
                .spawn();
        }
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("open")
                .arg(canonical.as_os_str())
                .spawn();
        }
        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("explorer")
                .arg(canonical.as_os_str())
                .spawn();
        }
    }
}

/// Handles audit entries loaded
pub(crate) fn handle_audit_entries_loaded(
    state: &mut State,
    entries: Vec<crate::audit::AuditEvent>,
) {
    state.cached_audit_entries = entries;
    state.audit_log_dirty = false;
}

/// Handles audit log write completed
pub(crate) fn handle_audit_log_written(state: &mut State) {
    if state.enable_event_log {
        state.audit_log_dirty = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::handlers::test_utils::create_test_state;

    #[test]
    fn test_handle_export_result_success() {
        let mut state = create_test_state();
        handle_export_result(&mut state, Ok("/path/to/file.json".to_string()));
        assert!(!state.show_export_modal);
        assert!(!state.banners.is_empty());
    }

    #[test]
    fn test_handle_audit_log_written() {
        let mut state = create_test_state();
        state.enable_event_log = true;
        handle_audit_log_written(&mut state);
        assert!(state.audit_log_dirty);
    }
}
