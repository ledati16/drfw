//! UI state management
//!
//! Handles UI state changes:
//! - Tab switching
//! - Modal dialogs (export, shortcuts help, diagnostics)
//! - Theme picker
//! - Font picker
//! - Undo/redo
//! - Banner management

use crate::app::{DiagnosticsFilter, FontPickerTarget, Message, State, ThemeFilter, WorkspaceTab};
use iced::Task;
use strum::IntoEnumIterator;

/// Handles tab change
pub(crate) fn handle_tab_changed(state: &mut State, tab: WorkspaceTab) {
    state.active_tab = tab;
}

/// Handles toggling export modal
pub(crate) fn handle_toggle_export_modal(state: &mut State, show: bool) {
    state.show_export_modal = show;
}

/// Handles toggling shortcuts help
pub(crate) fn handle_toggle_shortcuts_help(state: &mut State, show: bool) {
    state.show_shortcuts_help = show;
}

/// Handles toggling diagnostics view
pub(crate) fn handle_toggle_diagnostics(state: &mut State, show: bool) -> Task<Message> {
    state.show_diagnostics = show;

    // Load audit log asynchronously if opening modal and cache is dirty
    if show && state.audit_log_dirty {
        return Task::perform(load_audit_entries(), Message::AuditEntriesLoaded);
    }

    Task::none()
}

/// Handles diagnostics filter change
pub(crate) fn handle_diagnostics_filter_changed(state: &mut State, filter: DiagnosticsFilter) {
    state.diagnostics_filter = filter;
}

/// Handles undo
pub(crate) fn handle_undo(state: &mut State) -> Task<Message> {
    if let Some(description) = state.command_history.undo(&mut state.ruleset) {
        state.mark_profile_dirty();
        tracing::info!("Undid: {}", description);
        let enable_event_log = state.enable_event_log;
        let desc = description.clone();
        return Task::perform(
            async move {
                crate::audit::log_undone(enable_event_log, &desc).await;
            },
            |_| Message::AuditLogWritten,
        );
    }
    Task::none()
}

/// Handles redo
pub(crate) fn handle_redo(state: &mut State) -> Task<Message> {
    if let Some(description) = state.command_history.redo(&mut state.ruleset) {
        state.mark_profile_dirty();
        tracing::info!("Redid: {}", description);
        let enable_event_log = state.enable_event_log;
        let desc = description.clone();
        return Task::perform(
            async move {
                crate::audit::log_redone(enable_event_log, &desc).await;
            },
            |_| Message::AuditLogWritten,
        );
    }
    Task::none()
}

/// Handles opening theme picker
pub(crate) fn handle_open_theme_picker(state: &mut State) {
    // Pre-compute all theme conversions once on modal open
    let cached_themes: Vec<_> = <crate::theme::ThemeChoice as IntoEnumIterator>::iter()
        .map(|choice| (choice, choice.to_theme()))
        .collect();

    state.theme_picker = Some(crate::app::ThemePickerState {
        search: String::new(),
        search_lowercase: String::new(),
        filter: ThemeFilter::All,
        original_theme: state.current_theme,
        cached_themes,
    });
}

/// Handles theme picker search change
pub(crate) fn handle_theme_picker_search_changed(state: &mut State, search: String) {
    if let Some(picker) = &mut state.theme_picker {
        picker.search_lowercase = search.to_lowercase();
        picker.search = search;
    }
}

/// Handles theme picker filter change
pub(crate) fn handle_theme_picker_filter_changed(state: &mut State, filter: ThemeFilter) {
    if let Some(picker) = &mut state.theme_picker {
        picker.filter = filter;
    }
}

/// Handles theme preview
pub(crate) fn handle_theme_preview(state: &mut State, choice: crate::theme::ThemeChoice) {
    state.current_theme = choice;
    state.theme = choice.to_theme();
}

/// Handles theme preview button click (cycles preview)
pub(crate) fn handle_theme_preview_button_click(_state: &mut State) {
    // No-op placeholder for UI action
}

/// Handles applying theme
pub(crate) fn handle_apply_theme(state: &mut State) -> Task<Message> {
    state.theme_picker = None;
    state.mark_config_dirty();
    let enable_event_log = state.enable_event_log;
    let desc = format!("Theme changed to {}", state.current_theme.name());
    Task::perform(
        async move {
            crate::audit::log_settings_saved(enable_event_log, &desc).await;
        },
        |_| Message::AuditLogWritten,
    )
}

/// Handles canceling theme picker
pub(crate) fn handle_cancel_theme_picker(state: &mut State) {
    if let Some(picker) = &state.theme_picker {
        state.current_theme = picker.original_theme;
        state.theme = picker.original_theme.to_theme();
    }
    state.theme_picker = None;
}

/// Handles opening font picker
pub(crate) fn handle_open_font_picker(state: &mut State, target: FontPickerTarget) {
    state.font_picker = Some(crate::app::FontPickerState {
        target,
        search: String::new(),
        search_lowercase: String::new(),
    });
}

/// Handles font picker search change
pub(crate) fn handle_font_picker_search_changed(state: &mut State, search: String) {
    if let Some(picker) = &mut state.font_picker {
        picker.search_lowercase = search.to_lowercase();
        picker.search = search;
    }
}

/// Handles closing font picker
pub(crate) fn handle_close_font_picker(state: &mut State) {
    state.font_picker = None;
}

/// Handles pruning expired banners
pub(crate) fn handle_prune_banners(state: &mut State) {
    state.prune_expired_banners();
}

/// Handles dismissing a specific banner
pub(crate) fn handle_dismiss_banner(state: &mut State, index: usize) {
    if index < state.banners.len() {
        state.banners.remove(index);
    }
}

/// Handles deleting rule request (shows confirmation)
pub(crate) fn handle_delete_rule_requested(state: &mut State, id: uuid::Uuid) {
    state.deleting_id = Some(id);
}

/// Handles canceling delete
pub(crate) fn handle_cancel_delete(state: &mut State) {
    state.deleting_id = None;
}

/// Handles checking if audit log needs refresh (auto-refresh subscription)
pub(crate) fn handle_check_audit_log_refresh(state: &mut State) -> Task<Message> {
    // Auto-refresh: only load if dirty (subscription fires every 100ms while modal open)
    if state.audit_log_dirty {
        return Task::perform(load_audit_entries(), Message::AuditEntriesLoaded);
    }
    Task::none()
}

/// Loads audit log entries asynchronously
/// Returns parsed events, most recent first (reversed order)
pub(crate) async fn load_audit_entries() -> Vec<crate::audit::AuditEvent> {
    use tokio::io::AsyncBufReadExt;

    let Some(mut path) = crate::utils::get_state_dir() else {
        return Vec::new();
    };
    path.push("audit.log");

    let Ok(file) = tokio::fs::File::open(&path).await else {
        return Vec::new();
    };

    let reader = tokio::io::BufReader::new(file);
    let mut lines = reader.lines();
    let mut events = Vec::new();

    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(event) = serde_json::from_str::<crate::audit::AuditEvent>(&line) {
            events.push(event);
        }
    }

    // Most recent first
    events.reverse();
    events
}

/// Handles keyboard events (shortcuts)
pub(crate) fn handle_event(state: &mut State, event: iced::Event) -> Task<Message> {
    use crate::app::AppStatus;

    if let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed { key, modifiers, .. }) = event {
        match key.as_ref() {
            iced::keyboard::Key::Named(iced::keyboard::key::Named::Enter)
                if state.rule_form.is_some() =>
            {
                return Task::done(Message::SaveRuleForm);
            }
            iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape) => {
                if state.rule_form.is_some() {
                    return Task::done(Message::CancelRuleForm);
                }
                if state.deleting_id.is_some() {
                    return Task::done(Message::CancelDelete);
                }
                if state.show_shortcuts_help {
                    return Task::done(Message::ToggleShortcutsHelp(false));
                }
                if state.show_diagnostics {
                    return Task::done(Message::ToggleDiagnostics(false));
                }
                if state.show_export_modal {
                    return Task::done(Message::ToggleExportModal(false));
                }
                if state.font_picker.is_some() {
                    return Task::done(Message::CloseFontPicker);
                }
                if state.theme_picker.is_some() {
                    return Task::done(Message::CancelThemePicker);
                }
                if state.profile_manager.is_some() {
                    return Task::done(Message::CloseProfileManager);
                }
                if !state.rule_search.is_empty() {
                    state.rule_search.clear();
                }
            }
            iced::keyboard::Key::Named(iced::keyboard::key::Named::F1) => {
                return Task::done(Message::ToggleShortcutsHelp(true));
            }
            iced::keyboard::Key::Character("n") if modifiers.command() || modifiers.control() => {
                if !matches!(state.status, AppStatus::PendingConfirmation { .. }) {
                    return Task::done(Message::AddRuleClicked);
                }
            }
            iced::keyboard::Key::Character("s") if modifiers.command() || modifiers.control() => {
                return Task::done(Message::ApplyClicked);
            }
            iced::keyboard::Key::Character("e") if modifiers.command() || modifiers.control() => {
                return Task::done(Message::ToggleExportModal(true));
            }
            iced::keyboard::Key::Character("z")
                if (modifiers.command() || modifiers.control()) && !modifiers.shift() =>
            {
                if state.command_history.can_undo() {
                    return Task::done(Message::Undo);
                }
            }
            iced::keyboard::Key::Character("z")
                if (modifiers.command() || modifiers.control()) && modifiers.shift() =>
            {
                if state.command_history.can_redo() {
                    return Task::done(Message::Redo);
                }
            }
            iced::keyboard::Key::Character("y") if modifiers.command() || modifiers.control() => {
                if state.command_history.can_redo() {
                    return Task::done(Message::Redo);
                }
            }
            _ => {}
        }
    }
    Task::none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::handlers::test_utils::create_test_state;

    #[test]
    fn test_handle_tab_changed() {
        let mut state = create_test_state();
        handle_tab_changed(&mut state, WorkspaceTab::Settings);
        assert_eq!(state.active_tab, WorkspaceTab::Settings);
    }

    #[test]
    fn test_handle_undo_with_empty_history() {
        let mut state = create_test_state();
        let _task = handle_undo(&mut state);
        // Should not panic
    }
}
