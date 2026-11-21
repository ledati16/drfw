//! UI state management
//!
//! Handles UI state changes:
//! - Tab switching
//! - Modal dialogs (export, shortcuts help, diagnostics)
//! - Theme picker
//! - Font picker
//! - Undo/redo
//! - Banner management
//! - Keyboard shortcuts and the Escape layer order

use crate::app::{
    BannerSeverity, DiagnosticsFilter, FontPickerTarget, Message, State, ThemeFilter, WorkspaceTab,
};
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
    state.diagnostics.confirm_clear = false;

    // Read the log on open if it changed since it was last shown
    if show {
        return super::export::refresh_audit_log(state);
    }

    Task::none()
}

/// Handles diagnostics filter change
pub(crate) fn handle_diagnostics_filter_changed(state: &mut State, filter: DiagnosticsFilter) {
    state.diagnostics_filter = filter;
    state.diagnostics.refilter(filter);
}

/// Handles undo
pub(crate) fn handle_undo(state: &mut State) -> Task<Message> {
    let Some(description) = state.command_history.undo(&mut state.ruleset) else {
        return Task::none();
    };
    // Clear drag state (undo may add/remove rules, invalidating drag references)
    state.clear_drag_state();
    state.mark_profile_dirty();
    tracing::info!("Undid: {description}");
    let enable_event_log = state.enable_event_log;
    super::audit_task(async move {
        crate::audit::log_undone(enable_event_log, &description).await;
    })
}

/// Handles redo
pub(crate) fn handle_redo(state: &mut State) -> Task<Message> {
    let Some(description) = state.command_history.redo(&mut state.ruleset) else {
        return Task::none();
    };
    // Clear drag state (redo may add/remove rules, invalidating drag references)
    state.clear_drag_state();
    state.mark_profile_dirty();
    tracing::info!("Redid: {description}");
    let enable_event_log = state.enable_event_log;
    super::audit_task(async move {
        crate::audit::log_redone(enable_event_log, &description).await;
    })
}

/// Handles opening theme picker
pub(crate) fn handle_open_theme_picker(state: &mut State) {
    // Pre-compute all theme conversions once on modal open
    let cached_themes: Vec<_> = <crate::theme::ThemeChoice as IntoEnumIterator>::iter()
        .map(|choice| (choice, choice.to_theme()))
        .collect();

    let mut picker = crate::app::ThemePickerState {
        search: String::new(),
        search_lowercase: String::new(),
        filter: ThemeFilter::All,
        original_theme: state.current_theme,
        cached_themes,
        filtered: Vec::new(),
        count_display: String::new(),
    };
    picker.refilter();
    state.theme_picker = Some(picker);
}

/// Handles theme picker search change
pub(crate) fn handle_theme_picker_search_changed(state: &mut State, search: String) {
    if let Some(picker) = &mut state.theme_picker {
        picker.search_lowercase = search.to_lowercase();
        picker.search = search;
        picker.refilter();
    }
}

/// Handles theme picker filter change
pub(crate) fn handle_theme_picker_filter_changed(state: &mut State, filter: ThemeFilter) {
    if let Some(picker) = &mut state.theme_picker {
        picker.filter = filter;
        picker.refilter();
    }
}

/// Handles theme preview
pub(crate) fn handle_theme_preview(state: &mut State, choice: crate::theme::ThemeChoice) {
    state.set_theme(choice);
}

/// Handles applying theme
pub(crate) fn handle_apply_theme(state: &mut State) -> Task<Message> {
    state.theme_picker = None;
    state.mark_config_dirty();
    super::log_setting_change(
        state,
        format!("Theme changed to {}", state.current_theme.name()),
    )
}

/// Handles canceling theme picker
pub(crate) fn handle_cancel_theme_picker(state: &mut State) {
    if let Some(picker) = state.theme_picker.take() {
        state.set_theme(picker.original_theme);
    }
}

/// Handles opening font picker
pub(crate) fn handle_open_font_picker(state: &mut State, target: FontPickerTarget) {
    let mut picker = crate::app::FontPickerState {
        target,
        search: String::new(),
        search_lowercase: String::new(),
        filtered: Vec::new(),
        count_display: String::new(),
        overflow_display: None,
    };
    picker.refilter(state.available_fonts, state.fonts_loaded);
    state.font_picker = Some(picker);
}

/// Handles font picker search change
pub(crate) fn handle_font_picker_search_changed(state: &mut State, search: String) {
    if let Some(picker) = &mut state.font_picker {
        picker.search_lowercase = search.to_lowercase();
        picker.search = search;
        picker.refilter(state.available_fonts, state.fonts_loaded);
    }
}

/// Handles the end of the startup font enumeration: the configured fonts
/// are checked against the installed ones (falling back to the defaults if
/// gone) and an open font picker is filled.
pub(crate) fn handle_fonts_loaded(state: &mut State, fonts: &'static [crate::fonts::FontChoice]) {
    state.available_fonts = fonts;
    state.fonts_loaded = true;
    // An empty list means the enumeration failed: keep the configured fonts
    // (used by name) rather than resetting them to the defaults
    if !fonts.is_empty() {
        state.regular_font_choice.resolve(fonts, false);
        state.mono_font_choice.resolve(fonts, true);
        state.font_regular = state.regular_font_choice.to_font();
        state.font_mono = state.mono_font_choice.to_font();
    }
    if let Some(picker) = &mut state.font_picker {
        picker.refilter(fonts, true);
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

/// Handles copying a preview line to clipboard (right-click)
///
/// Reconstructs the line text from the cached tokens and copies to system clipboard.
/// Works with both normal and diff view - uses whichever is currently active.
pub(crate) fn handle_copy_preview_line(state: &mut State, line_number: usize) -> Task<Message> {
    // Try diff view first if enabled, otherwise use normal tokens
    let line_opt = if state.show_diff {
        state
            .cached_diff_tokens
            .as_ref()
            .and_then(|diff| diff.iter().find(|(_, hl)| hl.line_number == line_number))
            .map(|(_, hl)| hl)
    } else {
        state
            .cached_nft_tokens
            .iter()
            .find(|hl| hl.line_number == line_number)
    };

    let Some(line) = line_opt else {
        tracing::warn!(
            "Attempted to copy non-existent preview line {}",
            line_number
        );
        return Task::none();
    };

    // Reconstruct line text: indentation + all token text concatenated
    let mut text = String::with_capacity(
        line.indent + line.tokens.iter().map(|t| t.text.len()).sum::<usize>(),
    );
    for _ in 0..line.indent {
        text.push(' ');
    }
    for token in &line.tokens {
        text.push_str(&token.text);
    }

    state.push_banner(
        format!("Line {line_number} copied to clipboard"),
        BannerSeverity::Info,
    );

    iced::clipboard::write(text)
}

/// Extracts the comment text from a line containing a `comment "..."` pattern.
/// Returns `None` if there is no (non-empty) comment.
fn extract_comment_from_line(line_text: &str) -> Option<&str> {
    let marker = "comment \"";
    let start = line_text.find(marker)? + marker.len();
    let rest = &line_text[start..];
    let end = rest.find('"')?;
    let comment = &rest[..end];
    (!comment.is_empty()).then_some(comment)
}

/// Finds the label of the user rule whose generated comment is `comment`.
///
/// User rules get `sanitize_nft_quoted(label)` as their comment (see
/// `FirewallRuleset::rule_add`); system rules (loopback, ICMP, ...) have
/// comments no user rule produces, so they yield `None` without keeping a
/// separate list of system comment strings in sync with the generator.
fn user_label_for_comment<'a>(
    rules: &'a [crate::core::firewall::Rule],
    comment: &str,
) -> Option<&'a str> {
    rules
        .iter()
        .find(|r| {
            !r.label.is_empty() && crate::validators::sanitize_nft_quoted(&r.label) == comment
        })
        .map(|r| r.label.as_str())
}

/// Handles clicking on a preview line to filter sidebar by rule label (left-click)
///
/// Extracts the label from the line's `comment "LABEL"` and sets the sidebar search
/// to filter to matching rules. Works with both normal and diff view.
pub(crate) fn handle_click_preview_line(state: &mut State, line_number: usize) {
    // Get line from either diff or normal view (same logic as copy handler)
    let line_opt = if state.show_diff {
        state
            .cached_diff_tokens
            .as_ref()
            .and_then(|diff| diff.iter().find(|(_, hl)| hl.line_number == line_number))
            .map(|(_, hl)| hl)
    } else {
        state
            .cached_nft_tokens
            .iter()
            .find(|hl| hl.line_number == line_number)
    };

    let Some(line) = line_opt else {
        return; // Line not found - silently ignore
    };

    // Reconstruct line text from tokens
    let mut text = String::with_capacity(
        line.indent + line.tokens.iter().map(|t| t.text.len()).sum::<usize>(),
    );
    for _ in 0..line.indent {
        text.push(' ');
    }
    for token in &line.tokens {
        text.push_str(&token.text);
    }

    // No user rule for this line (system rule, header, unlabeled rule):
    // silently ignore - the user can use other methods to find the rule
    let Some(label) = extract_comment_from_line(&text)
        .and_then(|comment| user_label_for_comment(&state.ruleset.rules, comment))
    else {
        return;
    };

    // Set the search filter to the rule's label
    let label = label.to_string();
    state.rule_search_lowercase = label.to_lowercase();
    state.rule_search = label;
    state.update_filter_cache();
}

/// Handles deleting rule request (shows confirmation)
pub(crate) fn handle_delete_rule_requested(state: &mut State, id: uuid::Uuid) {
    state.deleting_id = Some(id);
}

/// Handles canceling delete
pub(crate) fn handle_cancel_delete(state: &mut State) {
    state.deleting_id = None;
}

/// Upper bound for flushing saves when the window closes, so a hung disk
/// cannot keep the app from closing.
const CLOSE_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Handles a window close request: writes pending profile and config changes
/// (bounded by [`CLOSE_FLUSH_TIMEOUT`]), then exits via `Message::CloseFlushed`.
///
/// The debounced autosave would otherwise lose the last second of edits.
/// A read-only (unreadable) profile is never written.
pub(crate) fn handle_close_requested(state: &mut State, _id: iced::window::Id) -> Task<Message> {
    if state.closing {
        return Task::none();
    }
    state.closing = true;
    // Pending saves are flushed below; armed timers must not start more
    state.timers.cancel_all();

    // Re-save while a save is in flight too: the profile save lock orders it
    // after the running one, so the newest snapshot always lands last.
    let profile = ((state.profile_dirty || state.profile_save_in_flight)
        && state.unreadable_profile.is_none())
    .then(|| (state.active_profile_name.clone(), state.ruleset.clone()));
    let config = state.config_dirty.then(|| state.config_snapshot());

    if profile.is_none() && config.is_none() {
        return Task::done(Message::CloseFlushed);
    }

    Task::perform(
        async move {
            let flush = async {
                if let Some((name, ruleset)) = profile
                    && let Err(e) = crate::core::profiles::save_profile(&name, &ruleset).await
                {
                    tracing::error!("Failed to save profile '{name}' on close: {e}");
                }
                if let Some(config) = config
                    && let Err(e) = crate::config::save_config(&config).await
                {
                    tracing::error!("Failed to save configuration on close: {e}");
                }
            };
            if tokio::time::timeout(CLOSE_FLUSH_TIMEOUT, flush)
                .await
                .is_err()
            {
                tracing::error!("Saving on close timed out; exiting anyway");
            }
        },
        |()| Message::CloseFlushed,
    )
}

/// The top-most open layer of the UI, following the stacking order of
/// `view::view` (first variant = drawn on top).
///
/// Escape closes exactly this layer, and shortcuts that act on the rules
/// behind it only fire when nothing is open ([`TopLayer::Base`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TopLayer {
    ShortcutsHelp,
    /// "Unsaved changes" dialog before a profile switch (drawn above, and
    /// hiding, the profile manager)
    ProfileSwitchConfirm,
    ProfileManager,
    ThemePicker,
    FontPicker,
    ExportModal,
    Diagnostics,
    /// Port/address/tag helper on top of the rule form
    HelperModal,
    /// Confirmation for enabling a risky setting
    Warning,
    RuleForm,
    /// "Commit Changes?", "Applying" and the auto-revert countdown
    ApplyFlow,
    SaveToSystem,
    /// No modal: the sidebar and workspace
    Base,
}

/// Returns the top-most open layer (see [`TopLayer`]).
pub(crate) fn top_layer(state: &State) -> TopLayer {
    use crate::app::AppStatus;

    if state.show_shortcuts_help {
        TopLayer::ShortcutsHelp
    } else if state.pending_profile_switch.is_some() {
        TopLayer::ProfileSwitchConfirm
    } else if state.profile_manager.is_some() {
        TopLayer::ProfileManager
    } else if state.theme_picker.is_some() {
        TopLayer::ThemePicker
    } else if state.font_picker.is_some() {
        TopLayer::FontPicker
    } else if state.show_export_modal {
        TopLayer::ExportModal
    } else if state.show_diagnostics {
        TopLayer::Diagnostics
    } else if state.rule_form.is_some()
        && state
            .rule_form_helper
            .as_ref()
            .is_some_and(|h| h.helper_type.is_some())
    {
        TopLayer::HelperModal
    } else if state.pending_warning.is_some() {
        TopLayer::Warning
    } else if state.rule_form.is_some() {
        TopLayer::RuleForm
    } else {
        match state.status {
            AppStatus::AwaitingApply
            | AppStatus::Applying
            | AppStatus::PendingConfirmation { .. } => TopLayer::ApplyFlow,
            AppStatus::AwaitingSaveToSystem => TopLayer::SaveToSystem,
            _ => TopLayer::Base,
        }
    }
}

/// The message that closes the top-most layer on Escape, if any.
///
/// The apply countdown and a running apply are deliberately not closable by
/// Escape: keeping or rolling back firewall rules needs an explicit click.
fn escape_message(state: &State) -> Option<Message> {
    use crate::app::AppStatus;

    match top_layer(state) {
        TopLayer::ShortcutsHelp => Some(Message::ToggleShortcutsHelp(false)),
        TopLayer::ProfileSwitchConfirm => Some(Message::CancelProfileSwitch),
        TopLayer::ProfileManager => {
            // Close an inner prompt (delete confirm, rename, create) first
            let mgr = state.profile_manager.as_ref()?;
            Some(if mgr.deleting_name.is_some() {
                Message::CancelDeleteProfile
            } else if mgr.renaming_name.is_some() {
                Message::CancelRenameProfile
            } else if mgr.creating_new {
                Message::CancelCreatingNewProfile
            } else {
                Message::CloseProfileManager
            })
        }
        TopLayer::ThemePicker => Some(Message::CancelThemePicker),
        TopLayer::FontPicker => Some(Message::CloseFontPicker),
        TopLayer::ExportModal => Some(Message::ToggleExportModal(false)),
        TopLayer::Diagnostics => Some(Message::ToggleDiagnostics(false)),
        TopLayer::HelperModal => Some(Message::CloseHelper),
        TopLayer::Warning => Some(Message::CancelWarning),
        TopLayer::RuleForm => Some(Message::CancelRuleForm),
        TopLayer::ApplyFlow => {
            (state.status == AppStatus::AwaitingApply).then_some(Message::CancelApply)
        }
        TopLayer::SaveToSystem => Some(Message::SaveToSystemCancelled),
        TopLayer::Base => state.deleting_id.is_some().then_some(Message::CancelDelete),
    }
}

/// Subscription filter (`iced::event::listen_with`): forwards keyboard key
/// presses with their capture status. Everything else is dropped here so it
/// never reaches `update()`.
pub(crate) fn keyboard_event_message(
    event: iced::Event,
    status: iced::event::Status,
    _window: iced::window::Id,
) -> Option<Message> {
    match event {
        iced::Event::Keyboard(iced::keyboard::Event::KeyPressed { .. }) => {
            Some(Message::EventOccurred(event, status))
        }
        _ => None,
    }
}

/// Handles keyboard shortcuts.
///
/// - Escape is global (a focused text input captures it to unfocus, and it
///   still closes the top-most layer). On the base layer it cancels an active
///   drag, then a pending rule delete, then clears the search.
/// - Every other key only acts if no widget handled it
///   (`Status::Ignored`), so Enter in a helper input adds the value instead of
///   also saving the rule form.
/// - Enter saves the rule form only while the form is the top layer.
/// - Ctrl+N/S/E/Z/Y act on the rules behind any modal, so they only fire on
///   the base layer (no form or dialog open).
pub(crate) fn handle_event(
    state: &mut State,
    event: &iced::Event,
    status: iced::event::Status,
) -> Task<Message> {
    if let Some(message) = shortcut_message(state, event, status) {
        return Task::done(message);
    }
    if is_escape(event) {
        // Base layer, nothing to confirm or cancel
        if state.dragged_rule_id.is_some() {
            state.clear_drag_state();
        } else if !state.rule_search.is_empty() {
            state.rule_search.clear();
            state.rule_search_lowercase.clear();
            state.update_filter_cache();
        }
    }
    Task::none()
}

fn is_escape(event: &iced::Event) -> bool {
    matches!(
        event,
        iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
            key: iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape),
            ..
        })
    )
}

/// The message a key press maps to in the current state (see
/// [`handle_event`] for the rules), without side effects.
fn shortcut_message(
    state: &State,
    event: &iced::Event,
    status: iced::event::Status,
) -> Option<Message> {
    use crate::app::AppStatus;
    use iced::keyboard::{Key, key::Named};

    let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed { key, modifiers, .. }) = event
    else {
        return None;
    };

    if is_escape(event) {
        return escape_message(state);
    }
    if status == iced::event::Status::Captured {
        return None;
    }

    let layer = top_layer(state);
    let command = modifiers.command() || modifiers.control();
    match key.as_ref() {
        Key::Named(Named::Enter) if layer == TopLayer::RuleForm => Some(Message::SaveRuleForm),
        Key::Named(Named::F1) => Some(Message::ToggleShortcutsHelp(true)),
        _ if !command || layer != TopLayer::Base => None,
        Key::Character("n") => (!matches!(state.status, AppStatus::PendingConfirmation { .. }))
            .then_some(Message::AddRuleClicked),
        Key::Character("s") => Some(Message::ApplyClicked),
        Key::Character("e") => Some(Message::ToggleExportModal(true)),
        Key::Character("z") if !modifiers.shift() => {
            state.command_history.can_undo().then_some(Message::Undo)
        }
        Key::Character("z" | "y") => state.command_history.can_redo().then_some(Message::Redo),
        _ => None,
    }
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
    fn test_close_without_pending_changes_exits_immediately() {
        let mut state = create_test_state();
        let _ = handle_close_requested(&mut state, iced::window::Id::unique());
        assert!(state.closing);
        // A second request while closing is ignored
        let _ = handle_close_requested(&mut state, iced::window::Id::unique());
        assert!(state.closing);
    }

    #[test]
    fn test_handle_undo_with_empty_history() {
        let mut state = create_test_state();
        let _task = handle_undo(&mut state);
        // Should not panic
    }

    #[test]
    fn test_extract_comment_from_line() {
        let line = r#"tcp dport 80 accept comment "Web Server - Port 80""#;
        assert_eq!(
            extract_comment_from_line(line),
            Some("Web Server - Port 80")
        );
        assert_eq!(
            extract_comment_from_line(r#"tcp dport 22 accept comment """#),
            None
        );
        assert_eq!(extract_comment_from_line("tcp dport 22 accept"), None);
        assert_eq!(extract_comment_from_line("# Chain input rules:"), None);
        assert_eq!(extract_comment_from_line(""), None);
        assert_eq!(extract_comment_from_line("    "), None);
    }

    #[test]
    fn test_comment_maps_to_user_rules_only() {
        use crate::core::test_helpers::create_test_rule;
        let mut quoted = create_test_rule("placeholder", Some(80));
        quoted.label = r#"Quote "q" rule"#.to_string();
        let rules = vec![create_test_rule("Allow SSH", Some(22)), quoted];
        assert_eq!(
            user_label_for_comment(&rules, "Allow SSH"),
            Some("Allow SSH")
        );
        // The generated comment is sanitized; the real label is returned
        assert_eq!(
            user_label_for_comment(&rules, "Quote q rule"),
            Some(r#"Quote "q" rule"#)
        );
        // System comments (whatever the generator emits) match no user rule
        assert_eq!(user_label_for_comment(&rules, "allow from loopback"), None);
        assert_eq!(user_label_for_comment(&rules, "allow icmp"), None);
    }

    #[test]
    fn test_click_on_system_line_changes_nothing() {
        use crate::core::test_helpers::create_test_rule;
        let mut state = create_test_state();
        state
            .ruleset
            .rules
            .push(create_test_rule("Allow SSH", Some(22)));
        state.mark_profile_dirty();
        for line in state.cached_nft_tokens.clone() {
            handle_click_preview_line(&mut state, line.line_number);
            assert!(
                state.rule_search.is_empty() || state.rule_search == "Allow SSH",
                "unexpected search {:?}",
                state.rule_search
            );
        }
        assert_eq!(
            state.rule_search, "Allow SSH",
            "the user rule line was found"
        );
    }

    // ------------------------------------------------------------------
    // Keyboard: status filtering, layer order, Escape
    // ------------------------------------------------------------------

    use crate::app::{AppStatus, HelperType, PendingWarning, RuleForm, RuleFormHelper};
    use iced::event::Status;
    use iced::keyboard::{Key, Modifiers, key::Named};

    fn key_event(key: Key, modifiers: Modifiers) -> iced::Event {
        iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
            key: key.clone(),
            modified_key: key,
            physical_key: iced::keyboard::key::Physical::Unidentified(
                iced::keyboard::key::NativeCode::Unidentified,
            ),
            location: iced::keyboard::Location::Standard,
            modifiers,
            text: None,
            repeat: false,
        })
    }

    fn named(key: Named) -> iced::Event {
        key_event(Key::Named(key), Modifiers::empty())
    }

    fn ctrl(c: &str) -> iced::Event {
        key_event(Key::Character(c.into()), Modifiers::CTRL)
    }

    /// Runs a key press and returns (the debug form of) the message it sends,
    /// if any; side effects of `handle_event` are applied to `state`.
    fn press(state: &mut State, event: &iced::Event, status: Status) -> Option<String> {
        let message = shortcut_message(state, event, status).map(|m| format!("{m:?}"));
        let _ = handle_event(state, event, status);
        message
    }

    fn open_helper(state: &mut State) {
        state.rule_form = Some(RuleForm::default());
        state.rule_form_helper = Some(RuleFormHelper {
            helper_type: Some(HelperType::Ports),
            input: "22".into(),
            error: None,
        });
    }

    #[test]
    fn test_enter_in_helper_input_does_not_save_form() {
        let mut state = create_test_state();
        open_helper(&mut state);
        // The helper input handled Enter (on_submit): nothing else happens
        assert_eq!(
            press(&mut state, &named(Named::Enter), Status::Captured),
            None
        );
        // Even unhandled, Enter does not save the form behind the helper
        assert_eq!(
            press(&mut state, &named(Named::Enter), Status::Ignored),
            None
        );
        // With the helper closed, Enter saves the form
        state.rule_form_helper = None;
        assert_eq!(
            press(&mut state, &named(Named::Enter), Status::Ignored).as_deref(),
            Some("SaveRuleForm")
        );
    }

    #[test]
    fn test_shortcuts_ignored_when_captured_or_behind_a_modal() {
        let mut state = create_test_state();
        state
            .ruleset
            .rules
            .push(crate::core::test_helpers::create_test_rule("A", Some(1)));
        state.command_history.execute(
            Box::new(crate::command::ToggleRuleCommand {
                rule_id: state.ruleset.rules[0].id,
                was_enabled: true,
            }),
            &mut state.ruleset,
        );
        state.mark_profile_dirty();

        // Base layer: shortcuts work
        assert_eq!(
            press(&mut state, &ctrl("z"), Status::Ignored).as_deref(),
            Some("Undo")
        );
        assert_eq!(
            press(&mut state, &ctrl("e"), Status::Ignored).as_deref(),
            Some("ToggleExportModal(true)")
        );
        // Captured by a widget: ignored
        assert_eq!(press(&mut state, &ctrl("z"), Status::Captured), None);

        // Rule form open: no undo/apply/new/export behind it
        state.rule_form = Some(RuleForm::default());
        for c in ["z", "y", "s", "n", "e"] {
            assert_eq!(
                press(&mut state, &ctrl(c), Status::Ignored),
                None,
                "Ctrl+{c}"
            );
        }
        // F1 still opens the help
        assert_eq!(
            press(&mut state, &named(Named::F1), Status::Ignored).as_deref(),
            Some("ToggleShortcutsHelp(true)")
        );
    }

    #[test]
    fn test_ctrl_y_and_ctrl_shift_z_redo() {
        let mut state = create_test_state();
        state
            .ruleset
            .rules
            .push(crate::core::test_helpers::create_test_rule("A", Some(1)));
        state.command_history.execute(
            Box::new(crate::command::ToggleRuleCommand {
                rule_id: state.ruleset.rules[0].id,
                was_enabled: true,
            }),
            &mut state.ruleset,
        );
        let _ = state.command_history.undo(&mut state.ruleset);
        state.mark_profile_dirty();
        assert_eq!(
            press(&mut state, &ctrl("y"), Status::Ignored).as_deref(),
            Some("Redo")
        );
        let shift_z = key_event(
            Key::Character("z".into()),
            Modifiers::CTRL | Modifiers::SHIFT,
        );
        assert_eq!(
            press(&mut state, &shift_z, Status::Ignored).as_deref(),
            Some("Redo")
        );
    }

    /// Escape closes the top-most layer only, one layer per press, in the
    /// order the view stacks them.
    #[test]
    fn test_escape_closes_layers_top_down() {
        let mut state = create_test_state();
        state.rule_search = "ssh".into();
        state.rule_search_lowercase = "ssh".into();
        open_helper(&mut state);
        state.show_diagnostics = true;
        state.show_export_modal = true;
        handle_open_font_picker(&mut state, FontPickerTarget::Mono);
        handle_open_theme_picker(&mut state);
        crate::app::handlers::handle_open_profile_manager(&mut state);
        state.pending_profile_switch = Some("other".into());
        state.show_shortcuts_help = true;

        let expected = [
            "ToggleShortcutsHelp(false)",
            "CancelProfileSwitch",
            "CloseProfileManager",
            "CancelThemePicker",
            "CloseFontPicker",
            "ToggleExportModal(false)",
            "ToggleDiagnostics(false)",
            "CloseHelper",
            "CancelRuleForm",
        ];
        for want in expected {
            let got = press(&mut state, &named(Named::Escape), Status::Ignored)
                .expect("a layer to close");
            assert_eq!(got, want);
            // Apply the message so the next layer becomes the top one
            let message = match want {
                "ToggleShortcutsHelp(false)" => Message::ToggleShortcutsHelp(false),
                "CancelProfileSwitch" => Message::CancelProfileSwitch,
                "CloseProfileManager" => Message::CloseProfileManager,
                "CancelThemePicker" => Message::CancelThemePicker,
                "CloseFontPicker" => Message::CloseFontPicker,
                "ToggleExportModal(false)" => Message::ToggleExportModal(false),
                "ToggleDiagnostics(false)" => Message::ToggleDiagnostics(false),
                "CloseHelper" => Message::CloseHelper,
                _ => Message::CancelRuleForm,
            };
            let _ = state.update(message);
        }
        assert_eq!(top_layer(&state), TopLayer::Base);
        // Base layer: Escape clears the search
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored),
            None
        );
        assert_eq!(state.rule_search, "");
    }

    #[test]
    fn test_escape_is_global_even_when_an_input_captured_it() {
        let mut state = create_test_state();
        state.rule_form = Some(RuleForm::default());
        // A focused text input captures Escape (to unfocus); the form still closes
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Captured).as_deref(),
            Some("CancelRuleForm")
        );
    }

    #[test]
    fn test_escape_in_profile_manager_closes_inner_prompt_first() {
        let mut state = create_test_state();
        crate::app::handlers::handle_open_profile_manager(&mut state);
        crate::app::handlers::handle_delete_profile_requested(&mut state, "x".into());
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored).as_deref(),
            Some("CancelDeleteProfile")
        );
        crate::app::handlers::handle_cancel_delete_profile(&mut state);
        crate::app::handlers::handle_rename_profile_requested(&mut state, "test".into());
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored).as_deref(),
            Some("CancelRenameProfile")
        );
    }

    #[test]
    fn test_escape_on_confirmation_modals() {
        let mut state = create_test_state();
        state.pending_warning = Some(PendingWarning::EnableRpf);
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored).as_deref(),
            Some("CancelWarning")
        );
        state.pending_warning = None;

        state.status = AppStatus::AwaitingApply;
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored).as_deref(),
            Some("CancelApply")
        );
        state.status = AppStatus::AwaitingSaveToSystem;
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored).as_deref(),
            Some("SaveToSystemCancelled")
        );
        // Applying / countdown: Escape must not confirm or roll back
        state.status = AppStatus::Applying;
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored),
            None
        );
        assert_eq!(state.status, AppStatus::Applying);

        state.status = AppStatus::Idle;
        state.deleting_id = Some(uuid::Uuid::new_v4());
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored).as_deref(),
            Some("CancelDelete")
        );
    }

    #[test]
    fn test_escape_cancels_active_drag() {
        let mut state = create_test_state();
        state.rule_search = "keep".into();
        state.dragged_rule_id = Some(uuid::Uuid::new_v4());
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored),
            None
        );
        assert!(state.dragged_rule_id.is_none());
        assert_eq!(state.rule_search, "keep", "only the drag was cancelled");
    }

    #[test]
    fn test_keyboard_filter_forwards_key_presses_only() {
        let id = iced::window::Id::unique();
        assert!(keyboard_event_message(named(Named::Enter), Status::Captured, id).is_some());
        let release =
            iced::Event::Keyboard(iced::keyboard::Event::ModifiersChanged(Modifiers::empty()));
        assert!(keyboard_event_message(release, Status::Ignored, id).is_none());
    }

    #[test]
    fn test_font_picker_caches_filtered_list() {
        static FONTS: std::sync::LazyLock<Vec<crate::fonts::FontChoice>> =
            std::sync::LazyLock::new(|| {
                vec![
                    crate::fonts::FontChoice::SystemDefault,
                    crate::fonts::FontChoice::SystemMonospace,
                ]
            });
        let mut state = create_test_state();
        handle_open_font_picker(&mut state, FontPickerTarget::Regular);
        let picker = state.font_picker.as_ref().unwrap();
        assert_eq!(picker.filtered, Vec::<usize>::new());
        assert!(picker.count_display.contains("Loading"));
        handle_fonts_loaded(&mut state, FONTS.as_slice());
        assert_eq!(state.font_picker.as_ref().unwrap().filtered.len(), 2);
        handle_font_picker_search_changed(&mut state, "monosp".into());
        let picker = state.font_picker.as_ref().unwrap();
        assert_eq!(picker.filtered, vec![1]);
        assert_eq!(picker.count_display, "1 fonts match");
    }

    #[test]
    fn test_theme_picker_caches_filtered_list() {
        let mut state = create_test_state();
        handle_open_theme_picker(&mut state);
        let all = state.theme_picker.as_ref().unwrap().filtered.len();
        assert!(all > 1);
        handle_theme_picker_filter_changed(&mut state, ThemeFilter::Light);
        let picker = state.theme_picker.as_ref().unwrap();
        assert!(picker.filtered.len() < all);
        assert!(
            picker
                .filtered
                .iter()
                .all(|&i| picker.cached_themes[i].1.is_light())
        );
    }

    #[test]
    fn test_theme_change_updates_iced_theme() {
        let mut state = create_test_state();
        let light = <crate::theme::ThemeChoice as IntoEnumIterator>::iter()
            .find(|c| c.to_theme().is_light())
            .expect("a light theme");
        handle_theme_preview(&mut state, light);
        let palette = state.iced_theme().palette();
        assert_eq!(palette.background, state.theme.bg_base);
        assert_eq!(palette.text, state.theme.fg_primary);
    }
}
