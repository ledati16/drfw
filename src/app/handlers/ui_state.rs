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

use iced::Task;
use strum::IntoEnumIterator;

use crate::app::{
    BannerSeverity, DiagnosticsFilter, FontPickerTarget, Message, State, ThemeFilter, WorkspaceTab,
};

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

/// Opens or closes the "Verification Errors" panel (only while there are
/// errors to show).
pub(crate) fn handle_toggle_verify_errors(state: &mut State, show: bool) {
    state.show_verify_errors = show && state.verify_errors.is_some();
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
    state.push_banner(format!("Undid: {description}"), BannerSeverity::Info);
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
    state.push_banner(format!("Redid: {description}"), BannerSeverity::Info);
    let enable_event_log = state.enable_event_log;
    super::audit_task(async move {
        crate::audit::log_redone(enable_event_log, &description).await;
    })
}

/// Handles opening theme picker (its search input gets the focus)
pub(crate) fn handle_open_theme_picker(state: &mut State) -> Task<Message> {
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
    crate::app::focus::focus_input(crate::app::focus::THEME_SEARCH)
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

/// The preview line `line_number` as it is on screen: the diff view when it
/// is shown (diff enabled and there is a diff), the plain ruleset otherwise.
/// Must match the choice in `view::view`.
fn preview_line(
    state: &State,
    line_number: usize,
) -> Option<&crate::app::syntax_cache::HighlightedLine> {
    match (state.show_diff, &state.cached_diff_tokens) {
        (true, Some(diff)) => diff
            .iter()
            .map(|(_, line)| line)
            .find(|line| line.line_number == line_number),
        _ => state
            .cached_nft_tokens
            .iter()
            .find(|line| line.line_number == line_number),
    }
}

/// The text of a preview line: indentation plus its tokens.
fn preview_line_text(line: &crate::app::syntax_cache::HighlightedLine) -> String {
    let mut text = String::with_capacity(
        line.indent + line.tokens.iter().map(|t| t.text.len()).sum::<usize>(),
    );
    text.extend(std::iter::repeat_n(' ', line.indent));
    for token in &line.tokens {
        text.push_str(&token.text);
    }
    text
}

/// Handles copying a preview line to clipboard (right-click)
pub(crate) fn handle_copy_preview_line(state: &mut State, line_number: usize) -> Task<Message> {
    let Some(text) = preview_line(state, line_number).map(preview_line_text) else {
        tracing::warn!(
            "Attempted to copy non-existent preview line {}",
            line_number
        );
        return Task::none();
    };

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
    let Some(text) = preview_line(state, line_number).map(preview_line_text) else {
        return; // Line not found - silently ignore
    };

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
/// A read-only (unreadable) profile is never written. While a profile rename
/// runs, the flush waits for it (see `handle_profile_renamed`): saving under
/// the old name now would recreate the file the rename is moving away.
pub(crate) fn handle_close_requested(state: &mut State, _id: iced::window::Id) -> Task<Message> {
    if state.closing {
        return Task::none();
    }
    state.closing = true;
    state.close_error = None;
    // Pending saves are flushed below; armed timers must not start more
    state.timers.cancel_all();
    if state.profile_rename_in_flight {
        state.close_after_rename = true;
        return Task::none();
    }
    start_close_flush(state)
}

/// Writes what is pending and reports the outcome as `Message::CloseFlushed`.
pub(crate) fn start_close_flush(state: &mut State) -> Task<Message> {
    // Re-save while a save is in flight too: the profile save lock orders it
    // after the running one, so the newest snapshot always lands last.
    let profile = ((state.profile_dirty || state.profile_save_in_flight)
        && state.unreadable_profile.is_none())
    .then(|| (state.active_profile_name.clone(), state.ruleset.clone()));
    let config =
        (state.config_dirty || state.config_save_in_flight).then(|| state.config_snapshot());

    if profile.is_none() && config.is_none() {
        return Task::done(Message::CloseFlushed(Ok(())));
    }

    Task::perform(
        async move {
            let flush = async {
                let mut errors = Vec::new();
                if let Some((name, ruleset)) = profile
                    && let Err(e) = crate::core::profiles::save_profile(&name, &ruleset).await
                {
                    tracing::error!("Failed to save profile '{name}' on close: {e}");
                    errors.push(format!("profile '{name}': {e}"));
                }
                if let Some(config) = config
                    && let Err(e) = crate::config::save_config(&config).await
                {
                    tracing::error!("Failed to save configuration on close: {e}");
                    errors.push(format!("settings: {e}"));
                }
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(errors.join("; "))
                }
            };
            tokio::time::timeout(CLOSE_FLUSH_TIMEOUT, flush)
                .await
                .unwrap_or_else(|_| {
                    tracing::error!("Saving on close timed out");
                    Err("saving timed out".to_string())
                })
        },
        Message::CloseFlushed,
    )
}

/// Handles the end of the close flush: exits if everything was written,
/// otherwise keeps the window open and asks (see the "Close anyway" dialog).
pub(crate) fn handle_close_flushed(state: &mut State, result: Result<(), String>) -> Task<Message> {
    match result {
        Ok(()) => iced::exit(),
        Err(e) => {
            // Back to normal operation: autosave resumes and retries
            state.closing = false;
            state.close_error = Some(format!(
                "Your changes could not be saved ({e}). If you close now, they are lost."
            ));
            Task::none()
        }
    }
}

/// "Keep DRFW open" in the failed-close dialog
pub(crate) fn handle_cancel_close(state: &mut State) {
    state.close_error = None;
}

/// "Close anyway" in the failed-close dialog: exits without saving
pub(crate) fn handle_close_anyway(state: &mut State) -> Task<Message> {
    if state.close_error.take().is_none() {
        return Task::none();
    }
    tracing::warn!("Closing without saving after a failed save");
    iced::exit()
}

/// The top-most open layer of the UI, following the stacking order of
/// `view::view` (first variant = drawn on top).
///
/// Escape closes exactly this layer, Enter runs its primary action, Tab moves
/// between its text inputs, and shortcuts that act on the rules behind it
/// only fire when nothing is open ([`TopLayer::Base`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TopLayer {
    /// "Your changes could not be saved" after a close request
    CloseFailed,
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
    /// "Start fresh?" for a profile that could not be loaded
    StartFreshConfirm,
    /// Confirmation for enabling a risky setting
    Warning,
    RuleForm,
    /// "Commit Changes?", "Applying" and the auto-revert countdown
    ApplyFlow,
    SaveToSystem,
    /// "Verification Errors" panel. Below the rule form, so a rule opened
    /// from the panel is edited on top of it and Escape returns to the list.
    VerifyErrors,
    /// Exposure panel (listening sockets). Below every dialog, so a rule
    /// opened from it is edited on top and Escape returns to the panel.
    Exposure,
    /// No modal: the sidebar and workspace
    Base,
}

/// Returns the top-most open layer (see [`TopLayer`]).
pub(crate) fn top_layer(state: &State) -> TopLayer {
    use crate::app::AppStatus;

    if state.close_error.is_some() {
        TopLayer::CloseFailed
    } else if state.show_shortcuts_help {
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
    } else if state.confirm_start_fresh && state.unreadable_profile.is_some() {
        TopLayer::StartFreshConfirm
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
            _ if state.show_verify_errors => TopLayer::VerifyErrors,
            _ if state.exposure.panel.is_some() => TopLayer::Exposure,
            _ => TopLayer::Base,
        }
    }
}

/// The text inputs of `layer`, for the Tab cycle. Inputs that are not on
/// screen (e.g. the rate limit fields while it is off) are skipped.
pub(crate) fn layer_inputs(layer: TopLayer) -> &'static [&'static str] {
    use crate::app::focus;

    match layer {
        TopLayer::Base => &[focus::RULE_SEARCH, focus::LOG_PREFIX],
        TopLayer::RuleForm => &[
            focus::RULE_FORM_LABEL,
            focus::RULE_FORM_RATE_COUNT,
            focus::RULE_FORM_RATE_BURST,
            focus::RULE_FORM_CONNECTION_LIMIT,
        ],
        TopLayer::HelperModal => &[focus::HELPER_INPUT],
        TopLayer::ProfileManager => &[focus::PROFILE_RENAME, focus::PROFILE_NEW_NAME],
        TopLayer::Diagnostics => &[focus::DIAGNOSTICS_SEARCH],
        TopLayer::FontPicker => &[focus::FONT_SEARCH],
        TopLayer::ThemePicker => &[focus::THEME_SEARCH],
        TopLayer::CloseFailed
        | TopLayer::ShortcutsHelp
        | TopLayer::ProfileSwitchConfirm
        | TopLayer::ExportModal
        | TopLayer::StartFreshConfirm
        | TopLayer::Warning
        | TopLayer::ApplyFlow
        | TopLayer::SaveToSystem
        | TopLayer::VerifyErrors
        | TopLayer::Exposure => &[],
    }
}

/// The message that closes the top-most layer on Escape, if any.
///
/// The apply countdown and a running apply are deliberately not closable by
/// Escape: keeping or rolling back firewall rules needs an explicit choice.
pub(crate) fn escape_message(state: &State) -> Option<Message> {
    use crate::app::AppStatus;

    match top_layer(state) {
        TopLayer::CloseFailed => Some(Message::CancelClose),
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
        // The "Clear log?" prompt first, then the modal
        TopLayer::Diagnostics => Some(if state.diagnostics.confirm_clear {
            Message::ClearEventLogCancelled
        } else {
            Message::ToggleDiagnostics(false)
        }),
        TopLayer::HelperModal => Some(Message::CloseHelper),
        TopLayer::StartFreshConfirm => Some(Message::CancelStartFresh),
        TopLayer::Warning => Some(Message::CancelWarning),
        TopLayer::RuleForm => Some(if state.confirm_discard_form {
            Message::KeepEditingRuleForm
        } else {
            Message::CancelRuleForm
        }),
        TopLayer::ApplyFlow => {
            (state.status == AppStatus::AwaitingApply).then_some(Message::CancelApply)
        }
        TopLayer::SaveToSystem => Some(Message::SaveToSystemCancelled),
        TopLayer::VerifyErrors => Some(Message::ToggleVerifyErrors(false)),
        TopLayer::Exposure => Some(Message::ToggleExposure(false)),
        TopLayer::Base if state.deleting_id.is_some() => Some(Message::CancelDelete),
        TopLayer::Base => state
            .template_menu
            .is_some()
            .then_some(Message::ToggleTemplateMenu(false)),
    }
}

/// The primary action of the top-most layer, run by Enter.
///
/// Chosen deliberately per layer:
/// - Dialogs run their highlighted (primary) button; the dialog after a
///   failed close keeps DRFW open. Read-only panels (shortcuts, verification
///   errors, exposure) close.
/// - Yes/no prompts (delete a rule or profile, clear the log, discard form
///   changes) confirm, as their confirm button is the one being asked about.
/// - The auto-revert countdown does **not** confirm on Enter: a stray or
///   repeated Enter right after applying would keep untested rules and defeat
///   the dead-man switch. Confirming by keyboard takes Ctrl+Enter (see
///   [`key_action`]); plain Enter only shows how.
/// - "Start fresh" without a backup copy, and Save to System with only
///   untested rules to save, have no Enter action: both lose data or skip the
///   safety net, so they need a click.
fn enter_message(state: &State) -> Option<Message> {
    use crate::app::AppStatus;

    match top_layer(state) {
        TopLayer::CloseFailed => Some(Message::CancelClose),
        TopLayer::ShortcutsHelp => Some(Message::ToggleShortcutsHelp(false)),
        TopLayer::ProfileSwitchConfirm => Some(Message::ConfirmProfileSwitch),
        TopLayer::ProfileManager => {
            let mgr = state.profile_manager.as_ref()?;
            if mgr.deleting_name.is_some() {
                Some(Message::ConfirmDeleteProfile)
            } else if mgr.renaming_name.is_some() {
                mgr.rename_error
                    .is_none()
                    .then_some(Message::ConfirmRenameProfile)
            } else if mgr.creating_new {
                mgr.new_name_error
                    .is_none()
                    .then(|| Message::SaveProfileAs(mgr.new_name_input.clone()))
            } else {
                None
            }
        }
        TopLayer::ThemePicker => Some(Message::ApplyTheme),
        TopLayer::FontPicker | TopLayer::ExportModal => None,
        TopLayer::Diagnostics => state
            .diagnostics
            .confirm_clear
            .then_some(Message::ClearEventLogConfirmed),
        TopLayer::HelperModal => Some(Message::HelperAddValue),
        TopLayer::StartFreshConfirm => state
            .unreadable_profile
            .as_ref()
            .is_some_and(|issue| issue.backup.is_some())
            .then_some(Message::ConfirmStartFresh),
        TopLayer::Warning => state.pending_warning.as_ref().map(|warning| match warning {
            crate::app::PendingWarning::EnableRpf => Message::ConfirmEnableRpf,
            crate::app::PendingWarning::EnableServerMode(_) => Message::ConfirmServerMode,
            crate::app::PendingWarning::EnableStrictIcmp => Message::ConfirmStrictIcmp,
        }),
        TopLayer::RuleForm => Some(if state.confirm_discard_form {
            Message::DiscardRuleForm
        } else {
            Message::SaveRuleForm
        }),
        TopLayer::ApplyFlow => {
            (state.status == AppStatus::AwaitingApply).then_some(Message::ProceedToApply)
        }
        TopLayer::SaveToSystem => state
            .save_dialog
            .primary_source()
            .map(Message::SaveToSystemConfirmed),
        TopLayer::VerifyErrors => Some(Message::ToggleVerifyErrors(false)),
        // A read-only panel: Enter closes it (its highlighted button)
        TopLayer::Exposure => Some(Message::ToggleExposure(false)),
        TopLayer::Base => state.deleting_id.map(Message::DeleteRule),
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

/// Ctrl shortcuts that act on the rules behind any modal. They only run on
/// the base layer, and only while no text input is focused: iced's text
/// input does not capture Ctrl+Z/Y/N/S/E, so Ctrl+Z in the search box would
/// otherwise undo a rule change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseShortcut {
    AddRule,
    Apply,
    Export,
    Undo,
    Redo,
}

impl BaseShortcut {
    /// The message the shortcut sends, if it can act now.
    fn message(self, state: &State) -> Option<Message> {
        match self {
            Self::AddRule => Some(Message::AddRuleClicked),
            Self::Apply => Some(Message::ApplyClicked),
            Self::Export => Some(Message::ToggleExportModal(true)),
            Self::Undo => state.command_history.can_undo().then_some(Message::Undo),
            Self::Redo => state.command_history.can_redo().then_some(Message::Redo),
        }
    }
}

/// What a key press does in the current state.
#[derive(Debug)]
enum KeyAction {
    Send(Message),
    /// Run a base-layer shortcut once it is known no text input is focused
    Shortcut(BaseShortcut),
    /// Tab / Shift+Tab: move focus among the top layer's inputs
    MoveFocus {
        forward: bool,
    },
    /// Escape on the base layer: cancel a drag, else clear the search
    BaseEscape,
    /// Enter during the auto-revert countdown: say how to confirm
    ConfirmHint,
}

/// Banner shown when Enter is pressed during the auto-revert countdown.
const CONFIRM_HINT: &str = "Press Ctrl+Enter or click \"Confirm & Stay\" to keep the new rules.";

/// Handles keyboard shortcuts (see [`key_action`] for the mapping).
pub(crate) fn handle_event(
    state: &mut State,
    event: &iced::Event,
    status: iced::event::Status,
) -> Task<Message> {
    match key_action(state, event, status) {
        Some(KeyAction::Send(message)) => Task::done(message),
        Some(KeyAction::Shortcut(shortcut)) => crate::app::focus::any_input_focused()
            .map(move |input_focused| Message::BaseShortcut(shortcut, input_focused)),
        Some(KeyAction::MoveFocus { forward }) => {
            crate::app::focus::cycle(layer_inputs(top_layer(state)), forward)
        }
        Some(KeyAction::BaseEscape) => {
            if state.dragged_rule_id.is_some() {
                state.clear_drag_state();
            } else if !state.rule_search.is_empty() {
                state.rule_search.clear();
                state.rule_search_lowercase.clear();
                state.update_filter_cache();
            }
            Task::none()
        }
        Some(KeyAction::ConfirmHint) => {
            state.push_banner(CONFIRM_HINT, BannerSeverity::Info);
            Task::none()
        }
        None => Task::none(),
    }
}

/// Handles a base-layer shortcut after the focus query (see
/// [`BaseShortcut`]). The layer is checked again: a dialog may have opened
/// while the query ran.
pub(crate) fn handle_base_shortcut(
    state: &State,
    shortcut: BaseShortcut,
    input_focused: bool,
) -> Task<Message> {
    if input_focused || top_layer(state) != TopLayer::Base {
        return Task::none();
    }
    shortcut.message(state).map_or_else(Task::none, Task::done)
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

/// What a key press does in the current state, without side effects.
///
/// - Escape is global (a focused text input captures it to unfocus, and it
///   still closes the top-most layer). Only on the base layer, and when no
///   input took it, does it cancel a drag or clear the search; never behind
///   a dialog.
/// - Every other key only acts if no widget handled it (`Status::Ignored`),
///   so Enter in an input with its own submit action (a helper input adds
///   the value) does not also run the layer's primary action.
/// - Enter (not auto-repeated) runs the top layer's primary action (see
///   [`enter_message`]); Ctrl+Enter confirms the auto-revert countdown.
/// - Tab / Shift+Tab move focus among the top layer's text inputs.
/// - Ctrl+N/S/E/Z/Y act on the rules behind any modal, so they only fire on
///   the base layer, with no text input focused ([`BaseShortcut`]).
fn key_action(
    state: &State,
    event: &iced::Event,
    status: iced::event::Status,
) -> Option<KeyAction> {
    use iced::keyboard::Key;
    use iced::keyboard::key::Named;

    use crate::app::AppStatus;

    let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
        key,
        modifiers,
        repeat,
        ..
    }) = event
    else {
        return None;
    };

    let layer = top_layer(state);
    if is_escape(event) {
        return match escape_message(state) {
            Some(message) => Some(KeyAction::Send(message)),
            // A focused input took this Escape to unfocus; the next one clears
            None if layer == TopLayer::Base && status == iced::event::Status::Ignored => {
                Some(KeyAction::BaseEscape)
            }
            None => None,
        };
    }
    if status == iced::event::Status::Captured {
        return None;
    }

    let command = modifiers.command() || modifiers.control();
    match key.as_ref() {
        // A held key must not click through dialogs
        Key::Named(Named::Enter) if *repeat => None,
        Key::Named(Named::Enter)
            if matches!(state.status, AppStatus::PendingConfirmation { .. })
                && layer == TopLayer::ApplyFlow =>
        {
            Some(if command {
                KeyAction::Send(Message::ConfirmClicked)
            } else {
                KeyAction::ConfirmHint
            })
        }
        Key::Named(Named::Enter) => enter_message(state).map(KeyAction::Send),
        Key::Named(Named::Tab) => Some(KeyAction::MoveFocus {
            forward: !modifiers.shift(),
        }),
        Key::Named(Named::F1) => Some(KeyAction::Send(Message::ToggleShortcutsHelp(true))),
        _ if !command || layer != TopLayer::Base => None,
        Key::Character("n") => Some(KeyAction::Shortcut(BaseShortcut::AddRule)),
        Key::Character("s") => Some(KeyAction::Shortcut(BaseShortcut::Apply)),
        Key::Character("e") => Some(KeyAction::Shortcut(BaseShortcut::Export)),
        Key::Character("z") if !modifiers.shift() => state
            .command_history
            .can_undo()
            .then_some(KeyAction::Shortcut(BaseShortcut::Undo)),
        Key::Character("z" | "y") => state
            .command_history
            .can_redo()
            .then_some(KeyAction::Shortcut(BaseShortcut::Redo)),
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

    use iced::event::Status;
    use iced::keyboard::key::Named;
    use iced::keyboard::{Key, Modifiers};

    use crate::app::{AppStatus, HelperType, PendingWarning, RuleForm, RuleFormHelper};

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
    /// Runs a key press and returns what it does as text: the message it
    /// sends (for a base shortcut: the message it sends once no input is
    /// focused), `MoveFocus(forward)` or `ConfirmHint`. Side effects of
    /// `handle_event` are applied to `state`.
    fn press(state: &mut State, event: &iced::Event, status: Status) -> Option<String> {
        let action = key_action(state, event, status).and_then(|action| match action {
            KeyAction::Send(message) => Some(format!("{message:?}")),
            KeyAction::Shortcut(shortcut) => shortcut.message(state).map(|m| format!("{m:?}")),
            KeyAction::MoveFocus { forward } => Some(format!("MoveFocus({forward})")),
            KeyAction::ConfirmHint => Some("ConfirmHint".to_string()),
            KeyAction::BaseEscape => None,
        });
        let _ = handle_event(state, event, status);
        action
    }

    fn open_helper(state: &mut State) {
        state.rule_form = Some(RuleForm::default());
        state.rule_form_helper = Some(RuleFormHelper {
            helper_type: Some(HelperType::Ports),
            input: "22".into(),
            ..Default::default()
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
        // Unhandled (input not focused), Enter adds the value, and still
        // does not save the form behind the helper
        assert_eq!(
            press(&mut state, &named(Named::Enter), Status::Ignored).as_deref(),
            Some("HelperAddValue")
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
        let _ = crate::app::handlers::handle_toggle_exposure(&mut state, true);
        state.verify_errors = Some(verify_errors_panel());
        handle_toggle_verify_errors(&mut state, true);
        open_helper(&mut state);
        state.show_diagnostics = true;
        state.show_export_modal = true;
        handle_open_font_picker(&mut state, FontPickerTarget::Mono);
        let _ = handle_open_theme_picker(&mut state);
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
            "ToggleVerifyErrors(false)",
            "ToggleExposure(false)",
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
                "CancelRuleForm" => Message::CancelRuleForm,
                "ToggleVerifyErrors(false)" => Message::ToggleVerifyErrors(false),
                _ => Message::ToggleExposure(false),
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

    fn verify_errors_panel() -> crate::app::verify_errors::VerifyErrorsPanel {
        crate::app::verify_errors::VerifyErrorsPanel::new(
            &crate::core::verify::VerifyResult::failure(vec![
                crate::core::verify::VerifyIssue::unlocated("bad"),
            ]),
            &crate::core::firewall::FirewallRuleset::new(),
        )
    }

    /// Deleting the rule an error points at hides its "Edit Rule"; undoing
    /// the delete brings it back.
    #[test]
    fn test_verify_errors_follow_rule_deletion() {
        use crate::core::verify::{ErrorOrigin, VerifyIssue};

        let mut state = create_test_state();
        state
            .ruleset
            .rules
            .push(crate::core::test_helpers::create_test_rule("Web", Some(80)));
        state.mark_profile_dirty();
        let id = state.ruleset.rules[0].id;
        let result = crate::core::verify::VerifyResult::failure(vec![VerifyIssue {
            origin: Some(ErrorOrigin::UserRule {
                id,
                label: "Web".into(),
            }),
            message: "Service out of range".into(),
            source_line: None,
            caret: None,
        }]);
        state.verify_errors = Some(crate::app::verify_errors::VerifyErrorsPanel::new(
            &result,
            &state.ruleset,
        ));
        let edit_target =
            |state: &State| state.verify_errors.as_ref().expect("panel").rows[0].edit_rule_id();
        assert_eq!(edit_target(&state), Some(id));

        let _ = state.update(Message::DeleteRule(id));
        assert_eq!(state.ruleset.rules.len(), 0);
        assert_eq!(edit_target(&state), None, "the rule is gone");

        let _ = state.update(Message::Undo);
        assert_eq!(state.ruleset.rules.len(), 1);
        assert_eq!(edit_target(&state), Some(id));
    }

    #[test]
    fn test_verify_errors_panel_needs_errors() {
        let mut state = create_test_state();
        handle_toggle_verify_errors(&mut state, true);
        assert!(!state.show_verify_errors, "nothing to show");
        state.verify_errors = Some(verify_errors_panel());
        handle_toggle_verify_errors(&mut state, true);
        assert_eq!(top_layer(&state), TopLayer::VerifyErrors);
        // A rule opened from the panel is edited on top of it
        state.rule_form = Some(RuleForm::default());
        assert_eq!(top_layer(&state), TopLayer::RuleForm);
        state.rule_form = None;
        // The apply flow is never hidden behind it
        state.status = AppStatus::AwaitingApply;
        assert_eq!(top_layer(&state), TopLayer::ApplyFlow);
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
        let _ = crate::app::handlers::handle_rename_profile_requested(&mut state, "test".into());
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
        let _ = handle_open_theme_picker(&mut state);
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

    // ------------------------------------------------------------------
    // Enter, Tab, focus-guarded shortcuts, close flush, preview fallback
    // ------------------------------------------------------------------

    fn enter_repeat() -> iced::Event {
        iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
            key: Key::Named(Named::Enter),
            modified_key: Key::Named(Named::Enter),
            physical_key: iced::keyboard::key::Physical::Unidentified(
                iced::keyboard::key::NativeCode::Unidentified,
            ),
            location: iced::keyboard::Location::Standard,
            modifiers: Modifiers::empty(),
            text: None,
            repeat: true,
        })
    }

    fn enter(state: &mut State) -> Option<String> {
        press(state, &named(Named::Enter), Status::Ignored)
    }

    #[test]
    fn test_enter_runs_the_primary_action_of_the_top_layer() {
        let mut state = create_test_state();
        assert_eq!(enter(&mut state), None, "base layer, nothing to confirm");

        let id = uuid::Uuid::new_v4();
        state.deleting_id = Some(id);
        assert_eq!(enter(&mut state), Some(format!("DeleteRule({id:?})")));
        state.deleting_id = None;

        state.status = AppStatus::AwaitingApply;
        assert_eq!(enter(&mut state).as_deref(), Some("ProceedToApply"));
        state.status = AppStatus::Applying;
        assert_eq!(enter(&mut state), None);
        state.status = AppStatus::Idle;

        state.pending_warning = Some(PendingWarning::EnableServerMode(
            crate::app::ServerEssentials::for_ruleset(&state.ruleset),
        ));
        assert_eq!(enter(&mut state).as_deref(), Some("ConfirmServerMode"));
        state.pending_warning = None;

        crate::app::handlers::handle_open_profile_manager(&mut state);
        assert_eq!(enter(&mut state), None, "nothing chosen in the manager");
        crate::app::handlers::handle_delete_profile_requested(&mut state, "x".into());
        assert_eq!(enter(&mut state).as_deref(), Some("ConfirmDeleteProfile"));
        state.profile_manager = None;

        let _ = crate::app::handlers::handle_toggle_exposure(&mut state, true);
        assert_eq!(enter(&mut state).as_deref(), Some("ToggleExposure(false)"));
        state.exposure.panel = None;

        state.show_diagnostics = true;
        assert_eq!(enter(&mut state), None);
        state.diagnostics.confirm_clear = true;
        assert_eq!(enter(&mut state).as_deref(), Some("ClearEventLogConfirmed"));
        state.show_diagnostics = false;

        state.close_error = Some("disk full".into());
        assert_eq!(
            enter(&mut state).as_deref(),
            Some("CancelClose"),
            "keeps DRFW open"
        );
    }

    #[test]
    fn test_enter_never_confirms_the_countdown_but_ctrl_enter_does() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = create_test_state();
        state.status = AppStatus::PendingConfirmation {
            guard: crate::core::apply_guard::GuardHandle::new_for_testing(
                dir.path(),
                std::time::Duration::from_secs(30),
            ),
        };
        assert_eq!(enter(&mut state).as_deref(), Some("ConfirmHint"));
        assert!(matches!(
            state.status,
            AppStatus::PendingConfirmation { .. }
        ));
        assert!(
            state
                .banners
                .back()
                .is_some_and(|b| b.message.contains("Ctrl+Enter"))
        );
        // A held Enter (repeat) does nothing at all
        assert_eq!(press(&mut state, &enter_repeat(), Status::Ignored), None);
        let ctrl_enter = key_event(Key::Named(Named::Enter), Modifiers::CTRL);
        assert_eq!(
            press(&mut state, &ctrl_enter, Status::Ignored).as_deref(),
            Some("ConfirmClicked")
        );
        // Escape still does nothing here
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored),
            None
        );
    }

    #[test]
    fn test_enter_has_no_action_where_data_or_the_safety_net_is_at_stake() {
        let mut state = create_test_state();
        // Save to System with only untested rules: a click is required
        state.status = AppStatus::AwaitingSaveToSystem;
        state.save_dialog.tested = crate::app::handlers::SaveTested::NothingApplied;
        assert_eq!(enter(&mut state), None);
        state.save_dialog.tested = crate::app::handlers::SaveTested::Differs;
        assert_eq!(
            enter(&mut state).as_deref(),
            Some("SaveToSystemConfirmed(LastConfirmed)")
        );
        state.status = AppStatus::Idle;

        // Start fresh without a backup copy
        state.unreadable_profile = Some(crate::core::profiles::UnreadableProfile {
            name: "test".into(),
            reason: "damaged".into(),
            backup: None,
        });
        state.confirm_start_fresh = true;
        assert_eq!(top_layer(&state), TopLayer::StartFreshConfirm);
        assert_eq!(enter(&mut state), None);
        state.unreadable_profile.as_mut().unwrap().backup = Some("/x/test.json.corrupt-1".into());
        assert_eq!(enter(&mut state).as_deref(), Some("ConfirmStartFresh"));
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored).as_deref(),
            Some("CancelStartFresh")
        );
    }

    #[test]
    fn test_tab_moves_focus_within_the_top_layer() {
        let mut state = create_test_state();
        assert_eq!(
            press(&mut state, &named(Named::Tab), Status::Ignored).as_deref(),
            Some("MoveFocus(true)")
        );
        let shift_tab = key_event(Key::Named(Named::Tab), Modifiers::SHIFT);
        assert_eq!(
            press(&mut state, &shift_tab, Status::Ignored).as_deref(),
            Some("MoveFocus(false)")
        );
        // The inputs cycled are those of the top layer only
        open_helper(&mut state);
        assert_eq!(
            layer_inputs(top_layer(&state)),
            &[crate::app::focus::HELPER_INPUT]
        );
        state.rule_form_helper = None;
        assert!(layer_inputs(top_layer(&state)).contains(&crate::app::focus::RULE_FORM_LABEL));
        assert!(!layer_inputs(top_layer(&state)).contains(&crate::app::focus::RULE_SEARCH));
    }

    #[test]
    fn test_escape_behind_a_dialog_leaves_the_base_layer_alone() {
        let mut state = create_test_state();
        state.rule_search = "ssh".into();
        state.dragged_rule_id = Some(uuid::Uuid::new_v4());
        state.status = AppStatus::Applying;
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored),
            None
        );
        assert!(state.dragged_rule_id.is_some(), "no drag cancel behind it");
        assert_eq!(state.rule_search, "ssh", "no search clear behind it");

        // Base layer: an Escape the search input took (to unfocus) keeps the
        // search; the next one clears it
        state.status = AppStatus::Idle;
        state.clear_drag_state();
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Captured),
            None
        );
        assert_eq!(state.rule_search, "ssh");
        let _ = press(&mut state, &named(Named::Escape), Status::Ignored);
        assert_eq!(state.rule_search, "");
    }

    #[test]
    fn test_escape_in_diagnostics_cancels_the_clear_prompt_first() {
        let mut state = create_test_state();
        state.show_diagnostics = true;
        handle_toggle_diagnostics_confirm(&mut state);
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored).as_deref(),
            Some("ClearEventLogCancelled")
        );
        state.diagnostics.confirm_clear = false;
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored).as_deref(),
            Some("ToggleDiagnostics(false)")
        );
    }

    fn handle_toggle_diagnostics_confirm(state: &mut State) {
        crate::app::handlers::handle_clear_event_log(state);
        assert!(state.diagnostics.confirm_clear);
    }

    /// Ctrl shortcuts wait for the focus query: with a text input focused
    /// (typing in the search box) they do nothing.
    #[test]
    fn test_base_shortcuts_do_nothing_while_typing() {
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
        assert!(!state.ruleset.rules[0].enabled);

        let _ = state.update(Message::BaseShortcut(BaseShortcut::Undo, true));
        assert!(!state.ruleset.rules[0].enabled, "typing: no undo");

        // A dialog opened while the query ran: no undo behind it either
        state.show_export_modal = true;
        let task = handle_base_shortcut(&state, BaseShortcut::Undo, false);
        assert_eq!(task.units(), 0);
        state.show_export_modal = false;

        // Nothing focused: the shortcut sends its message
        let task = handle_base_shortcut(&state, BaseShortcut::Undo, false);
        assert!(task.units() > 0);
        let _ = state.update(Message::Undo);
        assert!(state.ruleset.rules[0].enabled);
        assert!(
            state
                .banners
                .back()
                .is_some_and(|b| b.message.starts_with("Undid: ")),
            "the undo is announced"
        );
        let _ = state.update(Message::Redo);
        assert!(
            state
                .banners
                .back()
                .is_some_and(|b| b.message.starts_with("Redid: "))
        );
    }

    #[test]
    fn test_close_with_failed_save_stays_open_and_asks() {
        let mut state = create_test_state();
        let _ = handle_close_requested(&mut state, iced::window::Id::unique());
        assert!(state.closing);
        let _ = handle_close_flushed(&mut state, Err("profile 'test': disk full".into()));
        assert!(!state.closing, "autosave resumes");
        assert_eq!(top_layer(&state), TopLayer::CloseFailed);
        assert!(state.close_error.as_ref().unwrap().contains("disk full"));
        // Escape keeps DRFW open
        assert_eq!(
            press(&mut state, &named(Named::Escape), Status::Ignored).as_deref(),
            Some("CancelClose")
        );
        handle_cancel_close(&mut state);
        assert!(state.close_error.is_none());
        // "Close anyway" only acts from the dialog
        assert_eq!(handle_close_anyway(&mut state).units(), 0);
        state.close_error = Some("x".into());
        assert!(handle_close_anyway(&mut state).units() > 0);
        assert!(state.close_error.is_none());
    }

    #[test]
    fn test_close_waits_for_a_running_rename() {
        let mut state = create_test_state();
        state.profile_rename_in_flight = true;
        let task = handle_close_requested(&mut state, iced::window::Id::unique());
        assert_eq!(task.units(), 0, "nothing is saved under the old name");
        assert!(state.closing && state.close_after_rename);
        let _ = crate::app::handlers::handle_profile_renamed(
            &mut state,
            "test".into(),
            "renamed".into(),
            Ok(vec!["renamed".into()]),
        );
        assert!(!state.close_after_rename, "the flush started");
        assert_eq!(state.active_profile_name, "renamed");
    }

    /// With the diff enabled but no diff yet (every launch), the preview
    /// shows the plain ruleset, and clicks resolve against it.
    #[test]
    fn test_preview_click_falls_back_to_the_plain_ruleset() {
        use crate::core::test_helpers::create_test_rule;
        let mut state = create_test_state();
        state.last_applied_ruleset = None;
        state.cached_applied_text = None;
        state
            .ruleset
            .rules
            .push(create_test_rule("Allow SSH", Some(22)));
        state.mark_profile_dirty();
        state.show_diff = true;
        assert!(state.cached_diff_tokens.is_none());
        let line = state
            .cached_nft_tokens
            .iter()
            .find(|l| l.tokens.iter().any(|t| t.text.contains("Allow SSH")))
            .expect("the rule's line")
            .line_number;
        handle_click_preview_line(&mut state, line);
        assert_eq!(state.rule_search, "Allow SSH");
        assert!(handle_copy_preview_line(&mut state, line).units() > 0);
    }

    /// The diff at startup (nothing applied this session) compares with the
    /// kept record when there is one, labelled by where it comes from; the
    /// record never makes the ruleset "applied" (the Apply button stays
    /// marked).
    mod diff_baseline {
        use crate::app::handlers::test_utils::create_test_state;
        use crate::app::syntax_cache::DiffType;
        use crate::app::{BaselineKind, State};
        use crate::core::confirmed::{ConfirmedRecord, RecordKind, current_boot_id};
        use crate::core::firewall::FirewallRuleset;
        use crate::core::test_helpers::create_test_rule;

        fn kept_ruleset() -> FirewallRuleset {
            let mut kept = FirewallRuleset::new();
            kept.rules.push(create_test_rule("Old web", Some(8080)));
            kept
        }

        fn record(boot_id: Option<&str>) -> ConfirmedRecord {
            let kept = kept_ruleset();
            ConfirmedRecord::new(&kept.to_nftables_json(), &kept, RecordKind::Confirmed)
                .unwrap()
                .with_boot_id(boot_id)
        }

        /// As `State::new` leaves it: nothing applied, `record` loaded, and
        /// an editor rule the record does not have.
        fn startup_state(record: Option<ConfirmedRecord>) -> State {
            let mut state = create_test_state();
            state.last_applied_ruleset = None;
            state.confirmed_record = record;
            state.refresh_diff_baseline();
            state.show_diff = true;
            state
                .ruleset
                .rules
                .push(create_test_rule("Allow SSH", Some(22)));
            state.mark_profile_dirty();
            state
        }

        fn changed_lines(state: &State, kind: DiffType) -> Vec<String> {
            state
                .cached_diff_tokens
                .as_ref()
                .expect("a diff")
                .iter()
                .filter(|(t, _)| *t == kind)
                .map(|(_, line)| line.tokens.iter().map(|t| &*t.text).collect())
                .collect()
        }

        #[test]
        fn test_no_record_no_diff() {
            let state = startup_state(None);
            assert_eq!(state.diff_baseline, None);
            assert!(state.cached_diff_tokens.is_none());
            assert!(state.is_dirty(), "unknown: Apply Changes*");
        }

        #[test]
        fn test_record_from_this_boot_is_the_last_applied() {
            let Some(boot) = current_boot_id() else {
                return; // no procfs boot id: every record is "earlier"
            };
            let mut state = startup_state(Some(record(Some(boot))));
            assert_eq!(state.diff_baseline, Some(BaselineKind::KeptThisBoot));
            assert_eq!(
                BaselineKind::KeptThisBoot.diff_label(),
                "Show diff (vs last applied)"
            );
            assert!(
                changed_lines(&state, DiffType::Added)
                    .iter()
                    .any(|l| l.contains("Allow SSH"))
            );
            assert!(
                changed_lines(&state, DiffType::Removed)
                    .iter()
                    .any(|l| l.contains("Old web"))
            );
            assert!(state.last_applied_ruleset.is_none(), "not faked as applied");
            assert!(state.is_dirty());

            // The editor holds the kept rules: no changed lines, but still
            // not known to be applied
            state.ruleset = state
                .confirmed_record
                .as_ref()
                .and_then(ConfirmedRecord::ruleset)
                .unwrap()
                .clone();
            state.mark_profile_dirty();
            assert!(
                state
                    .cached_diff_tokens
                    .as_ref()
                    .unwrap()
                    .iter()
                    .all(|(t, _)| *t == DiffType::Unchanged)
            );
            assert!(state.is_dirty(), "the record is not \"applied\"");

            // The Exposure panel compares with the same baseline
            state.exposure.panel = Some(crate::app::exposure::ExposurePanel::scanning());
            state.mark_profile_dirty();
            let panel = state.exposure.panel.as_ref().unwrap();
            assert_eq!(
                panel.applied,
                crate::app::exposure::AppliedState::SameAsEditor
            );
            assert!(panel.applied_note.contains("this boot"));

            // An apply of this session that is not kept: the record is only
            // the last kept rules
            state.set_last_applied(None);
            assert_eq!(state.diff_baseline, Some(BaselineKind::LastKept));
            assert_eq!(
                BaselineKind::LastKept.diff_label(),
                "Show diff (vs last kept)"
            );
        }

        #[test]
        fn test_record_from_an_earlier_boot() {
            let state = startup_state(Some(record(Some("an-earlier-boot"))));
            assert_eq!(state.diff_baseline, Some(BaselineKind::KeptEarlierSession));
            assert_eq!(
                BaselineKind::KeptEarlierSession.diff_label(),
                "Show diff (vs last kept, earlier session)"
            );
            assert!(state.cached_diff_tokens.is_some());
            assert!(state.is_dirty());
        }

        /// A record read later (Apply re-reads it) becomes the baseline; once
        /// this GUI applied, what it applied is the baseline instead.
        #[test]
        fn test_reloaded_record_and_applied_rules() {
            let mut state = startup_state(None);
            state.replace_confirmed_record(Some(record(None)));
            assert_eq!(state.diff_baseline, Some(BaselineKind::KeptEarlierSession));
            assert!(state.cached_diff_tokens.is_some());

            let applied = state.ruleset.clone();
            state.set_last_applied(Some(applied));
            assert_eq!(state.diff_baseline, Some(BaselineKind::Applied));
            assert!(!state.is_dirty());
            state.replace_confirmed_record(None);
            assert_eq!(state.diff_baseline, Some(BaselineKind::Applied));
        }
    }
}
