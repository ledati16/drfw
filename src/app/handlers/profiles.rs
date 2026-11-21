//! Profile management, switching and saving
//!
//! Handles all message variants related to firewall profile management:
//! - Profile creation (from current ruleset or empty), never replacing a profile
//! - Profile switching with dirty-state detection
//! - Profile deletion and renaming (audit-logged with their real outcome)
//! - Read-only handling of profiles that could not be loaded
//! - Debounced autosave and the "Save & Switch" flow
//!
//! # Save model
//!
//! - `profile_dirty` is cleared only after a save *succeeded* and nothing
//!   changed meanwhile; a failed save shows a banner and is retried.
//! - Autosave pauses while the "unsaved changes" dialog is open (so "Discard"
//!   really discards), while a rename runs, and while the profile is read-only.
//! - Async results carry `profile_generation` / `switch_request`; results that
//!   belong to a profile that is no longer active are dropped.

use std::time::{Duration, Instant};

use iced::Task;
use tracing::error;

use crate::app::{BannerSeverity, FirewallRuleset, Message, ProfileSaveOutcome, State};
use crate::audit;
use crate::core::profiles::{UnreadableProfile, find_name_conflict, validate_profile_name};

/// Normal autosave debounce after the last edit.
const AUTOSAVE_DEBOUNCE: Duration = Duration::from_millis(1000);
/// Retry delay after a failed save (avoids hammering a full or read-only disk).
const AUTOSAVE_RETRY: Duration = Duration::from_millis(5000);

/// Returns `true` for messages that change the active profile's content, or
/// would apply/persist it. They are refused while the profile is read-only
/// (see `State::unreadable_profile`).
pub(crate) fn edits_profile(message: &Message) -> bool {
    matches!(
        message,
        Message::AddRuleClicked
            | Message::EditRuleClicked(_)
            | Message::SaveRuleForm
            | Message::ToggleRuleEnabled(_)
            | Message::DeleteRuleRequested(_)
            | Message::DeleteRule(_)
            | Message::RuleDragStart(_)
            | Message::RuleDropped(_)
            | Message::Undo
            | Message::Redo
            | Message::ToggleStrictIcmpRequested(_)
            | Message::ConfirmStrictIcmp
            | Message::IcmpRateLimitChanged(_)
            | Message::ToggleRpfRequested(_)
            | Message::ConfirmEnableRpf
            | Message::ToggleBlockForwarding(_)
            | Message::ToggleDroppedLogging(_)
            | Message::LogRateChanged(_)
            | Message::LogPrefixChanged(_)
            | Message::ServerModeToggled(_)
            | Message::ConfirmServerMode
            | Message::ApplyClicked
            | Message::SaveToSystemClicked
    )
}

/// Why `name` can't be used for a new (or renamed) profile, if anything.
///
/// `except` is the profile being renamed (renaming "Work" to "work" is fine).
pub(crate) fn profile_name_error(
    existing: &[String],
    name: &str,
    except: Option<&str>,
) -> Option<String> {
    if let Err(e) = validate_profile_name(name) {
        return Some(e.to_string());
    }
    find_name_conflict(existing, name, except)
        .map(|conflict| format!("A profile named '{conflict}' already exists"))
}

/// Clears all per-profile editing state (undo history, open form, pending
/// delete, drag state, pending warning, verification errors). Rule ids and
/// undo entries of the previous profile must never act on the new one.
fn reset_editing_state(state: &mut State) {
    super::clear_verify_errors(state);
    state.command_history = crate::command::CommandHistory::default();
    state.rule_form = None;
    state.rule_form_initial = None;
    state.confirm_discard_form = false;
    state.rule_form_helper = None;
    state.form_errors = None;
    state.deleting_id = None;
    state.pending_warning = None;
    state.confirm_start_fresh = false;
    state.clear_drag_state();
}

/// Shortens long error messages for banners.
fn banner_error(prefix: &str, error: &str) -> String {
    if error.len() > 120 {
        format!("{prefix}: {}...", crate::utils::truncate_str(error, 117))
    } else {
        format!("{prefix}: {error}")
    }
}

/// Handles profile selection (with dirty check)
///
/// Clicking the active profile does nothing: reloading it from disk would
/// wipe the undo history and silently drop unsaved edits. Only a read-only
/// (unreadable) active profile is reloaded, to retry it.
pub(crate) fn handle_profile_selected(state: &mut State, name: String) -> Task<Message> {
    if name == state.active_profile_name && state.unreadable_profile.is_none() {
        return Task::none();
    }
    if state.is_profile_dirty() {
        // Autosave pauses while this dialog is open
        state.pending_profile_switch = Some(name);
        return Task::none();
    }
    perform_profile_switch(state, name)
}

/// Starts loading `name`; the result is applied by [`handle_profile_switched`]
/// unless a newer switch was requested meanwhile.
pub(crate) fn perform_profile_switch(state: &mut State, name: String) -> Task<Message> {
    state.pending_profile_switch = None;
    state.switch_request += 1;
    let request = state.switch_request;

    Task::perform(
        async move {
            let result = crate::core::profiles::load_profile_or_preserve(&name).await;
            (name, result)
        },
        move |(name, result)| Message::ProfileSwitched(request, name, result),
    )
}

/// Handles profile switch completion
///
/// A profile that could not be loaded is still switched to, but opened
/// read-only (empty, no autosave) with an error banner; its file was copied
/// aside by the loader.
pub(crate) fn handle_profile_switched(
    state: &mut State,
    request: u64,
    name: String,
    result: Result<FirewallRuleset, UnreadableProfile>,
) -> Task<Message> {
    if request != state.switch_request {
        tracing::debug!("Ignoring stale load of profile '{name}'");
        return Task::none();
    }
    // An apply started while the profile loaded: it owns the ruleset now.
    // Say so instead of dropping the switch silently.
    if super::edits_locked(state) {
        state.push_banner(
            format!(
                "Switching to '{name}' was cancelled because an apply started. \
                 Switch again when it is done."
            ),
            BannerSeverity::Warning,
        );
        return Task::none();
    }

    let from_profile = state.active_profile_name.clone();
    let ruleset = match result {
        Ok(ruleset) => {
            state.unreadable_profile = None;
            ruleset
        }
        Err(issue) => {
            state.push_banner(issue.user_message(), BannerSeverity::Error);
            state.unreadable_profile = Some(issue);
            FirewallRuleset::default()
        }
    };

    state.cached_disk_profile = Some(ruleset.clone());
    state.ruleset = ruleset;
    state.active_profile_name.clone_from(&name);
    state.profile_dirty = false;
    state.profile_save_error = None;
    state.profile_generation += 1;
    reset_editing_state(state);

    state.update_cached_text();
    state.mark_config_dirty();

    let enable_event_log = state.enable_event_log;
    let to_profile = name;
    super::audit_task(async move {
        audit::log_profile_switched(enable_event_log, &from_profile, &to_profile).await;
    })
}

/// "Start fresh" in the read-only notice: asks for confirmation first (see
/// `view::profile::view_start_fresh_confirm`; stronger when no backup copy
/// of the file exists).
pub(crate) fn handle_start_fresh_requested(state: &mut State) {
    if state.unreadable_profile.is_some() {
        state.confirm_start_fresh = true;
    }
}

/// Cancels the "Start fresh?" confirmation
pub(crate) fn handle_cancel_start_fresh(state: &mut State) {
    state.confirm_start_fresh = false;
}

/// Replaces an unreadable profile with an empty one (confirmed "Start fresh").
///
/// The original file was copied aside when the load failed, if that was
/// possible (the confirmation warns when it wasn't); the empty profile is
/// saved over it by the next autosave. Audit-logged with the backup path.
pub(crate) fn handle_start_fresh_profile(state: &mut State) -> Task<Message> {
    state.confirm_start_fresh = false;
    let Some(issue) = state.unreadable_profile.take() else {
        return Task::none();
    };
    state.ruleset = FirewallRuleset::default();
    state.cached_disk_profile = Some(FirewallRuleset::default());
    state.profile_save_error = None;
    state.profile_generation += 1;
    reset_editing_state(state);
    // Write the empty profile (the dirty flag is what triggers autosave)
    state.mark_profile_dirty();

    let backup = issue.backup.as_ref().map(|path| path.display().to_string());
    let note = match &backup {
        Some(path) => format!(" The old file is kept at {path}."),
        None => String::new(),
    };
    state.push_banner(
        format!("Started fresh: '{}' is now empty.{note}", issue.name),
        BannerSeverity::Info,
    );
    let enable_event_log = state.enable_event_log;
    super::audit_task(async move {
        audit::log_profile_reset(enable_event_log, &issue.name, backup).await;
    })
}

/// Handles creating a profile from the current rules, or an empty one.
///
/// Refuses invalid names and names that already exist (ignoring case); the
/// active profile only changes once the file was created.
pub(crate) fn handle_save_profile_as(state: &mut State, name: String) -> Task<Message> {
    if let Some(reason) = profile_name_error(&state.available_profiles, &name, None) {
        state.push_banner(reason, BannerSeverity::Error);
        return Task::none();
    }

    let creating_empty = state
        .profile_manager
        .as_ref()
        .is_some_and(|mgr| mgr.creating_empty);
    let ruleset = if creating_empty {
        FirewallRuleset::default()
    } else {
        state.ruleset.clone()
    };
    // The new profile becomes the active one: write the current profile's
    // edits that autosave has not written yet, or they would be lost.
    let flush = (state.profile_dirty && state.unreadable_profile.is_none())
        .then(|| (state.active_profile_name.clone(), state.ruleset.clone()));

    if let Some(mgr) = &mut state.profile_manager {
        mgr.creating_new = false;
        mgr.creating_empty = false;
        mgr.new_name_input.clear();
        mgr.new_name_error = None;
    }

    Task::perform(
        async move {
            let result = async {
                if let Some((current, current_rules)) = flush {
                    crate::core::profiles::save_profile(&current, &current_rules)
                        .await
                        .map_err(|e| format!("could not save '{current}' first: {e}"))?;
                }
                crate::core::profiles::create_profile(&name, &ruleset)
                    .await
                    .map_err(|e| e.to_string())?;
                crate::core::profiles::list_profiles()
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            (name, ruleset, result)
        },
        |(name, ruleset, result)| Message::ProfileCreated(name, Box::new(ruleset), result),
    )
}

/// Handles the result of profile creation: switches to the new profile on
/// success, reports (and audit-logs) the failure otherwise.
pub(crate) fn handle_profile_created(
    state: &mut State,
    name: String,
    ruleset: FirewallRuleset,
    result: Result<Vec<String>, String>,
) -> Task<Message> {
    let enable_event_log = state.enable_event_log;
    match result {
        Ok(profiles) if super::edits_locked(state) => {
            // An apply owns the ruleset: list the new profile, don't switch
            state.set_available_profiles(profiles);
            state.push_banner(
                format!("Profile '{name}' was created. Switch to it when the apply is done."),
                BannerSeverity::Info,
            );
            super::audit_task(async move {
                audit::log_profile_created(enable_event_log, &name).await;
            })
        }
        Ok(profiles) => {
            state.set_available_profiles(profiles);
            // The new profile holds exactly what was written (the profile
            // manager is modal, so nothing changed meanwhile)
            state.profile_dirty = false;
            state.ruleset = ruleset.clone();
            state.cached_disk_profile = Some(ruleset);
            state.active_profile_name.clone_from(&name);
            state.unreadable_profile = None;
            state.profile_save_error = None;
            state.profile_generation += 1;
            reset_editing_state(state);
            state.update_cached_text();
            state.mark_config_dirty();
            super::audit_task(async move {
                audit::log_profile_created(enable_event_log, &name).await;
            })
        }
        Err(e) => {
            state.push_banner(
                banner_error("Failed to create profile", &e),
                BannerSeverity::Error,
            );
            super::audit_task(async move {
                audit::log_profile_create_failed(enable_event_log, &name, e).await;
            })
        }
    }
}

/// Opens the name field for a new profile (from the current rules, or
/// empty) and focuses it; an open rename is closed (one name field at a time).
fn start_creating_profile(state: &mut State, empty: bool) -> Task<Message> {
    let Some(mgr) = &mut state.profile_manager else {
        return Task::none();
    };
    mgr.creating_new = true;
    mgr.creating_empty = empty;
    mgr.new_name_input = String::new();
    mgr.new_name_error = profile_name_error(&state.available_profiles, "", None);
    mgr.renaming_name = None;
    mgr.rename_error = None;
    crate::app::focus::focus_input(crate::app::focus::PROFILE_NEW_NAME)
}

/// Handles opening profile creation flow
pub(crate) fn handle_start_creating_new_profile(state: &mut State) -> Task<Message> {
    start_creating_profile(state, false)
}

/// Handles creating empty profile flow
pub(crate) fn handle_create_empty_profile(state: &mut State) -> Task<Message> {
    start_creating_profile(state, true)
}

/// Handles new profile name input change
pub(crate) fn handle_new_profile_name_changed(state: &mut State, name: String) {
    if let Some(mgr) = &mut state.profile_manager {
        mgr.new_name_error = profile_name_error(&state.available_profiles, &name, None);
        mgr.new_name_input = name;
    }
}

/// Handles canceling profile creation
pub(crate) fn handle_cancel_creating_new_profile(state: &mut State) {
    if let Some(mgr) = &mut state.profile_manager {
        mgr.creating_new = false;
        mgr.creating_empty = false;
        mgr.new_name_input.clear();
        mgr.new_name_error = None;
    }
}

/// Handles opening profile manager modal
pub(crate) fn handle_open_profile_manager(state: &mut State) {
    state.profile_manager = Some(crate::app::ProfileManagerState {
        renaming_name: None,
        deleting_name: None,
        creating_new: false,
        creating_empty: false,
        new_name_input: String::new(),
        new_name_error: None,
        rename_error: None,
    });
}

/// Handles closing profile manager modal
pub(crate) fn handle_close_profile_manager(state: &mut State) {
    state.profile_manager = None;
}

/// Handles requesting profile deletion
pub(crate) fn handle_delete_profile_requested(state: &mut State, name: String) {
    if let Some(mgr) = &mut state.profile_manager {
        mgr.deleting_name = Some(name);
    }
}

/// Logs a refused or failed profile deletion.
fn log_delete_failed(state: &State, name: String, reason: String) -> Task<Message> {
    let enable_event_log = state.enable_event_log;
    super::audit_task(async move {
        audit::log_profile_delete_failed(enable_event_log, &name, reason).await;
    })
}

/// Handles confirming profile deletion
pub(crate) fn handle_confirm_delete_profile(state: &mut State) -> Task<Message> {
    let Some(name) = state
        .profile_manager
        .as_mut()
        .and_then(|mgr| mgr.deleting_name.take())
    else {
        return Task::none();
    };

    // Validation: ensure at least one profile remains
    if state.available_profiles.len() <= 1 {
        state.push_banner("Cannot delete last profile", BannerSeverity::Error);
        return log_delete_failed(state, name, "Cannot delete last profile".to_string());
    }

    // Validation: cannot delete active profile
    if name == state.active_profile_name {
        state.push_banner(
            "Cannot delete active profile - switch to another profile first",
            BannerSeverity::Error,
        );
        return log_delete_failed(state, name, "Cannot delete active profile".to_string());
    }

    Task::perform(
        async move {
            let result = async {
                crate::core::profiles::delete_profile(&name).await?;
                crate::core::profiles::list_profiles().await
            }
            .await
            .map_err(|e| e.to_string());
            (name, result)
        },
        |(name, result)| Message::ProfileDeleted(name, result),
    )
}

/// Handles profile deletion result (audit-logs the real outcome)
pub(crate) fn handle_profile_deleted(
    state: &mut State,
    name: String,
    result: Result<Vec<String>, String>,
) -> Task<Message> {
    let enable_event_log = state.enable_event_log;
    match result {
        Ok(profiles) => {
            let old_active = state.active_profile_name.clone();
            state.set_available_profiles(profiles.clone());
            let audit_task = super::audit_task(async move {
                audit::log_profile_deleted(enable_event_log, &name).await;
            });
            // If the active profile vanished, switch to the first available
            if !profiles.iter().any(|p| p == &old_active) {
                let next = profiles
                    .first()
                    .cloned()
                    .unwrap_or_else(|| crate::core::profiles::DEFAULT_PROFILE_NAME.to_string());
                return audit_task.chain(perform_profile_switch(state, next));
            }
            audit_task
        }
        Err(e) => {
            state.push_banner(
                banner_error("Failed to delete profile", &e),
                BannerSeverity::Error,
            );
            log_delete_failed(state, name, e)
        }
    }
}

/// Handles canceling profile deletion
pub(crate) fn handle_cancel_delete_profile(state: &mut State) {
    if let Some(mgr) = &mut state.profile_manager {
        mgr.deleting_name = None;
    }
}

/// Handles requesting profile rename: opens the inline name field, focused
/// (closing the new-profile field: one name field at a time)
pub(crate) fn handle_rename_profile_requested(state: &mut State, name: String) -> Task<Message> {
    let Some(mgr) = &mut state.profile_manager else {
        return Task::none();
    };
    mgr.rename_error = None;
    mgr.renaming_name = Some((name.clone(), name));
    mgr.creating_new = false;
    mgr.creating_empty = false;
    mgr.new_name_input.clear();
    mgr.new_name_error = None;
    crate::app::focus::focus_input(crate::app::focus::PROFILE_RENAME)
}

/// Handles profile new name input change
pub(crate) fn handle_profile_new_name_changed(state: &mut State, new_name: String) {
    if let Some(mgr) = &mut state.profile_manager
        && let Some((old, _)) = &mgr.renaming_name
    {
        let old = old.clone();
        mgr.rename_error = profile_name_error(&state.available_profiles, &new_name, Some(&old));
        mgr.renaming_name = Some((old, new_name));
    }
}

/// Handles confirming profile rename
///
/// The active profile name changes only after the rename succeeded (see
/// [`handle_profile_renamed`]); an existing profile is never replaced.
pub(crate) fn handle_confirm_rename_profile(state: &mut State) -> Task<Message> {
    let Some((old, new)) = state
        .profile_manager
        .as_ref()
        .and_then(|mgr| mgr.renaming_name.clone())
    else {
        return Task::none();
    };

    if old == new {
        if let Some(mgr) = &mut state.profile_manager {
            mgr.renaming_name = None;
        }
        return Task::none();
    }
    if let Some(reason) = profile_name_error(&state.available_profiles, &new, Some(&old)) {
        // Keep the rename field open so the user can fix the name
        if let Some(mgr) = &mut state.profile_manager {
            mgr.rename_error = Some(reason);
        }
        return Task::none();
    }
    if old == state.active_profile_name
        && (state.profile_save_in_flight || state.profile_rename_in_flight)
    {
        state.push_banner(
            "The profile is being saved; try renaming again in a moment",
            BannerSeverity::Warning,
        );
        return Task::none();
    }

    if let Some(mgr) = &mut state.profile_manager {
        mgr.renaming_name = None;
        mgr.rename_error = None;
    }
    // Autosave pauses until the rename finished, so it can't recreate `old`
    state.profile_rename_in_flight = true;

    Task::perform(
        async move {
            let result = async {
                crate::core::profiles::rename_profile(&old, &new).await?;
                crate::core::profiles::list_profiles().await
            }
            .await
            .map_err(|e| e.to_string());
            (old, new, result)
        },
        |(old, new, result)| Message::ProfileRenamed(old, new, result),
    )
}

/// Handles profile rename result (audit-logs the real outcome)
pub(crate) fn handle_profile_renamed(
    state: &mut State,
    old: String,
    new: String,
    result: Result<Vec<String>, String>,
) -> Task<Message> {
    state.profile_rename_in_flight = false;
    let enable_event_log = state.enable_event_log;
    let audit = handle_rename_outcome(state, old, new, result, enable_event_log);
    // A close request waited for the rename (see `handle_close_requested`)
    if std::mem::take(&mut state.close_after_rename) {
        return Task::batch([audit, super::start_close_flush(state)]);
    }
    audit
}

/// Applies a finished rename and returns its audit task.
fn handle_rename_outcome(
    state: &mut State,
    old: String,
    new: String,
    result: Result<Vec<String>, String>,
    enable_event_log: bool,
) -> Task<Message> {
    match result {
        Ok(profiles) => {
            state.set_available_profiles(profiles);
            if state.active_profile_name == old {
                state.active_profile_name.clone_from(&new);
                state.profile_generation += 1;
                // The errors were found under the old name; start clean
                super::clear_verify_errors(state);
                if let Some(issue) = &mut state.unreadable_profile {
                    issue.name.clone_from(&new);
                }
                state.mark_config_dirty();
            }
            super::audit_task(async move {
                audit::log_profile_renamed(enable_event_log, &old, &new).await;
            })
        }
        Err(e) => {
            state.push_banner(
                banner_error("Failed to rename profile", &e),
                BannerSeverity::Error,
            );
            super::audit_task(async move {
                audit::log_profile_rename_failed(enable_event_log, &old, e).await;
            })
        }
    }
}

/// Handles canceling profile rename
pub(crate) fn handle_cancel_rename_profile(state: &mut State) {
    if let Some(mgr) = &mut state.profile_manager {
        mgr.renaming_name = None;
        mgr.rename_error = None;
    }
}

/// Starts saving the current ruleset to the active profile.
///
/// `then_switch_to` is the "Save & Switch" target: the switch happens only if
/// the save succeeds.
fn start_profile_save(state: &mut State, then_switch_to: Option<String>) -> Task<Message> {
    state.profile_save_in_flight = true;
    let generation = state.profile_generation;
    let name = state.active_profile_name.clone();
    let snapshot = state.ruleset.clone();

    Task::perform(
        async move {
            let result = crate::core::profiles::save_profile(&name, &snapshot)
                .await
                .map_err(|e| e.to_string());
            ProfileSaveOutcome {
                generation,
                name,
                snapshot,
                then_switch_to,
                result,
            }
        },
        |outcome| Message::ProfileSaved(Box::new(outcome)),
    )
}

/// Handles confirming profile switch (saves current profile first)
///
/// Refused while a rename of the profile runs: the save would recreate the
/// file under its old name. The dialog stays open to try again.
pub(crate) fn handle_confirm_profile_switch(state: &mut State) -> Task<Message> {
    if state.pending_profile_switch.is_none() {
        return Task::none();
    }
    if state.profile_rename_in_flight {
        state.push_banner(
            "The profile is being renamed; try again in a moment",
            BannerSeverity::Warning,
        );
        return Task::none();
    }
    let Some(name) = state.pending_profile_switch.take() else {
        return Task::none();
    };
    start_profile_save(state, Some(name))
}

/// Handles discarding changes and switching profile
///
/// Autosave was paused while the dialog was open, so the discarded edits were
/// never written; clearing the dirty flag keeps them from being saved before
/// the other profile has loaded from disk.
pub(crate) fn handle_discard_profile_switch(state: &mut State) -> Task<Message> {
    let Some(name) = state.pending_profile_switch.take() else {
        return Task::none();
    };
    state.profile_dirty = false;
    perform_profile_switch(state, name)
}

/// Handles canceling profile switch dialog (autosave resumes)
pub(crate) fn handle_cancel_profile_switch(state: &mut State) {
    state.pending_profile_switch = None;
}

/// `true` while autosave must not run: the "unsaved changes" dialog is open
/// (so "Discard" discards), a rename is running, or the profile is read-only.
fn autosave_paused(state: &State) -> bool {
    state.pending_profile_switch.is_some()
        || state.profile_rename_in_flight
        || state.unreadable_profile.is_some()
}

/// When the next autosave is due: `None` while there is nothing to save, a
/// save is running, or autosave is paused. The debounce timer is re-armed
/// after any message that makes this `Some` again (e.g. the running save
/// finished, the switch dialog closed).
pub(crate) fn profile_save_deadline(state: &State, now: Instant) -> Option<Instant> {
    if !state.profile_dirty || state.profile_save_in_flight || autosave_paused(state) {
        return None;
    }
    let debounce = if state.profile_save_error.is_some() {
        AUTOSAVE_RETRY
    } else {
        AUTOSAVE_DEBOUNCE
    };
    Some(
        state
            .last_profile_change
            .map_or(now, |last_change| last_change + debounce),
    )
}

/// Starts the autosave if it is due (see [`profile_save_deadline`]).
pub(crate) fn run_profile_save_if_due(state: &mut State, now: Instant) -> Task<Message> {
    if profile_save_deadline(state, now).is_none_or(|deadline| now < deadline) {
        return Task::none();
    }
    start_profile_save(state, None)
}

/// Handles the result of a profile save.
///
/// Success: the snapshot becomes the "on disk" reference and the dirty flag
/// clears unless the ruleset changed meanwhile. Failure: a banner (once per
/// distinct error), the dirty flag stays set and the save is retried; a failed
/// "Save & Switch" cancels the switch.
pub(crate) fn handle_profile_saved(
    state: &mut State,
    outcome: ProfileSaveOutcome,
) -> Task<Message> {
    state.profile_save_in_flight = false;
    let current = outcome.generation == state.profile_generation;

    match outcome.result {
        Ok(()) => {
            if !current {
                if let Some(target) = outcome.then_switch_to {
                    state.push_banner(
                        format!(
                            "The switch to '{target}' was cancelled because the profile \
                             changed meanwhile. Choose it again to switch."
                        ),
                        BannerSeverity::Warning,
                    );
                }
                return Task::none();
            }
            let unchanged = crate::app::rulesets_match(&outcome.snapshot, &state.ruleset);
            state.set_cached_disk_profile(outcome.snapshot);
            if unchanged {
                state.profile_dirty = false;
            }
            if state.profile_save_error.take().is_some() {
                state.push_banner(
                    format!("Profile '{}' saved", outcome.name),
                    BannerSeverity::Success,
                );
            }
            match outcome.then_switch_to {
                // Edited while "Save & Switch" was saving: save those edits
                // too before switching, or the switch would drop them
                Some(target) if !unchanged => start_profile_save(state, Some(target)),
                Some(target) => perform_profile_switch(state, target),
                None => Task::none(),
            }
        }
        Err(e) => {
            error!("Failed to save profile '{}': {e}", outcome.name);
            let message = if outcome.then_switch_to.is_some() {
                format!(
                    "Could not save profile '{}': {e}. The switch was cancelled; your changes are kept.",
                    outcome.name
                )
            } else {
                format!(
                    "Could not save profile '{}': {e}. Changes are kept and saving will be retried.",
                    outcome.name
                )
            };
            if state.profile_save_error.as_deref() != Some(message.as_str()) {
                state.push_banner(message.clone(), BannerSeverity::Error);
            }
            if current {
                state.profile_save_error = Some(message);
                // Retry later (see AUTOSAVE_RETRY_MS), not on the next tick
                state.last_profile_change = Some(std::time::Instant::now());
            }
            Task::none()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::handlers::test_utils::create_test_state;
    use crate::core::test_helpers::create_test_rule;

    fn saved(
        state: &State,
        then_switch_to: Option<&str>,
        result: Result<(), String>,
    ) -> ProfileSaveOutcome {
        ProfileSaveOutcome {
            generation: state.profile_generation,
            name: state.active_profile_name.clone(),
            snapshot: state.ruleset.clone(),
            then_switch_to: then_switch_to.map(str::to_string),
            result,
        }
    }

    /// Makes the test state's profile dirty with an edit older than the debounce.
    fn dirty_state() -> State {
        let mut state = create_test_state();
        state.ruleset.rules.push(create_test_rule("New", Some(80)));
        state.mark_profile_dirty();
        state.last_profile_change =
            std::time::Instant::now().checked_sub(std::time::Duration::from_secs(10));
        state
    }

    fn switch_done(
        state: &mut State,
        name: &str,
        result: Result<FirewallRuleset, UnreadableProfile>,
    ) {
        let _ = perform_profile_switch(state, name.to_string());
        let request = state.switch_request;
        let _ = handle_profile_switched(state, request, name.to_string(), result);
    }

    /// Opens the "Verification Errors" panel with an error on the first rule.
    fn show_verify_errors(state: &mut State) {
        use crate::core::verify::{ErrorOrigin, VerifyIssue, VerifyResult};

        let rule = &state.ruleset.rules[0];
        let result = VerifyResult::failure(vec![VerifyIssue {
            origin: Some(ErrorOrigin::UserRule {
                id: rule.id,
                label: rule.label.clone(),
            }),
            message: "Service out of range".into(),
            source_line: None,
            caret: None,
        }]);
        state.verify_errors = Some(crate::app::verify_errors::VerifyErrorsPanel::new(
            &result,
            &state.ruleset,
        ));
        state.show_verify_errors = true;
    }

    fn verify_errors_cleared(state: &State) -> bool {
        state.verify_errors.is_none() && !state.show_verify_errors
    }

    /// The panel's "Edit Rule" buttons name rules of the active profile, so
    /// every change of profile drops it.
    #[test]
    fn test_profile_changes_clear_verify_errors() {
        // Switch
        let mut state = dirty_state();
        show_verify_errors(&mut state);
        switch_done(&mut state, "other", Ok(FirewallRuleset::default()));
        assert!(verify_errors_cleared(&state));

        // Create (from the current rules too: it is another profile)
        let mut state = dirty_state();
        show_verify_errors(&mut state);
        let rules = state.ruleset.clone();
        let _ = handle_profile_created(
            &mut state,
            "copy".into(),
            rules,
            Ok(vec!["copy".into(), "test".into()]),
        );
        assert!(verify_errors_cleared(&state));

        // A failed create changes nothing
        let mut state = dirty_state();
        show_verify_errors(&mut state);
        let _ = handle_profile_created(
            &mut state,
            "dup".into(),
            FirewallRuleset::default(),
            Err("A profile named 'dup' already exists".into()),
        );
        assert!(state.show_verify_errors);

        // Start fresh
        let mut state = dirty_state();
        show_verify_errors(&mut state);
        state.unreadable_profile = Some(UnreadableProfile {
            name: "test".into(),
            reason: "damaged".into(),
            backup: None,
        });
        let _ = handle_start_fresh_profile(&mut state);
        assert!(verify_errors_cleared(&state));

        // Rename: only a successful rename of the active profile
        let mut state = dirty_state();
        show_verify_errors(&mut state);
        let _ = handle_profile_renamed(
            &mut state,
            "test".into(),
            "renamed".into(),
            Err("A profile named 'renamed' already exists".into()),
        );
        let _ = handle_profile_renamed(
            &mut state,
            "other".into(),
            "other2".into(),
            Ok(vec!["other2".into(), "test".into()]),
        );
        assert!(state.show_verify_errors, "another profile was renamed");
        let _ = handle_profile_renamed(
            &mut state,
            "test".into(),
            "renamed".into(),
            Ok(vec!["other2".into(), "renamed".into()]),
        );
        assert!(verify_errors_cleared(&state));
    }

    #[test]
    fn test_handle_open_profile_manager() {
        let mut state = create_test_state();
        handle_open_profile_manager(&mut state);
        assert!(state.profile_manager.is_some());
    }

    #[test]
    fn test_handle_close_profile_manager() {
        let mut state = create_test_state();
        handle_open_profile_manager(&mut state);
        handle_close_profile_manager(&mut state);
        assert!(state.profile_manager.is_none());
    }

    #[test]
    fn test_autosave_starts_and_marks_in_flight() {
        let mut state = dirty_state();
        let _ = run_profile_save_if_due(&mut state, Instant::now());
        assert!(state.profile_save_in_flight);
        assert!(state.profile_dirty, "dirty until the save result arrives");
    }

    #[test]
    fn test_autosave_timer_rearms_when_pause_ends() {
        use crate::app::TimerKind;
        let mut state = dirty_state();
        state.pending_profile_switch = Some("other".into());
        let _ = state.update(Message::Noop);
        assert!(
            !state.timers.is_armed(TimerKind::ProfileSave),
            "no timer while paused"
        );
        let _ = state.update(Message::CancelProfileSwitch);
        assert!(state.timers.is_armed(TimerKind::ProfileSave), "resumes");
        // The edit is older than the debounce: the fired timer saves at once
        let _ = state.update(Message::TimerFired(TimerKind::ProfileSave, 1));
        assert!(state.profile_save_in_flight);
        assert!(!state.timers.is_armed(TimerKind::ProfileSave));
    }

    #[test]
    fn test_autosave_waits_for_debounce() {
        let mut state = create_test_state();
        state.ruleset.rules.push(create_test_rule("New", Some(80)));
        state.mark_profile_dirty();
        let edited = state.last_profile_change.unwrap();
        let _ = run_profile_save_if_due(&mut state, edited + Duration::from_millis(999));
        assert!(!state.profile_save_in_flight, "too early");
        let _ = run_profile_save_if_due(&mut state, edited + AUTOSAVE_DEBOUNCE);
        assert!(state.profile_save_in_flight);
    }

    #[test]
    fn test_autosave_paused_while_switch_dialog_open() {
        let mut state = dirty_state();
        state.pending_profile_switch = Some("other".into());
        let _ = run_profile_save_if_due(&mut state, Instant::now());
        assert!(
            !state.profile_save_in_flight,
            "Discard must be able to discard"
        );
    }

    #[test]
    fn test_autosave_paused_while_read_only() {
        let mut state = dirty_state();
        state.unreadable_profile = Some(UnreadableProfile {
            name: "test".into(),
            reason: "damaged".into(),
            backup: None,
        });
        let _ = run_profile_save_if_due(&mut state, Instant::now());
        assert!(!state.profile_save_in_flight);
    }

    #[test]
    fn test_discard_clears_dirty_and_switches() {
        let mut state = dirty_state();
        state.pending_profile_switch = Some("other".into());
        let request = state.switch_request;
        let _ = handle_discard_profile_switch(&mut state);
        assert!(!state.profile_dirty);
        assert!(state.pending_profile_switch.is_none());
        assert_eq!(state.switch_request, request + 1);
    }

    #[test]
    fn test_save_success_clears_dirty_only_if_unchanged() {
        let mut state = dirty_state();
        let _ = run_profile_save_if_due(&mut state, Instant::now());
        let outcome = saved(&state, None, Ok(()));
        // Another edit lands while the save is running
        state
            .ruleset
            .rules
            .push(create_test_rule("Later", Some(81)));
        state.mark_profile_dirty();
        let _ = handle_profile_saved(&mut state, outcome);
        assert!(!state.profile_save_in_flight);
        assert!(state.profile_dirty, "newer edit is not on disk yet");

        let outcome = saved(&state, None, Ok(()));
        let _ = handle_profile_saved(&mut state, outcome);
        assert!(!state.profile_dirty);
        assert!(!state.is_profile_dirty());
    }

    #[test]
    fn test_save_failure_keeps_dirty_and_shows_banner_once() {
        let mut state = dirty_state();
        let outcome = saved(&state, None, Err("Disk full".into()));
        let _ = handle_profile_saved(&mut state, outcome.clone());
        assert!(state.profile_dirty);
        assert!(state.profile_save_error.is_some());
        assert_eq!(state.banners.len(), 1);
        assert_eq!(state.banners[0].severity, BannerSeverity::Error);
        // Same error again: no second banner
        let _ = handle_profile_saved(&mut state, outcome);
        assert_eq!(state.banners.len(), 1);
        // Recovery clears the error
        let outcome = saved(&state, None, Ok(()));
        let _ = handle_profile_saved(&mut state, outcome);
        assert!(state.profile_save_error.is_none());
        assert!(!state.profile_dirty);
    }

    #[test]
    fn test_save_then_switch_aborts_on_failure() {
        let mut state = dirty_state();
        state.pending_profile_switch = Some("other".into());
        let _ = handle_confirm_profile_switch(&mut state);
        assert!(state.profile_save_in_flight);
        let request = state.switch_request;
        let outcome = saved(&state, Some("other"), Err("Permission denied".into()));
        let _ = handle_profile_saved(&mut state, outcome);
        assert_eq!(state.switch_request, request, "no switch after failed save");
        assert_eq!(state.active_profile_name, "test");
        assert!(state.profile_dirty);
        assert!(state.banners[0].message.contains("switch was cancelled"));

        let outcome = saved(&state, Some("other"), Ok(()));
        let _ = handle_profile_saved(&mut state, outcome);
        assert_eq!(
            state.switch_request,
            request + 1,
            "switch after successful save"
        );
    }

    #[test]
    fn test_stale_save_result_is_ignored() {
        let mut state = dirty_state();
        let outcome = saved(&state, None, Ok(()));
        state.profile_generation += 1; // profile replaced meanwhile
        let _ = handle_profile_saved(&mut state, outcome);
        assert!(state.profile_dirty);
    }

    #[test]
    fn test_stale_switch_result_is_ignored() {
        let mut state = create_test_state();
        let _ = perform_profile_switch(&mut state, "a".into());
        let first = state.switch_request;
        let _ = perform_profile_switch(&mut state, "b".into());
        let _ = handle_profile_switched(
            &mut state,
            first,
            "a".into(),
            Ok(FirewallRuleset::default()),
        );
        assert_eq!(state.active_profile_name, "test");
        let latest = state.switch_request;
        let _ = handle_profile_switched(
            &mut state,
            latest,
            "b".into(),
            Ok(FirewallRuleset::default()),
        );
        assert_eq!(state.active_profile_name, "b");
    }

    #[test]
    fn test_switch_resets_editing_state() {
        let mut state = dirty_state();
        state.command_history.execute(
            Box::new(crate::command::AddRuleCommand {
                rule: create_test_rule("Undoable", Some(1)),
            }),
            &mut state.ruleset,
        );
        state.rule_form = Some(crate::app::RuleForm::default());
        state.deleting_id = Some(uuid::Uuid::new_v4());
        switch_done(&mut state, "other", Ok(FirewallRuleset::default()));
        assert!(!state.command_history.can_undo());
        assert!(state.rule_form.is_none());
        assert!(state.deleting_id.is_none());
        assert!(!state.profile_dirty);
    }

    #[test]
    fn test_switch_to_unreadable_profile_is_read_only() {
        let mut state = create_test_state();
        let issue = UnreadableProfile {
            name: "broken".into(),
            reason: "Profile 'broken' is damaged".into(),
            backup: Some("/x/broken.json.corrupt-1".into()),
        };
        switch_done(&mut state, "broken", Err(issue));
        assert!(state.unreadable_profile.is_some());
        assert_eq!(state.ruleset.rules.len(), 0);
        assert!(state.banners[0].message.contains("broken.json.corrupt-1"));

        // Edits are refused by update()
        let _ = state.update(Message::AddRuleClicked);
        assert!(state.rule_form.is_none());

        // Start fresh: editable again and the empty profile gets saved
        let _ = handle_start_fresh_profile(&mut state);
        assert!(state.unreadable_profile.is_none());
        assert!(state.profile_dirty);
        let _ = state.update(Message::AddRuleClicked);
        assert!(state.rule_form.is_some());
    }

    #[test]
    fn test_create_empty_profile_resets_history() {
        let mut state = dirty_state();
        state.command_history.execute(
            Box::new(crate::command::AddRuleCommand {
                rule: create_test_rule("Old", Some(2)),
            }),
            &mut state.ruleset,
        );
        let _ = handle_profile_created(
            &mut state,
            "fresh".into(),
            FirewallRuleset::default(),
            Ok(vec!["fresh".into(), "test".into()]),
        );
        assert_eq!(state.active_profile_name, "fresh");
        assert_eq!(state.ruleset.rules.len(), 0);
        assert!(
            !state.command_history.can_undo(),
            "undo must not leak old rules"
        );
        assert!(!state.profile_dirty);
    }

    #[test]
    fn test_create_failure_keeps_active_profile() {
        let mut state = create_test_state();
        let _ = handle_profile_created(
            &mut state,
            "dup".into(),
            FirewallRuleset::default(),
            Err("A profile named 'dup' already exists".into()),
        );
        assert_eq!(state.active_profile_name, "test");
        assert_eq!(state.banners.len(), 1);
    }

    #[test]
    fn test_profile_name_error() {
        let existing = vec!["default".to_string(), "Work".to_string()];
        assert!(profile_name_error(&existing, "work", None).is_some());
        assert!(profile_name_error(&existing, "DEFAULT", None).is_some());
        assert!(profile_name_error(&existing, "bad name", None).is_some());
        assert!(profile_name_error(&existing, "", None).is_some());
        assert!(profile_name_error(&existing, "home", None).is_none());
        assert!(profile_name_error(&existing, "work", Some("Work")).is_none());
    }

    #[test]
    fn test_save_as_existing_name_refused() {
        let mut state = create_test_state();
        handle_open_profile_manager(&mut state);
        let _ = handle_save_profile_as(&mut state, "TEST".into());
        assert_eq!(state.active_profile_name, "test");
        assert!(state.banners[0].message.contains("already exists"));
    }

    #[test]
    fn test_rename_active_changes_name_only_on_success() {
        let mut state = create_test_state();
        handle_open_profile_manager(&mut state);
        let _ = handle_rename_profile_requested(&mut state, "test".into());
        handle_profile_new_name_changed(&mut state, "renamed".into());
        let _ = handle_confirm_rename_profile(&mut state);
        assert_eq!(state.active_profile_name, "test");
        assert!(state.profile_rename_in_flight);

        let _ = handle_profile_renamed(
            &mut state,
            "test".into(),
            "renamed".into(),
            Err("A profile named 'renamed' already exists".into()),
        );
        assert_eq!(state.active_profile_name, "test");
        assert!(!state.profile_rename_in_flight);

        let _ = handle_profile_renamed(
            &mut state,
            "test".into(),
            "renamed".into(),
            Ok(vec!["renamed".into()]),
        );
        assert_eq!(state.active_profile_name, "renamed");
    }

    #[test]
    fn test_rename_to_existing_name_refused_in_handler() {
        let mut state = create_test_state();
        state.available_profiles = vec!["test".into(), "beta".into()];
        handle_open_profile_manager(&mut state);
        let _ = handle_rename_profile_requested(&mut state, "test".into());
        handle_profile_new_name_changed(&mut state, "Beta".into());
        assert!(
            state
                .profile_manager
                .as_ref()
                .unwrap()
                .rename_error
                .is_some()
        );
        let _ = handle_confirm_rename_profile(&mut state);
        assert!(!state.profile_rename_in_flight);
        assert!(
            state
                .profile_manager
                .as_ref()
                .unwrap()
                .renaming_name
                .is_some()
        );
    }

    fn unreadable(backup: Option<&str>) -> UnreadableProfile {
        UnreadableProfile {
            name: "test".into(),
            reason: "Profile 'test' is damaged".into(),
            backup: backup.map(Into::into),
        }
    }

    /// H2: "Start fresh" overwrites the profile, so it asks first.
    #[test]
    fn test_start_fresh_asks_first() {
        let mut state = create_test_state();
        state.unreadable_profile = Some(unreadable(None));
        let _ = state.update(Message::StartFreshProfile);
        assert!(state.confirm_start_fresh, "confirmation shown");
        assert!(state.unreadable_profile.is_some(), "nothing replaced yet");
        assert!(!state.profile_dirty);

        let _ = state.update(Message::CancelStartFresh);
        assert!(!state.confirm_start_fresh);
        assert!(state.unreadable_profile.is_some());

        let _ = state.update(Message::StartFreshProfile);
        let task = handle_start_fresh_profile(&mut state);
        assert!(task.units() > 0, "audit-logged");
        assert!(!state.confirm_start_fresh);
        assert!(state.unreadable_profile.is_none());
        assert!(state.profile_dirty, "the empty profile gets saved");
        assert!(
            state
                .banners
                .back()
                .unwrap()
                .message
                .contains("Started fresh")
        );
    }

    #[test]
    fn test_start_fresh_request_needs_an_unreadable_profile() {
        let mut state = create_test_state();
        handle_start_fresh_requested(&mut state);
        assert!(!state.confirm_start_fresh);
    }

    /// M5: clicking the active profile must not reload it (that would wipe
    /// undo and drop unsaved edits); only a read-only one is retried.
    #[test]
    fn test_clicking_the_active_profile_is_a_no_op() {
        let mut state = dirty_state();
        state.command_history.execute(
            Box::new(crate::command::AddRuleCommand {
                rule: create_test_rule("Undoable", Some(1)),
            }),
            &mut state.ruleset,
        );
        state.mark_profile_dirty();
        let request = state.switch_request;
        let _ = state.update(Message::ProfileSelected("test".into()));
        assert_eq!(state.switch_request, request, "no reload");
        assert!(state.pending_profile_switch.is_none(), "no dialog");
        assert!(state.command_history.can_undo());

        let mut state = create_test_state();
        state.unreadable_profile = Some(unreadable(None));
        let _ = handle_profile_selected(&mut state, "test".into());
        assert_eq!(state.switch_request, 1, "read-only: retried");
    }

    /// Edits made while "Save & Switch" is saving are saved too before the
    /// switch, instead of being dropped by it.
    #[test]
    fn test_save_and_switch_saves_edits_made_meanwhile() {
        let mut state = dirty_state();
        state.pending_profile_switch = Some("other".into());
        let _ = handle_confirm_profile_switch(&mut state);
        let outcome = saved(&state, Some("other"), Ok(()));
        state
            .ruleset
            .rules
            .push(create_test_rule("Meanwhile", Some(81)));
        state.mark_profile_dirty();
        let request = state.switch_request;
        let _ = handle_profile_saved(&mut state, outcome);
        assert_eq!(state.switch_request, request, "not switched yet");
        assert!(state.profile_save_in_flight, "saving again");

        let outcome = saved(&state, Some("other"), Ok(()));
        let _ = handle_profile_saved(&mut state, outcome);
        assert_eq!(state.switch_request, request + 1, "switched");
    }

    #[test]
    fn test_save_and_switch_cancelled_by_a_profile_change_says_so() {
        let mut state = dirty_state();
        let outcome = saved(&state, Some("other"), Ok(()));
        state.profile_generation += 1;
        let request = state.switch_request;
        let _ = handle_profile_saved(&mut state, outcome);
        assert_eq!(state.switch_request, request);
        assert!(
            state
                .banners
                .back()
                .unwrap()
                .message
                .contains("'other' was cancelled")
        );
    }

    #[test]
    fn test_save_and_switch_waits_for_a_rename() {
        let mut state = dirty_state();
        state.pending_profile_switch = Some("other".into());
        state.profile_rename_in_flight = true;
        let _ = handle_confirm_profile_switch(&mut state);
        assert!(!state.profile_save_in_flight, "no save under the old name");
        assert!(state.pending_profile_switch.is_some(), "dialog stays");
        assert!(state.banners.back().unwrap().message.contains("renamed"));
    }

    /// Load/create results that arrive while an apply runs are reported or
    /// applied, never dropped silently.
    #[test]
    fn test_profile_results_during_an_apply_are_not_dropped() {
        let mut state = create_test_state();
        let _ = perform_profile_switch(&mut state, "other".into());
        let request = state.switch_request;
        state.status = crate::app::AppStatus::Verifying;
        let _ = state.update(Message::ProfileSwitched(
            request,
            "other".into(),
            Ok(FirewallRuleset::default()),
        ));
        assert_eq!(state.active_profile_name, "test");
        assert!(state.banners.back().unwrap().message.contains("cancelled"));

        let _ = state.update(Message::ProfileCreated(
            "fresh".into(),
            Box::default(),
            Ok(vec!["fresh".into(), "test".into()]),
        ));
        assert_eq!(state.active_profile_name, "test", "not switched");
        assert!(
            state.available_profiles.contains(&"fresh".to_string()),
            "listed"
        );
        assert_eq!(state.profile_count_display, "2 profiles");
    }

    #[test]
    fn test_one_profile_name_field_at_a_time() {
        let mut state = create_test_state();
        handle_open_profile_manager(&mut state);
        let _ = handle_create_empty_profile(&mut state);
        let _ = handle_rename_profile_requested(&mut state, "test".into());
        let mgr = state.profile_manager.as_ref().unwrap();
        assert!(mgr.renaming_name.is_some() && !mgr.creating_new);
        let _ = handle_start_creating_new_profile(&mut state);
        let mgr = state.profile_manager.as_ref().unwrap();
        assert!(mgr.renaming_name.is_none() && mgr.creating_new);
    }
}
