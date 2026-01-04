//! Profile management and switching
//!
//! Handles all message variants related to firewall profile management:
//! - Profile creation (from current ruleset or empty)
//! - Profile switching with dirty-state detection
//! - Profile deletion and renaming
//! - Profile manager UI state
//! - Profile list refreshing

use crate::app::{BannerSeverity, FirewallRuleset, Message, State};
use crate::audit;
use iced::Task;

/// Handles profile selection (with dirty check)
pub(crate) fn handle_profile_selected(state: &mut State, name: String) -> Task<Message> {
    if state.is_profile_dirty() {
        state.pending_profile_switch = Some(name);
        return Task::none();
    }
    perform_profile_switch(state, name)
}

/// Performs the actual profile switch
pub(crate) fn perform_profile_switch(state: &mut State, name: String) -> Task<Message> {
    let active_profile = name.clone();
    state.pending_profile_switch = None;

    Task::perform(
        async move { crate::core::profiles::load_profile(&active_profile).await },
        move |result| match result {
            Ok(ruleset) => Message::ProfileSwitched(name, ruleset),
            Err(e) => {
                eprintln!("Failed to load profile: {e}");
                Message::Noop
            }
        },
    )
}

/// Handles profile switch completion
pub(crate) fn handle_profile_switched(
    state: &mut State,
    name: String,
    ruleset: FirewallRuleset,
) -> Task<Message> {
    let from_profile = state.active_profile_name.clone();
    state.ruleset = ruleset.clone();
    state.cached_disk_profile = Some(ruleset);
    state.active_profile_name = name.clone();
    state.command_history = crate::command::CommandHistory::default();
    state.update_cached_text();
    state.mark_config_dirty();

    let enable_event_log = state.enable_event_log;
    let to_profile = name;
    Task::perform(
        async move {
            audit::log_profile_switched(enable_event_log, &from_profile, &to_profile).await;
        },
        |_| Message::AuditLogWritten,
    )
}

/// Handles saving current ruleset as a new profile or saving empty profile
pub(crate) fn handle_save_profile_as(state: &mut State, name: String) -> Task<Message> {
    let creating_empty = state
        .profile_manager
        .as_ref()
        .map(|mgr| mgr.creating_empty)
        .unwrap_or(false);

    let ruleset = if creating_empty {
        FirewallRuleset::default()
    } else {
        state.ruleset.clone()
    };

    let name_clone = name.clone();
    let name_for_log = name.clone();
    let enable_event_log = state.enable_event_log;

    // Update current ruleset if creating empty profile
    if creating_empty {
        state.ruleset = ruleset.clone();
        state.update_cached_text();
    }

    // Update cached disk profile to prevent false dirty detection
    state.cached_disk_profile = Some(ruleset.clone());

    state.active_profile_name = name;
    state.mark_config_dirty();
    if let Some(mgr) = &mut state.profile_manager {
        mgr.creating_new = false;
        mgr.creating_empty = false;
        mgr.new_name_input.clear();
    }

    Task::perform(
        async move {
            crate::core::profiles::save_profile(&name_clone, &ruleset).await?;
            crate::core::profiles::list_profiles().await
        },
        |result| match result {
            Ok(profiles) => Message::ProfileListUpdated(profiles),
            Err(e) => {
                eprintln!("Failed to save/list profiles: {e}");
                Message::Noop
            }
        },
    )
    .chain(Task::future(async move {
        audit::log_profile_created(enable_event_log, &name_for_log).await;
        Message::AuditLogWritten
    }))
}

/// Handles profile list update from async operation
pub(crate) fn handle_profile_list_updated(state: &mut State, profiles: Vec<String>) {
    state.available_profiles = profiles;
}

/// Handles opening profile creation flow
pub(crate) fn handle_start_creating_new_profile(state: &mut State) {
    if let Some(mgr) = &mut state.profile_manager {
        mgr.creating_new = true;
        mgr.creating_empty = false;
        mgr.new_name_input = String::new();
    }
}

/// Handles creating empty profile flow
pub(crate) fn handle_create_empty_profile(state: &mut State) {
    if let Some(mgr) = &mut state.profile_manager {
        mgr.creating_new = true;
        mgr.creating_empty = true;
        mgr.new_name_input = String::new();
    }
}

/// Handles new profile name input change
pub(crate) fn handle_new_profile_name_changed(state: &mut State, name: String) {
    if let Some(mgr) = &mut state.profile_manager {
        mgr.new_name_input = name;
    }
}

/// Handles canceling profile creation
pub(crate) fn handle_cancel_creating_new_profile(state: &mut State) {
    if let Some(mgr) = &mut state.profile_manager {
        mgr.creating_new = false;
        mgr.creating_empty = false;
        mgr.new_name_input.clear();
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

/// Handles confirming profile deletion
pub(crate) fn handle_confirm_delete_profile(state: &mut State) -> Task<Message> {
    if let Some(mgr) = &mut state.profile_manager
        && let Some(name) = mgr.deleting_name.take()
    {
        // Validation: ensure at least one profile remains
        if state.available_profiles.len() <= 1 {
            state.push_banner("Cannot delete last profile", BannerSeverity::Error, 6);
            return Task::none();
        }

        // Validation: cannot delete active profile
        if name == state.active_profile_name {
            state.push_banner(
                "Cannot delete active profile - switch to another profile first",
                BannerSeverity::Error,
                8,
            );
            return Task::none();
        }

        let enable_event_log = state.enable_event_log;
        let deleted_name = name.clone();
        return Task::perform(
            async move {
                crate::core::profiles::delete_profile(&name).await?;
                crate::core::profiles::list_profiles().await
            },
            move |result| match result {
                Ok(profiles) => Message::ProfileDeleted(Ok(profiles)),
                Err(e) => Message::ProfileDeleted(Err(format!("Failed to delete profile: {e}"))),
            },
        )
        .chain(Task::future(async move {
            audit::log_profile_deleted(enable_event_log, &deleted_name).await;
            Message::AuditLogWritten
        }));
    }
    Task::none()
}

/// Handles profile deletion result
pub(crate) fn handle_profile_deleted(
    state: &mut State,
    result: Result<Vec<String>, String>,
) -> Task<Message> {
    match result {
        Ok(profiles) => {
            let old_active = state.active_profile_name.clone();
            state.available_profiles = profiles.clone();
            // If we deleted the active profile, switch to first available
            if !profiles.iter().any(|p| p == &old_active) {
                let next = profiles
                    .first()
                    .cloned()
                    .unwrap_or_else(|| crate::core::profiles::DEFAULT_PROFILE_NAME.to_string());
                return perform_profile_switch(state, next);
            }
            Task::none()
        }
        Err(e) => {
            let msg = if e.len() > 55 {
                format!("Failed to delete profile: {}...", &e[..46])
            } else {
                format!("Failed to delete profile: {}", e)
            };
            state.push_banner(&msg, BannerSeverity::Error, 8);
            Task::none()
        }
    }
}

/// Handles canceling profile deletion
pub(crate) fn handle_cancel_delete_profile(state: &mut State) {
    if let Some(mgr) = &mut state.profile_manager {
        mgr.deleting_name = None;
    }
}

/// Handles requesting profile rename
pub(crate) fn handle_rename_profile_requested(state: &mut State, name: String) {
    if let Some(mgr) = &mut state.profile_manager {
        mgr.renaming_name = Some((name.clone(), name));
    }
}

/// Handles profile new name input change
pub(crate) fn handle_profile_new_name_changed(state: &mut State, new_name: String) {
    if let Some(mgr) = &mut state.profile_manager
        && let Some((old, _)) = &mgr.renaming_name
    {
        mgr.renaming_name = Some((old.clone(), new_name));
    }
}

/// Handles confirming profile rename
pub(crate) fn handle_confirm_rename_profile(state: &mut State) -> Task<Message> {
    if let Some(mgr) = &mut state.profile_manager
        && let Some((old, new)) = mgr.renaming_name.take()
    {
        let was_active = state.active_profile_name == old;
        if was_active {
            state.active_profile_name = new.clone();
            state.mark_config_dirty();
        }

        let enable_event_log = state.enable_event_log;
        let old_name = old.clone();
        let new_name = new.clone();

        return Task::perform(
            async move {
                crate::core::profiles::rename_profile(&old, &new).await?;
                crate::core::profiles::list_profiles().await
            },
            move |result| match result {
                Ok(profiles) => Message::ProfileRenamed(Ok(profiles)),
                Err(e) => Message::ProfileRenamed(Err(format!("Rename failed: {e}"))),
            },
        )
        .chain(Task::future(async move {
            audit::log_profile_renamed(enable_event_log, &old_name, &new_name).await;
            Message::AuditLogWritten
        }));
    }
    Task::none()
}

/// Handles profile rename result
pub(crate) fn handle_profile_renamed(state: &mut State, result: Result<Vec<String>, String>) {
    match result {
        Ok(profiles) => {
            state.available_profiles = profiles;
        }
        Err(e) => {
            let msg = if e.len() > 55 {
                format!("Failed to rename profile: {}...", &e[..46])
            } else {
                format!("Failed to rename profile: {}", e)
            };
            state.push_banner(&msg, BannerSeverity::Error, 8);
        }
    }
}

/// Handles canceling profile rename
pub(crate) fn handle_cancel_rename_profile(state: &mut State) {
    if let Some(mgr) = &mut state.profile_manager {
        mgr.renaming_name = None;
    }
}

/// Handles confirming profile switch (saves current profile first)
pub(crate) fn handle_confirm_profile_switch(state: &mut State) -> Task<Message> {
    if let Some(name) = state.pending_profile_switch.take() {
        let profile_name = state.active_profile_name.clone();
        let ruleset = state.ruleset.clone();

        // Update cached disk profile before saving to avoid false dirty detection
        state.cached_disk_profile = Some(ruleset.clone());

        return Task::perform(
            async move { crate::core::profiles::save_profile(&profile_name, &ruleset).await },
            move |_result| Message::ProfileSwitchAfterSave(name.clone()),
        );
    }
    Task::none()
}

/// Handles discarding changes and switching profile
pub(crate) fn handle_discard_profile_switch(state: &mut State) -> Task<Message> {
    if let Some(name) = state.pending_profile_switch.take() {
        return perform_profile_switch(state, name);
    }
    Task::none()
}

/// Handles canceling profile switch dialog
pub(crate) fn handle_cancel_profile_switch(state: &mut State) {
    state.pending_profile_switch = None;
}

/// Handles profile switch after save completes
pub(crate) fn handle_profile_switch_after_save(state: &mut State, name: String) -> Task<Message> {
    perform_profile_switch(state, name)
}

/// Handles periodic profile save check (debounced)
pub(crate) fn handle_check_profile_save(state: &mut State) -> Task<Message> {
    if !state.is_profile_dirty() {
        return Task::none();
    }

    let profile_name = state.active_profile_name.clone();
    let ruleset = state.ruleset.clone();

    // Update cached disk profile before saving to avoid false dirty detection
    state.cached_disk_profile = Some(ruleset.clone());

    Task::perform(
        async move { crate::core::profiles::save_profile(&profile_name, &ruleset).await },
        |result| {
            if let Err(e) = result {
                eprintln!("Auto-save profile failed: {e}");
            }
            Message::DiskProfileLoaded(None)
        },
    )
}

/// Handles disk profile loaded for cache refresh
pub(crate) fn handle_disk_profile_loaded(state: &mut State, profile: Option<FirewallRuleset>) {
    state.cached_disk_profile = profile;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::handlers::test_utils::create_test_state;

    #[test]
    fn test_handle_open_profile_manager() {
        let mut state = create_test_state();
        handle_open_profile_manager(&mut state);
        assert!(state.profile_manager.is_some());
    }

    #[test]
    fn test_handle_close_profile_manager() {
        let mut state = create_test_state();
        state.profile_manager = Some(crate::app::ProfileManagerState {
            renaming_name: None,
            deleting_name: None,
            creating_new: false,
            creating_empty: false,
            new_name_input: String::new(),
        });
        handle_close_profile_manager(&mut state);
        assert!(state.profile_manager.is_none());
    }
}
