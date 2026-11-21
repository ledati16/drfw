//! Application settings and configuration
//!
//! Handles configuration changes:
//! - Display settings (diff view, zebra striping)
//! - Security settings (auto-revert, strict ICMP, RPF, forwarding, local
//!   discovery, Server Mode with its essential rules)
//! - Logging settings (event log, dropped packet logging)
//! - Theme and font selection
//! - Debounced auto-save

use std::time::{Duration, Instant};

use iced::Task;

use crate::app::{Message, PendingWarning, ServerEssentials, State};
use crate::core::firewall::EgressProfile;

/// Handles toggling diff view
pub(crate) fn handle_toggle_diff(state: &mut State, enabled: bool) -> Task<Message> {
    state.show_diff = enabled;
    state.mark_config_dirty();
    super::log_setting_change(
        state,
        if enabled {
            "Diff view enabled"
        } else {
            "Diff view disabled"
        },
    )
}

/// Handles toggling zebra striping
pub(crate) fn handle_toggle_zebra_striping(state: &mut State, enabled: bool) -> Task<Message> {
    state.show_zebra_striping = enabled;
    state.mark_config_dirty();
    super::log_setting_change(
        state,
        if enabled {
            "Zebra striping enabled"
        } else {
            "Zebra striping disabled"
        },
    )
}

/// Handles toggling auto-revert feature. A choice in Settings also answers
/// the one-time "Auto-revert is off" notice.
pub(crate) fn handle_toggle_auto_revert(state: &mut State, enabled: bool) -> Task<Message> {
    state.auto_revert_enabled = enabled;
    state.auto_revert_notice_shown = true;
    state.mark_config_dirty();
    super::log_setting_change(
        state,
        if enabled {
            "Auto-revert enabled"
        } else {
            "Auto-revert disabled"
        },
    )
}

/// Handles the "Auto-revert is off" notice: "Turn on" enables auto-revert,
/// "Keep off" leaves it; either way the notice is not shown again (saved
/// with the debounced config save).
pub(crate) fn handle_auto_revert_notice_answered(
    state: &mut State,
    turn_on: bool,
) -> Task<Message> {
    if !state.auto_revert_notice_visible() {
        return Task::none();
    }
    if turn_on {
        return handle_toggle_auto_revert(state, true);
    }
    state.auto_revert_notice_shown = true;
    state.mark_config_dirty();
    super::log_setting_change(state, "Auto-revert kept off (notice answered)")
}

/// Handles auto-revert timeout change
pub(crate) fn handle_auto_revert_timeout_changed(state: &mut State, timeout: u64) {
    state.auto_revert_timeout_secs = timeout.clamp(5, 120);
    state.refresh_settings_display();
    state.mark_config_dirty();
    // Schedule debounced logging - log after 2s of no changes
    let desc = format!("Auto-revert timeout set to {timeout}s");
    state.schedule_slider_log(desc);
}

/// Handles toggling event log
pub(crate) fn handle_toggle_event_log(state: &mut State, enabled: bool) -> Task<Message> {
    // Log settings change BEFORE changing the value
    // When disabling, we need to log with the OLD value (true) so it actually logs
    let old_value = state.enable_event_log;
    state.enable_event_log = enabled;
    state.mark_config_dirty();
    let desc = if enabled {
        "Event logging enabled"
    } else {
        "Event logging disabled"
    };
    Task::perform(
        async move {
            // Use old_value when disabling (true), new value when enabling (true)
            // This ensures "disabled" message gets logged before turning off
            crate::audit::log_settings_saved(old_value || enabled, desc).await;
        },
        |()| Message::AuditLogWritten,
    )
}

/// Handles toggling reduced syntax colors (accessibility feature)
pub(crate) fn handle_toggle_reduced_colors(state: &mut State, enabled: bool) -> Task<Message> {
    state.reduced_colors = enabled;
    // Reapply theme with or without reduced colors
    state.refresh_theme();
    state.mark_config_dirty();
    super::log_setting_change(
        state,
        if enabled {
            "Reduced syntax colors enabled"
        } else {
            "Reduced syntax colors disabled"
        },
    )
}

/// Handles strict ICMP toggle request (shows warning when enabling)
pub(crate) fn handle_toggle_strict_icmp_requested(
    state: &mut State,
    enabled: bool,
) -> Task<Message> {
    if enabled {
        state.pending_warning = Some(PendingWarning::EnableStrictIcmp);
        Task::none()
    } else {
        state.ruleset.advanced_security.strict_icmp = false;
        state.mark_profile_dirty();
        super::log_setting_change(state, "Strict ICMP filtering disabled")
    }
}

/// Handles confirming strict ICMP enable
pub(crate) fn handle_confirm_strict_icmp(state: &mut State) -> Task<Message> {
    state.pending_warning = None;
    state.ruleset.advanced_security.strict_icmp = true;
    state.mark_profile_dirty();
    super::log_setting_change(state, "Strict ICMP filtering enabled")
}

/// Handles ICMP rate limit change
pub(crate) fn handle_icmp_rate_limit_changed(state: &mut State, rate: u32) {
    state.ruleset.advanced_security.icmp_rate_limit = rate;
    state.mark_profile_dirty();
    // Schedule debounced logging - log after 2s of no changes
    let desc = format!("ICMP rate limit set to {rate}/s");
    state.schedule_slider_log(desc);
}

/// Handles RPF toggle request (shows warning)
pub(crate) fn handle_toggle_rpf_requested(state: &mut State, enabled: bool) -> Task<Message> {
    if enabled {
        state.pending_warning = Some(PendingWarning::EnableRpf);
        Task::none()
    } else {
        state.ruleset.advanced_security.enable_rpf = false;
        state.mark_profile_dirty();
        super::log_setting_change(state, "RPF (reverse path filtering) disabled")
    }
}

/// Handles confirming RPF enable
pub(crate) fn handle_confirm_enable_rpf(state: &mut State) -> Task<Message> {
    state.pending_warning = None;
    state.ruleset.advanced_security.enable_rpf = true;
    state.mark_profile_dirty();
    super::log_setting_change(state, "RPF (reverse path filtering) enabled")
}

/// Handles the "Local network discovery" toggle. Desktop mode only (the
/// generator ignores it in Server Mode, where the toggle is disabled). A
/// choice here also answers the one-time notice.
pub(crate) fn handle_toggle_local_discovery(state: &mut State, enabled: bool) -> Task<Message> {
    if state.ruleset.advanced_security.egress_profile == EgressProfile::Server {
        return Task::none();
    }
    state.ruleset.advanced_security.local_discovery = enabled;
    state.mark_profile_dirty();
    if !state.local_discovery_notice_shown {
        state.local_discovery_notice_shown = true;
        state.mark_config_dirty();
    }
    super::log_setting_change(
        state,
        if enabled {
            "Local network discovery enabled"
        } else {
            "Local network discovery disabled"
        },
    )
}

/// Handles the local discovery notice: "Turn on local network discovery"
/// turns it on for the open profile, "Not now" leaves it; either way the
/// notice is not shown again (saved with the debounced config save).
pub(crate) fn handle_local_discovery_notice_answered(
    state: &mut State,
    turn_on: bool,
) -> Task<Message> {
    if !state.local_discovery_notice_visible() {
        return Task::none();
    }
    if turn_on {
        return handle_toggle_local_discovery(state, true);
    }
    state.local_discovery_notice_shown = true;
    state.mark_config_dirty();
    super::log_setting_change(state, "Local network discovery kept off (notice answered)")
}

/// Handles toggling forwarded-traffic blocking (forward chain policy)
///
/// No warning modal: the settings row explains that forwarded traffic then
/// needs Forwarded rules, and the change only takes effect on Apply.
pub(crate) fn handle_toggle_block_forwarding(state: &mut State, enabled: bool) -> Task<Message> {
    state.ruleset.advanced_security.block_forwarding = enabled;
    state.mark_profile_dirty();
    super::log_setting_change(
        state,
        if enabled {
            "Forwarded traffic blocking enabled"
        } else {
            "Forwarded traffic blocking disabled"
        },
    )
}

/// Handles canceling warning dialog
pub(crate) fn handle_cancel_warning(state: &mut State) {
    state.pending_warning = None;
}

/// Handles toggling dropped packet logging
pub(crate) fn handle_toggle_dropped_logging(state: &mut State, enabled: bool) -> Task<Message> {
    state.ruleset.advanced_security.log_dropped = enabled;
    state.mark_profile_dirty();
    super::log_setting_change(
        state,
        if enabled {
            "Dropped packet logging enabled"
        } else {
            "Dropped packet logging disabled"
        },
    )
}

/// Handles log rate change
pub(crate) fn handle_log_rate_changed(state: &mut State, rate: u32) {
    // Validate log rate (slider ensures 1-100 range, but check for warnings)
    match crate::validators::validate_log_rate(rate) {
        Ok(Some(warning)) => {
            // Valid but with warning - still accept it
            tracing::debug!("Log rate {rate}/min: {warning}");
        }
        Ok(None) => {
            // Valid with no warnings
        }
        Err(e) => {
            // Should not happen with slider, but handle it
            tracing::warn!("Invalid log rate {rate}: {e}");
            return;
        }
    }
    state.ruleset.advanced_security.log_rate_per_minute = rate;
    state.mark_profile_dirty();
    // Schedule debounced logging - log after 2s of no changes
    let desc = format!("Log rate limit set to {rate}/min");
    state.schedule_slider_log(desc);
}

/// Quiet period after the last slider (or log prefix) change before its
/// audit entry is written: one entry per adjustment, not per step.
const SLIDER_LOG_DEBOUNCE: Duration = Duration::from_secs(2);

/// When the pending slider audit entry is due, if there is one.
pub(crate) fn slider_log_deadline(state: &State) -> Option<Instant> {
    state
        .pending_slider_log
        .as_ref()
        .map(|(_, last_change)| *last_change + SLIDER_LOG_DEBOUNCE)
}

/// Writes the pending slider audit entry if its quiet period is over.
pub(crate) fn run_slider_log_if_due(state: &mut State, now: Instant) -> Task<Message> {
    if slider_log_deadline(state).is_none_or(|deadline| now < deadline) {
        return Task::none();
    }
    let Some((description, _)) = state.pending_slider_log.take() else {
        return Task::none();
    };
    super::log_setting_change(state, description)
}

/// Handles log prefix change
pub(crate) fn handle_log_prefix_changed(state: &mut State, prefix: &str) -> Task<Message> {
    // Validate and sanitize log prefix
    match crate::validators::validate_log_prefix(prefix) {
        Ok(sanitized) => {
            state
                .ruleset
                .advanced_security
                .log_prefix
                .clone_from(&sanitized);
            state.mark_profile_dirty();
            // Debounced like the sliders: one audit entry per edit, not per keystroke
            state.schedule_slider_log(format!("Log prefix changed to '{sanitized}'"));
            Task::none()
        }
        Err(e) => {
            // Invalid prefix - don't save, just log the error
            tracing::warn!("Invalid log prefix '{prefix}': {e}");
            Task::none()
        }
    }
}

/// Handles server mode toggle request (shows the warning, with the
/// essential Output rules it offers to add)
pub(crate) fn handle_server_mode_toggled(state: &mut State, enabled: bool) -> Task<Message> {
    if enabled {
        state.pending_warning = Some(PendingWarning::EnableServerMode(
            ServerEssentials::for_ruleset(&state.ruleset),
        ));
        Task::none()
    } else {
        state.ruleset.advanced_security.egress_profile =
            crate::core::firewall::EgressProfile::Desktop;
        state.mark_profile_dirty();
        super::log_setting_change(state, "Server mode disabled (desktop profile)")
    }
}

/// Ticks or unticks one essential rule in the Server Mode dialog.
pub(crate) fn handle_server_essential_toggled(state: &mut State, index: usize, ticked: bool) {
    if let Some(PendingWarning::EnableServerMode(essentials)) = &mut state.pending_warning
        && let Some(choice) = essentials.choices.get_mut(index)
    {
        choice.ticked = ticked;
    }
}

/// Handles confirming server mode: switches the mode and adds the ticked
/// essential rules as ordinary Output rules, in one undoable step (undo
/// removes the rules; the mode stays, like every setting).
pub(crate) fn handle_confirm_server_mode(state: &mut State) -> Task<Message> {
    let added = match state.pending_warning.take() {
        Some(PendingWarning::EnableServerMode(essentials)) => essentials.ticked_rules(),
        _ => Vec::new(),
    };
    state.ruleset.advanced_security.egress_profile = EgressProfile::Server;
    let room = crate::core::firewall::MAX_RULES.saturating_sub(state.ruleset.rules.len());
    let count = added.len();
    if count > 0 && count <= room {
        let command = crate::command::AddRulesCommand {
            rules: added,
            description: "Add rules: Server Mode essentials".to_string(),
        };
        state
            .command_history
            .execute(Box::new(command), &mut state.ruleset);
    } else if count > 0 {
        state.push_banner(
            "The essential rules were not added: the profile has too many rules.",
            crate::app::BannerSeverity::Error,
        );
    }
    state.mark_profile_dirty();
    let description = if count > 0 && count <= room {
        format!("Server mode enabled (server profile), {count} essential rules added")
    } else {
        "Server mode enabled (server profile)".to_string()
    };
    super::log_setting_change(state, description)
}

/// Quiet period after the last settings change before the config is written.
const CONFIG_SAVE_DEBOUNCE: Duration = Duration::from_millis(500);
/// Retry delay after a failed config save.
const CONFIG_SAVE_RETRY: Duration = Duration::from_secs(5);

/// When the pending config save is due: `None` while the config is clean or
/// a save is running (the next one starts after it, so an older snapshot can
/// never land last).
pub(crate) fn config_save_deadline(state: &State, now: Instant) -> Option<Instant> {
    if !state.config_dirty || state.config_save_in_flight {
        return None;
    }
    let debounce = if state.config_save_error.is_some() {
        CONFIG_SAVE_RETRY
    } else {
        CONFIG_SAVE_DEBOUNCE
    };
    Some(
        state
            .last_config_change
            .map_or(now, |last_change| last_change + debounce),
    )
}

/// Saves the config if it is dirty and its quiet period is over.
pub(crate) fn run_config_save_if_due(state: &mut State, now: Instant) -> Task<Message> {
    if config_save_deadline(state, now).is_none_or(|deadline| now < deadline) {
        return Task::none();
    }
    state.config_dirty = false;
    state.config_save_in_flight = true;
    state.save_config()
}

/// Handles the result of a config save. A failure keeps the config dirty so
/// it is retried (after [`CONFIG_SAVE_RETRY`]), with one banner per distinct
/// error; the first success after a failure says so.
pub(crate) fn handle_config_saved(state: &mut State, result: Result<(), String>) {
    use crate::app::BannerSeverity;

    state.config_save_in_flight = false;
    match result {
        Ok(()) => {
            if state.config_save_error.take().is_some() {
                state.push_banner("Settings saved", BannerSeverity::Success);
            }
        }
        Err(e) => {
            tracing::error!("Failed to save configuration: {e}");
            let message = format!("Could not save settings: {e}. Retrying.");
            if state.config_save_error.as_deref() != Some(message.as_str()) {
                state.push_banner(message.clone(), BannerSeverity::Error);
            }
            state.config_save_error = Some(message);
            state.config_dirty = true;
            state.last_config_change = Some(Instant::now());
        }
    }
}

/// Handles regular font changed
pub(crate) fn handle_regular_font_changed(
    state: &mut State,
    choice: &crate::fonts::RegularFontChoice,
) -> Task<Message> {
    state.regular_font_choice = choice.clone();
    state.font_regular = choice.to_font();
    // Closes like the monospace picker does
    state.font_picker = None;
    state.mark_config_dirty();
    super::log_setting_change(state, format!("UI font changed to {}", choice.name()))
}

/// Handles mono font changed
pub(crate) fn handle_mono_font_changed(
    state: &mut State,
    choice: &crate::fonts::MonoFontChoice,
) -> Task<Message> {
    state.mono_font_choice = choice.clone();
    state.font_mono = choice.to_font();
    state.font_picker = None;
    state.mark_config_dirty();
    super::log_setting_change(
        state,
        format!("Monospace font changed to {}", choice.name()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::handlers::test_utils::create_test_state;

    #[test]
    fn test_handle_toggle_diff() {
        let mut state = create_test_state();
        let _ = handle_toggle_diff(&mut state, true);
        assert!(state.show_diff);
        assert!(state.config_dirty);
    }

    #[test]
    fn test_handle_toggle_block_forwarding() {
        let mut state = create_test_state();
        let _ = handle_toggle_block_forwarding(&mut state, true);
        assert!(state.ruleset.advanced_security.block_forwarding);
        let _ = handle_toggle_block_forwarding(&mut state, false);
        assert!(!state.ruleset.advanced_security.block_forwarding);
    }

    #[test]
    fn test_log_prefix_change_is_debounced() {
        let mut state = create_test_state();
        let _ = handle_log_prefix_changed(&mut state, "MY-DROP: ");
        assert_eq!(state.ruleset.advanced_security.log_prefix, "MY-DROP: ");
        assert!(state.pending_slider_log.is_some());
    }

    #[test]
    fn test_slider_log_waits_for_quiet_period() {
        let mut state = create_test_state();
        handle_icmp_rate_limit_changed(&mut state, 5);
        let start = state.pending_slider_log.as_ref().unwrap().1;
        let _ = run_slider_log_if_due(&mut state, start + Duration::from_millis(1999));
        assert!(state.pending_slider_log.is_some(), "too early");
        let _ = run_slider_log_if_due(&mut state, start + SLIDER_LOG_DEBOUNCE);
        assert!(state.pending_slider_log.is_none(), "written once quiet");
    }

    #[test]
    fn test_config_save_debounce_and_timer_generations() {
        use crate::app::TimerKind;
        let mut state = create_test_state();
        // A settings change through update() arms exactly one timer
        let _ = state.update(Message::ToggleZebraStriping(false));
        assert!(state.config_dirty);
        assert!(state.timers.is_armed(TimerKind::ConfigSave));
        let generation = 1;
        // Another change while armed: no second timer, deadline moves
        let _ = state.update(Message::ToggleDiff(true));
        assert!(state.timers.is_armed(TimerKind::ConfigSave));

        // A stale timer (wrong generation) does nothing
        let _ = state.update(Message::TimerFired(TimerKind::ConfigSave, generation + 7));
        assert!(state.config_dirty);
        assert!(state.timers.is_armed(TimerKind::ConfigSave));

        // The armed timer fires before the (moved) deadline: nothing is
        // saved, and update()'s second step re-arms it for the remaining
        // time. Both steps run at a time just after the last change (not the
        // wall clock: a loaded machine could be past the deadline already).
        let early = state.last_config_change.expect("changed") + Duration::from_millis(100);
        let _ = crate::app::handlers::handle_timer_fired_at(
            &mut state,
            TimerKind::ConfigSave,
            generation,
            early,
        );
        assert!(state.config_dirty, "deadline not reached yet");
        assert!(!state.timers.is_armed(TimerKind::ConfigSave), "fired");
        let _ = state.arm_debounce_timers(early);
        assert!(state.timers.is_armed(TimerKind::ConfigSave), "re-armed");

        // Once the quiet period is over, the save starts and no timer remains
        let due = config_save_deadline(&state, Instant::now()).unwrap();
        let _ = run_config_save_if_due(&mut state, due);
        assert!(!state.config_dirty);
        // The re-armed timer (generation 2) then fires with nothing to do,
        // and nothing re-arms it
        let _ = state.update(Message::TimerFired(TimerKind::ConfigSave, generation + 1));
        assert!(!state.timers.is_armed(TimerKind::ConfigSave));
    }

    #[test]
    fn test_desktop_mode_lists_output_rules_as_inactive() {
        use crate::core::firewall::{Chain, EgressProfile};
        let mut state = create_test_state();
        let mut outbound = crate::core::test_helpers::create_test_rule("Out", Some(53));
        outbound.chain = Chain::Output;
        state.ruleset.rules.push(outbound);
        state
            .ruleset
            .rules
            .push(crate::core::test_helpers::create_test_rule("In", Some(22)));
        state.mark_profile_dirty();

        // Desktop mode: both rules are listed (the output one can be seen and
        // deleted), the output one is marked inactive, no chain arrows
        assert_eq!(
            state.ruleset.advanced_security.egress_profile,
            EgressProfile::Desktop
        );
        assert_eq!(state.cached_filtered_rule_indices, vec![0, 1]);
        assert_eq!(state.filter_count_display, "2/2");
        assert!(state.rule_is_inactive(&state.ruleset.rules[0]));
        assert!(!state.rule_is_inactive(&state.ruleset.rules[1]));
        assert!(!state.cached_rule_badges[0].starts_with('↑'));

        // Server mode: active, with chain arrows in the badges
        let _ = handle_confirm_server_mode(&mut state);
        assert!(!state.rule_is_inactive(&state.ruleset.rules[0]));
        assert!(state.cached_rule_badges[0].starts_with('↑'));
        assert!(state.cached_rule_badges[1].starts_with('↓'));

        // Deleting the output rule works in Desktop mode
        let _ = handle_server_mode_toggled(&mut state, false);
        let id = state.ruleset.rules[0].id;
        let _ = state.update(Message::DeleteRule(id));
        assert_eq!(state.ruleset.rules.len(), 1);
    }

    #[test]
    fn test_handle_toggle_auto_revert() {
        let mut state = create_test_state();
        let _ = handle_toggle_auto_revert(&mut state, true);
        assert!(state.auto_revert_enabled);
    }

    /// An upgraded config with auto-revert off (the old default): the notice
    /// shows; it is never flipped silently.
    fn state_with_old_config() -> State {
        let mut state = create_test_state();
        state.auto_revert_enabled = false;
        state.auto_revert_notice_shown = false;
        state.config_dirty = false;
        state
    }

    #[test]
    fn test_auto_revert_notice_turn_on() {
        let mut state = state_with_old_config();
        assert!(state.auto_revert_notice_visible());
        let _ = state.update(Message::AutoRevertNoticeAnswered(true));
        assert!(state.auto_revert_enabled);
        assert!(state.auto_revert_notice_shown);
        assert!(!state.auto_revert_notice_visible());
        assert!(state.config_dirty, "saved with the debounced config save");
        let config = state.config_snapshot();
        assert!(config.auto_revert_enabled && config.auto_revert_notice_shown);
    }

    #[test]
    fn test_auto_revert_notice_keep_off() {
        let mut state = state_with_old_config();
        let _ = state.update(Message::AutoRevertNoticeAnswered(false));
        assert!(!state.auto_revert_enabled, "the saved choice stays");
        assert!(!state.auto_revert_notice_visible());
        assert!(state.config_dirty);
        let config = state.config_snapshot();
        assert!(!config.auto_revert_enabled && config.auto_revert_notice_shown);

        // Answered: a second answer changes nothing
        state.config_dirty = false;
        let _ = state.update(Message::AutoRevertNoticeAnswered(true));
        assert!(!state.auto_revert_enabled);
        assert!(!state.config_dirty);
    }

    /// Turning auto-revert off in Settings is a choice too: no notice at the
    /// next start. With auto-revert on there is never a notice.
    #[test]
    fn test_auto_revert_notice_after_settings_change() {
        let mut state = create_test_state();
        assert!(!state.auto_revert_notice_visible(), "on: no notice");
        let _ = state.update(Message::ToggleAutoRevert(false));
        assert!(!state.auto_revert_notice_visible());
        assert!(state.config_snapshot().auto_revert_notice_shown);
    }

    #[test]
    fn test_failed_config_save_is_retried() {
        let mut state = create_test_state();
        handle_toggle_zebra_striping_dirty(&mut state);
        let due = config_save_deadline(&state, Instant::now()).unwrap();
        let _ = run_config_save_if_due(&mut state, due);
        assert!(state.config_save_in_flight);
        assert!(
            config_save_deadline(&state, Instant::now()).is_none(),
            "one save at a time"
        );

        handle_config_saved(&mut state, Err("Read-only file system".into()));
        assert!(!state.config_save_in_flight);
        assert!(state.config_dirty, "retried");
        let now = Instant::now();
        let retry = config_save_deadline(&state, now).unwrap();
        assert!(retry + Duration::from_millis(100) >= now + CONFIG_SAVE_RETRY);
        assert_eq!(state.banners.len(), 1);
        // The same failure again: no second banner
        let _ = run_config_save_if_due(&mut state, retry);
        handle_config_saved(&mut state, Err("Read-only file system".into()));
        assert_eq!(state.banners.len(), 1);
        // Recovery is announced
        let retry = config_save_deadline(&state, Instant::now()).unwrap();
        let _ = run_config_save_if_due(&mut state, retry);
        handle_config_saved(&mut state, Ok(()));
        assert!(!state.config_dirty);
        assert!(state.config_save_error.is_none());
        assert_eq!(state.banners.back().unwrap().message, "Settings saved");
    }

    fn handle_toggle_zebra_striping_dirty(state: &mut State) {
        let _ = handle_toggle_zebra_striping(state, false);
        assert!(state.config_dirty);
    }

    #[test]
    fn test_font_pickers_close_on_choice() {
        let mut state = create_test_state();
        crate::app::handlers::handle_open_font_picker(
            &mut state,
            crate::app::FontPickerTarget::Regular,
        );
        let _ =
            handle_regular_font_changed(&mut state, &crate::fonts::RegularFontChoice::default());
        assert!(state.font_picker.is_none());
    }

    #[test]
    fn test_settings_labels_are_cached() {
        let mut state = create_test_state();
        handle_icmp_rate_limit_changed(&mut state, 0);
        assert_eq!(state.settings_display.icmp_rate, "Off", "0 means no limit");
        handle_icmp_rate_limit_changed(&mut state, 7);
        assert_eq!(state.settings_display.icmp_rate, "7/s");
        handle_log_rate_changed(&mut state, 12);
        assert_eq!(state.settings_display.log_rate, "12/m");
        handle_auto_revert_timeout_changed(&mut state, 30);
        assert_eq!(state.settings_display.auto_revert_timeout, "30s");
        assert_eq!(state.settings_display.apply_timer_secs, "30");
    }

    // ── Local network discovery (S1) ──────────────────────────────────

    #[test]
    fn test_local_discovery_toggle_is_desktop_only() {
        let mut state = create_test_state();
        let _ = state.update(Message::ToggleLocalDiscovery(true));
        assert!(state.ruleset.advanced_security.local_discovery);
        assert!(state.profile_dirty, "saved with the profile");
        assert!(
            state.local_discovery_notice_shown,
            "a choice answers the notice"
        );
        assert!(state.config_dirty);

        let _ = handle_confirm_server_mode(&mut state);
        let _ = state.update(Message::ToggleLocalDiscovery(false));
        assert!(
            state.ruleset.advanced_security.local_discovery,
            "ignored in Server Mode (the toggle is disabled there)"
        );
    }

    /// An existing profile (discovery off, from before the setting): the
    /// notice shows once; "Turn on" enables it for this profile.
    #[test]
    fn test_local_discovery_notice_turn_on() {
        let mut state = create_test_state();
        assert!(state.local_discovery_notice_visible());
        let _ = state.update(Message::LocalDiscoveryNoticeAnswered(true));
        assert!(state.ruleset.advanced_security.local_discovery);
        assert!(state.profile_dirty);
        assert!(!state.local_discovery_notice_visible());
        assert!(state.config_snapshot().local_discovery_notice_shown);
    }

    #[test]
    fn test_local_discovery_notice_not_now() {
        let mut state = create_test_state();
        let _ = state.update(Message::LocalDiscoveryNoticeAnswered(false));
        assert!(
            !state.ruleset.advanced_security.local_discovery,
            "unchanged"
        );
        assert!(!state.profile_dirty);
        assert!(state.config_dirty, "saved with the debounced config save");
        assert!(!state.local_discovery_notice_visible());
        assert!(state.config_snapshot().local_discovery_notice_shown);
        // Answered: a second answer changes nothing
        let _ = state.update(Message::LocalDiscoveryNoticeAnswered(true));
        assert!(!state.ruleset.advanced_security.local_discovery);
    }

    /// No notice where it would not help: discovery already on (new
    /// profiles), Server Mode, or a read-only profile.
    #[test]
    fn test_local_discovery_notice_hidden_when_not_applicable() {
        let mut state = create_test_state();
        state.ruleset = crate::app::new_profile_ruleset();
        assert!(!state.local_discovery_notice_visible(), "already on");

        let mut state = create_test_state();
        state.ruleset.advanced_security.egress_profile = EgressProfile::Server;
        state.mark_profile_dirty();
        assert!(!state.local_discovery_notice_visible(), "Server Mode");
        let _ = state.update(Message::LocalDiscoveryNoticeAnswered(true));
        assert!(!state.ruleset.advanced_security.local_discovery);

        let mut state = create_test_state();
        state.unreadable_profile = Some(crate::core::profiles::UnreadableProfile {
            name: "test".into(),
            reason: "broken".into(),
            backup: None,
        });
        assert!(!state.local_discovery_notice_visible(), "read-only");
    }

    // ── Server Mode essentials (S2) ───────────────────────────────────

    fn essentials(state: &State) -> &crate::app::ServerEssentials {
        match &state.pending_warning {
            Some(PendingWarning::EnableServerMode(essentials)) => essentials,
            other => panic!("no Server Mode dialog: {other:?}"),
        }
    }

    /// The dialog offers every essential rule, pre-ticked; confirming adds
    /// the ticked ones as ordinary Output rules, and Ctrl+Z removes them
    /// all at once.
    #[test]
    fn test_server_mode_adds_ticked_essentials_undoably() {
        use crate::core::firewall::Chain;
        let mut state = create_test_state();
        state
            .ruleset
            .rules
            .push(crate::core::test_helpers::create_test_rule("SSH", Some(22)));
        state.mark_profile_dirty();

        let _ = state.update(Message::ServerModeToggled(true));
        let offered: Vec<&str> = essentials(&state)
            .choices
            .iter()
            .map(|c| c.rule.label.as_str())
            .collect();
        assert_eq!(
            offered,
            crate::core::templates::server_essentials()
                .iter()
                .map(|r| r.label.as_str())
                .collect::<Vec<_>>()
        );
        assert!(essentials(&state).choices.iter().all(|c| c.ticked));
        let checkboxes: Vec<&str> = essentials(&state)
            .choices
            .iter()
            .map(|c| c.label.as_str())
            .collect();
        assert_eq!(
            checkboxes,
            [
                "DNS (TCP+UDP: 53)",
                "DNS over TLS (TCP: 853)",
                "Time sync: NTP (UDP: 123)",
                "Web and updates: HTTP and HTTPS (TCP: 80, 443)",
                "Ping",
            ]
        );

        // Untick the second one
        let _ = state.update(Message::ServerEssentialToggled(1, false));
        let unticked = essentials(&state).choices[1].rule.label.clone();
        let _ = state.update(Message::ServerEssentialToggled(99, false));
        let _ = state.update(Message::ConfirmServerMode);
        assert!(state.pending_warning.is_none());
        assert_eq!(
            state.ruleset.advanced_security.egress_profile,
            EgressProfile::Server
        );
        let total = crate::core::templates::server_essentials().len();
        assert_eq!(state.ruleset.rules.len(), 1 + total - 1);
        assert!(
            state.ruleset.rules[1..]
                .iter()
                .all(|r| r.chain == Chain::Output && r.enabled)
        );
        assert!(!state.ruleset.rules.iter().any(|r| r.label == unticked));
        assert!(state.profile_dirty);

        let _ = state.update(Message::Undo);
        assert_eq!(state.ruleset.rules.len(), 1, "one step removes them all");
        assert_eq!(state.ruleset.rules[0].label, "SSH");
        assert!(
            state
                .banners
                .back()
                .unwrap()
                .message
                .contains("Server Mode essentials")
        );
        let _ = state.update(Message::Redo);
        assert_eq!(state.ruleset.rules.len(), total);
    }

    /// Nothing ticked: only the mode changes (no empty undo step). Rules the
    /// profile already has (an Output rule of the same name) start unticked.
    #[test]
    fn test_server_mode_without_essentials() {
        let mut state = create_test_state();
        let _ = state.update(Message::ServerModeToggled(true));
        let count = essentials(&state).choices.len();
        for index in 0..count {
            let _ = state.update(Message::ServerEssentialToggled(index, false));
        }
        let _ = state.update(Message::ConfirmServerMode);
        assert_eq!(
            state.ruleset.advanced_security.egress_profile,
            EgressProfile::Server
        );
        assert_eq!(state.ruleset.rules.len(), 0);
        assert!(!state.command_history.can_undo());

        // An Output rule the user already has under a real essentials label
        // ("Time sync: NTP") starts unticked; an Input rule of that name does not count
        let mut state = create_test_state();
        let mut ntp = crate::core::test_helpers::create_test_rule("Time sync: NTP", Some(123));
        ntp.chain = crate::core::firewall::Chain::Output;
        state.ruleset.rules.push(ntp);
        state
            .ruleset
            .rules
            .push(crate::core::test_helpers::create_test_rule("DNS", Some(53)));
        state.mark_profile_dirty();
        let _ = state.update(Message::ServerModeToggled(true));
        let unticked: Vec<&str> = essentials(&state)
            .choices
            .iter()
            .filter(|c| !c.ticked)
            .map(|c| c.rule.label.as_str())
            .collect();
        assert_eq!(unticked, ["Time sync: NTP"]);
        let _ = state.update(Message::CancelWarning);

        // Back to Desktop and on again: the essentials added before are
        // not offered twice
        let mut state = create_test_state();
        let _ = state.update(Message::ServerModeToggled(true));
        let _ = state.update(Message::ConfirmServerMode);
        let _ = state.update(Message::ServerModeToggled(false));
        let _ = state.update(Message::ServerModeToggled(true));
        assert!(essentials(&state).choices.iter().all(|c| !c.ticked));
        let _ = state.update(Message::CancelWarning);
        assert_eq!(
            state.ruleset.advanced_security.egress_profile,
            EgressProfile::Desktop,
            "cancelled"
        );
    }

    // ── Forwarded rules (S7) ──────────────────────────────────────────

    /// A Forwarded rule is listed with a "FWD" badge and inactive (dimmed,
    /// with its reason) until forwarded traffic is blocked.
    #[test]
    fn test_forward_rules_are_inactive_until_forwarding_is_blocked() {
        use crate::app::InactiveReason;
        use crate::core::firewall::Chain;
        let mut state = create_test_state();
        let mut forward = crate::core::test_helpers::create_test_rule("Routed", Some(80));
        forward.chain = Chain::Forward;
        forward.interface = Some("eth0".into());
        forward.output_interface = Some("wg0".into());
        state.ruleset.rules.push(forward);
        state.mark_profile_dirty();

        assert_eq!(
            state.inactive_reason(&state.ruleset.rules[0]),
            Some(InactiveReason::ForwardingNotBlocked)
        );
        assert!(
            state.cached_rule_badges[0].starts_with(crate::app::FORWARD_BADGE_PREFIX),
            "{}",
            state.cached_rule_badges[0]
        );
        assert!(
            !state
                .cached_rule_issues
                .contains_key(&state.ruleset.rules[0].id),
            "both interfaces are valid on a Forwarded rule"
        );

        let _ = state.update(Message::ToggleBlockForwarding(true));
        assert_eq!(state.inactive_reason(&state.ruleset.rules[0]), None);
        assert!(state.cached_rule_badges[0].starts_with(crate::app::FORWARD_BADGE_PREFIX));

        // Server Mode keeps the FWD badge (not an arrow)
        let _ = handle_confirm_server_mode(&mut state);
        assert!(state.cached_rule_badges[0].starts_with(crate::app::FORWARD_BADGE_PREFIX));
    }

    #[test]
    fn test_settings_texts_say_what_they_do() {
        let mut state = create_test_state();
        handle_icmp_rate_limit_changed(&mut state, 10);
        assert_eq!(
            state.settings_display.icmp_rate_desc,
            "Limit incoming ping requests to 10 per second (0 = off)"
        );
        handle_icmp_rate_limit_changed(&mut state, 0);
        assert_eq!(
            state.settings_display.icmp_rate_desc,
            "Limit incoming ping requests per second (0 = off)"
        );
    }
}
