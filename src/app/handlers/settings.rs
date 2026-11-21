//! Application settings and configuration
//!
//! Handles configuration changes:
//! - Display settings (diff view, zebra striping)
//! - Security settings (auto-revert, strict ICMP, RPF, forwarding)
//! - Logging settings (event log, dropped packet logging)
//! - Theme and font selection
//! - Debounced auto-save

use crate::app::{Message, PendingWarning, State};
use iced::Task;
use std::time::{Duration, Instant};

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

/// Handles toggling auto-revert feature
pub(crate) fn handle_toggle_auto_revert(state: &mut State, enabled: bool) -> Task<Message> {
    state.auto_revert_enabled = enabled;
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

/// Handles auto-revert timeout change
pub(crate) fn handle_auto_revert_timeout_changed(state: &mut State, timeout: u64) {
    state.auto_revert_timeout_secs = timeout.clamp(5, 120);
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
    state.audit_log_dirty = true; // Mark for refresh
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

/// Handles toggling forwarded-traffic blocking (forward chain policy)
///
/// No warning modal: the settings row explains that blocking breaks
/// Docker/VM/VPN routing, and the change only takes effect on Apply.
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

/// Handles server mode toggle request (shows warning)
pub(crate) fn handle_server_mode_toggled(state: &mut State, enabled: bool) -> Task<Message> {
    if enabled {
        state.pending_warning = Some(PendingWarning::EnableServerMode);
        Task::none()
    } else {
        state.ruleset.advanced_security.egress_profile =
            crate::core::firewall::EgressProfile::Desktop;
        state.mark_profile_dirty();
        super::log_setting_change(state, "Server mode disabled (desktop profile)")
    }
}

/// Handles confirming server mode
pub(crate) fn handle_confirm_server_mode(state: &mut State) -> Task<Message> {
    state.pending_warning = None;
    state.ruleset.advanced_security.egress_profile = crate::core::firewall::EgressProfile::Server;
    state.mark_profile_dirty();
    super::log_setting_change(state, "Server mode enabled (server profile)")
}

/// Quiet period after the last settings change before the config is written.
const CONFIG_SAVE_DEBOUNCE: Duration = Duration::from_millis(500);

/// When the pending config save is due, if the config is dirty.
pub(crate) fn config_save_deadline(state: &State, now: Instant) -> Option<Instant> {
    if !state.config_dirty {
        return None;
    }
    Some(
        state
            .last_config_change
            .map_or(now, |last_change| last_change + CONFIG_SAVE_DEBOUNCE),
    )
}

/// Saves the config if it is dirty and its quiet period is over.
pub(crate) fn run_config_save_if_due(state: &mut State, now: Instant) -> Task<Message> {
    if config_save_deadline(state, now).is_none_or(|deadline| now < deadline) {
        return Task::none();
    }
    state.config_dirty = false;
    state.save_config()
}

/// Handles the result of a config save: a failure is shown in a banner (the
/// next settings change tries again).
pub(crate) fn handle_config_saved(state: &mut State, result: Result<(), String>) {
    if let Err(e) = result {
        tracing::error!("Failed to save configuration: {e}");
        state.push_banner(
            format!("Could not save settings: {e}"),
            crate::app::BannerSeverity::Error,
        );
    }
}

/// Handles regular font changed
pub(crate) fn handle_regular_font_changed(
    state: &mut State,
    choice: &crate::fonts::RegularFontChoice,
) -> Task<Message> {
    state.regular_font_choice = choice.clone();
    state.font_regular = choice.to_font();
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
        // saved, and update() re-arms it for the remaining time
        let _ = state.update(Message::TimerFired(TimerKind::ConfigSave, generation));
        assert!(state.config_dirty, "deadline not reached yet");
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
}
