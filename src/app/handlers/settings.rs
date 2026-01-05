//! Application settings and configuration
//!
//! Handles configuration changes:
//! - Display settings (diff view, zebra striping)
//! - Security settings (auto-revert, strict ICMP, RPF)
//! - Logging settings (event log, dropped packet logging)
//! - Theme and font selection
//! - Debounced auto-save

use crate::app::{Message, PendingWarning, State};
use iced::Task;

/// Handles toggling diff view
pub(crate) fn handle_toggle_diff(state: &mut State, enabled: bool) -> Task<Message> {
    state.show_diff = enabled;
    state.mark_config_dirty();
    let enable_event_log = state.enable_event_log;
    let desc = if enabled {
        "Diff view enabled"
    } else {
        "Diff view disabled"
    };
    Task::perform(
        async move {
            crate::audit::log_settings_saved(enable_event_log, desc).await;
        },
        |()| Message::AuditLogWritten,
    )
}

/// Handles toggling zebra striping
pub(crate) fn handle_toggle_zebra_striping(state: &mut State, enabled: bool) -> Task<Message> {
    state.show_zebra_striping = enabled;
    state.mark_config_dirty();
    let enable_event_log = state.enable_event_log;
    let desc = if enabled {
        "Zebra striping enabled"
    } else {
        "Zebra striping disabled"
    };
    Task::perform(
        async move {
            crate::audit::log_settings_saved(enable_event_log, desc).await;
        },
        |()| Message::AuditLogWritten,
    )
}

/// Handles toggling auto-revert feature
pub(crate) fn handle_toggle_auto_revert(state: &mut State, enabled: bool) -> Task<Message> {
    state.auto_revert_enabled = enabled;
    state.mark_config_dirty();
    let enable_event_log = state.enable_event_log;
    let desc = if enabled {
        "Auto-revert enabled"
    } else {
        "Auto-revert disabled"
    };
    Task::perform(
        async move {
            crate::audit::log_settings_saved(enable_event_log, desc).await;
        },
        |()| Message::AuditLogWritten,
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

/// Handles toggling strict ICMP mode
pub(crate) fn handle_toggle_strict_icmp(state: &mut State, enabled: bool) -> Task<Message> {
    state.ruleset.advanced_security.strict_icmp = enabled;
    state.mark_profile_dirty();
    let enable_event_log = state.enable_event_log;
    let desc = if enabled {
        "Strict ICMP filtering enabled"
    } else {
        "Strict ICMP filtering disabled"
    };
    Task::perform(
        async move {
            crate::audit::log_settings_saved(enable_event_log, desc).await;
        },
        |()| Message::AuditLogWritten,
    )
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
        let enable_event_log = state.enable_event_log;
        Task::perform(
            async move {
                crate::audit::log_settings_saved(
                    enable_event_log,
                    "RPF (reverse path filtering) disabled",
                )
                .await;
            },
            |()| Message::AuditLogWritten,
        )
    }
}

/// Handles confirming RPF enable
pub(crate) fn handle_confirm_enable_rpf(state: &mut State) -> Task<Message> {
    state.pending_warning = None;
    state.ruleset.advanced_security.enable_rpf = true;
    state.mark_profile_dirty();
    let enable_event_log = state.enable_event_log;
    Task::perform(
        async move {
            crate::audit::log_settings_saved(
                enable_event_log,
                "RPF (reverse path filtering) enabled",
            )
            .await;
        },
        |()| Message::AuditLogWritten,
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
    let enable_event_log = state.enable_event_log;
    let desc = if enabled {
        "Dropped packet logging enabled"
    } else {
        "Dropped packet logging disabled"
    };
    Task::perform(
        async move {
            crate::audit::log_settings_saved(enable_event_log, desc).await;
        },
        |()| Message::AuditLogWritten,
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

/// Handles check slider log (debounced validation)
pub(crate) fn handle_check_slider_log(state: &mut State) -> Task<Message> {
    const DEBOUNCE_MS: u64 = 2000; // 2 seconds for slider changes

    if let Some((description, last_change)) = &state.pending_slider_log
        && last_change.elapsed().as_millis() >= u128::from(DEBOUNCE_MS)
    {
        let desc = description.clone();
        state.pending_slider_log = None;
        let enable_event_log = state.enable_event_log;
        return Task::perform(
            async move {
                crate::audit::log_settings_saved(enable_event_log, &desc).await;
            },
            |()| Message::AuditLogWritten,
        );
    }

    Task::none()
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
            let enable_event_log = state.enable_event_log;
            let desc = format!("Log prefix changed to '{sanitized}'");
            Task::perform(
                async move {
                    crate::audit::log_settings_saved(enable_event_log, &desc).await;
                },
                |()| Message::AuditLogWritten,
            )
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
        let enable_event_log = state.enable_event_log;
        Task::perform(
            async move {
                crate::audit::log_settings_saved(
                    enable_event_log,
                    "Server mode disabled (desktop profile)",
                )
                .await;
            },
            |()| Message::AuditLogWritten,
        )
    }
}

/// Handles confirming server mode
pub(crate) fn handle_confirm_server_mode(state: &mut State) -> Task<Message> {
    state.pending_warning = None;
    state.ruleset.advanced_security.egress_profile = crate::core::firewall::EgressProfile::Server;
    state.mark_profile_dirty();
    let enable_event_log = state.enable_event_log;
    Task::perform(
        async move {
            crate::audit::log_settings_saved(
                enable_event_log,
                "Server mode enabled (server profile)",
            )
            .await;
        },
        |()| Message::AuditLogWritten,
    )
}

/// Handles periodic config save check (debounced)
pub(crate) fn handle_check_config_save(state: &mut State) -> Task<Message> {
    const DEBOUNCE_MS: u64 = 500;

    if !state.config_dirty {
        return Task::none();
    }

    // Check if enough time has passed since last change
    if let Some(last_change) = state.last_config_change
        && last_change.elapsed().as_millis() < u128::from(DEBOUNCE_MS)
    {
        return Task::none();
    }

    state.config_dirty = false;
    state.save_config()
}

/// Handles regular font changed
pub(crate) fn handle_regular_font_changed(
    state: &mut State,
    choice: &crate::fonts::RegularFontChoice,
) -> Task<Message> {
    state.regular_font_choice = choice.clone();
    state.font_regular = choice.to_font();
    state.mark_config_dirty();
    let enable_event_log = state.enable_event_log;
    let desc = format!("UI font changed to {}", choice.name());
    Task::perform(
        async move {
            crate::audit::log_settings_saved(enable_event_log, &desc).await;
        },
        |()| Message::AuditLogWritten,
    )
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
    let enable_event_log = state.enable_event_log;
    let desc = format!("Monospace font changed to {}", choice.name());
    Task::perform(
        async move {
            crate::audit::log_settings_saved(enable_event_log, &desc).await;
        },
        |()| Message::AuditLogWritten,
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
    fn test_handle_toggle_auto_revert() {
        let mut state = create_test_state();
        let _ = handle_toggle_auto_revert(&mut state, true);
        assert!(state.auto_revert_enabled);
    }
}
