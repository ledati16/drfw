//! Message handlers organized by domain
//!
//! This module contains all message handlers extracted from the monolithic
//! `update()` method, organized by functional domain for better maintainability.

pub mod apply;
pub mod export;
pub mod exposure;
pub mod profiles;
pub mod rules;
pub mod settings;
pub mod ui_state;

#[cfg(test)]
pub mod test_utils;

// Re-export all handlers for clean imports in app/mod.rs
pub(crate) use apply::*;
pub(crate) use export::*;
pub(crate) use exposure::*;
use iced::Task;
pub(crate) use profiles::*;
pub(crate) use rules::*;
pub(crate) use settings::*;
pub(crate) use ui_state::*;

use crate::app::{Message, State};

/// Wraps an audit-log future as a task that marks the audit cache dirty when
/// the entry was written.
pub(crate) fn audit_task(
    future: impl std::future::Future<Output = ()> + Send + 'static,
) -> Task<Message> {
    Task::perform(future, |()| Message::AuditLogWritten)
}

/// Audit-logs a settings change (if event logging is enabled).
pub(crate) fn log_setting_change(state: &State, description: impl Into<String>) -> Task<Message> {
    let enable_event_log = state.enable_event_log;
    let description = description.into();
    audit_task(async move {
        crate::audit::log_settings_saved(enable_event_log, &description).await;
    })
}

/// Handles a debounce timer firing (see `app::debounce`): stale timers are
/// ignored; a current one runs its work if the deadline has passed. If more
/// changes moved the deadline meanwhile, nothing happens here and the timer
/// is re-armed for the remaining time after this message.
pub(crate) fn handle_timer_fired(
    state: &mut State,
    kind: crate::app::TimerKind,
    generation: u64,
) -> Task<Message> {
    handle_timer_fired_at(state, kind, generation, std::time::Instant::now())
}

/// [`handle_timer_fired`] at time `now` (tests pass their own clock).
pub(crate) fn handle_timer_fired_at(
    state: &mut State,
    kind: crate::app::TimerKind,
    generation: u64,
    now: std::time::Instant,
) -> Task<Message> {
    use crate::app::TimerKind;

    if !state.timers.get_mut(kind).fire(generation) {
        return Task::none();
    }
    match kind {
        TimerKind::ConfigSave => run_config_save_if_due(state, now),
        TimerKind::ProfileSave => run_profile_save_if_due(state, now),
        TimerKind::SliderLog => run_slider_log_if_due(state, now),
    }
}
