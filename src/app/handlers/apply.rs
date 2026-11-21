//! Apply, verify, and revert workflow
//!
//! Handles the complete firewall application lifecycle:
//! - Verification of rules before application (unprivileged when possible)
//! - Elevated application with a root-side revert guard
//!   ([`crate::core::apply_guard`])
//! - Auto-revert countdown, confirmation and manual revert (no elevation:
//!   they only signal the guard)
//! - Save to system configuration
//!
//! The ruleset is snapshotted when the user clicks Apply: exactly that
//! snapshot is verified and applied, and ruleset edits are refused until the
//! apply flow is over, so nothing unverified can slip in.
//!
//! # Confirmations
//!
//! Two checks can make "Commit Changes?" (and Save to System, for the
//! editor's rules) need an explicit "Apply anyway" / "Save anyway": the
//! retention guard ([`crate::core::retention`]) and the SSH lockout check
//! ([`crate::core::lockout`]). Both are computed in `update()` when Apply is
//! clicked (or the save dialog opens) from what is known then: the kept
//! record loaded earlier and the SSH sessions last found (at least the
//! `SSH_CONNECTION` session, read at startup). At the same time the record and
//! the sessions are re-read off the UI thread, next to the verification (or
//! the boot query), since a `drfw apply` in a terminal may have replaced the
//! record meanwhile. When they arrive (`Message::ApplyContextLoaded`) both
//! warnings are computed again for a dialog that is still open; for a closed
//! one only the record and sessions are stored. A reload started before this
//! GUI replaced the record itself is older and is not stored.

use std::time::Instant;

use iced::Task;

use super::audit_task;
use crate::app::{AppStatus, BannerSeverity, Message, State};
use crate::audit;
use crate::core::apply_guard::{ApplyError, GuardError, GuardHandle, GuardOutcome};
use crate::core::boot::BootStatus;
use crate::core::confirmed::{ConfirmedRecord, RecordKind};
use crate::core::firewall::FirewallRuleset;
use crate::core::lockout::{LockoutWarning, SshSession};
use crate::core::retention::RetentionWarning;
use crate::core::system_config::EnableOutcome;
use crate::core::verify::{VerifyError, VerifyResult};
use crate::elevation::AuthError;

// ============================================================================
// Helper Functions
// ============================================================================

/// Truncates an error message to fit within a maximum length, adding ellipsis if needed.
/// The prefix is always included, and the message is truncated to fit.
/// Lengths are in bytes; the cut never splits a multibyte character.
fn truncate_error_message(prefix: &str, message: &str, max_total_len: usize) -> String {
    let available = max_total_len.saturating_sub(prefix.len()).saturating_sub(3); // 3 for "..."
    if message.len() > available {
        format!(
            "{prefix}{}...",
            crate::utils::truncate_str(message, available)
        )
    } else {
        format!("{prefix}{message}")
    }
}

/// Error text of [`interpret_elevated_command_output`] for a cancelled
/// authentication (reported as a warning, not an error).
const AUTH_CANCELLED: &str = "Authentication cancelled";

/// Interprets the output of an elevated command and returns a user-friendly error message.
/// Returns Ok(()) on success, or Err with a descriptive message on failure.
fn interpret_elevated_command_output(output: &std::process::Output) -> Result<(), String> {
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let exit_code = output.status.code().unwrap_or(-1);

    // Detect common error patterns from pkexec/sudo/run0
    if exit_code == 126 {
        Err(AUTH_CANCELLED.into())
    } else if exit_code == 127 {
        // Preserve stderr for specific error detection (e.g. "No authentication agent")
        if stderr.is_empty() {
            Err("Authentication failed".into())
        } else {
            Err(format!("Authentication failed: {}", stderr.trim()))
        }
    } else if stderr.contains("Permission denied") {
        Err("Permission denied (check polkit configuration)".into())
    } else if stderr.is_empty() {
        Err(format!("Command failed (exit code {exit_code})"))
    } else {
        Err(format!("Command failed: {}", stderr.trim()))
    }
}

/// The ruleset being verified/applied, snapshotted when Apply was clicked.
#[derive(Debug, Clone)]
pub struct ApplySession {
    /// Exactly what was verified and will be applied
    verified: FirewallRuleset,
    /// `verified.to_nftables_json()`, computed once
    json: serde_json::Value,
    /// `last_applied_ruleset` before this apply, restored if it is reverted
    previous_applied: Option<FirewallRuleset>,
    /// Why this apply needs an explicit "Apply anyway" (compared with the
    /// last ruleset applied and kept), computed when Apply was clicked and
    /// again when the record is re-read
    retention: Option<RetentionWarning>,
    /// The SSH lockout check's warning for this apply (same timing)
    lockout: Option<LockoutWarning>,
}

impl ApplySession {
    /// The retention guard's warning for this apply, if any (shown in the
    /// "Commit Changes?" dialog).
    pub fn retention(&self) -> Option<&RetentionWarning> {
        self.retention.as_ref()
    }

    /// The SSH lockout check's warning for this apply, if any (shown in the
    /// "Commit Changes?" dialog).
    pub fn lockout(&self) -> Option<&LockoutWarning> {
        self.lockout.as_ref()
    }

    /// Applying takes "Apply anyway" (Enter is refused): the retention guard
    /// warns, or the lockout check does (its notes alone do not).
    pub fn needs_confirmation(&self) -> bool {
        self.retention.is_some()
            || self
                .lockout
                .as_ref()
                .is_some_and(LockoutWarning::needs_confirmation)
    }

    /// Computes both warnings for `verified` from the current record and
    /// sessions.
    fn check(&mut self, kept: Option<&FirewallRuleset>, sessions: &[SshSession]) {
        self.retention = RetentionWarning::check(kept, &self.verified);
        self.lockout = LockoutWarning::check(&self.verified, sessions);
    }

    /// The record of this ruleset once it is kept (the same one
    /// `apply_guarded` and the guard persist).
    fn kept_record(&self, kind: RecordKind) -> Option<ConfirmedRecord> {
        ConfirmedRecord::new(&self.json, &self.verified, kind)
            .map_err(|e| tracing::error!("Cannot record the kept ruleset: {e}"))
            .ok()
    }
}

/// The ruleset of the last apply that was kept, if known.
fn kept_ruleset(state: &State) -> Option<&FirewallRuleset> {
    state
        .confirmed_record
        .as_ref()
        .and_then(ConfirmedRecord::ruleset)
}

/// Replaces the kept-ruleset record with one this GUI just kept; a reload
/// from disk started before is then older (see the module docs).
fn set_confirmed_record(state: &mut State, record: Option<ConfirmedRecord>) {
    state.replace_confirmed_record(record);
    state.confirmed_record_generation = state.confirmed_record_generation.wrapping_add(1);
}

/// The kept record and the SSH sessions, re-read from disk and `/proc`.
#[derive(Debug, Clone)]
pub struct ApplyContext {
    /// `State::confirmed_record_generation` when the reload started
    pub record_generation: u64,
    pub record: Option<ConfirmedRecord>,
    pub sessions: Vec<SshSession>,
}

/// Re-reads the kept record and the SSH sessions on the blocking pool.
fn reload_context_task(state: &State) -> Task<Message> {
    let record_generation = state.confirmed_record_generation;
    let env = state.ssh_env_session.clone();
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || ApplyContext {
                record_generation,
                record: ConfirmedRecord::load_blocking(),
                sessions: crate::core::lockout::detect_sessions(env),
            })
            .await
            .map_err(|e| tracing::error!("Reloading the kept record failed: {e}"))
            .ok()
            .map(Box::new)
        },
        Message::ApplyContextLoaded,
    )
}

/// Handles the re-read record and sessions: stores them (the record only if
/// this GUI did not replace it meanwhile) and recomputes the warnings of an
/// open "Commit Changes?" or Save to System dialog.
pub(crate) fn handle_apply_context_loaded(state: &mut State, context: ApplyContext) {
    if context.record_generation == state.confirmed_record_generation {
        state.replace_confirmed_record(context.record);
    }
    state.ssh_sessions = context.sessions;
    match state.status {
        AppStatus::Verifying | AppStatus::AwaitingApply => {
            let kept = state
                .confirmed_record
                .as_ref()
                .and_then(ConfirmedRecord::ruleset);
            if let Some(session) = state.apply_session.as_mut() {
                session.check(kept, &state.ssh_sessions);
            }
        }
        AppStatus::AwaitingSaveToSystem => check_save_dialog(state),
        // Closed (or past the question): nothing to update
        _ => {}
    }
}

/// Longest banner text for apply errors.
const BANNER_MAX_LEN: usize = 100;

/// Banner for [`ApplyError::StateUnknown`] (at most 120 characters, the
/// banner's width); the details are in the panel it opens.
pub(crate) const STATE_UNKNOWN_BANNER: &str =
    "New rules MAY BE ACTIVE: the apply did not report its outcome. See Apply Details.";

/// Banner lifetime that never expires (dismiss by clicking it).
const PERSISTENT_BANNER_SECS: u64 = u64::MAX;

/// Pushes an error banner that stays until the user dismisses it.
fn push_persistent_banner(state: &mut State, message: String) {
    state.push_banner(message, BannerSeverity::Error);
    if let Some(banner) = state.banners.back_mut() {
        banner.duration_secs = PERSISTENT_BANNER_SECS;
    }
}

/// The revert timeout used for a configured timeout of `configured` seconds.
pub(crate) fn guard_timeout_secs_for(configured: u64) -> u64 {
    configured.clamp(1, 120)
}

/// The revert timeout to use, or 0 when auto-revert is disabled.
fn guard_timeout_secs(state: &State) -> u64 {
    if state.auto_revert_enabled {
        guard_timeout_secs_for(state.auto_revert_timeout_secs)
    } else {
        0
    }
}

/// Banner + audit entry for an authentication failure.
fn auth_error_feedback(state: &mut State, error: &AuthError) -> Task<Message> {
    let enable_event_log = state.enable_event_log;
    let detail = error.to_string();
    if *error == AuthError::Cancelled {
        state.push_banner(
            "Authentication was cancelled; nothing was changed",
            BannerSeverity::Warning,
        );
        return audit_task(audit::log_elevation_cancelled(enable_event_log, detail));
    }
    state.push_banner(
        truncate_error_message("", &detail, BANNER_MAX_LEN),
        BannerSeverity::Error,
    );
    audit_task(audit::log_elevation_failed(enable_event_log, detail))
}

/// Banner + audit entry for a verification that could not run.
fn verify_error_feedback(state: &mut State, error: &VerifyError) -> Task<Message> {
    let enable_event_log = state.enable_event_log;
    let audit = audit_task(audit::log_verify(
        enable_event_log,
        false,
        0,
        Some(error.to_string()),
    ));
    let feedback = match error {
        VerifyError::Auth(auth) => auth_error_feedback(state, auth),
        VerifyError::Failed(msg) => {
            state.push_banner(
                truncate_error_message("Verification error: ", msg, BANNER_MAX_LEN),
                BannerSeverity::Error,
            );
            Task::none()
        }
    };
    Task::batch([audit, feedback])
}

/// Verifies `ruleset` (JSON check, see `verify::verify_ruleset`) and, if nft
/// rejects it, maps the errors to the rules that caused them.
async fn verify_and_locate(
    ruleset: FirewallRuleset,
    json: serde_json::Value,
) -> Result<VerifyResult, VerifyError> {
    let result = crate::core::verify::verify_ruleset(json).await?;
    Ok(crate::core::verify::locate_errors(&ruleset, result).await)
}

/// What a verification was for; the errors panel says what to retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyPurpose {
    Apply,
    SaveToSystem,
}

/// Banner, "Verification Errors" panel and audit entry for a ruleset nft
/// rejected.
fn verify_rejected_feedback(
    state: &mut State,
    result: &VerifyResult,
    purpose: VerifyPurpose,
) -> Task<Message> {
    state.push_banner(
        crate::app::verify_errors::banner_message(result),
        BannerSeverity::Error,
    );
    let mut panel = crate::app::verify_errors::VerifyErrorsPanel::new(result, &state.ruleset);
    panel.next_step = match purpose {
        VerifyPurpose::Apply => "Nothing was changed. Fix the rules below, then apply again.",
        VerifyPurpose::SaveToSystem => {
            "Nothing was saved. Fix the rules below, then save to system again."
        }
    };
    state.verify_errors = Some(panel);
    state.show_verify_errors = true;
    audit_task(audit::log_verify(
        state.enable_event_log,
        false,
        result.issues.len(),
        Some(result.summary()),
    ))
}

/// Closes and drops the "Verification Errors" panel: a verification passed,
/// or the profile changed (its rows would name rules of another profile).
pub(crate) fn clear_verify_errors(state: &mut State) {
    state.verify_errors = None;
    state.show_verify_errors = false;
}

/// True while the apply flow (or Save to System) owns the ruleset.
pub(crate) fn edits_locked(state: &State) -> bool {
    state.is_busy() || state.status == AppStatus::AwaitingApply
}

/// Messages that open the rule form or start a rule edit. While the apply
/// flow owns the ruleset they are refused up front, so no form opens that
/// could not be saved.
pub(crate) fn starts_rule_edit(message: &Message) -> bool {
    matches!(
        message,
        Message::AddRuleClicked
            | Message::EditRuleClicked(_)
            | Message::DeleteRuleRequested(_)
            | Message::RuleDragStart(_)
    )
}

/// Messages that change the ruleset (or switch to another one).
///
/// Results of profile loads and creations (`ProfileSwitched`,
/// `ProfileCreated`) are not in this list: they were requested before the
/// lock and are handled (not dropped) by their handlers.
pub(crate) fn is_ruleset_edit(message: &Message) -> bool {
    matches!(
        message,
        Message::SaveRuleForm
            | Message::ToggleRuleEnabled(_)
            | Message::DeleteRule(_)
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
            | Message::ProfileSelected(_)
            | Message::SaveProfileAs(_)
            | Message::ConfirmProfileSwitch
            | Message::DiscardProfileSwitch
            | Message::CreateEmptyProfile
            | Message::ConfirmStartFresh
            | Message::ConfirmDeleteProfile
    )
}

/// Refuses a ruleset edit while the apply flow is running.
pub(crate) fn handle_edit_while_locked(state: &mut State) {
    const MSG: &str =
        "Rules can't be changed while an apply is in progress. Finish or cancel it first.";
    state.clear_drag_state();
    if state.banners.back().is_none_or(|b| b.message != MSG) {
        state.push_banner(MSG, BannerSeverity::Warning);
    }
}

/// Refuses to apply or save a ruleset with invalid enabled rules.
///
/// Invalid rules are kept in the profile (no data loss) but must never reach
/// nft: they would either fail with a cryptic error or do something other than
/// what the rule card shows. Returns `false` (after showing why) if blocked.
fn ruleset_ready_to_apply(state: &mut State) -> bool {
    match state.ruleset.validate_for_apply() {
        Ok(()) => true,
        Err(report) => {
            let summary = report
                .blocking_summary()
                .unwrap_or_else(|| "Cannot apply: the ruleset has invalid rules.".to_string());
            state.push_banner(summary, BannerSeverity::Error);
            false
        }
    }
}

/// Handles apply button click: snapshots the ruleset and verifies it
pub(crate) fn handle_apply_clicked(state: &mut State) -> Task<Message> {
    if state.is_busy() {
        return Task::none();
    }
    if !ruleset_ready_to_apply(state) {
        return Task::none();
    }

    let verified = state.ruleset.clone();
    let json = verified.to_nftables_json();
    let verify = Task::perform(
        verify_and_locate(verified.clone(), json.clone()),
        Message::VerifyCompleted,
    );
    let mut session = ApplySession {
        verified,
        json,
        previous_applied: None,
        retention: None,
        lockout: None,
    };
    session.check(kept_ruleset(state), &state.ssh_sessions);
    state.apply_session = Some(session);
    state.status = AppStatus::Verifying;
    Task::batch([verify, reload_context_task(state)])
}

/// Handles verification completion
pub(crate) fn handle_verify_completed(
    state: &mut State,
    result: Result<VerifyResult, VerifyError>,
) -> Task<Message> {
    if state.status != AppStatus::Verifying {
        return Task::none();
    }
    let enable_event_log = state.enable_event_log;
    match result {
        Ok(verify_result) if verify_result.success => {
            state.status = AppStatus::AwaitingApply;
            state.refresh_settings_display();
            clear_verify_errors(state);
            audit_task(audit::log_verify(enable_event_log, true, 0, None))
        }
        Ok(verify_result) => {
            state.status = AppStatus::Idle;
            state.apply_session = None;
            verify_rejected_feedback(state, &verify_result, VerifyPurpose::Apply)
        }
        Err(e) => {
            state.status = AppStatus::Idle;
            state.apply_session = None;
            verify_error_feedback(state, &e)
        }
    }
}

/// Handles "Cancel" in the "Commit Changes?" dialog: nothing is applied and
/// the edits stay as they are (the verified snapshot is dropped).
pub(crate) fn handle_cancel_apply(state: &mut State) {
    if state.status == AppStatus::AwaitingApply {
        state.status = AppStatus::Idle;
        state.apply_session = None;
    }
}

/// Handles proceeding to apply after successful verification ("Apply" or
/// Enter). Refused while the retention guard or the lockout check warns:
/// that takes the "Apply anyway" button ([`handle_proceed_to_apply_anyway`]).
pub(crate) fn handle_proceed_to_apply(state: &mut State) -> Task<Message> {
    proceed_to_apply(state, false)
}

/// Handles "Apply anyway": the user confirmed the warnings (retention guard,
/// lockout check).
pub(crate) fn handle_proceed_to_apply_anyway(state: &mut State) -> Task<Message> {
    proceed_to_apply(state, true)
}

/// Starts the elevated apply of the verified snapshot. `confirmed`: the user
/// explicitly accepted the warnings shown ("Apply anyway").
fn proceed_to_apply(state: &mut State, confirmed: bool) -> Task<Message> {
    if state.status != AppStatus::AwaitingApply {
        return Task::none();
    }
    let Some(session) = state.apply_session.as_mut() else {
        tracing::error!("ProceedToApply without a verified ruleset");
        state.status = AppStatus::Idle;
        return Task::none();
    };
    if session.needs_confirmation() && !confirmed {
        // The dialog stays open; only its "Apply anyway" button continues
        const HINT: &str = "Review the warning, then click \"Apply anyway\" to apply these rules.";
        if state.banners.back().is_none_or(|b| b.message != HINT) {
            state.push_banner(HINT, BannerSeverity::Warning);
        }
        return Task::none();
    }
    session
        .previous_applied
        .clone_from(&state.last_applied_ruleset);

    state.status = AppStatus::Applying;
    let json = session.json.clone();
    let ruleset = session.verified.clone();
    let rule_count = session.verified.rules.len();
    let enabled_count = session.verified.rules.iter().filter(|r| r.enabled).count();
    let enable_event_log = state.enable_event_log;
    let timeout_secs = guard_timeout_secs(state);

    Task::perform(
        async move {
            let result =
                crate::core::apply_guard::apply_guarded(&json, timeout_secs, &ruleset).await;
            audit::log_apply(
                enable_event_log,
                rule_count,
                enabled_count,
                result.is_ok(),
                result.as_ref().err().map(ToString::to_string),
            )
            .await;
            result
        },
        Message::ApplyResult,
    )
    .chain(Task::done(Message::AuditLogWritten))
}

/// Handles the result of the elevated apply
pub(crate) fn handle_apply_result(
    state: &mut State,
    result: Result<Option<GuardHandle>, ApplyError>,
) -> Task<Message> {
    if state.status != AppStatus::Applying {
        return Task::none();
    }
    let Some(session) = state.apply_session.as_ref() else {
        tracing::error!("ApplyResult without an apply session");
        state.status = AppStatus::Idle;
        return Task::none();
    };

    let guard = match result {
        Ok(guard) => guard,
        Err(error) => {
            state.status = AppStatus::Idle;
            if error.rules_may_be_active() {
                // Unknown whether the old or new rules are live
                state.set_last_applied(None);
            }
            state.apply_session = None;
            return apply_error_feedback(state, &error);
        }
    };

    let verified = session.verified.clone();
    state.set_last_applied(Some(verified));

    let Some(guard) = guard else {
        // Auto-revert is off: the user chose to keep these rules
        // unconditionally (`apply_guarded` persisted the same record)
        state.status = AppStatus::Idle;
        let record = state
            .apply_session
            .take()
            .and_then(|s| s.kept_record(RecordKind::Unguarded));
        set_confirmed_record(state, record);
        state.push_banner(
            "Firewall rules applied successfully!",
            BannerSeverity::Success,
        );
        return Task::none();
    };

    let timeout = guard.timeout();
    state.set_countdown(u32::try_from(timeout.as_secs()).unwrap_or(u32::MAX));
    state.progress_animation = iced::Animation::new(1.0)
        .easing(iced::animation::Easing::Linear)
        .duration(timeout)
        .go(0.0, iced::time::Instant::now());
    state.push_banner(
        format!(
            "Firewall rules applied! They revert in {}s unless confirmed.",
            timeout.as_secs()
        ),
        BannerSeverity::Info,
    );
    state.status = AppStatus::PendingConfirmation { guard };
    Task::none()
}

/// Banner + audit entry for a failed apply.
fn apply_error_feedback(state: &mut State, error: &ApplyError) -> Task<Message> {
    match error {
        ApplyError::Auth(auth) => return auth_error_feedback(state, auth),
        ApplyError::StateUnknown(detail) => {
            // Short enough for the banner; the full explanation goes to the
            // details panel, opened right away
            push_persistent_banner(state, STATE_UNKNOWN_BANNER.to_string());
            state.verify_errors =
                Some(crate::app::verify_errors::VerifyErrorsPanel::apply_state_unknown(detail));
            state.show_verify_errors = true;
        }
        ApplyError::GuardNotStarted(_) => state.push_banner(
            truncate_error_message("", &error.to_string(), BANNER_MAX_LEN),
            BannerSeverity::Warning,
        ),
        ApplyError::Rejected(_) | ApplyError::Failed(_) => state.push_banner(
            truncate_error_message("", &error.to_string(), BANNER_MAX_LEN),
            BannerSeverity::Error,
        ),
    }
    Task::none()
}

/// Handles the Rollback button: asks the guard to revert now (no elevation)
pub(crate) fn handle_revert_clicked(state: &mut State) -> Task<Message> {
    let AppStatus::PendingConfirmation { guard } = &state.status else {
        return Task::none();
    };
    let guard = guard.clone();
    if let Err(e) = guard.revert_now() {
        state.push_banner(
            truncate_error_message("", &e.to_string(), BANNER_MAX_LEN),
            BannerSeverity::Error,
        );
        return Task::none();
    }
    state.status = AppStatus::Reverting;
    Task::perform(
        async move {
            guard
                .wait_outcome(crate::core::apply_guard::OUTCOME_GRACE)
                .await
        },
        Message::GuardFinished,
    )
}

/// Handles the countdown tick (1 Hz): updates the display; at zero, waits
/// for the root-side guard to report the revert
pub(crate) fn handle_countdown_tick(state: &mut State) -> Task<Message> {
    let AppStatus::PendingConfirmation { guard } = &state.status else {
        return Task::none();
    };
    let guard = guard.clone();
    let remaining = guard.remaining_secs(Instant::now());
    state.set_countdown(u32::try_from(remaining).unwrap_or(u32::MAX));

    if remaining > 0 {
        if remaining == 5 {
            state.push_banner(
                "Firewall will revert in 5 seconds! Click Confirm to keep changes.",
                BannerSeverity::Warning,
            );
        }
        return Task::none();
    }

    let enable_event_log = state.enable_event_log;
    let timeout_secs = guard.timeout().as_secs();
    state.status = AppStatus::Reverting;
    state.push_banner(
        "Time is up: waiting for the guard to restore the previous rules...",
        BannerSeverity::Info,
    );
    Task::batch([
        audit_task(audit::log_auto_revert_timed_out(
            enable_event_log,
            timeout_secs,
        )),
        Task::perform(
            async move { guard.wait_for_timeout_outcome().await },
            Message::GuardFinished,
        ),
    ])
}

/// Handles Confirm: tells the guard to keep the rules (no elevation)
pub(crate) fn handle_confirm_clicked(state: &mut State) -> Task<Message> {
    let AppStatus::PendingConfirmation { guard } = &state.status else {
        return Task::none();
    };
    let guard = guard.clone();
    if let Err(e) = guard.confirm() {
        // The guard will revert on timeout; let the user retry or roll back
        state.push_banner(
            truncate_error_message("", &e.to_string(), BANNER_MAX_LEN),
            BannerSeverity::Error,
        );
        return Task::none();
    }
    state.status = AppStatus::Confirming;
    Task::perform(
        async move {
            guard
                .wait_outcome(crate::core::apply_guard::OUTCOME_GRACE)
                .await
        },
        Message::GuardFinished,
    )
}

/// Handles the guard's verdict (after confirm, rollback or timeout)
pub(crate) fn handle_guard_finished(
    state: &mut State,
    result: Result<GuardOutcome, GuardError>,
) -> Task<Message> {
    if !matches!(state.status, AppStatus::Confirming | AppStatus::Reverting) {
        return Task::none();
    }
    state.status = AppStatus::Idle;
    let session = state.apply_session.take();
    let previous_applied = session.as_ref().and_then(|s| s.previous_applied.clone());
    let enable_event_log = state.enable_event_log;
    let timeout_secs = guard_timeout_secs(state);

    match result {
        Ok(GuardOutcome::Confirmed) => {
            // The guard persisted the same record (`GuardHandle::wait_outcome`)
            set_confirmed_record(
                state,
                session.and_then(|s| s.kept_record(RecordKind::Confirmed)),
            );
            state.push_banner("Changes confirmed!", BannerSeverity::Success);
            audit_task(audit::log_auto_revert_confirmed(
                enable_event_log,
                timeout_secs,
            ))
        }
        Ok(GuardOutcome::Reverted) => {
            state.set_last_applied(previous_applied);
            state.push_banner(
                "Firewall rules reverted to the previous state",
                BannerSeverity::Info,
            );
            audit_task(audit::log_revert(enable_event_log, true, None))
        }
        Ok(GuardOutcome::Removed(err)) => {
            // Neither the old nor the new drfw rules are loaded now
            state.set_last_applied(None);
            push_persistent_banner(
                state,
                "Previous rules could not be restored; the drfw table was removed, so drfw is not filtering anything".to_string(),
            );
            audit_task(audit::log_revert(enable_event_log, true, Some(err)))
        }
        Ok(GuardOutcome::RevertFailed(err)) => {
            push_persistent_banner(
                state,
                truncate_error_message(
                    "Revert FAILED: the new rules are STILL ACTIVE. ",
                    &err,
                    160,
                ),
            );
            audit_task(audit::log_revert(enable_event_log, false, Some(err)))
        }
        Ok(GuardOutcome::Superseded) => {
            state.set_last_applied(None);
            state.push_banner(
                "Another apply replaced these rules before they were confirmed",
                BannerSeverity::Warning,
            );
            Task::none()
        }
        Err(e) => {
            state.set_last_applied(None);
            push_persistent_banner(state, e.to_string());
            audit_task(audit::log_generic_error(enable_event_log, e.to_string()))
        }
    }
}

/// Handles Save to System button click - starts verification
pub(crate) fn handle_save_to_system_clicked(state: &mut State) -> Task<Message> {
    if state.is_busy() {
        return Task::none();
    }
    if !ruleset_ready_to_apply(state) {
        return Task::none();
    }

    state.status = AppStatus::Verifying;
    let nft_json = state.ruleset.to_nftables_json();

    Task::perform(
        verify_and_locate(state.ruleset.clone(), nft_json),
        Message::SaveToSystemVerifyResult,
    )
}

/// Which rules Save to System writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveSource {
    /// The rules in the editor (what was just verified)
    Editor,
    /// The last rules applied and kept (`State::confirmed_record`)
    LastConfirmed,
}

/// Whether the editor's rules were tried live before they are saved: rules
/// in the system file take effect at the next boot, with no auto-revert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SaveTested {
    /// The editor's rules are the ones last applied and kept: their
    /// nftables JSON is byte for byte the recorded one (the test `drfw save`
    /// uses)
    #[default]
    Tested,
    /// Other rules were applied and kept (and can be saved instead)
    Differs,
    /// No kept rules that could be saved instead: nothing recorded, or a
    /// record from an older DRFW without its ruleset
    NothingApplied,
}

impl SaveTested {
    fn of(editor_json: &serde_json::Value, record: Option<&ConfirmedRecord>) -> Self {
        match record {
            Some(record) if record.matches(editor_json) => Self::Tested,
            Some(record) if record.ruleset().is_some() => Self::Differs,
            _ => Self::NothingApplied,
        }
    }

    /// The warning the dialog shows, if any.
    pub fn warning(self) -> Option<&'static str> {
        match self {
            Self::Tested => None,
            Self::Differs => Some(
                "The rules in the editor differ from the rules you last applied and \
                 kept. Untested rules take effect at the next boot, with no \
                 automatic revert if they lock you out.",
            ),
            Self::NothingApplied => Some(
                "These rules are not the ones last applied and kept on this machine. \
                 They take effect at the next boot, with no automatic revert if they \
                 lock you out. Apply and confirm them first to test them.",
            ),
        }
    }
}

/// Shown in the Save to System dialog when the kept rules it relies on were
/// applied before the current boot (or the record does not say when).
const EARLIER_SESSION_NOTE: &str = "The rules you last applied and kept are from an earlier \
     session (before a reboot, or recorded by an older DRFW), so they may not be the rules \
     running now.";

/// Boot persistence part of the Save to System dialog, prepared in `update()`
/// (the view only reads it).
#[derive(Debug, Clone, Default)]
pub struct SaveToSystemDialog {
    /// Whether the editor's rules were tested live (see [`SaveTested`])
    pub tested: SaveTested,
    /// [`EARLIER_SESSION_NOTE`] when the kept rules predate this boot
    pub earlier_session: Option<&'static str>,
    /// The retention guard's warning for saving the editor's rules
    pub retention: Option<RetentionWarning>,
    /// The SSH lockout check's warning for saving the editor's rules (they
    /// load at the next boot)
    pub lockout: Option<LockoutWarning>,
    /// What `systemctl` said; `None` while it is being asked
    pub boot: Option<BootStatus>,
    /// The line shown in the dialog
    pub boot_text: String,
    /// `boot_text` is a warning: the rules will not (or may not) load at boot
    pub boot_warning: bool,
    /// The "Also enable ... at boot" checkbox is shown
    pub offer_enable: bool,
    /// The checkbox is checked
    pub enable_at_boot: bool,
}

impl SaveToSystemDialog {
    /// The dialog while `systemctl` is being asked.
    fn checking() -> Self {
        Self {
            boot_text: format!(
                "Checking whether {} loads it at boot…",
                crate::SYSTEM_NFT_SERVICE
            ),
            ..Self::default()
        }
    }

    /// Fills in the answer; the checkbox starts checked when the unit is
    /// disabled.
    fn set_boot(&mut self, boot: BootStatus) {
        self.boot_text = boot.summary();
        self.boot_warning = boot.loads_at_boot() != Some(true);
        self.offer_enable = boot.offers_enable();
        self.enable_at_boot = boot.suggests_enable();
        self.boot = Some(boot);
    }

    /// The unit the save script should enable, if the user asked for it.
    fn service_to_enable(&self) -> Option<&'static str> {
        (self.offer_enable && self.enable_at_boot).then_some(crate::SYSTEM_NFT_SERVICE)
    }

    /// Saving the editor's rules takes "Save anyway": the retention guard or
    /// the lockout check warns about them (lockout notes alone do not).
    pub fn editor_needs_confirmation(&self) -> bool {
        self.retention.is_some()
            || self
                .lockout
                .as_ref()
                .is_some_and(LockoutWarning::needs_confirmation)
    }

    /// The dialog's primary (highlighted, Enter) choice: the tested rules.
    /// `None` when only untested rules could be saved, or when the retention
    /// guard or the lockout check warns about the editor's rules; that takes
    /// a click.
    pub fn primary_source(&self) -> Option<SaveSource> {
        match self.tested {
            SaveTested::Tested if !self.editor_needs_confirmation() => Some(SaveSource::Editor),
            SaveTested::Differs => Some(SaveSource::LastConfirmed),
            SaveTested::Tested | SaveTested::NothingApplied => None,
        }
    }
}

/// The Save to System that is running: what it writes, for the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaveInProgress {
    pub source: SaveSource,
    /// The editor's rules were saved without being applied and kept
    pub untested: bool,
}

/// Result of a successful Save to System.
#[derive(Debug, Clone)]
pub struct SaveOutcome {
    /// Where the previous file was backed up, if there was one
    pub backup: Option<String>,
    /// Result of `systemctl enable`, if it was requested
    pub enable: Option<EnableOutcome>,
    /// Boot persistence queried right after the save
    pub boot: BootStatus,
}

/// Handles Save to System verification result
pub(crate) fn handle_save_to_system_verify_result(
    state: &mut State,
    result: Result<VerifyResult, VerifyError>,
) -> Task<Message> {
    if state.status != AppStatus::Verifying {
        return Task::none();
    }
    match result {
        Ok(verify_result) if verify_result.success => {
            // Verification passed - show confirmation modal, then ask systemd
            // (unprivileged) whether the file is loaded at boot
            state.status = AppStatus::AwaitingSaveToSystem;
            clear_verify_errors(state);
            state.save_dialog = SaveToSystemDialog::checking();
            check_save_dialog(state);
            Task::batch([
                Task::perform(
                    crate::core::boot::query_boot_status(),
                    Message::SaveToSystemBootChecked,
                ),
                reload_context_task(state),
            ])
        }
        Ok(verify_result) => {
            state.status = AppStatus::Idle;
            verify_rejected_feedback(state, &verify_result, VerifyPurpose::SaveToSystem)
        }
        Err(e) => {
            // Verification could not run (authentication, nft missing, ...)
            state.status = AppStatus::Idle;
            verify_error_feedback(state, &e)
        }
    }
}

/// Fills the parts of the open Save to System dialog that depend on the kept
/// record and the SSH sessions (when it opens, and when they are re-read).
fn check_save_dialog(state: &mut State) {
    let record = state.confirmed_record.as_ref();
    let dialog = &mut state.save_dialog;
    dialog.tested = SaveTested::of(&state.ruleset.to_nftables_json(), record);
    dialog.earlier_session = record
        .filter(|r| !r.from_this_boot() && dialog.tested != SaveTested::NothingApplied)
        .map(|_| EARLIER_SESSION_NOTE);
    dialog.retention =
        RetentionWarning::check(record.and_then(ConfirmedRecord::ruleset), &state.ruleset);
    dialog.lockout = LockoutWarning::check(&state.ruleset, &state.ssh_sessions);
}

/// Handles the boot persistence answer for the open Save to System dialog
pub(crate) fn handle_save_to_system_boot_checked(state: &mut State, boot: BootStatus) {
    if state.status == AppStatus::AwaitingSaveToSystem && state.save_dialog.boot.is_none() {
        state.save_dialog.set_boot(boot);
    }
}

/// Handles the "Also enable ... at boot" checkbox
pub(crate) fn handle_save_to_system_enable_toggled(state: &mut State, enabled: bool) {
    if state.status == AppStatus::AwaitingSaveToSystem && state.save_dialog.offer_enable {
        state.save_dialog.enable_at_boot = enabled;
    }
}

/// Handles user confirming Save to System - proceeds with file write
///
/// One elevated invocation writes the text to a temp file next to the target,
/// checks it with `nft -c -f`, backs up the existing file, atomically renames
/// the new one into place and, if the checkbox is checked, enables the boot
/// service (see `elevation::SAVE_CONFIG_SCRIPT`). The earlier JSON
/// verification only gates the modal; the text check here is the
/// authoritative one because it covers the exact bytes being installed.
///
/// `source` picks the editor's rules or the last confirmed ones; saving the
/// editor's rules while they differ from the confirmed ones (or nothing was
/// confirmed) is recorded as an untested save in the audit log.
pub(crate) fn handle_save_to_system_confirmed(
    state: &mut State,
    source: SaveSource,
) -> Task<Message> {
    if state.status != AppStatus::AwaitingSaveToSystem {
        return Task::none();
    }
    let text = match source {
        SaveSource::Editor => state.ruleset.to_nft_text(),
        SaveSource::LastConfirmed => {
            let Some(confirmed) = kept_ruleset(state) else {
                tracing::error!("Save of the last confirmed rules without any");
                return Task::none();
            };
            confirmed.to_nft_text()
        }
    };
    let untested = source == SaveSource::Editor && state.save_dialog.tested != SaveTested::Tested;
    state.status = AppStatus::SavingToSystem;
    state.save_in_progress = Some(SaveInProgress { source, untested });
    let enable = state.save_dialog.service_to_enable();

    Task::perform(
        async move {
            let output = crate::core::system_config::write_config_file_and_enable(
                &text,
                crate::SYSTEM_NFT_PATH,
                enable,
            )
            .await
            .map_err(|e| e.to_string())?;
            interpret_elevated_command_output(&output)?;
            Ok(SaveOutcome {
                backup: crate::core::system_config::backup_path_from_output(&output)
                    .map(|p| p.display().to_string()),
                enable: crate::core::system_config::enable_outcome_from_output(&output),
                boot: crate::core::boot::query_boot_status().await,
            })
        },
        Message::SaveToSystemResult,
    )
}

/// Handles user cancelling Save to System modal
pub(crate) fn handle_save_to_system_cancelled(state: &mut State) {
    if state.status == AppStatus::AwaitingSaveToSystem {
        state.status = AppStatus::Idle;
        state.save_dialog = SaveToSystemDialog::default();
    }
}

/// Handles save to system result
///
/// Success: one banner for the saved file (with "Loaded at boot by ..." when
/// the boot service is enabled), plus a warning when enabling failed or the
/// rules will not load at boot.
pub(crate) fn handle_save_to_system_result(
    state: &mut State,
    result: Result<SaveOutcome, String>,
) -> Task<Message> {
    if state.status != AppStatus::SavingToSystem {
        return Task::none();
    }
    state.status = AppStatus::Idle;
    state.save_dialog = SaveToSystemDialog::default();
    let save = state.save_in_progress.take().unwrap_or(SaveInProgress {
        source: SaveSource::Editor,
        untested: false,
    });
    let enable_event_log = state.enable_event_log;
    let target_path = crate::SYSTEM_NFT_PATH.to_string();
    let details = audit::SaveDetails {
        last_confirmed: save.source == SaveSource::LastConfirmed,
        untested: save.untested,
    };

    let outcome = match result {
        Ok(outcome) => outcome,
        Err(e) => {
            if e == AUTH_CANCELLED {
                state.push_banner(
                    "Authentication was cancelled; nothing was saved",
                    BannerSeverity::Warning,
                );
            } else {
                let msg = truncate_error_message("Save failed: ", &e, 80);
                state.push_banner(&msg, BannerSeverity::Error);
            }
            return audit_task(async move {
                audit::log_save_to_system(enable_event_log, false, &target_path, details, Some(e))
                    .await;
            });
        }
    };

    let what = if details.last_confirmed {
        "Last applied rules saved"
    } else {
        "Configuration saved"
    };
    let mut message = match &outcome.backup {
        Some(backup) => format!(
            "{what} to {} (previous file kept as {backup})",
            crate::SYSTEM_NFT_PATH
        ),
        None => format!("{what} to {}", crate::SYSTEM_NFT_PATH),
    };
    let loads_at_boot = outcome.boot.loads_at_boot() == Some(true);
    if loads_at_boot {
        message.push_str(". ");
        message.push_str(&outcome.boot.summary());
    }
    state.push_banner(message, BannerSeverity::Success);

    if let Some(EnableOutcome::Failed(error)) = &outcome.enable {
        let msg = truncate_error_message(
            &format!("Saved, but {} was not enabled: ", crate::SYSTEM_NFT_SERVICE),
            error,
            120,
        );
        state.push_banner(msg, BannerSeverity::Warning);
    } else if !loads_at_boot {
        state.push_banner(
            format!("Saved, but {}", lowercase_first(&outcome.boot.summary())),
            BannerSeverity::Warning,
        );
    }

    let mut tasks = vec![audit_task(async move {
        audit::log_save_to_system(enable_event_log, true, &target_path, details, None).await;
    })];
    if let Some(enable) = outcome.enable {
        tasks.push(audit_task(async move {
            let error = match enable {
                EnableOutcome::Enabled => None,
                EnableOutcome::Failed(error) => Some(error),
            };
            audit::log_enable_at_boot(
                enable_event_log,
                error.is_none(),
                crate::SYSTEM_NFT_SERVICE,
                error,
            )
            .await;
        }));
    }
    Task::batch(tasks)
}

/// `text` with its first character in lowercase ("Could not" -> "could not");
/// unit names and "systemd" already start in lowercase.
fn lowercase_first(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_lowercase().chain(chars).collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::handlers::test_utils::create_test_state;

    // =========================================================================
    // Pure helper function tests
    // =========================================================================

    #[test]
    fn test_truncate_error_message_short() {
        let result = truncate_error_message("Error: ", "short message", 80);
        assert_eq!(result, "Error: short message");
    }

    #[test]
    fn test_truncate_error_message_long() {
        let result =
            truncate_error_message("Error: ", "this is a very long message that exceeds", 30);
        // prefix "Error: " = 7 chars, max 30, available = 30 - 7 - 3 = 20
        assert!(result.len() <= 30);
        assert!(result.ends_with("..."));
        assert!(result.starts_with("Error: "));
    }

    #[test]
    fn test_truncate_error_message_exact_fit() {
        // Message fits within available space (max - prefix - 3 for "...")
        let result = truncate_error_message("", "short", 10);
        assert_eq!(result, "short"); // 5 chars < 10 - 0 - 3 = 7 available
    }

    #[test]
    fn test_truncate_error_message_empty_prefix() {
        let result = truncate_error_message("", "some error", 80);
        assert_eq!(result, "some error");
    }

    #[test]
    fn test_truncate_error_message_multibyte_does_not_panic() {
        // available = 10 - 0 - 3 = 7 bytes; each "é" is 2 bytes, so byte 7
        // falls inside the 4th one and the cut must move back to byte 6.
        let result = truncate_error_message("", "éééééé", 10);
        assert_eq!(result, "ééé...");
        assert!(result.len() <= 10);
    }

    // Helper to create Output with specific exit code and stderr (Unix only)
    #[cfg(unix)]
    fn make_output(exit_code: i32, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(exit_code << 8),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_interpret_elevated_command_success() {
        let output = make_output(0, "");
        assert!(interpret_elevated_command_output(&output).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_interpret_elevated_command_auth_cancelled() {
        let output = make_output(126, "");
        let err = interpret_elevated_command_output(&output).unwrap_err();
        assert!(err.contains("cancelled"), "Expected 'cancelled' in: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn test_interpret_elevated_command_auth_failed() {
        let output = make_output(127, "");
        let err = interpret_elevated_command_output(&output).unwrap_err();
        assert!(err.contains("failed"), "Expected 'failed' in: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn test_interpret_elevated_command_permission_denied() {
        let output = make_output(1, "Permission denied");
        let err = interpret_elevated_command_output(&output).unwrap_err();
        assert!(
            err.contains("Permission denied"),
            "Expected 'Permission denied' in: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_interpret_elevated_command_generic_with_stderr() {
        let output = make_output(1, "some specific error");
        let err = interpret_elevated_command_output(&output).unwrap_err();
        assert!(
            err.contains("some specific error"),
            "Expected stderr in: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_interpret_elevated_command_generic_empty_stderr() {
        let output = make_output(42, "");
        let err = interpret_elevated_command_output(&output).unwrap_err();
        assert!(err.contains("exit code 42"), "Expected exit code in: {err}");
    }

    // =========================================================================
    // Handler tests
    // =========================================================================

    #[test]
    fn test_handle_apply_clicked_idle() {
        let mut state = create_test_state();
        state.status = AppStatus::Idle;
        let _task = handle_apply_clicked(&mut state);
        assert_eq!(state.status, AppStatus::Verifying);
    }

    // =========================================================================
    // Apply flow: snapshot, edit lock, guard outcomes, error classification
    // =========================================================================

    use std::time::Duration;

    use crate::core::test_helpers::create_test_rule;

    fn last_banner(state: &State) -> (&str, BannerSeverity) {
        let banner = state.banners.back().expect("a banner");
        (banner.message.as_str(), banner.severity)
    }

    /// Runs Apply -> verified -> Proceed, with a different ruleset applied before.
    fn state_applying() -> State {
        let mut state = create_test_state();
        let mut previous = FirewallRuleset::new();
        previous.rules.push(create_test_rule("Previous", Some(22)));
        state.set_last_applied(Some(previous));
        state.ruleset.rules.push(create_test_rule("New", Some(80)));
        state.mark_profile_dirty();
        let _ = handle_apply_clicked(&mut state);
        let _ = handle_verify_completed(&mut state, Ok(VerifyResult::success()));
        assert_eq!(state.status, AppStatus::AwaitingApply);
        let _ = handle_proceed_to_apply(&mut state);
        assert_eq!(state.status, AppStatus::Applying);
        state
    }

    fn applied_labels(state: &State) -> Vec<String> {
        state
            .last_applied_ruleset
            .as_ref()
            .map_or_else(Vec::new, |r| {
                r.rules.iter().map(|rule| rule.label.clone()).collect()
            })
    }

    #[test]
    fn test_ruleset_edits_are_refused_while_busy() {
        let mut state = create_test_state();
        state.ruleset.rules.push(create_test_rule("Keep", Some(22)));
        state.mark_profile_dirty();
        let id = state.ruleset.rules[0].id;
        let _ = handle_apply_clicked(&mut state);

        let _ = state.update(Message::ToggleRuleEnabled(id));
        let _ = state.update(Message::DeleteRule(id));
        assert_eq!(state.ruleset.rules.len(), 1);
        assert!(state.ruleset.rules[0].enabled, "edit must be ignored");
        let (message, severity) = last_banner(&state);
        assert!(message.contains("can't be changed"));
        assert_eq!(severity, BannerSeverity::Warning);
        // Repeated attempts (e.g. a slider) do not stack identical banners
        assert_eq!(state.banners.len(), 1);

        // Also locked while the verified ruleset awaits the user's go-ahead
        let _ = handle_verify_completed(&mut state, Ok(VerifyResult::success()));
        assert!(edits_locked(&state));
        state.status = AppStatus::Idle;
        assert!(!edits_locked(&state));
        assert!(!is_ruleset_edit(&Message::ConfirmClicked));
    }

    #[test]
    fn test_rejected_ruleset_opens_the_errors_panel() {
        use crate::core::verify::{ErrorOrigin, VerifyIssue};

        let mut state = create_test_state();
        state.ruleset.rules.push(create_test_rule("Web", Some(80)));
        state.mark_profile_dirty();
        let id = state.ruleset.rules[0].id;
        let rejected = || {
            VerifyResult::failure(vec![VerifyIssue {
                origin: Some(ErrorOrigin::UserRule {
                    id,
                    label: "Web".into(),
                }),
                message: "Service out of range".into(),
                source_line: None,
                caret: None,
            }])
        };

        let _ = handle_apply_clicked(&mut state);
        let _ = handle_verify_completed(&mut state, Ok(rejected()));
        assert_eq!(state.status, AppStatus::Idle);
        assert!(state.apply_session.is_none());
        let (message, severity) = last_banner(&state);
        assert_eq!(message, "nft rejected 1 rule, see details");
        assert_eq!(severity, BannerSeverity::Error);
        assert!(state.show_verify_errors);
        let panel = state.verify_errors.as_ref().expect("panel");
        assert_eq!(panel.rows[0].rule_id, Some(id));

        // Clicking the row opens the rule on top of the panel
        let _ = state.update(Message::EditRuleClicked(id));
        assert!(state.rule_form.is_some());
        let _ = state.update(Message::CancelRuleForm);
        assert!(state.show_verify_errors, "the panel stays open");
        let _ = state.update(Message::ToggleVerifyErrors(false));

        // Save to System reports the same way; a later success clears it
        let _ = handle_save_to_system_clicked(&mut state);
        let _ = handle_save_to_system_verify_result(&mut state, Ok(rejected()));
        assert!(state.show_verify_errors);
        let _ = state.update(Message::ToggleVerifyErrors(false));
        let _ = handle_save_to_system_clicked(&mut state);
        let _ = handle_save_to_system_verify_result(&mut state, Ok(VerifyResult::success()));
        assert!(state.verify_errors.is_none());
    }

    fn boot(enablement: crate::core::boot::Enablement) -> BootStatus {
        BootStatus {
            unit: crate::SYSTEM_NFT_SERVICE.to_string(),
            enablement,
            active: None,
        }
    }

    /// Save to System up to the open dialog
    fn state_awaiting_save() -> State {
        let mut state = create_test_state();
        state.ruleset.rules.push(create_test_rule("Web", Some(80)));
        state.mark_profile_dirty();
        let _ = handle_save_to_system_clicked(&mut state);
        let _ = handle_save_to_system_verify_result(&mut state, Ok(VerifyResult::success()));
        assert_eq!(state.status, AppStatus::AwaitingSaveToSystem);
        state
    }

    #[test]
    fn test_save_dialog_offers_enable_when_the_service_is_disabled() {
        use crate::core::boot::Enablement;

        let mut state = state_awaiting_save();
        assert!(state.save_dialog.boot.is_none(), "still checking");
        assert!(state.save_dialog.boot_text.starts_with("Checking"));
        assert_eq!(state.save_dialog.service_to_enable(), None);

        handle_save_to_system_boot_checked(&mut state, boot(Enablement::Disabled));
        assert!(state.save_dialog.boot_warning);
        assert!(
            state
                .save_dialog
                .boot_text
                .contains("will NOT load at boot")
        );
        assert!(state.save_dialog.offer_enable && state.save_dialog.enable_at_boot);
        assert_eq!(
            state.save_dialog.service_to_enable(),
            Some(crate::SYSTEM_NFT_SERVICE)
        );
        handle_save_to_system_enable_toggled(&mut state, false);
        assert_eq!(state.save_dialog.service_to_enable(), None);

        handle_save_to_system_cancelled(&mut state);
        assert_eq!(state.status, AppStatus::Idle);
        assert!(!state.save_dialog.offer_enable);
        // A late answer for the closed dialog is ignored
        handle_save_to_system_boot_checked(&mut state, boot(Enablement::Disabled));
        assert!(state.save_dialog.boot.is_none());
    }

    #[test]
    fn test_save_dialog_without_checkbox_when_enabled_or_unavailable() {
        use crate::core::boot::Enablement;

        for enablement in [
            Enablement::Enabled,
            Enablement::Masked,
            Enablement::NotFound,
            Enablement::SystemdUnavailable,
        ] {
            let mut state = state_awaiting_save();
            handle_save_to_system_boot_checked(&mut state, boot(enablement.clone()));
            assert!(!state.save_dialog.offer_enable, "{enablement:?}");
            handle_save_to_system_enable_toggled(&mut state, true);
            assert_eq!(
                state.save_dialog.service_to_enable(),
                None,
                "{enablement:?}"
            );
            assert_eq!(
                state.save_dialog.boot_warning,
                enablement != Enablement::Enabled
            );
        }
    }

    #[test]
    fn test_save_result_reports_boot_persistence() {
        use crate::core::boot::Enablement;

        let saved = |state: &mut State, enable, enablement| {
            *state = state_awaiting_save();
            let _ = handle_save_to_system_confirmed(state, SaveSource::Editor);
            assert_eq!(state.status, AppStatus::SavingToSystem);
            let _ = handle_save_to_system_result(
                state,
                Ok(SaveOutcome {
                    backup: None,
                    enable,
                    boot: boot(enablement),
                }),
            );
            assert_eq!(state.status, AppStatus::Idle);
        };
        let mut state = create_test_state();

        // Enabled: one success banner that says so
        saved(
            &mut state,
            Some(EnableOutcome::Enabled),
            Enablement::Enabled,
        );
        assert_eq!(state.banners.len(), 1);
        let (message, severity) = last_banner(&state);
        assert_eq!(severity, BannerSeverity::Success);
        assert!(
            message.ends_with(&format!("Loaded at boot by {}", crate::SYSTEM_NFT_SERVICE)),
            "{message}"
        );

        // Still disabled: saved, plus a warning that nothing loads at boot
        saved(&mut state, None, Enablement::Disabled);
        let (message, severity) = last_banner(&state);
        assert_eq!(severity, BannerSeverity::Warning);
        assert_eq!(
            message,
            format!(
                "Saved, but {} is disabled: the rules will NOT load at boot",
                crate::SYSTEM_NFT_SERVICE
            )
        );

        // Enabling failed: the warning names the failure
        saved(
            &mut state,
            Some(EnableOutcome::Failed("Unit is masked.".into())),
            Enablement::Masked,
        );
        let (message, severity) = last_banner(&state);
        assert_eq!(severity, BannerSeverity::Warning);
        assert!(
            message.contains("was not enabled: Unit is masked."),
            "{message}"
        );
    }

    #[test]
    fn test_lowercase_first() {
        assert_eq!(lowercase_first("Could not check"), "could not check");
        assert_eq!(lowercase_first("nftables.service"), "nftables.service");
        assert_eq!(lowercase_first(""), "");
    }

    #[test]
    fn test_apply_uses_the_verified_snapshot() {
        let mut state = state_applying();
        // An edit that slipped in anyway must not be reported as applied
        state
            .ruleset
            .rules
            .push(create_test_rule("Unverified", Some(81)));
        let _ = handle_apply_result(&mut state, Ok(None));
        assert_eq!(state.status, AppStatus::Idle);
        assert_eq!(applied_labels(&state), vec!["New".to_string()]);
    }

    #[test]
    fn test_stale_results_are_ignored() {
        let mut state = create_test_state();
        let _ = handle_verify_completed(&mut state, Ok(VerifyResult::success()));
        assert_eq!(state.status, AppStatus::Idle, "verify result while idle");
        let _ = handle_apply_result(&mut state, Ok(None));
        assert_eq!(state.status, AppStatus::Idle);
        let _ = handle_guard_finished(&mut state, Ok(GuardOutcome::Reverted));
        assert!(state.banners.is_empty());
    }

    #[test]
    fn test_guarded_apply_then_revert_restores_previous_applied() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state_applying();
        let guard = GuardHandle::new_for_testing(dir.path(), Duration::from_secs(15));
        let _ = handle_apply_result(&mut state, Ok(Some(guard)));
        assert!(matches!(
            state.status,
            AppStatus::PendingConfirmation { .. }
        ));
        assert_eq!(state.countdown_remaining, 15);
        assert_eq!(applied_labels(&state), vec!["New".to_string()]);

        // The guard (not the UI) decides; nothing claims "reverted" before it reports
        state.status = AppStatus::Reverting;
        let _ = handle_guard_finished(&mut state, Ok(GuardOutcome::Reverted));
        assert_eq!(state.status, AppStatus::Idle);
        assert_eq!(applied_labels(&state), vec!["Previous".to_string()]);
        assert!(last_banner(&state).0.contains("reverted"));
    }

    #[test]
    fn test_countdown_tick_uses_monotonic_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = create_test_state();
        state.status = AppStatus::PendingConfirmation {
            guard: GuardHandle::new_for_testing(dir.path(), Duration::from_secs(30)),
        };
        let _ = handle_countdown_tick(&mut state);
        assert_eq!(state.countdown_remaining, 30);
        assert!(matches!(
            state.status,
            AppStatus::PendingConfirmation { .. }
        ));

        // Deadline passed: wait for the guard instead of claiming a revert
        state.status = AppStatus::PendingConfirmation {
            guard: GuardHandle::new_for_testing(dir.path(), Duration::ZERO),
        };
        let _ = handle_countdown_tick(&mut state);
        assert_eq!(state.status, AppStatus::Reverting);
        assert!(!last_banner(&state).0.contains("reverted"));
    }

    #[test]
    fn test_confirm_creates_token_and_waits() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("confirm")).unwrap();
        let mut state = create_test_state();
        state.status = AppStatus::PendingConfirmation {
            guard: GuardHandle::new_for_testing(dir.path(), Duration::from_secs(30)),
        };
        let _ = handle_confirm_clicked(&mut state);
        assert_eq!(state.status, AppStatus::Confirming);
        assert!(
            dir.path()
                .join("confirm/drfw-confirm-0123456789abcdef0123456789abcdef")
                .exists()
        );
        let _ = handle_guard_finished(&mut state, Ok(GuardOutcome::Confirmed));
        assert_eq!(state.status, AppStatus::Idle);
        assert_eq!(last_banner(&state).1, BannerSeverity::Success);
    }

    #[test]
    fn test_revert_failure_is_persistent_and_prominent() {
        let mut state = state_applying();
        let _ = handle_apply_result(&mut state, Ok(None));
        state.status = AppStatus::Reverting;
        let _ = handle_guard_finished(
            &mut state,
            Ok(GuardOutcome::RevertFailed("netlink: busy".to_string())),
        );
        let (message, severity) = last_banner(&state);
        assert!(message.contains("STILL ACTIVE"), "{message}");
        assert_eq!(severity, BannerSeverity::Error);
        // Rules are still the new ones
        assert_eq!(applied_labels(&state), vec!["New".to_string()]);
        // Never expires, and later banners do not push it out
        state.push_banner("one", BannerSeverity::Info);
        state.push_banner("two", BannerSeverity::Info);
        assert!(
            state
                .banners
                .iter()
                .any(|b| b.message.contains("STILL ACTIVE") && !b.is_expired())
        );
    }

    #[test]
    fn test_apply_errors_are_classified_by_type() {
        let cases = [
            (
                ApplyError::Auth(AuthError::Cancelled),
                "cancelled",
                BannerSeverity::Warning,
            ),
            (
                ApplyError::Auth(AuthError::NoAgent),
                "authentication agent",
                BannerSeverity::Error,
            ),
            (
                ApplyError::Rejected("Error: nftables syntax".to_string()),
                "rejected",
                BannerSeverity::Error,
            ),
            (
                ApplyError::GuardNotStarted("x".to_string()),
                "nothing was changed",
                BannerSeverity::Warning,
            ),
            (
                ApplyError::StateUnknown("x".to_string()),
                "MAY BE ACTIVE",
                BannerSeverity::Error,
            ),
        ];
        for (error, expected, severity) in cases {
            let mut state = state_applying();
            let rules_active = error.rules_may_be_active();
            let _ = handle_apply_result(&mut state, Err(error));
            assert_eq!(state.status, AppStatus::Idle);
            let (message, got) = last_banner(&state);
            assert!(message.contains(expected), "{message:?} lacks {expected:?}");
            assert!(!message.contains("not installed"), "{message}");
            assert_eq!(got, severity, "{message}");
            if rules_active {
                assert!(state.last_applied_ruleset.is_none(), "state is unknown");
            } else {
                assert_eq!(applied_labels(&state), vec!["Previous".to_string()]);
            }
        }
    }

    #[test]
    fn test_cancel_apply_keeps_edits_and_drops_snapshot() {
        let mut state = create_test_state();
        state.ruleset.rules.push(create_test_rule("Edit", Some(22)));
        state.mark_profile_dirty();
        let _ = handle_apply_clicked(&mut state);
        let _ = handle_verify_completed(&mut state, Ok(VerifyResult::success()));
        assert_eq!(state.status, AppStatus::AwaitingApply);
        let _ = state.update(Message::CancelApply);
        assert_eq!(state.status, AppStatus::Idle);
        assert!(state.apply_session.is_none());
        assert_eq!(state.ruleset.rules.len(), 1, "edits are kept");
        assert!(state.is_dirty(), "still not applied");
        // Ignored outside the dialog
        state.status = AppStatus::Applying;
        let _ = state.update(Message::CancelApply);
        assert_eq!(state.status, AppStatus::Applying);
    }

    #[test]
    fn test_dirty_cache_follows_apply_and_revert() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state_applying();
        assert!(state.is_dirty());
        let guard = GuardHandle::new_for_testing(dir.path(), Duration::from_secs(15));
        let _ = handle_apply_result(&mut state, Ok(Some(guard)));
        assert!(!state.is_dirty(), "applied ruleset matches the edits");
        state.status = AppStatus::Reverting;
        let _ = handle_guard_finished(&mut state, Ok(GuardOutcome::Reverted));
        assert!(state.is_dirty(), "reverted to the previous rules");
        // Diff old side follows the applied ruleset
        let old = state
            .cached_applied_text
            .as_ref()
            .expect("applied text cached");
        assert!(old.text.contains("Previous"));
    }

    #[test]
    fn test_verify_auth_cancel_says_so() {
        let mut state = create_test_state();
        let _ = handle_apply_clicked(&mut state);
        let _ = handle_verify_completed(&mut state, Err(VerifyError::Auth(AuthError::Cancelled)));
        assert_eq!(state.status, AppStatus::Idle);
        let (message, severity) = last_banner(&state);
        assert!(message.contains("cancelled"));
        assert_eq!(severity, BannerSeverity::Warning);
    }

    // =========================================================================
    // Save to System: tested vs untested rules
    // =========================================================================

    /// Applies the current ruleset and confirms it within the countdown.
    fn apply_and_confirm(state: &mut State) {
        let dir = tempfile::tempdir().unwrap();
        let _ = handle_apply_clicked(state);
        let _ = handle_verify_completed(state, Ok(VerifyResult::success()));
        let _ = handle_proceed_to_apply(state);
        let guard = GuardHandle::new_for_testing(dir.path(), Duration::from_secs(15));
        let _ = handle_apply_result(state, Ok(Some(guard)));
        state.status = AppStatus::Confirming;
        let _ = handle_guard_finished(state, Ok(GuardOutcome::Confirmed));
        assert_eq!(state.status, AppStatus::Idle);
    }

    fn open_save_dialog(state: &mut State) {
        let _ = handle_save_to_system_clicked(state);
        let _ = handle_save_to_system_verify_result(state, Ok(VerifyResult::success()));
        assert_eq!(state.status, AppStatus::AwaitingSaveToSystem);
    }

    #[test]
    fn test_save_to_system_warns_when_nothing_was_applied() {
        let mut state = state_awaiting_save();
        assert!(state.confirmed_record.is_none());
        assert_eq!(state.save_dialog.tested, SaveTested::NothingApplied);
        assert!(
            state
                .save_dialog
                .tested
                .warning()
                .unwrap()
                .contains("next boot")
        );
        assert_eq!(state.save_dialog.primary_source(), None, "no safe default");
        let _ = handle_save_to_system_confirmed(&mut state, SaveSource::LastConfirmed);
        assert_eq!(
            state.status,
            AppStatus::AwaitingSaveToSystem,
            "nothing confirmed to save"
        );
        let _ = handle_save_to_system_confirmed(&mut state, SaveSource::Editor);
        assert_eq!(
            state.save_in_progress,
            Some(SaveInProgress {
                source: SaveSource::Editor,
                untested: true,
            })
        );
    }

    #[test]
    fn test_save_to_system_offers_the_last_confirmed_rules() {
        let mut state = create_test_state();
        state
            .ruleset
            .rules
            .push(create_test_rule("Tested", Some(22)));
        state.mark_profile_dirty();
        apply_and_confirm(&mut state);
        open_save_dialog(&mut state);
        assert_eq!(state.save_dialog.tested, SaveTested::Tested);
        assert_eq!(state.save_dialog.primary_source(), Some(SaveSource::Editor));
        assert!(state.save_dialog.tested.warning().is_none());
        handle_save_to_system_cancelled(&mut state);

        // Edited after confirming: the confirmed rules are the safe choice
        state
            .ruleset
            .rules
            .push(create_test_rule("Untested", Some(23)));
        state.mark_profile_dirty();
        open_save_dialog(&mut state);
        assert_eq!(state.save_dialog.tested, SaveTested::Differs);
        assert_eq!(
            state.save_dialog.primary_source(),
            Some(SaveSource::LastConfirmed)
        );
        let _ = handle_save_to_system_confirmed(&mut state, SaveSource::LastConfirmed);
        assert_eq!(state.status, AppStatus::SavingToSystem);
        assert_eq!(
            state.save_in_progress,
            Some(SaveInProgress {
                source: SaveSource::LastConfirmed,
                untested: false,
            })
        );
        let _ = handle_save_to_system_result(
            &mut state,
            Ok(SaveOutcome {
                backup: None,
                enable: None,
                boot: boot(crate::core::boot::Enablement::Enabled),
            }),
        );
        assert!(state.save_in_progress.is_none());
        assert!(
            last_banner(&state)
                .0
                .starts_with("Last applied rules saved"),
            "{:?}",
            state.banners
        );
    }

    /// Only a confirmed (or deliberately unguarded) apply counts as tested:
    /// a rollback or a failed revert never does.
    #[test]
    fn test_last_confirmed_only_follows_kept_rules() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state_applying();
        let guard = GuardHandle::new_for_testing(dir.path(), Duration::from_secs(15));
        let _ = handle_apply_result(&mut state, Ok(Some(guard)));
        state.status = AppStatus::Reverting;
        let _ = handle_guard_finished(
            &mut state,
            Ok(GuardOutcome::RevertFailed("busy".to_string())),
        );
        assert!(
            state.confirmed_record.is_none(),
            "still active, never confirmed"
        );

        // Auto-revert off: applied without a guard, kept by choice
        let mut state = state_applying();
        let _ = handle_apply_result(&mut state, Ok(None));
        let record = state.confirmed_record.as_ref().expect("kept");
        assert_eq!(record.kind(), RecordKind::Unguarded);
        assert_eq!(record.ruleset().expect("ruleset").rules[0].label, "New");
        assert!(record.matches(&state.ruleset.to_nftables_json()));

        // Confirmed in time: recorded as confirmed
        let mut state = create_test_state();
        state.ruleset.rules.push(create_test_rule("Kept", Some(22)));
        state.mark_profile_dirty();
        apply_and_confirm(&mut state);
        let record = state.confirmed_record.as_ref().expect("kept");
        assert_eq!(record.kind(), RecordKind::Confirmed);
        assert!(record.from_this_boot() || crate::core::confirmed::current_boot_id().is_none());
    }

    /// The record loaded at startup (shared with the CLI) drives the Save to
    /// System dialog: the same JSON bytes are "tested", and a record from an
    /// earlier boot says so.
    #[test]
    fn test_save_dialog_uses_the_persisted_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = create_test_state();
        state.ruleset.rules.push(create_test_rule("Web", Some(80)));
        state.mark_profile_dirty();
        let record = ConfirmedRecord::new(
            &state.ruleset.to_nftables_json(),
            &state.ruleset,
            RecordKind::Confirmed,
        )
        .unwrap();
        // As written by another process during an earlier boot
        let path = dir
            .path()
            .join(crate::core::confirmed::CONFIRMED_RULESET_FILE);
        crate::utils::block_on_async(record.save_in(dir.path()));
        let mut file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file["boot_id"] = serde_json::json!("earlier-boot");
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        state.confirmed_record = ConfirmedRecord::load_from_blocking(dir.path());

        open_save_dialog(&mut state);
        assert_eq!(state.save_dialog.tested, SaveTested::Tested);
        assert_eq!(
            state.save_dialog.earlier_session,
            Some(EARLIER_SESSION_NOTE)
        );
        assert_eq!(state.save_dialog.primary_source(), Some(SaveSource::Editor));
        handle_save_to_system_cancelled(&mut state);

        // This boot: no note
        state.confirmed_record = Some(record);
        open_save_dialog(&mut state);
        assert_eq!(
            state.save_dialog.earlier_session,
            crate::core::confirmed::current_boot_id()
                .is_none()
                .then_some(EARLIER_SESSION_NOTE)
        );
    }

    /// A state whose last kept ruleset has `count` enabled rules, with the
    /// editor holding the same rules.
    fn state_with_kept_rules(count: u16) -> State {
        let mut state = create_test_state();
        for i in 0..count {
            state
                .ruleset
                .rules
                .push(create_test_rule(&format!("rule{i}"), Some(1000 + i)));
        }
        state.mark_profile_dirty();
        state.confirmed_record = Some(
            ConfirmedRecord::new(
                &state.ruleset.to_nftables_json(),
                &state.ruleset,
                RecordKind::Confirmed,
            )
            .unwrap(),
        );
        state
    }

    #[test]
    fn test_retention_guard_needs_apply_anyway() {
        let mut state = state_with_kept_rules(5);
        state.ruleset.rules.truncate(2);
        state.mark_profile_dirty();
        let _ = handle_apply_clicked(&mut state);
        let _ = handle_verify_completed(&mut state, Ok(VerifyResult::success()));
        assert_eq!(state.status, AppStatus::AwaitingApply);
        let warning = state
            .apply_session
            .as_ref()
            .and_then(ApplySession::retention)
            .expect("3 of 5 removed")
            .clone();
        assert_eq!(warning.removed_count, 3);
        assert!(
            warning.lines[0].contains("\"rule2\", \"rule3\", \"rule4\""),
            "{warning:?}"
        );

        // Enter (ProceedToApply) is refused, with a hint
        let _ = state.update(Message::ProceedToApply);
        assert_eq!(state.status, AppStatus::AwaitingApply);
        assert!(last_banner(&state).0.contains("Apply anyway"));
        let _ = state.update(Message::ProceedToApply);
        assert_eq!(state.banners.len(), 1, "the hint is not repeated");

        // The button goes ahead
        let _ = state.update(Message::ProceedToApplyAnyway);
        assert_eq!(state.status, AppStatus::Applying);
    }

    #[test]
    fn test_retention_guard_stays_quiet_for_small_changes() {
        let mut state = state_with_kept_rules(10);
        state.ruleset.rules.truncate(7); // 3 of 10
        state.mark_profile_dirty();
        let _ = handle_apply_clicked(&mut state);
        let _ = handle_verify_completed(&mut state, Ok(VerifyResult::success()));
        assert!(state.apply_session.as_ref().unwrap().retention().is_none());
        let _ = state.update(Message::ProceedToApply);
        assert_eq!(state.status, AppStatus::Applying);
    }

    #[test]
    fn test_retention_guard_in_save_dialog() {
        let mut state = state_with_kept_rules(4);
        for rule in &mut state.ruleset.rules[..3] {
            rule.enabled = false;
        }
        state.ruleset.advanced_security.block_forwarding = true;
        state.mark_profile_dirty();
        open_save_dialog(&mut state);
        assert_eq!(state.save_dialog.tested, SaveTested::Differs);
        let retention = state.save_dialog.retention.as_ref().expect("warns");
        assert_eq!(retention.removed_count, 3);
        assert!(retention.enables_block_forwarding);
        assert_eq!(retention.lines.len(), 2);
        // Enter saves the kept rules, never the editor's
        assert_eq!(
            state.save_dialog.primary_source(),
            Some(SaveSource::LastConfirmed)
        );
    }

    /// Even if the editor's rules were the tested ones, a retention warning
    /// takes the Enter shortcut away from them.
    #[test]
    fn test_retention_warning_is_never_the_enter_choice() {
        let mut server = FirewallRuleset::new();
        server.advanced_security.egress_profile = crate::core::firewall::EgressProfile::Server;
        let dialog = SaveToSystemDialog {
            tested: SaveTested::Tested,
            retention: RetentionWarning::check(None, &server),
            ..SaveToSystemDialog::default()
        };
        assert!(dialog.retention.is_some());
        assert_eq!(dialog.primary_source(), None);
    }

    // =========================================================================
    // SSH lockout check and the reloaded record
    // =========================================================================

    /// An SSH session from 10.0.0.5 to port 22 of this computer.
    fn ssh_session() -> SshSession {
        crate::core::lockout::parse_ssh_connection("10.0.0.5 50000 10.0.0.1 22").unwrap()
    }

    fn context(
        state: &State,
        record: Option<ConfirmedRecord>,
        sessions: Vec<SshSession>,
    ) -> ApplyContext {
        ApplyContext {
            record_generation: state.confirmed_record_generation,
            record,
            sessions,
        }
    }

    fn record_of(ruleset: &FirewallRuleset) -> ConfirmedRecord {
        ConfirmedRecord::new(&ruleset.to_nftables_json(), ruleset, RecordKind::Confirmed).unwrap()
    }

    #[test]
    fn test_lockout_warning_needs_apply_anyway() {
        let mut state = create_test_state();
        state.ssh_sessions = vec![ssh_session()];
        // Nothing allows port 22: the client could not reconnect
        state.ruleset.rules.push(create_test_rule("Web", Some(80)));
        state.mark_profile_dirty();
        let _ = handle_apply_clicked(&mut state);
        let _ = handle_verify_completed(&mut state, Ok(VerifyResult::success()));
        let session = state.apply_session.as_ref().expect("session");
        assert!(session.retention().is_none());
        let warning = session.lockout().expect("lockout").clone();
        assert!(session.needs_confirmation());
        assert!(
            warning.lines[0].starts_with("You are connected from 10.0.0.5 to port 22"),
            "{warning:?}"
        );
        assert!(warning.lines[0].contains("BLOCKED"), "{warning:?}");

        let _ = state.update(Message::ProceedToApply);
        assert_eq!(state.status, AppStatus::AwaitingApply, "Enter is refused");
        assert!(last_banner(&state).0.contains("Apply anyway"));
        let _ = state.update(Message::ProceedToApplyAnyway);
        assert_eq!(state.status, AppStatus::Applying);
    }

    #[test]
    fn test_lockout_check_quiet_when_ssh_is_allowed() {
        let mut state = create_test_state();
        state.ssh_sessions = vec![ssh_session()];
        state.ruleset.rules.push(create_test_rule("SSH", Some(22)));
        state.mark_profile_dirty();
        let _ = handle_apply_clicked(&mut state);
        let _ = handle_verify_completed(&mut state, Ok(VerifyResult::success()));
        assert!(!state.apply_session.as_ref().unwrap().needs_confirmation());
        let _ = state.update(Message::ProceedToApply);
        assert_eq!(state.status, AppStatus::Applying);
    }

    /// Adds `rule` to the editor, clicks Apply, passes the verification and
    /// returns the session of the "Commit Changes?" dialog.
    fn apply_dialog_with(state: &mut State, rule: crate::core::firewall::Rule) -> &ApplySession {
        state.ruleset.rules.push(rule);
        state.mark_profile_dirty();
        let _ = handle_apply_clicked(state);
        let _ = handle_verify_completed(state, Ok(VerifyResult::success()));
        state.apply_session.as_ref().expect("session")
    }

    /// A rate-limited SSH accept (the recommended setup) is a note in the
    /// dialog: "Apply" and Enter work, no "Apply anyway".
    #[test]
    fn test_lockout_limited_ssh_is_a_note_without_confirmation() {
        let mut state = create_test_state();
        state.ssh_sessions = vec![ssh_session()];
        let mut ssh = create_test_rule("SSH", Some(22));
        ssh.rate_limit = Some(crate::core::firewall::RateLimit {
            count: 3,
            unit: crate::core::firewall::TimeUnit::Minute,
            burst: None,
            per_source: true,
        });
        ssh.rebuild_caches();
        let session = apply_dialog_with(&mut state, ssh);
        assert!(!session.needs_confirmation());
        let lockout = session.lockout().expect("a note");
        assert!(lockout.lines.is_empty(), "{lockout:?}");
        assert_eq!(lockout.notes.len(), 1);
        assert!(
            lockout.notes[0].contains("accepted up to 3/minute per source by rule \"SSH\""),
            "{lockout:?}"
        );
        let _ = state.update(Message::ProceedToApply);
        assert_eq!(state.status, AppStatus::Applying);
    }

    /// "SSH on eth0 only": allowed when the session's server address is on
    /// eth0, blocked (confirmation) when it is on another interface, and
    /// "blocked in some cases" (confirmation) when the interface is unknown.
    #[test]
    fn test_lockout_interface_bound_ssh_with_resolved_interface() {
        let mut on_eth0 = create_test_rule("SSH on eth0", Some(22));
        on_eth0.interface = Some("eth0".into());
        on_eth0.rebuild_caches();
        for (interface, confirm) in [(Some("eth0"), false), (Some("wlan0"), true), (None, true)] {
            let mut state = create_test_state();
            let mut session = ssh_session();
            session.interface = interface.map(str::to_owned);
            state.ssh_sessions = vec![session];
            let apply = apply_dialog_with(&mut state, on_eth0.clone());
            assert_eq!(apply.needs_confirmation(), confirm, "{interface:?}");
            if confirm {
                let _ = state.update(Message::ProceedToApply);
                assert_eq!(state.status, AppStatus::AwaitingApply, "{interface:?}");
            } else {
                assert!(apply.lockout().is_none(), "{:?}", apply.lockout());
                let _ = state.update(Message::ProceedToApply);
                assert_eq!(state.status, AppStatus::Applying);
            }
        }
    }

    /// The sessions found off the UI thread replace the known ones and the
    /// open dialog's warning follows them, both ways.
    #[test]
    fn test_lockout_recomputed_when_sessions_arrive() {
        let mut state = create_test_state();
        let _ = handle_apply_clicked(&mut state);
        assert!(state.apply_session.as_ref().unwrap().lockout().is_none());
        let found = context(&state, None, vec![ssh_session()]);
        let _ = state.update(Message::ApplyContextLoaded(Some(Box::new(found))));
        assert_eq!(state.ssh_sessions, [ssh_session()]);
        assert!(state.apply_session.as_ref().unwrap().lockout().is_some());

        let _ = handle_verify_completed(&mut state, Ok(VerifyResult::success()));
        let gone = context(&state, None, Vec::new());
        handle_apply_context_loaded(&mut state, gone);
        assert!(!state.apply_session.as_ref().unwrap().needs_confirmation());
        let _ = state.update(Message::ProceedToApply);
        assert_eq!(state.status, AppStatus::Applying);
        // A failed reload changes nothing
        let _ = state.update(Message::ApplyContextLoaded(None));
        assert_eq!(state.status, AppStatus::Applying);
    }

    #[test]
    fn test_lockout_in_save_dialog() {
        let mut state = state_with_kept_rules(2);
        state.ssh_sessions = vec![ssh_session()];
        open_save_dialog(&mut state);
        assert_eq!(state.save_dialog.tested, SaveTested::Tested);
        assert!(state.save_dialog.retention.is_none());
        assert!(
            state.save_dialog.lockout.is_some(),
            "the saved rules block SSH"
        );
        assert!(state.save_dialog.editor_needs_confirmation());
        assert_eq!(state.save_dialog.primary_source(), None, "takes a click");
    }

    /// A `drfw apply` in a terminal kept other rules while the GUI was open:
    /// the record re-read when Apply starts replaces the stale one and the
    /// retention guard follows it.
    #[test]
    fn test_record_reloaded_when_apply_starts() {
        let mut state = state_with_kept_rules(1);
        let mut on_disk = FirewallRuleset::new();
        for i in 0..5 {
            on_disk
                .rules
                .push(create_test_rule(&format!("cli{i}"), Some(2000 + i)));
        }
        let _ = handle_apply_clicked(&mut state);
        assert!(state.apply_session.as_ref().unwrap().retention().is_none());
        let reloaded = context(&state, Some(record_of(&on_disk)), Vec::new());
        let _ = state.update(Message::ApplyContextLoaded(Some(Box::new(reloaded))));
        let kept = kept_ruleset(&state).expect("reloaded");
        assert_eq!(kept.rules.len(), 5);
        let retention = state
            .apply_session
            .as_ref()
            .unwrap()
            .retention()
            .expect("5 of 5 removed");
        assert_eq!(retention.removed_count, 5);
    }

    /// The reloaded record updates an open Save to System dialog; one that
    /// arrives after the dialog closed is only stored.
    #[test]
    fn test_record_reloaded_for_save_dialog_and_after_it_closed() {
        let mut state = create_test_state();
        state.ruleset.rules.push(create_test_rule("Web", Some(80)));
        state.mark_profile_dirty();
        open_save_dialog(&mut state);
        assert_eq!(state.save_dialog.tested, SaveTested::NothingApplied);
        let reloaded = context(&state, Some(record_of(&state.ruleset)), Vec::new());
        handle_apply_context_loaded(&mut state, reloaded);
        assert_eq!(
            state.save_dialog.tested,
            SaveTested::Tested,
            "kept from a terminal"
        );
        assert_eq!(state.save_dialog.primary_source(), Some(SaveSource::Editor));

        handle_save_to_system_cancelled(&mut state);
        let mut other = FirewallRuleset::new();
        other.rules.push(create_test_rule("Other", Some(81)));
        let late = context(&state, Some(record_of(&other)), vec![ssh_session()]);
        handle_apply_context_loaded(&mut state, late);
        assert_eq!(state.status, AppStatus::Idle);
        assert_eq!(state.save_dialog.tested, SaveTested::default());
        assert!(
            state.save_dialog.lockout.is_none(),
            "closed dialog untouched"
        );
        assert!(
            state
                .confirmed_record
                .as_ref()
                .unwrap()
                .matches(&other.to_nftables_json())
        );
        assert_eq!(state.ssh_sessions, [ssh_session()]);
    }

    /// A reload started before this GUI kept rules itself is older: it must
    /// not overwrite the new record.
    #[test]
    fn test_stale_record_reload_does_not_overwrite_a_newer_keep() {
        let mut state = create_test_state();
        state.ruleset.rules.push(create_test_rule("Web", Some(80)));
        state.mark_profile_dirty();
        let old_reload = context(&state, None, vec![ssh_session()]);
        apply_and_confirm(&mut state);
        assert!(state.confirmed_record.is_some(), "kept");
        handle_apply_context_loaded(&mut state, old_reload);
        assert!(
            state
                .confirmed_record
                .as_ref()
                .is_some_and(|r| r.matches(&state.ruleset.to_nftables_json())),
            "the record kept by this GUI stays"
        );
        assert_eq!(
            state.ssh_sessions,
            [ssh_session()],
            "sessions are always fresh"
        );
    }

    /// The "may be active" banner fits the banner; the full explanation is in
    /// the details panel, opened at once.
    #[test]
    fn test_state_unknown_banner_is_short_with_details_panel() {
        assert!(STATE_UNKNOWN_BANNER.len() <= 120);
        assert!(STATE_UNKNOWN_BANNER.starts_with("New rules MAY BE ACTIVE"));
        let detail = "The apply script (running as root) did not finish within 90 seconds. \
                      If the rules were applied with auto-revert, they revert on their own \
                      when the countdown ends.";
        let mut state = state_applying();
        let _ = handle_apply_result(
            &mut state,
            Err(ApplyError::StateUnknown(detail.to_string())),
        );
        assert_eq!(last_banner(&state).0, STATE_UNKNOWN_BANNER);
        assert!(state.show_verify_errors);
        let panel = state.verify_errors.as_ref().expect("details");
        assert_eq!(panel.title, "Apply Details");
        assert!(panel.summary.contains("MAY BE ACTIVE"));
        assert_eq!(panel.rows[0].message, detail);
        assert_eq!(panel.rows[0].edit_rule_id(), None);
        assert!(panel.next_step.contains("nft list table inet drfw"));
    }

    #[test]
    fn test_save_errors_panel_says_save_again() {
        use crate::core::verify::VerifyIssue;
        let mut state = create_test_state();
        let _ = handle_save_to_system_clicked(&mut state);
        let _ = handle_save_to_system_verify_result(
            &mut state,
            Ok(VerifyResult::failure(vec![VerifyIssue::unlocated("bad")])),
        );
        let panel = state.verify_errors.as_ref().expect("panel");
        assert!(panel.next_step.contains("save to system again"));
        assert!(panel.next_step.contains("Nothing was saved"));
    }

    #[test]
    fn test_cancelled_save_authentication_is_a_warning() {
        let mut state = state_awaiting_save();
        let _ = handle_save_to_system_confirmed(&mut state, SaveSource::Editor);
        let _ = handle_save_to_system_result(&mut state, Err(AUTH_CANCELLED.to_string()));
        let (message, severity) = last_banner(&state);
        assert_eq!(severity, BannerSeverity::Warning);
        assert!(message.contains("nothing was saved"));
    }

    #[test]
    fn test_countdown_label_follows_the_countdown() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state_applying();
        let guard = GuardHandle::new_for_testing(dir.path(), Duration::from_secs(15));
        let _ = handle_apply_result(&mut state, Ok(Some(guard)));
        assert_eq!(state.countdown_display, "15");
        assert_eq!(state.settings_display.apply_timer_secs, "15");
    }
}
