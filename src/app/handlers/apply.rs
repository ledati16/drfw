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

use super::audit_task;
use crate::app::{AppStatus, BannerSeverity, Message, State};
use crate::audit;
use crate::core::apply_guard::{ApplyError, GuardError, GuardHandle, GuardOutcome};
use crate::core::firewall::FirewallRuleset;
use crate::core::verify::{VerifyError, VerifyResult};
use crate::elevation::AuthError;
use iced::Task;
use std::time::Instant;

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
        Err("Authentication cancelled".into())
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
}

/// Longest banner text for apply errors.
const BANNER_MAX_LEN: usize = 100;

/// Banner lifetime that never expires (dismiss by clicking it).
const PERSISTENT_BANNER_SECS: u64 = u64::MAX;

/// Pushes an error banner that stays until the user dismisses it.
fn push_persistent_banner(state: &mut State, message: String) {
    state.push_banner(message, BannerSeverity::Error);
    if let Some(banner) = state.banners.back_mut() {
        banner.duration_secs = PERSISTENT_BANNER_SECS;
    }
}

/// The revert timeout to use, or 0 when auto-revert is disabled.
fn guard_timeout_secs(state: &State) -> u64 {
    if state.auto_revert_enabled {
        state.auto_revert_timeout_secs.clamp(1, 120)
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

/// True while the apply flow (or Save to System) owns the ruleset.
pub(crate) fn edits_locked(state: &State) -> bool {
    state.is_busy() || state.status == AppStatus::AwaitingApply
}

/// Messages that change the ruleset (or switch to another one).
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
            | Message::ProfileSwitched(..)
            | Message::SaveProfileAs(_)
            | Message::ConfirmProfileSwitch
            | Message::DiscardProfileSwitch
            | Message::CreateEmptyProfile
            | Message::ProfileCreated(..)
            | Message::StartFreshProfile
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
    let payload = json.clone();
    state.apply_session = Some(ApplySession {
        verified,
        json,
        previous_applied: None,
    });
    state.status = AppStatus::Verifying;

    Task::perform(
        crate::core::verify::verify_ruleset(payload),
        Message::VerifyCompleted,
    )
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
            audit_task(audit::log_verify(enable_event_log, true, 0, None))
        }
        Ok(verify_result) => {
            state.status = AppStatus::Idle;
            state.apply_session = None;
            let error_summary = if verify_result.errors.is_empty() {
                "Ruleset verification failed".to_string()
            } else {
                format!(
                    "Ruleset verification failed: {} errors",
                    verify_result.errors.len()
                )
            };
            state.push_banner(&error_summary, BannerSeverity::Error);
            let error_count = verify_result.errors.len();
            let error = Some(verify_result.errors.join("; "));
            audit_task(audit::log_verify(
                enable_event_log,
                false,
                error_count,
                error,
            ))
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

/// Handles proceeding to apply after successful verification
pub(crate) fn handle_proceed_to_apply(state: &mut State) -> Task<Message> {
    if state.status != AppStatus::AwaitingApply {
        return Task::none();
    }
    let Some(session) = state.apply_session.as_mut() else {
        tracing::error!("ProceedToApply without a verified ruleset");
        state.status = AppStatus::Idle;
        return Task::none();
    };
    session
        .previous_applied
        .clone_from(&state.last_applied_ruleset);

    state.status = AppStatus::Applying;
    let json = session.json.clone();
    let rule_count = session.verified.rules.len();
    let enabled_count = session.verified.rules.iter().filter(|r| r.enabled).count();
    let enable_event_log = state.enable_event_log;
    let timeout_secs = guard_timeout_secs(state);

    Task::perform(
        async move {
            let result = crate::core::apply_guard::apply_guarded(&json, timeout_secs).await;
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
        state.status = AppStatus::Idle;
        state.apply_session = None;
        state.push_banner(
            "Firewall rules applied successfully!",
            BannerSeverity::Success,
        );
        return Task::none();
    };

    let timeout = guard.timeout();
    state.countdown_remaining = u32::try_from(timeout.as_secs()).unwrap_or(u32::MAX);
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
        ApplyError::GuardFailedRulesActive(_) => {
            push_persistent_banner(state, truncate_error_message("", &error.to_string(), 160));
        }
        ApplyError::GuardFailedRolledBack(_) => state.push_banner(
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
    let remaining = guard.remaining_secs(Instant::now());
    state.countdown_remaining = u32::try_from(remaining).unwrap_or(u32::MAX);

    if remaining > 0 {
        if remaining == 5 {
            state.push_banner(
                "Firewall will revert in 5 seconds! Click Confirm to keep changes.",
                BannerSeverity::Warning,
            );
        }
        return Task::none();
    }

    let guard = guard.clone();
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
    let previous_applied = state
        .apply_session
        .take()
        .and_then(|session| session.previous_applied);
    let enable_event_log = state.enable_event_log;
    let timeout_secs = guard_timeout_secs(state);

    match result {
        Ok(GuardOutcome::Confirmed) => {
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
        crate::core::verify::verify_ruleset(nft_json),
        Message::SaveToSystemVerifyResult,
    )
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
            // Verification passed - show confirmation modal
            state.status = AppStatus::AwaitingSaveToSystem;
            Task::none()
        }
        Ok(verify_result) => {
            // Verification failed
            state.status = AppStatus::Idle;
            let error_summary = if verify_result.errors.is_empty() {
                "Verification failed".to_string()
            } else {
                verify_result.errors.join("; ")
            };
            let msg = truncate_error_message("Cannot save - invalid config: ", &error_summary, 80);
            state.push_banner(&msg, BannerSeverity::Error);
            let enable_event_log = state.enable_event_log;
            let error_count = verify_result.errors.len();
            let error = Some(error_summary);
            audit_task(audit::log_verify(
                enable_event_log,
                false,
                error_count,
                error,
            ))
        }
        Err(e) => {
            // Verification could not run (authentication, nft missing, ...)
            state.status = AppStatus::Idle;
            verify_error_feedback(state, &e)
        }
    }
}

/// Handles user confirming Save to System - proceeds with file write
///
/// One elevated invocation writes the text to a temp file next to the target,
/// checks it with `nft -c -f`, backs up the existing file and atomically
/// renames the new one into place (see `elevation::SAVE_CONFIG_SCRIPT`). The
/// earlier JSON verification only gates the modal; the text check here is the
/// authoritative one because it covers the exact bytes being installed.
pub(crate) fn handle_save_to_system_confirmed(state: &mut State) -> Task<Message> {
    if state.status != AppStatus::AwaitingSaveToSystem {
        return Task::none();
    }
    state.status = AppStatus::SavingToSystem;

    let text = state.ruleset.to_nft_text();

    Task::perform(
        async move {
            let output =
                crate::core::system_config::write_config_file(&text, crate::SYSTEM_NFT_PATH)
                    .await
                    .map_err(|e| e.to_string())?;
            interpret_elevated_command_output(&output)?;
            Ok(crate::core::system_config::backup_path_from_output(&output)
                .map(|p| p.display().to_string()))
        },
        Message::SaveToSystemResult,
    )
}

/// Handles user cancelling Save to System modal
pub(crate) fn handle_save_to_system_cancelled(state: &mut State) {
    if state.status == AppStatus::AwaitingSaveToSystem {
        state.status = AppStatus::Idle;
    }
}

/// Handles save to system result
pub(crate) fn handle_save_to_system_result(
    state: &mut State,
    result: Result<Option<String>, String>,
) -> Task<Message> {
    if state.status != AppStatus::SavingToSystem {
        return Task::none();
    }
    state.status = AppStatus::Idle;
    let enable_event_log = state.enable_event_log;
    let target_path = crate::SYSTEM_NFT_PATH.to_string();

    match result {
        Ok(backup) => {
            let message = match backup {
                Some(backup) => format!(
                    "Configuration saved to {} (previous file kept as {backup})",
                    crate::SYSTEM_NFT_PATH
                ),
                None => format!("Configuration saved to {}", crate::SYSTEM_NFT_PATH),
            };
            state.push_banner(message, BannerSeverity::Success);
            audit_task(async move {
                audit::log_save_to_system(enable_event_log, true, &target_path, None).await;
            })
        }
        Err(e) => {
            let msg = truncate_error_message("Save failed: ", &e, 80);
            state.push_banner(&msg, BannerSeverity::Error);
            audit_task(async move {
                audit::log_save_to_system(enable_event_log, false, &target_path, Some(e)).await;
            })
        }
    }
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

    use crate::core::test_helpers::create_test_rule;
    use std::time::Duration;

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
                ApplyError::GuardFailedRolledBack("x".to_string()),
                "rolled back",
                BannerSeverity::Warning,
            ),
            (
                ApplyError::GuardFailedRulesActive("x".to_string()),
                "STILL ACTIVE",
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
}
