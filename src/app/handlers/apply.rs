//! Apply, verify, and revert workflow
//!
//! Handles the complete firewall application lifecycle:
//! - Verification of rules before application
//! - Elevated application with snapshot creation
//! - Auto-revert countdown and confirmation
//! - Manual revert operations
//! - Save to system configuration

use crate::app::{AppStatus, BannerSeverity, Message, State};
use crate::audit;
use chrono::Utc;
use iced::Task;
use std::time::Duration;
use tracing::warn;

// ============================================================================
// Helper Functions
// ============================================================================

/// Truncates an error message to fit within a maximum length, adding ellipsis if needed.
/// The prefix is always included, and the message is truncated to fit.
fn truncate_error_message(prefix: &str, message: &str, max_total_len: usize) -> String {
    let available = max_total_len.saturating_sub(prefix.len()).saturating_sub(3); // 3 for "..."
    if message.len() > available {
        format!("{prefix}{}...", &message[..available])
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
        Err("Authentication failed".into())
    } else if stderr.contains("Permission denied") {
        Err("Permission denied (check polkit configuration)".into())
    } else if stderr.is_empty() {
        Err(format!("Command failed (exit code {exit_code})"))
    } else {
        Err(format!("Command failed: {}", stderr.trim()))
    }
}

/// Checks if a polkit agent is available. Returns an error task with banner if not.
fn require_polkit_agent(state: &mut State) -> Result<(), Task<Message>> {
    if crate::elevation::is_polkit_agent_running() {
        Ok(())
    } else {
        state.push_banner(
            "No polkit agent running. Install and start an authentication agent.",
            BannerSeverity::Error,
        );
        Err(Task::none())
    }
}

/// Handles apply button click (starts verification)
pub(crate) fn handle_apply_clicked(state: &mut State) -> Task<Message> {
    if state.is_busy() {
        return Task::none();
    }

    if let Err(task) = require_polkit_agent(state) {
        return task;
    }

    state.status = AppStatus::Verifying;
    let nft_json = state.ruleset.to_nftables_json();

    Task::perform(
        async move {
            crate::core::verify::verify_ruleset(nft_json)
                .await
                .map_err(|e| e.to_string())
        },
        Message::VerifyCompleted,
    )
}

/// Handles verification completion
pub(crate) fn handle_verify_completed(
    state: &mut State,
    result: Result<crate::core::verify::VerifyResult, String>,
) -> Task<Message> {
    match result {
        Ok(verify_result) if verify_result.success => {
            state.status = AppStatus::AwaitingApply;
            let enable_event_log = state.enable_event_log;
            let error_count = verify_result.errors.len();
            Task::perform(
                async move {
                    audit::log_verify(enable_event_log, true, error_count, None).await;
                },
                |()| Message::AuditLogWritten,
            )
        }
        Ok(verify_result) => {
            state.status = AppStatus::Idle;
            let error_summary = if verify_result.errors.is_empty() {
                "Ruleset verification failed".to_string()
            } else {
                format!(
                    "Ruleset verification failed: {} errors",
                    verify_result.errors.len()
                )
            };
            state.push_banner(&error_summary, BannerSeverity::Error);
            let enable_event_log = state.enable_event_log;
            let error_count = verify_result.errors.len();
            let error = Some(verify_result.errors.join("; "));
            Task::perform(
                async move {
                    audit::log_verify(enable_event_log, false, error_count, error).await;
                },
                |()| Message::AuditLogWritten,
            )
        }
        Err(e) => {
            state.status = AppStatus::Idle;
            let msg = truncate_error_message("Verification error: ", &e, 80);
            state.push_banner(&msg, BannerSeverity::Error);
            let enable_event_log = state.enable_event_log;
            Task::perform(
                async move {
                    audit::log_verify(enable_event_log, false, 0, Some(e)).await;
                },
                |()| Message::AuditLogWritten,
            )
        }
    }
}

/// Handles proceeding to apply after successful verification
pub(crate) fn handle_proceed_to_apply(state: &mut State) -> Task<Message> {
    state.status = AppStatus::Applying;
    let nft_json = state.ruleset.to_nftables_json();
    let rule_count = state.ruleset.rules.len();
    let enabled_count = state.ruleset.rules.iter().filter(|r| r.enabled).count();
    let enable_event_log = state.enable_event_log;

    Task::perform(
        async move {
            let result = crate::core::nft_json::apply_with_snapshot(nft_json).await;
            let success = result.is_ok();
            let error = result.as_ref().err().map(std::string::ToString::to_string);
            audit::log_apply(
                enable_event_log,
                rule_count,
                enabled_count,
                success,
                error.clone(),
            )
            .await;
            result.map_err(|e| e.to_string())
        },
        Message::ApplyResult,
    )
    .chain(Task::done(Message::AuditLogWritten))
}

/// Handles apply result (success or failure)
pub(crate) fn handle_apply_result(state: &mut State, snapshot: serde_json::Value) {
    state.last_applied_ruleset = Some(state.ruleset.clone());

    if let Err(e) = crate::core::nft_json::save_snapshot_to_disk(&snapshot) {
        warn!("Failed to save snapshot to disk: {e}");
        let msg = if e.to_string().len() > 45 {
            "Warning: Failed to save snapshot. Rollback may be unavailable.".to_string()
        } else {
            format!("Warning: Failed to save snapshot: {e}")
        };
        state.push_banner(&msg, BannerSeverity::Warning);
    }

    if state.auto_revert_enabled {
        // Auto-revert enabled: show countdown modal
        state.countdown_remaining = state.auto_revert_timeout_secs.min(120) as u32;
        let timeout = state.auto_revert_timeout_secs.min(120);
        state.progress_animation = iced::Animation::new(1.0)
            .easing(iced::animation::Easing::Linear)
            .duration(Duration::from_secs(timeout))
            .go(0.0, iced::time::Instant::now());
        state.status = AppStatus::PendingConfirmation {
            deadline: Utc::now() + Duration::from_secs(timeout),
            snapshot,
        };
        state.push_banner(
            format!(
                "Firewall rules applied! Changes will auto-revert in {}s if not confirmed.",
                state.auto_revert_timeout_secs.min(120)
            ),
            BannerSeverity::Info,
        );
    } else {
        // Auto-revert disabled: show success banner and return to idle
        state.status = AppStatus::Idle;
        state.push_banner("Firewall rules applied successfully!", BannerSeverity::Success);
    }
}

/// Handles manual revert button click
pub(crate) fn handle_revert_clicked(state: &mut State) -> Task<Message> {
    if let AppStatus::PendingConfirmation { snapshot, .. } = &state.status {
        let snapshot = snapshot.clone();
        let enable_event_log = state.enable_event_log;
        state.status = AppStatus::Reverting;
        return Task::perform(
            async move {
                let result = crate::core::nft_json::restore_snapshot(&snapshot).await;
                let final_result = if result.is_err() {
                    crate::core::nft_json::restore_with_fallback().await
                } else {
                    result
                };
                let success = final_result.is_ok();
                let error = final_result
                    .as_ref()
                    .err()
                    .map(std::string::ToString::to_string);
                audit::log_revert(enable_event_log, success, error.clone()).await;
                final_result.map_err(|e| e.to_string())
            },
            Message::RevertResult,
        )
        .chain(Task::done(Message::AuditLogWritten));
    }
    Task::none()
}

/// Handles countdown tick for auto-revert
pub(crate) fn handle_countdown_tick(state: &mut State) -> Task<Message> {
    if let AppStatus::PendingConfirmation { deadline, snapshot } = &state.status {
        let now = Utc::now();
        if now >= *deadline {
            // Extract snapshot BEFORE changing status (fixes race condition)
            let snapshot = snapshot.clone();
            let enable_event_log = state.enable_event_log;
            let timeout_secs = state.auto_revert_timeout_secs;
            state.status = AppStatus::Reverting;
            state.countdown_remaining = 0;
            state.push_banner(
                "Firewall rules automatically reverted due to timeout.",
                BannerSeverity::Warning,
            );

            // Spawn revert task with audit logging
            return Task::perform(
                async move {
                    // Log timeout event
                    audit::log_auto_revert_timed_out(enable_event_log, timeout_secs).await;

                    // Perform revert
                    let result = crate::core::nft_json::restore_snapshot(&snapshot).await;
                    let final_result = if result.is_err() {
                        crate::core::nft_json::restore_with_fallback().await
                    } else {
                        result
                    };
                    let success = final_result.is_ok();
                    let error = final_result
                        .as_ref()
                        .err()
                        .map(std::string::ToString::to_string);

                    // Log revert result
                    audit::log_revert(enable_event_log, success, error.clone()).await;
                    final_result.map_err(|e| e.to_string())
                },
                Message::RevertResult,
            )
            .chain(Task::done(Message::AuditLogWritten));
        }

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let remaining = (*deadline - now).num_seconds().max(0) as u32;
        if state.countdown_remaining != remaining {
            state.countdown_remaining = remaining;
            if remaining == 5 {
                state.push_banner(
                    "Firewall will revert in 5 seconds! Click Confirm to keep changes.",
                    BannerSeverity::Warning,
                );
            }
        }
    }
    Task::none()
}

/// Handles confirmation of applied changes (stops auto-revert)
pub(crate) fn handle_confirm_clicked(state: &mut State) -> Task<Message> {
    if matches!(state.status, AppStatus::PendingConfirmation { .. }) {
        state.status = AppStatus::Idle;
        state.push_banner("Changes confirmed and saved!", BannerSeverity::Success);
        let enable_event_log = state.enable_event_log;
        let timeout_secs = state.auto_revert_timeout_secs;
        return Task::perform(
            async move {
                audit::log_auto_revert_confirmed(enable_event_log, timeout_secs).await;
            },
            |()| Message::AuditLogWritten,
        );
    }
    Task::none()
}

/// Handles revert result (success or failure)
pub(crate) fn handle_revert_result(state: &mut State, result: Result<(), String>) {
    match result {
        Ok(()) => {
            state.status = AppStatus::Idle;
            state.push_banner("Firewall rules reverted successfully", BannerSeverity::Info);
        }
        Err(e) => {
            state.status = AppStatus::Idle;
            let msg = truncate_error_message("Revert failed: ", &e, 80);
            state.push_banner(&msg, BannerSeverity::Error);
        }
    }
}

/// Handles Save to System button click - starts verification
pub(crate) fn handle_save_to_system_clicked(state: &mut State) -> Task<Message> {
    if state.is_busy() {
        return Task::none();
    }

    if let Err(task) = require_polkit_agent(state) {
        return task;
    }

    state.status = AppStatus::Verifying;
    let nft_json = state.ruleset.to_nftables_json();

    Task::perform(
        async move {
            crate::core::verify::verify_ruleset(nft_json)
                .await
                .map_err(|e| e.to_string())
        },
        Message::SaveToSystemVerifyResult,
    )
}

/// Handles Save to System verification result
pub(crate) fn handle_save_to_system_verify_result(
    state: &mut State,
    result: Result<crate::core::verify::VerifyResult, String>,
) -> Task<Message> {
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
            Task::none()
        }
        Err(e) => {
            // Verification error (e.g., nft command failed)
            state.status = AppStatus::Idle;
            let msg = truncate_error_message("Verification error: ", &e, 80);
            state.push_banner(&msg, BannerSeverity::Error);
            Task::none()
        }
    }
}

/// Handles user confirming Save to System - proceeds with file write
pub(crate) fn handle_save_to_system_confirmed(state: &mut State) -> Task<Message> {
    state.status = AppStatus::SavingToSystem;

    let text = state.ruleset.to_nft_text();

    Task::perform(
        async move {
            use std::io::Write;
            use tempfile::NamedTempFile;

            // Create temp file with content
            let mut temp =
                NamedTempFile::new().map_err(|e| format!("Failed to create temp file: {e}"))?;
            temp.write_all(text.as_bytes())
                .map_err(|e| format!("Failed to write temp file: {e}"))?;
            temp.flush()
                .map_err(|e| format!("Failed to flush temp file: {e}"))?;

            let temp_path_str = temp
                .path()
                .to_str()
                .ok_or_else(|| "Invalid temp path".to_string())?
                .to_string();

            // Use elevated install command with proper permissions (644)
            let mut cmd = crate::elevation::create_elevated_install_command(&[
                "-m",
                "644",
                &temp_path_str,
                drfw::SYSTEM_NFT_PATH,
            ])
            .map_err(|e| format!("Elevation error: {e}"))?;

            // Capture output for better error messages
            let output = match tokio::time::timeout(Duration::from_secs(120), cmd.output()).await {
                Ok(Ok(output)) => output,
                Ok(Err(e)) => return Err(format!("Failed to execute install: {e}")),
                Err(_) => return Err("Install timed out (authentication dialog expired?)".into()),
            };

            // Use shared helper to interpret exit codes
            interpret_elevated_command_output(&output)
        },
        Message::SaveToSystemResult,
    )
}

/// Handles user cancelling Save to System modal
pub(crate) fn handle_save_to_system_cancelled(state: &mut State) {
    state.status = AppStatus::Idle;
}

/// Handles save to system result
pub(crate) fn handle_save_to_system_result(
    state: &mut State,
    result: Result<(), String>,
) -> Task<Message> {
    state.status = AppStatus::Idle;
    let enable_event_log = state.enable_event_log;
    let target_path = drfw::SYSTEM_NFT_PATH.to_string();

    match result {
        Ok(()) => {
            state.push_banner(
                format!("Configuration saved to {}", drfw::SYSTEM_NFT_PATH),
                BannerSeverity::Success,
            );
            Task::perform(
                async move {
                    audit::log_save_to_system(enable_event_log, true, &target_path, None).await;
                },
                |()| Message::AuditLogWritten,
            )
        }
        Err(e) => {
            let msg = truncate_error_message("Save failed: ", &e, 80);
            state.push_banner(&msg, BannerSeverity::Error);
            Task::perform(
                async move {
                    audit::log_save_to_system(enable_event_log, false, &target_path, Some(e)).await;
                },
                |()| Message::AuditLogWritten,
            )
        }
    }
}

/// Handles apply/revert errors with user-friendly messages and audit logging
pub(crate) fn handle_apply_or_revert_error(state: &mut State, error: &str) -> Task<Message> {
    use crate::app::{AppStatus, BannerSeverity};

    state.status = AppStatus::Idle;

    // Detect elevation-specific errors and handle accordingly
    if error.contains("Authentication cancelled") {
        state.push_banner("Authentication was cancelled", BannerSeverity::Warning);
        let enable_event_log = state.enable_event_log;
        return Task::perform(
            async move {
                crate::audit::log_elevation_cancelled(
                    enable_event_log,
                    "User cancelled authentication".to_string(),
                )
                .await;
            },
            |()| Message::AuditLogWritten,
        );
    } else if error.contains("Authentication failed") {
        state.push_banner("Authentication failed", BannerSeverity::Error);
        let enable_event_log = state.enable_event_log;
        let error_msg = error.to_owned();
        return Task::perform(
            async move {
                crate::audit::log_elevation_failed(enable_event_log, error_msg).await;
            },
            |()| Message::AuditLogWritten,
        );
    } else if error.contains("timed out") || error.contains("Operation timed out") {
        state.push_banner("Authentication timed out", BannerSeverity::Error);
        let enable_event_log = state.enable_event_log;
        let error_msg = error.to_owned();
        return Task::perform(
            async move {
                crate::audit::log_elevation_failed(enable_event_log, error_msg).await;
            },
            |()| Message::AuditLogWritten,
        );
    } else if error.contains("No authentication agent") || error.contains("No polkit") {
        state.push_banner(
            "No authentication agent available. Install polkit.",
            BannerSeverity::Error,
        );
        let enable_event_log = state.enable_event_log;
        let error_msg = error.to_owned();
        return Task::perform(
            async move {
                crate::audit::log_elevation_failed(enable_event_log, error_msg).await;
            },
            |()| Message::AuditLogWritten,
        );
    } else if error.contains("nft binary not found") || error.contains("nftables") {
        state.push_banner("nftables not installed", BannerSeverity::Error);
        let enable_event_log = state.enable_event_log;
        let error_msg = error.to_owned();
        return Task::perform(
            async move {
                crate::audit::log_elevation_failed(enable_event_log, error_msg).await;
            },
            |()| Message::AuditLogWritten,
        );
    }

    // Generic error - show error message (no prefix for generic errors)
    let msg = truncate_error_message("", error, 80);
    state.push_banner(&msg, BannerSeverity::Error);

    Task::none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::handlers::test_utils::create_test_state;

    #[test]
    fn test_handle_apply_clicked_idle() {
        let mut state = create_test_state();
        state.status = AppStatus::Idle;
        let _task = handle_apply_clicked(&mut state);
        // Should transition to Verifying (or stay Idle if polkit agent not running)
        assert!(matches!(
            state.status,
            AppStatus::Verifying | AppStatus::Idle
        ));
    }
}
