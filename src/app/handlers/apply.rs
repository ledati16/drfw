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

/// Handles apply button click (starts verification)
pub(crate) fn handle_apply_clicked(state: &mut State) -> Task<Message> {
    if matches!(
        state.status,
        AppStatus::Verifying | AppStatus::Applying | AppStatus::PendingConfirmation { .. }
    ) {
        return Task::none();
    }

    // Check if polkit authentication agent is running
    if !crate::elevation::is_polkit_agent_running() {
        state.push_banner(
            "No polkit agent running. Install and start an authentication agent.",
            BannerSeverity::Error,
            10,
        );
        return Task::none();
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
            state.push_banner(&error_summary, BannerSeverity::Error, 8);
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
            let msg = if e.len() > 60 {
                format!("Verification error: {}...", &e[..57])
            } else {
                format!("Verification error: {e}")
            };
            state.push_banner(&msg, BannerSeverity::Error, 8);
            let enable_event_log = state.enable_event_log;
            let error = e.clone();
            Task::perform(
                async move {
                    audit::log_verify(enable_event_log, false, 0, Some(error)).await;
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
        state.push_banner(&msg, BannerSeverity::Warning, 10);
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
            state.auto_revert_timeout_secs.min(120),
        );
    } else {
        // Auto-revert disabled: show success banner and return to idle
        state.status = AppStatus::Idle;
        state.push_banner(
            "Firewall rules applied successfully!",
            BannerSeverity::Success,
            5,
        );
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
                10,
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
                    5,
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
        state.push_banner("Changes confirmed and saved!", BannerSeverity::Success, 5);
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
            state.push_banner(
                "Firewall rules reverted successfully",
                BannerSeverity::Info,
                5,
            );
        }
        Err(e) => {
            state.status = AppStatus::Idle;
            let msg = if e.len() > 55 {
                format!("Revert failed: {}...", &e[..52])
            } else {
                format!("Revert failed: {e}")
            };
            state.push_banner(&msg, BannerSeverity::Error, 10);
        }
    }
}

/// Handles save to system configuration file
pub(crate) fn handle_save_to_system(state: &mut State) -> Task<Message> {
    let text = state.ruleset.to_nft_text();
    Task::perform(
        async move {
            use std::io::Write;
            use tempfile::NamedTempFile;
            let mut temp =
                NamedTempFile::new().map_err(|e| format!("Failed to create temp file: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                temp.as_file()
                    .set_permissions(perms)
                    .map_err(|e| format!("Failed to set permissions: {e}"))?;
            }
            temp.write_all(text.as_bytes())
                .map_err(|e| format!("Failed to write temp file: {e}"))?;
            temp.flush()
                .map_err(|e| format!("Failed to flush temp file: {e}"))?;
            let temp_path_str = temp
                .path()
                .to_str()
                .ok_or_else(|| "Invalid temp path".to_string())?
                .to_string();
            let status = tokio::process::Command::new("pkexec")
                .args([
                    "cp",
                    "--preserve=mode",
                    &temp_path_str,
                    drfw::SYSTEM_NFT_PATH,
                ])
                .status()
                .await
                .map_err(|e| format!("Failed to execute pkexec: {e}"))?;
            if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "Failed to copy configuration to {}",
                    drfw::SYSTEM_NFT_PATH
                ))
            }
        },
        Message::SaveToSystemResult,
    )
}

/// Handles save to system result
pub(crate) fn handle_save_to_system_result(state: &mut State, result: Result<(), String>) {
    match result {
        Ok(()) => {
            state.push_banner(
                format!("Configuration saved to {}", drfw::SYSTEM_NFT_PATH),
                BannerSeverity::Success,
                5,
            );
        }
        Err(e) => {
            let msg = if e.len() > 50 {
                format!("Save failed: {}...", &e[..47])
            } else {
                format!("Save failed: {e}")
            };
            state.push_banner(&msg, BannerSeverity::Error, 8);
        }
    }
}

/// Handles apply/revert errors with user-friendly messages and audit logging
pub(crate) fn handle_apply_or_revert_error(state: &mut State, error: &str) -> Task<Message> {
    use crate::app::{AppStatus, BannerSeverity};

    state.status = AppStatus::Idle;

    // Detect elevation-specific errors and handle accordingly
    if error.contains("Authentication cancelled") {
        state.push_banner("Authentication was cancelled", BannerSeverity::Warning, 5);
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
        state.push_banner("Authentication failed", BannerSeverity::Error, 5);
        let enable_event_log = state.enable_event_log;
        let error_msg = error.to_owned();
        return Task::perform(
            async move {
                crate::audit::log_elevation_failed(enable_event_log, error_msg).await;
            },
            |()| Message::AuditLogWritten,
        );
    } else if error.contains("timed out") || error.contains("Operation timed out") {
        state.push_banner("Authentication timed out", BannerSeverity::Error, 5);
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
            8,
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
        state.push_banner("nftables not installed", BannerSeverity::Error, 5);
        let enable_event_log = state.enable_event_log;
        let error_msg = error.to_owned();
        return Task::perform(
            async move {
                crate::audit::log_elevation_failed(enable_event_log, error_msg).await;
            },
            |()| Message::AuditLogWritten,
        );
    }

    // Generic error - show error message
    let msg = if error.len() > 80 {
        format!("{}...", &error[..77])
    } else {
        error.to_owned()
    };
    state.push_banner(&msg, BannerSeverity::Error, 8);

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
