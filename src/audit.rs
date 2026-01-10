/// Audit logging for security-critical operations
///
/// This module provides structured logging of all privileged operations
/// including rule applications, reverts, and configuration changes.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

/// Types of auditable events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Firewall operations
    ApplyRules,
    RevertRules,
    VerifyRules,
    SnapshotFailed,

    // Elevation/authentication events
    ElevationCancelled,
    ElevationFailed,

    // Profile management (user-facing)
    ProfileCreated,
    ProfileDeleted,
    ProfileRenamed,
    ProfileSwitched,
    ProfileDeleteFailed,
    ProfileRenameFailed,

    // Settings changes (user-facing)
    SettingsSaved,

    // Auto-revert events (user-facing)
    AutoRevertConfirmed,
    AutoRevertTimedOut,

    // Rule CRUD operations
    RuleCreated,
    RuleDeleted,
    RuleModified,
    RuleToggled,
    RulesReordered,
    Undone,
    Redone,

    // Data export
    ExportCompleted,
    ExportFailed,

    // System configuration
    SaveToSystem,

    // Generic errors (fallthrough cases)
    GenericError,
}

/// A single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When the event occurred (UTC)
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Type of event
    pub event_type: EventType,

    /// Whether the operation succeeded
    pub success: bool,

    /// Additional structured data about the event
    pub details: serde_json::Value,

    /// Error message if operation failed
    pub error: Option<String>,
}

impl AuditEvent {
    /// Creates a new audit event
    pub fn new(
        event_type: EventType,
        success: bool,
        details: serde_json::Value,
        error: Option<String>,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now(),
            event_type,
            success,
            details,
            error,
        }
    }
}

/// Audit log writer
pub struct AuditLog {
    log_path: PathBuf,
}

impl AuditLog {
    /// Maximum audit log size before rotation (1 MB)
    const MAX_SIZE_BYTES: u64 = 1024 * 1024;

    /// Creates a new audit log instance
    ///
    /// # Errors
    ///
    /// Returns `Err` if state directory cannot be determined
    pub fn new() -> std::io::Result<Self> {
        let mut log_path = crate::utils::get_state_dir().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "State directory not found")
        })?;
        log_path.push("audit.log");

        Ok(Self { log_path })
    }

    /// Rotates the audit log if it exceeds the size limit.
    ///
    /// If `audit.log` > 1MB, renames it to `audit.log.old` (overwriting any previous backup)
    /// and starts fresh. Called once at application startup.
    ///
    /// This is a simple rotation scheme: at most one backup file exists at any time.
    pub fn rotate_if_needed(&self) {
        let Ok(metadata) = std::fs::metadata(&self.log_path) else {
            return; // File doesn't exist, nothing to rotate
        };

        if metadata.len() > Self::MAX_SIZE_BYTES {
            let mut old_path = self.log_path.clone();
            old_path.set_extension("log.old");

            // Rename current to .old (overwrites previous .old if it exists)
            if let Err(e) = std::fs::rename(&self.log_path, &old_path) {
                tracing::warn!("Failed to rotate audit log: {}", e);
            } else {
                tracing::info!("Rotated audit log (exceeded 1MB)");
            }
        }
    }

    /// Appends an event to the audit log
    ///
    /// Events are written as JSON-lines format (one JSON object per line)
    ///
    /// # Security
    ///
    /// On Unix systems, files are created with mode 0o600 (user read/write only).
    /// On Windows, files inherit directory permissions. Users should ensure the
    /// audit directory has appropriate ACLs: `%LOCALAPPDATA%\drfw\drfw\data\state`
    ///
    /// # Errors
    ///
    /// Returns `Err` if file cannot be opened or written
    pub async fn log(&self, event: AuditEvent) -> std::io::Result<()> {
        let json = serde_json::to_string(&event)?;

        #[cfg(unix)]
        let mut file = {
            #[allow(unused_imports)] // Used implicitly by .mode()
            use std::os::unix::fs::OpenOptionsExt;

            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600) // User read/write only
                .open(&self.log_path)
                .await?
        };

        #[cfg(not(unix))]
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await?;

        file.write_all(json.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.sync_all().await?;

        Ok(())
    }
}

/// Internal helper that handles the common audit logging pattern.
///
/// All public `log_*` functions delegate to this helper, reducing code duplication
/// from ~600 lines to ~200 lines across 20 logging functions.
async fn log_event_internal(
    enable_event_log: bool,
    event_type: EventType,
    success: bool,
    details: serde_json::Value,
    error: Option<String>,
) {
    if !enable_event_log {
        return;
    }

    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(event_type, success, details, error);
        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

/// Logs an apply operation
pub async fn log_apply(
    enable_event_log: bool,
    rule_count: usize,
    enabled_count: usize,
    success: bool,
    error: Option<String>,
) {
    log_event_internal(
        enable_event_log,
        EventType::ApplyRules,
        success,
        serde_json::json!({ "rule_count": rule_count, "enabled_count": enabled_count }),
        error,
    )
    .await;
}

/// Logs a revert operation
pub async fn log_revert(enable_event_log: bool, success: bool, error: Option<String>) {
    log_event_internal(
        enable_event_log,
        EventType::RevertRules,
        success,
        serde_json::json!({}),
        error,
    )
    .await;
}

/// Logs a verification operation
pub async fn log_verify(
    enable_event_log: bool,
    success: bool,
    error_count: usize,
    error: Option<String>,
) {
    log_event_internal(
        enable_event_log,
        EventType::VerifyRules,
        success,
        serde_json::json!({ "error_count": error_count }),
        error,
    )
    .await;
}

/// Logs a profile creation event
pub async fn log_profile_created(enable_event_log: bool, profile_name: &str) {
    log_event_internal(
        enable_event_log,
        EventType::ProfileCreated,
        true,
        serde_json::json!({ "profile_name": profile_name }),
        None,
    )
    .await;
}

/// Logs a profile deletion event
pub async fn log_profile_deleted(enable_event_log: bool, profile_name: &str) {
    log_event_internal(
        enable_event_log,
        EventType::ProfileDeleted,
        true,
        serde_json::json!({ "profile_name": profile_name }),
        None,
    )
    .await;
}

/// Logs a profile rename event
pub async fn log_profile_renamed(enable_event_log: bool, old_name: &str, new_name: &str) {
    log_event_internal(
        enable_event_log,
        EventType::ProfileRenamed,
        true,
        serde_json::json!({ "old_name": old_name, "new_name": new_name }),
        None,
    )
    .await;
}

/// Logs a profile switch event
pub async fn log_profile_switched(enable_event_log: bool, from_profile: &str, to_profile: &str) {
    log_event_internal(
        enable_event_log,
        EventType::ProfileSwitched,
        true,
        serde_json::json!({ "from": from_profile, "to": to_profile }),
        None,
    )
    .await;
}

/// Logs a settings save event
pub async fn log_settings_saved(enable_event_log: bool, description: &str) {
    log_event_internal(
        enable_event_log,
        EventType::SettingsSaved,
        true,
        serde_json::json!({ "description": description }),
        None,
    )
    .await;
}

/// Logs an auto-revert confirmation event
pub async fn log_auto_revert_confirmed(enable_event_log: bool, timeout_secs: u64) {
    log_event_internal(
        enable_event_log,
        EventType::AutoRevertConfirmed,
        true,
        serde_json::json!({ "timeout_secs": timeout_secs }),
        None,
    )
    .await;
}

/// Logs an auto-revert timeout event
pub async fn log_auto_revert_timed_out(enable_event_log: bool, timeout_secs: u64) {
    log_event_internal(
        enable_event_log,
        EventType::AutoRevertTimedOut,
        true,
        serde_json::json!({ "timeout_secs": timeout_secs }),
        None,
    )
    .await;
}

/// Logs an elevation cancellation event (user cancelled auth dialog)
pub async fn log_elevation_cancelled(enable_event_log: bool, error: String) {
    log_event_internal(
        enable_event_log,
        EventType::ElevationCancelled,
        false,
        serde_json::json!({ "error": &error }),
        Some(error),
    )
    .await;
}

/// Logs an elevation failure event (auth failed, timeout, no agent, etc.)
pub async fn log_elevation_failed(enable_event_log: bool, error: String) {
    log_event_internal(
        enable_event_log,
        EventType::ElevationFailed,
        false,
        serde_json::json!({ "error": &error }),
        Some(error),
    )
    .await;
}

/// Logs a rule creation event
pub async fn log_rule_created(
    enable_event_log: bool,
    label: &str,
    protocol: &str,
    ports: Option<String>,
) {
    log_event_internal(
        enable_event_log,
        EventType::RuleCreated,
        true,
        serde_json::json!({ "label": label, "protocol": protocol, "ports": ports }),
        None,
    )
    .await;
}

/// Logs a rule deletion event
pub async fn log_rule_deleted(enable_event_log: bool, label: &str) {
    log_event_internal(
        enable_event_log,
        EventType::RuleDeleted,
        true,
        serde_json::json!({ "label": label }),
        None,
    )
    .await;
}

/// Logs a rule modification event
pub async fn log_rule_modified(
    enable_event_log: bool,
    label: &str,
    protocol: &str,
    ports: Option<String>,
) {
    log_event_internal(
        enable_event_log,
        EventType::RuleModified,
        true,
        serde_json::json!({ "label": label, "protocol": protocol, "ports": ports }),
        None,
    )
    .await;
}

/// Logs a rule toggle event (enabled/disabled)
pub async fn log_rule_toggled(enable_event_log: bool, label: &str, enabled: bool) {
    log_event_internal(
        enable_event_log,
        EventType::RuleToggled,
        true,
        serde_json::json!({ "label": label, "enabled": enabled }),
        None,
    )
    .await;
}

/// Logs a rule reordering event (moved up/down)
pub async fn log_rules_reordered(enable_event_log: bool, label: &str, direction: &str) {
    log_event_internal(
        enable_event_log,
        EventType::RulesReordered,
        true,
        serde_json::json!({ "label": label, "direction": direction }),
        None,
    )
    .await;
}

/// Logs an undo operation
pub async fn log_undone(enable_event_log: bool, description: &str) {
    log_event_internal(
        enable_event_log,
        EventType::Undone,
        true,
        serde_json::json!({ "description": description }),
        None,
    )
    .await;
}

/// Logs a redo operation
pub async fn log_redone(enable_event_log: bool, description: &str) {
    log_event_internal(
        enable_event_log,
        EventType::Redone,
        true,
        serde_json::json!({ "description": description }),
        None,
    )
    .await;
}

/// Logs a save to system operation
pub async fn log_save_to_system(
    enable_event_log: bool,
    success: bool,
    target_path: &str,
    error: Option<String>,
) {
    log_event_internal(
        enable_event_log,
        EventType::SaveToSystem,
        success,
        serde_json::json!({ "target_path": target_path }),
        error,
    )
    .await;
}

/// Logs a snapshot save failure
pub async fn log_snapshot_failed(enable_event_log: bool, error: String) {
    log_event_internal(
        enable_event_log,
        EventType::SnapshotFailed,
        false,
        serde_json::json!({ "error": &error }),
        Some(error),
    )
    .await;
}

/// Logs a profile delete failure
pub async fn log_profile_delete_failed(enable_event_log: bool, profile_name: &str, error: String) {
    log_event_internal(
        enable_event_log,
        EventType::ProfileDeleteFailed,
        false,
        serde_json::json!({ "profile_name": profile_name, "error": &error }),
        Some(error),
    )
    .await;
}

/// Logs a profile rename failure
pub async fn log_profile_rename_failed(enable_event_log: bool, profile_name: &str, error: String) {
    log_event_internal(
        enable_event_log,
        EventType::ProfileRenameFailed,
        false,
        serde_json::json!({ "profile_name": profile_name, "error": &error }),
        Some(error),
    )
    .await;
}

/// Logs an export failure
pub async fn log_export_failed(enable_event_log: bool, error: String) {
    log_event_internal(
        enable_event_log,
        EventType::ExportFailed,
        false,
        serde_json::json!({ "error": &error }),
        Some(error),
    )
    .await;
}

/// Logs a generic error (fallthrough cases)
pub async fn log_generic_error(enable_event_log: bool, error: String) {
    log_event_internal(
        enable_event_log,
        EventType::GenericError,
        false,
        serde_json::json!({ "error": &error }),
        Some(error),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_event_creation() {
        let event = AuditEvent::new(
            EventType::ApplyRules,
            true,
            serde_json::json!({"rule_count": 5}),
            None,
        );

        assert!(event.success);
        assert!(event.error.is_none());
        assert_eq!(event.details["rule_count"], 5);
    }

    #[test]
    fn test_event_serialization() {
        let event = AuditEvent::new(
            EventType::VerifyRules,
            false,
            serde_json::json!({"errors": 2}),
            Some("validation failed".to_string()),
        );

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("verify_rules"));
        assert!(json.contains("validation failed"));
    }

    #[test]
    fn test_event_deserialization() {
        let json = r#"{"timestamp":"2024-01-01T00:00:00Z","event_type":"apply_rules","success":true,"details":{},"error":null}"#;
        let event: AuditEvent = serde_json::from_str(json).unwrap();

        assert!(event.success);
        assert!(matches!(event.event_type, EventType::ApplyRules));
    }

    #[test]
    fn test_rotate_if_needed() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("audit.log");
        let old_path = temp_dir.path().join("audit.log.old");

        // Create a file larger than 1MB
        let mut file = std::fs::File::create(&log_path).unwrap();
        let data = vec![b'x'; 1024 * 1024 + 100]; // Just over 1MB
        file.write_all(&data).unwrap();
        drop(file);

        assert!(log_path.exists());
        assert!(!old_path.exists());

        // Create AuditLog pointing to our temp file
        let audit = AuditLog {
            log_path: log_path.clone(),
        };
        audit.rotate_if_needed();

        // Original should be gone, .old should exist
        assert!(!log_path.exists());
        assert!(old_path.exists());
    }

    #[test]
    fn test_rotate_if_needed_small_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("audit.log");

        // Create a small file (under 1MB)
        std::fs::write(&log_path, "small content").unwrap();

        assert!(log_path.exists());

        let audit = AuditLog {
            log_path: log_path.clone(),
        };
        audit.rotate_if_needed();

        // File should still exist (not rotated)
        assert!(log_path.exists());
    }
}
