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
    SaveSnapshot,
    RestoreSnapshot,
    EnablePersistence,
    SaveToSystem,
    VerifyRules,

    // Profile management (user-facing)
    ProfileCreated,
    ProfileDeleted,
    ProfileRenamed,
    ProfileSwitched,

    // Settings changes (user-facing)
    SettingsSaved,

    // Auto-revert events (user-facing)
    AutoRevertConfirmed,
    AutoRevertTimedOut,
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

    /// Appends an event to the audit log
    ///
    /// Events are written as JSON-lines format (one JSON object per line)
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

    /// Reads the most recent events from the log
    ///
    /// **TODO**: Wire up to diagnostics viewer (Phase 6 or 7)
    ///
    /// This will enable a "View Audit Log" feature in the Settings/Diagnostics tab,
    /// allowing users to review recent security-critical operations.
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum number of events to return
    ///
    /// # Errors
    ///
    /// Returns `Err` if file cannot be read or contains invalid JSON
    #[allow(dead_code)]
    pub async fn read_recent(&self, count: usize) -> std::io::Result<Vec<AuditEvent>> {
        let content = tokio::fs::read_to_string(&self.log_path).await?;

        let events: Vec<AuditEvent> = content
            .lines()
            .rev()
            .take(count)
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        Ok(events)
    }

    /// Returns the path to the audit log file
    #[allow(dead_code)]
    pub fn path(&self) -> &PathBuf {
        &self.log_path
    }
}

/// Logs an apply operation
///
/// # Arguments
///
/// * `enable_event_log` - Whether event logging is enabled (opt-in via config)
/// * `rule_count` - Number of rules being applied
/// * `enabled_count` - Number of enabled rules
/// * `success` - Whether the operation succeeded
/// * `error` - Error message if operation failed
pub async fn log_apply(
    enable_event_log: bool,
    rule_count: usize,
    enabled_count: usize,
    success: bool,
    error: Option<String>,
) {
    if !enable_event_log {
        return;
    }

    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(
            EventType::ApplyRules,
            success,
            serde_json::json!({
                "rule_count": rule_count,
                "enabled_count": enabled_count,
            }),
            error,
        );

        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

/// Logs a revert operation
///
/// # Arguments
///
/// * `enable_event_log` - Whether event logging is enabled (opt-in via config)
/// * `success` - Whether the operation succeeded
/// * `error` - Error message if operation failed
pub async fn log_revert(enable_event_log: bool, success: bool, error: Option<String>) {
    if !enable_event_log {
        return;
    }

    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(
            EventType::RevertRules,
            success,
            serde_json::json!({}),
            error,
        );

        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

/// Logs a save-to-system operation
///
/// # Arguments
///
/// * `enable_event_log` - Whether event logging is enabled (opt-in via config)
/// * `success` - Whether the operation succeeded
/// * `error` - Error message if operation failed
#[allow(dead_code)]
pub async fn log_save_to_system(enable_event_log: bool, success: bool, error: Option<String>) {
    if !enable_event_log {
        return;
    }

    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(
            EventType::SaveToSystem,
            success,
            serde_json::json!({}),
            error,
        );

        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

/// Logs a verification operation
///
/// # Arguments
///
/// * `enable_event_log` - Whether event logging is enabled (opt-in via config)
/// * `success` - Whether the operation succeeded
/// * `error_count` - Number of validation errors
/// * `error` - Error message if operation failed
pub async fn log_verify(
    enable_event_log: bool,
    success: bool,
    error_count: usize,
    error: Option<String>,
) {
    if !enable_event_log {
        return;
    }

    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(
            EventType::VerifyRules,
            success,
            serde_json::json!({
                "error_count": error_count,
            }),
            error,
        );

        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

/// Logs a profile creation event
///
/// # Arguments
///
/// * `enable_event_log` - Whether event logging is enabled (opt-in via config)
/// * `profile_name` - Name of the profile that was created
pub async fn log_profile_created(enable_event_log: bool, profile_name: &str) {
    if !enable_event_log {
        return;
    }

    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(
            EventType::ProfileCreated,
            true,
            serde_json::json!({
                "profile_name": profile_name,
            }),
            None,
        );

        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

/// Logs a profile deletion event
///
/// # Arguments
///
/// * `enable_event_log` - Whether event logging is enabled (opt-in via config)
/// * `profile_name` - Name of the profile that was deleted
pub async fn log_profile_deleted(enable_event_log: bool, profile_name: &str) {
    if !enable_event_log {
        return;
    }

    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(
            EventType::ProfileDeleted,
            true,
            serde_json::json!({
                "profile_name": profile_name,
            }),
            None,
        );

        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

/// Logs a profile rename event
///
/// # Arguments
///
/// * `enable_event_log` - Whether event logging is enabled (opt-in via config)
/// * `old_name` - Original profile name
/// * `new_name` - New profile name
pub async fn log_profile_renamed(enable_event_log: bool, old_name: &str, new_name: &str) {
    if !enable_event_log {
        return;
    }

    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(
            EventType::ProfileRenamed,
            true,
            serde_json::json!({
                "old_name": old_name,
                "new_name": new_name,
            }),
            None,
        );

        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

/// Logs a profile switch event
///
/// # Arguments
///
/// * `enable_event_log` - Whether event logging is enabled (opt-in via config)
/// * `from_profile` - Profile being switched from
/// * `to_profile` - Profile being switched to
pub async fn log_profile_switched(enable_event_log: bool, from_profile: &str, to_profile: &str) {
    if !enable_event_log {
        return;
    }

    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(
            EventType::ProfileSwitched,
            true,
            serde_json::json!({
                "from": from_profile,
                "to": to_profile,
            }),
            None,
        );

        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

/// Logs a settings save event
///
/// # Arguments
///
/// * `enable_event_log` - Whether event logging is enabled (opt-in via config)
/// * `description` - Description of what setting changed
pub async fn log_settings_saved(enable_event_log: bool, description: &str) {
    if !enable_event_log {
        return;
    }

    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(
            EventType::SettingsSaved,
            true,
            serde_json::json!({
                "description": description,
            }),
            None,
        );

        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

/// Logs an auto-revert confirmation event
///
/// # Arguments
///
/// * `enable_event_log` - Whether event logging is enabled (opt-in via config)
/// * `timeout_secs` - The configured timeout that was used
pub async fn log_auto_revert_confirmed(enable_event_log: bool, timeout_secs: u64) {
    if !enable_event_log {
        return;
    }

    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(
            EventType::AutoRevertConfirmed,
            true,
            serde_json::json!({
                "timeout_secs": timeout_secs,
            }),
            None,
        );

        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

/// Logs an auto-revert timeout event
///
/// # Arguments
///
/// * `enable_event_log` - Whether event logging is enabled (opt-in via config)
/// * `timeout_secs` - The configured timeout that expired
pub async fn log_auto_revert_timed_out(enable_event_log: bool, timeout_secs: u64) {
    if !enable_event_log {
        return;
    }

    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(
            EventType::AutoRevertTimedOut,
            true,
            serde_json::json!({
                "timeout_secs": timeout_secs,
            }),
            None,
        );

        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
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
}
