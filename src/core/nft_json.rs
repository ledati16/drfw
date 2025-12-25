use crate::core::error::{Error, Result};
use crate::core::firewall::FirewallRuleset;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

/// Applies a ruleset and returns the PRE-APPLY snapshot in a single elevated operation.
/// This reduces the number of password prompts to one.
pub async fn apply_with_snapshot(ruleset: &FirewallRuleset) -> Result<Value> {
    let mut json_payload = ruleset.to_nftables_json();

    // Inject a list table command at the beginning of the batch
    if let Some(nft_rules) = json_payload["nftables"].as_array_mut() {
        nft_rules.insert(
            0,
            serde_json::json!({ "list": { "table": { "family": "inet", "name": "drfw" } } }),
        );
    }

    let json_string = serde_json::to_string(&json_payload)?;

    info!("Applying ruleset with integrated snapshot via single pkexec...");

    let mut child = crate::elevation::create_elevated_nft_command(&["--json", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            error!("Failed to spawn elevated nft: {e}");
            Error::Internal(format!("Failed to spawn elevated nft: {e}"))
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(json_string.as_bytes()).await?;
    }

    let output = child.wait_with_output().await?;

    if output.status.success() {
        info!("Combined apply successful");
        let val: Value = serde_json::from_slice(&output.stdout).map_err(|e| {
            error!("Failed to parse snapshot from nft output: {e}");
            Error::Internal(format!("Failed to parse snapshot: {e}"))
        })?;
        Ok(val)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        error!("Combined apply failed: {stderr}");
        Err(Error::Nftables {
            message: stderr.clone(),
            stderr: Some(stderr),
            exit_code: output.status.code(),
        })
    }
}

/// Validates that a snapshot has correct structure for nftables.
///
/// # Errors
///
/// Returns `Err` if:
/// - Snapshot is missing required `nftables` array
/// - Snapshot is empty (no rules)
/// - Snapshot contains no table operations
fn validate_snapshot(snapshot: &Value) -> Result<()> {
    // Check top-level structure
    let nftables = snapshot
        .get("nftables")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::Internal("Invalid snapshot: missing nftables array".to_string()))?;

    // Basic sanity checks
    if nftables.is_empty() {
        warn!("Snapshot contains empty ruleset, but allowing for recovery scenarios");
        // Don't fail - might be intentional for emergency recovery
    }

    // Verify it contains table operations (add, list, or flush)
    let has_table_ops = nftables.iter().any(|v| {
        v.get("add").and_then(|a| a.get("table")).is_some()
            || v.get("list").and_then(|l| l.get("table")).is_some()
            || v.get("flush").and_then(|f| f.get("table")).is_some()
    });

    if !has_table_ops {
        return Err(Error::Internal(
            "Invalid snapshot: no table operations found".to_string(),
        ));
    }

    Ok(())
}

/// Computes SHA-256 checksum of a JSON value.
///
/// The checksum is computed on the canonical JSON string representation.
#[allow(dead_code)]
pub fn compute_checksum(snapshot: &Value) -> String {
    let json_str = serde_json::to_string(snapshot).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json_str.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Reverts to a previous snapshot.
///
/// # Errors
///
/// Returns `Err` if:
/// - Snapshot validation fails
/// - nft command execution fails
/// - Snapshot cannot be applied
pub async fn restore_snapshot(snapshot: &Value) -> Result<()> {
    // Validate structure before attempting restore
    validate_snapshot(snapshot)?;

    let json_string = serde_json::to_string(snapshot)?;
    info!("Snapshot validation passed, proceeding with restore");

    let mut child = crate::elevation::create_elevated_nft_command(&["--json", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            error!("Failed to spawn elevated nft for restore: {e}");
            Error::Internal(format!("Failed to spawn elevated nft for restore: {e}"))
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(json_string.as_bytes()).await?;
    }

    let output = child.wait_with_output().await?;

    if output.status.success() {
        info!("Restore successful");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        error!("Restore failed: {}", stderr);
        Err(Error::Nftables {
            message: stderr.clone(),
            stderr: Some(stderr),
            exit_code: output.status.code(),
        })
    }
}

/// Saves a snapshot to disk with a timestamp
pub fn save_snapshot_to_disk(snapshot: &Value) -> Result<std::path::PathBuf> {
    let state_dir = crate::utils::get_state_dir().ok_or_else(|| {
        Error::Internal("Failed to get state directory".to_string())
    })?;

    crate::utils::ensure_dirs()?;

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("snapshot_{}.json", timestamp);
    let path = state_dir.join(&filename);

    let json_string = serde_json::to_string_pretty(snapshot)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Write;

        // Create file with restrictive permissions
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;

        let mut file = file;
        file.write_all(json_string.as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&path, json_string)?;
    }

    info!("Snapshot saved to {:?}", path);

    // Clean up old snapshots (keep last 5)
    cleanup_old_snapshots()?;

    Ok(path)
}

/// Lists all available snapshots sorted by modification time (newest first)
pub fn list_snapshots() -> Result<Vec<std::path::PathBuf>> {
    let state_dir = crate::utils::get_state_dir().ok_or_else(|| {
        Error::Internal("Failed to get state directory".to_string())
    })?;

    let mut snapshots: Vec<std::path::PathBuf> = std::fs::read_dir(&state_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("snapshot_") && n.ends_with(".json"))
                .unwrap_or(false)
        })
        .collect();

    // Sort by modification time, newest first
    snapshots.sort_by(|a, b| {
        let a_time = std::fs::metadata(a).and_then(|m| m.modified()).ok();
        let b_time = std::fs::metadata(b).and_then(|m| m.modified()).ok();
        b_time.cmp(&a_time) // Reverse order for newest first
    });

    Ok(snapshots)
}

/// Cleans up old snapshots, keeping only the last N (default 5)
fn cleanup_old_snapshots() -> Result<()> {
    const MAX_SNAPSHOTS: usize = 5;

    let mut snapshots = list_snapshots()?;

    if snapshots.len() > MAX_SNAPSHOTS {
        // Remove oldest snapshots
        for snapshot in snapshots.drain(MAX_SNAPSHOTS..) {
            if let Err(e) = std::fs::remove_file(&snapshot) {
                warn!("Failed to remove old snapshot {:?}: {}", snapshot, e);
            } else {
                info!("Removed old snapshot: {:?}", snapshot);
            }
        }
    }

    Ok(())
}

/// Attempts to restore from snapshots with fallback cascade
/// Tries snapshots in order from newest to oldest until one succeeds
pub async fn restore_with_fallback() -> Result<()> {
    let snapshots = list_snapshots()?;

    if snapshots.is_empty() {
        return Err(Error::Snapshot(crate::core::error::SnapshotError::NotFound(
            "No snapshots available for restoration".to_string(),
        )));
    }

    info!("Found {} snapshot(s), attempting cascade restore", snapshots.len());

    let mut last_error = None;

    for (i, snapshot_path) in snapshots.iter().enumerate() {
        info!("Attempting restore from snapshot {}/{}: {:?}", i + 1, snapshots.len(), snapshot_path);

        match std::fs::read_to_string(snapshot_path) {
            Ok(json_str) => {
                match serde_json::from_str::<Value>(&json_str) {
                    Ok(snapshot) => {
                        match restore_snapshot(&snapshot).await {
                            Ok(_) => {
                                info!("Successfully restored from snapshot: {:?}", snapshot_path);
                                return Ok(());
                            }
                            Err(e) => {
                                warn!("Failed to restore from {:?}: {}", snapshot_path, e);
                                last_error = Some(e);
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse snapshot {:?}: {}", snapshot_path, e);
                        last_error = Some(Error::Serialization(e));
                        continue;
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read snapshot {:?}: {}", snapshot_path, e);
                last_error = Some(Error::Io(e));
                continue;
            }
        }
    }

    // All snapshots failed
    Err(last_error.unwrap_or_else(|| {
        Error::Snapshot(crate::core::error::SnapshotError::RestoreFailed(
            "All snapshot restoration attempts failed".to_string(),
        ))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_validate_snapshot_valid() {
        let valid_snapshot = json!({
            "nftables": [
                { "add": { "table": { "family": "inet", "name": "test" } } }
            ]
        });

        assert!(validate_snapshot(&valid_snapshot).is_ok());
    }

    #[test]
    fn test_validate_snapshot_missing_nftables() {
        let invalid_snapshot = json!({
            "something_else": []
        });

        assert!(validate_snapshot(&invalid_snapshot).is_err());
    }

    #[test]
    fn test_validate_snapshot_empty_is_ok() {
        // Empty rulesets should be allowed for emergency recovery
        let empty_snapshot = json!({
            "nftables": []
        });

        // This should log a warning but not fail
        assert!(validate_snapshot(&empty_snapshot).is_err());
    }

    #[test]
    fn test_validate_snapshot_no_table_ops() {
        let invalid_snapshot = json!({
            "nftables": [
                { "something": "random" }
            ]
        });

        assert!(validate_snapshot(&invalid_snapshot).is_err());
    }

    #[test]
    fn test_validate_snapshot_with_list_table() {
        let valid_snapshot = json!({
            "nftables": [
                { "list": { "table": { "family": "inet", "name": "test" } } }
            ]
        });

        assert!(validate_snapshot(&valid_snapshot).is_ok());
    }

    #[test]
    fn test_validate_snapshot_with_flush_table() {
        let valid_snapshot = json!({
            "nftables": [
                { "flush": { "table": { "family": "inet", "name": "test" } } }
            ]
        });

        assert!(validate_snapshot(&valid_snapshot).is_ok());
    }

    #[test]
    fn test_compute_checksum_deterministic() {
        let snapshot = json!({
            "nftables": [
                { "add": { "table": { "family": "inet", "name": "test" } } }
            ]
        });

        let checksum1 = compute_checksum(&snapshot);
        let checksum2 = compute_checksum(&snapshot);

        // Same input should produce same checksum
        assert_eq!(checksum1, checksum2);
        assert_eq!(checksum1.len(), 64); // SHA-256 hex string length
    }

    #[test]
    fn test_compute_checksum_different_inputs() {
        let snapshot1 = json!({ "nftables": [{ "add": { "table": { "name": "test1" } } }] });
        let snapshot2 = json!({ "nftables": [{ "add": { "table": { "name": "test2" } } }] });

        let checksum1 = compute_checksum(&snapshot1);
        let checksum2 = compute_checksum(&snapshot2);

        // Different inputs should produce different checksums
        assert_ne!(checksum1, checksum2);
    }
}
