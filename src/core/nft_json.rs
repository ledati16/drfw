use crate::core::error::{Error, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::{error, info, warn};

/// Timeout for nft apply/restore operations
const NFT_APPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Applies a ruleset and returns the PRE-APPLY snapshot in a single elevated operation.
/// This reduces the number of password prompts to one.
///
/// # Arguments
///
/// * `json_payload` - The nftables JSON payload to apply (must contain `nftables` array)
///
/// # Errors
///
/// Returns error if:
/// - `nft` command execution fails
/// - Privilege escalation fails or is denied
/// - JSON parsing of snapshot fails
///
/// # Panics
///
/// May panic if `json_payload` structure is malformed (not an object or missing `nftables` key).
/// Callers should use `to_nftables_json()` to ensure correct structure.
///
/// # Phase 1 Optimization
///
/// Takes JSON directly to avoid cloning entire ruleset
pub async fn apply_with_snapshot(mut json_payload: Value) -> Result<Value> {
    // Inject a list table command AFTER the table creation (position 1, after "add table")
    // This captures the PRE-APPLY snapshot for rollback
    if let Some(nft_rules) = json_payload["nftables"].as_array_mut() {
        nft_rules.insert(
            1,
            serde_json::json!({ "list": { "table": { "family": "inet", "name": "drfw" } } }),
        );
    }

    let json_string = serde_json::to_string(&json_payload)?;

    info!("Applying ruleset with integrated snapshot via single pkexec...");

    let mut child = crate::elevation::create_elevated_nft_command(&["--json", "-f", "-"])
        .map_err(|e| {
            error!("Privilege escalation unavailable: {e}");
            Error::Internal(format!("Privilege escalation unavailable: {e}"))
        })?
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

    let output = match tokio::time::timeout(NFT_APPLY_TIMEOUT, child.wait_with_output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            error!("Failed to read nft output: {e}");
            return Err(Error::Internal(format!("Failed to read nft output: {e}")));
        }
        Err(_) => {
            error!("nft apply timed out after {} seconds", NFT_APPLY_TIMEOUT.as_secs());
            return Err(Error::Internal(format!(
                "nft apply timed out after {} seconds",
                NFT_APPLY_TIMEOUT.as_secs()
            )));
        }
    };

    if output.status.success() {
        info!("Combined apply successful");
        let val: Value = serde_json::from_slice(&output.stdout).map_err(|e| {
            error!("Failed to parse snapshot from nft output: {e}");
            Error::Internal(format!("Failed to parse snapshot: {e}"))
        })?;
        Ok(val)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
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
/// Accepts two formats:
/// 1. Command format: `{"nftables": [{"add": {"table": ...}}, ...]}`
/// 2. Output format: `{"nftables": [{"table": ...}, {"chain": ...}, ...]}`
///
/// # Errors
///
/// Returns `Err` if:
/// - Snapshot is missing required `nftables` array
/// - Snapshot contains neither table operations nor table objects
pub fn validate_snapshot(snapshot: &Value) -> Result<()> {
    // Check top-level structure
    let nftables = snapshot
        .get("nftables")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::Internal("Invalid snapshot: missing nftables array".to_string()))?;

    // Allow empty snapshots for emergency recovery scenarios
    if nftables.is_empty() {
        warn!("Snapshot contains empty ruleset, but allowing for recovery scenarios");
        return Ok(()); // Explicitly allow empty
    }

    // Verify it contains table operations (command format: add/list/flush)
    let has_table_ops = nftables.iter().any(|v| {
        v.get("add").and_then(|a| a.get("table")).is_some()
            || v.get("list").and_then(|l| l.get("table")).is_some()
            || v.get("flush").and_then(|f| f.get("table")).is_some()
    });

    // OR it contains table objects (output format from nft list)
    let has_table_objects = nftables.iter().any(|v| v.get("table").is_some());

    if !has_table_ops && !has_table_objects {
        return Err(Error::Internal(
            "Invalid snapshot: no table operations or table objects found".to_string(),
        ));
    }

    Ok(())
}

/// Computes SHA-256 checksum of a JSON value.
///
/// The checksum is computed on the canonical JSON string representation.
/// Used by integration tests to verify snapshot integrity.
#[allow(dead_code)] // Used in integration tests, not in binary
pub fn compute_checksum(snapshot: &Value) -> String {
    let json_str = serde_json::to_string(snapshot).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json_str.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Reverts to a previous snapshot.
///
/// **CRITICAL:** Prepends flush operations to prevent rule duplication.
/// Snapshots from `nft list` are in object format and would otherwise
/// APPEND to existing rules instead of replacing them.
///
/// # Safety: Atomic Flush + Restore
///
/// The flush operation (`flush table inet drfw`) temporarily leaves chains with
/// DROP policies but no rules, which **blocks all incoming traffic** including
/// established connections. However, this is safe because:
///
/// 1. **Atomic application**: `nft --json -f -` applies the entire JSON as a single
///    transaction. Flush and rule restoration happen atomically.
/// 2. **All-or-nothing**: If ANY operation fails validation, nft rejects the ENTIRE
///    batch without applying partial changes.
/// 3. **No intermediate state**: There is no observable moment where the table is
///    flushed but rules aren't restored - it's a single kernel operation.
///
/// If nft crashes mid-apply (kernel panic level event) or power is lost, the emergency
/// default ruleset (`get_emergency_default_ruleset()`) can restore basic connectivity
/// (loopback + established/related).
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

    // CRITICAL FIX: Prepend flush operations to prevent duplicate rules
    // Snapshots are in object format from "nft list", which APPENDs rules.
    // We need to flush first, then restore.
    let mut modified_snapshot = snapshot.clone();
    if let Some(nftables) = modified_snapshot["nftables"].as_array_mut() {
        // Insert flush and table creation at the beginning
        nftables.insert(
            0,
            serde_json::json!({ "add": { "table": { "family": "inet", "name": "drfw" } } }),
        );
        nftables.insert(
            1,
            serde_json::json!({ "flush": { "table": { "family": "inet", "name": "drfw" } } }),
        );
    }

    let json_string = serde_json::to_string(&modified_snapshot)?;
    info!("Snapshot validation passed, proceeding with restore (with flush prepended)");

    let mut child = crate::elevation::create_elevated_nft_command(&["--json", "-f", "-"])
        .map_err(|e| {
            error!("Privilege escalation unavailable for restore: {e}");
            Error::Internal(format!("Privilege escalation unavailable: {e}"))
        })?
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

    let output = match tokio::time::timeout(NFT_APPLY_TIMEOUT, child.wait_with_output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            error!("Failed to read nft output during restore: {e}");
            return Err(Error::Internal(format!("Failed to read nft output: {e}")));
        }
        Err(_) => {
            error!("nft restore timed out after {} seconds", NFT_APPLY_TIMEOUT.as_secs());
            return Err(Error::Internal(format!(
                "nft restore timed out after {} seconds",
                NFT_APPLY_TIMEOUT.as_secs()
            )));
        }
    };

    if output.status.success() {
        info!("Restore successful");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
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
    let state_dir = crate::utils::get_state_dir()
        .ok_or_else(|| Error::Internal("Failed to get state directory".to_string()))?;

    crate::utils::ensure_dirs()?;

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("snapshot_{timestamp}.json");
    let path = state_dir.join(&filename);

    let json_string = serde_json::to_string_pretty(snapshot)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

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
    let state_dir = crate::utils::get_state_dir()
        .ok_or_else(|| Error::Internal("Failed to get state directory".to_string()))?;

    // Case-sensitive extension check is intentional - on Linux/Unix systems, filenames are case-sensitive
    // and we specifically want lowercase `.json` files, not `.JSON` or other variants
    let snapshots: Vec<std::path::PathBuf> = std::fs::read_dir(&state_dir)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                n.starts_with("snapshot_")
                    && std::path::Path::new(n)
                        .extension()
                        .is_some_and(|ext| ext == "json") // Case-sensitive as intended
            })
        })
        .collect();

    // Issue #13: Sort by modification time with O(n log n) instead of O(n² log n)
    // Collect metadata once, then sort
    let mut snapshots_with_time: Vec<_> = snapshots
        .into_iter()
        .filter_map(|path| {
            let time = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
            Some((path, time))
        })
        .collect();

    snapshots_with_time.sort_unstable_by(|a, b| b.1.cmp(&a.1)); // Newest first
    let snapshots: Vec<_> = snapshots_with_time.into_iter().map(|(p, _)| p).collect();

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
/// Returns an ultra-safe emergency default ruleset for disaster recovery.
///
/// This ruleset is designed to be minimally disruptive while protecting the system:
/// - Allows loopback traffic (essential for local services)
/// - Allows established/related connections (preserves existing connections)
/// - Drops all new incoming connections
/// - Allows all outbound traffic
///
/// # Use Case
///
/// This is the "panic button" fallback when:
/// - All snapshots are corrupted or unavailable
/// - User accidentally locked themselves out
/// - Need immediate safe firewall state
///
/// # Safety
///
/// This ruleset is guaranteed to:
/// - Never break SSH connections (established traffic allowed)
/// - Never break local services (loopback allowed)
/// - Never prevent outbound traffic (policy accept on OUTPUT)
///
/// # Example
///
/// ```
/// use drfw::core::nft_json::get_emergency_default_ruleset;
///
/// let emergency_ruleset = get_emergency_default_ruleset();
/// // Apply when all else fails
/// ```
pub fn get_emergency_default_ruleset() -> Value {
    use serde_json::json;

    json!({
        "nftables": [
            // Metadata for identification
            { "metainfo": { "json_schema_version": 1 } },

            // Add the table
            { "add": { "table": { "family": "inet", "name": "drfw" } } },

            // Flush any existing rules
            { "flush": { "table": { "family": "inet", "name": "drfw" } } },

            // INPUT chain - default DROP
            { "add": {
                "chain": {
                    "family": "inet",
                    "table": "drfw",
                    "name": "input",
                    "type": "filter",
                    "hook": "input",
                    "prio": -10,
                    "policy": "drop"
                }
            } },

            // FORWARD chain - default DROP (we're not a router)
            { "add": {
                "chain": {
                    "family": "inet",
                    "table": "drfw",
                    "name": "forward",
                    "type": "filter",
                    "hook": "forward",
                    "prio": -10,
                    "policy": "drop"
                }
            } },

            // OUTPUT chain - default ACCEPT (allow outbound)
            { "add": {
                "chain": {
                    "family": "inet",
                    "table": "drfw",
                    "name": "output",
                    "type": "filter",
                    "hook": "output",
                    "prio": -10,
                    "policy": "accept"
                }
            } },

            // Rule 1: Allow loopback (essential for local services)
            { "add": {
                "rule": {
                    "family": "inet",
                    "table": "drfw",
                    "chain": "input",
                    "expr": [
                        { "match": {
                            "left": { "meta": { "key": "iifname" } },
                            "op": "==",
                            "right": "lo"
                        } },
                        { "accept": null }
                    ],
                    "comment": "EMERGENCY: allow loopback"
                }
            } },

            // Rule 2: Drop invalid packets early
            { "add": {
                "rule": {
                    "family": "inet",
                    "table": "drfw",
                    "chain": "input",
                    "expr": [
                        { "match": {
                            "left": { "ct": { "key": "state" } },
                            "op": "==",
                            "right": ["invalid"]
                        } },
                        { "drop": null }
                    ],
                    "comment": "EMERGENCY: drop invalid packets"
                }
            } },

            // Rule 3: Allow established/related (preserves SSH and existing connections)
            { "add": {
                "rule": {
                    "family": "inet",
                    "table": "drfw",
                    "chain": "input",
                    "expr": [
                        { "match": {
                            "left": { "ct": { "key": "state" } },
                            "op": "in",
                            "right": ["established", "related"]
                        } },
                        { "accept": null }
                    ],
                    "comment": "EMERGENCY: allow established connections (preserves SSH)"
                }
            } },

            // Rule 4: Allow ICMP (for network diagnostics)
            { "add": {
                "rule": {
                    "family": "inet",
                    "table": "drfw",
                    "chain": "input",
                    "expr": [
                        { "match": {
                            "left": { "meta": { "key": "l4proto" } },
                            "op": "==",
                            "right": "icmp"
                        } },
                        { "accept": null }
                    ],
                    "comment": "EMERGENCY: allow ICMP"
                }
            } },

            // Rule 5: Allow ICMPv6 (essential for IPv6)
            { "add": {
                "rule": {
                    "family": "inet",
                    "table": "drfw",
                    "chain": "input",
                    "expr": [
                        { "match": {
                            "left": { "meta": { "key": "l4proto" } },
                            "op": "==",
                            "right": "ipv6-icmp"
                        } },
                        { "accept": null }
                    ],
                    "comment": "EMERGENCY: allow ICMPv6"
                }
            } }

            // Everything else is dropped by default policy
        ]
    })
}

/// Attempts to restore firewall rules from snapshots with cascading fallback.
///
/// This function implements a robust recovery strategy:
/// 1. Tries each saved snapshot in order (newest first)
/// 2. If all snapshots fail, applies the emergency default ruleset
///
/// The emergency default ruleset ensures the system remains accessible while
/// providing basic protection.
///
/// # Recovery Strategy
///
/// - **Snapshot cascade**: Tries up to 5 most recent snapshots
/// - **Emergency fallback**: Ultra-safe ruleset (loopback + established only)
/// - **Never fails completely**: Always restores to a safe state
///
/// # Errors
///
/// Only returns `Err` if the emergency default ruleset fails to apply,
/// which indicates a fundamental system problem (nftables not working).
///
/// # Example
///
/// ```no_run
/// use drfw::core::nft_json::restore_with_fallback;
///
/// # async fn example() {
/// // Try to restore from snapshots, falling back to emergency default
/// match restore_with_fallback().await {
///     Ok(()) => println!("Firewall restored successfully"),
///     Err(e) => eprintln!("Critical: Even emergency ruleset failed: {}", e),
/// }
/// # }
/// ```
pub async fn restore_with_fallback() -> Result<()> {
    let snapshots = list_snapshots()?;

    if snapshots.is_empty() {
        warn!("No snapshots available, applying emergency default ruleset");
        let emergency = get_emergency_default_ruleset();
        return restore_snapshot(&emergency).await;
    }

    info!(
        "Found {} snapshot(s), attempting cascade restore",
        snapshots.len()
    );

    let mut last_error = None;

    for (i, snapshot_path) in snapshots.iter().enumerate() {
        info!(
            "Attempting restore from snapshot {}/{}: {:?}",
            i + 1,
            snapshots.len(),
            snapshot_path
        );

        match std::fs::read_to_string(snapshot_path) {
            Ok(json_str) => match serde_json::from_str::<Value>(&json_str) {
                Ok(snapshot) => match restore_snapshot(&snapshot).await {
                    Ok(()) => {
                        info!("Successfully restored from snapshot: {:?}", snapshot_path);
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("Failed to restore from {:?}: {}", snapshot_path, e);
                        last_error = Some(e);
                    }
                },
                Err(e) => {
                    warn!("Failed to parse snapshot {:?}: {}", snapshot_path, e);
                    last_error = Some(Error::Serialization(e));
                }
            },
            Err(e) => {
                warn!("Failed to read snapshot {:?}: {}", snapshot_path, e);
                last_error = Some(Error::Io(e));
            }
        }
    }

    // All snapshots failed - apply emergency default as last resort
    warn!(
        "All {} snapshot(s) failed to restore. Applying emergency default ruleset.",
        snapshots.len()
    );

    if let Some(ref err) = last_error {
        warn!("Last snapshot error: {}", err);
    }

    let emergency = get_emergency_default_ruleset();
    restore_snapshot(&emergency).await.map_err(|e| {
        error!("CRITICAL: Emergency default ruleset failed to apply: {}", e);
        e
    })
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

        // Should succeed with warning logged
        assert!(validate_snapshot(&empty_snapshot).is_ok()); // ✅ Fixed
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
    fn test_validate_snapshot_with_table_objects() {
        // Output format from nft --json list table (contains table objects, not operations)
        let valid_snapshot = json!({
            "nftables": [
                { "table": { "family": "inet", "name": "drfw", "handle": 1 } },
                { "chain": { "family": "inet", "table": "drfw", "name": "input", "handle": 2 } }
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

    #[test]
    fn test_emergency_default_ruleset_structure() {
        let emergency = get_emergency_default_ruleset();

        // Should be valid JSON
        assert!(emergency.is_object());

        // Should have nftables array
        let nftables = emergency["nftables"]
            .as_array()
            .expect("nftables should be an array");
        assert!(!nftables.is_empty());

        // Should pass validation
        assert!(validate_snapshot(&emergency).is_ok());
    }

    #[test]
    fn test_emergency_default_has_required_chains() {
        let emergency = get_emergency_default_ruleset();
        let nftables = emergency["nftables"].as_array().unwrap();

        // Count chain definitions
        let chains: Vec<_> = nftables
            .iter()
            .filter_map(|item| item.get("add").and_then(|a| a.get("chain")))
            .collect();

        // Should have input, forward, and output chains
        assert_eq!(
            chains.len(),
            3,
            "Should have 3 chains (input, forward, output)"
        );

        // Verify chain names
        let chain_names: Vec<_> = chains
            .iter()
            .filter_map(|chain| chain.get("name").and_then(|n| n.as_str()))
            .collect();

        assert!(chain_names.contains(&"input"));
        assert!(chain_names.contains(&"forward"));
        assert!(chain_names.contains(&"output"));
    }

    #[test]
    fn test_emergency_default_has_loopback_rule() {
        let emergency = get_emergency_default_ruleset();
        let nftables = emergency["nftables"].as_array().unwrap();

        // Look for loopback rule
        let has_loopback = nftables.iter().any(|item| {
            if let Some(rule) = item.get("add").and_then(|a| a.get("rule"))
                && let Some(comment) = rule.get("comment").and_then(|c| c.as_str())
            {
                return comment.contains("loopback");
            }
            false
        });

        assert!(
            has_loopback,
            "Emergency ruleset must allow loopback traffic"
        );
    }

    #[test]
    fn test_emergency_default_has_established_rule() {
        let emergency = get_emergency_default_ruleset();
        let nftables = emergency["nftables"].as_array().unwrap();

        // Look for established/related rule
        let has_established = nftables.iter().any(|item| {
            if let Some(rule) = item.get("add").and_then(|a| a.get("rule"))
                && let Some(comment) = rule.get("comment").and_then(|c| c.as_str())
            {
                return comment.contains("established");
            }
            false
        });

        assert!(
            has_established,
            "Emergency ruleset must allow established connections"
        );
    }

    #[test]
    fn test_emergency_default_has_icmp_rules() {
        let emergency = get_emergency_default_ruleset();
        let nftables = emergency["nftables"].as_array().unwrap();

        // Look for ICMP rules
        let has_icmp = nftables.iter().any(|item| {
            if let Some(rule) = item.get("add").and_then(|a| a.get("rule"))
                && let Some(comment) = rule.get("comment").and_then(|c| c.as_str())
            {
                return comment.contains("ICMP");
            }
            false
        });

        assert!(
            has_icmp,
            "Emergency ruleset must allow ICMP for diagnostics"
        );
    }

    #[test]
    fn test_emergency_default_policies() {
        let emergency = get_emergency_default_ruleset();
        let nftables = emergency["nftables"].as_array().unwrap();

        // Extract chains and their policies
        let chains: Vec<_> = nftables
            .iter()
            .filter_map(|item| item.get("add").and_then(|a| a.get("chain")))
            .collect();

        // Find input chain and verify DROP policy
        let input_chain = chains
            .iter()
            .find(|c| c.get("name").and_then(|n| n.as_str()) == Some("input"))
            .expect("Should have input chain");

        assert_eq!(
            input_chain.get("policy").and_then(|p| p.as_str()),
            Some("drop"),
            "Input chain should have DROP policy"
        );

        // Find output chain and verify ACCEPT policy
        let output_chain = chains
            .iter()
            .find(|c| c.get("name").and_then(|n| n.as_str()) == Some("output"))
            .expect("Should have output chain");

        assert_eq!(
            output_chain.get("policy").and_then(|p| p.as_str()),
            Some("accept"),
            "Output chain should have ACCEPT policy (don't block outbound)"
        );
    }

    #[test]
    fn test_emergency_default_has_table_ops() {
        let emergency = get_emergency_default_ruleset();
        let nftables = emergency["nftables"].as_array().unwrap();

        // Should have table add operation
        let has_table_add = nftables.iter().any(|item| {
            item.get("add")
                .and_then(|a| a.get("table"))
                .and_then(|t| t.get("name"))
                .and_then(|n| n.as_str())
                == Some("drfw")
        });

        assert!(has_table_add, "Should create drfw table");

        // Should have table flush operation
        let has_table_flush = nftables.iter().any(|item| {
            item.get("flush")
                .and_then(|f| f.get("table"))
                .and_then(|t| t.get("name"))
                .and_then(|n| n.as_str())
                == Some("drfw")
        });

        assert!(has_table_flush, "Should flush existing rules");
    }
}
