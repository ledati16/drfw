//! The confirmed-ruleset record: the last ruleset applied *and kept*
//!
//! One record, shared by the GUI and the CLI, in DRFW's state directory
//! (`confirmed-ruleset.json`, mode 0600, written atomically). It is written
//! when the user keeps an apply:
//!
//! - a guarded apply was confirmed in time ([`RecordKind::Confirmed`],
//!   written by [`crate::core::apply_guard::GuardHandle::wait_outcome`]), or
//! - an apply ran without auto-revert ([`RecordKind::Unguarded`]: GUI with
//!   auto-revert off, `drfw apply --no-confirm`; written by
//!   [`crate::core::apply_guard::apply_guarded`]).
//!
//! Reverted, superseded or failed applies never write it.
//!
//! # What it means
//!
//! The record says what was **applied** and kept, not what is live now: a
//! reboot without Save to System, `nft flush ruleset` or another tool can
//! change the kernel's rules without DRFW noticing. The boot id
//! (`/proc/sys/kernel/random/boot_id`) at the time of the apply is stored, so
//! a record from an earlier boot is reported as "applied in an earlier
//! session" ([`ConfirmedRecord::from_this_boot`]).
//!
//! # Uses
//!
//! - Save to System (GUI) and `drfw save`: a ruleset is "tested" when its
//!   nftables JSON is **byte for byte** the recorded one
//!   ([`ConfirmedRecord::matches`]).
//! - The GUI's "Save the last kept rules" writes the recorded nftables JSON
//!   as text ([`ConfirmedRecord::nft_text`]).
//! - The retention guard ([`crate::core::retention`]) compares a new ruleset
//!   with the recorded one.
//!
//! # File format
//!
//! A JSON object `{"drfw_confirmed_record": 1, "kind", "boot_id", "nftables",
//! "profile"}`: `nftables` holds the exact JSON text that was sent to nft (as
//! a string, so the bytes survive), `profile` the ruleset in the profile
//! format (parsed with [`crate::core::profiles::parse_profile`]). An older
//! DRFW wrote the bare nftables JSON; such a record is still read (as
//! confirmed, boot unknown, without a ruleset).

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::core::firewall::FirewallRuleset;

/// File in DRFW's state directory holding the record.
pub const CONFIRMED_RULESET_FILE: &str = "confirmed-ruleset.json";

/// Version of the record format written by this build.
const RECORD_FORMAT_VERSION: u32 = 1;

/// Records larger than this are not read (a record holds two copies of a
/// ruleset; profiles are capped at [`crate::core::profiles::MAX_PROFILE_BYTES`]).
const MAX_RECORD_BYTES: u64 = 2 * crate::core::profiles::MAX_PROFILE_BYTES;

/// Where the kernel publishes the id of the current boot.
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// How an apply came to be kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// Applied with auto-revert and confirmed within the countdown
    Confirmed,
    /// Applied without auto-revert (the user turned the safety net off)
    Unguarded,
}

/// The last ruleset applied and kept (see the module docs).
#[derive(Clone)]
pub struct ConfirmedRecord {
    kind: RecordKind,
    /// Boot id when it was applied; `None` if unknown (older record, no procfs)
    boot_id: Option<String>,
    /// Exactly the nftables JSON text that was applied
    nftables: Arc<str>,
    /// The ruleset it was generated from; `None` for an older record or one
    /// whose ruleset can no longer be parsed
    ruleset: Option<Arc<FirewallRuleset>>,
}

impl std::fmt::Debug for ConfirmedRecord {
    // Concise: records can hold hundreds of rules and end up in logs
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmedRecord")
            .field("kind", &self.kind)
            .field("boot_id", &self.boot_id)
            .field("nftables_bytes", &self.nftables.len())
            .field("rules", &self.ruleset.as_ref().map(|r| r.rules.len()))
            .finish()
    }
}

/// On-disk form (see the module docs).
#[derive(Serialize, Deserialize)]
struct RecordFile {
    drfw_confirmed_record: u32,
    kind: RecordKind,
    #[serde(default)]
    boot_id: Option<String>,
    nftables: String,
    #[serde(default)]
    profile: Option<serde_json::Value>,
}

/// Borrowing twin of [`RecordFile`] for writing.
#[derive(Serialize)]
struct RecordFileRef<'a> {
    drfw_confirmed_record: u32,
    kind: RecordKind,
    boot_id: Option<&'a str>,
    nftables: &'a str,
    profile: Option<serde_json::Value>,
}

/// The id of the running boot (read once per process; it cannot change
/// while the process lives). `None` where procfs does not provide it.
pub fn current_boot_id() -> Option<&'static str> {
    static BOOT_ID: OnceLock<Option<String>> = OnceLock::new();
    BOOT_ID
        .get_or_init(|| {
            std::fs::read_to_string(BOOT_ID_PATH)
                .ok()
                .map(|id| id.trim().to_string())
                .filter(|id| !id.is_empty())
        })
        .as_deref()
}

impl ConfirmedRecord {
    /// A record of `json` (the nftables JSON generated from `ruleset`, as it
    /// is applied), stamped with the current boot id.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `json` cannot be serialized (never happens for
    /// generated rulesets).
    pub fn new(
        json: &serde_json::Value,
        ruleset: &FirewallRuleset,
        kind: RecordKind,
    ) -> serde_json::Result<Self> {
        Ok(Self {
            kind,
            boot_id: current_boot_id().map(str::to_string),
            nftables: serde_json::to_string(json)?.into(),
            ruleset: Some(Arc::new(ruleset.clone())),
        })
    }

    /// The record as if written during the boot `boot_id` (tests of
    /// earlier-session records).
    #[cfg(test)]
    pub(crate) fn with_boot_id(mut self, boot_id: Option<&str>) -> Self {
        self.boot_id = boot_id.map(str::to_string);
        self
    }

    /// How the ruleset was kept.
    pub fn kind(&self) -> RecordKind {
        self.kind
    }

    /// The exact nftables JSON text that was applied (what nft read on stdin).
    pub fn nftables_text(&self) -> &Arc<str> {
        &self.nftables
    }

    /// The `nft -f` text of exactly the recorded JSON
    /// ([`crate::core::nft_text::render_json`]): what Save to System should
    /// write for "the last kept rules". Unlike rendering [`Self::ruleset`]
    /// again, it cannot change when a newer DRFW generates rules differently.
    ///
    /// # Errors
    ///
    /// The recorded JSON cannot be rendered (see `render_json`).
    pub fn nft_text(&self) -> Result<String, String> {
        crate::core::nft_text::render_json(&self.nftables)
    }

    /// The ruleset that was applied, if the record has it.
    pub fn ruleset(&self) -> Option<&FirewallRuleset> {
        self.ruleset.as_deref()
    }

    /// True if `json` serializes to exactly the recorded bytes: the ruleset
    /// is the one applied and kept. Says nothing about what is live now.
    pub fn matches(&self, json: &serde_json::Value) -> bool {
        serde_json::to_vec(json).is_ok_and(|bytes| bytes == self.nftables.as_bytes())
    }

    /// True only if the record was written during the running boot. `false`
    /// for an earlier boot and when either boot id is unknown: the rules may
    /// have been replaced (by the boot config) since.
    pub fn from_this_boot(&self) -> bool {
        self.boot_id
            .as_deref()
            .is_some_and(|id| Some(id) == current_boot_id())
    }

    /// The record file in `dir`.
    fn path_in(dir: &Path) -> PathBuf {
        dir.join(CONFIRMED_RULESET_FILE)
    }

    /// Serializes the record in the file format.
    fn to_file_bytes(&self) -> serde_json::Result<Vec<u8>> {
        let profile = self
            .ruleset
            .as_deref()
            .map(crate::core::profiles::profile_value)
            .transpose()?;
        serde_json::to_vec(&RecordFileRef {
            drfw_confirmed_record: RECORD_FORMAT_VERSION,
            kind: self.kind,
            boot_id: self.boot_id.as_deref(),
            nftables: &self.nftables,
            profile,
        })
    }

    /// Parses a record file (current or older format); `None` if it is not
    /// a record this build understands.
    fn parse(bytes: &[u8]) -> Option<Self> {
        if let Ok(file) = serde_json::from_slice::<RecordFile>(bytes) {
            if file.drfw_confirmed_record > RECORD_FORMAT_VERSION {
                warn!(
                    "The confirmed-ruleset record has format {} (newer than this DRFW); ignoring it",
                    file.drfw_confirmed_record
                );
                return None;
            }
            let ruleset = file.profile.and_then(|profile| {
                crate::core::profiles::parse_profile("confirmed-ruleset", &profile.to_string())
                    .map_err(|e| warn!("Ignoring the ruleset of the confirmed record: {e}"))
                    .ok()
            });
            return Some(Self {
                kind: file.kind,
                boot_id: file.boot_id,
                nftables: file.nftables.into(),
                ruleset: ruleset.map(Arc::new),
            });
        }
        // Older DRFW: the bare nftables JSON of a confirmed guard
        let text = std::str::from_utf8(bytes).ok()?;
        serde_json::from_str::<serde_json::Value>(text)
            .ok()?
            .get("nftables")?;
        Some(Self {
            kind: RecordKind::Confirmed,
            boot_id: None,
            nftables: text.into(),
            ruleset: None,
        })
    }

    /// Reads the record in `dir` (blocking; for GUI startup and tests).
    /// `None` when there is none or it cannot be used (logged).
    pub fn load_from_blocking(dir: &Path) -> Option<Self> {
        let path = Self::path_in(dir);
        let too_large = std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_RECORD_BYTES);
        if too_large {
            warn!("Ignoring {}: too large", path.display());
            return None;
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                warn!("Cannot read {}: {e}", path.display());
                return None;
            }
        };
        let record = Self::parse(&bytes);
        if record.is_none() {
            warn!(
                "Ignoring {}: not a confirmed-ruleset record",
                path.display()
            );
        }
        record
    }

    /// [`Self::load_from_blocking`] on the blocking pool.
    pub async fn load_from(dir: &Path) -> Option<Self> {
        let dir = dir.to_path_buf();
        tokio::task::spawn_blocking(move || Self::load_from_blocking(&dir))
            .await
            .ok()
            .flatten()
    }

    /// The record in DRFW's state directory (blocking).
    pub fn load_blocking() -> Option<Self> {
        Self::load_from_blocking(&crate::utils::get_state_dir()?)
    }

    /// The record in DRFW's state directory.
    pub async fn load() -> Option<Self> {
        Self::load_from(&crate::utils::get_state_dir()?).await
    }

    /// Writes the record to `dir` (atomic, 0600), replacing the previous one.
    /// Failures are only logged: the record is advisory, the apply it
    /// describes already happened.
    pub async fn save_in(&self, dir: &Path) {
        let path = Self::path_in(dir);
        let bytes = match self.to_file_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Cannot serialize the confirmed-ruleset record: {e}");
                return;
            }
        };
        if let Err(e) = crate::utils::write_atomic_private_async(path, bytes).await {
            warn!("Cannot record the confirmed ruleset: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_helpers::{create_test_rule, create_test_ruleset};

    fn record_of(ruleset: &FirewallRuleset, kind: RecordKind) -> ConfirmedRecord {
        ConfirmedRecord::new(&ruleset.to_nftables_json(), ruleset, kind).unwrap()
    }

    #[tokio::test]
    async fn test_round_trip_keeps_bytes_ruleset_kind_and_boot() {
        let dir = tempfile::tempdir().unwrap();
        let mut ruleset = create_test_ruleset();
        ruleset.rules.push(create_test_rule("Web", Some(443)));
        let json = ruleset.to_nftables_json();
        record_of(&ruleset, RecordKind::Unguarded)
            .save_in(dir.path())
            .await;

        let loaded = ConfirmedRecord::load_from(dir.path())
            .await
            .expect("record");
        assert_eq!(loaded.kind(), RecordKind::Unguarded);
        assert!(loaded.matches(&json), "same JSON bytes");
        assert_eq!(
            loaded.nftables_text().as_bytes(),
            serde_json::to_vec(&json).unwrap()
        );
        let rules = &loaded.ruleset().expect("ruleset").rules;
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].id, ruleset.rules[1].id);
        assert_eq!(rules[1].label, "Web");
        assert_eq!(loaded.from_this_boot(), current_boot_id().is_some());

        // Any change to the ruleset: no match
        ruleset.rules[0].enabled = false;
        assert!(!loaded.matches(&ruleset.to_nftables_json()));

        #[cfg(unix)]
        {
            let mode = std::os::unix::fs::PermissionsExt::mode(
                &std::fs::metadata(dir.path().join(CONFIRMED_RULESET_FILE))
                    .unwrap()
                    .permissions(),
            );
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn test_record_from_another_boot_is_an_earlier_session() {
        let dir = tempfile::tempdir().unwrap();
        let ruleset = create_test_ruleset();
        let mut file: serde_json::Value = serde_json::from_slice(
            &record_of(&ruleset, RecordKind::Confirmed)
                .to_file_bytes()
                .unwrap(),
        )
        .unwrap();
        file["boot_id"] = serde_json::json!("00000000-0000-0000-0000-000000000000");
        std::fs::write(
            dir.path().join(CONFIRMED_RULESET_FILE),
            serde_json::to_vec(&file).unwrap(),
        )
        .unwrap();

        let loaded = ConfirmedRecord::load_from_blocking(dir.path()).expect("record");
        assert!(!loaded.from_this_boot());
        assert!(loaded.matches(&ruleset.to_nftables_json()));
        assert_eq!(loaded.kind(), RecordKind::Confirmed);
    }

    /// A record written by an older DRFW (the bare nftables JSON) still
    /// counts as confirmed, with no ruleset and an unknown boot.
    #[test]
    fn test_legacy_record_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let json = create_test_ruleset().to_nftables_json();
        std::fs::write(
            dir.path().join(CONFIRMED_RULESET_FILE),
            serde_json::to_vec(&json).unwrap(),
        )
        .unwrap();

        let loaded = ConfirmedRecord::load_from_blocking(dir.path()).expect("record");
        assert!(loaded.matches(&json));
        assert_eq!(loaded.kind(), RecordKind::Confirmed);
        assert!(loaded.ruleset().is_none());
        assert!(!loaded.from_this_boot());
    }

    #[test]
    fn test_missing_garbage_and_newer_records_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ConfirmedRecord::load_from_blocking(dir.path()).is_none());

        let path = dir.path().join(CONFIRMED_RULESET_FILE);
        std::fs::write(&path, b"not json").unwrap();
        assert!(ConfirmedRecord::load_from_blocking(dir.path()).is_none());
        std::fs::write(&path, b"{\"something\": 1}").unwrap();
        assert!(ConfirmedRecord::load_from_blocking(dir.path()).is_none());
        std::fs::write(
            &path,
            br#"{"drfw_confirmed_record": 99, "kind": "confirmed", "nftables": "{}"}"#,
        )
        .unwrap();
        assert!(ConfirmedRecord::load_from_blocking(dir.path()).is_none());
    }

    /// An unparsable ruleset does not lose the byte comparison.
    #[test]
    fn test_unreadable_ruleset_keeps_the_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(CONFIRMED_RULESET_FILE),
            br#"{"drfw_confirmed_record": 1, "kind": "confirmed", "nftables": "{\"nftables\":[]}", "profile": {"version": 999}}"#,
        )
        .unwrap();
        let loaded = ConfirmedRecord::load_from_blocking(dir.path()).expect("record");
        assert!(loaded.ruleset().is_none());
        assert!(loaded.matches(&serde_json::json!({ "nftables": [] })));
    }
}
