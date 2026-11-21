//! Diagnostics event log: loading, change detection, display rows, filtering
//!
//! The audit log is read off the UI thread and turned into display rows once
//! per load ([`load_if_changed`]). Filter and search results are recomputed
//! only when the rows, the filter or the search text change
//! ([`DiagnosticsLog::refilter`]), so `view()` only borrows cached strings.
//!
//! Reloads are driven by a timer while the modal is open. Each tick stats the
//! log and re-reads it only when its length or modification time changed.
//! At most one load runs at a time (`in_flight`), and every load carries a
//! generation number: a result from a load that was superseded (the log was
//! cleared meanwhile) is dropped instead of overwriting newer rows.

use std::path::PathBuf;
use std::time::SystemTime;

use jiff::civil::Date;
use jiff::tz::TimeZone;

use crate::app::DiagnosticsFilter;
use crate::audit::{AuditEvent, EventType};
use crate::core::error::NftablesErrorPattern;

/// Maximum number of audit entries loaded for display (most recent kept)
pub(crate) const MAX_DISPLAY_ENTRIES: usize = 1000;

/// Semantic colour of a row's status dot (mapped to theme colours in the view)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowTone {
    Success,
    Warning,
    Danger,
    Accent,
}

/// One pre-formatted event log row
#[derive(Debug, Clone)]
pub struct DiagnosticRow {
    /// Local time, `HH:MM:SS` for today, `YYYY-MM-DD HH:MM:SS` otherwise
    pub time: String,
    /// Human-readable description of the event
    pub description: String,
    pub tone: RowTone,
    success: bool,
    event_type: EventType,
    /// Lowercased `time` + `description`, matched against the search text
    search_text: String,
}

/// What a load saw of the log file, used to skip re-reading an unchanged log
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStamp {
    Missing,
    Present {
        len: u64,
        modified: Option<SystemTime>,
    },
}

/// Result of [`load_if_changed`]
#[derive(Debug, Clone)]
pub enum AuditLoad {
    /// The log has the stamp the caller already showed; nothing was read
    Unchanged,
    /// The log was (re)read
    Loaded {
        stamp: LogStamp,
        /// The local date the `time` columns were formatted against
        day: Date,
        /// Most recent first, at most [`MAX_DISPLAY_ENTRIES`]
        rows: Vec<DiagnosticRow>,
    },
}

/// Diagnostics modal state: cached rows, filter results and load bookkeeping
#[derive(Debug, Default)]
pub struct DiagnosticsLog {
    rows: Vec<DiagnosticRow>,
    /// Indices into `rows` that pass the filter and search
    visible: Vec<usize>,
    /// Search text as typed
    pub search: String,
    search_lower: String,
    /// Cached "N events" / "N of M events" label
    pub count_label: String,
    /// Whether any visible row shows a date (the time column is then wider)
    pub any_visible_dated: bool,
    /// Stamp and day of the rows on screen; `None` until the first load lands
    loaded: Option<(LogStamp, Date)>,
    generation: u64,
    in_flight: bool,
    /// The "Clear log?" confirmation is showing
    pub confirm_clear: bool,
    /// A clear is running; loads are held off until it finishes
    pub clearing: bool,
}

impl DiagnosticsLog {
    /// Starts a load unless one is running or the log is being cleared.
    ///
    /// Returns the load's generation and the stamp it may skip re-reading
    /// for. The stamp is `None` (always read) before the first load and when
    /// the local day changed since the rows were formatted, so "today" rows
    /// regain their date after midnight.
    pub fn begin_load(&mut self, today: Date) -> Option<(u64, Option<LogStamp>)> {
        if self.in_flight || self.clearing {
            return None;
        }
        self.in_flight = true;
        self.generation = self.generation.wrapping_add(1);
        let known = self
            .loaded
            .and_then(|(stamp, day)| (day == today).then_some(stamp));
        Some((self.generation, known))
    }

    /// Applies a finished load. Results from a superseded generation are
    /// dropped. Returns `true` if the rows were replaced.
    pub fn finish_load(
        &mut self,
        generation: u64,
        load: AuditLoad,
        filter: DiagnosticsFilter,
    ) -> bool {
        if generation != self.generation {
            return false;
        }
        self.in_flight = false;
        let AuditLoad::Loaded { stamp, day, rows } = load else {
            return false;
        };
        self.rows = rows;
        self.loaded = Some((stamp, day));
        self.refilter(filter);
        true
    }

    /// Supersedes any running load: its result will be ignored, and the next
    /// load re-reads the log regardless of its stamp.
    pub fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.in_flight = false;
        self.loaded = None;
    }

    /// Updates the search text and the visible rows.
    pub fn set_search(&mut self, search: String, filter: DiagnosticsFilter) {
        self.search_lower = search.trim().to_lowercase();
        self.search = search;
        self.refilter(filter);
    }

    /// Recomputes the visible rows and the count label.
    pub fn refilter(&mut self, filter: DiagnosticsFilter) {
        let search = self.search_lower.as_str();
        self.visible.clear();
        self.visible.extend(
            self.rows
                .iter()
                .enumerate()
                .filter(|(_, row)| {
                    matches_filter(row, filter)
                        && (search.is_empty() || row.search_text.contains(search))
                })
                .map(|(i, _)| i),
        );
        let any_dated = self
            .visible_rows()
            .any(|row| row.time.len() > TIME_ONLY_LEN);
        self.any_visible_dated = any_dated;
        let total = self.rows.len();
        let matching = self.visible.len();
        let noun = if total == 1 { "event" } else { "events" };
        self.count_label = if matching > ROWS_SHOWN {
            format!("newest {ROWS_SHOWN} of {matching} matching ({total} {noun}); search to narrow")
        } else if matching == total {
            format!("{total} {noun}")
        } else {
            format!("{matching} of {total} {noun}")
        };
    }

    /// Rows passing the current filter and search, most recent first, at
    /// most [`ROWS_SHOWN`] (the modal is rebuilt on every refresh, so it
    /// stays cheap with a long log)
    pub fn visible_rows(&self) -> impl Iterator<Item = &DiagnosticRow> {
        self.visible
            .iter()
            .take(ROWS_SHOWN)
            .filter_map(|&i| self.rows.get(i))
    }

    /// Whether no row passes the current filter and search
    pub fn nothing_visible(&self) -> bool {
        self.visible.is_empty()
    }
}

/// Most rows the diagnostics modal lists at once.
pub const ROWS_SHOWN: usize = 200;

/// Length of an `HH:MM:SS` time
const TIME_ONLY_LEN: usize = 8;

fn matches_filter(row: &DiagnosticRow, filter: DiagnosticsFilter) -> bool {
    match filter {
        DiagnosticsFilter::All => true,
        DiagnosticsFilter::Successes => row.success,
        DiagnosticsFilter::Errors => !row.success,
        DiagnosticsFilter::ProfileChanges => matches!(
            row.event_type,
            EventType::ProfileCreated
                | EventType::ProfileDeleted
                | EventType::ProfileRenamed
                | EventType::ProfileSwitched
                | EventType::ProfileReset
        ),
        DiagnosticsFilter::Settings => matches!(row.event_type, EventType::SettingsSaved),
    }
}

/// Today's date in the system time zone
pub fn local_today() -> Date {
    jiff::ZonedDateTime::now().date()
}

/// Formats an event time in `tz`: `HH:MM:SS` on `today`, else with the date.
pub fn format_event_time(timestamp: jiff::Timestamp, tz: &TimeZone, today: Date) -> String {
    let local = timestamp.to_zoned_datetime(tz.clone());
    if local.date() == today {
        local.strftime("%H:%M:%S").to_string()
    } else {
        local.strftime("%Y-%m-%d %H:%M:%S").to_string()
    }
}

/// Builds display rows from events (order preserved).
pub fn build_rows(events: &[AuditEvent], tz: &TimeZone, today: Date) -> Vec<DiagnosticRow> {
    events
        .iter()
        .map(|event| {
            let time = format_event_time(event.timestamp, tz, today);
            let (tone, description) = describe_event(event);
            let search_text = format!("{time} {description}").to_lowercase();
            DiagnosticRow {
                time,
                description,
                tone,
                success: event.success,
                event_type: event.event_type.clone(),
                search_text,
            }
        })
        .collect()
}

/// Stats the log and, if its stamp differs from `known`, reads the last
/// [`MAX_DISPLAY_ENTRIES`] events and formats them for `today` in the system
/// time zone. Damaged lines are skipped.
pub async fn load_if_changed(
    path: Option<PathBuf>,
    known: Option<LogStamp>,
    today: Date,
) -> AuditLoad {
    let stamp = match &path {
        Some(path) => match tokio::fs::metadata(path).await {
            Ok(meta) => LogStamp::Present {
                len: meta.len(),
                modified: meta.modified().ok(),
            },
            Err(_) => LogStamp::Missing,
        },
        None => LogStamp::Missing,
    };
    if known == Some(stamp) {
        return AuditLoad::Unchanged;
    }

    let events = match (&path, stamp) {
        (Some(path), LogStamp::Present { .. }) => read_events(path).await,
        _ => Vec::new(),
    };
    let rows = build_rows(&events, &TimeZone::system(), today);
    AuditLoad::Loaded {
        stamp,
        day: today,
        rows,
    }
}

/// Reads the newest [`MAX_DISPLAY_ENTRIES`] events, most recent first.
async fn read_events(path: &std::path::Path) -> Vec<AuditEvent> {
    use tokio::io::AsyncBufReadExt;

    let Ok(file) = tokio::fs::File::open(path).await else {
        return Vec::new();
    };

    // Split on raw bytes: a damaged line (invalid UTF-8, truncated JSON) is
    // skipped instead of ending the whole read.
    let mut lines = tokio::io::BufReader::new(file).split(b'\n');
    let mut events = std::collections::VecDeque::with_capacity(MAX_DISPLAY_ENTRIES);
    while let Ok(Some(line)) = lines.next_segment().await {
        if let Ok(event) = serde_json::from_slice::<AuditEvent>(&line) {
            if events.len() == MAX_DISPLAY_ENTRIES {
                events.pop_front();
            }
            events.push_back(event);
        }
    }
    events.into_iter().rev().collect()
}

/// A detail field as plain text (strings without JSON quotes)
fn detail(event: &AuditEvent, key: &str) -> String {
    match &event.details[key] {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Translates a raw error into a user-friendly description with suggestions.
fn error_text(event: &AuditEvent) -> String {
    match event.error.as_deref() {
        Some(e) if !e.is_empty() => {
            let translation = NftablesErrorPattern::match_error(e);
            if translation.suggestions.is_empty() {
                translation.user_message
            } else {
                format!(
                    "{} — {}",
                    translation.user_message,
                    translation.suggestions.join("; ")
                )
            }
        }
        _ => "No error details available".to_string(),
    }
}

/// The status tone and description shown for an event.
fn describe_event(event: &AuditEvent) -> (RowTone, String) {
    let d = |key| detail(event, key);
    let ports = || {
        event.details["ports"]
            .as_str()
            .map_or_default(|p| format!(" ({p})"))
    };
    match (&event.event_type, event.success) {
        (EventType::ApplyRules, true) => (
            RowTone::Success,
            format!(
                "Applied {} rules ({} enabled)",
                d("rule_count"),
                d("enabled_count")
            ),
        ),
        (EventType::ApplyRules, false) => (
            RowTone::Danger,
            format!("Failed to apply rules: {}", error_text(event)),
        ),
        (EventType::RevertRules, true) => {
            (RowTone::Warning, "Reverted to previous ruleset".to_string())
        }
        (EventType::RevertRules, false) => (
            RowTone::Danger,
            format!("Revert failed: {}", error_text(event)),
        ),
        (EventType::VerifyRules, true) => {
            (RowTone::Success, "Rules verified successfully".to_string())
        }
        (EventType::VerifyRules, false) => (
            RowTone::Danger,
            if event.error.is_some() {
                format!("Verification failed: {}", error_text(event))
            } else {
                format!("Verification failed: {} errors", d("error_count"))
            },
        ),
        (EventType::ProfileCreated, _) => (
            RowTone::Accent,
            format!("Created profile '{}'", d("profile_name")),
        ),
        (EventType::ProfileDeleted, _) => (
            RowTone::Accent,
            format!("Deleted profile '{}'", d("profile_name")),
        ),
        (EventType::ProfileRenamed, _) => (
            RowTone::Accent,
            format!("Renamed profile '{}' → '{}'", d("old_name"), d("new_name")),
        ),
        (EventType::ProfileReset, _) => (
            RowTone::Warning,
            match event.details["backup"].as_str() {
                Some(backup) => format!(
                    "Started fresh: profile '{}' emptied (old file kept at {backup})",
                    d("profile_name")
                ),
                None => format!(
                    "Started fresh: profile '{}' emptied (no backup copy)",
                    d("profile_name")
                ),
            },
        ),
        (EventType::ProfileSwitched, _) => (
            RowTone::Accent,
            format!("Switched profile: '{}' → '{}'", d("from"), d("to")),
        ),
        (EventType::SettingsSaved, _) => (
            RowTone::Accent,
            event.details["description"]
                .as_str()
                .unwrap_or("Settings saved")
                .to_string(),
        ),
        (EventType::AutoRevertConfirmed, _) => (
            RowTone::Success,
            format!("Auto-revert confirmed ({}s timeout)", d("timeout_secs")),
        ),
        (EventType::AutoRevertTimedOut, _) => (
            RowTone::Warning,
            format!("Auto-revert timed out ({}s)", d("timeout_secs")),
        ),
        (EventType::ElevationCancelled, _) => (
            RowTone::Warning,
            "Authentication cancelled by user".to_string(),
        ),
        (EventType::ElevationFailed, _) => (
            RowTone::Danger,
            format!("Authentication failed: {}", error_text(event)),
        ),
        (EventType::RuleCreated, _) => (
            RowTone::Success,
            format!("Created rule '{}'{}", d("label"), ports()),
        ),
        (EventType::RuleDeleted, _) => (RowTone::Danger, format!("Deleted rule '{}'", d("label"))),
        (EventType::RuleModified, _) => (
            RowTone::Accent,
            format!("Modified rule '{}'{}", d("label"), ports()),
        ),
        (EventType::RuleToggled, _) => (
            RowTone::Accent,
            format!(
                "Rule '{}' {}",
                d("label"),
                if event.details["enabled"].as_bool().unwrap_or(false) {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
        ),
        (EventType::RulesReordered, _) => (
            RowTone::Accent,
            format!("Moved rule '{}' {}", d("label"), d("direction")),
        ),
        (EventType::Undone, _) => (
            RowTone::Warning,
            format!(
                "Undid: {}",
                event.details["description"]
                    .as_str()
                    .unwrap_or("unknown operation")
            ),
        ),
        (EventType::Redone, _) => (
            RowTone::Accent,
            format!(
                "Redid: {}",
                event.details["description"]
                    .as_str()
                    .unwrap_or("unknown operation")
            ),
        ),
        (EventType::ExportCompleted, _) => (
            RowTone::Success,
            format!(
                "Exported {} to {}",
                event.details["format"].as_str().unwrap_or("rules"),
                d("path")
            ),
        ),
        (EventType::SaveToSystem, true) => {
            let what = match (
                event.details["source"].as_str(),
                event.details["untested"].as_bool(),
            ) {
                (Some("last_confirmed"), _) => "Saved the last kept rules",
                (_, Some(true)) => "Saved untested rules",
                _ => "Saved",
            };
            (RowTone::Success, format!("{what} to {}", d("target_path")))
        }
        (EventType::SaveToSystem, false) => (
            RowTone::Danger,
            format!("Failed to save: {}", error_text(event)),
        ),
        (EventType::EnableAtBoot, true) => (
            RowTone::Success,
            format!("Enabled {} at boot", d("service")),
        ),
        (EventType::EnableAtBoot, false) => (
            RowTone::Warning,
            format!("Could not enable {}: {}", d("service"), error_text(event)),
        ),
        (EventType::SnapshotFailed, _) => (
            RowTone::Warning,
            format!("Snapshot failed: {}", error_text(event)),
        ),
        (EventType::ProfileDeleteFailed, _) => (
            RowTone::Danger,
            format!(
                "Failed to delete profile '{}': {}",
                d("profile_name"),
                error_text(event)
            ),
        ),
        (EventType::ProfileCreateFailed, _) => (
            RowTone::Danger,
            format!(
                "Failed to create profile '{}': {}",
                d("profile_name"),
                error_text(event)
            ),
        ),
        (EventType::ProfileRenameFailed, _) => (
            RowTone::Danger,
            format!(
                "Failed to rename profile '{}': {}",
                d("profile_name"),
                error_text(event)
            ),
        ),
        (EventType::ExportFailed, _) => (
            RowTone::Danger,
            format!("Export failed: {}", error_text(event)),
        ),
        (EventType::LogCleared, _) => (RowTone::Warning, "Event log cleared".to_string()),
        (EventType::GenericError, _) => (RowTone::Danger, format!("Error: {}", error_text(event))),
    }
}

#[cfg(test)]
mod tests {
    use jiff::civil::date;

    use super::*;

    fn event_at(stamp: &str, event_type: EventType, success: bool) -> AuditEvent {
        let mut event = AuditEvent::new(event_type, success, serde_json::json!({}), None);
        event.timestamp = stamp.parse().unwrap();
        event
    }

    fn profile_event(stamp: &str, name: &str) -> AuditEvent {
        let mut event = event_at(stamp, EventType::ProfileCreated, true);
        event.details = serde_json::json!({ "profile_name": name });
        event
    }

    fn loaded(rows: Vec<DiagnosticRow>) -> AuditLoad {
        AuditLoad::Loaded {
            stamp: LogStamp::Present {
                len: 1,
                modified: None,
            },
            day: date(2026, 11, 20),
            rows,
        }
    }

    #[test]
    fn test_event_time_local_with_date_only_when_not_today() {
        let tz = TimeZone::fixed(jiff::tz::offset(2));
        let today = date(2026, 11, 20);
        // 21:30 UTC is 23:30 local (+02:00): today, time only
        let ts = "2026-11-20T21:30:05Z".parse().unwrap();
        assert_eq!(format_event_time(ts, &tz, today), "23:30:05");
        // 22:30 UTC is 00:30 the next local day: shown with its date
        let ts = "2026-11-20T22:30:05Z".parse().unwrap();
        assert_eq!(format_event_time(ts, &tz, today), "2026-11-21 00:30:05");
        let ts = "2026-11-19T08:00:00Z".parse().unwrap();
        assert_eq!(format_event_time(ts, &tz, today), "2026-11-19 10:00:00");
    }

    #[test]
    fn test_build_rows_precomputes_text() {
        let tz = TimeZone::UTC;
        let today = date(2026, 11, 20);
        let mut failed = event_at("2026-11-20T10:00:00Z", EventType::ApplyRules, false);
        failed.error = Some("Permission denied".to_string());
        let events = [
            profile_event("2026-11-20T09:00:00Z", "work"),
            failed,
            event_at("2026-11-19T09:00:00Z", EventType::LogCleared, true),
        ];
        let rows = build_rows(&events, &tz, today);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].time, "09:00:00");
        // Detail strings are shown without JSON quotes
        assert_eq!(rows[0].description, "Created profile 'work'");
        assert_eq!(rows[0].tone, RowTone::Accent);
        assert_eq!(rows[1].tone, RowTone::Danger);
        assert!(rows[1].description.starts_with("Failed to apply rules: "));
        assert_eq!(rows[2].time, "2026-11-19 09:00:00");
        assert_eq!(rows[2].description, "Event log cleared");
    }

    #[test]
    fn test_filter_and_search_are_cached() {
        let tz = TimeZone::UTC;
        let today = date(2026, 11, 20);
        let events = [
            profile_event("2026-11-20T09:00:00Z", "Work"),
            event_at("2026-11-20T10:00:00Z", EventType::ApplyRules, false),
            profile_event("2026-11-20T11:00:00Z", "home"),
            event_at("2026-11-20T12:00:00Z", EventType::SettingsSaved, true),
        ];
        let mut log = DiagnosticsLog::default();
        let (generation, _) = log.begin_load(today).unwrap();
        assert!(log.finish_load(
            generation,
            loaded(build_rows(&events, &tz, today)),
            DiagnosticsFilter::All
        ));
        assert_eq!(log.visible_rows().count(), 4);
        assert_eq!(log.count_label, "4 events");
        assert!(!log.any_visible_dated);

        log.refilter(DiagnosticsFilter::Errors);
        assert_eq!(log.visible_rows().count(), 1);
        assert_eq!(log.count_label, "1 of 4 events");

        // Search is case-insensitive and combines with the filter
        log.refilter(DiagnosticsFilter::ProfileChanges);
        log.set_search("  WORK ".to_string(), DiagnosticsFilter::ProfileChanges);
        let shown: Vec<&str> = log.visible_rows().map(|r| r.description.as_str()).collect();
        assert_eq!(shown, ["Created profile 'Work'"]);
        assert_eq!(log.search, "  WORK ", "the field keeps what was typed");

        // The time column is searchable too
        log.set_search("12:00".to_string(), DiagnosticsFilter::All);
        assert_eq!(log.visible_rows().count(), 1);

        log.set_search("no such event".to_string(), DiagnosticsFilter::All);
        assert!(log.nothing_visible());
        assert_eq!(log.count_label, "0 of 4 events");
    }

    /// The modal lists at most `ROWS_SHOWN` rows (it is rebuilt on each
    /// refresh), and says so.
    #[test]
    fn test_long_logs_show_the_newest_rows_only() {
        let tz = TimeZone::UTC;
        let today = date(2026, 11, 20);
        let events: Vec<AuditEvent> = (0..ROWS_SHOWN + 5)
            .map(|_| event_at("2026-11-20T09:00:00Z", EventType::SettingsSaved, true))
            .collect();
        let mut log = DiagnosticsLog::default();
        let (generation, _) = log.begin_load(today).unwrap();
        log.finish_load(
            generation,
            loaded(build_rows(&events, &tz, today)),
            DiagnosticsFilter::All,
        );
        assert_eq!(log.visible_rows().count(), ROWS_SHOWN);
        assert!(
            log.count_label.starts_with("newest 200 of 205"),
            "{}",
            log.count_label
        );
    }

    #[test]
    fn test_save_and_reset_events_are_described() {
        let tz = TimeZone::UTC;
        let today = date(2026, 11, 20);
        let mut untested = event_at("2026-11-20T09:00:00Z", EventType::SaveToSystem, true);
        untested.details = serde_json::json!({
            "target_path": "/etc/nftables.conf", "source": "editor", "untested": true
        });
        let mut reset = event_at("2026-11-20T09:00:00Z", EventType::ProfileReset, true);
        reset.details = serde_json::json!({ "profile_name": "work", "backup": null });
        let rows = build_rows(&[untested, reset], &tz, today);
        let texts: Vec<&str> = rows.iter().map(|r| r.description.as_str()).collect();
        assert!(
            texts.contains(&"Saved untested rules to /etc/nftables.conf"),
            "{texts:?}"
        );
        assert!(
            texts.contains(&"Started fresh: profile 'work' emptied (no backup copy)"),
            "{texts:?}"
        );
    }

    #[test]
    fn test_only_one_load_in_flight() {
        let today = date(2026, 11, 20);
        let mut log = DiagnosticsLog::default();
        let (generation, known) = log.begin_load(today).unwrap();
        assert_eq!(known, None, "the first load always reads");
        // Timer ticks while the load runs start nothing
        assert!(log.begin_load(today).is_none());
        assert!(log.begin_load(today).is_none());

        log.finish_load(generation, loaded(Vec::new()), DiagnosticsFilter::All);
        // Next tick may skip the read if the stamp is unchanged
        let (next, known) = log.begin_load(today).unwrap();
        assert!(next > generation);
        assert_eq!(
            known,
            Some(LogStamp::Present {
                len: 1,
                modified: None
            })
        );
        // An unchanged log keeps the rows and frees the slot
        assert!(!log.finish_load(next, AuditLoad::Unchanged, DiagnosticsFilter::All));
        assert!(log.begin_load(today).is_some());
    }

    #[test]
    fn test_stale_generation_is_dropped() {
        let tz = TimeZone::UTC;
        let today = date(2026, 11, 20);
        let mut log = DiagnosticsLog::default();
        let (old, _) = log.begin_load(today).unwrap();
        // The log is cleared while that load runs
        log.invalidate();
        let (new, known) = log.begin_load(today).unwrap();
        assert_eq!(known, None);

        let fresh = build_rows(
            &[event_at(
                "2026-11-20T12:00:00Z",
                EventType::LogCleared,
                true,
            )],
            &tz,
            today,
        );
        assert!(log.finish_load(new, loaded(fresh), DiagnosticsFilter::All));
        // The older load finishing late must not overwrite the newer rows
        let stale = build_rows(
            &[
                profile_event("2026-11-20T09:00:00Z", "a"),
                profile_event("2026-11-20T10:00:00Z", "b"),
            ],
            &tz,
            today,
        );
        assert!(!log.finish_load(old, loaded(stale), DiagnosticsFilter::All));
        let shown: Vec<&str> = log.visible_rows().map(|r| r.description.as_str()).collect();
        assert_eq!(shown, ["Event log cleared"]);
    }

    #[test]
    fn test_clearing_holds_off_loads_and_new_day_forces_read() {
        let today = date(2026, 11, 20);
        let mut log = DiagnosticsLog::default();
        let (generation, _) = log.begin_load(today).unwrap();
        log.finish_load(generation, loaded(Vec::new()), DiagnosticsFilter::All);

        log.clearing = true;
        assert!(log.begin_load(today).is_none());
        log.clearing = false;

        // After midnight the rows' "today" is stale: read again
        let (_, known) = log.begin_load(date(2026, 11, 21)).unwrap();
        assert_eq!(known, None);
    }

    #[tokio::test]
    async fn test_load_if_changed_reads_only_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let today = date(2026, 11, 20);

        // Missing file: an empty, loaded result
        let AuditLoad::Loaded { stamp, rows, .. } =
            load_if_changed(Some(path.clone()), None, today).await
        else {
            panic!("first load must read");
        };
        assert_eq!(stamp, LogStamp::Missing);
        assert!(rows.is_empty());
        assert!(matches!(
            load_if_changed(Some(path.clone()), Some(stamp), today).await,
            AuditLoad::Unchanged
        ));

        let mut lines = String::new();
        for i in 0..(MAX_DISPLAY_ENTRIES + 5) {
            let mut event = profile_event("2026-11-20T09:00:00Z", &format!("p{i}"));
            event.details = serde_json::json!({ "profile_name": format!("p{i}") });
            lines.push_str(&serde_json::to_string(&event).unwrap());
            lines.push('\n');
        }
        lines.push_str("{ damaged line\n");
        std::fs::write(&path, &lines).unwrap();

        let AuditLoad::Loaded { stamp, rows, .. } =
            load_if_changed(Some(path.clone()), Some(stamp), today).await
        else {
            panic!("a changed log must be read");
        };
        // Newest first, capped, damaged line skipped
        assert_eq!(rows.len(), MAX_DISPLAY_ENTRIES);
        assert_eq!(
            rows[0].description,
            format!("Created profile 'p{}'", MAX_DISPLAY_ENTRIES + 4)
        );
        assert!(matches!(
            load_if_changed(Some(path.clone()), Some(stamp), today).await,
            AuditLoad::Unchanged
        ));
    }
}
