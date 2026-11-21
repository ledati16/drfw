mod debounce;
mod diagnostics;
mod exposure;
mod focus;
mod forms;
mod handlers;
mod helpers;
pub mod syntax_cache;
pub mod ui_components;
mod verify_errors;
mod view;

// Re-export form types
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

pub use debounce::TimerKind;
pub use forms::{FormErrors, HelperType, RuleForm, RuleFormHelper};
pub use handlers::apply::SaveSource;
pub use handlers::ui_state::BaseShortcut;
use helpers::{
    calculate_max_content_width, calculate_max_content_width_from_refs, fuzzy_filter_fonts,
    fuzzy_filter_themes,
};
use iced::{Animation, Element, Task};

use crate::core::firewall::{FirewallRuleset, Protocol};

/// Largest GUI log file before it is rotated to `drfw.log.1`.
const GUI_LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;

/// Runs the GUI until its window closes; this is what `drfw` without a
/// subcommand does.
///
/// Logs go to `drfw.log` in the state directory (0600, appended, rotated past
/// 5 MiB), or to stderr if that file cannot be opened. Iced runs its own async
/// runtime, so call this from a plain synchronous context, not from inside a
/// Tokio runtime.
///
/// Returns [`ExitCode::FAILURE`] if the window or the graphics backend cannot
/// be created.
pub fn run_gui() -> ExitCode {
    crate::elevation::set_context(crate::elevation::ElevationContext::Gui);
    if let Some(mut log_path) = crate::utils::get_state_dir() {
        log_path.push("drfw.log");
        if let Ok(file) = crate::utils::open_private_log(&log_path, GUI_LOG_MAX_BYTES) {
            tracing_subscriber::fmt().with_writer(file).init();
        } else {
            tracing_subscriber::fmt::init();
        }
    } else {
        tracing_subscriber::fmt::init();
    }

    let result = iced::application(State::new, State::update, State::view)
        .subscription(State::subscription)
        .window(iced::window::Settings {
            size: iced::Size::new(1000.0, 700.0),
            // Close requests are handled in `State::update` (pending saves are flushed first)
            exit_on_close_request: false,
            platform_specific: iced::window::settings::PlatformSpecific {
                application_id: "drfw".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .title("Dumb Rust Firewall")
        .theme(State::iced_theme)
        .run();

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Also on stderr: the log file may be the very thing that failed
            tracing::error!("GUI failed: {e}");
            eprintln!("drfw: GUI failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// In-app notification banner severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BannerSeverity {
    Success, // Green - positive outcomes (confirmed, exported)
    Info,    // Blue/Cyan - neutral information (applied)
    Warning, // Yellow/Orange - attention needed (auto-revert, warnings)
    Error,   // Red - failures, errors requiring attention
}

/// In-app notification banner
#[derive(Debug, Clone)]
pub struct NotificationBanner {
    pub message: String,
    pub severity: BannerSeverity,
    pub created_at: std::time::Instant, // Monotonic time, immune to clock changes
    pub duration_secs: u64,
}

impl NotificationBanner {
    /// Check if banner should be dismissed based on elapsed time
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() >= self.duration_secs
    }
}

pub struct State {
    pub ruleset: FirewallRuleset,
    /// What DRFW last applied to the kernel; `None` = unknown (e.g. at startup)
    pub last_applied_ruleset: Option<FirewallRuleset>,
    /// The last ruleset applied *and kept* (confirmed within the auto-revert
    /// countdown, or applied with auto-revert off), shared with the CLI
    /// through the persisted record (`core::confirmed`): loaded at startup,
    /// replaced when an apply is kept. Unlike `last_applied_ruleset` it is
    /// never an unconfirmed or failed-revert state, and it may come from an
    /// earlier boot. Save to System offers it as the tested choice; the
    /// retention guard compares new rulesets with it.
    pub confirmed_record: Option<crate::core::confirmed::ConfirmedRecord>,
    /// Bumped whenever this GUI replaces `confirmed_record` itself; a reload
    /// from disk started before that (`Message::ApplyContextLoaded`) is older
    /// and does not overwrite it.
    pub confirmed_record_generation: u64,
    /// This GUI has applied (or tried to apply) rules in this session; after
    /// that, a missing `last_applied_ruleset` means "lost track", and the
    /// record is only the last *kept* rules ([`BaselineKind::LastKept`])
    applied_this_session: bool,
    /// Where `cached_applied_text` (the old side of the diff) comes from;
    /// `None` when there is nothing to compare with. Refreshed with it.
    pub diff_baseline: Option<BaselineKind>,
    /// The SSH session DRFW runs in (`SSH_CONNECTION`), read at startup
    pub ssh_env_session: Option<crate::core::lockout::SshSession>,
    /// The SSH sessions last found (the one above and those in `/proc`),
    /// refreshed when Apply or Save to System starts and by the Exposure
    /// scan; the lockout check evaluates them
    pub ssh_sessions: Vec<crate::core::lockout::SshSession>,
    /// Ruleset snapshot carried through verify -> apply -> confirm/revert
    pub apply_session: Option<handlers::ApplySession>,
    pub cached_disk_profile: Option<FirewallRuleset>,
    pub status: AppStatus,
    pub banners: std::collections::VecDeque<NotificationBanner>,
    pub active_tab: WorkspaceTab,
    pub rule_form: Option<RuleForm>,
    /// The rule form as it was opened, to tell whether Cancel/Escape would
    /// discard changes
    pub rule_form_initial: Option<RuleForm>,
    /// The rule form shows "Discard changes?"
    pub confirm_discard_form: bool,
    pub rule_form_helper: Option<RuleFormHelper>,
    pub interface_combo: iced::widget::combo_box::State<String>,
    pub output_interface_combo: iced::widget::combo_box::State<String>,
    pub countdown_remaining: u32,
    /// `countdown_remaining` as text, for the countdown dialog
    pub countdown_display: String,
    pub progress_animation: Animation<f32>,
    pub form_errors: Option<FormErrors>,
    pub cached_nft_tokens: Vec<syntax_cache::HighlightedLine>,
    /// Text and tokens of the comparison baseline (the old side of the diff:
    /// `last_applied_ruleset`, else the kept record, see [`baseline_of`]);
    /// refreshed only when the baseline changes, not on every edit.
    pub cached_applied_text: Option<syntax_cache::TokenizedText>,
    pub cached_diff_tokens: Option<Vec<(syntax_cache::DiffType, syntax_cache::HighlightedLine)>>,
    pub cached_nft_width_px: f32,
    pub cached_diff_width_px: f32,
    pub rule_search: String,
    pub rule_search_lowercase: String,
    pub cached_all_tags: Vec<Arc<String>>,
    /// Cached truncated tag strings for tag cloud display (max 16 chars + ellipsis)
    /// Avoids format!() allocation every frame in sidebar tag cloud
    pub cached_all_tags_truncated: Vec<String>,
    pub cached_filtered_rule_indices: Vec<usize>,
    /// Protocol/port badge per rule (parallel to `ruleset.rules`), with the
    /// chain arrow in Server Mode. Avoids `format!()` in the sidebar every frame.
    pub cached_rule_badges: Vec<String>,
    /// `is_dirty()`: the ruleset differs from what DRFW last applied.
    /// Refreshed with the other caches whenever the ruleset or the applied
    /// ruleset changes, never computed in `view()`.
    cached_is_dirty: bool,
    /// `is_profile_dirty()`: the ruleset differs from the profile on disk.
    cached_is_profile_dirty: bool,
    /// Cached "{filtered}/{total}" display string for sidebar header
    /// Avoids format!() allocation every frame
    pub filter_count_display: String,
    pub deleting_id: Option<uuid::Uuid>,
    pub pending_warning: Option<PendingWarning>,
    pub show_diff: bool,
    pub show_zebra_striping: bool,
    pub auto_revert_enabled: bool,
    /// The user answered the "Auto-revert is off" notice (or changed the
    /// setting themselves); persisted, so the notice shows at most once
    pub auto_revert_notice_shown: bool,
    pub auto_revert_timeout_secs: u64,
    pub enable_event_log: bool,
    pub reduced_colors: bool,
    pub show_diagnostics: bool,
    /// Errors of the last failed verification (Apply or Save to System),
    /// prepared in `update()`; cleared by the next successful verification.
    pub verify_errors: Option<verify_errors::VerifyErrorsPanel>,
    /// The "Verification Errors" panel is open (needs `verify_errors`)
    pub show_verify_errors: bool,
    /// Boot persistence shown in the Save to System dialog (and its "Also
    /// enable at boot" checkbox), filled in `update()` from `systemctl`
    pub save_dialog: handlers::SaveToSystemDialog,
    /// The running Save to System (which rules, tested or not)
    pub save_in_progress: Option<handlers::SaveInProgress>,
    pub diagnostics_filter: DiagnosticsFilter,
    pub show_export_modal: bool,
    /// An export file dialog is open (the export buttons are disabled)
    pub export_in_progress: bool,
    pub show_shortcuts_help: bool,
    pub font_picker: Option<FontPickerState>,
    pub theme_picker: Option<ThemePickerState>,
    pub profile_manager: Option<ProfileManagerState>,
    pub command_history: crate::command::CommandHistory,
    pub current_theme: crate::theme::ThemeChoice,
    pub theme: crate::theme::AppTheme,
    /// iced's base theme built from `theme` (unstyled widgets, text input
    /// caret/selection, `button::text`); rebuilt only when `theme` changes.
    iced_theme: iced::Theme,
    pub filter_tag: Option<Arc<String>>,
    pub dragged_rule_id: Option<uuid::Uuid>,
    pub hovered_drop_target_id: Option<uuid::Uuid>,
    /// Pending hover target for debouncing (id, timestamp)
    /// Prevents rapid view rebuilds during drag-and-drop on large rulesets
    pub hover_pending: Option<(uuid::Uuid, std::time::Instant)>,
    pub regular_font_choice: crate::fonts::RegularFontChoice,
    pub mono_font_choice: crate::fonts::MonoFontChoice,
    pub font_regular: iced::Font,
    pub font_mono: iced::Font,
    /// System fonts; empty until the async enumeration at startup finished.
    pub available_fonts: &'static [crate::fonts::FontChoice],
    /// The system font enumeration finished (`available_fonts` is final).
    pub fonts_loaded: bool,
    // Config save debouncing
    pub config_dirty: bool,
    pub last_config_change: Option<std::time::Instant>,
    /// A config save task is running (the next one waits for it)
    pub config_save_in_flight: bool,
    /// Last config save error; saving is retried until it succeeds
    pub config_save_error: Option<String>,
    /// Slider value labels of the settings tab, refreshed on change
    pub settings_display: SettingsDisplay,
    // Profile save debouncing
    pub profile_dirty: bool,
    pub last_profile_change: Option<std::time::Instant>,
    // Slider logging debouncing (description, last_change_time)
    pub pending_slider_log: Option<(String, std::time::Instant)>,
    /// One-shot timers driving the debounced saves and slider logging
    timers: debounce::Timers,
    // Profile management
    pub active_profile_name: String,
    /// Set through [`State::set_available_profiles`] (keeps the count label)
    pub available_profiles: Vec<String>,
    /// "N profiles" for the profile manager
    pub profile_count_display: String,
    pub pending_profile_switch: Option<String>,
    /// Diagnostics modal: pre-formatted event log rows, filter/search
    /// results and reload bookkeeping (see `app::diagnostics`)
    pub diagnostics: diagnostics::DiagnosticsLog,
    /// Set when the active profile exists but could not be loaded. The profile
    /// is then open read-only (empty, edits and autosave blocked) until the user
    /// switches profile or chooses "Start fresh".
    pub unreadable_profile: Option<crate::core::profiles::UnreadableProfile>,
    /// The "Start fresh?" confirmation is open
    pub confirm_start_fresh: bool,
    /// Bumped whenever the active profile is replaced (switch, create, rename,
    /// start fresh); async save results from an older generation are ignored.
    pub profile_generation: u64,
    /// Id of the latest profile switch request; older load results are ignored.
    pub switch_request: u64,
    /// A profile save task is running (no second autosave is started meanwhile).
    pub profile_save_in_flight: bool,
    /// A rename task is running (autosave paused so it can't recreate the old file).
    pub profile_rename_in_flight: bool,
    /// Last profile save error, shown in the sidebar until a save succeeds.
    pub profile_save_error: Option<String>,
    /// Validation issues per rule id, recomputed whenever the ruleset changes
    /// (the sidebar flags these rules; never computed in `view()`).
    pub cached_rule_issues: std::collections::HashMap<uuid::Uuid, String>,
    /// One-line notice when the ruleset cannot be applied as is (invalid
    /// enabled rules or ruleset-level issues), recomputed with the cache above.
    pub cached_validation_notice: Option<String>,
    /// The window is closing; pending saves are being flushed.
    pub closing: bool,
    /// A close request waits for a running profile rename before flushing
    pub close_after_rename: bool,
    /// Saving on close failed: the "Close anyway?" dialog shows this text
    pub close_error: Option<String>,
    /// The Exposure panel (listening sockets and who can reach them)
    pub exposure: exposure::ExposureState,
}

/// Value labels of the settings tab sliders (and the apply dialog's timer),
/// formatted in `update()` when the values change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsDisplay {
    /// "15s"
    pub auto_revert_timeout: String,
    /// The timer of the "Commit Changes?" dialog in seconds ("15")
    pub apply_timer_secs: String,
    /// "5/s", or "Off" for 0 (no ICMP rate limit)
    pub icmp_rate: String,
    /// "10/m"
    pub log_rate: String,
}

/// Where the rules the editor is compared with (the old side of the diff,
/// the "Applied"/"Kept" answers of the Exposure panel) come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineKind {
    /// Applied by this GUI in this session (`State::last_applied_ruleset`)
    Applied,
    /// The kept-ruleset record, written during this boot (by the CLI or an
    /// earlier GUI); this GUI has not applied anything yet
    KeptThisBoot,
    /// The kept-ruleset record, after an apply of this session that was not
    /// kept or whose outcome is unknown: the last kept rules, not
    /// necessarily the last applied
    LastKept,
    /// The kept-ruleset record from an earlier boot (or an unknown one): a
    /// reboot or another tool may have replaced those rules since
    KeptEarlierSession,
}

impl BaselineKind {
    /// Label of the "Show diff" checkbox.
    pub const fn diff_label(self) -> &'static str {
        match self {
            Self::Applied | Self::KeptThisBoot => "Show diff (vs last applied)",
            Self::LastKept => "Show diff (vs last kept)",
            Self::KeptEarlierSession => "Show diff (vs last kept, earlier session)",
        }
    }
}

/// The rules the editor is compared with, and where they come from.
#[derive(Debug, Clone, Copy)]
pub struct Baseline<'a> {
    pub ruleset: &'a FirewallRuleset,
    pub kind: BaselineKind,
}

/// The comparison baseline: what this GUI applied, else the kept-ruleset
/// record (if it holds a ruleset), else none. A free function over the
/// fields so it can be called while another field is borrowed mutably.
/// The record is never treated as "applied this session": `is_dirty()`
/// ignores it.
fn baseline_of<'a>(
    applied: Option<&'a FirewallRuleset>,
    record: Option<&'a crate::core::confirmed::ConfirmedRecord>,
    applied_this_session: bool,
) -> Option<Baseline<'a>> {
    if let Some(ruleset) = applied {
        return Some(Baseline {
            ruleset,
            kind: BaselineKind::Applied,
        });
    }
    let record = record?;
    let kind = if !record.from_this_boot() {
        BaselineKind::KeptEarlierSession
    } else if applied_this_session {
        BaselineKind::LastKept
    } else {
        BaselineKind::KeptThisBoot
    };
    Some(Baseline {
        ruleset: record.ruleset()?,
        kind,
    })
}

/// Whether two rulesets produce the same firewall (rules and the advanced
/// settings; the rest is metadata).
pub(crate) fn rulesets_match(a: &FirewallRuleset, b: &FirewallRuleset) -> bool {
    a.rules == b.rules && a.advanced_security == b.advanced_security
}

/// Result of an async profile save (autosave, "Save & Switch", close flush).
#[derive(Debug, Clone)]
pub struct ProfileSaveOutcome {
    /// `State::profile_generation` when the save was started
    pub generation: u64,
    /// Profile that was written
    pub name: String,
    /// Exactly what was written
    pub snapshot: FirewallRuleset,
    /// Profile to switch to after a successful save ("Save & Switch")
    pub then_switch_to: Option<String>,
    pub result: Result<(), String>,
}

#[derive(Debug, Clone)]
pub struct FontPickerState {
    pub target: FontPickerTarget,
    pub search: String,
    pub search_lowercase: String,
    /// Indices into `State::available_fonts` matching the target and search,
    /// best match first. Recomputed on search change, never in `view()`.
    pub filtered: Vec<usize>,
    /// "N fonts match" / "N fonts available" / "Loading fonts…"
    pub count_display: String,
    /// "Showing X of N fonts…" when the list is truncated
    pub overflow_display: Option<String>,
}

/// Most fonts the picker lists at once (search to find others); keeps the
/// modal's layout fast with hundreds of system fonts.
pub const FONT_PICKER_DISPLAY_LIMIT: usize = 30;

impl FontPickerState {
    /// Recomputes the filtered list and its display strings.
    pub fn refilter(&mut self, fonts: &[crate::fonts::FontChoice], loaded: bool) {
        let is_mono_picker = self.target == FontPickerTarget::Mono;
        let candidates = fonts
            .iter()
            .enumerate()
            .filter(|(_, f)| !is_mono_picker || f.is_monospace());
        self.filtered = fuzzy_filter_fonts(candidates, &self.search_lowercase)
            .into_iter()
            .map(|(index, _score)| index)
            .collect();
        let count = self.filtered.len();
        self.count_display = if !loaded {
            "Loading fonts…".to_string()
        } else if count < fonts.len() {
            format!("{count} fonts match")
        } else {
            format!("{count} fonts available")
        };
        self.overflow_display = (count > FONT_PICKER_DISPLAY_LIMIT).then(|| {
            format!("Showing {FONT_PICKER_DISPLAY_LIMIT} of {count} fonts — search to find more")
        });
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::AsRefStr,
)]
pub enum FontPickerTarget {
    #[strum(serialize = "regular")]
    Regular,
    #[strum(serialize = "mono")]
    Mono,
}

#[derive(Debug, Clone)]
pub struct ThemePickerState {
    pub search: String,
    pub search_lowercase: String,
    pub filter: ThemeFilter,
    pub original_theme: crate::theme::ThemeChoice,
    /// Pre-computed theme conversions to avoid repeated `to_theme()` calls
    pub cached_themes: Vec<(crate::theme::ThemeChoice, crate::theme::AppTheme)>,
    /// Indices into `cached_themes` matching the filter and search, best
    /// match first. Recomputed on search/filter change, never in `view()`.
    pub filtered: Vec<usize>,
    /// "N themes match" / "N themes available"
    pub count_display: String,
}

impl ThemePickerState {
    /// Recomputes the filtered list and its count string.
    pub fn refilter(&mut self) {
        let filter = self.filter;
        let candidates = self
            .cached_themes
            .iter()
            .filter(move |(_, theme)| match filter {
                ThemeFilter::All => true,
                ThemeFilter::Light => theme.is_light(),
                ThemeFilter::Dark => !theme.is_light(),
            })
            .map(|(choice, _)| *choice);
        let matches = fuzzy_filter_themes(candidates, &self.search_lowercase);
        self.filtered = matches
            .into_iter()
            .filter_map(|(choice, _score)| {
                self.cached_themes.iter().position(|(c, _)| *c == choice)
            })
            .collect();
        let count = self.filtered.len();
        self.count_display = if count < self.cached_themes.len() {
            format!("{count} themes match")
        } else {
            format!("{count} themes available")
        };
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::AsRefStr,
)]
pub enum ThemeFilter {
    #[strum(serialize = "all")]
    All,
    #[strum(serialize = "light")]
    Light,
    #[strum(serialize = "dark")]
    Dark,
}

#[derive(Debug, Clone)]
pub struct ProfileManagerState {
    pub renaming_name: Option<(String, String)>, // (old, current_new)
    pub deleting_name: Option<String>,
    pub creating_new: bool,
    pub creating_empty: bool, // true = empty profile, false = from current rules
    pub new_name_input: String,
    /// Why `new_name_input` can't be used (computed on input, not in `view()`)
    pub new_name_error: Option<String>,
    /// Why the name being typed in the rename field can't be used
    pub rename_error: Option<String>,
}

/// Warning dialogs shown when enabling potentially disruptive features.
/// The "Enable" prefix is intentional - these are specifically warnings
/// about turning ON features that could break connectivity.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum PendingWarning {
    EnableRpf,
    EnableServerMode,
    EnableStrictIcmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiagnosticsFilter {
    #[default]
    All,
    Successes,
    Errors,
    ProfileChanges,
    Settings,
}

impl DiagnosticsFilter {
    pub fn label(&self) -> &str {
        match self {
            Self::All => "All Events",
            Self::Successes => "Successes Only",
            Self::Errors => "Errors Only",
            Self::ProfileChanges => "Profile Changes",
            Self::Settings => "Settings Changes",
        }
    }
}

impl std::fmt::Display for DiagnosticsFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::AsRefStr,
)]
pub enum WorkspaceTab {
    #[default]
    #[strum(serialize = "nftables")]
    Nftables,
    #[strum(serialize = "settings")]
    Settings,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AppStatus {
    #[default]
    Idle,
    Verifying,
    AwaitingApply,
    Applying,
    /// Applied; the root-side guard reverts unless confirmed in time
    PendingConfirmation {
        guard: crate::core::apply_guard::GuardHandle,
    },
    /// Confirm token created; waiting for the guard's verdict
    Confirming,
    /// Revert requested or timed out; waiting for the guard's verdict
    Reverting,
    /// Waiting for user to confirm Save to System operation
    AwaitingSaveToSystem,
    /// Save to System operation in progress
    SavingToSystem,
}

#[derive(Debug, Clone)]
pub enum Message {
    AddRuleClicked,
    EditRuleClicked(uuid::Uuid),
    /// Cancel/Escape in the rule form (asks first if it was changed)
    CancelRuleForm,
    /// "Keep editing" in the "Discard changes?" prompt
    KeepEditingRuleForm,
    /// "Discard" in the "Discard changes?" prompt
    DiscardRuleForm,
    SaveRuleForm,
    RuleFormLabelChanged(String),
    RuleFormProtocolChanged(Protocol),
    RuleFormInterfaceChanged(String),
    RuleFormChainChanged(crate::core::firewall::Chain),
    RuleFormToggleAdvanced(bool),
    RuleFormActionChanged(crate::core::firewall::Action),
    RuleFormToggleRateLimit(bool),
    RuleFormRateLimitCountChanged(String),
    RuleFormRateLimitUnitChanged(crate::core::firewall::TimeUnit),
    RuleFormConnectionLimitChanged(String),
    RuleSearchChanged(String),
    ToggleRuleEnabled(uuid::Uuid),
    DeleteRuleRequested(uuid::Uuid),
    CancelDelete,
    DeleteRule(uuid::Uuid),
    ApplyClicked,
    VerifyCompleted(Result<crate::core::verify::VerifyResult, crate::core::verify::VerifyError>),
    ProceedToApply,
    /// "Apply anyway" in "Commit Changes?" when the retention guard warns
    /// (Enter sends `ProceedToApply`, which is refused then)
    ProceedToApplyAnyway,
    /// Close the "Commit Changes?" dialog without applying (edits are kept)
    CancelApply,
    ApplyResult(
        Result<Option<crate::core::apply_guard::GuardHandle>, crate::core::apply_guard::ApplyError>,
    ),
    ConfirmClicked,
    RevertClicked,
    /// The revert guard's verdict after confirm, rollback or timeout
    GuardFinished(
        Result<crate::core::apply_guard::GuardOutcome, crate::core::apply_guard::GuardError>,
    ),
    CountdownTick,
    TabChanged(WorkspaceTab),
    ToggleExportModal(bool),
    SaveToSystemClicked,
    SaveToSystemVerifyResult(
        Result<crate::core::verify::VerifyResult, crate::core::verify::VerifyError>,
    ),
    /// Whether the saved file loads at boot (`systemctl`, unprivileged)
    SaveToSystemBootChecked(crate::core::boot::BootStatus),
    /// The "Also enable <service> at boot" checkbox
    SaveToSystemEnableToggled(bool),
    /// Save to System confirmed: write the editor's rules or the last
    /// confirmed ones
    SaveToSystemConfirmed(SaveSource),
    SaveToSystemCancelled,
    /// Backup path, `systemctl enable` result and boot persistence after saving
    SaveToSystemResult(Result<handlers::SaveOutcome, String>),
    /// A keyboard event, with whether a widget (e.g. a focused text input)
    /// already handled it
    EventOccurred(iced::Event, iced::event::Status),
    /// A base-layer Ctrl shortcut, with whether a text input had focus
    BaseShortcut(BaseShortcut, bool),
    ToggleDiff(bool),
    ToggleZebraStriping(bool),
    ToggleAutoRevert(bool),
    /// The "Auto-revert is off" notice: `true` = "Turn on", `false` = "Keep off"
    AutoRevertNoticeAnswered(bool),
    AutoRevertTimeoutChanged(u64),
    ToggleEventLog(bool),
    ToggleReducedColors(bool),
    ToggleStrictIcmpRequested(bool),
    ConfirmStrictIcmp,
    IcmpRateLimitChanged(u32),
    ToggleRpfRequested(bool),
    ConfirmEnableRpf,
    /// Block forwarded traffic (forward chain policy drop)
    ToggleBlockForwarding(bool),
    CancelWarning,
    ToggleDroppedLogging(bool),
    LogRateChanged(u32),
    /// Process pending hover target (debounced drag-and-drop)
    CheckHoverPending,
    LogPrefixChanged(String),
    ServerModeToggled(bool),
    ConfirmServerMode,
    ToggleDiagnostics(bool),
    /// Open/close the "Verification Errors" panel
    ToggleVerifyErrors(bool),
    DiagnosticsFilterChanged(DiagnosticsFilter),
    DiagnosticsSearchChanged(String),
    /// A diagnostics log load finished (generation, result)
    AuditLogLoaded(u64, diagnostics::AuditLoad),
    /// Timer tick while the diagnostics modal is open: reload if the log changed
    CheckAuditLogRefresh,
    /// An audit log write completed (completion message for logging tasks;
    /// the diagnostics modal notices the change by the log's size/mtime)
    AuditLogWritten,
    /// "Clear Log" pressed: ask for confirmation
    ClearEventLog,
    ClearEventLogCancelled,
    ClearEventLogConfirmed,
    /// Clearing finished (error text on failure)
    EventLogCleared(Result<(), String>),
    ExportAsJson,
    ExportAsNft,
    ExportResult(Result<String, String>),
    ToggleShortcutsHelp(bool),
    /// Open (and scan) or close the Exposure panel
    ToggleExposure(bool),
    /// Re-read the listening sockets
    RefreshExposure,
    /// A socket scan finished: (scan generation, sockets and SSH sessions or
    /// why not)
    ExposureScanned(u64, Result<exposure::ExposureScan, String>),
    /// The kept-ruleset record and the SSH sessions, re-read off the UI
    /// thread when Apply or Save to System starts (`None`: the reload failed)
    ApplyContextLoaded(Option<Box<handlers::ApplyContext>>),
    Undo,
    Redo,
    OpenThemePicker,
    ThemePickerSearchChanged(String),
    ThemePickerFilterChanged(ThemeFilter),
    ThemePreview(crate::theme::ThemeChoice),
    ApplyTheme,
    CancelThemePicker,
    RegularFontChanged(crate::fonts::RegularFontChoice),
    MonoFontChanged(crate::fonts::MonoFontChoice),
    OpenFontPicker(FontPickerTarget),
    FontPickerSearchChanged(String),
    CloseFontPicker,
    /// The system font enumeration (started at launch) finished
    FontsLoaded(&'static [crate::fonts::FontChoice]),
    FilterByTag(Option<Arc<String>>),
    RuleDragStart(uuid::Uuid),
    RuleDropped(uuid::Uuid),
    RuleHoverStart(uuid::Uuid),
    RuleHoverEnd,

    // Helper modal messages (for multi-value fields)
    OpenHelper(HelperType),
    CloseHelper,
    HelperInputChanged(String),
    HelperAddValue,
    HelperRemoveValue(usize),

    // New rule form fields (backend features from additional_nft.md)
    RuleFormOutputInterfaceChanged(String),
    RuleFormRejectTypeChanged(crate::core::firewall::RejectType),
    RuleFormRateLimitBurstChanged(String),
    RuleFormRateLimitPerSourceToggled(bool),
    RuleFormConnectionLimitPerSourceToggled(bool),
    RuleFormLogEnabledToggled(bool),

    // Profile messages
    ProfileSelected(String),
    /// Profile load finished: (switch request id, name, loaded ruleset or why not)
    ProfileSwitched(
        u64,
        String,
        Result<FirewallRuleset, crate::core::profiles::UnreadableProfile>,
    ),
    /// Profile creation finished: (name, created ruleset, new profile list or error)
    ProfileCreated(String, Box<FirewallRuleset>, Result<Vec<String>, String>),
    SaveProfileAs(String),
    StartCreatingNewProfile,
    CreateEmptyProfile,
    NewProfileNameChanged(String),
    CancelCreatingNewProfile,
    OpenProfileManager,
    CloseProfileManager,
    DeleteProfileRequested(String),
    ConfirmDeleteProfile,
    /// (deleted name, new profile list or error)
    ProfileDeleted(String, Result<Vec<String>, String>),
    CancelDeleteProfile,
    RenameProfileRequested(String),
    ProfileNewNameChanged(String),
    ConfirmRenameProfile,
    /// (old name, new name, new profile list or error)
    ProfileRenamed(String, String, Result<Vec<String>, String>),
    CancelRenameProfile,
    ConfirmProfileSwitch,
    DiscardProfileSwitch,
    CancelProfileSwitch,
    /// "Start fresh" for an unreadable profile: asks for confirmation
    StartFreshProfile,
    /// Confirmed: replace the unreadable profile with an empty one
    ConfirmStartFresh,
    CancelStartFresh,
    /// Periodic tick to prune expired banners
    PruneBanners,
    /// Dismiss a specific banner (click to dismiss)
    DismissBanner(usize),
    /// A one-shot debounce timer fired: (kind, timer generation)
    TimerFired(TimerKind, u64),
    /// A profile save finished
    ProfileSaved(Box<ProfileSaveOutcome>),
    /// A config save finished
    ConfigSaved(Result<(), String>),
    /// The window manager asked to close the window
    CloseRequested(iced::window::Id),
    /// Pending saves were flushed: exit on success, else ask
    CloseFlushed(Result<(), String>),
    /// "Keep DRFW open" after a failed save on close
    CancelClose,
    /// "Close anyway" after a failed save on close
    CloseAnyway,
    /// No-op message for async operations that don't need a result, and for
    /// the theme picker's sample buttons (enabled so they show real styling)
    Noop,
    /// Copy a preview line to clipboard (right-click on line)
    CopyPreviewLine(usize),
    /// Click on a preview line to filter sidebar by rule label (left-click on line)
    ClickPreviewLine(usize),
}

impl State {
    pub fn view(&self) -> Element<'_, Message> {
        view::view(self)
    }

    pub fn new() -> (Self, Task<Message>) {
        let crate::config::LoadedConfig {
            config,
            problem: config_problem,
        } = crate::config::load_config_checked_blocking();
        let current_theme = config.theme_choice;
        let mut regular_font_choice = config.regular_font;
        let mut mono_font_choice = config.mono_font;
        let show_diff = config.show_diff;
        let show_zebra_striping = config.show_zebra_striping;
        let auto_revert_enabled = config.auto_revert_enabled;
        let auto_revert_notice_shown = config.auto_revert_notice_shown;
        // Clamp timeout to prevent integer overflow (max 1 hour = 3600 seconds)
        let auto_revert_timeout_secs = config.auto_revert_timeout_secs.min(3600);
        let enable_event_log = config.enable_event_log;
        let reduced_colors = config.reduced_colors;
        let active_profile_name = config.active_profile;

        // The system font list loads in the background (see `load_fonts_task`);
        // until then the configured fonts are used by family name.
        regular_font_choice.set_provisional_handle();
        mono_font_choice.set_provisional_handle();

        // Startup guarantee: Ensure at least one profile exists
        // Handles first run, manual deletion, or filesystem corruption
        if let Err(e) = crate::core::profiles::ensure_profile_exists_blocking() {
            tracing::error!("Failed to ensure profile exists: {}", e);
        }

        // Rotate audit log if it exceeds 1MB (keeps one .old backup)
        if let Ok(audit) = crate::audit::AuditLog::new() {
            audit.rotate_if_needed();
        }

        // Never fall back silently: an unreadable profile is copied aside and
        // opened read-only, so no autosave can overwrite the user's file.
        let (ruleset, unreadable_profile) =
            match crate::core::profiles::load_profile_or_preserve_blocking(&active_profile_name) {
                Ok(ruleset) => (ruleset, None),
                Err(issue) => (FirewallRuleset::default(), Some(issue)),
            };

        let available_profiles = crate::core::profiles::list_profiles_blocking()
            .unwrap_or_else(|_| vec![crate::core::profiles::DEFAULT_PROFILE_NAME.to_string()]);

        let theme = build_theme(current_theme, reduced_colors);
        let iced_theme = theme.to_iced_theme();
        let font_regular = regular_font_choice.to_font();
        let font_mono = mono_font_choice.to_font();

        // Cheap (the environment only); the sessions in /proc are scanned
        // off the UI thread when Apply or Save to System starts
        let ssh_env_session = crate::core::lockout::session_from_env();

        let mut state = Self {
            // Unknown until DRFW applies something: the kernel may hold anything
            last_applied_ruleset: None,
            confirmed_record: crate::core::confirmed::ConfirmedRecord::load_blocking(),
            confirmed_record_generation: 0,
            applied_this_session: false,
            diff_baseline: None,
            ssh_env_session: ssh_env_session.clone(),
            ssh_sessions: ssh_env_session.into_iter().collect(),
            apply_session: None,
            cached_disk_profile: Some(ruleset.clone()),
            ruleset,
            status: AppStatus::Idle,
            banners: std::collections::VecDeque::new(),
            active_tab: WorkspaceTab::Nftables,
            rule_form: None,
            rule_form_initial: None,
            confirm_discard_form: false,
            rule_form_helper: None,
            // Filled when the rule form opens (interfaces can come and go)
            interface_combo: iced::widget::combo_box::State::new(Vec::new()),
            output_interface_combo: iced::widget::combo_box::State::new(Vec::new()),
            countdown_remaining: 15,
            countdown_display: String::new(),
            progress_animation: Animation::new(1.0),
            form_errors: None,
            cached_nft_tokens: Vec::new(),
            cached_applied_text: None,
            cached_diff_tokens: None,
            cached_nft_width_px: 800.0,
            cached_diff_width_px: 800.0,
            rule_search: String::new(),
            rule_search_lowercase: String::new(),
            cached_all_tags: Vec::new(),
            cached_all_tags_truncated: Vec::new(),
            cached_filtered_rule_indices: Vec::new(),
            cached_rule_badges: Vec::new(),
            cached_is_dirty: false,
            cached_is_profile_dirty: false,
            filter_count_display: String::new(),
            deleting_id: None,
            pending_warning: None,
            show_diff,
            show_zebra_striping,
            auto_revert_enabled,
            auto_revert_notice_shown,
            auto_revert_timeout_secs,
            enable_event_log,
            reduced_colors,
            show_diagnostics: false,
            verify_errors: None,
            show_verify_errors: false,
            save_dialog: handlers::SaveToSystemDialog::default(),
            save_in_progress: None,
            diagnostics_filter: DiagnosticsFilter::default(),
            show_export_modal: false,
            export_in_progress: false,
            show_shortcuts_help: false,
            font_picker: None,
            theme_picker: None,
            profile_manager: None,
            command_history: crate::command::CommandHistory::default(),
            current_theme,
            theme,
            iced_theme,
            filter_tag: None,
            dragged_rule_id: None,
            hovered_drop_target_id: None,
            hover_pending: None,
            regular_font_choice,
            mono_font_choice,
            font_regular,
            font_mono,
            available_fonts: &[],
            fonts_loaded: false,
            config_dirty: false,
            last_config_change: None,
            config_save_in_flight: false,
            config_save_error: None,
            settings_display: SettingsDisplay::default(),
            profile_dirty: false,
            last_profile_change: None,
            pending_slider_log: None,
            timers: debounce::Timers::default(),
            active_profile_name,
            available_profiles: Vec::new(),
            profile_count_display: String::new(),
            pending_profile_switch: None,
            diagnostics: diagnostics::DiagnosticsLog::default(),
            unreadable_profile,
            confirm_start_fresh: false,
            profile_generation: 0,
            switch_request: 0,
            profile_save_in_flight: false,
            profile_rename_in_flight: false,
            profile_save_error: None,
            cached_rule_issues: std::collections::HashMap::new(),
            cached_validation_notice: None,
            closing: false,
            close_after_rename: false,
            close_error: None,
            exposure: exposure::ExposureState::default(),
        };

        // Initialize all caches properly via centralized logic
        state.set_available_profiles(available_profiles);
        state.refresh_settings_display();
        // The diff starts against the kept record, if there is one
        state.refresh_diff_baseline();
        state.update_cached_text();

        if let Some(issue) = &state.unreadable_profile {
            let message = issue.user_message();
            state.push_banner(message, BannerSeverity::Error);
        }
        if let Some(problem) = config_problem {
            state.push_banner(problem, BannerSeverity::Error);
        }

        (state, load_fonts_task())
    }

    /// Creates a State instance for testing without filesystem access.
    ///
    /// This avoids the filesystem operations in `State::new()` that would:
    /// - Read the user's config file
    /// - Create/access the user's profiles directory
    /// - Load the user's profile data
    ///
    /// # Safety
    ///
    /// This method is only available in test builds. It creates a minimal
    /// State with default values suitable for unit testing handler functions.
    #[cfg(test)]
    pub fn new_for_testing() -> Self {
        let ruleset = FirewallRuleset::default();
        let current_theme = crate::theme::ThemeChoice::default();
        let theme = current_theme.to_theme();
        let iced_theme = theme.to_iced_theme();
        let regular_font_choice = crate::fonts::RegularFontChoice::default();
        let mono_font_choice = crate::fonts::MonoFontChoice::default();
        let font_regular = regular_font_choice.to_font();
        let font_mono = mono_font_choice.to_font();

        let mut state = Self {
            last_applied_ruleset: Some(ruleset.clone()),
            confirmed_record: None,
            confirmed_record_generation: 0,
            applied_this_session: false,
            diff_baseline: None,
            // Never the test runner's own SSH session
            ssh_env_session: None,
            ssh_sessions: Vec::new(),
            apply_session: None,
            cached_disk_profile: Some(ruleset.clone()),
            ruleset,
            status: AppStatus::Idle,
            banners: std::collections::VecDeque::new(),
            active_tab: WorkspaceTab::Nftables,
            rule_form: None,
            rule_form_initial: None,
            confirm_discard_form: false,
            rule_form_helper: None,
            interface_combo: iced::widget::combo_box::State::new(Vec::new()),
            output_interface_combo: iced::widget::combo_box::State::new(Vec::new()),
            countdown_remaining: 15,
            countdown_display: String::new(),
            progress_animation: Animation::new(1.0),
            form_errors: None,
            cached_nft_tokens: Vec::new(),
            cached_applied_text: None,
            cached_diff_tokens: None,
            cached_nft_width_px: 800.0,
            cached_diff_width_px: 800.0,
            rule_search: String::new(),
            rule_search_lowercase: String::new(),
            cached_all_tags: Vec::new(),
            cached_all_tags_truncated: Vec::new(),
            cached_filtered_rule_indices: Vec::new(),
            cached_rule_badges: Vec::new(),
            cached_is_dirty: false,
            cached_is_profile_dirty: false,
            filter_count_display: String::new(),
            deleting_id: None,
            pending_warning: None,
            show_diff: false,
            show_zebra_striping: true,
            auto_revert_enabled: true,
            auto_revert_notice_shown: false,
            auto_revert_timeout_secs: 15,
            enable_event_log: false,
            reduced_colors: false,
            show_diagnostics: false,
            verify_errors: None,
            show_verify_errors: false,
            save_dialog: handlers::SaveToSystemDialog::default(),
            save_in_progress: None,
            diagnostics_filter: DiagnosticsFilter::default(),
            show_export_modal: false,
            export_in_progress: false,
            show_shortcuts_help: false,
            font_picker: None,
            theme_picker: None,
            profile_manager: None,
            command_history: crate::command::CommandHistory::default(),
            current_theme,
            theme,
            iced_theme,
            filter_tag: None,
            dragged_rule_id: None,
            hovered_drop_target_id: None,
            hover_pending: None,
            regular_font_choice,
            mono_font_choice,
            font_regular,
            font_mono,
            available_fonts: &[],
            fonts_loaded: false,
            config_dirty: false,
            last_config_change: None,
            config_save_in_flight: false,
            config_save_error: None,
            settings_display: SettingsDisplay::default(),
            profile_dirty: false,
            last_profile_change: None,
            pending_slider_log: None,
            timers: debounce::Timers::default(),
            active_profile_name: "test".to_string(),
            available_profiles: Vec::new(),
            profile_count_display: String::new(),
            pending_profile_switch: None,
            diagnostics: diagnostics::DiagnosticsLog::default(),
            unreadable_profile: None,
            confirm_start_fresh: false,
            profile_generation: 0,
            switch_request: 0,
            profile_save_in_flight: false,
            profile_rename_in_flight: false,
            profile_save_error: None,
            cached_rule_issues: std::collections::HashMap::new(),
            cached_validation_notice: None,
            closing: false,
            close_after_rename: false,
            close_error: None,
            exposure: exposure::ExposureState::default(),
        };

        state.set_available_profiles(vec!["test".to_string()]);
        state.refresh_settings_display();
        state.refresh_diff_baseline();
        state.update_cached_text();
        state
    }

    /// Add a banner to the notification queue (max 2 visible)
    ///
    /// Duration is automatically determined by severity:
    /// - Success: 4 seconds (quick positive acknowledgment)
    /// - Info: 5 seconds (neutral information)
    /// - Warning: 7 seconds (needs attention)
    /// - Error: 10 seconds (problem requiring action)
    pub fn push_banner(&mut self, message: impl Into<String>, severity: BannerSeverity) {
        let duration_secs = match severity {
            BannerSeverity::Success => 4,
            BannerSeverity::Info => 5,
            BannerSeverity::Warning => 7,
            BannerSeverity::Error => 10,
        };

        let message = message.into();

        // Same message again (e.g. repeated blocked edits): restart its timer
        // instead of stacking duplicates.
        if let Some(last) = self.banners.back_mut()
            && last.message == message
            && last.severity == severity
        {
            last.created_at = std::time::Instant::now();
            return;
        }

        // Remove oldest if at capacity, sparing persistent (never-expiring) banners
        while self.banners.len() >= 2 {
            match self
                .banners
                .iter()
                .position(|b| b.duration_secs != u64::MAX)
            {
                Some(index) => {
                    self.banners.remove(index);
                }
                None => {
                    self.banners.pop_front();
                }
            }
        }

        self.banners.push_back(NotificationBanner {
            message,
            severity,
            created_at: std::time::Instant::now(),
            duration_secs,
        });
    }

    /// Remove expired banners from the queue
    pub fn prune_expired_banners(&mut self) {
        self.banners.retain(|banner| !banner.is_expired());
    }

    /// Recomputes every cache derived from the ruleset (preview tokens, diff,
    /// tags, filters, badges, validation, dirty flags). Called on every
    /// ruleset change, never in `view()`.
    fn update_cached_text(&mut self) {
        use std::collections::BTreeSet;

        let nft_text = self.ruleset.to_nft_text();

        // "Edit Rule" only for rules that still exist
        if let Some(panel) = &mut self.verify_errors {
            panel.sync_with(&self.ruleset);
        }
        // Who can reach the listening sockets now (no re-scan)
        if let Some(panel) = &mut self.exposure.panel {
            panel.rebuild(
                &self.ruleset,
                baseline_of(
                    self.last_applied_ruleset.as_ref(),
                    self.confirmed_record.as_ref(),
                    self.applied_this_session,
                ),
            );
        }

        self.cached_nft_tokens = syntax_cache::tokenize_nft(&nft_text);

        // The old side comes from the cache (it changes only on apply/revert)
        self.cached_diff_tokens = self.cached_applied_text.as_ref().and_then(|old| {
            syntax_cache::compute_and_tokenize_diff(
                old,
                &syntax_cache::TokenizedTextRef {
                    text: &nft_text,
                    lines: &self.cached_nft_tokens,
                },
            )
        });

        self.cached_nft_width_px = calculate_max_content_width(&self.cached_nft_tokens);
        self.cached_diff_width_px = if let Some(ref diff_tokens) = self.cached_diff_tokens {
            let diff_lines: Vec<&syntax_cache::HighlightedLine> =
                diff_tokens.iter().map(|(_, line)| line).collect();
            calculate_max_content_width_from_refs(&diff_lines) + view::DIFF_GUTTER_WIDTH_PX
        } else {
            self.cached_nft_width_px
        };

        // Collect unique tags using BTreeSet for automatic sorting
        let all_tags: BTreeSet<&String> = self
            .ruleset
            .rules
            .iter()
            .flat_map(|r| r.tags.iter())
            .collect();

        // Clone once directly into Arc (no intermediate Vec allocation)
        // Also build truncated versions for tag cloud display (avoids format! every frame)
        self.cached_all_tags = all_tags.iter().map(|s| Arc::new((*s).clone())).collect();
        self.cached_all_tags_truncated = all_tags
            .into_iter()
            .map(|s| {
                if s.len() > 16 {
                    format!("{}…", crate::utils::truncate_str(s, 15))
                } else {
                    s.clone()
                }
            })
            .collect();

        // Reset tag filter if the currently selected tag no longer exists
        if let Some(ref current_filter) = self.filter_tag
            && !self
                .cached_all_tags
                .iter()
                .any(|t| t.as_ref() == current_filter.as_ref())
        {
            // The typed search is the user's; only the gone tag is dropped
            self.filter_tag = None;
        }

        self.update_validation_cache();
        self.refresh_settings_display();
        self.update_rule_badges();
        self.update_filter_cache();
        self.refresh_dirty_flags();
    }

    /// The comparison baseline (see [`baseline_of`]).
    pub(crate) fn baseline(&self) -> Option<Baseline<'_>> {
        baseline_of(
            self.last_applied_ruleset.as_ref(),
            self.confirmed_record.as_ref(),
            self.applied_this_session,
        )
    }

    /// Re-tokenizes the old side of the diff and records where it comes
    /// from. Must run whenever the baseline changes: `last_applied_ruleset`
    /// ([`Self::set_last_applied`]) or the record
    /// ([`Self::replace_confirmed_record`]).
    fn refresh_diff_baseline(&mut self) {
        let baseline = self.baseline();
        let kind = baseline.map(|b| b.kind);
        let text = baseline.map(|b| syntax_cache::TokenizedText::new(b.ruleset.to_nft_text()));
        self.diff_baseline = kind;
        self.cached_applied_text = text;
    }

    /// Records what is now applied in the kernel (`None` = unknown) and
    /// refreshes the diff and the dirty state. Only the apply flow calls it.
    pub(crate) fn set_last_applied(&mut self, applied: Option<FirewallRuleset>) {
        self.last_applied_ruleset = applied;
        self.applied_this_session = true;
        self.refresh_diff_baseline();
        self.update_cached_text();
    }

    /// Replaces the kept-ruleset record (loaded from disk, or written by an
    /// apply this GUI kept). When the record is the comparison baseline
    /// (nothing applied this session), the diff and the Exposure panel
    /// follow; the dirty state never depends on it.
    pub(crate) fn replace_confirmed_record(
        &mut self,
        record: Option<crate::core::confirmed::ConfirmedRecord>,
    ) {
        let same = match (&self.confirmed_record, &record) {
            (None, None) => true,
            (Some(old), Some(new)) => {
                old.nftables_text() == new.nftables_text()
                    && old.from_this_boot() == new.from_this_boot()
                    && old.ruleset().is_some() == new.ruleset().is_some()
            }
            _ => false,
        };
        self.confirmed_record = record;
        if !same && self.last_applied_ruleset.is_none() {
            self.refresh_diff_baseline();
            self.update_cached_text();
        }
    }

    /// Records what the active profile file now contains and refreshes
    /// `is_profile_dirty()`.
    pub(crate) fn set_cached_disk_profile(&mut self, on_disk: FirewallRuleset) {
        self.cached_disk_profile = Some(on_disk);
        self.refresh_dirty_flags();
    }

    /// Replaces the profile list (and its "N profiles" label).
    pub(crate) fn set_available_profiles(&mut self, profiles: Vec<String>) {
        self.available_profiles = profiles;
        let count = self.available_profiles.len();
        self.profile_count_display = if count == 1 {
            "1 profile".to_string()
        } else {
            format!("{count} profiles")
        };
    }

    /// Sets the auto-revert countdown and its label.
    pub(crate) fn set_countdown(&mut self, remaining: u32) {
        self.countdown_remaining = remaining;
        self.countdown_display = remaining.to_string();
    }

    /// Reformats the settings slider labels (see [`SettingsDisplay`]).
    pub(crate) fn refresh_settings_display(&mut self) {
        let advanced = &self.ruleset.advanced_security;
        let display = &mut self.settings_display;
        display.auto_revert_timeout = format!("{}s", self.auto_revert_timeout_secs);
        display.apply_timer_secs =
            handlers::guard_timeout_secs_for(self.auto_revert_timeout_secs).to_string();
        display.icmp_rate = if advanced.icmp_rate_limit == 0 {
            "Off".to_string()
        } else {
            format!("{}/s", advanced.icmp_rate_limit)
        };
        display.log_rate = format!("{}/m", advanced.log_rate_per_minute);
    }

    /// Recomputes the cached `is_dirty()` / `is_profile_dirty()` flags.
    fn refresh_dirty_flags(&mut self) {
        self.cached_is_dirty = self.compute_is_dirty();
        self.cached_is_profile_dirty = self.compute_is_profile_dirty();
    }

    /// Sidebar protocol/port badge per rule; the chain arrow (↓/↑) is shown
    /// only in Server Mode, where the chain matters.
    fn update_rule_badges(&mut self) {
        let server_mode = self.ruleset.advanced_security.egress_profile
            == crate::core::firewall::EgressProfile::Server;
        self.cached_rule_badges.clear();
        self.cached_rule_badges
            .extend(self.ruleset.rules.iter().map(|rule| {
                if server_mode {
                    let arrow = match rule.chain {
                        crate::core::firewall::Chain::Input => '↓',
                        crate::core::firewall::Chain::Output => '↑',
                        crate::core::firewall::Chain::Forward => '→',
                    };
                    format!("{arrow}{}", rule.badge_display)
                } else {
                    rule.badge_display.clone()
                }
            }));
    }

    /// Recomputes which rules are invalid (and why) for the sidebar flags and
    /// the "cannot apply" notice. Called on every ruleset change, never in `view()`.
    fn update_validation_cache(&mut self) {
        self.cached_rule_issues.clear();
        self.cached_validation_notice = None;
        let Err(report) = self.ruleset.validate() else {
            return;
        };
        for problem in &report.rules {
            let text = problem
                .issues
                .iter()
                .map(|i| i.message.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            self.cached_rule_issues.insert(problem.rule_id, text);
        }
        self.cached_validation_notice = report.blocking_summary();
    }

    fn update_filter_cache(&mut self) {
        // Pre-allocate with worst-case capacity (all rules pass filter)
        let mut indices = Vec::with_capacity(self.ruleset.rules.len());

        indices.extend(
            self.ruleset
                .rules
                .iter()
                .enumerate()
                // Output rules stay listed in Desktop mode (shown as inactive)
                // so they can still be seen, edited and deleted.
                .filter(|(_, r)| {
                    if let Some(ref filter_tag) = self.filter_tag
                        && !r.tags.contains(filter_tag)
                    {
                        return false;
                    }

                    if self.rule_search.is_empty() {
                        return true;
                    }

                    let search_term = self.rule_search_lowercase.as_str();
                    r.label_lowercase.contains(search_term)
                        || r.protocol_lowercase.contains(search_term)
                        || r.interface_lowercase
                            .as_ref()
                            .is_some_and(|i| i.contains(search_term))
                        || r.tags_lowercase.iter().any(|tag| tag.contains(search_term))
                })
                .map(|(idx, _)| idx),
        );

        self.cached_filtered_rule_indices = indices;

        // Cache the filter count display string (avoids format! every frame)
        self.filter_count_display = format!(
            "{}/{}",
            self.cached_filtered_rule_indices.len(),
            self.ruleset.rules.len()
        );
    }

    /// `true` if `rule` is listed but not applied in the current mode:
    /// Output-chain rules only take effect in Server Mode (the generator skips
    /// them in Desktop mode). The sidebar shows such rules dimmed with a badge.
    pub(crate) fn rule_is_inactive(&self, rule: &crate::core::firewall::Rule) -> bool {
        self.ruleset.advanced_security.egress_profile
            == crate::core::firewall::EgressProfile::Desktop
            && rule.chain == crate::core::firewall::Chain::Output
    }

    pub(crate) fn clear_drag_state(&mut self) {
        self.dragged_rule_id = None;
        self.hovered_drop_target_id = None;
        self.hover_pending = None;
    }

    fn mark_config_dirty(&mut self) {
        self.config_dirty = true;
        self.last_config_change = Some(std::time::Instant::now());
    }

    fn mark_profile_dirty(&mut self) {
        self.profile_dirty = true;
        self.last_profile_change = Some(std::time::Instant::now());
        self.update_cached_text(); // UI updates immediately
    }

    fn schedule_slider_log(&mut self, description: String) {
        self.pending_slider_log = Some((description, std::time::Instant::now()));
    }

    /// The one-time "Auto-revert is off" notice is shown: auto-revert is
    /// off (e.g. an old config that saved the old default) and the user has
    /// not answered the notice or changed the setting.
    pub fn auto_revert_notice_visible(&self) -> bool {
        !self.auto_revert_enabled && !self.auto_revert_notice_shown
    }

    /// The ruleset differs from what DRFW last applied (or that is unknown).
    /// Never compared with the kept record: rules applied before this
    /// session may have been replaced since. Cached; safe to call from
    /// `view()`.
    pub fn is_dirty(&self) -> bool {
        self.cached_is_dirty
    }

    /// The ruleset differs from the profile file on disk.
    /// Cached; safe to call from `view()`.
    pub fn is_profile_dirty(&self) -> bool {
        self.cached_is_profile_dirty
    }

    fn compute_is_dirty(&self) -> bool {
        self.last_applied_ruleset
            .as_ref()
            .is_none_or(|last| !rulesets_match(last, &self.ruleset))
    }

    fn compute_is_profile_dirty(&self) -> bool {
        self.cached_disk_profile
            .as_ref()
            .is_some_and(|disk| !rulesets_match(disk, &self.ruleset))
    }

    /// Debug builds: the cached dirty flags and badges must match a fresh
    /// computation after every message (catches a mutation path that forgot to
    /// refresh). A mismatch is a bug: tests panic, while a debug GUI logs it and
    /// repairs the caches instead of crashing (the GUI never panics, see
    /// CLAUDE.md). Release builds skip the check entirely.
    fn debug_assert_caches(&mut self) {
        if !cfg!(debug_assertions) {
            return;
        }
        let stale = [
            ("is_dirty", self.cached_is_dirty != self.compute_is_dirty()),
            (
                "is_profile_dirty",
                self.cached_is_profile_dirty != self.compute_is_profile_dirty(),
            ),
            (
                "rule_badges",
                self.cached_rule_badges.len() != self.ruleset.rules.len(),
            ),
        ];
        let Some((name, _)) = stale.iter().find(|(_, is_stale)| *is_stale) else {
            return;
        };
        let msg = format!(
            "stale {name} cache: a ruleset/applied-state change skipped update_cached_text()"
        );
        report_stale_cache(&msg);
        self.update_cached_text();
        self.cached_is_dirty = self.compute_is_dirty();
        self.cached_is_profile_dirty = self.compute_is_profile_dirty();
    }

    /// Switches to `choice` (keeping the reduced-colors setting) and rebuilds
    /// the iced base theme.
    pub(crate) fn set_theme(&mut self, choice: crate::theme::ThemeChoice) {
        self.current_theme = choice;
        self.refresh_theme();
    }

    /// Rebuilds `theme` and the iced base theme from the current choice and
    /// the reduced-colors setting.
    pub(crate) fn refresh_theme(&mut self) {
        self.theme = build_theme(self.current_theme, self.reduced_colors);
        self.iced_theme = self.theme.to_iced_theme();
    }

    /// The iced base theme matching the current `AppTheme`, for
    /// `iced::application(..).theme(State::iced_theme)`. Cheap (an `Arc` clone).
    pub fn iced_theme(&self) -> iced::Theme {
        self.iced_theme.clone()
    }

    /// Arms the one-shot timer of every kind of debounced work that is
    /// pending (see `debounce`). Called after every message.
    fn arm_debounce_timers(&mut self, now: std::time::Instant) -> Task<Message> {
        if self.closing {
            return Task::none();
        }
        let deadlines = [
            (
                TimerKind::ConfigSave,
                handlers::config_save_deadline(self, now),
            ),
            (
                TimerKind::ProfileSave,
                handlers::profile_save_deadline(self, now),
            ),
            (TimerKind::SliderLog, handlers::slider_log_deadline(self)),
        ];
        let mut tasks = Vec::new();
        for (kind, deadline) in deadlines {
            if let Some(deadline) = deadline
                && let Some(generation) = self.timers.get_mut(kind).arm()
            {
                tasks.push(debounce::timer_task(
                    kind,
                    generation,
                    debounce::remaining(deadline, now),
                ));
            }
        }
        Task::batch(tasks)
    }

    /// Returns true if any operation is in progress that should block new operations
    pub fn is_busy(&self) -> bool {
        matches!(
            self.status,
            AppStatus::Verifying
                | AppStatus::Applying
                | AppStatus::PendingConfirmation { .. }
                | AppStatus::Confirming
                | AppStatus::Reverting
                | AppStatus::AwaitingSaveToSystem
                | AppStatus::SavingToSystem
        )
    }

    /// The config as it should be written to disk now.
    fn config_snapshot(&self) -> crate::config::AppConfig {
        crate::config::AppConfig {
            active_profile: self.active_profile_name.clone(),
            theme_choice: self.current_theme,
            regular_font: self.regular_font_choice.clone(),
            mono_font: self.mono_font_choice.clone(),
            show_diff: self.show_diff,
            show_zebra_striping: self.show_zebra_striping,
            auto_revert_enabled: self.auto_revert_enabled,
            auto_revert_notice_shown: self.auto_revert_notice_shown,
            auto_revert_timeout_secs: self.auto_revert_timeout_secs,
            enable_event_log: self.enable_event_log,
            reduced_colors: self.reduced_colors,
        }
    }

    fn save_config(&self) -> Task<Message> {
        let config = self.config_snapshot();

        Task::perform(
            async move {
                crate::config::save_config(&config)
                    .await
                    .map_err(|e| e.to_string())
            },
            Message::ConfigSaved,
        )
    }

    /// Handles one message, then arms the debounce timers for any work it
    /// left pending.
    pub fn update(&mut self, message: Message) -> Task<Message> {
        let task = self.dispatch(message);
        let timers = self.arm_debounce_timers(std::time::Instant::now());
        self.debug_assert_caches();
        Task::batch([task, timers])
    }

    fn dispatch(&mut self, message: Message) -> Task<Message> {
        // An unreadable profile is open read-only: refuse edits (and applying
        // its placeholder empty ruleset) instead of silently losing them.
        if self.unreadable_profile.is_some() && handlers::edits_profile(&message) {
            self.push_banner(
                "This profile could not be loaded and is read-only. Switch profiles, \
                 or choose \"Start fresh\" in the sidebar.",
                BannerSeverity::Warning,
            );
            return Task::none();
        }

        if (handlers::is_ruleset_edit(&message) || handlers::starts_rule_edit(&message))
            && handlers::edits_locked(self)
        {
            handlers::handle_edit_while_locked(self);
            return Task::none();
        }

        match message {
            // Rules domain
            Message::AddRuleClicked => return handlers::handle_add_rule_clicked(self),
            Message::EditRuleClicked(id) => return handlers::handle_edit_rule_clicked(self, id),
            Message::CancelRuleForm => handlers::handle_cancel_rule_form(self),
            Message::KeepEditingRuleForm => handlers::handle_keep_editing_rule_form(self),
            Message::DiscardRuleForm => handlers::handle_discard_rule_form(self),
            Message::SaveRuleForm => return handlers::handle_save_rule_form(self),
            Message::RuleFormLabelChanged(s) => handlers::handle_rule_form_label_changed(self, s),
            Message::RuleFormProtocolChanged(p) => {
                handlers::handle_rule_form_protocol_changed(self, p);
            }
            Message::RuleFormInterfaceChanged(s) => {
                handlers::handle_rule_form_interface_changed(self, s);
            }
            Message::RuleFormChainChanged(chain) => {
                handlers::handle_rule_form_chain_changed(self, chain);
            }
            Message::RuleFormToggleAdvanced(show) => {
                handlers::handle_rule_form_toggle_advanced(self, show);
            }
            Message::RuleFormActionChanged(action) => {
                handlers::handle_rule_form_action_changed(self, action);
            }
            Message::RuleFormToggleRateLimit(enabled) => {
                handlers::handle_rule_form_toggle_rate_limit(self, enabled);
            }
            Message::RuleFormRateLimitCountChanged(s) => {
                handlers::handle_rule_form_rate_limit_count_changed(self, s);
            }
            Message::RuleFormRateLimitUnitChanged(unit) => {
                handlers::handle_rule_form_rate_limit_unit_changed(self, unit);
            }
            Message::RuleFormConnectionLimitChanged(s) => {
                handlers::handle_rule_form_connection_limit_changed(self, s);
            }
            Message::RuleSearchChanged(s) => handlers::handle_rule_search_changed(self, &s),
            Message::ToggleRuleEnabled(id) => return handlers::handle_toggle_rule(self, id),
            Message::DeleteRuleRequested(id) => handlers::handle_delete_rule_requested(self, id),
            Message::CancelDelete => handlers::handle_cancel_delete(self),
            Message::DeleteRule(id) => return handlers::handle_delete_rule(self, id),

            // Apply domain
            Message::ApplyClicked => return handlers::handle_apply_clicked(self),
            Message::VerifyCompleted(result) => {
                return handlers::handle_verify_completed(self, result);
            }
            Message::ProceedToApply => return handlers::handle_proceed_to_apply(self),
            Message::ProceedToApplyAnyway => {
                return handlers::handle_proceed_to_apply_anyway(self);
            }
            Message::CancelApply => handlers::handle_cancel_apply(self),
            Message::ApplyResult(result) => return handlers::handle_apply_result(self, result),
            Message::ConfirmClicked => return handlers::handle_confirm_clicked(self),
            Message::RevertClicked => return handlers::handle_revert_clicked(self),
            Message::GuardFinished(result) => {
                return handlers::handle_guard_finished(self, result);
            }
            Message::CountdownTick => return handlers::handle_countdown_tick(self),
            Message::SaveToSystemClicked => return handlers::handle_save_to_system_clicked(self),
            Message::SaveToSystemVerifyResult(result) => {
                return handlers::handle_save_to_system_verify_result(self, result);
            }
            Message::SaveToSystemBootChecked(boot) => {
                handlers::handle_save_to_system_boot_checked(self, boot);
            }
            Message::SaveToSystemEnableToggled(enabled) => {
                handlers::handle_save_to_system_enable_toggled(self, enabled);
            }
            Message::SaveToSystemConfirmed(source) => {
                return handlers::handle_save_to_system_confirmed(self, source);
            }
            Message::SaveToSystemCancelled => {
                handlers::handle_save_to_system_cancelled(self);
            }
            Message::SaveToSystemResult(result) => {
                return handlers::handle_save_to_system_result(self, result);
            }

            // Export domain
            Message::ToggleExportModal(show) => handlers::handle_toggle_export_modal(self, show),
            Message::ExportAsJson => return handlers::handle_export_as_json(self),
            Message::ExportAsNft => return handlers::handle_export_as_nft(self),
            Message::ExportResult(result) => {
                return handlers::handle_export_result(self, result);
            }

            // UI state domain
            Message::TabChanged(tab) => handlers::handle_tab_changed(self, tab),
            Message::EventOccurred(event, status) => {
                return handlers::handle_event(self, &event, status);
            }
            Message::BaseShortcut(shortcut, input_focused) => {
                return handlers::handle_base_shortcut(self, shortcut, input_focused);
            }

            // Settings domain
            Message::ToggleDiff(enabled) => return handlers::handle_toggle_diff(self, enabled),
            Message::ToggleZebraStriping(enabled) => {
                return handlers::handle_toggle_zebra_striping(self, enabled);
            }
            Message::ToggleAutoRevert(enabled) => {
                return handlers::handle_toggle_auto_revert(self, enabled);
            }
            Message::AutoRevertNoticeAnswered(turn_on) => {
                return handlers::handle_auto_revert_notice_answered(self, turn_on);
            }
            Message::AutoRevertTimeoutChanged(timeout) => {
                handlers::handle_auto_revert_timeout_changed(self, timeout);
            }
            Message::ToggleEventLog(enabled) => {
                return handlers::handle_toggle_event_log(self, enabled);
            }
            Message::ToggleReducedColors(enabled) => {
                return handlers::handle_toggle_reduced_colors(self, enabled);
            }
            Message::ToggleStrictIcmpRequested(enabled) => {
                return handlers::handle_toggle_strict_icmp_requested(self, enabled);
            }
            Message::ConfirmStrictIcmp => return handlers::handle_confirm_strict_icmp(self),
            Message::IcmpRateLimitChanged(rate) => {
                handlers::handle_icmp_rate_limit_changed(self, rate);
            }
            Message::ToggleRpfRequested(enabled) => {
                return handlers::handle_toggle_rpf_requested(self, enabled);
            }
            Message::ConfirmEnableRpf => return handlers::handle_confirm_enable_rpf(self),
            Message::ToggleBlockForwarding(enabled) => {
                return handlers::handle_toggle_block_forwarding(self, enabled);
            }
            Message::CancelWarning => handlers::handle_cancel_warning(self),
            Message::ToggleDroppedLogging(enabled) => {
                return handlers::handle_toggle_dropped_logging(self, enabled);
            }
            Message::LogRateChanged(rate) => handlers::handle_log_rate_changed(self, rate),
            Message::CheckHoverPending => handlers::handle_check_hover_pending(self),
            Message::LogPrefixChanged(prefix) => {
                return handlers::handle_log_prefix_changed(self, &prefix);
            }
            Message::ServerModeToggled(enabled) => {
                return handlers::handle_server_mode_toggled(self, enabled);
            }
            Message::ConfirmServerMode => return handlers::handle_confirm_server_mode(self),
            Message::ToggleDiagnostics(show) => {
                return handlers::handle_toggle_diagnostics(self, show);
            }
            Message::ToggleVerifyErrors(show) => handlers::handle_toggle_verify_errors(self, show),
            Message::DiagnosticsFilterChanged(filter) => {
                handlers::handle_diagnostics_filter_changed(self, filter);
            }
            Message::DiagnosticsSearchChanged(search) => {
                handlers::handle_diagnostics_search_changed(self, search);
            }
            Message::AuditLogLoaded(generation, load) => {
                handlers::handle_audit_log_loaded(self, generation, load);
            }
            Message::CheckAuditLogRefresh => return handlers::refresh_audit_log(self),
            Message::AuditLogWritten => {}
            Message::ClearEventLog => handlers::handle_clear_event_log(self),
            Message::ClearEventLogCancelled => handlers::handle_cancel_clear_event_log(self),
            Message::ClearEventLogConfirmed => {
                return handlers::handle_confirm_clear_event_log(self);
            }
            Message::EventLogCleared(result) => {
                return handlers::handle_event_log_cleared(self, result);
            }
            Message::ToggleShortcutsHelp(show) => {
                handlers::handle_toggle_shortcuts_help(self, show);
            }
            Message::ToggleExposure(show) => return handlers::handle_toggle_exposure(self, show),
            Message::RefreshExposure => return handlers::handle_refresh_exposure(self),
            Message::ExposureScanned(generation, result) => {
                handlers::handle_exposure_scanned(self, generation, result);
            }
            Message::ApplyContextLoaded(context) => {
                if let Some(context) = context {
                    handlers::handle_apply_context_loaded(self, *context);
                }
            }
            Message::Undo => return handlers::handle_undo(self),
            Message::Redo => return handlers::handle_redo(self),
            Message::OpenThemePicker => return handlers::handle_open_theme_picker(self),
            Message::ThemePickerSearchChanged(search) => {
                handlers::handle_theme_picker_search_changed(self, search);
            }
            Message::ThemePickerFilterChanged(filter) => {
                handlers::handle_theme_picker_filter_changed(self, filter);
            }
            Message::ThemePreview(choice) => handlers::handle_theme_preview(self, choice),
            Message::ApplyTheme => return handlers::handle_apply_theme(self),
            Message::CancelThemePicker => handlers::handle_cancel_theme_picker(self),
            Message::RegularFontChanged(choice) => {
                return handlers::handle_regular_font_changed(self, &choice);
            }
            Message::MonoFontChanged(choice) => {
                return handlers::handle_mono_font_changed(self, &choice);
            }
            Message::OpenFontPicker(target) => {
                handlers::handle_open_font_picker(self, target);
                return focus::focus_input(focus::FONT_SEARCH);
            }
            Message::FontPickerSearchChanged(search) => {
                handlers::handle_font_picker_search_changed(self, search);
            }
            Message::CloseFontPicker => handlers::handle_close_font_picker(self),
            Message::FontsLoaded(fonts) => handlers::handle_fonts_loaded(self, fonts),
            Message::FilterByTag(tag) => handlers::handle_filter_by_tag(self, tag),
            Message::RuleDragStart(id) => handlers::handle_rule_drag_start(self, id),
            Message::RuleDropped(target_id) => {
                return handlers::handle_rule_dropped(self, target_id);
            }
            Message::RuleHoverStart(id) => handlers::handle_rule_hover_start(self, id),
            Message::RuleHoverEnd => handlers::handle_rule_hover_end(self),

            // Helper modal messages
            Message::OpenHelper(helper_type) => {
                return handlers::handle_open_helper(self, helper_type);
            }
            Message::CloseHelper => handlers::handle_close_helper(self),
            Message::HelperInputChanged(s) => handlers::handle_helper_input_changed(self, s),
            Message::HelperAddValue => handlers::handle_helper_add_value(self),
            Message::HelperRemoveValue(index) => handlers::handle_helper_remove_value(self, index),

            // New rule form field messages
            Message::RuleFormOutputInterfaceChanged(s) => {
                handlers::handle_rule_form_output_interface_changed(self, s);
            }
            Message::RuleFormRejectTypeChanged(reject_type) => {
                handlers::handle_rule_form_reject_type_changed(self, reject_type);
            }
            Message::RuleFormRateLimitBurstChanged(s) => {
                handlers::handle_rule_form_rate_limit_burst_changed(self, s);
            }
            Message::RuleFormRateLimitPerSourceToggled(enabled) => {
                handlers::handle_rule_form_rate_limit_per_source_toggled(self, enabled);
            }
            Message::RuleFormConnectionLimitPerSourceToggled(enabled) => {
                handlers::handle_rule_form_connection_limit_per_source_toggled(self, enabled);
            }
            Message::RuleFormLogEnabledToggled(enabled) => {
                handlers::handle_rule_form_log_enabled_toggled(self, enabled);
            }

            Message::ProfileSelected(name) => return handlers::handle_profile_selected(self, name),
            Message::ProfileSwitched(request, name, result) => {
                return handlers::handle_profile_switched(self, request, name, result);
            }
            Message::SaveProfileAs(name) => return handlers::handle_save_profile_as(self, name),
            Message::ProfileCreated(name, ruleset, result) => {
                return handlers::handle_profile_created(self, name, *ruleset, result);
            }
            Message::StartFreshProfile => handlers::handle_start_fresh_requested(self),
            Message::ConfirmStartFresh => return handlers::handle_start_fresh_profile(self),
            Message::CancelStartFresh => handlers::handle_cancel_start_fresh(self),
            Message::StartCreatingNewProfile => {
                return handlers::handle_start_creating_new_profile(self);
            }
            Message::CreateEmptyProfile => return handlers::handle_create_empty_profile(self),
            Message::NewProfileNameChanged(name) => {
                handlers::handle_new_profile_name_changed(self, name);
            }
            Message::CancelCreatingNewProfile => handlers::handle_cancel_creating_new_profile(self),
            Message::OpenProfileManager => handlers::handle_open_profile_manager(self),
            Message::CloseProfileManager => handlers::handle_close_profile_manager(self),
            Message::DeleteProfileRequested(name) => {
                handlers::handle_delete_profile_requested(self, name);
            }
            Message::ConfirmDeleteProfile => return handlers::handle_confirm_delete_profile(self),
            Message::ProfileDeleted(name, result) => {
                return handlers::handle_profile_deleted(self, name, result);
            }
            Message::CancelDeleteProfile => handlers::handle_cancel_delete_profile(self),
            Message::RenameProfileRequested(name) => {
                return handlers::handle_rename_profile_requested(self, name);
            }
            Message::ProfileNewNameChanged(new_name) => {
                handlers::handle_profile_new_name_changed(self, new_name);
            }
            Message::ConfirmRenameProfile => return handlers::handle_confirm_rename_profile(self),
            Message::ProfileRenamed(old, new, result) => {
                return handlers::handle_profile_renamed(self, old, new, result);
            }
            Message::CancelRenameProfile => handlers::handle_cancel_rename_profile(self),
            Message::ConfirmProfileSwitch => return handlers::handle_confirm_profile_switch(self),
            Message::DiscardProfileSwitch => return handlers::handle_discard_profile_switch(self),
            Message::CancelProfileSwitch => handlers::handle_cancel_profile_switch(self),
            Message::PruneBanners => handlers::handle_prune_banners(self),
            Message::DismissBanner(index) => handlers::handle_dismiss_banner(self, index),
            Message::TimerFired(kind, generation) => {
                return handlers::handle_timer_fired(self, kind, generation);
            }
            Message::ProfileSaved(outcome) => {
                return handlers::handle_profile_saved(self, *outcome);
            }
            Message::ConfigSaved(result) => handlers::handle_config_saved(self, result),
            Message::CloseRequested(id) => return handlers::handle_close_requested(self, id),
            Message::CloseFlushed(result) => return handlers::handle_close_flushed(self, result),
            Message::CancelClose => handlers::handle_cancel_close(self),
            Message::CloseAnyway => return handlers::handle_close_anyway(self),
            Message::Noop => {
                // No-op for async operations that don't need handling
            }
            Message::CopyPreviewLine(line_number) => {
                return handlers::handle_copy_preview_line(self, line_number);
            }
            Message::ClickPreviewLine(line_number) => {
                handlers::handle_click_preview_line(self, line_number);
            }
        }
        Task::none()
    }

    pub fn subscription(&self) -> iced::Subscription<Message> {
        iced::Subscription::batch(vec![
            iced::event::listen_with(handlers::keyboard_event_message),
            // Window close: flush pending saves first (exit_on_close_request is off)
            iced::window::close_requests().map(Message::CloseRequested),
            match self.status {
                AppStatus::PendingConfirmation { .. } => {
                    // The number changes once per second; so does the bar
                    iced::time::every(Duration::from_secs(1)).map(|_| Message::CountdownTick)
                }
                _ => iced::Subscription::none(),
            },
            // Prune expired banners every second (persistent banners never
            // expire, so they alone don't keep this tick running)
            if self.banners.iter().any(|b| b.duration_secs != u64::MAX) {
                iced::time::every(Duration::from_secs(1)).map(|_| Message::PruneBanners)
            } else {
                iced::Subscription::none()
            },
            // Debounced saves and slider logging use one-shot timer Tasks
            // (see `debounce`), not polling subscriptions.
            // Drag-and-drop hover debounce subscription
            // Runs at 60 FPS when there's a pending hover to process
            if self.hover_pending.is_some() {
                iced::time::every(Duration::from_millis(16)).map(|_| Message::CheckHoverPending)
            } else {
                iced::Subscription::none()
            },
            // Audit log auto-refresh while the diagnostics modal is open: each
            // tick stats the log and re-reads it only if it changed. Once a
            // second: every tick rebuilds the view, rows included.
            if self.show_diagnostics {
                iced::time::every(Duration::from_secs(1)).map(|_| Message::CheckAuditLogRefresh)
            } else {
                iced::Subscription::none()
            },
        ])
    }
}

/// Builds the app theme for `choice`, with reduced syntax colors if enabled.
fn build_theme(choice: crate::theme::ThemeChoice, reduced_colors: bool) -> crate::theme::AppTheme {
    let theme = choice.to_theme();
    if reduced_colors {
        theme.with_reduced_colors()
    } else {
        theme
    }
}

/// Enumerates the system fonts off the UI thread (parsing every font file
/// can take a noticeable time); the font pickers show "Loading" until done.
fn load_fonts_task() -> Task<Message> {
    Task::perform(
        async {
            tokio::task::spawn_blocking(crate::fonts::all_options)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("Font enumeration failed: {e}");
                    &[]
                })
        },
        Message::FontsLoaded,
    )
}

/// A stale GUI cache is a bug: fail loudly in tests.
#[cfg(test)]
fn report_stale_cache(msg: &str) {
    panic!("{msg}");
}

/// A stale GUI cache is a bug, but the GUI never panics: log it (the caller
/// repairs the caches).
#[cfg(not(test))]
fn report_stale_cache(msg: &str) {
    tracing::error!("{msg}; repairing caches");
}
