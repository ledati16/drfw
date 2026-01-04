pub mod syntax_cache;
pub mod ui_components;
mod view;

use crate::core::firewall::{FirewallRuleset, Protocol, Rule};
use chrono::Utc;
use iced::widget::Id;
use iced::widget::operation::focus;
use iced::{Animation, Element, Task, animation};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use strum::IntoEnumIterator;

/// Smart truncate a file path to fit in notifications
///
/// Keeps the filename and 1-2 parent directories for context.
/// Example: "/very/long/path/to/configs/production/rules.nft"
///       -> ".../production/rules.nft"
fn truncate_path_smart(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        return path.to_string();
    }

    let path_obj = Path::new(path);

    // Always keep filename
    let filename = path_obj
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("file");

    // Try to keep parent directory for context
    let parent = path_obj.parent();

    if let Some(parent) = parent
        && let Some(parent_name) = parent.file_name().and_then(|f| f.to_str())
    {
        let short = format!(".../{parent_name}/{filename}");
        if short.len() <= max_len {
            return short;
        }
    }

    // Fallback: just filename with ellipsis
    format!(".../{filename}")
}

/// Fuzzy filters fonts by name using the nucleo matcher.
///
/// Returns fonts sorted by match quality (best matches first).
/// Empty queries return all fonts with a score of 0.
///
/// Uses buffer reuse optimization to minimize allocations during filtering.
///
/// # Arguments
///
/// * `fonts` - Iterator of font choices to filter
/// * `query` - Search string (case-insensitive matching)
///
/// # Returns
///
/// Vector of (font, score) tuples sorted by descending score (best matches first).
/// Higher scores indicate better matches.
pub fn fuzzy_filter_fonts<'a>(
    fonts: impl Iterator<Item = &'a crate::fonts::FontChoice>,
    query: &str,
) -> Vec<(&'a crate::fonts::FontChoice, u16)> {
    if query.is_empty() {
        return fonts.map(|f| (f, 0)).collect();
    }

    let mut matcher = Matcher::new(Config::DEFAULT);
    let mut needle_buf = Vec::new();
    let needle = Utf32Str::new(query, &mut needle_buf);

    // Reuse buffer across all fonts to reduce allocations
    let mut haystack_buf = Vec::new();

    let mut results: Vec<_> = fonts
        .filter_map(|font| {
            haystack_buf.clear(); // Reuse instead of reallocate
            let haystack = Utf32Str::new(font.name_lowercase(), &mut haystack_buf);
            matcher
                .fuzzy_match(haystack, needle)
                .map(|score| (font, score))
        })
        .collect();

    // Sort by score descending (highest relevance first)
    results.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    results
}

/// Fuzzy filters themes by name using the nucleo matcher.
///
/// Returns themes sorted by match quality (best matches first).
/// Empty queries return all themes with a score of 0.
///
/// Uses buffer reuse optimization to minimize allocations during filtering.
///
/// # Arguments
///
/// * `themes` - Iterator of theme choices to filter
/// * `query` - Search string (case-insensitive matching)
///
/// # Returns
///
/// Vector of (theme, score) tuples sorted by descending score (best matches first).
/// Higher scores indicate better matches.
pub fn fuzzy_filter_themes(
    themes: impl Iterator<Item = crate::theme::ThemeChoice>,
    query: &str,
) -> Vec<(crate::theme::ThemeChoice, u16)> {
    if query.is_empty() {
        return themes.map(|t| (t, 0)).collect();
    }

    let mut matcher = Matcher::new(Config::DEFAULT);
    let query_lowercase = query.to_lowercase();
    let mut needle_buf = Vec::new();
    let needle = Utf32Str::new(&query_lowercase, &mut needle_buf);

    // Reuse buffer across all themes to reduce allocations
    let mut haystack_buf = Vec::new();

    let mut results: Vec<_> = themes
        .filter_map(|theme| {
            let theme_name_lowercase = theme.name().to_lowercase();
            haystack_buf.clear(); // Reuse instead of reallocate
            let haystack = Utf32Str::new(&theme_name_lowercase, &mut haystack_buf);
            matcher
                .fuzzy_match(haystack, needle)
                .map(|score| (theme, score))
        })
        .collect();

    // Sort by score descending (highest relevance first)
    results.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    results
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
    pub last_applied_ruleset: Option<FirewallRuleset>,
    pub cached_disk_profile: Option<FirewallRuleset>,
    pub status: AppStatus,
    pub banners: std::collections::VecDeque<NotificationBanner>,
    pub active_tab: WorkspaceTab,
    pub rule_form: Option<RuleForm>,
    pub countdown_remaining: u32,
    pub progress_animation: Animation<f32>,
    pub form_errors: Option<FormErrors>,
    pub interfaces_with_any: Vec<String>,
    pub cached_nft_tokens: Vec<syntax_cache::HighlightedLine>,
    pub cached_diff_tokens: Option<Vec<(syntax_cache::DiffType, syntax_cache::HighlightedLine)>>,
    pub cached_nft_width_px: f32,
    pub cached_diff_width_px: f32,
    pub rule_search: String,
    pub rule_search_lowercase: String,
    pub cached_all_tags: Vec<Arc<String>>,
    pub cached_filtered_rule_indices: Vec<usize>,
    pub deleting_id: Option<uuid::Uuid>,
    pub pending_warning: Option<PendingWarning>,
    pub show_diff: bool,
    pub show_zebra_striping: bool,
    pub auto_revert_enabled: bool,
    pub auto_revert_timeout_secs: u64,
    pub enable_event_log: bool,
    pub show_diagnostics: bool,
    pub diagnostics_filter: DiagnosticsFilter,
    pub show_export_modal: bool,
    pub show_shortcuts_help: bool,
    pub font_picker: Option<FontPickerState>,
    pub theme_picker: Option<ThemePickerState>,
    pub profile_manager: Option<ProfileManagerState>,
    pub command_history: crate::command::CommandHistory,
    pub current_theme: crate::theme::ThemeChoice,
    pub theme: crate::theme::AppTheme,
    pub filter_tag: Option<Arc<String>>,
    pub dragged_rule_id: Option<uuid::Uuid>,
    pub hovered_drop_target_id: Option<uuid::Uuid>,
    pub regular_font_choice: crate::fonts::RegularFontChoice,
    pub mono_font_choice: crate::fonts::MonoFontChoice,
    pub font_regular: iced::Font,
    pub font_mono: iced::Font,
    pub available_fonts: &'static [crate::fonts::FontChoice],
    // Config save debouncing
    pub config_dirty: bool,
    pub last_config_change: Option<std::time::Instant>,
    // Profile save debouncing
    pub profile_dirty: bool,
    pub last_profile_change: Option<std::time::Instant>,
    // Slider logging debouncing (description, last_change_time)
    pub pending_slider_log: Option<(String, std::time::Instant)>,
    // Profile management
    pub active_profile_name: String,
    pub available_profiles: Vec<String>,
    pub pending_profile_switch: Option<String>,
    // Audit log caching (Phase 1.1: Async diagnostics)
    /// Cached audit log entries for diagnostics modal
    /// Loaded asynchronously when modal opens, refreshed on demand
    pub cached_audit_entries: Vec<crate::audit::AuditEvent>,
    /// Tracks if audit log needs refresh (dirty flag)
    pub audit_log_dirty: bool,
}

#[derive(Debug, Clone)]
pub struct FontPickerState {
    pub target: FontPickerTarget,
    pub search: String,
    pub search_lowercase: String,
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
    /// Pre-computed theme conversions to avoid repeated to_theme() calls
    pub cached_themes: Vec<(crate::theme::ThemeChoice, crate::theme::AppTheme)>,
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
}

#[derive(Debug, Clone, PartialEq)]
pub enum PendingWarning {
    EnableRpf,
    EnableServerMode,
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
    PendingConfirmation {
        deadline: chrono::DateTime<Utc>,
        snapshot: serde_json::Value,
    },
    Confirmed,
    Reverting,
}

#[derive(Debug, Clone, Default)]
pub struct FormErrors {
    pub port: Option<String>,
    pub source: Option<String>,
    pub interface: Option<String>,
    pub destination: Option<String>,
    pub rate_limit: Option<String>,
    pub connection_limit: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RuleForm {
    pub id: Option<uuid::Uuid>,
    pub label: String,
    pub protocol: Protocol,
    pub port_start: String,
    pub port_end: String,
    pub source: String,
    pub interface: String,
    pub chain: crate::core::firewall::Chain,
    pub tags: Vec<String>,
    pub tag_input: String,
    pub show_advanced: bool,
    pub destination: String,
    pub action: crate::core::firewall::Action,
    pub rate_limit_enabled: bool,
    pub rate_limit_count: String,
    pub rate_limit_unit: crate::core::firewall::TimeUnit,
    pub connection_limit: String,
}

impl Default for RuleForm {
    fn default() -> Self {
        Self {
            id: None,
            label: String::new(),
            protocol: Protocol::Tcp,
            port_start: String::new(),
            port_end: String::new(),
            source: String::new(),
            interface: String::new(),
            chain: crate::core::firewall::Chain::Input,
            tags: Vec::new(),
            tag_input: String::new(),
            show_advanced: false,
            destination: String::new(),
            action: crate::core::firewall::Action::Accept,
            rate_limit_enabled: false,
            rate_limit_count: String::new(),
            rate_limit_unit: crate::core::firewall::TimeUnit::Second,
            connection_limit: String::new(),
        }
    }
}

impl RuleForm {
    pub fn validate(
        &self,
    ) -> (
        Option<crate::core::firewall::PortRange>,
        Option<ipnetwork::IpNetwork>,
        Option<FormErrors>,
    ) {
        let mut errors = FormErrors::default();
        let mut has_errors = false;

        let ports = self.validate_ports(&mut errors, &mut has_errors);
        let source = self.validate_source(&mut errors, &mut has_errors);
        self.validate_interface(&mut errors, &mut has_errors);
        self.validate_destination(&mut errors, &mut has_errors);
        self.validate_rate_limit(&mut errors, &mut has_errors);
        self.validate_connection_limit(&mut errors, &mut has_errors);

        if has_errors {
            (None, None, Some(errors))
        } else {
            (ports, source, None)
        }
    }

    fn validate_ports(
        &self,
        errors: &mut FormErrors,
        has_errors: &mut bool,
    ) -> Option<crate::core::firewall::PortRange> {
        if !matches!(
            self.protocol,
            Protocol::Tcp | Protocol::Udp | Protocol::TcpAndUdp
        ) {
            return None;
        }

        let port_start = self.port_start.parse::<u16>();
        let port_end = if self.port_end.is_empty() {
            port_start.clone() // Clone is necessary: Result doesn't implement Copy
        } else {
            self.port_end.parse::<u16>()
        };

        if let (Ok(s), Ok(e)) = (port_start, port_end) {
            match crate::validators::validate_port_range(s, e) {
                Ok((start, end)) => Some(crate::core::firewall::PortRange { start, end }),
                Err(msg) => {
                    errors.port = Some(msg.to_string());
                    *has_errors = true;
                    None
                }
            }
        } else {
            errors.port = Some("Invalid port number".to_string());
            *has_errors = true;
            None
        }
    }

    fn validate_source(
        &self,
        errors: &mut FormErrors,
        has_errors: &mut bool,
    ) -> Option<ipnetwork::IpNetwork> {
        let source = if self.source.is_empty() {
            return None;
        } else if let Ok(ip) = self.source.parse::<ipnetwork::IpNetwork>() {
            Some(ip)
        } else {
            errors.source = Some("Invalid IP address or CIDR (e.g. 192.168.1.0/24)".to_string());
            *has_errors = true;
            return None;
        };

        // Check protocol/IP version compatibility
        if let Some(src) = source {
            if self.protocol == Protocol::Icmp && src.is_ipv6() {
                errors.source = Some("ICMP (v4) selected with IPv6 source".to_string());
                *has_errors = true;
            } else if self.protocol == Protocol::Icmpv6 && src.is_ipv4() {
                errors.source = Some("ICMPv6 selected with IPv4 source".to_string());
                *has_errors = true;
            }
        }

        source
    }

    fn validate_interface(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        if !self.interface.is_empty()
            && let Err(msg) = crate::validators::validate_interface(&self.interface)
        {
            errors.interface = Some(msg.to_string());
            *has_errors = true;
        }
    }

    fn validate_destination(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        if !self.destination.is_empty() && self.destination.parse::<ipnetwork::IpNetwork>().is_err()
        {
            errors.destination =
                Some("Invalid destination IP or CIDR (domains not supported)".to_string());
            *has_errors = true;
        }
    }

    fn validate_rate_limit(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        if !self.rate_limit_enabled {
            return;
        }

        if let Ok(count) = self.rate_limit_count.parse::<u32>() {
            // Ignore warnings (Ok result), only handle errors
            if let Err(msg) = crate::validators::validate_rate_limit(count, self.rate_limit_unit) {
                errors.rate_limit = Some(msg);
                *has_errors = true;
            }
        } else if !self.rate_limit_count.is_empty() {
            errors.rate_limit = Some("Invalid rate limit number".to_string());
            *has_errors = true;
        }
    }

    fn validate_connection_limit(&self, errors: &mut FormErrors, has_errors: &mut bool) {
        if self.connection_limit.is_empty() {
            return;
        }

        if let Ok(limit) = self.connection_limit.parse::<u32>() {
            // Ignore warnings (Ok result), only handle errors
            if let Err(msg) = crate::validators::validate_connection_limit(limit) {
                errors.connection_limit = Some(msg);
                *has_errors = true;
            }
        } else {
            errors.connection_limit = Some("Invalid connection limit number".to_string());
            *has_errors = true;
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    AddRuleClicked,
    EditRuleClicked(uuid::Uuid),
    CancelRuleForm,
    SaveRuleForm,
    RuleFormLabelChanged(String),
    RuleFormProtocolChanged(Protocol),
    RuleFormPortStartChanged(String),
    RuleFormPortEndChanged(String),
    RuleFormSourceChanged(String),
    RuleFormInterfaceChanged(String),
    RuleFormChainChanged(crate::core::firewall::Chain),
    RuleFormToggleAdvanced(bool),
    RuleFormDestinationChanged(String),
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
    VerifyCompleted(Result<crate::core::verify::VerifyResult, String>),
    ProceedToApply,
    ApplyResult(Result<serde_json::Value, String>),
    ConfirmClicked,
    RevertClicked,
    RevertResult(Result<(), String>),
    CountdownTick,
    TabChanged(WorkspaceTab),
    ToggleExportModal(bool),
    SaveToSystemClicked,
    SaveToSystemResult(Result<(), String>),
    EventOccurred(iced::Event),
    ToggleDiff(bool),
    ToggleZebraStriping(bool),
    ToggleAutoRevert(bool),
    AutoRevertTimeoutChanged(u64),
    ToggleEventLog(bool),
    ToggleStrictIcmp(bool),
    IcmpRateLimitChanged(u32),
    ToggleRpfRequested(bool),
    ConfirmEnableRpf,
    CancelWarning,
    ToggleDroppedLogging(bool),
    LogRateChanged(u32),
    CheckSliderLog,
    LogPrefixChanged(String),
    ServerModeToggled(bool),
    ConfirmServerMode,
    ToggleDiagnostics(bool),
    DiagnosticsFilterChanged(DiagnosticsFilter),
    /// Audit log entries loaded asynchronously (Phase 1.1)
    AuditEntriesLoaded(Vec<crate::audit::AuditEvent>),
    /// Check if audit log needs refresh (auto-refresh subscription)
    CheckAuditLogRefresh,
    /// Audit log write completed (mark cache dirty)
    AuditLogWritten,
    ClearEventLog,
    OpenLogsFolder,
    ExportAsJson,
    ExportAsNft,
    ExportResult(Result<String, String>),
    ToggleShortcutsHelp(bool),
    Undo,
    Redo,
    #[allow(dead_code)]
    ThemeChanged(crate::theme::ThemeChoice),
    OpenThemePicker,
    ThemePickerSearchChanged(String),
    ThemePickerFilterChanged(ThemeFilter),
    ThemePreview(crate::theme::ThemeChoice),
    ApplyTheme,
    CancelThemePicker,
    ThemePreviewButtonClick,
    RegularFontChanged(crate::fonts::RegularFontChoice),
    MonoFontChanged(crate::fonts::MonoFontChoice),
    OpenFontPicker(FontPickerTarget),
    FontPickerSearchChanged(String),
    CloseFontPicker,
    RuleFormTagInputChanged(String),
    RuleFormAddTag,
    RuleFormRemoveTag(String),
    FilterByTag(Option<Arc<String>>),
    RuleDragStart(uuid::Uuid),
    RuleDropped(uuid::Uuid),
    RuleHoverStart(uuid::Uuid),
    RuleHoverEnd,
    // Profile messages
    ProfileSelected(String),
    ProfileSwitched(String, FirewallRuleset),
    SaveProfileAs(String),
    StartCreatingNewProfile,
    CreateEmptyProfile,
    NewProfileNameChanged(String),
    CancelCreatingNewProfile,
    OpenProfileManager,
    CloseProfileManager,
    DeleteProfileRequested(String),
    ConfirmDeleteProfile,
    ProfileDeleted(Result<Vec<String>, String>),
    CancelDeleteProfile,
    RenameProfileRequested(String),
    ProfileNewNameChanged(String),
    ConfirmRenameProfile,
    ProfileRenamed(Result<Vec<String>, String>),
    CancelRenameProfile,
    ConfirmProfileSwitch,
    DiscardProfileSwitch,
    CancelProfileSwitch,
    ProfileSwitchAfterSave(String),
    ProfileListUpdated(Vec<String>),
    /// Periodic tick to prune expired banners
    PruneBanners,
    /// Dismiss a specific banner (click to dismiss)
    DismissBanner(usize),
    /// Check if config should be saved (debounced)
    CheckConfigSave,
    /// Check if profile should be saved (debounced)
    CheckProfileSave,
    /// Disk profile loaded for cache refresh
    DiskProfileLoaded(Option<FirewallRuleset>),
    /// No-op message for async operations that don't need a result
    Noop,
}

impl State {
    pub fn view(&self) -> Element<'_, Message> {
        view::view(self)
    }

    fn calculate_max_content_width(tokens: &[syntax_cache::HighlightedLine]) -> f32 {
        const CHAR_WIDTH_PX: f32 = 8.4;
        const LINE_NUMBER_WIDTH_PX: f32 = 50.0;
        const TRAILING_PADDING_PX: f32 = 60.0;
        const MIN_WIDTH_PX: f32 = 800.0;
        const MAX_WIDTH_PX: f32 = 3000.0;

        let max_char_count = tokens
            .iter()
            .map(|line| {
                let indent_chars = line.indent;
                let token_chars: usize = line.tokens.iter().map(|t| t.text.len()).sum();
                indent_chars + token_chars
            })
            .max()
            .unwrap_or(0);

        let content_width =
            LINE_NUMBER_WIDTH_PX + (max_char_count as f32 * CHAR_WIDTH_PX) + TRAILING_PADDING_PX;
        content_width.clamp(MIN_WIDTH_PX, MAX_WIDTH_PX)
    }

    fn calculate_max_content_width_from_refs(tokens: &[&syntax_cache::HighlightedLine]) -> f32 {
        const CHAR_WIDTH_PX: f32 = 8.4;
        const LINE_NUMBER_WIDTH_PX: f32 = 50.0;
        const TRAILING_PADDING_PX: f32 = 60.0;
        const MIN_WIDTH_PX: f32 = 800.0;
        const MAX_WIDTH_PX: f32 = 3000.0;

        let max_char_count = tokens
            .iter()
            .map(|line| {
                let indent_chars = line.indent;
                let token_chars: usize = line.tokens.iter().map(|t| t.text.len()).sum();
                indent_chars + token_chars
            })
            .max()
            .unwrap_or(0);

        let content_width =
            LINE_NUMBER_WIDTH_PX + (max_char_count as f32 * CHAR_WIDTH_PX) + TRAILING_PADDING_PX;
        content_width.clamp(MIN_WIDTH_PX, MAX_WIDTH_PX)
    }

    pub fn new() -> (Self, Task<Message>) {
        let config = crate::config::load_config_blocking();
        let current_theme = config.theme_choice;
        let mut regular_font_choice = config.regular_font;
        let mut mono_font_choice = config.mono_font;
        let show_diff = config.show_diff;
        let show_zebra_striping = config.show_zebra_striping;
        let auto_revert_enabled = config.auto_revert_enabled;
        // Clamp timeout to prevent integer overflow (max 1 hour = 3600 seconds)
        let auto_revert_timeout_secs = config.auto_revert_timeout_secs.min(3600);
        let enable_event_log = config.enable_event_log;
        let active_profile_name = config.active_profile;

        regular_font_choice.resolve(false);
        mono_font_choice.resolve(true);

        // Startup guarantee: Ensure at least one profile exists
        // Handles first run, manual deletion, or filesystem corruption
        if let Err(e) = crate::core::profiles::ensure_profile_exists_blocking() {
            tracing::error!("Failed to ensure profile exists: {}", e);
        }

        let ruleset = crate::core::profiles::load_profile_blocking(&active_profile_name)
            .unwrap_or_else(|_| FirewallRuleset::default());

        let available_profiles = crate::core::profiles::list_profiles_blocking()
            .unwrap_or_else(|_| vec![crate::core::profiles::DEFAULT_PROFILE_NAME.to_string()]);

        let interfaces = crate::utils::list_interfaces();
        let interfaces_with_any: Vec<String> = std::iter::once("Any".to_string())
            .chain(interfaces.iter().cloned())
            .collect();

        let theme = current_theme.to_theme();
        let font_regular = regular_font_choice.to_font();
        let font_mono = mono_font_choice.to_font();
        let available_fonts = crate::fonts::all_options();

        let mut state = Self {
            last_applied_ruleset: Some(ruleset.clone()),
            cached_disk_profile: Some(ruleset.clone()),
            ruleset,
            status: AppStatus::Idle,
            banners: std::collections::VecDeque::new(),
            active_tab: WorkspaceTab::Nftables,
            rule_form: None,
            countdown_remaining: 15,
            progress_animation: Animation::new(1.0),
            form_errors: None,
            interfaces_with_any,
            cached_nft_tokens: Vec::new(),
            cached_diff_tokens: None,
            cached_nft_width_px: 800.0,
            cached_diff_width_px: 800.0,
            rule_search: String::new(),
            rule_search_lowercase: String::new(),
            cached_all_tags: Vec::new(),
            cached_filtered_rule_indices: Vec::new(),
            deleting_id: None,
            pending_warning: None,
            show_diff,
            show_zebra_striping,
            auto_revert_enabled,
            auto_revert_timeout_secs,
            enable_event_log,
            show_diagnostics: false,
            diagnostics_filter: DiagnosticsFilter::default(),
            show_export_modal: false,
            show_shortcuts_help: false,
            font_picker: None,
            theme_picker: None,
            profile_manager: None,
            command_history: crate::command::CommandHistory::default(),
            current_theme,
            theme,
            filter_tag: None,
            dragged_rule_id: None,
            hovered_drop_target_id: None,
            regular_font_choice,
            mono_font_choice,
            font_regular,
            font_mono,
            available_fonts,
            config_dirty: false,
            last_config_change: None,
            profile_dirty: false,
            last_profile_change: None,
            pending_slider_log: None,
            active_profile_name,
            available_profiles,
            pending_profile_switch: None,
            cached_audit_entries: Vec::new(),
            audit_log_dirty: true, // Load on first open
        };

        // Initialize all caches properly via centralized logic
        state.update_cached_text();

        (state, Task::none())
    }

    /// Loads audit log entries asynchronously
    /// Returns parsed events, most recent first (reversed order)
    async fn load_audit_entries() -> Vec<crate::audit::AuditEvent> {
        use tokio::io::AsyncBufReadExt;

        let Some(mut path) = crate::utils::get_state_dir() else {
            return Vec::new();
        };
        path.push("audit.log");

        let Ok(file) = tokio::fs::File::open(&path).await else {
            return Vec::new();
        };

        let reader = tokio::io::BufReader::new(file);
        let mut lines = reader.lines();
        let mut events = Vec::new();

        while let Ok(Some(line)) = lines.next_line().await {
            if let Ok(event) = serde_json::from_str::<crate::audit::AuditEvent>(&line) {
                events.push(event);
            }
        }

        // Most recent first
        events.reverse();
        events
    }

    /// Add a banner to the notification queue (max 2 visible)
    pub fn push_banner(
        &mut self,
        message: impl Into<String>,
        severity: BannerSeverity,
        duration_secs: u64,
    ) {
        // Remove oldest if at capacity
        while self.banners.len() >= 2 {
            self.banners.pop_front();
        }

        self.banners.push_back(NotificationBanner {
            message: message.into(),
            severity,
            created_at: std::time::Instant::now(),
            duration_secs,
        });
    }

    /// Remove expired banners from the queue
    pub fn prune_expired_banners(&mut self) {
        self.banners.retain(|banner| !banner.is_expired());
    }

    fn update_cached_text(&mut self) {
        use std::collections::BTreeSet;

        let nft_text = self.ruleset.to_nft_text();

        self.cached_nft_tokens = syntax_cache::tokenize_nft(&nft_text);

        self.cached_diff_tokens = if let Some(ref last) = self.last_applied_ruleset {
            let old_text = last.to_nft_text();
            syntax_cache::compute_and_tokenize_diff(&old_text, &nft_text)
        } else {
            None
        };

        self.cached_nft_width_px = Self::calculate_max_content_width(&self.cached_nft_tokens);
        self.cached_diff_width_px = if let Some(ref diff_tokens) = self.cached_diff_tokens {
            let diff_lines: Vec<&syntax_cache::HighlightedLine> =
                diff_tokens.iter().map(|(_, line)| line).collect();
            Self::calculate_max_content_width_from_refs(&diff_lines)
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
        self.cached_all_tags = all_tags.into_iter().map(|s| Arc::new(s.clone())).collect();

        // Reset tag filter if the currently selected tag no longer exists
        if let Some(ref current_filter) = self.filter_tag
            && !self
                .cached_all_tags
                .iter()
                .any(|t| t.as_ref() == current_filter.as_ref())
        {
            self.filter_tag = None;
            self.rule_search.clear();
            self.rule_search_lowercase.clear();
        }

        self.update_filter_cache();
    }

    fn update_filter_cache(&mut self) {
        // Pre-allocate with worst-case capacity (all rules pass filter)
        let mut indices = Vec::with_capacity(self.ruleset.rules.len());

        indices.extend(
            self.ruleset
                .rules
                .iter()
                .enumerate()
                .filter(|(_, r)| {
                    if self.ruleset.advanced_security.egress_profile
                        == crate::core::firewall::EgressProfile::Desktop
                        && r.chain == crate::core::firewall::Chain::Output
                    {
                        return false;
                    }

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
    }

    fn save_config(&self) -> Task<Message> {
        let config = crate::config::AppConfig {
            active_profile: self.active_profile_name.clone(),
            theme_choice: self.current_theme,
            regular_font: self.regular_font_choice.clone(),
            mono_font: self.mono_font_choice.clone(),
            show_diff: self.show_diff,
            show_zebra_striping: self.show_zebra_striping,
            auto_revert_enabled: self.auto_revert_enabled,
            auto_revert_timeout_secs: self.auto_revert_timeout_secs,
            enable_event_log: self.enable_event_log,
        };

        // Async save using Task::perform
        Task::perform(
            async move {
                if let Err(e) = crate::config::save_config(&config).await {
                    eprintln!("Failed to save configuration: {e}");
                }
            },
            |()| Message::Noop,
        )
    }

    fn mark_config_dirty(&mut self) {
        self.config_dirty = true;
        self.last_config_change = Some(std::time::Instant::now());
    }

    fn handle_check_config_save(&mut self) -> Task<Message> {
        const DEBOUNCE_MS: u64 = 500;

        if !self.config_dirty {
            return Task::none();
        }

        // Check if enough time has passed since last change
        if let Some(last_change) = self.last_config_change
            && last_change.elapsed().as_millis() < DEBOUNCE_MS as u128
        {
            return Task::none();
        }

        self.config_dirty = false;
        self.save_config()
    }

    fn mark_profile_dirty(&mut self) {
        self.profile_dirty = true;
        self.last_profile_change = Some(std::time::Instant::now());
        self.update_cached_text(); // UI updates immediately
    }

    fn handle_check_profile_save(&mut self) -> Task<Message> {
        const DEBOUNCE_MS: u64 = 1000; // 1 second for profiles

        if !self.profile_dirty {
            return Task::none();
        }

        // Check if enough time has passed since last change
        if let Some(last_change) = self.last_profile_change
            && last_change.elapsed().as_millis() < DEBOUNCE_MS as u128
        {
            return Task::none();
        }

        self.profile_dirty = false;
        let save_task = self.save_profile();
        let refresh_task = self.refresh_disk_profile_cache();
        save_task.chain(refresh_task)
    }

    fn schedule_slider_log(&mut self, description: String) {
        self.pending_slider_log = Some((description, std::time::Instant::now()));
    }

    fn handle_check_slider_log(&mut self) -> Task<Message> {
        const DEBOUNCE_MS: u64 = 2000; // 2 seconds for slider changes

        if let Some((description, last_change)) = &self.pending_slider_log
            && last_change.elapsed().as_millis() >= DEBOUNCE_MS as u128
        {
            let desc = description.clone();
            self.pending_slider_log = None;
            let enable_event_log = self.enable_event_log;
            return Task::perform(
                async move {
                    crate::audit::log_settings_saved(enable_event_log, &desc).await;
                },
                |_| Message::AuditLogWritten,
            );
        }
        Task::none()
    }

    fn save_profile(&self) -> Task<Message> {
        let profile_name = self.active_profile_name.clone();
        let ruleset = self.ruleset.clone();

        Task::perform(
            async move {
                if let Err(e) = crate::core::profiles::save_profile(&profile_name, &ruleset).await {
                    eprintln!("Failed to save profile: {e}");
                }
            },
            |()| Message::Noop,
        )
    }

    fn refresh_disk_profile_cache(&mut self) -> Task<Message> {
        let profile_name = self.active_profile_name.clone();

        Task::perform(
            async move {
                crate::core::profiles::load_profile(&profile_name)
                    .await
                    .ok()
            },
            Message::DiskProfileLoaded,
        )
    }

    fn handle_disk_profile_loaded(&mut self, profile: Option<FirewallRuleset>) {
        self.cached_disk_profile = profile;
    }

    pub fn is_dirty(&self) -> bool {
        self.last_applied_ruleset.as_ref().is_none_or(|last| {
            last.rules != self.ruleset.rules
                || last.advanced_security != self.ruleset.advanced_security
        })
    }

    pub fn is_profile_dirty(&self) -> bool {
        self.cached_disk_profile.as_ref().is_some_and(|disk| {
            disk.rules != self.ruleset.rules
                || disk.advanced_security != self.ruleset.advanced_security
        })
    }

    fn handle_switch_profile(&mut self, name: String) -> Task<Message> {
        if self.is_profile_dirty() {
            self.pending_profile_switch = Some(name);
            return Task::none();
        }
        self.perform_profile_switch(name)
    }

    fn perform_profile_switch(&mut self, name: String) -> Task<Message> {
        // Async load profile using Task::perform
        let active_profile = name.clone();
        self.pending_profile_switch = None;

        Task::perform(
            async move { crate::core::profiles::load_profile(&active_profile).await },
            move |result| match result {
                Ok(ruleset) => Message::ProfileSwitched(name, ruleset),
                Err(e) => {
                    eprintln!("Failed to load profile: {e}");
                    Message::Noop
                }
            },
        )
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::AddRuleClicked => {
                self.rule_form = Some(RuleForm::default());
                self.form_errors = None;
            }
            Message::EditRuleClicked(id) => self.handle_edit_clicked(id),
            Message::CancelRuleForm => {
                self.rule_form = None;
                self.form_errors = None;
                if self.status == AppStatus::AwaitingApply {
                    self.status = AppStatus::Idle;
                }
            }
            Message::SaveRuleForm => return self.handle_save_rule_form(),
            Message::RuleFormLabelChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.label = s;
                }
            }
            Message::RuleFormProtocolChanged(p) => {
                if let Some(f) = &mut self.rule_form {
                    f.protocol = p;
                }
            }
            Message::RuleFormPortStartChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.port_start = s;
                }
            }
            Message::RuleFormPortEndChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.port_end = s;
                }
            }
            Message::RuleFormSourceChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.source = s;
                }
            }
            Message::RuleFormInterfaceChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.interface = s;
                }
            }
            Message::RuleFormChainChanged(chain) => {
                if let Some(f) = &mut self.rule_form {
                    f.chain = chain;
                }
            }
            Message::RuleFormToggleAdvanced(show) => {
                if let Some(f) = &mut self.rule_form {
                    f.show_advanced = show;
                }
            }
            Message::RuleFormDestinationChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.destination = s;
                }
            }
            Message::RuleFormActionChanged(action) => {
                if let Some(f) = &mut self.rule_form {
                    f.action = action;
                }
            }
            Message::RuleFormToggleRateLimit(enabled) => {
                if let Some(f) = &mut self.rule_form {
                    f.rate_limit_enabled = enabled;
                }
            }
            Message::RuleFormRateLimitCountChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.rate_limit_count = s;
                }
            }
            Message::RuleFormRateLimitUnitChanged(unit) => {
                if let Some(f) = &mut self.rule_form {
                    f.rate_limit_unit = unit;
                }
            }
            Message::RuleFormConnectionLimitChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.connection_limit = s;
                }
            }
            Message::RuleSearchChanged(s) => {
                self.rule_search_lowercase = s.to_lowercase();
                self.rule_search = s;
                self.update_filter_cache();
            }
            Message::ToggleRuleEnabled(id) => return self.handle_toggle_rule(id),
            Message::DeleteRuleRequested(id) => self.deleting_id = Some(id),
            Message::CancelDelete => self.deleting_id = None,
            Message::DeleteRule(id) => return self.handle_delete_rule(id),
            Message::ApplyClicked => return self.handle_apply_clicked(),
            Message::VerifyCompleted(result) => return self.handle_verify_completed(result),
            Message::ProceedToApply => return self.handle_proceed_to_apply(),
            Message::ApplyResult(Err(e)) | Message::RevertResult(Err(e)) => {
                self.status = AppStatus::Idle;

                // Detect elevation-specific errors and handle accordingly
                if e.contains("Authentication cancelled") {
                    self.push_banner("Authentication was cancelled", BannerSeverity::Warning, 5);
                    let enable_event_log = self.enable_event_log;
                    return Task::perform(
                        async move {
                            crate::audit::log_elevation_cancelled(
                                enable_event_log,
                                "User cancelled authentication".to_string(),
                            )
                            .await;
                        },
                        |_| Message::AuditLogWritten,
                    );
                } else if e.contains("Authentication failed") {
                    self.push_banner("Authentication failed", BannerSeverity::Error, 5);
                    let enable_event_log = self.enable_event_log;
                    let error_msg = e.clone();
                    return Task::perform(
                        async move {
                            crate::audit::log_elevation_failed(enable_event_log, error_msg).await;
                        },
                        |_| Message::AuditLogWritten,
                    );
                } else if e.contains("timed out") || e.contains("Operation timed out") {
                    self.push_banner("Authentication timed out", BannerSeverity::Error, 5);
                    let enable_event_log = self.enable_event_log;
                    let error_msg = e.clone();
                    return Task::perform(
                        async move {
                            crate::audit::log_elevation_failed(enable_event_log, error_msg).await;
                        },
                        |_| Message::AuditLogWritten,
                    );
                } else if e.contains("No authentication agent") || e.contains("No polkit") {
                    self.push_banner(
                        "No authentication agent available. Install polkit.",
                        BannerSeverity::Error,
                        8,
                    );
                    let enable_event_log = self.enable_event_log;
                    let error_msg = e.clone();
                    return Task::perform(
                        async move {
                            crate::audit::log_elevation_failed(enable_event_log, error_msg).await;
                        },
                        |_| Message::AuditLogWritten,
                    );
                } else if e.contains("nft binary not found") || e.contains("nftables") {
                    self.push_banner("nftables not installed", BannerSeverity::Error, 5);
                    let enable_event_log = self.enable_event_log;
                    let error_msg = e.clone();
                    return Task::perform(
                        async move {
                            crate::audit::log_elevation_failed(enable_event_log, error_msg).await;
                        },
                        |_| Message::AuditLogWritten,
                    );
                } else {
                    // Generic error - show error message
                    let msg = if e.len() > 80 {
                        format!("{}...", &e[..77])
                    } else {
                        e.clone()
                    };
                    self.push_banner(&msg, BannerSeverity::Error, 8);
                }
            }
            Message::ApplyResult(Ok(snapshot)) => self.handle_apply_result(snapshot),
            Message::ConfirmClicked => {
                if matches!(self.status, AppStatus::PendingConfirmation { .. }) {
                    self.status = AppStatus::Confirmed;
                    self.push_banner(
                        "Firewall rules have been saved and will persist.",
                        BannerSeverity::Success,
                        5,
                    );
                    // Log auto-revert confirmation
                    let enable_event_log = self.enable_event_log;
                    let timeout_secs = self.auto_revert_timeout_secs;
                    return Task::perform(
                        async move {
                            crate::audit::log_auto_revert_confirmed(enable_event_log, timeout_secs)
                                .await;
                        },
                        |_| Message::AuditLogWritten,
                    );
                }
            }
            Message::RevertClicked => return self.handle_revert_clicked(),
            Message::RevertResult(Ok(())) => {
                self.status = AppStatus::Idle;
                self.push_banner(
                    "Firewall rules have been restored to previous state.",
                    BannerSeverity::Warning,
                    5,
                );
            }
            Message::CountdownTick => return self.handle_countdown_tick(),
            Message::TabChanged(tab) => self.active_tab = tab,
            Message::ToggleExportModal(show) => {
                self.show_export_modal = show;
            }
            Message::ExportAsJson => return self.handle_export_json(),
            Message::ExportAsNft => return self.handle_export_nft(),
            Message::ExportResult(Ok(path)) => {
                self.show_export_modal = false;
                let display_path = truncate_path_smart(&path, 50);
                self.push_banner(
                    format!("Rules exported to: {display_path}"),
                    BannerSeverity::Success,
                    5,
                );

                // Log export completion
                let enable_event_log = self.enable_event_log;
                let path_clone = path.clone();
                let format = if path.ends_with(".json") {
                    "json"
                } else {
                    "nft"
                };
                return Task::perform(
                    async move {
                        crate::audit::log_export_completed(enable_event_log, format, &path_clone)
                            .await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::ExportResult(Err(e)) => {
                self.show_export_modal = false;
                let msg = if e.len() > 70 {
                    format!("Export failed: {}...", &e[..67])
                } else {
                    format!("Export failed: {}", e)
                };
                self.push_banner(&msg, BannerSeverity::Error, 8);
            }
            Message::SaveToSystemClicked => return self.handle_save_to_system(),
            Message::SaveToSystemResult(Ok(())) => {
                self.push_banner(
                    "Successfully saved to /etc/nftables.conf",
                    BannerSeverity::Success,
                    5,
                );
            }
            Message::SaveToSystemResult(Err(e)) => {
                let msg = if e.len() > 60 {
                    format!("Save to system failed: {}...", &e[..52])
                } else {
                    format!("Save to system failed: {}", e)
                };
                self.push_banner(&msg, BannerSeverity::Error, 8);
            }
            Message::EventOccurred(event) => return self.handle_event(event),
            Message::ToggleDiff(enabled) => {
                self.show_diff = enabled;
                self.mark_config_dirty();
                let enable_event_log = self.enable_event_log;
                let desc = if enabled {
                    "Diff view enabled"
                } else {
                    "Diff view disabled"
                };
                return Task::perform(
                    async move {
                        crate::audit::log_settings_saved(enable_event_log, desc).await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::ToggleZebraStriping(enabled) => {
                self.show_zebra_striping = enabled;
                self.mark_config_dirty();
                let enable_event_log = self.enable_event_log;
                let desc = if enabled {
                    "Zebra striping enabled"
                } else {
                    "Zebra striping disabled"
                };
                return Task::perform(
                    async move {
                        crate::audit::log_settings_saved(enable_event_log, desc).await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::ToggleAutoRevert(enabled) => {
                self.auto_revert_enabled = enabled;
                self.mark_config_dirty();
                let enable_event_log = self.enable_event_log;
                let desc = if enabled {
                    "Auto-revert enabled"
                } else {
                    "Auto-revert disabled"
                };
                return Task::perform(
                    async move {
                        crate::audit::log_settings_saved(enable_event_log, desc).await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::AutoRevertTimeoutChanged(timeout) => {
                self.auto_revert_timeout_secs = timeout.clamp(5, 120);
                self.mark_config_dirty();
                // Schedule debounced logging - log after 2s of no changes
                let desc = format!("Auto-revert timeout set to {}s", timeout);
                self.schedule_slider_log(desc);
            }
            Message::ToggleEventLog(enabled) => {
                // Log settings change BEFORE changing the value
                // When disabling, we need to log with the OLD value (true) so it actually logs
                let old_value = self.enable_event_log;
                self.enable_event_log = enabled;
                self.mark_config_dirty();
                let desc = if enabled {
                    "Event logging enabled"
                } else {
                    "Event logging disabled"
                };
                return Task::perform(
                    async move {
                        // Use old_value when disabling (true), new value when enabling (true)
                        // This ensures "disabled" message gets logged before turning off
                        crate::audit::log_settings_saved(old_value || enabled, desc).await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::ToggleStrictIcmp(enabled) => {
                self.ruleset.advanced_security.strict_icmp = enabled;
                self.update_cached_text();
                self.mark_profile_dirty();
                let enable_event_log = self.enable_event_log;
                let desc = if enabled {
                    "Strict ICMP filtering enabled"
                } else {
                    "Strict ICMP filtering disabled"
                };
                return Task::perform(
                    async move {
                        crate::audit::log_settings_saved(enable_event_log, desc).await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::IcmpRateLimitChanged(rate) => {
                self.ruleset.advanced_security.icmp_rate_limit = rate;
                self.update_cached_text();
                self.mark_profile_dirty();
                // Schedule debounced logging - log after 2s of no changes
                let desc = format!("ICMP rate limit set to {}/s", rate);
                self.schedule_slider_log(desc);
            }
            Message::ToggleRpfRequested(enabled) => {
                if enabled {
                    self.pending_warning = Some(PendingWarning::EnableRpf);
                } else {
                    self.ruleset.advanced_security.enable_rpf = false;
                    self.update_cached_text();
                    self.mark_profile_dirty();
                    let enable_event_log = self.enable_event_log;
                    return Task::perform(
                        async move {
                            crate::audit::log_settings_saved(
                                enable_event_log,
                                "RPF (reverse path filtering) disabled",
                            )
                            .await;
                        },
                        |_| Message::AuditLogWritten,
                    );
                }
            }
            Message::ConfirmEnableRpf => {
                self.pending_warning = None;
                self.ruleset.advanced_security.enable_rpf = true;
                self.update_cached_text();
                self.mark_profile_dirty();
                let enable_event_log = self.enable_event_log;
                return Task::perform(
                    async move {
                        crate::audit::log_settings_saved(
                            enable_event_log,
                            "RPF (reverse path filtering) enabled",
                        )
                        .await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::CancelWarning => {
                self.pending_warning = None;
            }
            Message::ToggleDroppedLogging(enabled) => {
                self.ruleset.advanced_security.log_dropped = enabled;
                self.update_cached_text();
                self.mark_profile_dirty();
                let enable_event_log = self.enable_event_log;
                let desc = if enabled {
                    "Dropped packet logging enabled"
                } else {
                    "Dropped packet logging disabled"
                };
                return Task::perform(
                    async move {
                        crate::audit::log_settings_saved(enable_event_log, desc).await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::LogRateChanged(rate) => {
                // Validate log rate (slider ensures 1-100 range, but check for warnings)
                match crate::validators::validate_log_rate(rate) {
                    Ok(Some(warning)) => {
                        // Valid but with warning - still accept it
                        tracing::debug!("Log rate {rate}/min: {warning}");
                    }
                    Ok(None) => {
                        // Valid with no warnings
                    }
                    Err(e) => {
                        // Should not happen with slider, but handle it
                        tracing::warn!("Invalid log rate {rate}: {e}");
                        return Task::none();
                    }
                }
                self.ruleset.advanced_security.log_rate_per_minute = rate;
                self.update_cached_text();
                self.mark_profile_dirty();
                // Schedule debounced logging - log after 2s of no changes
                let desc = format!("Log rate limit set to {}/min", rate);
                self.schedule_slider_log(desc);
            }
            Message::CheckSliderLog => {
                return self.handle_check_slider_log();
            }
            Message::LogPrefixChanged(prefix) => {
                // Validate and sanitize log prefix
                match crate::validators::validate_log_prefix(&prefix) {
                    Ok(sanitized) => {
                        self.ruleset.advanced_security.log_prefix = sanitized.clone();
                        self.update_cached_text();
                        self.mark_profile_dirty();
                        let enable_event_log = self.enable_event_log;
                        let desc = format!("Log prefix changed to '{}'", sanitized);
                        return Task::perform(
                            async move {
                                crate::audit::log_settings_saved(enable_event_log, &desc).await;
                            },
                            |_| Message::AuditLogWritten,
                        );
                    }
                    Err(e) => {
                        // Invalid prefix - don't save, just log the error
                        tracing::warn!("Invalid log prefix '{prefix}': {e}");
                        return Task::none();
                    }
                }
            }
            Message::ServerModeToggled(enabled) => {
                if enabled {
                    self.pending_warning = Some(PendingWarning::EnableServerMode);
                } else {
                    self.ruleset.advanced_security.egress_profile =
                        crate::core::firewall::EgressProfile::Desktop;
                    self.update_cached_text();
                    self.mark_profile_dirty();
                    let enable_event_log = self.enable_event_log;
                    return Task::perform(
                        async move {
                            crate::audit::log_settings_saved(
                                enable_event_log,
                                "Server mode disabled (desktop profile)",
                            )
                            .await;
                        },
                        |_| Message::AuditLogWritten,
                    );
                }
            }
            Message::ConfirmServerMode => {
                self.pending_warning = None;
                self.ruleset.advanced_security.egress_profile =
                    crate::core::firewall::EgressProfile::Server;
                self.update_cached_text();
                self.mark_profile_dirty();
                let enable_event_log = self.enable_event_log;
                return Task::perform(
                    async move {
                        crate::audit::log_settings_saved(
                            enable_event_log,
                            "Server mode enabled (server profile)",
                        )
                        .await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::ToggleDiagnostics(show) => {
                self.show_diagnostics = show;

                // Load audit log asynchronously if opening modal and cache is dirty
                if show && self.audit_log_dirty {
                    return Task::perform(Self::load_audit_entries(), Message::AuditEntriesLoaded);
                }
            }
            Message::DiagnosticsFilterChanged(filter) => self.diagnostics_filter = filter,
            Message::AuditEntriesLoaded(entries) => {
                self.cached_audit_entries = entries;
                self.audit_log_dirty = false;
            }
            Message::CheckAuditLogRefresh => {
                // Auto-refresh: only load if dirty (subscription fires every 100ms while modal open)
                if self.audit_log_dirty {
                    return Task::perform(Self::load_audit_entries(), Message::AuditEntriesLoaded);
                }
            }
            Message::AuditLogWritten => {
                // Audit log write completed, mark cache dirty to trigger refresh
                self.audit_log_dirty = true;
            }
            Message::ClearEventLog => {
                if let Some(mut path) = crate::utils::get_state_dir() {
                    path.push("audit.log");
                    let _ = std::fs::remove_file(path);
                    self.audit_log_dirty = true; // Refresh after clearing
                }
            }
            Message::ToggleShortcutsHelp(show) => self.show_shortcuts_help = show,
            Message::Undo => {
                if let Some(description) = self.command_history.undo(&mut self.ruleset) {
                    self.mark_profile_dirty();
                    tracing::info!("Undid: {}", description);
                    let enable_event_log = self.enable_event_log;
                    let desc = description.clone();
                    return Task::perform(
                        async move {
                            crate::audit::log_undone(enable_event_log, &desc).await;
                        },
                        |_| Message::AuditLogWritten,
                    );
                }
            }
            Message::Redo => {
                if let Some(description) = self.command_history.redo(&mut self.ruleset) {
                    self.mark_profile_dirty();
                    tracing::info!("Redid: {}", description);
                    let enable_event_log = self.enable_event_log;
                    let desc = description.clone();
                    return Task::perform(
                        async move {
                            crate::audit::log_redone(enable_event_log, &desc).await;
                        },
                        |_| Message::AuditLogWritten,
                    );
                }
            }
            Message::ThemeChanged(choice) => {
                self.current_theme = choice;
                self.theme = choice.to_theme();
                self.mark_config_dirty();
                let enable_event_log = self.enable_event_log;
                let desc = format!("Theme changed to {}", choice.name());
                return Task::perform(
                    async move {
                        crate::audit::log_settings_saved(enable_event_log, &desc).await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::OpenThemePicker => {
                // Pre-compute all theme conversions once on modal open
                let cached_themes: Vec<_> = crate::theme::ThemeChoice::iter()
                    .map(|choice| (choice, choice.to_theme()))
                    .collect();

                self.theme_picker = Some(ThemePickerState {
                    search: String::new(),
                    search_lowercase: String::new(),
                    filter: ThemeFilter::All,
                    original_theme: self.current_theme,
                    cached_themes,
                });
            }
            Message::ThemePickerSearchChanged(search) => {
                if let Some(picker) = &mut self.theme_picker {
                    picker.search_lowercase = search.to_lowercase();
                    picker.search = search;
                }
            }
            Message::ThemePickerFilterChanged(filter) => {
                if let Some(picker) = &mut self.theme_picker {
                    picker.filter = filter;
                }
            }
            Message::ThemePreview(choice) => {
                self.current_theme = choice;
                self.theme = choice.to_theme();
            }
            Message::ApplyTheme => {
                self.theme_picker = None;
                self.mark_config_dirty();
                let enable_event_log = self.enable_event_log;
                let desc = format!("Theme changed to {}", self.current_theme.name());
                return Task::perform(
                    async move {
                        crate::audit::log_settings_saved(enable_event_log, &desc).await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::CancelThemePicker => {
                if let Some(picker) = &self.theme_picker {
                    self.current_theme = picker.original_theme;
                    self.theme = picker.original_theme.to_theme();
                }
                self.theme_picker = None;
            }
            Message::ThemePreviewButtonClick => {}
            Message::RegularFontChanged(choice) => {
                self.regular_font_choice = choice.clone();
                self.font_regular = choice.to_font();
                self.mark_config_dirty();
                let enable_event_log = self.enable_event_log;
                let desc = format!("UI font changed to {}", choice.name());
                return Task::perform(
                    async move {
                        crate::audit::log_settings_saved(enable_event_log, &desc).await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::MonoFontChanged(choice) => {
                self.mono_font_choice = choice.clone();
                self.font_mono = choice.to_font();
                self.font_picker = None;
                self.mark_config_dirty();
                let enable_event_log = self.enable_event_log;
                let desc = format!("Monospace font changed to {}", choice.name());
                return Task::perform(
                    async move {
                        crate::audit::log_settings_saved(enable_event_log, &desc).await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::OpenFontPicker(target) => {
                self.font_picker = Some(FontPickerState {
                    target,
                    search: String::new(),
                    search_lowercase: String::new(),
                });
                return focus(Id::from(view::FONT_SEARCH_INPUT_ID));
            }
            Message::FontPickerSearchChanged(search) => {
                if let Some(picker) = &mut self.font_picker {
                    picker.search_lowercase = search.to_lowercase();
                    picker.search = search;
                }
            }
            Message::CloseFontPicker => {
                self.font_picker = None;
            }
            Message::RuleFormTagInputChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.tag_input = s;
                }
            }
            Message::RuleFormAddTag => {
                if let Some(f) = &mut self.rule_form {
                    let tag = crate::validators::sanitize_label(f.tag_input.trim());
                    if !tag.is_empty()
                        && !f.tags.contains(&tag)
                        && tag.len() <= 20
                        && f.tags.len() < 10
                    {
                        f.tags.push(tag);
                        f.tag_input.clear();
                    }
                }
            }
            Message::RuleFormRemoveTag(tag) => {
                if let Some(f) = &mut self.rule_form {
                    f.tags.retain(|t| t != &tag);
                }
            }
            Message::FilterByTag(tag) => {
                self.filter_tag = tag;
                if self.filter_tag.is_none() {
                    self.rule_search.clear();
                    self.rule_search_lowercase.clear();
                }
                self.update_filter_cache();
            }
            Message::OpenLogsFolder => {
                if let Some(state_dir) = crate::utils::get_state_dir()
                    && state_dir.exists()
                    && state_dir.is_dir()
                    && let Ok(canonical) = state_dir.canonicalize()
                {
                    #[cfg(target_os = "linux")]
                    {
                        let _ = std::process::Command::new("xdg-open")
                            .arg(canonical.as_os_str())
                            .spawn();
                    }
                    #[cfg(target_os = "macos")]
                    {
                        let _ = std::process::Command::new("open")
                            .arg(canonical.as_os_str())
                            .spawn();
                    }
                    #[cfg(target_os = "windows")]
                    {
                        let _ = std::process::Command::new("explorer")
                            .arg(canonical.as_os_str())
                            .spawn();
                    }
                }
            }
            Message::RuleDragStart(id) => {
                self.dragged_rule_id = Some(id);
                self.hovered_drop_target_id = None;
            }
            Message::RuleDropped(target_id) => {
                if let Some(dragged_id) = self.dragged_rule_id
                    && dragged_id != target_id
                    && let Some(old_index) =
                        self.ruleset.rules.iter().position(|r| r.id == dragged_id)
                    && let Some(new_index) =
                        self.ruleset.rules.iter().position(|r| r.id == target_id)
                {
                    let label = self.ruleset.rules[old_index].label.clone();
                    let direction = if new_index < old_index { "up" } else { "down" };
                    let enable_event_log = self.enable_event_log;

                    let command = crate::command::ReorderRuleCommand {
                        rule_id: dragged_id,
                        old_index,
                        new_index,
                    };
                    self.command_history
                        .execute(Box::new(command), &mut self.ruleset);
                    self.mark_profile_dirty();
                    self.dragged_rule_id = None;
                    self.hovered_drop_target_id = None;

                    // Log reorder event
                    return Task::perform(
                        async move {
                            crate::audit::log_rules_reordered(enable_event_log, &label, direction)
                                .await;
                        },
                        |_| Message::AuditLogWritten,
                    );
                }
                self.dragged_rule_id = None;
                self.hovered_drop_target_id = None;
            }
            Message::RuleHoverStart(id) => {
                if self.dragged_rule_id.is_some() {
                    self.hovered_drop_target_id = Some(id);
                }
            }
            Message::RuleHoverEnd => {
                self.hovered_drop_target_id = None;
            }
            Message::ProfileSelected(name) => {
                return self.handle_switch_profile(name);
            }
            Message::ProfileSwitched(name, ruleset) => {
                let from_profile = self.active_profile_name.clone();
                self.ruleset = ruleset.clone();
                self.cached_disk_profile = Some(ruleset);
                self.active_profile_name = name.clone();
                self.command_history = crate::command::CommandHistory::default();
                self.update_cached_text();
                self.mark_config_dirty();

                // Log profile switch
                let enable_event_log = self.enable_event_log;
                let to_profile = name;
                return Task::perform(
                    async move {
                        crate::audit::log_profile_switched(
                            enable_event_log,
                            &from_profile,
                            &to_profile,
                        )
                        .await;
                    },
                    |_| Message::AuditLogWritten,
                );
            }
            Message::SaveProfileAs(name) => {
                let creating_empty = self
                    .profile_manager
                    .as_ref()
                    .map(|mgr| mgr.creating_empty)
                    .unwrap_or(false);

                let ruleset = if creating_empty {
                    FirewallRuleset::default()
                } else {
                    self.ruleset.clone()
                };

                let name_clone = name.clone();
                let name_for_log = name.clone();
                let enable_event_log = self.enable_event_log;

                // Update current ruleset if creating empty profile
                if creating_empty {
                    self.ruleset = ruleset.clone();
                    // Rebuild UI caches for new empty ruleset
                    self.update_cached_text();
                }

                // Update cached disk profile to reflect what we're about to save
                // This prevents false "dirty" detection when switching profiles
                self.cached_disk_profile = Some(ruleset.clone());

                self.active_profile_name = name;
                self.mark_config_dirty();
                if let Some(mgr) = &mut self.profile_manager {
                    mgr.creating_new = false;
                    mgr.creating_empty = false;
                    mgr.new_name_input.clear();
                }

                return Task::perform(
                    async move {
                        // Save profile then refresh list
                        crate::core::profiles::save_profile(&name_clone, &ruleset).await?;
                        crate::core::profiles::list_profiles().await
                    },
                    |result| match result {
                        Ok(profiles) => Message::ProfileListUpdated(profiles),
                        Err(e) => {
                            eprintln!("Failed to save/list profiles: {e}");
                            Message::Noop
                        }
                    },
                )
                .chain(Task::future(async move {
                    // Log profile creation
                    crate::audit::log_profile_created(enable_event_log, &name_for_log).await;
                    Message::AuditLogWritten
                }));
            }
            Message::ProfileListUpdated(profiles) => {
                self.available_profiles = profiles;
            }
            Message::StartCreatingNewProfile => {
                if let Some(mgr) = &mut self.profile_manager {
                    mgr.creating_new = true;
                    mgr.creating_empty = false;
                    mgr.new_name_input = String::new();
                }
            }
            Message::CreateEmptyProfile => {
                if let Some(mgr) = &mut self.profile_manager {
                    mgr.creating_new = true;
                    mgr.creating_empty = true;
                    mgr.new_name_input = String::new();
                }
            }
            Message::NewProfileNameChanged(name) => {
                if let Some(mgr) = &mut self.profile_manager {
                    mgr.new_name_input = name;
                }
            }
            Message::CancelCreatingNewProfile => {
                if let Some(mgr) = &mut self.profile_manager {
                    mgr.creating_new = false;
                    mgr.creating_empty = false;
                    mgr.new_name_input.clear();
                }
            }
            Message::OpenProfileManager => {
                self.profile_manager = Some(ProfileManagerState {
                    renaming_name: None,
                    deleting_name: None,
                    creating_new: false,
                    creating_empty: false,
                    new_name_input: String::new(),
                });
            }
            Message::CloseProfileManager => {
                self.profile_manager = None;
            }
            Message::DeleteProfileRequested(name) => {
                if let Some(mgr) = &mut self.profile_manager {
                    mgr.deleting_name = Some(name);
                }
            }
            Message::ConfirmDeleteProfile => {
                if let Some(mgr) = &mut self.profile_manager
                    && let Some(name) = mgr.deleting_name.take()
                {
                    // Business logic validation: ensure at least one profile remains
                    if self.available_profiles.len() <= 1 {
                        self.push_banner("Cannot delete last profile", BannerSeverity::Error, 6);
                        return Task::none();
                    }

                    // Business logic validation: cannot delete active profile
                    if name == self.active_profile_name {
                        self.push_banner(
                            "Cannot delete active profile - switch to another profile first",
                            BannerSeverity::Error,
                            8,
                        );
                        return Task::none();
                    }

                    let enable_event_log = self.enable_event_log;
                    let deleted_name = name.clone();
                    return Task::perform(
                        async move {
                            crate::core::profiles::delete_profile(&name).await?;
                            crate::core::profiles::list_profiles().await
                        },
                        move |result| match result {
                            Ok(profiles) => Message::ProfileDeleted(Ok(profiles)),
                            Err(e) => Message::ProfileDeleted(Err(format!(
                                "Failed to delete profile: {e}"
                            ))),
                        },
                    )
                    .chain(Task::future(async move {
                        // Log profile deletion
                        crate::audit::log_profile_deleted(enable_event_log, &deleted_name).await;
                        Message::AuditLogWritten
                    }));
                }
            }
            Message::ProfileDeleted(result) => match result {
                Ok(profiles) => {
                    let old_active = self.active_profile_name.clone();
                    self.available_profiles = profiles.clone();
                    // If we deleted the active profile, switch to first available
                    if !profiles.iter().any(|p| p == &old_active) {
                        let next = profiles.first().cloned().unwrap_or_else(|| {
                            crate::core::profiles::DEFAULT_PROFILE_NAME.to_string()
                        });
                        return self.perform_profile_switch(next);
                    }
                }
                Err(e) => {
                    let msg = if e.len() > 55 {
                        format!("Failed to delete profile: {}...", &e[..46])
                    } else {
                        format!("Failed to delete profile: {}", e)
                    };
                    self.push_banner(&msg, BannerSeverity::Error, 8);
                }
            },
            Message::CancelDeleteProfile => {
                if let Some(mgr) = &mut self.profile_manager {
                    mgr.deleting_name = None;
                }
            }
            Message::RenameProfileRequested(name) => {
                if let Some(mgr) = &mut self.profile_manager {
                    mgr.renaming_name = Some((name.clone(), name));
                }
            }
            Message::ProfileNewNameChanged(new_name) => {
                if let Some(mgr) = &mut self.profile_manager
                    && let Some((old, _)) = &mgr.renaming_name
                {
                    mgr.renaming_name = Some((old.clone(), new_name));
                }
            }
            Message::ConfirmRenameProfile => {
                if let Some(mgr) = &mut self.profile_manager
                    && let Some((old, new)) = mgr.renaming_name.take()
                {
                    let was_active = self.active_profile_name == old;
                    if was_active {
                        self.active_profile_name = new.clone();
                        self.mark_config_dirty();
                    }

                    let enable_event_log = self.enable_event_log;
                    let old_name = old.clone();
                    let new_name = new.clone();

                    return Task::perform(
                        async move {
                            crate::core::profiles::rename_profile(&old, &new).await?;
                            crate::core::profiles::list_profiles().await
                        },
                        move |result| match result {
                            Ok(profiles) => Message::ProfileRenamed(Ok(profiles)),
                            Err(e) => Message::ProfileRenamed(Err(format!("Rename failed: {e}"))),
                        },
                    )
                    .chain(Task::future(async move {
                        // Log profile rename
                        crate::audit::log_profile_renamed(enable_event_log, &old_name, &new_name)
                            .await;
                        Message::AuditLogWritten
                    }));
                }
            }
            Message::ProfileRenamed(result) => match result {
                Ok(profiles) => {
                    self.available_profiles = profiles;
                }
                Err(e) => {
                    let msg = if e.len() > 55 {
                        format!("Failed to rename profile: {}...", &e[..46])
                    } else {
                        format!("Failed to rename profile: {}", e)
                    };
                    self.push_banner(&msg, BannerSeverity::Error, 8);
                }
            },
            Message::CancelRenameProfile => {
                if let Some(mgr) = &mut self.profile_manager {
                    mgr.renaming_name = None;
                }
            }
            Message::ConfirmProfileSwitch => {
                if let Some(name) = self.pending_profile_switch.take() {
                    let profile_name = self.active_profile_name.clone();
                    let ruleset = self.ruleset.clone();

                    // Update cached disk profile before saving to avoid false dirty detection
                    self.cached_disk_profile = Some(ruleset.clone());

                    return Task::perform(
                        async move {
                            crate::core::profiles::save_profile(&profile_name, &ruleset).await
                        },
                        move |_result| Message::ProfileSwitchAfterSave(name.clone()),
                    );
                }
            }
            Message::DiscardProfileSwitch => {
                if let Some(name) = self.pending_profile_switch.take() {
                    return self.perform_profile_switch(name);
                }
            }
            Message::CancelProfileSwitch => {
                self.pending_profile_switch = None;
            }
            Message::ProfileSwitchAfterSave(name) => {
                // Directly perform switch without checking dirty flag
                // (we just saved, so cached_disk_profile is already updated)
                return self.perform_profile_switch(name);
            }
            Message::PruneBanners => {
                self.prune_expired_banners();
            }
            Message::DismissBanner(index) => {
                if index < self.banners.len() {
                    self.banners.remove(index);
                }
            }
            Message::CheckConfigSave => return self.handle_check_config_save(),
            Message::CheckProfileSave => return self.handle_check_profile_save(),
            Message::DiskProfileLoaded(profile) => self.handle_disk_profile_loaded(profile),
            Message::Noop => {
                // No-op for async operations that don't need handling
            }
        }
        Task::none()
    }

    fn handle_edit_clicked(&mut self, id: uuid::Uuid) {
        if let Some(rule) = self.ruleset.rules.iter().find(|r| r.id == id) {
            let has_advanced = rule.destination.is_some()
                || rule.action != crate::core::firewall::Action::Accept
                || rule.rate_limit.is_some()
                || rule.connection_limit > 0;

            self.rule_form = Some(RuleForm {
                id: Some(rule.id),
                label: rule.label.clone(),
                protocol: rule.protocol,
                port_start: rule
                    .ports
                    .as_ref()
                    .map_or_else(String::new, |p| p.start.to_string()),
                port_end: rule
                    .ports
                    .as_ref()
                    .map_or_else(String::new, |p| p.end.to_string()),
                source: rule
                    .source
                    .as_ref()
                    .map_or_else(String::new, std::string::ToString::to_string),
                interface: rule.interface.clone().unwrap_or_default(),
                chain: rule.chain,
                tags: rule.tags.clone(),
                tag_input: String::new(),
                show_advanced: has_advanced,
                destination: rule
                    .destination
                    .as_ref()
                    .map_or_else(String::new, std::string::ToString::to_string),
                action: rule.action,
                rate_limit_enabled: rule.rate_limit.is_some(),
                rate_limit_count: rule
                    .rate_limit
                    .as_ref()
                    .map_or_else(String::new, |rl| rl.count.to_string()),
                rate_limit_unit: rule
                    .rate_limit
                    .as_ref()
                    .map_or(crate::core::firewall::TimeUnit::Second, |rl| rl.unit),
                connection_limit: if rule.connection_limit > 0 {
                    rule.connection_limit.to_string()
                } else {
                    String::new()
                },
            });
            self.form_errors = None;
        }
    }

    fn handle_save_rule_form(&mut self) -> Task<Message> {
        if let Some(form_ref) = &self.rule_form {
            let (ports, source, errors) = form_ref.validate();
            if let Some(errs) = errors {
                self.form_errors = Some(errs);
                return Task::none();
            }

            let Some(form) = self.rule_form.take() else {
                tracing::error!("SaveRuleForm clicked but no form present - UI state desync");
                return Task::none();
            };
            let sanitized_label = crate::validators::sanitize_label(&form.label);
            let interface = if form.interface.is_empty() {
                None
            } else {
                Some(form.interface)
            };

            let destination = if form.destination.is_empty() {
                None
            } else {
                form.destination.parse().ok()
            };

            let rate_limit = if form.rate_limit_enabled && !form.rate_limit_count.is_empty() {
                form.rate_limit_count
                    .parse()
                    .ok()
                    .map(|count| crate::core::firewall::RateLimit {
                        count,
                        unit: form.rate_limit_unit,
                    })
            } else {
                None
            };

            let connection_limit = if form.connection_limit.is_empty() {
                0
            } else {
                form.connection_limit.parse().unwrap_or(0)
            };

            let mut rule = Rule {
                id: form.id.unwrap_or_else(uuid::Uuid::new_v4),
                label: sanitized_label,
                protocol: form.protocol,
                ports,
                source,
                interface,
                chain: form.chain,
                enabled: true,
                created_at: Utc::now(),
                tags: form.tags,
                destination,
                action: form.action,
                rate_limit,
                connection_limit,
                label_lowercase: String::new(),
                interface_lowercase: None,
                tags_lowercase: Vec::new(),
                protocol_lowercase: "",
                port_display: String::new(),
                source_string: None,
                destination_string: None,
                rate_limit_display: None,
            };
            rule.rebuild_caches();

            let is_edit = self.ruleset.rules.iter().any(|r| r.id == rule.id);
            let enable_event_log = self.enable_event_log;
            let label = rule.label.clone();
            let protocol = rule.protocol.to_string();
            let ports = rule.port_display.clone();

            if is_edit {
                // Safe pattern from CLAUDE.md Section 13
                let Some(old_rule) = self.ruleset.rules.iter().find(|r| r.id == rule.id).cloned()
                else {
                    tracing::error!(
                        "SaveRuleForm for non-existent rule ID: {}. This indicates a UI state desync bug.",
                        rule.id
                    );
                    self.rule_form = None;
                    self.form_errors = None;
                    return Task::none();
                };
                let command = crate::command::EditRuleCommand {
                    old_rule,
                    new_rule: rule,
                };
                self.command_history
                    .execute(Box::new(command), &mut self.ruleset);
            } else {
                let command = crate::command::AddRuleCommand { rule };
                self.command_history
                    .execute(Box::new(command), &mut self.ruleset);
            }

            self.mark_profile_dirty();
            self.form_errors = None;

            // Log rule change
            return Task::perform(
                async move {
                    let port_str = if ports.is_empty() { None } else { Some(ports) };
                    if is_edit {
                        crate::audit::log_rule_modified(
                            enable_event_log,
                            &label,
                            &protocol,
                            port_str,
                        )
                        .await;
                    } else {
                        crate::audit::log_rule_created(
                            enable_event_log,
                            &label,
                            &protocol,
                            port_str,
                        )
                        .await;
                    }
                },
                |_| Message::AuditLogWritten,
            );
        }
        Task::none()
    }

    fn handle_toggle_rule(&mut self, id: uuid::Uuid) -> Task<Message> {
        if let Some(rule) = self.ruleset.rules.iter().find(|r| r.id == id) {
            let was_enabled = rule.enabled;
            let label = rule.label.clone();
            let enable_event_log = self.enable_event_log;

            let command = crate::command::ToggleRuleCommand {
                rule_id: id,
                was_enabled,
            };
            self.command_history
                .execute(Box::new(command), &mut self.ruleset);
            self.mark_profile_dirty();

            // Log toggle event
            return Task::perform(
                async move {
                    crate::audit::log_rule_toggled(enable_event_log, &label, !was_enabled).await;
                },
                |_| Message::AuditLogWritten,
            );
        }
        Task::none()
    }

    fn handle_delete_rule(&mut self, id: uuid::Uuid) -> Task<Message> {
        if let Some(pos) = self.ruleset.rules.iter().position(|r| r.id == id) {
            let rule = self.ruleset.rules[pos].clone();
            let label = rule.label.clone();
            let enable_event_log = self.enable_event_log;

            let command = crate::command::DeleteRuleCommand { rule, index: pos };
            self.command_history
                .execute(Box::new(command), &mut self.ruleset);
            self.mark_profile_dirty();

            self.deleting_id = None;

            // Log delete event
            return Task::perform(
                async move {
                    crate::audit::log_rule_deleted(enable_event_log, &label).await;
                },
                |_| Message::AuditLogWritten,
            );
        }
        self.deleting_id = None;
        Task::none()
    }

    fn handle_apply_clicked(&mut self) -> Task<Message> {
        if matches!(
            self.status,
            AppStatus::Verifying | AppStatus::Applying | AppStatus::PendingConfirmation { .. }
        ) {
            return Task::none();
        }

        // Check if polkit authentication agent is running
        if !crate::elevation::is_polkit_agent_running() {
            self.push_banner(
                "No polkit agent running. Install and start an authentication agent.",
                BannerSeverity::Error,
                10,
            );
            return Task::none();
        }

        self.status = AppStatus::Verifying;
        let nft_json = self.ruleset.to_nftables_json();

        Task::perform(
            async move {
                crate::core::verify::verify_ruleset(nft_json)
                    .await
                    .map_err(|e| e.to_string())
            },
            Message::VerifyCompleted,
        )
    }

    fn handle_verify_completed(
        &mut self,
        result: Result<crate::core::verify::VerifyResult, String>,
    ) -> Task<Message> {
        match result {
            Ok(verify_result) if verify_result.success => {
                self.status = AppStatus::AwaitingApply;
                let enable_event_log = self.enable_event_log;
                let error_count = verify_result.errors.len();
                Task::perform(
                    async move {
                        crate::audit::log_verify(enable_event_log, true, error_count, None).await;
                    },
                    |_| Message::AuditLogWritten,
                )
            }
            Ok(verify_result) => {
                self.status = AppStatus::Idle;
                let error_summary = if verify_result.errors.is_empty() {
                    "Ruleset verification failed".to_string()
                } else {
                    format!(
                        "Ruleset verification failed: {} errors",
                        verify_result.errors.len()
                    )
                };
                self.push_banner(&error_summary, BannerSeverity::Error, 8);
                let enable_event_log = self.enable_event_log;
                let error_count = verify_result.errors.len();
                let error = Some(verify_result.errors.join("; "));
                Task::perform(
                    async move {
                        crate::audit::log_verify(enable_event_log, false, error_count, error).await;
                    },
                    |_| Message::AuditLogWritten,
                )
            }
            Err(e) => {
                self.status = AppStatus::Idle;
                let msg = if e.len() > 60 {
                    format!("Verification error: {}...", &e[..57])
                } else {
                    format!("Verification error: {}", e)
                };
                self.push_banner(&msg, BannerSeverity::Error, 8);
                let enable_event_log = self.enable_event_log;
                let error = e.clone();
                Task::perform(
                    async move {
                        crate::audit::log_verify(enable_event_log, false, 0, Some(error)).await;
                    },
                    |_| Message::AuditLogWritten,
                )
            }
        }
    }

    fn handle_proceed_to_apply(&mut self) -> Task<Message> {
        self.status = AppStatus::Applying;
        let nft_json = self.ruleset.to_nftables_json();
        let rule_count = self.ruleset.rules.len();
        let enabled_count = self.ruleset.rules.iter().filter(|r| r.enabled).count();
        let enable_event_log = self.enable_event_log;

        Task::perform(
            async move {
                let result = crate::core::nft_json::apply_with_snapshot(nft_json).await;
                let success = result.is_ok();
                let error = result.as_ref().err().map(std::string::ToString::to_string);
                crate::audit::log_apply(
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

    fn handle_apply_result(&mut self, snapshot: serde_json::Value) {
        self.last_applied_ruleset = Some(self.ruleset.clone());

        if let Err(e) = crate::core::nft_json::save_snapshot_to_disk(&snapshot) {
            eprintln!("Failed to save snapshot to disk: {e}");
            let msg = if e.to_string().len() > 45 {
                "Warning: Failed to save snapshot. Rollback may be unavailable.".to_string()
            } else {
                format!("Warning: Failed to save snapshot: {}", e)
            };
            self.push_banner(&msg, BannerSeverity::Warning, 10);
        }

        if self.auto_revert_enabled {
            // Auto-revert enabled: show countdown modal
            self.countdown_remaining = self.auto_revert_timeout_secs.min(120) as u32;
            // Animation transitions smoothly from 100% to 0% over the entire timeout duration
            let timeout = self.auto_revert_timeout_secs.min(120);
            self.progress_animation = Animation::new(1.0)
                .easing(animation::Easing::Linear) // Constant speed (no slow-down at start/end)
                .duration(Duration::from_secs(timeout))
                .go(0.0, iced::time::Instant::now());
            self.status = AppStatus::PendingConfirmation {
                deadline: Utc::now() + Duration::from_secs(timeout),
                snapshot,
            };
            self.push_banner(
                format!(
                    "Firewall rules applied! Changes will auto-revert in {}s if not confirmed.",
                    self.auto_revert_timeout_secs.min(120)
                ),
                BannerSeverity::Info,
                self.auto_revert_timeout_secs.min(120),
            );
        } else {
            // Auto-revert disabled: show success banner and return to idle
            self.status = AppStatus::Idle;
            self.push_banner(
                "Firewall rules applied successfully!",
                BannerSeverity::Success,
                5,
            );
        }
        // Note: audit_log_dirty set by handle_proceed_to_apply's Task chain to AuditLogWritten
    }

    fn handle_revert_clicked(&mut self) -> Task<Message> {
        if let AppStatus::PendingConfirmation { snapshot, .. } = &self.status {
            let snapshot = snapshot.clone();
            let enable_event_log = self.enable_event_log;
            self.status = AppStatus::Reverting;
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
                    crate::audit::log_revert(enable_event_log, success, error.clone()).await;
                    final_result.map_err(|e| e.to_string())
                },
                Message::RevertResult,
            )
            .chain(Task::done(Message::AuditLogWritten));
        }
        Task::none()
    }

    fn handle_countdown_tick(&mut self) -> Task<Message> {
        if let AppStatus::PendingConfirmation { deadline, snapshot } = &self.status {
            let now = Utc::now();
            if now >= *deadline {
                // Extract snapshot BEFORE changing status (fixes race condition)
                let snapshot = snapshot.clone();
                let enable_event_log = self.enable_event_log;
                let timeout_secs = self.auto_revert_timeout_secs;
                self.status = AppStatus::Reverting;
                self.countdown_remaining = 0;
                self.push_banner(
                    "Firewall rules automatically reverted due to timeout.",
                    BannerSeverity::Warning,
                    10,
                );

                // Spawn revert task with audit logging
                return Task::perform(
                    async move {
                        // Log timeout event
                        crate::audit::log_auto_revert_timed_out(enable_event_log, timeout_secs)
                            .await;

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
                        crate::audit::log_revert(enable_event_log, success, error.clone()).await;
                        final_result.map_err(|e| e.to_string())
                    },
                    Message::RevertResult,
                )
                .chain(Task::done(Message::AuditLogWritten));
            }

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let remaining = (*deadline - now).num_seconds().max(0) as u32;
            if self.countdown_remaining != remaining {
                self.countdown_remaining = remaining;
                // Animation runs continuously - no need to update it here
                if remaining == 5 {
                    self.push_banner(
                        "Firewall will revert in 5 seconds! Click Confirm to keep changes.",
                        BannerSeverity::Warning,
                        5,
                    );
                }
            }
        }
        Task::none()
    }

    fn handle_save_to_system(&mut self) -> Task<Message> {
        let text = self.ruleset.to_nft_text();
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
                        "/etc/nftables.conf",
                    ])
                    .status()
                    .await
                    .map_err(|e| format!("Failed to execute pkexec: {e}"))?;
                if status.success() {
                    Ok(())
                } else {
                    Err("Failed to copy configuration to /etc/nftables.conf".to_string())
                }
            },
            Message::SaveToSystemResult,
        )
    }

    fn handle_export_json(&self) -> Task<Message> {
        let json =
            serde_json::to_string_pretty(&self.ruleset.to_nftables_json()).unwrap_or_default();
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("drfw_rules_{timestamp}.json");
        Task::perform(
            async move {
                // Use native file dialog for better UX
                let Some(path) = crate::utils::pick_save_path(&filename, "json") else {
                    return None; // User canceled - do nothing
                };

                Some(
                    std::fs::write(&path, json)
                        .map(|()| path.to_string_lossy().to_string())
                        .map_err(|e| format!("Failed to export JSON: {e}")),
                )
            },
            |result| match result {
                Some(Ok(path)) => Message::ExportResult(Ok(path)),
                Some(Err(e)) => Message::ExportResult(Err(e)),
                None => Message::ToggleExportModal(false), // Just close modal on cancel
            },
        )
    }

    fn handle_export_nft(&self) -> Task<Message> {
        let nft_text = self.ruleset.to_nft_text();
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("drfw_rules_{timestamp}.nft");
        Task::perform(
            async move {
                // Use native file dialog for better UX
                let Some(path) = crate::utils::pick_save_path(&filename, "nft") else {
                    return None; // User canceled - do nothing
                };

                Some(
                    std::fs::write(&path, nft_text)
                        .map(|()| path.to_string_lossy().to_string())
                        .map_err(|e| format!("Failed to export nftables text: {e}")),
                )
            },
            |result| match result {
                Some(Ok(path)) => Message::ExportResult(Ok(path)),
                Some(Err(e)) => Message::ExportResult(Err(e)),
                None => Message::ToggleExportModal(false), // Just close modal on cancel
            },
        )
    }

    fn handle_event(&mut self, event: iced::Event) -> Task<Message> {
        if let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed { key, modifiers, .. }) =
            event
        {
            match key.as_ref() {
                iced::keyboard::Key::Named(iced::keyboard::key::Named::Enter)
                    if self.rule_form.is_some() =>
                {
                    return Task::done(Message::SaveRuleForm);
                }
                iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape) => {
                    if self.rule_form.is_some() {
                        return Task::done(Message::CancelRuleForm);
                    }
                    if self.deleting_id.is_some() {
                        return Task::done(Message::CancelDelete);
                    }
                    if self.show_shortcuts_help {
                        return Task::done(Message::ToggleShortcutsHelp(false));
                    }
                    if self.show_diagnostics {
                        return Task::done(Message::ToggleDiagnostics(false));
                    }
                    if self.show_export_modal {
                        return Task::done(Message::ToggleExportModal(false));
                    }
                    if self.font_picker.is_some() {
                        return Task::done(Message::CloseFontPicker);
                    }
                    if self.theme_picker.is_some() {
                        return Task::done(Message::CancelThemePicker);
                    }
                    if self.profile_manager.is_some() {
                        return Task::done(Message::CloseProfileManager);
                    }
                    if !self.rule_search.is_empty() {
                        self.rule_search.clear();
                    }
                }
                iced::keyboard::Key::Named(iced::keyboard::key::Named::F1) => {
                    return Task::done(Message::ToggleShortcutsHelp(true));
                }
                iced::keyboard::Key::Character("n")
                    if modifiers.command() || modifiers.control() =>
                {
                    if !matches!(self.status, AppStatus::PendingConfirmation { .. }) {
                        return Task::done(Message::AddRuleClicked);
                    }
                }
                iced::keyboard::Key::Character("s")
                    if modifiers.command() || modifiers.control() =>
                {
                    return Task::done(Message::ApplyClicked);
                }
                iced::keyboard::Key::Character("e")
                    if modifiers.command() || modifiers.control() =>
                {
                    return Task::done(Message::ToggleExportModal(true));
                }
                iced::keyboard::Key::Character("z")
                    if (modifiers.command() || modifiers.control()) && !modifiers.shift() =>
                {
                    if self.command_history.can_undo() {
                        return Task::done(Message::Undo);
                    }
                }
                iced::keyboard::Key::Character("z")
                    if (modifiers.command() || modifiers.control()) && modifiers.shift() =>
                {
                    if self.command_history.can_redo() {
                        return Task::done(Message::Redo);
                    }
                }
                iced::keyboard::Key::Character("y")
                    if modifiers.command() || modifiers.control() =>
                {
                    if self.command_history.can_redo() {
                        return Task::done(Message::Redo);
                    }
                }
                _ => {}
            }
        }
        Task::none()
    }

    pub fn subscription(&self) -> iced::Subscription<Message> {
        iced::Subscription::batch(vec![
            iced::event::listen_with(|event, _status, _id| match event {
                iced::Event::Keyboard(_) => Some(event),
                _ => None,
            })
            .map(Message::EventOccurred),
            match self.status {
                AppStatus::PendingConfirmation { .. } => {
                    // Update at 60 FPS for smooth animation
                    iced::time::every(Duration::from_millis(17)).map(|_| Message::CountdownTick)
                }
                _ => iced::Subscription::none(),
            },
            // Prune expired banners every second
            if !self.banners.is_empty() {
                iced::time::every(Duration::from_secs(1)).map(|_| Message::PruneBanners)
            } else {
                iced::Subscription::none()
            },
            // Config auto-save subscription
            if self.config_dirty {
                iced::time::every(Duration::from_millis(100)).map(|_| Message::CheckConfigSave)
            } else {
                iced::Subscription::none()
            },
            // Profile auto-save subscription
            if self.profile_dirty {
                iced::time::every(Duration::from_millis(100)).map(|_| Message::CheckProfileSave)
            } else {
                iced::Subscription::none()
            },
            // Slider logging debounce subscription
            if self.pending_slider_log.is_some() {
                iced::time::every(Duration::from_millis(100)).map(|_| Message::CheckSliderLog)
            } else {
                iced::Subscription::none()
            },
            // Audit log auto-refresh when diagnostics modal is open
            if self.show_diagnostics {
                iced::time::every(Duration::from_millis(100)).map(|_| Message::CheckAuditLogRefresh)
            } else {
                iced::Subscription::none()
            },
        ])
    }
}
