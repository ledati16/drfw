mod forms;
mod handlers;
mod helpers;
pub mod syntax_cache;
pub mod ui_components;
mod view;

// Re-export form types
pub use forms::{FormErrors, RuleForm};

use helpers::{
    calculate_max_content_width, calculate_max_content_width_from_refs, fuzzy_filter_fonts,
    fuzzy_filter_themes,
};

use crate::core::firewall::{FirewallRuleset, Protocol};
use chrono::Utc;
use iced::widget::Id;
use iced::widget::operation::focus;
use iced::{Animation, Element, Task};
use std::sync::Arc;
use std::time::Duration;

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

        self.cached_nft_width_px = calculate_max_content_width(&self.cached_nft_tokens);
        self.cached_diff_width_px = if let Some(ref diff_tokens) = self.cached_diff_tokens {
            let diff_lines: Vec<&syntax_cache::HighlightedLine> =
                diff_tokens.iter().map(|(_, line)| line).collect();
            calculate_max_content_width_from_refs(&diff_lines)
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

        Task::perform(
            async move {
                if let Err(e) = crate::config::save_config(&config).await {
                    eprintln!("Failed to save configuration: {e}");
                }
            },
            |()| Message::Noop,
        )
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

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            // Rules domain
            Message::AddRuleClicked => handlers::handle_add_rule_clicked(self),
            Message::EditRuleClicked(id) => handlers::handle_edit_rule_clicked(self, id),
            Message::CancelRuleForm => handlers::handle_cancel_rule_form(self),
            Message::SaveRuleForm => return handlers::handle_save_rule_form(self),
            Message::RuleFormLabelChanged(s) => handlers::handle_rule_form_label_changed(self, s),
            Message::RuleFormProtocolChanged(p) => {
                handlers::handle_rule_form_protocol_changed(self, p)
            }
            Message::RuleFormPortStartChanged(s) => {
                handlers::handle_rule_form_port_start_changed(self, s)
            }
            Message::RuleFormPortEndChanged(s) => {
                handlers::handle_rule_form_port_end_changed(self, s)
            }
            Message::RuleFormSourceChanged(s) => handlers::handle_rule_form_source_changed(self, s),
            Message::RuleFormInterfaceChanged(s) => {
                handlers::handle_rule_form_interface_changed(self, s)
            }
            Message::RuleFormChainChanged(chain) => {
                handlers::handle_rule_form_chain_changed(self, chain)
            }
            Message::RuleFormToggleAdvanced(show) => {
                handlers::handle_rule_form_toggle_advanced(self, show)
            }
            Message::RuleFormDestinationChanged(s) => {
                handlers::handle_rule_form_destination_changed(self, s)
            }
            Message::RuleFormActionChanged(action) => {
                handlers::handle_rule_form_action_changed(self, action)
            }
            Message::RuleFormToggleRateLimit(enabled) => {
                handlers::handle_rule_form_toggle_rate_limit(self, enabled)
            }
            Message::RuleFormRateLimitCountChanged(s) => {
                handlers::handle_rule_form_rate_limit_count_changed(self, s)
            }
            Message::RuleFormRateLimitUnitChanged(unit) => {
                handlers::handle_rule_form_rate_limit_unit_changed(self, unit)
            }
            Message::RuleFormConnectionLimitChanged(s) => {
                handlers::handle_rule_form_connection_limit_changed(self, s)
            }
            Message::RuleSearchChanged(s) => handlers::handle_rule_search_changed(self, s),
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
            Message::ApplyResult(Err(e)) | Message::RevertResult(Err(e)) => {
                return handlers::handle_apply_or_revert_error(self, e);
            }
            Message::ApplyResult(Ok(snapshot)) => handlers::handle_apply_result(self, snapshot),
            Message::ConfirmClicked => return handlers::handle_confirm_clicked(self),
            Message::RevertClicked => return handlers::handle_revert_clicked(self),
            Message::RevertResult(result) => handlers::handle_revert_result(self, result),
            Message::CountdownTick => return handlers::handle_countdown_tick(self),
            Message::SaveToSystemClicked => return handlers::handle_save_to_system(self),
            Message::SaveToSystemResult(result) => {
                handlers::handle_save_to_system_result(self, result)
            }

            // Export domain
            Message::ToggleExportModal(show) => handlers::handle_toggle_export_modal(self, show),
            Message::ExportAsJson => return handlers::handle_export_as_json(self),
            Message::ExportAsNft => return handlers::handle_export_as_nft(self),
            Message::ExportResult(result) => handlers::handle_export_result(self, result),

            // UI state domain
            Message::TabChanged(tab) => handlers::handle_tab_changed(self, tab),
            Message::EventOccurred(event) => return handlers::handle_event(self, event),

            // Settings domain
            Message::ToggleDiff(enabled) => return handlers::handle_toggle_diff(self, enabled),
            Message::ToggleZebraStriping(enabled) => {
                return handlers::handle_toggle_zebra_striping(self, enabled);
            }
            Message::ToggleAutoRevert(enabled) => {
                return handlers::handle_toggle_auto_revert(self, enabled);
            }
            Message::AutoRevertTimeoutChanged(timeout) => {
                handlers::handle_auto_revert_timeout_changed(self, timeout)
            }
            Message::ToggleEventLog(enabled) => {
                return handlers::handle_toggle_event_log(self, enabled);
            }
            Message::ToggleStrictIcmp(enabled) => {
                return handlers::handle_toggle_strict_icmp(self, enabled);
            }
            Message::IcmpRateLimitChanged(rate) => {
                handlers::handle_icmp_rate_limit_changed(self, rate)
            }
            Message::ToggleRpfRequested(enabled) => {
                return handlers::handle_toggle_rpf_requested(self, enabled);
            }
            Message::ConfirmEnableRpf => return handlers::handle_confirm_enable_rpf(self),
            Message::CancelWarning => handlers::handle_cancel_warning(self),
            Message::ToggleDroppedLogging(enabled) => {
                return handlers::handle_toggle_dropped_logging(self, enabled);
            }
            Message::LogRateChanged(rate) => handlers::handle_log_rate_changed(self, rate),
            Message::CheckSliderLog => return handlers::handle_check_slider_log(self),
            Message::LogPrefixChanged(prefix) => {
                return handlers::handle_log_prefix_changed(self, prefix);
            }
            Message::ServerModeToggled(enabled) => {
                return handlers::handle_server_mode_toggled(self, enabled);
            }
            Message::ConfirmServerMode => return handlers::handle_confirm_server_mode(self),
            Message::ToggleDiagnostics(show) => {
                return handlers::handle_toggle_diagnostics(self, show);
            }
            Message::DiagnosticsFilterChanged(filter) => {
                handlers::handle_diagnostics_filter_changed(self, filter)
            }
            Message::AuditEntriesLoaded(entries) => {
                handlers::handle_audit_entries_loaded(self, entries)
            }
            Message::CheckAuditLogRefresh => return handlers::handle_check_audit_log_refresh(self),
            Message::AuditLogWritten => handlers::handle_audit_log_written(self),
            Message::ClearEventLog => handlers::handle_clear_event_log(self),
            Message::ToggleShortcutsHelp(show) => {
                handlers::handle_toggle_shortcuts_help(self, show)
            }
            Message::Undo => return handlers::handle_undo(self),
            Message::Redo => return handlers::handle_redo(self),
            Message::OpenThemePicker => handlers::handle_open_theme_picker(self),
            Message::ThemePickerSearchChanged(search) => {
                handlers::handle_theme_picker_search_changed(self, search)
            }
            Message::ThemePickerFilterChanged(filter) => {
                handlers::handle_theme_picker_filter_changed(self, filter)
            }
            Message::ThemePreview(choice) => handlers::handle_theme_preview(self, choice),
            Message::ApplyTheme => return handlers::handle_apply_theme(self),
            Message::CancelThemePicker => handlers::handle_cancel_theme_picker(self),
            Message::ThemePreviewButtonClick => handlers::handle_theme_preview_button_click(self),
            Message::RegularFontChanged(choice) => {
                return handlers::handle_regular_font_changed(self, choice);
            }
            Message::MonoFontChanged(choice) => {
                return handlers::handle_mono_font_changed(self, choice);
            }
            Message::OpenFontPicker(target) => {
                handlers::handle_open_font_picker(self, target);
                return focus(Id::from(view::FONT_SEARCH_INPUT_ID));
            }
            Message::FontPickerSearchChanged(search) => {
                handlers::handle_font_picker_search_changed(self, search)
            }
            Message::CloseFontPicker => handlers::handle_close_font_picker(self),
            Message::RuleFormTagInputChanged(s) => {
                handlers::handle_rule_form_tag_input_changed(self, s)
            }
            Message::RuleFormAddTag => handlers::handle_rule_form_add_tag(self),
            Message::RuleFormRemoveTag(tag) => handlers::handle_rule_form_remove_tag(self, tag),
            Message::FilterByTag(tag) => handlers::handle_filter_by_tag(self, tag),
            Message::OpenLogsFolder => handlers::handle_open_logs_folder(),
            Message::RuleDragStart(id) => handlers::handle_rule_drag_start(self, id),
            Message::RuleDropped(target_id) => {
                return handlers::handle_rule_dropped(self, target_id);
            }
            Message::RuleHoverStart(id) => handlers::handle_rule_hover_start(self, id),
            Message::RuleHoverEnd => handlers::handle_rule_hover_end(self),
            Message::ProfileSelected(name) => return handlers::handle_profile_selected(self, name),
            Message::ProfileSwitched(name, ruleset) => {
                return handlers::handle_profile_switched(self, name, ruleset);
            }
            Message::SaveProfileAs(name) => return handlers::handle_save_profile_as(self, name),
            Message::ProfileListUpdated(profiles) => {
                handlers::handle_profile_list_updated(self, profiles)
            }
            Message::StartCreatingNewProfile => handlers::handle_start_creating_new_profile(self),
            Message::CreateEmptyProfile => handlers::handle_create_empty_profile(self),
            Message::NewProfileNameChanged(name) => {
                handlers::handle_new_profile_name_changed(self, name)
            }
            Message::CancelCreatingNewProfile => handlers::handle_cancel_creating_new_profile(self),
            Message::OpenProfileManager => handlers::handle_open_profile_manager(self),
            Message::CloseProfileManager => handlers::handle_close_profile_manager(self),
            Message::DeleteProfileRequested(name) => {
                handlers::handle_delete_profile_requested(self, name)
            }
            Message::ConfirmDeleteProfile => return handlers::handle_confirm_delete_profile(self),
            Message::ProfileDeleted(result) => {
                return handlers::handle_profile_deleted(self, result);
            }
            Message::CancelDeleteProfile => handlers::handle_cancel_delete_profile(self),
            Message::RenameProfileRequested(name) => {
                handlers::handle_rename_profile_requested(self, name)
            }
            Message::ProfileNewNameChanged(new_name) => {
                handlers::handle_profile_new_name_changed(self, new_name)
            }
            Message::ConfirmRenameProfile => return handlers::handle_confirm_rename_profile(self),
            Message::ProfileRenamed(result) => handlers::handle_profile_renamed(self, result),
            Message::CancelRenameProfile => handlers::handle_cancel_rename_profile(self),
            Message::ConfirmProfileSwitch => return handlers::handle_confirm_profile_switch(self),
            Message::DiscardProfileSwitch => return handlers::handle_discard_profile_switch(self),
            Message::CancelProfileSwitch => handlers::handle_cancel_profile_switch(self),
            Message::ProfileSwitchAfterSave(name) => {
                return handlers::handle_profile_switch_after_save(self, name);
            }
            Message::PruneBanners => handlers::handle_prune_banners(self),
            Message::DismissBanner(index) => handlers::handle_dismiss_banner(self, index),
            Message::CheckConfigSave => return handlers::handle_check_config_save(self),
            Message::CheckProfileSave => return handlers::handle_check_profile_save(self),
            Message::DiskProfileLoaded(profile) => {
                handlers::handle_disk_profile_loaded(self, profile)
            }
            Message::Noop => {
                // No-op for async operations that don't need handling
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
