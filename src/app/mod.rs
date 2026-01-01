pub mod syntax_cache;
pub mod ui_components;
pub mod view;

use crate::core::error::ErrorInfo;
use crate::core::firewall::{FirewallRuleset, Protocol, Rule};
use chrono::Utc;
use iced::widget::Id;
use iced::widget::operation::focus;
use iced::{Element, Task};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use std::sync::Arc;
use std::time::Duration;

/// Fuzzy filter fonts with relevance scoring
///
/// Returns fonts sorted by match quality (best matches first).
/// Empty query returns all fonts unsorted.
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

    let mut results: Vec<_> = fonts
        .filter_map(|font| {
            let mut haystack_buf = Vec::new();
            let haystack = Utf32Str::new(font.name_lowercase(), &mut haystack_buf);
            matcher
                .fuzzy_match(haystack, needle)
                .map(|score| (font, score))
        })
        .collect();

    // Sort by score descending (highest relevance first)
    results.sort_by(|a, b| b.1.cmp(&a.1));
    results
}

/// Fuzzy filter themes with relevance scoring
///
/// Returns themes sorted by match quality (best matches first).
/// Empty query returns all themes unsorted.
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

    let mut results: Vec<_> = themes
        .filter_map(|theme| {
            let theme_name_lowercase = theme.name().to_lowercase();
            let mut haystack_buf = Vec::new();
            let haystack = Utf32Str::new(&theme_name_lowercase, &mut haystack_buf);
            matcher
                .fuzzy_match(haystack, needle)
                .map(|score| (theme, score))
        })
        .collect();

    // Sort by score descending (highest relevance first)
    results.sort_by(|a, b| b.1.cmp(&a.1));
    results
}

pub struct State {
    pub ruleset: FirewallRuleset,
    pub last_applied_ruleset: Option<FirewallRuleset>,
    pub status: AppStatus,
    pub last_error: Option<ErrorInfo>,
    pub active_tab: WorkspaceTab,
    pub rule_form: Option<RuleForm>,
    pub countdown_remaining: u32,
    pub form_errors: Option<FormErrors>,
    pub interfaces_with_any: Vec<String>,
    pub cached_nft_tokens: Vec<syntax_cache::HighlightedLine>,
    pub cached_json_tokens: Vec<syntax_cache::HighlightedLine>,
    pub cached_diff_tokens: Option<Vec<(syntax_cache::DiffType, syntax_cache::HighlightedLine)>>,
    pub cached_nft_width_px: f32,
    pub cached_json_width_px: f32,
    pub cached_diff_width_px: f32,
    pub rule_search: String,
    pub rule_search_lowercase: String,
    pub cached_all_tags: Vec<Arc<String>>,
    pub cached_filtered_rule_indices: Vec<usize>,
    pub deleting_id: Option<uuid::Uuid>,
    pub pending_warning: Option<PendingWarning>,
    pub show_diff: bool,
    pub show_zebra_striping: bool,
    pub show_diagnostics: bool,
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
    // Profile management
    pub active_profile_name: String,
    pub available_profiles: Vec<String>,
    pub pending_profile_switch: Option<String>,
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
    pub new_name_input: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PendingWarning {
    EnableRpf,
    EnableServerMode,
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
    #[strum(serialize = "json")]
    Json,
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
    Error(String),
}

#[derive(Debug, Clone, Default)]
pub struct FormErrors {
    pub port: Option<String>,
    pub source: Option<String>,
    pub interface: Option<String>,
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

        let ports = if matches!(
            self.protocol,
            Protocol::Tcp | Protocol::Udp | Protocol::TcpAndUdp
        ) {
            let port_start = self.port_start.parse::<u16>();
            let port_end = if self.port_end.is_empty() {
                port_start.clone()
            } else {
                self.port_end.parse::<u16>()
            };

            if let (Ok(s), Ok(e)) = (port_start, port_end) {
                match crate::validators::validate_port_range(s, e) {
                    Ok((start, end)) => Some(crate::core::firewall::PortRange { start, end }),
                    Err(msg) => {
                        errors.port = Some(msg);
                        has_errors = true;
                        None
                    }
                }
            } else {
                errors.port = Some("Invalid port number".to_string());
                has_errors = true;
                None
            }
        } else {
            None
        };

        let source = if self.source.is_empty() {
            None
        } else if let Ok(ip) = self.source.parse::<ipnetwork::IpNetwork>() {
            Some(ip)
        } else {
            errors.source = Some("Invalid IP address or CIDR".to_string());
            has_errors = true;
            None
        };

        if let Some(src) = source {
            if self.protocol == Protocol::Icmp && src.is_ipv6() {
                errors.source = Some("ICMP (v4) selected with IPv6 source".to_string());
                has_errors = true;
            } else if self.protocol == Protocol::Icmpv6 && src.is_ipv4() {
                errors.source = Some("ICMPv6 selected with IPv4 source".to_string());
                has_errors = true;
            }
        }

        if !self.interface.is_empty()
            && let Err(msg) = crate::validators::validate_interface(&self.interface)
        {
            errors.interface = Some(msg);
            has_errors = true;
        }

        if has_errors {
            (None, None, Some(errors))
        } else {
            (ports, source, None)
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
    CopyErrorClicked,
    SaveToSystemClicked,
    SaveToSystemResult(Result<(), String>),
    EventOccurred(iced::Event),
    ToggleDiff(bool),
    ToggleZebraStriping(bool),
    ToggleStrictIcmp(bool),
    IcmpRateLimitChanged(u32),
    ToggleRpfRequested(bool),
    ConfirmEnableRpf,
    CancelWarning,
    ToggleDroppedLogging(bool),
    LogRateChanged(u32),
    LogPrefixChanged(String),
    ServerModeToggled(bool),
    ConfirmServerMode,
    ToggleDiagnostics(bool),
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
    SaveProfileClicked,
    SaveProfileAs(String),
    ProfileSaved(Result<(), String>),
    StartCreatingNewProfile,
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
    ProfileListUpdated(Vec<String>),
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

    fn validate_form_realtime(&mut self) {
        if let Some(form) = &self.rule_form {
            let (_, _, errors) = form.validate();
            self.form_errors = errors;
        }
    }

    pub fn new() -> (Self, Task<Message>) {
        let config = crate::config::load_config_blocking();
        let current_theme = config.theme_choice;
        let mut regular_font_choice = config.regular_font;
        let mut mono_font_choice = config.mono_font;
        let show_diff = config.show_diff;
        let show_zebra_striping = config.show_zebra_striping;
        let active_profile_name = config.active_profile;

        regular_font_choice.resolve(false);
        mono_font_choice.resolve(true);

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
            ruleset,
            status: AppStatus::Idle,
            last_error: None,
            active_tab: WorkspaceTab::Nftables,
            rule_form: None,
            countdown_remaining: 15,
            form_errors: None,
            interfaces_with_any,
            cached_nft_tokens: Vec::new(),
            cached_json_tokens: Vec::new(),
            cached_diff_tokens: None,
            cached_nft_width_px: 800.0,
            cached_json_width_px: 800.0,
            cached_diff_width_px: 800.0,
            rule_search: String::new(),
            rule_search_lowercase: String::new(),
            cached_all_tags: Vec::new(),
            cached_filtered_rule_indices: Vec::new(),
            deleting_id: None,
            pending_warning: None,
            show_diff,
            show_zebra_striping,
            show_diagnostics: false,
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
            active_profile_name,
            available_profiles,
            pending_profile_switch: None,
        };

        // Initialize all caches properly via centralized logic
        state.update_cached_text();

        (state, Task::none())
    }

    fn update_cached_text(&mut self) {
        use std::collections::HashSet;

        let nft_text = self.ruleset.to_nft_text();
        let json_text =
            serde_json::to_string_pretty(&self.ruleset.to_nftables_json()).unwrap_or_default();

        self.cached_nft_tokens = syntax_cache::tokenize_nft(&nft_text);
        self.cached_json_tokens = syntax_cache::tokenize_json(&json_text);

        self.cached_diff_tokens = if let Some(ref last) = self.last_applied_ruleset {
            let old_text = last.to_nft_text();
            syntax_cache::compute_and_tokenize_diff(&old_text, &nft_text)
        } else {
            None
        };

        self.cached_nft_width_px = Self::calculate_max_content_width(&self.cached_nft_tokens);
        self.cached_json_width_px = Self::calculate_max_content_width(&self.cached_json_tokens);
        self.cached_diff_width_px = if let Some(ref diff_tokens) = self.cached_diff_tokens {
            let diff_lines: Vec<&syntax_cache::HighlightedLine> =
                diff_tokens.iter().map(|(_, line)| line).collect();
            Self::calculate_max_content_width_from_refs(&diff_lines)
        } else {
            self.cached_nft_width_px
        };

        let mut all_tags: Vec<String> = self
            .ruleset
            .rules
            .iter()
            .flat_map(|r| r.tags.iter())
            .collect::<HashSet<&String>>()
            .into_iter()
            .cloned()
            .collect();
        all_tags.sort_unstable();
        self.cached_all_tags = all_tags.into_iter().map(Arc::new).collect();

        self.update_filter_cache();
    }

    fn update_filter_cache(&mut self) {
        self.cached_filtered_rule_indices = self
            .ruleset
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
            .map(|(idx, _)| idx)
            .collect();
    }

    fn save_config(&self) -> Task<Message> {
        let config = crate::config::AppConfig {
            active_profile: self.active_profile_name.clone(),
            theme_choice: self.current_theme,
            regular_font: self.regular_font_choice.clone(),
            mono_font: self.mono_font_choice.clone(),
            show_diff: self.show_diff,
            show_zebra_striping: self.show_zebra_striping,
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

    pub fn is_dirty(&self) -> bool {
        self.last_applied_ruleset.as_ref().is_none_or(|last| {
            last.rules != self.ruleset.rules
                || last.advanced_security != self.ruleset.advanced_security
        })
    }

    pub fn is_profile_dirty(&self) -> bool {
        if let Ok(on_disk) = crate::core::profiles::load_profile_blocking(&self.active_profile_name)
        {
            on_disk.rules != self.ruleset.rules
                || on_disk.advanced_security != self.ruleset.advanced_security
        } else {
            true
        }
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
                self.validate_form_realtime();
            }
            Message::RuleFormPortStartChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.port_start = s;
                }
                self.validate_form_realtime();
            }
            Message::RuleFormPortEndChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.port_end = s;
                }
                self.validate_form_realtime();
            }
            Message::RuleFormSourceChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.source = s;
                }
                self.validate_form_realtime();
            }
            Message::RuleFormInterfaceChanged(s) => {
                if let Some(f) = &mut self.rule_form {
                    f.interface = s;
                }
                self.validate_form_realtime();
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
            Message::ToggleRuleEnabled(id) => self.handle_toggle_rule(id),
            Message::DeleteRuleRequested(id) => self.deleting_id = Some(id),
            Message::CancelDelete => self.deleting_id = None,
            Message::DeleteRule(id) => self.handle_delete_rule(id),
            Message::ApplyClicked => return self.handle_apply_clicked(),
            Message::VerifyCompleted(result) => return self.handle_verify_completed(result),
            Message::ProceedToApply => return self.handle_proceed_to_apply(),
            Message::ApplyResult(Err(e)) | Message::RevertResult(Err(e)) => {
                self.status = AppStatus::Error(e.clone());
                self.last_error = Some(ErrorInfo::new(e));
            }
            Message::ApplyResult(Ok(snapshot)) => self.handle_apply_result(snapshot),
            Message::ConfirmClicked => {
                if matches!(self.status, AppStatus::PendingConfirmation { .. }) {
                    self.status = AppStatus::Confirmed;
                    let _ = notify_rust::Notification::new()
                        .summary("✅ DRFW — Changes Confirmed")
                        .body("Firewall rules have been saved and will persist.")
                        .urgency(notify_rust::Urgency::Normal)
                        .timeout(5000)
                        .show();
                }
            }
            Message::RevertClicked => return self.handle_revert_clicked(),
            Message::RevertResult(Ok(())) => {
                self.status = AppStatus::Idle;
                self.last_error = None;
                let _ = notify_rust::Notification::new()
                    .summary("↩️ DRFW — Rules Reverted")
                    .body("Firewall rules have been restored to previous state.")
                    .urgency(notify_rust::Urgency::Normal)
                    .timeout(5000)
                    .show();
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
                let _ = notify_rust::Notification::new()
                    .summary("✅ DRFW — Export Successful")
                    .body(&format!("Rules exported to: {path}"))
                    .timeout(5000)
                    .show();
            }
            Message::ExportResult(Err(e)) => {
                self.show_export_modal = false;
                self.last_error = Some(ErrorInfo::new(e));
            }
            Message::CopyErrorClicked => {
                if let Some(ref err) = self.last_error {
                    return iced::clipboard::write(err.message.clone());
                }
            }
            Message::SaveToSystemClicked => return self.handle_save_to_system(),
            Message::SaveToSystemResult(Ok(())) => {
                self.last_error = None;
            }
            Message::SaveToSystemResult(Err(e)) => self.last_error = Some(ErrorInfo::new(e)),
            Message::EventOccurred(event) => return self.handle_event(event),
            Message::ToggleDiff(enabled) => {
                self.show_diff = enabled;
                return self.save_config();
            }
            Message::ToggleZebraStriping(enabled) => {
                self.show_zebra_striping = enabled;
                return self.save_config();
            }
            Message::ToggleStrictIcmp(enabled) => {
                self.ruleset.advanced_security.strict_icmp = enabled;
                self.update_cached_text();
                return self.save_config();
            }
            Message::IcmpRateLimitChanged(rate) => {
                self.ruleset.advanced_security.icmp_rate_limit = rate;
                self.update_cached_text();
                return self.save_config();
            }
            Message::ToggleRpfRequested(enabled) => {
                if enabled {
                    self.pending_warning = Some(PendingWarning::EnableRpf);
                } else {
                    self.ruleset.advanced_security.enable_rpf = false;
                    self.update_cached_text();
                    return self.save_config();
                }
            }
            Message::ConfirmEnableRpf => {
                self.pending_warning = None;
                self.ruleset.advanced_security.enable_rpf = true;
                self.update_cached_text();
                return self.save_config();
            }
            Message::CancelWarning => {
                self.pending_warning = None;
            }
            Message::ToggleDroppedLogging(enabled) => {
                self.ruleset.advanced_security.log_dropped = enabled;
                self.update_cached_text();
                return self.save_config();
            }
            Message::LogRateChanged(rate) => {
                self.ruleset.advanced_security.log_rate_per_minute = rate;
                self.update_cached_text();
                return self.save_config();
            }
            Message::LogPrefixChanged(prefix) => {
                self.ruleset.advanced_security.log_prefix = prefix;
                self.update_cached_text();
                return self.save_config();
            }
            Message::ServerModeToggled(enabled) => {
                if enabled {
                    self.pending_warning = Some(PendingWarning::EnableServerMode);
                } else {
                    self.ruleset.advanced_security.egress_profile =
                        crate::core::firewall::EgressProfile::Desktop;
                    self.update_cached_text();
                    return self.save_config();
                }
            }
            Message::ConfirmServerMode => {
                self.pending_warning = None;
                self.ruleset.advanced_security.egress_profile =
                    crate::core::firewall::EgressProfile::Server;
                self.update_cached_text();
                return self.save_config();
            }
            Message::ToggleDiagnostics(show) => self.show_diagnostics = show,
            Message::ToggleShortcutsHelp(show) => self.show_shortcuts_help = show,
            Message::Undo => {
                if let Some(description) = self.command_history.undo(&mut self.ruleset) {
                    self.update_cached_text();
                    let _ = self.save_config();
                    tracing::info!("Undid: {}", description);
                }
            }
            Message::Redo => {
                if let Some(description) = self.command_history.redo(&mut self.ruleset) {
                    self.update_cached_text();
                    let _ = self.save_config();
                    tracing::info!("Redid: {}", description);
                }
            }
            Message::ThemeChanged(choice) => {
                self.current_theme = choice;
                self.theme = choice.to_theme();
                return self.save_config();
            }
            Message::OpenThemePicker => {
                self.theme_picker = Some(ThemePickerState {
                    search: String::new(),
                    search_lowercase: String::new(),
                    filter: ThemeFilter::All,
                    original_theme: self.current_theme,
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
                return self.save_config();
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
                return self.save_config();
            }
            Message::MonoFontChanged(choice) => {
                self.mono_font_choice = choice.clone();
                self.font_mono = choice.to_font();
                self.font_picker = None;
                return self.save_config();
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
                    if !tag.is_empty() && !f.tags.contains(&tag) && tag.len() <= 32 {
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
                    let command = crate::command::ReorderRuleCommand {
                        rule_id: dragged_id,
                        old_index,
                        new_index,
                    };
                    self.command_history
                        .execute(Box::new(command), &mut self.ruleset);
                    let _ = self.save_config();
                    self.update_cached_text();
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
                self.ruleset = ruleset;
                self.active_profile_name = name;
                self.command_history = crate::command::CommandHistory::default();
                self.update_cached_text();
                return self.save_config();
            }
            Message::SaveProfileClicked => {
                let name = self.active_profile_name.clone();
                let ruleset = self.ruleset.clone();
                return Task::perform(
                    async move {
                        crate::core::profiles::save_profile(&name, &ruleset)
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::ProfileSaved,
                );
            }
            Message::ProfileSaved(result) => {
                if let Err(e) = result {
                    self.last_error = Some(ErrorInfo::new(format!("Failed to save profile: {e}")));
                } else {
                    tracing::info!("Profile '{}' saved to disk.", self.active_profile_name);
                }
            }
            Message::SaveProfileAs(name) => {
                let ruleset = self.ruleset.clone();
                let name_clone = name.clone();
                self.active_profile_name = name;
                if let Some(mgr) = &mut self.profile_manager {
                    mgr.creating_new = false;
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
                .chain(self.save_config());
            }
            Message::ProfileListUpdated(profiles) => {
                self.available_profiles = profiles;
            }
            Message::StartCreatingNewProfile => {
                if let Some(mgr) = &mut self.profile_manager {
                    mgr.creating_new = true;
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
                    mgr.new_name_input.clear();
                }
            }
            Message::OpenProfileManager => {
                self.profile_manager = Some(ProfileManagerState {
                    renaming_name: None,
                    deleting_name: None,
                    creating_new: false,
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
                    );
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
                    self.last_error = Some(ErrorInfo::new(e));
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
                    }

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
                    .chain(if was_active {
                        self.save_config()
                    } else {
                        Task::none()
                    });
                }
            }
            Message::ProfileRenamed(result) => match result {
                Ok(profiles) => {
                    self.available_profiles = profiles;
                }
                Err(e) => {
                    self.last_error = Some(ErrorInfo::new(e));
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

                    return Task::perform(
                        async move {
                            crate::core::profiles::save_profile(&profile_name, &ruleset).await
                        },
                        move |_result| Message::ProfileSelected(name.clone()),
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

            let form = self.rule_form.take().unwrap();
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

            if let Some(pos) = self.ruleset.rules.iter().position(|r| r.id == rule.id) {
                let old_rule = self.ruleset.rules[pos].clone();
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
            let _ = self.save_config();
            self.update_cached_text();
            self.form_errors = None;
        }
        Task::none()
    }

    fn handle_toggle_rule(&mut self, id: uuid::Uuid) {
        if let Some(rule) = self.ruleset.rules.iter().find(|r| r.id == id) {
            let command = crate::command::ToggleRuleCommand {
                rule_id: id,
                was_enabled: rule.enabled,
            };
            self.command_history
                .execute(Box::new(command), &mut self.ruleset);
            let _ = self.save_config();
            self.update_cached_text();
        }
    }

    fn handle_delete_rule(&mut self, id: uuid::Uuid) {
        if let Some(pos) = self.ruleset.rules.iter().position(|r| r.id == id) {
            let rule = self.ruleset.rules[pos].clone();
            let command = crate::command::DeleteRuleCommand { rule, index: pos };
            self.command_history
                .execute(Box::new(command), &mut self.ruleset);
            let _ = self.save_config();
            self.update_cached_text();
        }
        self.deleting_id = None;
    }

    fn handle_apply_clicked(&mut self) -> Task<Message> {
        if matches!(
            self.status,
            AppStatus::Verifying | AppStatus::Applying | AppStatus::PendingConfirmation { .. }
        ) {
            return Task::none();
        }

        self.status = AppStatus::Verifying;
        self.last_error = None;
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
        match &result {
            Ok(verify_result) => {
                let success = verify_result.success;
                let error_count = verify_result.errors.len();
                let error = if verify_result.success {
                    None
                } else {
                    Some(verify_result.errors.join("; "))
                };
                tokio::spawn(async move {
                    crate::audit::log_verify(success, error_count, error).await;
                });
            }
            Err(e) => {
                let error = e.clone();
                tokio::spawn(async move {
                    crate::audit::log_verify(false, 0, Some(error)).await;
                });
            }
        }

        match result {
            Ok(verify_result) if verify_result.success => {
                self.status = AppStatus::AwaitingApply;
                self.last_error = None;
                Task::none()
            }
            Ok(verify_result) => {
                let error_msg = if verify_result.errors.is_empty() {
                    "Ruleset verification failed".to_string()
                } else {
                    verify_result.errors.join("\n")
                };
                self.status = AppStatus::Error(error_msg.clone());
                self.last_error = Some(ErrorInfo::new(error_msg));
                Task::none()
            }
            Err(e) => {
                self.status = AppStatus::Error(e.clone());
                self.last_error = Some(ErrorInfo::new(e));
                Task::none()
            }
        }
    }

    fn handle_proceed_to_apply(&mut self) -> Task<Message> {
        self.status = AppStatus::Applying;
        self.last_error = None;
        let nft_json = self.ruleset.to_nftables_json();
        let rule_count = self.ruleset.rules.len();
        let enabled_count = self.ruleset.rules.iter().filter(|r| r.enabled).count();

        Task::perform(
            async move {
                let result = crate::core::nft_json::apply_with_snapshot(nft_json).await;
                let success = result.is_ok();
                let error = result.as_ref().err().map(std::string::ToString::to_string);
                crate::audit::log_apply(rule_count, enabled_count, success, error.clone()).await;
                result.map_err(|e| e.to_string())
            },
            Message::ApplyResult,
        )
    }

    fn handle_apply_result(&mut self, snapshot: serde_json::Value) {
        self.last_applied_ruleset = Some(self.ruleset.clone());
        self.countdown_remaining = 15;
        if let Err(e) = crate::core::nft_json::save_snapshot_to_disk(&snapshot) {
            eprintln!("Failed to save snapshot to disk: {e}");
            self.last_error = Some(ErrorInfo::new(format!(
                "Warning: Failed to save snapshot to disk. Rollback may be unavailable after restart: {e}"
            )));
        }

        self.status = AppStatus::PendingConfirmation {
            deadline: Utc::now() + Duration::from_secs(15),
            snapshot,
        };
        self.last_error = None;
        let _ = notify_rust::Notification::new()
            .summary("DRFW — Firewall Changes Applied")
            .body("Changes will be automatically reverted in 15 seconds if not confirmed.")
            .timeout(15000)
            .show();
    }

    fn handle_revert_clicked(&mut self) -> Task<Message> {
        if let AppStatus::PendingConfirmation { snapshot, .. } = &self.status {
            let snapshot = snapshot.clone();
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
                    crate::audit::log_revert(success, error.clone()).await;
                    final_result.map_err(|e| e.to_string())
                },
                Message::RevertResult,
            );
        }
        Task::none()
    }

    fn handle_countdown_tick(&mut self) -> Task<Message> {
        if let AppStatus::PendingConfirmation { deadline, .. } = &self.status {
            let now = Utc::now();
            if now >= *deadline {
                self.status = AppStatus::Reverting;
                self.countdown_remaining = 0;
                let _ = notify_rust::Notification::new()
                    .summary("↩️ DRFW — Auto-Reverted")
                    .body("Firewall rules automatically reverted due to timeout.")
                    .urgency(notify_rust::Urgency::Normal)
                    .timeout(10000)
                    .show();
                return Task::done(Message::RevertClicked);
            }

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let remaining = (*deadline - now).num_seconds().max(0) as u32;
            if self.countdown_remaining != remaining {
                self.countdown_remaining = remaining;
                if remaining == 5 {
                    let _ = notify_rust::Notification::new()
                        .summary("⚠️ DRFW — Auto-Revert Warning")
                        .body("Firewall will revert in 5 seconds! Click Confirm to keep changes.")
                        .urgency(notify_rust::Urgency::Critical)
                        .timeout(5000)
                        .show();
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
                let path = crate::utils::pick_save_path(&filename, "json")
                    .or_else(|| {
                        // Fallback if user cancels dialog
                        crate::utils::get_data_dir().map(|mut p| {
                            p.push(&filename);
                            p
                        })
                    })
                    .unwrap_or_else(|| std::path::PathBuf::from(&filename));

                std::fs::write(&path, json)
                    .map(|()| path.to_string_lossy().to_string())
                    .map_err(|e| format!("Failed to export JSON: {e}"))
            },
            Message::ExportResult,
        )
    }

    fn handle_export_nft(&self) -> Task<Message> {
        let nft_text = self.ruleset.to_nft_text();
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("drfw_rules_{timestamp}.nft");
        Task::perform(
            async move {
                // Use native file dialog for better UX
                let path = crate::utils::pick_save_path(&filename, "nft")
                    .or_else(|| {
                        // Fallback if user cancels dialog
                        crate::utils::get_data_dir().map(|mut p| {
                            p.push(&filename);
                            p
                        })
                    })
                    .unwrap_or_else(|| std::path::PathBuf::from(&filename));

                std::fs::write(&path, nft_text)
                    .map(|()| path.to_string_lossy().to_string())
                    .map_err(|e| format!("Failed to export nftables text: {e}"))
            },
            Message::ExportResult,
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
                    iced::time::every(Duration::from_secs(1)).map(|_| Message::CountdownTick)
                }
                _ => iced::Subscription::none(),
            },
        ])
    }
}
