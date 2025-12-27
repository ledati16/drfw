pub mod ui_components;
pub mod view;

use crate::core::error::ErrorInfo;
use crate::core::firewall::{FirewallRuleset, Protocol, Rule};
use chrono::Utc;
use iced::{Element, Task};
use std::time::Duration;

// Fonts are now dynamically selected via settings

#[allow(clippy::struct_excessive_bools)]
pub struct State {
    pub ruleset: FirewallRuleset,
    pub last_applied_ruleset: Option<FirewallRuleset>,
    pub status: AppStatus,
    pub last_error: Option<ErrorInfo>,
    pub active_tab: WorkspaceTab,
    pub rule_form: Option<RuleForm>,
    pub countdown_remaining: u32,
    pub form_errors: Option<FormErrors>,
    pub interfaces: Vec<String>,
    pub cached_nft_text: String,
    pub cached_json_text: String,
    pub rule_search: String,
    pub rule_search_lowercase: String,
    pub cached_all_tags: Vec<String>,
    pub deleting_id: Option<uuid::Uuid>,
    pub pending_warning: Option<PendingWarning>,
    pub show_diff: bool,
    pub show_diagnostics: bool,
    pub show_export_modal: bool,
    pub show_shortcuts_help: bool,
    pub font_picker: Option<FontPickerState>,
    pub command_history: crate::command::CommandHistory,
    pub current_theme: crate::theme::ThemeChoice,
    pub theme: crate::theme::AppTheme,
    #[allow(dead_code)] // TODO: Add custom themes to theme picker UI
    pub custom_themes: Vec<crate::theme::AppTheme>,
    pub filter_tag: Option<String>,
    pub dragged_rule_id: Option<uuid::Uuid>,
    pub hovered_drop_target_id: Option<uuid::Uuid>,
    pub regular_font_choice: crate::fonts::RegularFontChoice,
    pub mono_font_choice: crate::fonts::MonoFontChoice,
    pub font_regular: iced::Font,
    pub font_mono: iced::Font,
    pub available_fonts: &'static [crate::fonts::FontChoice],
}

#[derive(Debug, Clone)]
pub struct FontPickerState {
    pub target: FontPickerTarget,
    pub search: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontPickerTarget {
    Regular,
    Mono,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PendingWarning {
    EnableRpf,
    EnableServerMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkspaceTab {
    #[default]
    Nftables,
    Json,
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
    pub selected_preset: Option<crate::core::firewall::ServicePreset>,
    pub tags: Vec<String>,
    pub tag_input: String,
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
            selected_preset: None,
            tags: Vec::new(),
            tag_input: String::new(),
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

        let ports = if matches!(self.protocol, Protocol::Tcp | Protocol::Udp) {
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

        // Validate interface name
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
    RuleFormPresetSelected(crate::core::firewall::ServicePreset),
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
    FontsLoaded,
    ToggleDiff(bool),
    // Advanced Security Settings
    ToggleStrictIcmp(bool),
    IcmpRateLimitChanged(u32),
    ToggleRpfRequested(bool),
    ConfirmEnableRpf,
    CancelWarning,
    ToggleDroppedLogging(bool),
    LogRateChanged(u32),
    LogPrefixChanged(String),
    EgressProfileRequested(crate::core::firewall::EgressProfile),
    ConfirmServerMode,
    // Diagnostics
    ToggleDiagnostics(bool),
    OpenLogsFolder,
    // Export
    ExportAsJson,
    ExportAsNft,
    ExportResult(Result<String, String>),
    // Help
    ToggleShortcutsHelp(bool),
    // Undo/Redo
    Undo,
    Redo,
    // Theme
    ThemeChanged(crate::theme::ThemeChoice),
    // Fonts
    RegularFontChanged(crate::fonts::RegularFontChoice),
    MonoFontChanged(crate::fonts::MonoFontChoice),
    OpenFontPicker(FontPickerTarget),
    FontPickerSearchChanged(String),
    CloseFontPicker,
    // Rule Tagging
    RuleFormTagInputChanged(String),
    RuleFormAddTag,
    RuleFormRemoveTag(String),
    #[allow(dead_code)] // TODO: Add filter UI buttons
    FilterByTag(Option<String>),
    // Drag and Drop
    RuleDragStart(uuid::Uuid),
    RuleDropped(uuid::Uuid),
    RuleHoverStart(uuid::Uuid),
    RuleHoverEnd,
}

impl State {
    pub fn view(&self) -> Element<'_, Message> {
        view::view(self)
    }

    /// Validates the current form and updates `form_errors` in real-time
    fn validate_form_realtime(&mut self) {
        if let Some(form) = &self.rule_form {
            let (_, _, errors) = form.validate();
            self.form_errors = errors;
        }
    }

    pub fn new() -> (Self, Task<Message>) {
        // Load complete config including theme choice and fonts
        let config = crate::config::load_config();
        let ruleset = config.ruleset;
        let current_theme = config.theme_choice;
        let mut regular_font_choice = config.regular_font;
        let mut mono_font_choice = config.mono_font;

        // Resolve fonts (hydrate handles from system cache, handle deleted fonts)
        regular_font_choice.resolve(false);
        mono_font_choice.resolve(true);

        let interfaces = crate::utils::list_interfaces();
        let cached_nft_text = ruleset.to_nft_text();
        let cached_json_text =
            serde_json::to_string_pretty(&ruleset.to_nftables_json()).unwrap_or_default();

        // Apply the theme
        let theme = current_theme.to_theme();

        // Apply the fonts
        let font_regular = regular_font_choice.to_font();
        let font_mono = mono_font_choice.to_font();

        // Load custom themes from config directory
        let custom_themes = crate::theme::custom::load_custom_themes();

        // Get available fonts (cached static slice)
        let available_fonts = crate::fonts::all_options();

        (
            Self {
                last_applied_ruleset: Some(ruleset.clone()),
                ruleset,
                status: AppStatus::Idle,
                last_error: None,
                active_tab: WorkspaceTab::Nftables,
                rule_form: None,
                countdown_remaining: 15,
                form_errors: None,
                interfaces,
                cached_nft_text,
                cached_json_text,
                rule_search: String::new(),
                rule_search_lowercase: String::new(),
                cached_all_tags: Vec::new(),
                deleting_id: None,
                pending_warning: None,
                show_diff: true,
                show_diagnostics: false,
                show_export_modal: false,
                show_shortcuts_help: false,
                font_picker: None,
                command_history: crate::command::CommandHistory::default(),
                current_theme,
                theme,
                custom_themes,
                filter_tag: None,
                dragged_rule_id: None,
                hovered_drop_target_id: None,
                regular_font_choice,
                mono_font_choice,
                font_regular,
                font_mono,
                available_fonts,
            },
            Task::batch(vec![
                iced::font::load(
                    include_bytes!("../../assets/fonts/JetBrainsMono-Regular.ttf").as_slice(),
                )
                .map(|_| Message::FontsLoaded),
            ]),
        )
    }

    fn update_cached_text(&mut self) {
        self.cached_nft_text = self.ruleset.to_nft_text();
        self.cached_json_text =
            serde_json::to_string_pretty(&self.ruleset.to_nftables_json()).unwrap_or_default();

        // Update tag cache (Phase 3: Cache Tag Collection)
        use std::collections::BTreeSet;
        let all_tags: BTreeSet<String> = self
            .ruleset
            .rules
            .iter()
            .flat_map(|r| r.tags.iter().cloned())
            .collect();
        self.cached_all_tags = all_tags.into_iter().collect();
    }

    fn save_config(&self) -> Task<Message> {
        let config = crate::config::AppConfig {
            ruleset: self.ruleset.clone(),
            theme_choice: self.current_theme,
            regular_font: self.regular_font_choice.clone(),
            mono_font: self.mono_font_choice.clone(),
        };
        if let Err(e) = crate::config::save_config(&config) {
            eprintln!("Failed to save configuration: {e}");
        }
        Task::none()
    }

    pub fn is_dirty(&self) -> bool {
        self.last_applied_ruleset.as_ref().is_none_or(|last| {
            last.rules != self.ruleset.rules
                || last.advanced_security != self.ruleset.advanced_security
        })
    }

    /// Computes a diff between the last applied ruleset and current ruleset
    pub fn compute_diff(&self) -> Option<String> {
        use std::fmt::Write;
        if let Some(ref last) = self.last_applied_ruleset {
            let old_text = last.to_nft_text();
            let new_text = self.cached_nft_text.clone();

            let diff = similar::TextDiff::from_lines(&old_text, &new_text);
            let mut result = String::new();

            for change in diff.iter_all_changes() {
                let sign = match change.tag() {
                    similar::ChangeTag::Delete => "- ",
                    similar::ChangeTag::Insert => "+ ",
                    similar::ChangeTag::Equal => "  ",
                };
                let _ = write!(result, "{sign}{change}");
            }

            if result.is_empty() || !self.is_dirty() {
                None
            } else {
                Some(result)
            }
        } else {
            None
        }
    }

    #[allow(clippy::too_many_lines)]
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
                // No validation needed for label (auto-sanitized)
            }
            Message::RuleFormProtocolChanged(p) => {
                if let Some(f) = &mut self.rule_form {
                    f.protocol = p;
                }
                // Revalidate in case port/source validation changes with protocol
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
            Message::RuleFormPresetSelected(preset) => self.handle_preset_selected(&preset),
            Message::RuleSearchChanged(s) => {
                self.rule_search_lowercase = s.to_lowercase();
                self.rule_search = s;
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
                self.status = AppStatus::Confirmed;
                // Confirmation notification
                let _ = notify_rust::Notification::new()
                    .summary("✅ DRFW — Changes Confirmed")
                    .body("Firewall rules have been saved and will persist.")
                    .urgency(notify_rust::Urgency::Normal)
                    .timeout(5000)
                    .show();
            }
            Message::RevertClicked => return self.handle_revert_clicked(),
            Message::RevertResult(Ok(())) => {
                self.status = AppStatus::Idle;
                self.last_error = None;
                // Manual revert notification
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
                // Could show a success notification here
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
            Message::FontsLoaded => {}
            Message::ToggleDiff(enabled) => self.show_diff = enabled,
            // Advanced Security Settings
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
                    // Show warning modal
                    self.pending_warning = Some(PendingWarning::EnableRpf);
                } else {
                    // Can disable without warning
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
            Message::EgressProfileRequested(profile) => {
                if profile == crate::core::firewall::EgressProfile::Server {
                    // Show warning modal
                    self.pending_warning = Some(PendingWarning::EnableServerMode);
                } else {
                    // Can switch to Desktop without warning
                    self.ruleset.advanced_security.egress_profile = profile;
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
                tracing::info!("Theme changed to: {}", choice.name());
                return self.save_config();
            }
            Message::RegularFontChanged(choice) => {
                self.regular_font_choice = choice.clone();
                self.font_regular = choice.to_font();
                tracing::info!("Regular font changed to: {}", choice.name());
                return self.save_config();
            }
            Message::MonoFontChanged(choice) => {
                self.mono_font_choice = choice.clone();
                self.font_mono = choice.to_font();
                tracing::info!("Monospace font changed to: {}", choice.name());
                self.font_picker = None; // Close picker after selection
                return self.save_config();
            }
            Message::OpenFontPicker(target) => {
                self.font_picker = Some(FontPickerState {
                    target,
                    search: String::new(),
                });
            }
            Message::FontPickerSearchChanged(search) => {
                if let Some(picker) = &mut self.font_picker {
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
                    let tag = f.tag_input.trim().to_string();
                    if !tag.is_empty() && !f.tags.contains(&tag) {
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
                }
            }
            Message::OpenLogsFolder => {
                if let Some(state_dir) = crate::utils::get_state_dir() {
                    let path_str = state_dir.to_string_lossy().to_string();
                    #[cfg(target_os = "linux")]
                    {
                        let _ = std::process::Command::new("xdg-open")
                            .arg(&path_str)
                            .spawn();
                    }
                    #[cfg(target_os = "macos")]
                    {
                        let _ = std::process::Command::new("open").arg(&path_str).spawn();
                    }
                    #[cfg(target_os = "windows")]
                    {
                        let _ = std::process::Command::new("explorer")
                            .arg(&path_str)
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
        }
        Task::none()
    }

    fn handle_edit_clicked(&mut self, id: uuid::Uuid) {
        if let Some(rule) = self.ruleset.rules.iter().find(|r| r.id == id) {
            self.rule_form = Some(RuleForm {
                id: Some(rule.id),
                label: rule.label.clone(),
                protocol: rule.protocol, // Copy, not clone
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
                selected_preset: None,
                tags: rule.tags.clone(),
                tag_input: String::new(),
            });
            self.form_errors = None;
        }
    }

    fn handle_save_rule_form(&mut self) -> Task<Message> {
        // First validate without taking ownership
        if let Some(form_ref) = &self.rule_form {
            let (ports, source, errors) = form_ref.validate();
            if let Some(errs) = errors {
                self.form_errors = Some(errs);
                return Task::none();
            }

            // Validation succeeded - now take ownership to avoid clone
            let form = self.rule_form.take().unwrap();

            // Sanitize label to prevent injection attacks
            let sanitized_label = crate::validators::sanitize_label(&form.label);

            let rule = Rule {
                id: form.id.unwrap_or_else(uuid::Uuid::new_v4),
                label: sanitized_label,
                protocol: form.protocol,
                ports,
                source,
                interface: if form.interface.is_empty() {
                    None
                } else {
                    Some(form.interface)
                },
                ipv6_only: false,
                enabled: true,
                created_at: Utc::now(),
                tags: form.tags, // No clone needed - we own form
            };

            // Use command pattern for undo/redo support
            if let Some(pos) = self.ruleset.rules.iter().position(|r| r.id == rule.id) {
                // Editing existing rule
                let old_rule = self.ruleset.rules[pos].clone();
                let command = crate::command::EditRuleCommand {
                    old_rule,
                    new_rule: rule,
                };
                self.command_history
                    .execute(Box::new(command), &mut self.ruleset);
            } else {
                // Adding new rule
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

    fn handle_preset_selected(&mut self, preset: &crate::core::firewall::ServicePreset) {
        if let Some(form) = &mut self.rule_form {
            form.selected_preset = Some(preset.clone());
            form.protocol = preset.protocol;
            form.port_start = preset.port.to_string();
            form.port_end = preset.port.to_string();
            if form.label.is_empty() {
                form.label = preset.name.to_string();
            }
        }
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

        // Start verification first
        self.status = AppStatus::Verifying;
        self.last_error = None;
        let ruleset = self.ruleset.clone();

        Task::perform(
            async move {
                crate::core::verify::verify_ruleset(&ruleset)
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
        // Log verification result (fire and forget)
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
                // Verification passed, show confirmation modal
                self.status = AppStatus::AwaitingApply;
                self.last_error = None;
                Task::none()
            }
            Ok(verify_result) => {
                // Verification failed with errors
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
                // Verification command failed
                self.status = AppStatus::Error(e.clone());
                self.last_error = Some(ErrorInfo::new(e));
                Task::none()
            }
        }
    }

    fn handle_proceed_to_apply(&mut self) -> Task<Message> {
        self.status = AppStatus::Applying;
        self.last_error = None;
        let ruleset = self.ruleset.clone();
        let rule_count = ruleset.rules.len();
        let enabled_count = ruleset.rules.iter().filter(|r| r.enabled).count();

        Task::perform(
            async move {
                let result = crate::core::nft_json::apply_with_snapshot(&ruleset).await;

                // Log the operation
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

        // Save snapshot to disk for persistence
        if let Err(e) = crate::core::nft_json::save_snapshot_to_disk(&snapshot) {
            eprintln!("Failed to save snapshot to disk: {e}");
            // Continue anyway - we still have the in-memory snapshot
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
                    // Try in-memory snapshot first
                    let result = crate::core::nft_json::restore_snapshot(&snapshot).await;

                    // If that fails, try fallback cascade from disk
                    let final_result = if result.is_err() {
                        eprintln!("In-memory snapshot failed, trying fallback cascade...");
                        crate::core::nft_json::restore_with_fallback().await
                    } else {
                        result
                    };

                    // Log the revert operation
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
        if let AppStatus::PendingConfirmation { .. } = self.status {
            if self.countdown_remaining > 0 {
                self.countdown_remaining -= 1;

                // Warning notification at 5 seconds remaining
                if self.countdown_remaining == 5 {
                    let _ = notify_rust::Notification::new()
                        .summary("⚠️ DRFW — Auto-Revert Warning")
                        .body("Firewall will revert in 5 seconds! Click Confirm to keep changes.")
                        .urgency(notify_rust::Urgency::Critical)
                        .timeout(5000)
                        .show();
                }
            } else {
                // Auto-revert notification
                let _ = notify_rust::Notification::new()
                    .summary("↩️ DRFW — Auto-Reverted")
                    .body("Firewall rules automatically reverted due to timeout.")
                    .urgency(notify_rust::Urgency::Normal)
                    .timeout(10000)
                    .show();

                return Task::done(Message::RevertClicked);
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

                // Create secure temp file with restricted permissions
                let mut temp =
                    NamedTempFile::new().map_err(|e| format!("Failed to create temp file: {e}"))?;

                // Set restrictive permissions (Unix only)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o600);
                    temp.as_file()
                        .set_permissions(perms)
                        .map_err(|e| format!("Failed to set permissions: {e}"))?;
                }

                // Write configuration to temp file
                temp.write_all(text.as_bytes())
                    .map_err(|e| format!("Failed to write temp file: {e}"))?;
                temp.flush()
                    .map_err(|e| format!("Failed to flush temp file: {e}"))?;

                // Get path and keep temp file alive
                let temp_path_str = temp
                    .path()
                    .to_str()
                    .ok_or_else(|| "Invalid temp path".to_string())?
                    .to_string();

                // Use cp instead of mv to avoid TOCTOU issues
                // --preserve=mode ensures permissions are maintained
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
        // Use cached JSON to avoid regenerating
        let json = self.cached_json_text.clone();
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("drfw_rules_{timestamp}.json");

        Task::perform(
            async move {
                // Try to save to Downloads folder first, fall back to data dir
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                let downloads_path = std::path::PathBuf::from(&home)
                    .join("Downloads")
                    .join(&filename);

                let path = if downloads_path.parent().is_some_and(std::path::Path::exists) {
                    downloads_path
                } else {
                    crate::utils::get_data_dir().map_or_else(
                        || std::path::PathBuf::from(&filename),
                        |mut p| {
                            p.push(&filename);
                            p
                        },
                    )
                };

                std::fs::write(&path, json)
                    .map(|()| path.to_string_lossy().to_string())
                    .map_err(|e| format!("Failed to export JSON: {e}"))
            },
            Message::ExportResult,
        )
    }

    fn handle_export_nft(&self) -> Task<Message> {
        let nft_text = self.cached_nft_text.clone();
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("drfw_rules_{timestamp}.nft");

        Task::perform(
            async move {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                let downloads_path = std::path::PathBuf::from(&home)
                    .join("Downloads")
                    .join(&filename);

                let path = if downloads_path.parent().is_some_and(std::path::Path::exists) {
                    downloads_path
                } else {
                    crate::utils::get_data_dir().map_or_else(
                        || std::path::PathBuf::from(&filename),
                        |mut p| {
                            p.push(&filename);
                            p
                        },
                    )
                };

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
                    // Ctrl+Z: Undo
                    if self.command_history.can_undo() {
                        return Task::done(Message::Undo);
                    }
                }
                iced::keyboard::Key::Character("z")
                    if (modifiers.command() || modifiers.control()) && modifiers.shift() =>
                {
                    // Ctrl+Shift+Z: Redo
                    if self.command_history.can_redo() {
                        return Task::done(Message::Redo);
                    }
                }
                iced::keyboard::Key::Character("y")
                    if modifiers.command() || modifiers.control() =>
                {
                    // Ctrl+Y: Redo (alternative)
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
            iced::event::listen().map(Message::EventOccurred),
            match self.status {
                AppStatus::PendingConfirmation { .. } => {
                    iced::time::every(Duration::from_secs(1)).map(|_| Message::CountdownTick)
                }
                _ => iced::Subscription::none(),
            },
        ])
    }
}
