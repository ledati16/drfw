//! Rule CRUD operations and form handling
//!
//! Handles all message variants related to firewall rule management:
//! - Adding, editing, deleting rules
//! - Toggling rules enabled/disabled
//! - Drag-and-drop reordering
//! - Form field updates (with UI state validation)
//! - Search and tag filtering

use std::sync::Arc;

use iced::Task;
use jiff::Timestamp;
use uuid::Uuid;

use crate::app::{Message, RuleForm, State};
use crate::command::{
    AddRuleCommand, AddRulesCommand, DeleteRuleCommand, EditRuleCommand, ReorderRuleCommand,
    ToggleRuleCommand,
};
use crate::core::firewall::{Chain, MAX_RULES, Protocol};
use crate::core::rule_constraints::{protocol_supports_ports, reject_type_valid_for_protocol};
use crate::{audit, validators};

/// Refreshes the interface suggestions of the rule form's combo boxes.
///
/// Interfaces come and go (VPNs, containers, USB adapters), so the list is
/// rebuilt each time the form opens; listing interfaces is a cheap syscall.
fn refresh_interface_suggestions(state: &mut State) {
    let suggestions = crate::utils::build_interface_suggestions();
    state.output_interface_combo = iced::widget::combo_box::State::new(suggestions.clone());
    state.interface_combo = iced::widget::combo_box::State::new(suggestions);
}

/// Opens the rule form (closing any helper left from an earlier form) and
/// focuses its first input.
fn open_rule_form(
    state: &mut State,
    form: RuleForm,
    errors: Option<crate::app::FormErrors>,
) -> Task<Message> {
    refresh_interface_suggestions(state);
    state.rule_form_initial = Some(form.clone());
    state.rule_form = Some(form);
    state.rule_form_helper = None;
    state.form_errors = errors;
    state.confirm_discard_form = false;
    crate::app::focus::focus_input(crate::app::focus::RULE_FORM_LABEL)
}

/// Closes the rule form, its helper modal and its errors.
fn close_rule_form(state: &mut State) {
    state.rule_form = None;
    state.rule_form_initial = None;
    state.rule_form_helper = None;
    state.form_errors = None;
    state.confirm_discard_form = false;
}

/// Handles opening the "Add New Rule" form
pub(crate) fn handle_add_rule_clicked(state: &mut State) -> Task<Message> {
    state.template_menu = None;
    open_rule_form(state, RuleForm::default(), None)
}

/// Opens or closes the "Add from template" menu. Opening lists the
/// interfaces again (they come and go) and builds the entries for those
/// that call for a template.
pub(crate) fn handle_toggle_template_menu(state: &mut State, open: bool) {
    state.template_menu = open.then(|| {
        crate::app::templates::TemplateMenu::for_interfaces(&crate::utils::list_interfaces())
    });
}

/// Adds the rules of template menu entry `index` as one undoable step
/// (ordinary rules: they can be edited or deleted like any other) and
/// closes the menu.
pub(crate) fn handle_add_template(state: &mut State, index: usize) -> Task<Message> {
    use crate::app::BannerSeverity;

    let Some(entry) = state
        .template_menu
        .take()
        .and_then(|mut menu| (index < menu.entries.len()).then(|| menu.entries.swap_remove(index)))
    else {
        return Task::none();
    };
    let rules = entry.rules();
    if state.ruleset.rules.len() + rules.len() > MAX_RULES {
        state.push_banner(
            format!("This profile already has the maximum of {MAX_RULES} rules"),
            BannerSeverity::Error,
        );
        return Task::none();
    }
    let count = rules.len();
    let logged: Vec<(String, String, String)> = rules
        .iter()
        .map(|r| {
            (
                r.label.clone(),
                r.protocol.to_string(),
                r.port_display.clone(),
            )
        })
        .collect();
    let command = AddRulesCommand {
        rules,
        description: format!("Add template: {}", entry.title),
    };
    state
        .command_history
        .execute(Box::new(command), &mut state.ruleset);
    state.mark_profile_dirty();
    let noun = if count == 1 { "rule" } else { "rules" };
    state.push_banner(
        format!("Added {count} {noun} from the template \"{}\"", entry.title),
        BannerSeverity::Success,
    );
    let enable_event_log = state.enable_event_log;
    super::audit_task(async move {
        for (label, protocol, ports) in logged {
            audit::log_rule_created(enable_event_log, &label, &protocol, Some(ports)).await;
        }
    })
}

/// Handles opening the "Edit Rule" form
pub(crate) fn handle_edit_rule_clicked(state: &mut State, id: Uuid) -> Task<Message> {
    let Some(rule) = state.ruleset.rules.iter().find(|r| r.id == id) else {
        return Task::none();
    };
    let form = RuleForm::from_rule(rule);
    // Show why a loaded rule is invalid right away
    let errors = form.validate();
    open_rule_form(state, form, errors)
}

/// Handles Cancel (and Escape) in the rule form: closes it, or first asks
/// "Discard changes?" when the form was changed since it opened.
pub(crate) fn handle_cancel_rule_form(state: &mut State) {
    let changed = match (&state.rule_form, &state.rule_form_initial) {
        (Some(form), Some(initial)) => form.has_changes(initial),
        _ => false,
    };
    if changed && !state.confirm_discard_form {
        state.confirm_discard_form = true;
        return;
    }
    close_rule_form(state);
}

/// "Keep editing" in the "Discard changes?" prompt (and Escape there)
pub(crate) fn handle_keep_editing_rule_form(state: &mut State) {
    state.confirm_discard_form = false;
}

/// "Discard" in the "Discard changes?" prompt
pub(crate) fn handle_discard_rule_form(state: &mut State) {
    close_rule_form(state);
}

/// Handles saving new or edited rule
///
/// # Security Note
/// This function uses the safe pattern from CLAUDE.md Section 13 ("The Unwrap Trap").
/// If the form state becomes None between validation and save, we log an error and
/// gracefully degrade instead of panicking.
pub(crate) fn handle_save_rule_form(state: &mut State) -> Task<Message> {
    // Validate form exists
    if let Some(form_ref) = &state.rule_form {
        if let Some(errs) = form_ref.validate() {
            state.form_errors = Some(errs);
            return Task::none();
        }
        let is_new = form_ref
            .id
            .is_none_or(|id| !state.ruleset.rules.iter().any(|r| r.id == id));
        if is_new && state.ruleset.rules.len() >= MAX_RULES {
            state.form_errors = Some(crate::app::FormErrors {
                general: Some(format!(
                    "This profile already has the maximum of {MAX_RULES} rules"
                )),
                ..Default::default()
            });
            return Task::none();
        }

        // Extract form (consumes it)
        let Some(form) = state.rule_form.take() else {
            tracing::error!(
                "SaveRuleForm clicked but form became None between validation and save. \
                 This indicates a UI state desync bug."
            );
            return Task::none();
        };

        // Editing keeps the rule's own id, enabled state and creation time;
        // only a new rule gets fresh ones.
        let existing = form
            .id
            .and_then(|id| state.ruleset.rules.iter().find(|r| r.id == id))
            .map(|r| (r.id, r.enabled, r.created_at));
        let (id, enabled, created_at) =
            existing.unwrap_or_else(|| (Uuid::new_v4(), true, Timestamp::now()));
        let rule = form.to_rule(id, enabled, created_at);

        let is_edit = state.ruleset.rules.iter().any(|r| r.id == rule.id);
        let enable_event_log = state.enable_event_log;
        let label = rule.label.clone();
        let protocol = rule.protocol.to_string();
        let ports = rule.port_display.clone();

        if is_edit {
            // EDIT EXISTING RULE
            // Safe pattern from CLAUDE.md Section 13
            let Some(old_rule) = state
                .ruleset
                .rules
                .iter()
                .find(|r| r.id == rule.id)
                .cloned()
            else {
                tracing::error!(
                    "SaveRuleForm for non-existent rule ID: {}. \
                     This indicates a UI state desync bug.",
                    rule.id
                );
                close_rule_form(state);
                return Task::none();
            };

            let command = EditRuleCommand {
                old_rule,
                new_rule: rule,
            };
            state
                .command_history
                .execute(Box::new(command), &mut state.ruleset);
        } else {
            // ADD NEW RULE
            let command = AddRuleCommand { rule };
            state
                .command_history
                .execute(Box::new(command), &mut state.ruleset);
        }

        state.mark_profile_dirty();
        close_rule_form(state);

        // Log rule change with proper completion tracking
        return super::audit_task(async move {
            let port_str = if ports.is_empty() { None } else { Some(ports) };
            if is_edit {
                audit::log_rule_modified(enable_event_log, &label, &protocol, port_str).await;
            } else {
                audit::log_rule_created(enable_event_log, &label, &protocol, port_str).await;
            }
        });
    }

    Task::none()
}

/// Handles toggling rule enabled/disabled
pub(crate) fn handle_toggle_rule(state: &mut State, id: Uuid) -> Task<Message> {
    let Some(rule) = state.ruleset.rules.iter().find(|r| r.id == id) else {
        return Task::none();
    };

    let was_enabled = rule.enabled;
    let label = rule.label.clone();
    let enable_event_log = state.enable_event_log;

    // Execute command
    let cmd = Box::new(ToggleRuleCommand {
        rule_id: id,
        was_enabled,
    });
    state.command_history.execute(cmd, &mut state.ruleset);

    state.mark_profile_dirty();

    // Audit log with proper completion tracking
    super::audit_task(async move {
        audit::log_rule_toggled(enable_event_log, &label, !was_enabled).await;
    })
}

/// Handles deleting a rule
pub(crate) fn handle_delete_rule(state: &mut State, id: Uuid) -> Task<Message> {
    let Some((index, rule_clone)) = state
        .ruleset
        .rules
        .iter()
        .enumerate()
        .find(|(_, r)| r.id == id)
        .map(|(i, r)| (i, r.clone()))
    else {
        state.deleting_id = None;
        return Task::none();
    };

    // Clear drag state if it references the rule being deleted
    if state.dragged_rule_id == Some(id)
        || state.hovered_drop_target_id == Some(id)
        || state.hover_pending.map(|(pid, _)| pid) == Some(id)
    {
        state.clear_drag_state();
    }
    let enable_event_log = state.enable_event_log;

    // Execute command
    let cmd = Box::new(DeleteRuleCommand {
        rule: rule_clone.clone(),
        index,
    });
    state.command_history.execute(cmd, &mut state.ruleset);

    state.deleting_id = None;
    state.mark_profile_dirty();

    // Audit log with proper completion tracking
    super::audit_task(async move {
        audit::log_rule_deleted(enable_event_log, &rule_clone.label).await;
    })
}

/// Handles drag-and-drop reordering of rules
pub(crate) fn handle_rule_dropped(state: &mut State, dropped_id: Uuid) -> Task<Message> {
    let Some(drag_id) = state.dragged_rule_id else {
        return Task::none();
    };

    if drag_id == dropped_id {
        state.clear_drag_state();
        return Task::none();
    }

    // Find indices
    let Some(old_index) = state.ruleset.rules.iter().position(|r| r.id == drag_id) else {
        state.clear_drag_state();
        return Task::none();
    };

    let Some(new_index) = state.ruleset.rules.iter().position(|r| r.id == dropped_id) else {
        state.clear_drag_state();
        return Task::none();
    };

    // Execute command
    let cmd = Box::new(ReorderRuleCommand {
        rule_id: drag_id,
        old_index,
        new_index,
    });
    state.command_history.execute(cmd, &mut state.ruleset);

    state.clear_drag_state();
    state.mark_profile_dirty();

    // Audit log
    if state.enable_event_log {
        let rule_label = state
            .ruleset
            .rules
            .iter()
            .find(|r| r.id == drag_id)
            .map_or_default(|r| r.label.clone());

        let direction = if new_index > old_index { "down" } else { "up" };
        let enable_event_log = state.enable_event_log;

        super::audit_task(async move {
            audit::log_rules_reordered(enable_event_log, &rule_label, direction).await;
        })
    } else {
        Task::none()
    }
}

// ============================================================================
// Form field handlers
//
// These handlers update individual form fields as the user types.
// They use the safe pattern from CLAUDE.md Section 13 to catch UI state bugs.
// ============================================================================

/// Runs `edit` on the open rule form.
///
/// Field messages only come from the form's widgets, so a missing form means
/// a UI state bug: it is logged (safe pattern from CLAUDE.md Section 13), not
/// a panic.
fn with_form(state: &mut State, message: &str, edit: impl FnOnce(&mut RuleForm)) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "{message} sent without active form. This indicates a UI state management bug."
        );
        return;
    };
    edit(form);
}

pub(crate) fn handle_rule_form_label_changed(state: &mut State, value: String) {
    with_form(state, "RuleFormLabelChanged", |form| {
        form.label = value;
    });
}

pub(crate) fn handle_rule_form_protocol_changed(state: &mut State, protocol: Protocol) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormProtocolChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.protocol = protocol;

    // Clear ports for protocols the form shows as "Not applicable" (ICMP
    // variants, Any): hidden ports would otherwise be saved and rejected.
    if !protocol_supports_ports(protocol) {
        form.ports.clear();
        form.refresh_display();
    }

    // Reset a reject type the new protocol can't use (TCP Reset off pure TCP),
    // so the form never gets stuck on an error for a hidden choice.
    if !reject_type_valid_for_protocol(form.reject_type, protocol) {
        form.reject_type = RejectType::Default;
    }

    // Re-check only if errors are already shown, so they clear as soon as fixed
    if state.form_errors.is_some() {
        state.form_errors = form.validate();
    }
}

pub(crate) fn handle_rule_form_interface_changed(state: &mut State, value: String) {
    with_form(state, "RuleFormInterfaceChanged", |form| {
        form.interface = value;
    });
}

pub(crate) fn handle_rule_form_chain_changed(state: &mut State, chain: Chain) {
    with_form(state, "RuleFormChainChanged", |form| {
        form.chain = chain;
    });
}

pub(crate) fn handle_rule_form_toggle_advanced(state: &mut State, show: bool) {
    with_form(state, "RuleFormToggleAdvanced", |form| {
        form.show_advanced = show;
    });
}

pub(crate) fn handle_rule_form_action_changed(
    state: &mut State,
    action: crate::core::firewall::Action,
) {
    with_form(state, "RuleFormActionChanged", |form| {
        form.action = action;
    });
}

pub(crate) fn handle_rule_form_toggle_rate_limit(state: &mut State, enabled: bool) {
    with_form(state, "RuleFormToggleRateLimit", |form| {
        form.rate_limit_enabled = enabled;
    });
}

pub(crate) fn handle_rule_form_rate_limit_count_changed(state: &mut State, value: String) {
    with_form(state, "RuleFormRateLimitCountChanged", |form| {
        form.rate_limit_count = value;
    });
}

pub(crate) fn handle_rule_form_rate_limit_unit_changed(
    state: &mut State,
    unit: crate::core::firewall::TimeUnit,
) {
    with_form(state, "RuleFormRateLimitUnitChanged", |form| {
        form.rate_limit_unit = unit;
    });
}

pub(crate) fn handle_rule_form_connection_limit_changed(state: &mut State, value: String) {
    with_form(state, "RuleFormConnectionLimitChanged", |form| {
        form.connection_limit = value;
    });
}

// ============================================================================
// Search and filtering
// ============================================================================

pub(crate) fn handle_rule_search_changed(state: &mut State, value: &str) {
    value.clone_into(&mut state.rule_search);
    state.rule_search_lowercase = value.to_lowercase();
    state.update_filter_cache();
}

/// Selects the tag filter ("All" clears it). The typed search is kept: the
/// two filters combine.
pub(crate) fn handle_filter_by_tag(state: &mut State, tag: Option<Arc<String>>) {
    state.filter_tag = tag;
    state.update_filter_cache();
}

// ============================================================================
// Drag and drop state
// ============================================================================

pub(crate) fn handle_rule_drag_start(state: &mut State, id: Uuid) {
    state.dragged_rule_id = Some(id);
    state.hovered_drop_target_id = None;
}

pub(crate) fn handle_rule_hover_start(state: &mut State, id: Uuid) {
    // Guard: Don't update if already hovering this target (prevents redundant rebuilds)
    if state.hovered_drop_target_id == Some(id) {
        return;
    }

    // Debounce: Set as pending instead of immediately updating
    // This prevents rapid view rebuilds when mouse moves quickly across cards
    // The pending hover is processed in the subscription tick (every 16ms)
    state.hover_pending = Some((id, std::time::Instant::now()));
}

pub(crate) fn handle_rule_hover_end(state: &mut State) {
    // Clear both pending and active hover state
    state.hover_pending = None;
    state.hovered_drop_target_id = None;
}

/// Process pending hover target after debounce delay.
/// This is called from the subscription tick (every 16ms) when `hover_pending` is Some.
pub(crate) fn handle_check_hover_pending(state: &mut State) {
    const HOVER_DEBOUNCE_MS: u128 = 16; // ~1 frame at 60 FPS

    if let Some((pending_id, timestamp)) = state.hover_pending {
        // Only update if enough time has passed since the hover started
        if timestamp.elapsed().as_millis() >= HOVER_DEBOUNCE_MS {
            // Guard: Only update if it's different from current hover target
            if state.hovered_drop_target_id != Some(pending_id) {
                state.hovered_drop_target_id = Some(pending_id);
            }
            state.hover_pending = None;
        }
    }
}

// ============================================================================
// Helper modal handlers
// ============================================================================

use crate::app::{HelperType, RuleFormHelper};
use crate::core::firewall::RejectType;

/// Most tags a rule can have.
const MAX_TAGS: usize = 10;

/// Opens the helper for a multi-value field and focuses its input.
pub(crate) fn handle_open_helper(state: &mut State, helper_type: HelperType) -> Task<Message> {
    if state.rule_form.is_none() {
        return Task::none();
    }
    state.rule_form_helper = Some(RuleFormHelper {
        helper_type: Some(helper_type),
        ..RuleFormHelper::default()
    });
    crate::app::focus::focus_input(crate::app::focus::HELPER_INPUT)
}

/// Handles "Done" (and Escape) in the helper.
///
/// A value still in the input is added first: dropping it would leave the
/// field empty, which means "all ports" / "any address", so the rule would
/// silently match more than the user typed. If it can't be added, the
/// helper stays open with the reason; clearing the input closes it.
pub(crate) fn handle_close_helper(state: &mut State) {
    if add_helper_value(state) == HelperAdd::Rejected {
        if let Some(helper) = &mut state.rule_form_helper
            && let Some(error) = &mut helper.error
        {
            error.push_str(" Fix it, or clear the field to close.");
        }
        return;
    }
    state.rule_form_helper = None;
}

pub(crate) fn handle_helper_input_changed(state: &mut State, value: String) {
    let Some(helper) = &mut state.rule_form_helper else {
        return;
    };
    helper.input = value;
    helper.error = None;
    helper.notice = None;
}

/// What adding the helper's typed value did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelperAdd {
    /// Nothing was typed (or no helper is open)
    Empty,
    /// Every typed value is in the list now (added, or already there)
    Done,
    /// Something could not be added; the helper's `error` says why
    Rejected,
}

/// Handles "+" and Enter in the helper.
pub(crate) fn handle_helper_add_value(state: &mut State) {
    let _ = add_helper_value(state);
}

/// Adds the helper's typed value(s) to the form field it edits.
///
/// Comma-separated input adds several values at once (ports and tags).
/// Values already in the list are skipped with a notice; on success the
/// input is cleared.
fn add_helper_value(state: &mut State) -> HelperAdd {
    let (Some(form), Some(helper)) = (&mut state.rule_form, &mut state.rule_form_helper) else {
        return HelperAdd::Empty;
    };
    let Some(helper_type) = helper.helper_type else {
        return HelperAdd::Empty;
    };
    let input = helper.input.trim().to_string();
    if input.is_empty() {
        return HelperAdd::Empty;
    }

    let outcome = match helper_type {
        HelperType::Ports => add_ports(&mut form.ports, &input),
        HelperType::SourceAddresses => add_address(&mut form.sources, &input),
        HelperType::DestinationAddresses => add_address(&mut form.destinations, &input),
        HelperType::Tags => add_tags(&mut form.tags, &input),
    };
    form.refresh_display();

    let added = outcome.error.is_none();
    helper.error = outcome.error;
    helper.notice = outcome.notice;
    if added {
        helper.input.clear();
        HelperAdd::Done
    } else {
        HelperAdd::Rejected
    }
}

/// Feedback of one helper add.
#[derive(Debug, Default)]
struct AddFeedback {
    error: Option<String>,
    notice: Option<String>,
}

/// "1 port" / "3 ports"
fn count_noun(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {plural}")
    }
}

/// Adds a port, a range, or a comma-separated list of them.
fn add_ports(ports: &mut Vec<crate::core::firewall::PortEntry>, input: &str) -> AddFeedback {
    let (entries, errors) = validators::parse_bulk_ports(input);
    let mut added = 0;
    let mut duplicates = 0;
    for entry in entries {
        if ports.contains(&entry) {
            duplicates += 1;
        } else {
            ports.push(entry);
            added += 1;
        }
    }
    if let Some((value, reason)) = errors.first() {
        let prefix = if added > 0 {
            format!("Added {}; ", count_noun(added, "port", "ports"))
        } else {
            String::new()
        };
        return AddFeedback {
            error: Some(format!("{prefix}'{value}': {reason}.")),
            notice: None,
        };
    }
    let notice = match (added, duplicates) {
        (_, 0) => None,
        (0, _) => Some("Already in the list".to_string()),
        (added, duplicates) => Some(format!(
            "Added {} ({} already in the list)",
            count_noun(added, "port", "ports"),
            duplicates
        )),
    };
    AddFeedback {
        error: None,
        notice,
    }
}

/// Adds one IP address or CIDR block.
fn add_address(addresses: &mut Vec<ipnetwork::IpNetwork>, input: &str) -> AddFeedback {
    match input.parse::<ipnetwork::IpNetwork>() {
        Ok(ip) if addresses.contains(&ip) => AddFeedback {
            error: None,
            notice: Some("Already in the list".to_string()),
        },
        Ok(ip) => {
            addresses.push(ip);
            AddFeedback::default()
        }
        Err(_) => AddFeedback {
            error: Some("Invalid IP/CIDR (e.g., 192.168.1.0/24).".to_string()),
            notice: None,
        },
    }
}

/// Adds one tag, or several separated by commas. Characters a tag can't
/// hold are removed, and the user is told.
fn add_tags(tags: &mut Vec<String>, input: &str) -> AddFeedback {
    let mut feedback = AddFeedback::default();
    let mut changed = Vec::new();
    for part in input.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let tag = validators::sanitize_label(part);
        if tag.is_empty() {
            feedback.error = Some(format!(
                "'{part}' has no usable characters (letters, digits, space, - _ . :)."
            ));
            break;
        }
        if tags.contains(&tag) {
            continue;
        }
        if tags.len() >= MAX_TAGS {
            feedback.error = Some(format!("Maximum {MAX_TAGS} tags allowed."));
            break;
        }
        if tag != part {
            changed.push(tag.clone());
        }
        tags.push(tag);
    }
    if !changed.is_empty() {
        feedback.notice = Some(format!(
            "Unsupported characters were removed: added as '{}'",
            changed.join("', '")
        ));
    }
    feedback
}

pub(crate) fn handle_helper_remove_value(state: &mut State, index: usize) {
    let (Some(form), Some(helper)) = (&mut state.rule_form, &state.rule_form_helper) else {
        return;
    };

    let Some(helper_type) = helper.helper_type else {
        return;
    };

    match helper_type {
        HelperType::Ports => {
            if index < form.ports.len() {
                form.ports.remove(index);
            }
        }
        HelperType::SourceAddresses => {
            if index < form.sources.len() {
                form.sources.remove(index);
            }
        }
        HelperType::DestinationAddresses => {
            if index < form.destinations.len() {
                form.destinations.remove(index);
            }
        }
        HelperType::Tags => {
            if index < form.tags.len() {
                form.tags.remove(index);
            }
        }
    }
    form.refresh_display();
}

// ============================================================================
// New rule form field handlers (backend features from additional_nft.md)
// ============================================================================

pub(crate) fn handle_rule_form_output_interface_changed(state: &mut State, value: String) {
    with_form(state, "RuleFormOutputInterfaceChanged", |form| {
        form.output_interface = value;
    });
}

pub(crate) fn handle_rule_form_reject_type_changed(state: &mut State, reject_type: RejectType) {
    with_form(state, "RuleFormRejectTypeChanged", |form| {
        form.reject_type = reject_type;
    });
}

pub(crate) fn handle_rule_form_rate_limit_burst_changed(state: &mut State, value: String) {
    with_form(state, "RuleFormRateLimitBurstChanged", |form| {
        form.rate_limit_burst = value;
    });
}

pub(crate) fn handle_rule_form_rate_limit_per_source_toggled(state: &mut State, enabled: bool) {
    with_form(state, "RuleFormRateLimitPerSourceToggled", |form| {
        form.rate_limit_per_source = enabled;
    });
}

pub(crate) fn handle_rule_form_connection_limit_per_source_toggled(
    state: &mut State,
    enabled: bool,
) {
    with_form(state, "RuleFormConnectionLimitPerSourceToggled", |form| {
        form.connection_limit_per_source = enabled;
    });
}

pub(crate) fn handle_rule_form_log_enabled_toggled(state: &mut State, enabled: bool) {
    with_form(state, "RuleFormLogEnabledToggled", |form| {
        form.log_enabled = enabled;
    });
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::handlers::test_utils::create_test_state;

    #[test]
    fn test_handle_add_rule_clicked() {
        let mut state = create_test_state();
        let _ = handle_add_rule_clicked(&mut state);
        assert!(state.rule_form.is_some());
        assert_eq!(state.rule_form.as_ref().unwrap().label, "");
    }

    #[test]
    fn test_handle_cancel_rule_form() {
        let mut state = create_test_state();
        state.rule_form = Some(RuleForm::default());
        handle_cancel_rule_form(&mut state);
        assert!(state.rule_form.is_none());
    }

    #[test]
    fn test_edit_preserves_enabled_and_created_at() {
        let mut state = create_test_state();
        let mut rule = crate::core::test_helpers::create_test_rule("SSH", Some(22));
        rule.enabled = false;
        rule.created_at = jiff::Timestamp::UNIX_EPOCH;
        let id = rule.id;
        state.ruleset.rules.push(rule);

        let _ = handle_edit_rule_clicked(&mut state, id);
        handle_rule_form_label_changed(&mut state, "SSH renamed".to_string());
        let _ = handle_save_rule_form(&mut state);

        let edited = &state.ruleset.rules[0];
        assert_eq!(edited.label, "SSH renamed");
        assert!(
            !edited.enabled,
            "editing must not re-enable a disabled rule"
        );
        assert_eq!(edited.created_at, jiff::Timestamp::UNIX_EPOCH);
        assert_eq!(edited.id, id);
    }

    #[test]
    fn test_protocol_change_clears_hidden_fields() {
        let mut state = create_test_state();
        state.rule_form = Some(RuleForm {
            ports: vec![crate::core::firewall::PortEntry::single(22)],
            action: crate::core::firewall::Action::Reject,
            reject_type: RejectType::TcpReset,
            ..RuleForm::default()
        });
        handle_rule_form_protocol_changed(&mut state, Protocol::TcpAndUdp);
        let form = state.rule_form.as_ref().unwrap();
        assert_eq!(form.reject_type, RejectType::Default, "no stuck TCP Reset");
        assert_eq!(form.ports.len(), 1);
        handle_rule_form_protocol_changed(&mut state, Protocol::IcmpBoth);
        assert_eq!(state.rule_form.as_ref().unwrap().ports.len(), 0);
    }

    #[test]
    fn test_editing_invalid_loaded_rule_shows_errors() {
        let mut state = create_test_state();
        let mut rule = crate::core::test_helpers::create_test_rule("Zero", Some(0));
        rule.rebuild_caches();
        let id = rule.id;
        state.ruleset.rules.push(rule);
        let _ = handle_edit_rule_clicked(&mut state, id);
        assert!(state.form_errors.as_ref().unwrap().port.is_some());
        // Saving is refused until fixed
        let _ = handle_save_rule_form(&mut state);
        assert!(state.rule_form.is_some());
    }

    #[test]
    fn test_saving_or_closing_the_form_clears_its_helper() {
        let helper = || crate::app::RuleFormHelper {
            helper_type: Some(HelperType::Tags),
            input: "web".into(),
            ..Default::default()
        };
        let mut state = create_test_state();
        let _ = handle_add_rule_clicked(&mut state);
        state.rule_form_helper = Some(helper());
        let _ = handle_save_rule_form(&mut state);
        assert!(state.rule_form.is_none(), "saved");
        assert!(
            state.rule_form_helper.is_none(),
            "helper closed with the form"
        );

        let _ = handle_add_rule_clicked(&mut state);
        state.rule_form_helper = Some(helper());
        handle_cancel_rule_form(&mut state);
        assert!(state.rule_form_helper.is_none());

        // A stale helper never reappears on the next form
        state.rule_form_helper = Some(helper());
        let _ = handle_add_rule_clicked(&mut state);
        assert!(state.rule_form_helper.is_none());
    }

    #[test]
    fn test_form_field_handler_without_form() {
        let mut state = create_test_state();
        state.rule_form = None;

        // Should not panic, should log error instead
        handle_rule_form_label_changed(&mut state, "Test".to_string());
        assert!(state.rule_form.is_none());
    }

    #[test]
    fn test_form_field_handler_with_form() {
        let mut state = create_test_state();
        state.rule_form = Some(RuleForm::default());

        handle_rule_form_label_changed(&mut state, "Test Label".to_string());
        assert_eq!(state.rule_form.as_ref().unwrap().label, "Test Label");
    }

    // ------------------------------------------------------------------
    // Helper: commit on close, feedback, tags; discard prompt; edit lock
    // ------------------------------------------------------------------

    fn open_form_with_helper(state: &mut State, helper_type: HelperType) {
        let _ = handle_add_rule_clicked(state);
        let _ = handle_open_helper(state, helper_type);
    }

    fn type_in_helper(state: &mut State, text: &str) {
        handle_helper_input_changed(state, text.to_string());
    }

    fn helper(state: &State) -> &RuleFormHelper {
        state.rule_form_helper.as_ref().expect("helper open")
    }

    /// H1: "Done" (or Escape) with a typed but not yet added value adds it.
    /// Dropping it would leave the list empty, i.e. "all ports" / "any
    /// address": the rule would silently match more than the user typed.
    #[test]
    fn test_helper_done_commits_the_typed_value() {
        let mut state = create_test_state();
        open_form_with_helper(&mut state, HelperType::Ports);
        type_in_helper(&mut state, "22");
        handle_close_helper(&mut state);
        assert!(state.rule_form_helper.is_none(), "closed");
        let form = state.rule_form.as_ref().unwrap();
        assert_eq!(
            form.ports,
            vec![crate::core::firewall::PortEntry::single(22)]
        );
        assert_eq!(form.display.ports_summary, "Port 22", "summary cached");

        for (helper_type, typed) in [
            (HelperType::SourceAddresses, "10.0.0.0/8"),
            (HelperType::DestinationAddresses, "192.0.2.1"),
        ] {
            let _ = handle_open_helper(&mut state, helper_type);
            type_in_helper(&mut state, typed);
            // Escape sends the same message as Done
            let _ = state.update(Message::CloseHelper);
            assert!(state.rule_form_helper.is_none());
        }
        let form = state.rule_form.as_ref().unwrap();
        assert_eq!(form.sources.len(), 1);
        assert_eq!(form.destinations.len(), 1);
        assert_eq!(form.display.sources_summary, "10.0.0.0/8");
    }

    #[test]
    fn test_helper_done_with_an_invalid_value_stays_open() {
        let mut state = create_test_state();
        open_form_with_helper(&mut state, HelperType::Ports);
        type_in_helper(&mut state, "99999");
        handle_close_helper(&mut state);
        let error = helper(&state).error.clone().expect("an error");
        assert!(error.contains("clear the field to close"), "{error}");
        assert_eq!(state.rule_form.as_ref().unwrap().ports.len(), 0);

        // Partly valid bulk input: the good ports are added, it stays open
        type_in_helper(&mut state, "80, 443, nope");
        handle_close_helper(&mut state);
        assert!(state.rule_form_helper.is_some());
        assert_eq!(state.rule_form.as_ref().unwrap().ports.len(), 2);

        // Clearing the input closes it
        type_in_helper(&mut state, "");
        handle_close_helper(&mut state);
        assert!(state.rule_form_helper.is_none());
    }

    #[test]
    fn test_helper_duplicates_are_a_notice_not_an_error() {
        let mut state = create_test_state();
        open_form_with_helper(&mut state, HelperType::Ports);
        type_in_helper(&mut state, "22");
        handle_helper_add_value(&mut state);
        type_in_helper(&mut state, "22, 80");
        handle_helper_add_value(&mut state);
        let h = helper(&state);
        assert!(h.error.is_none());
        assert_eq!(
            h.notice.as_deref(),
            Some("Added 1 port (1 already in the list)")
        );
        assert_eq!(h.input, "");
        // A duplicate typed when closing closes (nothing would be lost)
        type_in_helper(&mut state, "80");
        handle_close_helper(&mut state);
        assert!(state.rule_form_helper.is_none());
        assert_eq!(
            state.rule_form.as_ref().unwrap().display.port_items,
            vec!["22".to_string(), "80".to_string()]
        );
    }

    #[test]
    fn test_tags_split_on_commas_and_say_what_was_changed() {
        let mut state = create_test_state();
        open_form_with_helper(&mut state, HelperType::Tags);
        type_in_helper(&mut state, "web-server, production");
        handle_helper_add_value(&mut state);
        let form = state.rule_form.as_ref().unwrap();
        assert_eq!(form.tags, vec!["web-server", "production"]);
        assert_eq!(form.display.tags_summary, "2 tags");
        assert!(helper(&state).notice.is_none());

        type_in_helper(&mut state, "db$prod");
        handle_helper_add_value(&mut state);
        let h = helper(&state);
        assert!(h.error.is_none());
        assert!(h.notice.as_deref().unwrap().contains("'dbprod'"), "{h:?}");

        type_in_helper(&mut state, "$$$");
        handle_helper_add_value(&mut state);
        assert!(helper(&state).error.is_some());
        assert_eq!(state.rule_form.as_ref().unwrap().tags.len(), 3);

        // Long tags are cut for the chips (cached, not formatted in view())
        type_in_helper(&mut state, "a-very-long-tag-name-here");
        handle_helper_add_value(&mut state);
        let items = &state.rule_form.as_ref().unwrap().display.tag_items;
        assert_eq!(items.last().map(String::as_str), Some("a-very-long-tag…"));
    }

    #[test]
    fn test_removing_a_helper_value_refreshes_the_summary() {
        let mut state = create_test_state();
        open_form_with_helper(&mut state, HelperType::Ports);
        type_in_helper(&mut state, "22, 80");
        handle_helper_add_value(&mut state);
        assert_eq!(
            state.rule_form.as_ref().unwrap().display.ports_summary,
            "2 ports configured"
        );
        handle_helper_remove_value(&mut state, 0);
        assert_eq!(
            state.rule_form.as_ref().unwrap().display.ports_summary,
            "Port 80"
        );
    }

    #[test]
    fn test_cancel_asks_before_discarding_changes() {
        let mut state = create_test_state();
        let _ = handle_add_rule_clicked(&mut state);
        // Unchanged (showing the advanced options is not a change): closes
        handle_rule_form_toggle_advanced(&mut state, true);
        handle_cancel_rule_form(&mut state);
        assert!(state.rule_form.is_none());

        let _ = handle_add_rule_clicked(&mut state);
        handle_rule_form_label_changed(&mut state, "Web".into());
        handle_cancel_rule_form(&mut state);
        assert!(state.rule_form.is_some(), "asks first");
        assert!(state.confirm_discard_form);
        // Escape in the prompt keeps editing
        let _ = state.update(Message::KeepEditingRuleForm);
        assert!(!state.confirm_discard_form);
        assert_eq!(state.rule_form.as_ref().unwrap().label, "Web");
        handle_cancel_rule_form(&mut state);
        let _ = state.update(Message::DiscardRuleForm);
        assert!(state.rule_form.is_none());
        assert!(!state.confirm_discard_form);
        assert!(state.rule_form_initial.is_none());
    }

    #[test]
    fn test_editing_an_unchanged_rule_closes_without_asking() {
        let mut state = create_test_state();
        let rule = crate::core::test_helpers::create_test_rule("SSH", Some(22));
        let id = rule.id;
        state.ruleset.rules.push(rule);
        state.mark_profile_dirty();
        let _ = handle_edit_rule_clicked(&mut state, id);
        handle_cancel_rule_form(&mut state);
        assert!(state.rule_form.is_none());
    }

    /// M2: while the apply flow owns the ruleset (no dialog shown during
    /// Verifying/Confirming/...), the form can't be opened: it could not be
    /// saved, and would hide "Commit Changes?".
    #[test]
    fn test_add_and_edit_are_refused_while_edits_are_locked() {
        let mut state = create_test_state();
        let rule = crate::core::test_helpers::create_test_rule("SSH", Some(22));
        let id = rule.id;
        state.ruleset.rules.push(rule);
        state.mark_profile_dirty();
        for status in [
            crate::app::AppStatus::Verifying,
            crate::app::AppStatus::Confirming,
            crate::app::AppStatus::Reverting,
            crate::app::AppStatus::SavingToSystem,
        ] {
            state.status = status;
            let _ = state.update(Message::AddRuleClicked);
            let _ = state.update(Message::EditRuleClicked(id));
            assert!(state.rule_form.is_none());
            assert!(
                state
                    .banners
                    .back()
                    .is_some_and(|b| b.message.contains("can't be changed"))
            );
        }
        state.status = crate::app::AppStatus::Idle;
        let _ = state.update(Message::EditRuleClicked(id));
        assert!(state.rule_form.is_some());
    }

    #[test]
    fn test_tag_filter_keeps_the_typed_search() {
        let mut state = create_test_state();
        let mut rule = crate::core::test_helpers::create_test_rule("SSH", Some(22));
        rule.tags = vec!["admin".into()];
        rule.rebuild_caches();
        state.ruleset.rules.push(rule);
        state.mark_profile_dirty();
        handle_rule_search_changed(&mut state, "ss");
        let admin = state.cached_all_tags.first().cloned();
        handle_filter_by_tag(&mut state, admin.clone());
        handle_filter_by_tag(&mut state, None);
        assert_eq!(state.rule_search, "ss", "\"All\" keeps the search");
        // The selected tag disappearing keeps it too
        handle_filter_by_tag(&mut state, admin);
        state.ruleset.rules[0].tags.clear();
        state.ruleset.rules[0].rebuild_caches();
        state.mark_profile_dirty();
        assert!(state.filter_tag.is_none());
        assert_eq!(state.rule_search, "ss");
    }

    // ── Rule templates (S6) ───────────────────────────────────────────

    fn menu_for(state: &mut State, interfaces: &[&str]) {
        let names: Vec<String> = interfaces.iter().map(ToString::to_string).collect();
        state.template_menu = Some(crate::app::templates::TemplateMenu::for_interfaces(&names));
    }

    /// Choosing a template adds its rules as ordinary, editable rules in one
    /// undoable step and closes the menu.
    #[test]
    fn test_template_inserts_ordinary_rules_undoably() {
        let mut state = create_test_state();
        menu_for(&mut state, &["eth0", "virbr0", "tailscale0"]);
        let titles: Vec<String> = state
            .template_menu
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .map(|e| e.title.clone())
            .collect();
        assert_eq!(titles.len(), 3, "{titles:?}");
        let vm = titles
            .iter()
            .position(|t| t.starts_with("VM guests"))
            .unwrap();

        let _ = state.update(Message::AddTemplate(vm));
        assert!(state.template_menu.is_none(), "closed");
        assert_eq!(state.ruleset.rules.len(), 2, "UDP 53/67 and TCP 53");
        assert!(
            state
                .ruleset
                .rules
                .iter()
                .all(|r| r.interface.as_deref() == Some("virbr0") && r.chain == Chain::Input)
        );
        assert!(state.profile_dirty);
        assert!(state.banners.back().unwrap().message.contains("VM guests"));

        // Ordinary rules: they open in the editor like any other
        let id = state.ruleset.rules[0].id;
        let _ = state.update(Message::EditRuleClicked(id));
        assert!(state.rule_form.is_some());
        let _ = state.update(Message::CancelRuleForm);

        let _ = state.update(Message::Undo);
        assert_eq!(state.ruleset.rules.len(), 0, "one step");
        let _ = state.update(Message::Redo);
        assert_eq!(state.ruleset.rules.len(), 2);
    }

    #[test]
    fn test_template_menu_closed_or_stale_index_does_nothing() {
        let mut state = create_test_state();
        let _ = state.update(Message::AddTemplate(0));
        assert_eq!(state.ruleset.rules.len(), 0);
        menu_for(&mut state, &["eth0"]);
        assert_eq!(state.template_menu.as_ref().unwrap().entries.len(), 0);
        let _ = state.update(Message::AddTemplate(0));
        assert_eq!(state.ruleset.rules.len(), 0);
        assert!(!state.command_history.can_undo());

        // Opening it reads the interfaces; closing drops the entries;
        // Escape closes it too
        let _ = state.update(Message::ToggleTemplateMenu(true));
        assert!(state.template_menu.is_some());
        let _ = state.update(Message::ToggleTemplateMenu(false));
        assert!(state.template_menu.is_none());
        menu_for(&mut state, &["tailscale0"]);
        assert_eq!(
            crate::app::handlers::ui_state::escape_message(&state).map(|m| format!("{m:?}")),
            Some("ToggleTemplateMenu(false)".to_string())
        );
    }

    /// While an apply owns the ruleset, templates are refused like edits.
    #[test]
    fn test_template_refused_while_edits_are_locked() {
        let mut state = create_test_state();
        menu_for(&mut state, &["tailscale0"]);
        state.status = crate::app::AppStatus::AwaitingApply;
        let _ = state.update(Message::AddTemplate(0));
        assert_eq!(state.ruleset.rules.len(), 0);
        let _ = state.update(Message::ToggleTemplateMenu(true));
        assert!(
            state
                .template_menu
                .as_ref()
                .is_some_and(|m| m.entries.len() == 2),
            "not reopened (rebuilt) while locked"
        );
    }
}
