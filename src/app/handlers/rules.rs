//! Rule CRUD operations and form handling
//!
//! Handles all message variants related to firewall rule management:
//! - Adding, editing, deleting rules
//! - Toggling rules enabled/disabled
//! - Drag-and-drop reordering
//! - Form field updates (with UI state validation)
//! - Search and tag filtering

use crate::app::{Message, RuleForm, State};
use crate::audit;
use crate::command::{
    AddRuleCommand, DeleteRuleCommand, EditRuleCommand, ReorderRuleCommand, ToggleRuleCommand,
};
use crate::core::firewall::{Chain, MAX_RULES, Protocol};
use crate::core::rule_constraints::{protocol_supports_ports, reject_type_valid_for_protocol};
use crate::validators;
use chrono::Utc;
use iced::Task;
use std::sync::Arc;
use uuid::Uuid;

/// Refreshes the interface suggestions of the rule form's combo boxes.
///
/// Interfaces come and go (VPNs, containers, USB adapters), so the list is
/// rebuilt each time the form opens; listing interfaces is a cheap syscall.
fn refresh_interface_suggestions(state: &mut State) {
    let suggestions = crate::utils::build_interface_suggestions();
    state.output_interface_combo = iced::widget::combo_box::State::new(suggestions.clone());
    state.interface_combo = iced::widget::combo_box::State::new(suggestions);
}

/// Opens the rule form (closing any helper left from an earlier form).
fn open_rule_form(state: &mut State, form: RuleForm, errors: Option<crate::app::FormErrors>) {
    refresh_interface_suggestions(state);
    state.rule_form = Some(form);
    state.rule_form_helper = None;
    state.form_errors = errors;
}

/// Closes the rule form, its helper modal and its errors.
fn close_rule_form(state: &mut State) {
    state.rule_form = None;
    state.rule_form_helper = None;
    state.form_errors = None;
}

/// Handles opening the "Add New Rule" form
pub(crate) fn handle_add_rule_clicked(state: &mut State) {
    open_rule_form(state, RuleForm::default(), None);
}

/// Handles opening the "Edit Rule" form
pub(crate) fn handle_edit_rule_clicked(state: &mut State, id: Uuid) {
    if let Some(rule) = state.ruleset.rules.iter().find(|r| r.id == id) {
        let form = RuleForm::from_rule(rule);
        // Show why a loaded rule is invalid right away
        let errors = form.validate();
        open_rule_form(state, form, errors);
    }
}

/// Handles canceling rule form (Add or Edit)
pub(crate) fn handle_cancel_rule_form(state: &mut State) {
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
            existing.unwrap_or_else(|| (Uuid::new_v4(), true, Utc::now()));
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

pub(crate) fn handle_filter_by_tag(state: &mut State, tag: Option<Arc<String>>) {
    state.filter_tag = tag;
    if state.filter_tag.is_none() {
        state.rule_search.clear();
        state.rule_search_lowercase.clear();
    }
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

pub(crate) fn handle_open_helper(state: &mut State, helper_type: HelperType) {
    state.rule_form_helper = Some(RuleFormHelper {
        helper_type: Some(helper_type),
        input: String::new(),
        error: None,
    });
}

pub(crate) fn handle_close_helper(state: &mut State) {
    state.rule_form_helper = None;
}

pub(crate) fn handle_helper_input_changed(state: &mut State, value: String) {
    let Some(helper) = &mut state.rule_form_helper else {
        return;
    };
    helper.input = value;
    helper.error = None;
}

pub(crate) fn handle_helper_add_value(state: &mut State) {
    let (Some(form), Some(helper)) = (&mut state.rule_form, &mut state.rule_form_helper) else {
        return;
    };

    let Some(helper_type) = helper.helper_type else {
        return;
    };

    let input = helper.input.trim();
    if input.is_empty() {
        return;
    }

    match helper_type {
        HelperType::Ports => {
            // Support bulk paste: "22, 80, 443, 8000-8080"
            if input.contains(',') {
                let (entries, errors) = validators::parse_bulk_ports(input);
                let mut added = 0;
                let mut duplicates = 0;

                for entry in entries {
                    if form.ports.contains(&entry) {
                        duplicates += 1;
                    } else {
                        form.ports.push(entry);
                        added += 1;
                    }
                }

                if !errors.is_empty() {
                    helper.error = Some(format!(
                        "Added {} ports, {} errors: {}",
                        added,
                        errors.len(),
                        errors.first().map_or("", |(_, e)| e)
                    ));
                } else if duplicates > 0 {
                    helper.error = Some(format!(
                        "Added {added} ports ({duplicates} duplicates skipped)"
                    ));
                } else if added > 0 {
                    helper.input.clear();
                    helper.error = None;
                }
            } else {
                // Single port or range
                match validators::validate_port_entry(input) {
                    Ok(entry) => {
                        if form.ports.contains(&entry) {
                            helper.error = Some("Port already added".to_string());
                        } else {
                            form.ports.push(entry);
                            helper.input.clear();
                            helper.error = None;
                        }
                    }
                    Err(e) => {
                        helper.error = Some(e.to_string());
                    }
                }
            }
        }
        HelperType::SourceAddresses => match input.parse::<ipnetwork::IpNetwork>() {
            Ok(ip) => {
                if form.sources.contains(&ip) {
                    helper.error = Some("Address already added".to_string());
                } else {
                    form.sources.push(ip);
                    helper.input.clear();
                }
            }
            Err(_) => {
                helper.error = Some("Invalid IP/CIDR (e.g., 192.168.1.0/24)".to_string());
            }
        },
        HelperType::DestinationAddresses => match input.parse::<ipnetwork::IpNetwork>() {
            Ok(ip) => {
                if form.destinations.contains(&ip) {
                    helper.error = Some("Address already added".to_string());
                } else {
                    form.destinations.push(ip);
                    helper.input.clear();
                }
            }
            Err(_) => {
                helper.error = Some("Invalid IP/CIDR (e.g., 192.168.1.0/24)".to_string());
            }
        },
        HelperType::Tags => {
            let tag = validators::sanitize_label(input);
            if tag.is_empty() {
                helper.error = Some("Invalid tag".to_string());
            } else if form.tags.len() >= 10 {
                helper.error = Some("Maximum 10 tags allowed".to_string());
            } else if form.tags.contains(&tag) {
                helper.error = Some("Tag already added".to_string());
            } else {
                form.tags.push(tag);
                helper.input.clear();
            }
        }
    }
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
        handle_add_rule_clicked(&mut state);
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
        rule.created_at = chrono::DateTime::UNIX_EPOCH;
        let id = rule.id;
        state.ruleset.rules.push(rule);

        handle_edit_rule_clicked(&mut state, id);
        handle_rule_form_label_changed(&mut state, "SSH renamed".to_string());
        let _ = handle_save_rule_form(&mut state);

        let edited = &state.ruleset.rules[0];
        assert_eq!(edited.label, "SSH renamed");
        assert!(
            !edited.enabled,
            "editing must not re-enable a disabled rule"
        );
        assert_eq!(edited.created_at, chrono::DateTime::UNIX_EPOCH);
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
        handle_edit_rule_clicked(&mut state, id);
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
            error: None,
        };
        let mut state = create_test_state();
        handle_add_rule_clicked(&mut state);
        state.rule_form_helper = Some(helper());
        let _ = handle_save_rule_form(&mut state);
        assert!(state.rule_form.is_none(), "saved");
        assert!(
            state.rule_form_helper.is_none(),
            "helper closed with the form"
        );

        handle_add_rule_clicked(&mut state);
        state.rule_form_helper = Some(helper());
        handle_cancel_rule_form(&mut state);
        assert!(state.rule_form_helper.is_none());

        // A stale helper never reappears on the next form
        state.rule_form_helper = Some(helper());
        handle_add_rule_clicked(&mut state);
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
}
