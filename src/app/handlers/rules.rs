//! Rule CRUD operations and form handling
//!
//! Handles all message variants related to firewall rule management:
//! - Adding, editing, deleting rules
//! - Toggling rules enabled/disabled
//! - Drag-and-drop reordering
//! - Form field updates (with UI state validation)
//! - Search and tag filtering

#![allow(dead_code)]

use crate::app::{Message, RuleForm, State};
use crate::audit;
use crate::command::{
    AddRuleCommand, DeleteRuleCommand, EditRuleCommand, ReorderRuleCommand, ToggleRuleCommand,
};
use crate::core::firewall::{Chain, Protocol, Rule};
use crate::validators;
use chrono::Utc;
use iced::Task;
use std::sync::Arc;
use uuid::Uuid;

/// Handles opening the "Add New Rule" form
pub(crate) fn handle_add_rule_clicked(state: &mut State) {
    state.rule_form = Some(RuleForm::default());
    state.form_errors = None;
}

/// Handles opening the "Edit Rule" form
pub(crate) fn handle_edit_rule_clicked(state: &mut State, id: Uuid) {
    if let Some(rule) = state.ruleset.rules.iter().find(|r| r.id == id) {
        // Create form from existing rule
        let has_advanced = rule.destination.is_some()
            || !matches!(rule.action, crate::core::firewall::Action::Accept)
            || rule.rate_limit.is_some()
            || rule.connection_limit > 0;

        state.rule_form = Some(RuleForm {
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
        state.form_errors = None;
    }
}

/// Handles canceling rule form (Add or Edit)
pub(crate) fn handle_cancel_rule_form(state: &mut State) {
    state.rule_form = None;
    state.form_errors = None;
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
        let (ports, source, errors) = form_ref.validate();
        if let Some(errs) = errors {
            state.form_errors = Some(errs);
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

        let sanitized_label = validators::sanitize_label(&form.label);
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
            id: form.id.unwrap_or_else(Uuid::new_v4),
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

        let is_edit = state.ruleset.rules.iter().any(|r| r.id == rule.id);
        let enable_event_log = state.enable_event_log;
        let label = rule.label.clone();
        let protocol = rule.protocol.to_string();
        let ports = rule.port_display.clone();

        if is_edit {
            // EDIT EXISTING RULE
            // Safe pattern from CLAUDE.md Section 13
            let Some(old_rule) = state.ruleset.rules.iter().find(|r| r.id == rule.id).cloned()
            else {
                tracing::error!(
                    "SaveRuleForm for non-existent rule ID: {}. \
                     This indicates a UI state desync bug.",
                    rule.id
                );
                state.form_errors = None;
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
        state.update_cached_text();
        state.form_errors = None;

        // Log rule change with proper completion tracking
        return Task::perform(
            async move {
                let port_str = if ports.is_empty() { None } else { Some(ports) };
                if is_edit {
                    audit::log_rule_modified(enable_event_log, &label, &protocol, port_str).await;
                } else {
                    audit::log_rule_created(enable_event_log, &label, &protocol, port_str).await;
                }
            },
            |_| Message::AuditLogWritten, // ← Fixed: was Message::Noop in old plan
        );
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
    state
        .command_history
        .execute(cmd, &mut state.ruleset);

    state.mark_profile_dirty();
    state.update_cached_text();

    // Audit log with proper completion tracking
    Task::perform(
        async move {
            audit::log_rule_toggled(enable_event_log, &label, !was_enabled).await;
        },
        |_| Message::AuditLogWritten, // ← Fixed: was Message::Noop in old plan
    )
}

/// Handles deleting a rule
pub(crate) fn handle_delete_rule(state: &mut State, id: Uuid) -> Task<Message> {
    let Some((index, rule)) = state
        .ruleset
        .rules
        .iter()
        .enumerate()
        .find(|(_, r)| r.id == id)
    else {
        state.deleting_id = None;
        return Task::none();
    };

    let rule_clone = rule.clone();
    let enable_event_log = state.enable_event_log;

    // Execute command
    let cmd = Box::new(DeleteRuleCommand {
        rule: rule_clone.clone(),
        index,
    });
    state
        .command_history
        .execute(cmd, &mut state.ruleset);

    state.deleting_id = None;
    state.mark_profile_dirty();
    state.update_cached_text();

    // Audit log with proper completion tracking
    Task::perform(
        async move {
            audit::log_rule_deleted(enable_event_log, &rule_clone.label).await;
        },
        |_| Message::AuditLogWritten, // ← Fixed: was Message::Noop in old plan
    )
}

/// Handles drag-and-drop reordering of rules
#[allow(dead_code)]
pub(crate) fn handle_rule_dropped(state: &mut State, dropped_id: Uuid) -> Task<Message> {
    let Some(drag_id) = state.dragged_rule_id else {
        return Task::none();
    };

    if drag_id == dropped_id {
        state.dragged_rule_id = None;
        state.hovered_drop_target_id = None;
        return Task::none();
    }

    // Find indices
    let Some(old_index) = state.ruleset.rules.iter().position(|r| r.id == drag_id) else {
        state.dragged_rule_id = None;
        state.hovered_drop_target_id = None;
        return Task::none();
    };

    let Some(new_index) = state.ruleset.rules.iter().position(|r| r.id == dropped_id) else {
        state.dragged_rule_id = None;
        state.hovered_drop_target_id = None;
        return Task::none();
    };

    // Execute command
    let cmd = Box::new(ReorderRuleCommand {
        rule_id: drag_id,
        old_index,
        new_index,
    });
    state
        .command_history
        .execute(cmd, &mut state.ruleset);

    state.dragged_rule_id = None;
    state.hovered_drop_target_id = None;
    state.mark_profile_dirty();
    state.update_cached_text();

    // Audit log
    if state.enable_event_log {
        let rule_label = state
            .ruleset
            .rules
            .iter()
            .find(|r| r.id == drag_id)
            .map(|r| r.label.clone())
            .unwrap_or_default();

        let direction = if new_index > old_index { "down" } else { "up" };
        let enable_event_log = state.enable_event_log;

        Task::perform(
            async move {
                audit::log_rules_reordered(enable_event_log, &rule_label, direction).await;
            },
            |_| Message::AuditLogWritten, // ← Fixed: was Message::Noop in old plan
        )
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

pub(crate) fn handle_rule_form_label_changed(state: &mut State, value: String) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormLabelChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.label = value;
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

    // Clear ports if switching to ICMP or Any (doesn't use ports)
    if matches!(
        protocol,
        Protocol::Icmp | Protocol::Icmpv6 | Protocol::Any
    ) {
        form.port_start.clear();
        form.port_end.clear();
    }
}

pub(crate) fn handle_rule_form_port_start_changed(state: &mut State, value: String) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormPortStartChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.port_start = value;
}

pub(crate) fn handle_rule_form_port_end_changed(state: &mut State, value: String) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormPortEndChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.port_end = value;
}

pub(crate) fn handle_rule_form_source_changed(state: &mut State, value: String) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormSourceChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.source = value;
}

pub(crate) fn handle_rule_form_interface_changed(state: &mut State, value: String) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormInterfaceChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.interface = value;
}

pub(crate) fn handle_rule_form_chain_changed(state: &mut State, chain: Chain) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormChainChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.chain = chain;
}

pub(crate) fn handle_rule_form_toggle_advanced(state: &mut State, show: bool) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormToggleAdvanced sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.show_advanced = show;
}

pub(crate) fn handle_rule_form_destination_changed(state: &mut State, value: String) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormDestinationChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.destination = value;
}

pub(crate) fn handle_rule_form_action_changed(
    state: &mut State,
    action: crate::core::firewall::Action,
) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormActionChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.action = action;
}

pub(crate) fn handle_rule_form_toggle_rate_limit(state: &mut State, enabled: bool) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormToggleRateLimit sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.rate_limit_enabled = enabled;
}

pub(crate) fn handle_rule_form_rate_limit_count_changed(state: &mut State, value: String) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormRateLimitCountChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.rate_limit_count = value;
}

pub(crate) fn handle_rule_form_rate_limit_unit_changed(
    state: &mut State,
    unit: crate::core::firewall::TimeUnit,
) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormRateLimitUnitChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.rate_limit_unit = unit;
}

pub(crate) fn handle_rule_form_connection_limit_changed(state: &mut State, value: String) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormConnectionLimitChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.connection_limit = value;
}

pub(crate) fn handle_rule_form_tag_input_changed(state: &mut State, value: String) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormTagInputChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.tag_input = value;
}

pub(crate) fn handle_rule_form_add_tag(state: &mut State) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormAddTag sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };

    let tag = validators::sanitize_label(form.tag_input.trim());
    if !tag.is_empty() && !form.tags.contains(&tag) && form.tags.len() < 10 {
        form.tags.push(tag);
        form.tag_input.clear();
    }
}

pub(crate) fn handle_rule_form_remove_tag(state: &mut State, tag: String) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormRemoveTag sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.tags.retain(|t| t != &tag);
}

// ============================================================================
// Search and filtering
// ============================================================================

pub(crate) fn handle_rule_search_changed(state: &mut State, value: String) {
    state.rule_search = value.clone();
    state.rule_search_lowercase = value.to_lowercase();
    state.update_filter_cache();
}

pub(crate) fn handle_filter_by_tag(state: &mut State, tag: Option<Arc<String>>) {
    state.filter_tag = tag;
    state.update_filter_cache();
}

// ============================================================================
// Drag and drop state
// ============================================================================

pub(crate) fn handle_rule_drag_start(state: &mut State, id: Uuid) {
    state.dragged_rule_id = Some(id);
}

pub(crate) fn handle_rule_hover_start(state: &mut State, id: Uuid) {
    state.hovered_drop_target_id = Some(id);
}

pub(crate) fn handle_rule_hover_end(state: &mut State) {
    state.hovered_drop_target_id = None;
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
        assert_eq!(
            state.rule_form.as_ref().unwrap().label,
            "Test Label"
        );
    }
}
