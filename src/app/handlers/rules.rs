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
        let has_advanced = !rule.destinations.is_empty()
            || !matches!(rule.action, crate::core::firewall::Action::Accept)
            || rule.rate_limit.is_some()
            || rule.connection_limit > 0
            || rule.output_interface.is_some()
            || !matches!(rule.reject_type, crate::core::firewall::RejectType::Default)
            || rule.log_enabled;

        state.rule_form = Some(RuleForm {
            id: Some(rule.id),
            label: rule.label.clone(),
            protocol: rule.protocol,
            // Multi-value fields - clone directly
            ports: rule.ports.clone(),
            sources: rule.sources.clone(),
            destinations: rule.destinations.clone(),
            tags: rule.tags.clone(),
            // Single-value fields
            interface: rule.interface.clone().unwrap_or_default(),
            output_interface: rule.output_interface.clone().unwrap_or_default(),
            chain: rule.chain,
            action: rule.action,
            reject_type: rule.reject_type,
            // Rate limiting
            rate_limit_enabled: rule.rate_limit.is_some(),
            rate_limit_count: rule
                .rate_limit
                .as_ref()
                .map_or_else(String::new, |rl| rl.count.to_string()),
            rate_limit_unit: rule
                .rate_limit
                .as_ref()
                .map_or(crate::core::firewall::TimeUnit::Second, |rl| rl.unit),
            rate_limit_burst: rule
                .rate_limit
                .as_ref()
                .and_then(|rl| rl.burst)
                .map_or_else(String::new, |b| b.to_string()),
            // Connection limiting
            connection_limit: if rule.connection_limit > 0 {
                rule.connection_limit.to_string()
            } else {
                String::new()
            },
            // Per-rule logging
            log_enabled: rule.log_enabled,
            // UI state
            show_advanced: has_advanced,
        });
        state.form_errors = None;
    }
}

/// Handles canceling rule form (Add or Edit)
pub(crate) fn handle_cancel_rule_form(state: &mut State) {
    state.rule_form = None;
    state.rule_form_helper = None;
    state.form_errors = None;
    if state.status == crate::app::AppStatus::AwaitingApply {
        state.status = crate::app::AppStatus::Idle;
    }
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
        let output_interface = if form.output_interface.is_empty() {
            None
        } else {
            Some(form.output_interface)
        };

        // Parse rate limit with burst support
        let rate_limit = if form.rate_limit_enabled && !form.rate_limit_count.is_empty() {
            form.rate_limit_count.parse().ok().map(|count| {
                let burst = form.rate_limit_burst.parse::<u32>().ok().filter(|&b| b > 0);
                crate::core::firewall::RateLimit {
                    count,
                    unit: form.rate_limit_unit,
                    burst,
                }
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
            // Multi-value fields from form
            ports: form.ports,
            sources: form.sources,
            destinations: form.destinations,
            // Single-value fields
            interface,
            output_interface,
            chain: form.chain,
            enabled: true,
            created_at: Utc::now(),
            tags: form.tags,
            action: form.action,
            reject_type: form.reject_type,
            rate_limit,
            connection_limit,
            log_enabled: form.log_enabled,
            // Cached fields - will be populated by rebuild_caches()
            label_lowercase: String::new(),
            interface_lowercase: None,
            output_interface_lowercase: None,
            tags_lowercase: Vec::new(),
            protocol_lowercase: "",
            port_display: String::new(),
            sources_display: String::new(),
            destinations_display: String::new(),
            rate_limit_display: None,
            action_display: String::new(),
            interface_display: String::new(),
            log_prefix: String::new(),
            tags_truncated: Vec::new(),
            badge_display: String::new(),
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
            |()| Message::AuditLogWritten, // ← Fixed: was Message::Noop in old plan
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
    state.command_history.execute(cmd, &mut state.ruleset);

    state.mark_profile_dirty();

    // Audit log with proper completion tracking
    Task::perform(
        async move {
            audit::log_rule_toggled(enable_event_log, &label, !was_enabled).await;
        },
        |()| Message::AuditLogWritten, // ← Fixed: was Message::Noop in old plan
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
    state.command_history.execute(cmd, &mut state.ruleset);

    state.deleting_id = None;
    state.mark_profile_dirty();

    // Audit log with proper completion tracking
    Task::perform(
        async move {
            audit::log_rule_deleted(enable_event_log, &rule_clone.label).await;
        },
        |()| Message::AuditLogWritten, // ← Fixed: was Message::Noop in old plan
    )
}

/// Handles drag-and-drop reordering of rules
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
    state.command_history.execute(cmd, &mut state.ruleset);

    state.dragged_rule_id = None;
    state.hovered_drop_target_id = None;
    state.mark_profile_dirty();

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
            |()| Message::AuditLogWritten, // ← Fixed: was Message::Noop in old plan
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
    if matches!(protocol, Protocol::Icmp | Protocol::Icmpv6 | Protocol::Any) {
        form.ports.clear();
    }

    // TCP Reset reject type is only valid for TCP - auto-reset to Default
    if !matches!(protocol, Protocol::Tcp | Protocol::TcpAndUdp)
        && form.reject_type == RejectType::TcpReset
    {
        form.reject_type = RejectType::Default;
    }
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
    state.hovered_drop_target_id = Some(id);
}

pub(crate) fn handle_rule_hover_end(state: &mut State) {
    state.hovered_drop_target_id = None;
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
                    if !form.ports.contains(&entry) {
                        form.ports.push(entry);
                        added += 1;
                    } else {
                        duplicates += 1;
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
                        "Added {} ports ({} duplicates skipped)",
                        added, duplicates
                    ));
                } else if added > 0 {
                    helper.input.clear();
                    helper.error = None;
                }
            } else {
                // Single port or range
                match validators::validate_port_entry(input) {
                    Ok(entry) => {
                        if !form.ports.contains(&entry) {
                            form.ports.push(entry);
                            helper.input.clear();
                            helper.error = None;
                        } else {
                            helper.error = Some("Port already added".to_string());
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
                if !form.sources.contains(&ip) {
                    form.sources.push(ip);
                    helper.input.clear();
                } else {
                    helper.error = Some("Address already added".to_string());
                }
            }
            Err(_) => {
                helper.error = Some("Invalid IP/CIDR (e.g., 192.168.1.0/24)".to_string());
            }
        },
        HelperType::DestinationAddresses => match input.parse::<ipnetwork::IpNetwork>() {
            Ok(ip) => {
                if !form.destinations.contains(&ip) {
                    form.destinations.push(ip);
                    helper.input.clear();
                } else {
                    helper.error = Some("Address already added".to_string());
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
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormOutputInterfaceChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.output_interface = value;
}

pub(crate) fn handle_rule_form_reject_type_changed(state: &mut State, reject_type: RejectType) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormRejectTypeChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.reject_type = reject_type;
}

pub(crate) fn handle_rule_form_rate_limit_burst_changed(state: &mut State, value: String) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormRateLimitBurstChanged sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.rate_limit_burst = value;
}

pub(crate) fn handle_rule_form_log_enabled_toggled(state: &mut State, enabled: bool) {
    let Some(form) = &mut state.rule_form else {
        tracing::error!(
            "RuleFormLogEnabledToggled sent without active form. \
             This indicates a UI state management bug."
        );
        return;
    };
    form.log_enabled = enabled;
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
        assert_eq!(state.rule_form.as_ref().unwrap().label, "Test Label");
    }
}
