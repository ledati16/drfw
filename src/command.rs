//! Command pattern implementation for undo/redo functionality
//!
//! This module implements the Command design pattern to enable robust undo/redo
//! capabilities for all firewall rule modifications.
//!
//! # Architecture
//!
//! Each modification to the firewall ruleset is encapsulated as a [`Command`]:
//! - [`AddRuleCommand`]: Adds a new rule
//! - [`DeleteRuleCommand`]: Removes an existing rule
//! - [`EditRuleCommand`]: Modifies an existing rule
//! - [`ToggleRuleCommand`]: Enables/disables a rule
//! - [`ReorderRuleCommand`]: Changes rule priority order
//!
//! The [`CommandHistory`] manages the undo/redo stacks with configurable depth.
//!
//! # Example
//!
//! ```no_run
//! use drfw::command::{CommandHistory, AddRuleCommand};
//! use drfw::core::firewall::{FirewallRuleset, Rule, Protocol, PortRange, Chain, Action};
//! use uuid::Uuid;
//!
//! let mut ruleset = FirewallRuleset::new();
//! let mut history = CommandHistory::default();
//!
//! let mut rule = Rule {
//!     id: Uuid::new_v4(),
//!     label: "Allow HTTP".to_string(),
//!     protocol: Protocol::Tcp,
//!     ports: Some(PortRange::single(80)),
//!     source: None,
//!     interface: None,
//!     chain: Chain::Input,
//!     enabled: true,
//!     tags: vec![],
//!     created_at: chrono::Utc::now(),
//!     destination: None,
//!     action: Action::Accept,
//!     rate_limit: None,
//!     connection_limit: 0,
//!     // Cached fields (populated by rebuild_caches())
//!     label_lowercase: String::new(),
//!     interface_lowercase: None,
//!     tags_lowercase: Vec::new(),
//!     protocol_lowercase: "",
//!     port_display: String::new(),
//!     source_string: None,
//!     destination_string: None,
//!     rate_limit_display: None,
//! };
//! rule.rebuild_caches();
//!
//! let cmd = Box::new(AddRuleCommand { rule });
//! history.execute(cmd, &mut ruleset);
//!
//! // Later: undo the operation
//! history.undo(&mut ruleset);
//! ```

use crate::core::firewall::{FirewallRuleset, Rule};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Command pattern trait for undo/redo functionality
///
/// Each command encapsulates a state change operation and knows how to undo it.
/// Commands are serializable to enable persistence of command history.
pub trait Command: std::fmt::Debug {
    /// Executes the command, applying changes to the ruleset
    fn execute(&self, ruleset: &mut FirewallRuleset);

    /// Undoes the command, reverting changes to the ruleset
    fn undo(&self, ruleset: &mut FirewallRuleset);

    /// Returns a human-readable description of this command
    fn description(&self) -> String;

    /// Clones the command into a boxed trait object
    fn box_clone(&self) -> Box<dyn Command>;
}

impl Clone for Box<dyn Command> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

/// Adds a new rule to the ruleset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddRuleCommand {
    pub rule: Rule,
}

impl Command for AddRuleCommand {
    fn execute(&self, ruleset: &mut FirewallRuleset) {
        ruleset.rules.push(self.rule.clone());
    }

    fn undo(&self, ruleset: &mut FirewallRuleset) {
        ruleset.rules.retain(|r| r.id != self.rule.id);
    }

    fn description(&self) -> String {
        format!("Add rule: {}", self.rule.label)
    }

    fn box_clone(&self) -> Box<dyn Command> {
        Box::new(self.clone())
    }
}

/// Deletes an existing rule from the ruleset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRuleCommand {
    pub rule: Rule,
    pub index: usize,
}

impl Command for DeleteRuleCommand {
    fn execute(&self, ruleset: &mut FirewallRuleset) {
        ruleset.rules.retain(|r| r.id != self.rule.id);
    }

    fn undo(&self, ruleset: &mut FirewallRuleset) {
        // Insert at original index to preserve order
        if self.index <= ruleset.rules.len() {
            ruleset.rules.insert(self.index, self.rule.clone());
        } else {
            ruleset.rules.push(self.rule.clone());
        }
    }

    fn description(&self) -> String {
        format!("Delete rule: {}", self.rule.label)
    }

    fn box_clone(&self) -> Box<dyn Command> {
        Box::new(self.clone())
    }
}

/// Edits an existing rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRuleCommand {
    pub old_rule: Rule,
    pub new_rule: Rule,
}

impl Command for EditRuleCommand {
    fn execute(&self, ruleset: &mut FirewallRuleset) {
        if let Some(rule) = ruleset.rules.iter_mut().find(|r| r.id == self.old_rule.id) {
            *rule = self.new_rule.clone();
        }
    }

    fn undo(&self, ruleset: &mut FirewallRuleset) {
        if let Some(rule) = ruleset.rules.iter_mut().find(|r| r.id == self.new_rule.id) {
            *rule = self.old_rule.clone();
        }
    }

    fn description(&self) -> String {
        format!("Edit rule: {}", self.new_rule.label)
    }

    fn box_clone(&self) -> Box<dyn Command> {
        Box::new(self.clone())
    }
}

/// Toggles the enabled state of a rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToggleRuleCommand {
    pub rule_id: Uuid,
    pub was_enabled: bool,
}

impl Command for ToggleRuleCommand {
    fn execute(&self, ruleset: &mut FirewallRuleset) {
        if let Some(rule) = ruleset.rules.iter_mut().find(|r| r.id == self.rule_id) {
            rule.enabled = !self.was_enabled;
        }
    }

    fn undo(&self, ruleset: &mut FirewallRuleset) {
        if let Some(rule) = ruleset.rules.iter_mut().find(|r| r.id == self.rule_id) {
            rule.enabled = self.was_enabled;
        }
    }

    fn description(&self) -> String {
        if self.was_enabled {
            "Disable rule".to_string()
        } else {
            "Enable rule".to_string()
        }
    }

    fn box_clone(&self) -> Box<dyn Command> {
        Box::new(self.clone())
    }
}

/// Moves a rule from one position to another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReorderRuleCommand {
    pub rule_id: Uuid,
    pub old_index: usize,
    pub new_index: usize,
}

impl Command for ReorderRuleCommand {
    fn execute(&self, ruleset: &mut FirewallRuleset) {
        if let Some(pos) = ruleset.rules.iter().position(|r| r.id == self.rule_id) {
            let rule = ruleset.rules.remove(pos);
            let insert_pos = self.new_index.min(ruleset.rules.len());
            ruleset.rules.insert(insert_pos, rule);
        }
    }

    fn undo(&self, ruleset: &mut FirewallRuleset) {
        if let Some(pos) = ruleset.rules.iter().position(|r| r.id == self.rule_id) {
            let rule = ruleset.rules.remove(pos);
            let insert_pos = self.old_index.min(ruleset.rules.len());
            ruleset.rules.insert(insert_pos, rule);
        }
    }

    fn description(&self) -> String {
        format!(
            "Reorder rule (position {} → {})",
            self.old_index + 1,
            self.new_index + 1
        )
    }

    fn box_clone(&self) -> Box<dyn Command> {
        Box::new(self.clone())
    }
}

/// Manages the undo/redo history
#[derive(Debug, Clone)]
pub struct CommandHistory {
    undo_stack: Vec<Box<dyn Command>>,
    redo_stack: Vec<Box<dyn Command>>,
    max_history: usize,
}

impl Default for CommandHistory {
    fn default() -> Self {
        Self::new(20)
    }
}

impl CommandHistory {
    /// Creates a new command history with the specified maximum size
    pub fn new(max_history: usize) -> Self {
        Self {
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            max_history,
        }
    }

    /// Executes a command and adds it to the undo stack
    pub fn execute(&mut self, command: Box<dyn Command>, ruleset: &mut FirewallRuleset) {
        command.execute(ruleset);

        // Clear redo stack when new command is executed
        self.redo_stack.clear();

        // Add to undo stack
        self.undo_stack.push(command);

        // Trim undo stack to max size
        if self.undo_stack.len() > self.max_history {
            self.undo_stack.remove(0);
        }
    }

    /// Undoes the last command
    pub fn undo(&mut self, ruleset: &mut FirewallRuleset) -> Option<String> {
        if let Some(command) = self.undo_stack.pop() {
            let description = command.description();
            command.undo(ruleset);
            self.redo_stack.push(command);
            Some(description)
        } else {
            None
        }
    }

    /// Redoes the last undone command
    pub fn redo(&mut self, ruleset: &mut FirewallRuleset) -> Option<String> {
        if let Some(command) = self.redo_stack.pop() {
            let description = command.description();
            command.execute(ruleset);
            self.undo_stack.push(command);
            Some(description)
        } else {
            None
        }
    }

    /// Returns whether undo is available
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Returns whether redo is available
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Returns the description of the next undo operation
    #[allow(dead_code)]
    pub fn undo_description(&self) -> Option<String> {
        self.undo_stack.last().map(|cmd| cmd.description())
    }

    /// Returns the description of the next redo operation
    #[allow(dead_code)]
    pub fn redo_description(&self) -> Option<String> {
        self.redo_stack.last().map(|cmd| cmd.description())
    }

    /// Clears the entire history
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    /// Returns the number of operations in the undo stack
    #[allow(dead_code)]
    pub fn undo_count(&self) -> usize {
        self.undo_stack.len()
    }

    /// Returns the number of operations in the redo stack
    #[allow(dead_code)]
    pub fn redo_count(&self) -> usize {
        self.redo_stack.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::firewall::Protocol;

    fn create_test_rule(label: &str) -> Rule {
        Rule::with_caches(
            Uuid::new_v4(),
            label.to_string(),
            Protocol::Tcp,
            None,                                // ports
            None,                                // source
            None,                                // interface
            crate::core::firewall::Chain::Input, // chain
            true,                                // enabled
            chrono::Utc::now(),
            Vec::new(), // tags
        )
    }

    #[test]
    fn test_add_rule_command() {
        let mut ruleset = FirewallRuleset::new();
        let rule = create_test_rule("Test Rule");
        let cmd = AddRuleCommand { rule: rule.clone() };

        assert_eq!(ruleset.rules.len(), 0);

        cmd.execute(&mut ruleset);
        assert_eq!(ruleset.rules.len(), 1);
        assert_eq!(ruleset.rules[0].label, "Test Rule");

        cmd.undo(&mut ruleset);
        assert_eq!(ruleset.rules.len(), 0);
    }

    #[test]
    fn test_delete_rule_command() {
        let mut ruleset = FirewallRuleset::new();
        let rule = create_test_rule("Test Rule");
        ruleset.rules.push(rule.clone());

        let cmd = DeleteRuleCommand {
            rule: rule.clone(),
            index: 0,
        };

        cmd.execute(&mut ruleset);
        assert_eq!(ruleset.rules.len(), 0);

        cmd.undo(&mut ruleset);
        assert_eq!(ruleset.rules.len(), 1);
        assert_eq!(ruleset.rules[0].label, "Test Rule");
    }

    #[test]
    fn test_edit_rule_command() {
        let mut ruleset = FirewallRuleset::new();
        let old_rule = create_test_rule("Old Label");
        let mut new_rule = old_rule.clone();
        new_rule.label = "New Label".to_string();
        ruleset.rules.push(old_rule.clone());

        let cmd = EditRuleCommand {
            old_rule: old_rule.clone(),
            new_rule: new_rule.clone(),
        };

        cmd.execute(&mut ruleset);
        assert_eq!(ruleset.rules[0].label, "New Label");

        cmd.undo(&mut ruleset);
        assert_eq!(ruleset.rules[0].label, "Old Label");
    }

    #[test]
    fn test_toggle_rule_command() {
        let mut ruleset = FirewallRuleset::new();
        let mut rule = create_test_rule("Test Rule");
        rule.enabled = true;
        ruleset.rules.push(rule.clone());

        let cmd = ToggleRuleCommand {
            rule_id: rule.id,
            was_enabled: true,
        };

        cmd.execute(&mut ruleset);
        assert!(!ruleset.rules[0].enabled);

        cmd.undo(&mut ruleset);
        assert!(ruleset.rules[0].enabled);
    }

    #[test]
    fn test_reorder_rule_command() {
        let mut ruleset = FirewallRuleset::new();
        let rule1 = create_test_rule("Rule 1");
        let rule2 = create_test_rule("Rule 2");
        let rule3 = create_test_rule("Rule 3");

        ruleset.rules.push(rule1.clone());
        ruleset.rules.push(rule2.clone());
        ruleset.rules.push(rule3.clone());

        let cmd = ReorderRuleCommand {
            rule_id: rule1.id,
            old_index: 0,
            new_index: 2,
        };

        cmd.execute(&mut ruleset);
        assert_eq!(ruleset.rules[0].label, "Rule 2");
        assert_eq!(ruleset.rules[1].label, "Rule 3");
        assert_eq!(ruleset.rules[2].label, "Rule 1");

        cmd.undo(&mut ruleset);
        assert_eq!(ruleset.rules[0].label, "Rule 1");
        assert_eq!(ruleset.rules[1].label, "Rule 2");
        assert_eq!(ruleset.rules[2].label, "Rule 3");
    }

    #[test]
    fn test_command_history() {
        let mut ruleset = FirewallRuleset::new();
        let mut history = CommandHistory::new(3);

        let rule1 = create_test_rule("Rule 1");
        let rule2 = create_test_rule("Rule 2");

        // Execute commands
        history.execute(
            Box::new(AddRuleCommand {
                rule: rule1.clone(),
            }),
            &mut ruleset,
        );
        history.execute(
            Box::new(AddRuleCommand {
                rule: rule2.clone(),
            }),
            &mut ruleset,
        );

        assert_eq!(ruleset.rules.len(), 2);
        assert!(history.can_undo());
        assert!(!history.can_redo());

        // Undo
        history.undo(&mut ruleset);
        assert_eq!(ruleset.rules.len(), 1);
        assert!(history.can_undo());
        assert!(history.can_redo());

        // Redo
        history.redo(&mut ruleset);
        assert_eq!(ruleset.rules.len(), 2);
        assert!(history.can_undo());
        assert!(!history.can_redo());
    }

    #[test]
    fn test_command_history_max_size() {
        let mut ruleset = FirewallRuleset::new();
        let mut history = CommandHistory::new(2);

        // Add 3 rules
        for i in 1..=3 {
            let rule = create_test_rule(&format!("Rule {i}"));
            history.execute(Box::new(AddRuleCommand { rule }), &mut ruleset);
        }

        // Should only be able to undo 2 times (max_history = 2)
        assert_eq!(history.undo_count(), 2);

        history.undo(&mut ruleset);
        history.undo(&mut ruleset);
        assert!(!history.can_undo()); // All undone
        assert_eq!(ruleset.rules.len(), 1); // First rule can't be undone (was trimmed)
    }

    #[test]
    fn test_new_command_clears_redo() {
        let mut ruleset = FirewallRuleset::new();
        let mut history = CommandHistory::new(10);

        let rule1 = create_test_rule("Rule 1");
        let rule2 = create_test_rule("Rule 2");

        history.execute(Box::new(AddRuleCommand { rule: rule1 }), &mut ruleset);
        history.undo(&mut ruleset);

        assert!(history.can_redo());

        // Execute new command should clear redo stack
        history.execute(Box::new(AddRuleCommand { rule: rule2 }), &mut ruleset);
        assert!(!history.can_redo());
    }
}
