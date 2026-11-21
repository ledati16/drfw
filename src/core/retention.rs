//! Retention guard: a confirmation before a change that drops most of the
//! firewall or closes a lot more traffic than before
//!
//! Before Apply and Save to System (GUI and CLI), the ruleset about to be
//! used is compared with the last ruleset applied and kept (the
//! [`crate::core::confirmed`] record). A confirmation is required when it:
//!
//! - removes at least [`MIN_REMOVED`] of the enabled rules of the kept
//!   ruleset, and at least [`MIN_REMOVED_PERCENT`] % of them. Rules are matched
//!   by id; a rule that is disabled now counts as removed;
//! - switches the egress mode from Desktop to Server (outgoing connections
//!   then need allow rules);
//! - turns on "block forwarded traffic".
//!
//! Without a kept ruleset the comparison is against DRFW's defaults (no rules,
//! Desktop mode, forwarding not blocked): only the two mode changes can warn.
//!
//! Everything is computed once (in `update()` for the GUI); the GUI and the
//! CLI show the same [`RetentionWarning::lines`].

use std::collections::HashSet;
use std::fmt::Write as _;

use crate::core::firewall::{EgressProfile, FirewallRuleset};

/// Fewest removed rules that require a confirmation.
pub const MIN_REMOVED: usize = 3;

/// Smallest share (percent of the kept ruleset's enabled rules) of removed
/// rules that requires a confirmation.
pub const MIN_REMOVED_PERCENT: usize = 40;

/// Rule names listed before "+N more".
pub const MAX_NAMED: usize = 10;

/// Why a ruleset needs an explicit confirmation, ready to display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionWarning {
    /// Enabled rules of the kept ruleset that are gone or disabled
    pub removed_count: usize,
    /// Enabled rules of the kept ruleset
    pub kept_enabled: usize,
    /// Desktop -> Server egress mode
    pub enables_server_mode: bool,
    /// Block forwarded traffic: off -> on
    pub enables_block_forwarding: bool,
    /// One line per reason (count and names of removed rules, mode changes)
    pub lines: Vec<String>,
}

impl RetentionWarning {
    /// Compares `next` (about to be applied or saved) with `kept` (the last
    /// ruleset applied and kept; `None` when unknown). `None` when no
    /// confirmation is needed.
    pub fn check(kept: Option<&FirewallRuleset>, next: &FirewallRuleset) -> Option<Self> {
        let defaults = FirewallRuleset::new();
        let kept = kept.unwrap_or(&defaults);

        let still_enabled: HashSet<uuid::Uuid> = next
            .rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.id)
            .collect();
        let kept_enabled: Vec<_> = kept.rules.iter().filter(|r| r.enabled).collect();
        let removed: Vec<&str> = kept_enabled
            .iter()
            .filter(|r| !still_enabled.contains(&r.id))
            .map(|r| r.label.as_str())
            .collect();
        let removes_many = removed.len() >= MIN_REMOVED
            && removed.len() * 100 >= kept_enabled.len() * MIN_REMOVED_PERCENT;

        let enables_server_mode = kept.advanced_security.egress_profile == EgressProfile::Desktop
            && next.advanced_security.egress_profile == EgressProfile::Server;
        let enables_block_forwarding =
            !kept.advanced_security.block_forwarding && next.advanced_security.block_forwarding;

        if !removes_many && !enables_server_mode && !enables_block_forwarding {
            return None;
        }

        let mut lines = Vec::with_capacity(3);
        if removes_many {
            lines.push(format!(
                "Removes {} of the {} enabled rules last applied and kept (deleted or disabled): {}",
                removed.len(),
                kept_enabled.len(),
                name_list(&removed)
            ));
        }
        if enables_server_mode {
            lines.push(
                "Switches to Server mode: outgoing connections are blocked unless a rule allows them."
                    .to_string(),
            );
        }
        if enables_block_forwarding {
            lines.push(
                "Blocks forwarded traffic: breaks Docker, VMs and VPN routing unless allowed."
                    .to_string(),
            );
        }
        Some(Self {
            removed_count: removed.len(),
            kept_enabled: kept_enabled.len(),
            enables_server_mode,
            enables_block_forwarding,
            lines,
        })
    }
}

/// "a, b, c" for up to [`MAX_NAMED`] names, then "+N more".
fn name_list(names: &[&str]) -> String {
    let mut list = names
        .iter()
        .take(MAX_NAMED)
        .map(|name| {
            if name.is_empty() {
                "(unnamed)".to_string()
            } else {
                format!("\"{name}\"")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > MAX_NAMED {
        let _ = write!(list, ", +{} more", names.len() - MAX_NAMED);
    }
    list
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_helpers::create_test_rule;

    fn ruleset_with(count: usize) -> FirewallRuleset {
        let mut ruleset = FirewallRuleset::new();
        for i in 0..count {
            let port = u16::try_from(1000 + i).unwrap();
            ruleset
                .rules
                .push(create_test_rule(&format!("rule{i}"), Some(port)));
        }
        ruleset
    }

    #[test]
    fn test_thresholds() {
        let kept = ruleset_with(10);

        // 3 of 10 removed: 30 % is below the share
        let mut next = kept.clone();
        next.rules.truncate(7);
        assert_eq!(RetentionWarning::check(Some(&kept), &next), None);

        // 4 of 10: 40 %, at least 3
        next.rules.truncate(6);
        let warning = RetentionWarning::check(Some(&kept), &next).expect("warns");
        assert_eq!(warning.removed_count, 4);
        assert_eq!(warning.kept_enabled, 10);
        assert_eq!(
            warning.lines,
            vec![
                "Removes 4 of the 10 enabled rules last applied and kept (deleted or disabled): \
                 \"rule6\", \"rule7\", \"rule8\", \"rule9\""
                    .to_string()
            ]
        );

        // 2 of 3 (67 %) is fewer than 3 rules
        let small = ruleset_with(3);
        let mut next = small.clone();
        next.rules.truncate(1);
        assert_eq!(RetentionWarning::check(Some(&small), &next), None);
        // All 3 of 3
        next.rules.clear();
        assert_eq!(
            RetentionWarning::check(Some(&small), &next).map(|w| w.removed_count),
            Some(3)
        );
    }

    /// Disabling counts as removing; rules disabled in the kept ruleset and
    /// new rules do not count; matching is by id, not by label.
    #[test]
    fn test_matching_by_id_and_disabled_rules() {
        let mut kept = ruleset_with(6);
        kept.rules[5].enabled = false; // 5 enabled
        let mut next = kept.clone();
        for rule in &mut next.rules[..2] {
            rule.enabled = false;
        }
        assert_eq!(RetentionWarning::check(Some(&kept), &next), None, "2 of 5");
        next.rules[2].id = uuid::Uuid::new_v4(); // same label, another rule
        next.rules.push(create_test_rule("new", Some(9)));
        let warning = RetentionWarning::check(Some(&kept), &next).expect("3 of 5");
        assert_eq!((warning.removed_count, warning.kept_enabled), (3, 5));
    }

    #[test]
    fn test_names_are_capped() {
        let kept = ruleset_with(14);
        let next = FirewallRuleset::new();
        let warning = RetentionWarning::check(Some(&kept), &next).expect("warns");
        assert!(
            warning.lines[0].contains("\"rule9\", +4 more"),
            "{warning:?}"
        );
        assert!(!warning.lines[0].contains("rule10"), "{warning:?}");
    }

    #[test]
    fn test_mode_changes() {
        let kept = ruleset_with(2);
        let mut next = kept.clone();
        next.advanced_security.egress_profile = EgressProfile::Server;
        let warning = RetentionWarning::check(Some(&kept), &next).expect("server mode");
        assert!(warning.enables_server_mode && !warning.enables_block_forwarding);
        assert_eq!(warning.lines.len(), 1);
        assert!(warning.lines[0].starts_with("Switches to Server mode"));

        // Already Server: nothing new
        assert_eq!(RetentionWarning::check(Some(&next), &next), None);
        // Back to Desktop opens traffic: no confirmation
        assert_eq!(RetentionWarning::check(Some(&next), &kept), None);

        let mut forwarding = kept.clone();
        forwarding.advanced_security.block_forwarding = true;
        let warning = RetentionWarning::check(Some(&kept), &forwarding).expect("forwarding");
        assert!(warning.enables_block_forwarding);
        assert_eq!(RetentionWarning::check(Some(&forwarding), &kept), None);

        // Nothing kept yet: compared with the defaults
        assert_eq!(RetentionWarning::check(None, &kept), None);
        assert!(RetentionWarning::check(None, &next).is_some());
    }
}
