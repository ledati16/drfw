//! "Verification Errors" panel model
//!
//! Built once in `update()` from a failed [`VerifyResult`]; the view only
//! borrows these strings (see `view::verify_errors`).

use uuid::Uuid;

use crate::core::firewall::FirewallRuleset;
use crate::core::verify::VerifyResult;

/// The errors of the last failed verification, ready to display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyErrorsPanel {
    /// Panel title, also the label of the header button that reopens it
    pub title: &'static str,
    /// "nft rejected 2 rules." / "nft rejected the ruleset."
    pub summary: String,
    /// What to do next ("... then apply again"), set by whoever verified
    pub next_step: &'static str,
    pub rows: Vec<VerifyErrorRow>,
    /// The panel describes the kernel (an apply whose outcome is unknown),
    /// not the profile: switching profiles or a passing Save to System
    /// check does not clear it
    pub describes_kernel: bool,
}

/// One nft error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyErrorRow {
    /// What the error points at: `rule "ssh"`, `base rule "…"`, `nft`
    pub title: String,
    /// The user rule the error points at
    pub rule_id: Option<Uuid>,
    /// `rule_id` still exists in the ruleset (kept up to date by
    /// [`VerifyErrorsPanel::sync_with`]); only then can it be edited
    rule_exists: bool,
    pub message: String,
    /// Offending line of the generated ruleset and its caret line
    pub source_line: Option<String>,
    pub caret: Option<String>,
}

impl VerifyErrorsPanel {
    /// Prepares the panel for a failed verification of `ruleset`.
    pub fn new(result: &VerifyResult, ruleset: &FirewallRuleset) -> Self {
        let rows = result
            .issues
            .iter()
            .map(|issue| VerifyErrorRow {
                title: issue
                    .origin
                    .as_ref()
                    .map_or_else(|| "nft".to_string(), ToString::to_string),
                rule_id: issue.rule_id(),
                rule_exists: false,
                message: issue.message.clone(),
                source_line: issue.source_line.clone(),
                caret: issue.caret.clone(),
            })
            .collect();
        let mut panel = Self {
            title: "Verification Errors",
            summary: format!("{}.", rejected_phrase(result)),
            next_step: "Nothing was changed. Fix the rules below, then apply again.",
            rows,
            describes_kernel: false,
        };
        panel.sync_with(ruleset);
        panel
    }

    /// The details of an apply whose outcome is unknown (the new rules may be
    /// active): the banner is short, the full explanation is here. `detail`
    /// is the reason `ApplyError::StateUnknown` carries.
    pub fn apply_state_unknown(detail: &str) -> Self {
        Self {
            title: "Apply Details",
            summary: "Firewall state unknown: the new rules MAY BE ACTIVE.".to_string(),
            next_step: "DRFW cannot tell whether the old or the new rules are loaded. \
                        Check with `sudo nft list table inet drfw`. Applying again (with \
                        auto-revert) brings the firewall back to a known state.",
            rows: vec![VerifyErrorRow {
                title: "What happened".to_string(),
                rule_id: None,
                rule_exists: false,
                message: detail.to_string(),
                source_line: None,
                caret: None,
            }],
            describes_kernel: true,
        }
    }

    /// Re-checks which rules the rows point at still exist, after the
    /// ruleset changed (a rule deleted since the check offers no "Edit Rule";
    /// undoing the delete brings it back).
    pub fn sync_with(&mut self, ruleset: &FirewallRuleset) {
        for row in &mut self.rows {
            row.rule_exists = row
                .rule_id
                .is_some_and(|id| ruleset.rules.iter().any(|r| r.id == id));
        }
    }
}

impl VerifyErrorRow {
    /// The rule "Edit Rule" opens: the rule the error points at, if it still
    /// exists.
    pub fn edit_rule_id(&self) -> Option<Uuid> {
        self.rule_id.filter(|_| self.rule_exists)
    }
}

/// "nft rejected 1 rule" / "nft rejected 3 rules" / "nft rejected the ruleset".
fn rejected_phrase(result: &VerifyResult) -> String {
    match result.rejected_count() {
        0 => "nft rejected the ruleset".to_string(),
        1 => "nft rejected 1 rule".to_string(),
        n => format!("nft rejected {n} rules"),
    }
}

/// The short banner shown when a verification fails.
pub fn banner_message(result: &VerifyResult) -> String {
    format!("{}, see details", rejected_phrase(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::verify::{ErrorOrigin, VerifyIssue};

    #[test]
    fn test_panel_rows_and_banner() {
        let id = Uuid::new_v4();
        let result = VerifyResult::failure(vec![
            VerifyIssue {
                origin: Some(ErrorOrigin::UserRule {
                    id,
                    label: "ssh".into(),
                }),
                message: "Service out of range".into(),
                source_line: Some("tcp dport 99999 accept".into()),
                caret: Some("          ^^^^^".into()),
            },
            VerifyIssue::unlocated("something else"),
        ]);
        let mut ruleset = FirewallRuleset::new();
        let mut rule = crate::core::test_helpers::create_test_rule("ssh", Some(22));
        rule.id = id;
        ruleset.rules.push(rule);
        let mut panel = VerifyErrorsPanel::new(&result, &ruleset);
        assert_eq!(panel.summary, "nft rejected 1 rule.");
        assert_eq!(panel.rows[0].title, "rule \"ssh\"");
        assert_eq!(panel.rows[0].rule_id, Some(id));
        assert_eq!(panel.rows[0].edit_rule_id(), Some(id));
        assert_eq!(panel.rows[1].title, "nft");
        assert_eq!(panel.rows[1].edit_rule_id(), None);

        // The rule is deleted: no "Edit Rule"; restored: offered again
        let rule = ruleset.rules.pop().unwrap();
        panel.sync_with(&ruleset);
        assert_eq!(panel.rows[0].rule_id, Some(id));
        assert_eq!(panel.rows[0].edit_rule_id(), None);
        ruleset.rules.push(rule);
        panel.sync_with(&ruleset);
        assert_eq!(panel.rows[0].edit_rule_id(), Some(id));
        assert_eq!(banner_message(&result), "nft rejected 1 rule, see details");
        let raw = VerifyResult::failure(vec![VerifyIssue::unlocated("x")]);
        assert_eq!(
            banner_message(&raw),
            "nft rejected the ruleset, see details"
        );
    }
}
