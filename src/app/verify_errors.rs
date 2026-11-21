//! "Verification Errors" panel model
//!
//! Built once in `update()` from a failed [`VerifyResult`]; the view only
//! borrows these strings (see `view::verify_errors`).

use uuid::Uuid;

use crate::core::verify::VerifyResult;

/// The errors of the last failed verification, ready to display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyErrorsPanel {
    /// "nft rejected 2 rules." / "nft rejected the ruleset."
    pub summary: String,
    pub rows: Vec<VerifyErrorRow>,
}

/// One nft error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyErrorRow {
    /// What the error points at: `rule "ssh"`, `built-in rule "…"`, `nft`
    pub title: String,
    /// The user rule to open when the row is clicked
    pub rule_id: Option<Uuid>,
    pub message: String,
    /// Offending line of the generated ruleset and its caret line
    pub source_line: Option<String>,
    pub caret: Option<String>,
}

impl VerifyErrorsPanel {
    /// Prepares the panel for a failed verification.
    pub fn new(result: &VerifyResult) -> Self {
        let rows = result
            .issues
            .iter()
            .map(|issue| VerifyErrorRow {
                title: issue
                    .origin
                    .as_ref()
                    .map_or_else(|| "nft".to_string(), ToString::to_string),
                rule_id: issue.rule_id(),
                message: issue.message.clone(),
                source_line: issue.source_line.clone(),
                caret: issue.caret.clone(),
            })
            .collect();
        Self {
            summary: format!("{}.", rejected_phrase(result)),
            rows,
        }
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
        let panel = VerifyErrorsPanel::new(&result);
        assert_eq!(panel.summary, "nft rejected 1 rule.");
        assert_eq!(panel.rows[0].title, "rule \"ssh\"");
        assert_eq!(panel.rows[0].rule_id, Some(id));
        assert_eq!(panel.rows[1].title, "nft");
        assert_eq!(panel.rows[1].rule_id, None);
        assert_eq!(banner_message(&result), "nft rejected 1 rule, see details");
        let raw = VerifyResult::failure(vec![VerifyIssue::unlocated("x")]);
        assert_eq!(
            banner_message(&raw),
            "nft rejected the ruleset, see details"
        );
    }
}
