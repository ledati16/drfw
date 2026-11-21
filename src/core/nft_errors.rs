//! Readable nft errors, mapped back to the rules that caused them
//!
//! nft reports errors in JSON input without a usable location
//! (`internal:0:0-0: Error: …`). Its **text** parser does better: every error
//! names `<file>:<line>:<first>-<last>` and is followed by the offending
//! source line and a caret line:
//!
//! ```text
//! /dev/stdin:11:34-38: Error: Service out of range
//!         iifname "eth0" tcp dport 99999 accept comment "bad port"
//!                                  ^^^^^
//! ```
//!
//! [`FirewallRuleset::to_nft_text`] renders exactly the commands that are
//! verified as JSON, so when a check fails, `verify::locate_errors` checks the
//! text form too and [`AnnotatedText`] traces each error line back to what
//! produced it: a user rule, a built-in rule, a chain declaration or the
//! header (see `nft_text::render_with_map`).
//!
//! [`FirewallRuleset::to_nft_text`]: crate::core::firewall::FirewallRuleset::to_nft_text

use std::fmt;

use uuid::Uuid;

use crate::core::firewall::{FirewallRuleset, NftCommand};
use crate::core::nft_text::{LineSource, RenderedText};

/// Longest source excerpt shown, in characters; longer lines are cut around
/// the caret.
const MAX_EXCERPT_CHARS: usize = 100;
/// Characters of context kept before the caret when a long line is cut.
const EXCERPT_LEAD_CHARS: usize = 24;
/// Marks where a long source line was cut.
const ELLIPSIS: char = '…';

/// The part of the generated ruleset an nft error points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorOrigin {
    /// A rule of the profile
    UserRule { id: Uuid, label: String },
    /// A rule DRFW adds itself (loopback, ICMP, end-of-chain reject, ...):
    /// its comment, or the section it belongs to when it has none
    BaseRule { description: String },
    /// A chain block or its `type filter hook …` declaration
    Chain { name: String },
    /// The file header and table setup
    Header,
}

impl fmt::Display for ErrorOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserRule { label, .. } if label.is_empty() => f.write_str("unnamed rule"),
            Self::UserRule { label, .. } => write!(f, "rule \"{label}\""),
            Self::BaseRule { description } => write!(f, "built-in rule \"{description}\""),
            Self::Chain { name } => write!(f, "chain \"{name}\""),
            Self::Header => f.write_str("ruleset header"),
        }
    }
}

/// One error reported by nft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyIssue {
    /// What the error points at; `None` when nft gave no usable location
    /// (JSON check, or the text check could not run)
    pub origin: Option<ErrorOrigin>,
    /// nft's message, without the location prefix (may span several lines,
    /// e.g. a syntax error's "expected any of: …" list)
    pub message: String,
    /// The offending line of the generated text, dedented and cut to a
    /// readable width
    pub source_line: Option<String>,
    /// nft's `^^^`/`~~~` marker line, aligned with `source_line`
    pub caret: Option<String>,
}

impl VerifyIssue {
    /// An issue with only a message (no location).
    pub fn unlocated(message: impl Into<String>) -> Self {
        Self {
            origin: None,
            message: message.into(),
            source_line: None,
            caret: None,
        }
    }

    /// The id of the user rule this issue points at, if any.
    pub fn rule_id(&self) -> Option<Uuid> {
        match &self.origin {
            Some(ErrorOrigin::UserRule { id, .. }) => Some(*id),
            _ => None,
        }
    }
}

/// `rule "<label>": <message>`, or just the message when there is no origin.
impl fmt::Display for VerifyIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.origin {
            Some(origin) => write!(f, "{origin}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

/// One error parsed from nft's stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NftDiagnostic {
    /// 1-based line of the checked input; `None` without a usable location
    /// (JSON input reports `internal:0:0-0`)
    pub line: Option<usize>,
    pub message: String,
    /// The source line nft quoted, verbatim
    pub source: Option<String>,
    /// The marker line under `source`, verbatim
    pub caret: Option<String>,
}

/// Parses nft's stderr into diagnostics.
///
/// Recognizes `<file>:<line>:<first>-<last>: Error: <message>` headers; the
/// lines up to the next header are message continuations, then the quoted
/// source line and the caret line. Lines before the first header (e.g.
/// `Error: …` without a location, `nft: …`) become one diagnostic each.
pub(crate) fn parse_nft_output(stderr: &str) -> Vec<NftDiagnostic> {
    // Older nft versions could answer JSON input with a JSON error object
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(stderr)
        && let Some(errors) = json.get("errors").and_then(|e| e.as_array())
    {
        return errors
            .iter()
            .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
            .map(|message| NftDiagnostic {
                line: None,
                message: message.to_string(),
                source: None,
                caret: None,
            })
            .collect();
    }

    let mut diagnostics = Vec::new();
    let mut current: Option<(Option<usize>, String, Vec<&str>)> = None;
    for line in stderr.lines() {
        if let Some((line_no, message)) = parse_location_header(line) {
            if let Some(block) = current.take() {
                finish_block(block, &mut diagnostics);
            }
            current = Some((line_no, message.to_string(), Vec::new()));
        } else if let Some((_, _, rest)) = current.as_mut() {
            rest.push(line);
        } else if !line.trim().is_empty() {
            diagnostics.push(NftDiagnostic::unlocated(line));
        }
    }
    if let Some(block) = current.take() {
        finish_block(block, &mut diagnostics);
    }
    diagnostics
}

/// Removes the `Error: ` / `nft: ` prefixes of an unlocated message.
fn strip_error_prefix(line: &str) -> &str {
    line.trim()
        .trim_start_matches("Error: ")
        .trim_start_matches("nft: ")
}

/// Splits `<file>:<line>:<first>-<last>: Error: <message>` into the line
/// number (`None` for line 0, JSON's `internal:0:0-0`) and the message.
fn parse_location_header(line: &str) -> Option<(Option<usize>, &str)> {
    let (location, message) = line.split_once(": Error: ")?;
    // The file name may contain ':'; find `<line>:<first>-…` from the left
    // after it. A multi-line span looks like `3:5-4:2`.
    let parts: Vec<&str> = location.split(':').collect();
    let line_no = (1..parts.len().saturating_sub(1)).find_map(|i| {
        let is_number = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        let (first, _) = parts[i + 1].split_once('-')?;
        (is_number(parts[i]) && is_number(first)).then(|| parts[i].parse::<usize>().ok())?
    })?;
    Some(((line_no > 0).then_some(line_no), message.trim()))
}

/// True for nft's marker line: only spaces, `^` and `~`, with at least one marker.
fn is_caret_line(line: &str) -> bool {
    line.chars().any(|c| c == '^' || c == '~') && line.chars().all(|c| matches!(c, ' ' | '^' | '~'))
}

/// Turns a header plus the lines up to the next header into diagnostics.
///
/// The lines before the quoted source line continue the message; lines after
/// the caret line (if any) are unrelated messages without a location.
fn finish_block(
    (line, mut message, rest): (Option<usize>, String, Vec<&str>),
    diagnostics: &mut Vec<NftDiagnostic>,
) {
    let caret_at = (1..rest.len()).find(|&i| is_caret_line(rest[i]));
    let (continuations, quoted, trailing) = match caret_at {
        Some(i) => (&rest[..i - 1], Some((rest[i - 1], rest[i])), &rest[i + 1..]),
        None => (rest.as_slice(), None, &[][..]),
    };
    for continuation in continuations.iter().filter(|l| !l.trim().is_empty()) {
        message.push('\n');
        message.push_str(continuation.trim_end());
    }
    diagnostics.push(NftDiagnostic {
        line,
        message,
        source: quoted.map(|(source, _)| source.to_string()),
        caret: quoted.map(|(_, caret)| caret.to_string()),
    });
    for extra in trailing.iter().filter(|l| !l.trim().is_empty()) {
        diagnostics.push(NftDiagnostic::unlocated(extra));
    }
}

/// Dedents a source line and its caret line together and cuts long lines to
/// a window around the caret, so the pair stays aligned and readable.
fn excerpt(source: &str, caret: &str) -> (String, String) {
    let leading = |s: &str| s.chars().take_while(|c| *c == ' ').count();
    let indent = leading(source).min(leading(caret));
    let source: Vec<char> = source.chars().skip(indent).collect();
    let caret: Vec<char> = caret.trim_end().chars().skip(indent).collect();

    if source.len() <= MAX_EXCERPT_CHARS {
        return (source.into_iter().collect(), caret.into_iter().collect());
    }
    let marker = caret.iter().position(|c| *c != ' ').unwrap_or(0);
    let start = marker
        .saturating_sub(EXCERPT_LEAD_CHARS)
        .min(source.len().saturating_sub(MAX_EXCERPT_CHARS));
    let end = (start + MAX_EXCERPT_CHARS).min(source.len());

    let mut source_out = String::with_capacity(MAX_EXCERPT_CHARS + 8);
    let mut caret_out = String::with_capacity(MAX_EXCERPT_CHARS + 8);
    if start > 0 {
        source_out.push(ELLIPSIS);
        caret_out.push(' ');
    }
    source_out.extend(&source[start..end]);
    if end < source.len() {
        source_out.push(ELLIPSIS);
    }
    caret_out.extend(caret.iter().skip(start).take(end - start));
    (source_out, caret_out)
}

impl NftDiagnostic {
    /// A diagnostic for a line without a location (`Error: …`, `nft: …`).
    fn unlocated(line: &str) -> Self {
        Self {
            line: None,
            message: strip_error_prefix(line).to_string(),
            source: None,
            caret: None,
        }
    }

    /// Converts to an issue pointing at `origin`.
    fn into_issue(self, origin: Option<ErrorOrigin>) -> VerifyIssue {
        let (source_line, caret) = match (self.source, self.caret) {
            (Some(source), Some(caret)) => {
                let (source, caret) = excerpt(&source, &caret);
                (Some(source), Some(caret))
            }
            _ => (None, None),
        };
        VerifyIssue {
            origin,
            message: self.message,
            source_line,
            caret,
        }
    }
}

/// Issues from nft's stderr without any location mapping (JSON checks).
pub(crate) fn unlocated_issues(stderr: &str) -> Vec<VerifyIssue> {
    parse_nft_output(stderr)
        .into_iter()
        .map(|d| d.into_issue(None))
        .collect()
}

/// A ruleset's `nft -f` text plus what produced each of its lines.
pub(crate) struct AnnotatedText<'a> {
    ruleset: &'a FirewallRuleset,
    commands: Vec<NftCommand>,
    rendered: RenderedText,
    /// Per command: index of the user rule that produced it. `None` if the
    /// commands could not be attributed (see [`user_rule_owners`]).
    owners: Option<Vec<Option<usize>>>,
}

impl<'a> AnnotatedText<'a> {
    /// Renders `ruleset` (the same text as `to_nft_text()`) with its line map.
    pub fn new(ruleset: &'a FirewallRuleset) -> Self {
        let commands = ruleset.build_commands();
        let rendered = crate::core::nft_text::render_with_map(&commands);
        let owners = user_rule_owners(ruleset, &commands);
        Self {
            ruleset,
            commands,
            rendered,
            owners,
        }
    }

    /// The rendered text.
    pub fn text(&self) -> &str {
        &self.rendered.text
    }

    /// What produced 1-based line `line` of the text.
    pub fn origin(&self, line: usize) -> Option<ErrorOrigin> {
        match *self.rendered.lines.get(line.checked_sub(1)?)? {
            LineSource::Header => Some(ErrorOrigin::Header),
            LineSource::Chain(i) => Some(ErrorOrigin::Chain {
                name: self.rendered.chains.get(i)?.clone(),
            }),
            LineSource::Rule(command) => {
                if let Some(rule) = self.owners.as_ref()?.get(command).copied().flatten() {
                    let rule = self.ruleset.rules.get(rule)?;
                    return Some(ErrorOrigin::UserRule {
                        id: rule.id,
                        label: rule.label.clone(),
                    });
                }
                let command = self.commands.get(command)?;
                let description = command.value["add"]["rule"]["comment"]
                    .as_str()
                    .filter(|c| !c.is_empty())
                    .unwrap_or(command.section);
                Some(ErrorOrigin::BaseRule {
                    description: description.to_string(),
                })
            }
        }
    }

    /// Issues from the stderr of `nft -c -f -` run on [`Self::text`].
    pub fn issues(&self, stderr: &str) -> Vec<VerifyIssue> {
        parse_nft_output(stderr)
            .into_iter()
            .map(|d| {
                let origin = d.line.and_then(|line| self.origin(line));
                d.into_issue(origin)
            })
            .collect()
    }
}

/// Attributes the generated commands to the user rules that produced them.
///
/// The command list does not record which rule produced a command, so this
/// derives it: user rules only add commands, between the built-in rules
/// before them and the end-of-chain rules after them, in profile order. The
/// commands of the ruleset without any user rule are the shared prefix and
/// suffix; building the ruleset with each single rule gives that rule's
/// commands, which must then appear, in order, in between. Any mismatch
/// (which would mean generation changed shape) returns `None` rather than a
/// wrong attribution. Only runs when a check failed.
fn user_rule_owners(
    ruleset: &FirewallRuleset,
    commands: &[NftCommand],
) -> Option<Vec<Option<usize>>> {
    let mut single = FirewallRuleset::new();
    single
        .advanced_security
        .clone_from(&ruleset.advanced_security);
    let base = single.build_commands();
    let user_len = commands.len().checked_sub(base.len())?;
    let start = commands
        .iter()
        .zip(&base)
        .take_while(|(a, b)| a.value == b.value)
        .count()
        .min(base.len());
    let same = |a: &[NftCommand], b: &[NftCommand]| {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.value == y.value)
    };
    if !same(&commands[start + user_len..], &base[start..]) {
        tracing::warn!("cannot attribute nft commands to rules: unexpected base commands");
        return None;
    }

    let mut owners = vec![None; commands.len()];
    let mut offset = start;
    for (index, rule) in ruleset.rules.iter().enumerate() {
        single.rules.clear();
        single.rules.push(rule.clone());
        let own = single.build_commands();
        let count = own.len().checked_sub(base.len())?;
        if count == 0 {
            continue;
        }
        let (Some(expected), Some(actual)) = (
            own.get(start..start + count),
            commands.get(offset..offset + count),
        ) else {
            tracing::warn!("cannot attribute nft commands to rules: count mismatch");
            return None;
        };
        if !same(expected, actual) {
            tracing::warn!("cannot attribute nft commands to rules: content mismatch");
            return None;
        }
        owners[offset..offset + count].fill(Some(index));
        offset += count;
    }
    (offset == start + user_len).then_some(owners)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::firewall::{Chain, EgressProfile, PortEntry, Protocol};
    use crate::core::test_helpers::{create_full_test_rule, create_test_rule};

    /// Real nft 1.1.7 output (`unshare -rn nft -c -f -`) for a file with an
    /// out-of-range port, mixed address families and a too-long log prefix.
    const EVALUATION_ERRORS: &str = r#"/dev/stdin:11:34-38: Error: Service out of range
        iifname "eth0" tcp dport 99999 accept comment "bad port"
                                 ^^^^^
/dev/stdin:12:29-37: Error: conflicting network layer protocols specified: ip vs. ip6
        ip saddr 10.0.0.0/8 ip6 daddr ::1 accept comment "mixed"
                            ^^^^^^^^^
/dev/stdin:14:9-11: Error: log prefix is too long
        log prefix "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" accept
        ^^^
"#;

    /// Real nft 1.1.7 syntax error: the message continues on a second line.
    const SYNTAX_ERROR: &str = "/dev/stdin:8:27-27: Error: syntax error, unexpected newline
expected any of: ., ==, !=, <, >, >=, <=, <<, >>, &, ^, !, @, vmap, map, reset
        tcp dport 22 accep
                          ^
";

    /// Real nft 1.1.7 kernel (netlink) error and a `~~~` context marker.
    const KERNEL_AND_CONTEXT: &str =
        "/dev/stdin:8:9-18: Error: Could not process rule: Invalid argument
        limit rate 0/second accept comment \"zero\"
        ^^^^^^^^^^
/dev/stdin:9:26-31: Error: you cannot use tcp reset with this protocol
        meta l4proto udp reject with tcp reset
        ~~~~~~~~~~~~~~~~ ^^^^^^
";

    /// Real nft 1.1.7 output for JSON input (`nft --json --check`): no location.
    const JSON_ERROR: &str = "internal:0:0-0: Error: Range negative size\n\n";

    #[test]
    fn test_parse_located_errors() {
        let diags = parse_nft_output(EVALUATION_ERRORS);
        assert_eq!(diags.len(), 3);
        assert_eq!(diags[0].line, Some(11));
        assert_eq!(diags[0].message, "Service out of range");
        assert_eq!(
            diags[0].source.as_deref(),
            Some("        iifname \"eth0\" tcp dport 99999 accept comment \"bad port\"")
        );
        assert_eq!(
            diags[0].caret.as_deref(),
            Some("                                 ^^^^^")
        );
        assert_eq!(diags[1].line, Some(12));
        assert_eq!(
            diags[1].message,
            "conflicting network layer protocols specified: ip vs. ip6"
        );
        assert_eq!(diags[2].line, Some(14));
        assert_eq!(diags[2].message, "log prefix is too long");
    }

    #[test]
    fn test_parse_multiline_message() {
        let diags = parse_nft_output(SYNTAX_ERROR);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].line, Some(8));
        assert!(
            diags[0]
                .message
                .starts_with("syntax error, unexpected newline\nexpected any of:")
        );
        assert_eq!(
            diags[0].source.as_deref(),
            Some("        tcp dport 22 accep")
        );
        assert_eq!(
            diags[0].caret.as_deref(),
            Some("                          ^")
        );
    }

    #[test]
    fn test_parse_kernel_error_and_context_marker() {
        let diags = parse_nft_output(KERNEL_AND_CONTEXT);
        assert_eq!(diags.len(), 2);
        assert_eq!(diags[0].message, "Could not process rule: Invalid argument");
        assert_eq!(
            diags[1].caret.as_deref(),
            Some("        ~~~~~~~~~~~~~~~~ ^^^^^^")
        );
    }

    #[test]
    fn test_parse_json_error_has_no_location() {
        let diags = parse_nft_output(JSON_ERROR);
        assert_eq!(
            diags,
            vec![NftDiagnostic {
                line: None,
                message: "Range negative size".to_string(),
                source: None,
                caret: None,
            }]
        );
    }

    #[test]
    fn test_parse_unlocated_lines() {
        let diags = parse_nft_output(
            "nft: Operation not permitted\nError: Could not process rule: Permission denied\n",
        );
        let messages: Vec<_> = diags.iter().map(|d| d.message.as_str()).collect();
        assert_eq!(
            messages,
            [
                "Operation not permitted",
                "Could not process rule: Permission denied"
            ]
        );
        assert!(diags.iter().all(|d| d.line.is_none()));
        assert_eq!(parse_nft_output(""), Vec::new());
    }

    #[test]
    fn test_location_header_variants() {
        assert_eq!(
            parse_location_header("/dev/stdin:3:1-5: Error: x"),
            Some((Some(3), "x"))
        );
        // File names with ':' and multi-line spans
        assert_eq!(
            parse_location_header("/tmp/a:b.nft:12:5-13:2: Error: y"),
            Some((Some(12), "y"))
        );
        assert_eq!(
            parse_location_header("internal:0:0-0: Error: z"),
            Some((None, "z"))
        );
        assert_eq!(parse_location_header("Error: no location"), None);
        assert_eq!(parse_location_header("foo: Error: bar"), None);
    }

    #[test]
    fn test_excerpt_dedents_and_keeps_alignment() {
        let (source, caret) = excerpt("        tcp dport 99999 accept", "                  ^^^^^");
        assert_eq!(source, "tcp dport 99999 accept");
        assert_eq!(caret, "          ^^^^^");
        assert_eq!(source.find("99999"), caret.find('^'));
    }

    #[test]
    fn test_excerpt_cuts_long_lines_around_the_caret() {
        let long = format!("{}BAD{}", "a".repeat(150), "b".repeat(150));
        let caret = format!("{}^^^", " ".repeat(150));
        let (source, caret) = excerpt(&long, &caret);
        assert!(source.starts_with(ELLIPSIS) && source.ends_with(ELLIPSIS));
        assert!(source.chars().count() <= MAX_EXCERPT_CHARS + 2);
        let source_chars: Vec<char> = source.chars().collect();
        let caret_at = caret.chars().position(|c| c == '^').expect("caret kept");
        assert_eq!(
            source_chars[caret_at..caret_at + 3]
                .iter()
                .collect::<String>(),
            "BAD"
        );
    }

    fn ruleset_with(rules: Vec<crate::core::firewall::Rule>) -> FirewallRuleset {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules = rules;
        ruleset
    }

    /// Every line of a user rule maps to that rule's id, and nothing else does.
    #[test]
    fn test_every_user_rule_line_maps_to_its_rule() {
        let mut dual =
            create_full_test_rule("dual stack", Protocol::Tcp, Some(443), None, Some("eth0"));
        dual.sources = vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()];
        dual.rebuild_caches();
        let mut disabled = create_test_rule("disabled", Some(25));
        disabled.enabled = false;
        let mut output = create_test_rule("output", Some(53));
        output.chain = Chain::Output;
        let mut ruleset = ruleset_with(vec![
            create_test_rule("ssh", Some(22)),
            dual,
            disabled,
            create_test_rule("ssh", Some(2222)),
            output,
            crate::core::firewall::Rule::with_caches(
                Uuid::new_v4(),
                String::new(),
                Protocol::Udp,
                vec![PortEntry::range(9000, 9100)],
                Vec::new(),
                None,
                Chain::Input,
                true,
                jiff::Timestamp::now(),
                Vec::new(),
            ),
        ]);
        for egress in [EgressProfile::Desktop, EgressProfile::Server] {
            ruleset.advanced_security.egress_profile = egress;
            ruleset.advanced_security.log_dropped = egress == EgressProfile::Server;
            let annotated = AnnotatedText::new(&ruleset);
            assert!(annotated.owners.is_some(), "attribution succeeded");
            let mut lines_per_rule = std::collections::HashMap::new();
            for (n, line) in annotated.text().lines().enumerate() {
                let origin = annotated.origin(n + 1);
                if let Some(ErrorOrigin::UserRule { id, label }) = &origin {
                    let rule = ruleset.rules.iter().find(|r| r.id == *id).unwrap();
                    assert_eq!(&rule.label, label);
                    if !rule.label.is_empty() {
                        assert!(line.contains(&format!("comment \"{label}\"")), "{line}");
                    }
                    *lines_per_rule.entry(*id).or_insert(0) += 1;
                } else {
                    // Built-in rules never carry a user rule's comment
                    for rule in ruleset.rules.iter().filter(|r| !r.label.is_empty()) {
                        assert!(
                            !line.contains(&format!("comment \"{}\"", rule.label)),
                            "user rule line not attributed: {line}"
                        );
                    }
                }
            }
            let ids = |pred: &dyn Fn(&crate::core::firewall::Rule) -> bool| {
                ruleset
                    .rules
                    .iter()
                    .filter(|r| pred(r))
                    .map(|r| r.id)
                    .collect::<Vec<_>>()
            };
            let active =
                ids(&|r| r.enabled && (egress == EgressProfile::Server || r.chain == Chain::Input));
            for id in &active {
                assert!(lines_per_rule.contains_key(id), "rule {id} has no line");
            }
            assert_eq!(lines_per_rule.len(), active.len());
            // The IPv4 + IPv6 rule renders as two lines
            assert_eq!(lines_per_rule[&ruleset.rules[1].id], 2);
        }
    }

    #[test]
    fn test_non_rule_lines_map_to_header_chain_or_base_rule() {
        let ruleset = ruleset_with(vec![create_test_rule("ssh", Some(22))]);
        let annotated = AnnotatedText::new(&ruleset);
        let line_of = |needle: &str| {
            annotated
                .text()
                .lines()
                .position(|l| l.contains(needle))
                .map_or_else(|| panic!("no line with {needle}"), |i| i + 1)
        };
        assert_eq!(annotated.origin(1), Some(ErrorOrigin::Header));
        assert_eq!(
            annotated.origin(line_of("delete table inet drfw")),
            Some(ErrorOrigin::Header)
        );
        assert_eq!(
            annotated.origin(line_of("type filter hook input")),
            Some(ErrorOrigin::Chain {
                name: "input".to_string()
            })
        );
        assert!(matches!(
            annotated.origin(line_of("iifname \"lo\"")),
            Some(ErrorOrigin::BaseRule { .. })
        ));
        assert_eq!(annotated.origin(0), None);
        assert_eq!(annotated.origin(100_000), None);
    }

    #[test]
    fn test_annotated_text_is_to_nft_text() {
        let mut rule = create_full_test_rule(
            "everything",
            Protocol::Tcp,
            Some(22),
            Some("10.0.0.0/8"),
            Some("eth0"),
        );
        rule.log_enabled = true;
        rule.rebuild_caches();
        let mut ruleset = ruleset_with(vec![rule, create_test_rule("ssh", Some(22))]);
        ruleset.advanced_security.enable_rpf = true;
        ruleset.advanced_security.log_dropped = true;
        ruleset.advanced_security.egress_profile = EgressProfile::Server;
        let annotated = AnnotatedText::new(&ruleset);
        assert_eq!(annotated.text(), ruleset.to_nft_text());
        assert_eq!(
            annotated.rendered.lines.len(),
            annotated.text().lines().count()
        );
    }

    #[test]
    fn test_issues_map_text_errors_to_rules() {
        let ruleset = ruleset_with(vec![
            create_test_rule("ssh", Some(22)),
            create_test_rule("web", Some(80)),
        ]);
        let annotated = AnnotatedText::new(&ruleset);
        let web_line = annotated
            .text()
            .lines()
            .position(|l| l.contains("comment \"web\""))
            .unwrap()
            + 1;
        let stderr = format!(
            "/dev/stdin:{web_line}:9-11: Error: Something is wrong\n        tcp dport 80 accept comment \"web\"\n        ^^^\nError: trailing\n"
        );
        let issues = annotated.issues(&stderr);
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].rule_id(), Some(ruleset.rules[1].id));
        assert_eq!(issues[0].to_string(), "rule \"web\": Something is wrong");
        assert_eq!(issues[1], VerifyIssue::unlocated("trailing"));
        assert_eq!(
            issues[0].source_line.as_deref(),
            Some("tcp dport 80 accept comment \"web\"")
        );
        assert_eq!(issues[0].caret.as_deref(), Some("^^^"));
    }
}
