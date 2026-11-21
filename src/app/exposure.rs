//! Exposure panel model: listening sockets and who can reach them
//!
//! The sockets are scanned off the UI thread (`handlers::exposure`) when the
//! panel opens and on Refresh. Every row and string the view shows is built
//! here, in `update()`: after a scan, and again whenever the editor ruleset or
//! the applied ruleset changes while the panel is open (re-evaluating is
//! cheap; the sockets are not re-read). The scan also finds the SSH
//! sessions into this computer ([`crate::core::lockout`]); the panel says
//! whether the editor rules would let their clients reconnect.

use uuid::Uuid;

use crate::core::evaluate::InputChain;
use crate::core::exposure::{SocketExposure, SocketInfo, evaluate_socket};
use crate::core::firewall::FirewallRuleset;
use crate::core::lockout::{Access, SshSession};

/// What one Exposure scan found.
#[derive(Debug, Clone, Default)]
pub struct ExposureScan {
    pub sockets: Vec<SocketInfo>,
    /// SSH sessions (`SSH_CONNECTION` and `/proc`), see
    /// [`crate::core::lockout::detect_sessions`]
    pub sessions: Vec<SshSession>,
}

/// One "SSH: …" line of the panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshLine {
    /// "SSH: you are connected from … would be accepted by rule \"SSH\""
    pub text: String,
    /// New connections from this client would be (or may be) blocked
    pub warning: bool,
}

/// Badge text for sockets every address can reach (shown with color, never
/// color alone).
pub const OPEN_BADGE: &str = "OPEN TO EVERYONE";

/// Open/closed state of the Exposure panel, with the scan bookkeeping.
#[derive(Debug, Default)]
pub struct ExposureState {
    /// `Some` while the panel is open
    pub panel: Option<ExposurePanel>,
    /// Generation of the latest scan request; older results are ignored
    pub generation: u64,
}

/// How the applied ruleset relates to the editor's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppliedState {
    /// DRFW has not applied anything this session: only the editor rules
    Unknown,
    /// The applied rules are the editor's
    SameAsEditor,
    /// Both are evaluated; rows show the applied answer where it differs
    Differs,
}

/// The open Exposure panel.
#[derive(Debug, Clone)]
pub struct ExposurePanel {
    /// A scan is running
    pub scanning: bool,
    /// The last scan's sockets (re-evaluated on ruleset changes)
    sockets: Vec<SocketInfo>,
    /// The last scan's SSH sessions (re-evaluated on ruleset changes)
    sessions: Vec<SshSession>,
    /// One line per SSH session, under the editor rules
    pub ssh_lines: Vec<SshLine>,
    /// Why the last scan failed (user-facing)
    pub error: Option<String>,
    pub applied: AppliedState,
    /// Rows: sockets open to everyone first
    pub rows: Vec<ExposureRowView>,
    /// "12 listening sockets · 2 open to everyone"
    pub summary: String,
    /// What the rows compare (editor vs applied)
    pub applied_note: &'static str,
}

/// One socket in the panel; all text pre-formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureRowView {
    /// "TCP 22"
    pub port_proto: String,
    /// "IPv4", "IPv6", "IPv4+IPv6"
    pub family: &'static str,
    /// "sshd", "unknown (another user: root)"
    pub process: String,
    /// "all addresses", "127.0.0.1 (local only)", "192.168.1.5 only"
    pub bind: String,
    /// Open to everyone under the editor or the applied rules
    pub highlight: bool,
    /// The answer under the editor rules
    pub editor: ReachView,
    /// The answer under the applied rules, when it differs from `editor`
    pub applied: Option<ReachView>,
}

/// Tone of a reachability answer (the view picks the theme color).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachTone {
    /// Every address can connect
    Open,
    /// Some sources can connect
    Restricted,
    /// Nobody can connect
    Closed,
    /// Bound to loopback
    LocalOnly,
}

/// One reachability answer, pre-formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachView {
    /// "Reachable from: everyone", "Local only"
    pub text: String,
    pub tone: ReachTone,
    /// [`OPEN_BADGE`] for sockets open to everyone
    pub badge: Option<&'static str>,
    /// "rule \"SSH\"", "built-in rule \"…\""; empty when local only
    pub rule_text: String,
    /// The deciding user rule, if it exists in the editor (clickable)
    pub edit_rule_id: Option<Uuid>,
}

impl ReachView {
    fn new(exposure: &SocketExposure, editor: &FirewallRuleset) -> Self {
        let tone = if exposure.local_only {
            ReachTone::LocalOnly
        } else if exposure.open_to_everyone {
            ReachTone::Open
        } else if exposure.nobody {
            ReachTone::Closed
        } else {
            ReachTone::Restricted
        };
        let text = if exposure.local_only {
            "Local only: bound to loopback".to_string()
        } else {
            format!("Reachable from: {}", exposure.summary)
        };
        let edit_rule_id = exposure
            .decided_by
            .as_ref()
            .and_then(crate::core::evaluate::Decider::rule_id)
            .filter(|id| editor.rules.iter().any(|r| r.id == *id));
        Self {
            text,
            tone,
            badge: exposure.open_to_everyone.then_some(OPEN_BADGE),
            rule_text: exposure.decided_by_display.clone(),
            edit_rule_id,
        }
    }
}

impl ExposurePanel {
    /// A panel waiting for its first scan.
    pub fn scanning() -> Self {
        Self {
            scanning: true,
            sockets: Vec::new(),
            sessions: Vec::new(),
            ssh_lines: Vec::new(),
            error: None,
            applied: AppliedState::Unknown,
            rows: Vec::new(),
            summary: "Scanning listening sockets…".to_string(),
            applied_note: "",
        }
    }

    /// Stores a scan result and rebuilds the rows.
    pub fn set_scan(
        &mut self,
        result: Result<ExposureScan, String>,
        editor: &FirewallRuleset,
        applied: Option<&FirewallRuleset>,
    ) {
        self.scanning = false;
        match result {
            Ok(scan) => {
                self.sockets = scan.sockets;
                self.sessions = scan.sessions;
                self.error = None;
            }
            Err(message) => {
                self.sockets.clear();
                self.sessions.clear();
                self.error = Some(message);
            }
        }
        self.rebuild(editor, applied);
    }

    /// Re-evaluates the scanned sockets against the rulesets.
    pub fn rebuild(&mut self, editor: &FirewallRuleset, applied: Option<&FirewallRuleset>) {
        self.applied = match applied {
            None => AppliedState::Unknown,
            Some(applied) if crate::app::rulesets_match(applied, editor) => {
                AppliedState::SameAsEditor
            }
            Some(_) => AppliedState::Differs,
        };
        self.applied_note = match self.applied {
            AppliedState::Unknown => {
                "Evaluated against the rules in the editor. DRFW has not applied rules \
                 this session, so what the kernel enforces now is not known."
            }
            AppliedState::SameAsEditor => {
                "Evaluated against the rules in the editor, which are the applied rules."
            }
            AppliedState::Differs => {
                "Evaluated against the rules in the editor; \"Applied\" shows the rules in \
                 the kernel where they give a different answer."
            }
        };

        let editor_chain = InputChain::new(editor);
        let applied_chain = match (self.applied, applied) {
            (AppliedState::Differs, Some(applied)) => Some(InputChain::new(applied)),
            _ => None,
        };
        let mut rows: Vec<ExposureRowView> = self
            .sockets
            .iter()
            .map(|socket| {
                let editor_view = ReachView::new(&evaluate_socket(&editor_chain, socket), editor);
                let applied_view = applied_chain
                    .as_ref()
                    .map(|chain| ReachView::new(&evaluate_socket(chain, socket), editor))
                    .filter(|view| {
                        view.text != editor_view.text || view.rule_text != editor_view.rule_text
                    });
                let highlight = editor_view.badge.is_some()
                    || applied_view.as_ref().is_some_and(|v| v.badge.is_some());
                ExposureRowView {
                    port_proto: format!("{} {}", socket.transport.display_name(), socket.port),
                    family: socket.family_display,
                    process: socket.process_display.clone(),
                    bind: socket.bind_display.clone(),
                    highlight,
                    editor: editor_view,
                    applied: applied_view,
                }
            })
            .collect();
        // Stable: the scan's protocol/port order within each group
        rows.sort_by_key(|row| !row.highlight);
        self.rows = rows;

        self.ssh_lines = crate::core::lockout::check_sessions(editor, &self.sessions)
            .iter()
            .map(|check| SshLine {
                text: format!("SSH: {}", check.summary()),
                warning: check.access != Access::Accepted,
            })
            .collect();

        let total = self.rows.len();
        let open = self.rows.iter().filter(|r| r.highlight).count();
        self.summary = match (&self.error, total) {
            (Some(_), _) => "No sockets to show.".to_string(),
            (None, 0) => "No listening sockets found.".to_string(),
            (None, _) => {
                let sockets = if total == 1 { "socket" } else { "sockets" };
                format!("{total} listening {sockets} · {open} open to everyone")
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::core::evaluate::Transport;
    use crate::core::exposure::{ListeningSocket, build_socket_list};
    use crate::core::firewall::{PortEntry, Protocol, Rule};

    fn socket(transport: Transport, local: &str, port: u16) -> ListeningSocket {
        ListeningSocket {
            transport,
            ipv6_socket: local.contains(':'),
            local: local.parse().unwrap(),
            port,
            uid: 1000,
            inode: u64::from(port),
        }
    }

    fn sockets() -> Vec<SocketInfo> {
        build_socket_list(
            vec![
                socket(Transport::Tcp, "0.0.0.0", 22),
                socket(Transport::Tcp, "127.0.0.1", 631),
                socket(Transport::Udp, "0.0.0.0", 5353),
                socket(Transport::Tcp, "0.0.0.0", 8080),
            ],
            &HashMap::new(),
            1000,
            false,
            |_| None,
        )
    }

    fn scan(sockets: Vec<SocketInfo>) -> ExposureScan {
        ExposureScan {
            sockets,
            sessions: Vec::new(),
        }
    }

    fn rule(label: &str, protocol: Protocol, port: u16, sources: &[&str]) -> Rule {
        let mut r = crate::core::test_helpers::create_test_rule(label, None);
        r.protocol = protocol;
        r.ports = vec![PortEntry::Single(port)];
        r.sources = sources.iter().map(|s| s.parse().unwrap()).collect();
        r.rebuild_caches();
        r
    }

    #[test]
    fn test_rows_put_open_sockets_first_with_text_badges() {
        let mut editor = FirewallRuleset::new();
        editor.rules.push(rule("web", Protocol::Tcp, 8080, &[]));
        editor
            .rules
            .push(rule("ssh", Protocol::Tcp, 22, &["10.0.0.0/8"]));
        let web_id = editor.rules[0].id;
        let mut panel = ExposurePanel::scanning();
        panel.set_scan(Ok(scan(sockets())), &editor, None);

        assert_eq!(panel.applied, AppliedState::Unknown);
        assert_eq!(panel.summary, "4 listening sockets · 1 open to everyone");
        let first = &panel.rows[0];
        assert_eq!(first.port_proto, "TCP 8080");
        assert!(first.highlight);
        assert_eq!(first.editor.badge, Some(OPEN_BADGE));
        assert_eq!(first.editor.tone, ReachTone::Open);
        assert_eq!(first.editor.text, "Reachable from: everyone");
        assert_eq!(first.editor.rule_text, "rule \"web\"");
        assert_eq!(first.editor.edit_rule_id, Some(web_id));
        assert!(first.applied.is_none());

        let by_port = |p: &str| panel.rows.iter().find(|r| r.port_proto == p).unwrap();
        assert_eq!(by_port("TCP 22").editor.tone, ReachTone::Restricted);
        assert_eq!(by_port("TCP 22").editor.text, "Reachable from: 10.0.0.0/8");
        let local = &by_port("TCP 631").editor;
        assert_eq!(local.tone, ReachTone::LocalOnly);
        assert!(local.rule_text.is_empty() && local.edit_rule_id.is_none());
        let closed = &by_port("UDP 5353").editor;
        assert_eq!(closed.tone, ReachTone::Closed);
        assert_eq!(closed.edit_rule_id, None, "a built-in rule is not editable");
    }

    #[test]
    fn test_applied_rules_shown_only_where_they_differ() {
        let mut editor = FirewallRuleset::new();
        editor
            .rules
            .push(rule("ssh", Protocol::Tcp, 22, &["10.0.0.0/8"]));
        let mut applied = editor.clone();
        applied
            .rules
            .push(rule("old web", Protocol::Tcp, 8080, &[]));

        let mut panel = ExposurePanel::scanning();
        panel.set_scan(Ok(scan(sockets())), &editor, Some(&applied));
        assert_eq!(panel.applied, AppliedState::Differs);
        let web = &panel.rows[0];
        assert_eq!(web.port_proto, "TCP 8080");
        assert!(web.highlight, "open under the applied rules");
        assert_eq!(web.editor.tone, ReachTone::Closed);
        let applied_view = web.applied.as_ref().expect("differs");
        assert_eq!(applied_view.badge, Some(OPEN_BADGE));
        assert_eq!(applied_view.edit_rule_id, None, "not in the editor");
        let ssh = panel
            .rows
            .iter()
            .find(|r| r.port_proto == "TCP 22")
            .unwrap();
        assert!(ssh.applied.is_none(), "same answer");

        // The same rules: one answer per row
        panel.rebuild(&applied, Some(&applied));
        assert_eq!(panel.applied, AppliedState::SameAsEditor);
        assert!(panel.rows.iter().all(|r| r.applied.is_none()));
        assert_eq!(panel.rows[0].editor.badge, Some(OPEN_BADGE));
    }

    #[test]
    fn test_ssh_lines_follow_the_editor_rules() {
        let session = SshSession {
            client: "10.0.0.5".parse().unwrap(),
            client_port: 50000,
            server: "10.0.0.1".parse().unwrap(),
            server_port: 22,
            source: crate::core::lockout::SessionSource::Environment,
        };
        let mut editor = FirewallRuleset::new();
        let mut panel = ExposurePanel::scanning();
        panel.set_scan(
            Ok(ExposureScan {
                sockets: sockets(),
                sessions: vec![session],
            }),
            &editor,
            None,
        );
        assert_eq!(panel.ssh_lines.len(), 1);
        assert!(panel.ssh_lines[0].warning);
        assert!(
            panel.ssh_lines[0]
                .text
                .starts_with("SSH: you are connected from 10.0.0.5 to port 22;"),
            "{:?}",
            panel.ssh_lines
        );
        assert!(panel.ssh_lines[0].text.contains("BLOCKED"));

        editor.rules.push(rule("ssh", Protocol::Tcp, 22, &[]));
        panel.rebuild(&editor, None);
        assert!(!panel.ssh_lines[0].warning);
        assert!(
            panel.ssh_lines[0]
                .text
                .ends_with("accepted by rule \"ssh\"")
        );
    }

    #[test]
    fn test_scan_error_and_empty_scan() {
        let editor = FirewallRuleset::new();
        let mut panel = ExposurePanel::scanning();
        assert!(panel.scanning);
        panel.set_scan(Err("Could not read".into()), &editor, None);
        assert!(!panel.scanning);
        assert_eq!(panel.error.as_deref(), Some("Could not read"));
        assert_eq!(panel.rows, Vec::new());
        panel.set_scan(Ok(ExposureScan::default()), &editor, None);
        assert_eq!(panel.error, None);
        assert_eq!(panel.summary, "No listening sockets found.");
    }
}
