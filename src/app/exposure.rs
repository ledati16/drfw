//! Exposure panel model: listening sockets and who can reach them
//!
//! The sockets are scanned off the UI thread (`handlers::exposure`) when the
//! panel opens and on Refresh. Every row and string the view shows is built
//! here, in `update()`: after a scan, and again whenever the editor ruleset or
//! the applied ruleset changes while the panel is open (re-evaluating is
//! cheap; the sockets are not re-read). The scan also finds the SSH
//! sessions into this computer ([`crate::core::lockout`]); the panel says
//! whether the editor rules would let their clients reconnect.

use std::fmt::Write as _;

use uuid::Uuid;

use crate::app::{Baseline, BaselineKind};
use crate::core::evaluate::InputChain;
use crate::core::exposure::{SocketExposure, SocketInfo, evaluate_socket};
use crate::core::firewall::FirewallRuleset;
use crate::core::host_facts::{
    ContainerFacts, DOCKER_PUBLISHED, DOCKER_PUBLISHED_FORWARD_FILTERED, ForwardingState,
};
use crate::core::lockout::SshSession;

/// What one Exposure scan found.
#[derive(Debug, Clone, Default)]
pub struct ExposureScan {
    pub sockets: Vec<SocketInfo>,
    /// SSH sessions (`SSH_CONNECTION` and `/proc`), see
    /// [`crate::core::lockout::detect_sessions`]
    pub sessions: Vec<SshSession>,
    /// Whether the kernel forwards traffic (the forwarding notice)
    pub forwarding: ForwardingState,
    /// Docker published ports and container networks (the Docker marking)
    pub containers: ContainerFacts,
    /// `State::host_facts_epoch` when the scan started (which of the
    /// sessions read is newest)
    pub facts_epoch: u64,
}

/// One "SSH: …" line of the panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshLine {
    /// "SSH: you are connected from … would be accepted by rule \"SSH\""
    pub text: String,
    /// New connections from this client would be (or may be) blocked
    pub warning: bool,
}

/// Badge text for sockets every address can reach on any interface (shown
/// with color, never color alone). Sockets every address can reach on some
/// interfaces only get "OPEN ON <interfaces>"
/// ([`crate::core::exposure::SocketExposure::open_on_badge`]).
pub const OPEN_BADGE: &str = "OPEN TO EVERYONE";

/// Badge text for the host side of a port Docker publishes (warning color).
pub const DOCKER_BADGE: &str = "PUBLISHED BY DOCKER";

/// Open/closed state of the Exposure panel, with the scan bookkeeping.
#[derive(Debug, Default)]
pub struct ExposureState {
    /// `Some` while the panel is open
    pub panel: Option<ExposurePanel>,
    /// Generation of the latest scan request; older results are ignored
    pub generation: u64,
}

/// How the baseline ruleset (applied this session, or the kept record; see
/// [`crate::app::BaselineKind`]) relates to the editor's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppliedState {
    /// No baseline: only the editor rules
    Unknown,
    /// The baseline rules are the editor's
    SameAsEditor,
    /// Both are evaluated; rows show the baseline answer where it differs
    Differs,
}

/// The explanation under the summary: what the rows compare, and how much
/// is known about the kernel's rules.
fn applied_note(state: AppliedState, kind: Option<BaselineKind>) -> &'static str {
    match (state, kind) {
        (AppliedState::Unknown, _) | (_, None) => {
            "Evaluated against the rules in the editor. DRFW has no copy of rules it \
             applied and kept, so what the kernel enforces now is not known."
        }
        (AppliedState::SameAsEditor, Some(BaselineKind::Applied)) => {
            "Evaluated against the rules in the editor, which are the applied rules."
        }
        (AppliedState::Differs, Some(BaselineKind::Applied)) => {
            "Evaluated against the rules in the editor; \"Applied\" shows the rules in \
             the kernel where they give a different answer."
        }
        (AppliedState::SameAsEditor, Some(BaselineKind::KeptThisBoot)) => {
            "Evaluated against the rules in the editor, which are the rules last applied \
             and kept (this boot). DRFW has not applied rules this session, so whether \
             the kernel still enforces them is not known."
        }
        (AppliedState::Differs, Some(BaselineKind::KeptThisBoot)) => {
            "Evaluated against the rules in the editor; \"Applied\" shows the rules last \
             applied and kept (this boot) where they give a different answer. DRFW has not \
             applied rules this session, so whether the kernel still enforces them is not \
             known."
        }
        (AppliedState::SameAsEditor, Some(BaselineKind::LastKept)) => {
            "Evaluated against the rules in the editor, which are the rules last applied \
             and kept. This session's last apply was not kept, so what the kernel \
             enforces now is not known."
        }
        (AppliedState::Differs, Some(BaselineKind::LastKept)) => {
            "Evaluated against the rules in the editor; \"Kept\" shows the rules last \
             applied and kept where they give a different answer. This session's last \
             apply was not kept, so what the kernel enforces now is not known."
        }
        (AppliedState::SameAsEditor, Some(BaselineKind::KeptEarlierSession)) => {
            "Evaluated against the rules in the editor, which are the rules last applied \
             and kept, in an earlier session. A reboot or another tool may have replaced \
             them, so what the kernel enforces now is not known."
        }
        (AppliedState::Differs, Some(BaselineKind::KeptEarlierSession)) => {
            "Evaluated against the rules in the editor; \"Kept\" shows the rules last \
             applied and kept, in an earlier session, where they give a different answer. \
             A reboot or another tool may have replaced them, so what the kernel enforces \
             now is not known."
        }
    }
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
    /// The last scan's forwarding state and container facts
    forwarding: ForwardingState,
    containers: ContainerFacts,
    /// Info notices above the list (forwarding, container networks),
    /// rebuilt with the rows
    pub notes: Vec<&'static str>,
    /// One line per SSH session, under the editor rules
    pub ssh_lines: Vec<SshLine>,
    /// Why the last scan failed (user-facing)
    pub error: Option<String>,
    pub applied: AppliedState,
    /// Label of the baseline's answers: "APPLIED" (this session or this
    /// boot) or "KEPT" (the last kept rules, not known to be the last
    /// applied)
    pub applied_label: &'static str,
    /// Rows: sockets open to everyone first, then those open to everyone on
    /// some interfaces, then the rest
    pub rows: Vec<ExposureRowView>,
    /// "12 listening sockets · 2 open to everyone · 1 open on some
    /// interfaces only"
    pub summary: String,
    /// What the rows compare (editor vs baseline)
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
    /// The most exposed answer of the editor and the baseline rules (the
    /// card border, the sort order)
    pub highlight: Highlight,
    /// The answer under the editor rules
    pub editor: ReachView,
    /// The answer under the applied rules, when it differs from `editor`
    pub applied: Option<ReachView>,
}

/// How strongly a row is marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Highlight {
    /// Open to everyone on any interface (danger)
    Everyone,
    /// Open to everyone on some interfaces only (warning)
    Interfaces,
    None,
}

/// Tone of a reachability answer (the view picks the theme color).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachTone {
    /// Every address can connect, on any interface
    Open,
    /// Every address can connect, on some interfaces only
    OpenOnInterfaces,
    /// Some sources can connect
    Restricted,
    /// Nobody can connect
    Closed,
    /// Bound to loopback
    LocalOnly,
    /// The host side of a port Docker publishes: not decided by the rules
    PublishedByDocker,
    /// The host side of a port Docker publishes, with "Block forwarded
    /// traffic" on: the Forwarded rules decide it (blocked unless one allows it)
    PublishedByDockerFiltered,
}

impl ReachTone {
    /// Either Docker marking.
    pub fn is_docker(self) -> bool {
        matches!(
            self,
            Self::PublishedByDocker | Self::PublishedByDockerFiltered
        )
    }
}

/// One reachability answer, pre-formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachView {
    /// "Reachable from: everyone", "Local only"
    pub text: String,
    pub tone: ReachTone,
    /// [`OPEN_BADGE`] for sockets open to everyone, "OPEN ON tailscale0" for
    /// those open to everyone on some interfaces (`tone` gives the color)
    pub badge: Option<String>,
    /// [`crate::core::exposure::SocketExposure::rank`] (sort order)
    pub rank: u8,
    /// "rule \"SSH\"", "built-in rule \"…\""; empty when local only
    pub rule_text: String,
    /// The deciding user rule, if it exists in the editor (clickable)
    pub edit_rule_id: Option<Uuid>,
}

impl ReachView {
    fn new(exposure: &SocketExposure, editor: &FirewallRuleset) -> Self {
        if exposure.docker_published {
            let (text, tone) = if exposure.docker_forward_filtered {
                (
                    DOCKER_PUBLISHED_FORWARD_FILTERED,
                    ReachTone::PublishedByDockerFiltered,
                )
            } else {
                (DOCKER_PUBLISHED, ReachTone::PublishedByDocker)
            };
            return Self {
                text: capitalize_first(text),
                tone,
                badge: Some(DOCKER_BADGE.to_string()),
                rank: exposure.rank(),
                rule_text: String::new(),
                edit_rule_id: None,
            };
        }
        let open_on = exposure.open_on_badge();
        let tone = if exposure.local_only {
            ReachTone::LocalOnly
        } else if exposure.open_to_everyone {
            ReachTone::Open
        } else if open_on.is_some() {
            ReachTone::OpenOnInterfaces
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
            badge: if exposure.open_to_everyone {
                Some(OPEN_BADGE.to_string())
            } else {
                open_on
            },
            rank: exposure.rank(),
            rule_text: exposure.decided_by_display.clone(),
            edit_rule_id,
        }
    }

    /// The row marking this answer calls for.
    fn highlight(&self) -> Highlight {
        match self.tone {
            ReachTone::Open => Highlight::Everyone,
            ReachTone::OpenOnInterfaces | ReachTone::PublishedByDocker => Highlight::Interfaces,
            ReachTone::Restricted
            | ReachTone::Closed
            | ReachTone::LocalOnly
            | ReachTone::PublishedByDockerFiltered => Highlight::None,
        }
    }
}

/// The row text for a port Docker publishes (instead of "Reachable from: …"):
/// the core's wording ([`DOCKER_PUBLISHED`] or
/// [`DOCKER_PUBLISHED_FORWARD_FILTERED`]), starting with a capital.
fn capitalize_first(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

impl ExposurePanel {
    /// A panel waiting for its first scan.
    pub fn scanning() -> Self {
        Self {
            scanning: true,
            sockets: Vec::new(),
            sessions: Vec::new(),
            forwarding: ForwardingState::default(),
            containers: ContainerFacts::default(),
            notes: Vec::new(),
            ssh_lines: Vec::new(),
            error: None,
            applied: AppliedState::Unknown,
            applied_label: "APPLIED",
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
        baseline: Option<Baseline<'_>>,
    ) {
        self.scanning = false;
        match result {
            Ok(scan) => {
                self.sockets = scan.sockets;
                self.sessions = scan.sessions;
                self.forwarding = scan.forwarding;
                self.containers = scan.containers;
                self.error = None;
            }
            Err(message) => {
                self.sockets.clear();
                self.sessions.clear();
                self.forwarding = ForwardingState::default();
                self.containers = ContainerFacts::default();
                self.error = Some(message);
            }
        }
        self.rebuild(editor, baseline);
    }

    /// Re-evaluates the scanned sockets against the editor rules and the
    /// baseline (what DRFW applied this session, else the kept record).
    pub fn rebuild(&mut self, editor: &FirewallRuleset, baseline: Option<Baseline<'_>>) {
        self.applied = match baseline {
            None => AppliedState::Unknown,
            Some(b) if crate::app::rulesets_match(b.ruleset, editor) => AppliedState::SameAsEditor,
            Some(_) => AppliedState::Differs,
        };
        let kind = baseline.map(|b| b.kind);
        self.applied_note = applied_note(self.applied, kind);
        self.applied_label = match kind {
            Some(BaselineKind::LastKept | BaselineKind::KeptEarlierSession) => "KEPT",
            Some(BaselineKind::Applied | BaselineKind::KeptThisBoot) | None => "APPLIED",
        };

        let editor_chain = InputChain::new(editor);
        let applied_chain = match (self.applied, baseline) {
            (AppliedState::Differs, Some(b)) => Some(InputChain::new(b.ruleset)),
            _ => None,
        };
        let mut rows: Vec<ExposureRowView> = self
            .sockets
            .iter()
            .map(|socket| {
                // A port Docker publishes is not decided by the input rules;
                // with "Block forwarded traffic" on, the Forwarded rules decide it
                let docker = self.containers.publishes(socket);
                // (the evaluator records whether the chain blocks forwarding)
                let evaluate = |chain: &InputChain| {
                    let mut exposure = evaluate_socket(chain, socket);
                    if docker {
                        exposure.mark_published_by_docker();
                    }
                    exposure
                };
                let editor_view = ReachView::new(&evaluate(&editor_chain), editor);
                let applied_view = applied_chain
                    .as_ref()
                    .map(|chain| ReachView::new(&evaluate(chain), editor))
                    .filter(|view| {
                        view.text != editor_view.text || view.rule_text != editor_view.rule_text
                    });
                let highlight = applied_view.as_ref().map_or(editor_view.highlight(), |v| {
                    v.highlight().min(editor_view.highlight())
                });
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
        // Most exposed (under either ruleset) first; stable: the scan's
        // protocol/port order within each group
        rows.sort_by_key(|row| {
            row.applied
                .as_ref()
                .map_or(row.editor.rank, |v| v.rank.min(row.editor.rank))
        });
        self.rows = rows;

        self.ssh_lines = crate::core::lockout::check_sessions(editor, &self.sessions)
            .iter()
            .map(|check| SshLine {
                text: format!("SSH: {}", check.summary()),
                warning: check.access.needs_confirmation(),
            })
            .collect();

        self.notes = crate::core::host_facts::forwarding_warning(self.forwarding, editor)
            .into_iter()
            .chain(
                self.containers
                    .note_for(editor.advanced_security.block_forwarding),
            )
            .collect();

        let total = self.rows.len();
        let count = |level: Highlight| self.rows.iter().filter(|r| r.highlight == level).count();
        let open = count(Highlight::Everyone);
        // Docker-ness is the socket's, the same under both rulesets
        let docker = self
            .rows
            .iter()
            .filter(|r| r.editor.tone.is_docker())
            .count();
        let open_on = self
            .rows
            .iter()
            .filter(|r| r.highlight == Highlight::Interfaces && !r.editor.tone.is_docker())
            .count();
        self.summary = match (&self.error, total) {
            (Some(_), _) => "No sockets to show.".to_string(),
            (None, 0) => "No listening sockets found.".to_string(),
            (None, _) => {
                let sockets = if total == 1 { "socket" } else { "sockets" };
                let mut summary = format!("{total} listening {sockets} · {open} open to everyone");
                if open_on > 0 {
                    let _ = write!(summary, " · {open_on} open on some interfaces only");
                }
                if docker > 0 {
                    let _ = write!(summary, " · {docker} published by Docker");
                }
                summary
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
                // Docker's proxy runs as root
                ListeningSocket {
                    uid: 0,
                    ..socket(Transport::Tcp, "0.0.0.0", 8080)
                },
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
            ..ExposureScan::default()
        }
    }

    fn applied_baseline(ruleset: &FirewallRuleset) -> Baseline<'_> {
        Baseline {
            ruleset,
            kind: BaselineKind::Applied,
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
        assert_eq!(first.highlight, Highlight::Everyone);
        assert_eq!(first.editor.badge.as_deref(), Some(OPEN_BADGE));
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

    /// S3: a port Docker publishes is marked as such (not "open to
    /// everyone" or "nobody": the rules do not decide it), under both the
    /// editor and the applied rules; forwarding and container-network notes
    /// follow the editor rules.
    #[test]
    fn test_docker_published_ports_and_notes() {
        use crate::core::host_facts::{
            CONTAINER_NETWORKS_NOTE_FORWARD_FILTERED, FORWARDING_WARNING, ForwardingState,
            PublishedPort,
        };
        let mut editor = FirewallRuleset::new();
        editor.rules.push(rule("web", Protocol::Tcp, 8080, &[]));
        let applied = FirewallRuleset::new();
        let published = ContainerFacts {
            published: vec![PublishedPort {
                transport: Transport::Tcp,
                host_ip: Some("0.0.0.0".parse().unwrap()),
                host_port: 8080,
                container_ip: Some("172.17.0.2".parse().unwrap()),
                container_port: Some(80),
            }],
            bridges: true,
        };
        let mut panel = ExposurePanel::scanning();
        panel.set_scan(
            Ok(ExposureScan {
                sockets: sockets(),
                forwarding: ForwardingState {
                    ipv4: true,
                    ipv6: false,
                },
                containers: published,
                ..ExposureScan::default()
            }),
            &editor,
            Some(applied_baseline(&applied)),
        );
        let web = panel
            .rows
            .iter()
            .find(|r| r.port_proto == "TCP 8080")
            .unwrap();
        assert_eq!(web.editor.tone, ReachTone::PublishedByDocker);
        assert_eq!(web.editor.badge.as_deref(), Some(DOCKER_BADGE));
        assert_eq!(
            web.editor.text,
            "Published by Docker: not filtered by DRFW's rules"
        );
        assert_eq!(web.editor.edit_rule_id, None);
        assert!(web.applied.is_none(), "the same under both rulesets");
        assert_eq!(web.highlight, Highlight::Interfaces);
        assert_eq!(
            panel.summary,
            "4 listening sockets · 0 open to everyone · 1 published by Docker"
        );
        assert_eq!(panel.notes, [FORWARDING_WARNING], "a proxy was found");

        // Forwarding blocked in the editor: no forwarding note; container
        // networks without a proxy: the note for blocked forwarding
        editor.advanced_security.block_forwarding = true;
        panel.set_scan(
            Ok(ExposureScan {
                sockets: sockets(),
                forwarding: ForwardingState {
                    ipv4: true,
                    ipv6: true,
                },
                containers: ContainerFacts {
                    published: Vec::new(),
                    bridges: true,
                },
                ..ExposureScan::default()
            }),
            &editor,
            None,
        );
        assert_eq!(panel.notes, [CONTAINER_NETWORKS_NOTE_FORWARD_FILTERED]);
        let web = panel
            .rows
            .iter()
            .find(|r| r.port_proto == "TCP 8080")
            .unwrap();
        assert_eq!(web.editor.tone, ReachTone::Open);

        // A failed scan forgets them
        panel.set_scan(Err("no".into()), &editor, None);
        assert_eq!(panel.notes.len(), 0);
    }

    /// B.M2/L8: with "Block forwarded traffic" on, DRFW's forward chain
    /// decides a port Docker publishes; the row says so, is not highlighted,
    /// and the summary counts cannot underflow.
    #[test]
    fn test_docker_published_with_forwarded_traffic_blocked() {
        use crate::core::host_facts::PublishedPort;
        let containers = || ContainerFacts {
            published: vec![PublishedPort {
                transport: Transport::Tcp,
                host_ip: Some("0.0.0.0".parse().unwrap()),
                host_port: 8080,
                container_ip: Some("172.17.0.2".parse().unwrap()),
                container_port: Some(80),
            }],
            bridges: true,
        };
        let mut editor = FirewallRuleset::new();
        editor.advanced_security.block_forwarding = true;
        let both_blocked = editor.clone();
        let mut panel = ExposurePanel::scanning();
        panel.set_scan(
            Ok(ExposureScan {
                sockets: sockets(),
                containers: containers(),
                ..ExposureScan::default()
            }),
            &editor,
            Some(applied_baseline(&both_blocked)),
        );
        let web = |panel: &ExposurePanel| {
            panel
                .rows
                .iter()
                .find(|r| r.port_proto == "TCP 8080")
                .cloned()
                .unwrap()
        };
        let row = web(&panel);
        assert_eq!(row.editor.tone, ReachTone::PublishedByDockerFiltered);
        assert_eq!(
            row.editor.text,
            "Published by Docker: decided by your Forwarded rules (blocked unless one allows it)"
        );
        assert_eq!(row.editor.badge.as_deref(), Some(DOCKER_BADGE));
        assert_eq!(row.highlight, Highlight::None);
        assert_eq!(
            panel.summary,
            "4 listening sockets · 0 open to everyone · 1 published by Docker"
        );

        // Kernel rules without blocking: the row shows both answers and is
        // marked by the unfiltered one; still one Docker row, none "open on"
        let unblocked = FirewallRuleset::new();
        panel.set_scan(
            Ok(ExposureScan {
                sockets: sockets(),
                containers: containers(),
                ..ExposureScan::default()
            }),
            &editor,
            Some(applied_baseline(&unblocked)),
        );
        let row = web(&panel);
        assert_eq!(row.editor.tone, ReachTone::PublishedByDockerFiltered);
        assert_eq!(
            row.applied.as_ref().map(|v| v.tone),
            Some(ReachTone::PublishedByDocker)
        );
        assert_eq!(row.highlight, Highlight::Interfaces);
        assert!(panel.summary.ends_with(" · 1 published by Docker"));
        assert!(!panel.summary.contains("open on some interfaces"));
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
        panel.set_scan(
            Ok(scan(sockets())),
            &editor,
            Some(applied_baseline(&applied)),
        );
        assert_eq!(panel.applied, AppliedState::Differs);
        let web = &panel.rows[0];
        assert_eq!(web.port_proto, "TCP 8080");
        assert_eq!(
            web.highlight,
            Highlight::Everyone,
            "open under the applied rules"
        );
        assert_eq!(web.editor.tone, ReachTone::Closed);
        let applied_view = web.applied.as_ref().expect("differs");
        assert_eq!(applied_view.badge.as_deref(), Some(OPEN_BADGE));
        assert_eq!(applied_view.edit_rule_id, None, "not in the editor");
        let ssh = panel
            .rows
            .iter()
            .find(|r| r.port_proto == "TCP 22")
            .unwrap();
        assert!(ssh.applied.is_none(), "same answer");

        // The same rules: one answer per row
        panel.rebuild(&applied, Some(applied_baseline(&applied)));
        assert_eq!(panel.applied, AppliedState::SameAsEditor);
        assert!(panel.rows.iter().all(|r| r.applied.is_none()));
        assert_eq!(panel.rows[0].editor.badge.as_deref(), Some(OPEN_BADGE));
    }

    /// "Accept all TCP on tailscale0": everyone on the tailnet, an amber
    /// "OPEN ON" badge (not the red one), after the sockets open on any
    /// interface.
    #[test]
    fn test_interface_scoped_rows_are_amber_and_after_open_ones() {
        let mut editor = FirewallRuleset::new();
        editor.rules.push(rule("web", Protocol::Tcp, 8080, &[]));
        let mut tailnet = rule("Tailscale Interface", Protocol::Tcp, 0, &[]);
        tailnet.ports.clear();
        tailnet.interface = Some("tailscale0".into());
        tailnet.rebuild_caches();
        editor.rules.push(tailnet);
        let mut panel = ExposurePanel::scanning();
        panel.set_scan(Ok(scan(sockets())), &editor, None);

        assert_eq!(
            panel.summary,
            "4 listening sockets · 1 open to everyone · 1 open on some interfaces only"
        );
        let ports: Vec<&str> = panel.rows.iter().map(|r| r.port_proto.as_str()).collect();
        assert_eq!(ports[..2], ["TCP 8080", "TCP 22"]);
        let ssh = &panel.rows[1];
        assert_eq!(ssh.highlight, Highlight::Interfaces);
        assert_eq!(ssh.editor.tone, ReachTone::OpenOnInterfaces);
        assert_eq!(ssh.editor.badge.as_deref(), Some("OPEN ON tailscale0"));
        assert_eq!(ssh.editor.text, "Reachable from: everyone on tailscale0");
        assert_eq!(ssh.editor.rule_text, "rule \"Tailscale Interface\"");
        assert_eq!(panel.rows[2].highlight, Highlight::None);

        // The user's case: the only rule is the interface one
        editor.rules.remove(0);
        panel.rebuild(&editor, None);
        assert_eq!(
            panel.summary,
            "4 listening sockets · 0 open to everyone · 2 open on some interfaces only"
        );
        assert!(
            panel
                .rows
                .iter()
                .all(|r| r.editor.badge.as_deref() != Some(OPEN_BADGE))
        );
    }

    /// Before the first apply, the kept record is the baseline, labelled by
    /// where it comes from; without one the panel says nothing is known.
    #[test]
    fn test_kept_record_baseline_notes() {
        let mut editor = FirewallRuleset::new();
        editor.rules.push(rule("ssh", Protocol::Tcp, 22, &[]));
        let mut kept = FirewallRuleset::new();
        kept.rules.push(rule("old web", Protocol::Tcp, 8080, &[]));
        let mut panel = ExposurePanel::scanning();

        panel.set_scan(Ok(scan(sockets())), &editor, None);
        assert_eq!(panel.applied, AppliedState::Unknown);
        assert!(
            panel.applied_note.contains("not known"),
            "{}",
            panel.applied_note
        );

        let this_boot = Baseline {
            ruleset: &kept,
            kind: BaselineKind::KeptThisBoot,
        };
        panel.rebuild(&editor, Some(this_boot));
        assert_eq!(panel.applied, AppliedState::Differs);
        assert_eq!(panel.applied_label, "APPLIED");
        assert!(
            panel
                .applied_note
                .contains("last applied and kept (this boot)")
        );
        assert!(
            panel
                .applied_note
                .contains("not applied rules this session")
        );
        let web = panel
            .rows
            .iter()
            .find(|r| r.port_proto == "TCP 8080")
            .unwrap();
        assert!(web.applied.is_some(), "the kept answer differs");

        let earlier = Baseline {
            ruleset: &kept,
            kind: BaselineKind::KeptEarlierSession,
        };
        panel.rebuild(&editor, Some(earlier));
        assert_eq!(panel.applied_label, "KEPT");
        assert!(panel.applied_note.contains("\"Kept\""));
        assert!(panel.applied_note.contains("earlier session"));

        let same = Baseline {
            ruleset: &editor,
            kind: BaselineKind::KeptEarlierSession,
        };
        panel.rebuild(&editor, Some(same));
        assert_eq!(panel.applied, AppliedState::SameAsEditor);
        assert!(panel.applied_note.contains("may have replaced"));
    }

    #[test]
    fn test_ssh_lines_follow_the_editor_rules() {
        let session = SshSession {
            client: "10.0.0.5".parse().unwrap(),
            client_port: 50000,
            server: "10.0.0.1".parse().unwrap(),
            server_port: 22,
            source: crate::core::lockout::SessionSource::Environment,
            interface: None,
        };
        let mut editor = FirewallRuleset::new();
        let mut panel = ExposurePanel::scanning();
        panel.set_scan(
            Ok(ExposureScan {
                sockets: sockets(),
                sessions: vec![session],
                ..ExposureScan::default()
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

    /// With local network discovery on, the mDNS socket is "local network
    /// (discovery)", shown like a restricted socket (not open, not counted);
    /// ordinary UDP sockets are not reachable through discovery replies.
    #[test]
    fn test_local_discovery_is_not_counted_as_open() {
        let mut editor = FirewallRuleset::new();
        editor.advanced_security.local_discovery = true;
        let mut list = sockets();
        list.extend(build_socket_list(
            vec![socket(Transport::Udp, "0.0.0.0", 51820)],
            &HashMap::new(),
            1000,
            false,
            |_| None,
        ));
        let mut panel = ExposurePanel::scanning();
        panel.set_scan(Ok(scan(list)), &editor, None);
        assert_eq!(panel.summary, "5 listening sockets · 0 open to everyone");
        let by_port = |p: &str| panel.rows.iter().find(|r| r.port_proto == p).unwrap();
        let mdns = &by_port("UDP 5353").editor;
        assert_eq!(mdns.tone, ReachTone::Restricted);
        assert_eq!(
            mdns.text,
            format!("Reachable from: {}", crate::core::exposure::LOCAL_DISCOVERY)
        );
        assert_eq!(mdns.badge, None);
        assert_eq!(mdns.rule_text, "built-in rule \"allow mdns\"");
        let other = &by_port("UDP 51820").editor;
        assert_eq!(other.tone, ReachTone::Closed);
        assert_eq!(other.text, "Reachable from: nobody");
    }
}
