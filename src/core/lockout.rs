//! SSH lockout check: would the rules about to be applied keep you from
//! reconnecting over SSH?
//!
//! # Which sessions
//!
//! SSH sessions into this computer are found without privileges, from two
//! sources:
//!
//! 1. **`SSH_CONNECTION`** of the DRFW process (`client-ip client-port
//!    server-ip server-port`, set by `sshd` for the session DRFW runs in).
//!    This is the session that matters most and is exact.
//! 2. **Established TCP connections** in `/proc/net/tcp{,6}`
//!    ([`crate::core::exposure::scan_host`]). One counts as an SSH session
//!    when
//!    - a process holding the socket is readable and named `sshd*` or
//!      `dropbear` (OpenSSH runs each logged-in session as the user, so the
//!      user's own sessions are found this way, by name), or
//!    - no process holding it is readable (another user's, typically root's)
//!      and its local port is an SSH port: a listening TCP port whose
//!      readable owner is `sshd*`/`dropbear`, or port 22 when the owner of
//!      its listener is not readable.
//!
//!    Other users' sessions on a non-standard port whose server is not
//!    readable are not found: assuming every port with an unreadable server
//!    is SSH would count every root-owned service. A connection held by a
//!    readable process with another name is never counted.
//!
//! Sessions from loopback addresses are skipped (the loopback accept comes
//! first in the chain). Duplicates (the `SSH_CONNECTION` session also shows
//! up in `/proc`) are merged.
//!
//! # What is checked
//!
//! Open sessions survive any apply: established connections are accepted
//! before any user rule, on input and (in Server mode) on output. The risk is
//! the **next** connection. For each session the evaluator
//! ([`crate::core::evaluate`]) is asked what the input chain does with a new
//! TCP connection from the session's client address to the session's server
//! address and port, on an unknown interface:
//!
//! - [`Access::Blocked`]: the first packet is dropped or rejected;
//! - [`Access::MayBeBlocked`]: it is accepted only under a condition (a rate
//!   or connection limit, an interface) with a drop or reject behind it;
//! - [`Access::Accepted`] otherwise.
//!
//! Both of the first two need an explicit confirmation ([`LockoutWarning`]).
//!
//! # Server mode
//!
//! Server mode (output policy drop) cannot cut the replies of an SSH session:
//! the generated output chain accepts `ct state established,related` before
//! any user output rule, preceded only by the loopback accept and the
//! `ct state invalid` drop. Replies of an open session, and the SYN-ACK of a
//! new connection the input chain accepted, are in conntrack state
//! established. So no output check is needed; a test guards this order.
//! (Server mode can still slow a login down when `sshd` looks up the
//! client's name and no rule allows DNS.)

use std::collections::HashSet;
use std::fmt::Write as _;
use std::net::IpAddr;

use super::evaluate::{InputChain, IpFamily, Probe, ProbeSource, Transport, Verdict};
use super::exposure::{HostScan, ProcessInfo};
use super::firewall::{Action, FirewallRuleset};

/// Environment variable `sshd` sets for a session.
pub const SSH_CONNECTION_VAR: &str = "SSH_CONNECTION";

/// The default SSH port, assumed when the server's process is not readable.
const DEFAULT_SSH_PORT: u16 = 22;

/// How a session was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SessionSource {
    /// `SSH_CONNECTION` of this process: the session DRFW runs in
    Environment,
    /// An established connection held by an `sshd`/`dropbear` process
    SshdProcess,
    /// An established connection to an SSH port, process not readable
    SshPort,
}

impl SessionSource {
    /// Stable name for `--json` output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::SshdProcess => "sshd_process",
            Self::SshPort => "ssh_port",
        }
    }
}

/// An SSH session into this computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSession {
    /// The client's address (IPv4-mapped addresses as IPv4)
    pub client: IpAddr,
    pub client_port: u16,
    /// The address of this computer the client connected to
    pub server: IpAddr,
    pub server_port: u16,
    pub source: SessionSource,
}

/// Parses one address of `SSH_CONNECTION`: an IPv4 or IPv6 address, an IPv6
/// zone (`fe80::1%eth0`) dropped, IPv4-mapped addresses as IPv4.
fn parse_address(field: &str) -> Option<IpAddr> {
    let address = field.split_once('%').map_or(field, |(address, _)| address);
    address.parse::<IpAddr>().ok().map(|a| a.to_canonical())
}

/// Parses a port of `SSH_CONNECTION` (1-65535).
fn parse_port(field: &str) -> Option<u16> {
    field.parse::<u16>().ok().filter(|&port| port != 0)
}

/// Parses an `SSH_CONNECTION` value: `client-ip client-port server-ip
/// server-port`, separated by whitespace.
///
/// Returns `None` for anything else (wrong field count, bad address or port,
/// port 0).
///
/// # Example
///
/// ```
/// use drfw::core::lockout::parse_ssh_connection;
///
/// let session = parse_ssh_connection("2001:db8::5 50122 2001:db8::1 22").unwrap();
/// assert_eq!(session.client.to_string(), "2001:db8::5");
/// assert_eq!(session.server_port, 22);
/// assert!(parse_ssh_connection("10.0.0.5 50122 10.0.0.1").is_none());
/// ```
pub fn parse_ssh_connection(value: &str) -> Option<SshSession> {
    let fields: Vec<&str> = value.split_whitespace().collect();
    let [client, client_port, server, server_port] = fields.as_slice() else {
        return None;
    };
    Some(SshSession {
        client: parse_address(client)?,
        client_port: parse_port(client_port)?,
        server: parse_address(server)?,
        server_port: parse_port(server_port)?,
        source: SessionSource::Environment,
    })
}

/// The session of this process, from `SSH_CONNECTION` (cheap: reads the
/// environment only).
pub fn session_from_env() -> Option<SshSession> {
    std::env::var(SSH_CONNECTION_VAR)
        .ok()
        .and_then(|value| parse_ssh_connection(&value))
}

/// `true` for the process names of SSH servers.
fn is_ssh_server(name: &str) -> bool {
    name.starts_with("sshd") || name == "dropbear"
}

fn any_ssh_server(processes: &[ProcessInfo]) -> bool {
    processes.iter().any(|p| is_ssh_server(&p.name))
}

/// The SSH sessions among the established connections of `scan` (see the
/// module docs for the rules).
pub fn sessions_from_scan(scan: &HostScan) -> Vec<SshSession> {
    let ssh_ports: HashSet<u16> = scan
        .sockets
        .iter()
        .filter(|s| s.transport == Transport::Tcp)
        .filter(|s| {
            if s.processes.is_empty() {
                s.port == DEFAULT_SSH_PORT
            } else {
                any_ssh_server(&s.processes)
            }
        })
        .map(|s| s.port)
        .collect();
    scan.established
        .iter()
        .filter_map(|(connection, processes)| {
            let source = if any_ssh_server(processes) {
                SessionSource::SshdProcess
            } else if processes.is_empty() && ssh_ports.contains(&connection.local_port) {
                SessionSource::SshPort
            } else {
                return None;
            };
            Some(SshSession {
                client: connection.remote.to_canonical(),
                client_port: connection.remote_port,
                server: connection.local.to_canonical(),
                server_port: connection.local_port,
                source,
            })
        })
        .collect()
}

/// `env` first, then `found`; loopback clients skipped, duplicates (same
/// client address and port, same server port) merged, keeping the first.
pub fn merge_sessions(env: Option<SshSession>, found: Vec<SshSession>) -> Vec<SshSession> {
    let mut sessions: Vec<SshSession> = Vec::with_capacity(found.len() + 1);
    for session in env.into_iter().chain(found) {
        if session.client.is_loopback() {
            continue;
        }
        let duplicate = sessions.iter().any(|s| {
            s.client == session.client
                && s.client_port == session.client_port
                && s.server_port == session.server_port
        });
        if !duplicate {
            sessions.push(session);
        }
    }
    sessions
}

/// Every SSH session into this computer: `env` (the `SSH_CONNECTION`
/// session, see [`session_from_env`]) and the ones in `/proc`.
///
/// Blocking (reads `/proc`); run it off the UI thread. A failed scan only
/// loses the `/proc` sessions (logged).
pub fn detect_sessions(env: Option<SshSession>) -> Vec<SshSession> {
    let found = match crate::core::exposure::scan_host() {
        Ok(scan) => sessions_from_scan(&scan),
        Err(e) => {
            tracing::debug!("SSH session scan skipped: {e}");
            Vec::new()
        }
    };
    merge_sessions(env, found)
}

/// Whether a new connection from a session's client gets in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Accepted,
    /// Accepted only under a condition, with a drop or reject behind it
    MayBeBlocked,
    /// The first packet is dropped or rejected
    Blocked,
}

impl Access {
    /// Stable name for `--json` output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::MayBeBlocked => "may_be_blocked",
            Self::Blocked => "blocked",
        }
    }
}

/// What the rules do with a new connection from one session's client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCheck {
    pub session: SshSession,
    pub verdict: Verdict,
    pub access: Access,
    /// "accepted by rule \"SSH\"", "BLOCKED: rejected by …", …
    pub outcome: String,
}

impl SessionCheck {
    /// "you are connected from X to port 22; new connections from X would be
    /// …" (for `drfw status` and the Exposure panel, after "SSH: ").
    pub fn summary(&self) -> String {
        let session = &self.session;
        let mut line = match session.source {
            SessionSource::Environment => format!("you are connected from {}", session.client),
            SessionSource::SshdProcess => format!("an SSH session from {}", session.client),
            SessionSource::SshPort => {
                format!("a connection (assumed SSH) from {}", session.client)
            }
        };
        let _ = write!(
            line,
            " to port {}; new connections from {} would be {}",
            session.server_port, session.client, self.outcome
        );
        line
    }
}

/// The verdict at the end of the `Limited` layers.
fn innermost(verdict: &Verdict) -> &Verdict {
    match verdict {
        Verdict::Limited { otherwise, .. } => innermost(otherwise),
        other => other,
    }
}

const fn verb(action: Action) -> &'static str {
    match action {
        Action::Accept => "accepted",
        Action::Drop => "dropped",
        Action::Reject => "rejected",
    }
}

/// Evaluates a new connection from `session`'s client to its server address
/// and port (interface unknown) against `chain`.
pub fn check_session(chain: &InputChain, session: &SshSession) -> SessionCheck {
    let probe = Probe {
        transport: Transport::Tcp,
        port: session.server_port,
        family: IpFamily::of(session.client),
        interface: None,
        destination: Some(session.server),
        source: ProbeSource::Addr(session.client),
    };
    let verdict = chain.evaluate(&probe);
    let first = verdict.first_packet();
    let fallback_blocks = matches!(
        innermost(&verdict),
        Verdict::Dropped(_) | Verdict::Rejected(_)
    );
    let (access, outcome) = match first {
        Some((action @ (Action::Drop | Action::Reject), by)) => (
            Access::Blocked,
            format!("BLOCKED: {} by {by}", verb(action)),
        ),
        _ if fallback_blocks => (
            Access::MayBeBlocked,
            format!("blocked in some cases: {verdict}"),
        ),
        Some((_, by)) => (Access::Accepted, format!("accepted by {by}")),
        None => (Access::Accepted, verdict.to_string()),
    };
    SessionCheck {
        session: session.clone(),
        verdict,
        access,
        outcome,
    }
}

/// Checks every session against `ruleset`, one check per client address and
/// server address/port (sessions that would get the same answer are listed
/// once, the first one kept).
pub fn check_sessions(ruleset: &FirewallRuleset, sessions: &[SshSession]) -> Vec<SessionCheck> {
    let chain = InputChain::new(ruleset);
    let mut seen: HashSet<(IpAddr, IpAddr, u16)> = HashSet::with_capacity(sessions.len());
    sessions
        .iter()
        .filter(|s| seen.insert((s.client, s.server, s.server_port)))
        .map(|s| check_session(&chain, s))
        .collect()
}

/// `text` with its first letter in upper case.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// Why a ruleset needs an explicit confirmation: new SSH connections from a
/// current session's client would be (or may be) turned away. Shown with the
/// retention guard's warning, before Apply and Save to System.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockoutWarning {
    /// Checks that are [`Access::Blocked`] or [`Access::MayBeBlocked`]
    pub checks: Vec<SessionCheck>,
    /// One line per check, then what happens to the open sessions
    pub lines: Vec<String>,
}

impl LockoutWarning {
    /// Heading shown above [`Self::lines`].
    pub const HEADING: &'static str = "These rules could lock you out of SSH:";

    /// The warning for applying (or saving) `ruleset` while `sessions` are
    /// open; `None` when every session's client could reconnect.
    pub fn check(ruleset: &FirewallRuleset, sessions: &[SshSession]) -> Option<Self> {
        let checks: Vec<SessionCheck> = check_sessions(ruleset, sessions)
            .into_iter()
            .filter(|c| c.access != Access::Accepted)
            .collect();
        if checks.is_empty() {
            return None;
        }
        let mut lines: Vec<String> = checks.iter().map(|c| capitalized(&c.summary())).collect();
        lines.push(
            "Open sessions stay connected (established connections are always accepted); \
             the risk is the next connection."
                .to_string(),
        );
        Some(Self { checks, lines })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::exposure::{EstablishedSocket, SocketInfo, build_socket_list};
    use crate::core::firewall::{Chain, EgressProfile, PortEntry, Protocol, RateLimit, TimeUnit};
    use crate::core::test_helpers::create_test_rule;

    fn session(client: &str, port: u16) -> SshSession {
        SshSession {
            client: client.parse().unwrap(),
            client_port: 50000,
            server: if client.contains(':') {
                "fd00::1".parse().unwrap()
            } else {
                "192.168.1.1".parse().unwrap()
            },
            server_port: port,
            source: SessionSource::Environment,
        }
    }

    #[test]
    fn test_parse_ssh_connection_ipv4_and_ipv6() {
        let s = parse_ssh_connection("192.168.1.5 50122 192.168.1.1 22").unwrap();
        assert_eq!(s.client.to_string(), "192.168.1.5");
        assert_eq!(
            (s.client_port, s.server.to_string(), s.server_port),
            (50122, "192.168.1.1".to_string(), 22)
        );
        assert_eq!(s.source, SessionSource::Environment);

        let s = parse_ssh_connection("2001:db8::5 41000 2001:db8::1 2222").unwrap();
        assert_eq!(s.client.to_string(), "2001:db8::5");
        assert_eq!(s.server_port, 2222);
        // Zone ids are dropped, mapped addresses are IPv4, extra spaces are fine
        let s = parse_ssh_connection("  fe80::5%eth0  41000\tfe80::1%eth0 22\n").unwrap();
        assert_eq!(s.client.to_string(), "fe80::5");
        let s = parse_ssh_connection("::ffff:10.0.0.5 41000 ::ffff:10.0.0.1 22").unwrap();
        assert_eq!(s.client.to_string(), "10.0.0.5");
        assert!(s.client.is_ipv4());
    }

    #[test]
    fn test_parse_ssh_connection_rejects_malformed_values() {
        for value in [
            "",
            "10.0.0.5",
            "10.0.0.5 50122 10.0.0.1",
            "10.0.0.5 50122 10.0.0.1 22 extra",
            "10.0.0.500 50122 10.0.0.1 22",
            "host.example 50122 10.0.0.1 22",
            "10.0.0.5 0 10.0.0.1 22",
            "10.0.0.5 50122 10.0.0.1 0",
            "10.0.0.5 65536 10.0.0.1 22",
            "10.0.0.5 -1 10.0.0.1 22",
            "10.0.0.5 50122 10.0.0.1 ssh",
            "[2001:db8::5] 50122 2001:db8::1 22",
        ] {
            assert_eq!(parse_ssh_connection(value), None, "{value:?}");
        }
    }

    fn listener(port: u16, uid: u32, inode: u64) -> crate::core::exposure::ListeningSocket {
        crate::core::exposure::ListeningSocket {
            transport: Transport::Tcp,
            ipv6_socket: false,
            local: "0.0.0.0".parse().unwrap(),
            port,
            uid,
            inode,
        }
    }

    fn connection(local_port: u16, remote: &str, inode: u64) -> EstablishedSocket {
        EstablishedSocket {
            local: "192.168.1.1".parse().unwrap(),
            local_port,
            remote: remote.parse().unwrap(),
            remote_port: 40000 + local_port,
            uid: 0,
            inode,
        }
    }

    fn named(name: &str) -> Vec<ProcessInfo> {
        vec![ProcessInfo {
            pid: 1,
            name: name.into(),
        }]
    }

    fn sockets(owners: &[(u64, &str)]) -> Vec<SocketInfo> {
        let map: std::collections::HashMap<u64, Vec<ProcessInfo>> = owners
            .iter()
            .map(|&(inode, name)| (inode, named(name)))
            .collect();
        build_socket_list(
            vec![listener(22, 0, 1), listener(2222, 0, 2), listener(80, 0, 3)],
            &map,
            1000,
            false,
            |_| None,
        )
    }

    #[test]
    fn test_sessions_from_scan() {
        let scan = HostScan {
            // Only 2222's server is readable (sshd); 22 and 80 are not
            sockets: sockets(&[(2, "sshd")]),
            established: vec![
                // Held by the user's own session process: SSH by name
                (connection(22, "10.0.0.5", 10), named("sshd-session")),
                // Another user's, to port 22 (server not readable): assumed
                (connection(22, "10.0.0.6", 11), Vec::new()),
                // To the readable sshd on 2222
                (connection(2222, "::ffff:10.0.0.7", 12), Vec::new()),
                // Not SSH: port 80, or a readable non-SSH process
                (connection(80, "10.0.0.8", 13), Vec::new()),
                (connection(22, "10.0.0.9", 14), named("nc")),
            ],
        };
        let found: Vec<(String, u16, SessionSource)> = sessions_from_scan(&scan)
            .into_iter()
            .map(|s| (s.client.to_string(), s.server_port, s.source))
            .collect();
        assert_eq!(
            found,
            [
                ("10.0.0.5".to_string(), 22, SessionSource::SshdProcess),
                ("10.0.0.6".to_string(), 22, SessionSource::SshPort),
                ("10.0.0.7".to_string(), 2222, SessionSource::SshPort),
            ]
        );

        // 22's server readable and not sshd: port 22 is not assumed
        let scan = HostScan {
            sockets: sockets(&[(1, "gitea")]),
            established: vec![(connection(22, "10.0.0.6", 11), Vec::new())],
        };
        assert_eq!(sessions_from_scan(&scan), Vec::new());
    }

    #[test]
    fn test_merge_sessions_dedupes_and_skips_loopback() {
        let env = session("10.0.0.5", 22);
        let mut same = env.clone();
        same.source = SessionSource::SshdProcess;
        let mut other_port = env.clone();
        other_port.client_port = 50001;
        let lo = session("127.0.0.1", 22);
        let merged = merge_sessions(Some(env.clone()), vec![same, other_port.clone(), lo]);
        assert_eq!(merged, [env, other_port]);
        assert_eq!(
            merge_sessions(Some(session("::1", 22)), Vec::new()),
            Vec::new()
        );
    }

    fn ssh_rule(sources: &[&str]) -> crate::core::firewall::Rule {
        let mut r = create_test_rule("SSH", Some(22));
        r.protocol = Protocol::Tcp;
        r.sources = sources.iter().map(|s| s.parse().unwrap()).collect();
        r.rebuild_caches();
        r
    }

    #[test]
    fn test_blocked_accepted_and_limited_sessions() {
        let mut ruleset = FirewallRuleset::new();
        // No rule for SSH: the final reject turns new connections away
        let warning = LockoutWarning::check(&ruleset, &[session("10.0.0.5", 22)]).expect("warns");
        assert_eq!(warning.checks[0].access, Access::Blocked);
        assert_eq!(
            warning.lines[0],
            "You are connected from 10.0.0.5 to port 22; new connections from 10.0.0.5 \
             would be BLOCKED: rejected by built-in rule \"rate-limited reject\""
        );
        assert!(warning.lines[1].contains("Open sessions stay connected"));

        // Allowed from the LAN only: IPv4 client in it, IPv6 client not
        ruleset.rules.push(ssh_rule(&["10.0.0.0/8"]));
        let checks = check_sessions(&ruleset, &[session("10.0.0.5", 22), session("fd00::5", 22)]);
        assert_eq!(checks[0].access, Access::Accepted);
        assert_eq!(
            checks[0].summary(),
            "you are connected from 10.0.0.5 to port 22; new connections from 10.0.0.5 \
             would be accepted by rule \"SSH\""
        );
        assert_eq!(checks[1].access, Access::Blocked);
        let warning =
            LockoutWarning::check(&ruleset, &[session("10.0.0.5", 22), session("fd00::5", 22)])
                .expect("the IPv6 session");
        assert_eq!(warning.checks.len(), 1);

        // A rate-limited accept: accepted first, rejected over the limit
        let mut limited = ssh_rule(&[]);
        limited.rate_limit = Some(RateLimit {
            count: 3,
            unit: TimeUnit::Minute,
            burst: None,
            per_source: true,
        });
        let ruleset = FirewallRuleset {
            rules: vec![limited],
            ..FirewallRuleset::new()
        };
        let check = &check_sessions(&ruleset, &[session("10.0.0.5", 22)])[0];
        assert_eq!(check.access, Access::MayBeBlocked);
        assert!(
            check.outcome.starts_with(
                "blocked in some cases: accepted up to 3/minute per source by rule \"SSH\""
            ),
            "{}",
            check.outcome
        );

        // An interface-bound accept: the interface is unknown, the fallback rejects
        let mut on_eth = ssh_rule(&[]);
        on_eth.interface = Some("eth0".into());
        let ruleset = FirewallRuleset {
            rules: vec![on_eth],
            ..FirewallRuleset::new()
        };
        let check = &check_sessions(&ruleset, &[session("10.0.0.5", 22)])[0];
        assert_eq!(check.access, Access::MayBeBlocked);
    }

    #[test]
    fn test_same_client_and_port_checked_once_and_ports_differ() {
        let ruleset = FirewallRuleset {
            rules: vec![ssh_rule(&[])],
            ..FirewallRuleset::new()
        };
        let mut second = session("10.0.0.5", 22);
        second.client_port = 50001;
        let checks = check_sessions(
            &ruleset,
            &[session("10.0.0.5", 22), second, session("10.0.0.5", 2222)],
        );
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].access, Access::Accepted);
        assert_eq!(checks[1].access, Access::Blocked, "nothing allows 2222");
        assert!(LockoutWarning::check(&ruleset, &[session("10.0.0.5", 22)]).is_none());
        assert!(LockoutWarning::check(&ruleset, &[]).is_none());
    }

    /// The Server mode argument of the module docs: in the generated output
    /// chain the established accept comes before every user rule, after
    /// only the loopback accept and the invalid drop.
    #[test]
    fn test_server_mode_output_accepts_established_before_user_rules() {
        use crate::core::firewall::CommandOrigin;

        let mut block_all = create_test_rule("block everything out", None);
        block_all.protocol = Protocol::Any;
        block_all.chain = Chain::Output;
        block_all.action = crate::core::firewall::Action::Drop;
        let mut block_ssh = create_test_rule("block ssh out", None);
        block_ssh.protocol = Protocol::Tcp;
        block_ssh.ports = vec![PortEntry::Single(22)];
        block_ssh.chain = Chain::Output;
        block_ssh.action = crate::core::firewall::Action::Reject;
        let mut ruleset = FirewallRuleset {
            rules: vec![block_all, block_ssh],
            ..FirewallRuleset::new()
        };
        ruleset.advanced_security.egress_profile = EgressProfile::Server;
        let output: Vec<CommandOrigin> = ruleset
            .build_commands()
            .into_iter()
            .filter(|c| c.value["add"]["rule"]["chain"] == "output")
            .map(|c| c.origin)
            .collect();
        assert_eq!(
            output[..3],
            [
                CommandOrigin::BaseRule("allow to loopback"),
                CommandOrigin::BaseRule("early drop of invalid outbound connections"),
                CommandOrigin::BaseRule("allow outbound tracked connections"),
            ]
        );
        assert!(
            output[3..]
                .iter()
                .any(|o| matches!(o, CommandOrigin::UserRule(_))),
            "the user rules come later: {output:?}"
        );
    }
}
