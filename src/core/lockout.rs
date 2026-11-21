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
//! address and port, on the session's interface (see below):
//!
//! - [`Access::Blocked`]: the first packet is dropped or rejected;
//! - [`Access::MayBeBlocked`]: whether it is turned away depends on something
//!   the check cannot settle, typically an interface-bound rule when the
//!   interface is unknown;
//! - [`Access::Limited`]: it is accepted, but a rate or connection limit can
//!   turn later connections away (e.g. "SSH up to 3/minute per source", the
//!   recommended setup);
//! - [`Access::Accepted`] otherwise.
//!
//! The first two need an explicit confirmation ([`LockoutWarning::lines`]);
//! `Limited` is only a note ([`LockoutWarning::notes`]): asking every time
//! for a limit that is there on purpose would teach people to click through
//! the warning. Like the evaluator's first-packet answer, the check assumes
//! the client passes the reverse-path check (with RPF on), sends unicast and
//! uses an ephemeral source port: a rule that only decides otherwise (the
//! RPF drop) is neither a warning nor a note.
//!
//! # Which interface
//!
//! The session's interface is the one that owns its server address
//! ([`interface_owning`], from [`local_addresses`]). The incoming interface
//! is normally the one that owns the destination address, but with
//! asymmetric routing (two interfaces on reachable networks, an address on a
//! dummy device) a packet can arrive elsewhere: Linux accepts it on any
//! interface. The resolved interface is still used as known, because the
//! common cases (one uplink, one LAN per interface) are exact and treating it
//! as unknown would make every interface-bound SSH rule ask for a
//! confirmation; whenever the interface decided the answer, the outcome says
//! "assuming they arrive on eth0, the interface that has 10.0.0.1", so the
//! guess is visible. The interface stays unknown (and interface-bound rules
//! stay "blocked in some cases") when no interface has the address, when
//! several do, or when a loopback interface has it (an address on `lo` is
//! reached through another interface).
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

use super::evaluate::{Condition, InputChain, IpFamily, Probe, ProbeSource, Transport, Verdict};
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
    /// The local interface that owns `server`, when exactly one does (see
    /// the module docs and [`resolve_interfaces`]); `None` = unknown
    pub interface: Option<String>,
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
        interface: None,
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
                interface: None,
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

/// Fixture file under `DRFW_TEST_PROC_DIR` that replaces the interface
/// addresses of this computer in [`local_addresses`]: one `name address`
/// pair per line (`lo` counts as loopback; empty lines and `#` comments are
/// skipped).
pub const TEST_ADDRESSES_FILE: &str = "drfw-test-addresses";

/// Name of the loopback interface (in [`TEST_ADDRESSES_FILE`]).
const LOOPBACK_INTERFACE: &str = "lo";

/// One address of a local network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAddress {
    /// The interface as `iifname` matches it (an IPv4 alias label such as
    /// `eth0:1` is its interface, `eth0`)
    pub interface: String,
    pub addr: IpAddr,
    /// The interface is a loopback interface
    pub loopback: bool,
}

/// The interface part of a name `getifaddrs` reports: `eth0:1` (an IPv4
/// alias label) is `eth0`; Linux interface names cannot contain `:`.
fn interface_name(name: &str) -> &str {
    name.split_once(':')
        .map_or(name, |(interface, _)| interface)
}

/// Parses [`TEST_ADDRESSES_FILE`]; malformed lines are skipped.
fn parse_test_addresses(text: &str) -> Vec<LocalAddress> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let (name, addr) = line.split_once(char::is_whitespace)?;
            let interface = interface_name(name).to_string();
            Some(LocalAddress {
                loopback: interface == LOOPBACK_INTERFACE,
                addr: addr.trim().parse().ok()?,
                interface,
            })
        })
        .collect()
}

/// The addresses of this computer's interfaces (`getifaddrs`, through the
/// `network-interface` crate), or with `DRFW_TEST_PROC_DIR` set the ones in
/// its [`TEST_ADDRESSES_FILE`] (none when it is missing: tests never see the
/// machine's own interfaces).
///
/// Blocking (a system call); run it off the UI thread. A failure returns no
/// addresses (logged), which leaves every interface unknown.
pub fn local_addresses() -> Vec<LocalAddress> {
    use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};

    if let Some(dir) = crate::core::exposure::test_proc_root() {
        return std::fs::read_to_string(dir.join(TEST_ADDRESSES_FILE))
            .map_or_else(|_| Vec::new(), |text| parse_test_addresses(&text));
    }
    let interfaces = match NetworkInterface::show() {
        Ok(interfaces) => interfaces,
        Err(e) => {
            tracing::debug!("Interface addresses not read: {e}");
            return Vec::new();
        }
    };
    interfaces
        .iter()
        .flat_map(|iface| {
            iface.addr.iter().map(|addr| LocalAddress {
                interface: interface_name(&iface.name).to_string(),
                addr: match addr {
                    Addr::V4(v4) => IpAddr::V4(v4.ip),
                    Addr::V6(v6) => IpAddr::V6(v6.ip),
                },
                loopback: iface.internal,
            })
        })
        .collect()
}

/// The interface that owns `addr`, if exactly one non-loopback interface
/// has it: `None` when none does, when several do (the address is
/// ambiguous), or when a loopback interface has it.
///
/// # Example
///
/// ```
/// use drfw::core::lockout::{LocalAddress, interface_owning};
///
/// let addresses = [LocalAddress {
///     interface: "eth0".into(),
///     addr: "10.0.0.1".parse().unwrap(),
///     loopback: false,
/// }];
/// assert_eq!(
///     interface_owning(&addresses, "10.0.0.1".parse().unwrap()),
///     Some("eth0")
/// );
/// assert_eq!(
///     interface_owning(&addresses, "10.0.0.2".parse().unwrap()),
///     None
/// );
/// ```
pub fn interface_owning(addresses: &[LocalAddress], addr: IpAddr) -> Option<&str> {
    let addr = addr.to_canonical();
    let mut owner: Option<&str> = None;
    for local in addresses.iter().filter(|a| a.addr.to_canonical() == addr) {
        if local.loopback {
            return None;
        }
        match owner {
            Some(name) if name != local.interface => return None,
            _ => owner = Some(&local.interface),
        }
    }
    owner
}

/// Sets each session's [`SshSession::interface`] to the interface that owns
/// its server address in `addresses` ([`interface_owning`]).
pub fn resolve_interfaces(sessions: &mut [SshSession], addresses: &[LocalAddress]) {
    for session in sessions {
        session.interface = interface_owning(addresses, session.server).map(str::to_owned);
    }
}

/// `sessions` with their interfaces resolved from [`local_addresses`] (read
/// only when there is a session).
///
/// Blocking; run it off the UI thread.
pub fn with_interfaces(mut sessions: Vec<SshSession>) -> Vec<SshSession> {
    if !sessions.is_empty() {
        resolve_interfaces(&mut sessions, &local_addresses());
    }
    sessions
}

/// Every SSH session into this computer: `env` (the `SSH_CONNECTION`
/// session, see [`session_from_env`]) and the ones in `/proc`, with their
/// interfaces ([`with_interfaces`]).
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
    with_interfaces(merge_sessions(env, found))
}

/// Whether a new connection from a session's client gets in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Accepted,
    /// Accepted, but a rate or connection limit can turn later connections
    /// away (a note, no confirmation)
    Limited,
    /// Turned away in some cases the check cannot settle (an interface it
    /// does not know, …)
    MayBeBlocked,
    /// The first packet is dropped or rejected
    Blocked,
}

impl Access {
    /// Stable name for `--json` output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Limited => "limited",
            Self::MayBeBlocked => "may_be_blocked",
            Self::Blocked => "blocked",
        }
    }

    /// `true` for [`Access::Blocked`] and [`Access::MayBeBlocked`]: applying
    /// takes an explicit confirmation.
    pub const fn needs_confirmation(self) -> bool {
        matches!(self, Self::Blocked | Self::MayBeBlocked)
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

const fn verb(action: Action) -> &'static str {
    match action {
        Action::Accept => "accepted",
        Action::Drop => "dropped",
        Action::Reject => "rejected",
    }
}

/// Which outcomes a verdict can still have.
#[derive(Debug, Clone, Copy, Default)]
struct Outcomes {
    accept: bool,
    block: bool,
}

impl Outcomes {
    const fn of(action: Action) -> Self {
        let accept = matches!(action, Action::Accept);
        Self {
            accept,
            block: !accept,
        }
    }

    const fn or(self, other: Self) -> Self {
        Self {
            accept: self.accept || other.accept,
            block: self.block || other.block,
        }
    }
}

/// The outcomes `verdict` can have for a new connection: conditions the
/// probe leaves open (an interface, a destination) can go either way, and
/// so can rate and connection limits when `limits_vary` (else they are
/// fresh); the other conditions are fixed as for the first packet (the
/// source passes the reverse-path check, unicast, an ephemeral source port).
/// Conditions are taken as independent, which can only add outcomes.
fn possible_outcomes(verdict: &Verdict, limits_vary: bool) -> Outcomes {
    match verdict {
        Verdict::Accepted(_) => Outcomes::of(Action::Accept),
        Verdict::Dropped(_) | Verdict::Rejected(_) => Outcomes::of(Action::Drop),
        Verdict::Limited {
            action,
            when,
            otherwise,
            ..
        } => {
            let (mut can_hold, mut can_fail) = (true, false);
            for condition in when {
                let (holds, fails) = match condition.holds_for_first_packet() {
                    Some(holds) if !(limits_vary && condition.is_limit()) => (holds, !holds),
                    _ => (true, true),
                };
                can_hold &= holds;
                can_fail |= fails;
            }
            let mut outcomes = Outcomes::default();
            if can_hold {
                outcomes = outcomes.or(Outcomes::of(*action));
            }
            if can_fail {
                outcomes = outcomes.or(possible_outcomes(otherwise, limits_vary));
            }
            outcomes
        }
        // Not an answer for one source: anything
        Verdict::Reachable(_) => Outcomes {
            accept: true,
            block: true,
        },
    }
}

/// The limits of `conditions`, joined with " and " (empty without one).
fn limits_text(conditions: &[Condition]) -> String {
    let mut text = String::new();
    for condition in conditions.iter().filter(|c| c.is_limit()) {
        if !text.is_empty() {
            text.push_str(" and ");
        }
        let _ = write!(text, "{condition}");
    }
    text
}

/// The outcome of an [`Access::Limited`] verdict: the accept that takes the
/// first packet with its limits, and the limited drops before it ("accepted
/// up to 3/minute per source by rule \"SSH\"; more are turned away").
fn limited_outcome(verdict: &Verdict) -> String {
    let mut drops: Vec<String> = Vec::new();
    let mut current = verdict;
    let accept = loop {
        match current {
            Verdict::Limited {
                by,
                action,
                when,
                otherwise,
            } => {
                let limits = limits_text(when);
                let takes_first = when
                    .iter()
                    .all(|c| c.holds_for_first_packet() == Some(true));
                if *action == Action::Accept {
                    if takes_first {
                        break Some((by, limits));
                    }
                } else if !limits.is_empty() {
                    drops.push(format!("{} {limits} by {by}", verb(*action)));
                }
                current = otherwise;
            }
            Verdict::Accepted(by) => break Some((by, String::new())),
            _ => break None,
        }
    };
    let Some((by, limits)) = accept else {
        return verdict.to_string();
    };
    let mut text = if limits.is_empty() {
        format!("accepted by {by}")
    } else {
        format!("accepted {limits} by {by}")
    };
    for drop in &drops {
        let _ = write!(text, ", but {drop}");
    }
    if !limits.is_empty() {
        text.push_str("; more are turned away");
    }
    text
}

/// The access and outcome text of `verdict` (see [`Access`]).
fn classify(verdict: &Verdict) -> (Access, String) {
    let first = verdict.first_packet();
    if let Some((action @ (Action::Drop | Action::Reject), by)) = first {
        return (
            Access::Blocked,
            format!("BLOCKED: {} by {by}", verb(action)),
        );
    }
    if possible_outcomes(verdict, false).block {
        return (
            Access::MayBeBlocked,
            format!("blocked in some cases: {verdict}"),
        );
    }
    if possible_outcomes(verdict, true).block {
        return (Access::Limited, limited_outcome(verdict));
    }
    match first {
        Some((_, by)) => (Access::Accepted, format!("accepted by {by}")),
        None => (Access::Accepted, verdict.to_string()),
    }
}

/// Evaluates a new connection from `session`'s client to its server address
/// and port, on its interface when known, against `chain`. When the
/// interface decided the answer, the outcome says it was assumed.
pub fn check_session(chain: &InputChain, session: &SshSession) -> SessionCheck {
    let mut probe = Probe {
        transport: Transport::Tcp,
        port: session.server_port,
        family: IpFamily::of(session.client),
        interface: session.interface.clone(),
        destination: Some(session.server),
        source: ProbeSource::Addr(session.client),
    };
    let verdict = chain.evaluate(&probe);
    let (access, mut outcome) = classify(&verdict);
    if let Some(interface) = &session.interface {
        probe.interface = None;
        if chain.evaluate(&probe) != verdict {
            let _ = write!(
                outcome,
                " (assuming they arrive on {interface}, the interface that has {})",
                session.server
            );
        }
    }
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

/// What the lockout check says about a ruleset, shown with the retention
/// guard's warning before Apply and Save to System: sessions whose client
/// would be (or may be) turned away, which need an explicit confirmation,
/// and sessions whose new connections are only limited, a note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockoutWarning {
    /// Checks that are [`Access::Blocked`] or [`Access::MayBeBlocked`]
    pub checks: Vec<SessionCheck>,
    /// One line per check in [`Self::checks`], then what happens to the open
    /// sessions; empty when there is no such check
    pub lines: Vec<String>,
    /// Checks that are [`Access::Limited`]
    pub limited: Vec<SessionCheck>,
    /// One line per check in [`Self::limited`] (shown under
    /// [`Self::NOTE_HEADING`], no confirmation)
    pub notes: Vec<String>,
}

impl LockoutWarning {
    /// Heading shown above [`Self::lines`].
    pub const HEADING: &'static str = "These rules could lock you out of SSH:";
    /// Heading shown above [`Self::notes`].
    pub const NOTE_HEADING: &'static str = "New SSH connections are limited by these rules:";

    /// What to say about applying (or saving) `ruleset` while `sessions` are
    /// open; `None` when every session's client could reconnect without a
    /// limit.
    pub fn check(ruleset: &FirewallRuleset, sessions: &[SshSession]) -> Option<Self> {
        let (checks, rest): (Vec<SessionCheck>, Vec<SessionCheck>) =
            check_sessions(ruleset, sessions)
                .into_iter()
                .partition(|c| c.access.needs_confirmation());
        let limited: Vec<SessionCheck> = rest
            .into_iter()
            .filter(|c| c.access == Access::Limited)
            .collect();
        if checks.is_empty() && limited.is_empty() {
            return None;
        }
        let mut lines: Vec<String> = checks.iter().map(|c| capitalized(&c.summary())).collect();
        if !lines.is_empty() {
            lines.push(
                "Open sessions stay connected (established connections are always accepted); \
                 the risk is the next connection."
                    .to_string(),
            );
        }
        let notes = limited.iter().map(|c| capitalized(&c.summary())).collect();
        Some(Self {
            checks,
            lines,
            limited,
            notes,
        })
    }

    /// `true` when a session's client would be (or may be) turned away:
    /// applying takes an explicit confirmation. Notes alone do not.
    pub fn needs_confirmation(&self) -> bool {
        !self.checks.is_empty()
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
            interface: None,
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
        assert_eq!(check.access, Access::Limited);
        assert_eq!(
            check.outcome,
            "accepted up to 3/minute per source by rule \"SSH\"; more are turned away"
        );
        // A note, not a warning: no confirmation
        let warning = LockoutWarning::check(&ruleset, &[session("10.0.0.5", 22)]).expect("note");
        assert!(!warning.needs_confirmation());
        assert!(warning.checks.is_empty() && warning.lines.is_empty());
        assert_eq!(
            warning.notes,
            [
                "You are connected from 10.0.0.5 to port 22; new connections from 10.0.0.5 \
              would be accepted up to 3/minute per source by rule \"SSH\"; more are turned away"
            ]
        );
        // With a blocked session too: both, and the blocked one needs a confirmation
        let warning = LockoutWarning::check(
            &ruleset,
            &[session("10.0.0.5", 22), session("10.0.0.5", 2222)],
        )
        .expect("warns");
        assert!(warning.needs_confirmation());
        assert_eq!((warning.checks.len(), warning.limited.len()), (1, 1));
        assert_eq!(
            warning.lines.len(),
            2,
            "the check and the open-sessions line"
        );
    }

    fn ruleset_of(rules: Vec<crate::core::firewall::Rule>) -> FirewallRuleset {
        FirewallRuleset {
            rules,
            ..FirewallRuleset::new()
        }
    }

    fn on_interface(
        mut rule: crate::core::firewall::Rule,
        name: &str,
    ) -> crate::core::firewall::Rule {
        rule.interface = Some(name.into());
        rule.rebuild_caches();
        rule
    }

    fn with_interface(name: Option<&str>) -> SshSession {
        let mut s = session("10.0.0.5", 22);
        s.interface = name.map(str::to_owned);
        s
    }

    #[test]
    fn test_interface_bound_ssh_rule_and_the_resolved_interface() {
        let ruleset = ruleset_of(vec![on_interface(ssh_rule(&[]), "eth0")]);
        // Unknown interface: the fallback rejects, confirmation needed
        let check = &check_sessions(&ruleset, &[with_interface(None)])[0];
        assert_eq!(check.access, Access::MayBeBlocked);
        assert!(
            check
                .outcome
                .starts_with("blocked in some cases: accepted on interface eth0")
        );
        assert!(check.access.needs_confirmation());

        // Resolved to eth0: accepted, and the outcome says it was assumed
        let check = &check_sessions(&ruleset, &[with_interface(Some("eth0"))])[0];
        assert_eq!(check.access, Access::Accepted);
        assert_eq!(
            check.outcome,
            "accepted by rule \"SSH\" (assuming they arrive on eth0, the interface that has \
             192.168.1.1)"
        );
        assert!(LockoutWarning::check(&ruleset, &[with_interface(Some("eth0"))]).is_none());

        // Resolved to another interface: blocked
        let check = &check_sessions(&ruleset, &[with_interface(Some("wlan0"))])[0];
        assert_eq!(check.access, Access::Blocked);
        assert!(
            check
                .outcome
                .ends_with("(assuming they arrive on wlan0, the interface that has 192.168.1.1)"),
            "{}",
            check.outcome
        );

        // An interface that decides nothing is not mentioned
        let ruleset = ruleset_of(vec![ssh_rule(&[])]);
        let check = &check_sessions(&ruleset, &[with_interface(Some("eth0"))])[0];
        assert_eq!(check.outcome, "accepted by rule \"SSH\"");

        // Interface-bound and rate-limited, on its interface: a note
        let mut limited = on_interface(ssh_rule(&[]), "eth*");
        limited.connection_limit = 4;
        limited.connection_limit_per_source = true;
        let ruleset = ruleset_of(vec![limited]);
        let check = &check_sessions(&ruleset, &[with_interface(Some("eth0"))])[0];
        assert_eq!(check.access, Access::Limited);
        assert!(
            check
                .outcome
                .starts_with("accepted up to 4 connections per source by rule \"SSH\"; more are"),
            "{}",
            check.outcome
        );
        assert_eq!(
            check_sessions(&ruleset, &[with_interface(None)])[0].access,
            Access::MayBeBlocked
        );
    }

    #[test]
    fn test_cause_split_for_drops_and_rpf() {
        let mut flood = ssh_rule(&[]);
        flood.label = "Flood".into();
        flood.action = Action::Drop;
        flood.rate_limit = Some(RateLimit {
            count: 10,
            unit: TimeUnit::Minute,
            burst: None,
            per_source: false,
        });
        flood.rebuild_caches();
        // A drop over a limit before the accept: a note
        let ruleset = ruleset_of(vec![flood, ssh_rule(&[])]);
        let check = &check_sessions(&ruleset, &[session("10.0.0.5", 22)])[0];
        assert_eq!(check.access, Access::Limited);
        assert_eq!(
            check.outcome,
            "accepted by rule \"SSH\", but dropped over 10/minute by rule \"Flood\""
        );

        // A drop on an unknown interface before the accept: may be blocked
        let mut drop_eth = on_interface(ssh_rule(&[]), "eth0");
        drop_eth.action = Action::Drop;
        let ruleset = ruleset_of(vec![drop_eth, ssh_rule(&[])]);
        let check = &check_sessions(&ruleset, &[with_interface(None)])[0];
        assert_eq!(check.access, Access::MayBeBlocked);
        // ... and on a known one: blocked or accepted
        let check = &check_sessions(&ruleset, &[with_interface(Some("eth0"))])[0];
        assert_eq!(check.access, Access::Blocked);
        let check = &check_sessions(&ruleset, &[with_interface(Some("wlan0"))])[0];
        assert_eq!(check.access, Access::Accepted);

        // RPF: the client is assumed to pass it, so it changes neither answer
        let mut rpf = ruleset_of(vec![ssh_rule(&[])]);
        rpf.advanced_security.enable_rpf = true;
        assert_eq!(
            check_sessions(&rpf, &[session("10.0.0.5", 22)])[0].access,
            Access::Accepted
        );
        let mut limited = ssh_rule(&[]);
        limited.rate_limit = Some(RateLimit {
            count: 3,
            unit: TimeUnit::Minute,
            burst: None,
            per_source: true,
        });
        rpf.rules = vec![limited];
        assert_eq!(
            check_sessions(&rpf, &[session("10.0.0.5", 22)])[0].access,
            Access::Limited
        );
    }

    fn local(interface: &str, addr: &str) -> LocalAddress {
        LocalAddress {
            interface: interface.into(),
            addr: addr.parse().unwrap(),
            loopback: interface == "lo",
        }
    }

    #[test]
    fn test_interface_owning_an_address() {
        let addresses = [
            local("eth0", "192.168.1.1"),
            local("eth0", "fd00::1"),
            local("wlan0", "10.0.0.1"),
            // The same address on two interfaces: ambiguous
            local("eth1", "172.16.0.1"),
            local("br0", "172.16.0.1"),
            // Twice on one interface (an alias): still that interface
            local("eth2", "172.17.0.1"),
            local("eth2", "172.17.0.1"),
            // On loopback (and a dummy-style service address on lo)
            local("lo", "127.0.0.1"),
            local("lo", "203.0.113.7"),
        ];
        let owner = |addr: &str| interface_owning(&addresses, addr.parse().unwrap());
        assert_eq!(owner("192.168.1.1"), Some("eth0"));
        assert_eq!(owner("::ffff:192.168.1.1"), Some("eth0"), "IPv4-mapped");
        assert_eq!(owner("fd00::1"), Some("eth0"));
        assert_eq!(owner("10.0.0.1"), Some("wlan0"));
        assert_eq!(owner("172.16.0.1"), None, "ambiguous");
        assert_eq!(owner("172.17.0.1"), Some("eth2"));
        assert_eq!(owner("203.0.113.7"), None, "on loopback");
        assert_eq!(owner("127.0.0.1"), None);
        assert_eq!(owner("10.9.9.9"), None, "no interface has it");
        assert_eq!(interface_owning(&[], "10.0.0.1".parse().unwrap()), None);

        let mut sessions = vec![session("10.0.0.5", 22), session("fd00::5", 22)];
        sessions[0].interface = Some("stale".into());
        resolve_interfaces(&mut sessions, &[local("eth0", "fd00::1")]);
        assert_eq!(
            sessions[0].interface, None,
            "192.168.1.1 is on no interface"
        );
        assert_eq!(sessions[1].interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn test_parse_test_addresses() {
        let parsed = parse_test_addresses(
            "# fixture\n\neth0 10.0.0.1\n  eth0:1   10.0.0.2 \nlo 127.0.0.1\nbad\nwg0 not-an-ip\n",
        );
        assert_eq!(
            parsed,
            [
                local("eth0", "10.0.0.1"),
                local("eth0", "10.0.0.2"),
                local("lo", "127.0.0.1"),
            ]
        );
        assert!(parsed[2].loopback);
        assert_eq!(interface_name("eth0:1"), "eth0");
        assert_eq!(interface_name("enp3s0"), "enp3s0");
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
