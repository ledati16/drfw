//! Exposure: the sockets listening on this computer and who can reach them
//!
//! Listening sockets are read without privileges from
//! `/proc/net/{tcp,tcp6,udp,udp6}`: TCP sockets in state LISTEN and UDP sockets
//! that are bound but not connected. The owning process is found by walking
//! `/proc/<pid>/fd` for socket inodes, which only works for the user's own
//! processes; other users' sockets show "unknown (another user)". Finding
//! those would need root, which DRFW deliberately does not use here.
//!
//! Each socket is then evaluated against a ruleset with
//! [`crate::core::evaluate`] for a new connection from an arbitrary source.
//! [`exposure_rows`] returns one printable row per socket, for the GUI's
//! Exposure view and the command line.
//!
//! # Approximations
//!
//! - An IPv6 socket bound to `::` usually accepts IPv4 too (dual-stack). That
//!   is assumed unless `net.ipv6.bindv6only` is set or an IPv4 socket uses the
//!   same port (then the IPv6 socket must be IPv6-only). The per-socket
//!   `IPV6_V6ONLY` option is not visible in `/proc`, so an IPv6-only socket
//!   may be reported as reachable over IPv4 too (over-, never under-stated).
//! - Loopback-bound sockets are "local only": the firewall's loopback accept
//!   lets local programs in, and nothing else can reach them.
//! - Connected UDP sockets (which only take datagrams from their peer) are
//!   not listed.
//! - Local network discovery (a Desktop mode setting) is not counted as
//!   exposure (see [`SocketExposure::local_discovery`]). Its multicast accepts
//!   (mDNS, SSDP, WS-Discovery) only reach the discovery sockets themselves,
//!   which are shown as [`LOCAL_DISCOVERY`]. Its accept of unicast replies
//!   from private and link-local addresses holds for a UDP port that sent a
//!   discovery query (SSDP, WS-Discovery, mDNS, LLMNR, `NetBIOS` name query)
//!   within the last 10 seconds. The services on those protocols' own ports
//!   ([`crate::core::firewall::DISCOVERY_QUERY_PORTS`]) announce and query
//!   from them, so for UDP sockets on these ports the replies stay in the
//!   answer, as a conditional access ([`LOCAL_DISCOVERY_REPLIES`] when
//!   nothing else reaches them). Any other UDP socket only receives them
//!   after sending such a query itself: a discovery client's temporary port
//!   getting its answers, like the replies to an outgoing connection, so
//!   they are left out of its answer. (A program that deliberately sends a
//!   discovery query from a port it has bound opens that port to these
//!   replies too; it could receive on that port anyway.)
//!
//! [`scan_host`] also returns the established TCP connections with their
//! processes, for the SSH session detection of [`crate::core::lockout`].
//!
//! # Test override
//!
//! `DRFW_TEST_PROC_DIR`, when set, replaces `/proc` for every file read here
//! (`net/tcp*`, `net/udp*`, `<pid>/fd`, `<pid>/comm`,
//! `sys/net/ipv6/bindv6only`), so tests run on fixtures instead of the
//! machine's own sockets. It also replaces the interface addresses the SSH
//! lockout check reads ([`crate::core::lockout::local_addresses`]) with the
//! fixture file [`crate::core::lockout::TEST_ADDRESSES_FILE`] in it.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use super::evaluate::{
    BASE_MDNS, BASE_MDNS_V6, BASE_SSDP, BASE_SSDP_V6, Condition, ConditionalAccess, Decider,
    EveryoneScope, InputChain, IpFamily, Probe, ProbeSource, Reach, Reachability, Transport,
    Verdict,
};
use super::firewall::FirewallRuleset;

/// TCP state LISTEN in `/proc/net/tcp*`.
const TCP_LISTEN: &str = "0A";
/// TCP state ESTABLISHED in `/proc/net/tcp*`.
const TCP_ESTABLISHED: &str = "01";
/// Socket state of a bound, unconnected UDP socket (`TCP_CLOSE`).
const UDP_UNCONNECTED: &str = "07";

/// Environment variable that replaces `/proc` (see the module docs).
pub const TEST_PROC_DIR_VAR: &str = "DRFW_TEST_PROC_DIR";

/// `DRFW_TEST_PROC_DIR` when set and not empty: the fixture directory that
/// replaces `/proc`.
pub fn test_proc_root() -> Option<PathBuf> {
    std::env::var_os(TEST_PROC_DIR_VAR)
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
}

/// The directory read as `/proc`: `DRFW_TEST_PROC_DIR` when set and not
/// empty, otherwise `/proc`.
pub fn proc_root() -> PathBuf {
    test_proc_root().unwrap_or_else(|| PathBuf::from("/proc"))
}

/// One socket line of `/proc/net/{tcp,tcp6,udp,udp6}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListeningSocket {
    pub transport: Transport,
    /// Read from `tcp6`/`udp6` (an IPv6 socket, possibly dual-stack)
    pub ipv6_socket: bool,
    /// Local address as the kernel reports it (may be IPv4-mapped IPv6)
    pub local: IpAddr,
    pub port: u16,
    /// Owner of the socket
    pub uid: u32,
    pub inode: u64,
}

/// An established TCP connection from `/proc/net/tcp{,6}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishedSocket {
    /// Local address as the kernel reports it (may be IPv4-mapped IPv6)
    pub local: IpAddr,
    pub local_port: u16,
    /// The peer (may be IPv4-mapped IPv6)
    pub remote: IpAddr,
    pub remote_port: u16,
    /// Owner of the socket
    pub uid: u32,
    pub inode: u64,
}

/// The fields of one `/proc/net` socket line this module uses.
struct ProcNetLine<'a> {
    local: IpAddr,
    local_port: u16,
    remote: IpAddr,
    remote_port: u16,
    state: &'a str,
    uid: u32,
    inode: u64,
}

/// Splits one `/proc/net/{tcp,udp}{,6}` line; `None` for the header and
/// malformed lines.
fn parse_line(line: &str, ipv6: bool) -> Option<ProcNetLine<'_>> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }
    let (local, local_port) = parse_endpoint(fields[1], ipv6)?;
    let (remote, remote_port) = parse_endpoint(fields[2], ipv6)?;
    Some(ProcNetLine {
        local,
        local_port,
        remote,
        remote_port,
        state: fields[3],
        uid: fields[7].parse().ok()?,
        inode: fields[9].parse().ok()?,
    })
}

/// Parses the contents of one `/proc/net/{tcp,tcp6,udp,udp6}` file.
///
/// Returns TCP sockets in state LISTEN, or UDP sockets that are bound and not
/// connected (remote port 0). Malformed lines are skipped.
///
/// Addresses are printed by the kernel in host byte order, so this parser
/// must run on the machine that produced the text (as it does).
pub fn parse_proc_net(contents: &str, transport: Transport, ipv6: bool) -> Vec<ListeningSocket> {
    contents
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let line = parse_line(line, ipv6)?;
            let listening = match transport {
                Transport::Tcp => line.state == TCP_LISTEN,
                Transport::Udp => line.state == UDP_UNCONNECTED && line.remote_port == 0,
            };
            listening.then_some(ListeningSocket {
                transport,
                ipv6_socket: ipv6,
                local: line.local,
                port: line.local_port,
                uid: line.uid,
                inode: line.inode,
            })
        })
        .collect()
}

/// Parses the established connections of one `/proc/net/tcp{,6}` file
/// (state `01`). Malformed lines are skipped; byte order as for
/// [`parse_proc_net`].
pub fn parse_proc_net_established(contents: &str, ipv6: bool) -> Vec<EstablishedSocket> {
    contents
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let line = parse_line(line, ipv6)?;
            (line.state == TCP_ESTABLISHED).then_some(EstablishedSocket {
                local: line.local,
                local_port: line.local_port,
                remote: line.remote,
                remote_port: line.remote_port,
                uid: line.uid,
                inode: line.inode,
            })
        })
        .collect()
}

/// Parses `0100007F:0016` (IPv4) or 32 hex digits + port (IPv6).
fn parse_endpoint(field: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (addr, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let addr = if ipv6 {
        // Four 32-bit words, each printed in host byte order
        if addr.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let word = u32::from_str_radix(addr.get(i * 8..i * 8 + 8)?, 16).ok()?;
            *chunk = word.to_ne_bytes();
        }
        IpAddr::V6(Ipv6Addr::from(bytes))
    } else {
        if addr.len() != 8 {
            return None;
        }
        let word = u32::from_str_radix(addr, 16).ok()?;
        IpAddr::V4(Ipv4Addr::from(word.to_ne_bytes()))
    };
    Some((addr, port))
}

/// A process holding a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    /// `/proc/<pid>/comm`
    pub name: String,
}

/// Maps socket inodes in `wanted` to the processes holding them, by reading
/// the `socket:[inode]` links in `<proc_root>/<pid>/fd`.
///
/// Processes whose `fd` directory cannot be read (other users' processes, or
/// ones that exited meanwhile) are skipped silently.
pub fn map_socket_owners<S: std::hash::BuildHasher>(
    proc_root: &Path,
    wanted: &HashSet<u64, S>,
) -> HashMap<u64, Vec<ProcessInfo>> {
    let mut owners: HashMap<u64, Vec<ProcessInfo>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return owners;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let pid_dir = entry.path();
        let Ok(fds) = std::fs::read_dir(pid_dir.join("fd")) else {
            continue;
        };
        let mut name: Option<String> = None;
        for fd in fds.flatten() {
            let Some(inode) = std::fs::read_link(fd.path())
                .ok()
                .as_deref()
                .and_then(Path::to_str)
                .and_then(socket_inode)
            else {
                continue;
            };
            if !wanted.contains(&inode) {
                continue;
            }
            let name = name
                .get_or_insert_with(|| {
                    std::fs::read_to_string(pid_dir.join("comm"))
                        .map(|comm| comm.trim().to_string())
                        .ok()
                        .filter(|comm| !comm.is_empty())
                        .unwrap_or_else(|| format!("pid {pid}"))
                })
                .clone();
            let holders = owners.entry(inode).or_default();
            if !holders.iter().any(|p| p.pid == pid) {
                holders.push(ProcessInfo { pid, name });
            }
        }
    }
    owners
}

/// `socket:[12345]` → 12345
fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// What a socket is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindScope {
    /// Loopback (127.0.0.0/8, `::1`): only this computer can connect
    LocalOnly,
    /// The wildcard address: every address of this computer
    AllAddresses,
    /// One specific non-loopback address
    Specific,
}

/// A listening socket, ready to evaluate and display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketInfo {
    pub transport: Transport,
    pub port: u16,
    /// Bound address (IPv4-mapped addresses as IPv4)
    pub bind: IpAddr,
    pub scope: BindScope,
    /// Families that can reach the socket (both for a dual-stack socket)
    pub families: Vec<IpFamily>,
    pub uid: u32,
    /// Processes holding the socket (empty if not readable)
    pub processes: Vec<ProcessInfo>,
    /// "sshd", "unknown (another user: root)", …
    pub process_display: String,
    /// "all addresses", "127.0.0.1 (local only)", "192.168.1.5 only"
    pub bind_display: String,
    /// "IPv4", "IPv6" or "IPv4+IPv6"
    pub family_display: &'static str,
}

/// What [`scan_host`] found: the listening sockets and the established TCP
/// connections, with their processes where readable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostScan {
    pub sockets: Vec<SocketInfo>,
    /// Established TCP connections and the processes holding them (empty if
    /// not readable)
    pub established: Vec<(EstablishedSocket, Vec<ProcessInfo>)>,
}

/// Reads the listening sockets and established TCP connections of this
/// computer, and their processes (from [`proc_root`]).
///
/// Blocking (reads `/proc`); run it off the UI thread.
///
/// # Errors
///
/// Fails only if none of the four `/proc/net` files can be read (e.g. `/proc`
/// is not mounted); a missing `tcp6`/`udp6` (IPv6 disabled) is fine.
pub fn scan_host() -> std::io::Result<HostScan> {
    scan_host_in(&proc_root())
}

/// [`scan_host`] with `root` read as `/proc`.
///
/// # Errors
///
/// As [`scan_host`].
pub fn scan_host_in(root: &Path) -> std::io::Result<HostScan> {
    let mut raw = Vec::new();
    let mut established = Vec::new();
    let mut last_error = None;
    let mut any_read = false;
    for (file, transport, ipv6) in [
        ("tcp", Transport::Tcp, false),
        ("tcp6", Transport::Tcp, true),
        ("udp", Transport::Udp, false),
        ("udp6", Transport::Udp, true),
    ] {
        match std::fs::read_to_string(root.join("net").join(file)) {
            Ok(contents) => {
                any_read = true;
                raw.extend(parse_proc_net(&contents, transport, ipv6));
                if transport == Transport::Tcp {
                    established.extend(parse_proc_net_established(&contents, ipv6));
                }
            }
            Err(e) => last_error = Some(e),
        }
    }
    if !any_read && let Some(e) = last_error {
        return Err(e);
    }
    let wanted: HashSet<u64> = raw
        .iter()
        .map(|s| s.inode)
        .chain(established.iter().map(|c| c.inode))
        .collect();
    let owners = map_socket_owners(root, &wanted);
    let v6only_default = std::fs::read_to_string(root.join("sys/net/ipv6/bindv6only"))
        .is_ok_and(|v| v.trim() == "1");
    let own_uid = nix::unistd::getuid().as_raw();
    let established = established
        .into_iter()
        .map(|connection| {
            let processes = owners.get(&connection.inode).cloned().unwrap_or_default();
            (connection, processes)
        })
        .collect();
    Ok(HostScan {
        sockets: build_socket_list(raw, &owners, own_uid, v6only_default, user_name),
        established,
    })
}

/// The login name of `uid`, if known.
fn user_name(uid: u32) -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|user| user.name)
}

/// Combines parsed sockets with their owners into display-ready
/// [`SocketInfo`]s, merging duplicates (e.g. `SO_REUSEPORT` workers), sorted
/// by protocol, port and address.
///
/// `v6only_default` is `net.ipv6.bindv6only`; `user_name` resolves the owner
/// of sockets whose process is not readable.
pub fn build_socket_list<S: std::hash::BuildHasher>(
    raw: Vec<ListeningSocket>,
    owners: &HashMap<u64, Vec<ProcessInfo>, S>,
    own_uid: u32,
    v6only_default: bool,
    user_name: impl Fn(u32) -> Option<String>,
) -> Vec<SocketInfo> {
    // Ports with an IPv4 socket: an IPv6 wildcard socket on them is IPv6-only
    let ipv4_ports: HashSet<(Transport, u16)> = raw
        .iter()
        .filter(|s| !s.ipv6_socket)
        .map(|s| (s.transport, s.port))
        .collect();

    let mut merged: Vec<(ListeningSocket, Vec<ProcessInfo>)> = Vec::with_capacity(raw.len());
    for socket in raw {
        let processes = owners.get(&socket.inode).cloned().unwrap_or_default();
        if let Some((_, existing)) = merged.iter_mut().find(|(s, _)| {
            s.transport == socket.transport
                && s.ipv6_socket == socket.ipv6_socket
                && s.local == socket.local
                && s.port == socket.port
                && s.uid == socket.uid
        }) {
            for process in processes {
                if !existing.iter().any(|p| p.pid == process.pid) {
                    existing.push(process);
                }
            }
            continue;
        }
        merged.push((socket, processes));
    }

    let mut sockets: Vec<SocketInfo> = merged
        .into_iter()
        .map(|(socket, processes)| {
            let bind = socket.local.to_canonical();
            let scope = if bind.is_loopback() {
                BindScope::LocalOnly
            } else if bind.is_unspecified() {
                BindScope::AllAddresses
            } else {
                BindScope::Specific
            };
            let families = if !socket.ipv6_socket || bind.is_ipv4() {
                vec![IpFamily::V4]
            } else if scope == BindScope::AllAddresses
                && !v6only_default
                && !ipv4_ports.contains(&(socket.transport, socket.port))
            {
                vec![IpFamily::V4, IpFamily::V6]
            } else {
                vec![IpFamily::V6]
            };
            let family_display = match families.as_slice() {
                [IpFamily::V4] => "IPv4",
                [IpFamily::V6] => "IPv6",
                _ => "IPv4+IPv6",
            };
            let bind_display = match scope {
                BindScope::AllAddresses => "all addresses".to_string(),
                BindScope::LocalOnly => format!("{bind} (local only)"),
                BindScope::Specific => format!("{bind} only"),
            };
            let process_display = process_display(&processes, socket.uid, own_uid, &user_name);
            SocketInfo {
                transport: socket.transport,
                port: socket.port,
                bind,
                scope,
                families,
                uid: socket.uid,
                processes,
                process_display,
                bind_display,
                family_display,
            }
        })
        .collect();
    sockets.sort_by(|a, b| {
        (a.transport, a.port, a.bind, a.families.len()).cmp(&(
            b.transport,
            b.port,
            b.bind,
            b.families.len(),
        ))
    });
    sockets
}

/// "sshd", "nginx, nginx-worker", "unknown (another user: root)", "unknown"
fn process_display(
    processes: &[ProcessInfo],
    uid: u32,
    own_uid: u32,
    user_name: &impl Fn(u32) -> Option<String>,
) -> String {
    if processes.is_empty() {
        if uid == own_uid {
            return "unknown".to_string();
        }
        return match user_name(uid) {
            Some(name) => format!("unknown (another user: {name})"),
            None => "unknown (another user)".to_string(),
        };
    }
    let mut names: Vec<&str> = Vec::with_capacity(processes.len());
    for process in processes {
        if !names.contains(&process.name.as_str()) {
            names.push(&process.name);
        }
    }
    names.join(", ")
}

/// How reachable one socket is under a ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketExposure {
    /// Bound to loopback: nothing else is evaluated
    pub local_only: bool,
    /// One answer per family in [`SocketInfo::families`] (empty when local only)
    pub per_family: Vec<Reachability>,
    /// Every address of some family can connect on any interface (at least
    /// within a limit): open to the whole network, the internet included
    pub open_to_everyone: bool,
    /// When not `open_to_everyone`: the interfaces on which every address
    /// can connect (everyone on that link, e.g. the peers of a VPN), in rule
    /// order; empty when no interface lets everyone in
    pub open_on_interfaces: Vec<String>,
    /// Nobody can connect over any family
    pub nobody: bool,
    /// "everyone", "IPv4: 10.0.0.0/8; IPv6: nobody", "local only", …
    pub summary: String,
    /// The rule that matters most (see [`Reachability::deciding`])
    pub decided_by: Option<Decider>,
    /// `decided_by` as text ("rule \"SSH\"", …); empty when local only
    pub decided_by_display: String,
    /// The socket is the host side of a port Docker publishes: Docker sends
    /// that traffic through DNAT and the forward chain, so the input rules
    /// evaluated above do not decide it. Set by
    /// [`SocketExposure::mark_published_by_docker`], which replaces the
    /// verdict with [`crate::core::host_facts::DOCKER_PUBLISHED`] (or
    /// [`crate::core::host_facts::DOCKER_PUBLISHED_FORWARD_FILTERED`], see
    /// [`Self::docker_forward_filtered`]).
    pub docker_published: bool,
    /// The ruleset blocks forwarded traffic ("Block forwarded traffic"), so
    /// DRFW's forward chain does filter what Docker publishes: dropped
    /// unless a Forwarded rule allows it. Set for every socket from the
    /// ruleset ([`InputChain::blocks_forwarding`]); it only changes the
    /// answer of a socket that is [`Self::docker_published`].
    pub docker_forward_filtered: bool,
    /// Local network discovery lets the local network reach this socket:
    /// it is an mDNS, SSDP or WS-Discovery socket that the discovery
    /// multicast accepts reach, or a UDP socket on a discovery port that
    /// receives the replies to its queries (see the module docs). That is
    /// not counted as exposure: the `open_*` fields leave it out and
    /// [`SocketExposure::rank`] sorts it with the sockets only some sources
    /// reach. The summary says [`LOCAL_DISCOVERY`] (or
    /// [`LOCAL_DISCOVERY_REPLIES`]) for it, and `nobody` is `false`. The
    /// replies stay in `per_family` as a conditional access for a socket on
    /// a discovery port only; every other socket's answer leaves them out.
    pub local_discovery: bool,
}

/// How a socket that local network discovery lets in reads in a summary
/// ([`SocketExposure::local_discovery`]).
pub const LOCAL_DISCOVERY: &str = "local network (discovery)";

/// How a UDP socket on a discovery port reads in a summary when only the
/// replies to its own discovery queries reach it (a `NetBIOS` name service
/// socket on port 137, or one bound to a unicast address).
pub const LOCAL_DISCOVERY_REPLIES: &str =
    "local network, for 10 s after it sends a discovery query";

/// `true` for a decider that is one of local discovery's multicast accepts.
fn is_discovery_group_accept(decider: &Decider) -> bool {
    matches!(
        decider,
        Decider::BaseRule(comment)
            if [BASE_MDNS, BASE_MDNS_V6, BASE_SSDP, BASE_SSDP_V6].contains(comment)
    )
}

/// `true` for an access granted by local discovery: a multicast accept, or
/// the accept of replies to our own discovery queries.
fn is_discovery_access(access: &ConditionalAccess) -> bool {
    is_discovery_group_accept(&access.by) || access.when.contains(&Condition::DiscoveryReply)
}

/// What local discovery grants one family of a socket.
#[derive(Default)]
struct DiscoveryAccess {
    /// The multicast accept that reaches the socket
    group: Option<Decider>,
    /// The accept of replies to the socket's own queries, kept as a
    /// conditional access (a socket on a discovery port)
    replies: Option<Decider>,
}

impl DiscoveryAccess {
    /// Local discovery reaches the socket at all.
    const fn any(&self) -> bool {
        self.group.is_some() || self.replies.is_some()
    }

    /// The deciding discovery accept: the multicast accept, else the replies'.
    fn decider(&self) -> Option<&Decider> {
        self.group.as_ref().or(self.replies.as_ref())
    }
}

/// `true` for a UDP socket on one of the discovery protocols' ports, which
/// receives the replies to its own queries (see the module docs).
fn on_discovery_port(socket: &SocketInfo) -> bool {
    socket.transport == Transport::Udp
        && crate::core::firewall::DISCOVERY_QUERY_PORTS.contains(&socket.port)
}

/// Takes local discovery's accesses out of one family's answer (see the
/// module docs): `reach` keeps the reply access only when `keep_replies`
/// (a socket on a discovery port); `shown` (for the summary text) has none
/// of them.
fn split_off_discovery(
    reach: &mut Reachability,
    keep_replies: bool,
) -> (DiscoveryAccess, Reachability) {
    let mut found = DiscoveryAccess::default();
    reach.conditional.retain(|access| {
        if !is_discovery_access(access) {
            return true;
        }
        if is_discovery_group_accept(&access.by) {
            if found.group.is_none() {
                found.group = Some(access.by.clone());
            }
            return false;
        }
        if keep_replies {
            found.replies.get_or_insert_with(|| access.by.clone());
        }
        keep_replies
    });
    // A socket bound to the group address itself: the multicast accept
    // matches it without conditions
    if !reach.accepted_by.is_empty() && reach.accepted_by.iter().all(is_discovery_group_accept) {
        found.group = found.group.or_else(|| reach.accepted_by.first().cloned());
        reach.accepted_by.clear();
        reach.open = Reach::Nobody;
    }
    let mut shown = reach.clone();
    shown
        .conditional
        .retain(|access| !access.when.contains(&Condition::DiscoveryReply));
    (found, shown)
}

/// Evaluates who can open a new connection to `socket` under `chain`.
pub fn evaluate_socket(chain: &InputChain, socket: &SocketInfo) -> SocketExposure {
    if socket.scope == BindScope::LocalOnly {
        return SocketExposure {
            local_only: true,
            per_family: Vec::new(),
            open_to_everyone: false,
            open_on_interfaces: Vec::new(),
            nobody: false,
            summary: "local only".to_string(),
            decided_by: None,
            decided_by_display: String::new(),
            docker_published: false,
            docker_forward_filtered: chain.blocks_forwarding(),
            local_discovery: false,
        };
    }
    let destination = (socket.scope == BindScope::Specific).then_some(socket.bind);
    let mut per_family: Vec<Reachability> = socket
        .families
        .iter()
        .filter_map(|&family| {
            let probe = Probe {
                transport: socket.transport,
                port: socket.port,
                family,
                interface: None,
                destination,
                source: ProbeSource::Unknown,
            };
            match chain.evaluate(&probe) {
                Verdict::Reachable(reach) => Some(reach),
                _ => None,
            }
        })
        .collect();
    // Per family: what local discovery grants, and the answer without it
    // (for the text)
    let keep_replies = on_discovery_port(socket);
    let (discovery, shown): (Vec<DiscoveryAccess>, Vec<Reachability>) = per_family
        .iter_mut()
        .map(|reach| split_off_discovery(reach, keep_replies))
        .unzip();
    let local_discovery = discovery.iter().any(DiscoveryAccess::any);

    let scopes: Vec<EveryoneScope> = per_family
        .iter()
        .filter_map(Reachability::everyone_scope)
        .collect();
    let open_to_everyone = scopes.contains(&EveryoneScope::AnyInterface);
    let mut open_on_interfaces: Vec<String> = Vec::new();
    if !open_to_everyone {
        for scope in scopes {
            if let EveryoneScope::Interfaces(names) = scope {
                for name in names {
                    if !open_on_interfaces.contains(&name) {
                        open_on_interfaces.push(name);
                    }
                }
            }
        }
    }
    let nobody = per_family.iter().all(Reachability::nobody) && !local_discovery;
    let texts: Vec<String> = shown
        .iter()
        .zip(&discovery)
        .map(|(reach, access)| {
            let label = if access.group.is_some() {
                LOCAL_DISCOVERY
            } else {
                LOCAL_DISCOVERY_REPLIES
            };
            if !access.any() {
                reach.to_string()
            } else if reach.nobody() {
                label.to_string()
            } else {
                format!("{reach}; {label}")
            }
        })
        .collect();
    let summary = if texts.windows(2).all(|w| w[0] == w[1]) {
        texts
            .first()
            .cloned()
            .unwrap_or_else(|| "nobody".to_string())
    } else {
        let mut out = String::new();
        for (i, (reach, text)) in per_family.iter().zip(&texts).enumerate() {
            if i > 0 {
                out.push_str("; ");
            }
            let _ = write!(out, "{}: {text}", reach.family.display_name());
        }
        out
    };
    // The most exposed family's deciding rule; for a socket only discovery
    // reaches, the discovery accept
    let decided_by = shown
        .iter()
        .find(|r| r.everyone_scope() == Some(EveryoneScope::AnyInterface))
        .or_else(|| shown.iter().find(|r| r.open_to_everyone()))
        .or_else(|| shown.iter().find(|r| !r.nobody()))
        .and_then(Reachability::deciding)
        .or_else(|| discovery.iter().find_map(DiscoveryAccess::decider))
        .or_else(|| shown.first().and_then(Reachability::deciding))
        .cloned();
    let decided_by_display = decided_by.as_ref().map_or_default(ToString::to_string);
    SocketExposure {
        local_only: false,
        per_family,
        open_to_everyone,
        open_on_interfaces,
        nobody,
        summary,
        decided_by,
        decided_by_display,
        docker_published: false,
        docker_forward_filtered: chain.blocks_forwarding(),
        local_discovery,
    }
}

/// One listening socket with its exposure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureRow {
    pub socket: SocketInfo,
    pub exposure: SocketExposure,
}

/// Evaluates every socket against `ruleset`: one row per socket, those open
/// to everyone on any interface first, then those open to everyone on some
/// interfaces only, then those open to some sources, then the rest (nobody,
/// local only); each group in the scan's protocol and port order
/// ([`SocketExposure::rank`]).
///
/// The rows carry display strings ([`SocketInfo::process_display`],
/// [`SocketExposure::summary`], …) so a front end only prints them.
///
/// # Example
///
/// ```no_run
/// let ruleset = drfw::core::firewall::FirewallRuleset::new();
/// let sockets = drfw::core::exposure::scan_host()
///     .unwrap_or_default()
///     .sockets;
/// for row in drfw::core::exposure::exposure_rows(&ruleset, &sockets) {
///     println!(
///         "{} {} {}: {} ({})",
///         row.socket.transport.display_name(),
///         row.socket.port,
///         row.socket.process_display,
///         row.exposure.summary,
///         row.exposure.decided_by_display,
///     );
/// }
/// ```
pub fn exposure_rows(ruleset: &FirewallRuleset, sockets: &[SocketInfo]) -> Vec<ExposureRow> {
    let chain = InputChain::new(ruleset);
    let mut rows: Vec<ExposureRow> = sockets
        .iter()
        .map(|socket| ExposureRow {
            exposure: evaluate_socket(&chain, socket),
            socket: socket.clone(),
        })
        .collect();
    // Stable: keeps the socket order within each group
    rows.sort_by_key(|row| row.exposure.rank());
    rows
}

/// Marks the rows whose socket is the host side of a port Docker publishes
/// ([`crate::core::host_facts::ContainerFacts::publishes`]) with
/// [`SocketExposure::mark_published_by_docker`], then sorts again
/// ([`SocketExposure::rank`]). Returns how many rows were marked.
pub fn mark_docker_published(
    rows: &mut [ExposureRow],
    containers: &crate::core::host_facts::ContainerFacts,
) -> usize {
    let mut marked = 0;
    for row in rows.iter_mut() {
        if containers.publishes(&row.socket) {
            row.exposure.mark_published_by_docker();
            marked += 1;
        }
    }
    if marked > 0 {
        rows.sort_by_key(|row| row.exposure.rank());
    }
    marked
}

/// Interfaces named in [`SocketExposure::open_on_badge`]; more are counted.
const BADGE_INTERFACES: usize = 2;

/// Start of [`SocketExposure::open_on_badge`].
pub const OPEN_ON_BADGE_PREFIX: &str = "OPEN ON ";

impl SocketExposure {
    /// Replaces the evaluator's verdict for a port Docker publishes: the
    /// input rules do not filter it (see [`Self::docker_published`]), so
    /// "open to everyone", "nobody" and the deciding rule would all be
    /// wrong. The summary becomes
    /// [`crate::core::host_facts::DOCKER_PUBLISHED`], or
    /// [`crate::core::host_facts::DOCKER_PUBLISHED_FORWARD_FILTERED`] when
    /// [`Self::docker_forward_filtered`].
    pub fn mark_published_by_docker(&mut self) {
        use crate::core::host_facts::{DOCKER_PUBLISHED, DOCKER_PUBLISHED_FORWARD_FILTERED};
        self.docker_published = true;
        self.open_to_everyone = false;
        self.open_on_interfaces.clear();
        self.nobody = false;
        self.local_discovery = false;
        self.summary = if self.docker_forward_filtered {
            DOCKER_PUBLISHED_FORWARD_FILTERED
        } else {
            DOCKER_PUBLISHED
        }
        .to_string();
        self.decided_by = None;
        self.decided_by_display.clear();
    }

    /// "OPEN ON tailscale0", "OPEN ON eth0, wg0 +1": the badge of a socket
    /// every address can reach on some interfaces only (at most two named,
    /// the rest counted; the summary names them all). `None` when it is
    /// open on any interface or not to everyone.
    pub fn open_on_badge(&self) -> Option<String> {
        if self.open_to_everyone || self.open_on_interfaces.is_empty() {
            return None;
        }
        let shown = &self.open_on_interfaces[..self.open_on_interfaces.len().min(BADGE_INTERFACES)];
        let mut badge = format!("{OPEN_ON_BADGE_PREFIX}{}", shown.join(", "));
        let hidden = self.open_on_interfaces.len() - shown.len();
        if hidden > 0 {
            let _ = write!(badge, " +{hidden}");
        }
        Some(badge)
    }

    /// Sort rank, most exposed first: everyone on any interface (0),
    /// everyone on some interfaces only or published by Docker without
    /// forward filtering (1), some sources or published by Docker with
    /// forward filtering (2), nobody or local only (3).
    pub fn rank(&self) -> u8 {
        if self.docker_published {
            if self.docker_forward_filtered { 2 } else { 1 }
        } else if self.local_only || self.nobody {
            3
        } else if self.open_to_everyone {
            0
        } else if !self.open_on_interfaces.is_empty() {
            1
        } else {
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::firewall::{PortEntry, Protocol};

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5716 1 0000000090c5ebbe 100 0 0 10 0
   1: 3600007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   980        0 14298 1 00000000cff2fc64 100 0 0 10 5
   2: 0500A8C0:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000000000000000 100 0 0 10 0
   3: 0500A8C0:C350 0B00A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 778 1 0000000000000000 20 4 30 10 -1
   4: garbage
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5718 1 000000004b3a9470 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 901 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF0000050200C0:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 902 1 0000000000000000 100 0 0 10 0
   3: B80D0120000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 903 1 0000000000000000 100 0 0 10 0
";
    const UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 4028: 3600007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   980        0 14297 2 00000000c65f9251 0
 9328: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   980        0 14290 2 0000000088020b71 0
 9400: 0500A8C0:D431 0B00A8C0:0035 01 00000000:00000000 00:00000000 00000000  1000        0 14291 2 0000000088020b71 0
";
    const UDP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 4521: 000080FE000000000000000001000000:0222 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   981        0 21964 2 00000000be037b53 0
 4606: B80D0120000000000000000001000000:C277 B80D0120000000000000000002000000:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2847108 2 00000000b01609a4 0
";

    fn all_raw() -> Vec<ListeningSocket> {
        let mut raw = parse_proc_net(TCP, Transport::Tcp, false);
        raw.extend(parse_proc_net(TCP6, Transport::Tcp, true));
        raw.extend(parse_proc_net(UDP, Transport::Udp, false));
        raw.extend(parse_proc_net(UDP6, Transport::Udp, true));
        raw
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn test_parse_ipv4_tcp_listen_only() {
        let sockets = parse_proc_net(TCP, Transport::Tcp, false);
        let found: Vec<(String, u16, u32, u64)> = sockets
            .iter()
            .map(|s| (s.local.to_string(), s.port, s.uid, s.inode))
            .collect();
        assert_eq!(
            found,
            [
                ("0.0.0.0".to_string(), 22, 0, 5716),
                ("127.0.0.54".to_string(), 53, 980, 14298),
                ("192.168.0.5".to_string(), 8080, 1000, 777),
            ],
            "the established connection and the garbage line are skipped"
        );
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn test_parse_ipv6_including_v4_mapped() {
        let sockets = parse_proc_net(TCP6, Transport::Tcp, true);
        let found: Vec<(String, u16)> = sockets
            .iter()
            .map(|s| (s.local.to_string(), s.port))
            .collect();
        assert_eq!(
            found,
            [
                ("::".to_string(), 22),
                ("::1".to_string(), 631),
                ("::ffff:192.0.2.5".to_string(), 8081),
                ("2001:db8::1".to_string(), 443),
            ]
        );
        assert!(sockets.iter().all(|s| s.ipv6_socket));
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn test_parse_udp_bound_but_not_connected() {
        let v4 = parse_proc_net(UDP, Transport::Udp, false);
        let found: Vec<(String, u16)> = v4.iter().map(|s| (s.local.to_string(), s.port)).collect();
        assert_eq!(
            found,
            [
                ("127.0.0.54".to_string(), 53),
                ("0.0.0.0".to_string(), 5353)
            ]
        );
        let v6 = parse_proc_net(UDP6, Transport::Udp, true);
        assert_eq!(v6.len(), 1, "the connected socket is skipped");
        assert_eq!(v6[0].local.to_string(), "fe80::1");
        assert_eq!(v6[0].port, 546);
    }

    /// Established connections only (state 01), IPv4 and IPv6, with
    /// IPv4-mapped peers kept as the kernel prints them.
    #[cfg(target_endian = "little")]
    #[test]
    fn test_parse_established_connections() {
        let v4 = parse_proc_net_established(TCP, false);
        assert_eq!(
            v4,
            [EstablishedSocket {
                local: "192.168.0.5".parse().unwrap(),
                local_port: 50000,
                remote: "192.168.0.11".parse().unwrap(),
                remote_port: 443,
                uid: 1000,
                inode: 778,
            }],
            "listeners and the garbage line are skipped"
        );
        let tcp6 = format!(
            "{}\n{}\n{}\n",
            TCP6.lines().next().unwrap(),
            "   0: B80D0120000000000000000001000000:0016 B80D0120000000000000000002000000:D431 01 00000000:00000000 02:000A7E2F 00000000     0        0 4242 2 0000000000000000 20 4 29 10 -1",
            "   1: 0000000000000000FFFF00000100000A:0016 0000000000000000FFFF00000500000A:E290 01 00000000:00000000 02:000A7E2F 00000000     0        0 4243 2 0000000000000000 20 4 29 10 -1",
        );
        let v6 = parse_proc_net_established(&tcp6, true);
        let found: Vec<(String, u16, String, u16)> = v6
            .iter()
            .map(|c| {
                (
                    c.local.to_string(),
                    c.local_port,
                    c.remote.to_string(),
                    c.remote_port,
                )
            })
            .collect();
        assert_eq!(
            found,
            [
                (
                    "2001:db8::1".to_string(),
                    22,
                    "2001:db8::2".to_string(),
                    54321
                ),
                (
                    "::ffff:10.0.0.1".to_string(),
                    22,
                    "::ffff:10.0.0.5".to_string(),
                    58000
                ),
            ]
        );
        assert_eq!(
            parse_proc_net_established(TCP6, true),
            Vec::new(),
            "listeners only"
        );
        assert_eq!(
            parse_proc_net_established(
                "header
not a line
",
                false
            ),
            Vec::new()
        );
    }

    /// `scan_host_in` reads a `/proc`-like tree: sockets, connections and
    /// their processes.
    #[cfg(all(unix, target_endian = "little"))]
    #[test]
    fn test_scan_host_on_fixture_tree() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("net")).unwrap();
        std::fs::write(root.join("net/tcp"), TCP).unwrap();
        std::fs::create_dir_all(root.join("4000/fd")).unwrap();
        std::fs::write(root.join("4000/comm"), "firefox\n").unwrap();
        symlink("socket:[778]", root.join("4000/fd/3")).unwrap();

        let scan = scan_host_in(root).unwrap();
        assert_eq!(scan.sockets.len(), 3, "{:?}", scan.sockets);
        assert_eq!(scan.established.len(), 1);
        let (connection, processes) = &scan.established[0];
        assert_eq!(connection.remote_port, 443);
        assert_eq!(processes[0].name, "firefox");
        assert!(scan_host_in(&root.join("missing")).is_err());
    }

    #[test]
    fn test_socket_inode_links() {
        assert_eq!(socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode("pipe:[12345]"), None);
        assert_eq!(socket_inode("/dev/null"), None);
        assert_eq!(socket_inode("socket:[x]"), None);
    }

    #[cfg(unix)]
    #[test]
    fn test_map_socket_owners_on_fixture_tree() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let make = |pid: &str, comm: Option<&str>, links: &[&str]| {
            let fd = root.join(pid).join("fd");
            std::fs::create_dir_all(&fd).unwrap();
            if let Some(comm) = comm {
                std::fs::write(root.join(pid).join("comm"), format!("{comm}\n")).unwrap();
            }
            for (n, target) in links.iter().enumerate() {
                symlink(target, fd.join(n.to_string())).unwrap();
            }
        };
        make(
            "100",
            Some("sshd"),
            &["socket:[5716]", "/dev/null", "socket:[5718]"],
        );
        make("200", Some("nginx"), &["socket:[777]", "pipe:[1]"]);
        make("201", Some("nginx"), &["socket:[777]"]);
        make("300", None, &["socket:[903]"]);
        make("400", Some("other"), &["socket:[999999]"]);
        std::fs::create_dir_all(root.join("self")).unwrap(); // not a pid
        std::fs::create_dir_all(root.join("500")).unwrap(); // no readable fd dir

        let wanted: HashSet<u64> = [5716, 5718, 777, 903, 14298].into_iter().collect();
        let owners = map_socket_owners(root, &wanted);
        let names = |inode: u64| -> Vec<(u32, String)> {
            let mut list: Vec<(u32, String)> = owners
                .get(&inode)
                .map_or_default(|ps| ps.iter().map(|p| (p.pid, p.name.clone())).collect());
            list.sort();
            list
        };
        assert_eq!(names(5716), [(100, "sshd".to_string())]);
        assert_eq!(names(5718), [(100, "sshd".to_string())]);
        assert_eq!(
            names(777),
            [(200, "nginx".to_string()), (201, "nginx".to_string())]
        );
        assert_eq!(names(903), [(300, "pid 300".to_string())], "no comm file");
        assert_eq!(names(14298), Vec::new());
        assert!(!owners.contains_key(&999_999), "not wanted");
    }

    fn fixture_sockets(v6only_default: bool) -> Vec<SocketInfo> {
        let mut owners: HashMap<u64, Vec<ProcessInfo>> = HashMap::new();
        owners.insert(
            777,
            vec![ProcessInfo {
                pid: 200,
                name: "nginx".into(),
            }],
        );
        let user = |uid: u32| (uid == 0).then(|| "root".to_string());
        build_socket_list(all_raw(), &owners, 1000, v6only_default, user)
    }

    fn find(sockets: &[SocketInfo], transport: Transport, port: u16) -> Vec<&SocketInfo> {
        sockets
            .iter()
            .filter(|s| s.transport == transport && s.port == port)
            .collect()
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn test_socket_list_scopes_families_and_processes() {
        let sockets = fixture_sockets(false);
        // 22: IPv4 and IPv6 wildcard; the IPv4 socket makes the IPv6 one IPv6-only
        let ssh = find(&sockets, Transport::Tcp, 22);
        assert_eq!(ssh.len(), 2);
        assert_eq!(ssh[0].family_display, "IPv4");
        assert_eq!(ssh[1].family_display, "IPv6");
        assert_eq!(ssh[0].process_display, "unknown (another user: root)");
        assert_eq!(ssh[0].bind_display, "all addresses");

        let dns = find(&sockets, Transport::Tcp, 53);
        assert_eq!(dns[0].scope, BindScope::LocalOnly);
        assert_eq!(dns[0].bind_display, "127.0.0.54 (local only)");
        assert_eq!(dns[0].process_display, "unknown (another user)");

        let ipp = find(&sockets, Transport::Tcp, 631);
        assert_eq!(ipp[0].scope, BindScope::LocalOnly, "::1");

        let web = find(&sockets, Transport::Tcp, 8080);
        assert_eq!(web[0].scope, BindScope::Specific);
        assert_eq!(web[0].bind_display, "192.168.0.5 only");
        assert_eq!(web[0].process_display, "nginx");

        let mapped = find(&sockets, Transport::Tcp, 8081);
        assert_eq!(mapped[0].families, [IpFamily::V4], "IPv4-mapped");
        assert_eq!(mapped[0].bind.to_string(), "192.0.2.5");
        assert_eq!(
            mapped[0].process_display, "unknown",
            "own socket, no process"
        );

        let dhcp = find(&sockets, Transport::Udp, 546);
        assert_eq!(dhcp[0].families, [IpFamily::V6]);
        assert_eq!(dhcp[0].scope, BindScope::Specific, "link-local bind");
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn test_ipv6_wildcard_is_dual_stack_unless_v6only() {
        let raw = parse_proc_net(
            "header\n   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 42 1 0 100 0 0 10 0\n",
            Transport::Tcp,
            true,
        );
        let dual = build_socket_list(raw.clone(), &HashMap::new(), 1000, false, |_| None);
        assert_eq!(dual[0].families, [IpFamily::V4, IpFamily::V6]);
        assert_eq!(dual[0].family_display, "IPv4+IPv6");
        let v6only = build_socket_list(raw, &HashMap::new(), 1000, true, |_| None);
        assert_eq!(v6only[0].families, [IpFamily::V6]);
    }

    #[test]
    fn test_duplicate_sockets_are_merged() {
        let socket = |inode| ListeningSocket {
            transport: Transport::Tcp,
            ipv6_socket: false,
            local: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 80,
            uid: 1000,
            inode,
        };
        let mut owners = HashMap::new();
        owners.insert(
            1,
            vec![ProcessInfo {
                pid: 1,
                name: "a".into(),
            }],
        );
        owners.insert(
            2,
            vec![ProcessInfo {
                pid: 2,
                name: "b".into(),
            }],
        );
        let list = build_socket_list(vec![socket(1), socket(2)], &owners, 1000, false, |_| None);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].process_display, "a, b");
    }

    fn rule(label: &str, port: u16, sources: &[&str]) -> crate::core::firewall::Rule {
        let mut r = crate::core::test_helpers::create_test_rule(label, None);
        r.protocol = Protocol::Tcp;
        r.ports = vec![PortEntry::Single(port)];
        r.sources = sources.iter().map(|s| s.parse().unwrap()).collect();
        r.rebuild_caches();
        r
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn test_exposure_rows_put_open_sockets_first() {
        let mut ruleset = FirewallRuleset::new();
        let ssh = rule("SSH", 22, &[]);
        let ssh_id = ssh.id;
        ruleset.rules.push(ssh);
        ruleset.rules.push(rule("web", 8080, &["10.0.0.0/8"]));
        let rows = exposure_rows(&ruleset, &fixture_sockets(false));
        let open: Vec<_> = rows
            .iter()
            .take_while(|r| r.exposure.open_to_everyone)
            .map(|r| (r.socket.port, r.socket.family_display))
            .collect();
        assert_eq!(open, [(22, "IPv4"), (22, "IPv6")]);
        assert_eq!(rows[0].exposure.summary, "everyone");
        assert_eq!(
            rows[0]
                .exposure
                .decided_by
                .as_ref()
                .and_then(Decider::rule_id),
            Some(ssh_id)
        );
        assert_eq!(rows[0].exposure.decided_by_display, "rule \"SSH\"");

        let by_port = |port| rows.iter().find(|r| r.socket.port == port).unwrap();
        // Bound to 192.168.0.5 only; the rule does not restrict destinations
        assert_eq!(by_port(8080).exposure.summary, "10.0.0.0/8");
        let local = &by_port(53).exposure;
        assert!(local.local_only);
        assert_eq!(local.summary, "local only");
        let closed = &by_port(5353).exposure;
        assert!(closed.nobody);
        assert_eq!(
            closed.decided_by_display,
            "built-in rule \"rate-limited reject\""
        );
        // The DHCPv6 client socket is reachable from link-local servers only
        assert_eq!(
            by_port(546).exposure.summary,
            "fe80::/10 (from source port 547)"
        );
    }

    /// "Accept all TCP on tailscale0" opens the TCP sockets to everyone on
    /// the tailnet, not to everyone: a group of its own, after the sockets
    /// open on any interface.
    #[cfg(target_endian = "little")]
    #[test]
    fn test_interface_scoped_sockets_are_not_open_to_everyone() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(rule("SSH", 22, &[]));
        let mut tailnet = rule("Tailscale", 0, &[]);
        tailnet.ports.clear();
        tailnet.interface = Some("tailscale0".into());
        tailnet.rebuild_caches();
        ruleset.rules.push(tailnet);
        let rows = exposure_rows(&ruleset, &fixture_sockets(false));

        let ranks: Vec<u8> = rows.iter().map(|r| r.exposure.rank()).collect();
        assert!(ranks.windows(2).all(|w| w[0] <= w[1]), "{ranks:?}");
        assert!(rows[0].exposure.open_to_everyone);
        assert_eq!(rows[0].socket.port, 22);
        assert_eq!(rows[0].exposure.open_on_interfaces, Vec::<String>::new());

        let web = rows
            .iter()
            .find(|r| r.socket.port == 8080)
            .expect("TCP 8080");
        assert!(!web.exposure.open_to_everyone);
        assert_eq!(web.exposure.open_on_interfaces, ["tailscale0"]);
        assert_eq!(web.exposure.rank(), 1);
        assert_eq!(
            web.exposure.open_on_badge().as_deref(),
            Some("OPEN ON tailscale0")
        );
        assert_eq!(rows[0].exposure.open_on_badge(), None);
        assert_eq!(web.exposure.summary, "everyone on tailscale0");
        assert_eq!(web.exposure.decided_by_display, "rule \"Tailscale\"");
        // UDP is not covered by the rule
        let mdns = rows.iter().find(|r| r.socket.port == 5353).unwrap();
        assert_eq!(mdns.exposure.open_on_interfaces, Vec::<String>::new());
        assert_eq!(mdns.exposure.rank(), 3);
    }

    #[test]
    fn test_open_on_badge_names_two_interfaces() {
        let mut exposure = SocketExposure {
            local_only: false,
            per_family: Vec::new(),
            open_to_everyone: false,
            open_on_interfaces: vec!["eth0".into(), "wg*".into()],
            nobody: false,
            summary: String::new(),
            decided_by: None,
            decided_by_display: String::new(),
            docker_published: false,
            docker_forward_filtered: false,
            local_discovery: false,
        };
        assert_eq!(
            exposure.open_on_badge().as_deref(),
            Some("OPEN ON eth0, wg*")
        );
        exposure.open_on_interfaces.push("tailscale0".into());
        exposure.open_on_interfaces.push("br0".into());
        assert_eq!(
            exposure.open_on_badge().as_deref(),
            Some("OPEN ON eth0, wg* +2")
        );
        exposure.open_on_interfaces.clear();
        assert_eq!(exposure.open_on_badge(), None);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn test_summary_per_family_when_they_differ() {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules.push(rule("v4 only", 8000, &["10.0.0.0/8"]));
        let raw = parse_proc_net(
            "header\n   0: 00000000000000000000000000000000:1F40 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 42 1 0 100 0 0 10 0\n",
            Transport::Tcp,
            true,
        );
        let sockets = build_socket_list(raw, &HashMap::new(), 1000, false, |_| None);
        let rows = exposure_rows(&ruleset, &sockets);
        assert_eq!(rows[0].exposure.summary, "IPv4: 10.0.0.0/8; IPv6: nobody");
    }

    /// A port Docker publishes replaces the evaluator's verdict ("nobody"
    /// here: no rule allows 8080) and sorts with the exposed sockets.
    #[cfg(target_endian = "little")]
    #[test]
    fn test_docker_published_ports_replace_the_verdict() {
        use crate::core::host_facts::{ContainerFacts, DOCKER_PUBLISHED, PublishedPort};

        let ruleset = FirewallRuleset::new();
        let mut rows = exposure_rows(&ruleset, &fixture_sockets(false));
        let before = rows.iter().find(|r| r.socket.port == 8080).unwrap();
        assert!(before.exposure.nobody);
        let containers = ContainerFacts {
            published: vec![PublishedPort {
                transport: Transport::Tcp,
                host_ip: Some("192.168.0.5".parse().unwrap()),
                host_port: 8080,
                container_ip: None,
                container_port: Some(80),
            }],
            bridges: true,
        };
        // The fixture's socket belongs to a user: not Docker's proxy
        assert_eq!(mark_docker_published(&mut rows, &containers), 0);
        let root_owned = |rows: &mut [ExposureRow]| {
            for row in rows.iter_mut().filter(|r| r.socket.port == 8080) {
                row.socket.uid = 0;
            }
        };
        root_owned(&mut rows);
        assert_eq!(mark_docker_published(&mut rows, &containers), 1);
        let marked = &rows[0];
        assert_eq!(
            marked.socket.port, 8080,
            "sorted first (nothing else is open)"
        );
        assert!(marked.exposure.docker_published);
        assert!(!marked.exposure.nobody && !marked.exposure.open_to_everyone);
        assert_eq!(marked.exposure.summary, DOCKER_PUBLISHED);
        assert!(marked.exposure.decided_by.is_none());
        assert_eq!(marked.exposure.decided_by_display, "");
        assert_eq!(marked.exposure.rank(), 1);
        assert!(!marked.exposure.docker_forward_filtered);
        assert_eq!(
            rows.iter().filter(|r| r.exposure.docker_published).count(),
            1,
            "only the published socket"
        );

        // With "Block forwarded traffic" DRFW's Forwarded rules decide it
        let mut blocking = FirewallRuleset::new();
        blocking.advanced_security.block_forwarding = true;
        let mut rows = exposure_rows(&blocking, &fixture_sockets(false));
        assert!(rows.iter().all(|r| r.exposure.docker_forward_filtered));
        root_owned(&mut rows);
        assert_eq!(mark_docker_published(&mut rows, &containers), 1);
        let marked = rows.iter().find(|r| r.exposure.docker_published).unwrap();
        assert_eq!(
            marked.exposure.summary,
            crate::core::host_facts::DOCKER_PUBLISHED_FORWARD_FILTERED
        );
        assert!(!marked.exposure.nobody && !marked.exposure.open_to_everyone);
        assert_eq!(marked.exposure.rank(), 2);
    }

    // ── Local network discovery ───────────────────────────────────────

    /// A dual-stack UDP socket on all addresses (or on `bind`).
    fn udp_socket(port: u16, bind: &str) -> SocketInfo {
        let bind: IpAddr = bind.parse().unwrap();
        SocketInfo {
            transport: Transport::Udp,
            port,
            bind,
            scope: if bind.is_unspecified() {
                BindScope::AllAddresses
            } else {
                BindScope::Specific
            },
            families: if bind.is_unspecified() {
                vec![IpFamily::V4, IpFamily::V6]
            } else if bind.is_ipv4() {
                vec![IpFamily::V4]
            } else {
                vec![IpFamily::V6]
            },
            uid: 1000,
            processes: Vec::new(),
            process_display: String::new(),
            bind_display: String::new(),
            family_display: "IPv4+IPv6",
        }
    }

    fn discovery_ruleset() -> FirewallRuleset {
        let mut ruleset = FirewallRuleset::new();
        ruleset.advanced_security.local_discovery = true;
        ruleset
    }

    /// Ordinary UDP services are not shown as reachable just because local
    /// discovery accepts replies to our own queries: that only holds for a
    /// port that just sent a discovery query, which a service on another
    /// port than the discovery protocols' does not do.
    #[test]
    fn test_discovery_replies_are_not_exposure() {
        let ruleset = discovery_ruleset();
        // The evaluator itself reports the conditional reply accept
        let probe = Probe {
            transport: Transport::Udp,
            port: 51820,
            family: IpFamily::V4,
            interface: None,
            destination: None,
            source: ProbeSource::Unknown,
        };
        let Verdict::Reachable(raw) = InputChain::new(&ruleset).evaluate(&probe) else {
            panic!("not evaluated");
        };
        assert!(
            raw.conditional
                .iter()
                .any(|a| a.when.contains(&Condition::DiscoveryReply))
        );
        let rows = exposure_rows(
            &ruleset,
            &[udp_socket(51820, "::"), udp_socket(40000, "192.168.1.5")],
        );
        for row in &rows {
            assert!(
                row.exposure.nobody,
                "{}: {}",
                row.socket.port, row.exposure.summary
            );
            assert!(!row.exposure.local_discovery);
            assert_eq!(row.exposure.summary, "nobody");
            assert!(
                row.exposure
                    .per_family
                    .iter()
                    .all(|r| r.conditional.is_empty())
            );
            assert_eq!(row.exposure.rank(), 3);
        }

        // A rule still counts as usual (the reply accept is not appended)
        let mut ruleset = discovery_ruleset();
        let mut wg = rule("WireGuard", 51820, &[]);
        wg.protocol = Protocol::Udp;
        wg.rebuild_caches();
        ruleset.rules.push(wg);
        let rows = exposure_rows(&ruleset, &[udp_socket(51820, "::")]);
        assert!(rows[0].exposure.open_to_everyone);
        assert_eq!(rows[0].exposure.summary, "everyone");
    }

    /// UDP sockets on the discovery ports announce and query from them, so
    /// the replies reach them: kept as a conditional access. Only the
    /// replies reach the `NetBIOS` name service and LLMNR sockets, and a
    /// discovery socket bound to a unicast address.
    #[test]
    fn test_discovery_port_sockets_receive_replies() {
        use crate::core::evaluate::BASE_DISCOVERY_REPLY;
        let ruleset = discovery_ruleset();
        let replies_in = |exposure: &SocketExposure| {
            exposure.per_family.iter().all(|r| {
                r.conditional
                    .iter()
                    .any(|a| a.when.contains(&Condition::DiscoveryReply))
            })
        };
        for (port, bind) in [(137, "0.0.0.0"), (5355, "::"), (5353, "192.168.1.5")] {
            let rows = exposure_rows(&ruleset, &[udp_socket(port, bind)]);
            let exposure = &rows[0].exposure;
            assert_eq!(exposure.summary, LOCAL_DISCOVERY_REPLIES, "{port}");
            assert!(exposure.local_discovery && !exposure.nobody, "{port}");
            assert!(!exposure.open_to_everyone, "{port}");
            assert_eq!(exposure.rank(), 2, "{port}");
            assert!(replies_in(exposure), "{port}");
            assert_eq!(
                exposure.decided_by,
                Some(Decider::BaseRule(BASE_DISCOVERY_REPLY)),
                "{port}"
            );
            // Without discovery: closed
            let rows = exposure_rows(&FirewallRuleset::new(), &[udp_socket(port, bind)]);
            assert!(rows[0].exposure.nobody, "{port}");
        }
        // The multicast sockets keep the replies too
        for port in [5353, 1900, 3702] {
            let rows = exposure_rows(&ruleset, &[udp_socket(port, "::")]);
            assert!(replies_in(&rows[0].exposure), "{port}");
            assert_eq!(rows[0].exposure.summary, LOCAL_DISCOVERY, "{port}");
        }
        // TCP on 137 is not discovery
        let mut tcp = udp_socket(137, "0.0.0.0");
        tcp.transport = Transport::Tcp;
        assert!(exposure_rows(&ruleset, &[tcp])[0].exposure.nobody);
    }

    /// The discovery sockets read "local network (discovery)", decided by the
    /// discovery accept, not counted as open; with discovery off they are
    /// closed like any other port.
    #[test]
    fn test_discovery_sockets_read_local_network() {
        use crate::core::evaluate::{BASE_MDNS, BASE_SSDP};
        let ruleset = discovery_ruleset();
        for (port, base) in [(5353, BASE_MDNS), (1900, BASE_SSDP), (3702, BASE_SSDP)] {
            let rows = exposure_rows(&ruleset, &[udp_socket(port, "::")]);
            let exposure = &rows[0].exposure;
            assert_eq!(exposure.summary, LOCAL_DISCOVERY, "{port}");
            assert!(exposure.local_discovery);
            assert!(!exposure.nobody && !exposure.open_to_everyone);
            assert_eq!(exposure.open_on_interfaces, Vec::<String>::new());
            assert_eq!(exposure.open_on_badge(), None);
            assert_eq!(exposure.rank(), 2);
            assert_eq!(exposure.decided_by, Some(Decider::BaseRule(base)));

            let rows = exposure_rows(&FirewallRuleset::new(), &[udp_socket(port, "::")]);
            assert!(rows[0].exposure.nobody && !rows[0].exposure.local_discovery);
        }

        // Bound to the group address itself (some SSDP servers do this)
        let rows = exposure_rows(&ruleset, &[udp_socket(1900, "239.255.255.250")]);
        assert_eq!(rows[0].exposure.summary, LOCAL_DISCOVERY);
        assert!(!rows[0].exposure.open_to_everyone);

        // Bound to a unicast address: multicast does not reach it (the
        // replies to its queries do, see the test above)
        let rows = exposure_rows(&ruleset, &[udp_socket(5353, "192.168.1.5")]);
        assert_eq!(rows[0].exposure.summary, LOCAL_DISCOVERY_REPLIES);

        // TCP on a discovery port is not discovery
        let mut tcp = udp_socket(5353, "::");
        tcp.transport = Transport::Tcp;
        assert!(exposure_rows(&ruleset, &[tcp])[0].exposure.nobody);

        // Server Mode ignores the setting
        let mut server = discovery_ruleset();
        server.advanced_security.egress_profile = crate::core::firewall::EgressProfile::Server;
        assert!(
            exposure_rows(&server, &[udp_socket(5353, "::")])[0]
                .exposure
                .nobody
        );
    }

    /// A rule that also lets sources reach a discovery socket is shown with
    /// the discovery access after it, and decides.
    #[test]
    fn test_discovery_socket_with_a_rule() {
        let mut ruleset = discovery_ruleset();
        let mut mdns = rule("mDNS from the office", 5353, &["10.1.0.0/16"]);
        mdns.protocol = Protocol::Udp;
        mdns.rebuild_caches();
        let id = mdns.id;
        ruleset.rules.push(mdns);
        let rows = exposure_rows(&ruleset, &[udp_socket(5353, "::")]);
        let exposure = &rows[0].exposure;
        assert_eq!(
            exposure.summary,
            format!("IPv4: 10.1.0.0/16; {LOCAL_DISCOVERY}; IPv6: {LOCAL_DISCOVERY}")
        );
        assert_eq!(
            exposure.decided_by.as_ref().and_then(Decider::rule_id),
            Some(id)
        );
    }
}
