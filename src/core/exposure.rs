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
    Decider, InputChain, IpFamily, Probe, ProbeSource, Reachability, Transport, Verdict,
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
    /// Every address of some family can connect (at least within a limit)
    pub open_to_everyone: bool,
    /// Nobody can connect over any family
    pub nobody: bool,
    /// "everyone", "IPv4: 10.0.0.0/8; IPv6: nobody", "local only", …
    pub summary: String,
    /// The rule that matters most (see [`Reachability::deciding`])
    pub decided_by: Option<Decider>,
    /// `decided_by` as text ("rule \"SSH\"", …); empty when local only
    pub decided_by_display: String,
}

/// Evaluates who can open a new connection to `socket` under `chain`.
pub fn evaluate_socket(chain: &InputChain, socket: &SocketInfo) -> SocketExposure {
    if socket.scope == BindScope::LocalOnly {
        return SocketExposure {
            local_only: true,
            per_family: Vec::new(),
            open_to_everyone: false,
            nobody: false,
            summary: "local only".to_string(),
            decided_by: None,
            decided_by_display: String::new(),
        };
    }
    let destination = (socket.scope == BindScope::Specific).then_some(socket.bind);
    let per_family: Vec<Reachability> = socket
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

    let open_to_everyone = per_family.iter().any(Reachability::open_to_everyone);
    let nobody = per_family.iter().all(Reachability::nobody);
    let texts: Vec<String> = per_family.iter().map(ToString::to_string).collect();
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
    // The most exposed family's deciding rule
    let decided_by = per_family
        .iter()
        .find(|r| r.open_to_everyone())
        .or_else(|| per_family.iter().find(|r| !r.nobody()))
        .or_else(|| per_family.first())
        .and_then(Reachability::deciding)
        .cloned();
    let decided_by_display = decided_by.as_ref().map_or_default(ToString::to_string);
    SocketExposure {
        local_only: false,
        per_family,
        open_to_everyone,
        nobody,
        summary,
        decided_by,
        decided_by_display,
    }
}

/// One listening socket with its exposure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureRow {
    pub socket: SocketInfo,
    pub exposure: SocketExposure,
}

/// Evaluates every socket against `ruleset`: one row per socket, those open
/// to everyone first, then by protocol and port.
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
    rows.sort_by_key(|row| !row.exposure.open_to_everyone);
    rows
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
}
