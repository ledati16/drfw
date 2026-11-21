//! Host facts: what this computer does that DRFW's rules do not cover
//!
//! Read without privileges from `/proc` (world-readable files only), for
//! notices in `drfw status`, `drfw exposure`, the Exposure panel and the
//! apply dialog. Nothing here changes the generated rules.
//!
//! - [`forwarding_enabled`]: whether the kernel forwards (routes) traffic
//!   between interfaces (`net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding`).
//!   DRFW's forward chain accepts by default, so forwarded traffic is not
//!   filtered unless "Block forwarded traffic" is on.
//! - [`docker_published_ports`]: the ports Docker publishes through
//!   `docker-proxy` (its command line names them). Docker sends published
//!   traffic through DNAT and the forward chain, so DRFW's input rules never
//!   see it: with "Block forwarded traffic" on, DRFW's Forwarded rules
//!   decide it, otherwise DRFW does not filter it. Only proxies running as root count, and only for sockets root
//!   owns: any user can start a program named `docker-proxy`, which must not
//!   relabel a real listening socket. (Rootless Docker's proxy runs as the
//!   user; its traffic does reach the input rules.)
//! - [`container_bridges_present`]: whether Docker or Podman bridge
//!   interfaces exist (they may publish ports without a proxy).
//!
//! # Test override
//!
//! Like [`crate::core::exposure`], every file is read below
//! [`crate::core::exposure::proc_root`], so `DRFW_TEST_PROC_DIR` replaces
//! `/proc` (`sys/net/ipv4/ip_forward`, `sys/net/ipv6/conf/all/forwarding`,
//! `<pid>/cmdline`, `<pid>/status`, `net/dev`).

use std::net::IpAddr;
use std::path::Path;

use super::evaluate::Transport;
use super::exposure::{BindScope, SocketInfo, proc_root};
use super::firewall::FirewallRuleset;

/// The forwarding notice (only when forwarding is on and DRFW does not block
/// it; see [`forwarding_warning`]).
pub const FORWARDING_WARNING: &str = "This computer forwards traffic between its networks \
     (IP forwarding is on). DRFW does not filter forwarded traffic; containers, VMs or other \
     networks may be reachable through it.";

/// What the Exposure view and `drfw exposure` say instead of the evaluator's
/// verdict for a port Docker publishes, when the ruleset does not block
/// forwarded traffic.
pub const DOCKER_PUBLISHED: &str = "published by Docker: not filtered by DRFW's rules";

/// [`DOCKER_PUBLISHED`] when the ruleset blocks forwarded traffic: Docker's
/// DNAT sends the traffic through DRFW's forward chain, which drops it
/// unless a Forwarded rule allows it.
pub const DOCKER_PUBLISHED_FORWARD_FILTERED: &str =
    "published by Docker: decided by your Forwarded rules (blocked unless one allows it)";

/// The general note when Docker or Podman networks exist but no
/// `docker-proxy` was found (published ports may then exist without a
/// listening socket), when the ruleset does not block forwarded traffic.
pub const CONTAINER_NETWORKS_NOTE: &str = "Docker or Podman networks exist on this computer. \
     Ports they publish are not filtered by DRFW's rules and may not be listed here.";

/// [`CONTAINER_NETWORKS_NOTE`] when the ruleset blocks forwarded traffic.
pub const CONTAINER_NETWORKS_NOTE_FORWARD_FILTERED: &str = "Docker or Podman networks exist \
     on this computer. Ports they publish are decided by your Forwarded rules (blocked unless \
     one allows them) and may not be listed here.";

/// Whether the kernel forwards IPv4 and IPv6 traffic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForwardingState {
    /// `net.ipv4.ip_forward` is 1
    pub ipv4: bool,
    /// `net.ipv6.conf.all.forwarding` is 1
    pub ipv6: bool,
}

impl ForwardingState {
    /// Forwarding is on for either family.
    pub const fn any(self) -> bool {
        self.ipv4 || self.ipv6
    }
}

/// Reads the forwarding switches from [`proc_root`]. A missing or unreadable
/// file counts as off (IPv6 disabled, `/proc` not mounted).
pub fn forwarding_enabled() -> ForwardingState {
    forwarding_in(&proc_root())
}

/// [`forwarding_enabled`] with `root` read as `/proc`.
pub fn forwarding_in(root: &Path) -> ForwardingState {
    let on = |file: &str| {
        std::fs::read_to_string(root.join(file)).is_ok_and(|value| value.trim() == "1")
    };
    ForwardingState {
        ipv4: on("sys/net/ipv4/ip_forward"),
        ipv6: on("sys/net/ipv6/conf/all/forwarding"),
    }
}

/// [`FORWARDING_WARNING`] when the kernel forwards and `ruleset` does not
/// block forwarded traffic; `None` otherwise.
pub fn forwarding_warning(
    forwarding: ForwardingState,
    ruleset: &FirewallRuleset,
) -> Option<&'static str> {
    (forwarding.any() && !ruleset.advanced_security.block_forwarding).then_some(FORWARDING_WARNING)
}

/// A port Docker publishes, from one `docker-proxy` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPort {
    pub transport: Transport,
    /// `-host-ip`; `None` when absent (all addresses)
    pub host_ip: Option<IpAddr>,
    /// `-host-port`
    pub host_port: u16,
    /// `-container-ip`
    pub container_ip: Option<IpAddr>,
    /// `-container-port`
    pub container_port: Option<u16>,
}

impl PublishedPort {
    /// `socket` is the host side of this published port: same protocol and
    /// port, bound to the published address (or the wildcard address when
    /// the port is published on all addresses), owned by root (as Docker's
    /// proxy is). Loopback-only sockets are never matched: only this
    /// computer can reach them anyway.
    pub fn matches(&self, socket: &SocketInfo) -> bool {
        if socket.transport != self.transport
            || socket.port != self.host_port
            || socket.uid != 0
            || socket.scope == BindScope::LocalOnly
        {
            return false;
        }
        match self.host_ip {
            None => true,
            Some(ip) if ip.is_unspecified() => socket.bind.is_unspecified(),
            Some(ip) => socket.bind == ip,
        }
    }
}

/// Parses a `/proc/<pid>/cmdline` (NUL-separated arguments) of
/// `docker-proxy`. `None` for any other program, or when the protocol or
/// host port is missing or malformed.
///
/// Accepts `-flag value`, `--flag value` and `-flag=value` (Go's flag
/// syntax).
pub fn parse_docker_proxy_cmdline(cmdline: &[u8]) -> Option<PublishedPort> {
    let text = std::str::from_utf8(cmdline).ok()?;
    let mut args = text.split('\0').filter(|a| !a.is_empty());
    let program = args.next()?;
    if Path::new(program).file_name()?.to_str()? != "docker-proxy" {
        return None;
    }
    let mut proto = None;
    let mut host_ip = None;
    let mut host_port = None;
    let mut container_ip = None;
    let mut container_port = None;
    while let Some(arg) = args.next() {
        let Some(flag) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) else {
            continue;
        };
        let (name, value) = match flag.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (flag, None),
        };
        let wants_value = matches!(
            name,
            "proto" | "host-ip" | "host-port" | "container-ip" | "container-port"
        );
        if !wants_value {
            continue;
        }
        let Some(value) = value.or_else(|| args.next()) else {
            break;
        };
        match name {
            "proto" => proto = Some(value),
            "host-ip" => host_ip = value.parse().ok(),
            "host-port" => host_port = value.parse().ok(),
            "container-ip" => container_ip = value.parse().ok(),
            "container-port" => container_port = value.parse().ok(),
            _ => {}
        }
    }
    let transport = match proto? {
        "tcp" | "tcp4" | "tcp6" => Transport::Tcp,
        "udp" | "udp4" | "udp6" => Transport::Udp,
        _ => return None,
    };
    Some(PublishedPort {
        transport,
        host_ip,
        host_port: host_port?,
        container_ip,
        container_port,
    })
}

/// The ports published by the `docker-proxy` processes in [`proc_root`]
/// that run as root (`/proc/<pid>/cmdline` and `status` are
/// world-readable). Empty without Docker, or when Docker runs without its
/// userland proxy or rootless.
pub fn docker_published_ports() -> Vec<PublishedPort> {
    docker_published_ports_in(&proc_root())
}

/// [`docker_published_ports`] with `root` read as `/proc`.
pub fn docker_published_ports_in(root: &Path) -> Vec<PublishedPort> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut ports: Vec<PublishedPort> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.parse::<u32>().is_ok())
        })
        .filter(|entry| runs_as_root(&entry.path()))
        .filter_map(|entry| std::fs::read(entry.path().join("cmdline")).ok())
        .filter_map(|cmdline| parse_docker_proxy_cmdline(&cmdline))
        .collect();
    ports.sort_by_key(|p| (p.transport, p.host_port));
    ports.dedup();
    ports
}

/// The process of `/proc/<pid>` (`dir`) runs as root: the real and the
/// effective user of its `status` file's `Uid:` line are 0. (The owner of
/// the directory itself is not proof: a process that makes itself
/// non-dumpable gets a root-owned `/proc/<pid>`.)
fn runs_as_root(dir: &Path) -> bool {
    let Ok(status) = std::fs::read_to_string(dir.join("status")) else {
        return false;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .is_some_and(|uids| {
            let mut ids = uids.split_whitespace();
            ids.next() == Some("0") && ids.next() == Some("0")
        })
}

/// `true` for interface names Docker or Podman create for their networks:
/// `docker0`, `br-<id>` (Docker user-defined networks), `podman*` and
/// `cni-podman*`.
pub fn is_container_bridge(name: &str) -> bool {
    name.starts_with("docker")
        || name.starts_with("br-")
        || name.starts_with("podman")
        || name.starts_with("cni-podman")
}

/// The interface names in a `/proc/net/dev` text.
fn interface_names(net_dev: &str) -> impl Iterator<Item = &str> {
    net_dev
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, _)| name.trim())
        .filter(|name| !name.is_empty() && !name.contains(' ') && !name.contains('|'))
}

/// Docker or Podman bridge interfaces exist ([`is_container_bridge`], from
/// `/proc/net/dev` in [`proc_root`]).
pub fn container_bridges_present() -> bool {
    container_bridges_in(&proc_root())
}

/// [`container_bridges_present`] with `root` read as `/proc`.
pub fn container_bridges_in(root: &Path) -> bool {
    std::fs::read_to_string(root.join("net/dev"))
        .is_ok_and(|text| interface_names(&text).any(is_container_bridge))
}

/// What the container checks found: the published ports and whether
/// container networks exist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerFacts {
    /// Ports published through `docker-proxy`
    pub published: Vec<PublishedPort>,
    /// Docker or Podman bridge interfaces exist
    pub bridges: bool,
}

impl ContainerFacts {
    /// Reads both from [`proc_root`] (blocking; cheap).
    pub fn read() -> Self {
        Self::read_in(&proc_root())
    }

    /// [`Self::read`] with `root` read as `/proc`.
    pub fn read_in(root: &Path) -> Self {
        Self {
            published: docker_published_ports_in(root),
            bridges: container_bridges_in(root),
        }
    }

    /// `socket` is the host side of a published port.
    pub fn publishes(&self, socket: &SocketInfo) -> bool {
        self.published.iter().any(|port| port.matches(socket))
    }

    /// [`CONTAINER_NETWORKS_NOTE`] when container networks exist but no
    /// proxy was found; `None` otherwise. For a ruleset that blocks
    /// forwarded traffic, use [`Self::note_for`].
    pub fn note(&self) -> Option<&'static str> {
        self.note_for(false)
    }

    /// [`Self::note`] for a ruleset that blocks forwarded traffic
    /// (`blocks_forwarding`, [`CONTAINER_NETWORKS_NOTE_FORWARD_FILTERED`]) or
    /// not.
    pub fn note_for(&self, blocks_forwarding: bool) -> Option<&'static str> {
        (self.bridges && self.published.is_empty()).then_some(if blocks_forwarding {
            CONTAINER_NETWORKS_NOTE_FORWARD_FILTERED
        } else {
            CONTAINER_NETWORKS_NOTE
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::evaluate::IpFamily;

    fn write(root: &Path, file: &str, contents: &[u8]) {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn cmdline(args: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for arg in args {
            out.extend_from_slice(arg.as_bytes());
            out.push(0);
        }
        out
    }

    fn socket(transport: Transport, bind: &str, port: u16) -> SocketInfo {
        let bind: IpAddr = bind.parse().unwrap();
        SocketInfo {
            transport,
            port,
            bind,
            scope: if bind.is_loopback() {
                BindScope::LocalOnly
            } else if bind.is_unspecified() {
                BindScope::AllAddresses
            } else {
                BindScope::Specific
            },
            families: vec![IpFamily::V4],
            uid: 0,
            processes: Vec::new(),
            process_display: String::new(),
            bind_display: String::new(),
            family_display: "IPv4",
        }
    }

    #[test]
    fn test_forwarding_flags_from_fixture() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert_eq!(forwarding_in(root), ForwardingState::default(), "missing");
        write(root, "sys/net/ipv4/ip_forward", b"1\n");
        write(root, "sys/net/ipv6/conf/all/forwarding", b"0\n");
        let state = forwarding_in(root);
        assert!(state.ipv4 && !state.ipv6 && state.any());
        write(root, "sys/net/ipv4/ip_forward", b"0\n");
        write(root, "sys/net/ipv6/conf/all/forwarding", b"1\n");
        let state = forwarding_in(root);
        assert!(!state.ipv4 && state.ipv6 && state.any());
        write(root, "sys/net/ipv6/conf/all/forwarding", b"garbage");
        assert!(!forwarding_in(root).any());
    }

    #[test]
    fn test_forwarding_warning_only_when_not_blocked() {
        let on = ForwardingState {
            ipv4: true,
            ipv6: false,
        };
        let mut ruleset = FirewallRuleset::new();
        assert_eq!(forwarding_warning(on, &ruleset), Some(FORWARDING_WARNING));
        assert_eq!(
            forwarding_warning(ForwardingState::default(), &ruleset),
            None
        );
        ruleset.advanced_security.block_forwarding = true;
        assert_eq!(forwarding_warning(on, &ruleset), None);
    }

    #[test]
    fn test_parse_docker_proxy_cmdlines() {
        let port = parse_docker_proxy_cmdline(&cmdline(&[
            "/usr/bin/docker-proxy",
            "-proto",
            "tcp",
            "-host-ip",
            "0.0.0.0",
            "-host-port",
            "8080",
            "-container-ip",
            "172.17.0.2",
            "-container-port",
            "80",
            "-use-listen-fd",
        ]))
        .expect("docker-proxy");
        assert_eq!(
            port,
            PublishedPort {
                transport: Transport::Tcp,
                host_ip: Some("0.0.0.0".parse().unwrap()),
                host_port: 8080,
                container_ip: Some("172.17.0.2".parse().unwrap()),
                container_port: Some(80),
            }
        );
        // --flag and -flag=value forms, IPv6, UDP
        let port = parse_docker_proxy_cmdline(&cmdline(&[
            "docker-proxy",
            "--proto=udp",
            "--host-ip",
            "::",
            "-host-port=5353",
        ]))
        .expect("docker-proxy");
        assert_eq!(port.transport, Transport::Udp);
        assert_eq!(port.host_ip, Some("::".parse().unwrap()));
        assert_eq!(port.host_port, 5353);
        assert_eq!(port.container_port, None);

        // Other programs, missing or bad fields
        assert_eq!(
            parse_docker_proxy_cmdline(&cmdline(&["nginx", "-proto", "tcp", "-host-port", "80"])),
            None
        );
        assert_eq!(
            parse_docker_proxy_cmdline(&cmdline(&["docker-proxy", "-proto", "tcp"])),
            None
        );
        assert_eq!(
            parse_docker_proxy_cmdline(&cmdline(&[
                "docker-proxy",
                "-proto",
                "sctp",
                "-host-port",
                "80"
            ])),
            None
        );
        assert_eq!(
            parse_docker_proxy_cmdline(&cmdline(&[
                "docker-proxy",
                "-proto",
                "tcp",
                "-host-port",
                "99999"
            ])),
            None
        );
        assert_eq!(parse_docker_proxy_cmdline(b""), None);
        assert_eq!(parse_docker_proxy_cmdline(b"\xff\xfe"), None);
    }

    #[test]
    fn test_published_port_matching() {
        let all = PublishedPort {
            transport: Transport::Tcp,
            host_ip: Some("0.0.0.0".parse().unwrap()),
            host_port: 8080,
            container_ip: None,
            container_port: None,
        };
        assert!(all.matches(&socket(Transport::Tcp, "0.0.0.0", 8080)));
        assert!(all.matches(&socket(Transport::Tcp, "::", 8080)));
        assert!(!all.matches(&socket(Transport::Udp, "0.0.0.0", 8080)));
        assert!(!all.matches(&socket(Transport::Tcp, "0.0.0.0", 8081)));
        assert!(!all.matches(&socket(Transport::Tcp, "192.168.1.5", 8080)));

        let one = PublishedPort {
            host_ip: Some("192.168.1.5".parse().unwrap()),
            ..all.clone()
        };
        assert!(one.matches(&socket(Transport::Tcp, "192.168.1.5", 8080)));
        assert!(!one.matches(&socket(Transport::Tcp, "0.0.0.0", 8080)));

        let local = PublishedPort {
            host_ip: Some("127.0.0.1".parse().unwrap()),
            ..all.clone()
        };
        assert!(
            !local.matches(&socket(Transport::Tcp, "127.0.0.1", 8080)),
            "local only stays local only"
        );

        let any = PublishedPort {
            host_ip: None,
            ..all
        };
        assert!(any.matches(&socket(Transport::Tcp, "10.0.0.1", 8080)));
    }

    #[test]
    fn test_container_facts_from_fixture() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert_eq!(ContainerFacts::read_in(root), ContainerFacts::default());

        let net_dev = "Inter-|   Receive                            |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes
    lo:  1000      10    0    0    0     0          0         0  1000
  eth0:  2000      20    0    0    0     0          0         0  2000
";
        write(root, "net/dev", net_dev.as_bytes());
        assert!(!container_bridges_in(root), "no container bridge");
        write(
            root,
            "net/dev",
            format!("{net_dev}docker0: 0 0 0 0 0 0 0 0 0\n").as_bytes(),
        );
        let facts = ContainerFacts::read_in(root);
        assert!(facts.bridges);
        assert_eq!(
            facts.note(),
            Some(CONTAINER_NETWORKS_NOTE),
            "no proxy found"
        );
        assert_eq!(
            facts.note_for(true),
            Some(CONTAINER_NETWORKS_NOTE_FORWARD_FILTERED)
        );

        let proxy =
            |port: &str| cmdline(&["/usr/bin/docker-proxy", "-proto", "tcp", "-host-port", port]);
        write(root, "4100/cmdline", &proxy("8080"));
        write(
            root,
            "4100/status",
            b"Name:\tdocker-proxy\nUid:\t0\t0\t0\t0\n",
        );
        write(root, "4200/cmdline", &cmdline(&["/usr/bin/sshd", "-D"]));
        write(root, "4200/status", b"Uid:\t0\t0\t0\t0\n");
        // A user's program named docker-proxy (`exec -a docker-proxy …`),
        // and one without a readable status: not Docker's
        write(root, "4300/cmdline", &proxy("51022"));
        write(root, "4300/status", b"Uid:\t1000\t1000\t1000\t1000\n");
        write(root, "4400/cmdline", &proxy("51023"));
        write(root, "4500/cmdline", &proxy("51024"));
        write(root, "4500/status", b"Uid:\t1000\t0\t0\t0\n");
        write(
            root,
            "self/cmdline",
            &cmdline(&["docker-proxy", "-proto", "tcp", "-host-port", "1"]),
        );
        let facts = ContainerFacts::read_in(root);
        assert_eq!(facts.published.len(), 1, "{:?}", facts.published);
        assert_eq!(facts.published[0].host_port, 8080);
        assert_eq!(facts.note(), None, "the proxy is found");
        assert!(facts.publishes(&socket(Transport::Tcp, "0.0.0.0", 8080)));
        assert!(!facts.publishes(&socket(Transport::Tcp, "0.0.0.0", 22)));
        // A user's socket on the published port is not the proxy's
        let mut users = socket(Transport::Tcp, "0.0.0.0", 8080);
        users.uid = 1000;
        assert!(!facts.publishes(&users));
    }

    #[test]
    fn test_container_bridge_names() {
        for name in ["docker0", "br-3f2a9c1d0e4b", "podman0", "cni-podman0"] {
            assert!(is_container_bridge(name), "{name}");
        }
        for name in ["eth0", "virbr0", "wlan0", "tailscale0", "br0x"] {
            assert!(!is_container_bridge(name), "{name}");
        }
    }
}
