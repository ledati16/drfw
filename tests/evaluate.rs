//! Property tests of the rule evaluator (`drfw::core::evaluate`)
//!
//! - **Self-consistency** (no privileges, always runs): for random rulesets
//!   and sources, the per-source verdict and the "who can connect" set agree.
//! - **Agreement with the kernel**: random rulesets are applied with the real
//!   `nft -j -f` in a private network namespace, a TCP SYN or UDP datagram is
//!   sent from a second namespace over a veth pair, and the outcome (accepted,
//!   dropped, rejected) is compared with the evaluator's verdict for the first
//!   packet.
//!
//! The kernel tests run inside `unshare -rn` (no root needed). They need
//! `unshare`, `nsenter`, `ip` and `nft`; without them they print a skip notice
//! and pass, unless `DRFW_REQUIRE_REAL_NFT=1` is set, in which case they fail.
//!
//! # How the kernel test works
//!
//! The test binary re-executes itself: [`helper_kernel_server`] runs inside
//! `unshare -rn` (the firewalled "server" namespace) and builds the topology,
//! and for every probe [`helper_kernel_client`] runs inside the client
//! namespace (via `nsenter`). Without their environment variables both
//! helpers return at once, so in a normal test run they are no-ops.
//!
//! - The server listens on the probed port, so an accepted TCP SYN completes
//!   a connection and an accepted UDP datagram is echoed back. A rejection
//!   arrives as an error (TCP reset or ICMP), or at least raises the client
//!   namespace's ICMP "destination unreachable" counter (see `run_client`);
//!   a drop is silence.
//! - The ruleset is applied again before every probe: that resets rate and
//!   connection limits, so the first-packet verdict applies.
//! - Neighbor entries are static, so no ARP/NDP passes the firewall.

use std::fmt::Write as _;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use drfw::core::evaluate::{
    InputChain, IpFamily, Probe, ProbeSource, Reachability, Transport, Verdict,
};
use drfw::core::firewall::{
    Action, Chain, EgressProfile, FirewallRuleset, PortEntry, Protocol, RateLimit, RejectType,
    Rule, TimeUnit,
};
use ipnetwork::IpNetwork;
use proptest::prelude::*;

// ============================================================================
// Topology
// ============================================================================

/// Firewalled interface (server side of the veth pair).
const SERVER_IFACE: &str = "v0";
/// Client side of the veth pair.
const CLIENT_IFACE: &str = "v1";
const SERVER_V4: [&str; 2] = ["10.9.0.1", "10.9.1.1"];
const SERVER_V6: [&str; 2] = ["fd09::1", "fd09::1:1"];
const CLIENT_V4: [&str; 3] = ["10.9.0.2", "10.9.0.3", "10.9.2.5"];
const CLIENT_V6: [&str; 3] = ["fd09::2", "fd09::3", "fd09::2:5"];
/// Ports the probes use (overlapping the rule port pool below)
const PROBE_PORTS: [u16; 5] = [22, 80, 1500, 5353, 9999];
/// How long a probe waits for an answer before it counts as dropped (unless
/// an ICMP error arrived, see `run_client`).
const DROP_TIMEOUT: Duration = Duration::from_millis(300);

const SERVER_ENV: &str = "DRFW_EVALUATE_SERVER_DIR";
const CLIENT_ENV: &str = "DRFW_EVALUATE_CLIENT";
const OUTCOME_PREFIX: &str = "OUTCOME=";

/// One probe sent through the kernel.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct KernelProbe {
    tcp: bool,
    source: IpAddr,
    destination: IpAddr,
    port: u16,
}

impl KernelProbe {
    fn to_probe(&self) -> Probe {
        Probe {
            transport: if self.tcp {
                Transport::Tcp
            } else {
                Transport::Udp
            },
            port: self.port,
            family: IpFamily::of(self.source),
            interface: Some(SERVER_IFACE.to_string()),
            destination: Some(self.destination),
            source: ProbeSource::Addr(self.source),
        }
    }
}

/// The outcome name for an action ("accepted", "dropped", "rejected").
fn outcome_name(action: Action) -> &'static str {
    match action {
        Action::Accept => "accepted",
        Action::Drop => "dropped",
        Action::Reject => "rejected",
    }
}

// ============================================================================
// Availability
// ============================================================================

/// True when the kernel tests can run; prints a skip notice otherwise.
///
/// Panics instead of skipping when `DRFW_REQUIRE_REAL_NFT=1`.
fn kernel_available() -> bool {
    static AVAILABLE: OnceLock<Result<(), String>> = OnceLock::new();
    let status = AVAILABLE.get_or_init(|| {
        for tool in ["ip", "nsenter"] {
            let found = Command::new("sh")
                .args(["-c", &format!("command -v {tool}")])
                .output()
                .is_ok_and(|o| o.status.success());
            if !found {
                return Err(format!("{tool} is not installed"));
            }
        }
        let output = Command::new("unshare")
            .args(["-rn", "nft", "list", "ruleset"])
            .output()
            .map_err(|e| format!("cannot run unshare: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "`unshare -rn nft list ruleset` failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    });
    match status {
        Ok(()) => true,
        Err(reason) => {
            assert!(
                std::env::var("DRFW_REQUIRE_REAL_NFT").as_deref() != Ok("1"),
                "DRFW_REQUIRE_REAL_NFT=1 but the kernel evaluator test cannot run: {reason}"
            );
            eprintln!("SKIPPING kernel evaluator test: {reason}");
            false
        }
    }
}

// ============================================================================
// Helpers run inside the namespaces
// ============================================================================

/// Runs this test binary's helper `name` with `env` set (in `prefix`'s
/// namespace: `unshare -rn` or `nsenter -t <pid> -n`).
fn helper_command(prefix: &[&str], name: &str, env: (&str, &str)) -> Command {
    let exe = std::env::current_exe().expect("test binary path");
    let mut command = Command::new(prefix[0]);
    command
        .args(&prefix[1..])
        .arg(exe)
        .args([name, "--exact", "--nocapture", "--test-threads=1", "-q"])
        .env(env.0, env.1);
    command
}

/// Kills the client namespace's placeholder process when dropped.
struct ClientNamespace(Child);

impl Drop for ClientNamespace {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run_ok(command: &mut Command, what: &str) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|e| format!("{what}: cannot run: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{what} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Builds the two-namespace topology; returns the client namespace.
fn setup_topology() -> Result<ClientNamespace, String> {
    let child = Command::new("unshare")
        .args(["-n", "sleep", "120"])
        .spawn()
        .map_err(|e| format!("cannot start the client namespace: {e}"))?;
    let client = ClientNamespace(child);
    let pid = client.0.id();
    let own = std::fs::read_link("/proc/self/ns/net").map_err(|e| e.to_string())?;
    let mut ready = false;
    for _ in 0..200 {
        if std::fs::read_link(format!("/proc/{pid}/ns/net")).is_ok_and(|ns| ns != own) {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !ready {
        return Err("client namespace not ready".into());
    }

    let mut script = format!(
        "set -eu\n\
         ip link set lo up\n\
         ip link add {SERVER_IFACE} type veth peer name {CLIENT_IFACE} netns {pid}\n\
         ip link set {SERVER_IFACE} up\n\
         c() {{ nsenter -t {pid} -n \"$@\"; }}\n\
         c ip link set lo up\n\
         c ip link set {CLIENT_IFACE} up\n\
         # The kernel rate-limits ICMP errors; rejections must all arrive\n\
         echo 0 > /proc/sys/net/ipv4/icmp_ratelimit || true\n\
         echo 0 > /proc/sys/net/ipv6/icmp/ratelimit || true\n\
         # (not /sys/class/net: sysfs shows the namespace it was mounted in)\n\
         smac=$(ip -br link show dev {SERVER_IFACE} | awk '{{print $3}}')\n\
         cmac=$(c ip -br link show dev {CLIENT_IFACE} | awk '{{print $3}}')\n"
    );
    for addr in SERVER_V4 {
        let _ = writeln!(script, "ip addr add {addr}/16 dev {SERVER_IFACE}");
    }
    for addr in SERVER_V6 {
        let _ = writeln!(script, "ip addr add {addr}/64 dev {SERVER_IFACE} nodad");
    }
    for addr in CLIENT_V4 {
        let _ = writeln!(script, "c ip addr add {addr}/16 dev {CLIENT_IFACE}");
    }
    for addr in CLIENT_V6 {
        let _ = writeln!(script, "c ip addr add {addr}/64 dev {CLIENT_IFACE} nodad");
    }
    // Static neighbors: no ARP/NDP has to pass the firewall
    for addr in CLIENT_V4.iter().chain(&CLIENT_V6) {
        let _ = writeln!(
            script,
            "ip neigh replace {addr} lladdr \"$cmac\" dev {SERVER_IFACE} nud permanent"
        );
    }
    for addr in SERVER_V4.iter().chain(&SERVER_V6) {
        let _ = writeln!(
            script,
            "c ip neigh replace {addr} lladdr \"$smac\" dev {CLIENT_IFACE} nud permanent"
        );
    }
    run_ok(Command::new("sh").args(["-c", &script]), "topology setup")?;
    Ok(client)
}

/// Sends one probe from the client namespace; returns the outcome name.
fn probe_from_client(client_pid: u32, probe: &KernelProbe) -> Result<String, String> {
    // Bound to the probed address: an accepted datagram's echo must come
    // from it (a wildcard socket would answer from the primary address)
    let bind = SocketAddr::new(probe.destination, probe.port);
    // Keep the listener open until the client is done
    let _tcp;
    let mut udp_echo = None;
    if probe.tcp {
        _tcp = TcpListener::bind(bind).map_err(|e| format!("listen {bind}: {e}"))?;
    } else {
        let socket = UdpSocket::bind(bind).map_err(|e| format!("bind {bind}: {e}"))?;
        socket
            .set_read_timeout(Some(DROP_TIMEOUT * 4))
            .map_err(|e| e.to_string())?;
        udp_echo = Some(std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            if let Ok((len, from)) = socket.recv_from(&mut buf) {
                let _ = socket.send_to(&buf[..len], from);
            }
        }));
    }

    let spec = format!(
        "{},{},{},{}",
        if probe.tcp { "tcp" } else { "udp" },
        probe.source,
        probe.destination,
        probe.port
    );
    let pid = client_pid.to_string();
    let output = helper_command(
        &["nsenter", "-t", &pid, "-n"],
        "helper_kernel_client",
        (CLIENT_ENV, &spec),
    )
    .output()
    .map_err(|e| format!("cannot run the client: {e}"))?;
    if let Some(handle) = udp_echo {
        let _ = handle.join();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(OUTCOME_PREFIX))
        .map(str::to_string)
        .ok_or_else(|| {
            format!(
                "client printed no outcome:\n{stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
}

/// The server side, inside `unshare -rn`: topology, then for every probe a
/// fresh apply and one client run. Returns the outcomes.
fn run_server(dir: &Path) -> Result<Vec<String>, String> {
    let probes: Vec<KernelProbe> = serde_json::from_str(
        &std::fs::read_to_string(dir.join("probes.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let client = setup_topology()?;
    let rules = dir.join("rules.json");
    let mut outcomes = Vec::with_capacity(probes.len());
    for probe in &probes {
        run_ok(
            Command::new("nft").arg("-j").arg("-f").arg(&rules),
            "nft -j -f",
        )?;
        outcomes.push(probe_from_client(client.0.id(), probe)?);
    }
    Ok(outcomes)
}

/// Server helper (see the module docs); a no-op without its environment.
#[test]
fn helper_kernel_server() {
    let Ok(dir) = std::env::var(SERVER_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let result = run_server(&dir);
    std::fs::write(
        dir.join("results.json"),
        serde_json::to_string(&result).expect("serialize results"),
    )
    .expect("write results");
}

/// ICMP "destination unreachable" messages this namespace has received
/// (`/proc/net` is the reading process's network namespace).
fn dest_unreachables(v6: bool) -> Result<u64, String> {
    if v6 {
        let snmp6 = std::fs::read_to_string("/proc/net/snmp6").map_err(|e| e.to_string())?;
        return snmp6
            .lines()
            .find_map(|line| line.strip_prefix("Icmp6InDestUnreachs"))
            .and_then(|value| value.trim().parse().ok())
            .ok_or_else(|| "no Icmp6InDestUnreachs".to_string());
    }
    let snmp = std::fs::read_to_string("/proc/net/snmp").map_err(|e| e.to_string())?;
    let mut icmp = snmp.lines().filter(|line| line.starts_with("Icmp:"));
    let (Some(names), Some(values)) = (icmp.next(), icmp.next()) else {
        return Err("no Icmp lines".into());
    };
    let index = names
        .split_whitespace()
        .position(|name| name == "InDestUnreachs")
        .ok_or("no InDestUnreachs")?;
    values
        .split_whitespace()
        .nth(index)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "bad InDestUnreachs".to_string())
}

/// The client side, inside the client namespace: one connection attempt.
///
/// Accepted: the TCP connection completes / the UDP echo arrives. Rejected:
/// a TCP reset or ICMP error is reported to the socket, or (when it is not:
/// ICMP host-unreachable is a "soft" error for UDP, and an ICMP error that
/// arrives while `connect()` still holds the socket lock only becomes a soft
/// error for TCP) the namespace's ICMP destination-unreachable counter went
/// up. Dropped: nothing within [`DROP_TIMEOUT`].
fn run_client(spec: &str) -> Result<&'static str, String> {
    let parts: Vec<&str> = spec.split(',').collect();
    let [kind, source, destination, port] = parts.as_slice() else {
        return Err(format!("bad probe spec {spec}"));
    };
    let source: IpAddr = source.parse().map_err(|e| format!("{e}"))?;
    let destination: IpAddr = destination.parse().map_err(|e| format!("{e}"))?;
    let port: u16 = port.parse().map_err(|e| format!("{e}"))?;
    let target = SocketAddr::new(destination, port);
    let v6 = destination.is_ipv6();

    if *kind == "tcp" {
        // std cannot bind a TCP client socket: choose the source by route
        let (flag, len) = if v6 { ("-6", 128) } else { ("-4", 32) };
        run_ok(
            Command::new("ip").args([
                flag,
                "route",
                "replace",
                &format!("{destination}/{len}"),
                "dev",
                CLIENT_IFACE,
                "src",
                &source.to_string(),
            ]),
            "ip route replace",
        )?;
        let unreachables_before = dest_unreachables(v6)?;
        return match TcpStream::connect_timeout(&target, DROP_TIMEOUT) {
            Ok(stream) => {
                let local = stream.local_addr().map_err(|e| e.to_string())?;
                if local.ip() != source {
                    return Err(format!("connected from {local}, not {source}"));
                }
                Ok("accepted")
            }
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                silent_outcome(v6, unreachables_before)
            }
            Err(_) => Ok("rejected"),
        };
    }

    let socket =
        UdpSocket::bind(SocketAddr::new(source, 0)).map_err(|e| format!("bind {source}: {e}"))?;
    socket.connect(target).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(DROP_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let unreachables_before = dest_unreachables(v6)?;
    socket.send(b"probe").map_err(|e| e.to_string())?;
    let mut buf = [0u8; 16];
    match socket.recv(&mut buf) {
        Ok(_) => Ok("accepted"),
        Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            silent_outcome(v6, unreachables_before)
        }
        Err(_) => Ok("rejected"),
    }
}

/// No answer: rejected if an ICMP error arrived anyway, else dropped.
fn silent_outcome(v6: bool, unreachables_before: u64) -> Result<&'static str, String> {
    Ok(if dest_unreachables(v6)? > unreachables_before {
        "rejected"
    } else {
        "dropped"
    })
}

/// Client helper (see the module docs); a no-op without its environment.
#[test]
fn helper_kernel_client() {
    let Ok(spec) = std::env::var(CLIENT_ENV) else {
        return;
    };
    let outcome = run_client(&spec).unwrap_or_else(|e| {
        eprintln!("client error: {e}");
        "error"
    });
    println!("{OUTCOME_PREFIX}{outcome}");
}

/// Applies `ruleset` in a fresh namespace pair and sends `probes`; returns
/// the kernel's outcome per probe.
fn kernel_outcomes(ruleset: &FirewallRuleset, probes: &[KernelProbe]) -> Vec<String> {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::fs::write(
        dir.path().join("rules.json"),
        serde_json::to_string(&ruleset.to_nftables_json()).expect("serialize ruleset"),
    )
    .expect("write rules.json");
    std::fs::write(
        dir.path().join("probes.json"),
        serde_json::to_string(probes).expect("serialize probes"),
    )
    .expect("write probes.json");
    let dir_str = dir.path().to_str().expect("UTF-8 temp path");
    let output = helper_command(
        &["unshare", "-rn"],
        "helper_kernel_server",
        (SERVER_ENV, dir_str),
    )
    .output()
    .expect("run the server helper");
    let results = std::fs::read_to_string(dir.path().join("results.json")).unwrap_or_else(|e| {
        panic!(
            "server helper wrote no results ({e}):\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let results: Result<Vec<String>, String> =
        serde_json::from_str(&results).expect("parse results");
    results.unwrap_or_else(|e| {
        panic!(
            "kernel run failed: {e}\nruleset:\n{}",
            ruleset.to_nft_text()
        )
    })
}

/// Probes the kernel and the evaluator agreed on: accepted, dropped, rejected.
static AGREED: [AtomicUsize; 3] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];

/// "agreed so far: N accepted, N dropped, N rejected"
fn agreement_tally() -> String {
    let [a, d, r] = AGREED.each_ref().map(|n| n.load(Ordering::Relaxed));
    format!("agreed with the kernel so far: {a} accepted, {d} dropped, {r} rejected")
}

/// Checks every probe's kernel outcome against the evaluator.
fn assert_agrees(ruleset: &FirewallRuleset, probes: &[KernelProbe]) -> Result<(), String> {
    let outcomes = kernel_outcomes(ruleset, probes);
    let chain = InputChain::new(ruleset);
    for (probe, outcome) in probes.iter().zip(&outcomes) {
        let verdict = chain.evaluate(&probe.to_probe());
        let (action, _) = verdict
            .first_packet()
            .ok_or_else(|| format!("unsettled verdict {verdict}"))?;
        if outcome_name(action) != outcome {
            return Err(format!(
                "kernel {outcome}, evaluator {verdict}\nprobe: {probe:?}\nruleset:\n{}",
                ruleset.to_nft_text()
            ));
        }
        let index = match action {
            Action::Accept => 0,
            Action::Drop => 1,
            Action::Reject => 2,
        };
        AGREED[index].fetch_add(1, Ordering::Relaxed);
    }
    eprintln!("{}", agreement_tally());
    Ok(())
}

// ============================================================================
// Rule generation
// ============================================================================

fn nets(list: &[&str]) -> Vec<IpNetwork> {
    list.iter()
        .map(|s| s.parse().expect("valid test network"))
        .collect()
}

fn user_rule(label: &str, protocol: Protocol, ports: Vec<PortEntry>) -> Rule {
    Rule::with_caches(
        uuid::Uuid::new_v4(),
        label.to_string(),
        protocol,
        ports,
        Vec::new(),
        None,
        Chain::Input,
        true,
        jiff::Timestamp::now(),
        Vec::new(),
    )
}

const SOURCE_POOL: [&str; 12] = [
    "10.9.0.2/32",
    "10.9.0.0/24",
    "10.9.2.0/24",
    "10.0.0.0/8",
    "192.168.0.0/16",
    "0.0.0.0/0",
    "fd09::2/128",
    "fd09::/112",
    "fd09::2:0/112",
    "fd00::/8",
    "2001:db8::/32",
    "::/0",
];
const DESTINATION_POOL: [&str; 7] = [
    "10.9.0.1/32",
    "10.9.1.1/32",
    "10.9.0.0/16",
    "fd09::1/128",
    "fd09::1:1/128",
    "fd09::/64",
    "172.16.0.0/12",
];

fn arb_network(pool: &'static [&'static str]) -> impl Strategy<Value = IpNetwork> {
    proptest::sample::select(pool).prop_map(|s| s.parse().expect("valid pool network"))
}

fn arb_ports() -> impl Strategy<Value = Vec<PortEntry>> {
    prop::collection::vec(
        prop_oneof![
            Just(PortEntry::Single(22)),
            Just(PortEntry::Single(80)),
            Just(PortEntry::Single(5353)),
            Just(PortEntry::range(1000, 2000)),
            Just(PortEntry::range(9000, 9999)),
        ],
        0..2,
    )
}

fn arb_protocol() -> impl Strategy<Value = Protocol> {
    prop_oneof![
        3 => Just(Protocol::Tcp),
        3 => Just(Protocol::Udp),
        2 => Just(Protocol::Any),
        2 => Just(Protocol::TcpAndUdp),
        1 => prop_oneof![Just(Protocol::Icmp), Just(Protocol::Icmpv6), Just(Protocol::IcmpBoth)],
    ]
}

fn arb_interface() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        6 => Just(None),
        1 => Just(Some(SERVER_IFACE.to_string())),
        1 => Just(Some("v*".to_string())),
        1 => Just(Some("eth0".to_string())),
        1 => Just(Some("v0x".to_string())),
        1 => Just(Some("w*".to_string())),
    ]
}

prop_compose! {
    fn arb_rule()(
        protocol in arb_protocol(),
        ports in arb_ports(),
        // Mostly unrestricted, so that rules often match the probes
        sources in prop_oneof![
            2 => Just(Vec::new()),
            1 => prop::collection::vec(arb_network(&SOURCE_POOL), 1..3),
        ],
        destinations in prop_oneof![
            3 => Just(Vec::new()),
            1 => prop::collection::vec(arb_network(&DESTINATION_POOL), 1..2),
        ],
        interface in arb_interface(),
        enabled in prop::bool::weighted(0.9),
        output_chain in prop::bool::weighted(0.1),
        action in prop_oneof![2 => Just(Action::Accept), 2 => Just(Action::Drop), 1 => Just(Action::Reject)],
        reject_type in prop_oneof![
            Just(RejectType::Default),
            Just(RejectType::PortUnreachable),
            Just(RejectType::HostUnreachable),
            Just(RejectType::AdminProhibited),
            Just(RejectType::TcpReset),
        ],
        rate in proptest::option::weighted(0.25, (1u32..20, 0usize..4, proptest::option::of(1u32..6), any::<bool>())),
        connection_limit in prop_oneof![3 => Just(0u32), 1 => 1u32..5],
        connection_per_source in any::<bool>(),
        log_enabled in prop::bool::weighted(0.2),
    ) -> Rule {
        // ICMP rules cannot have ports (the validator refuses them)
        let ports = if matches!(protocol, Protocol::Icmp | Protocol::Icmpv6 | Protocol::IcmpBoth) {
            Vec::new()
        } else {
            ports
        };
        let mut r = user_rule("r", protocol, ports);
        // ICMP (v4) cannot have IPv6 addresses and vice versa
        let keep = |n: &IpNetwork| match protocol {
            Protocol::Icmp => n.is_ipv4(),
            Protocol::Icmpv6 => n.is_ipv6(),
            _ => true,
        };
        r.sources = sources.into_iter().filter(keep).collect();
        r.destinations = destinations.into_iter().filter(keep).collect();
        r.enabled = enabled;
        if output_chain {
            r.chain = Chain::Output;
        } else {
            r.interface = interface;
        }
        r.action = action;
        r.reject_type = if reject_type == RejectType::TcpReset && protocol != Protocol::Tcp {
            RejectType::Default
        } else {
            reject_type
        };
        r.rate_limit = rate.map(|(count, unit, burst, per_source)| RateLimit {
            count,
            unit: [TimeUnit::Second, TimeUnit::Minute, TimeUnit::Hour, TimeUnit::Day][unit],
            burst,
            per_source,
        });
        r.connection_limit = connection_limit;
        r.connection_limit_per_source = connection_limit > 0 && connection_per_source;
        r.log_enabled = log_enabled;
        r.rebuild_caches();
        r
    }
}

prop_compose! {
    fn arb_ruleset()(
        rules in prop::collection::vec(arb_rule(), 0..9),
        settings in any::<[bool; 4]>(),
    ) -> FirewallRuleset {
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules = rules;
        let adv = &mut ruleset.advanced_security;
        adv.enable_rpf = settings[0];
        adv.egress_profile = if settings[1] { EgressProfile::Server } else { EgressProfile::Desktop };
        adv.strict_icmp = settings[2];
        adv.log_dropped = settings[3];
        ruleset
    }
}

prop_compose! {
    fn arb_kernel_probe()(
        tcp in any::<bool>(),
        v6 in any::<bool>(),
        source in 0usize..3,
        destination in 0usize..2,
        port in proptest::sample::select(&PROBE_PORTS[..]),
    ) -> KernelProbe {
        let (sources, destinations) = if v6 {
            (&CLIENT_V6[..], &SERVER_V6[..])
        } else {
            (&CLIENT_V4[..], &SERVER_V4[..])
        };
        KernelProbe {
            tcp,
            source: sources[source].parse().expect("valid address"),
            destination: destinations[destination].parse().expect("valid address"),
            port,
        }
    }
}

// ============================================================================
// Self-consistency (no kernel)
// ============================================================================

/// The verdict at the end of the `Limited` chain, and whether some layer on
/// the way accepts under a condition.
fn unconditional_end(verdict: &Verdict) -> (&Verdict, bool) {
    let mut current = verdict;
    let mut conditional_accept = false;
    while let Verdict::Limited {
        action, otherwise, ..
    } = current
    {
        conditional_accept |= *action == Action::Accept;
        current = otherwise;
    }
    (current, conditional_accept)
}

fn arb_any_source() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        proptest::sample::select(&CLIENT_V4[..]).prop_map(|s| s.parse().expect("valid")),
        proptest::sample::select(&CLIENT_V6[..]).prop_map(|s| s.parse().expect("valid")),
        any::<[u8; 4]>().prop_map(IpAddr::from),
        any::<[u8; 16]>().prop_map(IpAddr::from),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// For one source, the "who can connect" set and the per-source verdict
    /// agree exactly: the source is in `open` iff its verdict ends in an
    /// unconditional accept, and in a conditional set iff it is only
    /// accepted under a condition.
    #[test]
    fn prop_reachability_matches_per_source_verdicts(
        ruleset in arb_ruleset(),
        source in arb_any_source(),
        tcp in any::<bool>(),
        port in proptest::sample::select(&[22u16, 80, 443, 546, 1500, 5353, 9999][..]),
        interface in prop_oneof![Just("v0"), Just("eth0"), Just("wg0")],
        destination in proptest::sample::select(&SERVER_V4[..]),
        destination6 in proptest::sample::select(&SERVER_V6[..]),
    ) {
        let chain = InputChain::new(&ruleset);
        let family = IpFamily::of(source);
        let destination: IpAddr = if family == IpFamily::V6 { destination6 } else { destination }
            .parse()
            .expect("valid");
        let mut probe = Probe {
            transport: if tcp { Transport::Tcp } else { Transport::Udp },
            port,
            family,
            interface: Some(interface.to_string()),
            destination: Some(destination),
            source: ProbeSource::Addr(source),
        };
        let verdict = chain.evaluate(&probe);
        probe.source = ProbeSource::Unknown;
        let Verdict::Reachable(reach) = chain.evaluate(&probe) else {
            panic!("expected a reachability set");
        };
        let (end, conditional_accept) = unconditional_end(&verdict);
        let accepted = matches!(end, Verdict::Accepted(_));
        prop_assert_eq!(reach.open.contains(source), accepted, "verdict {} vs {}", verdict, reach);
        let in_conditional = reach.conditional.iter().any(|c| c.sources.contains(source));
        prop_assert_eq!(
            in_conditional,
            conditional_accept && !accepted,
            "verdict {} vs {}", verdict, reach
        );
        check_reachability_invariants(&reach)?;
    }
}

fn check_reachability_invariants(reach: &Reachability) -> Result<(), TestCaseError> {
    prop_assert_eq!(reach.exact, reach.caveats.is_empty());
    prop_assert!(reach.nobody() || reach.deciding().is_some());
    Ok(())
}

// ============================================================================
// Agreement with the kernel
// ============================================================================

proptest! {
    // Each case builds a namespace pair and runs a few probes
    #![proptest_config(ProptestConfig {
        cases: 24,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn prop_evaluator_agrees_with_kernel(
        ruleset in arb_ruleset(),
        probes in prop::collection::vec(arb_kernel_probe(), 3),
    ) {
        if !kernel_available() {
            return Ok(());
        }
        // Only what DRFW would apply (and nft accepts)
        prop_assume!(ruleset.validate_for_apply().is_ok());
        if let Err(message) = assert_agrees(&ruleset, &probes) {
            prop_assert!(false, "{}", message);
        }
    }
}

/// Hand-picked cases covering each kind of verdict at least once.
#[test]
fn test_evaluator_agrees_with_kernel_on_directed_cases() {
    if !kernel_available() {
        return;
    }
    let probe = |tcp: bool, source: &str, destination: &str, port: u16| KernelProbe {
        tcp,
        source: source.parse().expect("valid"),
        destination: destination.parse().expect("valid"),
        port,
    };

    // Accept / drop / reject (TCP reset and ICMP), sources and destinations
    let mut ruleset = FirewallRuleset::new();
    let mut drop = user_rule("drop one host", Protocol::Tcp, vec![PortEntry::Single(22)]);
    drop.sources = nets(&["10.9.0.3/32"]);
    drop.action = Action::Drop;
    let mut reset = user_rule("reset", Protocol::Tcp, vec![PortEntry::Single(22)]);
    reset.sources = nets(&["fd09::3/128"]);
    reset.action = Action::Reject;
    reset.reject_type = RejectType::TcpReset;
    let mut ssh = user_rule("ssh", Protocol::Tcp, vec![PortEntry::Single(22)]);
    ssh.sources = nets(&["10.9.0.0/16", "fd09::/64"]);
    let mut dns = user_rule("dns", Protocol::Udp, vec![PortEntry::Single(5353)]);
    dns.destinations = nets(&["10.9.1.1/32"]);
    let mut udp_reject = user_rule("udp reject", Protocol::Udp, vec![PortEntry::Single(80)]);
    udp_reject.action = Action::Reject;
    let mut iface = user_rule(
        "on v*",
        Protocol::TcpAndUdp,
        vec![PortEntry::range(1000, 2000)],
    );
    iface.interface = Some("v*".to_string());
    let mut other_iface = user_rule("on eth0", Protocol::Any, vec![]);
    other_iface.interface = Some("eth0".to_string());
    ruleset.rules = vec![drop, reset, ssh, dns, udp_reject, iface, other_iface];
    let probes = [
        probe(true, "10.9.0.2", "10.9.0.1", 22),    // accepted (ssh)
        probe(true, "10.9.0.3", "10.9.0.1", 22),    // dropped
        probe(true, "fd09::3", "fd09::1", 22),      // rejected (reset)
        probe(true, "fd09::2", "fd09::1:1", 22),    // accepted (ssh)
        probe(false, "10.9.0.2", "10.9.1.1", 5353), // accepted (destination)
        probe(false, "10.9.0.2", "10.9.0.1", 5353), // rejected (final reject)
        probe(false, "fd09::2", "fd09::1", 80),     // rejected (udp reject)
        probe(true, "10.9.2.5", "10.9.0.1", 1500),  // accepted (v*)
        probe(false, "fd09::2:5", "fd09::1", 1999), // accepted (v*)
        probe(true, "10.9.0.2", "10.9.0.1", 9999),  // rejected (eth0 rule skipped)
        probe(false, "10.9.0.2", "10.9.0.1", 22),   // rejected (final reject)
        probe(true, "fd09::3", "fd09::1:1", 23),    // rejected (final reject)
    ];
    assert_agrees(&ruleset, &probes).unwrap_or_else(|e| panic!("{e}"));

    // Limits (first packet within), Server Mode, RPF, an over-limit drop
    let mut ruleset = FirewallRuleset::new();
    ruleset.advanced_security.egress_profile = EgressProfile::Server;
    ruleset.advanced_security.enable_rpf = true;
    let mut flood = user_rule("flood", Protocol::Tcp, vec![PortEntry::Single(80)]);
    flood.action = Action::Drop;
    flood.rate_limit = Some(RateLimit {
        count: 1,
        unit: TimeUnit::Minute,
        burst: None,
        per_source: false,
    });
    let mut web = user_rule("web", Protocol::Tcp, vec![PortEntry::Single(80)]);
    web.rate_limit = Some(RateLimit {
        count: 2,
        unit: TimeUnit::Minute,
        burst: Some(2),
        per_source: true,
    });
    web.connection_limit = 1;
    web.connection_limit_per_source = true;
    let mut mdns = user_rule("mdns", Protocol::Udp, vec![PortEntry::Single(5353)]);
    mdns.connection_limit = 2;
    ruleset.rules = vec![flood, web, mdns];
    let probes = [
        probe(true, "10.9.0.2", "10.9.0.1", 80),
        probe(true, "fd09::2", "fd09::1", 80),
        probe(false, "fd09::3", "fd09::1", 5353),
        probe(true, "10.9.0.3", "10.9.0.1", 22),
    ];
    assert_agrees(&ruleset, &probes).unwrap_or_else(|e| panic!("{e}"));
}
