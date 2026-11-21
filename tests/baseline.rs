//! Behaviour of DRFW's base rules in the kernel, in private namespaces
//!
//! Each test builds a small lab inside `unshare -rn` (no root, the host
//! firewall is never touched): this test's namespace is "the host" running
//! a generated ruleset, joined by a veth pair to a peer namespace (and, for
//! forwarding, a second one). The tests are ports of the namespace
//! experiments of the baseline design review:
//!
//! - ICMP redirects quoting a live flow are dropped (the drop comes before
//!   the established/related accept); path MTU discovery still works
//! - IGMP membership reports and queries pass, in and (Server Mode) out
//! - DHCP client replies from port 67 are accepted, also as broadcast
//! - local network discovery: mDNS/SSDP multicast and unicast replies to
//!   our own SSDP/WS-Discovery/mDNS/LLMNR/NetBIOS queries, but only from
//!   private sources and only to ports that sent such a query (other
//!   broadcast or multicast opens nothing)
//! - anti-spoofing (RPF) drops a spoofed container-subnet source, yet a
//!   full-tunnel VPN's underlay (fwmark policy routing) keeps working
//! - the ICMP rate limit limits a ping flood (not only new pings)
//! - loopback destinations arriving from the network are dropped
//!   (`route_localnet=1`)
//! - Forward rules with "Block forwarding": only the allowed port is routed
//!
//! # How a verdict is observed
//!
//! A second table (`inet obs`) has an input chain at priority 10, after
//! DRFW's chains (priority -10): a packet DRFW accepts goes on to it and
//! increments the counter of a matching rule there, a packet DRFW drops or
//! rejects never does. Its postrouting chain counts what leaves the host.
//! Datagrams with a chosen source port, to broadcast or multicast, come
//! from this test binary itself ([`helper_udp_send`], a no-op without its
//! environment variable), since shell tools cannot set those. TCP connects
//! use bash `/dev/tcp`: nothing listens, so an accepted SYN is answered by a
//! reset ("refused") while a dropped one times out.
//!
//! Without `unshare`, `nft`, `ip`, `nsenter`, `bash`, `ping` or `timeout` the
//! tests print a skip notice and pass, unless `DRFW_REQUIRE_REAL_NFT=1`.

mod common;

use std::fmt::Write as _;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::path::Path;

use drfw::core::firewall::{
    Action, Chain, EgressProfile, FirewallRuleset, PortEntry, Protocol, Rule,
};
use ipnetwork::IpNetwork;

use crate::common::rule;

/// Environment variable of [`helper_udp_send`]: `BIND DEST [broadcast]`.
const UDP_SEND_ENV: &str = "DRFW_BASELINE_UDP_SEND";

/// Shell prelude of every lab: helpers, the two-namespace topology, the
/// observer table.
///
/// - `mkns VAR`: a new network namespace, its holder pid in `VAR`
/// - `P cmd…`: run a program in the peer namespace
/// - `load NAME`: apply `NAME.json` (a generated ruleset)
/// - `watch NAME match…` / `watch_out NAME match…`: count accepted input /
///   leaving packets matching `match…` under `NAME`; `count NAME` prints it
/// - `udp BIND DEST [broadcast]` / `pudp …`: send one datagram from the host
///   / the peer (`[v6%ifindex]:port` for a scoped address)
/// - `attempt PID DEST PORT LABEL`: TCP connect from a namespace, prints
///   `LABEL passed` (reset: the SYN was accepted) or `LABEL blocked`
const PRELUDE: &str = r#"
set -eu
PIDS=""
trap 'for p in $PIDS; do kill $p 2>/dev/null; done' EXIT
mkns() {
    unshare -n sleep 120 &
    local pid=$!
    PIDS="$PIDS $pid"
    local i=0
    while [ "$(readlink /proc/$pid/ns/net)" = "$(readlink /proc/self/ns/net)" ]; do
        i=$((i + 1)); [ $i -lt 200 ] || { echo "namespace not ready" >&2; exit 1; }
        sleep 0.02
    done
    nsenter -t "$pid" -n ip link set lo up
    eval "$1=$pid"
}
P() { nsenter -t "$peer" -n "$@"; }
load() { nft -j -f "$1.json"; }
watch() { local name=$1; shift; nft add rule inet obs in "$@" counter comment "\"$name\""; }
watch_out() { local name=$1; shift; nft add rule inet obs post "$@" counter comment "\"$name\""; }
count() { nft list table inet obs | sed -nE "s/.* packets ([0-9]+) bytes [0-9]+ comment \"$1\"\$/\1/p"; }
udp() { env DRFW_BASELINE_UDP_SEND="$*" "$EXE" --exact helper_udp_send --quiet >/dev/null; }
pudp() { P env DRFW_BASELINE_UDP_SEND="$*" "$EXE" --exact helper_udp_send --quiet >/dev/null; }
ifindex() { "${@:2}" ip -o link show dev "$1" | cut -d: -f1; }
attempt() {
    local out
    if out=$(nsenter -t "$1" -n timeout 1.5 bash -c "exec 3<>/dev/tcp/$2/$3" 2>&1); then
        echo "$4 connected"
    else
        case $out in
            *refused*) echo "$4 passed" ;;
            *) echo "$4 blocked" ;;
        esac
    fi
}

ip link set lo up
mkns peer
ip link add v0 type veth peer name v1 netns "$peer"
ip addr add 10.9.0.1/24 dev v0
ip -6 addr add fd09::1/64 dev v0 nodad
ip link set v0 up
P ip addr add 10.9.0.2/24 dev v1
P ip -6 addr add fd09::2/64 dev v1 nodad
P ip link set v1 up
# Spoofed sources must reach DRFW's rules, not the kernel's own check
for conf in all v0; do echo 0 > /proc/sys/net/ipv4/conf/$conf/rp_filter; done
nft -f - <<'OBS'
table inet obs {
    chain in {
        type filter hook input priority 10; policy accept;
    }
    chain post {
        type filter hook postrouting priority 10; policy accept;
    }
}
OBS
"#;

/// True when the labs can run here; prints a skip notice otherwise.
fn lab_available() -> bool {
    if !common::real_nft_available() {
        return false;
    }
    let missing =
        common::missing_tools(&["bash", "ip", "nsenter", "ping", "timeout", "sed", "cut"]);
    missing.is_empty() || common::skip("baseline lab", &format!("missing {missing:?}"))
}

/// Writes the rulesets as `<name>.json`, runs `PRELUDE` + `script` with bash
/// in a fresh user + network namespace, and returns its stdout lines.
///
/// # Panics
///
/// If the script fails (with its output in the message).
fn lab(rulesets: &[(&str, &FirewallRuleset)], script: &str) -> Vec<String> {
    let dir = tempfile::tempdir().expect("create temp dir");
    for (name, ruleset) in rulesets {
        write_json(dir.path(), name, ruleset);
    }
    let exe = std::env::current_exe().expect("test binary path");
    let output = common::unshare()
        .args(["-rn", "bash", "-c", &format!("{PRELUDE}\n{script}")])
        .env("EXE", exe)
        .current_dir(dir.path())
        .output()
        .expect("failed to spawn unshare");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "lab script failed:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout.lines().map(str::to_string).collect()
}

fn write_json(dir: &Path, name: &str, ruleset: &FirewallRuleset) {
    std::fs::write(
        dir.join(format!("{name}.json")),
        serde_json::to_string(&ruleset.to_nftables_json()).expect("serialize ruleset"),
    )
    .expect("write ruleset");
}

/// The value after `key ` on the line starting with `key ` (a number the
/// script printed).
fn value(lines: &[String], key: &str) -> u64 {
    let prefix = format!("{key} ");
    lines
        .iter()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| panic!("no number for {key:?} in {lines:#?}"))
}

/// The words after `key ` on the line starting with `key `.
fn text<'a>(lines: &'a [String], key: &str) -> &'a str {
    let prefix = format!("{key} ");
    lines
        .iter()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no line for {key:?} in {lines:#?}"))
}

fn nets(list: &[&str]) -> Vec<IpNetwork> {
    list.iter()
        .map(|s| s.parse().expect("valid test network"))
        .collect()
}

fn with_rules(rules: Vec<Rule>) -> FirewallRuleset {
    let mut ruleset = FirewallRuleset::new();
    ruleset.rules = rules;
    ruleset
}

/// Parses `ip:port`, `[v6]:port` or `[v6%scope]:port`.
fn parse_socket_addr(s: &str) -> SocketAddr {
    if let Some(rest) = s.strip_prefix('[')
        && let Some((inner, port)) = rest.split_once("]:")
        && let Some((addr, scope)) = inner.split_once('%')
    {
        let addr: Ipv6Addr = addr.parse().expect("IPv6 address");
        let port = port.parse().expect("port");
        let scope = scope.parse().expect("numeric scope id");
        return SocketAddr::V6(SocketAddrV6::new(addr, port, 0, scope));
    }
    s.parse()
        .unwrap_or_else(|e| panic!("bad socket address {s:?}: {e}"))
}

/// Sends one datagram (`BIND DEST [broadcast]` in [`UDP_SEND_ENV`]) and
/// exits; a no-op in a normal test run (see the module docs).
#[test]
fn helper_udp_send() {
    let Ok(spec) = std::env::var(UDP_SEND_ENV) else {
        return;
    };
    let words: Vec<&str> = spec.split_whitespace().collect();
    let [bind, dest, rest @ ..] = words.as_slice() else {
        panic!("bad {UDP_SEND_ENV}: {spec:?}");
    };
    let socket = UdpSocket::bind(parse_socket_addr(bind)).expect("bind");
    if rest.contains(&"broadcast") {
        socket.set_broadcast(true).expect("SO_BROADCAST");
    }
    let dest = parse_socket_addr(dest);
    if let SocketAddr::V4(v4) = dest
        && v4.ip().is_multicast()
    {
        socket.set_multicast_ttl_v4(1).expect("multicast TTL");
    }
    socket.send_to(b"drfw", dest).expect("send");
}

// ============================================================================
// M1: ICMP redirects
// ============================================================================

/// A redirect that quotes one of our connections is `related`. The peer is
/// our default gateway and a real router: for traffic it would forward back
/// out the same link it sends a genuine kernel ICMP redirect (to
/// 10.9.0.66). Without a firewall the host follows it; with DRFW (redirect
/// drops before the established/related accept) the route stays. A
/// "fragmentation needed" error for a live flow (the peer forwards over a
/// 1280-byte link) still gets through, also with Strict ICMP.
#[test]
fn test_icmp_redirect_of_a_live_flow_is_dropped() {
    if !lab_available() {
        return;
    }
    let default = FirewallRuleset::new();
    let mut strict = FirewallRuleset::new();
    strict.advanced_security.strict_icmp = true;
    // The redirect sysctls are set explicitly: a new namespace's defaults
    // differ between kernels (some inherit the host's `accept_redirects=0`).
    let script = r#"
P sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
P sh -c 'for i in all v1; do echo 1 > /proc/sys/net/ipv4/conf/$i/send_redirects; done'
sh -c 'for i in all v0; do echo 1 > /proc/sys/net/ipv4/conf/$i/accept_redirects; echo 0 > /proc/sys/net/ipv4/conf/$i/secure_redirects; echo 1 > /proc/sys/net/ipv4/conf/$i/shared_media; done'
echo "sysctl host $(cat /proc/sys/net/ipv4/conf/{all,v0}/{accept,secure}_redirects | tr '\n' ' ')peer $(P cat /proc/sys/net/ipv4/conf/{all,v1}/send_redirects | tr '\n' ' ')"
P ip link add d0 type dummy
P ip link set d0 mtu 1280 up
P ip route add 198.51.100.20/32 dev d0
P ip route add 198.51.100.0/24 via 10.9.0.66 dev v1
ip route add default via 10.9.0.2
# The redirect's new next hop must be a valid neighbour for the host to use it
pmac=$(P ip -br link show dev v1 | awk '{print $3}')
ip neigh replace 10.9.0.66 lladdr "$pmac" dev v0 nud permanent
redirect() { # destination label: a live UDP flow (fd 3 open) while it arrives
    exec 3>/dev/udp/$1/9
    echo a >&3; sleep 0.3; echo a >&3; sleep 0.3
    echo "$2 $(ip route get $1 | grep -o 'via [0-9.]*')"
    exec 3>&-
}
redirect 198.51.100.9 none
load default
redirect 198.51.100.10 drfw
load strict
redirect 198.51.100.11 strict
exec 3>/dev/udp/198.51.100.20/9
head -c 1400 /dev/zero >&3 2>/dev/null || true
sleep 0.3
echo "pmtu $(ip route get 198.51.100.20 | grep -o 'mtu [0-9]*')"
exec 3>&-
"#;
    let lines = lab(&[("default", &default), ("strict", &strict)], script);
    assert_eq!(
        text(&lines, "none"),
        "via 10.9.0.66",
        "control: without a firewall the host follows the redirect ({})",
        text(&lines, "sysctl")
    );
    assert_eq!(text(&lines, "drfw"), "via 10.9.0.2", "redirect dropped");
    assert_eq!(text(&lines, "strict"), "via 10.9.0.2");
    assert_eq!(text(&lines, "pmtu"), "mtu 1280", "path MTU still learned");
}

// ============================================================================
// M2: IGMP
// ============================================================================

/// IGMP passes the input chain (after the user rules: a user Drop rule for
/// the sender stops it), and in Server Mode membership reports leave the
/// host. The peer speaks `IGMPv2`, whose reports go to the group itself (the
/// host is a member, so they reach the input hook).
#[test]
fn test_igmp_passes_in_and_out() {
    if !lab_available() {
        return;
    }
    let default = FirewallRuleset::new();
    let mut drop_peer = rule("Drop peer", Protocol::Any, vec![]);
    drop_peer.action = Action::Drop;
    drop_peer.sources = nets(&["10.9.0.2/32"]);
    let drop_peer = with_rules(vec![drop_peer]);
    let mut server = FirewallRuleset::new();
    server.advanced_security.egress_profile = EgressProfile::Server;
    let script = r#"
watch igmp ip saddr 10.9.0.2 ip protocol igmp
watch_out igmp_out ip protocol igmp
# IGMPv2 (reports to the group), retransmitted only much later
P sh -c 'echo 2 > /proc/sys/net/ipv4/conf/v1/force_igmp_version \
    && echo 100000 > /proc/sys/net/ipv4/conf/v1/igmpv2_unsolicited_report_interval'
echo "out_start $(count igmp_out)"
# Control: a bare output drop policy stops the host's reports
nft -f - <<'CTL'
table inet ctl {
    chain o {
        type filter hook output priority 0; policy drop;
    }
}
CTL
ip addr add 239.2.0.1/32 dev v0 autojoin; sleep 0.3
echo "out_blocked $(count igmp_out)"
nft delete table inet ctl
load server
ip addr add 239.2.0.2/32 dev v0 autojoin; sleep 0.3
echo "out_server $(count igmp_out)"

join() { # group: the host joins, then the peer (its report arrives)
    ip addr add $1/32 dev v0 autojoin
    P ip addr add $1/32 dev v1 autojoin
    sleep 0.5
}
echo "in_start $(count igmp)"
load default; join 239.1.2.3; echo "in_default $(count igmp)"
load drop_peer; join 239.1.2.4; echo "in_dropped $(count igmp)"
load server; join 239.1.2.5; echo "in_server $(count igmp)"
"#;
    let lines = lab(
        &[
            ("default", &default),
            ("drop_peer", &drop_peer),
            ("server", &server),
        ],
        script,
    );
    let out_start = value(&lines, "out_start");
    let out_blocked = value(&lines, "out_blocked");
    assert_eq!(out_blocked, out_start, "control: the report is dropped");
    assert!(value(&lines, "out_server") > out_blocked, "{lines:?}");
    let in_default = value(&lines, "in_default");
    assert!(in_default > value(&lines, "in_start"), "{lines:?}");
    let in_dropped = value(&lines, "in_dropped");
    assert_eq!(in_dropped, in_default, "a user Drop rule comes first");
    assert!(value(&lines, "in_server") > in_dropped, "{lines:?}");
}

// ============================================================================
// S5: DHCP client replies
// ============================================================================

/// A DHCP server's answer (from port 67 to 68) is accepted, unicast and
/// broadcast (an OFFER to a client without an address); from another port
/// it is not.
#[test]
fn test_dhcp_client_replies_are_accepted() {
    if !lab_available() {
        return;
    }
    let default = FirewallRuleset::new();
    let script = r#"
load default
watch dhcp ip saddr 10.9.0.2 udp dport 68
pudp 10.9.0.2:66 10.9.0.1:68; sleep 0.1
echo "other_port $(count dhcp)"
pudp 10.9.0.2:67 10.9.0.1:68; sleep 0.1
echo "unicast $(count dhcp)"
pudp 10.9.0.2:67 255.255.255.255:68 broadcast; sleep 0.1
echo "broadcast $(count dhcp)"
"#;
    let lines = lab(&[("default", &default)], script);
    assert_eq!(value(&lines, "other_port"), 0);
    assert_eq!(value(&lines, "unicast"), 1);
    assert_eq!(value(&lines, "broadcast"), 2);
}

// ============================================================================
// S1: local network discovery
// ============================================================================

/// Discovery queries of the host in [`test_local_discovery`]: (name, our
/// port, destination, extra `udp` argument). The answer comes from the
/// peer's address of the same family to our port.
const DISCOVERY_QUERIES: [(&str, u16, &str, &str); 10] = [
    ("ssdp", 40900, "239.255.255.250:1900", ""),
    ("wsd", 40901, "239.255.255.250:3702", ""),
    ("mdns", 40902, "224.0.0.251:5353", ""),
    ("llmnr", 40903, "224.0.0.252:5355", ""),
    ("nbns", 40904, "10.9.0.255:137", "broadcast"),
    ("nbns_all", 40905, "255.255.255.255:137", "broadcast"),
    ("ssdp6", 40910, "[ff02::c%HIDX]:1900", ""),
    ("wsd6", 40911, "[ff02::c%HIDX]:3702", ""),
    ("mdns6", 40912, "[ff02::fb%HIDX]:5353", ""),
    ("llmnr6", 40913, "[ff02::1:3%HIDX]:5355", ""),
];

/// Multicast and broadcast that is not a discovery query (the sweep's
/// scenario: one broadcast to an arbitrary port opened the sender's port):
/// the ports they are sent from must stay closed.
const NOT_QUERIES: [(&str, u16, &str, &str); 7] = [
    ("bcast_any_port", 40920, "10.9.0.255:9999", "broadcast"),
    (
        "bcast_all_any_port",
        40921,
        "255.255.255.255:9999",
        "broadcast",
    ),
    ("ssdp_group_other_port", 40922, "239.255.255.250:9999", ""),
    ("mdns_group_ssdp_port", 40923, "224.0.0.251:1900", ""),
    ("netbios_datagram", 40924, "10.9.0.255:138", "broadcast"),
    ("nbns_multicast", 40925, "224.0.0.1:137", ""),
    ("v6_other_port", 40926, "[ff02::c%HIDX]:9999", ""),
];

/// With local discovery: mDNS and SSDP multicast reach the host; the unicast
/// replies to our SSDP, WS-Discovery, mDNS and LLMNR queries (multicast,
/// IPv4 and IPv6) and `NetBIOS` name queries (broadcast) are accepted from
/// the private peer, but not from a public source, nor to a port that sent
/// no query, nor to a port that only sent other multicast or broadcast
/// ([`NOT_QUERIES`]: a broadcast to an arbitrary port no longer opens the
/// sender's port). Without the setting none of it passes.
#[test]
fn test_local_discovery() {
    if !lab_available() {
        return;
    }
    let mut on = FirewallRuleset::new();
    on.advanced_security.local_discovery = true;
    let off = FirewallRuleset::new();

    let mut sends = String::new();
    let mut answers = String::new();
    let mut watches = String::new();
    let mut names: Vec<&str> = Vec::new();
    for (name, port, dest, extra) in DISCOVERY_QUERIES.iter().chain(&NOT_QUERIES) {
        let (ours, peer, family) = if dest.starts_with('[') {
            (format!("[fd09::1]:{port}"), "[fd09::2]", "ip6")
        } else {
            (format!("10.9.0.1:{port}"), "10.9.0.2", "ip")
        };
        let dest = dest.replace("HIDX", "$hidx");
        let peer_addr = peer.trim_matches(['[', ']']);
        writeln!(sends, "udp \"{ours}\" \"{dest}\" {extra}").unwrap();
        writeln!(answers, "pudp \"{peer}:1900\" \"{ours}\"").unwrap();
        writeln!(
            watches,
            "watch {name} {family} saddr {peer_addr} udp dport {port}"
        )
        .unwrap();
        names.push(name);
    }
    let script = format!(
        r#"
ip route add 224.0.0.0/4 dev v0
P ip route add 224.0.0.0/4 dev v1
# A public address on the LAN (a spoofed or misconfigured device)
P ip addr add 203.0.113.1/32 dev v1
hidx=$(ifindex v0)
pidx=$(ifindex v1 P)
{watches}
watch no_query ip saddr 10.9.0.2 udp dport 40999
watch public ip saddr 203.0.113.1 udp dport 40900
watch mdns_in ip saddr 10.9.0.2 ip daddr 224.0.0.251 udp dport 5353
watch ssdp_in ip saddr 10.9.0.2 ip daddr 239.255.255.250 udp dport 1900
watch mdns6_in ip6 saddr fd09::2 ip6 daddr ff02::fb udp dport 5353
round() {{
    load "$1"
    # Our queries, and multicast/broadcast that is not one
{sends}
    {{ nft list set inet drfw discovery_reply 2>/dev/null || echo none; }} | tr -s ' \n\t' ' ' > "set_$1.out"
    # The answers, and what must not pass
{answers}
    pudp 10.9.0.2:1900 10.9.0.1:40999
    pudp 203.0.113.1:1900 10.9.0.1:40900
    # Multicast to us (we join the groups only now: a group address on v0
    # would turn our own queries to it into local traffic)
    ip addr add 224.0.0.251/32 dev v0 autojoin
    ip addr add 239.255.255.250/32 dev v0 autojoin
    ip -6 addr add ff02::fb/128 dev v0 autojoin
    pudp 10.9.0.2:5353 224.0.0.251:5353
    pudp 10.9.0.2:40000 239.255.255.250:1900
    pudp "[fd09::2]:5353" "[ff02::fb%$pidx]:5353"
    sleep 0.2
    ip addr del 224.0.0.251/32 dev v0
    ip addr del 239.255.255.250/32 dev v0
    ip -6 addr del ff02::fb/128 dev v0
    for name in {all} no_query public mdns_in ssdp_in mdns6_in; do
        echo "$1_$name $(count $name)"
    done
}}
round on
round off
cat set_on.out; echo
"#,
        all = names.join(" "),
    );
    let lines = lab(&[("on", &on), ("off", &off)], &script);
    let accepted = DISCOVERY_QUERIES
        .iter()
        .map(|q| q.0)
        .chain(["mdns_in", "ssdp_in", "mdns6_in"]);
    for name in accepted {
        let on = value(&lines, &format!("on_{name}"));
        assert_eq!(on, 1, "{name} accepted with local discovery: {lines:#?}");
        assert_eq!(
            value(&lines, &format!("off_{name}")),
            on,
            "{name} not accepted without it"
        );
    }
    for name in NOT_QUERIES
        .iter()
        .map(|q| q.0)
        .chain(["no_query", "public"])
    {
        assert_eq!(
            value(&lines, &format!("on_{name}")),
            0,
            "{name}: {lines:#?}"
        );
        assert_eq!(value(&lines, &format!("off_{name}")), 0, "{name}");
    }
    let set = lines.last().expect("set listing");
    for (name, port, ..) in DISCOVERY_QUERIES {
        assert!(
            set.contains(&format!("{port} expires")),
            "{name}: {port} not remembered: {set}"
        );
    }
    for (name, port, ..) in NOT_QUERIES {
        assert!(
            !set.contains(&format!("{port} ")),
            "{name}: {port} remembered: {set}"
        );
    }
}

// ============================================================================
// S4: anti-spoofing (RPF)
// ============================================================================

/// RPF drops a packet from the LAN with a source of the (container) subnet
/// behind another interface, which a source-based rule would trust; a real
/// LAN source still passes. A full-tunnel VPN (wg-quick style fwmark policy
/// routing: everything unmarked goes to the tunnel) keeps working: the
/// underlay's replies are vouched for by conntrack, which comes first. A
/// tunnel endpoint that sends first is still dropped (documented).
#[test]
fn test_rpf_drops_spoofed_sources_and_keeps_full_tunnel_vpn() {
    if !lab_available() {
        return;
    }
    let mut trust = rule(
        "Trust containers",
        Protocol::Udp,
        vec![PortEntry::Single(4444)],
    );
    trust.sources = nets(&["172.17.0.0/16"]);
    let lan = rule("LAN service", Protocol::Udp, vec![PortEntry::Single(4445)]);
    let off = with_rules(vec![trust.clone(), lan.clone()]);
    let mut on = with_rules(vec![trust, lan]);
    on.advanced_security.enable_rpf = true;
    let script = r#"
ip link add dock0 type dummy
ip addr add 172.17.0.1/24 dev dock0
ip link set dock0 up
P ip addr add 172.17.0.99/32 dev v1
watch spoof ip saddr 172.17.0.99 udp dport 4444
watch lan ip saddr 10.9.0.2 udp dport 4445
for rs in off on; do
    load $rs
    pudp 172.17.0.99:4444 10.9.0.1:4444
    pudp 10.9.0.2:40000 10.9.0.1:4445
    sleep 0.1
    echo "spoof_$rs $(count spoof)"
    echo "lan_$rs $(count lan)"
done

# Full-tunnel VPN, as wg-quick sets it up
P ip addr add 203.0.113.1/32 dev lo
ip route add default via 10.9.0.2
ip link add wg0 type dummy
ip addr add 10.200.0.1/24 dev wg0
ip link set wg0 up
ip route add default dev wg0 table 51820
ip rule add not fwmark 51820 table 51820
ip rule add table main suppress_prefixlength 0
ok() { if "$@" >/dev/null 2>&1; then echo ok; else echo FAILED; fi; }
watch endpoint ip saddr 203.0.113.1 icmp type echo-request
for rs in on off; do
    load $rs
    echo "underlay_$rs $(ok ping -c1 -W2 -m 51820 203.0.113.1)"
    echo "lan_ping_$rs $(ok ping -c1 -W2 10.9.0.2)"
    echo "own_$rs $(ok ping -c1 -W1 10.9.0.1)"
    echo "loopback_$rs $(ok ping -c1 -W1 127.0.0.1)"
    P ping -c1 -W1 -I 203.0.113.1 10.9.0.1 >/dev/null 2>&1 || true
    echo "endpoint_$rs $(count endpoint)"
done
"#;
    let lines = lab(&[("off", &off), ("on", &on)], script);
    assert_eq!(
        value(&lines, "spoof_off"),
        1,
        "control: the spoofed source is trusted"
    );
    assert_eq!(value(&lines, "spoof_on"), 1, "RPF drops it");
    assert_eq!(value(&lines, "lan_off"), 1);
    assert_eq!(value(&lines, "lan_on"), 2, "a real LAN source passes RPF");
    for rs in ["on", "off"] {
        for check in ["underlay", "lan_ping", "own", "loopback"] {
            assert_eq!(text(&lines, &format!("{check}_{rs}")), "ok", "{check} {rs}");
        }
    }
    assert_eq!(
        value(&lines, "endpoint_on"),
        0,
        "an endpoint that sends first fails RPF"
    );
    assert_eq!(value(&lines, "endpoint_off"), 1);
}

// ============================================================================
// C2: ICMP rate limit
// ============================================================================

/// A flood of 300 echo requests (one ping run, so one conntrack entry) is
/// answered in full without a limit, and only within the limit (10/s plus
/// the burst) with one, for IPv4 and IPv6. IPv6 neighbor discovery is not
/// limited (the IPv6 ping needs it).
#[test]
fn test_icmp_rate_limit_limits_a_ping_flood() {
    if !lab_available() {
        return;
    }
    let open = FirewallRuleset::new();
    let mut limited = FirewallRuleset::new();
    limited.advanced_security.icmp_rate_limit = 10;
    let script = r#"
flood() { P ping $1 -c300 -i0.002 -W1 -q $2 2>&1 | sed -nE 's/.* ([0-9]+) received.*/\1/p'; }
for rs in open limited; do
    load $rs
    P ip neigh flush dev v1
    echo "v4_$rs $(flood -4 10.9.0.1)"
    echo "v6_$rs $(flood -6 fd09::1)"
done
"#;
    let lines = lab(&[("open", &open), ("limited", &limited)], script);
    for family in ["v4", "v6"] {
        let open = value(&lines, &format!("{family}_open"));
        assert!(open >= 290, "{family} without a limit: {lines:?}");
        let limited = value(&lines, &format!("{family}_limited"));
        // 10/s over the flood's few seconds plus the burst: far fewer than
        // half (a limit on new pings only would answer all 300)
        assert!(
            (1..150).contains(&limited),
            "{family}: {limited} of 300 answered under 10/s"
        );
    }
}

// ============================================================================
// C1: loopback addresses from the network
// ============================================================================

/// With `route_localnet=1` (kube-proxy, some container setups) the kernel
/// routes packets for 127.0.0.1 arriving from the network to the input
/// hook; DRFW drops them.
#[test]
fn test_loopback_destination_from_the_network_is_dropped() {
    if !lab_available() {
        return;
    }
    let mut open = rule(
        "Local service",
        Protocol::Udp,
        vec![PortEntry::Single(8080)],
    );
    open.destinations = nets(&["127.0.0.1/32"]);
    let ruleset = with_rules(vec![open]);
    let script = r#"
echo 1 > /proc/sys/net/ipv4/conf/v0/route_localnet
P sh -c 'echo 1 > /proc/sys/net/ipv4/conf/v1/route_localnet && echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet'
# The peer routes 127.0.0.1 to us
P ip route add 127.0.0.1/32 via 10.9.0.1 dev v1 src 10.9.0.2 table 100
P ip rule add pref 10 to 127.0.0.1 lookup 100
P ip rule del pref 0 lookup local
P ip rule add pref 20 lookup local
watch lo ip daddr 127.0.0.1 udp dport 8080
pudp 10.9.0.2:40000 127.0.0.1:8080; sleep 0.1
echo "none $(count lo)"
load drfw
pudp 10.9.0.2:40000 127.0.0.1:8080; sleep 0.1
echo "drfw $(count lo)"
"#;
    let lines = lab(&[("drfw", &ruleset)], script);
    assert_eq!(
        value(&lines, "none"),
        1,
        "control: it reaches the input hook"
    );
    assert_eq!(
        value(&lines, "drfw"),
        1,
        "dropped, even with an accept rule"
    );
}

// ============================================================================
// S7: Forward rules
// ============================================================================

/// The host routes between two networks (namespaces A and B). With "Block
/// forwarding" and a Forward rule for TCP 8080 from A's interface to B's,
/// A reaches B on 8080 only, and B cannot reach A on 8080 (wrong
/// direction). Without "Block forwarding" everything is routed.
#[test]
fn test_forward_rules_with_block_forwarding() {
    if !lab_available() {
        return;
    }
    let mut allow = rule("A to B web", Protocol::Tcp, vec![PortEntry::Single(8080)]);
    allow.chain = Chain::Forward;
    allow.interface = Some("va".to_string());
    allow.output_interface = Some("vb".to_string());
    allow.rebuild_caches();
    let mut blocking = with_rules(vec![allow.clone()]);
    blocking.advanced_security.block_forwarding = true;
    assert!(blocking.validate_for_apply().is_ok());
    let open = with_rules(vec![allow]);
    let script = r#"
echo 1 > /proc/sys/net/ipv4/ip_forward
mkns a
mkns b
ip link add va type veth peer name eth0 netns "$a"
ip link add vb type veth peer name eth0 netns "$b"
ip addr add 10.9.1.1/24 dev va
ip addr add 10.9.2.1/24 dev vb
ip link set va up
ip link set vb up
nsenter -t "$a" -n sh -c 'ip addr add 10.9.1.2/24 dev eth0 && ip link set eth0 up && ip route add default via 10.9.1.1'
nsenter -t "$b" -n sh -c 'ip addr add 10.9.2.2/24 dev eth0 && ip link set eth0 up && ip route add default via 10.9.2.1'
for rs in blocking open; do
    load $rs
    attempt "$a" 10.9.2.2 8080 "${rs}_a_b_8080"
    attempt "$a" 10.9.2.2 8081 "${rs}_a_b_8081"
    attempt "$b" 10.9.1.2 8080 "${rs}_b_a_8080"
done
"#;
    let lines = lab(&[("blocking", &blocking), ("open", &open)], script);
    let expected = [
        ("blocking_a_b_8080", "passed"),
        ("blocking_a_b_8081", "blocked"),
        ("blocking_b_a_8080", "blocked"),
        ("open_a_b_8080", "passed"),
        ("open_a_b_8081", "passed"),
        ("open_b_a_8080", "passed"),
    ];
    for (key, outcome) in expected {
        assert_eq!(text(&lines, key), outcome, "{key}: {lines:?}");
    }
}
