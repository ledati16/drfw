//! Rule templates: ready-made, ordinary rules for common setups
//!
//! DRFW keeps its base ruleset small and the same on every machine; things
//! that depend on what runs on a machine (a VPN, virtual machines, Server
//! Mode's outbound services) are offered as templates instead. A template is
//! a function returning plain [`Rule`]s with fresh ids, labels and tags, and
//! caches built: once added they show up, can be edited and deleted like any
//! rule the user wrote. Nothing is hidden in the generated ruleset.
//!
//! - [`server_essentials`]: the outbound services a server in Server Mode
//!   usually needs (DNS, DNS over TLS, NTP, HTTP/HTTPS, ping)
//! - [`vm_guest_dhcp_dns`]: DHCP and DNS for libvirt guests on a bridge
//! - [`tailscale_direct`]: Tailscale's `WireGuard` port, for direct
//!   connections to peers behind hard NAT
//! - [`trust_interface`]: accept everything arriving on one interface
//!
//! [`available_templates`] says which templates apply to the interfaces of
//! this computer (the GUI builds its menu from it).
//!
//! # Example
//!
//! ```
//! use drfw::core::templates::{TemplateKind, available_templates};
//!
//! let interfaces = vec![
//!     "lo".to_string(),
//!     "virbr0".to_string(),
//!     "tailscale0".to_string(),
//! ];
//! let templates = available_templates(&interfaces);
//! assert_eq!(
//!     templates,
//!     vec![
//!         TemplateKind::VmGuestDhcpDns {
//!             interface: "virbr0".into()
//!         },
//!         TemplateKind::TailscaleDirect,
//!         TemplateKind::TrustInterface {
//!             interface: "tailscale0".into()
//!         },
//!     ]
//! );
//! assert_eq!(templates[0].rules().len(), 2);
//! ```

use uuid::Uuid;

use super::firewall::{Chain, PortEntry, Protocol, Rule};

/// Tag of the [`server_essentials`] rules.
const TAG_SERVER: &str = "server";
/// Tag of the [`vm_guest_dhcp_dns`] rules.
const TAG_VM: &str = "vm";
/// Tag of the Tailscale templates.
const TAG_TAILSCALE: &str = "tailscale";
/// Tag of [`trust_interface`] rules (other than Tailscale's).
const TAG_TRUSTED: &str = "trusted";

/// DNS port (UDP and TCP).
const DNS_PORT: u16 = 53;
/// DNS over TLS port.
const DOT_PORT: u16 = 853;
/// NTP port.
const NTP_PORT: u16 = 123;
/// DHCP server port.
const DHCP_SERVER_PORT: u16 = 67;
/// Tailscale's default `WireGuard` listen port.
const TAILSCALE_PORT: u16 = 41641;
/// Tailscale's interface name.
const TAILSCALE_INTERFACE: &str = "tailscale0";
/// Interface name prefix of libvirt's bridges (`virbr0`, `virbr1`, ...).
const LIBVIRT_BRIDGE_PREFIX: &str = "virbr";

/// A template that applies to this computer (see [`available_templates`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateKind {
    /// [`vm_guest_dhcp_dns`] for a libvirt bridge
    VmGuestDhcpDns { interface: String },
    /// [`tailscale_direct`]
    TailscaleDirect,
    /// [`trust_interface`] for an interface
    TrustInterface { interface: String },
}

impl TemplateKind {
    /// Menu entry text, e.g. "VM guests: DHCP and DNS on virbr0".
    pub fn title(&self) -> String {
        match self {
            Self::VmGuestDhcpDns { interface } => vm_label(interface),
            Self::TailscaleDirect => tailscale_direct().label,
            Self::TrustInterface { interface } => trust_label(interface),
        }
    }

    /// One sentence on what the template does and when to use it.
    pub const fn description(&self) -> &'static str {
        match self {
            Self::VmGuestDhcpDns { .. } => {
                "Lets virtual machines on this bridge get an address (DHCP) and resolve names \
                 (DNS) from libvirt's dnsmasq on this computer."
            }
            Self::TailscaleDirect => {
                "Accepts Tailscale's WireGuard port, so peers behind strict NAT can connect \
                 directly instead of through a relay."
            }
            Self::TrustInterface { .. } => {
                "Accepts every new connection arriving on this interface. Use only for networks \
                 whose devices you trust, such as your own tailnet."
            }
        }
    }

    /// The rules the template adds (fresh ids each call).
    pub fn rules(&self) -> Vec<Rule> {
        match self {
            Self::VmGuestDhcpDns { interface } => vm_guest_dhcp_dns(interface),
            Self::TailscaleDirect => vec![tailscale_direct()],
            Self::TrustInterface { interface } => vec![trust_interface(interface)],
        }
    }
}

/// Which templates apply to a computer with these interfaces, in menu order.
///
/// - every libvirt bridge (`virbr*`): [`TemplateKind::VmGuestDhcpDns`]
/// - `tailscale0`: [`TemplateKind::TailscaleDirect`] and
///   [`TemplateKind::TrustInterface`] for `tailscale0`
///
/// Interfaces are taken as given (e.g. from `/sys/class/net`); duplicates
/// are listed once.
pub fn available_templates(interfaces: &[String]) -> Vec<TemplateKind> {
    let mut templates = Vec::new();
    let mut bridges: Vec<&str> = interfaces
        .iter()
        .map(String::as_str)
        .filter(|name| {
            name.strip_prefix(LIBVIRT_BRIDGE_PREFIX)
                .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
        })
        .collect();
    bridges.sort_unstable();
    bridges.dedup();
    templates.extend(
        bridges
            .into_iter()
            .map(|interface| TemplateKind::VmGuestDhcpDns {
                interface: interface.to_string(),
            }),
    );
    if interfaces.iter().any(|name| name == TAILSCALE_INTERFACE) {
        templates.push(TemplateKind::TailscaleDirect);
        templates.push(TemplateKind::TrustInterface {
            interface: TAILSCALE_INTERFACE.to_string(),
        });
    }
    templates
}

/// A new enabled rule with caches built.
fn new_rule(label: &str, protocol: Protocol, ports: &[u16], chain: Chain, tag: &str) -> Rule {
    Rule::with_caches(
        Uuid::new_v4(),
        label.to_string(),
        protocol,
        ports.iter().copied().map(PortEntry::Single).collect(),
        Vec::new(),
        None,
        chain,
        true,
        jiff::Timestamp::now(),
        vec![tag.to_string()],
    )
}

/// Output rules for the outbound services a server usually needs, for
/// Server Mode (whose output policy drops everything else new):
///
/// | Label | Match |
/// |---|---|
/// | DNS | TCP and UDP 53 |
/// | DNS over TLS | TCP 853 |
/// | Time sync: NTP | UDP 123 |
/// | Web and updates: HTTP and HTTPS | TCP 80, 443 |
/// | Ping | ICMP and `ICMPv6` |
///
/// The ping rule is a single ICMP + `ICMPv6` rule: rules cannot match ICMP
/// types, so it accepts every outgoing ICMP message, not only echo
/// requests. That adds little: errors about known connections and IPv6
/// neighbor discovery are accepted by Server Mode's base rules anyway.
///
/// The rules are inactive (kept, not generated) in Desktop mode.
pub fn server_essentials() -> Vec<Rule> {
    vec![
        new_rule(
            "DNS",
            Protocol::TcpAndUdp,
            &[DNS_PORT],
            Chain::Output,
            TAG_SERVER,
        ),
        new_rule(
            "DNS over TLS",
            Protocol::Tcp,
            &[DOT_PORT],
            Chain::Output,
            TAG_SERVER,
        ),
        new_rule(
            "Time sync: NTP",
            Protocol::Udp,
            &[NTP_PORT],
            Chain::Output,
            TAG_SERVER,
        ),
        new_rule(
            "Web and updates: HTTP and HTTPS",
            Protocol::Tcp,
            &[80, 443],
            Chain::Output,
            TAG_SERVER,
        ),
        new_rule("Ping", Protocol::IcmpBoth, &[], Chain::Output, TAG_SERVER),
    ]
}

/// Label of the [`vm_guest_dhcp_dns`] UDP rule.
fn vm_label(interface: &str) -> String {
    format!("VM guests: DHCP and DNS on {interface}")
}

/// Input rules that let libvirt guests on bridge `interface` reach the
/// host's DHCP and DNS server (libvirt's dnsmasq): UDP 53 and 67, and TCP 53
/// (DNS answers too large for UDP), only on that interface.
///
/// Labels: "VM guests: DHCP and DNS on `<interface>`" (UDP) and
/// "VM guests: DNS over TCP on `<interface>`".
///
/// In Server Mode the DHCP offers to the guests are new outbound packets;
/// they additionally need an Output rule (UDP to port 68 on the bridge).
pub fn vm_guest_dhcp_dns(interface: &str) -> Vec<Rule> {
    let mut udp = new_rule(
        &vm_label(interface),
        Protocol::Udp,
        &[DNS_PORT, DHCP_SERVER_PORT],
        Chain::Input,
        TAG_VM,
    );
    udp.interface = Some(interface.to_string());
    udp.rebuild_caches();
    let mut tcp = new_rule(
        &format!("VM guests: DNS over TCP on {interface}"),
        Protocol::Tcp,
        &[DNS_PORT],
        Chain::Input,
        TAG_VM,
    );
    tcp.interface = Some(interface.to_string());
    tcp.rebuild_caches();
    vec![udp, tcp]
}

/// Input rule accepting Tailscale's `WireGuard` port (UDP 41641) on any
/// interface: peers behind hard NAT can then connect directly instead of
/// through a DERP relay. Label "Tailscale: direct connections".
pub fn tailscale_direct() -> Rule {
    new_rule(
        "Tailscale: direct connections",
        Protocol::Udp,
        &[TAILSCALE_PORT],
        Chain::Input,
        TAG_TAILSCALE,
    )
}

/// Label of a [`trust_interface`] rule.
fn trust_label(interface: &str) -> String {
    format!("Trust {interface}")
}

/// Input rule accepting every new connection (any protocol) arriving on
/// `interface`. Label "Trust `<interface>`".
pub fn trust_interface(interface: &str) -> Rule {
    let tag = if interface == TAILSCALE_INTERFACE {
        TAG_TAILSCALE
    } else {
        TAG_TRUSTED
    };
    let mut rule = new_rule(
        &trust_label(interface),
        Protocol::Any,
        &[],
        Chain::Input,
        tag,
    );
    rule.interface = Some(interface.to_string());
    rule.rebuild_caches();
    rule
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::firewall::{EgressProfile, FirewallRuleset};

    /// Every template rule is valid, labelled as documented, and its label
    /// survives sanitizing (what the GUI and the generator show).
    fn assert_valid(rules: &[Rule]) {
        for rule in rules {
            assert!(
                rule.validate().is_ok(),
                "{}: {:?}",
                rule.label,
                rule.validate()
            );
            assert_ne!(rule.label, "");
            assert_eq!(rule.label, crate::validators::sanitize_label(&rule.label));
            assert!(!rule.tags.is_empty(), "{}", rule.label);
            assert!(rule.enabled);
        }
    }

    #[test]
    fn test_server_essentials() {
        let rules = server_essentials();
        assert_valid(&rules);
        let labels: Vec<&str> = rules.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "DNS",
                "DNS over TLS",
                "Time sync: NTP",
                "Web and updates: HTTP and HTTPS",
                "Ping"
            ]
        );
        assert!(rules.iter().all(|r| r.chain == Chain::Output));

        // Generated in Server Mode only, as output rules
        let mut ruleset = FirewallRuleset::new();
        ruleset.rules = rules;
        assert!(!ruleset.to_nft_text().contains("comment \"DNS\""));
        ruleset.advanced_security.egress_profile = EgressProfile::Server;
        let text = ruleset.to_nft_text();
        let output = &text[text.find("chain output").unwrap()..];
        for line in [
            "meta l4proto { tcp, udp } th dport 53 accept comment \"DNS\"",
            "meta l4proto tcp tcp dport 853 accept comment \"DNS over TLS\"",
            "meta l4proto udp udp dport 123 accept comment \"Time sync: NTP\"",
            "tcp dport { 80, 443 } accept comment \"Web and updates: HTTP and HTTPS\"",
            "meta l4proto { icmp, ipv6-icmp } accept comment \"Ping\"",
        ] {
            assert!(output.contains(line), "{line} missing:\n{output}");
        }
    }

    #[test]
    fn test_vm_tailscale_and_trust_templates() {
        let vm = vm_guest_dhcp_dns("virbr0");
        assert_valid(&vm);
        assert_eq!(vm[0].label, "VM guests: DHCP and DNS on virbr0");
        assert_eq!(vm[0].protocol, Protocol::Udp);
        assert_eq!(vm[0].ports, [PortEntry::Single(53), PortEntry::Single(67)]);
        assert_eq!(vm[1].protocol, Protocol::Tcp);
        assert_eq!(vm[1].ports, [PortEntry::Single(53)]);
        assert!(
            vm.iter()
                .all(|r| r.interface.as_deref() == Some("virbr0") && r.chain == Chain::Input)
        );

        let ts = tailscale_direct();
        assert_valid(std::slice::from_ref(&ts));
        assert_eq!(ts.label, "Tailscale: direct connections");
        assert_eq!(
            (ts.protocol, ts.ports.as_slice()),
            (Protocol::Udp, &[PortEntry::Single(41641)][..])
        );

        let trust = trust_interface("tailscale0");
        assert_valid(std::slice::from_ref(&trust));
        assert_eq!(trust.label, "Trust tailscale0");
        assert_eq!(trust.protocol, Protocol::Any);
        assert_eq!(trust.ports, []);
        assert_eq!(trust.interface.as_deref(), Some("tailscale0"));
        assert_eq!(trust.tags, ["tailscale"]);
        assert_eq!(trust_interface("wg0").tags, ["trusted"]);

        // Fresh ids every time
        assert_ne!(tailscale_direct().id, tailscale_direct().id);
    }

    #[test]
    fn test_available_templates() {
        let names = |list: &[&str]| list.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(available_templates(&names(&["lo", "eth0", "wlan0"])), []);
        assert_eq!(
            available_templates(&names(&[
                "virbr1",
                "virbr0-nic",
                "virbr0",
                "eth0",
                "virbr0"
            ])),
            vec![
                TemplateKind::VmGuestDhcpDns {
                    interface: "virbr0".into()
                },
                TemplateKind::VmGuestDhcpDns {
                    interface: "virbr1".into()
                },
            ],
            "bridges only (not their -nic ports), sorted, once each"
        );
        let ts = available_templates(&names(&["tailscale0"]));
        assert_eq!(
            ts,
            vec![
                TemplateKind::TailscaleDirect,
                TemplateKind::TrustInterface {
                    interface: "tailscale0".into()
                }
            ]
        );
        for kind in &ts {
            assert_ne!(kind.description(), "");
            let rules = kind.rules();
            assert_valid(&rules);
            assert_eq!(kind.title(), rules[0].label);
        }
    }
}
