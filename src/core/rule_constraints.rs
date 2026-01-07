//! Rule constraint functions for firewall rules
//!
//! This module centralizes business logic about valid field combinations
//! for firewall rules. It's used by both the GUI rule form and the stress
//! test generator to ensure consistency.
//!
//! # Design Rationale
//!
//! Extracting constraints from UI code provides:
//! - Single source of truth for rule validation
//! - Testable constraint logic independent of UI
//! - Type-safe test data generation (stress_gen uses same rules as GUI)
//!
//! # Note on Dead Code Warnings
//!
//! Some functions in this module may show as "unused" when compiling the binary
//! target, but they ARE used by library consumers like `examples/stress_gen.rs`.
//! These are intentionally public API for external use.
//!
//! # Examples
//!
//! ```
//! use drfw::core::firewall::{Protocol, RejectType, Chain};
//! use drfw::core::rule_constraints::*;
//!
//! // Check if a protocol supports port filtering
//! assert!(protocol_supports_ports(Protocol::Tcp));
//! assert!(!protocol_supports_ports(Protocol::Icmp));
//!
//! // Check if a reject type is valid for a protocol
//! assert!(reject_type_valid_for_protocol(RejectType::TcpReset, Protocol::Tcp));
//! assert!(!reject_type_valid_for_protocol(RejectType::TcpReset, Protocol::Udp));
//! ```

// Allow dead_code for public API functions used by library consumers (e.g., stress_gen example)
// but not by the binary itself. These are intentionally exported for external use.
#![allow(dead_code)]

use super::firewall::{Chain, Protocol, RejectType};

// ═══════════════════════════════════════════════════════════════════════════
// Protocol Constraints
// ═══════════════════════════════════════════════════════════════════════════

/// Returns `true` if the protocol supports port filtering.
///
/// Only TCP and UDP-based protocols use ports. ICMP and "Any" protocols
/// do not support port filtering in nftables.
///
/// # Examples
///
/// ```
/// use drfw::core::firewall::Protocol;
/// use drfw::core::rule_constraints::protocol_supports_ports;
///
/// assert!(protocol_supports_ports(Protocol::Tcp));
/// assert!(protocol_supports_ports(Protocol::Udp));
/// assert!(protocol_supports_ports(Protocol::TcpAndUdp));
/// assert!(!protocol_supports_ports(Protocol::Any));
/// assert!(!protocol_supports_ports(Protocol::Icmp));
/// ```
#[inline]
pub fn protocol_supports_ports(protocol: Protocol) -> bool {
    matches!(protocol, Protocol::Tcp | Protocol::Udp | Protocol::TcpAndUdp)
}

/// Returns `true` if the protocol is an ICMP variant.
///
/// Groups ICMP, ICMPv6, and IcmpBoth for code that needs to handle
/// all ICMP-like protocols uniformly.
///
/// # Examples
///
/// ```
/// use drfw::core::firewall::Protocol;
/// use drfw::core::rule_constraints::protocol_is_icmp;
///
/// assert!(protocol_is_icmp(Protocol::Icmp));
/// assert!(protocol_is_icmp(Protocol::Icmpv6));
/// assert!(protocol_is_icmp(Protocol::IcmpBoth));
/// assert!(!protocol_is_icmp(Protocol::Tcp));
/// ```
#[inline]
pub fn protocol_is_icmp(protocol: Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Icmp | Protocol::Icmpv6 | Protocol::IcmpBoth
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// Reject Type Constraints
// ═══════════════════════════════════════════════════════════════════════════

/// Returns `true` if the reject type is valid for the given protocol.
///
/// TCP Reset (`TcpReset`) is only valid for pure TCP protocol because:
/// - UDP cannot receive RST packets (connectionless protocol)
/// - `TcpAndUdp` includes UDP, so RST would only work for the TCP portion
///
/// The GUI enforces `TcpReset` only for `Protocol::Tcp` to avoid confusion.
///
/// # Examples
///
/// ```
/// use drfw::core::firewall::{Protocol, RejectType};
/// use drfw::core::rule_constraints::reject_type_valid_for_protocol;
///
/// // TcpReset only valid for pure TCP
/// assert!(reject_type_valid_for_protocol(RejectType::TcpReset, Protocol::Tcp));
/// assert!(!reject_type_valid_for_protocol(RejectType::TcpReset, Protocol::Udp));
/// assert!(!reject_type_valid_for_protocol(RejectType::TcpReset, Protocol::TcpAndUdp));
///
/// // Other reject types valid for any protocol
/// assert!(reject_type_valid_for_protocol(RejectType::Default, Protocol::Udp));
/// assert!(reject_type_valid_for_protocol(RejectType::AdminProhibited, Protocol::Icmp));
/// ```
#[inline]
pub fn reject_type_valid_for_protocol(reject_type: RejectType, protocol: Protocol) -> bool {
    match reject_type {
        RejectType::TcpReset => protocol == Protocol::Tcp,
        _ => true,
    }
}

/// Returns the list of reject types available for a protocol.
///
/// The GUI shows a simplified list (Default, AdminProhibited, and TcpReset for TCP).
/// PortUnreachable and HostUnreachable are not shown in the GUI picker but may
/// exist in imported rulesets.
///
/// # Examples
///
/// ```
/// use drfw::core::firewall::{Protocol, RejectType};
/// use drfw::core::rule_constraints::available_reject_types_for_protocol;
///
/// let tcp_types = available_reject_types_for_protocol(Protocol::Tcp);
/// assert!(tcp_types.contains(&RejectType::TcpReset));
///
/// let udp_types = available_reject_types_for_protocol(Protocol::Udp);
/// assert!(!udp_types.contains(&RejectType::TcpReset));
/// ```
pub fn available_reject_types_for_protocol(protocol: Protocol) -> Vec<RejectType> {
    if protocol == Protocol::Tcp {
        vec![
            RejectType::Default,
            RejectType::AdminProhibited,
            RejectType::TcpReset,
        ]
    } else {
        vec![RejectType::Default, RejectType::AdminProhibited]
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Chain-Interface Constraints
// ═══════════════════════════════════════════════════════════════════════════

/// Which interface type is relevant for a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceType {
    /// Input interface (iif) - where packets enter
    Input,
    /// Output interface (oif) - where packets exit
    Output,
}

/// Returns `true` if the chain uses input interface (iif) matching.
///
/// In nftables:
/// - Input chain: packets arrive on an interface (iif is relevant)
/// - Output chain: packets leave on an interface (oif is relevant)
///
/// # Examples
///
/// ```
/// use drfw::core::firewall::Chain;
/// use drfw::core::rule_constraints::chain_uses_input_interface;
///
/// assert!(chain_uses_input_interface(Chain::Input));
/// assert!(!chain_uses_input_interface(Chain::Output));
/// ```
#[inline]
pub fn chain_uses_input_interface(chain: Chain) -> bool {
    chain == Chain::Input
}

/// Returns `true` if the chain uses output interface (oif) matching.
///
/// # Examples
///
/// ```
/// use drfw::core::firewall::Chain;
/// use drfw::core::rule_constraints::chain_uses_output_interface;
///
/// assert!(chain_uses_output_interface(Chain::Output));
/// assert!(!chain_uses_output_interface(Chain::Input));
/// ```
#[inline]
pub fn chain_uses_output_interface(chain: Chain) -> bool {
    chain == Chain::Output
}

/// Returns which interface type is semantically appropriate for a chain.
///
/// While both interface fields can technically be set, this indicates
/// which one is most relevant for the chain direction.
///
/// # Examples
///
/// ```
/// use drfw::core::firewall::Chain;
/// use drfw::core::rule_constraints::{chain_interface_type, InterfaceType};
///
/// assert_eq!(chain_interface_type(Chain::Input), InterfaceType::Input);
/// assert_eq!(chain_interface_type(Chain::Output), InterfaceType::Output);
/// ```
#[inline]
pub fn chain_interface_type(chain: Chain) -> InterfaceType {
    match chain {
        Chain::Input => InterfaceType::Input,
        Chain::Output => InterfaceType::Output,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Protocol port support tests
    #[test]
    fn test_protocol_supports_ports_tcp_variants() {
        assert!(protocol_supports_ports(Protocol::Tcp));
        assert!(protocol_supports_ports(Protocol::Udp));
        assert!(protocol_supports_ports(Protocol::TcpAndUdp));
    }

    #[test]
    fn test_protocol_supports_ports_non_port_protocols() {
        assert!(!protocol_supports_ports(Protocol::Any));
        assert!(!protocol_supports_ports(Protocol::Icmp));
        assert!(!protocol_supports_ports(Protocol::Icmpv6));
        assert!(!protocol_supports_ports(Protocol::IcmpBoth));
    }

    // ICMP grouping tests
    #[test]
    fn test_protocol_is_icmp() {
        assert!(protocol_is_icmp(Protocol::Icmp));
        assert!(protocol_is_icmp(Protocol::Icmpv6));
        assert!(protocol_is_icmp(Protocol::IcmpBoth));

        assert!(!protocol_is_icmp(Protocol::Any));
        assert!(!protocol_is_icmp(Protocol::Tcp));
        assert!(!protocol_is_icmp(Protocol::Udp));
        assert!(!protocol_is_icmp(Protocol::TcpAndUdp));
    }

    // Reject type validity tests
    #[test]
    fn test_tcp_reset_only_valid_for_pure_tcp() {
        // TcpReset should ONLY be valid for pure TCP
        assert!(reject_type_valid_for_protocol(
            RejectType::TcpReset,
            Protocol::Tcp
        ));

        // NOT valid for TcpAndUdp (UDP can't receive RST)
        assert!(!reject_type_valid_for_protocol(
            RejectType::TcpReset,
            Protocol::TcpAndUdp
        ));

        // NOT valid for other protocols
        assert!(!reject_type_valid_for_protocol(
            RejectType::TcpReset,
            Protocol::Udp
        ));
        assert!(!reject_type_valid_for_protocol(
            RejectType::TcpReset,
            Protocol::Any
        ));
        assert!(!reject_type_valid_for_protocol(
            RejectType::TcpReset,
            Protocol::Icmp
        ));
    }

    #[test]
    fn test_other_reject_types_valid_for_all() {
        let protocols = [
            Protocol::Any,
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::TcpAndUdp,
            Protocol::Icmp,
            Protocol::Icmpv6,
            Protocol::IcmpBoth,
        ];

        let non_tcp_reset_types = [
            RejectType::Default,
            RejectType::PortUnreachable,
            RejectType::HostUnreachable,
            RejectType::AdminProhibited,
        ];

        for reject_type in non_tcp_reset_types {
            for protocol in protocols {
                assert!(
                    reject_type_valid_for_protocol(reject_type, protocol),
                    "{:?} should be valid for {:?}",
                    reject_type,
                    protocol
                );
            }
        }
    }

    #[test]
    fn test_available_reject_types_tcp() {
        let types = available_reject_types_for_protocol(Protocol::Tcp);
        assert!(types.contains(&RejectType::Default));
        assert!(types.contains(&RejectType::AdminProhibited));
        assert!(types.contains(&RejectType::TcpReset));
    }

    #[test]
    fn test_available_reject_types_non_tcp() {
        for protocol in [
            Protocol::Any,
            Protocol::Udp,
            Protocol::TcpAndUdp,
            Protocol::Icmp,
        ] {
            let types = available_reject_types_for_protocol(protocol);
            assert!(types.contains(&RejectType::Default));
            assert!(types.contains(&RejectType::AdminProhibited));
            assert!(
                !types.contains(&RejectType::TcpReset),
                "TcpReset should not be in list for {:?}",
                protocol
            );
        }
    }

    // Chain-interface tests
    #[test]
    fn test_chain_uses_input_interface() {
        assert!(chain_uses_input_interface(Chain::Input));
        assert!(!chain_uses_input_interface(Chain::Output));
    }

    #[test]
    fn test_chain_uses_output_interface() {
        assert!(chain_uses_output_interface(Chain::Output));
        assert!(!chain_uses_output_interface(Chain::Input));
    }

    #[test]
    fn test_chain_interface_type() {
        assert_eq!(chain_interface_type(Chain::Input), InterfaceType::Input);
        assert_eq!(chain_interface_type(Chain::Output), InterfaceType::Output);
    }
}
