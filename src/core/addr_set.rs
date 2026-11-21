//! Exact sets of IP addresses of one family, as sorted inclusive ranges
//!
//! Used by [`crate::core::evaluate`] to compute which sources can reach a
//! port: rule source lists are unions of CIDR blocks, earlier drops subtract
//! from what later rules see, and the result is turned back into CIDR blocks
//! for display. Ranges keep every operation exact (no sampling); their count
//! is bounded by the number of CIDR blocks in the ruleset.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

/// A set of addresses of one family (IPv4 or IPv6).
///
/// Invariant: `ranges` is sorted, every range is `start <= end` within the
/// family's address space, and ranges neither overlap nor touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddrSet {
    v6: bool,
    ranges: Vec<(u128, u128)>,
}

impl AddrSet {
    /// Largest address value of the family.
    const fn max(v6: bool) -> u128 {
        if v6 { u128::MAX } else { u32::MAX as u128 }
    }

    /// Number of address bits of the family.
    const fn width(v6: bool) -> u32 {
        if v6 { 128 } else { 32 }
    }

    pub(crate) const fn empty(v6: bool) -> Self {
        Self {
            v6,
            ranges: Vec::new(),
        }
    }

    pub(crate) fn full(v6: bool) -> Self {
        Self {
            v6,
            ranges: vec![(0, Self::max(v6))],
        }
    }

    /// The union of the networks of this family in `networks` (others are ignored).
    pub(crate) fn from_networks<'a>(
        v6: bool,
        networks: impl IntoIterator<Item = &'a IpNetwork>,
    ) -> Self {
        let mut ranges: Vec<(u128, u128)> = networks
            .into_iter()
            .filter(|n| n.is_ipv6() == v6)
            .map(network_range)
            .collect();
        ranges.sort_unstable();
        Self {
            v6,
            ranges: merge_sorted(ranges),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.ranges == [(0, Self::max(self.v6))]
    }

    /// `true` if `addr` (of this set's family) is in the set.
    pub(crate) fn contains(&self, addr: IpAddr) -> bool {
        let Some(value) = addr_value(addr, self.v6) else {
            return false;
        };
        // First range starting after `value`; the one before it may contain it
        let after = self.ranges.partition_point(|&(start, _)| start <= value);
        after > 0 && self.ranges[after - 1].1 >= value
    }

    pub(crate) fn union(&self, other: &Self) -> Self {
        debug_assert_eq!(self.v6, other.v6, "address families differ");
        let mut ranges = Vec::with_capacity(self.ranges.len() + other.ranges.len());
        ranges.extend_from_slice(&self.ranges);
        ranges.extend_from_slice(&other.ranges);
        ranges.sort_unstable();
        Self {
            v6: self.v6,
            ranges: merge_sorted(ranges),
        }
    }

    pub(crate) fn intersection(&self, other: &Self) -> Self {
        debug_assert_eq!(self.v6, other.v6, "address families differ");
        let mut ranges = Vec::new();
        let (mut i, mut j) = (0, 0);
        while i < self.ranges.len() && j < other.ranges.len() {
            let (a_start, a_end) = self.ranges[i];
            let (b_start, b_end) = other.ranges[j];
            let start = a_start.max(b_start);
            let end = a_end.min(b_end);
            if start <= end {
                ranges.push((start, end));
            }
            if a_end < b_end {
                i += 1;
            } else {
                j += 1;
            }
        }
        Self {
            v6: self.v6,
            ranges,
        }
    }

    /// The addresses of the family that are not in the set.
    pub(crate) fn complement(&self) -> Self {
        let max = Self::max(self.v6);
        let mut ranges = Vec::with_capacity(self.ranges.len() + 1);
        let mut next = Some(0u128);
        for &(start, end) in &self.ranges {
            if let Some(from) = next
                && from < start
            {
                ranges.push((from, start - 1));
            }
            next = end.checked_add(1).filter(|&n| n <= max);
        }
        if let Some(from) = next {
            ranges.push((from, max));
        }
        Self {
            v6: self.v6,
            ranges,
        }
    }

    pub(crate) fn difference(&self, other: &Self) -> Self {
        self.intersection(&other.complement())
    }

    /// The set as the fewest CIDR blocks, in address order.
    pub(crate) fn to_networks(&self) -> Vec<IpNetwork> {
        let width = Self::width(self.v6);
        let mut networks = Vec::new();
        for &(start, end) in &self.ranges {
            let mut from = start;
            loop {
                // Largest aligned block starting at `from` that ends by `end`
                let mut host_bits = if from == 0 {
                    width
                } else {
                    from.trailing_zeros().min(width)
                };
                while block_end(from, host_bits) > end {
                    host_bits -= 1;
                }
                // `host_bits <= width <= 128`, so the prefix fits in a u8
                let prefix = u8::try_from(width - host_bits).unwrap_or(0);
                networks.push(make_network(from, prefix, self.v6));
                let last = block_end(from, host_bits);
                if last >= end {
                    break;
                }
                from = last + 1;
            }
        }
        networks
    }
}

/// Last address of the aligned block of `2^host_bits` addresses at `from`.
fn block_end(from: u128, host_bits: u32) -> u128 {
    if host_bits >= 128 {
        u128::MAX
    } else {
        from | ((1u128 << host_bits) - 1)
    }
}

/// Inclusive address range of a network (its host bits ignored).
fn network_range(network: &IpNetwork) -> (u128, u128) {
    let (value, width) = match network.ip() {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32),
        IpAddr::V6(v6) => (u128::from(v6), 128),
    };
    let host_bits = width - u32::from(network.prefix());
    let start = if host_bits >= 128 {
        0
    } else {
        value & !((1u128 << host_bits) - 1)
    };
    (start, block_end(start, host_bits))
}

/// Merges sorted ranges that overlap or touch.
fn merge_sorted(ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    merged
}

/// The numeric value of `addr` in the given family, if it belongs to it.
fn addr_value(addr: IpAddr, v6: bool) -> Option<u128> {
    match (addr, v6) {
        (IpAddr::V4(v4), false) => Some(u128::from(u32::from(v4))),
        (IpAddr::V6(v6addr), true) => Some(u128::from(v6addr)),
        _ => None,
    }
}

fn make_network(value: u128, prefix: u8, v6: bool) -> IpNetwork {
    if v6 {
        IpNetwork::V6(
            Ipv6Network::new(Ipv6Addr::from(value), prefix)
                .unwrap_or_else(|_| Ipv6Network::from(Ipv6Addr::UNSPECIFIED)),
        )
    } else {
        // `value` is an IPv4 address (at most u32::MAX) and `prefix <= 32`
        let addr = Ipv4Addr::from(u32::try_from(value).unwrap_or(u32::MAX));
        IpNetwork::V4(Ipv4Network::new(addr, prefix).unwrap_or_else(|_| Ipv4Network::from(addr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(list: &[&str]) -> Vec<IpNetwork> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn set(v6: bool, list: &[&str]) -> AddrSet {
        AddrSet::from_networks(v6, &nets(list))
    }

    fn shown(set: &AddrSet) -> Vec<String> {
        set.to_networks().iter().map(ToString::to_string).collect()
    }

    #[test]
    fn test_networks_round_trip_and_merge() {
        let s = set(false, &["10.0.0.0/25", "10.0.0.128/25", "192.168.1.7/24"]);
        assert_eq!(shown(&s), ["10.0.0.0/24", "192.168.1.0/24"]);
        assert!(s.contains("10.0.0.200".parse().unwrap()));
        assert!(!s.contains("10.0.1.0".parse().unwrap()));
        assert!(!s.contains("::1".parse().unwrap()), "other family");
        assert_eq!(shown(&AddrSet::full(false)), ["0.0.0.0/0"]);
        assert_eq!(shown(&AddrSet::full(true)), ["::/0"]);
        assert!(set(true, &["::/0"]).is_full());
        assert!(set(true, &["10.0.0.0/8"]).is_empty(), "IPv4 ignored");
    }

    #[test]
    fn test_difference_and_complement() {
        let all = AddrSet::full(false);
        let ten = set(false, &["10.0.0.0/8"]);
        let rest = all.difference(&ten);
        assert!(!rest.contains("10.1.2.3".parse().unwrap()));
        assert!(rest.contains("11.0.0.0".parse().unwrap()));
        assert_eq!(rest.complement(), ten);
        assert_eq!(rest.union(&ten), all);
        assert!(rest.intersection(&ten).is_empty());
        assert_eq!(
            shown(&rest).len(),
            8,
            "0/5 8/7 11/8 12/6 16/4 32/3 64/2 128/1"
        );

        let v6 = AddrSet::full(true).difference(&set(true, &["::/1"]));
        assert_eq!(shown(&v6), ["8000::/1"]);
        assert!(AddrSet::full(true).complement().is_empty());
        assert!(AddrSet::empty(true).complement().is_full());
    }

    #[test]
    fn test_odd_ranges_decompose_exactly() {
        let s = set(false, &["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/32"]);
        assert_eq!(shown(&s), ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/32"]);
        let top = set(false, &["255.255.255.255/32"]);
        assert_eq!(shown(&top.complement()).len(), 32);
    }
}
