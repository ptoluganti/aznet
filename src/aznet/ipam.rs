//! Pure IPv4 address-management maths. No I/O, fully unit-tested.
//!
//! All ranges are inclusive `(first, last)` in `u64` so a /0 never overflows.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Smallest IPv4 subnet Azure accepts.
pub const AZURE_MIN_SUBNET_PREFIX: u8 = 29;
/// Addresses Azure reserves in every subnet (network, gateway, 2x DNS, broadcast).
pub const AZURE_RESERVED_PER_SUBNET: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Cidr {
    network: u32,
    prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrParseError(String);

impl fmt::Display for CidrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IPv4 CIDR '{}'", self.0)
    }
}
impl std::error::Error for CidrParseError {}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

impl Ipv4Cidr {
    /// Builds a CIDR, normalising host bits away (10.0.0.5/24 -> 10.0.0.0/24).
    pub fn new(addr: u32, prefix: u8) -> Option<Self> {
        (prefix <= 32).then(|| Self {
            network: addr & mask(prefix),
            prefix,
        })
    }
    pub fn prefix(&self) -> u8 {
        self.prefix
    }
    pub fn size(&self) -> u64 {
        1u64 << (32 - self.prefix)
    }
    pub fn first(&self) -> u64 {
        self.network as u64
    }
    pub fn last(&self) -> u64 {
        self.first() + self.size() - 1
    }
}

impl FromStr for Ipv4Cidr {
    type Err = CidrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || CidrParseError(s.to_string());
        let (ip, len) = s.trim().split_once('/').ok_or_else(err)?;
        let ip: Ipv4Addr = ip.parse().map_err(|_| err())?;
        let len: u8 = len.parse().map_err(|_| err())?;
        Self::new(u32::from(ip), len).ok_or_else(err)
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.network), self.prefix)
    }
}

/// Gaps inside `space` not covered by any of `used` (which may overlap or lie outside `space`).
pub fn free_ranges(space: Ipv4Cidr, used: &[Ipv4Cidr]) -> Vec<(u64, u64)> {
    let (lo, hi) = (space.first(), space.last());
    let mut taken: Vec<(u64, u64)> = used
        .iter()
        .filter_map(|c| {
            let (a, b) = (c.first().max(lo), c.last().min(hi));
            (a <= b).then_some((a, b))
        })
        .collect();
    taken.sort_unstable();

    let mut free = Vec::new();
    let mut cursor = lo;
    for (a, b) in taken {
        if a > cursor {
            free.push((cursor, a - 1));
        }
        cursor = cursor.max(b + 1);
    }
    if cursor <= hi {
        free.push((cursor, hi));
    }
    free
}

/// Lowest-address, correctly aligned block of `prefix` that fits in a free range.
pub fn first_fit(free: &[(u64, u64)], prefix: u8) -> Option<Ipv4Cidr> {
    let size = 1u64 << (32 - prefix);
    free.iter().find_map(|&(a, b)| {
        let start = (a + size - 1) & !(size - 1);
        (start + size - 1 <= b).then_some(Ipv4Cidr {
            network: start as u32,
            prefix,
        })
    })
}

/// Minimal set of aligned CIDR blocks exactly covering `[a, b]`.
pub fn range_to_cidrs(a: u64, b: u64) -> Vec<Ipv4Cidr> {
    let mut out = Vec::new();
    let mut cur = a;
    while cur <= b {
        let mut bits = if cur == 0 {
            32
        } else {
            cur.trailing_zeros().min(32)
        };
        while bits > 0 && cur + (1u64 << bits) - 1 > b {
            bits -= 1;
        }
        out.push(Ipv4Cidr {
            network: cur as u32,
            prefix: (32 - bits) as u8,
        });
        cur += 1u64 << bits;
    }
    out
}

/// Outcome for a single address space, evaluated independently of the VNet's other ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceAllocation {
    pub space: Ipv4Cidr,
    /// First aligned block of the requested size inside this space, if any.
    pub next_available: Option<Ipv4Cidr>,
    /// Largest block that could still become an Azure subnet (lowest address on ties).
    pub largest_free: Option<Ipv4Cidr>,
    /// All free blocks >= /29, address order.
    pub free_blocks: Vec<Ipv4Cidr>,
    /// Addresses in those usable blocks (fragments smaller than /29 are excluded).
    pub usable_free_addresses: u64,
}

pub fn allocate_in_space(space: Ipv4Cidr, used: &[Ipv4Cidr], prefix: u8) -> SpaceAllocation {
    let free = free_ranges(space, used);
    let next_available = if space.prefix() <= prefix {
        first_fit(&free, prefix)
    } else {
        None
    };
    let free_blocks: Vec<Ipv4Cidr> = free
        .into_iter()
        .flat_map(|(a, b)| range_to_cidrs(a, b))
        .filter(|c| c.prefix() <= AZURE_MIN_SUBNET_PREFIX)
        .collect();
    SpaceAllocation {
        space,
        next_available,
        largest_free: largest(&free_blocks),
        usable_free_addresses: free_blocks.iter().map(Ipv4Cidr::size).sum(),
        free_blocks,
    }
}

/// Each address space in declared order, allocated independently.
pub fn per_space(spaces: &[Ipv4Cidr], used: &[Ipv4Cidr], prefix: u8) -> Vec<SpaceAllocation> {
    spaces
        .iter()
        .map(|&s| allocate_in_space(s, used, prefix))
        .collect()
}

fn largest(blocks: &[Ipv4Cidr]) -> Option<Ipv4Cidr> {
    blocks
        .iter()
        .min_by_key(|c| (c.prefix(), c.first()))
        .copied()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allocation {
    Available(Ipv4Cidr),
    Exhausted {
        /// Largest block that could still become an Azure subnet (lowest address on ties).
        largest_free: Option<Ipv4Cidr>,
        /// All free blocks >= /29, address order.
        free_blocks: Vec<Ipv4Cidr>,
        /// Addresses in those usable blocks (fragments smaller than /29 are excluded).
        usable_free_addresses: u64,
    },
}

/// First-fit across address spaces in declared order.
pub fn next_available(spaces: &[Ipv4Cidr], used: &[Ipv4Cidr], prefix: u8) -> Allocation {
    let mut blocks = Vec::new();
    for &space in spaces {
        let a = allocate_in_space(space, used, prefix);
        if let Some(c) = a.next_available {
            return Allocation::Available(c);
        }
        blocks.extend(a.free_blocks);
    }
    blocks.sort_unstable_by_key(|c| c.first());
    Allocation::Exhausted {
        largest_free: largest(&blocks),
        usable_free_addresses: blocks.iter().map(Ipv4Cidr::size).sum(),
        free_blocks: blocks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Ipv4Cidr {
        s.parse().unwrap()
    }
    fn cs(v: &[&str]) -> Vec<Ipv4Cidr> {
        v.iter().map(|s| c(s)).collect()
    }

    #[test]
    fn parse_and_normalise() {
        assert_eq!(c("10.0.0.5/24").to_string(), "10.0.0.0/24");
        assert!("10.0.0.0/33".parse::<Ipv4Cidr>().is_err());
        assert!("10.0.0.0".parse::<Ipv4Cidr>().is_err());
        assert!("fd00::/64".parse::<Ipv4Cidr>().is_err());
        assert_eq!(c("0.0.0.0/0").last(), u32::MAX as u64);
    }

    #[test]
    fn empty_vnet_returns_first_block() {
        let r = next_available(&cs(&["10.0.0.0/24"]), &[], 27);
        assert_eq!(r, Allocation::Available(c("10.0.0.0/27")));
    }

    #[test]
    fn respects_alignment_after_odd_sized_subnet() {
        // /28 used at .0 -> a /27 must start at .32, not .16
        let r = next_available(&cs(&["10.0.0.0/24"]), &cs(&["10.0.0.0/28"]), 27);
        assert_eq!(r, Allocation::Available(c("10.0.0.32/27")));
        // but a /28 fills the hole at .16
        let r = next_available(&cs(&["10.0.0.0/24"]), &cs(&["10.0.0.0/28"]), 28);
        assert_eq!(r, Allocation::Available(c("10.0.0.16/28")));
    }

    #[test]
    fn fills_gaps_first() {
        let used = cs(&["10.0.0.0/27", "10.0.0.64/27"]);
        let r = next_available(&cs(&["10.0.0.0/24"]), &used, 27);
        assert_eq!(r, Allocation::Available(c("10.0.0.32/27")));
    }

    #[test]
    fn falls_through_to_second_address_space() {
        let spaces = cs(&["10.0.0.0/26", "10.1.0.0/24"]);
        let used = cs(&["10.0.0.0/26"]);
        let r = next_available(&spaces, &used, 27);
        assert_eq!(r, Allocation::Available(c("10.1.0.0/27")));
    }

    #[test]
    fn per_space_reports_next_block_in_every_range() {
        let spaces = cs(&["10.0.0.0/26", "10.1.0.0/24", "10.2.0.0/28"]);
        let used = cs(&["10.0.0.0/26", "10.1.0.0/27"]);
        let r = per_space(&spaces, &used, 27);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].space, c("10.0.0.0/26"));
        assert_eq!(r[0].next_available, None);
        assert_eq!(r[0].largest_free, None);
        assert_eq!(r[1].next_available, Some(c("10.1.0.32/27")));
        // range smaller than the request: nothing fits, but its free block is still advised
        assert_eq!(r[2].next_available, None);
        assert_eq!(r[2].largest_free, Some(c("10.2.0.0/28")));
    }

    #[test]
    fn space_smaller_than_request_is_skipped() {
        let r = next_available(&cs(&["10.0.0.0/28", "10.2.0.0/24"]), &[], 27);
        assert_eq!(r, Allocation::Available(c("10.2.0.0/27")));
    }

    #[test]
    fn exhausted_reports_largest_and_blocks() {
        // /24 fully used except .224/28 and .248/29
        let used = cs(&[
            "10.0.0.0/25",
            "10.0.0.128/26",
            "10.0.0.192/27",
            "10.0.0.240/29",
        ]);
        match next_available(&cs(&["10.0.0.0/24"]), &used, 27) {
            Allocation::Exhausted {
                largest_free,
                free_blocks,
                usable_free_addresses,
            } => {
                assert_eq!(largest_free, Some(c("10.0.0.224/28")));
                assert_eq!(free_blocks, cs(&["10.0.0.224/28", "10.0.0.248/29"]));
                assert_eq!(usable_free_addresses, 24);
            }
            other => panic!("expected exhausted, got {other:?}"),
        }
    }

    #[test]
    fn fragments_below_azure_minimum_are_not_advised() {
        // only a /30 left: nothing Azure can use
        let used = cs(&["10.0.0.0/30"]);
        match next_available(&cs(&["10.0.0.0/29"]), &used, 28) {
            Allocation::Exhausted {
                largest_free,
                usable_free_addresses,
                ..
            } => {
                assert_eq!(largest_free, None);
                assert_eq!(usable_free_addresses, 0);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn overlapping_and_outside_subnets_are_tolerated() {
        let used = cs(&["10.0.0.0/27", "10.0.0.16/28", "192.168.0.0/24"]);
        let r = next_available(&cs(&["10.0.0.0/24"]), &used, 27);
        assert_eq!(r, Allocation::Available(c("10.0.0.32/27")));
    }

    #[test]
    fn range_decomposition_is_minimal() {
        let v = range_to_cidrs(c("10.0.0.8/29").first(), c("10.0.0.32/27").last());
        assert_eq!(v, cs(&["10.0.0.8/29", "10.0.0.16/28", "10.0.0.32/27"]));
    }
}
