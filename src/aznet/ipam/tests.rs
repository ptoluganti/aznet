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
