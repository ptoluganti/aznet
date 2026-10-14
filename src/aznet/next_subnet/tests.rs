use super::*;

fn vref() -> VnetRef {
    VnetRef {
        id: "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v"
            .into(),
        name: "v".into(),
        resource_group: "rg".into(),
        subscription_id: "x".into(),
        location: "uksouth".into(),
    }
}

fn vnet(json: &str) -> Vnet {
    serde_json::from_str(json).unwrap()
}

#[test]
fn evaluates_available_and_ignores_ipv6() {
    let v = vnet(
        r#"{"name":"v","properties":{
        "addressSpace":{"addressPrefixes":["fd00::/48","10.0.0.0/24"]},
        "subnets":[{"name":"a","properties":{"addressPrefixes":["10.0.0.0/27","fd00::/64"]}}]}}"#,
    );
    let r = evaluate(&vref(), "sub".into(), &v, 27);
    assert_eq!(r.status, Status::Available);
    assert_eq!(r.next_available.as_deref(), Some("10.0.0.32/27"));
    assert_eq!(r.subnet_count, 1);
}

#[test]
fn evaluates_exhausted_with_advice() {
    let v = vnet(
        r#"{"name":"v","properties":{
        "addressSpace":{"addressPrefixes":["10.0.0.0/26"]},
        "subnets":[{"name":"a","properties":{"addressPrefix":"10.0.0.0/27"}},
                   {"name":"b","properties":{"addressPrefix":"10.0.0.32/28"}}]}}"#,
    );
    let r = evaluate(&vref(), "sub".into(), &v, 27);
    assert_eq!(r.status, Status::Exhausted);
    assert_eq!(r.largest_free.as_deref(), Some("10.0.0.48/28"));
}

#[test]
fn evaluates_each_address_space() {
    let v = vnet(
        r#"{"name":"v","properties":{
        "addressSpace":{"addressPrefixes":["10.0.0.0/26","10.1.0.0/24"]},
        "subnets":[{"name":"a","properties":{"addressPrefix":"10.0.0.0/27"}},
                   {"name":"b","properties":{"addressPrefix":"10.1.0.0/27"}}]}}"#,
    );
    let r = evaluate(&vref(), "sub".into(), &v, 27);
    assert_eq!(r.next_available.as_deref(), Some("10.0.0.32/27"));
    let next: Vec<_> = r
        .spaces
        .iter()
        .map(|s| s.next_available.as_deref())
        .collect();
    assert_eq!(next, [Some("10.0.0.32/27"), Some("10.1.0.32/27")]);
}
