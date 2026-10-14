use super::*;

#[test]
fn deserialises_single_and_dual_stack_subnets() {
    let raw = r#"{
      "name": "vnet-hub",
      "properties": {
        "addressSpace": { "addressPrefixes": ["10.0.0.0/24", "fd00:db8::/48"] },
        "subnets": [
          { "name": "a", "properties": { "addressPrefix": "10.0.0.0/27" } },
          { "name": "b", "properties": { "addressPrefixes": ["10.0.0.32/28", "fd00:db8::/64"] } },
          { "name": "c", "properties": {} }
        ]
      }
    }"#;
    let v: Vnet = serde_json::from_str(raw).unwrap();
    let all: Vec<&str> = v
        .properties
        .subnets
        .iter()
        .flat_map(Subnet::prefixes)
        .collect();
    assert_eq!(all, ["10.0.0.0/27", "10.0.0.32/28", "fd00:db8::/64"]);
}
