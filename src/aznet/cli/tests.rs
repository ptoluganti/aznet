use super::*;

#[test]
fn prefix_forms() {
    assert_eq!(parse_prefix("/27"), Ok(27));
    assert_eq!(parse_prefix("28"), Ok(28));
    assert!(parse_prefix("/30").is_err());
    assert!(parse_prefix("abc").is_err());
}

#[test]
fn names_reject_kql_metacharacters() {
    assert!(parse_vnet_name("vnet-hub-01").is_ok());
    assert!(parse_vnet_name("x' | project *").is_err());
    assert!(parse_resource_group("rg-net(prod)").is_ok());
    assert!(parse_resource_group("rg' or 1==1").is_err());
}

#[test]
fn new_args_validation() {
    assert!(parse_project_name("platform-infra_01").is_ok());
    assert!(parse_project_name("Platform").is_err());
    assert!(parse_project_name("-x").is_err());
    assert!(parse_description("Hub networking").is_ok());
    assert!(parse_description("say \"hi\"").is_err());
    assert!(parse_version("1.13.3").is_ok());
    assert!(parse_version("~> 1.13").is_err());
}
