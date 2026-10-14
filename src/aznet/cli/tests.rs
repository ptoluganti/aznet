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

#[test]
fn resource_ids_must_be_full_ids() {
    let id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1";
    assert_eq!(parse_resource_id(&format!("{id}/")), Ok(id.to_string()));
    assert!(parse_resource_id("st1").is_err());
    assert!(parse_resource_id("/subscriptions/s/x\ny").is_err());
}

#[test]
fn policy_compliance_needs_a_definition_or_assignment() {
    let parse = |extra: &[&str]| {
        Cli::try_parse_from([&["aznet", "check-policy-compliance"], extra].concat())
    };
    assert!(parse(&[]).is_err());
    assert!(parse(&["-a", "baseline"]).is_ok());
    assert!(parse(&["-d", "def", "-a", "baseline", "-r", "/subscriptions/s/rg"]).is_ok());
}

#[test]
fn auth_flags_unchanged_for_get_next_subnet() {
    let cli = Cli::try_parse_from([
        "aznet",
        "get-next-subnet",
        "-n",
        "vnet",
        "-g",
        "rg",
        "-p",
        "27",
        "--auth",
        "cli",
        "--tenant",
        "t",
    ])
    .unwrap();
    let Command::GetNextSubnet(a) = cli.command else {
        panic!("wrong command")
    };
    assert_eq!(a.auth.method, AuthMethod::Cli);
    assert_eq!(a.auth.tenant.as_deref(), Some("t"));
}

#[test]
fn resource_id_explains_git_bash_path_rewrite() {
    let err = parse_resource_id("C:/Program Files/Git/subscriptions/s").unwrap_err();
    assert!(err.contains("MSYS_NO_PATHCONV"));
}
