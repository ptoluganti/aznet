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

#[test]
fn filter_reports_unknown_subscription() {
    let subs = vec![Subscription {
        subscription_id: "11111111-1111-1111-1111-111111111111".into(),
        display_name: "Prod".into(),
        state: "Enabled".into(),
    }];
    assert_eq!(
        filter_subscriptions(subs.clone(), &["prod".into()])
            .unwrap()
            .len(),
        1
    );
    assert!(filter_subscriptions(subs, &["dev".into()]).is_err());
}

#[test]
fn kql_string_escapes_quotes_and_backslashes() {
    assert_eq!(kql_string("plain"), "'plain'");
    assert_eq!(kql_string("it's"), r"'it\'s'");
    assert_eq!(kql_string(r"a\b"), r"'a\\b'");
    // A trailing backslash must not escape the closing quote.
    assert_eq!(kql_string(r"x\"), r"'x\\'");
}

#[test]
fn policy_query_matches_name_or_id() {
    let q = policy_states_query(&PolicyStateFilter {
        policy_definition: Some("06a78e20-9358-41c9-923c-fb736d382a4d"),
        policy_assignment: Some(
            "/subscriptions/s/providers/Microsoft.Authorization/policyAssignments/baseline",
        ),
        ..Default::default()
    });
    assert!(q.contains("where policyDefinitionName =~ '06a78e20-9358-41c9-923c-fb736d382a4d'"));
    assert!(q.contains(
        "where policyAssignmentId =~ '/subscriptions/s/providers/Microsoft.Authorization/policyAssignments/baseline'"
    ));
    assert!(!q.contains("resourceId in~"));
    assert!(!q.contains("!~ 'Compliant'"));
    assert!(q.contains("project id,"), "Resource Graph paging needs id");
}

#[test]
fn policy_query_filters_resources_group_and_state() {
    let ids = vec!["/subscriptions/s/resourceGroups/rg/providers/A/b/one".to_string()];
    let q = policy_states_query(&PolicyStateFilter {
        policy_assignment: Some("baseline"),
        resource_ids: &ids,
        resource_group: Some("rg-app"),
        non_compliant_only: true,
        ..Default::default()
    });
    assert!(
        q.contains("where resourceId in~ ('/subscriptions/s/resourceGroups/rg/providers/A/b/one')")
    );
    assert!(q.contains("where resourceGroup =~ 'rg-app'"));
    assert!(q.contains("where complianceState !~ 'Compliant'"));
}

#[test]
fn policy_query_keeps_injection_inside_the_literal() {
    let q = policy_states_query(&PolicyStateFilter {
        policy_assignment: Some("x' or 1==1 | project secrets //"),
        ..Default::default()
    });
    assert!(q.contains(r"=~ 'x\' or 1==1 | project secrets //'"));
}

#[test]
fn deserialises_policy_state_row() {
    let raw = r#"{
      "id": "/subscriptions/s/providers/Microsoft.PolicyInsights/policyStates/x",
      "subscriptionId": "s",
      "resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1",
      "resourceGroup": "rg",
      "complianceState": "NonCompliant",
      "policyAssignmentName": "baseline",
      "policyAssignmentId": "/subscriptions/s/providers/Microsoft.Authorization/policyAssignments/baseline",
      "policyDefinitionName": "def",
      "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/def",
      "resourceType": "Microsoft.Storage/storageAccounts",
      "effect": "audit",
      "policyDefinitionReferenceId": "",
      "policySetDefinitionName": "",
      "timestamp": "2026-10-14T08:15:42.123Z"
    }"#;
    let s: PolicyState = serde_json::from_str(raw).unwrap();
    assert_eq!(s.compliance_state, "NonCompliant");
    assert_eq!(s.effect, "audit");
}
