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
fn policy_query_filters_by_resolved_ids() {
    let assignments = vec![
        "/subscriptions/s/providers/Microsoft.Authorization/policyAssignments/baseline".to_string(),
    ];
    let definitions =
        vec!["/providers/Microsoft.Authorization/policySetDefinitions/mcsb".to_string()];
    let q = policy_states_query(&PolicyStateFilter {
        assignment_ids: &assignments,
        definition_ids: &definitions,
        ..Default::default()
    });
    assert!(q.contains(
        "where policyAssignmentId in~ ('/subscriptions/s/providers/Microsoft.Authorization/policyAssignments/baseline')"
    ));
    // A definition selector also matches states reached through an initiative.
    assert!(q.contains(
        "where policyDefinitionId in~ ('/providers/Microsoft.Authorization/policySetDefinitions/mcsb') \
         or policySetDefinitionId in~ ('/providers/Microsoft.Authorization/policySetDefinitions/mcsb')"
    ));
    assert!(!q.contains("resourceId in~"));
    assert!(!q.contains("join"));
    assert!(q.contains("project id,"), "Resource Graph paging needs id");
}

#[test]
fn policy_query_filters_resources_group_and_state() {
    let ids = vec!["/subscriptions/s/resourceGroups/rg/providers/A/b/one".to_string()];
    let q = policy_states_query(&PolicyStateFilter {
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
fn policy_query_joins_tags_case_insensitively() {
    let tags = vec![
        TagFilter {
            key: "Env".into(),
            value: Some("Prod".into()),
        },
        TagFilter {
            key: "CostCentre".into(),
            value: None,
        },
    ];
    let q = policy_states_query(&PolicyStateFilter {
        tags: &tags,
        ..Default::default()
    });
    assert!(q.contains("join kind=inner (resources | union resourcecontainers"));
    assert!(
        q.contains("resourceTags = tags"),
        "must not reuse policyresources' own tags column"
    );
    assert!(q.contains("where tostring(lowerTags['env']) == 'prod'"));
    assert!(q.contains("where isnotnull(lowerTags['costcentre'])"));
    assert!(q.contains(", tags = resourceTags"));
}

#[test]
fn pairs_query_ignores_policy_ids_and_summarises() {
    let assignments = vec!["/x/policyAssignments/a".to_string()];
    let q = policy_pairs_query(&PolicyStateFilter {
        assignment_ids: &assignments,
        resource_group: Some("rg"),
        ..Default::default()
    });
    assert!(!q.contains("policyAssignmentId in~"));
    assert!(q.contains("where resourceGroup =~ 'rg'"));
    assert!(q.ends_with(
        "summarize states = count() by policyAssignmentId, policyDefinitionId, policySetDefinitionId"
    ));
}

#[test]
fn policy_query_keeps_injection_inside_the_literal() {
    let ids = vec!["x' or 1==1 | project secrets //".to_string()];
    let tags = vec![TagFilter {
        key: "k'] | take 1 //".into(),
        value: Some("v' or true".into()),
    }];
    let q = policy_states_query(&PolicyStateFilter {
        assignment_ids: &ids,
        tags: &tags,
        ..Default::default()
    });
    assert!(q.contains(r"in~ ('x\' or 1==1 | project secrets //')"));
    assert!(q.contains(r"lowerTags['k\'] | take 1 //']) == 'v\' or true'"));
}

#[test]
fn only_plain_arm_paths_are_fetched() {
    assert!(is_plain_arm_path(
        "/providers/microsoft.authorization/policydefinitions/aaaa"
    ));
    for bad in [
        "providers/x",
        "/providers/x?api-version=1",
        "/providers/../x",
        "/a#b",
        r"/a\b",
    ] {
        assert!(!is_plain_arm_path(bad), "{bad} should be rejected");
    }
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

#[test]
fn policy_query_matches_resource_names_or_ids() {
    let ids = vec!["/subscriptions/s/resourceGroups/rg/providers/A/b/one".to_string()];
    let names = vec!["vm1".to_string(), "st1".to_string()];
    let q = policy_states_query(&PolicyStateFilter {
        resource_ids: &ids,
        resource_names: &names,
        ..Default::default()
    });
    assert!(q.contains(
        "where resourceId in~ ('/subscriptions/s/resourceGroups/rg/providers/A/b/one') \
         or extract('[^/]+$', 0, resourceId) in~ ('vm1', 'st1')"
    ));
}
