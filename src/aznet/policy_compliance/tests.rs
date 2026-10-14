use super::*;
use crate::aznet::policy_report::Scope;

const VM: &str = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm1";
const SA: &str = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/st1";
const ASSIGNMENT: &str = "/subscriptions/11111111-1111-1111-1111-111111111111/providers/microsoft.authorization/policyassignments/baseline";
const DEF_A: &str = "/providers/microsoft.authorization/policydefinitions/aaaa";
const DEF_B: &str = "/providers/microsoft.authorization/policydefinitions/bbbb";
const INITIATIVE: &str = "/providers/microsoft.authorization/policysetdefinitions/mcsb";

fn state(resource_id: &str, compliance: &str, reference: &str) -> PolicyState {
    PolicyState {
        subscription_id: "11111111-1111-1111-1111-111111111111".into(),
        resource_id: resource_id.into(),
        resource_type: String::new(),
        resource_group: "rg-app".into(),
        compliance_state: compliance.into(),
        effect: "audit".into(),
        policy_assignment_name: "baseline".into(),
        policy_assignment_id: ASSIGNMENT.into(),
        policy_definition_name: "aaaa".into(),
        policy_definition_id: DEF_A.into(),
        policy_definition_reference_id: reference.into(),
        policy_set_definition_name: String::new(),
        policy_set_definition_id: String::new(),
        timestamp: "2026-10-14T08:15:42Z".into(),
        tags: None,
    }
}

fn pair(assignment: &str, definition: &str, set: &str) -> PolicyPair {
    PolicyPair {
        policy_assignment_id: assignment.into(),
        policy_definition_id: definition.into(),
        policy_set_definition_id: set.into(),
    }
}

fn sub_names() -> HashMap<String, String> {
    HashMap::from([("11111111-1111-1111-1111-111111111111".into(), "Prod".into())])
}

fn report(s: Summary) -> ComplianceReport {
    ComplianceReport {
        account: String::new(),
        auth_method: String::new(),
        tenant_id: String::new(),
        subscriptions_scanned: 1,
        scope: Scope {
            policy_definition: None,
            policy_assignment: Some("baseline".into()),
            resource_group: None,
            tags: vec![],
            non_compliant_only: false,
        },
        assignments: s.assignments,
        policy_states: s.rows.len(),
        resources: s.resources,
        compliant_resources: s.compliant_resources,
        non_compliant_resources: s.non_compliant_resources,
        non_compliant_resource_ids: s.non_compliant_resource_ids,
        resources_without_state: s.resources_without_state,
        results: s.rows,
    }
}

#[test]
fn passing_states() {
    assert!(is_passing("Compliant"));
    assert!(is_passing("exempt"));
    assert!(is_passing("Protected"));
    assert!(!is_passing("NonCompliant"));
    assert!(!is_passing("Conflicting"));
    assert!(!is_passing("Unknown"));
}

#[test]
fn matches_by_name_or_full_id_case_insensitively() {
    let candidates = vec![ASSIGNMENT.to_string(), "/x/policyassignments/other".into()];
    assert_eq!(match_name_or_id("Baseline", &candidates), vec![ASSIGNMENT]);
    assert_eq!(
        match_name_or_id(&format!("{}/", ASSIGNMENT.to_uppercase()), &candidates),
        vec![ASSIGNMENT]
    );
    // A display name doesn't match by name, so resolution falls through to display names.
    assert!(match_name_or_id("Baseline security", &candidates).is_empty());
}

#[test]
fn matches_by_display_name() {
    let candidates = vec![DEF_A.to_string(), DEF_B.to_string()];
    let mut names = DisplayNames::default();
    names.insert(
        DEF_A,
        "Storage accounts should restrict network access".into(),
    );
    names.insert(DEF_B, String::new()); // lookup failed
    assert_eq!(
        match_display_name(
            " storage ACCOUNTS should restrict network access ",
            &candidates,
            &names
        ),
        vec![DEF_A]
    );
    assert!(match_display_name("Something else", &candidates, &names).is_empty());
}

#[test]
fn definition_candidates_include_initiatives_within_assignments() {
    let other = "/subscriptions/x/providers/microsoft.authorization/policyassignments/other";
    let pairs = vec![
        pair(ASSIGNMENT, DEF_A, INITIATIVE),
        pair(ASSIGNMENT, DEF_B, INITIATIVE),
        pair(
            other,
            "/providers/microsoft.authorization/policydefinitions/cccc",
            "",
        ),
    ];
    assert_eq!(
        definition_candidates(&pairs, &[ASSIGNMENT.to_uppercase()]),
        vec![DEF_A, DEF_B, INITIATIVE]
    );
    assert_eq!(definition_candidates(&pairs, &[]).len(), 4);
}

#[test]
fn resource_fails_if_any_initiative_member_fails() {
    let mut names = DisplayNames::default();
    names.insert(ASSIGNMENT, "Baseline security".into());
    names.insert(DEF_A, "Audit VMs".into());
    let s = summarise(
        vec![
            state(VM, "Compliant", "ref-a"),
            state(VM, "NonCompliant", "ref-b"),
            state(SA, "Compliant", "ref-a"),
        ],
        &sub_names(),
        &[],
        &names,
    );
    assert_eq!(s.resources, 2);
    assert_eq!(s.compliant_resources, 1);
    assert_eq!(s.non_compliant_resources, 1);
    assert_eq!(s.non_compliant_resource_ids, vec![VM]);
    assert_eq!(s.assignments.len(), 1);
    assert_eq!(s.assignments[0].display_name, "Baseline security");
    assert_eq!(s.rows[0].subscription_name, "Prod");
    assert_eq!(s.rows[0].policy_definition_display_name, "Audit VMs");
    assert_eq!(exit_code(&report(s)), exit::NON_COMPLIANT);
}

#[test]
fn requested_resources_match_case_insensitively_and_report_missing() {
    let missing = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-app/providers/Microsoft.Web/sites/app1";
    let s = summarise(
        vec![state(VM, "Compliant", "")],
        &sub_names(),
        &[VM.to_uppercase(), missing.into()],
        &DisplayNames::default(),
    );
    assert_eq!(s.resources_without_state, vec![missing.to_string()]);
    assert_eq!(exit_code(&report(s)), exit::NO_STATE);
}

#[test]
fn exit_codes() {
    let names = DisplayNames::default();
    let all_ok = summarise(
        vec![state(VM, "Compliant", "")],
        &sub_names(),
        &[VM.into()],
        &names,
    );
    assert_eq!(exit_code(&report(all_ok)), exit::ALL_COMPLIANT);
    let nothing = summarise(vec![], &sub_names(), &[], &names);
    assert_eq!(exit_code(&report(nothing)), exit::NO_STATE);
}

#[test]
fn resources_match_by_name_or_id() {
    assert!(resource_matches("VM1", VM));
    assert!(resource_matches(&VM.to_uppercase(), VM));
    assert!(!resource_matches("vm", VM));
    assert!(!resource_matches("rg-app", VM));
}

#[test]
fn requested_names_without_state_are_reported() {
    let s = summarise(
        vec![state(VM, "NonCompliant", "")],
        &sub_names(),
        &["vm1".into(), "st-missing".into()],
        &DisplayNames::default(),
    );
    assert_eq!(s.resources_without_state, vec!["st-missing".to_string()]);
    // Non-compliance outranks a missing resource.
    assert_eq!(exit_code(&report(s)), exit::NON_COMPLIANT);
}
