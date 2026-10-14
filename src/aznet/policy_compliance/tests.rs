use super::*;
use crate::aznet::policy_report::Scope;

const VM: &str = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm1";
const SA: &str = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/st1";

fn state(resource_id: &str, compliance: &str, reference: &str) -> PolicyState {
    PolicyState {
        subscription_id: "11111111-1111-1111-1111-111111111111".into(),
        resource_id: resource_id.into(),
        resource_type: String::new(),
        resource_group: "rg-app".into(),
        compliance_state: compliance.into(),
        effect: "audit".into(),
        policy_assignment_name: "baseline".into(),
        policy_assignment_id:
            "/subscriptions/x/providers/Microsoft.Authorization/policyAssignments/baseline".into(),
        policy_definition_name: "def".into(),
        policy_definition_id: "/providers/Microsoft.Authorization/policyDefinitions/def".into(),
        policy_definition_reference_id: reference.into(),
        policy_set_definition_name: String::new(),
        timestamp: "2026-10-14T08:15:42.123Z".into(),
    }
}

fn names() -> HashMap<String, String> {
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
            non_compliant_only: false,
        },
        policy_states: s.rows.len(),
        resources: s.resources,
        compliant_resources: s.compliant_resources,
        non_compliant_resources: s.non_compliant_resources,
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
fn resource_fails_if_any_initiative_member_fails() {
    let s = summarise(
        vec![
            state(VM, "Compliant", "ref-a"),
            state(VM, "NonCompliant", "ref-b"),
            state(SA, "Compliant", "ref-a"),
        ],
        &names(),
        &[],
    );
    assert_eq!(s.resources, 2);
    assert_eq!(s.compliant_resources, 1);
    assert_eq!(s.non_compliant_resources, 1);
    assert_eq!(s.rows[0].subscription_name, "Prod");
    assert_eq!(exit_code(&report(s)), exit::NON_COMPLIANT);
}

#[test]
fn requested_resources_match_case_insensitively_and_report_missing() {
    let missing = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-app/providers/Microsoft.Web/sites/app1";
    let s = summarise(
        vec![state(VM, "Compliant", "")],
        &names(),
        &[VM.to_uppercase(), missing.into()],
    );
    assert_eq!(s.resources_without_state, vec![missing.to_string()]);
    assert_eq!(exit_code(&report(s)), exit::NO_STATE);
}

#[test]
fn exit_codes() {
    let all_ok = summarise(vec![state(VM, "Compliant", "")], &names(), &[VM.into()]);
    assert_eq!(exit_code(&report(all_ok)), exit::ALL_COMPLIANT);
    let nothing = summarise(vec![], &names(), &[]);
    assert_eq!(exit_code(&report(nothing)), exit::NO_STATE);
}
