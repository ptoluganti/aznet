//! `check-policy-compliance` result model + table rendering. JSON output serialises
//! `ComplianceReport` directly.

use comfy_table::Cell;
use serde::Serialize;

use crate::aznet::auth::TokenProvider;
use crate::aznet::azure::PolicyState;
use crate::aznet::policy_compliance::Summary;
use crate::aznet::report::table;

#[derive(Debug, Serialize)]
pub struct StateRow {
    pub subscription_name: String,
    /// Compliant, exempt or protected.
    pub passing: bool,
    #[serde(flatten)]
    pub state: PolicyState,
}

/// What was asked for, echoed back so JSON output is self-describing.
#[derive(Debug, Serialize)]
pub struct Scope {
    pub policy_definition: Option<String>,
    pub policy_assignment: Option<String>,
    pub resource_group: Option<String>,
    pub non_compliant_only: bool,
}

#[derive(Debug, Serialize)]
pub struct ComplianceReport {
    pub account: String,
    pub auth_method: String,
    pub tenant_id: String,
    pub subscriptions_scanned: usize,
    pub scope: Scope,
    pub policy_states: usize,
    pub resources: usize,
    pub compliant_resources: usize,
    pub non_compliant_resources: usize,
    /// Requested with --resource but no policy state matched.
    pub resources_without_state: Vec<String>,
    pub results: Vec<StateRow>,
}

impl ComplianceReport {
    pub fn new(
        auth: &TokenProvider,
        tenant_id: String,
        subs: usize,
        scope: Scope,
        s: Summary,
    ) -> Self {
        Self {
            account: format!(
                "{} ({})",
                auth.identity.display_name(),
                auth.identity.kind()
            ),
            auth_method: format!("{:?}", auth.method),
            tenant_id,
            subscriptions_scanned: subs,
            scope,
            policy_states: s.rows.len(),
            resources: s.resources,
            compliant_resources: s.compliant_resources,
            non_compliant_resources: s.non_compliant_resources,
            resources_without_state: s.resources_without_state,
            results: s.rows,
        }
    }
}

pub fn print_table(r: &ComplianceReport) {
    let mut summary = table();
    summary.set_header(vec!["Summary", ""]);
    summary.add_row(vec!["Account".into(), r.account.clone()]);
    summary.add_row(vec!["Auth".into(), r.auth_method.clone()]);
    summary.add_row(vec!["Tenant".into(), r.tenant_id.clone()]);
    summary.add_row(vec![
        "Subscriptions scanned".into(),
        r.subscriptions_scanned.to_string(),
    ]);
    if let Some(d) = &r.scope.policy_definition {
        summary.add_row(vec!["Policy definition".into(), d.clone()]);
    }
    if let Some(a) = &r.scope.policy_assignment {
        summary.add_row(vec!["Policy assignment".into(), a.clone()]);
    }
    if let Some(g) = &r.scope.resource_group {
        summary.add_row(vec!["Resource group".into(), g.clone()]);
    }
    summary.add_row(vec!["Policy states".into(), r.policy_states.to_string()]);
    summary.add_row(vec!["Resources".into(), r.resources.to_string()]);
    if !r.scope.non_compliant_only {
        summary.add_row(vec!["Compliant".into(), r.compliant_resources.to_string()]);
    }
    summary.add_row(vec![
        "Non-compliant".into(),
        r.non_compliant_resources.to_string(),
    ]);
    if !r.resources_without_state.is_empty() {
        summary.add_row(vec![
            "Without policy state".into(),
            r.resources_without_state.len().to_string(),
        ]);
    }
    println!("{summary}");

    if r.results.is_empty() {
        if r.scope.non_compliant_only {
            println!("\nNo non-compliant policy state matched.");
        } else {
            println!(
                "\nNo policy state matched. Check the policy name/ID and subscriptions in scope; \
                 a new assignment can take ~30 minutes to get its first compliance scan."
            );
        }
    } else {
        let mut detail = table();
        detail.set_header(vec![
            "Subscription",
            "Resource Group",
            "Resource",
            "Type",
            "Assignment",
            "Policy",
            "Effect",
            "State",
            "Evaluated (UTC)",
        ]);
        for row in &r.results {
            let s = &row.state;
            detail.add_row(vec![
                Cell::new(&row.subscription_name),
                Cell::new(&s.resource_group),
                Cell::new(last_segment(&s.resource_id)),
                Cell::new(&s.resource_type),
                Cell::new(&s.policy_assignment_name),
                Cell::new(policy_cell(s)),
                Cell::new(&s.effect),
                Cell::new(if row.passing {
                    s.compliance_state.clone()
                } else {
                    format!("✗ {}", s.compliance_state)
                }),
                Cell::new(short_time(&s.timestamp)),
            ]);
        }
        println!("{detail}");
    }

    // Full IDs, ready to copy, for what needs action.
    let mut last = "";
    for row in r.results.iter().filter(|x| !x.passing) {
        if row.state.resource_id != last {
            println!("\n✗ {}", row.state.resource_id);
            last = &row.state.resource_id;
        }
        println!(
            "  {} — {} ({})",
            row.state.compliance_state,
            policy_cell(&row.state),
            row.state.policy_assignment_name
        );
    }
    for id in &r.resources_without_state {
        println!(
            "\n? {id}: no policy state. Not in the assignment's scope, excluded, \
             not a type the policy targets, or not evaluated yet."
        );
    }
}

/// Initiative members are clearer by reference ID; plain assignments by definition name.
fn policy_cell(s: &PolicyState) -> String {
    if s.policy_definition_reference_id.is_empty() {
        s.policy_definition_name.clone()
    } else {
        s.policy_definition_reference_id.clone()
    }
}

fn last_segment(id: &str) -> &str {
    id.rsplit('/').next().unwrap_or(id)
}

/// "2026-10-14T08:15:42.123Z" -> "2026-10-14 08:15".
fn short_time(ts: &str) -> String {
    match ts.get(..16) {
        Some(t) if ts.len() > 16 => t.replacen('T', " ", 1),
        _ => ts.to_string(),
    }
}
