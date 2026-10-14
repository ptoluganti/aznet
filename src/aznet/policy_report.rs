//! `check-policy-compliance` result model + table rendering. JSON output serialises
//! `ComplianceReport` directly.

use comfy_table::Cell;
use serde::Serialize;

use crate::aznet::auth::TokenProvider;
use crate::aznet::azure::PolicyState;
use crate::aznet::policy_compliance::Summary;
use crate::aznet::report::table;

/// Failing policies listed per resource in the table before "+N more".
const MAX_POLICIES_SHOWN: usize = 5;

#[derive(Debug, Serialize)]
pub struct StateRow {
    pub subscription_name: String,
    /// Compliant, exempt or protected.
    pub passing: bool,
    pub policy_assignment_display_name: String,
    /// Looked up for failing states only; empty otherwise or if unreadable.
    pub policy_definition_display_name: String,
    #[serde(flatten)]
    pub state: PolicyState,
}

#[derive(Debug, Serialize)]
pub struct AssignmentInfo {
    pub name: String,
    pub display_name: String,
    pub id: String,
}

/// What was asked for, echoed back so JSON output is self-describing.
#[derive(Debug, Serialize)]
pub struct Scope {
    pub policy_definition: Option<String>,
    pub policy_assignment: Option<String>,
    pub resource_group: Option<String>,
    pub tags: Vec<String>,
    pub non_compliant_only: bool,
}

#[derive(Debug, Serialize)]
pub struct ComplianceReport {
    pub account: String,
    pub auth_method: String,
    pub tenant_id: String,
    pub subscriptions_scanned: usize,
    pub scope: Scope,
    /// Assignments that matched and have states in the results.
    pub assignments: Vec<AssignmentInfo>,
    pub policy_states: usize,
    pub resources: usize,
    pub compliant_resources: usize,
    pub non_compliant_resources: usize,
    pub non_compliant_resource_ids: Vec<String>,
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
}

pub fn print_table(r: &ComplianceReport) {
    print_summary(r);

    if r.results.is_empty() {
        if r.scope.non_compliant_only {
            println!("\nNo non-compliant policy state matched.");
        } else {
            println!(
                "\nNo policy state matched. Check the policy name, display name or ID, the \
                 filters and subscriptions in scope; a new assignment can take ~30 minutes to \
                 get its first compliance scan."
            );
        }
    } else {
        print_resources(r);
    }

    if !r.non_compliant_resource_ids.is_empty() {
        println!("\nNon-compliant resource IDs:");
        for id in &r.non_compliant_resource_ids {
            println!("  {id}");
        }
    }
    for id in &r.resources_without_state {
        println!(
            "\n? {id}: no policy state. Not in the assignment's scope, excluded, \
             not a type the policy targets, or not evaluated yet."
        );
    }
}

fn print_summary(r: &ComplianceReport) {
    let mut t = table();
    t.set_header(vec!["Summary", ""]);
    let mut row = |k: &str, v: String| {
        t.add_row(vec![k.to_string(), v]);
    };
    row("Account", r.account.clone());
    row("Auth", r.auth_method.clone());
    row("Tenant", r.tenant_id.clone());
    row("Subscriptions scanned", r.subscriptions_scanned.to_string());
    if let Some(d) = &r.scope.policy_definition {
        row("Policy definition", d.clone());
    }
    if let Some(a) = &r.scope.policy_assignment {
        row("Policy assignment", a.clone());
    }
    if !r.assignments.is_empty() {
        let list: Vec<String> = r
            .assignments
            .iter()
            .map(|a| {
                if a.display_name.is_empty() || a.display_name == a.name {
                    a.name.clone()
                } else {
                    format!("{} ({})", a.display_name, a.name)
                }
            })
            .collect();
        row("Assignments matched", list.join("\n"));
    }
    if let Some(g) = &r.scope.resource_group {
        row("Resource group", g.clone());
    }
    if !r.scope.tags.is_empty() {
        row("Tags", r.scope.tags.join(", "));
    }
    row("Policy states", r.policy_states.to_string());
    row("Resources", r.resources.to_string());
    if !r.scope.non_compliant_only {
        row("Compliant", r.compliant_resources.to_string());
    }
    row("Non-compliant", r.non_compliant_resources.to_string());
    if !r.resources_without_state.is_empty() {
        row(
            "Without policy state",
            r.resources_without_state.len().to_string(),
        );
    }
    println!("{t}");
}

/// One row per resource (rows arrive sorted by subscription, then resource).
fn print_resources(r: &ComplianceReport) {
    let mut t = table();
    t.set_header(vec![
        "Subscription",
        "Resource Group",
        "Resource",
        "Type",
        "Compliance",
        "Failing policies",
        "Evaluated (UTC)",
    ]);
    for group in r.results.chunk_by(|a, b| {
        a.state
            .resource_id
            .eq_ignore_ascii_case(&b.state.resource_id)
    }) {
        let first = &group[0];
        let failing: Vec<&StateRow> = group.iter().filter(|x| !x.passing).collect();
        let compliance = if failing.is_empty() {
            "Compliant".to_string()
        } else {
            format!("✗ {} of {} failing", failing.len(), group.len())
        };
        let mut policies: Vec<String> = failing.iter().map(|x| policy_label(x)).collect();
        policies.sort();
        policies.dedup();
        let more = policies.len().saturating_sub(MAX_POLICIES_SHOWN);
        policies.truncate(MAX_POLICIES_SHOWN);
        if more > 0 {
            policies.push(format!("(+{more} more)"));
        }
        let latest = group
            .iter()
            .map(|x| x.state.timestamp.as_str())
            .max()
            .unwrap_or_default();
        t.add_row(vec![
            Cell::new(&first.subscription_name),
            Cell::new(&first.state.resource_group),
            Cell::new(last_segment(&first.state.resource_id)),
            Cell::new(&first.state.resource_type),
            Cell::new(compliance),
            Cell::new(policies.join("\n")),
            Cell::new(short_time(latest)),
        ]);
    }
    println!("{t}");
}

/// Display name if known; else the initiative member reference, else the definition name.
fn policy_label(row: &StateRow) -> String {
    let s = &row.state;
    if !row.policy_definition_display_name.is_empty() {
        row.policy_definition_display_name.clone()
    } else if !s.policy_definition_reference_id.is_empty() {
        s.policy_definition_reference_id.clone()
    } else {
        s.policy_definition_name.clone()
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
