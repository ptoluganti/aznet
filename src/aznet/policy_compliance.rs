//! `check-policy-compliance` orchestration.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{bail, Result};

use crate::aznet::auth::TokenProvider;
use crate::aznet::azure::{filter_subscriptions, ArmClient, PolicyState, PolicyStateFilter};
use crate::aznet::cli::{CheckPolicyComplianceArgs, Output};
use crate::aznet::policy_report::{self, ComplianceReport, Scope, StateRow};

pub mod exit {
    pub const ALL_COMPLIANT: u8 = 0;
    pub const NON_COMPLIANT: u8 = 2;
    /// No state matched at all, or a requested resource has none.
    pub const NO_STATE: u8 = 3;
}

pub async fn run(args: CheckPolicyComplianceArgs) -> Result<ExitCode> {
    let progress = |msg: &str| {
        if args.output == Output::Table {
            eprintln!("{msg}");
        }
    };

    let auth = Arc::new(TokenProvider::connect(&(&args.auth).into()).await?);
    let who = auth.identity.display_name();
    let tenant_id = auth.identity.tenant_id.clone();
    progress(&format!(
        "Authenticated via {:?} as {who} ({}), tenant {tenant_id}",
        auth.method,
        auth.identity.kind()
    ));

    let arm = ArmClient::new(auth.clone())?;
    let mut subs = arm.list_subscriptions().await?;
    if !args.subscriptions.is_empty() {
        subs = filter_subscriptions(subs, &args.subscriptions)?;
    }
    if subs.is_empty() {
        bail!("no subscriptions visible to {who} in tenant {tenant_id} (check RBAC: Reader is enough)");
    }
    progress(&format!(
        "Querying policy states in {} subscription(s)...",
        subs.len()
    ));

    let ids: Vec<String> = subs.iter().map(|s| s.subscription_id.clone()).collect();
    let filter = PolicyStateFilter {
        policy_definition: args.policy_definition.as_deref(),
        policy_assignment: args.policy_assignment.as_deref(),
        resource_ids: &args.resources,
        resource_group: args.resource_group.as_deref(),
        non_compliant_only: args.non_compliant_only,
    };
    let states = arm.policy_states(&ids, &filter).await?;

    let names: HashMap<String, String> = subs
        .iter()
        .map(|s| {
            (
                s.subscription_id.to_ascii_lowercase(),
                s.display_name.clone(),
            )
        })
        .collect();
    let scope = Scope {
        policy_definition: args.policy_definition.clone(),
        policy_assignment: args.policy_assignment.clone(),
        resource_group: args.resource_group.clone(),
        non_compliant_only: args.non_compliant_only,
    };
    let report = ComplianceReport::new(
        &auth,
        tenant_id,
        subs.len(),
        scope,
        summarise(states, &names, &args.resources),
    );
    match args.output {
        Output::Table => policy_report::print_table(&report),
        Output::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }
    Ok(ExitCode::from(exit_code(&report)))
}

/// Pure: raw states -> sorted rows, per-resource tallies and requested resources with no state.
pub fn summarise(
    states: Vec<PolicyState>,
    sub_names: &HashMap<String, String>,
    requested: &[String],
) -> Summary {
    let mut rows: Vec<StateRow> = states
        .into_iter()
        .map(|s| StateRow {
            subscription_name: sub_names
                .get(&s.subscription_id.to_ascii_lowercase())
                .cloned()
                .unwrap_or_default(),
            passing: is_passing(&s.compliance_state),
            state: s,
        })
        .collect();
    rows.sort_by(|a, b| {
        let key = |r: &StateRow| {
            (
                r.subscription_name.to_lowercase(),
                r.state.resource_id.to_lowercase(),
                r.state.policy_assignment_name.to_lowercase(),
                r.state.policy_definition_reference_id.to_lowercase(),
            )
        };
        key(a).cmp(&key(b))
    });

    // A resource passes only if every policy that evaluated it passes.
    let mut per_resource: BTreeMap<String, bool> = BTreeMap::new();
    for r in &rows {
        *per_resource
            .entry(r.state.resource_id.to_lowercase())
            .or_insert(true) &= r.passing;
    }
    let seen: HashSet<&String> = per_resource.keys().collect();
    let missing = requested
        .iter()
        .filter(|r| !seen.contains(&r.to_lowercase()))
        .cloned()
        .collect();

    Summary {
        resources: per_resource.len(),
        compliant_resources: per_resource.values().filter(|p| **p).count(),
        non_compliant_resources: per_resource.values().filter(|p| !**p).count(),
        resources_without_state: missing,
        rows,
    }
}

#[derive(Debug)]
pub struct Summary {
    pub resources: usize,
    pub compliant_resources: usize,
    pub non_compliant_resources: usize,
    pub resources_without_state: Vec<String>,
    pub rows: Vec<StateRow>,
}

/// Compliant, exempt (waived) and protected (blocked by denyAction) are acceptable; anything
/// else (NonCompliant, Conflicting, Unknown, Error) needs attention.
pub fn is_passing(compliance_state: &str) -> bool {
    ["compliant", "exempt", "protected"]
        .iter()
        .any(|ok| compliance_state.eq_ignore_ascii_case(ok))
}

pub fn exit_code(r: &ComplianceReport) -> u8 {
    if r.non_compliant_resources > 0 {
        exit::NON_COMPLIANT
    } else if r.results.is_empty() || !r.resources_without_state.is_empty() {
        exit::NO_STATE
    } else {
        exit::ALL_COMPLIANT
    }
}

#[cfg(test)]
mod tests;
