//! `check-policy-compliance` orchestration.
//!
//! 1. Discover which assignment / definition / initiative combinations have states under the
//!    resource filters (one Resource Graph query).
//! 2. Resolve `--policy-assignment` / `--policy-definition` against those: name or full ID
//!    first, display name (via ARM) only when nothing matched that way.
//! 3. Query the states for the resolved IDs, then look up display names for what's shown.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{bail, Result};
use futures::stream::{self, StreamExt};

use crate::aznet::auth::TokenProvider;
use crate::aznet::azure::{
    filter_subscriptions, ArmClient, PolicyPair, PolicyState, PolicyStateFilter,
};
use crate::aznet::cli::{CheckPolicyComplianceArgs, Output};
use crate::aznet::policy_report::{self, AssignmentInfo, ComplianceReport, Scope, StateRow};

pub mod exit {
    pub const ALL_COMPLIANT: u8 = 0;
    pub const NON_COMPLIANT: u8 = 2;
    /// No state matched at all, or a requested resource has none.
    pub const NO_STATE: u8 = 3;
}

/// Concurrent ARM reads when looking up display names.
const NAME_LOOKUP_CONCURRENCY: usize = 8;

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
    let ids: Vec<String> = subs.iter().map(|s| s.subscription_id.clone()).collect();
    let (resource_ids, resource_names): (Vec<String>, Vec<String>) = args
        .resources
        .iter()
        .cloned()
        .partition(|r| is_resource_id(r));
    let resource_filter = PolicyStateFilter {
        resource_ids: &resource_ids,
        resource_names: &resource_names,
        resource_group: args.resource_group.as_deref(),
        tags: &args.tags,
        non_compliant_only: args.non_compliant_only,
        ..Default::default()
    };

    // 1-2. Resolve the policy selectors against what actually has states in scope.
    progress(&format!(
        "Finding policies with compliance states in {} subscription(s)...",
        subs.len()
    ));
    let pairs = arm.policy_pairs(&ids, &resource_filter).await?;
    let mut names = DisplayNames::default();
    let assignment_ids = match &args.policy_assignment {
        Some(sel) => {
            let candidates = distinct(pairs.iter().map(|p| p.policy_assignment_id.as_str()));
            resolve(&arm, sel, &candidates, &mut names, &progress).await
        }
        None => vec![],
    };
    let definition_ids = match &args.policy_definition {
        Some(sel) => {
            let candidates = definition_candidates(&pairs, &assignment_ids);
            resolve(&arm, sel, &candidates, &mut names, &progress).await
        }
        None => vec![],
    };
    let unresolved = (args.policy_assignment.is_some() && assignment_ids.is_empty())
        || (args.policy_definition.is_some() && definition_ids.is_empty());

    // 3. States for the resolved policies, then display names for what's shown.
    let states = if unresolved {
        vec![]
    } else {
        progress("Querying policy states...");
        let filter = PolicyStateFilter {
            assignment_ids: &assignment_ids,
            definition_ids: &definition_ids,
            ..resource_filter
        };
        arm.policy_states(&ids, &filter).await?
    };
    let shown = distinct(states.iter().flat_map(|s| {
        let failing = (!is_passing(&s.compliance_state)).then_some(s.policy_definition_id.as_str());
        std::iter::once(s.policy_assignment_id.as_str()).chain(failing)
    }));
    names.fetch(&arm, &shown, &progress).await;

    let sub_names: HashMap<String, String> = subs
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
        tags: args
            .tags
            .iter()
            .map(|t| match &t.value {
                Some(v) => format!("{}={v}", t.key),
                None => t.key.clone(),
            })
            .collect(),
        non_compliant_only: args.non_compliant_only,
    };
    let report = ComplianceReport::new(
        &auth,
        tenant_id,
        subs.len(),
        scope,
        summarise(states, &sub_names, &args.resources, &names),
    );
    match args.output {
        Output::Table => policy_report::print_table(&report),
        Output::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }
    Ok(ExitCode::from(exit_code(&report)))
}

/// Display names of policy objects, keyed by lower-cased ID. Empty when the lookup failed
/// (no read access, deleted), so a failure isn't retried.
#[derive(Debug, Default)]
pub struct DisplayNames(HashMap<String, String>);

impl DisplayNames {
    pub fn get(&self, id: &str) -> Option<&str> {
        self.0
            .get(&id.to_ascii_lowercase())
            .map(String::as_str)
            .filter(|n| !n.is_empty())
    }

    pub fn insert(&mut self, id: &str, display_name: String) {
        self.0.insert(id.to_ascii_lowercase(), display_name);
    }

    async fn fetch(&mut self, arm: &ArmClient, ids: &[String], progress: &dyn Fn(&str)) {
        let missing: Vec<&String> = ids
            .iter()
            .filter(|id| !self.0.contains_key(&id.to_ascii_lowercase()))
            .collect();
        if missing.is_empty() {
            return;
        }
        progress(&format!(
            "Looking up display names of {} policy object(s)...",
            missing.len()
        ));
        let found: Vec<(String, String)> = stream::iter(missing)
            .map(|id| async move {
                let name = match arm.get_policy_object(id).await {
                    Ok(o) => o.properties.display_name.unwrap_or(o.name),
                    Err(_) => String::new(),
                };
                (id.clone(), name)
            })
            .buffer_unordered(NAME_LOOKUP_CONCURRENCY)
            .collect()
            .await;
        for (id, name) in found {
            self.insert(&id, name);
        }
    }
}

/// Selector -> matching IDs among `candidates`: by name or full ID first; by display name
/// only if that found nothing (it costs an ARM read per candidate not already known).
async fn resolve(
    arm: &ArmClient,
    selector: &str,
    candidates: &[String],
    names: &mut DisplayNames,
    progress: &dyn Fn(&str),
) -> Vec<String> {
    let direct = match_name_or_id(selector, candidates);
    if !direct.is_empty() {
        return direct;
    }
    names.fetch(arm, candidates, progress).await;
    match_display_name(selector, candidates, names)
}

/// Full ID when the selector contains `/`, otherwise the last ID segment (the name).
pub fn match_name_or_id(selector: &str, candidates: &[String]) -> Vec<String> {
    let sel = selector.trim().trim_end_matches('/');
    candidates
        .iter()
        .filter(|id| {
            if sel.contains('/') {
                id.eq_ignore_ascii_case(sel)
            } else {
                id.rsplit('/')
                    .next()
                    .is_some_and(|n| n.eq_ignore_ascii_case(sel))
            }
        })
        .cloned()
        .collect()
}

pub fn match_display_name(
    selector: &str,
    candidates: &[String],
    names: &DisplayNames,
) -> Vec<String> {
    let sel = selector.trim();
    candidates
        .iter()
        .filter(|id| {
            names
                .get(id)
                .is_some_and(|n| n.trim().eq_ignore_ascii_case(sel))
        })
        .cloned()
        .collect()
}

/// Definitions and initiatives that have states, within the resolved assignments (if any).
pub fn definition_candidates(pairs: &[PolicyPair], assignment_ids: &[String]) -> Vec<String> {
    distinct(
        pairs
            .iter()
            .filter(|p| {
                assignment_ids.is_empty()
                    || assignment_ids
                        .iter()
                        .any(|a| a.eq_ignore_ascii_case(&p.policy_assignment_id))
            })
            .flat_map(|p| {
                [
                    p.policy_definition_id.as_str(),
                    p.policy_set_definition_id.as_str(),
                ]
            }),
    )
}

/// Sorted, case-insensitively distinct, non-empty.
fn distinct<'a>(ids: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut seen = HashSet::new();
    let set: BTreeSet<String> = ids
        .filter(|i| !i.is_empty() && seen.insert(i.to_ascii_lowercase()))
        .map(str::to_string)
        .collect();
    set.into_iter().collect()
}

/// Pure: raw states -> sorted rows, per-resource tallies and requested resources with no state.
pub fn summarise(
    states: Vec<PolicyState>,
    sub_names: &HashMap<String, String>,
    requested: &[String],
    names: &DisplayNames,
) -> Summary {
    let mut rows: Vec<StateRow> = states
        .into_iter()
        .map(|s| StateRow {
            subscription_name: sub_names
                .get(&s.subscription_id.to_ascii_lowercase())
                .cloned()
                .unwrap_or_default(),
            passing: is_passing(&s.compliance_state),
            policy_assignment_display_name: names
                .get(&s.policy_assignment_id)
                .unwrap_or_default()
                .to_string(),
            policy_definition_display_name: names
                .get(&s.policy_definition_id)
                .unwrap_or_default()
                .to_string(),
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
    let mut per_resource: BTreeMap<String, (bool, &str)> = BTreeMap::new();
    for r in &rows {
        per_resource
            .entry(r.state.resource_id.to_lowercase())
            .or_insert((true, &r.state.resource_id))
            .0 &= r.passing;
    }
    let missing = requested
        .iter()
        .filter(|sel| {
            !per_resource
                .values()
                .any(|(_, id)| resource_matches(sel, id))
        })
        .cloned()
        .collect();
    let non_compliant_resource_ids: Vec<String> = per_resource
        .values()
        .filter(|(passing, _)| !passing)
        .map(|(_, id)| id.to_string())
        .collect();

    let mut assignments: BTreeMap<String, AssignmentInfo> = BTreeMap::new();
    for r in &rows {
        assignments
            .entry(r.state.policy_assignment_id.to_lowercase())
            .or_insert_with(|| AssignmentInfo {
                name: r.state.policy_assignment_name.clone(),
                display_name: r.policy_assignment_display_name.clone(),
                id: r.state.policy_assignment_id.clone(),
            });
    }

    Summary {
        resources: per_resource.len(),
        compliant_resources: per_resource.len() - non_compliant_resource_ids.len(),
        non_compliant_resources: non_compliant_resource_ids.len(),
        resources_without_state: missing,
        assignments: assignments.into_values().collect(),
        non_compliant_resource_ids,
        rows,
    }
}

#[derive(Debug)]
pub struct Summary {
    pub resources: usize,
    pub compliant_resources: usize,
    pub non_compliant_resources: usize,
    pub resources_without_state: Vec<String>,
    pub non_compliant_resource_ids: Vec<String>,
    pub assignments: Vec<AssignmentInfo>,
    pub rows: Vec<StateRow>,
}

/// `--resource` values starting with `/` are full IDs; anything else is a resource name.
pub fn is_resource_id(selector: &str) -> bool {
    selector.starts_with('/')
}

/// Full ID match, or name match against the ID's last segment; case-insensitive.
pub fn resource_matches(selector: &str, resource_id: &str) -> bool {
    if is_resource_id(selector) {
        resource_id.eq_ignore_ascii_case(selector)
    } else {
        resource_id
            .rsplit('/')
            .next()
            .is_some_and(|n| n.eq_ignore_ascii_case(selector))
    }
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
