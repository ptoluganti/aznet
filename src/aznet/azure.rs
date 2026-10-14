//! Minimal ARM / Resource Graph client. Authentication lives in `auth`.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::header::RETRY_AFTER;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::aznet::auth::TokenProvider;

const ARM: &str = "https://management.azure.com";
const API_SUBSCRIPTIONS: &str = "2022-12-01";
const API_RESOURCE_GRAPH: &str = "2021-03-01";
const API_NETWORK: &str = "2024-05-01";
const API_POLICY: &str = "2023-04-01";
const MAX_RETRIES: u32 = 4;
/// Resource Graph accepts at most 1000 subscriptions per request.
const RG_SUBSCRIPTION_CHUNK: usize = 1000;

// ---------------------------------------------------------------------------
// ARM models
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub subscription_id: String,
    pub display_name: String,
    pub state: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VnetRef {
    pub id: String,
    pub name: String,
    pub resource_group: String,
    pub subscription_id: String,
    pub location: String,
}

#[derive(Debug, Deserialize)]
pub struct Vnet {
    #[serde(default)]
    pub properties: VnetProperties,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VnetProperties {
    #[serde(default)]
    pub address_space: AddressSpace,
    #[serde(default)]
    pub subnets: Vec<Subnet>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressSpace {
    #[serde(default)]
    pub address_prefixes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Subnet {
    #[serde(default)]
    pub properties: SubnetProperties,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubnetProperties {
    pub address_prefix: Option<String>,
    #[serde(default)]
    pub address_prefixes: Vec<String>,
}

impl Subnet {
    /// Azure uses `addressPrefix` for single-prefix subnets and `addressPrefixes` for dual-stack.
    pub fn prefixes(&self) -> impl Iterator<Item = &str> {
        self.properties
            .address_prefix
            .iter()
            .chain(self.properties.address_prefixes.iter())
            .map(String::as_str)
    }
}

/// One row of Azure Policy compliance: a resource evaluated against one policy definition
/// within one assignment (initiatives yield one row per member definition).
/// Read in Resource Graph's camelCase; written in snake_case like the rest of the JSON output.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct PolicyState {
    pub subscription_id: String,
    pub resource_id: String,
    #[serde(default)]
    pub resource_type: String,
    #[serde(default)]
    pub resource_group: String,
    pub compliance_state: String,
    /// Policy effect, e.g. audit, deny, deployIfNotExists.
    #[serde(default)]
    pub effect: String,
    pub policy_assignment_name: String,
    pub policy_assignment_id: String,
    pub policy_definition_name: String,
    pub policy_definition_id: String,
    /// Member reference within an initiative; empty for a plain policy assignment.
    #[serde(default)]
    pub policy_definition_reference_id: String,
    #[serde(default)]
    pub policy_set_definition_name: String,
    #[serde(default)]
    pub policy_set_definition_id: String,
    /// When the state was last evaluated (ISO 8601).
    #[serde(default)]
    pub timestamp: String,
    /// The resource's tags; only fetched when filtering by tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}

/// `--tag key` (present, any value) or `--tag key=value`. Matched case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagFilter {
    pub key: String,
    pub value: Option<String>,
}

/// Filters for the policy-state queries. Empty slices / `None` mean "no filter". Policy
/// selectors are resolved to full IDs first (see `policy_compliance::resolve`).
#[derive(Debug, Default)]
pub struct PolicyStateFilter<'a> {
    pub assignment_ids: &'a [String],
    /// Matches a state's policy definition or its initiative (policy set definition).
    pub definition_ids: &'a [String],
    pub resource_ids: &'a [String],
    /// Matched against the last segment of the resource ID (case-insensitive).
    pub resource_names: &'a [String],
    pub resource_group: Option<&'a str>,
    pub tags: &'a [TagFilter],
    pub non_compliant_only: bool,
}

/// One assignment / definition / initiative combination that has states in scope.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyPair {
    pub policy_assignment_id: String,
    pub policy_definition_id: String,
    #[serde(default)]
    pub policy_set_definition_id: String,
}

/// Name and display name of a policy assignment, definition or initiative (ARM read).
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyObject {
    pub name: String,
    #[serde(default)]
    pub properties: PolicyObjectProperties,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyObjectProperties {
    pub display_name: Option<String>,
}

#[derive(Deserialize)]
struct Page<T> {
    value: Vec<T>,
    #[serde(rename = "nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize)]
struct GraphResponse<T> {
    data: Vec<T>,
    #[serde(rename = "$skipToken")]
    skip_token: Option<String>,
    /// "true" when Resource Graph dropped rows it couldn't page (queries without `id`).
    #[serde(rename = "resultTruncated", default)]
    result_truncated: Option<String>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct ArmClient {
    http: reqwest::Client,
    auth: Arc<TokenProvider>,
}

impl ArmClient {
    pub fn new(auth: Arc<TokenProvider>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("aznet/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self { http, auth })
    }

    /// Sends with retry on 429/5xx, honouring Retry-After (ARM throttles per principal).
    async fn send<T: DeserializeOwned>(
        &self,
        build: impl Fn() -> reqwest::RequestBuilder,
    ) -> Result<T> {
        let mut attempt = 0;
        loop {
            let token = self.auth.token().await?;
            let resp = build().bearer_auth(token.secret()).send().await?;
            let status = resp.status();
            if status.is_success() {
                return resp
                    .json::<T>()
                    .await
                    .context("failed to decode ARM response");
            }
            let retryable = status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
            if retryable && attempt < MAX_RETRIES {
                let wait = resp
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| Duration::from_millis(500 << attempt))
                    .min(Duration::from_secs(30));
                tokio::time::sleep(wait).await;
                attempt += 1;
                continue;
            }
            let mut body = resp.text().await.unwrap_or_default();
            body.truncate(600);
            if status == StatusCode::UNAUTHORIZED {
                bail!("ARM rejected the token (401) — re-authenticate. {body}");
            }
            bail!("ARM request failed ({status}): {body}");
        }
    }

    pub async fn list_subscriptions(&self) -> Result<Vec<Subscription>> {
        let mut url = format!("{ARM}/subscriptions?api-version={API_SUBSCRIPTIONS}");
        let mut out = Vec::new();
        loop {
            let page: Page<Subscription> = self.send(|| self.http.get(&url)).await?;
            out.extend(page.value);
            match page.next_link {
                // Never forward the bearer token to a host we didn't choose.
                Some(next) if next.starts_with(ARM) => url = next,
                Some(next) => bail!("refusing to follow nextLink to unexpected host: {next}"),
                None => break,
            }
        }
        Ok(out)
    }

    /// Runs a Resource Graph query across `subscription_ids`, following `$skipToken` paging.
    /// The query must project `id`: Resource Graph only pages results that include it.
    async fn graph_query<T: DeserializeOwned>(
        &self,
        subscription_ids: &[String],
        query: &str,
    ) -> Result<Vec<T>> {
        let url = format!(
            "{ARM}/providers/Microsoft.ResourceGraph/resources?api-version={API_RESOURCE_GRAPH}"
        );
        let mut out = Vec::new();
        for chunk in subscription_ids.chunks(RG_SUBSCRIPTION_CHUNK) {
            let mut skip: Option<String> = None;
            loop {
                let mut options = json!({ "$top": 1000, "resultFormat": "objectArray" });
                if let Some(s) = &skip {
                    options["$skipToken"] = json!(s);
                }
                let body = json!({ "subscriptions": chunk, "query": query, "options": options });
                let resp: GraphResponse<T> = self.send(|| self.http.post(&url).json(&body)).await?;
                if resp.result_truncated.as_deref() == Some("true") {
                    bail!("Resource Graph truncated the results; narrow the scope (--subscription, --resource-group, --policy-assignment)");
                }
                out.extend(resp.data);
                match resp.skip_token {
                    Some(t) => skip = Some(t),
                    None => break,
                }
            }
        }
        Ok(out)
    }

    /// One Resource Graph query instead of N per-subscription ARM list calls.
    /// `vnet`/`rg` are validated by the CLI parser (no quotes possible), so interpolation is safe.
    pub async fn find_vnets(
        &self,
        subscription_ids: &[String],
        vnet: &str,
        rg: &str,
    ) -> Result<Vec<VnetRef>> {
        let query = format!(
            "resources \
             | where type =~ 'microsoft.network/virtualnetworks' \
             | where name =~ '{vnet}' and resourceGroup =~ '{rg}' \
             | project id, name, resourceGroup, subscriptionId, location"
        );
        self.graph_query(subscription_ids, &query).await
    }

    /// Latest Azure Policy states from Resource Graph's `policyresources` table, in one query
    /// for all subscriptions. States refresh on Azure Policy's own cycle (after a resource
    /// changes, plus a full scan about every 24h); each row's `timestamp` shows its age.
    pub async fn policy_states(
        &self,
        subscription_ids: &[String],
        filter: &PolicyStateFilter<'_>,
    ) -> Result<Vec<PolicyState>> {
        self.graph_query(subscription_ids, &policy_states_query(filter))
            .await
    }

    /// Which assignment / definition / initiative combinations have states under `filter`
    /// (its policy ID lists are ignored). Used to resolve names and display names.
    pub async fn policy_pairs(
        &self,
        subscription_ids: &[String],
        filter: &PolicyStateFilter<'_>,
    ) -> Result<Vec<PolicyPair>> {
        self.graph_query(subscription_ids, &policy_pairs_query(filter))
            .await
    }

    /// Reads a policy assignment, definition or initiative by ID. Built-in definitions live
    /// at tenant level and aren't in Resource Graph, so display names come from ARM.
    pub async fn get_policy_object(&self, id: &str) -> Result<PolicyObject> {
        // IDs come from Resource Graph; still refuse anything that could change the URL.
        if !is_plain_arm_path(id) {
            bail!("unexpected policy ID: {id}");
        }
        let url = format!("{ARM}{id}?api-version={API_POLICY}");
        self.send(|| self.http.get(&url)).await
    }

    /// Authoritative read: Resource Graph can lag ARM by seconds to minutes, which is
    /// unacceptable for allocation decisions.
    pub async fn get_vnet(&self, id: &str) -> Result<Vnet> {
        let url = format!("{ARM}{id}?api-version={API_NETWORK}");
        self.send(|| self.http.get(&url)).await
    }
}

/// Builds the `policyresources` query behind [`ArmClient::policy_states`]. Every user value
/// goes through [`kql_string`].
pub fn policy_states_query(f: &PolicyStateFilter<'_>) -> String {
    let mut q = policy_states_filtered(f, true);
    q.push_str(
        " | project id, subscriptionId, resourceId, resourceGroup, complianceState, \
                   policyAssignmentName, policyAssignmentId, \
                   policyDefinitionName, policyDefinitionId, policySetDefinitionId, \
                   resourceType = tostring(p.resourceType), \
                   effect = tostring(p.policyDefinitionAction), \
                   policyDefinitionReferenceId = tostring(p.policyDefinitionReferenceId), \
                   policySetDefinitionName = tostring(p.policySetDefinitionName), \
                   timestamp = todatetime(p.timestamp)",
    );
    if !f.tags.is_empty() {
        q.push_str(", tags = resourceTags");
    }
    q.push_str(
        " | order by resourceId asc, policyAssignmentName asc, policyDefinitionReferenceId asc",
    );
    q
}

/// Builds the query behind [`ArmClient::policy_pairs`]: distinct policy combinations under
/// the non-policy filters.
pub fn policy_pairs_query(f: &PolicyStateFilter<'_>) -> String {
    let mut q = policy_states_filtered(f, false);
    q.push_str(
        " | summarize states = count() by policyAssignmentId, policyDefinitionId, policySetDefinitionId",
    );
    q
}

fn policy_states_filtered(f: &PolicyStateFilter<'_>, by_policy: bool) -> String {
    let mut q = String::from(
        "policyresources \
         | where type =~ 'microsoft.policyinsights/policystates' \
         | extend p = properties \
         | extend resourceId = tostring(p.resourceId), \
                  complianceState = tostring(p.complianceState), \
                  policyAssignmentName = tostring(p.policyAssignmentName), \
                  policyAssignmentId = tostring(p.policyAssignmentId), \
                  policyDefinitionName = tostring(p.policyDefinitionName), \
                  policyDefinitionId = tostring(p.policyDefinitionId), \
                  policySetDefinitionId = tostring(p.policySetDefinitionId)",
    );
    let list = |ids: &[String]| {
        ids.iter()
            .map(|i| kql_string(i))
            .collect::<Vec<_>>()
            .join(", ")
    };
    if by_policy && !f.assignment_ids.is_empty() {
        let _ = write!(
            q,
            " | where policyAssignmentId in~ ({})",
            list(f.assignment_ids)
        );
    }
    if by_policy && !f.definition_ids.is_empty() {
        let ids = list(f.definition_ids);
        let _ = write!(
            q,
            " | where policyDefinitionId in~ ({ids}) or policySetDefinitionId in~ ({ids})"
        );
    }
    let mut resource_match = Vec::new();
    if !f.resource_ids.is_empty() {
        resource_match.push(format!("resourceId in~ ({})", list(f.resource_ids)));
    }
    if !f.resource_names.is_empty() {
        resource_match.push(format!(
            "extract('[^/]+$', 0, resourceId) in~ ({})",
            list(f.resource_names)
        ));
    }
    if !resource_match.is_empty() {
        let _ = write!(q, " | where {}", resource_match.join(" or "));
    }
    q.push_str(" | extend resourceGroup = extract('(?i)/resourcegroups/([^/]+)', 1, resourceId)");
    if let Some(rg) = f.resource_group {
        let _ = write!(q, " | where resourceGroup =~ {}", kql_string(rg));
    }
    if f.non_compliant_only {
        q.push_str(" | where complianceState !~ 'Compliant'");
    }
    if !f.tags.is_empty() {
        // policyresources has its own (empty) `tags` column, hence `resourceTags`. Lower-casing
        // the whole bag makes key and value matching case-insensitive, like Azure tag keys.
        q.push_str(
            " | extend joinId = tolower(resourceId) \
             | join kind=inner (resources | union resourcecontainers \
                                | project joinId = tolower(id), resourceTags = tags) on joinId \
             | extend lowerTags = parse_json(tolower(tostring(resourceTags)))",
        );
        for t in f.tags {
            let key = kql_string(&t.key.to_lowercase());
            match &t.value {
                Some(v) => {
                    let _ = write!(
                        q,
                        " | where tostring(lowerTags[{key}]) == {}",
                        kql_string(&v.to_lowercase())
                    );
                }
                None => {
                    let _ = write!(q, " | where isnotnull(lowerTags[{key}])");
                }
            }
        }
    }
    q
}

/// An ARM resource path that's safe to append to the ARM host: absolute, with no query,
/// fragment, backslash or `..` that could change which URL is requested.
pub fn is_plain_arm_path(id: &str) -> bool {
    id.starts_with('/') && !id.contains(['?', '#', '\\']) && !id.contains("..")
}

/// Quotes `s` as a KQL string literal. Backslash and single quote are the only characters
/// that can end or alter a `'...'` literal; control characters are rejected by the CLI parsers.
pub fn kql_string(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

pub fn filter_subscriptions(
    subs: Vec<Subscription>,
    wanted: &[String],
) -> Result<Vec<Subscription>> {
    let matches = |s: &Subscription, w: &str| {
        s.subscription_id.eq_ignore_ascii_case(w) || s.display_name.eq_ignore_ascii_case(w)
    };
    if let Some(missing) = wanted.iter().find(|w| !subs.iter().any(|s| matches(s, w))) {
        bail!("subscription '{missing}' not found or not accessible in this tenant");
    }
    Ok(subs
        .into_iter()
        .filter(|s| wanted.iter().any(|w| matches(s, w)))
        .collect())
}

#[cfg(test)]
mod tests;
