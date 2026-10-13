//! Minimal ARM / Resource Graph client. Authentication lives in `auth`.

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
                let resp: GraphResponse<VnetRef> =
                    self.send(|| self.http.post(&url).json(&body)).await?;
                out.extend(resp.data);
                match resp.skip_token {
                    Some(t) => skip = Some(t),
                    None => break,
                }
            }
        }
        Ok(out)
    }

    /// Authoritative read: Resource Graph can lag ARM by seconds to minutes, which is
    /// unacceptable for allocation decisions.
    pub async fn get_vnet(&self, id: &str) -> Result<Vnet> {
        let url = format!("{ARM}{id}?api-version={API_NETWORK}");
        self.send(|| self.http.get(&url)).await
    }
}

#[cfg(test)]
mod tests {
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
}
