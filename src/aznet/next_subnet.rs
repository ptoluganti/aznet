//! `get-next-subnet` orchestration.

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{bail, Result};
use futures::stream::{self, StreamExt};

use crate::aznet::auth::{AuthConfig, TokenProvider};
use crate::aznet::azure::{ArmClient, Subscription, Vnet, VnetRef};
use crate::aznet::cli::{GetNextSubnetArgs, Output};
use crate::aznet::ipam::{self, Allocation, Ipv4Cidr};
use crate::aznet::report::{self, Report, Status, VnetResult};

pub mod exit {
    pub const ALL_AVAILABLE: u8 = 0;
    pub const SOME_EXHAUSTED: u8 = 2;
    pub const NOT_FOUND: u8 = 3;
}

pub async fn run(args: GetNextSubnetArgs) -> Result<ExitCode> {
    let progress = |msg: &str| {
        if args.output == Output::Table {
            eprintln!("{msg}");
        }
    };

    // 1. Auth: resolve a credential and acquire an ARM token before any API work.
    let auth = TokenProvider::connect(&AuthConfig {
        method: Some(args.auth),
        tenant: args.tenant.clone(),
        managed_identity_client_id: args.managed_identity_client_id.clone(),
    })
    .await?;
    let auth = Arc::new(auth);
    let who = auth.identity.display_name();
    let tenant_id = auth.identity.tenant_id.clone();
    progress(&format!(
        "Authenticated via {:?} as {who} ({}), tenant {tenant_id}",
        auth.method,
        auth.identity.kind()
    ));

    let arm = ArmClient::new(auth.clone())?;

    // 2. Subscriptions in scope.
    let mut subs = arm.list_subscriptions().await?;
    if !args.subscriptions.is_empty() {
        subs = filter_subscriptions(subs, &args.subscriptions)?;
    }
    if subs.is_empty() {
        bail!("no subscriptions visible to {who} in tenant {tenant_id} (check RBAC: Reader is enough)");
    }
    progress(&format!(
        "Searching {} subscription(s) for VNet '{}' in resource group '{}'...",
        subs.len(),
        args.vnet,
        args.resource_group
    ));

    // 3. Locate matching VNets with a single Resource Graph query.
    let ids: Vec<String> = subs.iter().map(|s| s.subscription_id.clone()).collect();
    let refs = arm
        .find_vnets(&ids, &args.vnet, &args.resource_group)
        .await?;

    // 4. Authoritative read + allocation per VNet, bounded concurrency.
    let names: HashMap<String, String> = subs
        .iter()
        .map(|s| {
            (
                s.subscription_id.to_ascii_lowercase(),
                s.display_name.clone(),
            )
        })
        .collect();
    let prefix = args.prefix;
    let mut results: Vec<VnetResult> = stream::iter(refs)
        .map(|r| {
            let arm = &arm;
            let sub_name = names
                .get(&r.subscription_id.to_ascii_lowercase())
                .cloned()
                .unwrap_or_default();
            async move {
                match arm.get_vnet(&r.id).await {
                    Ok(vnet) => evaluate(&r, sub_name, &vnet, prefix),
                    Err(e) => VnetResult::error(&r, sub_name, prefix, format!("{e:#}")),
                }
            }
        })
        .buffer_unordered(args.concurrency as usize)
        .collect()
        .await;
    results.sort_by(|a, b| {
        (a.subscription_name.to_lowercase(), &a.subscription_id)
            .cmp(&(b.subscription_name.to_lowercase(), &b.subscription_id))
    });

    let report = Report::new(&auth, tenant_id, subs.len(), prefix, results);
    match args.output {
        Output::Table => report::print_table(&report),
        Output::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }

    Ok(ExitCode::from(if report.vnets_matched == 0 {
        exit::NOT_FOUND
    } else if report.without_capacity + report.errors > 0 {
        exit::SOME_EXHAUSTED
    } else {
        exit::ALL_AVAILABLE
    }))
}

fn filter_subscriptions(subs: Vec<Subscription>, wanted: &[String]) -> Result<Vec<Subscription>> {
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

/// Pure: VNet JSON -> result row. IPv6 prefixes are ignored.
pub fn evaluate(r: &VnetRef, sub_name: String, vnet: &Vnet, prefix: u8) -> VnetResult {
    let v4 = |s: &&str| !s.contains(':');
    let spaces: Vec<Ipv4Cidr> = vnet
        .properties
        .address_space
        .address_prefixes
        .iter()
        .map(String::as_str)
        .filter(v4)
        .filter_map(|s| s.parse().ok())
        .collect();
    let used: Vec<Ipv4Cidr> = vnet
        .properties
        .subnets
        .iter()
        .flat_map(|s| s.prefixes())
        .filter(v4)
        .filter_map(|s| s.parse().ok())
        .collect();

    let mut row = VnetResult::base(r, sub_name, prefix);
    row.address_space = spaces.iter().map(ToString::to_string).collect();
    row.subnet_count = vnet.properties.subnets.len();

    if spaces.is_empty() {
        row.status = Status::Error;
        row.error = Some("VNet has no IPv4 address space".into());
        return row;
    }
    match ipam::next_available(&spaces, &used, prefix) {
        Allocation::Available(c) => {
            row.status = Status::Available;
            row.next_available = Some(c.to_string());
        }
        Allocation::Exhausted {
            largest_free,
            free_blocks,
            usable_free_addresses,
            per_space,
        } => {
            row.status = Status::Exhausted;
            row.largest_free = largest_free.map(|c| c.to_string());
            row.free_blocks = free_blocks.iter().map(ToString::to_string).collect();
            row.usable_free_addresses = usable_free_addresses;
            if per_space.len() > 1 {
                row.error = Some(format!(
                    "Multiple IPv4 address spaces; suggest checking each range: {}",
                    per_space
                        .iter()
                        .map(|s| format!(
                            "{} (largest free: {})",
                            s.space,
                            s.largest_free
                                .map(|c| c.to_string())
                                .unwrap_or_else(|| "none".into())
                        ))
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
        }
    }
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vref() -> VnetRef {
        VnetRef {
            id: "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v"
                .into(),
            name: "v".into(),
            resource_group: "rg".into(),
            subscription_id: "x".into(),
            location: "uksouth".into(),
        }
    }

    fn vnet(json: &str) -> Vnet {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn evaluates_available_and_ignores_ipv6() {
        let v = vnet(
            r#"{"name":"v","properties":{
            "addressSpace":{"addressPrefixes":["fd00::/48","10.0.0.0/24"]},
            "subnets":[{"name":"a","properties":{"addressPrefixes":["10.0.0.0/27","fd00::/64"]}}]}}"#,
        );
        let r = evaluate(&vref(), "sub".into(), &v, 27);
        assert_eq!(r.status, Status::Available);
        assert_eq!(r.next_available.as_deref(), Some("10.0.0.32/27"));
        assert_eq!(r.subnet_count, 1);
    }

    #[test]
    fn evaluates_exhausted_with_advice() {
        let v = vnet(
            r#"{"name":"v","properties":{
            "addressSpace":{"addressPrefixes":["10.0.0.0/26"]},
            "subnets":[{"name":"a","properties":{"addressPrefix":"10.0.0.0/27"}},
                       {"name":"b","properties":{"addressPrefix":"10.0.0.32/28"}}]}}"#,
        );
        let r = evaluate(&vref(), "sub".into(), &v, 27);
        assert_eq!(r.status, Status::Exhausted);
        assert_eq!(r.largest_free.as_deref(), Some("10.0.0.48/28"));
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
}
