//! `get-next-subnet` orchestration.

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{bail, Result};
use futures::stream::{self, StreamExt};

use crate::aznet::auth::TokenProvider;
use crate::aznet::azure::{filter_subscriptions, ArmClient, Vnet, VnetRef};
use crate::aznet::cli::{GetNextSubnetArgs, Output};
use crate::aznet::ipam::{self, Allocation, Ipv4Cidr};
use crate::aznet::report::{self, Report, SpaceResult, Status, VnetResult};

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
    let auth = TokenProvider::connect(&(&args.auth).into()).await?;
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
    row.spaces = ipam::per_space(&spaces, &used, prefix)
        .into_iter()
        .map(|s| SpaceResult {
            address_space: s.space.to_string(),
            status: if s.next_available.is_some() {
                Status::Available
            } else {
                Status::Exhausted
            },
            next_available: s.next_available.map(|c| c.to_string()),
            largest_free: s.largest_free.map(|c| c.to_string()),
        })
        .collect();
    match ipam::next_available(&spaces, &used, prefix) {
        Allocation::Available(c) => {
            row.status = Status::Available;
            row.next_available = Some(c.to_string());
        }
        Allocation::Exhausted {
            largest_free,
            free_blocks,
            usable_free_addresses,
        } => {
            row.status = Status::Exhausted;
            row.largest_free = largest_free.map(|c| c.to_string());
            row.free_blocks = free_blocks.iter().map(ToString::to_string).collect();
            row.usable_free_addresses = usable_free_addresses;
        }
    }
    row
}

#[cfg(test)]
mod tests;
