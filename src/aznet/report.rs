//! Result model + table rendering. JSON output serialises `Report` directly.

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, CellAlignment, ContentArrangement, Table};
use serde::Serialize;

use crate::aznet::auth::TokenProvider;
use crate::aznet::azure::VnetRef;
use crate::aznet::ipam::AZURE_RESERVED_PER_SUBNET;

const MAX_ADVICE_BLOCKS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Available,
    Exhausted,
    Error,
}

#[derive(Debug, Serialize)]
pub struct VnetResult {
    pub subscription_name: String,
    pub subscription_id: String,
    pub vnet_name: String,
    pub resource_group: String,
    pub location: String,
    pub address_space: Vec<String>,
    pub subnet_count: usize,
    pub requested_prefix: u8,
    pub status: Status,
    pub next_available: Option<String>,
    pub largest_free: Option<String>,
    pub free_blocks: Vec<String>,
    pub usable_free_addresses: u64,
    pub error: Option<String>,
}

impl VnetResult {
    pub fn base(r: &VnetRef, subscription_name: String, prefix: u8) -> Self {
        Self {
            subscription_name,
            subscription_id: r.subscription_id.clone(),
            vnet_name: r.name.clone(),
            resource_group: r.resource_group.clone(),
            location: r.location.clone(),
            address_space: vec![],
            subnet_count: 0,
            requested_prefix: prefix,
            status: Status::Error,
            next_available: None,
            largest_free: None,
            free_blocks: vec![],
            usable_free_addresses: 0,
            error: None,
        }
    }

    pub fn error(r: &VnetRef, subscription_name: String, prefix: u8, msg: String) -> Self {
        Self {
            error: Some(msg),
            ..Self::base(r, subscription_name, prefix)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub account: String,
    pub auth_method: String,
    pub tenant_id: String,
    pub subscriptions_scanned: usize,
    pub requested_prefix: u8,
    pub vnets_matched: usize,
    pub with_capacity: usize,
    pub without_capacity: usize,
    pub errors: usize,
    pub results: Vec<VnetResult>,
}

impl Report {
    pub fn new(
        auth: &TokenProvider,
        tenant_id: String,
        subs: usize,
        prefix: u8,
        results: Vec<VnetResult>,
    ) -> Self {
        let count = |s| results.iter().filter(|r| r.status == s).count();
        Self {
            account: format!(
                "{} ({})",
                auth.identity.display_name(),
                auth.identity.kind()
            ),
            auth_method: format!("{:?}", auth.method),
            tenant_id,
            subscriptions_scanned: subs,
            requested_prefix: prefix,
            vnets_matched: results.len(),
            with_capacity: count(Status::Available),
            without_capacity: count(Status::Exhausted),
            errors: count(Status::Error),
            results,
        }
    }
}

fn table() -> Table {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);
    t
}

pub fn print_table(r: &Report) {
    let size = 1u64 << (32 - r.requested_prefix);

    let mut summary = table();
    summary.set_header(vec!["Summary", ""]);
    summary.add_row(vec!["Account".into(), r.account.clone()]);
    summary.add_row(vec!["Auth".into(), r.auth_method.clone()]);
    summary.add_row(vec!["Tenant".into(), r.tenant_id.clone()]);
    summary.add_row(vec![
        "Subscriptions scanned".into(),
        r.subscriptions_scanned.to_string(),
    ]);
    summary.add_row(vec![
        "Requested size".into(),
        format!(
            "/{} ({size} addresses, {} usable in Azure)",
            r.requested_prefix,
            size.saturating_sub(AZURE_RESERVED_PER_SUBNET)
        ),
    ]);
    summary.add_row(vec!["VNets matched".into(), r.vnets_matched.to_string()]);
    summary.add_row(vec!["With capacity".into(), r.with_capacity.to_string()]);
    summary.add_row(vec![
        "Without capacity".into(),
        r.without_capacity.to_string(),
    ]);
    if r.errors > 0 {
        summary.add_row(vec!["Errors".into(), r.errors.to_string()]);
    }
    println!("{summary}");

    if r.results.is_empty() {
        println!("\nNo matching VNet found in the scanned subscriptions.");
        return;
    }

    let mut detail = table();
    detail.set_header(vec![
        "Subscription",
        "Subscription ID",
        "VNet",
        "Resource Group",
        "Subnets",
        "Next Available CIDR",
    ]);
    for row in &r.results {
        let next = match row.status {
            Status::Available => row.next_available.clone().unwrap_or_default(),
            Status::Exhausted => match &row.largest_free {
                Some(l) => format!("none (largest free: {l})"),
                None => "none (VNet full)".into(),
            },
            Status::Error => "error".into(),
        };
        detail.add_row(vec![
            Cell::new(&row.subscription_name),
            Cell::new(&row.subscription_id),
            Cell::new(&row.vnet_name),
            Cell::new(&row.resource_group),
            Cell::new(row.subnet_count).set_alignment(CellAlignment::Right),
            Cell::new(next),
        ]);
    }
    println!("{detail}");

    for row in r.results.iter().filter(|x| x.status != Status::Available) {
        let id = format!("{} / {}", row.subscription_name, row.vnet_name);
        if row.status == Status::Error {
            println!(
                "\n✗ {id}: {}",
                row.error.as_deref().unwrap_or("unknown error")
            );
            continue;
        }
        println!(
            "\n! {id}: no free /{} in {}.",
            row.requested_prefix,
            row.address_space.join(", ")
        );
        if row.address_space.len() > 1 {
            println!("  VNet has multiple IPv4 address spaces. Check each range for a free block:");
            for space in &row.address_space {
                println!("    - {space}");
            }
        }
        match &row.largest_free {
            Some(l) => {
                let p = l.rsplit('/').next().unwrap_or_default();
                println!("  Largest free block: {l} — re-run with --prefix {p}, or add an address space to the VNet.");
                let shown: Vec<&str> = row
                    .free_blocks
                    .iter()
                    .take(MAX_ADVICE_BLOCKS)
                    .map(String::as_str)
                    .collect();
                let more = row.free_blocks.len().saturating_sub(MAX_ADVICE_BLOCKS);
                println!(
                    "  Free blocks ({} addresses): {}{}",
                    row.usable_free_addresses,
                    shown.join(", "),
                    if more > 0 {
                        format!(" (+{more} more)")
                    } else {
                        String::new()
                    }
                );
            }
            None => {
                println!("  No block of /29 or larger remains — add an address space to the VNet.")
            }
        }
    }
}
