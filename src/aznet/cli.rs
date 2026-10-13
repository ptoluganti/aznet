use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::aznet::auth::AuthMethod;
use crate::aznet::ipam::AZURE_MIN_SUBNET_PREFIX;

#[derive(Parser, Debug)]
#[command(
    name = "aznet",
    version,
    about = "Azure network helper",
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Find the next free subnet of a given size in a VNet, across every subscription you can see
    GetNextSubnet(GetNextSubnetArgs),
}

#[derive(Args, Debug)]
pub struct GetNextSubnetArgs {
    /// VNet name (case-insensitive)
    #[arg(short = 'n', long, value_parser = parse_vnet_name)]
    pub vnet: String,

    /// Resource group containing the VNet (case-insensitive)
    #[arg(short = 'g', long, value_parser = parse_resource_group)]
    pub resource_group: String,

    /// Subnet size: "/27" or "27". Prefer "27" in Git Bash (MSYS rewrites "/27" into a path)
    #[arg(short = 'p', long, value_parser = parse_prefix)]
    pub prefix: u8,

    /// Limit search to these subscriptions (ID or display name, repeatable)
    #[arg(short = 's', long = "subscription")]
    pub subscriptions: Vec<String>,

    /// How to authenticate
    #[arg(long, value_enum, default_value_t = AuthMethod::Auto, env = "AZNET_AUTH")]
    pub auth: AuthMethod,

    /// Tenant to authenticate against (defaults to the credential's home tenant)
    #[arg(long, env = "AZNET_TENANT")]
    pub tenant: Option<String>,

    /// Client ID of a user-assigned managed identity (with --auth managed-identity)
    #[arg(long, env = "AZNET_MI_CLIENT_ID")]
    pub managed_identity_client_id: Option<String>,

    /// Output format
    #[arg(short = 'o', long, value_enum, default_value_t = Output::Table)]
    pub output: Output,

    /// Max concurrent VNet reads
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..=64))]
    pub concurrency: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Output {
    Table,
    Json,
}

fn parse_prefix(s: &str) -> Result<u8, String> {
    let p: u8 = s
        .trim()
        .trim_start_matches('/')
        .parse()
        .map_err(|_| format!("'{s}' is not a prefix length like /27"))?;
    if !(8..=AZURE_MIN_SUBNET_PREFIX).contains(&p) {
        return Err(format!("prefix must be between /8 and /{AZURE_MIN_SUBNET_PREFIX} (Azure's smallest IPv4 subnet)"));
    }
    Ok(p)
}

// Strict validation doubles as KQL-injection protection: the values are interpolated
// into a Resource Graph query, and neither charset admits quotes or pipes.
fn parse_vnet_name(s: &str) -> Result<String, String> {
    let ok = (2..=64).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && s.starts_with(|c: char| c.is_ascii_alphanumeric())
        && !s.ends_with('.');
    ok.then(|| s.to_string())
        .ok_or_else(|| "invalid VNet name (2-64 chars: letters, digits, '-', '_', '.')".into())
}

fn parse_resource_group(s: &str) -> Result<String, String> {
    let ok = (1..=90).contains(&s.chars().count())
        && s.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '(' | ')'))
        && !s.ends_with('.');
    ok.then(|| s.to_string()).ok_or_else(|| {
        "invalid resource group name (1-90 chars: letters, digits, - _ . ( ))".into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_forms() {
        assert_eq!(parse_prefix("/27"), Ok(27));
        assert_eq!(parse_prefix("28"), Ok(28));
        assert!(parse_prefix("/30").is_err());
        assert!(parse_prefix("abc").is_err());
    }

    #[test]
    fn names_reject_kql_metacharacters() {
        assert!(parse_vnet_name("vnet-hub-01").is_ok());
        assert!(parse_vnet_name("x' | project *").is_err());
        assert!(parse_resource_group("rg-net(prod)").is_ok());
        assert!(parse_resource_group("rg' or 1==1").is_err());
    }
}
