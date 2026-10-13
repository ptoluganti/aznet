use std::path::PathBuf;

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

    /// Scaffold a new repository from a built-in template
    New(NewArgs),
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

#[derive(Args, Debug)]
pub struct NewArgs {
    /// Repository template
    pub template: Template,

    /// Directory to create (must be absent or empty unless --force)
    pub path: PathBuf,

    /// Project name used inside the files [default: the directory name]
    #[arg(long, value_parser = parse_project_name)]
    pub name: Option<String>,

    /// One-line description for README and package.json
    #[arg(short = 'd', long, value_parser = parse_description)]
    pub description: Option<String>,

    /// Terraform version pinned in .terraform-version (Terraform templates)
    #[arg(long, default_value = "1.13.3", value_parser = parse_version)]
    pub terraform_version: String,

    /// Run `git init -b main` in the new directory
    #[arg(long)]
    pub git: bool,

    /// Write into a non-empty directory, overwriting files the template provides
    #[arg(long)]
    pub force: bool,

    /// Print the files that would be written without writing them
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Template {
    /// Terraform deployment: root config + local modules, per-env tfvars/backends, Azure DevOps CI/CD, pre-commit, commitlint
    TerraformDeployment,
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

/// Lowercase so the same name is valid for npm, ADO environments and Terraform state keys.
pub fn parse_project_name(s: &str) -> Result<String, String> {
    let ok = (1..=64).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'))
        && s.starts_with(|c: char| c.is_ascii_alphanumeric());
    ok.then(|| s.to_string()).ok_or_else(|| {
        format!("invalid project name '{s}' (1-64 chars: lowercase letters, digits, '-', '_')")
    })
}

// Rendered verbatim into JSON, YAML and Markdown, so keep out anything that needs escaping.
fn parse_description(s: &str) -> Result<String, String> {
    let ok = !s.trim().is_empty()
        && s.len() <= 200
        && !s
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\' | '`'));
    ok.then(|| s.trim().to_string()).ok_or_else(|| {
        "description must be 1-200 chars without quotes, backslashes or backticks".into()
    })
}

fn parse_version(s: &str) -> Result<String, String> {
    let parts: Vec<_> = s.split('.').collect();
    let ok = parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    ok.then(|| s.to_string())
        .ok_or_else(|| format!("'{s}' is not an exact version like 1.13.3"))
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

    #[test]
    fn new_args_validation() {
        assert!(parse_project_name("platform-infra_01").is_ok());
        assert!(parse_project_name("Platform").is_err());
        assert!(parse_project_name("-x").is_err());
        assert!(parse_description("Hub networking").is_ok());
        assert!(parse_description("say \"hi\"").is_err());
        assert!(parse_version("1.13.3").is_ok());
        assert!(parse_version("~> 1.13").is_err());
    }
}
