use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use crate::aznet::auth::{AuthConfig, AuthMethod};
use crate::aznet::azure::TagFilter;
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

    /// Report the compliance state of resources against a policy definition and/or assignment
    CheckPolicyCompliance(CheckPolicyComplianceArgs),

    /// Scaffold a new repository from a built-in template
    New(NewArgs),
}

/// Credential selection, shared by every command that talks to Azure.
#[derive(Args, Debug)]
pub struct AuthArgs {
    /// How to authenticate
    #[arg(long = "auth", value_enum, default_value_t = AuthMethod::Auto, env = "AZNET_AUTH")]
    pub method: AuthMethod,

    /// Tenant to authenticate against (defaults to the credential's home tenant)
    #[arg(long, env = "AZNET_TENANT")]
    pub tenant: Option<String>,

    /// Client ID of a user-assigned managed identity (with --auth managed-identity)
    #[arg(long, env = "AZNET_MI_CLIENT_ID")]
    pub managed_identity_client_id: Option<String>,
}

impl From<&AuthArgs> for AuthConfig {
    fn from(a: &AuthArgs) -> Self {
        Self {
            method: Some(a.method),
            tenant: a.tenant.clone(),
            managed_identity_client_id: a.managed_identity_client_id.clone(),
        }
    }
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

    #[command(flatten)]
    pub auth: AuthArgs,

    /// Output format
    #[arg(short = 'o', long, value_enum, default_value_t = Output::Table)]
    pub output: Output,

    /// Max concurrent VNet reads
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..=64))]
    pub concurrency: u16,
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("policy")
        .args(["policy_definition", "policy_assignment"])
        .required(true)
        .multiple(true)
))]
pub struct CheckPolicyComplianceArgs {
    /// Policy or initiative definition: display name, name (usually a GUID) or full resource ID
    #[arg(short = 'd', long, value_parser = parse_kql_value)]
    pub policy_definition: Option<String>,

    /// Policy assignment: display name, name or full resource ID. Initiatives report each member policy
    #[arg(short = 'a', long, value_parser = parse_kql_value)]
    pub policy_assignment: Option<String>,

    /// Resources to check, by name or full ID: comma-separated and/or repeated. Omit to report
    /// every resource the policy evaluated
    #[arg(short = 'r', long = "resource", value_delimiter = ',', value_parser = parse_resource)]
    pub resources: Vec<String>,

    /// Only resources in this resource group (case-insensitive)
    #[arg(short = 'g', long, value_parser = parse_resource_group)]
    pub resource_group: Option<String>,

    /// Only resources with this tag: "key" (any value) or "key=value"; repeatable, all must match
    #[arg(short = 't', long = "tag", value_parser = parse_tag)]
    pub tags: Vec<TagFilter>,

    /// Limit search to these subscriptions (ID or display name, repeatable)
    #[arg(short = 's', long = "subscription")]
    pub subscriptions: Vec<String>,

    /// Fetch only states that aren't compliant (smaller output for broad assignments)
    #[arg(long)]
    pub non_compliant_only: bool,

    #[command(flatten)]
    pub auth: AuthArgs,

    /// Output format
    #[arg(short = 'o', long, value_enum, default_value_t = Output::Table)]
    pub output: Output,
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

// Policy and resource IDs can hold characters a strict charset would wrongly reject, so these
// are escaped into KQL string literals (`azure::kql_string`) instead; reject only what can't be
// escaped safely or can't be real.
fn parse_kql_value(s: &str) -> Result<String, String> {
    let s = s.trim();
    let ok = (1..=1024).contains(&s.len()) && !s.chars().any(char::is_control);
    ok.then(|| s.to_string())
        .ok_or_else(|| "must be 1-1024 characters without control characters".into())
}

fn parse_tag(s: &str) -> Result<TagFilter, String> {
    let s = parse_kql_value(s)?;
    let (key, value) = match s.split_once('=') {
        Some((k, v)) => (k.trim(), Some(v.trim().to_string())),
        None => (s.as_str(), None),
    };
    // Azure tag limits: key 512 chars, value 256.
    if key.is_empty() || key.len() > 512 || value.as_ref().is_some_and(|v| v.len() > 256) {
        return Err("expected key or key=value (key 1-512 chars, value up to 256)".into());
    }
    Ok(TagFilter {
        key: key.to_string(),
        value,
    })
}

/// A resource name, or a full resource ID (anything starting with `/`, or a Git Bash rewrite of one).
fn parse_resource(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.starts_with('/') || s.contains(":/") {
        return parse_resource_id(s);
    }
    let ok = (1..=260).contains(&s.len()) && !s.chars().any(char::is_control);
    ok.then(|| s.to_string())
        .ok_or_else(|| "expected a resource name (1-260 characters) or a full resource ID".into())
}

fn parse_resource_id(s: &str) -> Result<String, String> {
    let s = parse_kql_value(s)?.trim_end_matches('/').to_string();
    // Git Bash (MSYS) rewrites a leading "/subscriptions/..." into "C:/Program Files/Git/subscriptions/...".
    if s.contains(":/") && s.to_ascii_lowercase().contains("/subscriptions/") {
        return Err(
            "looks like Git Bash rewrote the leading '/' into a Windows path; \
             run with MSYS_NO_PATHCONV=1, or use PowerShell/cmd"
                .into(),
        );
    }
    let ok = s.to_ascii_lowercase().starts_with("/subscriptions/") && s.split('/').count() >= 3;
    ok.then_some(s).ok_or_else(|| {
        "expected a full resource ID: /subscriptions/<id>/resourceGroups/<rg>/providers/...".into()
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
mod tests;
