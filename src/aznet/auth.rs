//! Credential selection. No hard dependency on the az CLI.
//!
//! `auto` *selects* a credential from the environment instead of trying every source in turn
//! (the old `DefaultAzureCredential` behaviour). A half-configured service principal in CI
//! should fail loudly, not silently fall back to whichever human is logged into `az`.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use azure_core::credentials::{AccessToken, Secret, TokenCredential};
use azure_core::time::OffsetDateTime;
use azure_identity::{
    AzureCliCredential, AzureCliCredentialOptions, AzureDeveloperCliCredential,
    AzureDeveloperCliCredentialOptions, ClientSecretCredential, ManagedIdentityCredential,
    ManagedIdentityCredentialOptions, UserAssignedId, WorkloadIdentityCredential,
    WorkloadIdentityCredentialOptions,
};
use base64::Engine;
use clap::ValueEnum;
use serde::Deserialize;
use tokio::sync::Mutex;

pub const ARM_SCOPE: &str = "https://management.azure.com/.default";
/// Refresh this long before expiry so an in-flight request never carries a dead token.
const REFRESH_MARGIN: Duration = Duration::from_secs(300);
/// The SDK retries connection failures with backoff for up to ~60s. Cap it so a blocked
/// network fails fast with a useful message instead of a silent hang.
const AUTH_TIMEOUT: Duration = Duration::from_secs(25);

const ENV_TENANT: &str = "AZURE_TENANT_ID";
const ENV_CLIENT: &str = "AZURE_CLIENT_ID";
const ENV_SECRET: &str = "AZURE_CLIENT_SECRET";
const ENV_FED_TOKEN: &str = "AZURE_FEDERATED_TOKEN_FILE";

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum AuthMethod {
    /// Service principal / workload identity from env vars, else Azure CLI, else azd
    Auto,
    /// Azure CLI login (`az login`)
    Cli,
    /// Azure Developer CLI login (`azd auth login`)
    Azd,
    /// Service principal: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
    Env,
    /// Federated token: AKS workload identity, GitHub Actions OIDC (AZURE_FEDERATED_TOKEN_FILE)
    WorkloadIdentity,
    /// Managed identity (VM, App Service, Container Apps, Arc). Never auto-selected.
    ManagedIdentity,
}

#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    pub method: Option<AuthMethod>,
    pub tenant: Option<String>,
    pub managed_identity_client_id: Option<String>,
}

/// Who we authenticated as, read from the token's claims. Display only — ARM does the
/// real validation, so the signature is deliberately not checked here.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Identity {
    #[serde(rename = "tid", default)]
    pub tenant_id: String,
    #[serde(rename = "oid", default)]
    pub object_id: String,
    upn: Option<String>,
    unique_name: Option<String>,
    preferred_username: Option<String>,
    appid: Option<String>,
    azp: Option<String>,
    idtyp: Option<String>,
}

impl Identity {
    pub fn from_jwt(token: &str) -> Option<Self> {
        let payload = token.split('.').nth(1)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload.trim_end_matches('='))
            .ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn display_name(&self) -> String {
        let user = self
            .upn
            .as_ref()
            .or(self.unique_name.as_ref())
            .or(self.preferred_username.as_ref());
        match (user, self.app_id()) {
            (Some(u), _) => u.clone(),
            (None, Some(app)) => format!("app {app}"),
            (None, None) => format!("object {}", self.object_id),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self.idtyp.as_deref() {
            Some("user") => "user",
            Some("app") => "service principal / managed identity",
            _ if self.upn.is_some() || self.unique_name.is_some() => "user",
            _ => "service principal / managed identity",
        }
    }

    fn app_id(&self) -> Option<&String> {
        self.appid.as_ref().or(self.azp.as_ref())
    }
}

struct Cached {
    token: Secret,
    expires_on: OffsetDateTime,
}

/// Fetches lazily, caches, refreshes near expiry. Matters for the CLI credentials, which
/// spawn a process per `get_token` and don't cache themselves.
pub struct TokenProvider {
    credential: Arc<dyn TokenCredential>,
    cache: Mutex<Option<Cached>>,
    pub method: AuthMethod,
    pub identity: Identity,
}

impl fmt::Debug for TokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenProvider")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

impl TokenProvider {
    /// Resolves a credential and proves it works by acquiring an ARM token up front,
    /// so "not logged in" surfaces before any API work starts.
    pub async fn connect(cfg: &AuthConfig) -> Result<Self> {
        let method = resolve_method(cfg.method.unwrap_or(AuthMethod::Auto), &env_present)?;
        if cfg.managed_identity_client_id.is_some() && method != AuthMethod::ManagedIdentity {
            bail!("--managed-identity-client-id only applies with --auth managed-identity");
        }
        let (method, credential, token) = match method {
            // Developer tools: az first, then azd. Both are local logins of the same human,
            // so falling through between them is safe.
            AuthMethod::Auto => dev_tools(cfg).await?,
            m => {
                let c = build(m, cfg)?;
                let t = fetch(&*c).await.map_err(|e| explain(m, e))?;
                (m, c, t)
            }
        };
        let identity = Identity::from_jwt(token.token.secret()).unwrap_or_default();
        Ok(Self {
            credential,
            method,
            identity,
            cache: Mutex::new(Some(Cached {
                token: token.token,
                expires_on: token.expires_on,
            })),
        })
    }

    pub async fn token(&self) -> Result<Secret> {
        let mut guard = self.cache.lock().await;
        if let Some(c) = guard.as_ref() {
            if c.expires_on - REFRESH_MARGIN > OffsetDateTime::now_utc() {
                return Ok(c.token.clone());
            }
        }
        let t = fetch(&*self.credential)
            .await
            .map_err(|e| explain(self.method, e))?;
        let secret = t.token.clone();
        *guard = Some(Cached {
            token: t.token,
            expires_on: t.expires_on,
        });
        Ok(secret)
    }
}

async fn fetch(c: &dyn TokenCredential) -> azure_core::Result<AccessToken> {
    match tokio::time::timeout(AUTH_TIMEOUT, c.get_token(&[ARM_SCOPE], None)).await {
        Ok(r) => r,
        Err(_) => Err(azure_core::Error::with_message(
            azure_core::error::ErrorKind::Credential,
            format!(
                "timed out after {}s acquiring a token. Check network/proxy access to \
                 login.microsoftonline.com (HTTPS_PROXY is honoured)",
                AUTH_TIMEOUT.as_secs()
            ),
        )),
    }
}

async fn dev_tools(
    cfg: &AuthConfig,
) -> Result<(AuthMethod, Arc<dyn TokenCredential>, AccessToken)> {
    let mut errors = Vec::new();
    for m in [AuthMethod::Cli, AuthMethod::Azd] {
        let c = build(m, cfg)?;
        match fetch(&*c).await {
            Ok(t) => return Ok((m, c, t)),
            Err(e) => errors.push(format!("  {m:?}: {e}")),
        }
    }
    bail!(
        "no Azure credential available. Do one of:\n\
         \x20 - `az login` (or `azd auth login`) for interactive use\n\
         \x20 - set {ENV_TENANT}, {ENV_CLIENT}, {ENV_SECRET} for a service principal\n\
         \x20 - set {ENV_FED_TOKEN} (+ tenant/client id) for workload identity / OIDC\n\
         \x20 - pass --auth managed-identity on an Azure-hosted machine\n\
         Attempts:\n{}",
        errors.join("\n")
    )
}

/// Pure so the selection rules are unit-testable without touching the process env.
pub fn resolve_method(requested: AuthMethod, has: &dyn Fn(&str) -> bool) -> Result<AuthMethod> {
    if requested != AuthMethod::Auto {
        return Ok(requested);
    }
    if has(ENV_SECRET) {
        let missing: Vec<_> = [ENV_TENANT, ENV_CLIENT]
            .into_iter()
            .filter(|v| !has(v))
            .collect();
        if !missing.is_empty() {
            bail!(
                "{ENV_SECRET} is set but {} missing — refusing to fall back to another identity",
                missing.join(" and ")
            );
        }
        return Ok(AuthMethod::Env);
    }
    if has(ENV_FED_TOKEN) {
        return Ok(AuthMethod::WorkloadIdentity);
    }
    Ok(AuthMethod::Auto)
}

fn env_present(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

fn env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set"))
}

fn build(method: AuthMethod, cfg: &AuthConfig) -> Result<Arc<dyn TokenCredential>> {
    let tenant = cfg.tenant.clone();
    let c: Arc<dyn TokenCredential> = match method {
        AuthMethod::Cli => AzureCliCredential::new(Some(AzureCliCredentialOptions {
            tenant_id: tenant,
            ..Default::default()
        }))?,
        AuthMethod::Azd => {
            AzureDeveloperCliCredential::new(Some(AzureDeveloperCliCredentialOptions {
                tenant_id: tenant,
                ..Default::default()
            }))?
        }
        AuthMethod::Env => {
            let tenant = match tenant {
                Some(t) => t,
                None => env(ENV_TENANT)?,
            };
            ClientSecretCredential::new(
                &tenant,
                env(ENV_CLIENT)?,
                Secret::new(env(ENV_SECRET)?),
                None,
            )?
        }
        AuthMethod::WorkloadIdentity => {
            WorkloadIdentityCredential::new(Some(WorkloadIdentityCredentialOptions {
                tenant_id: tenant,
                ..Default::default()
            }))?
        }
        AuthMethod::ManagedIdentity => {
            ManagedIdentityCredential::new(Some(ManagedIdentityCredentialOptions {
                user_assigned_id: cfg
                    .managed_identity_client_id
                    .clone()
                    .map(UserAssignedId::ClientId),
                ..Default::default()
            }))?
        }
        AuthMethod::Auto => unreachable!("auto is resolved before build"),
    };
    Ok(c)
}

fn explain(method: AuthMethod, e: azure_core::Error) -> anyhow::Error {
    let hint = match method {
        AuthMethod::Cli => "run `az login` (install: https://aka.ms/azcli)",
        AuthMethod::Azd => "run `azd auth login`",
        AuthMethod::Env => "check AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET",
        AuthMethod::WorkloadIdentity => {
            "check the federated credential and AZURE_FEDERATED_TOKEN_FILE"
        }
        AuthMethod::ManagedIdentity => {
            "this must run on an Azure host with a managed identity assigned"
        }
        AuthMethod::Auto => "",
    };
    anyhow!("{method:?} authentication failed: {e}\nhint: {hint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(vars: &'static [&'static str]) -> impl Fn(&str) -> bool {
        move |n| vars.contains(&n)
    }

    #[test]
    fn explicit_method_wins() {
        let m = resolve_method(AuthMethod::ManagedIdentity, &with(&[ENV_SECRET])).unwrap();
        assert_eq!(m, AuthMethod::ManagedIdentity);
    }

    #[test]
    fn full_sp_env_selects_env() {
        let m = resolve_method(
            AuthMethod::Auto,
            &with(&[ENV_SECRET, ENV_TENANT, ENV_CLIENT]),
        )
        .unwrap();
        assert_eq!(m, AuthMethod::Env);
    }

    #[test]
    fn partial_sp_env_fails_instead_of_falling_back() {
        let e = resolve_method(AuthMethod::Auto, &with(&[ENV_SECRET, ENV_CLIENT])).unwrap_err();
        assert!(e.to_string().contains(ENV_TENANT));
    }

    #[test]
    fn federated_token_selects_workload_identity() {
        let m = resolve_method(AuthMethod::Auto, &with(&[ENV_FED_TOKEN, ENV_CLIENT])).unwrap();
        assert_eq!(m, AuthMethod::WorkloadIdentity);
    }

    #[test]
    fn nothing_set_means_developer_tools() {
        assert_eq!(
            resolve_method(AuthMethod::Auto, &with(&[])).unwrap(),
            AuthMethod::Auto
        );
    }

    fn jwt(claims: &str) -> String {
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!("{}.{}.sig", b.encode(r#"{"alg":"none"}"#), b.encode(claims))
    }

    #[test]
    fn identity_from_user_token() {
        let id = Identity::from_jwt(&jwt(
            r#"{"tid":"t1","oid":"o1","upn":"me@contoso.com","idtyp":"user"}"#,
        ))
        .unwrap();
        assert_eq!(id.display_name(), "me@contoso.com");
        assert_eq!(id.kind(), "user");
        assert_eq!(id.tenant_id, "t1");
    }

    #[test]
    fn identity_from_app_token() {
        let id = Identity::from_jwt(&jwt(
            r#"{"tid":"t1","oid":"o1","appid":"a1","idtyp":"app"}"#,
        ))
        .unwrap();
        assert_eq!(id.display_name(), "app a1");
        assert_eq!(id.kind(), "service principal / managed identity");
    }

    #[test]
    fn garbage_token_is_none() {
        assert!(Identity::from_jwt("not-a-jwt").is_none());
    }
}
