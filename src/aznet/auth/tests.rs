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
