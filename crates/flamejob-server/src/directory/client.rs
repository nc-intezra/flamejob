//! LDAP I/O: search-then-bind authentication and `tokenGroups` resolution via
//! the `ldap3` async client. This module is the only part of the directory
//! feature that touches the network; the logic it depends on (SID formatting,
//! filter escaping, bind-error decoding, role resolution) lives in `util`/
//! `resolve` and is unit-tested. CI has no directory server, so these functions
//! are not exercised there.

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

use super::util::{
    describe_bind_error, escape_filter, extract_ad_sub_code, format_sid, password_is_bindable,
};
use super::{DirectoryConfig, Transport};
use crate::crypto::Cipher;

/// Outcome of a directory authentication attempt.
#[derive(Debug)]
pub enum DirectoryError {
    /// Config is incomplete (missing base DN, bind account, servers, …).
    Config(String),
    /// Could not reach / service-bind to any directory server.
    Unreachable(String),
    /// The user was not found under the base DN.
    NoSuchUser,
    /// The user's own credentials were rejected (message is operator-facing).
    BadCredentials(String),
}

/// A directory user resolved and credential-verified.
#[derive(Debug, Clone)]
pub struct ResolvedUser {
    pub dn: String,
    pub sid: Option<String>,
    pub group_sids: Vec<String>,
    /// Which server answered (for audit).
    pub server: String,
}

/// One stage of a connection test, for the config page.
#[derive(Debug, Clone)]
pub struct TestStep {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

fn connect_settings(cfg: &DirectoryConfig) -> LdapConnSettings {
    let mut s = LdapConnSettings::new();
    if cfg.transport == Transport::StartTls {
        s = s.set_starttls(true);
    }
    if cfg.transport.is_tls() && cfg.allow_insecure_tls {
        s = s.set_no_tls_verify(true);
    }
    // NOTE (follow-up): an in-DB `ca_bundle_pem` for a private CA is accepted and
    // stored, but not yet wired into the rustls client config here; today TLS
    // trusts the system root store (or, in a lab, `allow_insecure_tls`). Wiring a
    // custom trust anchor is tracked for a later increment.
    s
}

fn server_url(cfg: &DirectoryConfig, server: &str) -> String {
    let scheme = if cfg.transport == Transport::Ldaps {
        "ldaps"
    } else {
        "ldap"
    };
    // Honor an explicit host:port; otherwise apply the transport's default port
    // (or the Global Catalog port when requested).
    if server.contains(':') {
        format!("{scheme}://{server}")
    } else {
        let port = if cfg.use_global_catalog && cfg.transport == Transport::Ldaps {
            3269
        } else if cfg.use_global_catalog {
            3268
        } else {
            cfg.transport.default_port()
        };
        format!("{scheme}://{server}:{port}")
    }
}

fn candidate_servers(cfg: &DirectoryConfig) -> Vec<String> {
    // PR1 supports a static server list. SRV discovery
    // (_ldap._tcp.dc._msdcs.<domain>) is a tracked follow-up.
    cfg.servers.clone()
}

fn decrypt_bind_password(cfg: &DirectoryConfig, cipher: &Cipher) -> Option<String> {
    cfg.bind_password_enc
        .as_deref()
        .and_then(|enc| cipher.decrypt(enc))
        .and_then(|v| String::from_utf8(v).ok())
}

/// Full search-then-bind + group resolution against the first reachable server.
pub async fn authenticate(
    cfg: &DirectoryConfig,
    cipher: &Cipher,
    login: &str,
    password: &str,
) -> Result<ResolvedUser, DirectoryError> {
    // Guard BEFORE any bind: AD may treat non-empty DN + empty password as a
    // successful "unauthenticated bind".
    if !password_is_bindable(password) {
        return Err(DirectoryError::BadCredentials("empty password".into()));
    }
    let base_dn = cfg
        .base_dn
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DirectoryError::Config("base DN not set".into()))?;
    let bind_dn = cfg
        .bind_dn
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DirectoryError::Config("service bind DN not set".into()))?;
    let bind_pw = decrypt_bind_password(cfg, cipher)
        .ok_or_else(|| DirectoryError::Config("service bind password not set".into()))?;
    let servers = candidate_servers(cfg);
    if servers.is_empty() {
        return Err(DirectoryError::Config(
            "no directory servers configured".into(),
        ));
    }

    let settings = connect_settings(cfg);
    let mut last_err = String::from("no servers tried");

    for server in servers {
        let url = server_url(cfg, &server);
        match authenticate_on(
            &url, cfg, bind_dn, &bind_pw, base_dn, login, password, &settings,
        )
        .await
        {
            Ok(mut user) => {
                user.server = server;
                return Ok(user);
            }
            // A credential rejection / missing user is definitive — don't fail
            // over to another DC and risk an AD lockout storm.
            Err(e @ DirectoryError::BadCredentials(_)) => return Err(e),
            Err(DirectoryError::NoSuchUser) => return Err(DirectoryError::NoSuchUser),
            Err(DirectoryError::Config(m)) => return Err(DirectoryError::Config(m)),
            Err(DirectoryError::Unreachable(m)) => last_err = m, // try the next server
        }
    }
    Err(DirectoryError::Unreachable(last_err))
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_on(
    url: &str,
    cfg: &DirectoryConfig,
    bind_dn: &str,
    bind_pw: &str,
    base_dn: &str,
    login: &str,
    password: &str,
    settings: &LdapConnSettings,
) -> Result<ResolvedUser, DirectoryError> {
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings.clone(), url)
        .await
        .map_err(|e| DirectoryError::Unreachable(format!("{url}: {e}")))?;
    ldap3::drive!(conn);

    // 1) Service bind.
    ldap.simple_bind(bind_dn, bind_pw)
        .await
        .map_err(|e| DirectoryError::Unreachable(format!("{url}: {e}")))?
        .success()
        .map_err(|e| DirectoryError::Unreachable(format!("{url}: service bind failed: {e}")))?;

    // 2) Search for the user, retrieving DN + objectSid.
    let filter = cfg.user_filter.replace("%u", &escape_filter(login));
    let (entries, _res) = ldap
        .search(base_dn, Scope::Subtree, &filter, vec!["objectSid"])
        .await
        .map_err(|e| DirectoryError::Unreachable(format!("{url}: search failed: {e}")))?
        .success()
        .map_err(|e| DirectoryError::Unreachable(format!("{url}: search failed: {e}")))?;
    let entry = entries
        .into_iter()
        .next()
        .ok_or(DirectoryError::NoSuchUser)?;
    let se = SearchEntry::construct(entry);
    let user_dn = se.dn.clone();
    if user_dn.is_empty() {
        return Err(DirectoryError::NoSuchUser);
    }
    let sid = se
        .bin_attrs
        .get("objectSid")
        .and_then(|v| v.first())
        .and_then(|b| format_sid(b));

    // 3) Re-bind as the user on a FRESH connection to verify credentials.
    {
        let (uconn, mut uldap) = LdapConnAsync::with_settings(settings.clone(), url)
            .await
            .map_err(|e| DirectoryError::Unreachable(format!("{url}: {e}")))?;
        ldap3::drive!(uconn);
        let res = uldap
            .simple_bind(&user_dn, password)
            .await
            .map_err(|e| DirectoryError::Unreachable(format!("{url}: {e}")))?;
        if res.rc != 0 {
            let sub = extract_ad_sub_code(&res.text);
            let _ = uldap.unbind().await;
            return Err(DirectoryError::BadCredentials(describe_bind_error(
                res.rc,
                sub.as_deref(),
            )));
        }
        let _ = uldap.unbind().await;
    }

    // 4) Resolve effective groups via tokenGroups (base-scoped on the user DN).
    let group_sids = read_token_groups(&mut ldap, &user_dn).await;
    let _ = ldap.unbind().await;

    Ok(ResolvedUser {
        dn: user_dn,
        sid,
        group_sids,
        server: String::new(),
    })
}

/// Read `tokenGroups` (authoritative effective SIDs incl. nested + primary) from
/// a base-scoped search of the user object. Returns an empty vec on failure
/// (the caller then applies default-deny / default-role).
async fn read_token_groups(ldap: &mut ldap3::Ldap, user_dn: &str) -> Vec<String> {
    let Ok(res) = ldap
        .search(user_dn, Scope::Base, "(objectClass=*)", vec!["tokenGroups"])
        .await
    else {
        return Vec::new();
    };
    let Ok((entries, _)) = res.success() else {
        return Vec::new();
    };
    let Some(entry) = entries.into_iter().next() else {
        return Vec::new();
    };
    let se = SearchEntry::construct(entry);
    se.bin_attrs
        .get("tokenGroups")
        .map(|vals| vals.iter().filter_map(|b| format_sid(b)).collect())
        .unwrap_or_default()
}

/// Staged connection test for the config page: discovery -> connect/TLS ->
/// service bind -> (optional) sample search. Persists nothing.
pub async fn test_connection(
    cfg: &DirectoryConfig,
    cipher: &Cipher,
    sample_user: Option<&str>,
) -> Vec<TestStep> {
    let mut steps = Vec::new();
    let servers = candidate_servers(cfg);
    if servers.is_empty() {
        steps.push(TestStep {
            name: "discovery".into(),
            ok: false,
            detail: "no servers configured (static list empty)".into(),
        });
        return steps;
    }
    steps.push(TestStep {
        name: "discovery".into(),
        ok: true,
        detail: format!("{} server(s): {}", servers.len(), servers.join(", ")),
    });

    let settings = connect_settings(cfg);
    let url = server_url(cfg, &servers[0]);
    let tls_note = match cfg.transport {
        Transport::Plaintext => "no TLS — credentials cross the network in cleartext".to_string(),
        t => format!("{} (verify_hostname={})", t.as_str(), cfg.verify_hostname),
    };

    let (conn, mut ldap) = match LdapConnAsync::with_settings(settings.clone(), &url).await {
        Ok(v) => v,
        Err(e) => {
            steps.push(TestStep {
                name: "connect+tls".into(),
                ok: false,
                detail: format!("{url}: {e}"),
            });
            return steps;
        }
    };
    ldap3::drive!(conn);
    steps.push(TestStep {
        name: "connect+tls".into(),
        ok: true,
        detail: format!("connected to {url}; {tls_note}"),
    });

    // Service bind.
    let bind_dn = cfg.bind_dn.clone().unwrap_or_default();
    let bind_pw = decrypt_bind_password(cfg, cipher).unwrap_or_default();
    match ldap
        .simple_bind(&bind_dn, &bind_pw)
        .await
        .map(|r| r.success())
    {
        Ok(Ok(_)) => steps.push(TestStep {
            name: "service-bind".into(),
            ok: true,
            detail: format!("bound as {bind_dn}"),
        }),
        Ok(Err(e)) => {
            let sub = extract_ad_sub_code(&e.to_string());
            steps.push(TestStep {
                name: "service-bind".into(),
                ok: false,
                detail: describe_bind_error(49, sub.as_deref()),
            });
            return steps;
        }
        Err(e) => {
            steps.push(TestStep {
                name: "service-bind".into(),
                ok: false,
                detail: e.to_string(),
            });
            return steps;
        }
    }

    // Optional sample search.
    if let Some(user) = sample_user.filter(|s| !s.is_empty()) {
        let base = cfg.base_dn.clone().unwrap_or_default();
        let filter = cfg.user_filter.replace("%u", &escape_filter(user));
        match ldap
            .search(&base, Scope::Subtree, &filter, vec!["objectSid"])
            .await
            .map(|r| r.success())
        {
            Ok(Ok((entries, _))) => {
                let n = entries.len();
                steps.push(TestStep {
                    name: "sample-search".into(),
                    ok: n == 1,
                    detail: format!(
                        "filter matched {n} entr{}",
                        if n == 1 { "y" } else { "ies" }
                    ),
                });
            }
            Ok(Err(e)) | Err(e) => steps.push(TestStep {
                name: "sample-search".into(),
                ok: false,
                detail: e.to_string(),
            }),
        }
    }
    let _ = ldap.unbind().await;
    steps
}
