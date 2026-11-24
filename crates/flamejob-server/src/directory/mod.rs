//! Directory (AD/LDAP) authentication and SID->role mapping — flamejob v2.0
//! Phase 5. Connection config is a runtime-editable singleton row
//! (`directory_config`), the service-account bind password is encrypted at rest
//! with the shared cipher, and all authorization matching is on immutable group
//! `objectSid`s. See `claude/ad-ldap-integration-design.md`.

pub mod client;
pub mod resolve;
pub mod routes;
pub mod util;

use chrono::{DateTime, Utc};
use flamejob_core::Role;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::error::AppError;
use flamejob_db::Db;

/// Transport security for the directory connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// LDAPS (implicit TLS, usually tcp/636).
    Ldaps,
    /// StartTLS on the plain port (usually tcp/389), upgraded to TLS.
    StartTls,
    /// Plain LDAP, no TLS — opt-in, acknowledged, never the default.
    Plaintext,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Ldaps => "ldaps",
            Transport::StartTls => "starttls",
            Transport::Plaintext => "plaintext",
        }
    }
    pub fn parse(s: &str) -> Transport {
        match s {
            "starttls" => Transport::StartTls,
            "plaintext" => Transport::Plaintext,
            _ => Transport::Ldaps,
        }
    }
    pub fn is_tls(self) -> bool {
        !matches!(self, Transport::Plaintext)
    }
    pub fn default_port(self) -> u16 {
        match self {
            Transport::Ldaps => 636,
            _ => 389,
        }
    }
}

/// Runtime directory configuration, loaded from the `directory_config` row.
/// The bind password stays encrypted here and is only decrypted inside the
/// client at bind time.
#[derive(Clone, Debug)]
pub struct DirectoryConfig {
    pub enabled: bool,
    pub transport: Transport,
    pub discovery: String,
    pub domain: Option<String>,
    pub servers: Vec<String>,
    pub use_global_catalog: bool,
    pub base_dn: Option<String>,
    pub bind_dn: Option<String>,
    pub bind_password_enc: Option<Vec<u8>>,
    pub user_filter: String,
    pub login_attributes: Vec<String>,
    pub ca_bundle_pem: Option<String>,
    pub verify_hostname: bool,
    pub allow_insecure_tls: bool,
    pub plaintext_ack: bool,
    pub group_source: String,
    pub cache_ttl_secs: i32,
    pub on_directory_down: String,
    pub default_role: Option<Role>,
    pub jwt_ttl_hours: i32,
    pub last_test_ok_at: Option<DateTime<Utc>>,
}

fn parse_role(s: &str) -> Option<Role> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

/// Load the singleton directory config row into the runtime struct.
pub async fn load_config(db: &Db) -> Result<DirectoryConfig, AppError> {
    let row = sqlx::query(
        "SELECT enabled, transport, discovery, domain, servers, use_global_catalog, \
                base_dn, bind_dn, bind_password_enc, user_filter, login_attributes, \
                ca_bundle_pem, verify_hostname, allow_insecure_tls, plaintext_ack, \
                group_source, cache_ttl_secs, on_directory_down, default_role::text, \
                jwt_ttl_hours, last_test_ok_at \
         FROM directory_config WHERE id = 1",
    )
    .fetch_one(db)
    .await?;

    Ok(DirectoryConfig {
        enabled: row.get("enabled"),
        transport: Transport::parse(row.get::<String, _>("transport").as_str()),
        discovery: row.get("discovery"),
        domain: row.get("domain"),
        servers: row.get("servers"),
        use_global_catalog: row.get("use_global_catalog"),
        base_dn: row.get("base_dn"),
        bind_dn: row.get("bind_dn"),
        bind_password_enc: row.get("bind_password_enc"),
        user_filter: row.get("user_filter"),
        login_attributes: row.get("login_attributes"),
        ca_bundle_pem: row.get("ca_bundle_pem"),
        verify_hostname: row.get("verify_hostname"),
        allow_insecure_tls: row.get("allow_insecure_tls"),
        plaintext_ack: row.get("plaintext_ack"),
        group_source: row.get("group_source"),
        cache_ttl_secs: row.get("cache_ttl_secs"),
        on_directory_down: row.get("on_directory_down"),
        default_role: row
            .get::<Option<String>, _>("default_role")
            .as_deref()
            .and_then(parse_role),
        jwt_ttl_hours: row.get("jwt_ttl_hours"),
        last_test_ok_at: row.get("last_test_ok_at"),
    })
}

/// The `(group_sid, role)` map rows, for the pure resolver.
pub async fn load_role_map(db: &Db) -> Result<Vec<(String, Role)>, AppError> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT group_sid, role::text FROM directory_role_map")
            .fetch_all(db)
            .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(sid, r)| parse_role(&r).map(|role| (sid, role)))
        .collect())
}
