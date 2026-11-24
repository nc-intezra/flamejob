use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerCfg,
    pub database: DatabaseCfg,
    pub auth: AuthCfg,
    pub hashcat: HashcatCfg,
    pub crypto: CryptoCfg,
    pub scheduler: SchedulerCfg,
    pub telemetry: TelemetryCfg,
    #[serde(default)]
    pub web: WebCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCfg {
    pub bind: String,
    /// PEM cert + key for the API listener. When both are set the API is served
    /// over HTTPS (rustls); otherwise it is served over plain HTTP and transport
    /// TLS is expected to be terminated by a reverse proxy (e.g. Caddy). Use this
    /// to serve a pre-created certificate from an enterprise CA directly, with no
    /// proxy. Both must be set together.
    #[serde(default)]
    pub tls_cert: Option<String>,
    #[serde(default)]
    pub tls_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseCfg {
    /// 'local' = installer manages a Postgres on this box; 'external' = use dsn.
    pub mode: String,
    pub dsn: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCfg {
    pub jwt_secret: String,
    pub token_ttl_hours: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashcatCfg {
    pub binary: String,
    pub data_dir: String,
    pub workload: u8,
    /// Soft cap on the TOTAL size of all uploaded files (wordlists, rules, masks,
    /// other) in bytes. 0 = unlimited (default). When set, an upload that would
    /// push the stored total past this ceiling is rejected (HTTP 507). Distinct
    /// from the per-request body limit (`MAX_FILE_UPLOAD_BYTES`); this bounds the
    /// cumulative corpus. Surfaced to the dashboard's total-storage gauge.
    #[serde(default)]
    pub files_quota_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoCfg {
    pub plaintext_key_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerCfg {
    /// Keyspace units per chunk. hashcat's reported keyspace is divided into
    /// chunks of this size (capped by max_chunks). 0 or an unknown keyspace
    /// means a single full-keyspace task.
    pub chunk_size: i64,
    pub max_chunks: i64,
    /// "local" runs chunks as hashcat subprocesses on this box; "remote"
    /// dispatches them to enrolled agents over the WebSocket protocol.
    pub runner: String,
    /// How many chunks of the active job run concurrently on the LOCAL runner.
    /// Default 1 (one hashcat subprocess at a time). The remote runner ignores
    /// this and instead fans chunks across the fleet's reported free slots.
    #[serde(default = "default_local_parallelism")]
    pub local_parallelism: usize,
    /// How many jobs may run concurrently (admitted at once). Their chunks share
    /// the fleet's capacity. 0 = unlimited. Default 8.
    #[serde(default = "default_max_concurrent_jobs")]
    pub max_concurrent_jobs: usize,
    /// Display name for work run on this server host by the local runner (shown
    /// as the executing "agent" in the dashboard when no agents are enrolled).
    /// Defaults to the machine hostname.
    #[serde(default = "default_local_agent_name")]
    pub local_agent_name: String,
}

fn default_local_parallelism() -> usize {
    1
}

fn default_max_concurrent_jobs() -> usize {
    8
}

fn default_local_agent_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "local-host".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryCfg {
    /// Whether the local GPU/host telemetry collector runs.
    pub enabled: bool,
    /// Seconds between metric samples.
    pub sample_interval_secs: u64,
    /// Max rows returned by the per-device history endpoint.
    pub history_limit: i64,
}

/// The browser-facing web dashboard. Served on its own listener, separate from
/// the API (`[server].bind`). The dashboard is a static single-page app that
/// talks to the existing API over HTTP(S); the API enables CORS so the browser
/// can reach it cross-origin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebCfg {
    /// Serve the web dashboard listener at all.
    pub enabled: bool,
    /// Listen address for the dashboard.
    pub bind: String,
    /// PEM cert + key. When both are set the dashboard is served over HTTPS;
    /// otherwise it is served over plain HTTP.
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// Absolute API base URL the browser should call (e.g. behind a reverse
    /// proxy: `https://flamejob.example/api`). When unset, the page derives it
    /// from its own host and the API port, and the user can override it in the
    /// UI.
    pub api_base: Option<String>,
    /// Default theme the dashboard opens with: `dark` or `light`.
    pub theme: String,
    /// Address for the optional HTTPS dashboard listener that a superadmin/admin
    /// enables at runtime from Sitewide settings (cert/key live in the database,
    /// not here). Separate from `bind`, which always stays plain HTTP. Binding
    /// 443 needs elevated privilege (root or `CAP_NET_BIND_SERVICE`); if the bind
    /// fails the HTTP listener is unaffected.
    #[serde(default = "default_https_bind")]
    pub https_bind: String,
    /// Browser origins allowed to call the API (CORS). Empty = allow any origin
    /// (the API is still protected by bearer-token auth).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

fn default_https_bind() -> String {
    "0.0.0.0:443".into()
}

impl Default for WebCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: "0.0.0.0:9443".into(),
            tls_cert: None,
            tls_key: None,
            api_base: None,
            theme: "dark".into(),
            https_bind: default_https_bind(),
            allowed_origins: Vec::new(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerCfg {
                bind: "0.0.0.0:8443".into(),
                tls_cert: None,
                tls_key: None,
            },
            database: DatabaseCfg {
                mode: "local".into(),
                dsn: "postgres://flamejob@localhost/flamejob".into(),
                max_connections: 10,
            },
            auth: AuthCfg {
                jwt_secret: "dev-insecure-change-me".into(),
                token_ttl_hours: 1,
            },
            hashcat: HashcatCfg {
                binary: "/usr/bin/hashcat".into(),
                data_dir: "/var/lib/flamejob".into(),
                workload: 3,
                files_quota_bytes: 0, // unlimited by default
            },
            crypto: CryptoCfg {
                plaintext_key_file: None,
            },
            scheduler: SchedulerCfg {
                chunk_size: 50_000_000,
                max_chunks: 500,
                runner: "local".into(),
                local_parallelism: 1,
                max_concurrent_jobs: 8,
                local_agent_name: default_local_agent_name(),
            },
            telemetry: TelemetryCfg {
                enabled: true,
                sample_interval_secs: 5,
                history_limit: 500,
            },
            web: WebCfg::default(),
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        use figment::{
            providers::{Env, Format, Serialized, Toml},
            Figment,
        };
        let path = std::env::var("FLAMEJOB_CONFIG")
            .unwrap_or_else(|_| "/etc/flamejob/flamejob.toml".into());
        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file(path))
            .merge(Env::prefixed("FJ_").split("__"))
            .extract()?;
        Ok(cfg)
    }
}
