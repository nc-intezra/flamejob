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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCfg {
    pub bind: String,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerCfg {
                bind: "0.0.0.0:8443".into(),
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
            },
            crypto: CryptoCfg {
                plaintext_key_file: None,
            },
            scheduler: SchedulerCfg {
                chunk_size: 50_000_000,
                max_chunks: 500,
                runner: "local".into(),
            },
            telemetry: TelemetryCfg {
                enabled: true,
                sample_interval_secs: 5,
                history_limit: 500,
            },
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
