use std::ops::Deref;
use std::sync::Arc;

use jsonwebtoken::{DecodingKey, EncodingKey};
use metrics_exporter_prometheus::PrometheusHandle;

use crate::agent::AgentHub;
use crate::config::Config;
use crate::crypto::Cipher;
use crate::pki::Pki;
use flamejob_api::DeviceView;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub cfg: Config,
    pub db: flamejob_db::Db,
    pub encode_key: EncodingKey,
    pub decode_key: DecodingKey,
    pub metrics: PrometheusHandle,
    pub cipher: Cipher,
    pub devices: RwLock<Vec<DeviceView>>,
    pub agents: Arc<AgentHub>,
    pub pki: Arc<Pki>,
}

impl AppState {
    pub fn new(cfg: Config, db: flamejob_db::Db) -> anyhow::Result<Self> {
        let encode_key = EncodingKey::from_secret(cfg.auth.jwt_secret.as_bytes());
        let decode_key = DecodingKey::from_secret(cfg.auth.jwt_secret.as_bytes());
        let metrics = crate::metrics::recorder()?;
        let cipher = Cipher::from_bytes(crate::crypto::key_from_config(&cfg));
        let pki = Pki::load_or_create(std::path::Path::new(&cfg.hashcat.data_dir))?;
        Ok(Self(Arc::new(Inner {
            cfg,
            db,
            encode_key,
            decode_key,
            metrics,
            cipher,
            devices: RwLock::new(Vec::new()),
            agents: AgentHub::new(),
            pki: Arc::new(pki),
        })))
    }
}

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}
