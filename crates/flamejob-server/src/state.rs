use std::ops::Deref;
use std::sync::Arc;

use jsonwebtoken::{DecodingKey, EncodingKey};
use metrics_exporter_prometheus::PrometheusHandle;

use crate::config::Config;
use crate::crypto::Cipher;
use flamejob_api::Event;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub cfg: Config,
    pub db: flamejob_db::Db,
    pub encode_key: EncodingKey,
    pub decode_key: DecodingKey,
    pub metrics: PrometheusHandle,
    pub cipher: Cipher,
    pub events: broadcast::Sender<Event>,
}

impl AppState {
    pub fn new(cfg: Config, db: flamejob_db::Db) -> anyhow::Result<Self> {
        let encode_key = EncodingKey::from_secret(cfg.auth.jwt_secret.as_bytes());
        let decode_key = DecodingKey::from_secret(cfg.auth.jwt_secret.as_bytes());
        let metrics = crate::metrics::recorder()?;
        let cipher = Cipher::from_bytes(crate::crypto::key_from_config(&cfg));
        let (events, _) = broadcast::channel(256);
        Ok(Self(Arc::new(Inner {
            cfg,
            db,
            encode_key,
            decode_key,
            metrics,
            cipher,
            events,
        })))
    }
}

impl AppState {
    pub fn publish(&self, ev: Event) {
        let _ = self.events.send(ev);
    }
}

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}
