use std::ops::Deref;
use std::sync::Arc;

use jsonwebtoken::{DecodingKey, EncodingKey};
use metrics_exporter_prometheus::PrometheusHandle;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub cfg: Config,
    pub db: flamejob_db::Db,
    pub encode_key: EncodingKey,
    pub decode_key: DecodingKey,
    pub metrics: PrometheusHandle,
}

impl AppState {
    pub fn new(cfg: Config, db: flamejob_db::Db) -> anyhow::Result<Self> {
        let encode_key = EncodingKey::from_secret(cfg.auth.jwt_secret.as_bytes());
        let decode_key = DecodingKey::from_secret(cfg.auth.jwt_secret.as_bytes());
        let metrics = crate::metrics::recorder()?;
        Ok(Self(Arc::new(Inner {
            cfg,
            db,
            encode_key,
            decode_key,
            metrics,
        })))
    }
}

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}
