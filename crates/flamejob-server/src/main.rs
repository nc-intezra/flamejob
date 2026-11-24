//! flamejobd — the flamejob control-plane server.
mod agent;
mod auth;
mod bootstrap;
mod config;
mod crypto;
mod directory;
mod error;
mod fairness;
mod metrics;
mod openapi;
mod pki;
mod pools;
mod preempt;
mod routes;
mod scheduler;
mod settings;
mod state;
mod telemetry;
mod web;

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tracing_subscriber::{prelude::*, EnvFilter};

fn init_tracing() {
    let filter = EnvFilter::try_from_env("FJ_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cfg = config::Config::load()?;
    tracing::info!(bind = %cfg.server.bind, "starting flamejobd");

    let pool = flamejob_db::connect(&cfg.database.dsn, cfg.database.max_connections).await?;
    flamejob_db::migrate(&pool).await?;

    let state = state::AppState::new(cfg.clone(), pool)?;
    bootstrap::ensure_superadmin(&state).await?;
    scheduler::spawn(state.clone());
    telemetry::spawn(state.clone());
    web::spawn(state.clone());

    let app = routes::router(state);
    let addr: SocketAddr = cfg.server.bind.parse()?;
    // Serve the API over HTTPS when a cert+key are configured ([server].tls_cert
    // / tls_key), e.g. a pre-created certificate from an enterprise CA. Otherwise
    // serve plain HTTP and let the deployment terminate TLS (a reverse proxy such
    // as Caddy, which can also automate Let's Encrypt). Agent identity is verified
    // at the application layer (cert fingerprint in the WS Hello), so a
    // terminating proxy does not interfere with it.
    match (
        cfg.server.tls_cert.as_deref(),
        cfg.server.tls_key.as_deref(),
    ) {
        (Some(cert), Some(key)) => {
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .with_context(|| format!("loading [server] TLS cert={cert} key={key}"))?;
            tracing::info!(%addr, "flamejobd listening (https)");
            axum_server::bind_rustls(addr, tls)
                .serve(app.into_make_service())
                .await?;
        }
        (None, None) => {
            tracing::info!(%addr, "flamejobd listening (http)");
            axum_server::bind(addr)
                .serve(app.into_make_service())
                .await?;
        }
        _ => anyhow::bail!("[server] tls_cert and tls_key must be set together"),
    }
    Ok(())
}
