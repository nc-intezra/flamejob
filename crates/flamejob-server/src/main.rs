//! flamejobd — the flamejob control-plane server.
mod agent;
mod auth;
mod bootstrap;
mod config;
mod crypto;
mod error;
mod metrics;
mod pki;
mod routes;
mod scheduler;
mod state;
mod telemetry;

use std::net::SocketAddr;

use anyhow::Result;
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

    let app = routes::router(state);
    let addr: SocketAddr = cfg.server.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "flamejobd listening");
    axum::serve(listener, app).await?;
    Ok(())
}
