//! The browser-facing web dashboard listener.
//!
//! Served separately from the API (`[server].bind`) on `[web].bind` (default
//! `0.0.0.0:9443`), over plain HTTP or — when a cert and key are configured —
//! HTTPS via rustls. The dashboard itself is a static single-page app that
//! talks to the existing API over HTTP(S); the API enables CORS so the browser
//! can reach it cross-origin. The interactive OpenAPI reference lives on the
//! API origin at `GET /docs` (so its spec URL is same-origin); the dashboard
//! links to it.
use std::net::SocketAddr;
use std::sync::Arc;

use axum::response::Html;
use axum::routing::get;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;

use crate::config::Config;

const DASHBOARD_HTML: &str = include_str!("web/dashboard.html");

/// Start the web dashboard listener (no-op when `[web].enabled = false`).
pub fn spawn(state: crate::state::AppState) {
    let cfg = state.cfg.web.clone();
    if !cfg.enabled {
        tracing::info!("web dashboard disabled ([web].enabled = false)");
        return;
    }
    let page: Arc<str> = render_dashboard(&state.cfg).into();
    tokio::spawn(async move {
        let addr: SocketAddr = match cfg.bind.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(bind = %cfg.bind, error = %e, "invalid [web].bind; dashboard not started");
                return;
            }
        };
        let app = router(page);
        match (cfg.tls_cert.as_deref(), cfg.tls_key.as_deref()) {
            (Some(cert), Some(key)) => match RustlsConfig::from_pem_file(cert, key).await {
                Ok(tls) => {
                    tracing::info!(%addr, "flamejob web dashboard listening (https)");
                    if let Err(e) = axum_server::bind_rustls(addr, tls)
                        .serve(app.into_make_service())
                        .await
                    {
                        tracing::error!(error = %e, "web dashboard (https) stopped");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, cert, key, "failed to load web TLS cert/key; dashboard not started");
                }
            },
            _ => {
                tracing::info!(%addr, "flamejob web dashboard listening (http)");
                if let Err(e) = axum_server::bind(addr).serve(app.into_make_service()).await {
                    tracing::error!(error = %e, "web dashboard (http) stopped");
                }
            }
        }
    });
}

fn router(page: Arc<str>) -> Router {
    let index = page.clone();
    Router::new()
        .route(
            "/",
            get(move || {
                let index = index.clone();
                async move { Html(index.to_string()) }
            }),
        )
        .route("/healthz", get(|| async { "ok" }))
}

/// Inject runtime configuration (API location + default theme) into the static
/// page by replacing the `__FJCFG__` placeholder with a JSON blob.
fn render_dashboard(cfg: &Config) -> String {
    let api_port = cfg
        .server
        .bind
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8443);
    let api_base = match &cfg.web.api_base {
        Some(b) => serde_json::Value::String(b.clone()),
        None => serde_json::Value::Null,
    };
    let blob = serde_json::json!({
        "apiBase": api_base,
        "apiPort": api_port,
        "theme": cfg.web.theme,
    });
    DASHBOARD_HTML.replace("\"__FJCFG__\"", &blob.to_string())
}
