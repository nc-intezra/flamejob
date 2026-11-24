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
    // Optional HTTPS dashboard listener on [web].https_bind (default :443),
    // toggled at runtime from Sitewide settings with a DB-stored cert/key. Fully
    // independent of — and never disturbs — the plain HTTP listener below.
    tokio::spawn(site_https_manager(state.clone(), page.clone()));
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

/// Manage the optional HTTPS dashboard listener on `[web].https_bind` (default
/// :443). Reads the `site_settings` row and, when HTTPS is enabled with a valid
/// cert/key, binds the listener; when disabled it drops it. Re-evaluates every
/// time `state.tls_reload` is bumped (the Sitewide-settings PUT handler), so the
/// toggle takes effect live. Binding :443 needs elevated privilege — a bind
/// failure is logged and leaves the plain HTTP dashboard untouched.
async fn site_https_manager(state: crate::state::AppState, page: Arc<str>) {
    use std::sync::atomic::Ordering;
    let addr: SocketAddr = match state.cfg.web.https_bind.parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(bind = %state.cfg.web.https_bind, error = %e,
                "invalid [web].https_bind; HTTPS-on-443 disabled");
            return;
        }
    };
    let mut reload_rx = state.tls_reload.subscribe();
    loop {
        // Desired state from the database.
        let mut handle: Option<axum_server::Handle<SocketAddr>> = None;
        match crate::settings::tls_material(&state).await {
            Some((cert, key)) => match RustlsConfig::from_pem(cert, key).await {
                // Bind a std listener first so a port-permission failure (e.g. 443
                // without privilege) is detected synchronously, keeping the HTTP
                // dashboard untouched.
                Ok(tls) => match std::net::TcpListener::bind(addr) {
                    Ok(listener) => {
                        let _ = listener.set_nonblocking(true);
                        match axum_server::from_tcp_rustls(listener, tls) {
                            Ok(server) => {
                                let h: axum_server::Handle<SocketAddr> = axum_server::Handle::new();
                                let app = router(page.clone());
                                state.tls_listening.store(true, Ordering::Relaxed);
                                tracing::info!(%addr, "flamejob dashboard HTTPS listening (sitewide settings)");
                                let listening = state.tls_listening.clone();
                                let server = server.handle(h.clone());
                                tokio::spawn(async move {
                                    if let Err(e) = server.serve(app.into_make_service()).await {
                                        tracing::error!(error = %e, "dashboard HTTPS listener stopped");
                                    }
                                    listening.store(false, Ordering::Relaxed);
                                });
                                handle = Some(h);
                            }
                            Err(e) => {
                                state.tls_listening.store(false, Ordering::Relaxed);
                                tracing::error!(error = %e, "could not start dashboard HTTPS server");
                            }
                        }
                    }
                    Err(e) => {
                        state.tls_listening.store(false, Ordering::Relaxed);
                        tracing::error!(%addr, error = %e,
                            "could not bind dashboard HTTPS (port 443 needs root or CAP_NET_BIND_SERVICE)");
                    }
                },
                Err(e) => {
                    state.tls_listening.store(false, Ordering::Relaxed);
                    tracing::error!(error = %e, "stored TLS cert/key failed to load; HTTPS not started");
                }
            },
            None => {
                state.tls_listening.store(false, Ordering::Relaxed);
            }
        }
        // Block until the settings change, then tear down and re-evaluate.
        if reload_rx.changed().await.is_err() {
            break; // state (and the sender) dropped — process shutting down
        }
        if let Some(h) = handle {
            h.graceful_shutdown(Some(std::time::Duration::from_secs(3)));
        }
        state.tls_listening.store(false, Ordering::Relaxed);
    }
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
        "version": env!("CARGO_PKG_VERSION"),
        // Per-request upload ceiling (bytes) so the ingest pane can gauge each
        // file against the /files route's DefaultBodyLimit. 8 GiB < 2^53, so it
        // stays an exact JS number.
        "uploadLimit": crate::routes::MAX_FILE_UPLOAD_BYTES,
    });
    DASHBOARD_HTML.replace("\"__FJCFG__\"", &blob.to_string())
}
