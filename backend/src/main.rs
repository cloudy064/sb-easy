//! sb-easy: Unified WireGuard + Sing-box management platform.
//!
//! Brings up the WireGuard interface on startup, manages the web UI on port 51821.

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get_service;
use std::net::SocketAddr;
use tokio::signal;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod api;
mod auth;
mod config;
mod db;
mod error;
mod models;
mod services;

/// Build the application router: API → static files → SPA fallback.
fn build_app(state: AppState) -> Router {
    let dist_dir = "frontend/dist";

    let app = api::router::build(state)
        .nest_service("/assets", ServeDir::new(format!("{dist_dir}/assets")))
        .fallback_service(
            get_service(ServeFile::new(format!("{dist_dir}/index.html")))
                .handle_error(|e| async move {
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("SPA error: {e}"))
                }),
        );

    app.layer(CorsLayer::permissive())
}

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::SqlitePool,
    pub cfg: config::Config,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = config::Config::from_env()?;
    info!("sb-easy v{} starting", env!("CARGO_PKG_VERSION"));

    // ── Database ──────────────────────────────────────────
    let pool = db::init(&cfg).await?;
    info!("Database ready");

    // ── WireGuard startup ─────────────────────────────────
    // This generates keys, writes wg0.conf, applies iptables, and brings up the interface.
    let _wg_shutdown_guard = services::wireguard::startup(&pool, &cfg).await
        .map(|guard| {
            info!(
                "WireGuard interface {} is UP on port {} (UDP)",
                cfg.wg_interface, cfg.wg_port
            );
            guard
        })?;

    // ── Auth seed ─────────────────────────────────────────
    auth::ensure_default_user(&pool, &cfg).await?;

    // ── Build state and start HTTP server ─────────────────
    let state = AppState { db: pool, cfg: cfg.clone() };
    let addr: SocketAddr = cfg.bind_addr.parse()?;
    info!("Web UI listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Graceful shutdown: on SIGINT/SIGTERM, tear down WireGuard cleanly
    let app = build_app(state);
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // ── Cleanup ───────────────────────────────────────────
    services::wireguard::shutdown(&cfg).await;
    info!("sb-easy stopped");

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { info!("Received SIGINT, shutting down..."); },
        _ = terminate => { info!("Received SIGTERM, shutting down..."); },
    }
}
