//! sb-easy: Unified WireGuard + Sing-box management platform.
//!
//! Brings up the WireGuard interface on startup, manages the web UI on port 51821.

use axum::Router;
use axum::http::{HeaderValue, StatusCode};
use axum::routing::get_service;
use std::net::SocketAddr;
use tokio::signal;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod agent_mode;
mod api;
mod auth;
mod config;
mod db;
mod error;
mod models;
mod services;
mod util;

/// Build the application router: API → static files → SPA fallback.
fn build_app(state: AppState) -> Router {
    let dist_dir = "frontend/dist";
    let cors = build_cors(&state.cfg.cors_origins);

    let app = api::router::build(state)
        .nest_service("/assets", ServeDir::new(format!("{dist_dir}/assets")))
        .fallback_service(
            get_service(ServeFile::new(format!("{dist_dir}/index.html")))
                .handle_error(|e| async move {
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("SPA error: {e}"))
                }),
        );

    app.layer(cors)
}

/// Build a CORS layer. Empty or "*" → permissive (dev default); otherwise restrict
/// to the comma-separated allowlist in CORS_ORIGINS.
fn build_cors(origins: &str) -> CorsLayer {
    let trimmed = origins.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return CorsLayer::permissive();
    }
    let list: Vec<HeaderValue> = trimmed
        .split(',')
        .filter_map(|o| o.trim().parse().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(list)
        .allow_methods(Any)
        .allow_headers(Any)
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

    let _ = dotenvy::dotenv();

    // `sb-easy agent` runs this same binary as a managed node (no panel): it
    // pulls config from a remote panel and supervises sing-box in process.
    if std::env::args().nth(1).as_deref() == Some("agent") {
        info!("sb-easy v{} starting (agent mode)", env!("CARGO_PKG_VERSION"));
        return agent_mode::run().await;
    }

    let cfg = config::Config::from_env()?;
    info!("sb-easy v{} starting", env!("CARGO_PKG_VERSION"));

    // ── Database ──────────────────────────────────────────
    let pool = db::init(&cfg).await?;
    info!("Database ready");

    // ── WireGuard startup (skip if WG_ENABLED=false) ────────
    if cfg.wg_enabled {
        let _guard = services::wireguard::startup(&pool, &cfg).await?;
        info!(
            "WireGuard interface {} is UP on port {} (UDP)",
            cfg.wg_interface, cfg.wg_port
        );
    } else {
        info!("WireGuard startup skipped (WG_ENABLED=false)");
    }

    // ── Auth seed ─────────────────────────────────────────
    auth::ensure_default_user(&pool, &cfg).await?;

    // ── Build state and start HTTP server ─────────────────
    let shutdown_pool = pool.clone();
    let state = AppState { db: pool, cfg: cfg.clone() };

    // Built-in `self` host's sing-box management (opt-in):
    // - SINGBOX_MANAGED=true → sb-easy supervises sing-box as a child process.
    // - else SELF_SINGBOX_CONFIG_PATH set → write config + external reload cmd.
    if state.cfg.singbox_managed {
        tokio::spawn(services::singbox_supervisor::run(state.clone()));
    } else {
        tokio::spawn(services::self_agent::run(state.clone()));
    }

    let addr: SocketAddr = cfg.bind_addr.parse()?;
    info!("Web UI listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Graceful shutdown: on SIGINT/SIGTERM, tear down WireGuard cleanly
    let app = build_app(state);
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // ── Cleanup ───────────────────────────────────────────
    if cfg.wg_enabled {
        services::wireguard::shutdown(&shutdown_pool, &cfg).await;
    }
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
