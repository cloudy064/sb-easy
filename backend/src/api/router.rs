//! Aggregate all API routers into the main application router.
use axum::{middleware, Router};
use axum::routing::any;
use axum::http::StatusCode;
use axum::Json;

use crate::AppState;

use super::auth;
use super::wireguard;
use super::proxy_nodes;
use super::subscriptions;
use super::config_download;
use super::singbox_proxy;
use super::singbox_ws;
use super::settings;
use super::system;
use super::users;
use super::agent;
use super::hosts;

/// Build the complete API router.
pub fn build(state: AppState) -> Router {
    let public = Router::new()
        .nest("/api/auth", auth::router())
        .nest("/api/agent", agent::router())
        // WebSocket streams authenticate via ?token=<jwt> in-handler, since
        // browsers can't set an Authorization header on the WS handshake.
        .nest("/api/sing-box", singbox_ws::router())
        .route("/api/system/status", axum::routing::get(system::status_handler));

    // Protected routes: require JWT
    let protected = Router::new()
        .nest("/api/wireguard", wireguard::router())
        .nest("/api/proxy", proxy_nodes::router())
        .nest("/api/subscriptions", subscriptions::router())
        .nest("/api/config", config_download::router())
        .nest("/api/sing-box", singbox_proxy::router())
        .nest("/api/settings", settings::router())
        .nest("/api/users", users::router())
        .nest("/api/hosts", hosts::router())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    // Catch-all for unmatched /api/* paths. Without this they fall through to the
    // SPA fallback (index.html, 200) and the frontend silently parses HTML as
    // JSON — e.g. a stale binary missing a route would blank the page. Specific
    // routes above take precedence over this wildcard.
    let api_fallback = Router::new().route("/api/{*rest}", any(api_not_found));

    public.merge(protected).merge(api_fallback).with_state(state)
}

async fn api_not_found() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Not found" })))
}
