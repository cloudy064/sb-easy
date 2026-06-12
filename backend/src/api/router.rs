//! Aggregate all API routers into the main application router.
use axum::{middleware, Router};

use crate::AppState;

use super::auth;
use super::wireguard;
use super::proxy_nodes;
use super::subscriptions;
use super::config_download;
use super::singbox_proxy;
use super::settings;
use super::system;
use super::agent;

/// Build the complete API router.
pub fn build(state: AppState) -> Router {
    let public = Router::new()
        .nest("/api/auth", auth::router())
        .nest("/api/agent", agent::router())
        .route("/api/system/status", axum::routing::get(system::status_handler));

    // Protected routes: require JWT
    let protected = Router::new()
        .nest("/api/wireguard", wireguard::router())
        .nest("/api/proxy", proxy_nodes::router())
        .nest("/api/subscriptions", subscriptions::router())
        .nest("/api/config", config_download::router())
        .nest("/api/sing-box", singbox_proxy::router())
        .nest("/api/settings", settings::router())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    public.merge(protected).with_state(state)
}
