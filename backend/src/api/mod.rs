pub mod agent;
pub mod auth;
pub mod config_download;
pub mod proxy_nodes;
pub mod router;
pub mod settings;
pub mod singbox_proxy;
pub mod subscriptions;
pub mod system;
pub mod wireguard;

use crate::AppState;

/// Extractor for authenticated requests (JWT from Authorization header).
/// Returns the Claims if valid.
pub async fn extract_claims(
    state: &AppState,
    auth_header: Option<&str>,
) -> Result<crate::auth::Claims, crate::error::AppError> {
    let token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::error::AppError::Unauthorized("Missing token".into()))?;

    crate::auth::verify_token(token, &state.cfg.jwt_secret)
}
