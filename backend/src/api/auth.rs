//! Authentication API handlers.
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    Json, Router,
};
use axum::routing::{get, post};

use crate::auth::{self, LoginRequest, LoginResponse, SessionInfo};
use crate::error::AppError;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login_handler))
        .route("/session", get(session_handler))
}

/// POST /api/auth/login
async fn login_handler(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // Look up user by the supplied username (defaults to "admin").
    let lookup = req.username.clone().unwrap_or_else(|| "admin".into());
    let user: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT id, username, password_hash, role FROM users WHERE username = ? LIMIT 1"
    )
    .bind(&lookup)
    .fetch_optional(&state.db)
    .await?;

    let (user_id, username, password_hash, role) = user
        .ok_or_else(|| AppError::Unauthorized("Invalid credentials".into()))?;

    // Verify password
    if !auth::verify_password(&req.password, &password_hash)? {
        return Err(AppError::Unauthorized("Invalid credentials".into()));
    }

    // Generate JWT
    let token = auth::create_token(&user_id, &username, &role, &state.cfg.jwt_secret)?;

    Ok(Json(LoginResponse { token, username, role }))
}

/// GET /api/auth/session
async fn session_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<SessionInfo>, AppError> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let claims = super::extract_claims(&state, auth_header).await?;

    Ok(Json(SessionInfo {
        username: claims.username,
        role: claims.role,
        authenticated: true,
    }))
}

fn is_safe_method(m: &axum::http::Method) -> bool {
    matches!(*m, axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS)
}

/// Authentication middleware for protected routes. Verifies the JWT, enforces
/// read-only access for the `viewer` role, injects Claims into request
/// extensions, and audit-logs successful mutating requests.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let token = match auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
        Some(t) => t,
        None => return Err(StatusCode::UNAUTHORIZED),
    };
    let claims = auth::verify_token(token, &state.cfg.jwt_secret)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let method = request.method().clone();

    // RBAC: viewers may only perform safe (read) requests.
    if claims.role == "viewer" && !is_safe_method(&method) {
        return Err(StatusCode::FORBIDDEN);
    }

    let actor = claims.username.clone();
    let path = request.uri().path().to_string();
    request.extensions_mut().insert(claims);

    let response = next.run(request).await;

    // Audit successful mutations.
    if !is_safe_method(&method) && response.status().is_success() {
        crate::services::audit::record(&state.db, &actor, method.as_str(), &path).await;
    }

    Ok(response)
}
