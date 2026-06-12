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
    // Look up user
    let user: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, username, password_hash FROM users WHERE username = 'admin' LIMIT 1"
    )
    .fetch_optional(&state.db)
    .await?;

    let (user_id, username, password_hash) = user
        .ok_or_else(|| AppError::Unauthorized("Invalid credentials".into()))?;

    // Verify password
    if !auth::verify_password(&req.password, &password_hash)? {
        return Err(AppError::Unauthorized("Invalid credentials".into()));
    }

    // Generate JWT
    let token = auth::create_token(&user_id, &username, &state.cfg.jwt_secret)?;

    Ok(Json(LoginResponse { token, username }))
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
        authenticated: true,
    }))
}

/// Authentication middleware — protects routes by requiring valid JWT.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) => {
            let token = header.strip_prefix("Bearer ").unwrap_or("");
            match auth::verify_token(token, &state.cfg.jwt_secret) {
                Ok(_) => Ok(next.run(request).await),
                Err(_) => Err(StatusCode::UNAUTHORIZED),
            }
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}
