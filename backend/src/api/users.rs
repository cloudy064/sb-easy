//! User management + audit log API. All routes require an authenticated admin;
//! the `require_admin` guard reads Claims injected by the auth middleware.

use axum::{
    extract::{Path, State},
    Extension, Json, Router,
};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::{self, Claims};
use crate::error::{AppError, Result};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route("/{id}", axum::routing::delete(delete_user))
        .route("/{id}/password", post(reset_password))
        .route("/audit", get(list_audit))
}

fn require_admin(claims: &Claims) -> Result<()> {
    if claims.role == "admin" {
        Ok(())
    } else {
        Err(AppError::Forbidden("Admin role required".into()))
    }
}

#[derive(Deserialize)]
struct CreateUser {
    username: String,
    password: String,
    #[serde(default = "default_role")]
    role: String,
}
fn default_role() -> String {
    "viewer".into()
}

#[derive(Deserialize)]
struct PasswordReset {
    password: String,
}

async fn list_users(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<Value>>> {
    require_admin(&claims)?;
    let rows: Vec<(String, String, String, String)> =
        sqlx::query_as("SELECT id, username, role, created_at FROM users ORDER BY created_at")
            .fetch_all(&state.db)
            .await?;
    let users = rows
        .into_iter()
        .map(|(id, username, role, created_at)| json!({
            "id": id, "username": username, "role": role, "created_at": created_at,
        }))
        .collect();
    Ok(Json(users))
}

async fn create_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateUser>,
) -> Result<Json<Value>> {
    require_admin(&claims)?;
    if req.username.trim().is_empty() || req.password.len() < 4 {
        return Err(AppError::BadRequest("Username required, password ≥ 4 chars".into()));
    }
    if req.role != "admin" && req.role != "viewer" {
        return Err(AppError::BadRequest("Role must be admin or viewer".into()));
    }
    let id = Uuid::new_v4().to_string();
    let hash = auth::hash_password(&req.password)?;
    sqlx::query("INSERT INTO users (id, username, password_hash, role) VALUES (?,?,?,?)")
        .bind(&id).bind(&req.username).bind(&hash).bind(&req.role)
        .execute(&state.db)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref de) if de.message().contains("UNIQUE") => {
                AppError::Conflict("Username already exists".into())
            }
            other => other.into(),
        })?;
    Ok(Json(json!({ "id": id, "username": req.username, "role": req.role })))
}

async fn delete_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    require_admin(&claims)?;
    if id == claims.sub {
        return Err(AppError::BadRequest("You cannot delete your own account".into()));
    }
    // Never leave the system with zero admins.
    let admins: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        .fetch_one(&state.db).await?;
    let target_role: Option<(String,)> = sqlx::query_as("SELECT role FROM users WHERE id = ?")
        .bind(&id).fetch_optional(&state.db).await?;
    if target_role.map(|(r,)| r == "admin").unwrap_or(false) && admins.0 <= 1 {
        return Err(AppError::BadRequest("Cannot delete the last admin".into()));
    }
    sqlx::query("DELETE FROM users WHERE id = ?").bind(&id).execute(&state.db).await?;
    Ok(Json(json!({ "success": true })))
}

async fn reset_password(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<PasswordReset>,
) -> Result<Json<Value>> {
    require_admin(&claims)?;
    if req.password.len() < 4 {
        return Err(AppError::BadRequest("Password must be ≥ 4 chars".into()));
    }
    let hash = auth::hash_password(&req.password)?;
    let res = sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(&hash).bind(&id).execute(&state.db).await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("User not found".into()));
    }
    Ok(Json(json!({ "success": true })))
}

async fn list_audit(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<Value>>> {
    require_admin(&claims)?;
    let rows: Vec<(i64, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, ts, actor, action, target FROM audit_log ORDER BY id DESC LIMIT 200",
    )
    .fetch_all(&state.db)
    .await?;
    let entries = rows
        .into_iter()
        .map(|(id, ts, actor, action, target)| json!({
            "id": id, "ts": ts, "actor": actor, "action": action, "target": target,
        }))
        .collect();
    Ok(Json(entries))
}
