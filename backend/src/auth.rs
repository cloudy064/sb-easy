//! JWT authentication and user management.
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{http::StatusCode, Json};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tracing::info;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, Result};

const TOKEN_EXPIRY_HOURS: i64 = 72;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user id
    pub username: String,
    #[serde(default = "default_role")]
    pub role: String,
    pub exp: usize,
    pub iat: usize,
}

fn default_role() -> String {
    "admin".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    #[serde(default)]
    pub username: Option<String>,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub username: String,
    pub role: String,
    pub authenticated: bool,
}

/// Generate a JWT token for a user.
pub fn create_token(user_id: &str, username: &str, role: &str, secret: &str) -> Result<String> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role: role.to_string(),
        exp: (now + Duration::hours(TOKEN_EXPIRY_HOURS)).timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("Token generation failed: {e}")))
}

/// Verify a JWT token and return the claims.
pub fn verify_token(token: &str, secret: &str) -> Result<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::Unauthorized("Invalid or expired token".into()))
}

/// Hash a password using argon2.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a password against an argon2 hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(format!("Invalid password hash: {e}")))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Ensure a default admin user exists. Creates one if none found.
pub async fn ensure_default_user(pool: &SqlitePool, cfg: &Config) -> Result<()> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;

    if count.0 == 0 {
        let id = Uuid::new_v4().to_string();
        let password_hash = hash_password(&cfg.admin_password)?;

        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)")
            .bind(&id)
            .bind("admin")
            .bind(&password_hash)
            .execute(pool)
            .await?;

        info!("Default admin user created (username: admin)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
        assert!(!verify_password("wrong password", &hash).unwrap());
    }

    #[test]
    fn password_hash_is_salted() {
        // Same password hashes differently (random salt) but both verify.
        let h1 = hash_password("pw").unwrap();
        let h2 = hash_password("pw").unwrap();
        assert_ne!(h1, h2);
        assert!(verify_password("pw", &h1).unwrap());
        assert!(verify_password("pw", &h2).unwrap());
    }

    #[test]
    fn jwt_roundtrip() {
        let secret = "test-secret";
        let token = create_token("uid-1", "alice", "admin", secret).unwrap();
        let claims = verify_token(&token, secret).unwrap();
        assert_eq!(claims.sub, "uid-1");
        assert_eq!(claims.username, "alice");
        assert_eq!(claims.role, "admin");
    }

    #[test]
    fn jwt_rejects_wrong_secret() {
        let token = create_token("uid-1", "alice", "admin", "secret-a").unwrap();
        assert!(verify_token(&token, "secret-b").is_err());
    }

    #[test]
    fn jwt_rejects_tampered_token() {
        let token = create_token("uid-1", "alice", "admin", "s").unwrap();
        let mut t = token.clone();
        t.push('x');
        assert!(verify_token(&t, "s").is_err());
    }
}
