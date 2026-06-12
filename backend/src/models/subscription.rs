//! Subscription model.
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub refresh_interval: i32,
    pub last_fetched_at: Option<String>,
    pub last_fetch_result: Option<String>, // JSON
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateSubscriptionRequest {
    pub name: String,
    pub url: String,
    #[serde(default = "default_interval")]
    pub refresh_interval: Option<i32>,
}

fn default_interval() -> Option<i32> { Some(3600) }

#[derive(Debug, Serialize)]
pub struct FetchResult {
    pub added: usize,
    pub updated: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}
