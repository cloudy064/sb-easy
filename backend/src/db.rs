//! Database initialization and migrations.
use anyhow::Context;
use sqlx::sqlite::SqlitePoolOptions;
use tracing::info;

/// Initialize the database pool and run migrations.
pub async fn init(cfg: &super::config::Config) -> anyhow::Result<sqlx::SqlitePool> {
    // Ensure data directory exists
    if let Some(db_path) = cfg.database_url.strip_prefix("sqlite:") {
        let path = db_path.split('?').next().unwrap_or(db_path);
        if let Some(parent) = std::path::Path::new(path).parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect(&cfg.database_url)
        .await
        .context("Failed to connect to database")?;

    // Enable WAL mode for better concurrent read performance
    sqlx::query("PRAGMA journal_mode=WAL;")
        .execute(&pool)
        .await?;

    sqlx::query("PRAGMA foreign_keys=ON;")
        .execute(&pool)
        .await?;

    // Run migrations from the embedded sqlx migrations directory
    sqlx::migrate!("../migrations")
        .run(&pool)
        .await
        .context("Failed to run migrations")?;

    info!("Database migrations completed");
    Ok(pool)
}
