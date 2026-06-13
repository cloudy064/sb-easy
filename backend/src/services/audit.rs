//! Audit log of mutating actions. Best-effort: a logging failure never blocks
//! the request that triggered it.

use tracing::warn;

/// Record one audit entry. `action` is the HTTP method, `target` the path.
pub async fn record(pool: &sqlx::SqlitePool, actor: &str, action: &str, target: &str) {
    let res = sqlx::query(
        "INSERT INTO audit_log (actor, action, target) VALUES (?, ?, ?)",
    )
    .bind(actor)
    .bind(action)
    .bind(target)
    .execute(pool)
    .await;
    if let Err(e) = res {
        warn!("audit log write failed: {e}");
    }
}
