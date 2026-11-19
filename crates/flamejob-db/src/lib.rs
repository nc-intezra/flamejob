//! flamejob-db: Postgres pool, migrations and row models.
//! Phase 1 uses runtime queries (no compile-time DATABASE_URL required).
use sqlx::postgres::{PgPool, PgPoolOptions};

pub mod models;

pub type Db = PgPool;

/// Open a connection pool to Postgres.
pub async fn connect(dsn: &str, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(dsn)
        .await
}

/// Run all pending migrations from the workspace `migrations/` directory.
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("../../migrations").run(pool).await
}

/// Count jobs grouped by state (example aggregate used by /metrics).
pub async fn count_jobs_by_state(pool: &PgPool) -> Result<Vec<(String, i64)>, sqlx::Error> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT state::text, count(*) FROM jobs GROUP BY state")
            .fetch_all(pool)
            .await?;
    Ok(rows)
}
