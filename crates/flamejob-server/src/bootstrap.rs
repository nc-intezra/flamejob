//! First-run seeding of the break-glass superadmin (local account).
use uuid::Uuid;

use crate::auth::hash_password;
use crate::state::AppState;

pub async fn ensure_superadmin(state: &AppState) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&state.db)
        .await?;
    if count > 0 {
        return Ok(());
    }
    let password = std::env::var("FJ_BOOTSTRAP_PASSWORD").unwrap_or_else(|_| {
        use rand::Rng;
        (0..16)
            .map(|_| rand::thread_rng().sample(rand::distributions::Alphanumeric) as char)
            .collect()
    });
    let hash = hash_password(&password).map_err(|e| anyhow::anyhow!("hash: {e:?}"))?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, username, source, password_hash) VALUES ($1, 'superadmin', 'local', $2)",
    )
    .bind(id)
    .bind(&hash)
    .execute(&state.db)
    .await?;
    sqlx::query("INSERT INTO user_roles (user_id, role) VALUES ($1, 'superadmin')")
        .bind(id)
        .execute(&state.db)
        .await?;
    tracing::warn!(username = "superadmin", password = %password, "seeded break-glass superadmin");
    Ok(())
}
