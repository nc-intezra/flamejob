//! Agent pools and server-enforced job→pool eligibility (v2.0 Phase 5, PR2).
//!
//! A pool is a named set of agents; a directory security group is granted a pool
//! (`directory_agent_grants`); a job's eligible agents are the members of the
//! pools its owner's groups are granted. Eligibility is computed at submit from
//! the owner's *verified* cached group SIDs — never from a client field — and
//! re-derived live in the scheduler at each chunk dispatch.

use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use flamejob_api::{PoolCreate, PoolMemberUpdate, PoolView};
use flamejob_core::Capability;
use sqlx::Row;

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::state::AppState;

/// Reduce the grant pairs that apply to a user into (owner_group_sid,
/// eligible_pool_ids). The owning group (charged for fairness later) is chosen
/// deterministically as the lexicographically smallest granting group SID; the
/// eligible pools are the distinct granted pools. Pure, so it is unit-tested.
pub fn summarize_grants(pairs: &[(String, Uuid)]) -> (Option<String>, Vec<Uuid>) {
    let mut pools: Vec<Uuid> = Vec::new();
    for (_, pool) in pairs {
        if !pools.contains(pool) {
            pools.push(*pool);
        }
    }
    let owner = pairs.iter().map(|(g, _)| g.clone()).min();
    (owner, pools)
}

/// Compute a job owner's eligibility at submit time.
///
/// Returns `(owner_group_sid, eligible_pool_ids)`. Rules:
/// - No pools defined anywhere → unrestricted `(None, [])` (pre-v2.0 behavior).
/// - Local (non-directory) user → unrestricted `(None, [])`.
/// - Directory user with ≥1 granted pool → `(Some(group), [pools…])`.
/// - Directory user with groups but NO granted pool → `Err(Forbidden)`.
pub async fn compute_eligibility(
    state: &AppState,
    owner_user_id: Uuid,
) -> Result<(Option<String>, Vec<Uuid>), AppError> {
    let pools_exist: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_pools")
        .fetch_one(&state.db)
        .await?;
    if pools_exist == 0 {
        return Ok((None, Vec::new()));
    }
    let external_sid: Option<String> =
        sqlx::query_scalar("SELECT external_sid FROM users WHERE id = $1")
            .bind(owner_user_id)
            .fetch_optional(&state.db)
            .await?
            .flatten();
    if external_sid.is_none() {
        // Local / break-glass accounts are not pool-restricted.
        return Ok((None, Vec::new()));
    }
    let pairs: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT g.group_sid, g.pool_id FROM directory_agent_grants g \
         JOIN user_dir_groups u ON u.group_sid = g.group_sid WHERE u.user_id = $1",
    )
    .bind(owner_user_id)
    .fetch_all(&state.db)
    .await?;
    if pairs.is_empty() {
        return Err(AppError::Forbidden(
            "no authorized agent pools for your groups — ask an admin for a pool grant".into(),
        ));
    }
    Ok(summarize_grants(&pairs))
}

#[utoipa::path(
    get, path = "/admin/pools", tag = "directory", security(("bearer" = [])),
    responses((status = 200, body = [PoolView]), (status = 403, description = "Missing ManageAgents"))
)]
pub async fn list_pools(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<PoolView>>, AppError> {
    auth.require(Capability::ManageAgents)?;
    let rows = sqlx::query(
        "SELECT p.id, p.name, p.created_at, \
           COALESCE(array_agg(m.agent_id) FILTER (WHERE m.agent_id IS NOT NULL), '{}') AS agent_ids \
         FROM agent_pools p LEFT JOIN agent_pool_members m ON m.pool_id = p.id \
         GROUP BY p.id ORDER BY p.name",
    )
    .fetch_all(&state.db)
    .await?;
    let out = rows
        .into_iter()
        .map(|r| PoolView {
            id: r.get("id"),
            name: r.get("name"),
            agent_ids: r.get("agent_ids"),
            created_at: r.get("created_at"),
        })
        .collect();
    Ok(Json(out))
}

#[utoipa::path(
    post, path = "/admin/pools", tag = "directory", security(("bearer" = [])),
    request_body = PoolCreate,
    responses((status = 200, body = PoolView), (status = 403, description = "Missing ManageAgents"))
)]
pub async fn create_pool(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<PoolCreate>,
) -> Result<Json<PoolView>, AppError> {
    auth.require(Capability::ManageAgents)?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("pool name is required".into()));
    }
    let row = sqlx::query(
        "INSERT INTO agent_pools (name, created_by) VALUES ($1, $2) RETURNING id, created_at",
    )
    .bind(name)
    .bind(auth.id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate") || e.to_string().contains("unique") {
            AppError::BadRequest(format!("a pool named '{name}' already exists"))
        } else {
            AppError::from(e)
        }
    })?;
    Ok(Json(PoolView {
        id: row.get("id"),
        name: name.to_string(),
        agent_ids: Vec::new(),
        created_at: row.get("created_at"),
    }))
}

#[utoipa::path(
    delete, path = "/admin/pools/{id}", tag = "directory", security(("bearer" = [])),
    params(("id" = Uuid, Path,)),
    responses((status = 200, description = "Deleted"), (status = 403, description = "Missing ManageAgents"))
)]
pub async fn delete_pool(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require(Capability::ManageAgents)?;
    sqlx::query("DELETE FROM agent_pools WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

#[utoipa::path(
    post, path = "/admin/pools/{id}/members", tag = "directory", security(("bearer" = [])),
    params(("id" = Uuid, Path,)), request_body = PoolMemberUpdate,
    responses((status = 200, description = "Added"), (status = 403, description = "Missing ManageAgents"))
)]
pub async fn add_pool_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<PoolMemberUpdate>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require(Capability::ManageAgents)?;
    sqlx::query(
        "INSERT INTO agent_pool_members (pool_id, agent_id) VALUES ($1, $2) \
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(body.agent_id)
    .execute(&state.db)
    .await
    .map_err(|_| AppError::BadRequest("unknown pool or agent".into()))?;
    Ok(Json(serde_json::json!({ "added": true })))
}

#[utoipa::path(
    delete, path = "/admin/pools/{id}/members/{agent_id}", tag = "directory", security(("bearer" = [])),
    params(("id" = Uuid, Path,), ("agent_id" = Uuid, Path,)),
    responses((status = 200, description = "Removed"), (status = 403, description = "Missing ManageAgents"))
)]
pub async fn remove_pool_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((id, agent_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require(Capability::ManageAgents)?;
    sqlx::query("DELETE FROM agent_pool_members WHERE pool_id = $1 AND agent_id = $2")
        .bind(id)
        .bind(agent_id)
        .execute(&state.db)
        .await?;
    Ok(Json(serde_json::json!({ "removed": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_picks_min_group_and_distinct_pools() {
        let p1 = Uuid::from_u128(1);
        let p2 = Uuid::from_u128(2);
        let pairs = vec![
            ("S-1-5-21-ops".to_string(), p1),
            ("S-1-5-21-admins".to_string(), p2),
            ("S-1-5-21-ops".to_string(), p2), // duplicate pool via another path
        ];
        let (owner, pools) = summarize_grants(&pairs);
        assert_eq!(owner.as_deref(), Some("S-1-5-21-admins")); // lexicographically smallest
        assert_eq!(pools, vec![p1, p2]); // distinct, first-seen order
    }

    #[test]
    fn summarize_empty() {
        let (owner, pools) = summarize_grants(&[]);
        assert!(owner.is_none());
        assert!(pools.is_empty());
    }
}
