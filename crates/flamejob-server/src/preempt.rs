//! Preemption + priority override (v2.0 Phase 5, PR4) — the "management decree"
//! lever. Deliberately able to act against fair-share, so every action is
//! audited. The pure split/guard helpers are unit-tested; the scheduler-side
//! resume + keyspace handoff lives in `scheduler.rs`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use uuid::Uuid;

use flamejob_api::{Event, PreemptRequest, PriorityOverrideRequest};
use flamejob_core::{Capability, JobState};

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::state::AppState;

/// A running job is not preemptible if it only just started (not worth
/// checkpoint + re-dispatch) or is near completion (finishing frees the GPU
/// sooner than evicting it). `force` bypasses this.
pub const MIN_RUN_SECS: i64 = 60;
pub const SHIELD_FRAC: f64 = 0.90;

/// The unfinished keyspace window of a chunk given its last observed progress —
/// the basis of the cross-agent/pool keyspace handoff (resume from the durable
/// offset via hashcat `--skip`/`--limit`, never a host-bound `.restore` file).
/// `len <= 0` (unknown / full-run chunk) is returned unchanged.
pub fn remaining_window(offset: i64, len: i64, progress: f64) -> (i64, i64) {
    if len <= 0 {
        return (offset, len);
    }
    let consumed = (((len as f64) * progress.clamp(0.0, 1.0)).floor() as i64).clamp(0, len);
    (offset + consumed, len - consumed)
}

/// Whether a running job may be preempted under the guards.
pub fn is_preemptible(
    run_secs: i64,
    overall_progress: f64,
    min_run_secs: i64,
    shield_frac: f64,
) -> bool {
    run_secs >= min_run_secs && overall_progress < shield_frac
}

async fn audit(state: &AppState, actor: Uuid, action: &str, job: Uuid, detail: &str) {
    let _ = sqlx::query(
        "INSERT INTO audit_events (actor_user_id, action, target_type, target_id, outcome, detail) \
         VALUES ($1, $2, 'job', $3, 'ok', $4)",
    )
    .bind(actor)
    .bind(action)
    .bind(job.to_string())
    .bind(serde_json::json!({ "detail": detail }))
    .execute(&state.db)
    .await;
}

async fn overall_progress(state: &AppState, job: Uuid) -> f64 {
    sqlx::query_scalar(
        "SELECT COALESCE(SUM(CASE WHEN state='done' THEN GREATEST(keyspace_len,1)::float8 \
             ELSE progress*GREATEST(keyspace_len,1)::float8 END) \
             / NULLIF(SUM(GREATEST(keyspace_len,1)),0), 0)::float8 \
         FROM tasks WHERE job_id = $1",
    )
    .bind(job)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0.0)
}

#[utoipa::path(
    post, path = "/jobs/{id}/priority", tag = "jobs", security(("bearer" = [])),
    params(("id" = Uuid, Path,)), request_body = PriorityOverrideRequest,
    responses((status = 202, description = "Override set/cleared"), (status = 403, description = "Missing ManageScheduling"))
)]
pub async fn set_priority_override(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<PriorityOverrideRequest>,
) -> Result<StatusCode, AppError> {
    auth.require(Capability::ManageScheduling)?;
    let updated = sqlx::query("UPDATE jobs SET priority_override = $2 WHERE id = $1")
        .bind(id)
        .bind(req.priority_override)
        .execute(&state.db)
        .await?
        .rows_affected();
    if updated == 0 {
        return Err(AppError::NotFound("job not found".into()));
    }
    audit(
        &state,
        auth.id,
        "schedule.priority_override",
        id,
        &format!(
            "override={:?} reason={}",
            req.priority_override,
            req.reason.as_deref().unwrap_or("")
        ),
    )
    .await;
    Ok(StatusCode::ACCEPTED)
}

#[utoipa::path(
    post, path = "/jobs/{id}/preempt", tag = "jobs", security(("bearer" = [])),
    params(("id" = Uuid, Path,)), request_body = PreemptRequest,
    responses(
        (status = 202, description = "Preemption requested"),
        (status = 400, description = "Not running, guarded, or bad mode/pool"),
        (status = 403, description = "Missing ManageScheduling")
    )
)]
pub async fn preempt_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<PreemptRequest>,
) -> Result<StatusCode, AppError> {
    auth.require(Capability::ManageScheduling)?;

    let row: Option<(String, Option<chrono::DateTime<Utc>>)> =
        sqlx::query_as("SELECT state::text, started_at FROM jobs WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let (job_state, started_at) = row.ok_or_else(|| AppError::NotFound("job not found".into()))?;
    if job_state != "running" {
        return Err(AppError::BadRequest(format!(
            "job is {job_state}, only a running job can be preempted"
        )));
    }

    let reason = req.reason.as_deref().unwrap_or("");
    match req.mode.as_str() {
        "cancel" => {
            sqlx::query(
                "UPDATE jobs SET state = 'cancelled', preempt_state = 'cancelled', \
                 preempted_at = now(), preempt_reason = $2, est_completion = NULL WHERE id = $1",
            )
            .bind(id)
            .bind(reason)
            .execute(&state.db)
            .await?;
            state.publish(Event::JobUpdated {
                job_id: id,
                state: JobState::Cancelled,
            });
        }
        "requeue" => {
            // Guards (skippable with force): don't evict a just-started or nearly
            // finished job.
            if !req.force {
                let run_secs = started_at
                    .map(|s| (Utc::now() - s).num_seconds())
                    .unwrap_or(0);
                let prog = overall_progress(&state, id).await;
                if !is_preemptible(run_secs, prog, MIN_RUN_SECS, SHIELD_FRAC) {
                    return Err(AppError::BadRequest(
                        "job just started or is near completion — pass force to override".into(),
                    ));
                }
            }
            // Optional demotion: hand the remaining keyspace to another pool.
            if let Some(pool) = req.target_pool_id {
                let exists: Option<Uuid> =
                    sqlx::query_scalar("SELECT id FROM agent_pools WHERE id = $1")
                        .bind(pool)
                        .fetch_optional(&state.db)
                        .await?;
                exists.ok_or_else(|| AppError::BadRequest("unknown target pool".into()))?;
                sqlx::query("UPDATE jobs SET eligible_pool_ids = ARRAY[$2]::uuid[] WHERE id = $1")
                    .bind(id)
                    .bind(pool)
                    .execute(&state.db)
                    .await?;
            }
            // Ride the paused→running machinery: 'paused' makes the scheduler stop
            // the in-flight chunks cleanly; `preempt_state='requeued'` tells its
            // resume path to split the stopped chunks at their offset and
            // re-dispatch the remainder (on the — possibly new — pool).
            sqlx::query(
                "UPDATE jobs SET state = 'paused', preempt_state = 'requeued', \
                 preempted_at = now(), preempt_reason = $2, resume_after = now(), \
                 est_completion = NULL WHERE id = $1",
            )
            .bind(id)
            .bind(reason)
            .execute(&state.db)
            .await?;
            state.publish(Event::JobUpdated {
                job_id: id,
                state: JobState::Paused,
            });
        }
        other => {
            return Err(AppError::BadRequest(format!(
                "mode must be requeue|cancel, got '{other}'"
            )));
        }
    }

    audit(
        &state,
        auth.id,
        "schedule.preempt",
        id,
        &format!(
            "mode={} target_pool={:?} reason={}",
            req.mode, req.target_pool_id, reason
        ),
    )
    .await;
    Ok(StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_window_splits_at_progress_offset() {
        // 50% through a 1000-wide chunk starting at 2000 → resume at 2500 for 500.
        assert_eq!(remaining_window(2000, 1000, 0.5), (2500, 500));
        // Barely started → almost the whole chunk remains.
        assert_eq!(remaining_window(0, 100, 0.0), (0, 100));
        // Essentially done → tiny/zero remainder.
        assert_eq!(remaining_window(0, 100, 1.0), (100, 0));
        // Clamps out-of-range progress.
        assert_eq!(remaining_window(10, 40, 2.0), (50, 0));
        // Unknown/full-run chunk (len 0) passes through unchanged.
        assert_eq!(remaining_window(0, 0, 0.5), (0, 0));
    }

    #[test]
    fn preemptible_guards() {
        // Healthy mid-run job: preemptible.
        assert!(is_preemptible(300, 0.4, MIN_RUN_SECS, SHIELD_FRAC));
        // Just started: shielded.
        assert!(!is_preemptible(10, 0.4, MIN_RUN_SECS, SHIELD_FRAC));
        // Near completion: shielded.
        assert!(!is_preemptible(300, 0.95, MIN_RUN_SECS, SHIELD_FRAC));
        // Exactly at the boundaries.
        assert!(is_preemptible(60, 0.0, MIN_RUN_SECS, SHIELD_FRAC));
        assert!(!is_preemptible(60, 0.90, MIN_RUN_SECS, SHIELD_FRAC));
    }
}
