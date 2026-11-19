//! Phase 1 scheduler skeleton. The full loop (claim queued jobs, split into
//! tasks, dispatch to the Runner, apply status updates) is task 8 of the build
//! checklist; this establishes the background task and its wiring.
use std::time::Duration;

use crate::state::AppState;

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = tick(&state).await {
                tracing::warn!(error = %e, "scheduler tick failed");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

async fn tick(state: &AppState) -> anyhow::Result<()> {
    // TODO(phase1-task8): SELECT queued jobs FOR UPDATE SKIP LOCKED, create
    // tasks, dispatch to the runner, and apply StatusUpdate samples.
    let _ = &state.db;
    Ok(())
}
