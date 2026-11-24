//! Weighted fair-share selection of the next chunk to dispatch (v2.0 Phase 5,
//! PR3). Pure and unit-tested — the scheduler supplies live in-flight counts and
//! quotas; this module decides *whose* chunk goes into the next free slot.
//!
//! Model (per the design §5, specialized for uniform single-GPU-slot chunks):
//!
//! - A group at its `ceil` is skipped.
//! - A group under its `floor` is serviced before any weighted sharing.
//! - Otherwise pick the group with the smallest `in_flight / weight` — weighted
//!   max-min fair share of contested slots; idle groups' slots flow to demanding
//!   ones (work-conserving borrowing falls out for free).
//! - Within the chosen group, pick the job with the fewest in-flight chunks
//!   (per-job round-robin), tie-broken by priority then age.
//!
//! Oldest-waiting is the cross-group tie-break, so a low-weight group can't be
//! starved indefinitely.
//!
//! NOTE (deferred): long-horizon decayed-usage fairshare (Slurm FAIR_TREE) and
//! per-pool fairness domains are follow-ups; this is instantaneous weighted
//! max-min over current in-flight slots across all groups.

use std::cmp::Ordering;
use std::collections::HashMap;
use uuid::Uuid;

/// Per-group fair-share policy. Defaults apply to a group with no `group_quota`.
#[derive(Clone, Copy, Debug)]
pub struct Quota {
    pub weight: f64,
    pub floor: i64,
    pub ceil: Option<i64>,
}

impl Default for Quota {
    fn default() -> Self {
        Self {
            weight: 100.0,
            floor: 0,
            ceil: None,
        }
    }
}

/// A dispatchable job (one with a pending chunk and ready inputs).
#[derive(Clone, Debug)]
pub struct Candidate {
    pub job_id: Uuid,
    /// Owning group SID, or "" for an ungrouped (local / no-pool) job.
    pub group: String,
    pub priority: i32,
    /// Unix seconds; older (smaller) wins ties (age / anti-starvation).
    pub created_at: i64,
    /// Chunks of THIS job currently in flight (for per-job round-robin).
    pub in_flight_job: i64,
}

/// Choose the next job to dispatch a chunk from. Returns `None` only when every
/// candidate group is at its ceiling (nothing may start right now).
pub fn select_job(
    cands: &[Candidate],
    group_inflight: &HashMap<String, i64>,
    quotas: &HashMap<String, Quota>,
) -> Option<Uuid> {
    if cands.is_empty() {
        return None;
    }
    let q = |g: &str| quotas.get(g).copied().unwrap_or_default();
    let gif = |g: &str| *group_inflight.get(g).unwrap_or(&0);

    // Distinct candidate groups that are under their ceiling.
    let mut groups: Vec<&str> = Vec::new();
    for c in cands {
        let g = c.group.as_str();
        if !groups.contains(&g) && q(g).ceil.is_none_or(|cl| gif(g) < cl) {
            groups.push(g);
        }
    }
    if groups.is_empty() {
        return None;
    }

    // Under-floor groups take precedence over weighted sharing.
    let under: Vec<&str> = groups
        .iter()
        .copied()
        .filter(|g| gif(g) < q(g).floor)
        .collect();
    let pool: &[&str] = if under.is_empty() { &groups } else { &under };

    let oldest = |g: &str| {
        cands
            .iter()
            .filter(|c| c.group == g)
            .map(|c| c.created_at)
            .min()
            .unwrap_or(i64::MAX)
    };
    // Smallest in_flight/weight wins; tie-break by oldest waiting, then name.
    let chosen = *pool.iter().min_by(|a, b| {
        let ra = gif(a) as f64 / q(a).weight.max(1.0);
        let rb = gif(b) as f64 / q(b).weight.max(1.0);
        ra.partial_cmp(&rb)
            .unwrap_or(Ordering::Equal)
            .then_with(|| oldest(a).cmp(&oldest(b)))
            .then_with(|| a.cmp(b))
    })?;

    // Within the group: fewest in-flight chunks (round-robin), then priority, age.
    cands
        .iter()
        .filter(|c| c.group == chosen)
        .min_by(|a, b| {
            a.in_flight_job
                .cmp(&b.in_flight_job)
                .then(a.priority.cmp(&b.priority))
                .then(a.created_at.cmp(&b.created_at))
        })
        .map(|c| c.job_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: u128, group: &str, prio: i32, created: i64, inflight: i64) -> Candidate {
        Candidate {
            job_id: Uuid::from_u128(id),
            group: group.into(),
            priority: prio,
            created_at: created,
            in_flight_job: inflight,
        }
    }

    #[test]
    fn single_group_round_robins_across_jobs() {
        // Same group, two jobs; the one with fewer in-flight chunks is next.
        let cands = vec![cand(1, "", 100, 10, 3), cand(2, "", 100, 11, 1)];
        let gif = HashMap::from([("".to_string(), 4)]);
        assert_eq!(
            select_job(&cands, &gif, &HashMap::new()),
            Some(Uuid::from_u128(2))
        );
    }

    #[test]
    fn favors_the_under_utilized_group() {
        // Equal weights; group B has fewer in-flight chunks → B is next.
        let cands = vec![cand(1, "A", 100, 10, 2), cand(2, "B", 100, 10, 0)];
        let gif = HashMap::from([("A".to_string(), 4), ("B".to_string(), 1)]);
        assert_eq!(
            select_job(&cands, &gif, &HashMap::new()),
            Some(Uuid::from_u128(2))
        );
    }

    #[test]
    fn weight_gives_proportional_share() {
        // A has 2x the weight; at 2:1 in-flight the ratios tie, so the tie-break
        // (older created_at) decides. Give A the older job → A wins at 2:1,
        // proving A is allowed twice B's concurrency before yielding.
        let cands = vec![cand(1, "A", 100, 5, 2), cand(2, "B", 100, 9, 1)];
        let gif = HashMap::from([("A".to_string(), 2), ("B".to_string(), 1)]);
        let quotas = HashMap::from([
            (
                "A".to_string(),
                Quota {
                    weight: 200.0,
                    floor: 0,
                    ceil: None,
                },
            ),
            ("B".to_string(), Quota::default()),
        ]);
        assert_eq!(select_job(&cands, &gif, &quotas), Some(Uuid::from_u128(1)));
        // Push A ahead of its 2:1 share (3:1) → B becomes more starved, B wins.
        let gif2 = HashMap::from([("A".to_string(), 3), ("B".to_string(), 1)]);
        assert_eq!(select_job(&cands, &gif2, &quotas), Some(Uuid::from_u128(2)));
    }

    #[test]
    fn ceiling_excludes_a_group() {
        // A is at its ceiling; only B's job is eligible even though B is "busier".
        let cands = vec![cand(1, "A", 100, 10, 0), cand(2, "B", 100, 10, 5)];
        let gif = HashMap::from([("A".to_string(), 2), ("B".to_string(), 5)]);
        let quotas = HashMap::from([(
            "A".to_string(),
            Quota {
                weight: 100.0,
                floor: 0,
                ceil: Some(2),
            },
        )]);
        assert_eq!(select_job(&cands, &gif, &quotas), Some(Uuid::from_u128(2)));
    }

    #[test]
    fn floor_is_serviced_before_weighted_share() {
        // B is under its floor (needs 2, has 1) → B wins despite A being more
        // starved by the weighted ratio.
        let cands = vec![cand(1, "A", 100, 10, 0), cand(2, "B", 100, 10, 1)];
        let gif = HashMap::from([("A".to_string(), 0), ("B".to_string(), 1)]);
        let quotas = HashMap::from([(
            "B".to_string(),
            Quota {
                weight: 100.0,
                floor: 2,
                ceil: None,
            },
        )]);
        assert_eq!(select_job(&cands, &gif, &quotas), Some(Uuid::from_u128(2)));
    }

    #[test]
    fn all_at_ceiling_returns_none() {
        let cands = vec![cand(1, "A", 100, 10, 0)];
        let gif = HashMap::from([("A".to_string(), 3)]);
        let quotas = HashMap::from([(
            "A".to_string(),
            Quota {
                weight: 100.0,
                floor: 0,
                ceil: Some(3),
            },
        )]);
        assert_eq!(select_job(&cands, &gif, &quotas), None);
    }
}
