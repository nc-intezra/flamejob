//! Pure resolution of a directory user's effective roles from their resolved
//! group SIDs and the `directory_role_map`. No I/O — unit-tested in CI.

use flamejob_core::Role;

/// Compute the effective role set for a user, given the SIDs in their
/// `tokenGroups` and the `(group_sid, role)` mapping rows. A user receives the
/// UNION of the roles of every mapped group they belong to (capabilities union,
/// so there is no precedence to resolve). If they match no mapped group, they
/// get `default_role` if one is configured, else nothing (default deny).
///
/// The result is deduplicated and returned in a stable order
/// (Superadmin, Admin, Operator, Viewer) so tokens and audit are reproducible.
pub fn resolve_roles(
    member_sids: &[String],
    role_map: &[(String, Role)],
    default_role: Option<Role>,
) -> Vec<Role> {
    let mut have = [false; 4];
    let mark = |have: &mut [bool; 4], r: Role| {
        have[role_index(r)] = true;
    };
    for sid in member_sids {
        for (map_sid, role) in role_map {
            if map_sid == sid {
                mark(&mut have, *role);
            }
        }
    }
    if !have.iter().any(|&h| h) {
        if let Some(r) = default_role {
            mark(&mut have, r);
        }
    }
    [Role::Superadmin, Role::Admin, Role::Operator, Role::Viewer]
        .into_iter()
        .filter(|&r| have[role_index(r)])
        .collect()
}

fn role_index(r: Role) -> usize {
    match r {
        Role::Superadmin => 0,
        Role::Admin => 1,
        Role::Operator => 2,
        Role::Viewer => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> Vec<(String, Role)> {
        vec![
            ("S-1-5-21-1-2-3-admins".into(), Role::Admin),
            ("S-1-5-21-1-2-3-ops".into(), Role::Operator),
            ("S-1-5-21-1-2-3-ops2".into(), Role::Operator),
            ("S-1-5-21-1-2-3-super".into(), Role::Superadmin),
        ]
    }

    #[test]
    fn unions_roles_across_groups_and_dedups() {
        let sids = vec![
            "S-1-5-21-1-2-3-ops".to_string(),
            "S-1-5-21-1-2-3-ops2".to_string(), // also Operator -> dedup
            "S-1-5-21-1-2-3-admins".to_string(),
        ];
        assert_eq!(
            resolve_roles(&sids, &map(), None),
            vec![Role::Admin, Role::Operator]
        );
    }

    #[test]
    fn stable_order_regardless_of_input_order() {
        let sids = vec![
            "S-1-5-21-1-2-3-ops".to_string(),
            "S-1-5-21-1-2-3-super".to_string(),
        ];
        assert_eq!(
            resolve_roles(&sids, &map(), None),
            vec![Role::Superadmin, Role::Operator]
        );
    }

    #[test]
    fn no_match_is_default_deny() {
        let sids = vec!["S-1-5-21-9-9-9-nobody".to_string()];
        assert!(resolve_roles(&sids, &map(), None).is_empty());
    }

    #[test]
    fn default_role_applies_only_when_no_match() {
        let none = vec!["S-1-5-21-9-9-9-nobody".to_string()];
        assert_eq!(
            resolve_roles(&none, &map(), Some(Role::Viewer)),
            vec![Role::Viewer]
        );
        // A real match suppresses the default floor.
        let matched = vec!["S-1-5-21-1-2-3-admins".to_string()];
        assert_eq!(
            resolve_roles(&matched, &map(), Some(Role::Viewer)),
            vec![Role::Admin]
        );
    }
}
