use serde::{Deserialize, Serialize};

/// Directory-mapped roles. In Phase 1 these come from the local `user_roles`
/// table; in Phase 5 they are mapped from AD/LDAP group membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Superadmin,
    Admin,
    Operator,
    Viewer,
}

/// Fine-grained capabilities. Routes require a capability, not a role, so the
/// mapping can change without touching handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ManageUsers,
    SubmitJobs,
    Ingest,
    ViewPlaintext,
    ViewStats,
    ViewJobs,
    ManageDirectory,
    /// View (read-only) the directory/AD-LDAP connection config and run
    /// connection/login tests. Granted to admin + superadmin; the dangerous
    /// mutations (save, enable/disable, edit the SID->role map) stay on
    /// `ManageDirectory` (superadmin only), since a wrong directory config is an
    /// org-wide-auth event.
    ViewDirectoryConfig,
    ManageAgents,
    /// Change sitewide settings, including the TLS certificate/key and the
    /// HTTPS-on-443 toggle. High-privilege: whoever holds it controls the site's
    /// transport security. Granted to superadmin and admin.
    ManageSettings,
}

impl Role {
    pub fn capabilities(self) -> &'static [Capability] {
        use Capability::*;
        match self {
            Role::Superadmin => &[
                ManageUsers,
                SubmitJobs,
                Ingest,
                ViewPlaintext,
                ViewStats,
                ViewJobs,
                ManageDirectory,
                ViewDirectoryConfig,
                ManageAgents,
                ManageSettings,
            ],
            // Admin manages users and agents; ViewJobs lets an admin see the
            // job queue they pin to agents (you can't pin what you can't see).
            // ViewDirectoryConfig lets an admin view and test the directory
            // config, but not save/enable it (that stays superadmin).
            Role::Admin => &[
                ManageUsers,
                ManageAgents,
                ViewJobs,
                ManageSettings,
                ViewDirectoryConfig,
            ],
            Role::Operator => &[SubmitJobs, Ingest, ViewPlaintext, ViewStats, ViewJobs],
            Role::Viewer => &[ViewStats, ViewJobs],
        }
    }

    pub fn has(self, cap: Capability) -> bool {
        self.capabilities().contains(&cap)
    }
}

/// True if any of the roles grants the capability.
pub fn roles_have(roles: &[Role], cap: Capability) -> bool {
    roles.iter().any(|r| r.has(cap))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    Queued,
    Assigned,
    Running,
    Paused,
    Completed,
    Exhausted,
    Cancelled,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskState {
    Pending,
    Running,
    Paused,
    Done,
    Failed,
}

impl JobState {
    /// The legal job transitions (see the state machine in the Phase 1 spec).
    pub fn can_transition(self, to: JobState) -> bool {
        use JobState::*;
        matches!(
            (self, to),
            (Queued, Assigned)
                | (Queued, Cancelled)
                | (Assigned, Running)
                | (Assigned, Queued)
                | (Assigned, Cancelled)
                | (Running, Paused)
                | (Running, Completed)
                | (Running, Exhausted)
                | (Running, Error)
                | (Running, Cancelled)
                | (Paused, Running)
                | (Paused, Cancelled)
        )
    }

    pub fn is_terminal(self) -> bool {
        use JobState::*;
        matches!(self, Completed | Exhausted | Cancelled | Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rbac_matches_spec() {
        assert!(Role::Operator.has(Capability::SubmitJobs));
        assert!(!Role::Admin.has(Capability::SubmitJobs));
        assert!(Role::Admin.has(Capability::ManageUsers));
        assert!(Role::Admin.has(Capability::ViewJobs)); // admins see the queue to pin jobs
        assert!(!Role::Admin.has(Capability::SubmitJobs)); // but still cannot submit
        assert!(!Role::Viewer.has(Capability::SubmitJobs));
        assert!(Role::Viewer.has(Capability::ViewJobs));
        assert!(Role::Superadmin.has(Capability::ManageDirectory));
        // ViewDirectoryConfig: admin + superadmin may view/test the directory
        // config; write/enable stays on ManageDirectory (superadmin only).
        assert!(Role::Superadmin.has(Capability::ViewDirectoryConfig));
        assert!(Role::Admin.has(Capability::ViewDirectoryConfig));
        assert!(!Role::Admin.has(Capability::ManageDirectory));
        assert!(!Role::Operator.has(Capability::ViewDirectoryConfig));
        assert!(Role::Superadmin.has(Capability::ManageAgents));
        assert!(Role::Admin.has(Capability::ManageAgents));
        assert!(!Role::Operator.has(Capability::ManageAgents));
        // Sitewide settings (TLS cert/key, HTTPS toggle): superadmin + admin only.
        assert!(Role::Superadmin.has(Capability::ManageSettings));
        assert!(Role::Admin.has(Capability::ManageSettings));
        assert!(!Role::Operator.has(Capability::ManageSettings));
        assert!(!Role::Viewer.has(Capability::ManageSettings));
    }

    #[test]
    fn job_transitions() {
        assert!(JobState::Queued.can_transition(JobState::Assigned));
        assert!(JobState::Running.can_transition(JobState::Completed));
        assert!(!JobState::Completed.can_transition(JobState::Running));
        assert!(JobState::Completed.is_terminal());
    }
}
