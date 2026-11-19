//! flamejob-core: pure domain model, state machines and the Runner trait.
//! No IO beyond the async channel used to stream runner status.
pub mod error;
pub mod model;
pub mod runner;

pub use error::{Error, Result};
pub use model::{roles_have, Capability, JobState, Role, TaskState};
pub use runner::{RunHandle, Runner, RunnerTask, StatusSink, StatusUpdate};
