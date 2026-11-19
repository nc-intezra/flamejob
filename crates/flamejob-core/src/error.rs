use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid state transition: {from} -> {to}")]
    InvalidTransition { from: String, to: String },
    #[error("runner error: {0}")]
    Runner(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
