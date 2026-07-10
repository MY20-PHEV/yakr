use thiserror::Error;

#[derive(Debug, Error)]
pub enum YakrError {
    #[error("contact not found: {0}")]
    ContactNotFound(String),
    #[error("decrypt failed: {0}")]
    Decrypt(String),
    #[error("duplicate message")]
    DuplicateSeq,
    #[error("message expired")]
    MessageExpired,
    #[error("PQ session rekey required")]
    RekeyRequired,
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, YakrError>;
