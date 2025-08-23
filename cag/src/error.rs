#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Generic {0}")]
    Generic(String),

    #[error("DocumentNotFound {0}")]
    DocumentNotFound(String),

    #[error("ArangoArangoError {0}")]
    ArangoArangoError(#[from] arangors::error::ArangoError),

    #[error("ArangoClientError {0}")]
    ArangoClientError(#[from] arangors::error::ClientError),

    #[error("SerdeJsonError {0}")]
    SerdeJsonError(#[from] serde_json::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
