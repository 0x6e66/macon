pub use crate::error::Error;

pub type Result<T> = core::result::Result<T, Error>;

pub type Database = arangors::Database<arangors::client::reqwest::ReqwestClient>;
pub type Collection = arangors::Collection<arangors::client::reqwest::ReqwestClient>;
