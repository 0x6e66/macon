use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub url: String,
    pub user: String,
    pub password: String,
    pub database: String,
    pub graph: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8529".to_string(),
            user: "root".to_string(),
            password: "root".to_string(),
            database: "cag_default_database".to_string(),
            graph: "cag_default_graph".to_string(),
        }
    }
}

impl Config {
    pub fn new<S: Into<String>>(url: S, user: S, password: S, database: S, graph: S) -> Self {
        Self {
            url: url.into(),
            user: user.into(),
            password: password.into(),
            database: database.into(),
            graph: graph.into(),
        }
    }
}
