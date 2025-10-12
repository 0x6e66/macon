pub mod coper;

use macon_cag::impl_edge_attributes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct FocusedCorpus {
    pub name: String,
    pub display_name: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct HasMalwareFamily {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

impl_edge_attributes!(HasMalwareFamily);
