use arangors::graph::EdgeDefinition;
use macon_cag::{impl_edge_attributes, utils::get_name};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct DarkWatchmen {
    pub name: String,
    pub display_name: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct DarkWatchmenHasPE {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct DarkWatchmenPE {
    pub sha256sum: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct DarkWatchmenHasJS {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct DarkWatchmenJS {
    pub sha256sum: String,
}

impl_edge_attributes!(DarkWatchmenHasPE);
impl_edge_attributes!(DarkWatchmenHasJS);

pub fn dark_watchmen_edge_definitions() -> Vec<EdgeDefinition> {
    vec![
        EdgeDefinition {
            collection: get_name::<DarkWatchmenHasPE>(),
            from: vec![get_name::<DarkWatchmen>()],
            to: vec![get_name::<DarkWatchmenPE>()],
        },
        EdgeDefinition {
            collection: get_name::<DarkWatchmenHasJS>(),
            from: vec![get_name::<DarkWatchmenPE>()],
            to: vec![get_name::<DarkWatchmenJS>()],
        },
    ]
}
