pub mod coper;
pub mod mintsloader;

use arangors::graph::EdgeDefinition;
use macon_cag::{impl_edge_attributes, utils::get_name};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::graph_creators::focused_graph::nodes::{coper::Coper, mintsloader::Mintsloader};

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

pub fn base_edge_definitions() -> Vec<EdgeDefinition> {
    vec![EdgeDefinition {
        collection: get_name::<HasMalwareFamily>(),
        from: vec![get_name::<FocusedCorpus>()],
        to: vec![get_name::<Coper>(), get_name::<Mintsloader>()],
    }]
}
