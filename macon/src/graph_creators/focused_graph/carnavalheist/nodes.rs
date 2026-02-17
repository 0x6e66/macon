use arangors::graph::EdgeDefinition;
use macon_cag::{impl_edge_attributes, utils::get_name};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct Carnavalheist {
    pub name: String,
    pub display_name: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct CarnavalheistHasBatch {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct CarnavalheistBatch {
    pub sha256sum: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct CarnavalheistHasPs {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema)]
pub struct CarnavalheistPs {
    pub sha256sum: String,
    pub ps_type: PsType,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema)]
pub enum PsType {
    Normal,
    Concat,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct CarnavalheistHasPython {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct CarnavalheistPython {
    pub sha256sum: String,
}

impl_edge_attributes!(CarnavalheistHasBatch);
impl_edge_attributes!(CarnavalheistHasPs);
impl_edge_attributes!(CarnavalheistHasPython);

pub fn carnavalheist_edge_definitions() -> Vec<EdgeDefinition> {
    vec![
        EdgeDefinition {
            collection: get_name::<CarnavalheistHasBatch>(),
            from: vec![get_name::<Carnavalheist>()],
            to: vec![get_name::<CarnavalheistBatch>()],
        },
        EdgeDefinition {
            collection: get_name::<CarnavalheistHasPs>(),
            from: vec![get_name::<CarnavalheistBatch>()],
            to: vec![get_name::<CarnavalheistPs>()],
        },
        EdgeDefinition {
            collection: get_name::<CarnavalheistHasPython>(),
            from: vec![get_name::<CarnavalheistPs>()],
            to: vec![get_name::<CarnavalheistPython>()],
        },
    ]
}
