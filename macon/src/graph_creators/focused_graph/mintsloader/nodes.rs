use arangors::graph::EdgeDefinition;
use macon_cag::{impl_edge_attributes, utils::get_name};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct Mintsloader {
    pub name: String,
    pub display_name: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MintsloaderHasPs {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema)]
pub struct MintsloaderPs {
    pub sha256sum: String,
    pub kind: MintsloaderPsKind,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema)]
pub enum MintsloaderPsKind {
    XorBase64,
    DgaIex,
    StartProcess,
    TwoLiner,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MintsloaderHasJava {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MintsloaderJava {
    pub sha256sum: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MintsloaderHasX509Cert {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MintsloaderX509Cert {
    pub sha256sum: String,
}

impl_edge_attributes!(MintsloaderHasPs);
impl_edge_attributes!(MintsloaderHasJava);
impl_edge_attributes!(MintsloaderHasX509Cert);

pub fn mintsloader_edge_definitions() -> Vec<EdgeDefinition> {
    vec![
        EdgeDefinition {
            collection: get_name::<MintsloaderHasPs>(),
            from: vec![get_name::<Mintsloader>(), get_name::<MintsloaderPs>()],
            to: vec![get_name::<MintsloaderPs>()],
        },
        EdgeDefinition {
            collection: get_name::<MintsloaderHasJava>(),
            from: vec![get_name::<MintsloaderPs>()],
            to: vec![get_name::<MintsloaderJava>()],
        },
        EdgeDefinition {
            collection: get_name::<MintsloaderHasX509Cert>(),
            from: vec![get_name::<MintsloaderPs>()],
            to: vec![get_name::<MintsloaderX509Cert>()],
        },
    ]
}
