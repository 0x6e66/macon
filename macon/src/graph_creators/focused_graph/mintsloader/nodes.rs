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
pub struct MintsloaderHasPsXorBase64 {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MintsloaderPsXorBase64 {
    pub sha256sum: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MintsloaderHasPsDgaIex {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MintsloaderPsDgaIex {
    pub sha256sum: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MintsloaderHasPsStartProcess {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MintsloaderPsStartProcess {
    pub sha256sum: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MintsloaderHasPsTwoLiner {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MintsloaderPsTwoLiner {
    pub sha256sum: String,
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

impl_edge_attributes!(MintsloaderHasPsXorBase64);
impl_edge_attributes!(MintsloaderHasPsDgaIex);
impl_edge_attributes!(MintsloaderHasPsStartProcess);
impl_edge_attributes!(MintsloaderHasPsTwoLiner);
impl_edge_attributes!(MintsloaderHasJava);
impl_edge_attributes!(MintsloaderHasX509Cert);

pub fn mintsloader_edge_definitions() -> Vec<EdgeDefinition> {
    vec![
        EdgeDefinition {
            collection: get_name::<MintsloaderHasPsXorBase64>(),
            from: vec![get_name::<Mintsloader>()],
            to: vec![get_name::<MintsloaderPsXorBase64>()],
        },
        EdgeDefinition {
            collection: get_name::<MintsloaderHasPsDgaIex>(),
            from: vec![get_name::<MintsloaderPsXorBase64>()],
            to: vec![get_name::<MintsloaderPsDgaIex>()],
        },
        EdgeDefinition {
            collection: get_name::<MintsloaderHasPsStartProcess>(),
            from: vec![get_name::<MintsloaderPsXorBase64>()],
            to: vec![get_name::<MintsloaderPsStartProcess>()],
        },
        EdgeDefinition {
            collection: get_name::<MintsloaderHasPsTwoLiner>(),
            from: vec![get_name::<Mintsloader>()],
            to: vec![get_name::<MintsloaderPsTwoLiner>()],
        },
        EdgeDefinition {
            collection: get_name::<MintsloaderHasJava>(),
            from: vec![
                get_name::<MintsloaderPsTwoLiner>(),
                get_name::<MintsloaderPsXorBase64>(),
            ],
            to: vec![get_name::<MintsloaderJava>()],
        },
        EdgeDefinition {
            collection: get_name::<MintsloaderHasX509Cert>(),
            from: vec![
                get_name::<MintsloaderPsTwoLiner>(),
                get_name::<MintsloaderPsXorBase64>(),
            ],
            to: vec![get_name::<MintsloaderX509Cert>()],
        },
    ]
}
