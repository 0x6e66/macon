use arangors::graph::EdgeDefinition;
use macon_cag::{impl_edge_attributes, utils::get_name};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::graph_creators::focused_graph::nodes::{FocusedCorpus, HasMalwareFamily};

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct Coper {
    pub name: String,
    pub display_name: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct CoperHasAPK {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct CoperAPK {
    pub sha256sum: String,

    // true if the EOCD of the APK/Zip is missing. This indicated the original sample was cut off
    // at some point
    pub is_cut: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct CoperHasELF {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema)]
pub struct CoperELF {
    pub sha256sum: String,
    pub architecture: Option<CoperELFArchitecture>,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema)]
pub enum CoperELFArchitecture {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "x86")]
    X86,
    #[serde(rename = "arm64-v8a")]
    Arm64V8a,
    #[serde(rename = "armeabi-v7a")]
    ArmEabiV7a,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct CoperHasDEX {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema)]
pub struct CoperDEX {
    pub sha256sum: String,
}

impl_edge_attributes!(CoperHasAPK);
impl_edge_attributes!(CoperHasELF);
impl_edge_attributes!(CoperHasDEX);

pub fn coper_edge_definitions() -> Vec<EdgeDefinition> {
    vec![
        EdgeDefinition {
            collection: get_name::<HasMalwareFamily>(),
            from: vec![get_name::<FocusedCorpus>()],
            to: vec![get_name::<Coper>()],
        },
        EdgeDefinition {
            collection: get_name::<CoperHasAPK>(),
            from: vec![get_name::<Coper>()],
            to: vec![get_name::<CoperAPK>()],
        },
        EdgeDefinition {
            collection: get_name::<CoperHasELF>(),
            from: vec![get_name::<CoperAPK>()],
            to: vec![get_name::<CoperELF>()],
        },
        EdgeDefinition {
            collection: get_name::<CoperHasDEX>(),
            from: vec![get_name::<CoperAPK>()],
            to: vec![get_name::<CoperDEX>()],
        },
    ]
}
