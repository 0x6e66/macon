use arangors::graph::EdgeDefinition;
use cag::{impl_edge_attributes, utils::get_name};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::graph_creators::focused_graph::nodes::{FokusedCorpus, HasMalwareFamily};

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
    pub original_filename: Option<String>,
    pub display_name: String,
    pub sha256sum: String,

    // true if the APK contains a /lib directory with subdirectories for a native version of the
    // app (ELF in various architectures)
    pub has_native_lib: bool,

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
    pub original_filename: String,
    pub display_name: String,
    pub sha256sum: String,
    pub architecture: CoperELFArchitecture,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema)]
pub enum CoperELFArchitecture {
    X86_64,
    X86,
    Arm64V8a,
    ArmEabiV7a,
}

impl_edge_attributes!(CoperHasAPK);
impl_edge_attributes!(CoperHasELF);

pub fn coper_edge_definitions() -> Vec<EdgeDefinition> {
    vec![
        EdgeDefinition {
            collection: get_name::<HasMalwareFamily>(),
            from: vec![get_name::<FokusedCorpus>()],
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
    ]
}
