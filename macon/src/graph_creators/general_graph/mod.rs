pub mod evaluation;
pub mod general;

use std::fmt::Debug;

use arangors::{Document, graph::EdgeDefinition};
use macon_cag::{
    base_creator::GraphCreatorBase,
    impl_edge_attributes,
    prelude::{Database, Result},
    utils::{
        config::Config, ensure_database, ensure_graph, ensure_index, establish_database_connection,
        get_name,
    },
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::cli::MainArgs;

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct GeneralCorpus {
    pub name: String,
    pub display_name: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct MalwareSample {
    pub sha256sum: String,
    pub ssdeep: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct SampleDistance {
    pub _key: String,
    pub _from: String,
    pub _to: String,
    pub ssdeep_distance: u32,
}

#[derive(Deserialize, Serialize, Debug, Clone, JsonSchema, Default)]
pub struct DummyEdge {
    pub _key: String,
    pub _from: String,
    pub _to: String,
}

impl_edge_attributes!(SampleDistance);
impl_edge_attributes!(DummyEdge);

struct GeneralGraph {
    db: Database,
}

impl GeneralGraph {
    pub fn try_new(config: &Config) -> Result<Self> {
        let conn = establish_database_connection(config)?;
        let db = ensure_database(&conn, &config.database)?;

        Ok(Self { db })
    }
}

pub fn general_graph_main(main_args: MainArgs) -> Result<()> {
    let edge_definitions = vec![
        EdgeDefinition {
            collection: get_name::<SampleDistance>(),
            from: vec![get_name::<MalwareSample>()],
            to: vec![get_name::<MalwareSample>()],
        },
        EdgeDefinition {
            collection: get_name::<DummyEdge>(),
            from: vec![get_name::<GeneralCorpus>()],
            to: vec![get_name::<GeneralCorpus>()],
        },
    ];

    let corpus_data = GeneralCorpus {
        name: "GeneralCorpus".to_string(),
        display_name: "GeneralCorpus".to_string(),
    };

    let config = Config {
        database: "general_corpus".to_string(),
        graph: "general_corpus_graph".to_string(),
        ..Default::default()
    };

    let gc = GeneralGraph::try_new(&config)?;
    let _ = gc.init::<GeneralCorpus>(config, corpus_data, edge_definitions)?;

    gc.general_graph_entry(main_args.files)?;

    Ok(())
}

impl GraphCreatorBase for GeneralGraph {
    fn init<T>(
        &self,
        config: Config,
        corpus_node_data: T,
        edge_definitions: Vec<EdgeDefinition>,
    ) -> macon_cag::prelude::Result<Document<T>>
    where
        T: DeserializeOwned + Serialize + Clone + JsonSchema + Debug,
    {
        let _ = ensure_graph(&self.db, &config.graph, edge_definitions)?;

        let db = self.get_db();

        // Create index for name and sha256sum field
        ensure_index::<GeneralCorpus>(db, vec!["name".to_string()])?;
        ensure_index::<MalwareSample>(db, vec!["sha256sum".to_string()])?;

        // create corpus node
        let corpus_node: Document<T> = self
            .upsert_node::<T>(corpus_node_data, "name", &get_name::<T>())?
            .document;

        Ok(corpus_node)
    }

    fn get_db(&self) -> &Database {
        &self.db
    }
}
