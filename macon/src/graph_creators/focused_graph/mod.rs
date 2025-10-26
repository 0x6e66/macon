pub mod carnavalheist;
pub mod coper;
pub mod mintsloader;

use std::{fmt::Debug, path::PathBuf};

use anyhow::Result;
use arangors::{Document, collection::CollectionType, graph::EdgeDefinition};
use macon_cag::{
    base_creator::GraphCreatorBase,
    impl_edge_attributes,
    prelude::Database,
    utils::{
        config::Config, ensure_collection, ensure_database, ensure_graph,
        establish_database_connection, get_name,
    },
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    classifier::MalwareFamiliy,
    graph_creators::focused_graph::{
        carnavalheist::nodes::{Carnavalheist, carnavalheist_edge_definitions},
        coper::nodes::{Coper, coper_edge_definitions},
        mintsloader::nodes::{Mintsloader, mintsloader_edge_definitions},
    },
};

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

fn base_edge_definitions() -> Vec<EdgeDefinition> {
    vec![EdgeDefinition {
        collection: get_name::<HasMalwareFamily>(),
        from: vec![get_name::<FocusedCorpus>()],
        to: vec![
            get_name::<Carnavalheist>(),
            get_name::<Coper>(),
            get_name::<Mintsloader>(),
        ],
    }]
}

struct FocusedGraph {
    db: Database,
}

impl FocusedGraph {
    pub fn try_new(config: &Config) -> Result<Self> {
        let conn = establish_database_connection(config)?;
        let db = ensure_database(&conn, &config.database)?;

        Ok(Self { db })
    }
}

pub fn focused_graph_main(files: &[PathBuf], family: MalwareFamiliy) -> Result<()> {
    let edge_definitions: Vec<EdgeDefinition> = vec![
        base_edge_definitions(),
        carnavalheist_edge_definitions(),
        coper_edge_definitions(),
        mintsloader_edge_definitions(),
    ]
    .into_iter()
    .flatten()
    .collect();

    let corpus_data = FocusedCorpus {
        name: "FocusedCorpus".to_string(),
        display_name: "FocusedCorpus".to_string(),
    };

    let config = Config {
        database: "focused_corpus".to_string(),
        graph: "focused_corpus_graph".to_string(),
        ..Default::default()
    };

    let gc = FocusedGraph::try_new(&config)?;
    let corpus_node = gc.init::<FocusedCorpus>(config, corpus_data, edge_definitions)?;

    match family {
        MalwareFamiliy::Carnavalheist => gc.carnavalheist_main(files, &corpus_node)?,
        MalwareFamiliy::Coper => gc.coper_main(files, &corpus_node)?,
        MalwareFamiliy::Mintsloader => gc.mintsloader_main(files, &corpus_node)?,
    }

    Ok(())
}

impl GraphCreatorBase for FocusedGraph {
    fn init<T>(
        &self,
        config: Config,
        corpus_node_data: T,
        edge_definitions: Vec<EdgeDefinition>,
    ) -> macon_cag::prelude::Result<Document<T>>
    where
        T: DeserializeOwned + Serialize + Clone + JsonSchema + Debug,
    {
        // Base Nodes and Edges
        ensure_collection::<FocusedCorpus>(&self.db, CollectionType::Document, None)?;
        ensure_collection::<HasMalwareFamily>(&self.db, CollectionType::Edge, None)?;

        let _ = ensure_graph(&self.db, &config.graph, edge_definitions)?;

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
