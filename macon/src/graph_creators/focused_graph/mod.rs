pub mod coper;
pub mod nodes;

use std::fmt::Debug;
use std::path::PathBuf;

use anyhow::Result;
use arangors::{Document, collection::CollectionType, graph::EdgeDefinition};
use cag::{
    base_creator::GraphCreatorBase,
    prelude::Database,
    utils::{
        config::Config, ensure_collection, ensure_database, ensure_graph,
        establish_database_connection, get_name,
    },
};
use schemars::JsonSchema;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    classifier::MalwareFamiliy,
    graph_creators::focused_graph::nodes::{
        FocusedCorpus, HasMalwareFamily, coper::coper_edge_definitions,
    },
};

pub struct FocusedGraph;

pub fn focused_graph_main(files: &[PathBuf], family: MalwareFamiliy) -> Result<()> {
    let edge_definitions: Vec<EdgeDefinition> = vec![coper_edge_definitions()]
        .into_iter()
        .flatten()
        .collect();

    let gc = FocusedGraph;

    let config = Config {
        database: "focused_corpus".to_string(),
        graph: "focused_corpus_graph".to_string(),
        ..Default::default()
    };

    let corpus_data = FocusedCorpus {
        name: "FocusedCorpus".to_string(),
        display_name: "FocusedCorpus".to_string(),
    };

    let (db, corpus_node) = gc.init::<FocusedCorpus>(config, corpus_data, edge_definitions)?;

    match family {
        MalwareFamiliy::Coper => gc.coper_main(files, &corpus_node, &db)?,
    }

    Ok(())
}

impl GraphCreatorBase for FocusedGraph {
    fn init<T>(
        &self,
        config: cag::utils::config::Config,
        corpus_node_data: T,
        edge_definitions: Vec<EdgeDefinition>,
    ) -> cag::prelude::Result<(Database, Document<T>)>
    where
        T: DeserializeOwned + Serialize + Clone + JsonSchema + Debug,
    {
        let conn = establish_database_connection(&config)?;
        let db = ensure_database(&conn, &config.database)?;

        // Base Nodes and Edges
        ensure_collection::<FocusedCorpus>(&db, CollectionType::Document, None)?;
        ensure_collection::<HasMalwareFamily>(&db, CollectionType::Edge, None)?;

        let _ = ensure_graph(&db, &config.graph, edge_definitions)?;

        // create corpus node
        let corpus_node: Document<T> = self
            .upsert_node::<T>(corpus_node_data, "name".to_string(), get_name::<T>(), &db)?
            .document;

        Ok((db, corpus_node))
    }
}
