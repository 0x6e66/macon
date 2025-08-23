pub mod coper;
pub mod nodes;

use anyhow::{Result, anyhow};
use arangors::{Document, collection::CollectionType, graph::EdgeDefinition};
use cag::{
    base_creator::GraphCreatorBase,
    utils::{
        config::Config, ensure_collection, ensure_database, ensure_graph,
        establish_database_connection,
    },
};

use crate::graph_creators::focused_graph::nodes::{
    FocusedCorpus, HasMalwareFamily,
    coper::{Coper, CoperAPK, CoperELF, CoperHasAPK, CoperHasELF, coper_edge_definitions},
};

pub struct FocusedGraph;

pub fn focused_graph_main() -> Result<()> {
    let edge_definitions = vec![coper_edge_definitions()]
        .into_iter()
        .flatten()
        .collect::<Vec<EdgeDefinition>>();

    let gc = FocusedGraph;

    let config = Config {
        database: "focused_corpus".to_string(),
        graph: "focused_corpus_graph".to_string(),
        ..Default::default()
    };

    gc.init(
        config,
        "/home/niklas/git/mace/samples/".into(),
        edge_definitions,
    )?;

    Ok(())
}

impl GraphCreatorBase for FocusedGraph {
    fn init(
        &self,
        config: cag::utils::config::Config,
        data_path: String,
        edge_definitions: Vec<EdgeDefinition>,
    ) -> cag::prelude::Result<()> {
        let conn = establish_database_connection(&config)?;
        let db = ensure_database(&conn, &config.database)?;

        ensure_collection::<FocusedCorpus>(&db, CollectionType::Document)?;
        ensure_collection::<HasMalwareFamily>(&db, CollectionType::Edge)?;

        ensure_collection::<Coper>(&db, CollectionType::Document)?;
        ensure_collection::<CoperAPK>(&db, CollectionType::Document)?;
        ensure_collection::<CoperELF>(&db, CollectionType::Document)?;

        ensure_collection::<CoperHasAPK>(&db, CollectionType::Edge)?;
        ensure_collection::<CoperHasELF>(&db, CollectionType::Edge)?;

        let corpus_node: Document<FocusedCorpus> = self.upsert_node::<FocusedCorpus>(
            FocusedCorpus {
                name: "FocusedCorpus".to_string(),
                display_name: "FocusedCorpus".to_string(),
            },
            "name".to_string(),
            "FocusedCorpus".to_string(),
            &db,
        )?;

        let rd = std::fs::read_dir(data_path).map_err(anyhow::Error::new)?;
        for entry in rd {
            let entry = entry.map_err(anyhow::Error::new)?;

            let file_name = entry
                .file_name()
                .into_string()
                .map_err(|e| anyhow!("{e:?}"))?;

            if file_name.as_str() == "apk.coper" {
                self.coper_main(entry.path(), &corpus_node, &db)?;
            }
        }

        let _ = ensure_graph(&db, &config.graph, edge_definitions)?;

        Ok(())
    }
}
