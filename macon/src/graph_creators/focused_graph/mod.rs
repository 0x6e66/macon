pub mod coper;
pub mod nodes;

use arangors::{Document, collection::CollectionType, graph::EdgeDefinition};
use cag::{
    base_creator::GraphCreatorBase,
    utils::{ensure_collection, ensure_database, ensure_graph, establish_database_connection},
};

use crate::graph_creators::focused_graph::nodes::{
    FokusedCorpus, HasMalwareFamily,
    coper::{Coper, CoperAPK, CoperELF, CoperHasAPK, CoperHasELF},
};

pub struct FokusedGraph;

impl GraphCreatorBase for FokusedGraph {
    fn init(
        &self,
        config: cag::utils::config::Config,
        data_path: String,
        edge_definitions: Vec<EdgeDefinition>,
    ) -> cag::prelude::Result<()> {
        let conn = establish_database_connection(&config)?;
        let db = ensure_database(&conn, &config.database)?;

        ensure_collection::<FokusedCorpus>(&db, CollectionType::Document)?;
        ensure_collection::<HasMalwareFamily>(&db, CollectionType::Edge)?;

        ensure_collection::<Coper>(&db, CollectionType::Document)?;
        ensure_collection::<CoperAPK>(&db, CollectionType::Document)?;
        ensure_collection::<CoperELF>(&db, CollectionType::Document)?;

        ensure_collection::<CoperHasAPK>(&db, CollectionType::Edge)?;
        ensure_collection::<CoperHasELF>(&db, CollectionType::Edge)?;

        let corpus_node: Document<FokusedCorpus> = self.upsert_node::<FokusedCorpus>(
            FokusedCorpus {
                name: "FokusedCorpus".to_string(),
                display_name: "FokusedCorpus".to_string(),
            },
            "name".to_string(),
            "FokusedCorpus".to_string(),
            &db,
        )?;

        let rd = std::fs::read_dir(data_path).unwrap();
        for entry in rd {
            let entry = entry.unwrap();

            let file_name = entry.file_name().into_string().unwrap();

            if file_name.as_str() == "apk.coper" {
                self.coper_main(entry.path(), &corpus_node, &db).unwrap();
            }
        }

        let _ = ensure_graph(&db, &config.graph, edge_definitions)?;

        Ok(())
    }
}
