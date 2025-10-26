pub mod nodes;

use std::{
    io::Read,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Result, anyhow};
use arangors::{Document, collection::CollectionType};
use indicatif::ParallelProgressIterator;
use macon_cag::{
    base_creator::{GraphCreatorBase, UpsertResult},
    utils::ensure_collection,
};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sha256::digest;

use crate::{
    graph_creators::focused_graph::{
        FocusedCorpus, FocusedGraph, HasMalwareFamily,
        carnavalheist::nodes::{
            Carnavalheist, CarnavalheistBatch, CarnavalheistHasBatch, CarnavalheistHasPs,
            CarnavalheistHasPython, CarnavalheistPs, CarnavalheistPython,
        },
    },
    utils::get_string_from_binary,
};

impl FocusedGraph {
    pub fn carnavalheist_main(
        &self,
        files: &[PathBuf],
        corpus_node: &Document<FocusedCorpus>,
    ) -> Result<()> {
        let idxs = Some(vec!["sha256sum".into()]);
        let db = self.get_db();

        // Nodes
        ensure_collection::<Carnavalheist>(db, CollectionType::Document, None)?;
        ensure_collection::<CarnavalheistBatch>(db, CollectionType::Document, idxs.clone())?;
        ensure_collection::<CarnavalheistPs>(db, CollectionType::Document, idxs.clone())?;
        ensure_collection::<CarnavalheistPython>(db, CollectionType::Document, idxs)?;

        // Edges
        ensure_collection::<CarnavalheistHasBatch>(db, CollectionType::Edge, None)?;
        ensure_collection::<CarnavalheistHasPs>(db, CollectionType::Edge, None)?;
        ensure_collection::<CarnavalheistHasPython>(db, CollectionType::Edge, None)?;

        let main_node = self.carnavalheist_create_main_node(corpus_node)?;

        let errors: Arc<Mutex<Vec<anyhow::Error>>> = Arc::new(Mutex::new(Vec::new()));

        files
            .par_iter()
            .progress()
            .for_each(|entry| match std::fs::File::open(entry) {
                Ok(mut file) => {
                    let mut buf = Vec::new();
                    match file.read_to_end(&mut buf) {
                        Ok(_) => {
                            match self.carnavalheist_handle_sample(
                                &format!("{entry:?}"),
                                &buf,
                                &main_node,
                            ) {
                                Ok(_) => (),
                                Err(e) => errors.lock().unwrap().push(e),
                            }
                        }
                        Err(e) => errors.lock().unwrap().push(e.into()),
                    }
                }
                Err(e) => errors.lock().unwrap().push(e.into()),
            });

        for e in errors.lock().unwrap().iter() {
            eprintln!("{e}");
        }

        Ok(())
    }

    fn carnavalheist_create_main_node(
        &self,
        corpus_node: &Document<FocusedCorpus>,
    ) -> Result<Document<Carnavalheist>> {
        let main_node_data = Carnavalheist {
            name: "Carnavalheist".to_string(),
            display_name: "Carnavalheist".to_string(),
        };

        let UpsertResult {
            document: main_node,
            created: _,
        } = self.upsert_node::<Carnavalheist>(main_node_data, "name", "Carnavalheist")?;

        self.upsert_edge::<FocusedCorpus, Carnavalheist, HasMalwareFamily>(
            corpus_node,
            &main_node,
        )?;

        Ok(main_node)
    }

    fn carnavalheist_handle_sample(
        &self,
        sample_filename: &str,
        sample_data: &[u8],
        main_node: &Document<Carnavalheist>,
    ) -> Result<()> {
        match detect_sample_type(sample_data) {
            Some(SampleType::BatchE) => {
                let batch_node = self.carnavalheist_create_batch_node(sample_data)?;
                self.upsert_edge::<Carnavalheist, CarnavalheistBatch, CarnavalheistHasBatch>(
                    main_node,
                    &batch_node,
                )?;
            }
            Some(SampleType::BatchCommandNormal) => todo!(),
            Some(SampleType::BatchCommandConcat) => todo!(),
            Some(SampleType::Ps) => todo!(),
            Some(SampleType::Python) => todo!(),
            None => {
                return Err(anyhow!(
                    "Sample type of the sample {sample_filename} could not be detected"
                ));
            }
        }

        Ok(())
    }

    fn carnavalheist_create_batch_node(
        &self,
        sample_data: &[u8],
    ) -> Result<Document<CarnavalheistBatch>> {
        let sha256sum = digest(sample_data);

        let batch_node_data = CarnavalheistBatch {
            sha256sum: sha256sum.clone(),
        };

        let UpsertResult {
            document: batch_node,
            created,
        } = self.upsert_node::<CarnavalheistBatch>(batch_node_data, "sha256sum", &sha256sum)?;

        // Sample is already in DB => no need for further analysis
        if !created {
            return Ok(batch_node);
        }

        // TODO: extract next stage

        Ok(batch_node)
    }
}

enum SampleType {
    BatchE,
    BatchCommandNormal,
    BatchCommandConcat,
    Ps,
    Python,
}

fn detect_sample_type(sample_data: &[u8]) -> Option<SampleType> {
    let sample_str = get_string_from_binary(sample_data);

    if sample_str.contains("powershell -WindowStyle Hidden -e") {
        return Some(SampleType::BatchE);
    } else if sample_str.contains("powershell -WindowStyle Hidden -Command") {
        if sample_str.contains("set \"base64=") {
            return Some(SampleType::BatchCommandConcat);
        }
        return Some(SampleType::BatchCommandNormal);
    } else if sample_str.contains("RANDOMIZADO") || sample_str.contains("import pickle") {
        return Some(SampleType::Python);
    }

    None
}
