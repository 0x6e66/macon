pub mod nodes;

use std::{
    io::Read,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Result, anyhow};
use arangors::Document;
use base64::{
    Engine, alphabet,
    engine::{GeneralPurpose, general_purpose::PAD},
};
use indicatif::ParallelProgressIterator;
use lazy_static::lazy_static;
use macon_cag::{
    base_creator::{GraphCreatorBase, UpsertResult},
    utils::ensure_index,
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

lazy_static! {
    static ref BASE64_DECODER: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, PAD);
}

impl FocusedGraph {
    pub fn carnavalheist_main(
        &self,
        files: &[PathBuf],
        corpus_node: &Document<FocusedCorpus>,
    ) -> Result<()> {
        let db = self.get_db();
        let idx = vec!["sha256sum".to_string()];

        // Create index for sha256sum field
        ensure_index::<CarnavalheistBatch>(db, idx.clone())?;
        ensure_index::<CarnavalheistPs>(db, idx.clone())?;
        ensure_index::<CarnavalheistPython>(db, idx)?;

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
                let batch_node =
                    self.carnavalheist_create_batch_node(sample_data, SampleType::BatchE)?;
                self.upsert_edge::<Carnavalheist, CarnavalheistBatch, CarnavalheistHasBatch>(
                    main_node,
                    &batch_node,
                )?;
            }
            Some(SampleType::BatchCommandNormal) => {
                let batch_node = self
                    .carnavalheist_create_batch_node(sample_data, SampleType::BatchCommandNormal)?;
                self.upsert_edge::<Carnavalheist, CarnavalheistBatch, CarnavalheistHasBatch>(
                    main_node,
                    &batch_node,
                )?;
            }
            Some(SampleType::BatchCommandConcat) => {
                println!("{sample_filename}: BatchCommandConcat (not implemented)")
            }
            Some(SampleType::Ps) => println!("{sample_filename}: Ps (not implemented)"),
            Some(SampleType::Python) => {
                self.carnavalheist_create_python_node(sample_data)?;
            }
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
        sample_type: SampleType,
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

        // extract next stage
        let sample_str = get_string_from_binary(sample_data);

        let ps_stage = match sample_type {
            SampleType::BatchE => extract_from_batch_e(&sample_str)?,
            SampleType::BatchCommandNormal => extract_from_batch_command_normal(&sample_str)?,
            // SampleType::BatchCommandConcat => extract_from_batch_command_concat(&sample_str)?,
            _ => return Err(anyhow!("wrong sample type")),
        };

        let ps_node = self.carnavalheist_create_ps_node(&ps_stage)?;
        self.upsert_edge::<CarnavalheistBatch, CarnavalheistPs, CarnavalheistHasPs>(
            &batch_node,
            &ps_node,
        )?;

        Ok(batch_node)
    }

    fn carnavalheist_create_ps_node(
        &self,
        sample_data: &[u8],
    ) -> Result<Document<CarnavalheistPs>> {
        let sha256sum = digest(sample_data);

        let ps_node_data = CarnavalheistPs {
            sha256sum: sha256sum.clone(),
        };

        let UpsertResult {
            document: ps_node,
            created,
        } = self.upsert_node::<CarnavalheistPs>(ps_node_data, "sha256sum", &sha256sum)?;

        // Sample is already in DB => no need for further analysis
        if !created {
            return Ok(ps_node);
        }

        // extract next stage (python)
        let sample_str = get_string_from_binary(sample_data);

        // account for two variants
        //  1. `base64.b64decode(''''BASE64_ENCODED_STRING''')`
        //  2. `base64.b64decode(r'''BASE64_ENCODED_STRING''')`
        let start = sample_str
            .find("base64.b64decode(\'")
            .and_then(|l| Some(l + 18))
            .or(sample_str
                .find("base64.b64decode(r\'")
                .and_then(|l| Some(l + 19)))
            .ok_or(anyhow!("Could not find next stage in ps stage"))?;

        // find start of base64 encoded string
        let start = sample_str[start..]
            .find(|c| c != '\'')
            .ok_or(anyhow!("Could not find next stage in ps stage"))?
            + start;

        // find end of base64 encoded string
        let end = sample_str[start..]
            .find("'")
            .ok_or(anyhow!("Could not find next stage in ps stage"))?
            + start;

        let mut python_base64 = sample_str[start..end].as_bytes().to_vec();

        // account for multiple times of encoding
        let times_encoded = sample_str.matches("base64.b64decode(").count();
        for _ in 0..times_encoded {
            python_base64 = BASE64_DECODER.decode(&python_base64)?;
        }

        let python_node = self.carnavalheist_create_python_node(&python_base64)?;
        self.upsert_edge::<CarnavalheistPs, CarnavalheistPython, CarnavalheistHasPython>(
            &ps_node,
            &python_node,
        )?;

        Ok(ps_node)
    }

    fn carnavalheist_create_python_node(
        &self,
        sample_data: &[u8],
    ) -> Result<Document<CarnavalheistPython>> {
        let sha256sum = digest(sample_data);

        let python_node_data = CarnavalheistPython {
            sha256sum: sha256sum.clone(),
        };

        let UpsertResult {
            document: python_node,
            created: _,
        } = self.upsert_node::<CarnavalheistPython>(python_node_data, "sha256sum", &sha256sum)?;

        Ok(python_node)
    }
}

enum SampleType {
    BatchE,
    BatchCommandNormal,
    BatchCommandConcat,
    Ps,
    Python,
}

fn extract_from_batch_e(sample_str: &str) -> Result<Vec<u8>> {
    let tmp = "powershell -WindowStyle Hidden -e";
    let start = sample_str
        .find(tmp)
        .ok_or(anyhow!("Could not find next stage in batch stage"))?
        + tmp.len()
        + 1;

    let end = sample_str[start..]
        .find(char::is_whitespace)
        .ok_or(anyhow!("Could not find next stage in batch stage"))?
        + start;

    let ps_base64_encoded = sample_str[start..end].as_bytes();
    let ps_base64_decoded = BASE64_DECODER.decode(ps_base64_encoded)?;

    Ok(ps_base64_decoded)
}

fn extract_from_batch_command_normal(sample_str: &str) -> Result<Vec<u8>> {
    let tmp = "powershell -WindowStyle Hidden -Command \"& {";
    let start = sample_str
        .find(tmp)
        .ok_or(anyhow!("Could not find next stage in batch stage"))?
        + tmp.len()
        + 1;

    let mut pos = 1;
    let mut end = start;

    // // indicates that obfuscated_string is not ascii, because char boundary was crossed
    let mut failed = false;
    while pos != 0 && end < sample_str.len() {
        // check is char boundary gets crossed
        if !(sample_str.is_char_boundary(end) && sample_str.is_char_boundary(end + 1)) {
            failed = true;
            break;
        }

        if &sample_str[end..end + 1] == "{" {
            pos += 1;
        }
        if &sample_str[end..end + 1] == "}" {
            pos -= 1;
        }
        end += 1;
    }

    if failed {
        return Err(anyhow!("Could not find next stage in batch stage"));
    }

    Ok(sample_str[start..end - 1].as_bytes().to_vec())
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
