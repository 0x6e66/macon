pub mod nodes;

use std::{
    io::{Cursor, Read},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Result, anyhow};
use arangors::{Document, collection::CollectionType};
use base64::{
    Engine, alphabet,
    engine::{GeneralPurpose, general_purpose::PAD},
};
use flate2::bufread::GzDecoder;
use indicatif::ParallelProgressIterator;
use macon_cag::{
    base_creator::{GraphCreatorBase, UpsertResult},
    utils::ensure_collection,
};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use sha256::digest;

use crate::graph_creators::focused_graph::{
    FocusedCorpus, FocusedGraph, HasMalwareFamily,
    mintsloader::nodes::{
        Mintsloader, MintsloaderHasPsDgaIex, MintsloaderHasPsStartProcess,
        MintsloaderHasPsXorBase64, MintsloaderPsDgaIex, MintsloaderPsStartProcess,
        MintsloaderPsXorBase64,
    },
};

impl FocusedGraph {
    pub fn mintsloader_main(
        &self,
        files: &[PathBuf],
        corpus_node: &Document<FocusedCorpus>,
    ) -> Result<()> {
        let idxs = Some(vec!["sha256sum".into()]);
        let db = self.get_db();

        // Nodes
        ensure_collection::<Mintsloader>(db, CollectionType::Document, None)?;
        ensure_collection::<MintsloaderPsXorBase64>(db, CollectionType::Document, idxs.clone())?;
        ensure_collection::<MintsloaderPsDgaIex>(db, CollectionType::Document, idxs.clone())?;
        ensure_collection::<MintsloaderHasPsStartProcess>(db, CollectionType::Document, idxs)?;

        // Edges
        ensure_collection::<MintsloaderHasPsXorBase64>(db, CollectionType::Edge, None)?;
        ensure_collection::<MintsloaderHasPsDgaIex>(db, CollectionType::Edge, None)?;
        ensure_collection::<MintsloaderHasPsStartProcess>(db, CollectionType::Edge, None)?;

        let main_node = self.mintsloader_create_main_node(corpus_node)?;

        let errors: Arc<Mutex<Vec<anyhow::Error>>> = Arc::new(Mutex::new(Vec::new()));

        files
            .par_iter()
            .progress()
            .for_each(|entry| match std::fs::File::open(entry) {
                Ok(mut file) => {
                    let mut buf = Vec::new();
                    match file.read_to_end(&mut buf) {
                        Ok(_) => {
                            match self.mintsloader_handle_sample(
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

    fn mintsloader_create_main_node(
        &self,
        corpus_node: &Document<FocusedCorpus>,
    ) -> Result<Document<Mintsloader>> {
        let mintsloader = Mintsloader {
            name: "Mintsloader".to_string(),
            display_name: "Mintsloader".to_string(),
        };

        let UpsertResult {
            document: main_node,
            created: _,
        } = self.upsert_node::<Mintsloader>(mintsloader, "name", "Mintsloader")?;

        self.upsert_edge::<FocusedCorpus, Mintsloader, HasMalwareFamily>(corpus_node, &main_node)?;

        Ok(main_node)
    }

    fn mintsloader_handle_sample(
        &self,
        sample_filename: &str,
        sample_data: &[u8],
        main_node: &Document<Mintsloader>,
    ) -> Result<()> {
        match detect_sample_type(sample_data) {
            Some(SampleType::PS_Xor_B64(xor_key, base64)) => {
                let ps_xor_node =
                    self.mintsloader_create_ps_xor_node(sample_data, &xor_key, &base64)?;
                self.upsert_edge::<Mintsloader, MintsloaderPsXorBase64, MintsloaderHasPsXorBase64>(
                    main_node,
                    &ps_xor_node,
                )?;
            }
            Some(SampleType::PS_DGA_iex) => {
                let _ = self.mintsloader_create_ps_dga_iex_node(sample_data)?;
            }
            Some(SampleType::PS_Start_Process) => {
                let _ = self.mintsloader_create_ps_start_process_node(sample_data)?;
            }
            None => {
                return Err(anyhow!(
                    "Sample type of the sample {sample_filename} could not be detected."
                ));
            }
        }

        Ok(())
    }

    fn mintsloader_create_ps_xor_node(
        &self,
        sample_data: &[u8],
        xor_key: &str,
        base64: &str,
    ) -> Result<Document<MintsloaderPsXorBase64>> {
        let sha256sum = digest(sample_data);

        let ps_xor_data = MintsloaderPsXorBase64 {
            sha256sum: sha256sum.clone(),
        };

        let UpsertResult {
            document: ps_xor_node,
            created,
        } = self.upsert_node::<MintsloaderPsXorBase64>(ps_xor_data, "sha256sum", &sha256sum)?;

        // Sample is already in DB => no need for further analysis
        if !created {
            return Ok(ps_xor_node);
        }

        let next_stage = decode_base64_with_xor_key(xor_key, base64)?;

        if next_stage.contains("$executioncontext;") {
            let ps_dga_iex_node = self.mintsloader_create_ps_dga_iex_node(next_stage.as_bytes())?;
            self.upsert_edge::<MintsloaderPsXorBase64, MintsloaderPsDgaIex, MintsloaderHasPsDgaIex>(&ps_xor_node, &ps_dga_iex_node)?;
        } else if next_stage.contains("start-process powershell") {
            let ps_start_process_node =
                self.mintsloader_create_ps_start_process_node(next_stage.as_bytes())?;
            self.upsert_edge::<MintsloaderPsXorBase64, MintsloaderPsStartProcess, MintsloaderHasPsStartProcess>(&ps_xor_node, &ps_start_process_node)?;
        }

        Ok(ps_xor_node)
    }

    fn mintsloader_create_ps_dga_iex_node(
        &self,
        sample_data: &[u8],
    ) -> Result<Document<MintsloaderPsDgaIex>> {
        let sha256sum = digest(sample_data);

        let ps_dga_iex_data = MintsloaderPsDgaIex {
            sha256sum: sha256sum.clone(),
        };

        let UpsertResult {
            document: ps_dga_iex_node,
            created: _,
        } = self.upsert_node::<MintsloaderPsDgaIex>(ps_dga_iex_data, "sha256sum", &sha256sum)?;

        Ok(ps_dga_iex_node)
    }

    fn mintsloader_create_ps_start_process_node(
        &self,
        sample_data: &[u8],
    ) -> Result<Document<MintsloaderPsStartProcess>> {
        let sha256sum = digest(sample_data);

        let ps_start_process_data = MintsloaderPsStartProcess {
            sha256sum: sha256sum.clone(),
        };

        let UpsertResult {
            document: ps_start_process_node,
            created: _,
        } = self.upsert_node::<MintsloaderPsStartProcess>(
            ps_start_process_data,
            "sha256sum",
            &sha256sum,
        )?;

        Ok(ps_start_process_node)
    }
}

fn extract_key_and_base64_from_ps_xor_base64(sample_str: &str) -> Result<(&str, &str)> {
    let s = r#"\("(?<key>[A-z0-9]{12})"\)"#;
    let re = Regex::new(s).unwrap();
    let xor_key = re
        .captures(sample_str)
        .map(|c| c.extract::<1>())
        .map(|(_, [c])| c);

    let s = r#""(?<base64>[A-z][A-z0-9+/=]{100,})""#;
    let re = Regex::new(s).unwrap();
    let base64 = re
        .captures(sample_str)
        .map(|c| c.extract::<1>())
        .map(|(_, [c])| c);

    let res = xor_key.zip(base64).ok_or(anyhow!(
        "Could not extract xor key and base64 blob from sample"
    ))?;

    Ok(res)
}

fn decode_base64_with_xor_key(xor_key: &str, base64: &str) -> Result<String> {
    let base64_decoder = GeneralPurpose::new(&alphabet::STANDARD, PAD);
    let mut res = base64_decoder.decode(base64)?;

    let xor_key = xor_key.as_bytes();
    for i in 0..res.len() {
        res[i] ^= xor_key[i % xor_key.len()];
    }

    let cursor = Cursor::new(res);
    let mut gzip_decoder = GzDecoder::new(cursor);
    let mut s = String::new();

    gzip_decoder.read_to_string(&mut s)?;

    Ok(s)
}

#[allow(non_camel_case_types)]
enum SampleType {
    /// Sample is a powershell script.
    /// It has a base64 encoded blob, which is
    ///  1. base64-decoded and
    ///  2. "decrypted" with a static xor key and
    ///  3. gzip-decoded
    ///
    /// Produces [`SampleType::PS_DGA_iex`] xor [`SampleType::PS_Start_Process`]
    ///
    /// This enum contains the xor key and the base64 blob of the sample like this:
    /// `SampleType::PS_Xor_B64(xor_key, base64)`
    PS_Xor_B64(String, String),

    /// Sample is a powershell script.
    /// It runs a dga, contacts the generated url and pipes the response in iex
    PS_DGA_iex,

    /// Sample is a powershell script.
    /// It starts a new powershell process with a new alias "rzs"
    PS_Start_Process,
}

fn detect_sample_type(sample_data: &[u8]) -> Option<SampleType> {
    // count number of null bytes in odd positions
    let count = sample_data
        .iter()
        .enumerate()
        .filter(|(i, e)| *i % 2 == 1 && **e == 0)
        .count();
    // if more than 98% percent of odd bytes are null it is probably utf16
    let is_utf16 = (2 * count) as f32 / sample_data.len() as f32 > 0.98;

    // get sample data as string based on utf-8 oder utf-16
    let sample_str = match is_utf16 {
        false => String::from_utf8_lossy(sample_data).to_string(),
        true => {
            let tmp: Vec<u16> = (0..sample_data.len() / 2)
                .map(|i| u16::from_le_bytes([sample_data[2 * i], sample_data[2 * i + 1]]))
                .collect();

            String::from_utf16_lossy(&tmp)
        }
    };

    if let Ok((xor_key, base64)) = extract_key_and_base64_from_ps_xor_base64(&sample_str) {
        return Some(SampleType::PS_Xor_B64(
            xor_key.to_owned(),
            base64.to_owned(),
        ));
    } else if sample_str
        .find("$executioncontext;")
        .and(
            sample_str
                .find("$global:block=(curl")
                .or(sample_str.find("iex(curl")),
        )
        .is_some()
    {
        return Some(SampleType::PS_DGA_iex);
    } else if sample_str.contains("start-process powershell") {
        return Some(SampleType::PS_Start_Process);
    }

    None
}
