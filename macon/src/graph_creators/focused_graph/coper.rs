use std::{
    io::{Cursor, Read},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Result, anyhow};
use arangors::{Document, collection::CollectionType};
use cag::{
    base_creator::{GraphCreatorBase, UpsertResult},
    prelude::Database,
    utils::ensure_collection,
};
use indicatif::ParallelProgressIterator;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sha256::digest;
use zip::ZipArchive;

use crate::graph_creators::focused_graph::{
    FocusedGraph,
    nodes::{
        FocusedCorpus, HasMalwareFamily,
        coper::{
            Coper, CoperAPK, CoperDEX, CoperELF, CoperELFArchitecture, CoperHasAPK, CoperHasDEX,
            CoperHasELF,
        },
    },
};

impl FocusedGraph {
    pub fn coper_main(
        &self,
        files: &[PathBuf],
        corpus_node: &Document<FocusedCorpus>,
        db: &Database,
    ) -> Result<()> {
        let sha_index_fields = Some(vec!["sha256sum".into()]);

        // create collections for all nodes
        ensure_collection::<Coper>(db, CollectionType::Document, None)?;
        ensure_collection::<CoperAPK>(db, CollectionType::Document, sha_index_fields.clone())?;
        ensure_collection::<CoperELF>(db, CollectionType::Document, sha_index_fields.clone())?;
        ensure_collection::<CoperDEX>(db, CollectionType::Document, sha_index_fields)?;

        // create collections for all edges
        ensure_collection::<CoperHasAPK>(db, CollectionType::Edge, None)?;
        ensure_collection::<CoperHasELF>(db, CollectionType::Edge, None)?;
        ensure_collection::<CoperHasDEX>(db, CollectionType::Edge, None)?;

        let main_node = self.coper_create_main_node(corpus_node, db)?;

        let errors: Arc<Mutex<Vec<anyhow::Error>>> = Arc::new(Mutex::new(Vec::new()));

        // handle each sample
        files
            .par_iter()
            .progress()
            .for_each(|entry| match std::fs::File::open(entry) {
                Ok(mut file) => {
                    let mut buf = Vec::new();
                    match file.read_to_end(&mut buf) {
                        Ok(_) => match self.coper_handle_sample(&buf, &main_node, db) {
                            Ok(_) => (),
                            Err(e) => errors.lock().unwrap().push(e),
                        },
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

    /// Creates node in "Coper" collection and creates an edge to the corpus node
    fn coper_create_main_node(
        &self,
        corpus_node: &Document<FocusedCorpus>,
        db: &Database,
    ) -> Result<Document<Coper>> {
        let coper = Coper {
            name: "Coper".to_string(),
            display_name: "Coper".to_string(),
        };

        let UpsertResult {
            document: main_node,
            created: _,
        } = self.upsert_node::<Coper>(coper, "name".to_string(), "Coper".to_string(), db)?;

        self.upsert_edge::<FocusedCorpus, Coper, HasMalwareFamily>(corpus_node, &main_node, db)?;

        Ok(main_node)
    }

    fn coper_handle_sample(
        &self,
        sample_data: &[u8],
        main_node: &Document<Coper>,
        db: &Database,
    ) -> Result<()> {
        // TODO: Implement other sample types
        match detect_sample_type(sample_data) {
            Some(CoperSampleType::APK) => {
                let apk_node = self.coper_create_apk_node(sample_data, db)?;
                self.upsert_edge::<Coper, CoperAPK, CoperHasAPK>(main_node, &apk_node, db)?;
            }
            Some(CoperSampleType::ELF) => {
                let _ = self.coper_create_elf_node(sample_data, None, db)?;
            }
            Some(CoperSampleType::DEX) => {
                let _ = self.coper_create_dex_node(sample_data, db)?;
            }
            Some(CoperSampleType::JAR) => {
                todo!();
            }
            None => {
                let digest = digest(sample_data);

                return Err(anyhow!(
                    "Sample type of the sample with the SHA-256 hash '{digest}' could not be detected."
                ));
            }
        }

        Ok(())
    }

    fn coper_create_elf_node(
        &self,
        sample_data: &[u8],
        mut architecture: Option<CoperELFArchitecture>,
        db: &Database,
    ) -> Result<Document<CoperELF>> {
        let sha256sum = digest(sample_data);

        // try to determine architecture (eg. when elf was not extracted from apk)
        if architecture.is_none() {
            architecture = detect_elf_architecture(sample_data);
        }

        let elf_data = CoperELF {
            sha256sum: sha256sum.clone(),
            architecture,
        };

        let UpsertResult {
            document: elf_node,
            created: _,
        } = self.upsert_node::<CoperELF>(elf_data, "sha256sum".to_string(), sha256sum, db)?;

        Ok(elf_node)
    }

    fn coper_create_apk_node(
        &self,
        sample_data: &[u8],
        db: &Database,
    ) -> Result<Document<CoperAPK>> {
        // extract elfs
        let apk_analysis_result = analyse_apk(sample_data);

        let sha256sum = digest(sample_data);
        let apk_data = CoperAPK {
            sha256sum: sha256sum.clone(),
            is_cut: apk_analysis_result.as_ref().is_ok_and(|res| res.is_cut),
        };

        let UpsertResult {
            document: apk_node,
            created,
        } = self.upsert_node::<CoperAPK>(apk_data, "sha256sum".to_string(), sha256sum, db)?;

        // Sample was not created => sample was already present in DB
        // Can be aborted here
        if !created {
            return Ok(apk_node);
        }

        // create and upsert elf nodes and edges
        if let Ok(res) = apk_analysis_result {
            for (sample_data, architecture) in res.elfs {
                let elf_node = self.coper_create_elf_node(&sample_data, Some(architecture), db)?;
                self.upsert_edge::<CoperAPK, CoperELF, CoperHasELF>(&apk_node, &elf_node, db)?;
            }

            for sample_data in res.dexs {
                let dex_node = self.coper_create_dex_node(&sample_data, db)?;
                self.upsert_edge::<CoperAPK, CoperDEX, CoperHasDEX>(&apk_node, &dex_node, db)?;
            }
        }

        Ok(apk_node)
    }

    fn coper_create_dex_node(
        &self,
        sample_data: &[u8],
        db: &Database,
    ) -> Result<Document<CoperDEX>> {
        let sha256sum = digest(sample_data);
        let dex_data = CoperDEX {
            sha256sum: sha256sum.clone(),
        };

        let UpsertResult {
            document: dex_node,
            created: _,
        } = self.upsert_node::<CoperDEX>(dex_data, "sha256sum".to_string(), sha256sum, db)?;

        Ok(dex_node)
    }
}

fn detect_elf_architecture(sample_data: &[u8]) -> Option<CoperELFArchitecture> {
    let endianness = sample_data[5];

    let architecture;

    // Little Endian
    if endianness == 1 {
        architecture = sample_data[18];
    // Big Endian
    } else if endianness == 2 {
        architecture = sample_data[19];
    } else {
        return None;
    }

    match architecture {
        0x03 => Some(CoperELFArchitecture::X86),
        0x28 => Some(CoperELFArchitecture::ArmEabiV7a),
        0x3e => Some(CoperELFArchitecture::X86_64),
        0xb7 => Some(CoperELFArchitecture::Arm64V8a),
        _ => None,
    }
}

#[allow(clippy::upper_case_acronyms)]
enum CoperSampleType {
    APK,
    ELF,
    DEX,
    JAR,
}

fn detect_sample_type(sample_data: &[u8]) -> Option<CoperSampleType> {
    // check magic bytes at start of file

    // APK or JAR
    if sample_data.starts_with(&[0x50, 0x4B]) {
        // TODO: Implement distinction between APK and JAR
        return Some(CoperSampleType::APK);
    }
    // DEX
    else if sample_data.starts_with(&[0x64, 0x65, 0x78, 0x0a]) && sample_data[7] == 0 {
        return Some(CoperSampleType::DEX);
    // ELF
    } else if sample_data.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
        return Some(CoperSampleType::ELF);
    }

    None
}

struct APKAnalysisResult {
    is_cut: bool,
    elfs: Vec<(Vec<u8>, CoperELFArchitecture)>,
    dexs: Vec<Vec<u8>>,
}

fn analyse_apk(sample_data: &[u8]) -> Result<APKAnalysisResult> {
    // open ziparchive
    let cursor = Cursor::new(sample_data);
    let Ok(mut archive) = ZipArchive::new(cursor) else {
        return Ok(APKAnalysisResult {
            is_cut: true,
            elfs: vec![],
            dexs: vec![],
        });
    };

    let mut elfs = vec![];
    let mut dexs = vec![];

    // extract all filenames in the lib/ directory
    let elf_files: Vec<String> = archive
        .file_names()
        .filter(|filename| filename.starts_with("lib/"))
        .map(|s| s.to_owned())
        .collect();

    // extract contents of each elf file and their architecture
    for elf_file in elf_files {
        if let Ok(mut zipfile) = archive.by_name(&elf_file) {
            // read data of elf to buffer
            let mut buff = Vec::with_capacity(zipfile.size() as usize);
            if zipfile.read_to_end(&mut buff).is_err() {
                continue;
            }

            let architecture: CoperELFArchitecture;

            if elf_file.starts_with("lib/armeabi-v7a/") {
                architecture = CoperELFArchitecture::ArmEabiV7a;
            } else if elf_file.starts_with("lib/arm64-v8a/") {
                architecture = CoperELFArchitecture::Arm64V8a;
            } else if elf_file.starts_with("lib/x86_64/") {
                architecture = CoperELFArchitecture::X86_64;
            } else if elf_file.starts_with("lib/x86/") {
                architecture = CoperELFArchitecture::X86;
            } else {
                continue;
            }

            elfs.push((buff, architecture));
        }
    }

    // extract all filenames that end with .dex
    let dex_files: Vec<String> = archive
        .file_names()
        .filter(|filename| filename.ends_with(".dex"))
        .map(|s| s.to_owned())
        .collect();

    // extract all .dex files
    for dex_file in dex_files {
        if let Ok(mut zipfile) = archive.by_name(&dex_file) {
            // read data of dex to buffer
            let mut buff = Vec::with_capacity(zipfile.size() as usize);
            if zipfile.read_to_end(&mut buff).is_err() {
                continue;
            }

            dexs.push(buff);
        }
    }

    Ok(APKAnalysisResult {
        is_cut: false,
        elfs,
        dexs,
    })
}
