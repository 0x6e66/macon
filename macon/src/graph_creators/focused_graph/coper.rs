use std::{
    io::{Cursor, Read},
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
use zip::ZipArchive;

use crate::{
    graph_creators::focused_graph::{
        FocusedGraph,
        nodes::{
            FocusedCorpus, HasMalwareFamily,
            coper::{
                Coper, CoperAPK, CoperDEX, CoperELF, CoperELFArchitecture, CoperHasAPK,
                CoperHasDEX, CoperHasELF, CoperHasInnerAPK,
            },
        },
    },
    utils::extract_from_zip,
};

impl FocusedGraph {
    pub fn coper_main(
        &self,
        files: &[PathBuf],
        corpus_node: &Document<FocusedCorpus>,
    ) -> Result<()> {
        let sha_index_fields = Some(vec!["sha256sum".into()]);

        let db = self.get_db();

        // create collections for all nodes
        ensure_collection::<Coper>(db, CollectionType::Document, None)?;
        ensure_collection::<CoperAPK>(db, CollectionType::Document, sha_index_fields.clone())?;
        ensure_collection::<CoperELF>(db, CollectionType::Document, sha_index_fields.clone())?;
        ensure_collection::<CoperDEX>(db, CollectionType::Document, sha_index_fields)?;

        // create collections for all edges
        ensure_collection::<CoperHasAPK>(db, CollectionType::Edge, None)?;
        ensure_collection::<CoperHasELF>(db, CollectionType::Edge, None)?;
        ensure_collection::<CoperHasDEX>(db, CollectionType::Edge, None)?;

        let main_node = self.coper_create_main_node(corpus_node)?;

        let errors: Arc<Mutex<Vec<anyhow::Error>>> = Arc::new(Mutex::new(Vec::new()));

        // handle each sample
        files
            .par_iter()
            .progress()
            .for_each(|entry| match std::fs::File::open(entry) {
                Ok(mut file) => {
                    let mut buf = Vec::new();
                    match file.read_to_end(&mut buf) {
                        Ok(_) => {
                            match self.coper_handle_sample(&format!("{entry:?}"), &buf, &main_node)
                            {
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

    /// Creates node in "Coper" collection and creates an edge to the corpus node
    fn coper_create_main_node(
        &self,
        corpus_node: &Document<FocusedCorpus>,
    ) -> Result<Document<Coper>> {
        let coper = Coper {
            name: "Coper".to_string(),
            display_name: "Coper".to_string(),
        };

        let UpsertResult {
            document: main_node,
            created: _,
        } = self.upsert_node::<Coper>(coper, "name", "Coper")?;

        self.upsert_edge::<FocusedCorpus, Coper, HasMalwareFamily>(corpus_node, &main_node)?;

        Ok(main_node)
    }

    fn coper_handle_sample(
        &self,
        sample_filename: &str,
        sample_data: &[u8],
        main_node: &Document<Coper>,
    ) -> Result<()> {
        match detect_sample_type(sample_data) {
            Some(CoperSampleType::APK) => {
                let apk_nodes = self.coper_create_apk_node(sample_data)?;
                for apk_node in apk_nodes {
                    self.upsert_edge::<Coper, CoperAPK, CoperHasAPK>(main_node, &apk_node)?;
                }
            }
            Some(CoperSampleType::ELF) => {
                let _ = self.coper_create_elf_node(sample_data, None)?;
            }
            Some(CoperSampleType::DEX) => {
                let _ = self.coper_create_dex_node(sample_data)?;
            }
            None => {
                return Err(anyhow!(
                    "Sample type of the sample {sample_filename} could not be detected."
                ));
            }
        }

        Ok(())
    }

    fn coper_create_elf_node(
        &self,
        sample_data: &[u8],
        mut architecture: Option<CoperELFArchitecture>,
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
        } = self.upsert_node::<CoperELF>(elf_data, "sha256sum", &sha256sum)?;

        Ok(elf_node)
    }

    fn coper_create_apk_node(&self, sample_data: &[u8]) -> Result<Vec<Document<CoperAPK>>> {
        let apk_analysis_result = self.analyse_apk(sample_data);

        let sha256sum = digest(sample_data);
        let apk_data = CoperAPK {
            sha256sum: sha256sum.clone(),
            is_cut: apk_analysis_result.is_cut,
        };

        let UpsertResult {
            document: apk_node,
            created,
        } = self.upsert_node::<CoperAPK>(apk_data, "sha256sum", &sha256sum)?;

        let mut apk_nodes = vec![apk_node];

        // Sample was not created => sample was already present in DB
        // Can be aborted here
        if !created {
            return Ok(apk_nodes);
        }

        // create and upsert elf nodes and edges
        if !apk_analysis_result.is_cut {
            // handle elf files in apk
            for (sample_data, architecture) in apk_analysis_result.elfs {
                let elf_node = self.coper_create_elf_node(&sample_data, Some(architecture))?;
                self.upsert_edge::<CoperAPK, CoperELF, CoperHasELF>(&apk_nodes[0], &elf_node)?;
            }

            // handle dex files in apk
            for sample_data in apk_analysis_result.dexs {
                let dex_node = self.coper_create_dex_node(&sample_data)?;
                self.upsert_edge::<CoperAPK, CoperDEX, CoperHasDEX>(&apk_nodes[0], &dex_node)?;
            }

            // handle inner apks of apk
            for (sample_data, sample_filename) in apk_analysis_result.apks {
                let inner_apk_nodes = self.coper_create_apk_node(&sample_data)?;

                for inner_apk_node in inner_apk_nodes {
                    self.upsert_edge::<CoperAPK, CoperAPK, CoperHasInnerAPK>(
                        &apk_nodes[0],
                        &inner_apk_node,
                    )?;
                    apk_nodes.push(inner_apk_node);
                }
            }
        }

        Ok(apk_nodes)
    }

    fn coper_create_dex_node(&self, sample_data: &[u8]) -> Result<Document<CoperDEX>> {
        let sha256sum = digest(sample_data);
        let dex_data = CoperDEX {
            sha256sum: sha256sum.clone(),
        };

        let UpsertResult {
            document: dex_node,
            created: _,
        } = self.upsert_node::<CoperDEX>(dex_data, "sha256sum", &sha256sum)?;

        Ok(dex_node)
    }

    fn analyse_apk(&self, sample_data: &[u8]) -> APKAnalysisResult {
        // open zip archive
        let cursor = Cursor::new(sample_data);
        let Ok(mut archive) = ZipArchive::new(cursor) else {
            return APKAnalysisResult {
                is_cut: true,
                elfs: vec![],
                dexs: vec![],
                apks: vec![],
            };
        };

        // extract all filenames that end with .apk
        // some samples are wrapped with tanglebot. This tries to get the inner apk(s) and analyse them as well
        let apk_files: Vec<String> = archive
            .file_names()
            .filter(|filename| filename.ends_with(".apk"))
            .map(|s| s.to_owned())
            .collect();
        let apks = extract_inner_apks_from_apk(&mut archive, apk_files);

        // extract all filenames in the lib/ directory
        let elf_files: Vec<String> = archive
            .file_names()
            .filter(|filename| filename.starts_with("lib/"))
            .map(|s| s.to_owned())
            .collect();
        let elfs = extract_elfs_from_apk(&mut archive, elf_files);

        // extract all filenames that end with .dex
        let dex_files: Vec<String> = archive
            .file_names()
            .filter(|filename| filename.ends_with(".dex"))
            .map(|s| s.to_owned())
            .collect();
        let dexs = extract_dexs_from_apk(&mut archive, dex_files);

        APKAnalysisResult {
            is_cut: false,
            elfs,
            dexs,
            apks,
        }
    }
}

fn extract_inner_apks_from_apk(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    apk_files: Vec<String>,
) -> Vec<(Vec<u8>, String)> {
    let mut apks = vec![];

    for apk_filename in apk_files {
        if let Ok(apk_data) = extract_from_zip(archive, &apk_filename, true) {
            // check if file is really a apk file
            if !apk_data.starts_with(&[0x50, 0x4B]) {
                continue;
            }

            apks.push((apk_data, apk_filename));
        }
    }

    apks
}

fn extract_elfs_from_apk(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    elf_files: Vec<String>,
) -> Vec<(Vec<u8>, CoperELFArchitecture)> {
    let mut elfs = vec![];

    for elf_filename in elf_files {
        if let Ok(elf_data) = extract_from_zip(archive, &elf_filename, true) {
            // check if file is really a elf file
            if !elf_data.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
                continue;
            }

            let architecture: CoperELFArchitecture;

            if elf_filename.starts_with("lib/armeabi-v7a/") {
                architecture = CoperELFArchitecture::ArmEabiV7a;
            } else if elf_filename.starts_with("lib/arm64-v8a/") {
                architecture = CoperELFArchitecture::Arm64V8a;
            } else if elf_filename.starts_with("lib/x86_64/") {
                architecture = CoperELFArchitecture::X86_64;
            } else if elf_filename.starts_with("lib/x86/") {
                architecture = CoperELFArchitecture::X86;
            } else {
                continue;
            }

            elfs.push((elf_data, architecture));
        }
    }

    elfs
}

fn extract_dexs_from_apk(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    dex_files: Vec<String>,
) -> Vec<Vec<u8>> {
    let mut dexs = vec![];

    for dex_filename in dex_files {
        if let Ok(dex_data) = extract_from_zip(archive, &dex_filename, true) {
            // check if file is really a .dex file
            if !dex_data.starts_with(&[0x64, 0x65, 0x78, 0x0a]) && dex_data[7] == 0 {
                continue;
            }

            dexs.push(dex_data);
        }
    }

    dexs
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
}

fn detect_sample_type(sample_data: &[u8]) -> Option<CoperSampleType> {
    // check magic bytes at start of file

    // APK
    if sample_data.starts_with(&[0x50, 0x4B]) {
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
    apks: Vec<(Vec<u8>, String)>,
}
