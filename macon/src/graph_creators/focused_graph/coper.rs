use std::{
    fs::read_dir,
    io::{Cursor, Read},
    path::PathBuf,
};

use anyhow::Result;
use arangors::{client::reqwest::ReqwestClient, collection::CollectionType, Document};
use cag::{
    base_creator::{GraphCreatorBase, UpsertResult},
    utils::ensure_collection,
};
use sha256::digest;
use zip::ZipArchive;

use crate::graph_creators::focused_graph::{
    nodes::{
        coper::{Coper, CoperAPK, CoperELF, CoperELFArchitecture, CoperHasAPK, CoperHasELF},
        FocusedCorpus, HasMalwareFamily,
    },
    FocusedGraph,
};

type Database = arangors::Database<ReqwestClient>;

impl FocusedGraph {
    pub fn coper_main(
        &self,
        mut path: PathBuf,
        corpus_node: &Document<FocusedCorpus>,
        db: &Database,
    ) -> Result<()> {
        let sha_index_fields = Some(vec!["sha256sum".into()]);

        // Nodes
        ensure_collection::<Coper>(db, CollectionType::Document, None)?;
        ensure_collection::<CoperAPK>(db, CollectionType::Document, sha_index_fields.clone())?;
        ensure_collection::<CoperELF>(db, CollectionType::Document, sha_index_fields)?;

        // Edges
        ensure_collection::<CoperHasAPK>(db, CollectionType::Edge, None)?;
        ensure_collection::<CoperHasELF>(db, CollectionType::Edge, None)?;

        let main_node = self.coper_create_main_node(corpus_node, db)?;

        path.push("direct");
        let rd = read_dir(&path)?;

        // Iterate over Coper samples in "direct" directory
        for entry in tqdm::tqdm(rd.filter_map(|e| e.ok())) {
            let mut file = std::fs::File::open(entry.path())?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;

            // handle sample
            self.coper_handle_sample(&buf, &main_node, db)?;
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
            created,
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
        // check if sample is APK or ELF
        // Planned workflow:
        //  1. Determine if sample is APK or ELF
        //  2. If APK
        //      2.1 upsert APK node
        //      2.2 extract ELFs
        //      2.3 if ELFs in DB
        //          - check if APK is ghost node
        //          - if GN remove GN
        //      2.4 upsert ELF nodes
        //      2.5 create edges
        //
        //  3. If ELF
        //      3.1 if ELF is in DB
        //          - continue
        //      3.2 if ELF not in DB
        //          - create ghost APK node
        //          - upsert ELF
        //          - create edge

        // determine if sample is APK or ELF

        // sample is APK
        let apk_node = self.coper_create_apk_node(sample_data, db)?;
        self.upsert_edge::<Coper, CoperAPK, CoperHasAPK>(main_node, &apk_node, db)?;

        // TODO:sample is ELF

        Ok(())
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

        // create and upsert elf nodes and edges
        if let Ok(res) = apk_analysis_result {
            for (sha256sum, architecture) in res.elfs {
                let elf_data = CoperELF {
                    architecture,
                    sha256sum: sha256sum.clone(),
                };

                // TODO: if ELF is already in DB, handle potential ghost node

                let UpsertResult {
                    document: elf_node,
                    created,
                } =
                    self.upsert_node::<CoperELF>(elf_data, "sha256sum".to_string(), sha256sum, db)?;
                self.upsert_edge::<CoperAPK, CoperELF, CoperHasELF>(&apk_node, &elf_node, db)?;
            }
        }

        Ok(apk_node)
    }
}

struct APKAnalysisResult {
    is_cut: bool,
    elfs: Vec<(String, CoperELFArchitecture)>,
}

fn analyse_apk(sample_data: &[u8]) -> Result<APKAnalysisResult> {
    let cursor = Cursor::new(sample_data);
    let Ok(mut archive) = ZipArchive::new(cursor) else {
        return Ok(APKAnalysisResult {
            is_cut: true,
            elfs: vec![],
        });
    };

    let mut elfs = vec![];

    let filenames: Vec<String> = archive
        .file_names()
        .filter(|filename| filename.starts_with("lib/"))
        .map(|s| s.to_owned())
        .collect();

    for filename in filenames {
        if let Ok(mut zipfile) = archive.by_name(&filename) {
            // read data of elf to buffer
            let mut buff = Vec::with_capacity(zipfile.size() as usize);
            if zipfile.read_to_end(&mut buff).is_err() {
                continue;
            }

            let architecture: CoperELFArchitecture;

            if filename.starts_with("lib/armeabi-v7a/") {
                architecture = CoperELFArchitecture::ArmEabiV7a;
            } else if filename.starts_with("lib/arm64-v8a/") {
                architecture = CoperELFArchitecture::Arm64V8a;
            } else if filename.starts_with("lib/x86_64/") {
                architecture = CoperELFArchitecture::X86_64;
            } else if filename.starts_with("lib/x86/") {
                architecture = CoperELFArchitecture::X86;
            } else {
                continue;
            }

            let digest = digest(&buff);
            elfs.push((digest, architecture));
        }
    }

    Ok(APKAnalysisResult {
        is_cut: false,
        elfs,
    })
}
