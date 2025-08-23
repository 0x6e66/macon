use std::{fs::read_dir, io::Read, path::PathBuf};

use anyhow::Result;
use arangors::{Document, client::reqwest::ReqwestClient};
use cag::base_creator::GraphCreatorBase;
use sha256::digest;

use crate::graph_creators::focused_graph::{
    FocusedGraph,
    nodes::{
        FocusedCorpus, HasMalwareFamily,
        coper::{Coper, CoperAPK, CoperHasAPK},
    },
};

type Database = arangors::Database<ReqwestClient>;

impl FocusedGraph {
    pub fn coper_main(
        &self,
        mut path: PathBuf,
        corpus_node: &Document<FocusedCorpus>,
        db: &Database,
    ) -> Result<()> {
        let main_node = self.coper_create_main_node(corpus_node, db)?;

        path.push("direct");
        let rd = read_dir(&path)?;

        for entry in tqdm::tqdm(rd.filter_map(|e| e.ok())) {
            let mut file = std::fs::File::open(entry.path())?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;

            let file_name = entry.file_name().into_string().unwrap();

            self.coper_handle_sample(&buf, file_name, &main_node, db)?;
        }

        Ok(())
    }

    fn coper_create_main_node(
        &self,
        corpus_node: &Document<FocusedCorpus>,
        db: &Database,
    ) -> Result<Document<Coper>> {
        let coper = Coper {
            name: "Coper".to_string(),
            display_name: "Coper".to_string(),
        };

        let main_node: Document<Coper> =
            self.upsert_node::<Coper>(coper, "name".to_string(), "Coper".to_string(), db)?;

        self.upsert_edge::<FocusedCorpus, Coper, HasMalwareFamily>(corpus_node, &main_node, db)?;

        Ok(main_node)
    }

    fn coper_handle_sample(
        &self,
        sample_data: &[u8],
        file_name: String,
        main_node: &Document<Coper>,
        db: &Database,
    ) -> Result<()> {
        let apk_node = self.coper_create_apk_node(sample_data, file_name, db)?;

        self.upsert_edge::<Coper, CoperAPK, CoperHasAPK>(main_node, &apk_node, db)
            .unwrap();

        Ok(())
    }

    fn coper_create_apk_node(
        &self,
        sample_data: &[u8],
        file_name: String,
        db: &Database,
    ) -> Result<Document<CoperAPK>> {
        let sha256sum = digest(sample_data);

        // TODO: actually check for native libs and EOCD

        let apk_data = CoperAPK {
            original_filename: Some(file_name.clone()),
            display_name: file_name,
            sha256sum: sha256sum.clone(),
            has_native_lib: false,
            is_cut: false,
        };

        let apk_node: Document<CoperAPK> =
            self.upsert_node::<CoperAPK>(apk_data, "sha256sum".to_string(), sha256sum, db)?;

        // TODO: extract ELF and create nodes

        Ok(apk_node)
    }
}
