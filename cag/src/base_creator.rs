use std::fmt::Debug;

use crate::{
    prelude::*,
    utils::{config::Config, ensure_index, get_name, handle_document_response},
};

use arangors::{
    client::reqwest::ReqwestClient,
    document::options::{InsertOptions, UpdateOptions},
    graph::EdgeDefinition,
    AqlQuery, Document,
};
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Serialize};

type Database = arangors::Database<ReqwestClient>;

pub struct UpsertResult<CollType> {
    pub document: Document<CollType>,
    pub created: bool,
}

pub trait GraphCreatorBase {
    fn init(
        &self,
        config: Config,
        data_path: String,
        edge_definitions: Vec<EdgeDefinition>,
    ) -> Result<()>;

    fn create_vertex<CollType>(&self, data: CollType, db: &Database) -> Result<Document<CollType>>
    where
        CollType: DeserializeOwned + Serialize + Clone + JsonSchema,
    {
        let collection_name = get_name::<CollType>();
        let coll = db.collection(&collection_name)?;

        let doc_res = coll.create_document::<CollType>(
            data,
            InsertOptions::builder()
                .return_new(true)
                .overwrite(true)
                .build(),
        )?;

        let doc = handle_document_response(doc_res)?;
        Ok(doc)
    }

    fn upsert_node<CollType>(
        &self,
        data: CollType,
        alt_key: String,
        alt_val: String,
        db: &Database,
    ) -> Result<UpsertResult<CollType>>
    where
        CollType: DeserializeOwned + Serialize + Clone + JsonSchema + Debug,
    {
        // check if document is already in DB
        match self.get_document::<CollType>(alt_key, alt_val, db) {
            Err(e) => {
                if matches!(e, Error::DocumentNotFound(_)) {
                    // create new document in collection `CollType`
                    let doc: Document<CollType> = self.create_vertex::<CollType>(data, db)?;

                    // return new document
                    Ok(UpsertResult {
                        document: doc,
                        created: true,
                    })
                } else {
                    Err(e)
                }
            }
            // document was found in DB, return old document
            Ok(doc) => Ok(UpsertResult {
                document: doc,
                created: false,
            }),
        }
    }

    /// Searches for a document in collection `CollType` with the key, value combination alt_key,
    /// alt_val
    fn get_document<CollType>(
        &self,
        alt_key: String,
        alt_val: String,
        db: &Database,
    ) -> Result<Document<CollType>>
    where
        CollType: DeserializeOwned + JsonSchema,
    {
        ensure_index::<CollType>(db, vec![alt_key.clone()])?;

        let collection_name = get_name::<CollType>();

        let aql = AqlQuery::builder()
            .query("for d in @@collection_name filter d.@alt_key == @alt_val limit 1 return d")
            .bind_var("@collection_name", collection_name)
            .bind_var("alt_key", alt_key.clone())
            .bind_var("alt_val", alt_val.clone())
            .build();

        let mut result: Vec<Document<CollType>> = db.aql_query(aql)?;

        match result.pop() {
            Some(doc) => Ok(doc),
            None => Err(Error::DocumentNotFound(format!(
                "Document with alt_key: '{alt_key}' and alt_val '{alt_val}' was not found"
            ))),
        }
    }

    fn upsert_edge<FromType, ToType, EdgeType>(
        &self,
        from_doc: &Document<FromType>,
        to_doc: &Document<ToType>,
        db: &Database,
    ) -> Result<Document<EdgeType>>
    where
        FromType: DeserializeOwned + Serialize + Clone,
        ToType: DeserializeOwned + Serialize + Clone,
        EdgeType:
            DeserializeOwned + Serialize + Clone + JsonSchema + Debug + EdgeAttributes + Default,
    {
        let collection_name = get_name::<EdgeType>();
        let coll = db.collection(&collection_name)?;

        let mut edge = EdgeType::default();

        edge.apply_edge_attributes(from_doc.header._id.clone(), to_doc.header._id.clone());
        let edge_key = edge.get_key();

        let node = coll.document::<EdgeType>(&edge_key);

        match node {
            Err(_) => {
                let doc: Document<EdgeType> = self.create_vertex::<EdgeType>(edge.clone(), db)?;
                Ok(doc)
            }
            Ok(doc) => {
                let key = doc.header._key.as_str();
                let doc = doc.document;

                let update_ops = UpdateOptions::builder().return_new(true).build();
                let response = coll.update_document(key, doc, update_ops);

                match response {
                    Err(e) => Err(e.into()),
                    Ok(doc_res) => {
                        let new_doc = handle_document_response::<EdgeType>(doc_res)?;
                        Ok(new_doc)
                    }
                }
            }
        }
    }
}

pub trait EdgeAttributes {
    fn apply_edge_attributes(&mut self, from_id: String, to_id: String);
    fn get_key(&self) -> String;
}
