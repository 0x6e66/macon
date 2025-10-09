pub mod config;

use arangors::{
    Connection, Document,
    collection::{
        CollectionType,
        options::{CreateOptions, CreateParameters},
    },
    document::{Header, response::DocumentResponse},
    graph::{EdgeDefinition, Graph},
    index::{Index, IndexSettings},
};
use schemars::JsonSchema;
use serde::{Serialize, de::DeserializeOwned};

use crate::{prelude::*, utils::config::Config};

pub fn establish_database_connection(config: &Config) -> Result<Connection> {
    match Connection::establish_basic_auth(&config.url, &config.user, &config.password) {
        Ok(connection) => Ok(connection),
        Err(e) => Err(Error::ArangoClientError(e)),
    }
}

fn ensure_index<CollType>(db: &Database, fields: Vec<String>) -> Result<Index>
where
    CollType: JsonSchema,
{
    let collection_name = get_name::<CollType>();

    let index = Index::builder()
        .name(format!("{}--{}", collection_name, fields.join("-")))
        .fields(fields)
        .settings(IndexSettings::Hash {
            unique: true,
            sparse: true,
            deduplicate: false,
        })
        .build();

    let index = db.create_index(&collection_name, &index)?;
    Ok(index)
}

pub fn ensure_database(conn: &Connection, db_name: &str) -> Result<Database> {
    if let Ok(db) = conn.db(db_name) {
        return Ok(db);
    };

    let db = conn.create_database(db_name)?;
    Ok(db)
}

pub fn ensure_collection<CollType>(
    db: &Database,
    collection_type: CollectionType,
    index_fields: Option<Vec<String>>,
) -> Result<Collection>
where
    CollType: DeserializeOwned + Serialize + JsonSchema,
{
    let collection_name = get_name::<CollType>();

    if let Ok(collection) = db.collection(&collection_name) {
        return Ok(collection);
    }

    let create_options = CreateOptions::builder()
        .name(&collection_name)
        .collection_type(collection_type)
        .build();
    let create_parameters = CreateParameters::builder().build();

    let collection = db.create_collection_with_options(create_options, create_parameters)?;

    if let Some(fields) = index_fields {
        ensure_index::<CollType>(db, fields)?;
    }

    Ok(collection)
}

pub fn ensure_graph(
    db: &Database,
    graph_name: &str,
    edge_definitions: Vec<EdgeDefinition>,
) -> Result<Graph> {
    if let Ok(graph) = db.graph(graph_name) {
        return Ok(graph);
    };

    let graph = Graph::builder()
        .name(graph_name.to_string())
        .edge_definitions(edge_definitions)
        .build();

    let graph = db.create_graph(graph, true)?;
    Ok(graph)
}

pub fn handle_document_response<T>(document_response: DocumentResponse<T>) -> Result<Document<T>>
where
    T: Clone,
{
    let header = match document_response.header() {
        None => panic!(),
        Some(h) => h,
    };
    let document = match document_response.new_doc() {
        None => panic!(),
        Some(d) => d,
    };
    let new_doc: Document<T> = Document {
        header: Header {
            _id: header._id.clone(),
            _key: header._key.clone(),
            _rev: header._rev.clone(),
        },
        document: document.clone(),
    };
    Ok(new_doc)
}

pub fn get_name<T>() -> String {
    std::any::type_name::<T>()
        .split("::")
        .last()
        .unwrap_or_else(|| {
            panic!(
                "Getting the name of Type '{}' failed",
                std::any::type_name::<T>()
            )
        })
        .to_owned()
}

#[macro_export]
macro_rules! impl_edge_attributes {
    ($edge:ty) => {
        impl $crate::base_creator::EdgeAttributes for $edge {
            fn apply_edge_attributes(&mut self, from_id: String, to_id: String) {
                self._from = from_id.clone();
                self._to = to_id.clone();

                let from_id = from_id.replace('/', "-");
                let to_id = to_id.replace('/', "-");
                self._key = format!("{from_id}--{to_id}");
            }

            fn get_key(&self) -> String {
                self._key.clone()
            }
        }
    };
}
