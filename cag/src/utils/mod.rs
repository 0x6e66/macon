pub mod config;

use arangors::{
    Connection, Document,
    client::reqwest::ReqwestClient,
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

use crate::prelude::*;

use config::Config;

type Database = arangors::Database<ReqwestClient>;
type Collection = arangors::Collection<ReqwestClient>;

pub fn establish_database_connection(config: &Config) -> Result<Connection> {
    match Connection::establish_basic_auth(&config.url, &config.user, &config.password) {
        Ok(connection) => Ok(connection),
        Err(e) => Err(Error::ArangoClientError(e)),
    }
}

pub fn ensure_index<CollType>(db: &Database, fields: Vec<String>) -> Result<Index>
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
) -> Result<Collection>
where
    CollType: DeserializeOwned + Serialize + JsonSchema,
{
    let collection_name = get_name::<CollType>();

    if let Ok(collection) = db.collection(&collection_name) {
        return Ok(collection);
    }

    // let mut root_schema = serde_json::to_value(schema_for!(CollType))?;

    // remove the keys `_key`, `_from`, `_to` and `_id` from schema because creation of edges does not work otherwise
    // if collection_type == CollectionType::Edge {
    //     let tmp = serde_json::to_value(&root_schema)?;
    //     let mut obj = tmp
    //         .as_object()
    //         .ok_or(Error::Generic(format!(
    //             "Could not transform CollType '{}' to serde object",
    //             get_name::<CollType>()
    //         )))?
    //         .clone();
    //
    //     let properties = obj.get_mut("properties").unwrap().as_object_mut().unwrap();
    //     properties.remove("_key");
    //     properties.remove("_from");
    //     properties.remove("_to");
    //     properties.remove("_id");
    //     let properties = serde_json::to_value(properties)?;
    //
    //     let required = obj.get("required").unwrap().as_array().unwrap();
    //     let mut new_required: Vec<Value> = vec![];
    //     for val in required {
    //         if let Some(s) = val.as_str() {
    //             if !["_key", "_from", "_to", "_id"].contains(&s) {
    //                 new_required.push(Value::String(s.to_owned()));
    //             }
    //         }
    //     }
    //     let required = serde_json::to_value(new_required)?;
    //
    //     obj.insert("properties".to_owned(), properties);
    //     obj.insert("required".to_owned(), required);
    //
    //     root_schema = serde_json::to_value(obj)?;
    // }

    // let schema = json!({
    //     "rule": root_schema,
    //     "level": "strict",
    //     "message": format!("The document you supplied does not fit the schema that this collection is restricted to. Schema: '{}'", serde_json::to_string(&root_schema)?)
    // });

    // let create_options = CreateOptions::builder()
    //     .name(&collection_name)
    //     .schema(schema)
    //     .collection_type(collection_type)
    //     .build();
    // let create_parameters = CreateParameters::builder().build();
    //
    // let collection = db.create_collection_with_options(create_options, create_parameters)?;

    let create_options = CreateOptions::builder()
        .name(&collection_name)
        .collection_type(collection_type)
        .build();
    let create_parameters = CreateParameters::builder().build();

    let collection = db.create_collection_with_options(create_options, create_parameters)?;

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
        .unwrap()
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
