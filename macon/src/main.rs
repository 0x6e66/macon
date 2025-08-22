use anyhow::Result;
use arangors::graph::EdgeDefinition;
use cag::{base_creator::GraphCreatorBase, utils::config::Config};

use crate::graph_creators::focused_graph::{FokusedGraph, nodes::coper::coper_edge_definitions};

mod graph_creators;

fn main() -> Result<()> {
    let edge_definitions = vec![coper_edge_definitions()]
        .into_iter()
        .flatten()
        .collect::<Vec<EdgeDefinition>>();

    let gc = FokusedGraph;

    let config = Config {
        database: "fokused_corpus".to_string(),
        graph: "fokused_corpus_graph".to_string(),
        ..Default::default()
    };

    gc.init(
        config,
        "/home/niklas/git/mace/samples/".into(),
        edge_definitions,
    )?;

    Ok(())
}
