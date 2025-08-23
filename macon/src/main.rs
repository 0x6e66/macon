use anyhow::Result;

use crate::graph_creators::focused_graph::focused_graph_main;

mod graph_creators;

fn main() -> Result<()> {
    focused_graph_main()
}
