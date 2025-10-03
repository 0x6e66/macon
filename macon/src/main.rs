mod graph_creators;

use anyhow::Result;

use crate::graph_creators::focused_graph::focused_graph_main;

fn main() -> Result<()> {
    focused_graph_main()
}
