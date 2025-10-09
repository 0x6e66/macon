mod classifier;
mod cli;
mod graph_creators;

use anyhow::Result;
use clap::Parser;

use crate::{
    cli::{Cli, FocusedArgs},
    graph_creators::focused_graph::focused_graph_main,
};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        cli::Commands::Focused(FocusedArgs { files, family }) => {
            focused_graph_main(&files, family)?
        }
    }

    Ok(())
}
