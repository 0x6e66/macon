mod cli;
mod graph_creators;
mod utils;

use anyhow::Result;
use clap::Parser;

use crate::{
    cli::Cli,
    graph_creators::{focused_graph::focused_graph_main, general_graph::general_graph_main},
};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // dbg!(&cli);

    match cli.command {
        cli::MainCommands::Focused(focused_families) => focused_graph_main(focused_families)?,
        cli::MainCommands::General(main_args) => general_graph_main(main_args)?,
    }

    Ok(())
}
