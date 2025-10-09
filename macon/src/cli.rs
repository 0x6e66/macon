use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::classifier::MalwareFamiliy;

#[derive(Parser, Debug)]
#[command(
    name = "macon",
    version,
    about = "Malware Corpus Normalization",
    long_about = ""
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(
        about = "Pass the sample directly",
        long_about = "With this command the sample has to be passed directly"
    )]
    Focused(FocusedArgs),
}

#[derive(Args, Debug)]
pub struct FocusedArgs {
    #[arg(
        value_parser = validate_file,
        help = "Path to the sample(s)",
        long_help = "Set the path to the sample(s) you want to analyze"
    )]
    pub files: Vec<PathBuf>,

    #[arg(
        short,
        long,
        value_enum,
        help = "Specify the malware family of the sample(s) you are trying to analyze"
    )]
    pub family: MalwareFamiliy,
}

fn validate_file(s: &str) -> Result<PathBuf, String> {
    let pathbuf = PathBuf::from(s);

    if !pathbuf.exists() {
        return Err("The path does not exists".to_string());
    } else if !pathbuf.is_file() {
        return Err("The specified path is either not a file, permissions are missing or symbolic links are broken".to_string());
    }

    Ok(pathbuf)
}
