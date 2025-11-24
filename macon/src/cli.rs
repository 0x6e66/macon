use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "macon", version, about = "Malware Corpus Normalization")]
pub struct Cli {
    #[command(subcommand)]
    pub command: MainCommands,
}

#[derive(Subcommand, Debug)]
pub enum MainCommands {
    #[command(
        subcommand,
        about = "Analyze malware samples where the family is already known"
    )]
    Focused(FocusedFamilies),
}

#[derive(Subcommand, Debug)]
pub enum FocusedFamilies {
    #[command(about = "Analyze sample from the Carnavalheist malware")]
    Carnavalheist(MainArgs),
    #[command(about = "Analyze sample from the Coper malware")]
    Coper(MainArgs),
    #[command(
        about = "Analyze sample from the DarkHorsemen malware.\nWARNING: This will run the provided samples in a VM"
    )]
    DarkWatchmen(VMArgs),
    #[command(about = "Analyze sample from the Mintsloader malware")]
    Mintsloader(MainArgs),
}

#[derive(Args, Debug)]
pub struct MainArgs {
    #[arg(
        value_parser = validate_file,
        help = "Path to the sample(s)",
        long_help = "Set the path to the sample(s) you want to analyze"
    )]
    pub files: Vec<PathBuf>,
}

#[derive(Args, Debug)]
pub struct VMArgs {
    #[clap(flatten)]
    pub main_args: MainArgs,

    #[arg(help = "Name of the VM", short, long)]
    pub vm_name: String,

    #[arg(help = "Username of the VM", short, long)]
    pub vm_user: String,

    #[arg(help = "Password associated with the user", short, long)]
    pub vm_pass: String,

    #[arg(help = "Path of the shared directory on the host", short, long, value_parser = validate_dir)]
    pub shared_dir: PathBuf,
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

fn validate_dir(s: &str) -> Result<PathBuf, String> {
    let pathbuf = PathBuf::from(s);

    if !pathbuf.exists() {
        return Err("The path does not exists".to_string());
    } else if pathbuf.is_file() {
        return Err("The specified path is either not a directory, permissions are missing or symbolic links are broken".to_string());
    }

    Ok(pathbuf)
}
