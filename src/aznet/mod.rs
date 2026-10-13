mod auth;
mod azure;
mod cli;
mod ipam;
mod next_subnet;
mod report;

use std::process::ExitCode;

use clap::Parser;

pub use cli::{Cli, Command};

pub async fn run() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::GetNextSubnet(args) => next_subnet::run(args).await,
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
