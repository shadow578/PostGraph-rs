mod app;
mod cli;
mod util;
mod proxy;
#[cfg(windows)]
mod service;

use crate::app::{run_config_cli, run_mail_proxy};
use crate::cli::{Cli, CliCommand};

#[cfg(windows)]
use crate::service::dispatch_service;
use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    pretty_env_logger::init();

    let cli = Cli::parse();
    match cli.command
    {
        Some(CliCommand::Run {
                 #[cfg(windows)]
                 service: false
             }) | None => {
            let task = run_mail_proxy(&cli);
            tokio::runtime::Runtime::new()?
                .block_on(task)?
        }
        #[cfg(windows)]
        Some(CliCommand::Run { service: true }) => {
            dispatch_service()?;
        }
        Some(CliCommand::Config { .. }) => {
            let task = run_config_cli(&cli);
            tokio::runtime::Runtime::new()?
                .block_on(task)?
        }
    }

    Ok(())
}
