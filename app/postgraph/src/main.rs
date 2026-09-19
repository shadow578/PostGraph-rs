mod app;
mod cli;
mod util;
#[cfg(windows)]
mod service;

use crate::app::{run_config_cli, run_mail_proxy};
use crate::cli::{Cli, CliCommand};
#[cfg(windows)]
use crate::service::dispatch_service;
use anyhow::Result;
use clap::Parser;

#[cfg(windows)]
const LOG_SOURCE_NAME: &str = "PostGraph";

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command
    {
        Some(CliCommand::Run {
                 #[cfg(windows)]
                 service: false
             }) | None => {
            pretty_env_logger::init();

            let task = run_mail_proxy(&cli);
            tokio::runtime::Runtime::new()?
                .block_on(task)?
        }
        #[cfg(windows)]
        Some(CliCommand::Run { service: true }) => {
            // service has no stdout, log to eventlog instead
            eventlog::init(LOG_SOURCE_NAME, log::Level::Info)?;
            dispatch_service()?;
        }
        #[cfg(windows)]
        Some(CliCommand::RegisterEventlog) => {
            pretty_env_logger::init();
            eventlog::register(LOG_SOURCE_NAME)?;
        }
        Some(CliCommand::Config { .. }) => {
            pretty_env_logger::init();

            let task = run_config_cli(&cli);
            tokio::runtime::Runtime::new()?
                .block_on(task)?
        }
    }

    Ok(())
}
