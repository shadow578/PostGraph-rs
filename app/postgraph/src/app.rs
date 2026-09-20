use crate::cli::{Cli, CliCommand};
use crate::proxy::config_file::ConfigFile;
use anyhow::{Result, anyhow};

/// Run mail proxy logic (standalone or service mode)
/// cli: parsed cli args. requires `cli.command != CliCommand::Config`.
pub(crate) async fn run_mail_proxy(cli: &Cli) -> Result<()> {
    if let Some(CliCommand::Config { .. }) = cli.command.as_ref() {
        panic!("run_mail_prox requires CLI with run command!")
    }

    let config = ConfigFile::from_file(&cli.config).await
        .map_err(|err| {
            anyhow!("Failed to load configuration file: {}", err)
        })?;

    crate::proxy::proxy::run(config).await?;

    Ok(())
}

/// Run configuration CLI.
/// cli: parsed cli args. requires `cli.command == CliCommand::Config`.
pub(crate) async fn run_config_cli(cli: &Cli) -> Result<()> {
    let mut config = ConfigFile::from_file(&cli.config).await
        .map_err(|err| {
            anyhow!("Failed to load configuration file: {}", err)
        })?;

    if let Some(CliCommand::Config { command }) = cli.command.as_ref() {
        command.execute(&mut config).await;
    } else {
        panic!("run_config_cli requires CLI with config command!")
    }

    config.to_file(&cli.config).await
        .unwrap_or_else(|err| {
            eprintln!("Failed to save configuration file: {}", err);
        });

    Ok(())
}
