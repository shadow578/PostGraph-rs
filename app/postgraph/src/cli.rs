use crate::util::{existing_file, mask_string, parse_ip_addr, parse_ip_net, prompt_user_confirmation};
use base64::Engine;
use clap::{ArgGroup, Parser};
use humantime::{format_duration, parse_duration};
use ipnet::IpNet;
use mail_proxy::config_file::{ConfigFile, Fail2BanConfig, TLSConfig};
use mail_proxy::ip_net_list::IpNetList;
use ms_graph::client::Client as GraphClient;
use ms_graph::{API_MAX_MESSAGE_SIZE, RECOMMENDED_MAX_MESSAGE_SIZE};
use std::net::IpAddr;
use std::time::Duration;

/// PostGraph: A SMTP to Microsoft Graph API mail proxy, developed by Chris.
/// This tool is licensed under the GNU General Public License v3.0.
/// For more information, refer to https://github.com/shadow578/PostGraph-rs.
#[derive(Parser, Debug)]
pub(crate) struct Cli
{
    /// Path to the configuration file.
    #[arg(short, long, default_value = "config.yaml")]
    pub(crate) config: String,

    #[command(subcommand)]
    pub(crate) command: Option<CliCommand>,
}

#[derive(Parser, Debug)]
pub(crate) enum CliCommand
{
    /// Run PostGraph.
    Run
    {
        /// Run PostGraph as a Windows service.
        /// Please note that in this mode, you must provide the absolute config path via '--config'.
        #[cfg(windows)]
        #[clap(short, long)]
        service: bool
    },

    /// Update the configuration.
    Config {
        #[clap(subcommand)]
        command: ConfigCommand
    },
}

#[derive(Parser, Debug)]
pub(crate) enum ConfigCommand
{
    /// Manage SMTP server.
    Smtp {
        #[command(subcommand)]
        command: SmtpCommand
    },

    /// Manage Microsoft Graph API client.
    Graph {
        #[command(subcommand)]
        command: GraphCommand
    },

    /// Manage authentication configuration.
    Auth {
        #[command(subcommand)]
        command: AuthCommand
    },

    /// Restore default configuration.
    Reset,
}

impl ConfigCommand
{
    pub(crate) async fn execute(&self, config: &mut ConfigFile)
    {
        match self {
            ConfigCommand::Smtp { command } => command.execute(config).await,
            ConfigCommand::Graph { command } => command.execute(config).await,
            ConfigCommand::Auth { command } => command.execute(config).await,
            ConfigCommand::Reset => {
                let defaults = ConfigFile::empty();
                config.smtp = defaults.smtp;
                config.graph = defaults.graph;
            }
        }

        // disable insecure auth when not needed
        if config.smtp.allow_insecure_auth && (config.smtp.tls.is_some() || !config.smtp.auth.has_users()) {
            config.smtp.allow_insecure_auth = false;
        }
    }
}

#[derive(Parser, Debug)]
pub(crate) enum SmtpCommand
{
    /// Show current SMTP server configuration.
    #[command()]
    Show,

    /// Setup SMTP server.
    #[command(group(
        ArgGroup::new("setup")
            .required(true)
            .multiple(true)
            .args(["address", "name", "max_message_size"])
    ))]
    Setup {
        /// SMTP server listen address. Example: '0.0.0.0:25'.
        #[arg(short, long)]
        address: Option<String>,

        /// SMTP server name.
        #[arg(short, long)]
        name: Option<String>,

        /// Maximum E-Mail message size, in bytes.
        #[arg(short, long)]
        max_message_size: Option<usize>,
    },

    /// Setup fail2ban for SMTP server.
    #[command(name = "fail2ban",
        group(
        ArgGroup::new("update")
            .required(true)
            .multiple(true)
            .args(["connections", "failures", "duration", "reset"])
        ))]
    Fail2Ban {
        /// Maximum number of connections a client is allowed to hold.
        #[arg(short, long)]
        connections: Option<u32>,

        /// Maximum number of suspicious / failed sessions before a client's IP is banned.
        #[arg(short, long)]
        failures: Option<u32>,

        /// For how long a client's IP remains banned.
        #[arg(short, long, value_parser = parse_duration)]
        duration: Option<Duration>,

        /// Reset to default settings.
        #[arg(long)]
        reset: bool,
    },

    /// Manage SMTP peer allowlist.
    #[command()]
    Peers {
        #[command(subcommand)]
        command: PeersCommand
    },

    /// Manage SMTP server TLS configuration.
    #[command()]
    Tls {
        #[command(subcommand)]
        command: TlsCommand
    },
}
impl SmtpCommand
{
    pub(crate) async fn execute(&self, config: &mut ConfigFile)
    {
        match self {
            SmtpCommand::Show => {
                Self::show(config);
            }
            SmtpCommand::Setup { address, name, max_message_size } => {
                if let Some(address) = address {
                    config.smtp.address = address.into();
                }

                if let Some(name) = name {
                    config.smtp.name = Some(name.into());
                }

                if let Some(max_message_size) = max_message_size {
                    config.smtp.max_message_size = if *max_message_size == 0 {
                        None
                    } else {
                        Some(*max_message_size)
                    }
                }

                Self::show(config);
            }
            SmtpCommand::Fail2Ban { connections, failures, duration, reset } => {
                config.smtp.fail2ban = if *reset {
                    None
                } else {
                    let mut fail2ban =
                        if let Some(fail2ban) = config.smtp.fail2ban.clone() { fail2ban } else { Fail2BanConfig { max_connections: None, max_failures: None, ban_duration: None } };

                    if let Some(connections) = connections {
                        fail2ban.max_connections = Some(*connections);
                    }

                    if let Some(failures) = failures {
                        fail2ban.max_failures = Some(*failures);
                    }

                    if let Some(duration) = duration {
                        fail2ban.ban_duration = Some(*duration)
                    }

                    Some(fail2ban)
                };

                Self::show(config);
            }
            SmtpCommand::Peers { command } => {
                command.execute(config).await;
            }
            SmtpCommand::Tls { command } => {
                command.execute(config).await;
                Self::show(config);
            }
        }
    }

    fn show(config: &ConfigFile)
    {
        println!("SMTP Server Configuration:");
        println!(" Listen Address: {}", config.smtp.address);
        println!(" Server Name: {}", config.smtp.name.clone().unwrap_or("N/A".into()));

        print!(" Maximum Message Size: ");
        if let Some(max_message_size) = config.smtp.max_message_size {
            print!("{} bytes", max_message_size);

            if max_message_size > API_MAX_MESSAGE_SIZE {
                println!(" (above maximum of {API_MAX_MESSAGE_SIZE} bytes the Graph API can reliably handle)")
            } else if max_message_size > RECOMMENDED_MAX_MESSAGE_SIZE {
                println!(" (above recommended maximum of {RECOMMENDED_MAX_MESSAGE_SIZE} bytes)")
            } else {
                println!();
            }
        } else {
            println!("Automatic");
        }

        let (max_connections, max_failures, ban_duration) = config.smtp.get_effective_fail2ban_config();
        println!();
        println!("Fail2Ban Configuration:");
        println!(" Maximum Connections: {}", max_connections);
        println!(" Max Failures: {}", max_failures);
        println!(" Ban Duration: {}", format_duration(ban_duration));

        PeersCommand::show(config);

        println!();
        print!("TLS Configuration:");
        if let Some(tls) = &config.smtp.tls
        {
            println!();
            println!(" Certificate Chain: ");
            for cert in &tls.certificate_chain {
                println!("   {}", cert);
            }

            println!(" Private Key: {}", tls.private_key);
        } else {
            println!(" N/A");
        }

        show_insecure_auth_warning(config);
    }
}

#[derive(Parser, Debug)]
pub(crate) enum PeersCommand
{
    /// Add an IP subnet to the allow list.
    #[command()]
    Allow {
        /// The IP network to add.
        #[clap(value_parser = parse_ip_net)]
        network: IpNet
    },

    /// Add an IP subnet to the deny list.
    #[command()]
    Deny {
        /// The IP network to add.
        #[clap(value_parser = parse_ip_net)]
        network: IpNet
    },

    /// Remove an IP network from *both* the allow and deny list.
    #[command()]
    Remove {
        /// The IP network to remove.
        #[clap(value_parser = parse_ip_net)]
        network: IpNet
    },

    /// Test if an IP address matches against the allow and deny list.
    #[command()]
    Test {
        /// The IP to test.
        #[clap(value_parser = parse_ip_addr)]
        ip: IpAddr
    },
}

impl PeersCommand
{
    pub(crate) async fn execute(&self, config: &mut ConfigFile)
    {
        match self {
            PeersCommand::Allow { network } => {
                if config.smtp.allowed_peers.is_none() {
                    config.smtp.allowed_peers = Some(IpNetList::default())
                }

                config.smtp.allowed_peers.as_mut().unwrap().add(*network);

                Self::show(config);
            }
            PeersCommand::Deny { network } => {
                if config.smtp.denied_peers.is_none() {
                    config.smtp.denied_peers = Some(IpNetList::default())
                }

                config.smtp.denied_peers.as_mut().unwrap().add(*network);

                Self::show(config);
            }
            PeersCommand::Remove { network } => {
                if let Some(allowlist) = config.smtp.allowed_peers.as_mut() {
                    allowlist.remove(*network);
                    if allowlist.is_empty() {
                        config.smtp.allowed_peers = None;
                    }
                }

                if let Some(denylist) = config.smtp.denied_peers.as_mut() {
                    denylist.remove(*network);
                    if denylist.is_empty() {
                        config.smtp.allowed_peers = None;
                    }
                }

                Self::show(config);
            }
            PeersCommand::Test { ip } => {
                if let Some(allowlist) = config.smtp.allowed_peers.as_ref()
                    && !allowlist.contains(*ip) {
                    println!("Peer IP '{}' will be rejected because it is not included in the allow list.", ip);
                    return;
                }
                if let Some(denylist) = config.smtp.denied_peers.as_ref()
                    && denylist.contains(*ip) {
                    println!("Peer IP '{}' will be rejected because it is included in the deny list.", ip);
                    return;
                }

                println!("Peer IP '{}' will be accepted.", ip);
            }
        }
    }

    pub(crate) fn show(config: &ConfigFile)
    {
        // only print allow / deny list if configured
        if let Some(allowlist) = config.smtp.allowed_peers.as_ref() {
            println!();
            println!("Only allow peers in these subnets:");
            for net in allowlist.iter() {
                println!(" {}", net);
            }
        }
        if let Some(denylist) = config.smtp.denied_peers.as_ref() {
            println!();
            println!("Deny all peers in these subnets:");
            for net in denylist.iter() {
                println!(" {}", net);
            }
        }
    }
}

#[derive(Parser, Debug)]
pub(crate) enum TlsCommand
{
    /// Setup TLS.
    #[command()]
    Setup {
        /// Path to certificate(s) for certificate chain, most concrete listed first.
        /// For a self-signed certificate, you'll only need one.
        #[arg(short, long, value_parser = existing_file)]
        certificate: Vec<String>,

        /// Private key for TLS certificate.
        #[arg(short, long, value_parser = existing_file)]
        private_key: String,
    },

    /// Disable TLS.
    #[command()]
    Disable,
}

impl TlsCommand
{
    pub(crate) async fn execute(&self, config: &mut ConfigFile)
    {
        match self {
            TlsCommand::Setup { certificate, private_key } => {
                config.smtp.tls = Some(TLSConfig {
                    certificate_chain: certificate.clone(),
                    private_key: private_key.clone(),
                })
            }
            TlsCommand::Disable => {
                config.smtp.tls = None;
            }
        }
    }
}

#[derive(Parser, Debug)]
pub(crate) enum GraphCommand
{
    /// Show current Microsoft Graph API configuration.
    #[command()]
    Show,

    /// Setup Microsoft Graph API configuration.
    #[command(group(
        ArgGroup::new("setup")
            .required(true)
            .multiple(true)
            .args(["tenant_id", "client_id", "client_secret"])
    ))]
    Setup {
        /// ID of the Microsoft Entra tenant the application is registered in.
        #[arg(long)]
        tenant_id: Option<String>,

        /// ID of the Microsoft Entra app / client registration.
        #[arg(long)]
        client_id: Option<String>,

        /// Client secret used for authentication against Microsoft Graph API.
        #[arg(long)]
        client_secret: Option<String>,
    },

    /// Test connection to Microsoft Graph API.
    #[command()]
    Test,
}

impl GraphCommand
{
    pub(crate) async fn execute(&self, config: &mut ConfigFile)
    {
        match self {
            GraphCommand::Show => {
                Self::show(config);
            }
            GraphCommand::Setup { tenant_id, client_id, client_secret } => {
                if let Some(tenant_id) = tenant_id {
                    config.graph.tenant_id = tenant_id.into();
                }

                if let Some(client_id) = client_id {
                    config.graph.client_id = client_id.into();
                }

                if let Some(client_secret) = client_secret {
                    config.graph.client_secret = client_secret.into();
                }

                Self::show(config);
                println!();
                Self::test(config).await;
            }
            GraphCommand::Test => {
                Self::test(config).await;
            }
        }
    }

    fn show(config: &ConfigFile)
    {
        println!("Microsoft Graph API Configuration:");
        println!(" Tenant ID: {}", mask_string(&config.graph.tenant_id, 6));
        println!(" Client ID: {}", mask_string(&config.graph.client_id, 6));
        println!(" Client Secret: {}", mask_string(&config.graph.client_secret, 6));
    }

    async fn test(config: &ConfigFile)
    {
        println!("Testing connection to Microsoft Graph API...");

        let graph_config = config.graph.clone().into_client_config();
        let mut client = GraphClient::new(graph_config);

        match client.authenticate().await
        {
            Ok(_) => {
                println!("Connected to Microsoft Graph successfully");
            }
            Err(err) => {
                eprintln!("Error connecting to Microsoft Graph: {}", err);
            }
        }
    }
}

#[derive(Parser, Debug)]
pub(crate) enum AuthCommand
{
    /// Manage users.
    User {
        #[command(subcommand)]
        command: UserCommand
    },

    /// Allow authentication over insecure connections.
    #[command()]
    AllowInsecureAuth {
        #[command(subcommand)]
        command: AllowInsecureAuthCommand
    },
}

impl AuthCommand
{
    pub(crate) async fn execute(&self, config: &mut ConfigFile)
    {
        match self {
            AuthCommand::User { command } => command.execute(config).await,
            AuthCommand::AllowInsecureAuth { command } => command.execute(config).await,
        }
    }
}

#[derive(Parser, Debug)]
pub(crate) enum UserCommand
{
    /// Show all currently configured users.
    #[command()]
    Show,

    /// Add or modify a user.
    #[command(visible_alias = "modify")]
    Add {
        /// Username to add. Must match Microsoft Entra User UPN.
        username: String,

        /// Password for authentication against mail proxy.
        password: Option<String>,

        /// Force accept the username, even if it is likely invalid.
        #[arg(long)]
        force: bool,
    },

    /// Remove an existing user.
    #[command()]
    Remove {
        /// Username to remove.
        username: String,
    },
}

impl UserCommand
{
    pub(crate) async fn execute(&self, config: &mut ConfigFile)
    {
        match self {
            UserCommand::Show => {
                Self::show(config);
            }
            UserCommand::Add { username, password, force } => {
                println!("{} user {}",
                         if config.smtp.auth.has_user(username) { "Updating" } else { "Adding" },
                         username
                );

                if !username.contains("@")
                {
                    println!("Username does not look like a Microsoft 365 username.");
                    println!("Please note that the username *must* match the username in M365.");

                    if !force
                    {
                        return;
                    }
                }

                let password = match password
                {
                    Some(password) => password.into(),
                    None => {
                        // auto-generate a password
                        // 24 bytes / 32 chars = 192 bits entropy
                        let mut pwd = [0u8; 24];
                        rand::fill(&mut pwd);
                        let pwd = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pwd);

                        println!("Password: {}", pwd);
                        pwd
                    }
                };

                if let Err(err) = config.smtp.auth.set_user_password(username, &password)
                {
                    eprintln!("Failed to update user: {}", err);
                }

                println!();
                Self::show(config);
            }
            UserCommand::Remove { username } => {
                println!("Removing user {}", username);
                if let Err(err) = config.smtp.auth.remove_user(username)
                {
                    eprintln!("Failed to remove user: {}", err);
                }

                println!();
                Self::show(config);
            }
        }
    }

    fn show(config: &ConfigFile)
    {
        let users = config.smtp.auth.list_users();

        println!("Listing {} Users:", users.len());
        for user in users
        {
            println!(" {}", user);
        }

        show_insecure_auth_warning(config);
    }
}

#[derive(Parser, Debug)]
pub(crate) enum AllowInsecureAuthCommand {
    /// Allow authentication over plain text.
    Yes,

    /// Allow authentication only over TLS connection.
    No,
}

impl AllowInsecureAuthCommand
{
    pub(crate) async fn execute(&self, config: &mut ConfigFile)
    {
        if config.smtp.tls.is_some() {
            println!("Cannot enable insecure authentication, secure authentication via TLS is available in your configuration.");
            return;
        }

        match self {
            AllowInsecureAuthCommand::Yes => {
                println!("WARNING: You're about to allow authentication over unsecure, plain-text connections.");
                println!("In this configuration, credentials are sent in plain-text, potentially allowing credential theft.");
                println!("This configuration is NOT recommended.");

                if prompt_user_confirmation("yes, i understand").is_ok() {
                    println!("Insecure auth enabled");
                    config.smtp.allow_insecure_auth = true;
                } else {
                    println!("Aborting");
                }
            }
            AllowInsecureAuthCommand::No => {
                config.smtp.allow_insecure_auth = false;
            }
        }
    }
}

fn show_insecure_auth_warning(config: &ConfigFile)
{
    if config.smtp.tls.is_none() && config.smtp.auth.has_users() {
        println!();
        println!("WARNING: You've configured user authentication, but have not configured TLS.");

        if config.smtp.allow_insecure_auth {
            println!("In this configuration, credentials are sent in plain-text, potentially allowing credential theft.");
        } else {
            println!("Authentication is currently not enabled.");
            println!("If you wish to enable authentication anyway, run 'postgraph config auth allow-insecure-auth yes'")
        }
    }
}
