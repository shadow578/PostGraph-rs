use crate::util::{
    existing_file, mail_address_string, mask_string, parse_ip_addr, parse_ip_net,
    prompt_user_confirmation,
};
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

/// PostGraph is an SMTP-to-Microsoft Graph mail proxy developed by Chris.
/// This tool is licensed under the GNU General Public License v3.0.
/// For more information, see https://github.com/shadow578/PostGraph-rs.
#[derive(Parser, Debug)]
pub(crate) struct Cli {
    /// Path to the PostGraph configuration file.
    #[arg(short, long, default_value = "config.yaml")]
    pub(crate) config: String,

    #[command(subcommand)]
    pub(crate) command: Option<CliCommand>,
}

#[derive(Parser, Debug)]
pub(crate) enum CliCommand {
    /// Run the PostGraph SMTP proxy.
    Run {
        /// Run PostGraph as a Windows service.
        /// In this mode, you must provide the absolute config path via --config.
        #[cfg(windows)]
        #[clap(short, long)]
        service: bool,
    },

    /// Manage PostGraph configuration.
    Config {
        #[clap(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Parser, Debug)]
pub(crate) enum ConfigCommand {
    /// Manage SMTP server settings.
    Smtp {
        #[command(subcommand)]
        command: SmtpCommand,
    },

    /// Manage Microsoft Graph client settings.
    Graph {
        #[command(subcommand)]
        command: GraphCommand,
    },

    /// Manage authentication settings.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },

    /// Restore the default configuration.
    Reset,
}

impl ConfigCommand {
    pub(crate) async fn execute(&self, config: &mut ConfigFile) {
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
        if config.smtp.allow_insecure_auth
            && (config.smtp.tls.is_some() || !config.smtp.users.has_users())
        {
            config.smtp.allow_insecure_auth = false;
        }
    }
}

#[derive(Parser, Debug)]
pub(crate) enum SmtpCommand {
    /// Display the current SMTP server configuration.
    #[command()]
    Show,

    /// Configure the SMTP server.
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

        /// Maximum message size in bytes.
        #[arg(short, long)]
        max_message_size: Option<usize>,
    },

    /// Configure the SMTP fail2ban policy.
    #[command(name = "fail2ban",
        group(
        ArgGroup::new("update")
            .required(true)
            .multiple(true)
            .args(["connections", "failures", "duration", "reset"])
        ))]
    Fail2Ban {
        /// Maximum number of simultaneous connections allowed per client.
        #[arg(short, long)]
        connections: Option<u32>,

        /// Number of suspicious or failed sessions before a client IP is banned.
        #[arg(short, long)]
        failures: Option<u32>,

        /// How long a client IP remains banned.
        #[arg(short, long, value_parser = parse_duration)]
        duration: Option<Duration>,

        /// Reset the fail2ban configuration to its defaults.
        #[arg(long)]
        reset: bool,
    },

    /// Manage SMTP peer allow/deny lists.
    #[command()]
    Peers {
        #[command(subcommand)]
        command: PeersCommand,
    },

    /// Manage SMTP TLS settings.
    #[command()]
    Tls {
        #[command(subcommand)]
        command: TlsCommand,
    },
}
impl SmtpCommand {
    async fn execute(&self, config: &mut ConfigFile) {
        match self {
            SmtpCommand::Show => {
                Self::show(config);
            }
            SmtpCommand::Setup {
                address,
                name,
                max_message_size,
            } => {
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
            SmtpCommand::Fail2Ban {
                connections,
                failures,
                duration,
                reset,
            } => {
                config.smtp.fail2ban = if *reset {
                    None
                } else {
                    let mut fail2ban = if let Some(fail2ban) = config.smtp.fail2ban.clone() {
                        fail2ban
                    } else {
                        Fail2BanConfig {
                            max_connections: None,
                            max_failures: None,
                            ban_duration: None,
                        }
                    };

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

    fn show(config: &ConfigFile) {
        println!("SMTP Server Configuration:");
        println!("  Listen Address: {}", config.smtp.address);
        println!(
            "  Server Name: {}",
            config.smtp.name.clone().unwrap_or("N/A".into())
        );

        print!("  Maximum Message Size: ");
        if let Some(max_message_size) = config.smtp.max_message_size {
            print!("{} bytes", max_message_size);

            if max_message_size > API_MAX_MESSAGE_SIZE {
                println!(
                    " (above the maximum of {API_MAX_MESSAGE_SIZE} bytes the Graph API can reliably handle)"
                )
            } else if max_message_size > RECOMMENDED_MAX_MESSAGE_SIZE {
                println!(" (above the recommended maximum of {RECOMMENDED_MAX_MESSAGE_SIZE} bytes)")
            } else {
                println!();
            }
        } else {
            println!("Automatic");
        }

        let (max_connections, max_failures, ban_duration) =
            config.smtp.get_effective_fail2ban_config();
        println!();
        println!("Fail2Ban Configuration:");
        println!("  Maximum Connections: {}", max_connections);
        println!("  Maximum Failures: {}", max_failures);
        println!("  Ban Duration: {}", format_duration(ban_duration));

        if config.smtp.allowed_peers.is_some() || config.smtp.denied_peers.is_some() {
            println!();
            PeersCommand::show(config);
        }

        println!();
        print!("TLS Configuration:");
        if let Some(tls) = &config.smtp.tls {
            println!();
            println!("  Certificate Chain:");
            for cert in &tls.certificate_chain {
                println!("    {}", cert);
            }

            println!("  Private Key: {}", tls.private_key);
        } else {
            println!("  N/A");
        }

        show_insecure_auth_warning(config);
    }
}

#[derive(Parser, Debug)]
pub(crate) enum PeersCommand {
    /// Add a subnet to the allow list.
    #[command()]
    Allow {
        /// The IP network to add.
        #[clap(value_parser = parse_ip_net)]
        network: IpNet,
    },

    /// Add a subnet to the deny list.
    #[command()]
    Deny {
        /// The IP network to add.
        #[clap(value_parser = parse_ip_net)]
        network: IpNet,
    },

    /// Remove a subnet from both the allow and deny lists.
    #[command()]
    Remove {
        /// The IP network to remove.
        #[clap(value_parser = parse_ip_net)]
        network: IpNet,
    },

    /// Check whether an IP address matches the allow and deny rules.
    #[command()]
    Test {
        /// The IP address to test.
        #[clap(value_parser = parse_ip_addr)]
        ip: IpAddr,
    },

    /// Display the current peer allow/deny lists.
    #[command()]
    Show,
}

impl PeersCommand {
    async fn execute(&self, config: &mut ConfigFile) {
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
                        config.smtp.denied_peers = None;
                    }
                }

                Self::show(config);
            }
            PeersCommand::Test { ip } => {
                if let Some(allowlist) = config.smtp.allowed_peers.as_ref()
                    && !allowlist.contains(*ip)
                {
                    println!(
                        "Peer IP '{}' will be rejected because it is not included in the allow list.",
                        ip
                    );
                    return;
                }
                if let Some(denylist) = config.smtp.denied_peers.as_ref()
                    && denylist.contains(*ip)
                {
                    println!(
                        "Peer IP '{}' will be rejected because it is included in the deny list.",
                        ip
                    );
                    return;
                }

                println!("Peer IP '{}' will be accepted.", ip);
            }
            PeersCommand::Show => Self::show(config),
        }
    }

    pub(crate) fn show(config: &ConfigFile) {
        let mut printed_allowlist = false;
        if let Some(allowlist) = config.smtp.allowed_peers.as_ref() {
            printed_allowlist = true;
            println!("Allow peers only from these subnets:");
            for net in allowlist.iter() {
                println!("  - {}", net);
            }
        }

        if let Some(denylist) = config.smtp.denied_peers.as_ref() {
            if printed_allowlist {
                println!()
            }

            println!("Deny peers in these subnets:");
            for net in denylist.iter() {
                println!("  - {}", net);
            }
        }
    }
}

#[derive(Parser, Debug)]
pub(crate) enum TlsCommand {
    /// Configure TLS for the SMTP server.
    #[command()]
    Setup {
        /// Path to the certificate chain, with the most specific certificate first.
        /// For a self-signed certificate, only one file is required.
        #[arg(short, long, value_parser = existing_file)]
        certificate: Vec<String>,

        /// Path to the private key matching the certificate.
        #[arg(short, long, value_parser = existing_file)]
        private_key: String,
    },

    /// Disable TLS for the SMTP server.
    #[command()]
    Disable,
}

impl TlsCommand {
    async fn execute(&self, config: &mut ConfigFile) {
        match self {
            TlsCommand::Setup {
                certificate,
                private_key,
            } => {
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
pub(crate) enum GraphCommand {
    /// Display the current Microsoft Graph configuration.
    #[command()]
    Show,

    /// Configure the Microsoft Graph client.
    #[command(group(
        ArgGroup::new("setup")
            .required(true)
            .multiple(true)
            .args(["tenant_id", "client_id", "client_secret"])
    ))]
    Setup {
        /// ID of the Microsoft Entra tenant where the application is registered.
        #[arg(long)]
        tenant_id: Option<String>,

        /// ID of the Microsoft Entra application or client registration.
        #[arg(long)]
        client_id: Option<String>,

        /// Client secret used to authenticate against Microsoft Graph.
        #[arg(long)]
        client_secret: Option<String>,
    },

    /// Test connectivity to Microsoft Graph.
    #[command()]
    Test,
}

impl GraphCommand {
    async fn execute(&self, config: &mut ConfigFile) {
        match self {
            GraphCommand::Show => {
                Self::show(config);
            }
            GraphCommand::Setup {
                tenant_id,
                client_id,
                client_secret,
            } => {
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

    fn show(config: &ConfigFile) {
        println!("Microsoft Graph API Configuration:");
        println!(" Tenant ID: {}", mask_string(&config.graph.tenant_id, 6));
        println!(" Client ID: {}", mask_string(&config.graph.client_id, 6));
        println!(
            " Client Secret: {}",
            mask_string(&config.graph.client_secret, 6)
        );
    }

    async fn test(config: &ConfigFile) {
        println!("Testing connection to Microsoft Graph API...");

        let graph_config = config.graph.clone().into_client_config();
        let mut client = GraphClient::new(graph_config);

        match client.authenticate().await {
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
pub(crate) enum AuthCommand {
    /// Manage users.
    #[command()]
    User {
        username: String,

        #[command(subcommand)]
        command: UserCommand,
    },

    /// Show all currently configured users.
    #[command()]
    ShowUsers,

    /// Allow authentication over insecure connections.
    #[command()]
    AllowInsecureAuth {
        #[command(subcommand)]
        command: AllowInsecureAuthCommand,
    },
}

impl AuthCommand {
    async fn execute(&self, config: &mut ConfigFile) {
        match self {
            AuthCommand::User { username, command } => command.execute(config, username).await,
            AuthCommand::ShowUsers => {
                let users = config.smtp.users.list_users();

                println!("Listing {} Users:", users.len());
                for user in users {
                    println!(" {}", user);
                }

                show_insecure_auth_warning(config);
            }
            AuthCommand::AllowInsecureAuth { command } => command.execute(config).await,
        }
    }
}

#[derive(Parser, Debug)]
pub(crate) enum UserCommand {
    /// Set the password of a user.
    /// If the user does not exist, this will create a new user.
    #[command(visible_alias = "passwd")]
    SetPassword {
        /// Password for authentication against mail proxy.
        /// If not provided, a password will be generated.
        password: Option<String>,

        /// Force accept the username.
        #[arg(long)]
        force: bool,
    },

    /// Remove an existing user.
    #[command()]
    Remove,

    /// Manage allowed senders for an existing user.
    #[command()]
    Senders {
        #[command(subcommand)]
        command: UserSendAsCommand,
    },
}

impl UserCommand {
    async fn execute(&self, config: &mut ConfigFile, username: &str) {
        match self {
            UserCommand::SetPassword { password, force } => {
                let is_new = !config.smtp.users.has_user(username);
                if is_new && !username.contains("@") {
                    println!("Username does not look like a Microsoft 365 username.");
                    println!("It is recommended that the username matches the one in M365.");
                    println!("To force this username, use the '--force' option.");

                    if !force {
                        return;
                    }
                }

                println!(
                    "{} user {}",
                    if is_new { "Adding" } else { "Updating" },
                    username
                );

                let password = match password {
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

                if let Err(err) = config.smtp.users.set_user_password(username, &password) {
                    eprintln!("Failed to update user: {}", err);
                }
            }
            UserCommand::Remove => {
                println!("Removing user {}", username);
                if let Err(err) = config.smtp.users.remove_user(username) {
                    eprintln!("Failed to remove user: {}", err);
                }
            }
            UserCommand::Senders { command } => command.execute(config, username).await,
        }
    }
}

#[derive(Parser, Debug)]
pub(crate) enum UserSendAsCommand {
    /// Add an allowed sender for a user.
    #[command()]
    Add {
        /// E-mail address that the user is allowed to send as.
        /// This may be an exact address, a whole-domain pattern like '*@example.com',
        /// or any address using '*@*'.
        #[arg(value_parser = mail_address_string)]
        sender: String,
    },

    /// Remove an allowed sender from a user.
    #[command()]
    Remove {
        /// E-mail address to remove from the user's allowed senders.
        /// This may be an exact address, a whole-domain pattern like '*@example.com',
        /// or any address using '*@*'.
        #[arg(value_parser = mail_address_string)]
        sender: String,
    },

    /// Display the allowed senders for a user.
    #[command()]
    Show,
}

impl UserSendAsCommand {
    async fn execute(&self, config: &mut ConfigFile, username: &str) {
        match self {
            UserSendAsCommand::Add { sender } => {
                println!("Adding allowed sender '{}' for user '{}'", sender, username);
                if let Err(err) = config.smtp.users.add_user_send_as(username, sender) {
                    eprintln!("Failed to update user: {}", err);
                }
            }
            UserSendAsCommand::Remove { sender } => {
                println!(
                    "Removing allowed sender '{}' for user '{}'",
                    sender, username
                );
                if let Err(err) = config.smtp.users.remove_user_send_as(username, sender) {
                    eprintln!("Failed to update user: {}", err);
                }
            }
            UserSendAsCommand::Show => {
                println!("User '{}' is allowed to send as:", username);

                // username is implicitly included in senders
                println!(" - {}", username);

                for sender in config.smtp.users.list_user_send_as(username).unwrap() {
                    println!(" - {}", sender);
                }
            }
        }
    }
}

#[derive(Parser, Debug)]
pub(crate) enum AllowInsecureAuthCommand {
    /// Allow authentication over plain text.
    Yes,

    /// Allow authentication only over TLS connection.
    No,
}

impl AllowInsecureAuthCommand {
    async fn execute(&self, config: &mut ConfigFile) {
        if config.smtp.tls.is_some() {
            println!(
                "Cannot enable insecure authentication, secure authentication via TLS is available in your configuration."
            );
            return;
        }

        match self {
            AllowInsecureAuthCommand::Yes => {
                println!(
                    "WARNING: You're about to allow authentication over unsecure, plain-text connections."
                );
                println!(
                    "In this configuration, credentials are sent in plain-text, potentially allowing credential theft."
                );
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

fn show_insecure_auth_warning(config: &ConfigFile) {
    if config.smtp.tls.is_none() && config.smtp.users.has_users() {
        println!();
        println!("WARNING: You've configured user authentication, but have not configured TLS.");

        if config.smtp.allow_insecure_auth {
            println!(
                "In this configuration, credentials are sent in plain-text, potentially allowing credential theft."
            );
        } else {
            println!("Authentication is currently not enabled.");
            println!(
                "If you wish to enable authentication anyway, run 'postgraph config auth allow-insecure-auth yes'"
            )
        }
    }
}
