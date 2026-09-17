use crate::config_file::ConfigFile;
use crate::fail2ban::{Fail2Ban, Verdict};
use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use ms_graph::client::Client as GraphClient;
use smtp::Mail;
use smtp::config::Config as SmtpConfig;
use smtp::handler::{ConnectResult, Handler as SmtpHandler, LoginResult};
use smtp::server::Server as SmtpServer;
use std::error::Error;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct ProxyHandler {
    /// proxy configuration data.
    /// note: per-session (cloned).
    config: ConfigFile,

    /// graph client instance.
    /// note: per-session (cloned).
    graph_client: GraphClient,

    /// fail2ban instance to track and reject problematic peers
    /// note: shared between all sessions.
    fail2ban: Arc<Mutex<Fail2Ban>>,

    /// username provided in on_login.
    /// note: per-session.
    username: Option<String>,

    /// did this session do anything productive (e.g. send mail)?
    /// unproductive sessions are reported to fail2ban.
    /// note: per-session.
    productive: bool,
}

impl ProxyHandler
{
    fn new(config: ConfigFile, graph_client: GraphClient, fail2ban: Fail2Ban) -> Self {
        Self {
            config,
            graph_client,
            fail2ban: Arc::new(Mutex::new(fail2ban)),
            username: None,
            productive: false,
        }
    }
}

#[async_trait]
impl SmtpHandler for ProxyHandler {
    async fn on_connect(&mut self, peer_addr: IpAddr) -> std::result::Result<ConnectResult, Box<dyn Error + Send + Sync>> {
        // connection peer filter
        if let Some(allowlist) = self.config.smtp.peer_allowlist.as_ref() {
            if !allowlist.contains(peer_addr) {
                return Ok(ConnectResult::Reject);
            }
        }

        // fail2ban logic
        self.productive = false;

        let mut fail2ban = self.fail2ban.lock().await;
        fail2ban.push_connection(peer_addr);
        let verdict = fail2ban.get_verdict(peer_addr);

        Ok(
            if verdict == Verdict::Ok {
                ConnectResult::Ok
            } else {
                ConnectResult::Reject
            }
        )
    }

    async fn on_disconnect(&mut self, peer_addr: IpAddr) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        let mut fail2ban = self.fail2ban.lock().await;

        // unproductive? -> ban on repeated offense.
        if !self.productive {
            fail2ban.push_fail(peer_addr);
        }

        fail2ban.pop_connection(peer_addr);

        Ok(())
    }

    async fn on_login(&mut self, username: String, password: String) -> Result<LoginResult, Box<dyn Error + Send + Sync>> {
        match self.config.smtp.auth.verify_user_password(&username, &password)
        {
            Ok(_) => {
                self.username = Some(username.clone());
                Ok(LoginResult::Ok)
            }
            Err(err) => {
                debug!("on_login for {} failed: {}", username, err);
                self.username = None;
                self.productive = false;
                Ok(LoginResult::Reject)
            }
        }
    }

    async fn on_mail(&mut self, mail: &Mail) -> Result<(), Box<dyn Error + Send + Sync>> {
        let sender = mail.sender();

        if let Some(username) = self.username.as_ref() && username != sender {
            return Err("Sender address must match username!".into());
        }

        self.productive = true;

        self.graph_client.send_mail(sender, mail.data()).await?;

        Ok(())
    }

    async fn on_reset(&mut self) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.username = None;
        Ok(())
    }
}

pub async fn run(config: ConfigFile) -> Result<()>
{
    let fail2ban = {
        let (max_connections, max_failures, ban_duration) = config.smtp.get_effective_fail2ban_config();
        Fail2Ban::new(
            max_connections,
            max_failures,
            ban_duration,
        )
    };

    let handler = ProxyHandler::new(
        config.clone(),
        GraphClient::new(config.graph.into_client_config()),
        fail2ban,
    );

    let mut smtp_config = SmtpConfig::new(handler);
    config.smtp.apply_to_server_config(&mut smtp_config)?;

    println!("SMTP server listening on {}", config.smtp.address);
    SmtpServer::listen(&smtp_config).await
}
