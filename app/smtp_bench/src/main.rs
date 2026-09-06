use anyhow::Result;
use async_trait::async_trait;
use smtp::config::Config as SmtpConfig;
use smtp::handler::{Handler as SmtpHandler, LoginResult};
use smtp::server::Server as SmtpServer;
use smtp::{AuthMode, Mail};
use std::error::Error;
use std::time::Duration;
use tokio::time::sleep;

/// Credentials expected in on_login.
const LOGIN_CREDENTIALS: (&str, &str) = ("alice", "hunter2");

/// (Simulated) time login verification takes.
const LOGIN_DELAY: Duration = Duration::from_millis(500);

/// (Simulated) time mail send takes.
const MAIL_SEND_DELAY: Duration = Duration::from_millis(1500);

#[derive(Clone)]
struct ProxyHandler {}

#[async_trait]
impl SmtpHandler for ProxyHandler {
    async fn on_login(&mut self, username: String, password: String) -> Result<LoginResult, Box<dyn Error + Send + Sync>> {
        sleep(LOGIN_DELAY).await;

        let (expected_username, expected_password) = LOGIN_CREDENTIALS;
        if username == expected_username && password == expected_password {
            Ok(LoginResult::Ok)
        } else {
            println!("Rejected login for username={}, password={}", username, password);
            Ok(LoginResult::Reject)
        }
    }

    async fn on_mail(&mut self, _mail: &Mail) -> Result<(), Box<dyn Error + Send + Sync>> {
        sleep(MAIL_SEND_DELAY).await;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()>
{
    pretty_env_logger::init();

    let mut smtp_config = SmtpConfig::new(ProxyHandler {});
    smtp_config
        .with_address("127.0.0.1:2525")
        .with_auth(AuthMode::Always);

    println!("SMTP server listening on 127.0.0.1:2525");
    SmtpServer::listen(&smtp_config).await
}
