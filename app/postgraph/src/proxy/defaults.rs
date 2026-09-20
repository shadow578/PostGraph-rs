use std::time::Duration;

/// default bind address for SMTP server
pub(crate) const DEFAULT_SMTP_BIND_ADDRESS: &str = "127.0.0.1:25";

/// default maximum number of connections a peer is allowed to hold.
pub(crate) const DEFAULT_FAIL2BAN_CONNECTIONS: u32 = 5;

/// default maximum number of fails before peer is banned.
pub(crate) const DEFAULT_FAIL2BAN_FAILS: u32 = 5;

/// default time before a peers fails are forgotten.
pub(crate) const DEFAULT_FAIL2BAN_DURATION: Duration = Duration::from_mins(30);

