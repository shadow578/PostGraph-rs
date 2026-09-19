use ipnet::IpNet;
use std::io;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

// CLAP validator that validates file path exists.
pub(crate) fn existing_file(path: &str) -> Result<String, String> {
    let path = PathBuf::from(path);
    let path = path.canonicalize().map_err(|e| e.to_string())?;

    if path.is_file() {
        Ok(path.to_string_lossy().to_string())
    } else {
        Err(format!("'{}' is not a file", path.display()))
    }
}

// CLAP validator that validates string looks like a e-mail address.
pub(crate) fn mail_address_string(address: &str) -> Result<String, String> {
    let address = address.trim();
    if address.contains("@") {
        Ok(address.into())
    } else {
        Err(format!("'{}' is not a mail address", address))
    }
}


// CLAP validator that parses validates an IpAddr.
pub(crate) fn parse_ip_addr(net: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = IpAddr::from_str(net) {
        Ok(ip)
    } else {
        Err(format!("'{}' is not a valid IP address", net))
    }
}

// CLAP validator that parses validates an IpNet.
pub(crate) fn parse_ip_net(net: &str) -> Result<IpNet, String> {
    if let Ok(net) = IpNet::from_str(net) {
        Ok(net)
    } else {
        Err(format!("'{}' is not a valid IP network in CIDR notation", net))
    }
}

/// prompt the user for confirmation of a potentially dangerous operation.
/// prompt: prompt the user has to type to confirm.
pub(crate) fn prompt_user_confirmation(prompt: &str) -> anyhow::Result<()> {
    print!("Type '{}' to continue: ", prompt);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let input = input.trim();
    if input != prompt {
        return Err(anyhow::anyhow!("Confirmation did not match"));
    }

    Ok(())
}

/// mask all but the last n chars of a string with '*'
/// s: string to mask.
/// last_n: how many chars at the end are still visible.
pub(crate) fn mask_string(s: &str, last_n: usize) -> String {
    let n = s.chars().count();
    "*".repeat(n.saturating_sub(last_n)) + &s.chars().skip(n.saturating_sub(last_n)).collect::<String>()
}
