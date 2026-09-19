use anyhow::anyhow;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use log::debug;
use password_hash::PasswordHasher;
use serde;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct UserList
{
    /// list of configured users.
    users: HashMap<String, UserEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserEntry
{
    /// password hash of this user.
    #[serde(
        serialize_with = "serialize_password_hash",
        deserialize_with = "deserialize_password_hash"
    )]
    password: PasswordHash,

    /// list of mail addresses this user may send as.
    /// the user may always send using a mail address matching their username.
    /// this list may contain exact entries (alice@example.com) or whole domains entries (*@example.com).
    #[serde(
        rename = "send_as",
        skip_serializing_if = "HashSet::is_empty",
        default
    )]
    allow_send_as: HashSet<String>,
}


// region: Serialize / Deserialize
fn serialize_password_hash<S>(
    value: &PasswordHash,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value.to_string().serialize(serializer)
}

fn deserialize_password_hash<'de, D>(
    deserializer: D,
) -> Result<PasswordHash, D::Error>
where
    D: Deserializer<'de>,
{
    let hash: String = String::deserialize(deserializer)?;
    PasswordHash::new(&*hash)
        .map_err(|e| D::Error::custom(e.to_string()))
}

impl Serialize for UserList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.users.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UserList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let users: HashMap<String, UserEntry> = HashMap::deserialize(deserializer)?;
        Ok(Self { users })
    }
}
// endregion

// region: auth API
impl Default for UserList {
    // create a new UserAuth instance without any users configured.
    fn default() -> Self {
        Self {
            users: HashMap::new(),
        }
    }
}

impl UserList
{
    /// add or update user entry.
    /// username: username to add or modify.
    /// password: new password to set.
    pub fn set_user_password(&mut self, username: &str, password: &str) -> anyhow::Result<()>
    {
        debug!("Updating user password for {}", username);

        let hash = Argon2::default()
            .hash_password(password.as_bytes())
            .map_err(|_| anyhow!("could not set password"))?;

        self.users.insert(username.into(), UserEntry { password: hash, allow_send_as: HashSet::new() });

        Ok(())
    }

    /// remove an existing user entry.
    /// username: username to remove.
    pub fn remove_user(&mut self, username: &str) -> anyhow::Result<()>
    {
        debug!("Removing user {}", username);
        self.users.remove(username).ok_or_else(|| anyhow!("User not found"))?;
        Ok(())
    }

    /// check if a user exists.
    /// username: the username to check for.
    pub fn has_user(&self, username: &str) -> bool
    {
        self.users.contains_key(username)
    }

    /// are any users configured, enabling authentication?
    pub fn has_users(&self) -> bool
    {
        !self.users.is_empty()
    }

    /// get a list of all users.
    pub fn list_users(&self) -> impl ExactSizeIterator<Item=&String>
    {
        self.users.keys()
    }

    /// verify username exists and password is correct.
    /// username: username to match to.
    /// password: clear-text password to validate is correct.
    pub(crate) fn verify_user_password(&self, username: &str, password: &str) -> anyhow::Result<()>
    {
        let hash = &self.users.get(username)
            .ok_or_else(|| anyhow!("user {} not found", username))?
            .password;

        Argon2::default()
            .verify_password(password.as_bytes(), hash)
            .map_err(|_| anyhow!("invalid password"))?;

        Ok(())
    }

    /// Add an entry to a users allowed senders list.
    /// username: username to update.
    /// sender: sender address to add to allowed sender list.
    pub fn add_user_send_as(&mut self, username: &str, sender: &str) -> anyhow::Result<()>
    {
        debug!("Adding allowed sender {} for {}", sender, username);

        self.users.get_mut(username)
            .ok_or_else(|| anyhow!("user {} not found", username))?
            .allow_send_as
            .insert(sender.into());

        Ok(())
    }

    /// Remove an entry from a users allowed senders list.
    /// username: username to update.
    /// sender: sender address to add to allowed sender list.
    pub fn remove_user_send_as(&mut self, username: &str, sender: &str) -> anyhow::Result<()>
    {
        debug!("Removing allowed sender {} for {}", sender, username);

        self.users.get_mut(username)
            .ok_or_else(|| anyhow!("user {} not found", username))?
            .allow_send_as
            .remove::<String>(&sender.into());

        Ok(())
    }

    /// List all entries in a users  allowed senders list.
    /// username: username to list for.
    pub fn list_user_send_as(&self, username: &str) -> anyhow::Result<impl ExactSizeIterator<Item=&String>>
    {
        Ok(
            self.users.get(username)
                .ok_or_else(|| anyhow!("user {} not found", username))?
                .allow_send_as
                .iter()
        )
    }

    /// verify user is allowed to send using the given address.
    /// username: username to match to.
    /// sender: sender address to check.
    pub(crate) fn verify_user_can_send_as(&self, username: &str, sender: &str) -> anyhow::Result<()>
    {
        let sender = sender.to_lowercase();

        // check for username match
        if sender == username.to_lowercase() {
            return Ok(());
        }

        // check allow_send_as
        let user = &self.users.get(username)
            .ok_or_else(|| anyhow!("user {} not found", username))?;

        for entry in &user.allow_send_as {
            let entry = entry.to_lowercase();

            // domain match
            if let Some(domain) = entry.strip_prefix("*@") {
                if sender.ends_with(domain) {
                    return Ok(());
                }
            }
            // exact match
            else if entry == sender {
                return Ok(());
            }
        }

        anyhow::bail!("user {} not allowed to send as {}", username, sender);
    }
}
// endregion


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_user_auth() -> anyhow::Result<()>
    {
        let mut auth = UserList::default();

        // add two users
        auth.set_user_password("alice", "hunter2")?;
        auth.set_user_password("bob", "password")?;

        // users are tested for
        assert!(auth.has_users());
        assert!(auth.has_user("alice"));
        assert!(auth.has_user("bob"));

        // correct passwords
        assert!(auth.verify_user_password("alice", "hunter2").is_ok());
        assert!(auth.verify_user_password("bob", "password").is_ok());

        // wrong password
        assert!(auth.verify_user_password("alice", "password").is_err());

        // cannot verify after removal
        auth.remove_user("alice")?;
        assert!(auth.verify_user_password("alice", "hunter2").is_err());

        Ok(())
    }

    #[test]
    fn test_user_serialize() -> anyhow::Result<()>
    {
        let mut auth = UserList::default();

        auth.set_user_password("alice", "hunter2")?;
        assert!(auth.verify_user_password("alice", "hunter2").is_ok());

        let yaml = yaml_serde::to_string(&auth)?;
        let auth: UserList = yaml_serde::from_str(&yaml)?;

        assert!(auth.verify_user_password("alice", "hunter2").is_ok());

        Ok(())
    }

    #[test]
    fn test_check_send_as() -> anyhow::Result<()>
    {
        let mut auth = UserList::default();

        auth.set_user_password("alice@example.com", "hunter2")?;
        auth.add_user_send_as("alice@example.com", "bob@example.com")?;

        assert!(auth.verify_user_can_send_as("alice@example.com", "alice@example.com").is_ok());
        assert!(auth.verify_user_can_send_as("alice@example.com", "bob@example.com").is_ok());
        assert!(auth.verify_user_can_send_as("alice@example.com", "eve@example.com").is_err());

        // don't case about case
        assert!(auth.verify_user_can_send_as("alice@example.com", "ALICE@Example.com").is_ok());
        assert!(auth.verify_user_can_send_as("alice@example.com", "BOB@example.com").is_ok());

        auth.remove_user_send_as("alice@example.com", "bob@example.com")?;

        assert!(auth.verify_user_can_send_as("alice@example.com", "bob@example.com").is_err());

        Ok(())
    }

    #[test]
    fn test_check_send_as_domain() -> anyhow::Result<()>
    {
        let mut auth = UserList::default();

        auth.set_user_password("alice@example.com", "hunter2")?;
        auth.add_user_send_as("alice@example.com", "*@example.com")?;

        assert!(auth.verify_user_can_send_as("alice@example.com", "alice@example.com").is_ok());
        assert!(auth.verify_user_can_send_as("alice@example.com", "bob@example.com").is_ok());
        assert!(auth.verify_user_can_send_as("alice@example.com", "eve@example.com").is_ok());
        assert!(auth.verify_user_can_send_as("alice@example.com", "eve@example.org").is_err());

        // don't care about case
        assert!(auth.verify_user_can_send_as("alice@example.com", "BOB@Example.com").is_ok());

        Ok(())
    }
}
