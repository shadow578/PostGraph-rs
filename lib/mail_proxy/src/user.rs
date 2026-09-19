use anyhow::anyhow;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use log::debug;
use password_hash::PasswordHasher;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::collections::hash_map::Keys;

#[derive(Debug, Clone)]
pub struct UserList
{
    users: HashMap<String, PasswordHash>,
}

// region: Serialize / Deserialize
impl Serialize for UserList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let users: HashMap<String, String> = self
            .users
            .iter()
            .map(|(username, hash)| (username.clone(), hash.to_string()))
            .collect();

        users.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UserList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let users: HashMap<String, String> = HashMap::deserialize(deserializer)?;
        let users = users
            .into_iter()
            .map(|(username, hash)| {
                PasswordHash::new(hash.as_str())
                    .map(|hash| (username, hash))
            })
            .filter(|r| r.is_ok())
            .flatten()
            .collect();

        Ok(Self { users })
    }
}
// endregion

// region: auth API
impl UserList
{
    // create a new UserAuth instance without any users configured.
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    /// add or update user entry.
    /// username: username to add or modify.
    /// password: new password to set.
    pub fn set_user_password(&mut self, username: &str, password: &str) -> anyhow::Result<()>
    {
        debug!("Updating user password for {}", username);

        let hash = Argon2::default()
            .hash_password(password.as_bytes())
            .map_err(|_| anyhow!("could not set password"))?;

        self.users.insert(username.into(), hash);

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
    pub fn list_users(&self) -> Keys<'_, String, PasswordHash>
    {
        self.users.keys()
    }

    /// verify username exists and password is correct.
    /// username: username to match to.
    /// password: clear-text password to validate is correct.
    pub(crate) fn verify_user_password(&self, username: &str, password: &str) -> anyhow::Result<()>
    {
        let hash = self.users.get(username).ok_or_else(|| anyhow!("user {} not found", username))?;

        Argon2::default()
            .verify_password(password.as_bytes(), hash)
            .map_err(|_| anyhow!("invalid password"))?;

        Ok(())
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
        let mut auth = UserList::new();

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
        let mut auth = UserList::new();

        auth.set_user_password("alice", "hunter2")?;
        assert!(auth.verify_user_password("alice", "hunter2").is_ok());

        let yaml = yaml_serde::to_string(&auth)?;
        let auth: UserList = yaml_serde::from_str(&yaml)?;

        assert!(auth.verify_user_password("alice", "hunter2").is_ok());

        Ok(())
    }
}
