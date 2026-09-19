use anyhow::anyhow;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use log::debug;
use password_hash::PasswordHasher;
use serde;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct UserList
{
    users: HashMap<String, UserEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserEntry
{
    #[serde(
        serialize_with = "serialize_password_hash",
        deserialize_with = "deserialize_password_hash"
    )]
    password: PasswordHash,
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

        self.users.insert(username.into(), UserEntry { password: hash });

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
}
