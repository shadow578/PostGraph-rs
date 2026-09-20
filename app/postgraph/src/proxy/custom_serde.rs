use serde::{Deserialize, Deserializer, Serializer};
use std::time::Duration;

/// Option<Duration> serialization and deserialization as seconds integer.
pub(crate) mod opt_duration_secs {
    use super::*;
    use serde::Serialize;

    pub fn serialize<S>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        d.map(|d| d.as_secs())
            .serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<u64>::deserialize(d)
            .map(|opt| opt.map(Duration::from_secs))
    }
}
