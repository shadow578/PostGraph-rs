use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

/// List of IP networks to allow / disallow.
#[derive(Debug, Clone)]
pub struct IpNetList
{
    nets: HashSet<IpNet>,
}

// region: Serialize / Deserialize
impl Serialize for IpNetList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let nets: HashSet<String> = self
            .nets
            .iter()
            .map(|net| net.to_string())
            .collect();

        nets.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IpNetList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let nets: HashSet<String> = HashSet::deserialize(deserializer)?;
        let nets = nets
            .into_iter()
            .map(|net| {
                IpNet::from_str(&net)
            })
            .filter(|r| r.is_ok())
            .flatten()
            .collect();

        Ok(Self { nets })
    }
}
// endregion

impl IpNetList
{
    /// create new IpNetList instance without any networks set.
    pub fn new() -> Self
    {
        Self { nets: HashSet::new() }
    }

    /// add a new network to the list.
    /// net: IP network to add.
    pub fn add(&mut self, net: IpNet)
    {
        self.nets.insert(net);
    }

    /// remove a network from the list.
    /// net: IP network to remove.
    pub fn remove(&mut self, net: IpNet)
    {
        self.nets.retain(|n| *n != net);
    }

    /// does the network list contain the given IP address?
    /// peer: IP address to check for.
    pub fn contains(&self, peer: IpAddr) -> bool
    {
        for net in self.nets.iter() {
            if net.contains(&peer)
            {
                return true;
            }
        }

        false
    }

    /// iterate over IP network list.
    pub fn iter(&self) -> impl Iterator<Item=&IpNet>
    {
        self.nets.iter()
    }

    /// does this list contain any elements?
    pub fn is_empty(&self) -> bool
    {
        self.nets.is_empty()
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_peer_check() -> anyhow::Result<()>
    {
        let mut list = IpNetList::new();

        // add allowed nets
        list.add("192.168.1.1/24".parse()?);
        list.add("10.0.0.0/16".parse()?);
        list.add("10.10.0.1/32".parse()?);


        // valid peers
        assert!(list.contains("192.168.1.16".parse()?));
        assert!(list.contains("192.168.1.254".parse()?));
        assert!(list.contains("10.0.0.10".parse()?));
        assert!(list.contains("10.0.10.10".parse()?));
        assert!(list.contains("10.10.0.1".parse()?));

        // invalid peers
        assert!(!list.contains("192.168.2.16".parse()?));
        assert!(!list.contains("80.86.86.16".parse()?));

        Ok(())
    }

    #[test]
    fn test_serialize() -> anyhow::Result<()>
    {
        let mut list = IpNetList::new();

        list.add("10.10.0.1/32".parse()?);
        assert!(list.contains("10.10.0.1".parse()?));

        let yaml = yaml_serde::to_string(&list)?;
        let list: IpNetList = yaml_serde::from_str(&yaml)?;

        assert!(list.contains("10.10.0.1".parse()?));

        Ok(())
    }
}
