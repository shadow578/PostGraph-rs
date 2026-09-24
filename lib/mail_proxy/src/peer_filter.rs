use anyhow::{Result, anyhow};
use ipnet::IpNet;
use log::error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Actions for a FilterRule.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum PeerAction
{
    /// Allow connections from the subnet.
    Allow,

    /// Deny connections from the subnet.
    Deny,
}

/// Provides facilities for filtering peer connections against a configurable ruleset.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerFilter
{
    /// list of rules configured in the filter.
    rules: Vec<FilterRule>,
}

impl PeerFilter
{
    /// Create a new PeerFilter containing two allow any rules ("ALLOW:0.0.0.0/0" and "ALLOW:::/0").
    pub fn new_allow_any() -> Self
    {
        let allow_any_ipv4 = FilterRule::new(
            PeerAction::Allow,
            IpNet::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0).unwrap(), // net is ok, will never panic during unwrap
        );
        let allow_any_ipv6 = FilterRule::new(
            PeerAction::Allow,
            IpNet::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(), 0).unwrap(), // net is ok, will never panic during unwrap
        );

        let mut filter = Self::default();
        filter.add(allow_any_ipv4);
        filter.add(allow_any_ipv6);
        filter
    }

    /// Insert a new rule to the ruleset.
    /// rule: Rule to add.
    pub fn add(&mut self, rule: FilterRule) -> bool
    {
        // don't insert if equal rule exists
        if !self.rules.contains(&rule) {
            self.rules.push(rule);
            true
        } else {
            false
        }
    }

    /// Remove a rule from the ruleset.
    /// rule: Rule to remove.
    pub fn remove(&mut self, rule: &FilterRule)
    {
        self.rules.retain(|x| *x != *rule);
    }

    /// Evaluate all rules.
    /// ip: IP address to evaluate ruleset for.
    pub fn evaluate(&self, ip: &IpAddr) -> PeerAction
    {
        if let Some((action, _)) = self.evaluate_with_context(ip) {
            return action;
        }

        // should never get here due to implicit deny any in iter().
        // if we do anyway, reject and continue on.
        error!("evaluate() did not match ANY rule. This should not happen, ever.");
        PeerAction::Deny
    }

    /// Evaluate all rules, returning context for the rule that matched.
    /// ip: IP address to evaluate ruleset for.
    pub fn evaluate_with_context(&self, ip: &IpAddr) -> Option<(PeerAction, FilterRule)>
    {
        for rule in self.iter() {
            if let Some(action) = rule.evaluate(ip) {
                return Some((action, rule));
            }
        }

        None
    }

    /// Iterate over the ruleset in order of evaluation.
    /// This will also add an implicit DENY:0.0.0.0/0 rule to the end.
    pub fn iter(&self) -> impl Iterator<Item=FilterRule>
    {
        let deny_any_ipv4 = FilterRule::new(
            PeerAction::Deny,
            IpNet::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0).unwrap(), // net is ok, will never panic during unwrap
        );
        let deny_any_ipv6 = FilterRule::new(
            PeerAction::Deny,
            IpNet::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(), 0).unwrap(), // net is ok, will never panic during unwrap
        );

        let mut indices: Vec<_> = (0..self.rules.len()).collect();
        indices.sort_by(|&a, &b| Self::filter_rule_cmp(&self.rules[a], &self.rules[b]));

        indices
            .into_iter()
            .map(|i| self.rules[i])
            .chain(std::iter::once(deny_any_ipv4))
            .chain(std::iter::once(deny_any_ipv6))
    }

    /// Are there no rules configured in this filter?
    pub fn is_empty(&self) -> bool
    {
        self.rules.is_empty()
    }


    /// Ordering function for evaluation ordering of FilterRule.
    fn filter_rule_cmp(a: &FilterRule, b: &FilterRule) -> Ordering {
        fn get_ord(r: &FilterRule) -> usize {
            let mut v = (r.target.prefix_len() as usize) << 1;
            if r.action == PeerAction::Allow {
                v += 1;
            }
            v
        }

        // a and b are reversed here to invert ordering
        get_ord(b).cmp(&get_ord(a))
    }
}

impl Default for PeerFilter
{
    /// Construct a PeerFilter instance with no rules.
    fn default() -> Self
    {
        Self { rules: Vec::new() }
    }
}

// region: FilterRule
/// A filter rule applying to a single IP subnet.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct FilterRule
{
    /// The action to perform.
    action: PeerAction,

    /// The targeted IP subnet.
    target: IpNet,
}

impl FilterRule
{
    /// Create a new filter rule.
    /// action: The action to perform.
    /// target: The targeted IP subnet.
    pub fn new(action: PeerAction, target: IpNet) -> Self
    {
        FilterRule { action, target }
    }

    /// Parse a rule from a rule string as provided by to_string().
    /// str: Rule string to parse.
    fn from_string(str: &str) -> Result<Self>
    {
        let (action, target) = str.split_once(":")
            .ok_or_else(|| anyhow!("invalid filter rule syntax"))?;

        let action = match action.to_uppercase().as_str() {
            "ALLOW" => PeerAction::Allow,
            "DENY" => PeerAction::Deny,
            _ => anyhow::bail!("invalid filter action '{}'", action),
        };
        let target = IpNet::from_str(target)?;

        Ok(Self { action, target })
    }

    /// Evaluate this rule.
    /// ip: peer IP to evaluate against.
    fn evaluate(&self, ip: &IpAddr) -> Option<PeerAction>
    {
        if self.target.contains(ip) {
            Some(self.action)
        } else {
            None
        }
    }
}

impl Display for FilterRule
{
    /// Convert this rule to a string like "ALLOW:0.0.0.0/0".
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let action = match self.action {
            PeerAction::Allow => "ALLOW",
            PeerAction::Deny => "DENY",
        };
        write!(f, "{}:{}", action, self.target)
    }
}

impl Serialize for FilterRule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FilterRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let rule = String::deserialize(deserializer)?;
        FilterRule::from_string(&rule)
            .map_err(serde::de::Error::custom)
    }
}
// endregion


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_rule_ordering() -> Result<()>
    {
        let host_allow = FilterRule::new(PeerAction::Allow, "10.0.0.1/32".parse()?);
        let host_deny = FilterRule::new(PeerAction::Deny, "10.0.0.1/32".parse()?);
        let net_allow = FilterRule::new(PeerAction::Allow, "10.10.0.1/16".parse()?);
        let net_deny = FilterRule::new(PeerAction::Deny, "10.10.0.1/16".parse()?);
        let any_allow = FilterRule::new(PeerAction::Allow, "0.0.0.0/0".parse()?);
        let any_deny = FilterRule::new(PeerAction::Deny, "0.0.0.0/0".parse()?);

        // ordering should be most specific first, allow before deny:
        // host_allow
        // host_deny
        // net_allow
        // net_deny
        // any_allow
        // any_deny
        assert_eq!(PeerFilter::filter_rule_cmp(&host_allow, &host_deny), Ordering::Less);
        assert_eq!(PeerFilter::filter_rule_cmp(&host_deny, &net_allow), Ordering::Less);
        assert_eq!(PeerFilter::filter_rule_cmp(&net_allow, &net_deny), Ordering::Less);
        assert_eq!(PeerFilter::filter_rule_cmp(&net_deny, &any_allow), Ordering::Less);
        assert_eq!(PeerFilter::filter_rule_cmp(&any_allow, &any_deny), Ordering::Less);

        // check against behaviour of PeerFilter iter()
        let mut filter = PeerFilter::default();
        filter.add(host_allow);
        filter.add(host_deny);
        filter.add(net_allow);
        filter.add(net_deny);
        filter.add(any_allow);
        filter.add(any_deny);

        let filter: Vec<_> = filter.iter().collect();
        assert_eq!(filter[0], host_allow);
        assert_eq!(filter[1], host_deny);
        assert_eq!(filter[2], net_allow);
        assert_eq!(filter[3], net_deny);
        assert_eq!(filter[4], any_allow);
        assert_eq!(filter[5], any_deny);

        Ok(())
    }

    #[test]
    fn test_filter_rule_from_to_string() -> Result<()>
    {
        let rule = FilterRule::from_string("ALLOW:0.0.0.0/0")?;
        assert_eq!(rule.action, PeerAction::Allow);
        assert_eq!(rule.target, "0.0.0.0/0".parse()?);

        let rule = FilterRule::from_string("DENY:10.10.0.10/32")?;
        assert_eq!(rule.action, PeerAction::Deny);
        assert_eq!(rule.target, "10.10.0.10/32".parse()?);

        let rule = FilterRule::from_string("ALLOW:10.10.1.1/16")?;
        assert_eq!(rule.action, PeerAction::Allow);
        assert_eq!(rule.target, "10.10.1.1/16".parse()?);

        assert!(FilterRule::from_string("").is_err()); // empty string
        assert!(FilterRule::from_string("DENY").is_err()); // no target
        assert!(FilterRule::from_string("DENY:10.10.0.1").is_err()); // target not a subnet
        assert!(FilterRule::from_string("DENY:10.10.0.1/33").is_err()); // subnet prefix invalid
        assert!(FilterRule::from_string(":10.10.0.1/32").is_err()); // no action
        assert!(FilterRule::from_string("BOB:10.10.0.1/32").is_err()); // invalid action

        Ok(())
    }

    #[test]
    fn test_peer_filtering_ipv4() -> Result<()>
    {
        let mut filter = PeerFilter::default();

        // allow all peers in subnet 10.10.0.0/16 EXCEPT for subnet 10.10.1.0/24 and host 10.10.2.1/32.
        // also allow host 192.168.100.1.
        filter.add(FilterRule::new(PeerAction::Deny, "10.10.1.0/24".parse()?));
        filter.add(FilterRule::new(PeerAction::Deny, "10.10.2.1/32".parse()?));
        filter.add(FilterRule::new(PeerAction::Allow, "10.10.0.0/16".parse()?));
        filter.add(FilterRule::new(PeerAction::Allow, "192.168.100.1/32".parse()?));

        assert_eq!(filter.evaluate(&"10.10.10.1".parse()?), PeerAction::Allow); // allow due to 10.10.0.0/16
        assert_eq!(filter.evaluate(&"10.10.10.10".parse()?), PeerAction::Allow); // allow due to 10.10.0.0/16
        assert_eq!(filter.evaluate(&"10.10.1.11".parse()?), PeerAction::Deny); // deny due to 10.10.1.0/24
        assert_eq!(filter.evaluate(&"10.10.2.1".parse()?), PeerAction::Deny); // deny due to 10.10.2.1/32
        assert_eq!(filter.evaluate(&"192.168.100.1".parse()?), PeerAction::Allow); // allow due to 192.168.100.1/32
        assert_eq!(filter.evaluate(&"80.10.1.1".parse()?), PeerAction::Deny); // deny because not listed -> implicit DENY:0.0.0.0/0

        Ok(())
    }

    #[test]
    fn test_peer_filtering_ipv6() -> Result<()>
    {
        let mut filter = PeerFilter::default();

        // allow all peers in subnet 2001:db8:10::/48 EXCEPT for subnet
        // 2001:db8:10:1::/64 and host 2001:db8:10:2::1/128.
        // also allow host 2001:db8:100::1.
        filter.add(FilterRule::new(PeerAction::Deny, "2001:db8:10:1::/64".parse()?));
        filter.add(FilterRule::new(PeerAction::Deny, "2001:db8:10:2::1/128".parse()?));
        filter.add(FilterRule::new(PeerAction::Allow, "2001:db8:10::/48".parse()?));
        filter.add(FilterRule::new(PeerAction::Allow, "2001:db8:100::1/128".parse()?));

        assert_eq!(filter.evaluate(&"2001:db8:10:10::1".parse()?), PeerAction::Allow); // allow due to 2001:db8:10::/48
        assert_eq!(filter.evaluate(&"2001:db8:10:10::10".parse()?), PeerAction::Allow); // allow due to 2001:db8:10::/48
        assert_eq!(filter.evaluate(&"2001:db8:10:1::11".parse()?), PeerAction::Deny); // deny due to 2001:db8:10:1::/64
        assert_eq!(filter.evaluate(&"2001:db8:10:2::1".parse()?), PeerAction::Deny); // deny due to 2001:db8:10:2::1/128
        assert_eq!(filter.evaluate(&"2001:db8:100::1".parse()?), PeerAction::Allow); // allow due to 2001:db8:100::1/128
        assert_eq!(filter.evaluate(&"2001:db9::1".parse()?), PeerAction::Deny); // deny because not listed

        Ok(())
    }

    #[test]
    fn test_peer_filtering_precedence() -> Result<()>
    {
        let mut filter = PeerFilter::default();

        // adding an ALLOW:0.0.0.0/0 will still allow denies for more specific entries
        filter.add(FilterRule::new(PeerAction::Allow, "0.0.0.0/0".parse()?));
        filter.add(FilterRule::new(PeerAction::Deny, "10.10.2.1/32".parse()?));

        assert_eq!(filter.evaluate(&"10.10.10.1".parse()?), PeerAction::Allow); // allow due to 0.0.0.0/0
        assert_eq!(filter.evaluate(&"10.10.1.11".parse()?), PeerAction::Allow); // allow due to 0.0.0.0/0
        assert_eq!(filter.evaluate(&"10.10.2.1".parse()?), PeerAction::Deny); // deny due to 10.10.2.1/32

        Ok(())
    }

    #[test]
    fn test_peer_filter_add_remove() -> Result<()>
    {
        let mut filter = PeerFilter::default();

        filter.add(FilterRule::new(PeerAction::Allow, "10.10.1.1/32".parse()?));
        filter.add(FilterRule::new(PeerAction::Allow, "192.168.100.1/32".parse()?));

        assert_eq!(filter.evaluate(&"10.10.1.1".parse()?), PeerAction::Allow);
        assert_eq!(filter.evaluate(&"192.168.100.1".parse()?), PeerAction::Allow);

        filter.remove(&FilterRule::new(PeerAction::Allow, "192.168.100.1/32".parse()?));

        assert_eq!(filter.evaluate(&"10.10.1.1".parse()?), PeerAction::Allow);
        assert_eq!(filter.evaluate(&"192.168.100.1".parse()?), PeerAction::Deny); // no longer included in ruleset

        Ok(())
    }

    #[test]
    fn test_reject_duplicate_rule_add() -> Result<()>
    {
        let host_allow = FilterRule::new(PeerAction::Allow, "10.0.0.1/32".parse()?);
        let host_deny = FilterRule::new(PeerAction::Deny, "10.0.0.1/32".parse()?);

        let mut filter = PeerFilter::default();

        // two unique rules are accepted
        assert!(filter.add(host_allow));
        assert!(filter.add(host_deny));

        // duplicate is ignored
        assert!(!filter.add(host_allow));

        assert_eq!(filter.rules.len(), 2);

        Ok(())
    }

    #[test]
    fn test_peer_filter_serialize() -> anyhow::Result<()>
    {
        let mut filter = PeerFilter::default();

        filter.add(FilterRule::new(PeerAction::Allow, "10.10.1.1/32".parse()?));
        assert_eq!(filter.evaluate(&"10.10.1.1".parse()?), PeerAction::Allow);

        let yaml = yaml_serde::to_string(&filter)?;
        let filter: PeerFilter = yaml_serde::from_str(&yaml)?;

        assert_eq!(filter.evaluate(&"10.10.1.1".parse()?), PeerAction::Allow);
        Ok(())
    }
}
