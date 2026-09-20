use log::{debug, trace, warn};
use std::collections::HashMap;
use std::fmt::Display;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq)]
pub(crate) enum Verdict
{
    /// peer can be accepted.
    Ok,

    /// peer has too many active connections.
    TooManyConnections,

    /// peer has to many failed sessions on record.
    TooManyFails,

    /// peer has no records, cannot form verdict.
    /// (you likely did something wrong and called .should_reject before .push_connection).
    NoRecord,
}

impl Display for Verdict
{
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Verdict::Ok => write!(fmt, "OK"),
            Verdict::TooManyConnections => write!(fmt, "Too many connections"),
            Verdict::TooManyFails => write!(fmt, "Too many fails"),
            Verdict::NoRecord => write!(fmt, "No record"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct PeerInfo
{
    /// how many active connections this peer is currently holding.
    connections: u32,

    /// how many fails this peer stacked up.
    fails: u32,

    /// time of the most recent activity of this peer.
    time: Instant,
}

#[derive(Debug)]
pub(crate) struct Fail2Ban
{
    /// maximum number of connections a peer is allowed.
    max_connections: u32,

    /// maximum number of fails before peer is banned.
    max_fails: u32,

    /// time before a peers fails are forgotten.
    max_age: Duration,

    /// record of peers and their fails.
    peers: HashMap<IpAddr, PeerInfo>,
}

impl Fail2Ban
{
    /// create a new instance.
    /// max_connections: maximum number of connections a peer is allowed to hold.
    /// max_fails: maximum number of fails before peer is banned.
    /// max_age: time before a peers is forgotten.
    pub(crate) fn new(max_connections: u32, max_fails: u32, max_age: Duration) -> Self
    {
        Self {
            max_connections,
            max_fails,
            max_age,
            peers: HashMap::new(),
        }
    }

    /// Record a new connection by a peer.
    /// peer: the peer to record.
    pub(crate) fn push_connection(&mut self, peer: IpAddr)
    {
        let connections = if let Some(info) = self.peers.get_mut(&peer) {
            info.connections += 1;
            info.time = Instant::now();
            info.connections
        } else {
            let info = PeerInfo {
                connections: 1,
                fails: 0,
                time: Instant::now(),
            };
            self.peers.insert(peer, info);
            1
        };

        debug!("Recorded new connection for peer {}. They have {} active connection(s)", peer, connections);
    }

    /// Record a new connection close for a peer.
    /// peer: the peer to record.
    pub(crate) fn pop_connection(&mut self, peer: IpAddr)
    {
        if let Some(info) = self.peers.get_mut(&peer) {
            info.connections -= 1;
            debug!("Recorded disconnection for peer {}. They now have {} active connection(s)", peer, info.connections);
        }
    }

    /// Record a new failure for a peer.
    /// peer: IP to record a fail for.
    pub(crate) fn push_fail(&mut self, peer: IpAddr) {
        // note: peer should already be known from push_connection
        if let Some(info) = self.peers.get_mut(&peer) {
            info.fails += 1;
            info.time = Instant::now();
            debug!("Recorded new fail for peer {}. They now have {} fail(s)", peer, info.fails);
        }
    }

    /// check if a peer IP has reached fail thresholds, resulting in their ban.
    /// note: this function will also clean up old peer fails.
    /// peer: IP to check for.
    pub(crate) fn get_verdict(&mut self, peer: IpAddr) -> Verdict {
        // remove old fails
        self.peers.retain(|_, info| info.time.elapsed() <= self.max_age);

        // get verdict for this peer
        if let Some(info) = self.peers.get(&peer) {
            let verdict = if info.fails > self.max_fails {
                Verdict::TooManyFails
            } else if info.connections > self.max_connections {
                Verdict::TooManyConnections
            } else {
                Verdict::Ok
            };

            trace!("Validating peer {} /w {} connections and {} fails; verdict={}",
                peer,
                info.connections,
                info.fails,
                verdict
            );

            verdict
        } else {
            warn!("Failing peer {} because no record found. \
            If you see this, you likely did something wrong. \
            Fail2Ban::push_connection must be called before Fail2Ban::should_reject!", peer);
            Verdict::NoRecord
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn get_mock_ip(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(169, 1, 2, d))
    }

    #[test]
    fn test_nice_client()
    {
        let mut fail2ban = Fail2Ban::new(5, 5, Duration::from_secs(60));

        fail2ban.push_connection(get_mock_ip(1));
        assert_eq!(fail2ban.get_verdict(get_mock_ip(1)), Verdict::Ok);
    }

    #[test]
    fn test_too_many_connections()
    {
        let mut fail2ban = Fail2Ban::new(5, 5, Duration::from_secs(60));

        // fill all five allowed connections
        for _ in 0..5 {
            fail2ban.push_connection(get_mock_ip(1));
        }

        // on the 5th connection, everything is still fine
        assert_eq!(fail2ban.get_verdict(get_mock_ip(1)), Verdict::Ok);

        // on the 6th connection, we get banned
        fail2ban.push_connection(get_mock_ip(1));
        assert_eq!(fail2ban.get_verdict(get_mock_ip(1)), Verdict::TooManyConnections);
    }

    #[test]
    fn test_too_many_fails()
    {
        let mut fail2ban = Fail2Ban::new(5, 5, Duration::from_secs(60));

        // fill all five allowed fails, each in a separate connection that is then dropped
        for _ in 0..5 {
            fail2ban.push_connection(get_mock_ip(1));
            fail2ban.push_fail(get_mock_ip(1));
            fail2ban.pop_connection(get_mock_ip(1));
        }

        // we're still fine here, tho we're at the last strike
        fail2ban.push_connection(get_mock_ip(1));
        assert_eq!(fail2ban.get_verdict(get_mock_ip(1)), Verdict::Ok);

        // fail again
        fail2ban.push_fail(get_mock_ip(1));
        fail2ban.pop_connection(get_mock_ip(1));

        // now we're banned
        fail2ban.push_connection(get_mock_ip(1));
        assert_eq!(fail2ban.get_verdict(get_mock_ip(1)), Verdict::TooManyFails);
    }

    #[test]
    fn test_no_record()
    {
        let mut fail2ban = Fail2Ban::new(5, 5, Duration::from_secs(60));

        // push_connection() must be called before get_verdict.
        // if this is not the case, we fail closed.
        assert_eq!(fail2ban.get_verdict(get_mock_ip(1)), Verdict::NoRecord);
    }
}
