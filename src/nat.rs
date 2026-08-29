//! NAT classification, keepalives, rendezvous hints, and hole-punch windows.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub const KEEPALIVE: Duration = Duration::from_secs(20);
pub const CONSENT_TTL: Duration = Duration::from_secs(30 * 60);
pub const RELAY_BUDGET_NUM: u64 = 1;
pub const RELAY_BUDGET_DEN: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatType {
    FullCone,
    Restricted,
    PortRestricted,
    Symmetric,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct EndpointHint {
    pub declared: SocketAddr,
    pub observed: Option<SocketAddr>,
    pub last_ok: Instant,
}

impl EndpointHint {
    pub fn fresh(&self) -> bool {
        self.last_ok.elapsed() < CONSENT_TTL
    }
}

pub fn classify(declared: SocketAddr, observed: SocketAddr) -> NatType {
    if declared.ip() == observed.ip() && declared.port() == observed.port() {
        NatType::FullCone
    } else if declared.ip() == observed.ip() {
        NatType::PortRestricted
    } else {
        NatType::Symmetric
    }
}

/// Timed simultaneous-open window (2 × 250 ms jitter).
pub fn punch_deadlines(now: Instant) -> [Instant; 2] {
    [now + Duration::from_millis(250), now + Duration::from_millis(500)]
}

pub struct RelayBudget {
    egress: u64,
    relayed: u64,
}

impl RelayBudget {
    pub fn new() -> Self {
        Self {
            egress: 0,
            relayed: 0,
        }
    }

    pub fn allow(&mut self, bytes: u64) -> bool {
        let next = self.relayed + bytes;
        if self.egress == 0 {
            self.relayed = next;
            return true;
        }
        if next * RELAY_BUDGET_DEN <= self.egress * RELAY_BUDGET_NUM + self.egress {
            self.relayed = next;
            true
        } else {
            false
        }
    }

    pub fn on_egress(&mut self, bytes: u64) {
        self.egress += bytes;
    }
}

impl Default for RelayBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn classify_same_is_full_cone() {
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        assert_eq!(classify(a, a), NatType::FullCone);
    }

    #[test]
    fn relay_budget_caps() {
        let mut b = RelayBudget::new();
        b.on_egress(1000);
        assert!(b.allow(50));
        assert!(!b.allow(10_000));
    }
}
