//! Two-hop relay (off by default) and TURN-like last-resort forwarding budgets.

use crate::nat::RelayBudget;
use crate::types::NodeId;
use std::net::SocketAddr;

pub struct RelayState {
    pub enabled: bool,
    pub budget: RelayBudget,
    pub prefer_control: bool,
}

impl RelayState {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            budget: RelayBudget::new(),
            prefer_control: true,
        }
    }

    pub fn forward(&mut self, bytes: usize, control: bool) -> bool {
        if !self.enabled && !control {
            return false;
        }
        self.budget.on_egress(bytes as u64);
        self.budget.allow(bytes as u64)
    }
}

/// Pick a disjoint-bucket relay: first peer whose XOR bucket differs from dest.
pub fn pick_relay(self_id: NodeId, dest: NodeId, candidates: &[(NodeId, SocketAddr)]) -> Option<SocketAddr> {
    let db = crate::types::bucket_index(&self_id, &dest);
    candidates
        .iter()
        .find(|(id, _)| crate::types::bucket_index(&self_id, id) != db)
        .map(|(_, a)| *a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn default_off_blocks_data() {
        let mut r = RelayState::new(false);
        assert!(!r.forward(100, false));
    }

    #[test]
    fn pick_skips_same_bucket() {
        let self_id = NodeId([0; 32]);
        let mut dest = [0u8; 32];
        dest[0] = 0x80;
        let mut same = dest;
        same[31] = 1;
        let mut other = [0u8; 32];
        other[0] = 0x01;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let got = pick_relay(self_id, NodeId(dest), &[(NodeId(same), addr), (NodeId(other), addr)]);
        assert!(got.is_some());
    }
}
