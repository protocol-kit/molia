//! Per-shard lock-free counters and a low-priority aggregator snapshot.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default)]
pub struct ShardMetrics {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub lookups: AtomicU64,
    pub lookup_ok: AtomicU64,
    pub store_ok: AtomicU64,
    pub store_reject: AtomicU64,
    pub drops_malformed: AtomicU64,
    pub drops_rate: AtomicU64,
    pub wg_decap_ok: AtomicU64,
    pub wg_decap_fail: AtomicU64,
    pub pow_fail: AtomicU64,
    pub cookies: AtomicU64,
    pub punch_ok: AtomicU64,
    pub relay_bytes: AtomicU64,
}

impl ShardMetrics {
    pub fn incr(a: &AtomicU64) {
        a.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(a: &AtomicU64, n: u64) {
        a.fetch_add(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            lookups: self.lookups.load(Ordering::Relaxed),
            lookup_ok: self.lookup_ok.load(Ordering::Relaxed),
            store_ok: self.store_ok.load(Ordering::Relaxed),
            store_reject: self.store_reject.load(Ordering::Relaxed),
            drops_malformed: self.drops_malformed.load(Ordering::Relaxed),
            drops_rate: self.drops_rate.load(Ordering::Relaxed),
            wg_decap_ok: self.wg_decap_ok.load(Ordering::Relaxed),
            wg_decap_fail: self.wg_decap_fail.load(Ordering::Relaxed),
            pow_fail: self.pow_fail.load(Ordering::Relaxed),
            cookies: self.cookies.load(Ordering::Relaxed),
            punch_ok: self.punch_ok.load(Ordering::Relaxed),
            relay_bytes: self.relay_bytes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub lookups: u64,
    pub lookup_ok: u64,
    pub store_ok: u64,
    pub store_reject: u64,
    pub drops_malformed: u64,
    pub drops_rate: u64,
    pub wg_decap_ok: u64,
    pub wg_decap_fail: u64,
    pub pow_fail: u64,
    pub cookies: u64,
    pub punch_ok: u64,
    pub relay_bytes: u64,
}

pub fn aggregate(shards: &[Arc<ShardMetrics>]) -> Snapshot {
    let mut t = Snapshot::default();
    for s in shards {
        let x = s.snapshot();
        t.rx_packets += x.rx_packets;
        t.tx_packets += x.tx_packets;
        t.rx_bytes += x.rx_bytes;
        t.tx_bytes += x.tx_bytes;
        t.lookups += x.lookups;
        t.lookup_ok += x.lookup_ok;
        t.store_ok += x.store_ok;
        t.store_reject += x.store_reject;
        t.drops_malformed += x.drops_malformed;
        t.drops_rate += x.drops_rate;
        t.wg_decap_ok += x.wg_decap_ok;
        t.wg_decap_fail += x.wg_decap_fail;
        t.pow_fail += x.pow_fail;
        t.cookies += x.cookies;
        t.punch_ok += x.punch_ok;
        t.relay_bytes += x.relay_bytes;
    }
    t
}

/// Prometheus text exposition (no HTTP server; caller may serve).
pub fn prometheus_text(s: &Snapshot) -> String {
    format!(
        "molia_rx_packets {}\nmolia_tx_packets {}\nmolia_lookups {}\nmolia_lookup_ok {}\nmolia_store_ok {}\nmolia_drops_malformed {}\nmolia_wg_decap_ok {}\nmolia_pow_fail {}\n",
        s.rx_packets, s.tx_packets, s.lookups, s.lookup_ok, s.store_ok, s.drops_malformed, s.wg_decap_ok, s.pow_fail
    )
}
