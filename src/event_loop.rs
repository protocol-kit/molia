//! Custom single-threaded shard reactor: poll UDP, timers, and command rings. No Tokio.

use polling::{Event, Events, Poller};
use std::collections::BinaryHeap;
use std::cmp::Reverse;
use std::io;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use crate::udp::{register_socket, reregister_readable, UdpIo};

pub const DRAIN_BATCH: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TimerKind {
    Keepalive,
    PeerstoreFlush,
    Gc,
    LookupTick,
    Punch,
}

#[derive(Eq, PartialEq)]
struct Timer(Reverse<Instant>, TimerKind);

impl Ord for Timer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0).then(self.1.cmp(&other.1))
    }
}

impl PartialOrd for Timer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub struct TimingWheel {
    heap: BinaryHeap<Timer>,
}

impl TimingWheel {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
        }
    }

    pub fn schedule(&mut self, at: Instant, kind: TimerKind) {
        self.heap.push(Timer(Reverse(at), kind));
    }

    pub fn pop_due(&mut self, now: Instant) -> Vec<TimerKind> {
        let mut out = Vec::new();
        while let Some(Timer(Reverse(t), k)) = self.heap.peek() {
            if *t <= now {
                out.push(*k);
                self.heap.pop();
            } else {
                break;
            }
        }
        out
    }

    pub fn next_timeout(&self, now: Instant) -> Option<Duration> {
        self.heap.peek().map(|Timer(Reverse(t), _)| t.saturating_duration_since(now))
    }
}

pub fn wait(
    poller: &Poller,
    io: &UdpIo,
    events: &mut Events,
    timeout: Option<Duration>,
) -> io::Result<bool> {
    events.clear();
    poller.wait(events, timeout)?;
    let readable = events.iter().any(|e: Event| e.key == 0 && e.readable);
    let _ = reregister_readable(poller, io, 0);
    Ok(readable)
}

pub fn setup_poller(io: &UdpIo) -> io::Result<(Poller, Events)> {
    let poller = Poller::new()?;
    register_socket(&poller, io, 0)?;
    Ok((poller, Events::new()))
}

/// Non-blocking drain of a command ring (at-most-once).
pub fn drain_cmds<T>(rx: &Receiver<T>, max: usize) -> Vec<T> {
    let mut out = Vec::new();
    for _ in 0..max {
        match rx.try_recv() {
            Ok(c) => out.push(c),
            Err(_) => break,
        }
    }
    out
}
