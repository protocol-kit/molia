//! Per-shard buffer pool and lookup scratch arena.

use crate::types::PMTU_FLOOR;
use std::cell::RefCell;

pub const BUFFER_SIZE: usize = 2048;
const POOL_CAP: usize = 256;

pub struct BufferPool {
    free: RefCell<Vec<Vec<u8>>>,
    hits: RefCell<u64>,
    misses: RefCell<u64>,
}

impl BufferPool {
    pub fn new() -> Self {
        let mut free = Vec::with_capacity(POOL_CAP);
        for _ in 0..64 {
            free.push(vec![0u8; BUFFER_SIZE]);
        }
        Self {
            free: RefCell::new(free),
            hits: RefCell::new(0),
            misses: RefCell::new(0),
        }
    }

    pub fn take(&self) -> Vec<u8> {
        if let Some(mut b) = self.free.borrow_mut().pop() {
            *self.hits.borrow_mut() += 1;
            b.clear();
            b.resize(BUFFER_SIZE, 0);
            b
        } else {
            *self.misses.borrow_mut() += 1;
            vec![0u8; BUFFER_SIZE]
        }
    }

    pub fn recycle(&self, mut buf: Vec<u8>) {
        if buf.capacity() >= PMTU_FLOOR && self.free.borrow().len() < POOL_CAP {
            buf.clear();
            self.free.borrow_mut().push(buf);
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (*self.hits.borrow(), *self.misses.borrow())
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Bump arena for one lookup; reset in O(1) by clearing the cursor.
pub struct LookupArena {
    buf: Vec<u8>,
    cursor: usize,
}

impl LookupArena {
    pub fn with_capacity(n: usize) -> Self {
        Self {
            buf: vec![0u8; n],
            cursor: 0,
        }
    }

    pub fn alloc(&mut self, n: usize) -> Option<&mut [u8]> {
        if self.cursor + n > self.buf.len() {
            return None;
        }
        let start = self.cursor;
        self.cursor += n;
        Some(&mut self.buf[start..self.cursor])
    }

    pub fn reset(&mut self) {
        self.cursor = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_reuses_after_warmup() {
        let pool = BufferPool::new();
        let a = pool.take();
        pool.recycle(a);
        let _b = pool.take();
        let (hits, _) = pool.stats();
        assert!(hits >= 2);
    }

    #[test]
    fn arena_reset_is_reuse() {
        let mut a = LookupArena::with_capacity(128);
        let _ = a.alloc(16).unwrap();
        a.reset();
        assert!(a.alloc(128).is_some());
    }
}
