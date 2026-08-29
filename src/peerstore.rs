//! In-memory peer index plus per-shard WAL (`peerstore/shard-<id>/`).

use crate::types::{NodeId, PeerInfo};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const TYPE_UPSERT: u8 = 1;
pub const TYPE_TOMBSTONE: u8 = 2;
/// Protobuf `Record` (DHT value), same framing as peer rows.
pub const TYPE_RECORD: u8 = 3;

pub struct Peerstore {
    dir: PathBuf,
    peers: HashMap<NodeId, PeerInfo>,
    pending: Vec<WalRecord>,
    wal: Option<File>,
}

struct WalRecord {
    ty: u8,
    payload: Vec<u8>,
}

impl Peerstore {
    pub fn open(base: impl AsRef<Path>, shard: u32) -> io::Result<Self> {
        let dir = base.as_ref().join(format!("shard-{shard}"));
        fs::create_dir_all(&dir)?;
        let mut store = Self {
            dir: dir.clone(),
            peers: HashMap::new(),
            pending: Vec::new(),
            wal: None,
        };
        store.recover()?;
        let wal = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("wal.log"))?;
        store.wal = Some(wal);
        Ok(store)
    }

    pub fn memory() -> Self {
        Self {
            dir: PathBuf::new(),
            peers: HashMap::new(),
            pending: Vec::new(),
            wal: None,
        }
    }

    pub fn upsert(&mut self, info: PeerInfo) {
        self.peers.insert(info.id, info.clone());
        let mut payload = Vec::new();
        payload.extend_from_slice(&info.id.0);
        if let Some(addr) = info.primary_addr() {
            payload.extend_from_slice(addr.to_string().as_bytes());
        }
        self.pending.push(WalRecord {
            ty: TYPE_UPSERT,
            payload,
        });
    }

    pub fn remove(&mut self, id: NodeId) {
        self.peers.remove(&id);
        self.pending.push(WalRecord {
            ty: TYPE_TOMBSTONE,
            payload: id.0.to_vec(),
        });
    }

    pub fn get(&self, id: &NodeId) -> Option<&PeerInfo> {
        self.peers.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values()
    }

    pub fn append(&mut self, ty: u8, payload: Vec<u8>) {
        self.pending.push(WalRecord { ty, payload });
    }

    /// Cooperative drain: write a batch, never called from a blocking path longer than one writev.
    pub fn flush(&mut self) -> io::Result<()> {
        let Some(wal) = self.wal.as_mut() else {
            self.pending.clear();
            return Ok(());
        };
        for rec in self.pending.drain(..) {
            write_frame(wal, rec.ty, &rec.payload)?;
        }
        Ok(())
    }

    pub fn compact(&mut self) -> io::Result<()> {
        self.compact_with_records(std::iter::empty())
    }

    pub fn compact_with_records(
        &mut self,
        records: impl IntoIterator<Item = Vec<u8>>,
    ) -> io::Result<()> {
        if self.dir.as_os_str().is_empty() {
            return Ok(());
        }
        let tmp = self.dir.join("compaction.tmp");
        let mut f = File::create(&tmp)?;
        for p in self.peers.values() {
            let mut payload = Vec::new();
            payload.extend_from_slice(&p.id.0);
            if let Some(addr) = p.primary_addr() {
                payload.extend_from_slice(addr.to_string().as_bytes());
            }
            write_frame(&mut f, TYPE_UPSERT, &payload)?;
        }
        for payload in records {
            write_frame(&mut f, TYPE_RECORD, &payload)?;
        }
        f.sync_all()?;
        fs::rename(tmp, self.dir.join("snapshot.bin"))?;
        let wal_path = self.dir.join("wal.log");
        self.wal = None;
        File::create(&wal_path)?;
        self.wal = Some(OpenOptions::new().append(true).open(wal_path)?);
        Ok(())
    }

    fn recover(&mut self) -> io::Result<()> {
        let snap = self.dir.join("snapshot.bin");
        if snap.exists() {
            self.replay(&snap)?;
        }
        let wal = self.dir.join("wal.log");
        if wal.exists() {
            self.replay(&wal)?;
        }
        Ok(())
    }

    fn replay(&mut self, path: &Path) -> io::Result<()> {
        let mut f = File::open(path)?;
        loop {
            let mut hdr = [0u8; 5];
            match f.read_exact(&mut hdr) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            let len = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
            let ty = hdr[4];
            let mut payload = vec![0u8; len];
            if f.read_exact(&mut payload).is_err() {
                break;
            }
            let mut crc_buf = [0u8; 4];
            if f.read_exact(&mut crc_buf).is_err() {
                break;
            }
            let crc = u32::from_le_bytes(crc_buf);
            if crc32fast::hash(&payload) != crc {
                break;
            }
            match ty {
                TYPE_UPSERT if payload.len() >= 32 => {
                    let id = NodeId(payload[..32].try_into().unwrap());
                    let addr_s = std::str::from_utf8(&payload[32..]).unwrap_or("");
                    if let Ok(addr) = addr_s.parse::<SocketAddr>() {
                        self.peers.insert(id, PeerInfo::new(id, addr));
                    }
                }
                TYPE_TOMBSTONE if payload.len() == 32 => {
                    self.peers.remove(&NodeId(payload[..].try_into().unwrap()));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn write_frame(w: &mut File, ty: u8, payload: &[u8]) -> io::Result<()> {
    let crc = crc32fast::hash(payload);
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(&[ty])?;
    w.write_all(payload)?;
    w.write_all(&crc.to_le_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn memory_upsert() {
        let mut ps = Peerstore::memory();
        let id = NodeId([3; 32]);
        ps.upsert(PeerInfo::new(
            id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
        ));
        assert!(ps.get(&id).is_some());
        ps.flush().unwrap();
    }

    #[test]
    fn wal_roundtrip() {
        let dir = std::env::temp_dir().join(format!("molia-wal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let id = NodeId([9; 32]);
        {
            let mut ps = Peerstore::open(&dir, 0).unwrap();
            ps.upsert(PeerInfo::new(
                id,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 77),
            ));
            ps.flush().unwrap();
            ps.compact().unwrap();
        }
        let ps = Peerstore::open(&dir, 0).unwrap();
        assert!(ps.get(&id).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
