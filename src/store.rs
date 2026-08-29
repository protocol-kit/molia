//! Immutable, mutable, provider, and cache storage on one shard.

use crate::crypto::{hash_value, mutable_key, verify_record};
use crate::proto;
use crate::types::{Key, NodeId, PMTU_FLOOR};
use prost::Message;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const KIND_IMMUTABLE: u32 = 0;
pub const KIND_MUTABLE: u32 = 1;
pub const KIND_PROVIDER: u32 = 2;
pub const KIND_TOMBSTONE: u32 = 3;

const CACHE_TTL_SECS: u64 = 10 * 60;
pub const MUTABLE_TTL_SECS: u64 = 24 * 3600;

#[derive(Clone, Debug)]
pub struct StoredRecord {
    pub key: Key,
    pub value: Vec<u8>,
    pub sequence: u64,
    pub ttl_secs: u64,
    pub not_before_unix: u64,
    pub owner_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub kind: u32,
    pub namespace: Vec<u8>,
    pub salt: Vec<u8>,
    pub stored_unix: u64,
    pub cache: bool,
}

impl StoredRecord {
    pub fn to_proto(&self) -> proto::Record {
        proto::Record {
            key: self.key.0.to_vec().into(),
            value: self.value.clone().into(),
            sequence: self.sequence,
            ttl_secs: self.ttl_secs,
            not_before_unix: self.not_before_unix,
            owner_pubkey: self.owner_pubkey.clone().into(),
            signature: self.signature.clone().into(),
            validators: Default::default(),
            kind: self.kind,
            namespace: self.namespace.clone().into(),
            salt: self.salt.clone().into(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    pub fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.stored_unix) > self.ttl_secs
    }

    /// Hash (immutable) or Ed25519 envelope (mutable / tombstone).
    pub fn authentic(&self) -> bool {
        match self.kind {
            KIND_IMMUTABLE => hash_value(&self.value) == self.key,
            KIND_MUTABLE | KIND_TOMBSTONE => {
                !self.owner_pubkey.is_empty()
                    && mutable_key(&self.owner_pubkey, &self.namespace, &self.salt) == self.key
                    && verify_record(
                        &self.owner_pubkey,
                        &self.key,
                        &self.value,
                        self.sequence,
                        self.ttl_secs,
                        self.not_before_unix,
                        &self.signature,
                    )
            }
            KIND_PROVIDER => true,
            _ => false,
        }
    }

    /// Mutable record signed by `owner_pk` (the `--get-mutable` PUBKEY).
    pub fn signed_by(&self, owner_pk: &[u8]) -> bool {
        self.kind == KIND_MUTABLE
            && self.owner_pubkey.as_slice() == owner_pk
            && self.authentic()
    }
}

pub fn record_from_proto(r: &proto::Record) -> Option<StoredRecord> {
    let key = Key::from_bytes(&r.key)?;
    Some(StoredRecord {
        key,
        value: r.value.to_vec(),
        sequence: r.sequence,
        ttl_secs: if r.ttl_secs == 0 { MUTABLE_TTL_SECS } else { r.ttl_secs },
        not_before_unix: r.not_before_unix,
        owner_pubkey: r.owner_pubkey.to_vec(),
        signature: r.signature.to_vec(),
        kind: r.kind,
        namespace: r.namespace.to_vec(),
        salt: r.salt.to_vec(),
        stored_unix: now_unix(),
        cache: false,
    })
}

#[derive(Clone, Debug)]
pub struct ProviderEntry {
    pub peer_id: NodeId,
    pub meta: Vec<u8>,
    pub stored_unix: u64,
    pub ttl_secs: u64,
}

pub struct Store {
    records: HashMap<Key, StoredRecord>,
    providers: HashMap<Key, Vec<ProviderEntry>>,
    cache: HashMap<Key, StoredRecord>,
    dir: Option<PathBuf>,
    pending_wal: Vec<Vec<u8>>,
}

impl Store {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            providers: HashMap::new(),
            cache: HashMap::new(),
            dir: None,
            pending_wal: Vec::new(),
        }
    }

    pub fn open(dir: impl AsRef<Path>, shard: u32) -> io::Result<Self> {
        let dir = dir.as_ref().join(format!("shard-{shard}"));
        fs::create_dir_all(&dir)?;
        let mut store = Self {
            dir: Some(dir.clone()),
            ..Self::new()
        };
        let wal = dir.join("wal.log");
        if wal.exists() {
            store.replay_wal(&wal)?;
        }
        Ok(store)
    }

    fn queue_record(&mut self, rec: &StoredRecord) {
        if self.dir.is_some() {
            self.pending_wal.push(rec.encode());
        }
    }

    /// Append queued records onto the shared shard `wal.log`.
    pub fn flush_wal(&mut self, peers: &mut crate::peerstore::Peerstore) -> io::Result<()> {
        for payload in self.pending_wal.drain(..) {
            peers.append(crate::peerstore::TYPE_RECORD, payload);
        }
        Ok(())
    }

    pub fn put_immutable(&mut self, value: &[u8]) -> Result<Key, &'static str> {
        self.put_immutable_ttl(value, MUTABLE_TTL_SECS)
    }

    pub fn put_immutable_ttl(&mut self, value: &[u8], ttl_secs: u64) -> Result<Key, &'static str> {
        if value.len() > PMTU_FLOOR * 64 {
            return Err("too large");
        }
        let key = hash_value(value);
        let rec = StoredRecord {
            key,
            value: value.to_vec(),
            sequence: 0,
            ttl_secs,
            not_before_unix: 0,
            owner_pubkey: Vec::new(),
            signature: Vec::new(),
            kind: KIND_IMMUTABLE,
            namespace: Vec::new(),
            salt: Vec::new(),
            stored_unix: now_unix(),
            cache: false,
        };
        self.queue_record(&rec);
        self.records.insert(key, rec);
        Ok(key)
    }

    pub fn put_record(&mut self, rec: StoredRecord, probe: bool) -> Result<(), &'static str> {
        if rec.value.len() + rec.signature.len() > 64 * 1024 {
            return Err("too large");
        }
        match rec.kind {
            KIND_IMMUTABLE => {
                if hash_value(&rec.value) != rec.key {
                    return Err("hash mismatch");
                }
            }
            KIND_MUTABLE => {
                if !rec.authentic() {
                    return Err("bad signature");
                }
                if let Some(old) = self.records.get(&rec.key) {
                    if rec.sequence <= old.sequence && old.kind != KIND_TOMBSTONE {
                        return Err("stale sequence");
                    }
                }
            }
            KIND_TOMBSTONE => {
                if !rec.authentic() {
                    return Err("bad tombstone");
                }
            }
            KIND_PROVIDER => {}
            _ => return Err("unknown kind"),
        }
        if rec.kind == KIND_TOMBSTONE {
            self.queue_record(&rec);
            self.records.insert(rec.key, rec);
            return Ok(());
        }
        if probe {
            return Ok(());
        }
        self.queue_record(&rec);
        self.records.insert(rec.key, rec);
        Ok(())
    }

    pub fn cache_hit(&mut self, rec: StoredRecord) {
        if rec.kind != KIND_IMMUTABLE {
            return;
        }
        let mut rec = rec;
        rec.cache = true;
        rec.ttl_secs = CACHE_TTL_SECS.min(30 * 60).max(5 * 60);
        rec.stored_unix = now_unix();
        self.cache.insert(rec.key, rec);
    }

    pub fn get(&self, key: &Key) -> Option<&StoredRecord> {
        let now = now_unix();
        if let Some(r) = self.records.get(key) {
            if !r.expired(now) && r.kind != KIND_TOMBSTONE {
                return Some(r);
            }
        }
        self.cache.get(key).filter(|r| !r.expired(now))
    }

    pub fn announce_provider(&mut self, key: Key, peer_id: NodeId, meta: Vec<u8>) {
        let list = self.providers.entry(key).or_default();
        if let Some(e) = list.iter_mut().find(|e| e.peer_id == peer_id) {
            e.meta = meta;
            e.stored_unix = now_unix();
            return;
        }
        if list.len() < 64 {
            list.push(ProviderEntry {
                peer_id,
                meta,
                stored_unix: now_unix(),
                ttl_secs: MUTABLE_TTL_SECS,
            });
        }
    }

    pub fn providers(&self, key: &Key, limit: usize) -> Vec<ProviderEntry> {
        let now = now_unix();
        self.providers
            .get(key)
            .map(|v| {
                v.iter()
                    .filter(|e| now.saturating_sub(e.stored_unix) <= e.ttl_secs)
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn gc(&mut self) {
        let now = now_unix();
        self.records.retain(|_, r| !r.expired(now));
        self.cache.retain(|_, r| !r.expired(now));
        for list in self.providers.values_mut() {
            list.retain(|e| now.saturating_sub(e.stored_unix) <= e.ttl_secs);
        }
    }

    fn replay_wal(&mut self, path: &Path) -> io::Result<()> {
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
            if crc32fast::hash(&payload) != u32::from_le_bytes(crc_buf) {
                break;
            }
            if ty != crate::peerstore::TYPE_RECORD {
                continue;
            }
            if let Ok(pr) = proto::Record::decode(payload.as_slice()) {
                if let Some(rec) = record_from_proto(&pr) {
                    if rec.authentic() {
                        self.records.insert(rec.key, rec);
                    }
                }
            }
        }
        Ok(())
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{mutable_key, sign_record, Identity};

    #[test]
    fn signed_by_rejects_tampered_value() {
        let id = Identity::generate();
        let pk = id.verifying_key();
        let key = mutable_key(pk.as_bytes(), b"ns", b"salt");
        let sig = sign_record(&id.signing, &key, b"ok", 1, MUTABLE_TTL_SECS, 0);
        let rec = StoredRecord {
            key,
            value: b"ok".to_vec(),
            sequence: 1,
            ttl_secs: MUTABLE_TTL_SECS,
            not_before_unix: 0,
            owner_pubkey: pk.as_bytes().to_vec(),
            signature: sig.to_vec(),
            kind: KIND_MUTABLE,
            namespace: b"ns".to_vec(),
            salt: b"salt".to_vec(),
            stored_unix: now_unix(),
            cache: false,
        };
        assert!(rec.signed_by(pk.as_bytes()));
        assert!(Store::new().put_record(rec.clone(), false).is_ok());
        let mut bad = rec.clone();
        bad.value = b"nope".to_vec();
        assert!(!bad.signed_by(pk.as_bytes()));
        assert!(Store::new().put_record(bad, false).is_err());
        let mut wrong_key = rec.clone();
        wrong_key.namespace = b"other".to_vec();
        assert!(!wrong_key.authentic());
        assert!(Store::new().put_record(wrong_key, false).is_err());
        let other = Identity::generate();
        assert!(!rec.signed_by(other.verifying_key().as_bytes()));
    }

    #[test]
    fn records_roundtrip_wal() {
        use crate::peerstore::Peerstore;
        let dir = std::env::temp_dir().join(format!("molia-rec-wal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let id = Identity::generate();
        let pk = id.verifying_key();
        let key = mutable_key(pk.as_bytes(), b"ns", b"s");
        let sig = sign_record(&id.signing, &key, b"v", 1, MUTABLE_TTL_SECS, 0);
        let rec = StoredRecord {
            key,
            value: b"v".to_vec(),
            sequence: 1,
            ttl_secs: MUTABLE_TTL_SECS,
            not_before_unix: 0,
            owner_pubkey: pk.as_bytes().to_vec(),
            signature: sig.to_vec(),
            kind: KIND_MUTABLE,
            namespace: b"ns".to_vec(),
            salt: b"s".to_vec(),
            stored_unix: now_unix(),
            cache: false,
        };
        {
            let mut peers = Peerstore::open(&dir, 0).unwrap();
            let mut store = Store::open(&dir, 0).unwrap();
            store.put_record(rec.clone(), false).unwrap();
            store.flush_wal(&mut peers).unwrap();
            peers.flush().unwrap();
        }
        let store = Store::open(&dir, 0).unwrap();
        assert_eq!(store.get(&key).map(|r| r.value.as_slice()), Some(&b"v"[..]));
        let _ = fs::remove_dir_all(&dir);
    }
}
