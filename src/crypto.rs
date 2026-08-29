//! Ed25519 identity, BLAKE3 hashing, and Ed25519→X25519 binding.

use crate::types::{Key, NodeId};
use boringtun::x25519::{PublicKey as X25519Public, StaticSecret};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    version: u32,
    ed25519_seed: String,
    x25519_secret: String,
    ed25519_pubkey: String,
    x25519_pubkey: String,
    node_id: String,
}

pub struct Identity {
    pub signing: Keypair,
    pub wg_secret: StaticSecret,
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let secret = SecretKey::from_bytes(&seed).expect("32-byte secret");
        let public = PublicKey::from(&secret);
        let signing = Keypair { secret, public };
        let wg_secret = StaticSecret::random_from_rng(OsRng);
        Self { signing, wg_secret }
    }

    pub fn verifying_key(&self) -> PublicKey {
        self.signing.public
    }

    pub fn node_id(&self) -> NodeId {
        node_id_from_pubkey(self.verifying_key().as_bytes())
    }

    pub fn wg_public(&self) -> X25519Public {
        X25519Public::from(&self.wg_secret)
    }

    pub fn binding_signature(&self) -> [u8; 64] {
        let msg = binding_message(self.verifying_key().as_bytes(), self.wg_public().as_bytes());
        self.signing.sign(&msg).to_bytes()
    }

    /// 64 bytes: Ed25519 seed || X25519 secret.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.signing.secret.as_bytes());
        out[32..].copy_from_slice(self.wg_secret.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        let secret = SecretKey::from_bytes(&bytes[..32]).ok()?;
        let public = PublicKey::from(&secret);
        let signing = Keypair { secret, public };
        let mut wg = [0u8; 32];
        wg.copy_from_slice(&bytes[32..]);
        let wg_secret = StaticSecret::from(wg);
        Some(Self { signing, wg_secret })
    }

    pub fn to_json(&self) -> String {
        let file = IdentityFile {
            version: 1,
            ed25519_seed: hex::encode(self.signing.secret.as_bytes()),
            x25519_secret: hex::encode(self.wg_secret.as_bytes()),
            ed25519_pubkey: hex::encode(self.verifying_key().as_bytes()),
            x25519_pubkey: hex::encode(self.wg_public().as_bytes()),
            node_id: hex::encode(self.node_id().0),
        };
        serde_json::to_string_pretty(&file).expect("identity json")
    }

    pub fn from_json(text: &str) -> Option<Self> {
        let file: IdentityFile = serde_json::from_str(text).ok()?;
        let seed = hex::decode(file.ed25519_seed).ok()?;
        let wg = hex::decode(file.x25519_secret).ok()?;
        if seed.len() != 32 || wg.len() != 32 {
            return None;
        }
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&seed);
        raw[32..].copy_from_slice(&wg);
        Self::from_bytes(&raw)
    }

    pub fn save(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        std::fs::write(path, self.to_json())
    }

    pub fn load_or_generate(path: impl AsRef<std::path::Path>) -> Self {
        let path = path.as_ref();
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Some(id) = Self::from_json(&text) {
                return id;
            }
        }
        let legacy = path.with_extension("bin");
        if legacy != path {
            if let Ok(raw) = std::fs::read(&legacy) {
                if let Ok(arr) = <[u8; 64]>::try_from(raw.as_slice()) {
                    if let Some(id) = Self::from_bytes(&arr) {
                        let _ = id.save(path);
                        return id;
                    }
                }
            }
        }
        let id = Self::generate();
        let _ = id.save(path);
        id
    }
}

pub fn node_id_from_pubkey(ed25519_pk: &[u8]) -> NodeId {
    NodeId(blake3::hash(ed25519_pk).into())
}

pub fn hash_value(value: &[u8]) -> Key {
    Key(blake3::hash(value).into())
}

pub fn mutable_key(owner_pubkey: &[u8], namespace: &[u8], salt: &[u8]) -> Key {
    let mut h = blake3::Hasher::new();
    h.update(owner_pubkey);
    h.update(namespace);
    h.update(salt);
    Key(h.finalize().into())
}

pub fn binding_message(ed25519_pk: &[u8], x25519_pk: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(ed25519_pk.len() + x25519_pk.len() + 16);
    m.extend_from_slice(b"molia-wg-bind-v1");
    m.extend_from_slice(ed25519_pk);
    m.extend_from_slice(x25519_pk);
    m
}

pub fn verify_binding(ed25519_pk: &[u8], x25519_pk: &[u8], sig: &[u8]) -> bool {
    let Ok(arr) = <[u8; 32]>::try_from(ed25519_pk) else {
        return false;
    };
    let Ok(vk) = PublicKey::from_bytes(&arr) else {
        return false;
    };
    let Ok(sig) = Signature::from_bytes(sig) else {
        return false;
    };
    vk.verify(&binding_message(ed25519_pk, x25519_pk), &sig)
        .is_ok()
}

pub fn sign_record(signing: &Keypair, key: &Key, value: &[u8], sequence: u64, ttl: u64, nb: u64) -> [u8; 64] {
    signing.sign(&record_bytes(key, value, sequence, ttl, nb)).to_bytes()
}

pub fn verify_record(
    owner_pk: &[u8],
    key: &Key,
    value: &[u8],
    sequence: u64,
    ttl: u64,
    nb: u64,
    sig: &[u8],
) -> bool {
    let Ok(arr) = <[u8; 32]>::try_from(owner_pk) else {
        return false;
    };
    let Ok(vk) = PublicKey::from_bytes(&arr) else {
        return false;
    };
    let Ok(sig) = Signature::from_bytes(sig) else {
        return false;
    };
    vk.verify(&record_bytes(key, value, sequence, ttl, nb), &sig)
        .is_ok()
}

fn record_bytes(key: &Key, value: &[u8], sequence: u64, ttl: u64, nb: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + value.len() + 24);
    m.extend_from_slice(&key.0);
    m.extend_from_slice(value);
    m.extend_from_slice(&sequence.to_be_bytes());
    m.extend_from_slice(&ttl.to_be_bytes());
    m.extend_from_slice(&nb.to_be_bytes());
    m
}

/// Pre-handshake PoW: `BLAKE3(E || Ns)` has at least `d` leading zero bits.
pub fn verify_ephemeral_pow(ephemeral_pub: &[u8; 32], nonce: &[u8; 16], difficulty_bits: u8) -> bool {
    let mut h = blake3::Hasher::new();
    h.update(ephemeral_pub);
    h.update(nonce);
    leading_zero_bits(&h.finalize().into()) >= u32::from(difficulty_bits)
}

pub fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut n = 0u32;
    for b in hash {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

pub fn solve_ephemeral_pow(nonce: &[u8; 16], difficulty_bits: u8) -> (StaticSecret, [u8; 32]) {
    loop {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Public::from(&sk);
        if verify_ephemeral_pow(pk.as_bytes(), nonce, difficulty_bits) {
            return (sk, *pk.as_bytes());
        }
        if difficulty_bits == 0 {
            return (sk, *pk.as_bytes());
        }
    }
}

pub fn cost_stamp(key: &Key, salt: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&key.0);
    h.update(salt);
    h.update(nonce);
    h.finalize().into()
}

pub fn verify_cost_stamp(key: &Key, salt: &[u8], nonce: &[u8], difficulty_bits: u8) -> bool {
    leading_zero_bits(&cost_stamp(key, salt, nonce)) >= u32::from(difficulty_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_is_blake3_of_pubkey() {
        let id = Identity::generate();
        let expected = blake3::hash(id.verifying_key().as_bytes());
        assert_eq!(id.node_id().0, *expected.as_bytes());
    }

    #[test]
    fn binding_roundtrip() {
        let id = Identity::generate();
        let sig = id.binding_signature();
        assert!(verify_binding(
            id.verifying_key().as_bytes(),
            id.wg_public().as_bytes(),
            &sig
        ));
    }

    #[test]
    fn pow_zero_difficulty_always_passes() {
        let e = [7u8; 32];
        let n = [1u8; 16];
        assert!(verify_ephemeral_pow(&e, &n, 0));
    }

    #[test]
    fn identity_json_roundtrip() {
        let id = Identity::generate();
        let parsed = Identity::from_json(&id.to_json()).unwrap();
        assert_eq!(parsed.to_bytes(), id.to_bytes());
        assert_eq!(parsed.node_id(), id.node_id());
    }
}
