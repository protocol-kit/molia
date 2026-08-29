//! Reed–Solomon 10:4 for blobs ≥ 1 MiB; smaller values replicate only.

use reed_solomon_erasure::galois_8::ReedSolomon;
use reed_solomon_erasure::Error;

pub const DATA_SHARDS: usize = 10;
pub const PARITY_SHARDS: usize = 4;
pub const THRESHOLD: usize = 1024 * 1024;

pub fn should_erasure(len: usize) -> bool {
    len >= THRESHOLD
}

pub fn encode(data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)?;
    let shard_len = data.len().div_ceil(DATA_SHARDS);
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(DATA_SHARDS + PARITY_SHARDS);
    for i in 0..DATA_SHARDS {
        let start = i * shard_len;
        let mut s = vec![0u8; shard_len];
        if start < data.len() {
            let n = (data.len() - start).min(shard_len);
            s[..n].copy_from_slice(&data[start..start + n]);
        }
        shards.push(s);
    }
    for _ in 0..PARITY_SHARDS {
        shards.push(vec![0u8; shard_len]);
    }
    rs.encode(&mut shards)?;
    Ok(shards)
}

pub fn reconstruct(mut shards: Vec<Option<Vec<u8>>>, original_len: usize) -> Result<Vec<u8>, Error> {
    let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)?;
    rs.reconstruct(&mut shards)?;
    let mut out = Vec::with_capacity(original_len);
    for s in shards.into_iter().take(DATA_SHARDS) {
        if let Some(b) = s {
            out.extend_from_slice(&b);
        }
    }
    out.truncate(original_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_loss() {
        let data: Vec<u8> = (0..2000).map(|i| i as u8).collect();
        let shards = encode(&data).unwrap();
        let mut opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        opt[0] = None;
        opt[3] = None;
        opt[11] = None;
        let out = reconstruct(opt, data.len()).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn small_blobs_skip() {
        assert!(!should_erasure(100));
        assert!(should_erasure(THRESHOLD));
    }
}
