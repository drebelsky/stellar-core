//! SipHash-2-4 keyed short ID computation for compact tx set relay.
//!
//! Used on the receiver path to resolve short IDs against the local mempool.
//! Must produce bit-identical results to the C++ sender-side implementation
//! in `src/crypto/ShortHash.cpp`.

use sha2::{Digest, Sha256};
use siphasher::sip::SipHasher24;
use std::hash::Hasher;

/// A 6-byte truncated SipHash-2-4 short transaction ID.
pub type ShortTxId = [u8; 6];

/// Derive the SipHash-2-4 key pair (k0, k1) from a tx set content hash and nonce.
///
/// Key derivation:
/// 1. SHA-256(tx_set_content_hash || nonce_le) → 32 bytes
/// 2. k0 = first 8 bytes as little-endian u64
/// 3. k1 = next 8 bytes as little-endian u64
pub fn derive_siphash_key(tx_set_content_hash: &[u8; 32], nonce: u64) -> (u64, u64) {
    let mut hasher = Sha256::new();
    hasher.update(tx_set_content_hash);
    hasher.update(nonce.to_le_bytes());
    let key_hash = hasher.finalize();

    let k0 = u64::from_le_bytes(key_hash[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key_hash[8..16].try_into().unwrap());
    (k0, k1)
}

/// Compute a 6-byte short ID for a single transaction.
///
/// `tx_full_hash` is SHA-256(xdr(TransactionEnvelope)) — the same value
/// stored in the mempool's `TxEntry.hash`.
pub fn compute_short_id(k0: u64, k1: u64, tx_full_hash: &[u8; 32]) -> ShortTxId {
    let mut sip = SipHasher24::new_with_keys(k0, k1);
    sip.write(tx_full_hash);
    let digest = sip.finish();

    // Truncate to least significant 6 bytes in little-endian byte order.
    let bytes = digest.to_le_bytes();
    let mut result = [0u8; 6];
    result.copy_from_slice(&bytes[..6]);
    result
}

/// Batch-compute short IDs for a set of transaction hashes.
pub fn compute_short_ids_batch(
    tx_set_content_hash: &[u8; 32],
    nonce: u64,
    tx_hashes: &[[u8; 32]],
) -> Vec<ShortTxId> {
    let (k0, k1) = derive_siphash_key(tx_set_content_hash, nonce);
    tx_hashes
        .iter()
        .map(|h| compute_short_id(k0, k1, h))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_siphash_key_deterministic() {
        let hash = [0xABu8; 32];
        let nonce = 42u64;
        let (k0a, k1a) = derive_siphash_key(&hash, nonce);
        let (k0b, k1b) = derive_siphash_key(&hash, nonce);
        assert_eq!(k0a, k0b);
        assert_eq!(k1a, k1b);
    }

    #[test]
    fn test_different_nonce_different_keys() {
        let hash = [0xABu8; 32];
        let (k0a, k1a) = derive_siphash_key(&hash, 1);
        let (k0b, k1b) = derive_siphash_key(&hash, 2);
        assert!(k0a != k0b || k1a != k1b);
    }

    #[test]
    fn test_short_id_is_6_bytes() {
        let (k0, k1) = derive_siphash_key(&[0u8; 32], 0);
        let id = compute_short_id(k0, k1, &[1u8; 32]);
        assert_eq!(id.len(), 6);
    }

    #[test]
    fn test_batch_matches_individual() {
        let tx_set_hash = [0x42u8; 32];
        let nonce = 99u64;
        let hashes: Vec<[u8; 32]> = (0..5).map(|i| [i as u8; 32]).collect();

        let batch = compute_short_ids_batch(&tx_set_hash, nonce, &hashes);
        let (k0, k1) = derive_siphash_key(&tx_set_hash, nonce);
        for (i, h) in hashes.iter().enumerate() {
            assert_eq!(batch[i], compute_short_id(k0, k1, h));
        }
    }
}
