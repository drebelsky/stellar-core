//! Short-ID resolution against the mempool for compact tx set reconstruction.

use crate::compact::short_id::{compute_short_id, derive_siphash_key, ShortTxId};
use crate::flood::Mempool;
use std::collections::HashMap;

/// Resolution status for a single short ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveStatus {
    /// Exactly one mempool entry matched.
    Unique(Vec<u8>),
    /// No mempool entry matched.
    Missing,
    /// Multiple mempool entries matched (ambiguous).
    Ambiguous,
}

/// Result of resolving a batch of short IDs against the mempool.
pub struct ResolveResult {
    /// Per-short-ID results in positional order.
    pub entries: Vec<ResolveStatus>,
    /// Number of UNIQUE matches.
    pub unique_count: usize,
    /// Number of MISSING entries.
    pub missing_count: usize,
    /// Number of AMBIGUOUS entries.
    pub ambiguous_count: usize,
}

/// Resolve a list of short IDs against the mempool.
///
/// This scans the entire mempool once, SipHashing each entry with the derived
/// key, then matches requested short IDs against the results.
pub fn resolve(
    mempool: &Mempool,
    tx_set_content_hash: &[u8; 32],
    nonce: u64,
    requested_short_ids: &[ShortTxId],
) -> ResolveResult {
    let (k0, k1) = derive_siphash_key(tx_set_content_hash, nonce);

    // Build a map from short ID → list of (tx_hash, envelope_bytes) for all
    // mempool entries.
    let mut mempool_by_short_id: HashMap<ShortTxId, Vec<([u8; 32], Vec<u8>)>> =
        HashMap::new();

    // Iterate all mempool entries. We use top_by_fee with a very large N to
    // get all hashes, then look up each entry.
    let all_hashes = mempool.top_by_fee(usize::MAX);
    for tx_hash in &all_hashes {
        let short_id = compute_short_id(k0, k1, tx_hash);
        if let Some(entry) = mempool.get(tx_hash) {
            mempool_by_short_id
                .entry(short_id)
                .or_default()
                .push((*tx_hash, entry.data.clone()));
        }
    }

    // Resolve each requested short ID
    let mut entries = Vec::with_capacity(requested_short_ids.len());
    let mut unique_count = 0usize;
    let mut missing_count = 0usize;
    let mut ambiguous_count = 0usize;

    for sid in requested_short_ids {
        match mempool_by_short_id.get(sid) {
            None => {
                entries.push(ResolveStatus::Missing);
                missing_count += 1;
            }
            Some(matches) if matches.len() == 1 => {
                entries.push(ResolveStatus::Unique(matches[0].1.clone()));
                unique_count += 1;
            }
            Some(_) => {
                entries.push(ResolveStatus::Ambiguous);
                ambiguous_count += 1;
            }
        }
    }

    ResolveResult {
        entries,
        unique_count,
        missing_count,
        ambiguous_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flood::{compute_tx_hash, Mempool, TxEntry};
    use std::time::{Duration, Instant};

    fn make_tx_entry(data: &[u8]) -> TxEntry {
        TxEntry {
            data: data.to_vec(),
            hash: compute_tx_hash(data),
            source_account: [0u8; 32],
            sequence: 1,
            fee: 100,
            num_ops: 1,
            received_at: Instant::now(),
            from_peer: 0,
        }
    }

    #[test]
    fn test_resolve_all_unique() {
        let mut mempool = Mempool::new(1000, Duration::from_secs(3600));
        let tx_data: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 100]).collect();
        let tx_hashes: Vec<[u8; 32]> = tx_data.iter().map(|d| compute_tx_hash(d)).collect();

        for d in &tx_data {
            mempool.insert(make_tx_entry(d));
        }

        let tx_set_hash = [0xAAu8; 32];
        let nonce = 42u64;
        let (k0, k1) = crate::compact::short_id::derive_siphash_key(&tx_set_hash, nonce);
        let short_ids: Vec<ShortTxId> = tx_hashes
            .iter()
            .map(|h| crate::compact::short_id::compute_short_id(k0, k1, h))
            .collect();

        let result = resolve(&mempool, &tx_set_hash, nonce, &short_ids);
        assert_eq!(result.unique_count, 3);
        assert_eq!(result.missing_count, 0);
        assert_eq!(result.ambiguous_count, 0);
        assert_eq!(result.entries.len(), 3);
    }

    #[test]
    fn test_resolve_missing() {
        let mempool = Mempool::new(1000, Duration::from_secs(3600));
        let fake_short_id: ShortTxId = [1, 2, 3, 4, 5, 6];
        let result = resolve(&mempool, &[0u8; 32], 0, &[fake_short_id]);
        assert_eq!(result.missing_count, 1);
        assert_eq!(result.unique_count, 0);
    }
}
