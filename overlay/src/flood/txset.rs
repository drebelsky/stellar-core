//! TX Set builder for nomination.
//!
//! Builds GeneralizedTransactionSet XDR from mempool transactions.
//! Uses CLASSIC phase only for MVP. TODO: Add SOROBAN phase support.

use crate::flood::blake2b_hash;
use sha2::{Digest, Sha256};
use siphasher::sip::SipHasher24;
use std::collections::HashMap;
use std::hash::Hasher;
use stellar_xdr::{
    CompactTxSet, GeneralizedTransactionSet, Hash, Limits, ReadXdr, TransactionPhase,
    TxSetComponent, WriteXdr,
};

/// 32-byte hash
pub type Hash256 = [u8; 32];

/// TX hash type (for mempool lookup)
pub type TxHash = [u8; 32];

/// A cached TX set with its XDR and hash.
#[derive(Debug, Clone, Default)]
pub struct CachedTxSet {
    /// The TX set hash (SHA256 of XDR)
    pub hash: Hash256,
    /// The serialized GeneralizedTransactionSet XDR
    pub xdr: Vec<u8>,
    /// Ledger sequence this was built for
    pub ledger_seq: u32,
    /// Hashes of TXs included in this set (for mempool cleanup)
    pub tx_hashes: Vec<TxHash>,
    /// Previous ledger hash, extracted from the GeneralizedTransactionSet XDR
    pub previous_ledger_hash: Hash256,
    /// Base fee for the CLASSIC component (None when no discounted fee was set)
    pub base_fee: Option<i64>,
    /// Eagerly built serialized stellar_xdr::CompactTxSet for this set
    pub compact_xdr: Vec<u8>,
    /// Per-tx already-serialized TransactionEnvelope XDR, in flat CLASSIC
    /// order (matches the indices used in CompactTxSet.txs). Populated at
    /// insert time so peer GET_TXS responses don't need to re-parse the
    /// cached GeneralizedTransactionSet on every request.
    pub tx_envelopes_xdr: Vec<Vec<u8>>,
}

/// TX set cache - stores built TX sets by hash for retrieval.
pub struct TxSetCache {
    /// TX sets by hash
    by_hash: HashMap<Hash256, CachedTxSet>,
    /// Max cache size
    max_size: usize,
}

impl TxSetCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            by_hash: HashMap::new(),
            max_size,
        }
    }

    /// Insert a TX set into the cache.
    pub fn insert(&mut self, tx_set: CachedTxSet) {
        if self.by_hash.len() >= self.max_size {
            // Evict oldest (simple strategy - just remove one)
            if let Some(&hash) = self.by_hash.keys().next() {
                self.by_hash.remove(&hash);
            }
        }
        self.by_hash.insert(tx_set.hash, tx_set);
    }

    /// Get a TX set by hash.
    pub fn get(&self, hash: &Hash256) -> Option<&CachedTxSet> {
        self.by_hash.get(hash)
    }

    /// Remove a TX set by hash and return the TX hashes it contained.
    pub fn remove(&mut self, hash: &Hash256) -> Option<Vec<TxHash>> {
        self.by_hash.remove(hash).map(|ts| ts.tx_hashes)
    }

    /// Remove TX sets for ledgers before the given sequence.
    pub fn evict_before(&mut self, ledger_seq: u32) {
        self.by_hash.retain(|_, v| v.ledger_seq >= ledger_seq);
    }

    /// Clear all cached TX sets.
    pub fn clear(&mut self) {
        self.by_hash.clear();
    }

    /// Get number of cached TX sets.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }
}

/// Build a GeneralizedTransactionSet XDR from transaction envelopes.
///
/// Format (v1, CLASSIC sequential + SOROBAN parallel phases):
/// Protocol >= 23 requires Soroban phase to use parallel format (v=1).
/// ```text
/// GeneralizedTransactionSet {
///   v: 1
///   v1TxSet: TransactionSetV1 {
///     previousLedgerHash: Hash
///     phases: [TransactionPhase] {
///       [0]: TransactionPhase::v0Components (CLASSIC, sequential) {
///         [TxSetComponent {
///           type: TXSET_COMP_TXS_MAYBE_DISCOUNTED_FEE (0)
///           txsMaybeDiscountedFee: {
///             baseFee: null (no discount)
///             txs: [TransactionEnvelope]
///           }
///         }]
///       }
///       [1]: TransactionPhase::parallelTxsComponent (SOROBAN, parallel, empty) {
///         baseFee: null
///         executionStages: []
///       }
///     }
///   }
/// }
/// ```
pub fn build_tx_set_xdr(prev_ledger_hash: &Hash256, tx_envelopes: &[Vec<u8>]) -> Vec<u8> {
    let mut xdr = Vec::new();

    // GeneralizedTransactionSet union discriminant: v = 1 (4 bytes, big-endian)
    xdr.extend_from_slice(&1u32.to_be_bytes());

    // TransactionSetV1.previousLedgerHash (32 bytes)
    xdr.extend_from_slice(prev_ledger_hash);

    // TransactionSetV1.phases (xdr::xvector<TransactionPhase>)
    // Length = 2 (CLASSIC + SOROBAN phases - both required by validation)
    xdr.extend_from_slice(&2u32.to_be_bytes());

    // === PHASE 0: CLASSIC ===
    // TransactionPhase union discriminant: v = 0 (v0Components)
    xdr.extend_from_slice(&0u32.to_be_bytes());

    if tx_envelopes.is_empty() {
        // Empty phase: 0 components
        // Note: Empty components are rejected by validateSequentialPhaseXDRStructure
        xdr.extend_from_slice(&0u32.to_be_bytes());
    } else {
        // v0Components: xdr::xvector<TxSetComponent>
        // Length = 1 (single component with all txs, no discount)
        xdr.extend_from_slice(&1u32.to_be_bytes());

        // TxSetComponent union discriminant: TXSET_COMP_TXS_MAYBE_DISCOUNTED_FEE = 0
        xdr.extend_from_slice(&0u32.to_be_bytes());

        // txsMaybeDiscountedFee.baseFee: optional<int64>
        // 0 = not present (no discount)
        xdr.extend_from_slice(&0u32.to_be_bytes());

        // txsMaybeDiscountedFee.txs: xdr::xvector<TransactionEnvelope>
        // Length = number of transactions
        xdr.extend_from_slice(&(tx_envelopes.len() as u32).to_be_bytes());

        // Append each transaction envelope
        for tx in tx_envelopes {
            xdr.extend_from_slice(tx);
        }
    }

    // === PHASE 1: SOROBAN (empty, parallel format) ===
    // Protocol >= 23 requires parallelTxsComponent (v=1) for Soroban phase
    // TransactionPhase union discriminant: v = 1 (parallelTxsComponent)
    xdr.extend_from_slice(&1u32.to_be_bytes());

    // ParallelTxsComponent.baseFee: optional<int64>
    // 0 = not present (no discount)
    xdr.extend_from_slice(&0u32.to_be_bytes());

    // ParallelTxsComponent.executionStages: xvector<ParallelTxExecutionStage>
    // Length = 0 (no Soroban transactions)
    xdr.extend_from_slice(&0u32.to_be_bytes());

    xdr
}

impl CachedTxSet {
    /// Build a `CachedTxSet` from a serialized GeneralizedTransactionSet.
    ///
    /// Parses the XDR once to extract `tx_hashes`, `previous_ledger_hash`, and
    /// the CLASSIC component's `base_fee`, then eagerly builds the serialized
    /// `CompactTxSet` for use by the broadcast path.
    ///
    /// Panics on malformed XDR or unexpected structure (matches existing
    /// invariants: exactly one CLASSIC component, zero SOROBAN execution stages).
    pub fn from_xdr(hash: Hash256, xdr: Vec<u8>, ledger_seq: u32) -> Self {
        let txset = GeneralizedTransactionSet::from_xdr(&xdr, Limits::none())
            .expect("Failed to parse TX set XDR for caching");
        let GeneralizedTransactionSet::V1(txset) = txset;

        let previous_ledger_hash: Hash256 = txset.previous_ledger_hash.0;

        let mut tx_hashes = Vec::new();
        let mut tx_envelopes_xdr: Vec<Vec<u8>> = Vec::new();
        let mut base_fee: Option<i64> = None;

        for phase in txset.phases.iter() {
            match phase {
                TransactionPhase::V0(components) => {
                    if components.len() != 1 {
                        panic!("Unexpected number of components in TX set");
                    }
                    let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(txset_comp) =
                        components.iter().next().unwrap();
                    base_fee = txset_comp.base_fee;
                    for tx in &txset_comp.txs {
                        let tx_xdr = tx
                            .to_xdr(Limits::none())
                            .expect("Failed to convert TxEnvelope to XDR");
                        tx_hashes.push(blake2b_hash(&tx_xdr));
                        tx_envelopes_xdr.push(tx_xdr);
                    }
                }
                TransactionPhase::V1(parallel) => {
                    if !parallel.execution_stages.is_empty() {
                        panic!("Unexpected execution stages in TX set");
                    }
                }
            }
        }

        let compact_xdr =
            build_compact_tx_set_xdr(&hash, &previous_ledger_hash, base_fee, &tx_hashes);

        Self {
            hash,
            xdr,
            ledger_seq,
            tx_hashes,
            previous_ledger_hash,
            base_fee,
            compact_xdr,
            tx_envelopes_xdr,
        }
    }
}

/// Compute the hash of a TX set XDR.
pub fn hash_tx_set(xdr: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(xdr);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Build a serialized `stellar_xdr::CompactTxSet` for the given tx set.
///
/// `txs` is built from per-tx 6-byte SipHash-2-4 digests, where the SipHash
/// key is the first 16 bytes of `tx_set_hash` and the input is the 32-byte
/// `tx_hash`. This matches the C++ stellar-core compact tx set wire format.
pub fn build_compact_tx_set_xdr(
    tx_set_hash: &Hash256,
    previous_ledger_hash: &Hash256,
    base_fee: Option<i64>,
    tx_hashes: &[TxHash],
) -> Vec<u8> {
    let mut key = [0u8; 16];
    key.copy_from_slice(&tx_set_hash[..16]);

    let mut txs_bytes = Vec::with_capacity(tx_hashes.len() * 6);
    for tx_hash in tx_hashes {
        let mut hasher = SipHasher24::new_with_key(&key);
        hasher.write(tx_hash);
        let digest = hasher.finish().to_le_bytes();
        txs_bytes.extend_from_slice(&digest[..6]);
    }

    let compact = CompactTxSet {
        tx_set_hash: Hash(*tx_set_hash),
        previous_ledger_hash: Hash(*previous_ledger_hash),
        base_fee,
        txs: txs_bytes
            .try_into()
            .expect("compact tx set txs field exceeded XDR length limit"),
    };

    compact
        .to_xdr(Limits::none())
        .expect("CompactTxSet XDR serialization failed")
}

/// Build a `GeneralizedTransactionSet` XDR (V1, CLASSIC sequential + empty
/// SOROBAN parallel) like `build_tx_set_xdr`, but also encodes a discounted
/// `base_fee` in the CLASSIC component when `Some`.
pub fn build_full_tx_set_xdr(
    prev_ledger_hash: &Hash256,
    base_fee: Option<i64>,
    tx_envelopes: &[Vec<u8>],
) -> Vec<u8> {
    let mut xdr = Vec::new();

    // GeneralizedTransactionSet union discriminant: v = 1
    xdr.extend_from_slice(&1u32.to_be_bytes());
    // TransactionSetV1.previousLedgerHash
    xdr.extend_from_slice(prev_ledger_hash);
    // TransactionSetV1.phases length = 2 (CLASSIC + SOROBAN)
    xdr.extend_from_slice(&2u32.to_be_bytes());

    // ── PHASE 0: CLASSIC (v0Components) ──
    xdr.extend_from_slice(&0u32.to_be_bytes());
    if tx_envelopes.is_empty() {
        // Empty phase: 0 components
        xdr.extend_from_slice(&0u32.to_be_bytes());
    } else {
        // 1 component
        xdr.extend_from_slice(&1u32.to_be_bytes());
        // TxSetComponent discriminant: TXSET_COMP_TXS_MAYBE_DISCOUNTED_FEE = 0
        xdr.extend_from_slice(&0u32.to_be_bytes());
        // Optional<int64> baseFee
        match base_fee {
            None => xdr.extend_from_slice(&0u32.to_be_bytes()),
            Some(fee) => {
                xdr.extend_from_slice(&1u32.to_be_bytes());
                xdr.extend_from_slice(&fee.to_be_bytes());
            }
        }
        // txs length
        xdr.extend_from_slice(&(tx_envelopes.len() as u32).to_be_bytes());
        for tx in tx_envelopes {
            xdr.extend_from_slice(tx);
        }
    }

    // ── PHASE 1: SOROBAN (parallelTxsComponent, empty) ──
    xdr.extend_from_slice(&1u32.to_be_bytes());
    // Optional baseFee = None
    xdr.extend_from_slice(&0u32.to_be_bytes());
    // executionStages length = 0
    xdr.extend_from_slice(&0u32.to_be_bytes());

    xdr
}

/// Outcome of attempting to reconstruct a full tx set from a `CompactTxSet`
/// announcement and the local pool of known transaction envelopes.
#[derive(Debug)]
pub enum ReconstructResult {
    /// All siphash digests matched a known tx and the resulting full tx set
    /// XDR re-hashes to `compact.tx_set_hash`. Caller can forward these
    /// bytes via `TX_SET_AVAILABLE`.
    Complete(Vec<u8>),
    /// One or more digests didn't match any known tx. `indices` are positions
    /// within `compact.txs` (0-based, in the order the compact set lists
    /// them) for the slots that didn't match — caller should request these
    /// via `COMPACT_TX_SET_GET_TXS`. `matched` is the per-slot vector with
    /// `Some(envelope_xdr)` for already-resolved slots and `None` for the
    /// missing ones; the caller can stash it as the start of a pending
    /// reconstruction.
    Missing {
        indices: Vec<u32>,
        matched: Vec<Option<Vec<u8>>>,
    },
    /// All digests matched a known tx, but the resulting XDR hashes to a
    /// different value than `compact.tx_set_hash` — the digest space is too
    /// small (6 bytes) and a collision led us to pick the wrong tx.
    HashMismatch { reconstructed_hash: Hash256 },
}

/// Compute a 6-byte SipHash-2-4 digest using the first 16 bytes of
/// `tx_set_hash` as the key. Matches `build_compact_tx_set_xdr`.
pub fn compact_tx_digest(tx_set_hash: &Hash256, tx_hash: &TxHash) -> [u8; 6] {
    let mut key = [0u8; 16];
    key.copy_from_slice(&tx_set_hash[..16]);
    let mut hasher = SipHasher24::new_with_key(&key);
    hasher.write(tx_hash);
    let digest = hasher.finish().to_le_bytes();
    let mut out = [0u8; 6];
    out.copy_from_slice(&digest[..6]);
    out
}

/// Try to reconstruct a full `GeneralizedTransactionSet` from a compact
/// announcement plus an iterable of known `(tx_hash, tx_envelope_xdr)`
/// pairs (typically the local TxBuffer / mempool snapshot).
pub fn reconstruct_full_tx_set<I>(compact: &CompactTxSet, known_txs: I) -> ReconstructResult
where
    I: IntoIterator<Item = (TxHash, Vec<u8>)>,
{
    let tx_set_hash: Hash256 = compact.tx_set_hash.0;

    // Index known txs by their 6-byte digest.
    let mut digest_to_tx: HashMap<[u8; 6], Vec<u8>> = HashMap::new();
    for (tx_hash, tx_data) in known_txs {
        let digest = compact_tx_digest(&tx_set_hash, &tx_hash);
        digest_to_tx.insert(digest, tx_data);
    }

    // Walk compact.txs in 6-byte chunks.
    let txs_bytes = compact.txs.as_slice();
    let n = txs_bytes.len() / 6;
    let mut matched: Vec<Option<Vec<u8>>> = Vec::with_capacity(n);
    let mut missing: Vec<u32> = Vec::new();

    for i in 0..n {
        let mut chunk = [0u8; 6];
        chunk.copy_from_slice(&txs_bytes[i * 6..(i + 1) * 6]);
        match digest_to_tx.get(&chunk) {
            Some(tx_data) => matched.push(Some(tx_data.clone())),
            None => {
                matched.push(None);
                missing.push(i as u32);
            }
        }
    }

    if !missing.is_empty() {
        return ReconstructResult::Missing {
            indices: missing,
            matched,
        };
    }

    let tx_envelopes: Vec<Vec<u8>> = matched.into_iter().map(|x| x.unwrap()).collect();
    let prev_hash: Hash256 = compact.previous_ledger_hash.0;
    let full_xdr = build_full_tx_set_xdr(&prev_hash, compact.base_fee, &tx_envelopes);

    let actual_hash = hash_tx_set(&full_xdr);
    if actual_hash != tx_set_hash {
        return ReconstructResult::HashMismatch {
            reconstructed_hash: actual_hash,
        };
    }

    ReconstructResult::Complete(full_xdr)
}

/// Encode a sorted ascending list of unique tx-set indices as the
/// `differentially encoded indices` payload of `CompactTxSetGetTxs`.
///
/// First index → unsigned LEB128. Each subsequent index → unsigned LEB128
/// of `(current - previous - 1)` (since strict ascending guarantees
/// delta ≥ 1, encoding the offset saves a bit per delta).
///
/// The input MUST be sorted ascending and contain no duplicates. Pass an
/// already-sorted slice; this function does not sort.
pub fn encode_indices(indices: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev: Option<u32> = None;
    for &i in indices {
        let to_write = match prev {
            None => i,
            Some(p) => i.saturating_sub(p).saturating_sub(1),
        };
        write_uleb128(&mut out, to_write as u64);
        prev = Some(i);
    }
    out
}

/// Inverse of `encode_indices`. Returns `None` if the input is malformed
/// (truncated LEB128, or deltas that overflow u32).
pub fn decode_indices(bytes: &[u8]) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    let mut cur = 0usize;
    let mut prev: Option<u32> = None;
    while cur < bytes.len() {
        let (val, used) = read_uleb128(&bytes[cur..])?;
        cur += used;
        let next = match prev {
            None => u32::try_from(val).ok()?,
            Some(p) => {
                let delta = u32::try_from(val).ok()?;
                p.checked_add(delta)?.checked_add(1)?
            }
        };
        out.push(next);
        prev = Some(next);
    }
    Some(out)
}

/// Append unsigned LEB128 of `v` to `out`.
fn write_uleb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            return;
        }
    }
}

/// Decode an unsigned LEB128 value at the start of `bytes`. Returns
/// `(value, bytes_consumed)`. `None` on truncation or overflow.
fn read_uleb128(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let chunk = (b & 0x7f) as u64;
        result = result.checked_add(chunk.checked_shl(shift)?)?;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift = shift.checked_add(7)?;
        if shift >= 64 {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_empty_tx_set() {
        let prev_hash = [1u8; 32];
        let xdr = build_tx_set_xdr(&prev_hash, &[]);

        // Check structure for empty tx set (no components when empty):
        // [0..4]: v = 1
        assert_eq!(&xdr[0..4], &1u32.to_be_bytes());
        // [4..36]: previousLedgerHash
        assert_eq!(&xdr[4..36], &prev_hash);
        // [36..40]: phases length = 2 (CLASSIC + SOROBAN)
        assert_eq!(&xdr[36..40], &2u32.to_be_bytes());
        // [40..44]: phase 0 discriminant = 0 (v0Components for CLASSIC)
        assert_eq!(&xdr[40..44], &0u32.to_be_bytes());
        // [44..48]: phase 0 components length = 0 (empty CLASSIC)
        assert_eq!(&xdr[44..48], &0u32.to_be_bytes());
        // [48..52]: phase 1 discriminant = 1 (parallelTxsComponent for SOROBAN, protocol >= 23)
        assert_eq!(&xdr[48..52], &1u32.to_be_bytes());
        // [52..56]: phase 1 baseFee = 0 (not present)
        assert_eq!(&xdr[52..56], &0u32.to_be_bytes());
        // [56..60]: phase 1 executionStages length = 0 (empty SOROBAN)
        assert_eq!(&xdr[56..60], &0u32.to_be_bytes());
    }

    #[test]
    fn test_build_tx_set_with_txs() {
        let prev_hash = [2u8; 32];
        let tx1 = vec![0xAA, 0xBB, 0xCC];
        let tx2 = vec![0xDD, 0xEE];

        let xdr = build_tx_set_xdr(&prev_hash, &[tx1.clone(), tx2.clone()]);

        // Structure with TXs:
        // [0..4]: v = 1
        // [4..36]: prev_hash
        // [36..40]: phases len = 2
        // [40..44]: phase 0 discriminant = 0 (v0Components)
        // [44..48]: components len = 1
        // [48..52]: component discriminant = 0 (TXSET_COMP_TXS_MAYBE_DISCOUNTED_FEE)
        // [52..56]: baseFee = 0 (not present)
        // [56..60]: txs len = 2
        assert_eq!(&xdr[56..60], &2u32.to_be_bytes());

        // TXs are appended raw (the test txs have no length prefix in this simplified format)
        // [60..63]: tx1 (3 bytes)
        assert_eq!(&xdr[60..63], &tx1[..]);
        // [63..65]: tx2 (2 bytes)
        assert_eq!(&xdr[63..65], &tx2[..]);

        // SOROBAN phase follows with parallel format (v=1):
        // [65..69]: phase 1 discriminant = 1 (parallelTxsComponent)
        assert_eq!(&xdr[65..69], &1u32.to_be_bytes());
        // [69..73]: baseFee = 0 (not present)
        assert_eq!(&xdr[69..73], &0u32.to_be_bytes());
        // [73..77]: executionStages len = 0
        assert_eq!(&xdr[73..77], &0u32.to_be_bytes());
    }

    #[test]
    fn test_hash_deterministic() {
        let prev_hash = [3u8; 32];
        let xdr = build_tx_set_xdr(&prev_hash, &[]);

        let hash1 = hash_tx_set(&xdr);
        let hash2 = hash_tx_set(&xdr);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_different_for_different_content() {
        let prev_hash = [3u8; 32];
        let xdr1 = build_tx_set_xdr(&prev_hash, &[]);
        let xdr2 = build_tx_set_xdr(&prev_hash, &[vec![1, 2, 3]]);

        let hash1 = hash_tx_set(&xdr1);
        let hash2 = hash_tx_set(&xdr2);

        assert_ne!(
            hash1, hash2,
            "Different TX sets should have different hashes"
        );
    }

    #[test]
    fn test_hash_different_for_different_prev_hash() {
        let xdr1 = build_tx_set_xdr(&[1u8; 32], &[]);
        let xdr2 = build_tx_set_xdr(&[2u8; 32], &[]);

        let hash1 = hash_tx_set(&xdr1);
        let hash2 = hash_tx_set(&xdr2);

        assert_ne!(
            hash1, hash2,
            "TX sets with different prev_hash should have different hashes"
        );
    }

    #[test]
    fn test_cache_insert_and_get() {
        let mut cache = TxSetCache::new(10);

        let tx_set = CachedTxSet {
            hash: [1u8; 32],
            xdr: vec![1, 2, 3],
            ledger_seq: 100,
            tx_hashes: vec![],
            ..Default::default()
        };

        cache.insert(tx_set.clone());

        let retrieved = cache.get(&[1u8; 32]);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().ledger_seq, 100);
    }

    #[test]
    fn test_cache_evict_before() {
        let mut cache = TxSetCache::new(10);

        cache.insert(CachedTxSet {
            hash: [1u8; 32],
            xdr: vec![],
            ledger_seq: 100,
            tx_hashes: vec![],
            ..Default::default()
        });
        cache.insert(CachedTxSet {
            hash: [2u8; 32],
            xdr: vec![],
            ledger_seq: 200,
            tx_hashes: vec![],
            ..Default::default()
        });

        cache.evict_before(150);

        assert!(cache.get(&[1u8; 32]).is_none()); // evicted
        assert!(cache.get(&[2u8; 32]).is_some()); // kept
    }

    #[test]
    fn test_cache_capacity_eviction() {
        let mut cache = TxSetCache::new(2); // Small cache

        cache.insert(CachedTxSet {
            hash: [1u8; 32],
            xdr: vec![],
            ledger_seq: 100,
            tx_hashes: vec![],
            ..Default::default()
        });
        cache.insert(CachedTxSet {
            hash: [2u8; 32],
            xdr: vec![],
            ledger_seq: 101,
            tx_hashes: vec![],
            ..Default::default()
        });

        assert_eq!(cache.len(), 2);

        // Insert 3rd - should evict one
        cache.insert(CachedTxSet {
            hash: [3u8; 32],
            xdr: vec![],
            ledger_seq: 102,
            tx_hashes: vec![],
            ..Default::default()
        });

        assert_eq!(cache.len(), 2, "Cache should stay at capacity");
        assert!(
            cache.get(&[3u8; 32]).is_some(),
            "New item should be present"
        );
    }

    #[test]
    fn test_cache_remove_returns_tx_hashes() {
        let mut cache = TxSetCache::new(10);

        let tx_hashes = vec![[0xAA; 32], [0xBB; 32]];
        cache.insert(CachedTxSet {
            hash: [1u8; 32],
            xdr: vec![],
            ledger_seq: 100,
            tx_hashes: tx_hashes.clone(),
            ..Default::default()
        });

        let removed = cache.remove(&[1u8; 32]);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap(), tx_hashes);

        // Should be gone now
        assert!(cache.get(&[1u8; 32]).is_none());
    }

    #[test]
    fn test_cache_remove_nonexistent() {
        let mut cache = TxSetCache::new(10);

        let removed = cache.remove(&[99u8; 32]);
        assert!(removed.is_none());
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = TxSetCache::new(10);

        cache.insert(CachedTxSet {
            hash: [1u8; 32],
            xdr: vec![],
            ledger_seq: 100,
            tx_hashes: vec![],
            ..Default::default()
        });
        cache.insert(CachedTxSet {
            hash: [2u8; 32],
            xdr: vec![],
            ledger_seq: 101,
            tx_hashes: vec![],
            ..Default::default()
        });

        assert_eq!(cache.len(), 2);

        cache.clear();

        assert_eq!(cache.len(), 0);
        assert!(cache.get(&[1u8; 32]).is_none());
        assert!(cache.get(&[2u8; 32]).is_none());
    }

    #[test]
    fn test_cache_overwrite_same_hash() {
        let mut cache = TxSetCache::new(10);

        cache.insert(CachedTxSet {
            hash: [1u8; 32],
            xdr: vec![1, 2, 3],
            ledger_seq: 100,
            tx_hashes: vec![],
            ..Default::default()
        });

        // Insert with same hash but different data
        cache.insert(CachedTxSet {
            hash: [1u8; 32],
            xdr: vec![4, 5, 6],
            ledger_seq: 200,
            tx_hashes: vec![],
            ..Default::default()
        });

        assert_eq!(cache.len(), 1, "Should not create duplicate");
        let retrieved = cache.get(&[1u8; 32]).unwrap();
        assert_eq!(retrieved.ledger_seq, 200, "Should have newer data");
        assert_eq!(retrieved.xdr, vec![4, 5, 6]);
    }

    #[test]
    fn test_build_compact_tx_set_xdr_empty() {
        let tx_set_hash = [0xAA; 32];
        let prev = [0xBB; 32];
        let bytes = build_compact_tx_set_xdr(&tx_set_hash, &prev, None, &[]);

        let parsed = CompactTxSet::from_xdr(&bytes, Limits::none()).unwrap();
        assert_eq!(parsed.tx_set_hash.0, tx_set_hash);
        assert_eq!(parsed.previous_ledger_hash.0, prev);
        assert_eq!(parsed.base_fee, None);
        assert_eq!(parsed.txs.len(), 0);
    }

    #[test]
    fn test_build_compact_tx_set_xdr_single_tx() {
        let tx_set_hash = [0x11; 32];
        let prev = [0x22; 32];
        let tx_hashes = vec![[0x33; 32]];
        let bytes = build_compact_tx_set_xdr(&tx_set_hash, &prev, Some(100), &tx_hashes);

        let parsed = CompactTxSet::from_xdr(&bytes, Limits::none()).unwrap();
        assert_eq!(parsed.base_fee, Some(100));
        assert_eq!(parsed.txs.len(), 6, "single tx siphash is 6 bytes");

        // Same inputs produce identical output (deterministic).
        let bytes2 = build_compact_tx_set_xdr(&tx_set_hash, &prev, Some(100), &tx_hashes);
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn test_build_compact_tx_set_xdr_multi_tx() {
        let tx_set_hash = [0x44; 32];
        let prev = [0x55; 32];
        let tx_hashes = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
        let bytes = build_compact_tx_set_xdr(&tx_set_hash, &prev, None, &tx_hashes);

        let parsed = CompactTxSet::from_xdr(&bytes, Limits::none()).unwrap();
        assert_eq!(parsed.txs.len(), 18, "3 txs * 6 bytes each");

        let chunk0 = &parsed.txs[0..6];
        let chunk1 = &parsed.txs[6..12];
        let chunk2 = &parsed.txs[12..18];
        assert_ne!(chunk0, chunk1);
        assert_ne!(chunk1, chunk2);
    }

    #[test]
    fn test_build_compact_tx_set_xdr_key_depends_on_tx_set_hash() {
        let prev = [0u8; 32];
        let tx_hashes = vec![[0xCD; 32]];

        let bytes_a = build_compact_tx_set_xdr(&[0x01; 32], &prev, None, &tx_hashes);
        let bytes_b = build_compact_tx_set_xdr(&[0x02; 32], &prev, None, &tx_hashes);

        let a = CompactTxSet::from_xdr(&bytes_a, Limits::none()).unwrap();
        let b = CompactTxSet::from_xdr(&bytes_b, Limits::none()).unwrap();
        assert_ne!(
            a.txs.as_slice(),
            b.txs.as_slice(),
            "different tx_set_hash keys must produce different siphash output"
        );
    }

    // ─── LEB128 differential index encoding ───

    #[test]
    fn test_leb128_indices_roundtrip_empty() {
        let encoded = encode_indices(&[]);
        assert!(encoded.is_empty());
        assert_eq!(decode_indices(&encoded), Some(vec![]));
    }

    #[test]
    fn test_leb128_indices_roundtrip_single() {
        let encoded = encode_indices(&[42]);
        assert_eq!(decode_indices(&encoded), Some(vec![42]));
    }

    #[test]
    fn test_leb128_indices_roundtrip_dense() {
        let input: Vec<u32> = (0..20).collect();
        let encoded = encode_indices(&input);
        // 20 deltas of 0 (after first), each one byte
        assert_eq!(encoded.len(), 20);
        assert_eq!(decode_indices(&encoded), Some(input));
    }

    #[test]
    fn test_leb128_indices_roundtrip_sparse() {
        let input: Vec<u32> = vec![0, 100, 200, 1000, 100_000, 1_000_000];
        let encoded = encode_indices(&input);
        assert_eq!(decode_indices(&encoded), Some(input));
    }

    #[test]
    fn test_leb128_indices_decode_truncated() {
        // 0x80 indicates more bytes to come, but no more bytes follow.
        assert_eq!(decode_indices(&[0x80]), None);
    }

    // ─── Reconstruction ───

    /// Build a CompactTxSet from a list of (tx_hash, _tx_data) pairs.
    fn make_compact(
        tx_set_hash: [u8; 32],
        prev: [u8; 32],
        base_fee: Option<i64>,
        tx_hashes: &[TxHash],
    ) -> CompactTxSet {
        let bytes = build_compact_tx_set_xdr(&tx_set_hash, &prev, base_fee, tx_hashes);
        CompactTxSet::from_xdr(&bytes, Limits::none()).unwrap()
    }

    #[test]
    fn test_reconstruct_complete_empty_set() {
        // Build an empty full tx set, derive its hash, build the matching
        // compact, then reconstruct from an empty mempool.
        let prev = [0x42; 32];
        let full_xdr = build_full_tx_set_xdr(&prev, None, &[]);
        let tx_set_hash = hash_tx_set(&full_xdr);

        let compact = make_compact(tx_set_hash, prev, None, &[]);
        let result = reconstruct_full_tx_set(&compact, std::iter::empty());
        match result {
            ReconstructResult::Complete(xdr) => {
                assert_eq!(hash_tx_set(&xdr), tx_set_hash);
                assert_eq!(xdr, full_xdr);
            }
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[test]
    fn test_reconstruct_missing_when_mempool_empty() {
        // Build a tx set with one tx; mempool is empty so reconstruction
        // must report the index as missing.
        let prev = [0x11; 32];
        let tx_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let tx_hash = blake2b_hash(&tx_data);

        let full_xdr = build_full_tx_set_xdr(&prev, None, &[tx_data.clone()]);
        let tx_set_hash = hash_tx_set(&full_xdr);

        let compact = make_compact(tx_set_hash, prev, None, &[tx_hash]);
        let result = reconstruct_full_tx_set(&compact, std::iter::empty());
        match result {
            ReconstructResult::Missing { indices, matched } => {
                assert_eq!(indices, vec![0]);
                assert_eq!(matched.len(), 1);
                assert!(matched[0].is_none());
            }
            other => panic!("expected Missing, got {:?}", other),
        }
    }

    #[test]
    fn test_reconstruct_complete_when_mempool_has_all() {
        let prev = [0x77; 32];
        let tx_data = vec![1u8, 2, 3, 4, 5];
        let tx_hash = blake2b_hash(&tx_data);

        let full_xdr = build_full_tx_set_xdr(&prev, None, &[tx_data.clone()]);
        let tx_set_hash = hash_tx_set(&full_xdr);

        let compact = make_compact(tx_set_hash, prev, None, &[tx_hash]);
        let result =
            reconstruct_full_tx_set(&compact, vec![(tx_hash, tx_data.clone())].into_iter());
        match result {
            ReconstructResult::Complete(xdr) => {
                assert_eq!(hash_tx_set(&xdr), tx_set_hash);
                assert_eq!(xdr, full_xdr);
            }
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[test]
    fn test_reconstruct_complete_with_base_fee() {
        let prev = [0x99; 32];
        let tx_a = vec![10u8; 12];
        let tx_b = vec![20u8; 16];
        let hash_a = blake2b_hash(&tx_a);
        let hash_b = blake2b_hash(&tx_b);

        let full_xdr = build_full_tx_set_xdr(&prev, Some(12345), &[tx_a.clone(), tx_b.clone()]);
        let tx_set_hash = hash_tx_set(&full_xdr);

        let compact = make_compact(tx_set_hash, prev, Some(12345), &[hash_a, hash_b]);
        let result = reconstruct_full_tx_set(
            &compact,
            vec![(hash_a, tx_a.clone()), (hash_b, tx_b.clone())].into_iter(),
        );
        match result {
            ReconstructResult::Complete(xdr) => assert_eq!(hash_tx_set(&xdr), tx_set_hash),
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[test]
    fn test_reconstruct_missing_partial() {
        let prev = [0x33; 32];
        let tx_a = vec![0xAA; 8];
        let tx_b = vec![0xBB; 8];
        let tx_c = vec![0xCC; 8];
        let hash_a = blake2b_hash(&tx_a);
        let hash_b = blake2b_hash(&tx_b);
        let hash_c = blake2b_hash(&tx_c);

        let full_xdr =
            build_full_tx_set_xdr(&prev, None, &[tx_a.clone(), tx_b.clone(), tx_c.clone()]);
        let tx_set_hash = hash_tx_set(&full_xdr);

        let compact = make_compact(tx_set_hash, prev, None, &[hash_a, hash_b, hash_c]);
        // Mempool only has tx_a and tx_c; tx_b is missing.
        let result = reconstruct_full_tx_set(
            &compact,
            vec![(hash_a, tx_a.clone()), (hash_c, tx_c.clone())].into_iter(),
        );
        match result {
            ReconstructResult::Missing { indices, matched } => {
                assert_eq!(indices, vec![1]);
                assert_eq!(matched.len(), 3);
                assert!(matched[0].is_some());
                assert!(matched[1].is_none());
                assert!(matched[2].is_some());
            }
            other => panic!("expected Missing, got {:?}", other),
        }
    }
}
