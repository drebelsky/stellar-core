//! Stellar XDR parsing helpers for overlay wire data.
//!
//! Perf note: XDR is a canonical encoding — a value has exactly one valid
//! byte representation, and `from_xdr` requires the input to be consumed
//! in full. Bytes that parse successfully therefore *are* the canonical
//! encoding, so nothing here re-encodes after a successful parse. A
//! `StellarMessage` is encoded as a 4-byte big-endian discriminant
//! followed by the arm's own encoding, so wrapping already-validated
//! payload bytes is a prepend, not a decode/encode round trip. The
//! equivalence tests below pin both assumptions against the stellar-xdr
//! encoder.

use sha2::{Digest, Sha256};
use std::fmt;
use stellar_xdr::curr as xdr;
use xdr::{
    Limits, MessageType, MuxedAccount, Operation, OperationBody, ReadXdr, ScpBallot, ScpEnvelope,
    ScpStatementPledges, StellarMessage, StellarValue, TransactionEnvelope, Uint256, WriteXdr,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxClass {
    Classic,
    Soroban,
}

/// A transaction that was validated at an ingress boundary (Core IPC or a
/// peer stream). `envelope_xdr` holds the canonical encoding and
/// `full_hash` its SHA-256; both are computed exactly once and passed
/// through the pipeline instead of being re-derived at every layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTx {
    pub envelope_xdr: Vec<u8>,
    pub full_hash: [u8; 32],
    pub source_account: [u8; 32],
    pub sequence: i64,
    pub fee: u64,
    pub num_ops: u32,
    pub class: TxClass,
}

impl ParsedTx {
    pub fn fee_per_op(&self) -> i64 {
        (self.fee / u64::from(self.num_ops.max(1))) as i64
    }
}

#[derive(Debug)]
pub enum XdrError {
    Malformed(String),
    UnsupportedFeeBump,
}

impl fmt::Display for XdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XdrError::Malformed(e) => write!(f, "malformed XDR: {e}"),
            XdrError::UnsupportedFeeBump => write!(f, "fee-bump transactions are unsupported"),
        }
    }
}

impl std::error::Error for XdrError {}

impl From<xdr::Error> for XdrError {
    fn from(value: xdr::Error) -> Self {
        XdrError::Malformed(value.to_string())
    }
}

pub(crate) fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Validate transaction bytes and extract flooding metadata. The single
/// parse on any path a transaction takes through this process.
pub fn parse_supported_transaction(bytes: &[u8]) -> Result<ParsedTx, XdrError> {
    let envelope = TransactionEnvelope::from_xdr(bytes, Limits::none())?;
    let (source_account, sequence, fee, num_ops, class) = match &envelope {
        TransactionEnvelope::TxV0(v0) => {
            let tx = &v0.tx;
            (
                tx.source_account_ed25519.0,
                tx.seq_num.0,
                tx.fee as u64,
                tx.operations.len() as u32,
                classify_operations(tx.operations.as_ref()),
            )
        }
        TransactionEnvelope::Tx(v1) => {
            let tx = &v1.tx;
            (
                source_account_bytes(&tx.source_account),
                tx.seq_num.0,
                tx.fee as u64,
                tx.operations.len() as u32,
                classify_operations(tx.operations.as_ref()),
            )
        }
        TransactionEnvelope::TxFeeBump(_) => {
            // TODO: Support fee-bump transactions by classifying the inner
            // transaction and using the outer fee bid for prioritization.
            return Err(XdrError::UnsupportedFeeBump);
        }
    };

    Ok(ParsedTx {
        envelope_xdr: bytes.to_vec(),
        full_hash: sha256_hash(bytes),
        source_account,
        sequence,
        fee,
        num_ops,
        class,
    })
}

pub(crate) fn parse_stellar_message(bytes: &[u8]) -> Result<StellarMessage, XdrError> {
    Ok(StellarMessage::from_xdr(bytes, Limits::none())?)
}

pub(crate) fn encode_stellar_message(message: &StellarMessage) -> Result<Vec<u8>, XdrError> {
    Ok(message.to_xdr(Limits::none())?)
}

/// Read the `MessageType` discriminant of an encoded `StellarMessage`
/// without parsing the body.
pub(crate) fn peek_message_type(data: &[u8]) -> Option<MessageType> {
    let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
    MessageType::try_from(i32::from_be_bytes(bytes)).ok()
}

/// Prepend the `StellarMessage` discriminant to an already-canonical arm
/// payload. Callers must only pass bytes that were validated at ingress.
fn wrap_stellar_message(message_type: MessageType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(message_type as i32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub(crate) fn wrap_transaction_message(tx_xdr: &[u8]) -> Vec<u8> {
    wrap_stellar_message(MessageType::Transaction, tx_xdr)
}

pub(crate) fn wrap_scp_message(envelope_xdr: &[u8]) -> Vec<u8> {
    wrap_stellar_message(MessageType::ScpMessage, envelope_xdr)
}

pub(crate) fn wrap_generalized_tx_set_message(tx_set_xdr: &[u8]) -> Vec<u8> {
    wrap_stellar_message(MessageType::GeneralizedTxSet, tx_set_xdr)
}

pub(crate) fn encode_get_scp_state(ledger_seq: u32) -> Result<Vec<u8>, XdrError> {
    encode_stellar_message(&StellarMessage::GetScpState(ledger_seq))
}

pub(crate) fn encode_get_tx_set(hash: [u8; 32]) -> Result<Vec<u8>, XdrError> {
    encode_stellar_message(&StellarMessage::GetTxSet(Uint256(hash)))
}

/// Check that `data` is the tx set whose contents-hash is `expected_hash`
/// (the hash of a `GeneralizedTransactionSet` is the SHA-256 of its XDR).
/// A hash-only check: structural validation is left to the consumer.
pub fn checked_tx_set_hash(expected_hash: &[u8; 32], data: &[u8]) -> Result<(), XdrError> {
    let actual_hash = sha256_hash(data);
    if &actual_hash == expected_hash {
        Ok(())
    } else {
        Err(XdrError::Malformed(format!(
            "tx set hash mismatch: expected {:02x?}, got {:02x?}",
            &expected_hash[..4],
            &actual_hash[..4]
        )))
    }
}

pub fn extract_txset_hashes_from_scp(envelope_xdr: &[u8]) -> Vec<[u8; 32]> {
    let Ok(envelope) = ScpEnvelope::from_xdr(envelope_xdr, Limits::none()) else {
        return Vec::new();
    };

    let mut hashes = Vec::new();
    match &envelope.statement.pledges {
        ScpStatementPledges::Prepare(prepare) => {
            collect_ballot_hash(&mut hashes, &prepare.ballot);
            if let Some(ballot) = &prepare.prepared {
                collect_ballot_hash(&mut hashes, ballot);
            }
            if let Some(ballot) = &prepare.prepared_prime {
                collect_ballot_hash(&mut hashes, ballot);
            }
        }
        ScpStatementPledges::Confirm(confirm) => collect_ballot_hash(&mut hashes, &confirm.ballot),
        ScpStatementPledges::Externalize(externalize) => {
            collect_ballot_hash(&mut hashes, &externalize.commit);
        }
        ScpStatementPledges::Nominate(nominate) => {
            for value in nominate.votes.iter().chain(nominate.accepted.iter()) {
                collect_stellar_value_hash(&mut hashes, value.as_ref());
            }
        }
    }
    hashes
}

fn collect_ballot_hash(hashes: &mut Vec<[u8; 32]>, ballot: &ScpBallot) {
    collect_stellar_value_hash(hashes, ballot.value.as_ref());
}

fn collect_stellar_value_hash(hashes: &mut Vec<[u8; 32]>, value: &[u8]) {
    let Ok(stellar_value) = StellarValue::from_xdr(value, Limits::none()) else {
        return;
    };
    let hash: [u8; 32] = stellar_value.tx_set_hash.into();
    if !hashes.contains(&hash) {
        hashes.push(hash);
    }
}

fn source_account_bytes(account: &MuxedAccount) -> [u8; 32] {
    match account {
        MuxedAccount::Ed25519(ed25519) => ed25519.0,
        MuxedAccount::MuxedEd25519(muxed) => muxed.ed25519.0,
    }
}

fn classify_operations(operations: &[Operation]) -> TxClass {
    if operations.iter().any(|op| {
        matches!(
            op.body,
            OperationBody::InvokeHostFunction(_)
                | OperationBody::ExtendFootprintTtl(_)
                | OperationBody::RestoreFootprint(_)
        )
    }) {
        TxClass::Soroban
    } else {
        TxClass::Classic
    }
}

/// Canonically encode and hash a tx set (test helper).
#[cfg(test)]
pub(crate) fn canonical_generalized_tx_set_xdr(
    tx_set: xdr::GeneralizedTransactionSet,
) -> Result<([u8; 32], Vec<u8>), XdrError> {
    let canonical = tx_set.to_xdr(Limits::none())?;
    let hash = sha256_hash(&canonical);
    Ok((hash, canonical))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use xdr::{
        DecoratedSignature, GeneralizedTransactionSet, Hash, Operation, ScpNomination,
        ScpStatementPledges, SequenceNumber, StellarValueExt, TimePoint, Transaction,
        TransactionV1Envelope, Value, VecM,
    };

    pub(crate) fn valid_transaction_xdr(fee: u32, sequence: i64, num_ops: usize) -> Vec<u8> {
        let mut tx = Transaction {
            fee,
            seq_num: SequenceNumber(sequence),
            ..Transaction::default()
        };
        tx.operations = VecM::try_from(vec![Operation::default(); num_ops]).unwrap();
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::<DecoratedSignature, 20>::default(),
        });
        envelope.to_xdr(Limits::none()).unwrap()
    }

    #[test]
    fn parses_supported_transaction_metadata() {
        let tx_xdr = valid_transaction_xdr(1000, 12345, 1);
        let parsed = parse_supported_transaction(&tx_xdr).unwrap();

        assert_eq!(parsed.fee, 1000);
        assert_eq!(parsed.num_ops, 1);
        assert_eq!(parsed.sequence, 12345);
        assert_eq!(parsed.class, TxClass::Classic);
        assert_eq!(parsed.envelope_xdr, tx_xdr);
        assert_eq!(parsed.full_hash, sha256_hash(&tx_xdr));
    }

    #[test]
    fn rejects_malformed_transaction_xdr() {
        assert!(matches!(
            parse_supported_transaction(&[1, 2, 3]),
            Err(XdrError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_trailing_garbage_after_transaction() {
        let mut tx_xdr = valid_transaction_xdr(1000, 1, 1);
        tx_xdr.push(0);
        assert!(matches!(
            parse_supported_transaction(&tx_xdr),
            Err(XdrError::Malformed(_))
        ));
    }

    /// Pins the assumption that bytes accepted by `from_xdr` are the
    /// canonical encoding (so keeping the input bytes == re-encoding).
    #[test]
    fn accepted_transaction_bytes_are_canonical() {
        let tx_xdr = valid_transaction_xdr(1000, 12345, 3);
        let envelope = TransactionEnvelope::from_xdr(&tx_xdr, Limits::none()).unwrap();
        assert_eq!(envelope.to_xdr(Limits::none()).unwrap(), tx_xdr);
    }

    #[test]
    fn wrap_transaction_message_matches_full_encoder() {
        let tx_xdr = valid_transaction_xdr(1000, 1, 1);
        let envelope = TransactionEnvelope::from_xdr(&tx_xdr, Limits::none()).unwrap();
        let full = encode_stellar_message(&StellarMessage::Transaction(envelope)).unwrap();
        assert_eq!(wrap_transaction_message(&tx_xdr), full);
        assert_eq!(
            peek_message_type(&full),
            Some(MessageType::Transaction)
        );
    }

    #[test]
    fn wrap_scp_message_matches_full_encoder() {
        let mut envelope = ScpEnvelope::default();
        envelope.statement.slot_index = 7;
        let envelope_xdr = envelope.to_xdr(Limits::none()).unwrap();
        let full = encode_stellar_message(&StellarMessage::ScpMessage(envelope)).unwrap();
        assert_eq!(wrap_scp_message(&envelope_xdr), full);
        assert_eq!(peek_message_type(&full), Some(MessageType::ScpMessage));
        // The inbound path recovers the envelope bytes by slicing off the
        // discriminant.
        assert_eq!(&full[4..], envelope_xdr.as_slice());
    }

    #[test]
    fn wrap_generalized_tx_set_message_matches_full_encoder() {
        let tx_set = GeneralizedTransactionSet::default();
        let tx_set_xdr = tx_set.to_xdr(Limits::none()).unwrap();
        let full =
            encode_stellar_message(&StellarMessage::GeneralizedTxSet(tx_set)).unwrap();
        assert_eq!(wrap_generalized_tx_set_message(&tx_set_xdr), full);
        assert_eq!(
            peek_message_type(&full),
            Some(MessageType::GeneralizedTxSet)
        );
        assert_eq!(&full[4..], tx_set_xdr.as_slice());
    }

    /// Pins the wire layout the txset stream handler relies on:
    /// GetTxSet == 4-byte discriminant + 32-byte hash.
    #[test]
    fn get_tx_set_is_discriminant_plus_hash() {
        let hash = [0x5a; 32];
        let encoded = encode_get_tx_set(hash).unwrap();
        assert_eq!(encoded.len(), 36);
        assert_eq!(peek_message_type(&encoded), Some(MessageType::GetTxSet));
        assert_eq!(&encoded[4..], &hash);
    }

    #[test]
    fn checked_tx_set_hash_accepts_matching_and_rejects_mismatch() {
        let data = b"arbitrary tx set bytes".to_vec();
        let hash = sha256_hash(&data);
        assert!(checked_tx_set_hash(&hash, &data).is_ok());
        assert!(checked_tx_set_hash(&[0u8; 32], &data).is_err());
    }

    #[test]
    fn extracts_txset_hashes_from_scp_values() {
        let expected_hash = [0x42; 32];
        let stellar_value = StellarValue {
            tx_set_hash: Hash(expected_hash),
            close_time: TimePoint(1_704_067_200),
            upgrades: VecM::default(),
            ext: StellarValueExt::Basic,
        };
        let value = Value::try_from(stellar_value.to_xdr(Limits::none()).unwrap()).unwrap();

        let mut envelope = ScpEnvelope::default();
        envelope.statement.pledges = ScpStatementPledges::Nominate(ScpNomination {
            quorum_set_hash: Hash([0; 32]),
            votes: VecM::try_from(vec![value.clone()]).unwrap(),
            accepted: VecM::try_from(vec![value]).unwrap(),
        });

        let envelope_xdr = envelope.to_xdr(Limits::none()).unwrap();
        let hashes = extract_txset_hashes_from_scp(&envelope_xdr);

        assert_eq!(hashes, vec![expected_hash]);
    }
}
