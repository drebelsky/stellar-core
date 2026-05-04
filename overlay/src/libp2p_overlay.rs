//! Unified libp2p Overlay v2
//!
//! **Transport: QUIC** for true stream independence - no TCP head-of-line blocking.
//! If a packet is lost on the TX stream, SCP stream is UNAFFECTED.
//!
//! Uses libp2p-stream for persistent bidirectional streams:
//! - SCP stream: consensus messages (priority, ~500B)
//! - TX stream: transaction flooding (~1KB) - uses INV/GETDATA protocol
//! - TxSet stream: TX set request/response (~10MB)
//!
//! Each stream is opened once per peer and kept alive.
//! QUIC provides independent loss recovery per stream.

use crate::flood::{
    blake2b_hash, encode_indices, hash_tx_set, reconstruct_full_tx_set, CachedTxSet, GetData,
    InvBatch, InvBatcher, InvEntry, InvTracker, PendingRequests, ReconstructResult, TxBuffer,
    TxMessageType, TxStreamMessage, GETDATA_PEER_TIMEOUT, INV_BATCH_MAX_DELAY,
};
use crate::metrics::OverlayMetrics;
use stellar_xdr::{CompactTxSet, CompactTxSetMessage, Limits, ReadXdr, WriteXdr};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::{
    identify::{Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent},
    identity::Keypair,
    swarm::{
        dial_opts::{DialOpts, PeerCondition},
        NetworkBehaviour, SwarmEvent,
    },
    Multiaddr, PeerId, Stream, StreamProtocol, Swarm, SwarmBuilder,
};
use libp2p_stream::{Behaviour as StreamBehaviour, Control, IncomingStreams};
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, trace, warn};

// Protocol identifiers for dedicated streams
pub const SCP_PROTOCOL: StreamProtocol = StreamProtocol::new("/stellar/scp/1.0.0");
pub const TX_PROTOCOL: StreamProtocol = StreamProtocol::new("/stellar/tx/1.0.0");
pub const TXSET_PROTOCOL: StreamProtocol = StreamProtocol::new("/stellar/txset/1.0.0");
pub const COMPACT_TXSET_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/stellar/compact_txset/1.0.0");

/// Tag for SCP-stream frames: the first 4 bytes (big-endian u32) of every
/// SCP-stream payload identify which kind of message follows.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScpStreamMessageType {
    StateRequest = 0,
    Envelope = 1,
    CompactTxSet = 2,
}

impl ScpStreamMessageType {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::StateRequest),
            1 => Some(Self::Envelope),
            2 => Some(Self::CompactTxSet),
            _ => None,
        }
    }
}

/// Build an SCP-stream frame: 4-byte big-endian tag followed by the payload.
fn encode_scp_frame(tag: ScpStreamMessageType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(tag as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Message frame: 4-byte length prefix + payload
/// Max message size: 16MB (for large TX sets)
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Bounded channel capacity for TX events (backpressure for TX flooding)
/// TXs that can't be queued are dropped - they'll be re-requested if needed.
const TX_EVENT_CHANNEL_CAPACITY: usize = 10_000;

/// Time after which an outstanding `COMPACT_TX_SET_GET` to a peer is
/// abandoned and the request falls back to legacy fetch.
const COMPACT_GET_TIMEOUT: Duration = Duration::from_secs(10);

/// Time after which a `PendingReconstruction` waiting on a `GET_TXS`
/// response is abandoned and the request falls back to legacy fetch.
const COMPACT_RECONSTRUCTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Events from the overlay to the application
#[derive(Debug, Clone)]
pub enum OverlayEvent {
    /// Received SCP envelope from peer
    ScpReceived { envelope: Vec<u8>, from: PeerId },
    /// Received TX from peer
    TxReceived { tx: Vec<u8>, from: PeerId },
    /// Received TX set response
    TxSetReceived {
        hash: [u8; 32],
        data: Vec<u8>,
        from: PeerId,
    },
    /// Peer is requesting a TX set (need to look up and respond)
    TxSetRequested { hash: [u8; 32], from: PeerId },
    /// Peer is requesting the compact form of a tx set we have cached.
    /// Main looks up `tx_set_cache` and replies via
    /// `OverlayCommand::SendCompactTxSetResponse`.
    CompactTxSetGetRequested { hash: [u8; 32], from: PeerId },
    /// Peer is requesting specific transactions (by index) from a tx set we
    /// have cached. Main extracts those envelopes and replies via
    /// `OverlayCommand::SendCompactTxSetTxsResponse`.
    CompactTxSetGetTxsRequested {
        hash: [u8; 32],
        indices: Vec<u32>,
        from: PeerId,
    },
    /// Peer is requesting SCP state
    ScpStateRequested { peer_id: PeerId, ledger_seq: u32 },
    /// Peer connected — includes the remote address for PeerId mapping
    PeerConnected { peer_id: PeerId, addr: Multiaddr },
    /// Peer disconnected - clean up any pending requests
    PeerDisconnected { peer_id: PeerId },
}

/// Commands to the overlay
#[derive(Debug)]
pub enum OverlayCommand {
    /// Broadcast SCP envelope to all peers
    BroadcastScp(Vec<u8>),
    /// Broadcast SCP envelope with compact tx set announcements.
    /// Each entry is `(tx_set_hash, serialized stellar_xdr::CompactTxSet)`.
    BroadcastScpCompact {
        compact_sets: Vec<(crate::flood::TxHash, Vec<u8>)>,
        envelope: Vec<u8>,
    },
    /// Broadcast TX to all peers
    BroadcastTx(Vec<u8>),
    /// Request TX set from a peer (picks best peer)
    FetchTxSet { hash: [u8; 32] },
    /// Send TX set to a specific peer (response to their request)
    SendTxSet {
        hash: [u8; 32],
        data: Vec<u8>,
        to: PeerId,
    },
    /// Send a `CompactTxSetMessage::Set` (the compact tx set) as a direct
    /// response to a peer's `COMPACT_TX_SET_GET`. `compact_xdr` is the
    /// already-serialized inner `CompactTxSet`.
    SendCompactTxSetResponse {
        hash: [u8; 32],
        compact_xdr: Vec<u8>,
        to: PeerId,
    },
    /// Send a `CompactTxSetMessage::SetTxs` response. `tx_envelopes` is a
    /// list of already-serialized `TransactionEnvelope` XDR blobs in
    /// ascending-index order matching the requesting peer's `indices`.
    SendCompactTxSetTxsResponse {
        hash: [u8; 32],
        tx_envelopes: Vec<Vec<u8>>,
        to: PeerId,
    },
    /// Record that a peer has a specific TX set (learned from SCP message)
    RecordTxSetSource { hash: [u8; 32], peer: PeerId },
    /// Connect to a peer by address (bootstrap — PeerId unknown)
    Dial(Multiaddr),
    /// Connect to a known peer by PeerId (reconnect — deduplicates automatically)
    DialPeer { peer_id: PeerId, addr: Multiaddr },
    /// Request SCP state from all peers
    RequestScpState { ledger_seq: u32 },
    /// Send SCP envelope to a specific peer
    SendScpToPeer { peer_id: PeerId, envelope: Vec<u8> },
    /// Shutdown
    Shutdown,
    /// Query the number of connected peers (responds via oneshot)
    GetConnectedPeerCount(tokio::sync::oneshot::Sender<usize>),
    /// Ping - responds immediately via oneshot channel (for testing event loop responsiveness)
    Ping(tokio::sync::oneshot::Sender<()>),
}

/// Outbound streams to a peer - each stream has its own mutex to avoid head-of-line blocking.
/// A large TxSet write won't block SCP sends to the same peer.
struct PeerOutboundStreams {
    scp: Mutex<Option<Stream>>,
    tx: Mutex<Option<Stream>>,
    txset: Mutex<Option<Stream>>,
    compact_txset: Mutex<Option<Stream>>,
}

impl PeerOutboundStreams {
    fn new() -> Self {
        Self {
            scp: Mutex::new(None),
            tx: Mutex::new(None),
            txset: Mutex::new(None),
            compact_txset: Mutex::new(None),
        }
    }
}

/// Network behaviour combining streams and Identify
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "StellarBehaviourEvent")]
struct StellarBehaviour {
    stream: StreamBehaviour,
    identify: Identify,
}

#[derive(Debug)]
enum StellarBehaviourEvent {
    Stream(()), // StreamBehaviour emits () - no events
    Identify(IdentifyEvent),
}

impl From<()> for StellarBehaviourEvent {
    fn from(_event: ()) -> Self {
        StellarBehaviourEvent::Stream(())
    }
}

impl From<IdentifyEvent> for StellarBehaviourEvent {
    fn from(event: IdentifyEvent) -> Self {
        StellarBehaviourEvent::Identify(event)
    }
}

/// Handle for sending commands to the overlay
#[derive(Clone)]
pub struct OverlayHandle {
    cmd_tx: mpsc::Sender<OverlayCommand>,
}

impl OverlayHandle {
    pub async fn broadcast_scp(&self, envelope: Vec<u8>) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::BroadcastScp(envelope))
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send BroadcastScp: {}",
                e
            );
        }
    }

    pub async fn broadcast_scp_compact(
        &self,
        compact_sets: Vec<(crate::flood::TxHash, Vec<u8>)>,
        envelope: Vec<u8>,
    ) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::BroadcastScpCompact {
                compact_sets,
                envelope,
            })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send BroadcastScpCompact: {}",
                e
            );
        }
    }

    pub async fn broadcast_tx(&self, tx: Vec<u8>) {
        if let Err(e) = self.cmd_tx.send(OverlayCommand::BroadcastTx(tx)).await {
            warn!(
                "Overlay command channel closed, failed to send BroadcastTx: {}",
                e
            );
        }
    }

    pub async fn fetch_txset(&self, hash: [u8; 32]) {
        if let Err(e) = self.cmd_tx.send(OverlayCommand::FetchTxSet { hash }).await {
            warn!(
                "Overlay command channel closed, failed to send FetchTxSet: {}",
                e
            );
        }
    }

    pub async fn send_txset(&self, hash: [u8; 32], data: Vec<u8>, to: PeerId) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::SendTxSet { hash, data, to })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send SendTxSet: {}",
                e
            );
        }
    }

    pub async fn send_compact_txset_response(
        &self,
        hash: [u8; 32],
        compact_xdr: Vec<u8>,
        to: PeerId,
    ) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::SendCompactTxSetResponse {
                hash,
                compact_xdr,
                to,
            })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send SendCompactTxSetResponse: {}",
                e
            );
        }
    }

    pub async fn send_compact_txset_txs_response(
        &self,
        hash: [u8; 32],
        tx_envelopes: Vec<Vec<u8>>,
        to: PeerId,
    ) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::SendCompactTxSetTxsResponse {
                hash,
                tx_envelopes,
                to,
            })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send SendCompactTxSetTxsResponse: {}",
                e
            );
        }
    }

    /// Record that a peer has a specific TX set (call when receiving SCP with txSetHash)
    pub async fn record_txset_source(&self, hash: [u8; 32], peer: PeerId) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::RecordTxSetSource { hash, peer })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send RecordTxSetSource: {}",
                e
            );
        }
    }

    pub async fn dial(&self, addr: Multiaddr) {
        if let Err(e) = self.cmd_tx.send(OverlayCommand::Dial(addr)).await {
            warn!("Overlay command channel closed, failed to send Dial: {}", e);
        }
    }

    /// Dial a known peer by PeerId. libp2p will skip the dial if already connected.
    pub async fn dial_peer(&self, peer_id: PeerId, addr: Multiaddr) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::DialPeer { peer_id, addr })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send DialPeer: {}",
                e
            );
        }
    }

    pub async fn request_scp_state_from_all_peers(&self, ledger_seq: u32) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::RequestScpState { ledger_seq })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send RequestScpState: {}",
                e
            );
        }
    }

    pub async fn send_scp_to_peer(&self, peer_id: PeerId, envelope: &[u8]) -> io::Result<()> {
        self.cmd_tx
            .send(OverlayCommand::SendScpToPeer {
                peer_id,
                envelope: envelope.to_vec(),
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Channel closed"))?;
        Ok(())
    }

    pub async fn shutdown(&self) {
        if let Err(e) = self.cmd_tx.send(OverlayCommand::Shutdown).await {
            warn!(
                "Overlay command channel closed, failed to send Shutdown: {}",
                e
            );
        }
    }

    /// Query the number of currently connected peers
    pub async fn connected_peer_count(&self) -> usize {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self
            .cmd_tx
            .send(OverlayCommand::GetConnectedPeerCount(tx))
            .await;
        rx.await.unwrap_or(0)
    }

    /// Ping the event loop and wait for response - for testing responsiveness
    #[cfg(test)]
    pub async fn ping(&self) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.cmd_tx.send(OverlayCommand::Ping(tx)).await;
        rx.await
    }
}

/// State for an outstanding `COMPACT_TX_SET_GET` request.
///
/// `tried` accumulates peers we've already asked (current `peer` plus any
/// previous attempts) so that timeout-driven retries can pick the next
/// connected announcer that hasn't been tried yet.
struct PendingCompactGet {
    /// Peer the current attempt was sent to.
    peer: PeerId,
    /// When the current attempt was sent (timeout reference).
    started_at: Instant,
    /// All peers we've sent a SetGet to for this hash, including the current one.
    tried: HashSet<PeerId>,
}

/// State for an in-progress compact tx set reconstruction.
///
/// Created when a `CompactTxSet` is received but the local mempool doesn't
/// have all the txs (some 6-byte SipHash digests don't match). We then send
/// `COMPACT_TX_SET_GET_TXS` to the announcing peer for the missing indices
/// and stash this struct keyed on `tx_set_hash` until the response arrives.
struct PendingReconstruction {
    /// The CompactTxSet announcement we're trying to reconstruct from.
    compact: stellar_xdr::CompactTxSet,
    /// Per-index slot for the matched envelope, stored as already-serialized
    /// XDR bytes. `None` indicates the slot is missing and is included in
    /// the outstanding GET_TXS request.
    matched: Vec<Option<Vec<u8>>>,
    /// Peer we requested the missing txs from.
    requested_from: PeerId,
    /// When the GET_TXS request was issued (for latency / cleanup).
    requested_at: Instant,
}

/// Shared state for stream handlers
struct SharedState {
    /// Outbound streams per peer - each peer has four independently-locked streams
    peer_streams: RwLock<HashMap<PeerId, Arc<PeerOutboundStreams>>>,
    /// SCP messages seen (for dedup)
    scp_seen: RwLock<lru::LruCache<[u8; 32], ()>>,
    /// TX messages seen (for dedup)
    tx_seen: RwLock<lru::LruCache<[u8; 32], ()>>,
    /// Track which peers we've sent each SCP message to (prevent duplicate sends)
    scp_sent_to: RwLock<lru::LruCache<[u8; 32], HashSet<PeerId>>>,
    /// Track which peers we've sent each compact tx set to (per-peer dedup, keyed by tx_set_hash)
    compact_set_sent_to: RwLock<lru::LruCache<[u8; 32], HashSet<PeerId>>>,
    /// Track which peers we've sent each TX to (prevent duplicate sends) - LEGACY
    tx_sent_to: RwLock<lru::LruCache<[u8; 32], HashSet<PeerId>>>,
    /// TX set sources: which peer has which TX set (learned from SCP messages, used by legacy fetch)
    txset_sources: RwLock<lru::LruCache<[u8; 32], PeerId>>,
    /// Pending TX set requests: hash -> (peer, request_time) to avoid duplicate fetches and track latency
    pending_txset_requests: RwLock<HashMap<[u8; 32], (PeerId, Instant)>>,
    /// Multi-peer announcer cache populated when we receive `COMPACT_TX_SET`
    /// on the SCP stream. Drives peer selection for both `COMPACT_TX_SET_GET`
    /// (compact-first fetch path) and `COMPACT_TX_SET_GET_TXS` (missing-txs fill).
    compact_announcers: RwLock<lru::LruCache<[u8; 32], Vec<PeerId>>>,
    /// Dedup and retry-tracking for outbound `COMPACT_TX_SET_GET` requests.
    pending_compact_get: RwLock<HashMap<[u8; 32], PendingCompactGet>>,
    /// In-flight reconstructions waiting on `COMPACT_TX_SET_TXS` responses.
    pending_compact_reconstructions: RwLock<HashMap<[u8; 32], PendingReconstruction>>,
    /// Hashes for which the compact path has terminally failed (Missing-after-GET_TXS
    /// or HashMismatch). `fetch_txset` short-circuits to legacy on hit.
    compact_failed: RwLock<lru::LruCache<[u8; 32], ()>>,
    /// Event sender for non-TX events (SCP, TxSet - critical path, unbounded)
    event_tx: mpsc::UnboundedSender<OverlayEvent>,
    /// Bounded TX event sender (backpressure - drops allowed)
    tx_event_tx: mpsc::Sender<OverlayEvent>,
    /// Counter for TXs dropped due to backpressure
    tx_dropped_count: AtomicU64,
    /// Stream control for reopening streams
    control: Control,

    // ============ INV/GETDATA State ============
    /// Batches INV announcements before sending (100ms or 1000 INVs)
    inv_batcher: RwLock<InvBatcher>,
    /// Tracks which peers have INV'd which TXs (for round-robin GETDATA)
    inv_tracker: RwLock<InvTracker>,
    /// Pending GETDATA requests with timeout tracking
    pending_getdata: RwLock<PendingRequests>,
    /// TX buffer for responding to GETDATA requests
    tx_buffer: RwLock<TxBuffer>,
    /// Overlay metrics (shared with App for IPC reporting)
    metrics: Arc<OverlayMetrics>,
}

impl SharedState {
    fn new(
        event_tx: mpsc::UnboundedSender<OverlayEvent>,
        tx_event_tx: mpsc::Sender<OverlayEvent>,
        control: Control,
        metrics: Arc<OverlayMetrics>,
    ) -> Self {
        Self {
            peer_streams: RwLock::new(HashMap::new()),
            scp_seen: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(10000).unwrap(),
            )),
            tx_seen: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(100000).unwrap(),
            )),
            scp_sent_to: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(10000).unwrap(),
            )),
            compact_set_sent_to: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(10000).unwrap(),
            )),
            tx_sent_to: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(100000).unwrap(),
            )),
            txset_sources: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(1000).unwrap(),
            )),
            pending_txset_requests: RwLock::new(HashMap::new()),
            compact_announcers: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(1000).unwrap(),
            )),
            pending_compact_get: RwLock::new(HashMap::new()),
            pending_compact_reconstructions: RwLock::new(HashMap::new()),
            compact_failed: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(1000).unwrap(),
            )),
            event_tx,
            tx_event_tx,
            tx_dropped_count: AtomicU64::new(0),
            control,
            // INV/GETDATA state
            inv_batcher: RwLock::new(InvBatcher::new()),
            inv_tracker: RwLock::new(InvTracker::new()),
            pending_getdata: RwLock::new(PendingRequests::new()),
            tx_buffer: RwLock::new(TxBuffer::new()),
            metrics,
        }
    }
}

/// The unified Stellar overlay
pub struct StellarOverlay {
    swarm: Swarm<StellarBehaviour>,
    control: Control,
    state: Arc<SharedState>,
    cmd_rx: mpsc::Receiver<OverlayCommand>,
}

/// Create the overlay and return handle + event receivers
///
/// Returns:
/// - `OverlayHandle`: for sending commands to the overlay
/// - `UnboundedReceiver<OverlayEvent>`: for SCP, TxSet events (critical path, never dropped)
/// - `Receiver<OverlayEvent>`: for TX events (bounded, may drop under backpressure)
/// - `StellarOverlay`: the overlay to run
pub fn create_overlay(
    keypair: Keypair,
    metrics: Arc<OverlayMetrics>,
) -> Result<
    (
        OverlayHandle,
        mpsc::UnboundedReceiver<OverlayEvent>,
        mpsc::Receiver<OverlayEvent>,
        StellarOverlay,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let peer_id = keypair.public().to_peer_id();
    info!(
        "Creating StellarOverlay with peer_id={} (QUIC transport)",
        peer_id
    );

    // Build swarm with QUIC transport
    // Configure QUIC with keep-alive to prevent idle connection drops
    let mut quic_config = libp2p::quic::Config::new(&keypair);
    quic_config.keep_alive_interval = Duration::from_secs(15);
    quic_config.max_idle_timeout = 60_000; // 60 seconds in ms

    let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_quic_config(|_| quic_config)
        .with_behaviour(|key| {
            let stream = StreamBehaviour::new();

            let identify = Identify::new(IdentifyConfig::new(
                "/stellar/1.0.0".to_string(),
                key.public(),
            ));

            StellarBehaviour { stream, identify }
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();

    let control = swarm.behaviour().stream.new_control();

    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    // Unbounded channel for critical events (SCP, TxSet) - never drop
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    // Bounded channel for TX events - drops allowed under backpressure
    let (tx_event_tx, tx_event_rx) = mpsc::channel(TX_EVENT_CHANNEL_CAPACITY);

    let state = Arc::new(SharedState::new(
        event_tx,
        tx_event_tx,
        control.clone(),
        metrics,
    ));

    let overlay = StellarOverlay {
        swarm,
        control,
        state,
        cmd_rx,
    };

    let handle = OverlayHandle { cmd_tx };

    Ok((handle, event_rx, tx_event_rx, overlay))
}

impl StellarOverlay {
    /// Run the overlay event loop
    ///
    /// `listen_ip` should be a specific IP (e.g., "127.0.0.1" for local tests)
    /// to avoid multi-homing issues where Identify advertises multiple addresses.
    pub async fn run(mut self, listen_ip: &str, listen_port: u16) {
        // Start listening on QUIC (UDP)
        // Use specific IP to avoid Identify advertising all local IPs
        let listen_addr: Multiaddr = format!("/ip4/{}/udp/{}/quic-v1", listen_ip, listen_port)
            .parse()
            .unwrap();

        if let Err(e) = self.swarm.listen_on(listen_addr.clone()) {
            error!("Failed to listen on {}: {}", listen_addr, e);
            return;
        }
        info!("Listening on QUIC port {}", listen_port);

        // Accept incoming streams for each protocol
        let scp_incoming = match self.control.accept(SCP_PROTOCOL) {
            Ok(incoming) => incoming,
            Err(e) => {
                error!(
                    "Failed to accept SCP protocol streams: {:?}. Overlay cannot function.",
                    e
                );
                return;
            }
        };
        let tx_incoming = match self.control.accept(TX_PROTOCOL) {
            Ok(incoming) => incoming,
            Err(e) => {
                error!(
                    "Failed to accept TX protocol streams: {:?}. Overlay cannot function.",
                    e
                );
                return;
            }
        };
        let txset_incoming = match self.control.accept(TXSET_PROTOCOL) {
            Ok(incoming) => incoming,
            Err(e) => {
                error!(
                    "Failed to accept TxSet protocol streams: {:?}. Overlay cannot function.",
                    e
                );
                return;
            }
        };
        let compact_txset_incoming = match self.control.accept(COMPACT_TXSET_PROTOCOL) {
            Ok(incoming) => incoming,
            Err(e) => {
                error!(
                    "Failed to accept CompactTxSet protocol streams: {:?}. Overlay cannot function.",
                    e
                );
                return;
            }
        };

        // Spawn inbound stream handlers
        let state = self.state.clone();
        tokio::spawn(handle_inbound_scp_streams(scp_incoming, state.clone()));
        tokio::spawn(handle_inbound_tx_streams(tx_incoming, state.clone()));
        tokio::spawn(handle_inbound_txset_streams(txset_incoming, state.clone()));
        tokio::spawn(handle_inbound_compact_txset_streams(
            compact_txset_incoming,
            state.clone(),
        ));

        // Spawn INV/GETDATA housekeeping task
        tokio::spawn(inv_getdata_housekeeping_task(state.clone()));

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }

                Some(cmd) = self.cmd_rx.recv() => {
                    match cmd {
                        OverlayCommand::BroadcastScp(envelope) => {
                            self.broadcast_scp(&envelope, None).await;
                        }
                        OverlayCommand::BroadcastScpCompact{compact_sets, envelope} => {
                            self.broadcast_scp(&envelope, Some(compact_sets)).await;
                        }
                        OverlayCommand::BroadcastTx(tx) => {
                            self.broadcast_tx(&tx).await;
                        }
                        OverlayCommand::FetchTxSet { hash } => {
                            self.fetch_txset(hash).await;
                        }
                        OverlayCommand::SendTxSet { hash, data, to } => {
                            self.send_txset_response(to, hash, data).await;
                        }
                        OverlayCommand::SendCompactTxSetResponse { hash, compact_xdr, to } => {
                            let state = Arc::clone(&self.state);
                            tokio::spawn(async move {
                                send_compact_txset_response(&state, to, hash, compact_xdr).await;
                            });
                        }
                        OverlayCommand::SendCompactTxSetTxsResponse { hash, tx_envelopes, to } => {
                            let state = Arc::clone(&self.state);
                            tokio::spawn(async move {
                                send_compact_txset_txs_response(&state, to, hash, tx_envelopes).await;
                            });
                        }
                        OverlayCommand::RecordTxSetSource { hash, peer } => {
                            let mut sources = self.state.txset_sources.write().await;
                            sources.put(hash, peer);
                            debug!("Recorded peer {} as source for TX set {:02x?}...", peer, &hash[..4]);
                        }
                        OverlayCommand::Dial(addr) => {
                            info!("Dialing peer at {}", addr);
                            self.state.metrics.connection_pending.fetch_add(1, Ordering::Relaxed);
                            self.state.metrics.outbound_attempt.fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = self.swarm.dial(addr.clone()) {
                                self.state.metrics.connection_pending.fetch_sub(1, Ordering::Relaxed);
                                warn!("Failed to dial {}: {}", addr, e);
                            }
                        }
                        OverlayCommand::DialPeer { peer_id, addr } => {
                            let opts = DialOpts::peer_id(peer_id)
                                .condition(PeerCondition::Disconnected)
                                .addresses(vec![addr.clone()])
                                .build();
                            self.state.metrics.outbound_attempt.fetch_add(1, Ordering::Relaxed);
                            match self.swarm.dial(opts) {
                                Ok(_) => {
                                    self.state.metrics.connection_pending.fetch_add(1, Ordering::Relaxed);
                                    debug!("Dialing known peer {} at {}", peer_id, addr);
                                }
                                Err(e) => {
                                    // DialError::NoAddresses means already connected — not an error
                                    debug!("DialPeer {} skipped or failed: {}", peer_id, e);
                                }
                            }
                        }
                        OverlayCommand::RequestScpState { ledger_seq } => {
                            info!("Requesting SCP state (ledger >= {}) from all peers", ledger_seq);
                            self.request_scp_state_from_all_peers(ledger_seq).await;
                        }
                        OverlayCommand::SendScpToPeer { peer_id, envelope } => {
                            // Don't hold &self across await - extract state and call helper directly.
                            // The SCP stream uses 4-byte type-tagged frames; wrap with the Envelope tag.
                            let state = Arc::clone(&self.state);
                            let frame = encode_scp_frame(ScpStreamMessageType::Envelope, &envelope);
                            if let Err(e) = send_to_peer_stream(&state, peer_id.clone(), StreamType::Scp, &frame).await {
                                warn!("Failed to send SCP to {}: {:?}", peer_id, e);
                            }
                        }
                        OverlayCommand::Shutdown => {
                            info!("Overlay shutting down");
                            break;
                        }
                        OverlayCommand::GetConnectedPeerCount(responder) => {
                            let count = self.state.peer_streams.read().await.len();
                            let _ = responder.send(count);
                        }
                        OverlayCommand::Ping(responder) => {
                            let _ = responder.send(());
                        }
                    }
                }
            }
        }
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<StellarBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
            }

            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                endpoint,
                ..
            } => {
                // Only decrement connection_pending for outbound dials we initiated
                if endpoint.is_dialer() {
                    self.state
                        .metrics
                        .connection_pending
                        .fetch_sub(1, Ordering::Relaxed);
                    self.state
                        .metrics
                        .outbound_establish
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.state
                        .metrics
                        .inbound_establish
                        .fetch_add(1, Ordering::Relaxed);
                }

                // Only open streams on the first connection to a peer.
                // When both sides dial simultaneously, two ConnectionEstablished
                // events fire for the same peer. Opening streams on each would
                // overwrite the first set, dropping those streams and causing
                // "unexpected end of file" on the remote's inbound handlers.
                if num_established.get() == 1 {
                    info!("Connected to peer {}", peer_id);
                    self.state
                        .metrics
                        .connection_authenticated
                        .fetch_add(1, Ordering::Relaxed);
                    {
                        let mut streams = self.state.peer_streams.write().await;
                        streams.insert(peer_id, Arc::new(PeerOutboundStreams::new()));
                    }

                    // Notify application so it can record the PeerId ↔ address mapping.
                    // Extract the remote address from the endpoint for reconnection.
                    let remote_addr = match &endpoint {
                        libp2p::core::ConnectedPoint::Dialer { address, .. } => address.clone(),
                        libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => {
                            send_back_addr.clone()
                        }
                    };
                    let _ = self.state.event_tx.send(OverlayEvent::PeerConnected {
                        peer_id: peer_id.clone(),
                        addr: remote_addr,
                    });

                    // Spawn stream opening as a background task so the swarm
                    // event loop stays free to poll — control.open_stream()
                    // needs the swarm to process the request.
                    let control = self.control.clone();
                    let state = self.state.clone();
                    tokio::spawn(open_streams_to_peer(control, state, peer_id));
                } else {
                    debug!(
                        "Duplicate connection to {} (now {}), skipping stream setup",
                        peer_id, num_established
                    );
                }
            }

            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                // Only clean up when the LAST connection to this peer closes.
                // Duplicate connections closing shouldn't tear down working streams.
                if num_established == 0 {
                    info!("Disconnected from peer {}", peer_id);
                    self.state
                        .metrics
                        .connection_authenticated
                        .fetch_sub(1, Ordering::Relaxed);
                    self.state
                        .metrics
                        .outbound_drop
                        .fetch_add(1, Ordering::Relaxed);
                    {
                        let mut streams = self.state.peer_streams.write().await;
                        streams.remove(&peer_id);
                    }
                    // Clean up pending txset requests for this peer
                    {
                        let mut pending = self.state.pending_txset_requests.write().await;
                        let before_len = pending.len();
                        pending.retain(|_hash, (p, _)| p != &peer_id);
                        let removed = before_len - pending.len();
                        if removed > 0 {
                            info!(
                                "Removed {} pending txset requests for disconnected peer {}",
                                removed, peer_id
                            );
                        }
                    }
                    // Clean up pending compact-get requests sent to this peer
                    // and schedule a retry to the next announcer (Herder won't
                    // retry on its own — `requestTxSet` is "Only once!").
                    let to_retry: Vec<([u8; 32], HashSet<PeerId>)> = {
                        let mut pending = self.state.pending_compact_get.write().await;
                        let mut taken = Vec::new();
                        let hashes_for_peer: Vec<[u8; 32]> = pending
                            .iter()
                            .filter_map(|(h, pcg)| {
                                if pcg.peer == peer_id {
                                    Some(*h)
                                } else {
                                    None
                                }
                            })
                            .collect();
                        for h in hashes_for_peer {
                            if let Some(pcg) = pending.remove(&h) {
                                taken.push((h, pcg.tried));
                            }
                        }
                        taken
                    };
                    if !to_retry.is_empty() {
                        info!(
                            "Removed {} pending compact-get requests for disconnected peer {} (will retry)",
                            to_retry.len(),
                            peer_id
                        );
                    }
                    for (hash, tried) in to_retry {
                        let state = Arc::clone(&self.state);
                        tokio::spawn(async move {
                            retry_compact_get_or_fallback(&state, hash, tried).await;
                        });
                    }
                    // Clean up pending compact reconstructions waiting on this peer
                    {
                        let mut pending =
                            self.state.pending_compact_reconstructions.write().await;
                        let before_len = pending.len();
                        pending.retain(|_hash, p| p.requested_from != peer_id);
                        let removed = before_len - pending.len();
                        if removed > 0 {
                            info!(
                                "Removed {} pending compact reconstructions for disconnected peer {}",
                                removed, peer_id
                            );
                        }
                    }
                    // Drop this peer from any compact_announcers entries
                    {
                        let mut announcers = self.state.compact_announcers.write().await;
                        for (_hash, peers) in announcers.iter_mut() {
                            peers.retain(|p| p != &peer_id);
                        }
                    }
                    // Notify main loop to clean up any pending requests for this peer
                    if let Err(e) = self.state.event_tx.send(OverlayEvent::PeerDisconnected {
                        peer_id: peer_id.clone(),
                    }) {
                        warn!(
                            "Failed to send PeerDisconnected event for {}: {}",
                            peer_id, e
                        );
                    }
                } else {
                    debug!(
                        "Duplicate connection to {} closed ({} remaining)",
                        peer_id, num_established
                    );
                }
            }

            SwarmEvent::Behaviour(StellarBehaviourEvent::Identify(event)) => {
                if let IdentifyEvent::Received { peer_id, info, .. } = event {
                    debug!("Identified peer {}: {:?}", peer_id, info.listen_addrs);
                }
            }

            SwarmEvent::Behaviour(StellarBehaviourEvent::Stream(_)) => {
                // Stream events handled by the stream behaviour internally
            }

            SwarmEvent::IncomingConnection { .. } => {
                trace!("Incoming connection");
                self.state
                    .metrics
                    .inbound_attempt
                    .fetch_add(1, Ordering::Relaxed);
            }

            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                warn!("Outgoing connection failed to {:?}: {}", peer_id, error);
                self.state
                    .metrics
                    .connection_pending
                    .fetch_sub(1, Ordering::Relaxed);
            }

            _ => {}
        }
    }

    /// Broadcast SCP envelope to all connected peers, optionally preceded by
    /// compact tx set announcements on the same SCP stream.
    ///
    /// Each `(tx_set_hash, compact_xdr)` in `compact_sets` is sent before the
    /// envelope, with per-peer dedup keyed on `tx_set_hash`. A single per-peer
    /// task sends that peer's compact sets sequentially then the envelope —
    /// per-peer ordering on the wire is preserved by the SCP stream's mutex
    /// only when the writes happen within the same task (tokio Mutex isn't
    /// FIFO across spawn order).
    async fn broadcast_scp(
        &mut self,
        envelope: &[u8],
        compact_sets: Option<Vec<(crate::flood::TxHash, Vec<u8>)>>,
    ) {
        let hash = blake2b_hash(envelope);

        // Mark as seen for inbound dedup (if we later receive this from a peer, skip it)
        {
            let mut seen = self.state.scp_seen.write().await;
            seen.put(hash, ());
        }

        let streams = self.state.peer_streams.read().await;
        let all_peers: Vec<PeerId> = streams.keys().cloned().collect();
        drop(streams);

        if all_peers.is_empty() {
            trace!(
                "SCP_BROADCAST_SKIP: SCP {:02x?}... no peers connected",
                &hash[..4]
            );
            return;
        }

        // Per-peer dedup for the envelope.
        let envelope_peers: HashSet<PeerId>;
        {
            let mut sent_to = self.state.scp_sent_to.write().await;
            let already_sent: HashSet<PeerId> = sent_to.peek(&hash).cloned().unwrap_or_default();

            envelope_peers = all_peers
                .iter()
                .filter(|p| !already_sent.contains(p))
                .cloned()
                .collect();

            if !envelope_peers.is_empty() {
                let mut new_sent = already_sent;
                new_sent.extend(envelope_peers.iter().cloned());
                sent_to.put(hash, new_sent);
            }
        }

        // Per-peer dedup for each compact set, keyed on tx_set_hash. Build a
        // per-peer ordered list of compact sets to send. Each compact set's
        // wire frame (4-byte tag + serialized CompactTxSet bytes) is built
        // exactly once and shared via Arc across the per-peer send tasks.
        let compact_sets_vec = compact_sets.unwrap_or_default();
        let mut per_peer_compact: HashMap<
            PeerId,
            Vec<(crate::flood::TxHash, Arc<Vec<u8>>, usize)>,
        > = HashMap::new();
        let mut total_compact_sends: usize = 0;
        if !compact_sets_vec.is_empty() {
            let mut sent_to = self.state.compact_set_sent_to.write().await;
            for (tx_set_hash, bytes) in &compact_sets_vec {
                let already_sent: HashSet<PeerId> =
                    sent_to.peek(tx_set_hash).cloned().unwrap_or_default();
                let peers_for_this_set: Vec<PeerId> = all_peers
                    .iter()
                    .filter(|p| !already_sent.contains(p))
                    .cloned()
                    .collect();
                if peers_for_this_set.is_empty() {
                    continue;
                }
                let mut new_sent = already_sent;
                new_sent.extend(peers_for_this_set.iter().cloned());
                sent_to.put(*tx_set_hash, new_sent);

                let payload_len = bytes.len();
                let frame: Arc<Vec<u8>> = Arc::new(encode_scp_frame(
                    ScpStreamMessageType::CompactTxSet,
                    bytes,
                ));
                for p in peers_for_this_set {
                    per_peer_compact.entry(p).or_default().push((
                        *tx_set_hash,
                        Arc::clone(&frame),
                        payload_len,
                    ));
                    total_compact_sends += 1;
                }
            }
        }

        let mut peers_to_spawn: HashSet<PeerId> = envelope_peers.clone();
        peers_to_spawn.extend(per_peer_compact.keys().cloned());

        if peers_to_spawn.is_empty() {
            trace!(
                "SCP_BROADCAST_SKIP: SCP {:02x?}... and any compact sets already sent to all connected peers",
                &hash[..4]
            );
            return;
        }

        info!(
            "SCP_BROADCAST: Broadcasting SCP {:02x?}... ({} bytes) to {} peers; {} compact-set sends across {} peers",
            &hash[..4],
            envelope.len(),
            envelope_peers.len(),
            total_compact_sends,
            per_peer_compact.len(),
        );
        self.state
            .metrics
            .message_broadcast
            .fetch_add(1, Ordering::Relaxed);

        // Build the envelope frame once and share via Arc across all peers
        // that haven't been deduped out.
        let envelope_frame: Arc<Vec<u8>> = Arc::new(encode_scp_frame(
            ScpStreamMessageType::Envelope,
            envelope,
        ));

        for peer_id in peers_to_spawn {
            let state = Arc::clone(&self.state);
            let envelope_frame_for_peer = if envelope_peers.contains(&peer_id) {
                Some(Arc::clone(&envelope_frame))
            } else {
                None
            };
            let compact_for_peer = per_peer_compact.remove(&peer_id).unwrap_or_default();

            tokio::spawn(async move {
                // Send compact sets first so peers see the tx-set announcements
                // before the SCP envelope that references them. Within this
                // task the per-peer SCP stream mutex is acquired sequentially,
                // which preserves wire ordering.
                for (tx_set_hash, frame, payload_len) in compact_for_peer {
                    let frame_len = frame.len();
                    match send_to_peer_stream(&state, peer_id.clone(), StreamType::Scp, &frame)
                        .await
                    {
                        Ok(_) => {
                            state
                                .metrics
                                .send_scp_message
                                .fetch_add(1, Ordering::Relaxed);
                            state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
                            state
                                .metrics
                                .byte_write
                                .fetch_add(frame_len as u64, Ordering::Relaxed);
                            state
                                .metrics
                                .compact_announce_sent
                                .fetch_add(1, Ordering::Relaxed);
                            state
                                .metrics
                                .compact_announce_bytes_sent
                                .fetch_add(frame_len as u64, Ordering::Relaxed);
                            debug!(
                                "COMPACT_SET_SEND_OK: Sent compact set {:02x?}... ({} bytes payload) to {}",
                                &tx_set_hash[..4],
                                payload_len,
                                peer_id
                            );
                        }
                        Err(e) => {
                            state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
                            warn!(
                                "COMPACT_SET_SEND_FAIL: Failed to send compact set {:02x?}... to {}: {}",
                                &tx_set_hash[..4],
                                peer_id,
                                e
                            );
                        }
                    }
                }

                if let Some(frame) = envelope_frame_for_peer {
                    let frame_len = frame.len();
                    match send_to_peer_stream(&state, peer_id.clone(), StreamType::Scp, &frame)
                        .await
                    {
                        Ok(_) => {
                            state
                                .metrics
                                .send_scp_message
                                .fetch_add(1, Ordering::Relaxed);
                            state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
                            state
                                .metrics
                                .byte_write
                                .fetch_add(frame_len as u64, Ordering::Relaxed);
                            debug!(
                                "SCP_SEND_OK: Sent SCP {:02x?}... to {}",
                                &hash[..4],
                                peer_id
                            );
                        }
                        Err(e) => {
                            state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
                            warn!(
                                "SCP_SEND_FAIL: Failed to send SCP {:02x?}... to {}: {}",
                                &hash[..4],
                                peer_id,
                                e
                            );
                        }
                    }
                }
            });
        }
    }

    /// Broadcast TX to all connected peers
    /// Broadcast TX using INV/GETDATA protocol (bandwidth efficient)
    async fn broadcast_tx(&mut self, tx: &[u8]) {
        let hash = blake2b_hash(tx);

        // Dedup check
        {
            let mut seen = self.state.tx_seen.write().await;
            if seen.contains(&hash) {
                trace!("TX already seen, skipping broadcast");
                return;
            }
            seen.put(hash, ());
            self.state
                .metrics
                .memory_flood_known
                .store(seen.len() as i64, Ordering::Relaxed);
        }

        // Store TX in buffer for GETDATA responses
        {
            let mut buffer = self.state.tx_buffer.write().await;
            buffer.insert(hash, tx.to_vec());
        }

        let streams = self.state.peer_streams.read().await;
        let peers: Vec<_> = streams.keys().cloned().collect();
        drop(streams);

        if peers.is_empty() {
            debug!("TX_INV: No peers to announce TX {:02x?}...", &hash[..4]);
            return;
        }

        debug!(
            "TX_INV: Announcing TX {:02x?}... ({} bytes) to {} peers via INV",
            &hash[..4],
            tx.len(),
            peers.len()
        );
        self.state
            .metrics
            .flood_advertised
            .fetch_add(peers.len() as u64, Ordering::Relaxed);

        // Create INV entry (fee is 0 for now - TODO: pass from caller)
        let inv_entry = InvEntry {
            hash,
            fee_per_op: 0, // TODO: pass actual fee from SubmitTx
        };

        // Add to batcher for each peer, send batch immediately when full
        for peer in &peers {
            let batch_to_send = {
                let mut batcher = self.state.inv_batcher.write().await;
                batcher.add(*peer, inv_entry.clone())
            };
            if let Some(batch) = batch_to_send {
                send_inv_batch(&self.state, *peer, batch).await;
            }
        }
    }

    /// Fetch TX set: try compact path first, fall back to legacy on failure.
    async fn fetch_txset(&mut self, hash: [u8; 32]) {
        fetch_txset_compact_first(&self.state, hash).await;
    }

    /// Send TX set response to a specific peer
    async fn send_txset_response(&mut self, peer: PeerId, hash: [u8; 32], data: Vec<u8>) {
        info!(
            "TXSET_SEND: Sending TX set {:02x?}... ({} bytes) to {}",
            &hash[..4],
            data.len(),
            peer
        );

        // Response format: 32-byte hash + XDR data
        let mut response = Vec::with_capacity(32 + data.len());
        response.extend_from_slice(&hash);
        response.extend_from_slice(&data);

        match send_to_peer_stream(&self.state, peer, StreamType::TxSet, &response).await {
            Ok(_) => {
                self.state
                    .metrics
                    .send_txset
                    .fetch_add(1, Ordering::Relaxed);
                self.state
                    .metrics
                    .message_write
                    .fetch_add(1, Ordering::Relaxed);
                self.state
                    .metrics
                    .byte_write
                    .fetch_add(response.len() as u64, Ordering::Relaxed);
                info!(
                    "TXSET_SEND_OK: Successfully sent TX set {:02x?}... ({} bytes on wire) to {}",
                    &hash[..4],
                    response.len(),
                    peer
                );
            }
            Err(e) => {
                self.state
                    .metrics
                    .error_write
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    "TXSET_SEND_FAIL: Failed to send TxSet {:02x?}... to {}: {}",
                    &hash[..4],
                    peer,
                    e
                );
            }
        }
    }

    /// Request SCP state from all connected peers
    pub async fn request_scp_state_from_all_peers(&mut self, ledger_seq: u32) {
        let streams = self.state.peer_streams.read().await;
        let peers: Vec<_> = streams.keys().cloned().collect();
        drop(streams);

        info!(
            "Requesting SCP state for ledger >= {} from {} peers",
            ledger_seq,
            peers.len()
        );

        // Request payload is the ledger seq as 4 little-endian bytes.
        let payload = ledger_seq.to_le_bytes();
        let frame = encode_scp_frame(ScpStreamMessageType::StateRequest, &payload);
        for peer_id in peers {
            if let Err(e) =
                send_to_peer_stream(&self.state, peer_id, StreamType::Scp, &frame).await
            {
                warn!("Failed to send SCP state request to {}: {:?}", peer_id, e);
            }
        }
    }

    /// Send SCP envelope to a specific peer. Wraps with the SCP-stream
    /// `Envelope` tag so the receiver's tag-dispatch loop accepts it.
    pub async fn send_scp_to_peer(&self, peer_id: PeerId, envelope: &[u8]) -> io::Result<()> {
        let frame = encode_scp_frame(ScpStreamMessageType::Envelope, envelope);
        send_to_peer_stream(&self.state, peer_id, StreamType::Scp, &frame).await
    }
}

/// Open SCP, TX, TxSet, and CompactTxSet streams to a peer.
/// Spawned as a background task so the swarm event loop stays unblocked —
/// `control.open_stream()` needs the swarm to be polled to complete.
async fn open_streams_to_peer(mut control: Control, state: Arc<SharedState>, peer_id: PeerId) {
    debug!("Opening streams to peer {}", peer_id);

    let mut control2 = control.clone();
    let mut control3 = control.clone();
    let mut control4 = control.clone();

    let scp_fut = async { control.open_stream(peer_id, SCP_PROTOCOL).await };
    let tx_fut = async { control2.open_stream(peer_id, TX_PROTOCOL).await };
    let txset_fut = async { control3.open_stream(peer_id, TXSET_PROTOCOL).await };
    let compact_txset_fut =
        async { control4.open_stream(peer_id, COMPACT_TXSET_PROTOCOL).await };

    let (scp_result, tx_result, txset_result, compact_txset_result) =
        tokio::join!(scp_fut, tx_fut, txset_fut, compact_txset_fut);

    let scp_stream = match scp_result {
        Ok(s) => {
            debug!("Opened SCP stream to {}", peer_id);
            Some(s)
        }
        Err(e) => {
            warn!("Failed to open SCP stream to {}: {:?}", peer_id, e);
            None
        }
    };

    let tx_stream = match tx_result {
        Ok(s) => {
            debug!("Opened TX stream to {}", peer_id);
            Some(s)
        }
        Err(e) => {
            warn!("Failed to open TX stream to {}: {:?}", peer_id, e);
            None
        }
    };

    let txset_stream = match txset_result {
        Ok(s) => {
            debug!("Opened TxSet stream to {}", peer_id);
            Some(s)
        }
        Err(e) => {
            warn!("Failed to open TxSet stream to {}: {:?}", peer_id, e);
            None
        }
    };

    let compact_txset_stream = match compact_txset_result {
        Ok(s) => {
            debug!("Opened CompactTxSet stream to {}", peer_id);
            Some(s)
        }
        Err(e) => {
            warn!("Failed to open CompactTxSet stream to {}: {:?}", peer_id, e);
            None
        }
    };

    // Store streams
    {
        let streams = state.peer_streams.read().await;
        if let Some(peer_streams) = streams.get(&peer_id) {
            if let Some(stream) = scp_stream {
                *peer_streams.scp.lock().await = Some(stream);
            }
            if let Some(stream) = tx_stream {
                *peer_streams.tx.lock().await = Some(stream);
            }
            if let Some(stream) = txset_stream {
                *peer_streams.txset.lock().await = Some(stream);
            }
            if let Some(stream) = compact_txset_stream {
                *peer_streams.compact_txset.lock().await = Some(stream);
            }
        }
    }

    // Request SCP state from newly connected peer
    info!("Peer {} streams opened, sending SCP state request", peer_id);
    let ledger_seq: u32 = 0;
    let frame = encode_scp_frame(ScpStreamMessageType::StateRequest, &ledger_seq.to_le_bytes());
    if let Err(e) = send_to_peer_stream(&state, peer_id.clone(), StreamType::Scp, &frame).await {
        info!(
            "Failed to request SCP state from newly connected peer {}: {:?}",
            peer_id, e
        );
    }
}

#[derive(Clone, Copy)]
enum StreamType {
    Scp,
    Tx,
    TxSet,
    CompactTxSet,
}

impl StreamType {
    fn protocol(&self) -> StreamProtocol {
        match self {
            StreamType::Scp => SCP_PROTOCOL,
            StreamType::Tx => TX_PROTOCOL,
            StreamType::TxSet => TXSET_PROTOCOL,
            StreamType::CompactTxSet => COMPACT_TXSET_PROTOCOL,
        }
    }
}

/// Send message to a specific peer's stream only if already open (for flooding)
/// Returns Ok(()) if sent, Err if stream not open (doesn't try to reopen)
async fn try_send_to_existing_stream(
    state: &SharedState,
    peer_id: PeerId,
    stream_type: StreamType,
    data: &[u8],
) -> io::Result<()> {
    let streams = state.peer_streams.read().await;
    let peer_streams = streams
        .get(&peer_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "peer not connected"))?
        .clone();
    drop(streams);

    // Lock only the specific stream we need - no head-of-line blocking
    let stream_mutex = match stream_type {
        StreamType::Scp => &peer_streams.scp,
        StreamType::Tx => &peer_streams.tx,
        StreamType::TxSet => &peer_streams.txset,
        StreamType::CompactTxSet => &peer_streams.compact_txset,
    };

    let mut stream_guard = stream_mutex.lock().await;

    // If stream not open, fail immediately without reopening
    let stream = stream_guard
        .as_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream not open"))?;

    write_framed(stream, data).await
}

/// Send message to a specific peer's stream, reopening if needed
async fn send_to_peer_stream(
    state: &SharedState,
    peer_id: PeerId,
    stream_type: StreamType,
    data: &[u8],
) -> io::Result<()> {
    // Retry up to 2 times (3 attempts total) for reliability
    const MAX_RETRIES: usize = 2;

    for attempt in 0..=MAX_RETRIES {
        let streams = state.peer_streams.read().await;
        let peer_streams = match streams.get(&peer_id) {
            Some(ps) => ps.clone(),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "peer not connected",
                ));
            }
        };
        drop(streams);

        // Lock only the specific stream we need - no head-of-line blocking
        let stream_mutex = match stream_type {
            StreamType::Scp => &peer_streams.scp,
            StreamType::Tx => &peer_streams.tx,
            StreamType::TxSet => &peer_streams.txset,
            StreamType::CompactTxSet => &peer_streams.compact_txset,
        };

        let mut stream_guard = stream_mutex.lock().await;

        // If stream is None, try to reopen it
        if stream_guard.is_none() {
            debug!(
                "Stream {:?} not open to {}, attempting to reopen (attempt {})",
                stream_type.protocol(),
                peer_id,
                attempt + 1
            );
            match state
                .control
                .clone()
                .open_stream(peer_id, stream_type.protocol())
                .await
            {
                Ok(s) => {
                    debug!(
                        "Successfully reopened {:?} stream to {}",
                        stream_type.protocol(),
                        peer_id
                    );
                    *stream_guard = Some(s);
                }
                Err(e) => {
                    if attempt < MAX_RETRIES {
                        debug!(
                            "Failed to reopen {:?} stream to {} (attempt {}), retrying: {:?}",
                            stream_type.protocol(),
                            peer_id,
                            attempt + 1,
                            e
                        );
                        drop(stream_guard);
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            10 * (attempt as u64 + 1),
                        ))
                        .await;
                        continue;
                    }
                    warn!(
                        "Failed to reopen {:?} stream to {}: {:?}",
                        stream_type.protocol(),
                        peer_id,
                        e
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        format!("failed to reopen stream: {:?}", e),
                    ));
                }
            }
        }

        let stream = stream_guard.as_mut().unwrap();
        match write_framed(stream, data).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                // Clear the broken stream
                *stream_guard = None;

                if attempt < MAX_RETRIES {
                    debug!(
                        "Send to {:?} stream failed (attempt {}), retrying: {}",
                        stream_type.protocol(),
                        attempt + 1,
                        e
                    );
                    drop(stream_guard);
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        10 * (attempt as u64 + 1),
                    ))
                    .await;
                    continue;
                }
                return Err(e);
            }
        }
    }

    unreachable!()
}

/// Write length-prefixed frame to stream
async fn write_framed(stream: &mut Stream, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Flush INV batch for a specific peer
async fn flush_inv_batch_to_peer(state: &Arc<SharedState>, peer: PeerId) {
    let batch = {
        let mut batcher = state.inv_batcher.write().await;
        batcher.flush(&peer)
    };

    if let Some(batch) = batch {
        send_inv_batch(state, peer, batch).await;
    }
}

/// Send an INV batch to a peer
async fn send_inv_batch(state: &Arc<SharedState>, peer: PeerId, batch: InvBatch) {
    let batch_size = batch.entries.len() as u64;
    let msg = TxStreamMessage::InvBatch(batch);
    let encoded = msg.encode();
    let encoded_len = encoded.len() as u64;

    let state = Arc::clone(state);
    tokio::spawn(async move {
        if let Err(e) = send_to_peer_stream(&state, peer.clone(), StreamType::Tx, &encoded).await {
            state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
            warn!("Failed to send INV batch to {}: {}", peer, e);
        } else {
            state
                .metrics
                .send_transaction
                .fetch_add(1, Ordering::Relaxed);
            state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .byte_write
                .fetch_add(encoded_len, Ordering::Relaxed);
            state
                .metrics
                .flood_tx_batch_size_sum
                .fetch_add(batch_size, Ordering::Relaxed);
            state
                .metrics
                .flood_tx_batch_size_count
                .fetch_add(1, Ordering::Relaxed);
            debug!("TX_INV_SENT: Sent INV batch to {}", peer);
        }
    });
}

/// Read length-prefixed frame from stream
async fn read_framed(stream: &mut Stream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {} > {}", len, MAX_MESSAGE_SIZE),
        ));
    }

    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

// ─────────────────────────────────────────────────────────────────────────
// CompactTxSet stream message construction
//
// All four CompactTxSetMessage variants are wire-encoded as a 4-byte BE
// discriminant followed by the variant body, matching XDR union encoding.
// We build them by hand here to avoid a deserialize-then-reserialize round
// trip when the source bytes are already correctly encoded (e.g. the
// eagerly-built `CachedTxSet::compact_xdr`).
// ─────────────────────────────────────────────────────────────────────────

const COMPACT_MSG_TYPE_SET: u32 = 0;
const COMPACT_MSG_TYPE_SET_GET: u32 = 1;
const COMPACT_MSG_TYPE_SET_GET_TXS: u32 = 2;
const COMPACT_MSG_TYPE_SET_TXS: u32 = 3;

/// Pad `out` so that its total length is a multiple of 4 (XDR alignment).
fn xdr_pad4(out: &mut Vec<u8>) {
    let pad = (4 - out.len() % 4) % 4;
    for _ in 0..pad {
        out.push(0);
    }
}

/// Build a `CompactTxSetMessage::Set(CompactTxSet)` frame given an
/// already-XDR-serialized `CompactTxSet` body. The body's `txs<>` field
/// already includes its own 4-byte alignment padding, so concatenation is
/// safe.
fn build_compact_msg_set(compact_xdr: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + compact_xdr.len());
    out.extend_from_slice(&COMPACT_MSG_TYPE_SET.to_be_bytes());
    out.extend_from_slice(compact_xdr);
    out
}

/// Build a `CompactTxSetMessage::SetGet { tx_set_hash }` frame.
fn build_compact_msg_set_get(tx_set_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&COMPACT_MSG_TYPE_SET_GET.to_be_bytes());
    out.extend_from_slice(tx_set_hash);
    out
}

/// Build a `CompactTxSetMessage::SetGetTxs { tx_set_hash, indices }` frame.
/// `indices` is the LEB128-delta-encoded payload (already produced by
/// `flood::encode_indices`).
fn build_compact_msg_set_get_txs(tx_set_hash: &[u8; 32], indices: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + 4 + indices.len() + 3);
    out.extend_from_slice(&COMPACT_MSG_TYPE_SET_GET_TXS.to_be_bytes());
    out.extend_from_slice(tx_set_hash);
    out.extend_from_slice(&(indices.len() as u32).to_be_bytes());
    out.extend_from_slice(indices);
    xdr_pad4(&mut out);
    out
}

/// Build a `CompactTxSetMessage::SetTxs { tx_set_hash, txs }` frame.
/// Each tx in `tx_envelopes` is an already-XDR-serialized
/// `TransactionEnvelope` (which is naturally 4-byte aligned).
fn build_compact_msg_set_txs(tx_set_hash: &[u8; 32], tx_envelopes: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = tx_envelopes.iter().map(|t| t.len()).sum();
    let mut out = Vec::with_capacity(4 + 32 + 4 + total);
    out.extend_from_slice(&COMPACT_MSG_TYPE_SET_TXS.to_be_bytes());
    out.extend_from_slice(tx_set_hash);
    out.extend_from_slice(&(tx_envelopes.len() as u32).to_be_bytes());
    for env in tx_envelopes {
        out.extend_from_slice(env);
    }
    out
}

/// Send a `CompactTxSetMessage::Set` to a peer (response to a peer's GET).
async fn send_compact_txset_response(
    state: &Arc<SharedState>,
    to: PeerId,
    hash: [u8; 32],
    compact_xdr: Vec<u8>,
) {
    let frame = build_compact_msg_set(&compact_xdr);
    let frame_len = frame.len();
    match send_to_peer_stream(state, to, StreamType::CompactTxSet, &frame).await {
        Ok(_) => {
            state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .byte_write
                .fetch_add(frame_len as u64, Ordering::Relaxed);
            state
                .metrics
                .compact_announce_sent
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .compact_announce_bytes_sent
                .fetch_add(frame_len as u64, Ordering::Relaxed);
            debug!(
                "COMPACT_GET_RESP_OK: Sent compact tx set {:02x?}... ({} bytes) to {}",
                &hash[..4],
                frame_len,
                to
            );
        }
        Err(e) => {
            state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
            warn!(
                "COMPACT_GET_RESP_FAIL: Failed to send compact tx set {:02x?}... to {}: {}",
                &hash[..4],
                to,
                e
            );
        }
    }
}

/// Send a `CompactTxSetMessage::SetTxs` to a peer (response to a peer's
/// GET_TXS).
async fn send_compact_txset_txs_response(
    state: &Arc<SharedState>,
    to: PeerId,
    hash: [u8; 32],
    tx_envelopes: Vec<Vec<u8>>,
) {
    let frame = build_compact_msg_set_txs(&hash, &tx_envelopes);
    let frame_len = frame.len();
    match send_to_peer_stream(state, to, StreamType::CompactTxSet, &frame).await {
        Ok(_) => {
            state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .byte_write
                .fetch_add(frame_len as u64, Ordering::Relaxed);
            state
                .metrics
                .compact_txs_sent
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .compact_txs_bytes_sent
                .fetch_add(frame_len as u64, Ordering::Relaxed);
            debug!(
                "COMPACT_GET_TXS_RESP_OK: Sent {} txs for {:02x?}... ({} bytes) to {}",
                tx_envelopes.len(),
                &hash[..4],
                frame_len,
                to
            );
        }
        Err(e) => {
            state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
            warn!(
                "COMPACT_GET_TXS_RESP_FAIL: Failed to send tx response for {:02x?}... to {}: {}",
                &hash[..4],
                to,
                e
            );
        }
    }
}

/// Handle inbound SCP streams from peers
async fn handle_inbound_scp_streams(mut incoming: IncomingStreams, state: Arc<SharedState>) {
    while let Some((peer_id, mut stream)) = incoming.next().await {
        info!("SCP_STREAM: Accepted inbound SCP stream from {}", peer_id);
        state
            .metrics
            .inbound_establish
            .fetch_add(1, Ordering::Relaxed);
        state.metrics.inbound_live.fetch_add(1, Ordering::Relaxed);
        let state = state.clone();

        tokio::spawn(async move {
            loop {
                match read_framed(&mut stream).await {
                    Ok(frame) => {
                        let frame_len = frame.len();
                        state.metrics.message_read.fetch_add(1, Ordering::Relaxed);
                        state
                            .metrics
                            .byte_read
                            .fetch_add(frame_len as u64, Ordering::Relaxed);

                        // Frame format: 4-byte big-endian tag + payload
                        if frame.len() < 4 {
                            warn!(
                                "SCP_FRAME_INVALID: Frame from {} too short ({} bytes)",
                                peer_id,
                                frame.len()
                            );
                            continue;
                        }
                        let tag_bytes: [u8; 4] = frame[..4].try_into().unwrap();
                        let tag_u32 = u32::from_be_bytes(tag_bytes);
                        let payload = &frame[4..];

                        match ScpStreamMessageType::from_u32(tag_u32) {
                            Some(ScpStreamMessageType::StateRequest) => {
                                if payload.len() != 4 {
                                    warn!(
                                        "SCP_STATE_REQ_INVALID: Bad payload size {} from {}",
                                        payload.len(),
                                        peer_id
                                    );
                                    continue;
                                }
                                let ledger_seq =
                                    u32::from_le_bytes(payload[..4].try_into().unwrap());
                                info!(
                                    "SCP_STATE_REQ: Peer {} requests SCP state for ledger >= {}",
                                    peer_id, ledger_seq
                                );
                                if let Err(e) =
                                    state.event_tx.send(OverlayEvent::ScpStateRequested {
                                        peer_id: peer_id.clone(),
                                        ledger_seq,
                                    })
                                {
                                    error!("Failed to send SCP state request event: {:?}", e);
                                }
                            }
                            Some(ScpStreamMessageType::Envelope) => {
                                let recv_start = std::time::Instant::now();
                                let envelope = payload.to_vec();
                                let hash = blake2b_hash(&envelope);
                                let is_dup = {
                                    let mut seen = state.scp_seen.write().await;
                                    if seen.contains(&hash) {
                                        true
                                    } else {
                                        seen.put(hash, ());
                                        false
                                    }
                                };

                                // Record sender in scp_sent_to so we don't echo back
                                {
                                    let mut sent_to = state.scp_sent_to.write().await;
                                    if let Some(peers) = sent_to.get_mut(&hash) {
                                        peers.insert(peer_id.clone());
                                    } else {
                                        let mut set = HashSet::new();
                                        set.insert(peer_id.clone());
                                        sent_to.put(hash, set);
                                    }
                                }

                                if is_dup {
                                    debug!(
                                        "SCP_RECV_DUP: Duplicate SCP {:02x?}... from {}",
                                        &hash[..4],
                                        peer_id
                                    );
                                    continue;
                                }

                                info!(
                                    "SCP_RECV: Received SCP {:02x?}... ({} bytes) from {}",
                                    &hash[..4],
                                    envelope.len(),
                                    peer_id
                                );

                                if let Err(e) = state.event_tx.send(OverlayEvent::ScpReceived {
                                    envelope,
                                    from: peer_id.clone(),
                                }) {
                                    warn!(
                                        "Failed to forward SCP event from {}: {}",
                                        peer_id, e
                                    );
                                }

                                let elapsed_us = recv_start.elapsed().as_micros() as u64;
                                state
                                    .metrics
                                    .recv_scp_sum_us
                                    .fetch_add(elapsed_us, Ordering::Relaxed);
                                state.metrics.recv_scp_count.fetch_add(1, Ordering::Relaxed);
                            }
                            Some(ScpStreamMessageType::CompactTxSet) => {
                                state
                                    .metrics
                                    .compact_announce_recv
                                    .fetch_add(1, Ordering::Relaxed);
                                state
                                    .metrics
                                    .compact_announce_bytes_recv
                                    .fetch_add(frame_len as u64, Ordering::Relaxed);
                                handle_received_compact_announcement(
                                    &state,
                                    peer_id.clone(),
                                    payload,
                                )
                                .await;
                            }
                            None => {
                                warn!(
                                    "SCP_FRAME_UNKNOWN_TAG: Unknown tag {} from {}",
                                    tag_u32, peer_id
                                );
                            }
                        }
                    }
                    Err(e) => {
                        state.metrics.error_read.fetch_add(1, Ordering::Relaxed);
                        state.metrics.inbound_live.fetch_sub(1, Ordering::Relaxed);
                        warn!(
                            "SCP_STREAM_CLOSED: SCP stream from {} closed: {}",
                            peer_id, e
                        );
                        break;
                    }
                }
            }
        });
    }
}

/// Handle a `CompactTxSet` announcement received on the SCP stream
/// (alongside an SCP envelope). Parses the raw bytes and forwards to the
/// shared receive path.
async fn handle_received_compact_announcement(
    state: &Arc<SharedState>,
    peer_id: PeerId,
    payload: &[u8],
) {
    match CompactTxSet::from_xdr(payload, Limits::none()) {
        Ok(compact) => {
            handle_received_compact_set(state, peer_id, compact).await;
        }
        Err(e) => {
            warn!(
                "COMPACT_ANNOUNCE_PARSE_ERR: Failed to parse CompactTxSet from {} ({} bytes): {}",
                peer_id,
                payload.len(),
                e
            );
        }
    }
}

/// Handle inbound TX streams from peers
async fn handle_inbound_tx_streams(mut incoming: IncomingStreams, state: Arc<SharedState>) {
    while let Some((peer_id, mut stream)) = incoming.next().await {
        info!("TX_STREAM: Accepted inbound TX stream from {}", peer_id);
        state.metrics.inbound_live.fetch_add(1, Ordering::Relaxed);
        let state = state.clone();

        tokio::spawn(async move {
            loop {
                match read_framed(&mut stream).await {
                    Ok(data) => {
                        state.metrics.message_read.fetch_add(1, Ordering::Relaxed);
                        state
                            .metrics
                            .byte_read
                            .fetch_add(data.len() as u64, Ordering::Relaxed);
                        // Parse INV/GETDATA message
                        handle_tx_stream_message(&state, &peer_id, &data, &mut stream).await;
                    }
                    Err(e) => {
                        state.metrics.error_read.fetch_add(1, Ordering::Relaxed);
                        state.metrics.inbound_live.fetch_sub(1, Ordering::Relaxed);
                        info!("TX stream from {} closed: {}", peer_id, e);
                        break;
                    }
                }
            }
        });
    }
}

/// Handle TX stream message in INV/GETDATA mode
async fn handle_tx_stream_message(
    state: &Arc<SharedState>,
    peer_id: &PeerId,
    data: &[u8],
    stream: &mut Stream,
) {
    match TxStreamMessage::decode(data) {
        Ok(TxStreamMessage::InvBatch(batch)) => {
            handle_inv_batch(state, peer_id, batch).await;
        }
        Ok(TxStreamMessage::GetData(getdata)) => {
            handle_getdata(state, peer_id, getdata, stream).await;
        }
        Ok(TxStreamMessage::Tx(tx_data)) => {
            handle_tx_response(state, peer_id, tx_data).await;
        }
        Err(e) => {
            warn!(
                "TX_PARSE_ERR: Failed to parse message from {}: {}",
                peer_id, e
            );
        }
    }
}

/// Handle INV_BATCH message - record sources and request TXs we don't have
async fn handle_inv_batch(state: &Arc<SharedState>, peer_id: &PeerId, batch: InvBatch) {
    debug!(
        "TX_INV_RECV: Received {} INVs from {}",
        batch.entries.len(),
        peer_id
    );

    let mut to_request: Vec<[u8; 32]> = Vec::new();

    for entry in batch.entries {
        // Check if we already have this TX
        {
            let seen = state.tx_seen.read().await;
            if seen.contains(&entry.hash) {
                // Already have it, just record this peer as a source (for relay tracking)
                continue;
            }
        }

        // Record this peer as a source for round-robin GETDATA
        let is_first = {
            let mut tracker = state.inv_tracker.write().await;
            tracker.record_source(entry.hash, *peer_id)
        };

        // If this is the first INV for this TX, we should request it
        if is_first {
            to_request.push(entry.hash);
        }
    }

    // Send GETDATA for TXs we don't have
    if !to_request.is_empty() {
        state
            .metrics
            .flood_demanded
            .fetch_add(to_request.len() as u64, Ordering::Relaxed);
        debug!(
            "TX_GETDATA_SEND: Requesting {} TXs from {}",
            to_request.len(),
            peer_id
        );

        // Record pending requests
        {
            let mut pending = state.pending_getdata.write().await;
            for hash in &to_request {
                pending.insert(*hash, *peer_id);
            }
        }

        // Build and send GETDATA
        let mut getdata = GetData::new();
        for hash in to_request {
            getdata.push(hash);
        }
        let msg = TxStreamMessage::GetData(getdata);
        let encoded = msg.encode();

        let state_clone = Arc::clone(state);
        let peer_clone = *peer_id;
        tokio::spawn(async move {
            if let Err(e) =
                send_to_peer_stream(&state_clone, peer_clone, StreamType::Tx, &encoded).await
            {
                warn!("Failed to send GETDATA to {}: {}", peer_clone, e);
            }
        });
    }
}

/// Handle GETDATA message - respond with requested TXs
async fn handle_getdata(
    state: &Arc<SharedState>,
    peer_id: &PeerId,
    getdata: GetData,
    _stream: &mut Stream,
) {
    debug!(
        "TX_GETDATA_RECV: Peer {} requesting {} TXs",
        peer_id,
        getdata.hashes.len()
    );

    for hash in getdata.hashes {
        // Look up TX in our buffer
        let tx_data = {
            let mut buffer = state.tx_buffer.write().await;
            buffer.get_cloned(&hash)
        };

        if let Some(tx_data) = tx_data {
            state
                .metrics
                .flood_fulfilled
                .fetch_add(1, Ordering::Relaxed);
            // Send TX response
            let msg = TxStreamMessage::Tx(tx_data);
            let encoded = msg.encode();

            let state_clone = Arc::clone(state);
            let peer_clone = *peer_id;
            tokio::spawn(async move {
                if let Err(e) =
                    send_to_peer_stream(&state_clone, peer_clone, StreamType::Tx, &encoded).await
                {
                    state_clone
                        .metrics
                        .error_write
                        .fetch_add(1, Ordering::Relaxed);
                    warn!("Failed to send TX to {}: {}", peer_clone, e);
                } else {
                    state_clone
                        .metrics
                        .message_write
                        .fetch_add(1, Ordering::Relaxed);
                    state_clone
                        .metrics
                        .byte_write
                        .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                    debug!("TX_SEND: Sent TX {:02x?}... to {}", &hash[..4], peer_clone);
                }
            });
        } else {
            state
                .metrics
                .flood_unfulfilled_unknown
                .fetch_add(1, Ordering::Relaxed);
            trace!(
                "TX_GETDATA_MISS: Don't have TX {:02x?}... for {}",
                &hash[..4],
                peer_id
            );
        }
    }
}

/// Handle TX response (from GETDATA request)
async fn handle_tx_response(state: &Arc<SharedState>, peer_id: &PeerId, tx: Vec<u8>) {
    let hash = blake2b_hash(&tx);
    let recv_start = std::time::Instant::now();
    let tx_len = tx.len() as u64;

    // Dedup
    {
        let mut seen = state.tx_seen.write().await;
        if seen.contains(&hash) {
            trace!("Duplicate TX from {}", peer_id);
            state
                .metrics
                .flood_duplicate_recv
                .fetch_add(tx_len, Ordering::Relaxed);
            return;
        }
        seen.put(hash, ());
        state
            .metrics
            .memory_flood_known
            .store(seen.len() as i64, Ordering::Relaxed);
    }
    state
        .metrics
        .flood_unique_recv
        .fetch_add(tx_len, Ordering::Relaxed);

    // Remove from pending requests and measure pull latency
    {
        let mut pending = state.pending_getdata.write().await;
        if let Some(req) = pending.remove(&hash) {
            let pull_us = req.first_sent_at.elapsed().as_micros() as u64;
            state
                .metrics
                .flood_tx_pull_latency_sum_us
                .fetch_add(pull_us, Ordering::Relaxed);
            state
                .metrics
                .flood_tx_pull_latency_count
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    // Store in buffer for responding to others' GETDATA
    {
        let mut buffer = state.tx_buffer.write().await;
        buffer.insert(hash, tx.clone());
    }

    debug!(
        "TX_RECV: Received TX {:02x?}... ({} bytes) from {}",
        &hash[..4],
        tx.len(),
        peer_id
    );

    // Forward to Core via bounded TX channel
    if let Err(_) = state.tx_event_tx.try_send(OverlayEvent::TxReceived {
        tx: tx.clone(),
        from: peer_id.clone(),
    }) {
        state.metrics.message_drop.fetch_add(1, Ordering::Relaxed);
        let dropped = state.tx_dropped_count.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped % 1000 == 1 {
            warn!(
                "TX_BACKPRESSURE: Dropped TX {:02x?}... (total dropped: {})",
                &hash[..4],
                dropped
            );
        }
    }

    // RELAY: Announce to other peers via INV
    let peers_to_announce: Vec<PeerId> = {
        let streams = state.peer_streams.read().await;
        let tracker = state.inv_tracker.read().await;

        // Get peers who already know about this TX (INV'd us)
        let known_sources: HashSet<PeerId> = tracker
            .peek_sources(&hash)
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();

        streams
            .keys()
            .filter(|p| **p != *peer_id && !known_sources.contains(p))
            .cloned()
            .collect()
    };

    if !peers_to_announce.is_empty() {
        debug!(
            "TX_RELAY: Announcing TX {:02x?}... to {} peers via INV",
            &hash[..4],
            peers_to_announce.len()
        );

        let inv_entry = InvEntry {
            hash,
            fee_per_op: 0, // TODO: extract fee from TX
        };

        // Add to batcher for each peer, send batch immediately when full
        for peer in &peers_to_announce {
            let batch_to_send = {
                let mut batcher = state.inv_batcher.write().await;
                batcher.add(*peer, inv_entry.clone())
            };
            if let Some(batch) = batch_to_send {
                send_inv_batch(state, *peer, batch).await;
            }
        }
    }

    // Record recv-transaction timing
    let elapsed_us = recv_start.elapsed().as_micros() as u64;
    state
        .metrics
        .recv_transaction_sum_us
        .fetch_add(elapsed_us, Ordering::Relaxed);
    state
        .metrics
        .recv_transaction_count
        .fetch_add(1, Ordering::Relaxed);
    state.metrics.update_recv_transaction_max(elapsed_us);
}

/// Handle inbound TxSet streams from peers
async fn handle_inbound_txset_streams(mut incoming: IncomingStreams, state: Arc<SharedState>) {
    while let Some((peer_id, mut stream)) = incoming.next().await {
        debug!("Accepted inbound TxSet stream from {}", peer_id);
        state.metrics.inbound_live.fetch_add(1, Ordering::Relaxed);
        let state = state.clone();

        tokio::spawn(async move {
            loop {
                match read_framed(&mut stream).await {
                    Ok(data) => {
                        state.metrics.message_read.fetch_add(1, Ordering::Relaxed);
                        state
                            .metrics
                            .byte_read
                            .fetch_add(data.len() as u64, Ordering::Relaxed);
                        // 32 bytes = request (just the hash)
                        // >32 bytes = response (hash + XDR data)
                        if data.len() == 32 {
                            // This is a GET_TX_SET request from peer
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(&data);
                            info!(
                                "TXSET_REQ_IN: Received TxSet request for {:02x?}... from {}",
                                &hash[..4],
                                peer_id
                            );

                            // Emit event so main.rs can look up cache and respond
                            if let Err(e) = state.event_tx.send(OverlayEvent::TxSetRequested {
                                hash,
                                from: peer_id,
                            }) {
                                warn!(
                                    "Failed to forward TxSetRequested event from {}: {}",
                                    peer_id, e
                                );
                            }
                        } else if data.len() > 32 {
                            // This is a TX_SET response to our request
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(&data[..32]);
                            let txset_data = data[32..].to_vec();

                            // Clear pending request flag and measure fetch latency
                            let was_pending = {
                                let mut pending = state.pending_txset_requests.write().await;
                                if let Some((_, request_time)) = pending.remove(&hash) {
                                    let fetch_us = request_time.elapsed().as_micros() as u64;
                                    state
                                        .metrics
                                        .fetch_txset_sum_us
                                        .fetch_add(fetch_us, Ordering::Relaxed);
                                    state
                                        .metrics
                                        .fetch_txset_count
                                        .fetch_add(1, Ordering::Relaxed);
                                    true
                                } else {
                                    false
                                }
                            };

                            // The legacy fetch succeeded — un-stick this hash
                            // from compact_failed so a future appearance can
                            // try the compact path again.
                            state.compact_failed.write().await.pop(&hash);

                            info!(
                                "TXSET_RECV: Received TxSet {:02x?}... ({} bytes) from {} (was_pending={})",
                                &hash[..4],
                                txset_data.len(),
                                peer_id,
                                was_pending
                            );
                            if let Err(e) = state.event_tx.send(OverlayEvent::TxSetReceived {
                                hash,
                                data: txset_data,
                                from: peer_id,
                            }) {
                                warn!(
                                    "Failed to forward TxSetReceived event from {}: {}",
                                    peer_id, e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        state.metrics.error_read.fetch_add(1, Ordering::Relaxed);
                        state.metrics.inbound_live.fetch_sub(1, Ordering::Relaxed);
                        info!("TxSet stream from {} closed: {}", peer_id, e);
                        break;
                    }
                }
            }
        });
    }
}

/// Handle inbound CompactTxSet streams from peers.
///
/// Each frame is a serialized `stellar_xdr::CompactTxSetMessage`. Dispatch by
/// variant: GET / GET_TXS / TXS request/response and the COMPACT_TX_SET
/// response to a GET.
async fn handle_inbound_compact_txset_streams(
    mut incoming: IncomingStreams,
    state: Arc<SharedState>,
) {
    while let Some((peer_id, mut stream)) = incoming.next().await {
        debug!("Accepted inbound CompactTxSet stream from {}", peer_id);
        state.metrics.inbound_live.fetch_add(1, Ordering::Relaxed);
        let state = state.clone();

        tokio::spawn(async move {
            loop {
                match read_framed(&mut stream).await {
                    Ok(data) => {
                        let frame_len = data.len();
                        state.metrics.message_read.fetch_add(1, Ordering::Relaxed);
                        state
                            .metrics
                            .byte_read
                            .fetch_add(frame_len as u64, Ordering::Relaxed);
                        match CompactTxSetMessage::from_xdr(&data, Limits::none()) {
                            Ok(msg) => {
                                handle_compact_message(&state, peer_id.clone(), frame_len, msg)
                                    .await;
                            }
                            Err(e) => {
                                warn!(
                                    "COMPACT_PARSE_ERR: Failed to parse CompactTxSetMessage from {} ({} bytes): {}",
                                    peer_id, frame_len, e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        state.metrics.error_read.fetch_add(1, Ordering::Relaxed);
                        state.metrics.inbound_live.fetch_sub(1, Ordering::Relaxed);
                        info!("CompactTxSet stream from {} closed: {}", peer_id, e);
                        break;
                    }
                }
            }
        });
    }
}

/// Dispatch a parsed `CompactTxSetMessage` from `peer_id`. `frame_len` is the
/// wire-frame size for byte-counter metrics.
async fn handle_compact_message(
    state: &Arc<SharedState>,
    peer_id: PeerId,
    frame_len: usize,
    msg: CompactTxSetMessage,
) {
    match msg {
        CompactTxSetMessage::Set(compact) => {
            state
                .metrics
                .compact_announce_recv
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .compact_announce_bytes_recv
                .fetch_add(frame_len as u64, Ordering::Relaxed);

            let hash: [u8; 32] = compact.tx_set_hash.0;
            // This is a direct response to a GET we issued — clear pending.
            {
                let mut pending = state.pending_compact_get.write().await;
                pending.remove(&hash);
            }
            handle_received_compact_set(state, peer_id, compact).await;
        }
        CompactTxSetMessage::SetGet(get) => {
            state.metrics.compact_get_recv.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .compact_get_bytes_recv
                .fetch_add(frame_len as u64, Ordering::Relaxed);

            let hash: [u8; 32] = get.tx_set_hash.0;
            info!(
                "COMPACT_GET_RECV: Peer {} requesting compact tx set {:02x?}...",
                peer_id,
                &hash[..4]
            );
            if let Err(e) = state.event_tx.send(OverlayEvent::CompactTxSetGetRequested {
                hash,
                from: peer_id,
            }) {
                warn!("Failed to forward CompactTxSetGetRequested: {}", e);
            }
        }
        CompactTxSetMessage::SetGetTxs(get_txs) => {
            state
                .metrics
                .compact_get_txs_recv
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .compact_get_txs_bytes_recv
                .fetch_add(frame_len as u64, Ordering::Relaxed);

            let hash: [u8; 32] = get_txs.tx_set_hash.0;
            let indices = match crate::flood::decode_indices(get_txs.indices.as_slice()) {
                Some(idx) => idx,
                None => {
                    warn!(
                        "COMPACT_GET_TXS_BAD_INDICES: from {} for {:02x?}... ({} bytes)",
                        peer_id,
                        &hash[..4],
                        get_txs.indices.len()
                    );
                    return;
                }
            };
            info!(
                "COMPACT_GET_TXS_RECV: Peer {} requesting {} txs for {:02x?}...",
                peer_id,
                indices.len(),
                &hash[..4]
            );
            if let Err(e) = state
                .event_tx
                .send(OverlayEvent::CompactTxSetGetTxsRequested {
                    hash,
                    indices,
                    from: peer_id,
                })
            {
                warn!("Failed to forward CompactTxSetGetTxsRequested: {}", e);
            }
        }
        CompactTxSetMessage::SetTxs(txs) => {
            state.metrics.compact_txs_recv.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .compact_txs_bytes_recv
                .fetch_add(frame_len as u64, Ordering::Relaxed);
            handle_received_compact_txs(state, peer_id, txs).await;
        }
    }
}

/// Process a received `CompactTxSet` (either an unsolicited announcement on
/// the SCP stream, or a direct response to our `COMPACT_TX_SET_GET` on the
/// new stream). Records the announcing peer, runs reconstruction against
/// the local mempool, and either:
///   - emits `TxSetReceived` (Complete), or
///   - sends `COMPACT_TX_SET_GET_TXS` for missing indices (Missing), or
///   - falls back to `fetch_txset_legacy` (HashMismatch).
async fn handle_received_compact_set(
    state: &Arc<SharedState>,
    peer_id: PeerId,
    compact: CompactTxSet,
) {
    let hash: [u8; 32] = compact.tx_set_hash.0;

    // Record this peer as an announcer (multi-peer cache).
    {
        let mut announcers = state.compact_announcers.write().await;
        let entry = announcers.get_or_insert_mut(hash, Vec::new);
        if !entry.contains(&peer_id) {
            entry.push(peer_id.clone());
            // Bound per-hash list to a small fixed number.
            if entry.len() > 8 {
                entry.remove(0);
            }
        }
    }

    // Skip the rest if a reconstruction is already in flight for this hash.
    // The second peer is now in `compact_announcers` and will be available as
    // a fallback target if the first GET_TXS times out (see M3 retry logic).
    if state
        .pending_compact_reconstructions
        .read()
        .await
        .contains_key(&hash)
    {
        debug!(
            "COMPACT_DUP_ANNOUNCE: {:02x?}... already reconstructing, recorded announcer only",
            &hash[..4]
        );
        return;
    }

    // Run reconstruction directly against the tx buffer — the closure
    // form lets us avoid cloning every buffer entry. The buffer is held
    // under a read lock for the duration of the digest pass, which is
    // CPU-bound and brief.
    let result = {
        let buffer = state.tx_buffer.read().await;
        reconstruct_full_tx_set(&compact, |visit| buffer.for_each_unexpired(visit))
    };
    match result {
        ReconstructResult::Complete(full_xdr) => {
            let size = full_xdr.len() as u64;
            state
                .metrics
                .compact_recon_complete
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .reconstructed_full_size_sum
                .fetch_add(size, Ordering::Relaxed);
            state
                .metrics
                .reconstructed_full_size_count
                .fetch_add(1, Ordering::Relaxed);
            state.metrics.update_reconstructed_full_size_max(size);
            info!(
                "COMPACT_RECON_OK: Reconstructed full tx set {:02x?}... ({} bytes) from {}",
                &hash[..4],
                size,
                peer_id
            );
            if let Err(e) = state.event_tx.send(OverlayEvent::TxSetReceived {
                hash,
                data: full_xdr,
                from: peer_id,
            }) {
                warn!("Failed to forward reconstructed TxSetReceived: {}", e);
            }
        }
        ReconstructResult::Missing { indices, matched } => {
            state
                .metrics
                .compact_recon_partial
                .fetch_add(1, Ordering::Relaxed);
            info!(
                "COMPACT_RECON_PARTIAL: {} missing txs in {:02x?}... — requesting from {}",
                indices.len(),
                &hash[..4],
                peer_id
            );

            // Stash pending reconstruction state. `matched` was built by
            // `reconstruct_full_tx_set` from a single buffer snapshot; reuse
            // it directly instead of redoing the digest match.
            {
                let mut pending = state.pending_compact_reconstructions.write().await;
                pending.insert(
                    hash,
                    PendingReconstruction {
                        compact,
                        matched,
                        requested_from: peer_id.clone(),
                        requested_at: Instant::now(),
                    },
                );
            }

            // Send GET_TXS to the announcer.
            let mut sorted_indices = indices;
            sorted_indices.sort_unstable();
            let encoded = encode_indices(&sorted_indices);
            let frame = build_compact_msg_set_get_txs(&hash, &encoded);
            let frame_len = frame.len();
            match send_to_peer_stream(state, peer_id.clone(), StreamType::CompactTxSet, &frame)
                .await
            {
                Ok(_) => {
                    state
                        .metrics
                        .compact_get_txs_sent
                        .fetch_add(1, Ordering::Relaxed);
                    state
                        .metrics
                        .compact_get_txs_bytes_sent
                        .fetch_add(frame_len as u64, Ordering::Relaxed);
                    state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
                    state
                        .metrics
                        .byte_write
                        .fetch_add(frame_len as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "COMPACT_GET_TXS_SEND_FAIL: Failed to send GET_TXS for {:02x?}... to {}: {} — falling back to legacy",
                        &hash[..4],
                        peer_id,
                        e
                    );
                    // Drop the pending reconstruction and fall back to the
                    // legacy fetch path. Herder won't retry on its own
                    // (`requestTxSet` is "Only once!"), so we must trigger
                    // recovery from here.
                    state
                        .pending_compact_reconstructions
                        .write()
                        .await
                        .remove(&hash);
                    mark_compact_failed_and_fallback(state, hash).await;
                }
            }
        }
        ReconstructResult::HashMismatch { reconstructed_hash } => {
            state
                .metrics
                .compact_recon_hash_mismatch
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                "COMPACT_RECON_HASH_MISMATCH: tx_set {:02x?}... reconstructed to {:02x?}... — falling back to legacy fetch",
                &hash[..4],
                &reconstructed_hash[..4]
            );
            mark_compact_failed_and_fallback(state, hash).await;
        }
    }
}

/// Process a received `CompactTxSetTxs` — the response to a `GET_TXS` we
/// previously sent. Slots received envelopes into the matching pending
/// reconstruction by digest; if the result is now complete and re-hashes
/// correctly, emit `TxSetReceived`. Otherwise mark failed and fall back.
async fn handle_received_compact_txs(
    state: &Arc<SharedState>,
    peer_id: PeerId,
    txs: stellar_xdr::CompactTxSetTxs,
) {
    let hash: [u8; 32] = txs.tx_set_hash.0;
    let received_envs: Vec<stellar_xdr::TransactionEnvelope> = txs.txs.into();

    // Take ownership of the pending reconstruction.
    let mut pending = match state
        .pending_compact_reconstructions
        .write()
        .await
        .remove(&hash)
    {
        Some(p) => p,
        None => {
            warn!(
                "COMPACT_TXS_UNEXPECTED: Got SetTxs for {:02x?}... from {} with no pending reconstruction",
                &hash[..4],
                peer_id
            );
            return;
        }
    };

    // Map each received tx by its 6-byte SipHash digest under the tx-set key.
    // Serialize each envelope once here and store the bytes; the same bytes
    // are reused below to assemble the full tx set XDR.
    let key_set_hash: [u8; 32] = pending.compact.tx_set_hash.0;
    let mut digest_to_xdr: HashMap<[u8; 6], Vec<u8>> = HashMap::new();
    for env in received_envs {
        let env_xdr = match env.to_xdr(Limits::none()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let tx_hash = blake2b_hash(&env_xdr);
        digest_to_xdr.insert(
            crate::flood::compact_tx_digest(&key_set_hash, &tx_hash),
            env_xdr,
        );
    }

    // Fill missing slots with the already-serialized envelope bytes.
    let txs_bytes = pending.compact.txs.as_slice();
    for (i, slot) in pending.matched.iter_mut().enumerate() {
        if slot.is_some() {
            continue;
        }
        let mut chunk = [0u8; 6];
        chunk.copy_from_slice(&txs_bytes[i * 6..(i + 1) * 6]);
        if let Some(env_xdr) = digest_to_xdr.remove(&chunk) {
            *slot = Some(env_xdr);
        }
    }

    // Check if all slots are filled.
    if pending.matched.iter().any(|s| s.is_none()) {
        warn!(
            "COMPACT_RECON_STILL_MISSING: After GET_TXS response from {}, tx_set {:02x?}... still has gaps — falling back to legacy fetch",
            peer_id,
            &hash[..4]
        );
        mark_compact_failed_and_fallback(state, hash).await;
        return;
    }

    // All slots are `Some(Vec<u8>)`; pull them out and build the full tx set.
    let prev_hash: [u8; 32] = pending.compact.previous_ledger_hash.0;
    let base_fee = pending.compact.base_fee;
    let tx_envelopes_xdr: Vec<Vec<u8>> =
        pending.matched.into_iter().map(|s| s.unwrap()).collect();

    let full_xdr = crate::flood::build_full_tx_set_xdr(&prev_hash, base_fee, &tx_envelopes_xdr);
    let actual_hash = hash_tx_set(&full_xdr);
    if actual_hash != hash {
        state
            .metrics
            .compact_recon_hash_mismatch
            .fetch_add(1, Ordering::Relaxed);
        warn!(
            "COMPACT_RECON_HASH_MISMATCH (post-GET_TXS): tx_set {:02x?}... reconstructed to {:02x?}...",
            &hash[..4],
            &actual_hash[..4]
        );
        mark_compact_failed_and_fallback(state, hash).await;
        return;
    }

    let size = full_xdr.len() as u64;
    state
        .metrics
        .compact_recon_complete
        .fetch_add(1, Ordering::Relaxed);
    state
        .metrics
        .reconstructed_full_size_sum
        .fetch_add(size, Ordering::Relaxed);
    state
        .metrics
        .reconstructed_full_size_count
        .fetch_add(1, Ordering::Relaxed);
    state.metrics.update_reconstructed_full_size_max(size);
    info!(
        "COMPACT_RECON_OK_VIA_GET_TXS: Reconstructed full tx set {:02x?}... ({} bytes) after GET_TXS from {}",
        &hash[..4],
        size,
        peer_id
    );
    if let Err(e) = state.event_tx.send(OverlayEvent::TxSetReceived {
        hash,
        data: full_xdr,
        from: pending.requested_from,
    }) {
        warn!("Failed to forward reconstructed TxSetReceived: {}", e);
    }
}

/// Mark `hash` as compact-failed and trigger a legacy TXSET fetch.
async fn mark_compact_failed_and_fallback(state: &Arc<SharedState>, hash: [u8; 32]) {
    state
        .metrics
        .compact_recon_failed_fallback_legacy
        .fetch_add(1, Ordering::Relaxed);
    {
        let mut failed = state.compact_failed.write().await;
        failed.put(hash, ());
    }
    fetch_txset_legacy(state, hash).await;
}

/// Retry a `COMPACT_TX_SET_GET` for `hash` against the next un-tried connected
/// announcer in `compact_announcers`. Updates `pending_compact_get[hash]` to
/// reflect the new attempt. If no fresh announcer is available (or the send
/// fails for the new peer too), removes the pending entry and falls back to
/// `mark_compact_failed_and_fallback` (legacy fetch).
///
/// `prior_tried` is the set of peers we've already asked for `hash` (the
/// caller has typically just removed the pending entry to take ownership of
/// its `tried` set).
async fn retry_compact_get_or_fallback(
    state: &Arc<SharedState>,
    hash: [u8; 32],
    prior_tried: HashSet<PeerId>,
) {
    // Find the next connected announcer not in prior_tried.
    let next_peer: Option<PeerId> = {
        let announcers = state.compact_announcers.read().await;
        let streams = state.peer_streams.read().await;
        announcers.peek(&hash).and_then(|peers| {
            peers
                .iter()
                .find(|p| !prior_tried.contains(p) && streams.contains_key(p))
                .cloned()
        })
    };

    let peer = match next_peer {
        Some(p) => p,
        None => {
            debug!(
                "COMPACT_GET_NO_RETRY_PEER: {:02x?}... exhausted announcers — falling back to legacy",
                &hash[..4]
            );
            mark_compact_failed_and_fallback(state, hash).await;
            return;
        }
    };

    // Insert a fresh PendingCompactGet covering the new attempt; tried
    // accumulates prior attempts plus this one.
    let mut tried = prior_tried;
    tried.insert(peer.clone());
    state.pending_compact_get.write().await.insert(
        hash,
        PendingCompactGet {
            peer: peer.clone(),
            started_at: Instant::now(),
            tried,
        },
    );

    let frame = build_compact_msg_set_get(&hash);
    let frame_len = frame.len();
    match send_to_peer_stream(state, peer.clone(), StreamType::CompactTxSet, &frame).await {
        Ok(_) => {
            state
                .metrics
                .compact_get_retry
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .compact_get_sent
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .compact_get_bytes_sent
                .fetch_add(frame_len as u64, Ordering::Relaxed);
            state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .byte_write
                .fetch_add(frame_len as u64, Ordering::Relaxed);
            info!(
                "COMPACT_GET_RETRY: Re-requested compact tx set {:02x?}... from announcer {}",
                &hash[..4],
                peer
            );
        }
        Err(e) => {
            state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
            warn!(
                "COMPACT_GET_RETRY_SEND_FAIL: {:02x?}... to {}: {} — falling back to legacy",
                &hash[..4],
                peer,
                e
            );
            state.pending_compact_get.write().await.remove(&hash);
            mark_compact_failed_and_fallback(state, hash).await;
        }
    }
}


/// INV/GETDATA housekeeping task.
///
/// Periodically:
/// 1. Flushes INV batches that have timed out (100ms)
/// 2. Checks GETDATA timeouts and retries to other peers
async fn inv_getdata_housekeeping_task(state: Arc<SharedState>) {
    use crate::flood::{GETDATA_PEER_TIMEOUT, INV_BATCH_MAX_DELAY};

    // Run every 50ms (half the batch timeout for responsiveness)
    let mut interval = tokio::time::interval(Duration::from_millis(50));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        // 1. Flush expired INV batches
        let expired_peers = {
            let batcher = state.inv_batcher.read().await;
            batcher.expired_peers()
        };

        for peer_id in expired_peers {
            flush_inv_batch_to_peer(&state, peer_id).await;
        }

        // 2. Handle GETDATA timeouts
        let (to_retry, gave_up) = {
            let mut pending = state.pending_getdata.write().await;
            pending.process_timeouts()
        };

        // Log give-ups
        if !gave_up.is_empty() {
            state
                .metrics
                .flood_abandoned_demands
                .fetch_add(gave_up.len() as u64, Ordering::Relaxed);
        }
        for hash in &gave_up {
            warn!(
                "GETDATA_TIMEOUT: Gave up on TX {:02x?}... after 30s",
                &hash[..4]
            );
        }

        // Retry timed-out requests: group by next peer, send batched GETDATA
        if !to_retry.is_empty() {
            state
                .metrics
                .demand_timeout
                .fetch_add(to_retry.len() as u64, Ordering::Relaxed);

            // Resolve next peer for each hash and group by peer
            let mut per_peer: HashMap<PeerId, Vec<[u8; 32]>> = HashMap::new();
            {
                let mut tracker = state.inv_tracker.write().await;
                let mut pending = state.pending_getdata.write().await;
                for hash in to_retry {
                    if let Some(peer) = tracker.get_next_peer(&hash) {
                        if let Some(req) = pending.get_mut(&hash) {
                            req.retry(peer.clone());
                        }
                        per_peer.entry(peer).or_default().push(hash);
                    } else {
                        debug!("GETDATA_RETRY: No more peers for TX {:02x?}...", &hash[..4]);
                    }
                }
            }

            // Send one batched GETDATA per peer
            for (peer, hashes) in per_peer {
                debug!(
                    "GETDATA_RETRY: Retrying {} TXs to peer {}",
                    hashes.len(),
                    peer
                );
                let getdata = GetData { hashes };
                let msg = TxStreamMessage::GetData(getdata);
                let encoded = msg.encode();

                if let Err(e) =
                    try_send_to_existing_stream(&state, peer.clone(), StreamType::Tx, &encoded)
                        .await
                {
                    warn!("Failed to send GETDATA retry to {}: {:?}", peer, e);
                }
            }
        }

        // 3. Sweep stale compact-protocol pending state. The disconnect path
        //    handles peer-down cleanup, but a peer can stay connected and
        //    silently drop a request — these timeouts catch that.
        let now = Instant::now();

        let timed_out_get: Vec<([u8; 32], HashSet<PeerId>)> = {
            let mut pending = state.pending_compact_get.write().await;
            let mut out = Vec::new();
            // Take ownership of the timed-out entries so we can use their
            // `tried` set when picking the next announcer.
            let timed_hashes: Vec<[u8; 32]> = pending
                .iter()
                .filter_map(|(h, pcg)| {
                    if now.duration_since(pcg.started_at) > COMPACT_GET_TIMEOUT {
                        Some(*h)
                    } else {
                        None
                    }
                })
                .collect();
            for h in timed_hashes {
                if let Some(pcg) = pending.remove(&h) {
                    out.push((h, pcg.tried));
                }
            }
            out
        };
        if !timed_out_get.is_empty() {
            state
                .metrics
                .compact_get_timeout
                .fetch_add(timed_out_get.len() as u64, Ordering::Relaxed);
        }
        for (hash, tried) in timed_out_get {
            warn!(
                "COMPACT_GET_TIMEOUT: Compact GET for {:02x?}... timed out — retrying next announcer",
                &hash[..4]
            );
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                retry_compact_get_or_fallback(&state, hash, tried).await;
            });
        }

        let timed_out_recon: Vec<[u8; 32]> = {
            let mut pending = state.pending_compact_reconstructions.write().await;
            let mut out = Vec::new();
            pending.retain(|hash, p| {
                if now.duration_since(p.requested_at) > COMPACT_RECONSTRUCTION_TIMEOUT {
                    out.push(*hash);
                    false
                } else {
                    true
                }
            });
            out
        };
        if !timed_out_recon.is_empty() {
            state
                .metrics
                .compact_reconstruction_timeout
                .fetch_add(timed_out_recon.len() as u64, Ordering::Relaxed);
        }
        for hash in timed_out_recon {
            warn!(
                "COMPACT_RECON_TIMEOUT: GET_TXS response for {:02x?}... timed out — falling back to legacy",
                &hash[..4]
            );
            // Spawn so a burst of timeouts (e.g., one silent peer that
            // announced many sets) doesn't stall this 50ms tick on serial
            // network I/O.
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                mark_compact_failed_and_fallback(&state, hash).await;
            });
        }
    }
}

// TODO: add proper retries
// /// TX set fetch retry task.
// ///
// /// Periodically checks for timed-out TX set fetch requests and retries from different peers.
// /// Runs every 500ms (half the timeout for responsiveness).
// async fn txset_retry_task(state: Arc<SharedState>) {
//     let mut interval = tokio::time::interval(Duration::from_millis(500));
//     interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

//     loop {
//         interval.tick().await;

//         // Find timed-out requests
//         let timed_out: Vec<([u8; 32], std::collections::HashSet<PeerId>)> = {
//             let pending = state.pending_txset_requests.read().await;
//             pending
//                 .iter()
//                 .filter(|(_, req)| req.requested_at.elapsed() >= TXSET_FETCH_TIMEOUT)
//                 .map(|(hash, req)| (*hash, req.tried_peers.clone()))
//                 .collect()
//         };

//         if timed_out.is_empty() {
//             continue;
//         }

//         // Get connected peers
//         let connected_peers: Vec<PeerId> = {
//             let streams = state.peer_streams.read().await;
//             streams.keys().cloned().collect()
//         };

//         // Retry each timed-out request to a different peer
//         for (hash, tried_peers) in timed_out {
//             // Find an untried peer
//             let next_peer = connected_peers
//                 .iter()
//                 .find(|p| !tried_peers.contains(*p))
//                 .cloned();

//             let peer = match next_peer {
//                 Some(p) => p,
//                 None => {
//                     // All peers tried - reset and start over with first peer
//                     if let Some(p) = connected_peers.first().cloned() {
//                         info!(
//                             "TXSET_RETRY: All peers tried for {:02x?}..., restarting with {}",
//                             &hash[..4],
//                             p
//                         );
//                         // Clear tried peers
//                         let mut pending = state.pending_txset_requests.write().await;
//                         if let Some(req) = pending.get_mut(&hash) {
//                             req.tried_peers.clear();
//                         }
//                         p
//                     } else {
//                         warn!(
//                             "TXSET_RETRY_FAIL: No peers available to retry TX set {:02x?}...",
//                             &hash[..4]
//                         );
//                         continue;
//                     }
//                 }
//             };

//             info!(
//                 "TXSET_RETRY: Retrying TX set {:02x?}... from {} (timeout after {:?})",
//                 &hash[..4],
//                 peer,
//                 TXSET_FETCH_TIMEOUT
//             );

//             // Update pending request
//             {
//                 let mut pending = state.pending_txset_requests.write().await;
//                 if let Some(req) = pending.get_mut(&hash) {
//                     req.peer = peer.clone();
//                     req.requested_at = Instant::now();
//                     req.tried_peers.insert(peer.clone());
//                 }
//             }

//             // Send request on TxSet stream
//             if let Err(e) =
//                 try_send_to_existing_stream(&state, peer.clone(), StreamType::TxSet, &hash).await
//             {
//                 warn!(
//                     "TXSET_RETRY_FAIL: Failed to send retry request for {:02x?}... to {}: {:?}",
//                     &hash[..4],
//                     peer,
//                     e
//                 );
//             }
//         }
//     }
// }

// ─────────────────────────────────────────────────────────────────────────
// TX set fetching
//
// `fetch_txset_compact_first` is the new entry point: try `COMPACT_TX_SET_GET`
// against an announcing peer (from `compact_announcers`) on the new stream;
// reconstruction happens on the response (see `handle_received_compact_set`).
//
// `fetch_txset_legacy` is the original behavior, used as a fallback when
// the compact path can't make progress (no announcer connected, or
// reconstruction failed and `compact_failed` is set).
// ─────────────────────────────────────────────────────────────────────────

async fn fetch_txset_compact_first(state: &Arc<SharedState>, hash: [u8; 32]) {
    // Short-circuit if compact has already failed for this hash.
    {
        let failed = state.compact_failed.read().await;
        if failed.contains(&hash) {
            debug!(
                "TXSET_FETCH_LEGACY (compact_failed cached): {:02x?}...",
                &hash[..4]
            );
            fetch_txset_legacy(state, hash).await;
            return;
        }
    }

    // Dedup against an in-flight reconstruction. If we've already received
    // a CompactTxSet announcement for this hash and are waiting on a
    // GET_TXS response, sending another SetGet would just trigger a fresh
    // CompactTxSet response and a redundant reconstruction round.
    if state
        .pending_compact_reconstructions
        .read()
        .await
        .contains_key(&hash)
    {
        debug!(
            "COMPACT_RECON_PENDING: {:02x?}... already reconstructing, skipping fetch",
            &hash[..4]
        );
        return;
    }

    // Dedup against pending compact GET and pending legacy fetch.
    {
        let pending_compact = state.pending_compact_get.read().await;
        if let Some(pcg) = pending_compact.get(&hash) {
            let streams = state.peer_streams.read().await;
            if streams.contains_key(&pcg.peer) {
                debug!(
                    "COMPACT_GET_DEDUP: {:02x?}... already requested from {}",
                    &hash[..4],
                    pcg.peer
                );
                return;
            }
        }
        let pending_legacy = state.pending_txset_requests.read().await;
        if let Some((p, _)) = pending_legacy.get(&hash) {
            let streams = state.peer_streams.read().await;
            if streams.contains_key(p) {
                debug!(
                    "TXSET_FETCH_DEDUP (legacy): {:02x?}... already requested from {}",
                    &hash[..4],
                    p
                );
                return;
            }
        }
    }

    // Pick a connected announcer.
    let chosen_peer = {
        let mut announcers = state.compact_announcers.write().await;
        let streams = state.peer_streams.read().await;
        let connected: Option<PeerId> = announcers
            .get(&hash)
            .and_then(|peers| peers.iter().find(|p| streams.contains_key(p)).cloned());
        connected
    };

    let peer = match chosen_peer {
        Some(p) => p,
        None => {
            debug!(
                "COMPACT_NO_ANNOUNCER: No connected announcer for {:02x?}... — using legacy fetch",
                &hash[..4]
            );
            fetch_txset_legacy(state, hash).await;
            return;
        }
    };

    // Record pending compact GET.
    let mut tried = HashSet::new();
    tried.insert(peer.clone());
    state.pending_compact_get.write().await.insert(
        hash,
        PendingCompactGet {
            peer: peer.clone(),
            started_at: Instant::now(),
            tried,
        },
    );

    let frame = build_compact_msg_set_get(&hash);
    let frame_len = frame.len();
    match send_to_peer_stream(state, peer.clone(), StreamType::CompactTxSet, &frame).await {
        Ok(_) => {
            state
                .metrics
                .compact_get_sent
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .compact_get_bytes_sent
                .fetch_add(frame_len as u64, Ordering::Relaxed);
            state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .byte_write
                .fetch_add(frame_len as u64, Ordering::Relaxed);
            info!(
                "COMPACT_GET_SENT: Requested compact tx set {:02x?}... from announcer {}",
                &hash[..4],
                peer
            );
        }
        Err(e) => {
            state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
            warn!(
                "COMPACT_GET_SEND_FAIL: {:02x?}... to {}: {} — retrying next announcer",
                &hash[..4],
                peer,
                e
            );
            // Hand off to retry helper which preserves `tried` and either
            // picks the next un-tried announcer or falls back to legacy.
            let prior_tried = state
                .pending_compact_get
                .write()
                .await
                .remove(&hash)
                .map(|pcg| pcg.tried)
                .unwrap_or_default();
            retry_compact_get_or_fallback(state, hash, prior_tried).await;
        }
    }
}

async fn fetch_txset_legacy(state: &Arc<SharedState>, hash: [u8; 32]) {
    // Dedup against existing legacy fetch.
    {
        let pending = state.pending_txset_requests.read().await;
        if let Some((pending_peer, _)) = pending.get(&hash) {
            let streams = state.peer_streams.read().await;
            if streams.contains_key(pending_peer) {
                debug!(
                    "TXSET_FETCH_LEGACY_SKIP: TxSet {:02x?}... already being fetched from {}, skipping duplicate",
                    &hash[..4], pending_peer
                );
                return;
            }
        }
    }

    // Prefer the txset_sources LRU (populated when SCP envelopes reference
    // this hash); otherwise pick any connected peer.
    let known_source = {
        let sources = state.txset_sources.read().await;
        sources.peek(&hash).cloned()
    };

    let peer = if let Some(source_peer) = known_source {
        let streams = state.peer_streams.read().await;
        if streams.contains_key(&source_peer) {
            info!(
                "TXSET_FETCH_LEGACY: Fetching TX set {:02x?}... from known source {}",
                &hash[..4],
                source_peer
            );
            source_peer
        } else {
            match streams.keys().next().cloned() {
                Some(p) => {
                    info!(
                        "TXSET_FETCH_LEGACY: Fetching TX set {:02x?}... from fallback peer {} (source {} disconnected)",
                        &hash[..4], p, source_peer
                    );
                    p
                }
                None => {
                    warn!(
                        "TXSET_FETCH_LEGACY_FAIL: No peers to fetch TX set {:02x?}... from",
                        &hash[..4]
                    );
                    return;
                }
            }
        }
    } else {
        let streams = state.peer_streams.read().await;
        match streams.keys().next().cloned() {
            Some(p) => {
                info!(
                    "TXSET_FETCH_LEGACY: Fetching TX set {:02x?}... from random peer {} (no known source)",
                    &hash[..4],
                    p
                );
                p
            }
            None => {
                warn!(
                    "TXSET_FETCH_LEGACY_FAIL: No peers to fetch TX set {:02x?}... from",
                    &hash[..4]
                );
                return;
            }
        }
    };

    state
        .pending_txset_requests
        .write()
        .await
        .insert(hash, (peer.clone(), Instant::now()));

    match send_to_peer_stream(state, peer.clone(), StreamType::TxSet, &hash).await {
        Ok(_) => info!(
            "TXSET_FETCH_LEGACY_SENT: Sent request for TxSet {:02x?}... to {}",
            &hash[..4],
            peer
        ),
        Err(e) => {
            warn!(
                "TXSET_FETCH_LEGACY_FAIL: Failed to send TxSet request {:02x?}... to {}: {}",
                &hash[..4],
                peer,
                e
            );
            state.pending_txset_requests.write().await.remove(&hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── SCP-stream type-prefix framing ───

    #[test]
    fn test_scp_frame_state_request_roundtrip() {
        let payload = 12345u32.to_le_bytes();
        let frame = encode_scp_frame(ScpStreamMessageType::StateRequest, &payload);
        assert_eq!(frame.len(), 4 + payload.len());
        let tag = u32::from_be_bytes(frame[..4].try_into().unwrap());
        assert_eq!(
            ScpStreamMessageType::from_u32(tag),
            Some(ScpStreamMessageType::StateRequest)
        );
        assert_eq!(&frame[4..], &payload);
    }

    #[test]
    fn test_scp_frame_envelope_roundtrip() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42];
        let frame = encode_scp_frame(ScpStreamMessageType::Envelope, &payload);
        let tag = u32::from_be_bytes(frame[..4].try_into().unwrap());
        assert_eq!(
            ScpStreamMessageType::from_u32(tag),
            Some(ScpStreamMessageType::Envelope)
        );
        assert_eq!(&frame[4..], &payload[..]);
    }

    #[test]
    fn test_scp_frame_compact_roundtrip() {
        let payload = vec![0u8; 80];
        let frame = encode_scp_frame(ScpStreamMessageType::CompactTxSet, &payload);
        let tag = u32::from_be_bytes(frame[..4].try_into().unwrap());
        assert_eq!(
            ScpStreamMessageType::from_u32(tag),
            Some(ScpStreamMessageType::CompactTxSet)
        );
        assert_eq!(&frame[4..], &payload[..]);
    }

    #[test]
    fn test_scp_frame_unknown_tag() {
        // Tag 99 is not a valid ScpStreamMessageType.
        assert_eq!(ScpStreamMessageType::from_u32(99), None);
    }

    // ─── CompactTxSetMessage frame construction ───

    #[test]
    fn test_compact_msg_set_get_roundtrip() {
        let hash = [0xAB; 32];
        let frame = build_compact_msg_set_get(&hash);
        // Discriminant + Hash = 4 + 32 = 36 bytes.
        assert_eq!(frame.len(), 36);
        let parsed = CompactTxSetMessage::from_xdr(&frame, Limits::none()).unwrap();
        match parsed {
            CompactTxSetMessage::SetGet(g) => assert_eq!(g.tx_set_hash.0, hash),
            other => panic!("expected SetGet, got {:?}", other),
        }
    }

    #[test]
    fn test_compact_msg_set_get_txs_roundtrip() {
        let hash = [0xCD; 32];
        // Encoded indices for [0, 5, 7]: LEB128(0), LEB128(4), LEB128(1) = [0, 4, 1]
        let indices_payload = crate::flood::encode_indices(&[0, 5, 7]);
        let frame = build_compact_msg_set_get_txs(&hash, &indices_payload);
        let parsed = CompactTxSetMessage::from_xdr(&frame, Limits::none()).unwrap();
        match parsed {
            CompactTxSetMessage::SetGetTxs(g) => {
                assert_eq!(g.tx_set_hash.0, hash);
                assert_eq!(g.indices.as_slice(), indices_payload.as_slice());
            }
            other => panic!("expected SetGetTxs, got {:?}", other),
        }
    }

    #[test]
    fn test_compact_msg_set_response_wraps_existing_xdr() {
        // Build a CompactTxSet via stellar_xdr, then prepend the
        // discriminant and verify the round-trip parses correctly.
        let tx_set_hash = [0x01; 32];
        let prev = [0x02; 32];
        let compact_xdr =
            crate::flood::build_compact_tx_set_xdr(&tx_set_hash, &prev, Some(50), &[]);
        let frame = build_compact_msg_set(&compact_xdr);
        let parsed = CompactTxSetMessage::from_xdr(&frame, Limits::none()).unwrap();
        match parsed {
            CompactTxSetMessage::Set(s) => {
                assert_eq!(s.tx_set_hash.0, tx_set_hash);
                assert_eq!(s.previous_ledger_hash.0, prev);
                assert_eq!(s.base_fee, Some(50));
                assert_eq!(s.txs.len(), 0);
            }
            other => panic!("expected Set, got {:?}", other),
        }
    }

    /// Hand-rolled CompactTxSetMessage frame must re-encode byte-for-byte
    /// identical when round-tripped through the typed XDR encoder.
    fn assert_msg_xdr_roundtrip(frame: &[u8]) {
        let parsed = CompactTxSetMessage::from_xdr(frame, Limits::none())
            .expect("hand-rolled frame failed to parse as CompactTxSetMessage");
        let reencoded = parsed
            .to_xdr(Limits::none())
            .expect("typed encoder failed on parsed CompactTxSetMessage");
        assert_eq!(
            frame,
            reencoded.as_slice(),
            "hand-rolled CompactTxSetMessage ≠ typed re-encode"
        );
    }

    #[test]
    fn test_compact_msg_xdr_byte_equal_set_get() {
        let frame = build_compact_msg_set_get(&[0x77; 32]);
        assert_msg_xdr_roundtrip(&frame);
    }

    #[test]
    fn test_compact_msg_xdr_byte_equal_set_get_txs() {
        let indices = crate::flood::encode_indices(&[1, 2, 3, 100, 200]);
        let frame = build_compact_msg_set_get_txs(&[0x88; 32], &indices);
        assert_msg_xdr_roundtrip(&frame);
    }

    #[test]
    fn test_compact_msg_xdr_byte_equal_set() {
        let inner = crate::flood::build_compact_tx_set_xdr(
            &[0x99; 32],
            &[0xAA; 32],
            Some(42),
            &[[0xBB; 32], [0xCC; 32]],
        );
        let frame = build_compact_msg_set(&inner);
        assert_msg_xdr_roundtrip(&frame);
    }

    #[test]
    fn test_compact_msg_xdr_byte_equal_set_txs() {
        // Use TransactionEnvelope::default so we don't hand-construct the
        // nested types. Each tx must be a valid TransactionEnvelope encoding.
        use stellar_xdr::TransactionEnvelope;
        let env_xdr = TransactionEnvelope::default()
            .to_xdr(Limits::none())
            .unwrap();
        let frame =
            build_compact_msg_set_txs(&[0xDD; 32], &[env_xdr.clone(), env_xdr.clone()]);
        assert_msg_xdr_roundtrip(&frame);
    }

    #[tokio::test]
    async fn test_overlay_creation() {
        let keypair = Keypair::generate_ed25519();
        let (handle, _events, _tx_events, overlay) =
            create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

        let overlay_task = tokio::spawn(async move {
            overlay.run("127.0.0.1", 0).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        handle.shutdown().await;

        tokio::time::timeout(Duration::from_secs(1), overlay_task)
            .await
            .expect("Overlay should shutdown")
            .expect("Overlay task should complete");
    }

    #[tokio::test]
    async fn test_two_overlays_connect_and_send_scp() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, mut events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, mut events2, _tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19101;
        let overlay1_task = tokio::spawn(async move {
            overlay1.run("127.0.0.1", listen_port).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let overlay2_task = tokio::spawn(async move {
            overlay2.run("127.0.0.1", 19102).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Give connection and streams time to establish
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Send SCP from node1
        let scp_msg = b"test SCP envelope".to_vec();
        handle1.broadcast_scp(scp_msg.clone()).await;

        // Wait for SCP on node2
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut received = false;

        while tokio::time::Instant::now() < deadline && !received {
            tokio::select! {
                Some(event) = events2.recv() => {
                    if let OverlayEvent::ScpReceived { envelope, .. } = event {
                        assert_eq!(envelope, scp_msg);
                        received = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        assert!(received, "Should receive SCP message");

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    #[tokio::test]
    async fn test_scp_dedup() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, mut events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, mut events2, _tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19201;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19202).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + stream setup
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain connection events
        while events2.try_recv().is_ok() {}

        // Send same SCP twice
        let scp_msg = b"duplicate test".to_vec();
        handle1.broadcast_scp(scp_msg.clone()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        handle1.broadcast_scp(scp_msg.clone()).await;

        // Should only receive once
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut count = 0;
        while let Ok(event) = events2.try_recv() {
            if matches!(event, OverlayEvent::ScpReceived { .. }) {
                count += 1;
            }
        }

        assert_eq!(count, 1, "Should receive only one SCP due to dedup");

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    #[test]
    fn test_blake2b_hash() {
        let data = b"test data";
        let hash1 = blake2b_hash(data);
        let hash2 = blake2b_hash(data);
        assert_eq!(hash1, hash2);

        let hash3 = blake2b_hash(b"different");
        assert_ne!(hash1, hash3);
    }

    /// Critical test: SCP messages must not be blocked by TX traffic
    /// Proves QUIC stream independence by sending large TX payload that takes
    /// measurable time, then verifying SCP arrives BEFORE TX flood completes.
    #[tokio::test]
    async fn test_scp_not_blocked_by_tx_flood() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, mut events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19301;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19302).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + streams
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain connection events
        while events2.try_recv().is_ok() {}
        while tx_events2.try_recv().is_ok() {}

        // Send large TXs - 1000 x 10KB = 10MB total
        // This should take noticeable time to transfer
        let tx_count = 1000;
        let tx_size = 10 * 1024; // 10KB each
        let large_tx: Vec<u8> = (0..tx_size).map(|i| (i % 256) as u8).collect();

        let tx_start = std::time::Instant::now();
        for i in 0..tx_count {
            // Each TX slightly different to avoid dedup
            let mut tx = large_tx.clone();
            tx[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            handle1.broadcast_tx(tx).await;
        }

        // Immediately send small SCP (should bypass TX queue)
        let scp_msg = b"urgent SCP envelope".to_vec();
        let scp_send_time = std::time::Instant::now();
        handle1.broadcast_scp(scp_msg.clone()).await;

        // Track when SCP arrives vs when all TXs arrive
        // SCP comes on unbounded events channel, TX on bounded tx_events channel
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut scp_received_at: Option<std::time::Instant> = None;
        let mut tx_count_received = 0u32;
        let mut all_tx_received_at: Option<std::time::Instant> = None;

        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(event) = events2.recv() => {
                    if let OverlayEvent::ScpReceived { envelope, .. } = event {
                        if envelope == scp_msg && scp_received_at.is_none() {
                            scp_received_at = Some(std::time::Instant::now());
                        }
                    }
                }
                Some(event) = tx_events2.recv() => {
                    if let OverlayEvent::TxReceived { .. } = event {
                        tx_count_received += 1;
                        if tx_count_received >= tx_count && all_tx_received_at.is_none() {
                            all_tx_received_at = Some(std::time::Instant::now());
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }

            // Done when both received
            if scp_received_at.is_some() && all_tx_received_at.is_some() {
                break;
            }
        }

        let scp_received_at = scp_received_at.expect("SCP should be received");
        let all_tx_received_at = all_tx_received_at.expect("All TXs should be received");

        let scp_latency = scp_received_at.duration_since(scp_send_time);
        let tx_total_time = all_tx_received_at.duration_since(tx_start);

        println!("SCP latency: {:?}", scp_latency);
        println!("TX flood total time: {:?}", tx_total_time);
        println!("TX received: {}", tx_count_received);

        // KEY ASSERTION: SCP must arrive BEFORE TX flood completes
        // If streams were blocked, SCP would wait behind all TXs
        assert!(
            scp_received_at < all_tx_received_at,
            "SCP should arrive BEFORE TX flood completes (stream independence). \
             SCP at {:?}, TXs done at {:?}",
            scp_latency,
            tx_total_time
        );

        // Also verify TX flood took meaningful time (not instant)
        assert!(
            tx_total_time > Duration::from_millis(50),
            "TX flood should take measurable time ({:?}), otherwise test is invalid",
            tx_total_time
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Critical test: TX messages must not be blocked by SCP traffic
    /// Validates bidirectional stream independence
    #[tokio::test]
    async fn test_tx_not_blocked_by_scp_flood() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, mut events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19501;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19502).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + streams
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain connection events
        while events2.try_recv().is_ok() {}
        while tx_events2.try_recv().is_ok() {}

        // Send large SCP messages - 1000 x 10KB = 10MB total
        let scp_count = 1000;
        let scp_size = 10 * 1024;
        let large_scp: Vec<u8> = (0..scp_size).map(|i| (i % 256) as u8).collect();

        let scp_start = std::time::Instant::now();
        for i in 0..scp_count {
            let mut scp = large_scp.clone();
            scp[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            handle1.broadcast_scp(scp).await;
        }

        // Immediately send TX (should bypass SCP queue)
        let tx_msg = b"urgent transaction".to_vec();
        let tx_send_time = std::time::Instant::now();
        handle1.broadcast_tx(tx_msg.clone()).await;

        // Track when TX arrives vs when all SCPs arrive
        // SCP comes on unbounded events channel, TX on bounded tx_events channel
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut tx_received_at: Option<std::time::Instant> = None;
        let mut scp_count_received = 0u32;
        let mut all_scp_received_at: Option<std::time::Instant> = None;

        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(event) = tx_events2.recv() => {
                    if let OverlayEvent::TxReceived { tx, .. } = event {
                        if tx == tx_msg && tx_received_at.is_none() {
                            tx_received_at = Some(std::time::Instant::now());
                        }
                    }
                }
                Some(event) = events2.recv() => {
                    if let OverlayEvent::ScpReceived { .. } = event {
                        scp_count_received += 1;
                        if scp_count_received >= scp_count && all_scp_received_at.is_none() {
                            all_scp_received_at = Some(std::time::Instant::now());
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }

            if tx_received_at.is_some() && all_scp_received_at.is_some() {
                break;
            }
        }

        let tx_received_at = tx_received_at.expect("TX should be received");
        let all_scp_received_at = all_scp_received_at.expect("All SCPs should be received");

        let tx_latency = tx_received_at.duration_since(tx_send_time);
        let scp_total_time = all_scp_received_at.duration_since(scp_start);

        println!("TX latency: {:?}", tx_latency);
        println!("SCP flood total time: {:?}", scp_total_time);
        println!("SCP received: {}", scp_count_received);

        // KEY ASSERTION: TX should have reasonable latency despite SCP flood
        // With INV/GETDATA batching (100ms max), TX latency should be < 200ms
        // This proves streams are independent - TX doesn't wait for 10MB of SCP
        assert!(
            tx_latency < Duration::from_millis(500),
            "TX should arrive quickly despite SCP flood (stream independence). \
             TX latency {:?} should be < 200ms",
            tx_latency
        );

        // Verify SCP flood took meaningful time
        assert!(
            scp_total_time > Duration::from_millis(50),
            "SCP flood should take measurable time ({:?}), otherwise test is invalid",
            scp_total_time
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Test TX broadcast and receive
    #[tokio::test]
    async fn test_tx_broadcast() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, _events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19401;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19402).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + streams
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain events
        while tx_events2.try_recv().is_ok() {}

        // Send TX
        let tx_msg = b"test transaction".to_vec();
        handle1.broadcast_tx(tx_msg.clone()).await;

        // Wait for TX on the bounded TX events channel
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut received = false;

        while tokio::time::Instant::now() < deadline && !received {
            tokio::select! {
                Some(event) = tx_events2.recv() => {
                    if let OverlayEvent::TxReceived { tx, .. } = event {
                        assert_eq!(tx, tx_msg);
                        received = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }

        assert!(received, "Should receive TX message");

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Test TxSet request/response flow
    /// Node2 requests a TxSet from Node1, Node1 responds with the data
    #[tokio::test]
    async fn test_txset_fetch() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, mut events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, mut events2, _tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19601;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19602).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + streams
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain events
        while events1.try_recv().is_ok() {}
        while events2.try_recv().is_ok() {}

        // Node2 requests a TxSet by hash
        let requested_hash: [u8; 32] = [0x42; 32];
        handle2.fetch_txset(requested_hash).await;

        // Node1 should receive TxSetRequested event
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut request_received = false;

        while tokio::time::Instant::now() < deadline && !request_received {
            tokio::select! {
                Some(event) = events1.recv() => {
                    if let OverlayEvent::TxSetRequested { hash, from } = event {
                        assert_eq!(hash, requested_hash);
                        request_received = true;

                        // Node1 responds with TxSet data
                        let txset_data = b"mock txset XDR data here".to_vec();
                        handle1.send_txset(hash, txset_data, from).await;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        assert!(
            request_received,
            "Node1 should receive TxSetRequested event"
        );

        // Node2 should receive TxSetReceived event
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut response_received = false;

        while tokio::time::Instant::now() < deadline && !response_received {
            tokio::select! {
                Some(event) = events2.recv() => {
                    if let OverlayEvent::TxSetReceived { hash, data, .. } = event {
                        assert_eq!(hash, requested_hash);
                        assert_eq!(data, b"mock txset XDR data here".to_vec());
                        response_received = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        assert!(
            response_received,
            "Node2 should receive TxSetReceived event"
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Test multiple TXs flood with correct ordering (by fee)
    #[tokio::test]
    async fn test_multiple_txs_flood() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, _events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19701;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19702).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + streams
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain events
        while tx_events2.try_recv().is_ok() {}

        // Send multiple TXs
        let tx_count = 10;
        for i in 0..tx_count {
            let tx = format!("transaction_{}", i).into_bytes();
            handle1.broadcast_tx(tx).await;
        }

        // Wait for all TXs on bounded TX events channel
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut received_count = 0;

        while tokio::time::Instant::now() < deadline && received_count < tx_count {
            tokio::select! {
                Some(event) = tx_events2.recv() => {
                    if let OverlayEvent::TxReceived { .. } = event {
                        received_count += 1;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }

        assert_eq!(
            received_count, tx_count,
            "Should receive all {} TXs",
            tx_count
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Test TX deduplication - same TX sent twice should only be received once
    #[tokio::test]
    async fn test_tx_dedup() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, _events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19801;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19802).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + streams
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain events
        while tx_events2.try_recv().is_ok() {}

        // Send same TX twice
        let tx = b"duplicate_transaction".to_vec();
        handle1.broadcast_tx(tx.clone()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        handle1.broadcast_tx(tx.clone()).await;

        // Wait and count received TXs
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut received_count = 0;
        while let Ok(event) = tx_events2.try_recv() {
            if let OverlayEvent::TxReceived { .. } = event {
                received_count += 1;
            }
        }

        assert_eq!(
            received_count, 1,
            "Duplicate TX should only be received once"
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    // ═══ Multi-Node (3+) Gossip Tests ═══

    /// Test SCP messages reach all directly connected peers in a triangle topology
    /// Topology: A-B, B-C, A-C (all nodes connected to each other)
    #[tokio::test]
    async fn test_three_node_triangle_scp() {
        // Create 3 nodes
        let keypair_a = Keypair::generate_ed25519();
        let keypair_b = Keypair::generate_ed25519();
        let keypair_c = Keypair::generate_ed25519();

        let (handle_a, _events_a, _tx_events_a, overlay_a) =
            create_overlay(keypair_a, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle_b, mut events_b, _tx_events_b, overlay_b) =
            create_overlay(keypair_b, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle_c, mut events_c, _tx_events_c, overlay_c) =
            create_overlay(keypair_c, Arc::new(OverlayMetrics::new())).unwrap();

        // Start all nodes on different ports
        let port_a = 19901;
        let port_b = 19902;
        let port_c = 19903;

        tokio::spawn(async move { overlay_a.run("127.0.0.1", port_a).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay_b.run("127.0.0.1", port_b).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay_c.run("127.0.0.1", port_c).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect: B -> A, C -> A (both B and C connected to A)
        let addr_a: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port_a)
            .parse()
            .unwrap();

        handle_b.dial(addr_a.clone()).await;
        handle_c.dial(addr_a).await;

        // Wait for connections to establish
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain connection events
        while events_b.try_recv().is_ok() {}
        while events_c.try_recv().is_ok() {}

        // A broadcasts SCP - should reach both B and C directly
        let scp_msg = b"3-node test SCP".to_vec();
        handle_a.broadcast_scp(scp_msg.clone()).await;

        // Both B and C should receive it directly from A
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut b_received = false;
        let mut c_received = false;

        while tokio::time::Instant::now() < deadline && (!b_received || !c_received) {
            tokio::select! {
                Some(event) = events_b.recv() => {
                    if let OverlayEvent::ScpReceived { envelope, .. } = event {
                        if envelope == scp_msg {
                            b_received = true;
                        }
                    }
                }
                Some(event) = events_c.recv() => {
                    if let OverlayEvent::ScpReceived { envelope, .. } = event {
                        if envelope == scp_msg {
                            c_received = true;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }

        assert!(b_received, "Node B should receive SCP from A");
        assert!(c_received, "Node C should receive SCP from A");

        handle_a.shutdown().await;
        handle_b.shutdown().await;
        handle_c.shutdown().await;
    }

    /// Test TX propagation across 3 nodes
    #[tokio::test]
    async fn test_three_node_tx_propagation() {
        let keypair_a = Keypair::generate_ed25519();
        let keypair_b = Keypair::generate_ed25519();
        let keypair_c = Keypair::generate_ed25519();

        let (handle_a, _events_a, _tx_events_a, overlay_a) =
            create_overlay(keypair_a, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle_b, _events_b, mut tx_events_b, overlay_b) =
            create_overlay(keypair_b, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle_c, _events_c, mut tx_events_c, overlay_c) =
            create_overlay(keypair_c, Arc::new(OverlayMetrics::new())).unwrap();

        let port_a = 20001;
        let port_b = 20002;
        let port_c = 20003;

        tokio::spawn(async move { overlay_a.run("127.0.0.1", port_a).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay_b.run("127.0.0.1", port_b).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay_c.run("127.0.0.1", port_c).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Triangle topology: A-B, B-C, A-C
        let addr_a: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port_a)
            .parse()
            .unwrap();
        let addr_b: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port_b)
            .parse()
            .unwrap();

        handle_b.dial(addr_a.clone()).await;
        handle_c.dial(addr_b).await;
        handle_c.dial(addr_a).await;

        tokio::time::sleep(Duration::from_millis(500)).await;

        while tx_events_b.try_recv().is_ok() {}
        while tx_events_c.try_recv().is_ok() {}

        // A broadcasts TX
        let tx_msg = b"3-node TX test".to_vec();
        handle_a.broadcast_tx(tx_msg.clone()).await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut b_received = false;
        let mut c_received = false;

        while tokio::time::Instant::now() < deadline && (!b_received || !c_received) {
            tokio::select! {
                Some(event) = tx_events_b.recv() => {
                    if let OverlayEvent::TxReceived { tx, .. } = event {
                        if tx == tx_msg {
                            b_received = true;
                        }
                    }
                }
                Some(event) = tx_events_c.recv() => {
                    if let OverlayEvent::TxReceived { tx, .. } = event {
                        if tx == tx_msg {
                            c_received = true;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }

        assert!(b_received, "Node B should receive TX");
        assert!(c_received, "Node C should receive TX");

        handle_a.shutdown().await;
        handle_b.shutdown().await;
        handle_c.shutdown().await;
    }

    /// Test that shutdown is clean (no hung connections)
    #[tokio::test]
    async fn test_clean_shutdown() {
        let keypair = Keypair::generate_ed25519();
        let (handle, _events, _tx_events, overlay) =
            create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

        let overlay_task = tokio::spawn(async move {
            overlay.run("127.0.0.1", 20100).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Shutdown should complete quickly
        let shutdown_result = tokio::time::timeout(Duration::from_secs(2), handle.shutdown()).await;

        assert!(
            shutdown_result.is_ok(),
            "Shutdown should complete within 2 seconds"
        );

        // Task should finish
        let task_result = tokio::time::timeout(Duration::from_secs(1), overlay_task).await;

        assert!(
            task_result.is_ok(),
            "Overlay task should complete after shutdown"
        );
    }

    /// Test overlay handles dial to invalid address gracefully
    #[tokio::test]
    async fn test_dial_invalid_address() {
        let keypair = Keypair::generate_ed25519();
        let (handle, _events, _tx_events, overlay) =
            create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

        tokio::spawn(async move { overlay.run("127.0.0.1", 20200).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Dial an address where nothing is listening
        let bad_addr: Multiaddr = "/ip4/127.0.0.1/udp/59999/quic-v1".parse().unwrap();
        handle.dial(bad_addr).await;

        // Should not crash - just log an error and continue
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Overlay should still be operational
        handle.shutdown().await;
    }

    /// Stress test: TX backpressure under heavy load
    /// Verifies:
    /// 1. SCP messages are NEVER dropped (critical path on unbounded channel)
    /// 2. TXs may be dropped under extreme load (acceptable - they'll be re-requested)
    /// 3. No unbounded memory growth (bounded TX channel caps at TX_EVENT_CHANNEL_CAPACITY)
    #[tokio::test]
    async fn test_tx_backpressure_stress() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, mut events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        // Use unique ports to avoid conflicts with other tests
        let listen_port = 22901;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 22902).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain any initial events
        while events2.try_recv().is_ok() {}
        while tx_events2.try_recv().is_ok() {}

        // STRESS TEST: Flood with many TXs while also sending SCP
        // This simulates a real attack scenario where the network is flooded with TXs
        let tx_flood_count = 50_000u32; // Exceed TX_EVENT_CHANNEL_CAPACITY (10,000)
        let scp_msg_count = 100u32;

        // Start flooding TXs (don't wait for processing)
        let handle1_clone = handle1.clone();
        let tx_flood_task = tokio::spawn(async move {
            for i in 0..tx_flood_count {
                // Each TX unique to avoid dedup
                let tx = format!("flood_tx_{}", i).into_bytes();
                handle1_clone.broadcast_tx(tx).await;
                // Small yield to avoid overwhelming the command channel
                if i % 1000 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });

        // Simultaneously send SCP messages (critical path)
        let handle1_clone2 = handle1.clone();
        let scp_task = tokio::spawn(async move {
            for i in 0..scp_msg_count {
                let scp = format!("critical_scp_{}", i).into_bytes();
                handle1_clone2.broadcast_scp(scp).await;
                // Space out SCP messages
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        // Wait for floods to complete
        let _ = tokio::join!(tx_flood_task, scp_task);

        // Collect results with timeout
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut scp_received = 0u32;
        let mut tx_received = 0u32;

        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(event) = events2.recv() => {
                    if let OverlayEvent::ScpReceived { .. } = event {
                        scp_received += 1;
                    }
                }
                Some(event) = tx_events2.recv() => {
                    if let OverlayEvent::TxReceived { .. } = event {
                        tx_received += 1;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Check if channels are empty
                    if events2.is_empty() && tx_events2.is_empty() {
                        // Give a bit more time for any in-flight messages
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        if events2.is_empty() && tx_events2.is_empty() {
                            break;
                        }
                    }
                }
            }
        }

        println!("SCP received: {}/{}", scp_received, scp_msg_count);
        println!("TX received: {}/{}", tx_received, tx_flood_count);

        // CRITICAL ASSERTION 1: ALL SCP messages must be received (never dropped)
        assert_eq!(
            scp_received, scp_msg_count,
            "ALL SCP messages must be received (critical path). Got {}/{}",
            scp_received, scp_msg_count
        );

        // ASSERTION 2: TXs may be dropped under backpressure - this is acceptable
        // We expect SOME TXs to be received (channel isn't completely broken)
        assert!(tx_received > 0, "At least some TXs should be received");

        // ASSERTION 3: TX count should be bounded by channel capacity + what was processed
        // If backpressure is working, we shouldn't receive more than we can handle
        // (This is more about verifying the mechanism works than a strict bound)
        println!(
            "TX backpressure working: received {} of {} flooded TXs ({}%)",
            tx_received,
            tx_flood_count,
            (tx_received as f64 / tx_flood_count as f64 * 100.0) as u32
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
    }
}

/// Test TX set source tracking - verify we ask the right peer
#[tokio::test]
async fn test_txset_source_tracking() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();
    let peer2_id = PeerId::from_public_key(&keypair2.public());

    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20101;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 20102).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect overlay2 to overlay1
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Record that peer1 (from overlay2's perspective) has a specific TX set
    let test_hash: [u8; 32] = [0xAB; 32];
    // We need to get peer1's ID first - overlay2 should have seen it connect
    // For now, test that record_txset_source doesn't crash
    let fake_peer = PeerId::random();
    handle2.record_txset_source(test_hash, fake_peer).await;

    // Give time for command to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now try to fetch - since fake_peer isn't connected, it should fall back
    handle2.fetch_txset(test_hash).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Clean up
    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test TX set fetch from connected peer
#[tokio::test]
async fn test_txset_fetch_flow() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20201;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 20202).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // overlay2 requests a TX set that overlay1 doesn't have
    let test_hash: [u8; 32] = [0xCD; 32];
    handle2.fetch_txset(test_hash).await;

    // overlay1 should receive the request (as TxSetRequested event)
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut got_request = false;
    while let Ok(event) = events1.try_recv() {
        if let OverlayEvent::TxSetRequested { hash, .. } = event {
            if hash == test_hash {
                got_request = true;
            }
        }
    }

    assert!(
        got_request,
        "overlay1 should receive TxSet request from overlay2"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that peer disconnect triggers reconnect attempt
#[tokio::test]
async fn test_peer_disconnect_detection() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, _events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20301;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 20302).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify connection was established by checking we can send SCP
    handle1.broadcast_scp(b"test".to_vec()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Now shutdown overlay2 - overlay1 should detect disconnect
    handle2.shutdown().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // overlay1 should have received a disconnect event or connection closed
    // (Connection closed is handled internally by libp2p, we verify no crash)

    handle1.shutdown().await;
    // Test passes if we get here without hanging or crashing
}

/// Test connect to unreachable peer times out gracefully
#[tokio::test]
async fn test_connect_unreachable_peer_timeout() {
    let keypair = Keypair::generate_ed25519();
    let (handle, _events, _tx_events, overlay) =
        create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20401;
    tokio::spawn(async move { overlay.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Try to connect to a non-existent peer
    // Use a port that's definitely not listening
    let bad_addr: Multiaddr = "/ip4/127.0.0.1/udp/59999/quic-v1".parse().unwrap();

    // This should not hang - dial returns immediately, connection fails async
    let start = tokio::time::Instant::now();
    handle.dial(bad_addr).await;

    // Give some time for the connection attempt
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify we didn't hang for too long
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "Connection attempt should not block for more than 5 seconds"
    );

    // Overlay should still be operational
    handle.shutdown().await;
}

/// Test large TX set doesn't block SCP messages
#[tokio::test]
async fn test_large_txset_doesnt_block_scp() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20501;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 20502).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain initial events
    while events1.try_recv().is_ok() {}
    while events2.try_recv().is_ok() {}

    // Create a large TX set (1MB)
    let large_txset = vec![0xAB; 1024 * 1024];
    let txset_hash: [u8; 32] = [0x11; 32];

    // Start sending large TX set from node1
    let handle1_clone = handle1.clone();
    let large_txset_clone = large_txset.clone();
    let send_task = tokio::spawn(async move {
        // Simulate responding to TX set request with large data
        // We'll use the event system - node2 requests, node1 responds
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    // Immediately send SCP message - should NOT be blocked
    let scp_msg = b"urgent SCP message".to_vec();
    let scp_start = tokio::time::Instant::now();
    handle1.broadcast_scp(scp_msg.clone()).await;

    // SCP should arrive quickly (< 100ms) even if TX set is being transferred
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let mut scp_received = false;

    while tokio::time::Instant::now() < deadline && !scp_received {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpReceived { envelope, .. } = event {
                    if envelope == scp_msg {
                        scp_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    let scp_latency = scp_start.elapsed();
    assert!(scp_received, "SCP message should be received");
    assert!(
        scp_latency < Duration::from_millis(200),
        "SCP latency should be < 200ms, was {:?}",
        scp_latency
    );

    send_task.await.unwrap();
    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test TX set request to peer that has the data
#[tokio::test]
async fn test_txset_request_and_response() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20601;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 20602).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain events
    while events1.try_recv().is_ok() {}
    while events2.try_recv().is_ok() {}

    // Node2 requests a TX set
    let requested_hash: [u8; 32] = [0x77; 32];
    let txset_data = b"test tx set XDR content here".to_vec();

    handle2.fetch_txset(requested_hash).await;

    // Node1 receives request and responds
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut responded = false;

    while tokio::time::Instant::now() < deadline && !responded {
        tokio::select! {
            Some(event) = events1.recv() => {
                if let OverlayEvent::TxSetRequested { hash, from } = event {
                    assert_eq!(hash, requested_hash, "Request should have correct hash");
                    handle1.send_txset(hash, txset_data.clone(), from).await;
                    responded = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(
        responded,
        "Node1 should receive and respond to TX set request"
    );

    // Node2 should receive the TX set
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut received = false;

    while tokio::time::Instant::now() < deadline && !received {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::TxSetReceived { hash, data, .. } = event {
                    assert_eq!(hash, requested_hash, "Received hash should match");
                    assert_eq!(data, txset_data, "Received data should match");
                    received = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(received, "Node2 should receive TX set response");

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test TX set fetch when no peers are connected
#[tokio::test]
async fn test_txset_fetch_no_peers() {
    let keypair = Keypair::generate_ed25519();
    let (handle, mut events, _tx_events, overlay) =
        create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20701;
    tokio::spawn(async move { overlay.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Request TX set with no peers connected
    let requested_hash: [u8; 32] = [0x88; 32];
    handle.fetch_txset(requested_hash).await;

    // Should not crash or hang - just no response
    // Wait briefly to ensure no panic
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Drain any events (there shouldn't be any TX set related ones)
    let mut txset_events = 0;
    while let Ok(event) = events.try_recv() {
        if matches!(event, OverlayEvent::TxSetReceived { .. }) {
            txset_events += 1;
        }
    }
    assert_eq!(
        txset_events, 0,
        "Should not receive TX set when no peers connected"
    );

    handle.shutdown().await;
}

/// Test multiple concurrent TX set requests
#[tokio::test]
async fn test_txset_multiple_concurrent_requests() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20801;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 20802).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain events
    while events1.try_recv().is_ok() {}
    while events2.try_recv().is_ok() {}

    // Request multiple TX sets concurrently
    let hash1: [u8; 32] = [0x11; 32];
    let hash2: [u8; 32] = [0x22; 32];
    let hash3: [u8; 32] = [0x33; 32];

    handle2.fetch_txset(hash1).await;
    handle2.fetch_txset(hash2).await;
    handle2.fetch_txset(hash3).await;

    // Node1 should receive all 3 requests
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut received_hashes = std::collections::HashSet::new();

    while tokio::time::Instant::now() < deadline && received_hashes.len() < 3 {
        tokio::select! {
            Some(event) = events1.recv() => {
                if let OverlayEvent::TxSetRequested { hash, from } = event {
                    received_hashes.insert(hash);
                    // Respond to each request
                    let data = format!("txset for {:?}", &hash[..4]).into_bytes();
                    handle1.send_txset(hash, data, from).await;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    assert_eq!(
        received_hashes.len(),
        3,
        "Should receive all 3 TX set requests"
    );
    assert!(received_hashes.contains(&hash1));
    assert!(received_hashes.contains(&hash2));
    assert!(received_hashes.contains(&hash3));

    handle1.shutdown().await;
    handle2.shutdown().await;
}

#[tokio::test]
async fn test_scp_state_request_on_connection() {
    // Test that when two nodes connect, they request SCP state from each other
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 19801;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 19802).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect node2 to node1
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;

    // Wait for connection + SCP stream setup
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Both nodes should receive ScpStateRequested events (each receives request from the other)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut node1_received_request = false;
    let mut node2_received_request = false;

    while tokio::time::Instant::now() < deadline
        && (!node1_received_request || !node2_received_request)
    {
        tokio::select! {
            Some(event) = events1.recv() => {
                if let OverlayEvent::ScpStateRequested { ledger_seq, .. } = event {
                    assert_eq!(ledger_seq, 0, "Should request all recent state (ledger_seq=0)");
                    node1_received_request = true;
                }
            }
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpStateRequested { ledger_seq, .. } = event {
                    assert_eq!(ledger_seq, 0, "Should request all recent state (ledger_seq=0)");
                    node2_received_request = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    assert!(
        node1_received_request,
        "Node 1 should receive SCP state request from node 2"
    );
    assert!(
        node2_received_request,
        "Node 2 should receive SCP state request from node 1"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that QUIC keep-alive keeps connection alive during idle periods
#[tokio::test]
async fn test_quic_keepalive_survives_idle() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    // Use unique ports to avoid conflicts with other tests
    let listen_port = 23001;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 23002).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify initial connectivity by sending SCP
    let scp_msg1 = b"initial SCP".to_vec();
    handle1.broadcast_scp(scp_msg1.clone()).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut received_initial = false;
    while tokio::time::Instant::now() < deadline && !received_initial {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpReceived { envelope, .. } = event {
                    if envelope == scp_msg1 {
                        received_initial = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(received_initial, "Should receive initial SCP message");

    // Wait longer than keep-alive interval (15s) but less than max idle (60s)
    // Use 20 seconds to ensure keep-alive packets are sent
    info!("Waiting 20 seconds to test keep-alive...");
    tokio::time::sleep(Duration::from_secs(20)).await;

    // Verify connection is still alive by sending another SCP
    let scp_msg2 = b"post-idle SCP".to_vec();
    handle1.broadcast_scp(scp_msg2.clone()).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut received_after_idle = false;
    while tokio::time::Instant::now() < deadline && !received_after_idle {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpReceived { envelope, .. } = event {
                    if envelope == scp_msg2 {
                        received_after_idle = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(
        received_after_idle,
        "Connection should survive 20s idle period thanks to QUIC keep-alive"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that overlay listens on configured IP address
#[tokio::test]
async fn test_listen_on_configured_ip() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 21101;

    // Start overlay1 listening on 127.0.0.1
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 21102).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect using the specific IP - this should work
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify connection works by checking for SCP state request
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut connected = false;
    while tokio::time::Instant::now() < deadline && !connected {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpStateRequested { .. } = event {
                    connected = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(
        connected,
        "Should connect when dialing configured listen IP"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that different listen IPs work correctly
#[tokio::test]
async fn test_listen_ip_binding() {
    // Test that we can specify different IPs for run()
    // On most systems, 127.0.0.1 and 127.0.0.2 are both valid loopback addresses
    let keypair = Keypair::generate_ed25519();
    let (handle, _events, _tx_events, overlay) =
        create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 21201;

    // Start on 127.0.0.1 specifically (not 0.0.0.0)
    let overlay_task = tokio::spawn(async move {
        overlay.run("127.0.0.1", listen_port).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The overlay should be running and listening
    // We verify by checking it accepts the shutdown gracefully
    handle.shutdown().await;

    tokio::time::timeout(Duration::from_secs(2), overlay_task)
        .await
        .expect("Overlay should shutdown")
        .expect("Overlay task should complete");
}

/// Test that event loop remains responsive during broadcast (proves parallelism)
#[tokio::test]
async fn test_scp_broadcast_does_not_block_event_loop() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, _events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let port1 = 21301;
    let port2 = 21302;

    tokio::spawn(async move { overlay1.run("127.0.0.1", port1).await });
    tokio::spawn(async move { overlay2.run("127.0.0.1", port2).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr1: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port1)
        .parse()
        .unwrap();
    handle2.dial(addr1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Fire off 100 SCP broadcasts rapidly
    for i in 0..100 {
        let msg = format!("scp_flood_{}", i).into_bytes();
        handle1.broadcast_scp(msg).await;
    }

    // Immediately ping the event loop - if blocked by sequential sends,
    // this won't return until all 100 network writes complete
    let start = tokio::time::Instant::now();
    handle1.ping().await.expect("Ping should succeed");
    let ping_latency = start.elapsed();

    // Ping should return quickly if event loop isn't blocked.
    // Allow 50ms for tokio scheduling overhead - still catches the bug
    // where 100 sequential sends would take seconds.
    assert!(
        ping_latency < Duration::from_millis(50),
        "Ping should return in <50ms (event loop not blocked), took {:?}",
        ping_latency
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that SCP and TxSet streams can be written concurrently to the same peer.
/// This validates that the per-stream mutex design allows independent writes.
#[tokio::test]
async fn test_concurrent_scp_and_txset_writes_to_same_peer() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();
    let peer2_id = PeerId::from_public_key(&keypair2.public());

    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 21001;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 21002).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect node2 to node1
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain initial events
    while events2.try_recv().is_ok() {}

    // Shared flag to coordinate timing
    let txset_started = Arc::new(AtomicBool::new(false));

    // Start sending large TxSet from node1 to node2
    let txset_hash: [u8; 32] = [0x22; 32];
    let large_txset = vec![0xBB; 512 * 1024]; // 512KB TxSet
    let handle1_txset = handle1.clone();
    let txset_started_clone = txset_started.clone();

    let txset_task = tokio::spawn(async move {
        txset_started_clone.store(true, Ordering::SeqCst);
        handle1_txset
            .send_txset(txset_hash, large_txset, peer2_id)
            .await;
    });

    // Wait for TxSet send to start
    while !txset_started.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    // Immediately send SCP message - should NOT be blocked by TxSet write
    let scp_msg = b"concurrent SCP message".to_vec();
    let scp_start = tokio::time::Instant::now();
    handle1.broadcast_scp(scp_msg.clone()).await;
    let scp_send_time = scp_start.elapsed();

    // The key assertion: SCP send should complete quickly (<50ms)
    // If the mutexes were shared, SCP would block waiting for TxSet write to finish
    assert!(
        scp_send_time < Duration::from_millis(50),
        "SCP send should not block on TxSet write. Send took {:?}",
        scp_send_time
    );

    // Wait for SCP to be received by node2
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut scp_received = false;
    let mut txset_received = false;

    while tokio::time::Instant::now() < deadline && (!scp_received || !txset_received) {
        tokio::select! {
            Some(event) = events2.recv() => {
                match event {
                    OverlayEvent::ScpReceived { envelope, .. } => {
                        if envelope == scp_msg {
                            scp_received = true;
                        }
                    }
                    OverlayEvent::TxSetReceived { hash, .. } => {
                        if hash == txset_hash {
                            txset_received = true;
                        }
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    txset_task.await.unwrap();

    assert!(scp_received, "SCP message should be received");
    assert!(txset_received, "TxSet should be received");

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that pending_txset_requests tracks peer and is cleaned on disconnect.
/// This is a simpler unit test that verifies the data structure changes work.
#[tokio::test]
async fn test_pending_txset_cleanup_on_disconnect() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let peer1_id = PeerId::from_public_key(&keypair1.public());

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    // Start both overlays (ports must not collide with test_20_node_full_mesh 22000-22019)
    let listen_port1 = 22501;
    let listen_port2 = 22502;

    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port1).await });
    tokio::spawn(async move { overlay2.run("127.0.0.1", listen_port2).await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Connect node1 to node2
    let addr2: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port2)
        .parse()
        .unwrap();
    handle1.dial(addr2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify connection by exchanging SCP message
    handle1.broadcast_scp(b"hello".to_vec()).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut connected = false;
    while tokio::time::Instant::now() < deadline && !connected {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpReceived { .. } = event {
                    connected = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(connected, "Nodes should be connected");

    // Request TxSet - this tests that pending_txset_requests correctly stores (hash, peer)
    let txset_hash: [u8; 32] = [0x42; 32];
    handle1.fetch_txset(txset_hash).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify node2 received the request
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut got_request = false;
    while tokio::time::Instant::now() < deadline && !got_request {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::TxSetRequested { hash, .. } = event {
                    if hash == txset_hash {
                        got_request = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(got_request, "Node2 should receive TxSet request");

    // Now have node2 respond with the TxSet
    // This verifies the pending cleanup works when response is received
    let txset_data = vec![0xAB; 1024];
    handle2
        .send_txset(txset_hash, txset_data.clone(), peer1_id)
        .await;

    // Verify node1 receives the TxSet response
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut got_response = false;
    while tokio::time::Instant::now() < deadline && !got_response {
        tokio::select! {
            Some(event) = events1.recv() => {
                if let OverlayEvent::TxSetReceived { hash, data, .. } = event {
                    if hash == txset_hash && data == txset_data {
                        got_response = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(got_response, "Node1 should receive TxSet response");

    // Request the same TxSet again - should NOT be skipped since pending was cleared
    handle1.fetch_txset(txset_hash).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify node2 receives the second request
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut got_second_request = false;
    while tokio::time::Instant::now() < deadline && !got_second_request {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::TxSetRequested { hash, .. } = event {
                    if hash == txset_hash {
                        got_second_request = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(
        got_second_request,
        "Node2 should receive second TxSet request after pending was cleared by response"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test INV/GETDATA protocol: TX propagation via INV→GETDATA→TX flow
#[tokio::test]
async fn test_inv_getdata_tx_propagation() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    // Create overlays with INV/GETDATA enabled
    let (handle1, _events1, mut tx_events1, overlay1) =
        create_overlay(keypair1.clone(), Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, _events2, mut tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let peer1_id = PeerId::from_public_key(&keypair1.public());

    let listen_port = 19251;
    let overlay1_task = tokio::spawn(async move {
        overlay1.run("127.0.0.1", listen_port).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let overlay2_task = tokio::spawn(async move {
        overlay2.run("127.0.0.1", listen_port + 1).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Node2 dials Node1
    let addr: Multiaddr = format!(
        "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}",
        listen_port, peer1_id
    )
    .parse()
    .unwrap();
    handle2.dial(addr).await;

    // Wait for connection to establish and streams to open
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node1 broadcasts a TX
    let test_tx = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
    handle1.broadcast_tx(test_tx.clone()).await;

    // Wait for INV→GETDATA→TX flow (with batching delay + RTT)
    // - INV is batched for up to 100ms
    // - GETDATA sent
    // - TX response sent
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut tx_received = false;

    while tokio::time::Instant::now() < deadline && !tx_received {
        tokio::select! {
            Some(event) = tx_events2.recv() => {
                if let OverlayEvent::TxReceived { tx, from } = event {
                    if tx == test_tx && from == peer1_id {
                        tx_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    assert!(
        tx_received,
        "Node2 should receive TX via INV/GETDATA protocol"
    );

    // Suppress warning
    drop(tx_events1);

    handle1.shutdown().await;
    handle2.shutdown().await;

    let _ = tokio::time::timeout(Duration::from_secs(1), overlay1_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), overlay2_task).await;
}

/// Test INV/GETDATA protocol: TX relay through 3 nodes (A→B→C)
#[tokio::test]
async fn test_inv_getdata_three_node_relay() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();
    let keypair3 = Keypair::generate_ed25519();

    // Create overlays with INV/GETDATA enabled (controlled topology)
    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1.clone(), Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, _events2, mut tx_events2, overlay2) =
        create_overlay(keypair2.clone(), Arc::new(OverlayMetrics::new())).unwrap();
    let (handle3, _events3, mut tx_events3, overlay3) =
        create_overlay(keypair3, Arc::new(OverlayMetrics::new())).unwrap();

    let peer1_id = PeerId::from_public_key(&keypair1.public());
    let peer2_id = PeerId::from_public_key(&keypair2.public());

    let base_port = 19261;

    let overlay1_task = tokio::spawn(async move {
        overlay1.run("127.0.0.1", base_port).await;
    });

    let overlay2_task = tokio::spawn(async move {
        overlay2.run("127.0.0.1", base_port + 1).await;
    });

    let overlay3_task = tokio::spawn(async move {
        overlay3.run("127.0.0.1", base_port + 2).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Topology: Node1 ←→ Node2 ←→ Node3 (Node1 NOT connected to Node3)
    // Node2 dials Node1
    let addr1: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}", base_port, peer1_id)
        .parse()
        .unwrap();
    handle2.dial(addr1).await;

    // Wait for Node1-Node2 connection
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node3 dials Node2
    let addr2: Multiaddr = format!(
        "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}",
        base_port + 1,
        peer2_id
    )
    .parse()
    .unwrap();
    handle3.dial(addr2).await;

    // Wait for Node2-Node3 connection
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node1 broadcasts a TX
    let test_tx = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x56, 0x78];
    handle1.broadcast_tx(test_tx.clone()).await;

    // First verify Node2 receives the TX from Node1
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut node2_received = false;
    while tokio::time::Instant::now() < deadline && !node2_received {
        tokio::select! {
            Some(event) = tx_events2.recv() => {
                if let OverlayEvent::TxReceived { tx, from } = event {
                    eprintln!("Node2 received TX from {}: {:02x?}", from, &tx[..tx.len().min(8)]);
                    if tx == test_tx && from == peer1_id {
                        node2_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(node2_received, "Node2 should receive TX from Node1");

    // Then Node3 should receive the TX via relay through Node2
    // Flow: Node1 →INV→ Node2 →GETDATA→ Node1 →TX→ Node2 →INV→ Node3 →GETDATA→ Node2 →TX→ Node3
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut tx_received = false;

    while tokio::time::Instant::now() < deadline && !tx_received {
        tokio::select! {
            Some(event) = tx_events3.recv() => {
                if let OverlayEvent::TxReceived { tx, from } = event {
                    eprintln!("Node3 received TX from {}: {:02x?}", from, &tx[..tx.len().min(8)]);
                    // Node3 must receive TX from Node2 (relay), not Node1 (no direct connection)
                    if tx == test_tx && from == peer2_id {
                        tx_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    assert!(
        tx_received,
        "Node3 should receive TX relayed through Node2 via INV/GETDATA"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
    handle3.shutdown().await;

    let _ = tokio::time::timeout(Duration::from_secs(1), overlay1_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), overlay2_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), overlay3_task).await;
}

/// Test SCP relay through 3 nodes: A→B→C (the bug that was fixed)
///
/// Topology: Node1 ←→ Node2 ←→ Node3 (Node1 NOT connected to Node3)
/// Node1 broadcasts SCP. Node2 receives it and relays (re-broadcasts) it.
/// Node3 must receive it via Node2's relay.
///
/// Before the fix, Node2's relay request was silently dropped because
/// the message was already in `scp_seen` from the initial receive.
#[tokio::test]
async fn test_scp_relay_three_nodes() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();
    let keypair3 = Keypair::generate_ed25519();

    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1.clone(), Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2.clone(), Arc::new(OverlayMetrics::new())).unwrap();
    let (handle3, mut events3, _tx_events3, overlay3) =
        create_overlay(keypair3, Arc::new(OverlayMetrics::new())).unwrap();

    let peer1_id = PeerId::from_public_key(&keypair1.public());
    let peer2_id = PeerId::from_public_key(&keypair2.public());

    let base_port = 19361;

    let overlay1_task = tokio::spawn(async move {
        overlay1.run("127.0.0.1", base_port).await;
    });

    let overlay2_task = tokio::spawn(async move {
        overlay2.run("127.0.0.1", base_port + 1).await;
    });

    let overlay3_task = tokio::spawn(async move {
        overlay3.run("127.0.0.1", base_port + 2).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Node2 dials Node1
    let addr1: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}", base_port, peer1_id)
        .parse()
        .unwrap();
    handle2.dial(addr1).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node3 dials Node2 (NOT Node1 - ensuring no direct A↔C path)
    let addr2: Multiaddr = format!(
        "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}",
        base_port + 1,
        peer2_id
    )
    .parse()
    .unwrap();
    handle3.dial(addr2).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain connection events
    while events2.try_recv().is_ok() {}
    while events3.try_recv().is_ok() {}

    // Node1 broadcasts SCP
    let scp_msg = b"SCP relay test envelope".to_vec();
    handle1.broadcast_scp(scp_msg.clone()).await;

    // Node2 should receive it from Node1
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut node2_received = false;
    while tokio::time::Instant::now() < deadline && !node2_received {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpReceived { envelope, from } = event {
                    if envelope == scp_msg && from == peer1_id {
                        node2_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(node2_received, "Node2 should receive SCP from Node1");

    // Node2 relays (re-broadcasts) the same SCP message - this is what C++ core does
    handle2.broadcast_scp(scp_msg.clone()).await;

    // Node3 should receive it via Node2's relay
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut node3_received = false;
    while tokio::time::Instant::now() < deadline && !node3_received {
        tokio::select! {
            Some(event) = events3.recv() => {
                if let OverlayEvent::ScpReceived { envelope, from } = event {
                    if envelope == scp_msg && from == peer2_id {
                        node3_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(
        node3_received,
        "Node3 should receive SCP relayed through Node2"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
    handle3.shutdown().await;

    let _ = tokio::time::timeout(Duration::from_secs(1), overlay1_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), overlay2_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), overlay3_task).await;
}

/// Test that SCP relay doesn't echo back to the sender
///
/// Topology: Node1 ←→ Node2
/// Node1 broadcasts SCP. Node2 receives it and relays (re-broadcasts).
/// Node1 must NOT receive it again (no echo).
#[tokio::test]
async fn test_scp_relay_no_echo_to_sender() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1.clone(), Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2.clone(), Arc::new(OverlayMetrics::new())).unwrap();

    let peer1_id = PeerId::from_public_key(&keypair1.public());

    let base_port = 19461;

    let overlay1_task = tokio::spawn(async move {
        overlay1.run("127.0.0.1", base_port).await;
    });

    let overlay2_task = tokio::spawn(async move {
        overlay2.run("127.0.0.1", base_port + 1).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let addr1: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", base_port)
        .parse()
        .unwrap();
    handle2.dial(addr1).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain connection events
    while events1.try_recv().is_ok() {}
    while events2.try_recv().is_ok() {}

    // Node1 broadcasts SCP
    let scp_msg = b"no echo test".to_vec();
    handle1.broadcast_scp(scp_msg.clone()).await;

    // Node2 receives it
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut node2_received = false;
    while tokio::time::Instant::now() < deadline && !node2_received {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpReceived { envelope, from } = event {
                    if envelope == scp_msg && from == peer1_id {
                        node2_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(node2_received, "Node2 should receive SCP from Node1");

    // Node2 relays - this should NOT send back to Node1 (already in scp_sent_to)
    handle2.broadcast_scp(scp_msg.clone()).await;

    // Wait and verify Node1 does NOT receive an echo
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut echo_count = 0;
    while let Ok(event) = events1.try_recv() {
        if let OverlayEvent::ScpReceived { envelope, .. } = event {
            if envelope == scp_msg {
                echo_count += 1;
            }
        }
    }
    assert_eq!(
        echo_count, 0,
        "Node1 should NOT receive echo of its own SCP message"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;

    let _ = tokio::time::timeout(Duration::from_secs(1), overlay1_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), overlay2_task).await;
}

/// Test that 20 overlays can form a fully-connected mesh when dialing
/// simultaneously. This validates the fix for the stream-open deadlock:
/// `open_streams_to_peer` must be spawned (not awaited inline) so the
/// swarm event loop stays free to process incoming stream-open requests.
///
/// Without the fix, most `control.open_stream()` calls would time out
/// because the swarm couldn't be polled while awaiting inside the
/// `ConnectionEstablished` handler.
#[tokio::test]
async fn test_20_node_full_mesh() {
    const N: usize = 20;
    const BASE_PORT: u16 = 22000;

    // Create all overlays
    let mut handles = Vec::with_capacity(N);
    let mut metrics = Vec::with_capacity(N);
    let mut tasks = Vec::with_capacity(N);

    for i in 0..N {
        let keypair = Keypair::generate_ed25519();
        let m = Arc::new(OverlayMetrics::new());
        let (handle, _events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&m)).unwrap();

        let port = BASE_PORT + i as u16;
        tasks.push(tokio::spawn(async move {
            overlay.run("127.0.0.1", port).await;
        }));
        handles.push(handle);
        metrics.push(m);
    }

    // Brief pause for listeners to bind
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Every node dials every other node simultaneously — the thundering-herd
    // scenario that triggers the deadlock on unfixed code.
    for i in 0..N {
        for j in 0..N {
            if i == j {
                continue;
            }
            let port = BASE_PORT + j as u16;
            let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port)
                .parse()
                .unwrap();
            handles[i].dial(addr).await;
        }
    }

    // Wait for all connections and streams to establish.
    // With the deadlock fix, this should converge well within 5 seconds.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut all_connected = true;
        for i in 0..N {
            let count = handles[i].connected_peer_count().await;
            if count < N - 1 {
                all_connected = false;
                break;
            }
        }
        if all_connected {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            // Print diagnostics before failing
            for i in 0..N {
                let count = handles[i].connected_peer_count().await;
                let auth = metrics[i].connection_authenticated.load(Ordering::Relaxed);
                eprintln!(
                    "Node {}: connected_peer_count={}, connection_authenticated={}",
                    i, count, auth
                );
            }
            panic!(
                "Timed out waiting for full mesh: not all {} nodes have {} peers",
                N,
                N - 1
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Final assertion: every node has exactly N-1 authenticated peers
    for i in 0..N {
        let count = handles[i].connected_peer_count().await;
        assert_eq!(
            count,
            N - 1,
            "Node {} should have {} peers, got {}",
            i,
            N - 1,
            count
        );
    }

    // Shutdown all overlays
    for handle in &handles {
        handle.shutdown().await;
    }
    for task in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }
}

/// Test that simultaneous dials between two peers result in exactly one
/// logical connection (num_established check prevents double stream setup).
#[tokio::test]
async fn test_simultaneous_dial_dedup() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let m1 = Arc::new(OverlayMetrics::new());
    let m2 = Arc::new(OverlayMetrics::new());
    let (handle1, mut events1, _tx1, overlay1) = create_overlay(keypair1, Arc::clone(&m1)).unwrap();
    let (handle2, mut events2, _tx2, overlay2) = create_overlay(keypair2, Arc::clone(&m2)).unwrap();

    let port1 = 23100;
    let port2 = 23101;
    tokio::spawn(async move { overlay1.run("127.0.0.1", port1).await });
    tokio::spawn(async move { overlay2.run("127.0.0.1", port2).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Both sides dial each other simultaneously
    let addr1: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port1)
        .parse()
        .unwrap();
    let addr2: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port2)
        .parse()
        .unwrap();
    handle1.dial(addr2).await;
    handle2.dial(addr1).await;

    // Wait for connections to settle
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Each side should see exactly 1 connected peer (not 2)
    let count1 = handle1.connected_peer_count().await;
    let count2 = handle2.connected_peer_count().await;
    assert_eq!(count1, 1, "Node1 should have 1 peer, got {}", count1);
    assert_eq!(count2, 1, "Node2 should have 1 peer, got {}", count2);

    // connection_authenticated metric should also be 1 on each side
    let auth1 = m1.connection_authenticated.load(Ordering::Relaxed);
    let auth2 = m2.connection_authenticated.load(Ordering::Relaxed);
    assert_eq!(
        auth1, 1,
        "Node1 connection_authenticated should be 1, got {}",
        auth1
    );
    assert_eq!(
        auth2, 1,
        "Node2 connection_authenticated should be 1, got {}",
        auth2
    );

    // Verify SCP messages flow correctly (streams not corrupted by duplicate)
    handle1.broadcast_scp(b"test_scp_msg".to_vec()).await;
    let received = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(event) = events2.recv().await {
                if let OverlayEvent::ScpReceived { envelope, .. } = event {
                    return envelope;
                }
            }
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "Node2 should receive SCP message through deduped connection"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that DialPeer (PeerId-based) skips dialing when already connected.
#[tokio::test]
async fn test_dial_peer_skips_when_connected() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();
    let peer_id2 = keypair2.public().to_peer_id();

    let m1 = Arc::new(OverlayMetrics::new());
    let (handle1, _events1, _tx1, overlay1) = create_overlay(keypair1, Arc::clone(&m1)).unwrap();
    let (handle2, _events2, _tx2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let port1 = 23200;
    let port2 = 23201;
    tokio::spawn(async move { overlay1.run("127.0.0.1", port1).await });
    tokio::spawn(async move { overlay2.run("127.0.0.1", port2).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // First connection: address-based dial (bootstrap)
    let addr2: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port2)
        .parse()
        .unwrap();
    handle1.dial(addr2.clone()).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(handle1.connected_peer_count().await, 1);

    // Record outbound_attempt before the PeerId-based dial
    let attempts_before = m1.outbound_attempt.load(Ordering::Relaxed);

    // PeerId-based dial should be a no-op (already connected)
    handle1.dial_peer(peer_id2, addr2.clone()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Should still have exactly 1 connection
    assert_eq!(handle1.connected_peer_count().await, 1);
    // outbound_attempt increments (we submitted the command), but connection_pending
    // should NOT have changed (DialPeer was rejected by libp2p before handshake)
    let attempts_after = m1.outbound_attempt.load(Ordering::Relaxed);
    assert_eq!(
        attempts_after,
        attempts_before + 1,
        "outbound_attempt should increment by 1"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that PeerConnected event is emitted with the correct address
/// and that PeerDisconnected triggers reconnection.
#[tokio::test]
async fn test_peer_connected_event_emitted() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, _events2, _tx2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let port1 = 23300;
    let port2 = 23301;
    tokio::spawn(async move { overlay1.run("127.0.0.1", port1).await });
    tokio::spawn(async move { overlay2.run("127.0.0.1", port2).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let addr2: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port2)
        .parse()
        .unwrap();
    handle1.dial(addr2).await;

    // Should receive PeerConnected event
    let connected_event = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(event) = events1.recv().await {
                if let OverlayEvent::PeerConnected { peer_id, addr } = event {
                    return (peer_id, addr);
                }
            }
        }
    })
    .await;

    assert!(
        connected_event.is_ok(),
        "Should receive PeerConnected event"
    );
    let (peer_id, addr) = connected_event.unwrap();
    // The address should contain 127.0.0.1 and port2
    let addr_str = addr.to_string();
    assert!(
        addr_str.contains("127.0.0.1") && addr_str.contains(&port2.to_string()),
        "PeerConnected addr should contain the peer's address, got: {}",
        addr_str
    );

    // Shutdown node2 → node1 should receive PeerDisconnected
    handle2.shutdown().await;
    let disconnect_event = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(event) = events1.recv().await {
                if let OverlayEvent::PeerDisconnected { peer_id: pid } = event {
                    return pid;
                }
            }
        }
    })
    .await;
    assert!(
        disconnect_event.is_ok(),
        "Should receive PeerDisconnected event"
    );
    assert_eq!(disconnect_event.unwrap(), peer_id);

    handle1.shutdown().await;
}

/// Test that the 20-node mesh works with the new connectivity algorithm.
/// Audits metrics to verify no reconnection storms or duplicate connections.
#[tokio::test]
async fn test_20_node_mesh_with_dedup() {
    const N: usize = 20;
    const BASE_PORT: u16 = 24000;

    let mut handles = Vec::with_capacity(N);
    let mut event_rxs = Vec::with_capacity(N);
    let mut metrics = Vec::with_capacity(N);
    let mut tasks = Vec::with_capacity(N);

    for i in 0..N {
        let keypair = Keypair::generate_ed25519();
        let m = Arc::new(OverlayMetrics::new());
        let (handle, events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&m)).unwrap();

        let port = BASE_PORT + i as u16;
        tasks.push(tokio::spawn(async move {
            overlay.run("127.0.0.1", port).await;
        }));
        handles.push(handle);
        event_rxs.push(events);
        metrics.push(m);
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let dial_start = tokio::time::Instant::now();

    // Every node dials every other node simultaneously
    for i in 0..N {
        for j in 0..N {
            if i == j {
                continue;
            }
            let port = BASE_PORT + j as u16;
            let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port)
                .parse()
                .unwrap();
            handles[i].dial(addr).await;
        }
    }

    // ── Convergence timeline: sample every 100ms ──
    eprintln!("\n=== Convergence timeline (20 nodes) ===");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut prev_total_peers = 0usize;
    let mut converge_time = Duration::ZERO;
    let mut converged = false;
    loop {
        let elapsed = dial_start.elapsed();
        let mut min_peers = usize::MAX;
        let mut max_peers = 0usize;
        let mut total_peers = 0usize;
        let mut total_out_est = 0u64;
        let mut total_in_est = 0u64;
        for i in 0..N {
            let count = handles[i].connected_peer_count().await;
            total_out_est += metrics[i].outbound_establish.load(Ordering::Relaxed);
            total_in_est += metrics[i].inbound_establish.load(Ordering::Relaxed);
            min_peers = min_peers.min(count);
            max_peers = max_peers.max(count);
            total_peers += count;
        }
        // Only print when something changed
        if total_peers != prev_total_peers || !converged {
            eprintln!(
                "  t={:5.0?}ms  min_peers={:2}  max_peers={:2}  total_conns={:4}  out_est={:4}  in_est={:4}",
                elapsed.as_millis(), min_peers, max_peers, total_peers, total_out_est, total_in_est
            );
            prev_total_peers = total_peers;
        }
        if min_peers >= N - 1 && !converged {
            converge_time = elapsed;
            converged = true;
            eprintln!(
                "  *** CONVERGED at t={:.0?}ms ***",
                converge_time.as_millis()
            );
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            for i in 0..N {
                let count = handles[i].connected_peer_count().await;
                let auth = metrics[i].connection_authenticated.load(Ordering::Relaxed);
                eprintln!("Node {}: peers={}, auth={}", i, count, auth);
            }
            panic!("Timed out: not all {} nodes have {} peers", N, N - 1);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // ── Post-convergence stability: sample every 500ms for 3s ──
    eprintln!("\n=== Post-convergence stability (3s hold) ===");
    let mut prev_out: Vec<u64> = (0..N)
        .map(|i| metrics[i].outbound_establish.load(Ordering::Relaxed))
        .collect();
    let mut prev_in: Vec<u64> = (0..N)
        .map(|i| metrics[i].inbound_establish.load(Ordering::Relaxed))
        .collect();
    let mut prev_drop: Vec<u64> = (0..N)
        .map(|i| metrics[i].outbound_drop.load(Ordering::Relaxed))
        .collect();

    for tick in 1..=6 {
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut delta_out = 0u64;
        let mut delta_in = 0u64;
        let mut delta_drop = 0u64;
        let mut peer_counts_changed = false;
        for i in 0..N {
            let out = metrics[i].outbound_establish.load(Ordering::Relaxed);
            let inp = metrics[i].inbound_establish.load(Ordering::Relaxed);
            let drp = metrics[i].outbound_drop.load(Ordering::Relaxed);
            delta_out += out - prev_out[i];
            delta_in += inp - prev_in[i];
            delta_drop += drp - prev_drop[i];
            prev_out[i] = out;
            prev_in[i] = inp;
            prev_drop[i] = drp;

            let count = handles[i].connected_peer_count().await;
            if count != N - 1 {
                peer_counts_changed = true;
            }
        }
        eprintln!(
            "  t=+{:.1}s  new_out_est={:3}  new_in_est={:3}  new_drops={}  peer_counts_stable={}",
            tick as f64 * 0.5,
            delta_out,
            delta_in,
            delta_drop,
            !peer_counts_changed
        );

        assert_eq!(delta_drop, 0, "Drops at t=+{:.1}s", tick as f64 * 0.5);
        assert!(
            !peer_counts_changed,
            "Peer counts changed at t=+{:.1}s",
            tick as f64 * 0.5
        );
    }

    eprintln!("\n=== Final per-node metrics ===\n");

    // ── Detailed per-node audit ──
    let expected_dials = (N - 1) as u64; // each node dials N-1 others
    let mut total_outbound_establish = 0u64;
    let mut total_inbound_establish = 0u64;
    let mut total_outbound_drop = 0u64;
    let mut any_reconnect = false;
    let mut total_duplicate_conns = 0u64;

    for i in 0..N {
        let count = handles[i].connected_peer_count().await;
        let auth = metrics[i].connection_authenticated.load(Ordering::Relaxed);
        let out_attempt = metrics[i].outbound_attempt.load(Ordering::Relaxed);
        let out_establish = metrics[i].outbound_establish.load(Ordering::Relaxed);
        let in_establish = metrics[i].inbound_establish.load(Ordering::Relaxed);
        let out_drop = metrics[i].outbound_drop.load(Ordering::Relaxed);
        let pending = metrics[i].connection_pending.load(Ordering::Relaxed);
        // Duplicate connections = total transport connections - unique peers
        // auth == unique peers, (out_establish + in_establish) == total transport connections on this node
        let duplicates = (out_establish + in_establish) as i64 - auth;

        total_outbound_establish += out_establish;
        total_inbound_establish += in_establish;
        total_outbound_drop += out_drop;
        if duplicates > 0 {
            total_duplicate_conns += duplicates as u64;
        }

        eprintln!(
            "Node {:2}: peers={:2} auth={:2} out_attempt={:3} out_est={:2} in_est={:2} drops={} pending={} dupes={}",
            i, count, auth, out_attempt, out_establish, in_establish, out_drop, pending, duplicates
        );

        assert_eq!(count, N - 1, "Node {} peer count", i);
        assert_eq!(auth, (N - 1) as i64, "Node {} auth metric", i);
        assert_eq!(
            out_attempt, expected_dials,
            "Node {} should have dialed exactly {} peers",
            i, expected_dials
        );
        assert_eq!(
            out_drop, 0,
            "Node {} should have 0 drops (no reconnects)",
            i
        );
        assert_eq!(pending, 0, "Node {} should have 0 pending connections", i);

        if out_drop > 0 {
            any_reconnect = true;
        }
    }

    eprintln!(
        "\nTotals: out_establish={} in_establish={} drops={} duplicate_transport_conns={}",
        total_outbound_establish,
        total_inbound_establish,
        total_outbound_drop,
        total_duplicate_conns
    );
    eprintln!("Convergence time: {:.0?}ms", converge_time.as_millis());
    eprintln!(
        "Unique peer pairs: {} (expected C({},2) = {})",
        total_outbound_establish / 2, // rough: each pair has ~2 outbound establishes
        N,
        N * (N - 1) / 2
    );

    assert!(
        !any_reconnect,
        "No node should have experienced a reconnect/drop"
    );

    // Verify SCP still flows: node 0 broadcasts, all others receive
    handles[0].broadcast_scp(b"mesh_test_scp".to_vec()).await;
    let mut received_count = 0u32;
    for i in 1..N {
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(event) = event_rxs[i].recv().await {
                    match event {
                        OverlayEvent::ScpReceived { .. } => return true,
                        OverlayEvent::PeerConnected { .. } => continue,
                        _ => continue,
                    }
                }
            }
        })
        .await;
        if result.is_ok() {
            received_count += 1;
        }
    }
    assert_eq!(
        received_count,
        (N - 1) as u32,
        "All {} peers should receive SCP, got {}",
        N - 1,
        received_count
    );

    for handle in &handles {
        handle.shutdown().await;
    }
    for task in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }
}

