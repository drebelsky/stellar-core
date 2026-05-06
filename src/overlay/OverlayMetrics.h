// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

// Overlay-wide (non-peer-specific) metrics synced from the Rust overlay
// process.  Legacy per-message-type recv/send timers and C++-only queue
// metrics have been removed — the Rust overlay uses different stream
// protocols and doesn't have the old per-message framing.

#include "util/SimpleTimer.h"
namespace medida
{
class Timer;
class Meter;
class Counter;
class Histogram;
}

namespace stellar
{

class Application;

// OverlayMetrics is a thread-safe struct
struct OverlayMetrics
{
    OverlayMetrics(Application& app);

    // ── Byte / message throughput ──
    medida::Meter& mMessageRead;
    medida::Meter& mMessageWrite;
    medida::Meter& mMessageDrop;
    medida::Meter& mByteRead;
    medida::Meter& mByteWrite;
    medida::Meter& mErrorRead;
    medida::Meter& mErrorWrite;

    // ── Recv timers (aggregate) ──
    // SimpleTimer: high-frequency TX recv path
    SimpleTimer& mRecvTransactionTimer;
    medida::Timer& mRecvSCPMessageTimer;

    // ── Send meters (per logical message type) ──
    medida::Meter& mSendSCPMessageSetMeter;
    medida::Meter& mSendTransactionMeter;
    medida::Meter& mSendTxSetMeter;
    medida::Meter& mSendFloodAdvertMeter;

    // ── Flood / demand metrics ──
    medida::Meter& mMessagesDemanded;
    medida::Meter& mMessagesFulfilledMeter;
    medida::Meter& mUnknownMessageUnfulfilledMeter;
    medida::Timer& mTxPullLatency;
    medida::Meter& mDemandTimeouts;
    medida::Meter& mAbandonedDemandMeter;

    // ── Broadcast / dedup ──
    medida::Meter& mMessagesBroadcast;
    medida::Meter& mUniqueFloodBytesRecv;
    medida::Meter& mDuplicateFloodBytesRecv;
    medida::Histogram& mTxBatchSizeHistogram;

    // ── Connection gauges ──
    medida::Counter& mPendingPeersSize;
    medida::Counter& mAuthenticatedPeersSize;

    // ── TxSet fetch latency ──
    medida::Timer& mFetchTxSetTimer;

    // ── Compact tx set protocol: per-message-type counts and byte volume ──
    // Counts (one Mark per message); byte volume is tracked separately so the
    // average size of each message type can be computed.
    medida::Meter& mCompactAnnounceSent;
    medida::Meter& mCompactAnnounceBytesSent;
    medida::Meter& mCompactAnnounceRecv;
    medida::Meter& mCompactAnnounceBytesRecv;
    medida::Meter& mCompactGetRecv;
    medida::Meter& mCompactGetBytesRecv;
    medida::Meter& mCompactGetTxsSent;
    medida::Meter& mCompactGetTxsBytesSent;
    medida::Meter& mCompactGetTxsRecv;
    medida::Meter& mCompactGetTxsBytesRecv;
    medida::Meter& mCompactTxsSent;
    medida::Meter& mCompactTxsBytesSent;
    medida::Meter& mCompactTxsRecv;
    medida::Meter& mCompactTxsBytesRecv;

    // ── Reconstruction outcomes ──
    medida::Meter& mCompactReconComplete;
    medida::Meter& mCompactReconPartial;
    medida::Meter& mCompactReconHashMismatch;
    medida::Meter& mCompactReconFailedFallbackLegacy;
    medida::Meter& mCompactReconSkipCached;

    // ── Pending-state housekeeping (timeouts and retries) ──
    medida::Meter& mCompactReconstructionTimeout;
    medida::Meter& mCompactGetTxsRetry;

    // ── Reconstructed full tx-set size (bytes) ──
    medida::Histogram& mReconstructedFullSizeHistogram;

    // ── Lock-hold cost during digest pass in reconstruct_full_tx_set ──
    medida::Timer& mCompactReconLockHoldTimer;
};
}
