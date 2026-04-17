#include "overlay/OverlayMetrics.h"
#include "main/Application.h"

#include "util/MetricsRegistry.h"

namespace stellar
{

OverlayMetrics::OverlayMetrics(Application& app)
    : mMessageRead(
          app.getMetrics().NewMeter({"overlay", "message", "read"}, "message"))
    , mMessageWrite(
          app.getMetrics().NewMeter({"overlay", "message", "write"}, "message"))
    , mMessageDrop(
          app.getMetrics().NewMeter({"overlay", "message", "drop"}, "message"))
    , mByteRead(app.getMetrics().NewMeter({"overlay", "byte", "read"}, "byte"))
    , mByteWrite(
          app.getMetrics().NewMeter({"overlay", "byte", "write"}, "byte"))
    , mErrorRead(
          app.getMetrics().NewMeter({"overlay", "error", "read"}, "error"))
    , mErrorWrite(
          app.getMetrics().NewMeter({"overlay", "error", "write"}, "error"))
    , mRecvTransactionTimer(app.getMetrics().NewSimpleTimer(
          {"overlay", "recv-transaction", ""}, std::chrono::microseconds{1}))
    , mRecvSCPMessageTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "scp-message"}))
    , mSendSCPMessageSetMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "scp-message"}, "message"))
    , mSendTransactionMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "transaction"}, "message"))
    , mSendTxSetMeter(
          app.getMetrics().NewMeter({"overlay", "send", "txset"}, "message"))
    , mSendFloodAdvertMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "flood-advert"}, "message"))
    , mMessagesDemanded(app.getMetrics().NewMeter(
          {"overlay", "flood", "demanded"}, "message"))
    , mMessagesFulfilledMeter(app.getMetrics().NewMeter(
          {"overlay", "flood", "fulfilled"}, "message"))
    , mUnknownMessageUnfulfilledMeter(app.getMetrics().NewMeter(
          {"overlay", "flood", "unfulfilled-unknown"}, "message"))
    , mTxPullLatency(
          app.getMetrics().NewTimer({"overlay", "flood", "tx-pull-latency"}))
    , mDemandTimeouts(app.getMetrics().NewMeter(
          {"overlay", "demand", "timeout"}, "timeout"))
    , mAbandonedDemandMeter(app.getMetrics().NewMeter(
          {"overlay", "flood", "abandoned-demands"}, "message"))
    , mMessagesBroadcast(app.getMetrics().NewMeter(
          {"overlay", "message", "broadcast"}, "message"))
    , mUniqueFloodBytesRecv(app.getMetrics().NewMeter(
          {"overlay", "flood", "unique-recv"}, "byte"))
    , mDuplicateFloodBytesRecv(app.getMetrics().NewMeter(
          {"overlay", "flood", "duplicate-recv"}, "byte"))
    , mTxBatchSizeHistogram(
          app.getMetrics().NewHistogram({"overlay", "flood", "tx-batch-size"}))
    , mPendingPeersSize(
          app.getMetrics().NewCounter({"overlay", "connection", "pending"}))
    , mAuthenticatedPeersSize(app.getMetrics().NewCounter(
          {"overlay", "connection", "authenticated"}))
    , mFetchTxSetTimer(
          app.getMetrics().NewTimer({"overlay", "fetch", "txset"}))
    , mCompactTxSetSentCount(app.getMetrics().NewCounter(
          {"compact-txset", "sent", "count"}))
    , mCompactTxSetReceivedCount(app.getMetrics().NewCounter(
          {"compact-txset", "received", "count"}))
    , mCompactTxSetSendSkippedNoTxSetCount(app.getMetrics().NewCounter(
          {"compact-txset", "send-skipped-no-txset", "count"}))
    , mCompactTxSetArrivedAfterFullFetchCount(app.getMetrics().NewCounter(
          {"compact-txset", "arrived-after-full-fetch", "count"}))
    , mCompactTxSetBytesSentTotal(app.getMetrics().NewCounter(
          {"compact-txset", "bytes-sent", "total"}))
    , mCompactTxSetBytesReceivedTotal(app.getMetrics().NewCounter(
          {"compact-txset", "bytes-received", "total"}))
    , mCompactTxSetRequestBytesSentTotal(app.getMetrics().NewCounter(
          {"compact-txset", "request-bytes-sent", "total"}))
    , mCompactTxSetResponseBytesSentTotal(app.getMetrics().NewCounter(
          {"compact-txset", "response-bytes-sent", "total"}))
    , mCompactTxSetRequestBytesReceivedTotal(app.getMetrics().NewCounter(
          {"compact-txset", "request-bytes-received", "total"}))
    , mCompactTxSetResponseBytesReceivedTotal(app.getMetrics().NewCounter(
          {"compact-txset", "response-bytes-received", "total"}))
    , mCompactTxSetFullTxSetBytesTotal(app.getMetrics().NewCounter(
          {"compact-txset", "full-txset-bytes", "total"}))
    , mCompactTxSetNetBytesSavedTotal(app.getMetrics().NewCounter(
          {"compact-txset", "net-bytes-saved", "total"}))
    , mCompactTxSetNetBytesWastedTotal(app.getMetrics().NewCounter(
          {"compact-txset", "net-bytes-wasted", "total"}))
    , mCompactTxSetTxCountTotal(app.getMetrics().NewCounter(
          {"compact-txset", "tx-count", "total"}))
    , mCompactTxSetMissingTxCountTotal(app.getMetrics().NewCounter(
          {"compact-txset", "missing-tx-count", "total"}))
    , mCompactTxSetReconstructionSuccessCount(app.getMetrics().NewCounter(
          {"compact-txset", "reconstruction-success", "count"}))
    , mCompactTxSetReconstructionWithFetchCount(app.getMetrics().NewCounter(
          {"compact-txset", "reconstruction-with-fetch", "count"}))
    , mCompactTxSetFallbackToFullFetchCount(app.getMetrics().NewCounter(
          {"compact-txset", "fallback-to-full-fetch", "count"}))
    , mCompactTxSetRefillShortCircuitCount(app.getMetrics().NewCounter(
          {"compact-txset", "refill-short-circuit", "count"}))
    , mCompactTxSetShortIdAmbiguityCount(app.getMetrics().NewCounter(
          {"compact-txset", "short-id-ambiguity", "count"}))
    , mCompactTxSetReconstructionLatencyTotalMs(app.getMetrics().NewCounter(
          {"compact-txset", "reconstruction-latency-total", "ms"}))
    , mCompactTxSetRefillLatencyTotalMs(app.getMetrics().NewCounter(
          {"compact-txset", "refill-latency-total", "ms"}))
    , mCompactTxSetRedundantReceivedCount(app.getMetrics().NewCounter(
          {"compact-txset", "redundant-received", "count"}))
    , mCompactTxSetRedundantBytesReceivedTotal(app.getMetrics().NewCounter(
          {"compact-txset", "redundant-bytes-received", "total"}))
    , mCompactTxSetSendSkippedPerPeerDedupCount(app.getMetrics().NewCounter(
          {"compact-txset", "send-skipped-per-peer-dedup", "count"}))
{
}
}
