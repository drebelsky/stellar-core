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
    , mCompactAnnounceSent(app.getMetrics().NewMeter(
          {"overlay", "compact", "announce-sent"}, "message"))
    , mCompactAnnounceBytesSent(app.getMetrics().NewMeter(
          {"overlay", "compact", "announce-bytes-sent"}, "byte"))
    , mCompactAnnounceRecv(app.getMetrics().NewMeter(
          {"overlay", "compact", "announce-recv"}, "message"))
    , mCompactAnnounceBytesRecv(app.getMetrics().NewMeter(
          {"overlay", "compact", "announce-bytes-recv"}, "byte"))
    , mCompactGetSent(app.getMetrics().NewMeter(
          {"overlay", "compact", "get-sent"}, "message"))
    , mCompactGetBytesSent(app.getMetrics().NewMeter(
          {"overlay", "compact", "get-bytes-sent"}, "byte"))
    , mCompactGetRecv(app.getMetrics().NewMeter(
          {"overlay", "compact", "get-recv"}, "message"))
    , mCompactGetBytesRecv(app.getMetrics().NewMeter(
          {"overlay", "compact", "get-bytes-recv"}, "byte"))
    , mCompactGetTxsSent(app.getMetrics().NewMeter(
          {"overlay", "compact", "get-txs-sent"}, "message"))
    , mCompactGetTxsBytesSent(app.getMetrics().NewMeter(
          {"overlay", "compact", "get-txs-bytes-sent"}, "byte"))
    , mCompactGetTxsRecv(app.getMetrics().NewMeter(
          {"overlay", "compact", "get-txs-recv"}, "message"))
    , mCompactGetTxsBytesRecv(app.getMetrics().NewMeter(
          {"overlay", "compact", "get-txs-bytes-recv"}, "byte"))
    , mCompactTxsSent(app.getMetrics().NewMeter(
          {"overlay", "compact", "txs-sent"}, "message"))
    , mCompactTxsBytesSent(app.getMetrics().NewMeter(
          {"overlay", "compact", "txs-bytes-sent"}, "byte"))
    , mCompactTxsRecv(app.getMetrics().NewMeter(
          {"overlay", "compact", "txs-recv"}, "message"))
    , mCompactTxsBytesRecv(app.getMetrics().NewMeter(
          {"overlay", "compact", "txs-bytes-recv"}, "byte"))
    , mCompactReconComplete(app.getMetrics().NewMeter(
          {"overlay", "compact", "recon-complete"}, "set"))
    , mCompactReconPartial(app.getMetrics().NewMeter(
          {"overlay", "compact", "recon-partial"}, "set"))
    , mCompactReconHashMismatch(app.getMetrics().NewMeter(
          {"overlay", "compact", "recon-hash-mismatch"}, "set"))
    , mCompactReconFailedFallbackLegacy(app.getMetrics().NewMeter(
          {"overlay", "compact", "recon-failed-fallback-legacy"}, "set"))
    , mCompactReconSkipCached(app.getMetrics().NewMeter(
          {"overlay", "compact", "recon-skip-cached"}, "set"))
    , mCompactGetTimeout(app.getMetrics().NewMeter(
          {"overlay", "compact", "get-timeout"}, "timeout"))
    , mCompactReconstructionTimeout(app.getMetrics().NewMeter(
          {"overlay", "compact", "reconstruction-timeout"}, "timeout"))
    , mCompactGetRetry(app.getMetrics().NewMeter(
          {"overlay", "compact", "get-retry"}, "retry"))
    , mCompactGetTxsRetry(app.getMetrics().NewMeter(
          {"overlay", "compact", "get-txs-retry"}, "retry"))
    , mReconstructedFullSizeHistogram(app.getMetrics().NewHistogram(
          {"overlay", "compact", "reconstructed-full-size"}))
    , mCompactReconLockHoldTimer(app.getMetrics().NewTimer(
          {"overlay", "compact", "recon-lock-hold"}))
{
}
}
