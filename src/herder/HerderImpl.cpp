// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/HerderImpl.h"

#include "bucket/BucketManager.h"
#include "bucket/BucketSnapshotManager.h"
#include "crypto/Hex.h"
#include "crypto/KeyUtils.h"
#include "crypto/SHA.h"
#include "crypto/SecretKey.h"
#include "herder/CompactTxSet.h"
#include "herder/FilteredEntries.h"
#include "herder/HerderPersistence.h"
#include "herder/HerderUtils.h"
#include "herder/LedgerCloseData.h"
#include "herder/QuorumIntersectionChecker.h"
#include "herder/RustQuorumCheckerAdaptor.h"
#include "herder/TxSetFrame.h"
#include "herder/TxSetUtils.h"
#include "ledger/LedgerManager.h"
#include "ledger/LedgerTxnImpl.h"
#include "ledger/P23HotArchiveBug.h"
#include "lib/json/json.h"
#include "main/Application.h"
#include "main/Config.h"
#include "main/ErrorMessages.h"
#include "main/PersistentState.h"
#include "medida/counter.h"
#include "medida/meter.h"
#include "overlay/OverlayMetrics.h"
#include "overlay/RustOverlayManager.h"
#include "process/ProcessManager.h"
#include "scp/LocalNode.h"
#include "scp/Slot.h"
#include "transactions/MutableTransactionResult.h"
#include "transactions/TransactionFrameBase.h"
#include "transactions/TransactionUtils.h"
#include "util/DebugMetaUtils.h"
#include "util/Decoder.h"
#include "util/LogSlowExecution.h"
#include "util/Logging.h"
#include "util/Math.h"
#include "util/MetricsRegistry.h"
#include "util/StatusManager.h"
#include "util/Timer.h"
#include "util/XDRStream.h"
#include "xdr/Stellar-internal.h"
#include "xdrpp/marshal.h"
#include "xdrpp/types.h"
#include <Tracy.hpp>

#include "util/GlobalChecks.h"
#include <algorithm>
#include <ctime>
#include <fmt/format.h>
#include <unistd.h>

using namespace std;
namespace stellar
{

// Roughly ~10 minutes of consensus
constexpr uint32 const CLOSE_TIME_DRIFT_LEDGER_WINDOW_SIZE = 120;
// 10 seconds of drift threshold
constexpr uint32 const CLOSE_TIME_DRIFT_SECONDS_THRESHOLD = 10;

constexpr uint32 const TRANSACTION_QUEUE_TIMEOUT_LEDGERS = 4;
constexpr uint32 const TRANSACTION_QUEUE_BAN_LEDGERS = 10;

std::unique_ptr<Herder>
Herder::create(Application& app)
{
    return std::make_unique<HerderImpl>(app);
}

HerderImpl::SCPMetrics::SCPMetrics(Application& app)
    : mLostSync(app.getMetrics().NewMeter({"scp", "sync", "lost"}, "sync"))
    , mEnvelopeEmit(
          app.getMetrics().NewMeter({"scp", "envelope", "emit"}, "envelope"))
    , mEnvelopeReceive(
          app.getMetrics().NewMeter({"scp", "envelope", "receive"}, "envelope"))
    , mCumulativeStatements(app.getMetrics().NewCounter(
          {"scp", "memory", "cumulative-statements"}))
    , mEnvelopeValidSig(app.getMetrics().NewMeter(
          {"scp", "envelope", "validsig"}, "envelope"))
    , mEnvelopeInvalidSig(app.getMetrics().NewMeter(
          {"scp", "envelope", "invalidsig"}, "envelope"))
{
}

HerderImpl::HerderImpl(Application& app)
    : mPendingEnvelopes(app, *this)
    , mHerderSCPDriver(app, *this, mUpgrades, mPendingEnvelopes)
    , mLastSlotSaved(0)
    , mTrackingTimer(app)
    , mLastExternalize(app.getClock().now())
    , mTriggerTimer(app)
    , mOutOfSyncTimer(app)
    , mTxSetGarbageCollectTimer(app)
    , mCheckForDeadNodesTimer(app)
    , mApp(app)
    , mLedgerManager(app.getLedgerManager())
    , mSCPMetrics(app)
    , mLastQuorumMapIntersectionState(
          std::make_shared<QuorumMapIntersectionState>(app))
    , mState(Herder::HERDER_BOOTING_STATE)
{
    auto ln = getSCP().getLocalNode();

    mPendingEnvelopes.addSCPQuorumSet(ln->getQuorumSetHash(),
                                      ln->getQuorumSet());

    // Note: Rust overlay is now managed by RustOverlayManager
    // SCP broadcasts go through getOverlayManager().broadcastMessage()
}

HerderImpl::~HerderImpl()
{
}

Herder::State
HerderImpl::getState() const
{
    return mState;
}

uint32_t
HerderImpl::getMaxClassicTxSize() const
{
#ifdef BUILD_TESTS
    if (mMaxClassicTxSize)
    {
        return *mMaxClassicTxSize;
    }
#endif
    return MAX_CLASSIC_TX_SIZE_BYTES;
}

uint32_t
HerderImpl::getFlowControlExtraBuffer() const
{
#ifdef BUILD_TESTS
    if (mFlowControlExtraBuffer)
    {
        return *mFlowControlExtraBuffer;
    }
#endif
    return FLOW_CONTROL_BYTES_EXTRA_BUFFER;
}

void
HerderImpl::setTrackingSCPState(uint64_t index, StellarValue const& value,
                                bool isTrackingNetwork)
{
    mTrackingSCP = ConsensusData{index, value.closeTime};
    if (isTrackingNetwork)
    {
        setState(Herder::HERDER_TRACKING_NETWORK_STATE);
    }
    else
    {
        setState(Herder::HERDER_SYNCING_STATE);
    }
}

uint32
HerderImpl::trackingConsensusLedgerIndex() const
{
    releaseAssert(getState() != Herder::State::HERDER_BOOTING_STATE);
    releaseAssert(mTrackingSCP.mConsensusIndex <= UINT32_MAX);

    auto lcl = mLedgerManager.getLastClosedLedgerNum();
    if (lcl > mTrackingSCP.mConsensusIndex)
    {
        std::string msg =
            "Inconsistent state in Herder: LCL is ahead of tracking";
        CLOG_ERROR(Herder, "{}", msg);
        CLOG_ERROR(Herder, "{}", REPORT_INTERNAL_BUG);
        throw std::runtime_error(msg);
    }

    return static_cast<uint32>(mTrackingSCP.mConsensusIndex);
}

TimePoint
HerderImpl::trackingConsensusCloseTime() const
{
    releaseAssert(getState() != Herder::State::HERDER_BOOTING_STATE);
    return mTrackingSCP.mConsensusCloseTime;
}

void
HerderImpl::setState(State st)
{
    bool initState = st == HERDER_BOOTING_STATE;
    if (initState && (mState == HERDER_TRACKING_NETWORK_STATE ||
                      mState == HERDER_SYNCING_STATE))
    {
        throw std::runtime_error(fmt::format(
            FMT_STRING("Invalid state transition in Herder: {} -> {}"),
            getStateHuman(mState), getStateHuman(st)));
    }
    mState = st;
}

void
HerderImpl::lostSync()
{
    mHerderSCPDriver.stateChanged();
    setState(Herder::State::HERDER_SYNCING_STATE);
}

SCP&
HerderImpl::getSCP()
{
    return mHerderSCPDriver.getSCP();
}

void
HerderImpl::syncMetrics()
{
    int64_t count = getSCP().getCumulativeStatemtCount();
    mSCPMetrics.mCumulativeStatements.set_count(count);
    TracyPlot("scp.memory.cumulative-statements", count);
}

std::string
HerderImpl::getStateHuman(State st) const
{
    static std::array<char const*, HERDER_NUM_STATE> stateStrings = {
        "HERDER_BOOTING_STATE", "HERDER_SYNCING_STATE",
        "HERDER_TRACKING_NETWORK_STATE"};
    return std::string(stateStrings[st]);
}

void
HerderImpl::bootstrap()
{
    CLOG_INFO(Herder, "Force joining SCP with local state");
    releaseAssert(getSCP().isValidator());
    releaseAssert(mApp.getConfig().FORCE_SCP);

    mLedgerManager.moveToSynced();
    mHerderSCPDriver.bootstrap();

    setupTriggerNextLedger();
    newSlotExternalized(
        true, mLedgerManager.getLastClosedLedgerHeader().header.scpValue);
}

void
HerderImpl::newSlotExternalized(bool synchronous, StellarValue const& value)
{
    ZoneScoped;
    CLOG_TRACE(Herder, "HerderImpl::newSlotExternalized");

    // start timing next externalize from this point
    mLastExternalize = mApp.getClock().now();

    // perform cleanups
    // Evict slots that are outside of our ledger validity bracket
    auto minSlotToRemember = getMinLedgerSeqToRemember();
    if (minSlotToRemember > LedgerManager::GENESIS_LEDGER_SEQ)
    {
        eraseBelow(minSlotToRemember);
    }
    mPendingEnvelopes.forceRebuildQuorum();

    // Process new ready messages for the next slot
    safelyProcessSCPQueue(synchronous);
}

void
HerderImpl::shutdown()
{
    mTrackingTimer.cancel();
    mOutOfSyncTimer.cancel();
    mTriggerTimer.cancel();
    mTxSetGarbageCollectTimer.cancel();
    mCheckForDeadNodesTimer.cancel();
}

void
HerderImpl::processExternalized(uint64 slotIndex, StellarValue const& value,
                                bool isLatestSlot)
{
    ZoneScoped;

    releaseAssert(threadIsMain());

    bool validated = getSCP().isSlotFullyValidated(slotIndex);

    CLOG_DEBUG(Herder, "HerderSCPDriver::valueExternalized index: {} txSet: {}",
               slotIndex, hexAbbrev(value.txSetHash));

    if (getSCP().isValidator() && !validated)
    {
        CLOG_WARNING(Herder,
                     "Ledger {} ({}) closed and could NOT be fully "
                     "validated by validator",
                     slotIndex, hexAbbrev(value.txSetHash));
    }

    TxSetXDRFrameConstPtr externalizedSet =
        mPendingEnvelopes.getTxSet(value.txSetHash);

    // Notify overlay to clear TXs from mempool (for RustOverlayManager)
    // Extract TX hashes from the externalized set so Rust can remove them
    std::vector<Hash> txHashes;
    if (externalizedSet)
    {
        auto txFramesList =
            externalizedSet->createTransactionFrames(mApp.getNetworkID());
        for (auto const& txPhase : txFramesList)
        {
            for (auto const& txFrame : txPhase)
            {
                txHashes.push_back(txFrame->getFullHash());
            }
        }
    }
    mApp.getOverlayManager().notifyTxSetExternalized(value.txSetHash, txHashes);

    // save the SCP messages in the database
    if (mApp.getConfig().MODE_STORES_HISTORY_MISC)
    {
        ZoneNamedN(updateSCPHistoryZone, "update SCP history", true);
        if (slotIndex != 0)
        {
            // Save any new SCP messages received about the previous ledger.
            // NOTE: This call uses an empty `QuorumTracker::QuorumMap` because
            // there is no new quorum map for the previous ledger.
            mApp.getHerderPersistence().saveSCPHistory(
                static_cast<uint32>(slotIndex - 1),
                getSCP().getExternalizingState(slotIndex - 1),
                QuorumTracker::QuorumMap());
        }
        // Store SCP messages received about the current ledger being closed.
        mApp.getHerderPersistence().saveSCPHistory(
            static_cast<uint32>(slotIndex),
            getSCP().getExternalizingState(slotIndex),
            mPendingEnvelopes.getCurrentlyTrackedQuorum());
    }

    // reflect upgrades with the ones included in this SCP round
    {
        bool updated;
        auto newUpgrades = mUpgrades.removeUpgrades(value.upgrades.begin(),
                                                    value.upgrades.end(),
                                                    value.closeTime, updated);
        if (updated)
        {
            setUpgrades(newUpgrades);
        }
    }

    // tell the LedgerManager that this value got externalized
    // LedgerManager will perform the proper action based on its internal
    // state: apply, trigger catchup, etc
    LedgerCloseData ledgerData(static_cast<uint32_t>(slotIndex),
                               externalizedSet, value);

    // Only dump the most recent externalized tx set. Ledger sequence on a
    // written tx set shall only strictly move forward; it may have gaps with
    // the emitted debug meta, if the network is ahead of the local node
    // (assumption is that if the network is ahead of the local node, state can
    // be replayed from the archives)
    if (isLatestSlot && mApp.getConfig().METADATA_DEBUG_LEDGERS != 0)
    {
        writeDebugTxSet(ledgerData);
    }

    mLedgerManager.valueExternalized(ledgerData, isLatestSlot);
}

void
HerderImpl::writeDebugTxSet(LedgerCloseData const& lcd)
{
    ZoneScoped;

    // Dump latest externalized tx set. Do as much of error-handling as possible
    // to avoid crashing core, since this is used purely for debugging.
    auto path =
        metautils::getLatestTxSetFilePath(mApp.getConfig().BUCKET_DIR_PATH);
    try
    {
        if (fs::mkpath(path.parent_path().string()))
        {
            auto timer = LogSlowExecution(
                "write debug tx set", LogSlowExecution::Mode::AUTOMATIC_RAII,
                "took", std::chrono::milliseconds(100));
            // If we got here, then whatever previous tx set is saved has
            // already been applied, and debug meta has been emitted. Therefore,
            // it's safe to just remove it.
            std::filesystem::remove(path);
            XDROutputFileStream stream(mApp.getClock().getIOContext(),
                                       /*fsyncOnClose=*/false);
            stream.open(path.string());
            stream.writeOne(lcd.toXDR());
        }
        else
        {
            CLOG_WARNING(Ledger,
                         "Failed to make directory '{}' for debug tx set",
                         path.parent_path().string());
        }
    }
    catch (std::runtime_error& e)
    {
        CLOG_WARNING(Ledger, "Failed to dump debug tx set '{}': {}",
                     path.string(), e.what());
    }
}

static void
recordExternalizeAndCheckCloseTimeDrift(
    uint64 slotIndex, StellarValue const& value,
    std::map<uint32_t, std::pair<uint64_t, std::optional<uint64_t>>>& ctMap)
{
    auto it = ctMap.find(slotIndex);
    if (it != ctMap.end())
    {
        it->second.second = value.closeTime;
    }

    if (ctMap.size() >= CLOSE_TIME_DRIFT_LEDGER_WINDOW_SIZE)
    {
        medida::Histogram h(medida::SamplingInterface::SampleType::kSliding);
        for (auto const& [ledgerSeq, closeTimePair] : ctMap)
        {
            auto const& [localCT, externalizedCT] = closeTimePair;
            if (externalizedCT)
            {
                h.Update(*externalizedCT - localCT);
            }
        }
        auto drift = static_cast<int>(h.GetSnapshot().get75thPercentile());
        if (std::abs(drift) > CLOSE_TIME_DRIFT_SECONDS_THRESHOLD)
        {
            CLOG_WARNING(Herder, POSSIBLY_BAD_LOCAL_CLOCK);
            CLOG_WARNING(Herder, "Close time local drift is: {}", drift);
        }

        ctMap.clear();
    }
}

void
HerderImpl::valueExternalized(uint64 slotIndex, StellarValue const& value,
                              bool isLatestSlot)
{
    ZoneScoped;
    int const DUMP_SCP_TIMEOUT_SECONDS = 20;

    recordExternalizeAndCheckCloseTimeDrift(slotIndex, value,
                                            mDriftCTSlidingWindow);

    if (isLatestSlot)
    {
        // called both here and at the end (this one is in case of an exception)
        trackingHeartBeat();

        // dump SCP information if this ledger took a long time
        auto gap = std::chrono::duration<double>(mApp.getClock().now() -
                                                 mLastExternalize)
                       .count();
        if (gap > DUMP_SCP_TIMEOUT_SECONDS)
        {
            auto slotInfo = getJsonQuorumInfo(getSCP().getLocalNodeID(), false,
                                              false, slotIndex);
            Json::FastWriter fw;
            CLOG_WARNING(Herder, "Ledger took {} seconds, SCP information:{}",
                         gap, fw.write(slotInfo));
        }

        // trigger will be recreated when the ledger is closed
        // we do not want it to trigger while downloading the current set
        // and there is no point in taking a position after the round is over
        mTriggerTimer.cancel();

        // This call may cause LedgerManager to close ledger and trigger next
        // ledger
        processExternalized(slotIndex, value, isLatestSlot);

        // Perform cleanups, and maybe process SCP queue
        newSlotExternalized(false, value);

        // Check to see if quorums have changed and we need to reanalyze.
        if (mApp.getConfig().USE_QUORUM_INTERSECTION_CHECKER_V2)
        {
            // v2. performs quorum analysis in a separate process that runs the
            // Rust SAT solver.
            checkAndMaybeReanalyzeQuorumMapV2();
        }
        else
        {
            checkAndMaybeReanalyzeQuorumMap();
        }

        // heart beat *after* doing all the work (ensures that we do not include
        // the overhead of externalization in the way we track SCP)
        // Note: this only makes sense in the context of synchronous ledger
        // application on the main thread.
        if (!mApp.getConfig().parallelLedgerClose())
        {
            trackingHeartBeat();
        }
    }
    else
    {
        // This call may trigger application of buffered ledgers and in some
        // cases a ledger trigger
        processExternalized(slotIndex, value, isLatestSlot);
    }
}

void
HerderImpl::outOfSyncRecovery()
{
    ZoneScoped;

    if (isTracking())
    {
        CLOG_WARNING(Herder,
                     "HerderImpl::outOfSyncRecovery called when tracking");
        return;
    }

    // see if we can shed some data as to speed up recovery
    uint32_t maxSlotsAhead = Herder::LEDGER_VALIDITY_BRACKET;
    uint32 purgeSlot = 0;
    getSCP().processSlotsDescendingFrom(
        std::numeric_limits<uint64>::max(), [&](uint64 seq) {
            if (getSCP().gotVBlocking(seq))
            {
                if (--maxSlotsAhead == 0)
                {
                    purgeSlot = static_cast<uint32>(seq);
                }
            }
            return maxSlotsAhead != 0;
        });
    if (purgeSlot)
    {
        CLOG_INFO(Herder, "Purging slots older than {}", purgeSlot);
        eraseBelow(purgeSlot);
    }
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader().header;
    for (auto const& e : getSCP().getLatestMessagesSend(lcl.ledgerSeq + 1))
    {
        broadcast(e);
    }

    getMoreSCPState();
}

void
HerderImpl::broadcast(SCPEnvelope const& e)
{
    ZoneScoped;
    if (!mApp.getConfig().MANUAL_CLOSE)
    {
        CLOG_DEBUG(Herder, "broadcast  s:{} i:{}", e.statement.pledges.type(),
                   e.statement.slotIndex);

        mSCPMetrics.mEnvelopeEmit.Mark();

        // Route through overlay (RustOverlayManager handles IPC to Rust
        // overlay, OverlayManagerImpl handles built-in overlay in standalone
        // mode)
        auto m = std::make_shared<StellarMessage>();
        m->type(SCP_MESSAGE);
        m->envelope() = e;
        mApp.getOverlayManager().broadcastMessage(m);

        // Attempt to send compact tx set alongside the SCP envelope.
        maybeBroadcastCompactTxSetForEnvelope(e);
    }
}

void
HerderImpl::maybeBroadcastCompactTxSetForEnvelope(SCPEnvelope const& e)
{
    auto const& cfg = mApp.getConfig();

    // Determine if this envelope type qualifies for compact tx set sending.
    bool isNomination =
        (e.statement.pledges.type() == SCP_ST_NOMINATE);
    bool isBallot =
        (e.statement.pledges.type() == SCP_ST_PREPARE ||
         e.statement.pledges.type() == SCP_ST_CONFIRM ||
         e.statement.pledges.type() == SCP_ST_EXTERNALIZE);

    bool isOwnEnvelope =
        (e.statement.nodeID == getSCP().getLocalNode()->getNodeID());

    // Check config flags
    if (isNomination)
    {
        if (isOwnEnvelope && !cfg.COMPACT_TX_SET_LEADER_NOMINATION)
            return;
        if (!isOwnEnvelope && !cfg.COMPACT_TX_SET_NON_LEADER_NOMINATION)
            return;
    }
    else if (isBallot)
    {
        if (!cfg.COMPACT_TX_SET_BALLOT_ROUNDS)
            return;
    }
    else
    {
        return;
    }

    // Extract tx set hashes from the envelope
    auto txSetHashes = getTxSetHashes(e);
    if (!txSetHashes)
    {
        return;
    }

    auto& overlayMgr = mApp.getOverlayManager();
    auto& metrics = overlayMgr.getOverlayMetrics();

    for (auto const& txSetHash : *txSetHashes)
    {
        // Per-peer dedup (broadcast-level): skip if we already sent
        // a compact message for this tx set hash.
        if (mCompactTxSetBroadcastDedup.count(txSetHash))
        {
            metrics.mCompactTxSetSendSkippedPerPeerDedupCount.inc();
            continue;
        }

        // Check if we have a cached compact tx set for this hash
        auto cachedIt = mCachedCompactTxSets.find(txSetHash);
        if (cachedIt != mCachedCompactTxSets.end())
        {
            // Use cached serialized bytes
            StellarMessage compactMsg;
            try
            {
                xdr::xdr_from_opaque(cachedIt->second.serializedBytes,
                                     compactMsg);
            }
            catch (std::exception const& ex)
            {
                CLOG_WARNING(Herder,
                             "Failed to deserialize cached compact tx "
                             "set: {}",
                             ex.what());
                continue;
            }

            overlayMgr.broadcastDirect(compactMsg);
            mCompactTxSetBroadcastDedup.insert(txSetHash);
            metrics.mCompactTxSetSentCount.inc();
            metrics.mCompactTxSetBytesSentTotal.inc(
                static_cast<int64_t>(
                    cachedIt->second.serializedBytes.size()));
            continue;
        }

        // Try to build the compact tx set from the full tx set
        auto fullTxSet = mPendingEnvelopes.getTxSet(txSetHash);
        if (!fullTxSet || !fullTxSet->isGeneralizedTxSet())
        {
            metrics.mCompactTxSetSendSkippedNoTxSetCount.inc();
            continue;
        }

        // Generate a random nonce for this compact session
        uint64_t nonce;
        randombytes_buf(&nonce, sizeof(nonce));

        CompactTransactionSet compact;
        if (!buildCompactTxSet(*fullTxSet, nonce, compact))
        {
            continue;
        }

        // Wrap in StellarMessage
        StellarMessage compactMsg;
        compactMsg.type(COMPACT_TX_SET);
        compactMsg.compactTxSet() = compact;

        // Cache the serialized form
        CachedCompactTxSet cached;
        cached.nonce = nonce;
        cached.serializedBytes = xdr::xdr_to_opaque(compactMsg);
        mCachedCompactTxSets[txSetHash] = std::move(cached);

        overlayMgr.broadcastDirect(compactMsg);
        mCompactTxSetBroadcastDedup.insert(txSetHash);
        metrics.mCompactTxSetSentCount.inc();
        metrics.mCompactTxSetBytesSentTotal.inc(
            static_cast<int64_t>(
                mCachedCompactTxSets[txSetHash].serializedBytes.size()));

        CLOG_DEBUG(Herder,
                   "Broadcast compact tx set for hash {} (nonce={}, "
                   "{} txs)",
                   hexAbbrev(txSetHash), nonce,
                   fullTxSet->sizeTxTotal());
    }
}

// ---------------------------------------------------------------------------
// Compact tx set receive-side handlers
// ---------------------------------------------------------------------------

void
HerderImpl::onCompactTxSetReceived(
    uint64_t senderId, std::vector<uint8_t> const& rawBytes,
    std::vector<ResolveResultEntry> const& resolved)
{
    auto& metrics = mApp.getOverlayManager().getOverlayMetrics();

    // Parse the CompactTransactionSet from raw bytes.
    CompactTransactionSet compact;
    try
    {
        xdr::xdr_from_opaque(rawBytes, compact);
    }
    catch (std::exception const& ex)
    {
        CLOG_WARNING(Herder,
                     "onCompactTxSetReceived: failed to parse compact "
                     "tx set: {}",
                     ex.what());
        return;
    }

    auto const& txSetHash = compact.txSetHash;
    auto const nonce = compact.nonce;

    // Check if we already have this tx set (from full fetch or prior
    // reconstruction).
    if (mReconstructedTxSetHashes.count(txSetHash) ||
        mPendingEnvelopes.getTxSet(txSetHash))
    {
        metrics.mCompactTxSetArrivedAfterFullFetchCount.inc();
        CLOG_DEBUG(Herder,
                   "onCompactTxSetReceived: tx set {} already available, "
                   "ignoring compact",
                   hexAbbrev(txSetHash));
        return;
    }

    // Check for redundant compact sessions for the same (hash, nonce,
    // sender).
    CompactSessionKey key{txSetHash, nonce, senderId};
    if (mCompactSessions.count(key))
    {
        metrics.mCompactTxSetRedundantReceivedCount.inc();
        metrics.mCompactTxSetRedundantBytesReceivedTotal.inc(
            static_cast<int64_t>(rawBytes.size()));
        return;
    }

    metrics.mCompactTxSetReceivedCount.inc();
    metrics.mCompactTxSetBytesReceivedTotal.inc(
        static_cast<int64_t>(rawBytes.size()));

    // Count total transactions across all phases for metrics and
    // short-circuit.
    size_t totalTxCount = 0;
    for (size_t i = 0; i < 2; ++i)
    {
        auto const& phase = compact.phases[i];
        switch (phase.v())
        {
        case 0:
            for (auto const& comp : phase.v0Components())
            {
                totalTxCount += comp.shortTxIds.size() / 6;
            }
            break;
        case 1:
        {
            auto const& par = phase.parallelTxsComponent();
            for (auto const& stage : par.executionStages)
            {
                for (auto const& cluster : stage)
                {
                    totalTxCount += cluster.size() / 6;
                }
            }
            break;
        }
        default:
            break;
        }
    }

    metrics.mCompactTxSetTxCountTotal.inc(static_cast<int64_t>(totalTxCount));

    // Count missing and ambiguous from the resolution.
    size_t missingCount = 0;
    size_t ambiguousCount = 0;
    for (auto const& entry : resolved)
    {
        if (entry.status == ResolveResultEntry::Status::MISSING)
            ++missingCount;
        else if (entry.status == ResolveResultEntry::Status::AMBIGUOUS)
            ++ambiguousCount;
    }
    metrics.mCompactTxSetMissingTxCountTotal.inc(
        static_cast<int64_t>(missingCount));
    metrics.mCompactTxSetShortIdAmbiguityCount.inc(
        static_cast<int64_t>(ambiguousCount));

    // Create session.
    CompactSession session;
    session.compact = compact;
    session.resolved = resolved;
    session.totalTxCount = totalTxCount;
    session.receivedAt = mApp.getClock().now();

    mCompactSessions[key] = std::move(session);

    tryFinishCompactSession(txSetHash, nonce, senderId);
}

void
HerderImpl::onGetCompactTxSetTxsReceived(
    uint64_t senderId, std::vector<uint8_t> const& rawBytes)
{
    auto& metrics = mApp.getOverlayManager().getOverlayMetrics();

    GetCompactTxSetTransactions req;
    try
    {
        xdr::xdr_from_opaque(rawBytes, req);
    }
    catch (std::exception const& ex)
    {
        CLOG_WARNING(Herder,
                     "onGetCompactTxSetTxsReceived: failed to parse: {}",
                     ex.what());
        return;
    }

    metrics.mCompactTxSetRequestBytesReceivedTotal.inc(
        static_cast<int64_t>(rawBytes.size()));

    // Look up the full tx set.
    auto fullTxSet = mPendingEnvelopes.getTxSet(req.txSetHash);
    if (!fullTxSet || !fullTxSet->isGeneralizedTxSet())
    {
        CLOG_DEBUG(Herder,
                   "onGetCompactTxSetTxsReceived: tx set {} not available "
                   "for refill",
                   hexAbbrev(req.txSetHash));
        metrics.mCompactTxSetSendSkippedNoTxSetCount.inc();
        return;
    }

    // Unpack the requested short IDs.
    std::vector<ShortTxId> requestedIds;
    if (!unpackShortIds(req.shortTxIds, requestedIds))
    {
        CLOG_WARNING(Herder,
                     "onGetCompactTxSetTxsReceived: invalid short ID length");
        return;
    }

    // Build a set of requested short IDs for fast lookup.
    std::set<ShortTxId> requestedSet(requestedIds.begin(), requestedIds.end());

    // Walk the full tx set and compute short IDs using the request's nonce.
    // Match against requested short IDs.
    GeneralizedTransactionSet genTxSet;
    fullTxSet->toXDR(genTxSet);

    if (genTxSet.v() != 1)
    {
        return;
    }
    auto const& v1 = genTxSet.v1TxSet();

    std::vector<ShortTxId> matchedIds;
    xdr::xvector<TransactionEnvelope> matchedEnvs;

    auto const& contentHash = fullTxSet->getContentsHash();
    for (auto const& phase : v1.phases)
    {
        switch (phase.v())
        {
        case 0:
            for (auto const& comp : phase.v0Components())
            {
                for (auto const& env :
                     comp.txsMaybeDiscountedFee().txs)
                {
                    Hash txHash = xdrSha256(env);
                    ShortTxId sid =
                        shortHash::computeCompactTxSetShortId(
                            contentHash, req.nonce, txHash);
                    if (requestedSet.count(sid))
                    {
                        matchedIds.push_back(sid);
                        matchedEnvs.push_back(env);
                    }
                }
            }
            break;
        case 1:
        {
            auto const& par = phase.parallelTxsComponent();
            for (auto const& stage : par.executionStages)
            {
                for (auto const& cluster : stage)
                {
                    for (auto const& env : cluster)
                    {
                        Hash txHash = xdrSha256(env);
                        ShortTxId sid =
                            shortHash::computeCompactTxSetShortId(
                                contentHash, req.nonce, txHash);
                        if (requestedSet.count(sid))
                        {
                            matchedIds.push_back(sid);
                            matchedEnvs.push_back(env);
                        }
                    }
                }
            }
            break;
        }
        default:
            break;
        }
    }

    // Build the response.
    CompactTxSetTransactions resp;
    resp.txSetHash = req.txSetHash;
    resp.nonce = req.nonce;
    resp.shortTxIds = packShortIds(matchedIds);
    resp.txs = matchedEnvs;

    StellarMessage msg;
    msg.type(COMPACT_TX_SET_TXS);
    msg.compactTxSetTxs() = resp;

    auto responseBytes = xdr::xdr_to_opaque(msg);
    metrics.mCompactTxSetResponseBytesSentTotal.inc(
        static_cast<int64_t>(responseBytes.size()));

    mApp.getOverlayManager().sendToPeer(senderId, msg);

    CLOG_DEBUG(Herder,
               "Sent refill response for {} ({} txs) to peer {}",
               hexAbbrev(req.txSetHash), matchedEnvs.size(), senderId);
}

void
HerderImpl::onRefillForwarded(Hash const& txSetHash, uint64_t nonce,
                               uint64_t senderId,
                               std::vector<uint8_t> const& packedShortIds,
                               std::vector<uint8_t> const& envelopeArrayBytes)
{
    auto& metrics = mApp.getOverlayManager().getOverlayMetrics();
    metrics.mCompactTxSetResponseBytesReceivedTotal.inc(
        static_cast<int64_t>(packedShortIds.size() +
                             envelopeArrayBytes.size()));

    CompactSessionKey key{txSetHash, nonce, senderId};
    auto it = mCompactSessions.find(key);
    if (it == mCompactSessions.end())
    {
        CLOG_DEBUG(Herder,
                   "onRefillForwarded: no session for {} (nonce={}, "
                   "sender={})",
                   hexAbbrev(txSetHash), nonce, senderId);
        return;
    }

    // Unpack the short IDs from the response.
    PackedShortTxIds packed(packedShortIds.begin(), packedShortIds.end());
    std::vector<ShortTxId> refillIds;
    if (!unpackShortIds(packed, refillIds))
    {
        CLOG_WARNING(Herder, "onRefillForwarded: invalid short ID length");
        return;
    }

    // Parse the envelope array.
    xdr::xvector<TransactionEnvelope> envelopes;
    try
    {
        xdr::xdr_from_opaque(envelopeArrayBytes, envelopes);
    }
    catch (std::exception const& ex)
    {
        CLOG_WARNING(Herder,
                     "onRefillForwarded: failed to parse envelopes: {}",
                     ex.what());
        // Fall back.
        metrics.mCompactTxSetFallbackToFullFetchCount.inc();
        mCompactSessions.erase(it);
        mApp.getOverlayManager().requestTxSet(txSetHash);
        return;
    }

    if (refillIds.size() != envelopes.size())
    {
        CLOG_WARNING(Herder,
                     "onRefillForwarded: short ID count ({}) != envelope "
                     "count ({})",
                     refillIds.size(), envelopes.size());
        metrics.mCompactTxSetFallbackToFullFetchCount.inc();
        mCompactSessions.erase(it);
        mApp.getOverlayManager().requestTxSet(txSetHash);
        return;
    }

    // Record refill latency.
    auto now = mApp.getClock().now();
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                         now - it->second.receivedAt)
                         .count();
    metrics.mCompactTxSetRefillLatencyTotalMs.inc(
        static_cast<int64_t>(elapsedMs));

    // Build a map from refill short ID → envelope bytes for merging.
    std::map<ShortTxId, xdr::opaque_vec<>> refillMap;
    for (size_t i = 0; i < refillIds.size(); ++i)
    {
        refillMap[refillIds[i]] = xdr::xdr_to_opaque(envelopes[i]);
    }

    // Merge into the session's resolved map. Walk the compact structure
    // to find the positional indices of the refilled short IDs.
    auto& session = it->second;
    size_t resolvedIdx = 0;
    auto mergePhaseShortIds =
        [&](PackedShortTxIds const& packedIds) {
            std::vector<ShortTxId> ids;
            if (!unpackShortIds(packedIds, ids))
                return;
            for (auto const& id : ids)
            {
                if (resolvedIdx < session.resolved.size())
                {
                    auto& entry = session.resolved[resolvedIdx];
                    if (entry.status != ResolveResultEntry::Status::UNIQUE)
                    {
                        auto refillIt = refillMap.find(id);
                        if (refillIt != refillMap.end())
                        {
                            entry.status =
                                ResolveResultEntry::Status::UNIQUE;
                            entry.envelopeBytes = refillIt->second;
                        }
                    }
                }
                ++resolvedIdx;
            }
        };

    for (size_t phaseIdx = 0; phaseIdx < 2; ++phaseIdx)
    {
        auto const& phase = session.compact.phases[phaseIdx];
        switch (phase.v())
        {
        case 0:
            for (auto const& comp : phase.v0Components())
            {
                mergePhaseShortIds(comp.shortTxIds);
            }
            break;
        case 1:
        {
            auto const& par = phase.parallelTxsComponent();
            for (auto const& stage : par.executionStages)
            {
                for (auto const& cluster : stage)
                {
                    mergePhaseShortIds(cluster);
                }
            }
            break;
        }
        default:
            break;
        }
    }

    tryFinishCompactSession(txSetHash, nonce, senderId);
}

void
HerderImpl::tryFinishCompactSession(Hash const& txSetHash, uint64_t nonce,
                                     uint64_t senderId)
{
    auto& metrics = mApp.getOverlayManager().getOverlayMetrics();
    CompactSessionKey key{txSetHash, nonce, senderId};
    auto it = mCompactSessions.find(key);
    if (it == mCompactSessions.end())
    {
        return;
    }

    auto& session = it->second;
    auto const& lcl =
        mLedgerManager.getLastClosedLedgerHeader().hash;
    auto result = tryReconstruct(session.compact, session.resolved, lcl);

    switch (result.status)
    {
    case ReconstructResult::Status::COMPLETE:
    {
        auto now = mApp.getClock().now();
        auto latencyMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now - session.receivedAt)
                .count();
        metrics.mCompactTxSetReconstructionLatencyTotalMs.inc(
            static_cast<int64_t>(latencyMs));

        if (session.refillRequested)
        {
            metrics.mCompactTxSetReconstructionWithFetchCount.inc();
        }
        else
        {
            metrics.mCompactTxSetReconstructionSuccessCount.inc();
        }

        // Compute bandwidth savings.
        auto compactBytes = xdr::xdr_to_opaque(session.compact).size();
        GeneralizedTransactionSet fullXdr;
        result.txSet->toXDR(fullXdr);
        auto fullBytes = xdr::xdr_to_opaque(fullXdr).size();
        metrics.mCompactTxSetFullTxSetBytesTotal.inc(
            static_cast<int64_t>(fullBytes));

        if (fullBytes > compactBytes)
        {
            metrics.mCompactTxSetNetBytesSavedTotal.inc(
                static_cast<int64_t>(fullBytes - compactBytes));
        }
        else
        {
            metrics.mCompactTxSetNetBytesWastedTotal.inc(
                static_cast<int64_t>(compactBytes - fullBytes));
        }

        mReconstructedTxSetHashes.insert(txSetHash);

        // Save values before erasing the session (invalidates reference)
        auto const finalTxCount = session.totalTxCount;
        auto const finalRefillRequested = session.refillRequested;
        mCompactSessions.erase(it);

        // Deliver to PendingEnvelopes. Use recvTxSet which checks
        // pending fetches and re-processes waiting envelopes.
        if (!mPendingEnvelopes.recvTxSet(txSetHash, result.txSet))
        {
            // No pending fetch for this hash yet — cache it so it's
            // available when the SCP envelope arrives.
            mPendingEnvelopes.addTxSet(txSetHash, 0, result.txSet);
        }

        CLOG_INFO(Herder,
                  "Reconstructed tx set {} from compact ({}ms, {} txs, "
                  "refill={})",
                  hexAbbrev(txSetHash), latencyMs,
                  finalTxCount,
                  finalRefillRequested);
        break;
    }
    case ReconstructResult::Status::NEEDS_REFILL:
    {
        if (session.refillRequested)
        {
            // Already tried refill once, fall back.
            CLOG_WARNING(
                Herder,
                "Compact reconstruction still incomplete after refill "
                "for {}, falling back to full fetch",
                hexAbbrev(txSetHash));
            metrics.mCompactTxSetFallbackToFullFetchCount.inc();
            mCompactSessions.erase(it);
            mApp.getOverlayManager().requestTxSet(txSetHash);
            break;
        }

        // Check refill short-circuit: if too many are missing,
        // skip refill and go straight to full fetch.
        size_t refillCount = result.missingShortIds.size();
        double ratio =
            session.totalTxCount > 0
                ? static_cast<double>(refillCount) /
                      static_cast<double>(session.totalTxCount)
                : 1.0;

        if (ratio >= mApp.getConfig().COMPACT_TX_SET_REFILL_MAX_RATIO)
        {
            CLOG_INFO(Herder,
                      "Compact refill short-circuit for {} "
                      "(missing={}/{}, ratio={:.2f} >= {:.2f})",
                      hexAbbrev(txSetHash), refillCount,
                      session.totalTxCount, ratio,
                      mApp.getConfig().COMPACT_TX_SET_REFILL_MAX_RATIO);
            metrics.mCompactTxSetRefillShortCircuitCount.inc();
            mCompactSessions.erase(it);
            mApp.getOverlayManager().requestTxSet(txSetHash);
            break;
        }

        // Send refill request to the sender.
        session.refillRequested = true;

        GetCompactTxSetTransactions req;
        req.txSetHash = txSetHash;
        req.nonce = nonce;
        req.shortTxIds = packShortIds(result.missingShortIds);

        StellarMessage msg;
        msg.type(GET_COMPACT_TX_SET_TXS);
        msg.getCompactTxSetTxs() = req;

        auto reqBytes = xdr::xdr_to_opaque(msg);
        metrics.mCompactTxSetRequestBytesSentTotal.inc(
            static_cast<int64_t>(reqBytes.size()));

        mApp.getOverlayManager().sendToPeer(senderId, msg);

        CLOG_DEBUG(Herder,
                   "Sent refill request for {} ({} missing short IDs) "
                   "to peer {}",
                   hexAbbrev(txSetHash), refillCount, senderId);
        break;
    }
    case ReconstructResult::Status::FAILED:
    {
        CLOG_WARNING(Herder,
                     "Compact reconstruction failed for {}, falling "
                     "back to full fetch",
                     hexAbbrev(txSetHash));
        metrics.mCompactTxSetFallbackToFullFetchCount.inc();

        auto now = mApp.getClock().now();
        auto latencyMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now - session.receivedAt)
                .count();
        metrics.mCompactTxSetReconstructionLatencyTotalMs.inc(
            static_cast<int64_t>(latencyMs));

        mCompactSessions.erase(it);
        mApp.getOverlayManager().requestTxSet(txSetHash);
        break;
    }
    }
}

void
HerderImpl::startOutOfSyncTimer()
{
    if (mApp.getConfig().MANUAL_CLOSE && mApp.getConfig().RUN_STANDALONE)
    {
        return;
    }

    mOutOfSyncTimer.expires_from_now(Herder::OUT_OF_SYNC_RECOVERY_TIMER);

    mOutOfSyncTimer.async_wait(
        [&]() {
            outOfSyncRecovery();
            startOutOfSyncTimer();
        },
        &VirtualTimer::onFailureNoop);
}

void
HerderImpl::emitEnvelope(SCPEnvelope const& envelope)
{
    ZoneScoped;
    uint64 slotIndex = envelope.statement.slotIndex;

    CLOG_DEBUG(Herder, "emitEnvelope s:{} i:{} a:{}",
               envelope.statement.pledges.type(), slotIndex,
               mApp.getStateHuman());

    persistSCPState(slotIndex);

    broadcast(envelope);
}

TxSubmitStatus
HerderImpl::recvTransaction(TransactionFrameBasePtr tx, bool submittedFromSelf
#ifdef BUILD_TESTS
                            ,
                            bool isLoadgenTx
#endif
)
{
    ZoneScoped;
    CLOG_TRACE(Herder, "recv transaction {} for {}",
               hexAbbrev(tx->getFullHash()),
               KeyUtils::toShortString(tx->getSourceID()));

    auto const& env = tx->getEnvelope();
    mApp.getOverlayManager().broadcastTransaction(env, tx->getFullFee(),
                                                  tx->getNumOperations());
    return TxSubmitStatus::TX_STATUS_PENDING;
}

bool
HerderImpl::checkCloseTime(SCPEnvelope const& envelope, bool enforceRecent)
{
    ZoneScoped;
    using std::placeholders::_1;
    auto const& st = envelope.statement;

    uint64_t ctCutoff = 0;

    if (enforceRecent)
    {
        auto now = VirtualClock::to_time_t(mApp.getClock().system_now());
        if (now >= mApp.getConfig().MAXIMUM_LEDGER_CLOSETIME_DRIFT)
        {
            ctCutoff = now - mApp.getConfig().MAXIMUM_LEDGER_CLOSETIME_DRIFT;
        }
    }

    auto envLedgerIndex = envelope.statement.slotIndex;
    auto& scpD = getHerderSCPDriver();

    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader().header;
    auto lastCloseIndex = lcl.ledgerSeq;
    auto lastCloseTime = lcl.scpValue.closeTime;

    // see if we can get a better estimate of lastCloseTime for validating this
    // statement using consensus data:
    // update lastCloseIndex/lastCloseTime to be the highest possible but still
    // be less than envLedgerIndex
    if (getState() != HERDER_BOOTING_STATE)
    {
        auto trackingIndex = trackingConsensusLedgerIndex();
        if (envLedgerIndex >= trackingIndex && trackingIndex > lastCloseIndex)
        {
            lastCloseIndex = static_cast<uint32>(trackingIndex);
            lastCloseTime = trackingConsensusCloseTime();
        }
    }

    StellarValue sv;
    // performs the most conservative check:
    // returns true if one of the values is valid
    auto checkCTHelper = [&](std::vector<Value> const& values) {
        return std::any_of(values.begin(), values.end(), [&](Value const& e) {
            auto r = toStellarValue(e, sv);
            // sv must be after cutoff
            r = r && sv.closeTime >= ctCutoff;
            if (r)
            {
                // statement received after the fact, only keep externalized
                // value
                r = (lastCloseIndex == envLedgerIndex &&
                     lastCloseTime == sv.closeTime);
                // for older messages, just ensure that they occurred before
                r = r || (lastCloseIndex > envLedgerIndex &&
                          lastCloseTime > sv.closeTime);
                // for future message, perform the same validity check than
                // within SCP
                r = r || scpD.checkCloseTime(envLedgerIndex, lastCloseTime, sv);
            }
            return r;
        });
    };

    bool b;

    switch (st.pledges.type())
    {
    case SCP_ST_NOMINATE:
        b = checkCTHelper(st.pledges.nominate().accepted) ||
            checkCTHelper(st.pledges.nominate().votes);
        break;
    case SCP_ST_PREPARE:
    {
        auto& prep = st.pledges.prepare();
        b = checkCTHelper({prep.ballot.value});
        if (!b && prep.prepared)
        {
            b = checkCTHelper({prep.prepared->value});
        }
        if (!b && prep.preparedPrime)
        {
            b = checkCTHelper({prep.preparedPrime->value});
        }
    }
    break;
    case SCP_ST_CONFIRM:
        b = checkCTHelper({st.pledges.confirm().ballot.value});
        break;
    case SCP_ST_EXTERNALIZE:
        b = checkCTHelper({st.pledges.externalize().commit.value});
        break;
    default:
        abort();
    }

    if (!b)
    {
        CLOG_TRACE(Herder, "Invalid close time processing {}",
                   getSCP().envToStr(st));
    }
    return b;
}

uint32_t
HerderImpl::getMinLedgerSeqToRemember() const
{
    auto maxSlotsToRemember = mApp.getConfig().MAX_SLOTS_TO_REMEMBER;
    auto currSlot = trackingConsensusLedgerIndex();
    if (currSlot > maxSlotsToRemember)
    {
        return (currSlot - maxSlotsToRemember + 1);
    }
    else
    {
        return LedgerManager::GENESIS_LEDGER_SEQ;
    }
}

Herder::EnvelopeStatus
HerderImpl::recvSCPEnvelope(SCPEnvelope const& envelope)
{
    ZoneScoped;
    if (mApp.getConfig().MANUAL_CLOSE)
    {
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    mSCPMetrics.mEnvelopeReceive.Mark();

    // **** first perform checks that do NOT require signature verification
    // this allows to fast fail messages that we'd throw away anyways

    uint32_t minLedgerSeq = getMinLedgerSeqToRemember();
    uint32_t maxLedgerSeq = std::numeric_limits<uint32>::max();

    if (!checkCloseTime(envelope, false))
    {
        // if the envelope contains an invalid close time, don't bother
        // processing it as we're not going to forward it anyways and it's
        // going to just sit in our SCP state not contributing anything useful.
        CLOG_TRACE(
            Herder,
            "skipping invalid close time (incompatible with current state)");
        std::string txt("DISCARDED - incompatible close time");
        ZoneText(txt.c_str(), txt.size());
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    auto checkpoint = getMostRecentCheckpointSeq();
    auto index = envelope.statement.slotIndex;

    if (isTracking())
    {
        // when tracking, we can filter messages based on the information we got
        // from consensus for the max ledger

        // note that this filtering will cause a node on startup
        // to potentially drop messages outside of the bracket
        // causing it to discard CONSENSUS_STUCK_TIMEOUT_SECONDS worth of
        // ledger closing
        maxLedgerSeq = nextConsensusLedgerIndex() + LEDGER_VALIDITY_BRACKET;
    }
    // Allow message with a drift larger than MAXIMUM_LEDGER_CLOSETIME_DRIFT if
    // it is a checkpoint message
    else if (!checkCloseTime(envelope, trackingConsensusLedgerIndex() <=
                                           LedgerManager::GENESIS_LEDGER_SEQ) &&
             index != checkpoint)
    {
        // if we've never been in sync, we can be more aggressive in how we
        // filter messages: we can ignore messages that are unlikely to be
        // the latest messages from the network
        CLOG_TRACE(Herder, "recvSCPEnvelope: skipping invalid close time "
                           "(check MAXIMUM_LEDGER_CLOSETIME_DRIFT)");
        std::string txt("DISCARDED - invalid close time");
        ZoneText(txt.c_str(), txt.size());
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    // If envelopes are out of our validity brackets, or if envelope does not
    // contain the checkpoint for early catchup, we just ignore them.
    if ((index > maxLedgerSeq || index < minLedgerSeq) && index != checkpoint)
    {
        CLOG_TRACE(Herder, "Ignoring SCPEnvelope outside of range: {}( {},{})",
                   envelope.statement.slotIndex, minLedgerSeq, maxLedgerSeq);
        std::string txt("DISCARDED - out of range");
        ZoneText(txt.c_str(), txt.size());
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    // **** from this point, we have to check signatures
    if (!verifyEnvelope(envelope))
    {
        std::string txt("DISCARDED - bad envelope");
        ZoneText(txt.c_str(), txt.size());
        CLOG_TRACE(Herder, "Received bad envelope, discarding");
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    if (envelope.statement.nodeID == getSCP().getLocalNode()->getNodeID())
    {
        CLOG_TRACE(Herder, "recvSCPEnvelope: skipping own message");
        std::string txt("SKIPPED_SELF");
        ZoneText(txt.c_str(), txt.size());
        return Herder::ENVELOPE_STATUS_SKIPPED_SELF;
    }

    auto status = mPendingEnvelopes.recvSCPEnvelope(envelope);
    if (status == Herder::ENVELOPE_STATUS_READY)
    {
        std::string txt("READY");
        ZoneText(txt.c_str(), txt.size());
        CLOG_DEBUG(Herder, "recvSCPEnvelope (ready) from: {} s:{} i:{} a:{}",
                   mApp.getConfig().toShortString(envelope.statement.nodeID),
                   envelope.statement.pledges.type(),
                   envelope.statement.slotIndex, mApp.getStateHuman());

        processSCPQueue();
    }
    else
    {
        if (status == Herder::ENVELOPE_STATUS_FETCHING)
        {
            std::string txt("FETCHING");
            ZoneText(txt.c_str(), txt.size());
        }
        else if (status == Herder::ENVELOPE_STATUS_PROCESSED)
        {
            std::string txt("PROCESSED");
            ZoneText(txt.c_str(), txt.size());
        }
        CLOG_TRACE(Herder, "recvSCPEnvelope ({}) from: {} s:{} i:{} a:{}",
                   static_cast<int>(status),
                   mApp.getConfig().toShortString(envelope.statement.nodeID),
                   envelope.statement.pledges.type(),
                   envelope.statement.slotIndex, mApp.getStateHuman());
    }
    return status;
}

#ifdef BUILD_TESTS

Herder::EnvelopeStatus
HerderImpl::recvSCPEnvelope(SCPEnvelope const& envelope,
                            const SCPQuorumSet& qset,
                            TxSetXDRFrameConstPtr txset)
{
    ZoneScoped;
    mPendingEnvelopes.addTxSet(txset->getContentsHash(),
                               envelope.statement.slotIndex, txset);
    mPendingEnvelopes.addSCPQuorumSet(xdrSha256(qset), qset);
    return recvSCPEnvelope(envelope);
}

Herder::EnvelopeStatus
HerderImpl::recvSCPEnvelope(SCPEnvelope const& envelope,
                            SCPQuorumSet const& qset,
                            StellarMessage const& txset)
{
    auto txSetFrame =
        txset.type() == TX_SET
            ? TxSetXDRFrame::makeFromWire(txset.txSet())
            : TxSetXDRFrame::makeFromWire(txset.generalizedTxSet());
    return recvSCPEnvelope(envelope, qset, txSetFrame);
}

void
HerderImpl::externalizeValue(TxSetXDRFrameConstPtr txSet, uint32_t ledgerSeq,
                             uint64_t closeTime,
                             xdr::xvector<UpgradeType, 6> const& upgrades,
                             std::optional<SecretKey> skToSignValue)
{
    getPendingEnvelopes().putTxSet(txSet->getContentsHash(), ledgerSeq, txSet);
    auto sk = skToSignValue ? *skToSignValue : mApp.getConfig().NODE_SEED;
    StellarValue sv =
        makeStellarValue(txSet->getContentsHash(), closeTime, upgrades, sk);
    getHerderSCPDriver().valueExternalized(ledgerSeq, xdr::xdr_to_opaque(sv));
    while (mApp.getLedgerManager().getLastClosedLedgerNum() < ledgerSeq)
    {
        mApp.getClock().crank(true);
    }
}

#endif

std::vector<SCPEnvelope>
HerderImpl::getSCPStateForPeer(uint32 ledgerSeq)
{
    ZoneScoped;
    std::vector<SCPEnvelope> envelopes;
    auto maxSlots = Herder::LEDGER_VALIDITY_BRACKET;

    // Collect up to MAX_SLOTS_TO_SEND slots worth of envelopes
    getSCP().processSlotsAscendingFrom(ledgerSeq, [&](uint64 seq) {
        bool slotHadData = false;
        getSCP().processCurrentState(
            seq,
            [&](SCPEnvelope const& e) {
                envelopes.push_back(e);
                slotHadData = true;
                return true; // continue
            },
            false);
        if (slotHadData)
        {
            --maxSlots;
        }
        return maxSlots != 0;
    });

    return envelopes;
}

void
HerderImpl::processSCPQueue()
{
    ZoneScoped;
    if (isTracking())
    {
        std::string txt("tracking");
        ZoneText(txt.c_str(), txt.size());
        processSCPQueueUpToIndex(nextConsensusLedgerIndex());
    }
    else
    {
        std::string txt("not tracking");
        ZoneText(txt.c_str(), txt.size());
        // we don't know which ledger we're in
        // try to consume the messages from the queue
        // starting from the smallest slot
        for (auto& slot : mPendingEnvelopes.readySlots())
        {
            processSCPQueueUpToIndex(slot);
            if (isTracking())
            {
                // one of the slots externalized
                // we go back to regular flow
                break;
            }
        }
    }
}

void
HerderImpl::processSCPQueueUpToIndex(uint64 slotIndex)
{
    ZoneScoped;
    while (true)
    {
        SCPEnvelopeWrapperPtr envW = mPendingEnvelopes.pop(slotIndex);
        if (envW)
        {
            auto r = getSCP().receiveEnvelope(envW);
            if (r == SCP::EnvelopeState::VALID)
            {
                auto const& env = envW->getEnvelope();
                auto const& st = env.statement;
                if (st.pledges.type() == SCP_ST_EXTERNALIZE)
                {
                    mHerderSCPDriver.recordSCPExternalizeEvent(
                        st.slotIndex, st.nodeID, false);
                }
                mPendingEnvelopes.envelopeProcessed(env);
            }
        }
        else
        {
            return;
        }
    }
}

#ifdef BUILD_TESTS
PendingEnvelopes&
HerderImpl::getPendingEnvelopes()
{
    return mPendingEnvelopes;
}

Upgrades const&
HerderImpl::getUpgrades() const
{
    return mUpgrades;
}
#endif

std::chrono::milliseconds
HerderImpl::ctValidityOffset(uint64_t ct, std::chrono::milliseconds maxCtOffset)
{
    auto maxCandidateCt = mApp.getClock().system_now() + maxCtOffset +
                          Herder::MAX_TIME_SLIP_SECONDS;
    auto minCandidateCt = VirtualClock::from_time_t(ct);

    if (minCandidateCt > maxCandidateCt)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   minCandidateCt - maxCandidateCt) +
               std::chrono::milliseconds(1);
    }

    return std::chrono::milliseconds::zero();
}

void
HerderImpl::safelyProcessSCPQueue(bool synchronous)
{
    // process any statements up to the next slot
    // this may cause it to externalize
    auto nextIndex = nextConsensusLedgerIndex();
    auto processSCPQueueSomeMore = [this, nextIndex]() {
        if (mApp.isStopping())
        {
            return;
        }
        processSCPQueueUpToIndex(nextIndex);
    };

    if (synchronous)
    {
        processSCPQueueSomeMore();
    }
    else
    {
        mApp.postOnMainThread(processSCPQueueSomeMore,
                              "processSCPQueueSomeMore");
    }
}

void
HerderImpl::lastClosedLedgerIncreased(bool latest, TxSetXDRFrameConstPtr txSet,
                                      bool upgradeApplied)
{
    releaseAssert(threadIsMain());

    // Clean up compact tx set relay state — the referenced tx sets are moot
    // now that the ledger has advanced.
    mCachedCompactTxSets.clear();
    mCompactTxSetBroadcastDedup.clear();
    mCompactSessions.clear();
    mReconstructedTxSetHashes.clear();

    // Ensure potential upgrades are handled in overlay
    maybeHandleUpgrade();

    // If we're in sync and there are no buffered ledgers to apply, trigger next
    // ledger
    if (latest)
    {
        // Re-start heartbeat tracking _after_ applying the most up-to-date
        // ledger. This guarantees out-of-sync timer won't fire while we have
        // ledgers to apply (applicable during parallel ledger apply).
        trackingHeartBeat();

        // Ensure out of sync recovery did not get triggered while we were
        // applying
        releaseAssert(isTracking());
        releaseAssert(trackingConsensusLedgerIndex() ==
                      mLedgerManager.getLastClosedLedgerNum());
        releaseAssert(mLedgerManager.isSynced());

        setupTriggerNextLedger();
    }
}

void
HerderImpl::setupTriggerNextLedger()
{
    // Invariant: core proceeds to vote for the next ledger only when it's _not_
    // applying to ensure block production does not conflict with ledger close.
    releaseAssert(!mLedgerManager.isApplying());

    // Invariant: tracking is equal to LCL when we trigger. This helps ensure
    // core emits SCP messages only for slots it can fully validate
    // (any closed ledger is fully validated)
    releaseAssert(isTracking());
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();
    releaseAssert(trackingConsensusLedgerIndex() == lcl.header.ledgerSeq);
    releaseAssert(mLedgerManager.isSynced());

    mTriggerTimer.cancel();

    uint64_t nextIndex = nextConsensusLedgerIndex();
    auto lastIndex = trackingConsensusLedgerIndex();

    // if we're in sync, we setup mTriggerTimer
    // it may get cancelled if a more recent ledger externalizes

    std::chrono::milliseconds milliseconds =
        mLedgerManager.getExpectedLedgerCloseTime();

    // bootstrap with a pessimistic estimate of when
    // the ballot protocol started last
    auto now = mApp.getClock().now();
    auto lastBallotStart = now - milliseconds;
    auto lastStart = mHerderSCPDriver.getPrepareStart(lastIndex);
    if (lastStart)
    {
        lastBallotStart = *lastStart;
    }

    // Adjust trigger time in case node's clock has drifted.
    // This ensures that next value to nominate is valid
    auto triggerTime = lastBallotStart + milliseconds;

    if (triggerTime < now)
    {
        triggerTime = now;
    }

    auto triggerOffset = std::chrono::duration_cast<std::chrono::milliseconds>(
        triggerTime - now);

    auto minCandidateCt = lcl.header.scpValue.closeTime + 1;
    auto ctOffset = ctValidityOffset(minCandidateCt, triggerOffset);

    if (ctOffset > std::chrono::milliseconds::zero())
    {
        CLOG_INFO(Herder, "Adjust trigger time by {} ms", ctOffset.count());
        triggerTime += ctOffset;
    }

    // even if ballot protocol started before triggering, we just use that
    // time as reference point for triggering again (this may trigger right
    // away if externalizing took a long time)
    mTriggerTimer.expires_at(triggerTime);

    if (!mApp.getConfig().MANUAL_CLOSE)
    {
        mTriggerTimer.async_wait(std::bind(&HerderImpl::triggerNextLedger, this,
                                           static_cast<uint32_t>(nextIndex),
                                           true),
                                 &VirtualTimer::onFailureNoop);
    }

#ifdef BUILD_TESTS
    mTriggerNextLedgerSeq = static_cast<uint32_t>(nextIndex);
#endif
}

void
HerderImpl::eraseBelow(uint32 ledgerSeq)
{
    auto lastCheckpointSeq = getMostRecentCheckpointSeq();
    getHerderSCPDriver().purgeSlots(ledgerSeq, lastCheckpointSeq);
    mPendingEnvelopes.eraseBelow(ledgerSeq, lastCheckpointSeq);
    auto lastIndex = trackingConsensusLedgerIndex();
    mApp.getOverlayManager().clearLedgersBelow(ledgerSeq, lastIndex);
}

bool
HerderImpl::recvSCPQuorumSet(Hash const& hash, SCPQuorumSet const& qset)
{
    ZoneScoped;
    return mPendingEnvelopes.recvSCPQuorumSet(hash, qset);
}

bool
HerderImpl::recvTxSet(Hash const& hash, TxSetXDRFrameConstPtr txset)
{
    ZoneScoped;
    return mPendingEnvelopes.recvTxSet(hash, txset);
}

TxSetXDRFrameConstPtr
HerderImpl::getTxSet(Hash const& hash)
{
    return mPendingEnvelopes.getTxSet(hash);
}

SCPQuorumSetPtr
HerderImpl::getQSet(Hash const& qSetHash)
{
    return mHerderSCPDriver.getQSet(qSetHash);
}

uint32
HerderImpl::getMinLedgerSeqToAskPeers() const
{
    // computes the smallest ledger for which we *think* we need more SCP
    // messages
    // we ask for messages older than lcl in case they have SCP
    // messages needed by other peers
    auto low = mApp.getLedgerManager().getLastClosedLedgerNum() + 1;

    auto maxSlots = std::min<uint32>(mApp.getConfig().MAX_SLOTS_TO_REMEMBER,
                                     SCP_EXTRA_LOOKBACK_LEDGERS);

    if (low > maxSlots)
    {
        low -= maxSlots;
    }
    else
    {
        low = LedgerManager::GENESIS_LEDGER_SEQ;
    }

    // do not ask for slots we'd be dropping anyways
    auto herderLow = getMinLedgerSeqToRemember();
    low = std::max<uint32>(low, herderLow);

    return low;
}

uint32_t
HerderImpl::getMostRecentCheckpointSeq()
{
    auto lastIndex = trackingConsensusLedgerIndex();
    return HistoryManager::firstLedgerInCheckpointContaining(lastIndex,
                                                             mApp.getConfig());
}

void
HerderImpl::setInSyncAndTriggerNextLedger()
{
    // We either have not set trigger timer, or we're in the
    // middle of a consensus round. Either way, we do not want
    // to trigger ledger, as the node is already making progress
    if (mTriggerTimer.seq() > 0)
    {
        CLOG_DEBUG(Herder, "Skipping setInSyncAndTriggerNextLedger: "
                           "trigger timer already set");
        return;
    }

    // Bring Herder and LM in sync in case they aren't
    if (mLedgerManager.getState() == LedgerManager::LM_BOOTING_STATE)
    {
        mLedgerManager.moveToSynced();
    }

    // Trigger next ledger, without requiring Herder to properly track SCP
    auto lcl = mLedgerManager.getLastClosedLedgerNum();
    triggerNextLedger(lcl + 1, false);
}

// called to take a position during the next round
// uses the state in LedgerManager to derive a starting position
void
HerderImpl::triggerNextLedger(uint32_t ledgerSeqToTrigger,
                              bool checkTrackingSCP)
{
    ZoneScoped;
    ZoneValue(static_cast<int64_t>(ledgerSeqToTrigger));

    auto isTrackingValid = isTracking() || !checkTrackingSCP;

    if (!isTrackingValid || !mLedgerManager.isSynced())
    {
        CLOG_DEBUG(Herder, "triggerNextLedger: skipping (out of sync) : {}",
                   mApp.getStateHuman());
        return;
    }

    // If applying, the next ledger will trigger voting
    if (mLedgerManager.isApplying())
    {
        // This can only happen when closing ledgers in parallel
        releaseAssert(mApp.getConfig().parallelLedgerClose());
        CLOG_DEBUG(Herder, "triggerNextLedger: skipping (applying) : {}",
                   mApp.getStateHuman());
        return;
    }

    // our first choice for this round's set is all the tx we have collected
    // during last few ledger closes
    // Since we are not currently applying, it is safe to use read-only LCL, as
    // it's guaranteed to be up-to-date
    auto lcl = mLedgerManager.getLastClosedLedgerHeader();

    // We pick as next close time the current time unless it's before the last
    // close time. We don't know how much time it will take to reach consensus
    // so this is the most appropriate value to use as closeTime.
    uint64_t nextCloseTime =
        VirtualClock::to_time_t(mApp.getClock().system_now());
    if (ledgerSeqToTrigger == lcl.header.ledgerSeq + 1)
    {
        auto it = mDriftCTSlidingWindow.find(ledgerSeqToTrigger);
        if (it == mDriftCTSlidingWindow.end())
        {
            // Record local close time _before_ it gets adjusted to be valid
            // below
            mDriftCTSlidingWindow[ledgerSeqToTrigger] =
                std::make_pair(nextCloseTime, std::nullopt);
            while (mDriftCTSlidingWindow.size() >
                   CLOSE_TIME_DRIFT_LEDGER_WINDOW_SIZE)
            {
                mDriftCTSlidingWindow.erase(mDriftCTSlidingWindow.begin());
            }
        }
        else
        {
            CLOG_WARNING(Herder,
                         "Herder::triggerNextLedger called twice on ledger {}",
                         ledgerSeqToTrigger);
        }
    }

    if (nextCloseTime <= lcl.header.scpValue.closeTime)
    {
        nextCloseTime = lcl.header.scpValue.closeTime + 1;
    }

    // Ensure we're about to nominate a value with valid close time
    auto isCtValid =
        ctValidityOffset(nextCloseTime) == std::chrono::milliseconds::zero();

    if (!isCtValid)
    {
        CLOG_WARNING(Herder,
                     "Invalid close time selected ({}), skipping nomination",
                     nextCloseTime);
        return;
    }

    // Protocols including the "closetime change" (CAP-0034) externalize
    // the exact closeTime contained in the StellarValue with the best
    // transaction set, so we know the exact closeTime against which to
    // validate here -- 'nextCloseTime'.  (The _offset_, therefore, is
    // the difference between 'nextCloseTime' and the last ledger close time.)
    TimePoint upperBoundCloseTimeOffset, lowerBoundCloseTimeOffset;
    upperBoundCloseTimeOffset = nextCloseTime - lcl.header.scpValue.closeTime;
    lowerBoundCloseTimeOffset = upperBoundCloseTimeOffset;

    TxSetXDRFrameConstPtr proposedSet;
    ApplicableTxSetFrameConstPtr applicableProposedSet;
    Hash txSetHash;

    // Build TX set from Rust overlay's mempool (not local TransactionQueue)
    // The Rust overlay maintains the mempool via TX flooding
    PerPhaseTransactionList txPhases;

    // Get TXs from Rust overlay
    auto& overlayMgr = mApp.getOverlayManager();
    auto txEnvelopes = overlayMgr.getTopTransactions(
        mApp.getLedgerManager().getLastMaxTxSetSizeOps() * 2, 5000);

    CLOG_INFO(Herder, "Got {} transactions from Rust overlay mempool",
              txEnvelopes.size());

    // Convert TransactionEnvelopes to TransactionFrameBasePtrs
    TxFrameList classicTxs;
    Hash const& networkID = mApp.getNetworkID();
    for (auto const& env : txEnvelopes)
    {
        auto txFrame =
            TransactionFrameBase::makeTransactionFromWire(networkID, env);
        classicTxs.push_back(txFrame);
    }
    txPhases.emplace_back(std::move(classicTxs));
    if (protocolVersionStartsFrom(lcl.header.ledgerVersion,
                                  SOROBAN_PROTOCOL_VERSION))
    {
        txPhases.emplace_back(); // empty Soroban phase
    }

    PerPhaseTransactionList invalidTxPhases;
    invalidTxPhases.resize(txPhases.size());

    std::tie(proposedSet, applicableProposedSet) =
        makeTxSetFromTransactions(txPhases, mApp, lowerBoundCloseTimeOffset,
                                  upperBoundCloseTimeOffset, invalidTxPhases);
    CLOG_INFO(Herder, "Proposed TX set has {} transactions",
              proposedSet->sizeTxTotal());

    if (!applicableProposedSet)
    {
        releaseAssert(!mApp.getConfig().FORCE_SCP);
        return;
    }

    txSetHash = proposedSet->getContentsHash();

    CLOG_INFO(Herder, "Built TX set: hash={}",
              binToHex(txSetHash).substr(0, 8));

    // New proposed tx set must be valid, so we explicitly populate tx set
    // validity cache so SCP can reuse the result.
    mHerderSCPDriver.cacheValidTxSet(*applicableProposedSet, lcl,
                                     upperBoundCloseTimeOffset);

    // Inform the item fetcher so queries from other peers about his txSet
    // can be answered. Note this can trigger SCP callbacks, externalize, etc
    // if we happen to build a txset that we were trying to download.
    mPendingEnvelopes.addTxSet(txSetHash, lcl.header.ledgerSeq + 1,
                               proposedSet);

    // Cache the TX set in Rust overlay so it can serve it to other peers.
    // When a peer receives an SCP message referencing this TX set hash,
    // they'll request it via TX set fetching, and Rust needs the XDR.
    // Note: Rust overlay only supports GeneralizedTransactionSet (protocol >= 20)
    if (proposedSet->isGeneralizedTxSet())
    {
        GeneralizedTransactionSet xdrTxSet;
        proposedSet->toXDR(xdrTxSet);
        auto xdrBytes = xdr::xdr_to_opaque(xdrTxSet);
        mApp.getOverlayManager().cacheTxSet(txSetHash, xdrBytes);
    }

    lcl = mLedgerManager.getLastClosedLedgerHeader();
    // use the slot index from ledger manager here as our vote is based off
    // the last closed ledger stored in ledger manager
    uint32_t slotIndex = lcl.header.ledgerSeq + 1;

    // no point in sending out a prepare:
    // externalize was triggered on a more recent ledger
    // Also skip trigger if side effects from `addTxSet` caused us to start
    // applying
    if (ledgerSeqToTrigger != slotIndex || mLedgerManager.isApplying())
    {
        return;
    }

    auto newUpgrades = emptyUpgradeSteps;

    // see if we need to include some upgrades
    std::vector<LedgerUpgrade> upgrades;
    {
        LedgerSnapshot ls(mApp);
        upgrades = mUpgrades.createUpgradesFor(lcl.header, ls, mApp.getConfig());
    }
    for (auto const& upgrade : upgrades)
    {
        Value v(xdr::xdr_to_opaque(upgrade));
        if (v.size() >= UpgradeType::max_size())
        {
            CLOG_ERROR(
                Herder,
                "HerderImpl::triggerNextLedger exceeded size for upgrade "
                "step (got {} ) for upgrade type {}",
                v.size(), upgrade.type());
            CLOG_ERROR(Herder, "{}", REPORT_INTERNAL_BUG);
        }
        else
        {
            newUpgrades.emplace_back(v.begin(), v.end());
        }
    }

    getHerderSCPDriver().recordSCPEvent(slotIndex, true);

    // If we are not a validating node we stop here and don't start nomination
    if (!getSCP().isValidator())
    {
        CLOG_DEBUG(Herder, "Non-validating node, skipping nomination (SCP).");
        return;
    }

    StellarValue newProposedValue = makeStellarValue(
        txSetHash, nextCloseTime, newUpgrades, mApp.getConfig().NODE_SEED);
    mHerderSCPDriver.nominate(slotIndex, newProposedValue, proposedSet,
                              lcl.header.scpValue);
}

void
HerderImpl::setUpgrades(Upgrades::UpgradeParameters const& upgrades)
{
    mUpgrades.setParameters(upgrades, mApp.getConfig());
    persistUpgrades();

    auto desc = mUpgrades.toString();

    if (!desc.empty())
    {
        auto message =
            fmt::format(FMT_STRING("Armed with network upgrades: {}"), desc);
        auto prev = mApp.getStatusManager().getStatusMessage(
            StatusCategory::REQUIRES_UPGRADES);
        if (prev != message)
        {
            CLOG_INFO(Herder, "{}", message);
            mApp.getStatusManager().setStatusMessage(
                StatusCategory::REQUIRES_UPGRADES, message);
        }
    }
    else
    {
        CLOG_INFO(Herder, "Network upgrades cleared");
        mApp.getStatusManager().removeStatusMessage(
            StatusCategory::REQUIRES_UPGRADES);
    }
}

std::string
HerderImpl::getUpgradesJson()
{
    auto ls = LedgerSnapshot(mApp);
    return mUpgrades.getParameters().toDebugJson(ls);
}

void
HerderImpl::forceSCPStateIntoSyncWithLastClosedLedger()
{
    auto const& header = mLedgerManager.getLastClosedLedgerHeader().header;
    setTrackingSCPState(header.ledgerSeq, header.scpValue,
                        /* isTrackingNetwork */ true);
}

bool
HerderImpl::resolveNodeID(std::string const& s, PublicKey& retKey)
{
    bool r = mApp.getConfig().resolveNodeID(s, retKey);
    if (!r)
    {
        if (s.size() > 1 && s[0] == '@')
        {
            std::string arg = s.substr(1);
            getSCP().processSlotsDescendingFrom(
                std::numeric_limits<uint64>::max(), [&](uint64_t seq) {
                    getSCP().processCurrentState(
                        seq,
                        [&](SCPEnvelope const& e) {
                            std::string curK =
                                KeyUtils::toStrKey(e.statement.nodeID);
                            if (curK.compare(0, arg.size(), arg) == 0)
                            {
                                retKey = e.statement.nodeID;
                                r = true;
                                return false;
                            }
                            return true;
                        },
                        true);

                    return !r;
                });
        }
    }
    return r;
}

Json::Value
HerderImpl::getJsonInfo(size_t limit, bool fullKeys)
{
    Json::Value ret;
    ret["you"] = mApp.getConfig().toStrKey(
        mApp.getConfig().NODE_SEED.getPublicKey(), fullKeys);

    ret["scp"] = getSCP().getJsonInfo(limit, fullKeys);
    ret["queue"] = mPendingEnvelopes.getJsonInfo(limit);
    return ret;
}

Json::Value
HerderImpl::getJsonTransitiveQuorumIntersectionInfo(bool fullKeys) const
{
    Json::Value ret;
    ret["intersection"] =
        mLastQuorumMapIntersectionState->enjoysQuorunIntersection();
    ret["node_count"] =
        static_cast<Json::UInt64>(mLastQuorumMapIntersectionState->mNumNodes);
    ret["last_check_ledger"] = static_cast<Json::UInt64>(
        mLastQuorumMapIntersectionState->mLastCheckLedger);
    if (mLastQuorumMapIntersectionState->enjoysQuorunIntersection())
    {
        Json::Value critical;
        for (auto const& group :
             mLastQuorumMapIntersectionState->mIntersectionCriticalNodes)
        {
            Json::Value jg;
            for (auto const& k : group)
            {
                auto s = mApp.getConfig().toStrKey(k, fullKeys);
                jg.append(s);
            }
            critical.append(jg);
        }
        ret["critical"] = critical;
    }
    else
    {
        ret["last_good_ledger"] = static_cast<Json::UInt64>(
            mLastQuorumMapIntersectionState->mLastGoodLedger);
        Json::Value split, a, b;
        auto const& pair = mLastQuorumMapIntersectionState->mPotentialSplit;
        for (auto const& k : pair.first)
        {
            auto s = mApp.getConfig().toStrKey(k, fullKeys);
            a.append(s);
        }
        for (auto const& k : pair.second)
        {
            auto s = mApp.getConfig().toStrKey(k, fullKeys);
            b.append(s);
        }
        split.append(a);
        split.append(b);
        ret["potential_split"] = split;
    }
    return ret;
}

Json::Value
HerderImpl::getJsonQuorumInfo(NodeID const& id, bool summary, bool fullKeys,
                              uint64 index)
{
    Json::Value ret;
    ret["node"] = mApp.getConfig().toStrKey(id, fullKeys);
    ret["qset"] = getSCP().getJsonQuorumInfo(id, summary, fullKeys, index);

    bool isSelf = id == mApp.getConfig().NODE_SEED.getPublicKey();
    if (isSelf)
    {
        if (mLastQuorumMapIntersectionState->hasAnyResults())
        {
            ret["transitive"] =
                getJsonTransitiveQuorumIntersectionInfo(fullKeys);
        }

        ret["qset"]["lag_ms"] =
            getHerderSCPDriver().getQsetLagInfo(summary, fullKeys);
        ret["qset"]["cost"] =
            mPendingEnvelopes.getJsonValidatorCost(summary, fullKeys, index);
        ret["maybe_dead_nodes"] = mHerderSCPDriver.getMaybeDeadNodes(fullKeys);
    }
    return ret;
}

Json::Value
HerderImpl::getJsonTransitiveQuorumInfo(NodeID const& rootID, bool summary,
                                        bool fullKeys)
{
    Json::Value ret;
    bool isSelf = rootID == mApp.getConfig().NODE_SEED.getPublicKey();
    if (isSelf && mLastQuorumMapIntersectionState->hasAnyResults())
    {
        ret = getJsonTransitiveQuorumIntersectionInfo(fullKeys);
    }

    Json::Value& nodes = ret["nodes"];

    auto& q = mPendingEnvelopes.getCurrentlyTrackedQuorum();

    auto rootLatest = getSCP().getLatestMessage(rootID);
    std::map<Value, int> knownValues;

    // walk the quorum graph, starting at id
    UnorderedSet<NodeID> visited;
    std::vector<NodeID> next;
    next.push_back(rootID);
    visited.emplace(rootID);
    int distance = 0;
    int valGenID = 0;
    while (!next.empty())
    {
        std::vector<NodeID> frontier(std::move(next));
        next.clear();
        std::sort(frontier.begin(), frontier.end());
        for (auto const& id : frontier)
        {
            Json::Value cur;
            valGenID++;
            cur["node"] = mApp.getConfig().toStrKey(id, fullKeys);
            if (!summary)
            {
                cur["distance"] = distance;
            }
            auto it = q.find(id);
            std::string status;
            if (it != q.end())
            {
                auto qSet = it->second.mQuorumSet;
                if (qSet)
                {
                    if (!summary)
                    {
                        cur["qset"] =
                            getSCP().getLocalNode()->toJson(*qSet, fullKeys);
                    }
                    LocalNode::forAllNodes(*qSet, [&](NodeID const& n) {
                        auto b = visited.emplace(n);
                        if (b.second)
                        {
                            next.emplace_back(n);
                        }
                        return true;
                    });
                }
                auto latest = getSCP().getLatestMessage(id);
                if (latest)
                {
                    auto vals = Slot::getStatementValues(latest->statement);
                    // updates the `knownValues` map, and generate a unique ID
                    // for the value (heuristic to group votes)
                    int trackingValID = -1;
                    Value const* trackingValue = nullptr;
                    for (auto const& v : vals)
                    {
                        auto p =
                            knownValues.insert(std::make_pair(v, valGenID));
                        if (p.first->second > trackingValID)
                        {
                            trackingValID = p.first->second;
                            trackingValue = &v;
                        }
                    }

                    cur["heard"] =
                        static_cast<Json::UInt64>(latest->statement.slotIndex);
                    if (!summary)
                    {
                        cur["value"] = trackingValue
                                           ? mHerderSCPDriver.getValueString(
                                                 *trackingValue)
                                           : "";
                        cur["value_id"] = trackingValID;
                    }
                    // give a sense of how this node is doing compared to rootID
                    if (rootLatest)
                    {
                        if (latest->statement.slotIndex <
                            rootLatest->statement.slotIndex)
                        {
                            status = "behind";
                        }
                        else if (latest->statement.slotIndex >
                                 rootLatest->statement.slotIndex)
                        {
                            status = "ahead";
                        }
                        else
                        {
                            status = "tracking";
                        }
                    }
                }
                else
                {
                    status = "missing";
                }
            }
            else
            {
                status = "unknown";
            }
            cur["status"] = status;
            nodes.append(cur);
        }
        distance++;
    }
    ret["maybe_dead_nodes"] = mHerderSCPDriver.getMaybeDeadNodes(fullKeys);
    return ret;
}

QuorumTracker::QuorumMap const&
HerderImpl::getCurrentlyTrackedQuorum() const
{
    return mPendingEnvelopes.getCurrentlyTrackedQuorum();
}

static Hash
getQmapHash(QuorumTracker::QuorumMap const& qmap)
{
    ZoneScoped;
    SHA256 hasher;
    std::map<NodeID, QuorumTracker::NodeInfo> ordered_map(qmap.begin(),
                                                          qmap.end());
    for (auto const& pair : ordered_map)
    {
        hasher.add(xdr::xdr_to_opaque(pair.first));
        if (pair.second.mQuorumSet)
        {
            hasher.add(xdr::xdr_to_opaque(*(pair.second.mQuorumSet)));
        }
        else
        {
            hasher.add("\0");
        }
    }
    return hasher.finish();
}

void
HerderImpl::checkAndMaybeReanalyzeQuorumMapV2()
{
    ZoneScoped;
    if (!mApp.getConfig().QUORUM_INTERSECTION_CHECKER)
    {
        return;
    }
    auto& qmap = getCurrentlyTrackedQuorum();
    Hash curr = getQmapHash(qmap);
    if (mLastQuorumMapIntersectionState->mLastCheckQuorumMapHash == curr)
    {
        // Everything's stable, nothing to do.
        return;
    }
    if (mLastQuorumMapIntersectionState->mRecalculating)
    {
        if (mLastQuorumMapIntersectionState->mCheckingQuorumMapHash == curr)
        {
            CLOG_DEBUG(Herder, "Transitive closure of quorum has "
                               "changed, already analyzing new "
                               "configuration.");
        }
        else
        {
            CLOG_DEBUG(Herder, "Transitive closure of quorum has changed,"
                               "however the previous analysis is still "
                               "in progress, the new analysis will start after "
                               "the previous one finishes or gets interrupted "
                               "by the timer");
        }
        return;
    }

    CLOG_INFO(Herder,
              "Transitive closure of quorum has changed, re-analyzing.");
    mLastQuorumMapIntersectionState->reset(mApp);
    mLastQuorumMapIntersectionState->mRecalculating = true;
    mLastQuorumMapIntersectionState->mCheckingQuorumMapHash = curr;
    quorum_checker::runQuorumIntersectionCheckAsync(
        mApp, curr, trackingConsensusLedgerIndex(),
        mLastQuorumMapIntersectionState->mTmpDir->getName(), qmap,
        mLastQuorumMapIntersectionState, mApp.getProcessManager(),
        mApp.getConfig().QUORUM_INTERSECTION_CHECKER_TIME_LIMIT_MS,
        mApp.getConfig().QUORUM_INTERSECTION_CHECKER_MEMORY_LIMIT_BYTES,
        true /*analyzeCriticalGroups*/);
}

void
HerderImpl::checkAndMaybeReanalyzeQuorumMap()
{
    if (!mApp.getConfig().QUORUM_INTERSECTION_CHECKER)
    {
        return;
    }
    ZoneScoped;
    QuorumTracker::QuorumMap const& qmap = getCurrentlyTrackedQuorum();
    Hash curr = getQmapHash(qmap);
    if (mLastQuorumMapIntersectionState->mLastCheckQuorumMapHash == curr)
    {
        // Everything's stable, nothing to do.
        return;
    }

    if (mLastQuorumMapIntersectionState->mRecalculating)
    {
        // Already recalculating. If we're recalculating for the hash we want,
        // we do nothing, just wait for it to finish. If we're recalculating for
        // a hash that has changed _again_ (since the calculation started), we
        // _interrupt_ the calculation-in-progress: we'll return to this
        // function on the next externalize and start a new calculation for the
        // new hash we want.
        if (mLastQuorumMapIntersectionState->mCheckingQuorumMapHash == curr)
        {
            CLOG_DEBUG(Herder, "Transitive closure of quorum has "
                               "changed, already analyzing new "
                               "configuration.");
        }
        else
        {
            CLOG_DEBUG(Herder, "Transitive closure of quorum has "
                               "changed, interrupting existing "
                               "analysis.");
            mLastQuorumMapIntersectionState->mInterruptFlag = true;
        }
    }
    else
    {
        CLOG_INFO(Herder,
                  "Transitive closure of quorum has changed, re-analyzing.");
        // Not currently recalculating: start doing so.
        mLastQuorumMapIntersectionState->mRecalculating = true;
        mLastQuorumMapIntersectionState->mInterruptFlag = false;
        mLastQuorumMapIntersectionState->mCheckingQuorumMapHash = curr;
        auto& cfg = mApp.getConfig();
        auto seed = getGlobalRandomEngine()();

        auto ledger = trackingConsensusLedgerIndex();
        auto nNodes = qmap.size();
        auto hState = mLastQuorumMapIntersectionState;
        auto& app = mApp;
        auto worker = [curr, ledger, nNodes, qmap, cfg, seed, &app, hState] {
            try
            {
                ZoneScoped;
                bool ok = false;
                std::pair<std::vector<PublicKey>, std::vector<PublicKey>> split;
                auto qic = QuorumIntersectionChecker::create(
                    qmap, cfg, hState->mInterruptFlag, seed);
                ok = qic->networkEnjoysQuorumIntersection();
                split = qic->getPotentialSplit();
                std::set<std::set<PublicKey>> critical;
                if (ok)
                {
                    // Only bother calculating the _critical_ groups if we're
                    // intersecting; if not intersecting we should finish ASAP
                    // and raise an alarm.
                    auto cb = [&hState, seed](
                                  QuorumIntersectionChecker::QuorumSetMap const&
                                      qSetMap,
                                  std::optional<Config> const& config) -> bool {
                        auto checker = QuorumIntersectionChecker::create(
                            qSetMap, config, hState->mInterruptFlag, seed,
                            /*quiet=*/true);
                        return checker->networkEnjoysQuorumIntersection();
                    };
                    critical = QuorumIntersectionChecker::
                        getIntersectionCriticalGroups(
                            toQuorumIntersectionMap(qmap), cfg, cb);
                }
                app.postOnMainThread(
                    [ok, curr, ledger, nNodes, split, critical, hState, &app] {
                        hState->reset(app);

                        hState->mNumNodes = nNodes;
                        hState->mLastCheckLedger = ledger;
                        hState->mLastCheckQuorumMapHash = curr;
                        hState->mPotentialSplit = split;
                        hState->mIntersectionCriticalNodes = critical;
                        if (ok)
                        {
                            hState->mLastGoodLedger = ledger;
                        }
                    },
                    "QuorumIntersectionChecker finished");
            }
            catch (QuorumIntersectionChecker::InterruptedException&)
            {
                CLOG_DEBUG(Herder,
                           "Quorum transitive closure analysis interrupted.");
                app.postOnMainThread([hState, &app] { hState->reset(app); },
                                     "QuorumIntersectionChecker interrupted");
            }
            catch (RustQuorumCheckerError const& e)
            {
                CLOG_DEBUG(Herder,
                           "Quorum transitive closure analysis failed due to "
                           "Rust solver error: {}",
                           e.what());
                app.postOnMainThread([hState, &app] { hState->reset(app); },
                                     "QuorumIntersectionChecker rust error");
            }
        };
        mApp.postOnBackgroundThread(worker, "QuorumIntersectionChecker");
    }
}

void
HerderImpl::persistSCPState(uint64 slot)
{
    ZoneScoped;
    if (slot < mLastSlotSaved)
    {
        return;
    }

    mLastSlotSaved = slot;
    // saves SCP messages and related data (transaction sets, quorum sets)
    PersistedSCPState scpState;
    scpState.v(1);

    auto& latestEnvs = scpState.v1().scpEnvelopes;
    std::map<Hash, TxSetXDRFrameConstPtr> txSets;
    std::map<Hash, SCPQuorumSetPtr> quorumSets;

    for (auto const& e : getSCP().getLatestMessagesSend(slot))
    {
        latestEnvs.emplace_back(e);

        // saves transaction sets referred by the statement
        for (auto const& h : getValidatedTxSetHashes(e))
        {
            auto txSet = mPendingEnvelopes.getTxSet(h);
            if (txSet && !mApp.getPersistentState().hasTxSet(h))
            {
                txSets.insert(std::make_pair(h, txSet));
            }
        }
        Hash qsHash = Slot::getCompanionQuorumSetHashFromStatement(e.statement);
        SCPQuorumSetPtr qSet = mPendingEnvelopes.getQSet(qsHash);
        if (qSet)
        {
            quorumSets.insert(std::make_pair(qsHash, qSet));
        }
    }

    auto& latestQSets = scpState.v1().quorumSets;
    for (auto it : quorumSets)
    {
        latestQSets.emplace_back(*it.second);
    }

    stellar::Value latestSCPData;

    std::unordered_map<Hash, std::string> txSetsToPersist;
    for (auto it : txSets)
    {
        StoredTransactionSet tempTxSet;
        it.second->storeXDR(tempTxSet);
        txSetsToPersist.emplace(
            it.first, decoder::encode_b64(xdr::xdr_to_opaque(tempTxSet)));
    }

    latestSCPData = xdr::xdr_to_opaque(scpState);

    std::string encodedScpState = decoder::encode_b64(latestSCPData);

    mApp.getPersistentState().setSCPStateV1ForSlot(slot, encodedScpState,
                                                   txSetsToPersist);
}

void
HerderImpl::restoreSCPState()
{
    ZoneScoped;

    // Delete any old tx sets
    purgeOldPersistedTxSets();

    // Load all known tx sets
    auto latestTxSets = mApp.getPersistentState().getTxSetsForAllSlots();
    for (auto const& [_, txSet] : latestTxSets)
    {
        try
        {
            std::vector<uint8_t> buffer;
            decoder::decode_b64(txSet, buffer);

            StoredTransactionSet storedSet;
            xdr::xdr_from_opaque(buffer, storedSet);
            TxSetXDRFrameConstPtr cur =
                TxSetXDRFrame::makeFromStoredTxSet(storedSet);
            Hash h = cur->getContentsHash();
            mPendingEnvelopes.addTxSet(h, 0, cur);
        }
        catch (std::exception& e)
        {
            // we may have exceptions when upgrading the protocol
            // this should be the only time we get exceptions decoding old
            // messages.
            CLOG_INFO(Herder,
                      "Error while restoring old tx sets, "
                      "proceeding without them : {}",
                      e.what());
        }
    }

    // load saved state from database
    auto latest64 = mApp.getPersistentState().getSCPStateAllSlots();

    for (auto const& [_, state] : latest64)
    {
        try
        {
            std::vector<uint8_t> buffer;
            decoder::decode_b64(state, buffer);

            PersistedSCPState scpState;
            xdr::xdr_from_opaque(buffer, scpState);
            for (auto const& qset : scpState.v1().quorumSets)
            {
                Hash hash = xdrSha256(qset);
                mPendingEnvelopes.addSCPQuorumSet(hash, qset);
            }
            for (auto const& e : scpState.v1().scpEnvelopes)
            {
                auto envW = getHerderSCPDriver().wrapEnvelope(e);
                getSCP().setStateFromEnvelope(e.statement.slotIndex, envW);
                mLastSlotSaved =
                    std::max<uint64>(mLastSlotSaved, e.statement.slotIndex);
            }
        }
        catch (std::exception& e)
        {
            // we may have exceptions when upgrading the protocol
            // this should be the only time we get exceptions decoding old
            // messages.
            CLOG_INFO(Herder,
                      "Error while restoring old scp messages, "
                      "proceeding without them : {}",
                      e.what());
        }
        mPendingEnvelopes.rebuildQuorumTrackerState();
    }
}

void
HerderImpl::persistUpgrades()
{
    ZoneScoped;
    releaseAssert(threadIsMain());
    auto s = mUpgrades.getParameters().toJson();
    mApp.getPersistentState().setMiscState(PersistentState::kLedgerUpgrades, s);
}

void
HerderImpl::restoreUpgrades()
{
    ZoneScoped;
    releaseAssert(threadIsMain());

    std::string s = mApp.getPersistentState().getState(
        PersistentState::kLedgerUpgrades, mApp.getDatabase().getMiscSession());
    if (!s.empty())
    {
        Upgrades::UpgradeParameters p;

        p.fromJson(s);
        try
        {
            // use common code to set status
            setUpgrades(p);
        }
        catch (std::exception& e)
        {
            CLOG_INFO(Herder,
                      "Error restoring upgrades '{}' with upgrades '{}'",
                      e.what(), s);
        }
    }
}

void
HerderImpl::maybeHandleUpgrade()
{
    ZoneScoped;

    uint32_t diff = 0;
    {
        if (protocolVersionIsBefore(mApp.getLedgerManager()
                                        .getLastClosedLedgerHeader()
                                        .header.ledgerVersion,
                                    SOROBAN_PROTOCOL_VERSION))
        {
            // no-op on any earlier protocol
            return;
        }
        auto const& conf =
            mApp.getLedgerManager().getLastClosedSorobanNetworkConfig();

        auto maybeNewMaxTxSize = saturatingAdd<uint32_t>(
            conf.txMaxSizeBytes(), getFlowControlExtraBuffer());
        if (maybeNewMaxTxSize > mMaxTxSize)
        {
            diff = maybeNewMaxTxSize - mMaxTxSize;
        }
        // mMaxTxSize may decrease post-upgrade, always choose the max between
        // classic tx size (static) and Soroban max tx size
        mMaxTxSize = std::max(getMaxClassicTxSize(), maybeNewMaxTxSize);
    }

    // Note: With Rust overlay, no per-peer notifications needed here
    // The overlay handles message sizes internally
}

void
HerderImpl::start()
{
    mMaxTxSize = mApp.getHerder().getMaxClassicTxSize();
    {
        uint32_t version = mApp.getLedgerManager()
                               .getLastClosedLedgerHeader()
                               .header.ledgerVersion;
        if (protocolVersionStartsFrom(version, SOROBAN_PROTOCOL_VERSION))
        {
            auto const& conf =
                mApp.getLedgerManager().getLastClosedSorobanNetworkConfig();
            mMaxTxSize =
                std::max(mMaxTxSize,
                         saturatingAdd<uint32_t>(conf.txMaxSizeBytes(),
                                                 getFlowControlExtraBuffer()));
        }
    }

    auto const& cfg = mApp.getConfig();
    // Core will calculate default values automatically
    bool calculateDefaults = cfg.PEER_FLOOD_READING_CAPACITY_BYTES == 0 &&
                             cfg.FLOW_CONTROL_SEND_MORE_BATCH_SIZE_BYTES == 0;

    if (!calculateDefaults &&
        !(cfg.PEER_FLOOD_READING_CAPACITY_BYTES -
              cfg.FLOW_CONTROL_SEND_MORE_BATCH_SIZE_BYTES >=
          mMaxTxSize))
    {
        std::string msg = fmt::format(
            "Invalid configuration: the difference between "
            "PEER_FLOOD_READING_CAPACITY_BYTES ({}) and "
            "FLOW_CONTROL_SEND_MORE_BATCH_SIZE_BYTES ({}) must be at"
            " least {} bytes",
            cfg.PEER_FLOOD_READING_CAPACITY_BYTES,
            cfg.FLOW_CONTROL_SEND_MORE_BATCH_SIZE_BYTES, mMaxTxSize);
        throw std::runtime_error(msg);
    }

    // setup a sufficient state that we can participate in consensus
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();

    if (!mApp.getConfig().FORCE_SCP &&
        lcl.header.ledgerSeq == LedgerManager::GENESIS_LEDGER_SEQ)
    {
        // if we're on genesis ledger, there is no point in claiming
        // that we're "in sync"
        setTrackingSCPState(lcl.header.ledgerSeq, lcl.header.scpValue,
                            /* isTrackingNetwork */ false);
    }
    else
    {
        setTrackingSCPState(lcl.header.ledgerSeq, lcl.header.scpValue,
                            /* isTrackingNetwork */ true);
        trackingHeartBeat();
        // Load SCP state from the database
        restoreSCPState();
    }

    restoreUpgrades();
    startTxSetGCTimer();
    startCheckForDeadNodesInterval();

    // RustOverlayManager is started automatically in OverlayManager::start()
    // which is called by ApplicationImpl::start() before Herder::start()
}

void
HerderImpl::startTxSetGCTimer()
{
    mTxSetGarbageCollectTimer.expires_from_now(TX_SET_GC_DELAY);
    mTxSetGarbageCollectTimer.async_wait(
        [this]() { purgeOldPersistedTxSets(); }, &VirtualTimer::onFailureNoop);
}

void
HerderImpl::purgeOldPersistedTxSets()
{
    ZoneScoped;

    try
    {
        auto hashesToDelete =
            mApp.getPersistentState().getTxSetHashesForAllSlots();
        for (auto const& [_, state] :
             mApp.getPersistentState().getSCPStateAllSlots())
        {
            try
            {
                std::vector<uint8_t> buffer;
                decoder::decode_b64(state, buffer);

                PersistedSCPState scpState;
                xdr::xdr_from_opaque(buffer, scpState);
                for (auto const& e : scpState.v1().scpEnvelopes)
                {
                    for (auto const& hash : getValidatedTxSetHashes(e))
                    {
                        hashesToDelete.erase(hash);
                    }
                }
            }
            catch (std::exception& e)
            {
                CLOG_ERROR(Herder, "Error while deleting old tx sets: {}",
                           e.what());
            }
        }
        mApp.getPersistentState().deleteTxSets(hashesToDelete);
        startTxSetGCTimer();
    }
    catch (std::exception& e)
    {
        CLOG_ERROR(Herder, "Error while deleting old tx sets: {}", e.what());
    }
}

void
HerderImpl::startCheckForDeadNodesInterval()
{
    mCheckForDeadNodesTimer.expires_from_now(CHECK_FOR_DEAD_NODES_MINUTES);
    mCheckForDeadNodesTimer.async_wait(
        [this]() {
            mHerderSCPDriver.startCheckForDeadNodesInterval();
            startCheckForDeadNodesInterval();
        },
        &VirtualTimer::onFailureNoop);
}

void
HerderImpl::trackingHeartBeat()
{
    releaseAssert(threadIsMain());
    if (mApp.getConfig().MANUAL_CLOSE)
    {
        return;
    }

    mOutOfSyncTimer.cancel();

    releaseAssert(isTracking());

    mTrackingTimer.expires_from_now(
        std::chrono::seconds(CONSENSUS_STUCK_TIMEOUT_SECONDS));
    mTrackingTimer.async_wait(
        [this]() {
            if (mApp.getLedgerManager().isApplying())
            {
                // if we're applying a ledger, it's possible that we're just
                // slow and the timer expired; reset the timer and wait until we
                // finished application
                trackingHeartBeat();
            }
            else
            {
                herderOutOfSync();
            }
        },
        &VirtualTimer::onFailureNoop);
}

UnorderedSet<LedgerKey>
HerderImpl::recomputeKeysToFilter(uint32_t protocolVersion) const
{
    if (!gIsProductionNetwork)
    {
        return UnorderedSet<LedgerKey>{};
    }

    auto filteredSet = [](size_t count,
                          auto const& arr) mutable -> UnorderedSet<LedgerKey> {
        UnorderedSet<LedgerKey> result;
        for (size_t i = 0; i < count; ++i)
        {
            LedgerKey key;
            fromOpaqueBase64(key, arr[i]);
            result.insert(key);
        }
        return result;
    };
    return filteredSet(KEYS_TO_FILTER_P24_COUNT, KEYS_TO_FILTER_P24);
}

void
HerderImpl::herderOutOfSync()
{
    ZoneScoped;
    // State switch from "tracking" to "out of sync" should only happen if
    // there are no ledgers queued to be applied. If there are ledgers
    // queued, it's possible the rest of the network is waiting for this
    // node to vote. In this case we should _still_ remain in tracking and
    // emit nomination; If the node does not hear anything from the network
    // after that, then node can go into out of sync recovery.
    releaseAssert(threadIsMain());
    releaseAssert(!mLedgerManager.isApplying());

    CLOG_WARNING(Herder, "Lost track of consensus");

    auto s = getJsonInfo(20).toStyledString();
    CLOG_WARNING(Herder, "Out of sync context: {}", s);

    mSCPMetrics.mLostSync.Mark();
    lostSync();

    releaseAssert(getState() == Herder::HERDER_SYNCING_STATE);
    mPendingEnvelopes.reportCostOutliersForSlot(trackingConsensusLedgerIndex(),
                                                false);

    startOutOfSyncTimer();

    processSCPQueue();
}

void
HerderImpl::getMoreSCPState()
{
    ZoneScoped;
    auto low = getMinLedgerSeqToAskPeers();
    CLOG_INFO(Herder, "Requesting SCP state from peers, ledger >= {}", low);

    // Request SCP state via Rust overlay - it will ask random peers
    mApp.getOverlayManager().getOverlayIPC().requestScpState(low);
}

bool
HerderImpl::verifyEnvelope(SCPEnvelope const& envelope)
{
    ZoneScoped;
    auto [b, _] = PubKeyUtils::verifySig(
        envelope.statement.nodeID, envelope.signature,
        xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_SCP,
                           envelope.statement));
    if (b)
    {
        mSCPMetrics.mEnvelopeValidSig.Mark();
    }
    else
    {
        mSCPMetrics.mEnvelopeInvalidSig.Mark();
    }

    return b;
}
void
HerderImpl::signEnvelope(SecretKey const& s, SCPEnvelope& envelope)
{
    ZoneScoped;
    envelope.signature = s.sign(xdr::xdr_to_opaque(
        mApp.getNetworkID(), ENVELOPE_TYPE_SCP, envelope.statement));
}
bool
HerderImpl::verifyStellarValueSignature(StellarValue const& sv)
{
    ZoneScoped;
    auto [b, _] = PubKeyUtils::verifySig(
        sv.ext.lcValueSignature().nodeID, sv.ext.lcValueSignature().signature,
        xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_SCPVALUE,
                           sv.txSetHash, sv.closeTime));
    return b;
}

StellarValue
HerderImpl::makeStellarValue(Hash const& txSetHash, uint64_t closeTime,
                             xdr::xvector<UpgradeType, 6> const& upgrades,
                             SecretKey const& s)
{
    ZoneScoped;
    StellarValue sv;
    sv.ext.v(STELLAR_VALUE_SIGNED);
    sv.txSetHash = txSetHash;
    sv.closeTime = closeTime;
    sv.upgrades = upgrades;
    sv.ext.lcValueSignature().nodeID = s.getPublicKey();
    sv.ext.lcValueSignature().signature =
        s.sign(xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_SCPVALUE,
                                  sv.txSetHash, sv.closeTime));
    return sv;
}

bool
HerderImpl::isNewerNominationOrBallotSt(SCPStatement const& oldSt,
                                        SCPStatement const& newSt)
{
    return getSCP().isNewerNominationOrBallotSt(oldSt, newSt);
}
}
