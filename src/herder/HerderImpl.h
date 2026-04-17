// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "herder/CompactTxSet.h"
#include "herder/Herder.h"
#include "herder/HerderSCPDriver.h"
#include "herder/LedgerCloseData.h"
#include "herder/PendingEnvelopes.h"
#include "herder/QuorumIntersectionChecker.h"
#include "herder/Upgrades.h"
#include "overlay/NetworkConstants.h"
#include "util/Timer.h"
#include "util/UnorderedMap.h"
#include "util/XDROperators.h"
#include <chrono>
#include <deque>
#include <memory>
#include <set>
#include <vector>

namespace medida
{
class Meter;
class Counter;
class Timer;
}

namespace stellar
{

class Application;
class LedgerManager;
class HerderSCPDriver;

/*
 * Is in charge of receiving transactions from the network.
 */
class HerderImpl : public Herder
{
  public:
    struct ConsensusData
    {
        uint64_t mConsensusIndex{0};
        TimePoint mConsensusCloseTime{0};
    };

    void setTrackingSCPState(uint64_t index, StellarValue const& value,
                             bool isTrackingNetwork) override;

    // returns the latest known ledger from the network, requires Herder to be
    // in fully booted state
    uint32 trackingConsensusLedgerIndex() const override;

    TimePoint trackingConsensusCloseTime() const;

    // the ledger index that we expect to externalize next
    uint32
    nextConsensusLedgerIndex() const
    {
        return trackingConsensusLedgerIndex() + 1;
    }

    void lostSync();

    HerderImpl(Application& app);
    ~HerderImpl();

    State getState() const override;
    std::string getStateHuman(State st) const override;

    void syncMetrics() override;

    // Bootstraps the HerderImpl if we're creating a new Network
    void bootstrap() override;
    void shutdown() override;

    void start() override;

    void lastClosedLedgerIncreased(bool latest, TxSetXDRFrameConstPtr txSet,
                                   bool queueRebuildNeeded) override;

    SCP& getSCP();
    HerderSCPDriver&
    getHerderSCPDriver()
    {
        return mHerderSCPDriver;
    }

    bool
    isTracking() const override
    {
        return mState == State::HERDER_TRACKING_NETWORK_STATE;
    }

    void processExternalized(uint64 slotIndex, StellarValue const& value,
                             bool isLatestSlot);
    void valueExternalized(uint64 slotIndex, StellarValue const& value,
                           bool isLatestSlot);
    void emitEnvelope(SCPEnvelope const& envelope);

#ifdef BUILD_TESTS
    TxSubmitStatus recvTransaction(TransactionFrameBasePtr tx,
                                   bool submittedFromSelf,
                                   bool isLoadgenTx = false) override;
#else
    TxSubmitStatus recvTransaction(TransactionFrameBasePtr tx,
                                   bool submittedFromSelf) override;
#endif

    EnvelopeStatus recvSCPEnvelope(SCPEnvelope const& envelope) override;
#ifdef BUILD_TESTS
    EnvelopeStatus recvSCPEnvelope(SCPEnvelope const& envelope,
                                   const SCPQuorumSet& qset,
                                   TxSetXDRFrameConstPtr txset) override;
    EnvelopeStatus recvSCPEnvelope(SCPEnvelope const& envelope,
                                   SCPQuorumSet const& qset,
                                   StellarMessage const& txset) override;

    void externalizeValue(TxSetXDRFrameConstPtr txSet, uint32_t ledgerSeq,
                          uint64_t closeTime,
                          xdr::xvector<UpgradeType, 6> const& upgrades,
                          std::optional<SecretKey> skToSignValue) override;

    VirtualTimer const&
    getTriggerTimer() const override
    {
        return mTriggerTimer;
    }

    uint32_t mTriggerNextLedgerSeq{0};

    std::optional<uint32_t> mMaxClassicTxSize;
    std::optional<uint32_t> mMaxTxSizeOverride;
    void
    setMaxClassicTxSize(uint32 bytes) override
    {
        mMaxClassicTxSize = std::make_optional<uint32_t>(bytes);
    }
    void
    setMaxTxSize(uint32 bytes) override
    {
        mMaxTxSizeOverride = bytes;
    }
    std::optional<uint32_t> mFlowControlExtraBuffer;
    void
    setFlowControlExtraBufferSize(uint32 bytes) override
    {
        mFlowControlExtraBuffer = std::make_optional<uint32_t>(bytes);
    }
#endif
    std::vector<SCPEnvelope> getSCPStateForPeer(uint32 ledgerSeq) override;

    bool recvSCPQuorumSet(Hash const& hash, SCPQuorumSet const& qset) override;
    bool recvTxSet(Hash const& hash, TxSetXDRFrameConstPtr txset) override;
    TxSetXDRFrameConstPtr getTxSet(Hash const& hash) override;
    SCPQuorumSetPtr getQSet(Hash const& qSetHash) override;

    void processSCPQueue();

    uint32_t getMaxClassicTxSize() const override;
    uint32_t getFlowControlExtraBuffer() const override;

    uint32_t
    getMaxTxSize() const override
    {
#ifdef BUILD_TESTS
        if (mMaxTxSizeOverride)
        {
            return *mMaxTxSizeOverride;
        }
#endif
        return mMaxTxSize;
    }

    uint32 getMinLedgerSeqToAskPeers() const override;

    uint32_t getMinLedgerSeqToRemember() const override;

    bool isNewerNominationOrBallotSt(SCPStatement const& oldSt,
                                     SCPStatement const& newSt) override;

    uint32_t getMostRecentCheckpointSeq() override;

    void triggerNextLedger(uint32_t ledgerSeqToTrigger,
                           bool checkTrackingSCP) override;

    void setInSyncAndTriggerNextLedger() override;

    void setUpgrades(Upgrades::UpgradeParameters const& upgrades) override;
    std::string getUpgradesJson() override;

    void forceSCPStateIntoSyncWithLastClosedLedger() override;

    bool resolveNodeID(std::string const& s, PublicKey& retKey) override;

    Json::Value getJsonInfo(size_t limit, bool fullKeys = false) override;
    Json::Value getJsonQuorumInfo(NodeID const& id, bool summary, bool fullKeys,
                                  uint64 index) override;
    Json::Value getJsonTransitiveQuorumIntersectionInfo(bool fullKeys) const;
    virtual Json::Value getJsonTransitiveQuorumInfo(NodeID const& id,
                                                    bool summary,
                                                    bool fullKeys) override;
    QuorumTracker::QuorumMap const& getCurrentlyTrackedQuorum() const override;

    virtual StellarValue
    makeStellarValue(Hash const& txSetHash, uint64_t closeTime,
                     xdr::xvector<UpgradeType, 6> const& upgrades,
                     SecretKey const& s) override;

    void startTxSetGCTimer();

#ifdef BUILD_TESTS
    PendingEnvelopes& getPendingEnvelopes();
    Upgrades const& getUpgrades() const;
#endif

    // helper function to verify envelopes are signed
    bool verifyEnvelope(SCPEnvelope const& envelope);
    // helper function to sign envelopes
    void signEnvelope(SecretKey const& s, SCPEnvelope& envelope);

    // helper function to verify SCPValues are signed
    bool verifyStellarValueSignature(StellarValue const& sv);

    void maybeHandleUpgrade() override;

    // --- Compact tx set receive-side handlers (called from IPC callbacks) ---

    void onCompactTxSetReceived(
        uint64_t senderId, std::vector<uint8_t> const& rawBytes,
        std::vector<ResolveResultEntry> const& resolved);

    void onGetCompactTxSetTxsReceived(uint64_t senderId,
                                      std::vector<uint8_t> const& rawBytes);

    void onRefillForwarded(Hash const& txSetHash, uint64_t nonce,
                           uint64_t senderId,
                           std::vector<uint8_t> const& packedShortIds,
                           std::vector<uint8_t> const& envelopeArrayBytes);

  private:
    // return true if values referenced by envelope have a valid close time:
    // * it's within the allowed range (using lcl if possible)
    // * it's recent enough (if `enforceRecent` is set)
    bool checkCloseTime(SCPEnvelope const& envelope, bool enforceRecent);

    // Given a candidate close time, determine an offset needed to make it
    // valid (at current system time). Returns 0 if ct is already valid
    std::chrono::milliseconds
    ctValidityOffset(uint64_t ct, std::chrono::milliseconds maxCtOffset =
                                      std::chrono::milliseconds::zero());

    void setupTriggerNextLedger();

    void startOutOfSyncTimer();
    void outOfSyncRecovery();
    void broadcast(SCPEnvelope const& e);

    // Compact tx set relay: attempt to send a compact tx set alongside
    // an SCP envelope, subject to config flags and per-peer dedup.
    void maybeBroadcastCompactTxSetForEnvelope(SCPEnvelope const& e);

    // Try to reconstruct a compact session and deliver to PendingEnvelopes
    // if complete, or request refill / fallback as needed.
    void tryFinishCompactSession(Hash const& txSetHash, uint64_t nonce,
                                 uint64_t senderId);

    void processSCPQueueUpToIndex(uint64 slotIndex);
    void safelyProcessSCPQueue(bool synchronous);
    void newSlotExternalized(bool synchronous, StellarValue const& value);
    void purgeOldPersistedTxSets();
    void writeDebugTxSet(LedgerCloseData const& lcd);

    PendingEnvelopes mPendingEnvelopes;
    Upgrades mUpgrades;
    HerderSCPDriver mHerderSCPDriver;

    void herderOutOfSync();

    // attempt to retrieve additional SCP messages from peers
    void getMoreSCPState();

    // last slot that was persisted into the database
    // keep track of all messages for MAX_SLOTS_TO_REMEMBER slots
    uint64 mLastSlotSaved;

    // timer that detects that we're stuck on an SCP slot
    VirtualTimer mTrackingTimer;

    // tracks the last time externalize was called
    VirtualClock::time_point mLastExternalize;

    // saves the SCP messages that the instance sent out last
    void persistSCPState(uint64 slot);
    // restores SCP state based on the last messages saved on disk
    void restoreSCPState();

    // Map SCP slots to local time of nomination and the time slot was
    // externalized by the network
    std::map<uint32_t, std::pair<uint64_t, std::optional<uint64_t>>>
        mDriftCTSlidingWindow;

    // saves upgrade parameters
    void persistUpgrades();
    void restoreUpgrades();

    // called every time we get ledger externalized
    // ensures that if we don't hear from the network, we throw the herder into
    // indeterminate mode
    void trackingHeartBeat();

    VirtualTimer mTriggerTimer;

    VirtualTimer mOutOfSyncTimer;

    VirtualTimer mTxSetGarbageCollectTimer;

    // Every CHECK_FOR_DEAD_NODES_MINUTES, we keep track of all nodes that SCP
    // reports as missing throughout the interval.
    VirtualTimer mCheckForDeadNodesTimer;
    void startCheckForDeadNodesInterval();

    Application& mApp;
    LedgerManager& mLedgerManager;

    struct SCPMetrics
    {
        medida::Meter& mLostSync;

        medida::Meter& mEnvelopeEmit;
        medida::Meter& mEnvelopeReceive;

        // Counters for things reached-through the
        // SCP maps: Slots and Nodes
        medida::Counter& mCumulativeStatements;

        // envelope signature verification
        medida::Meter& mEnvelopeValidSig;
        medida::Meter& mEnvelopeInvalidSig;

        SCPMetrics(Application& app);
    };

    SCPMetrics mSCPMetrics;

    // Check that the quorum map intersection state is up to date, and if not
    // run a background job that re-analyzes the current quorum map.
    void checkAndMaybeReanalyzeQuorumMap();

    void checkAndMaybeReanalyzeQuorumMapV2();

    // erase all data for ledgers strictly less than ledgerSeq except for the
    // first ledger on the current checkpoint. Hold onto this ledger so
    // peers can catchup without waiting for the next checkpoint.
    void eraseBelow(uint32 ledgerSeq);

    std::shared_ptr<QuorumMapIntersectionState> mLastQuorumMapIntersectionState;

    State mState;
    void setState(State st);

    // --- Compact tx set relay state (sender side) ---

    // Cached serialized CompactTransactionSet, keyed by txSetHash.
    // Built once per (txSetHash, nonce) and reused for all sends.
    struct CachedCompactTxSet
    {
        uint64_t nonce;
        std::vector<uint8_t> serializedBytes;
    };
    std::map<Hash, CachedCompactTxSet> mCachedCompactTxSets;

    // Per-peer dedup: (txSetHash, peerId) pairs we have already emitted
    // a compact tx set for. Prevents redundant sends across different
    // SCP phases / relay paths.
    // Note: peerId == 0 means "broadcast to all"; we don't track per-peer
    // in broadcast mode, only skip duplicate broadcasts for the same hash.
    std::set<Hash> mCompactTxSetBroadcastDedup;

    // --- Compact tx set reconstruction state (receiver side) ---

    // Key for a compact reconstruction session.
    struct CompactSessionKey
    {
        Hash txSetHash;
        uint64_t nonce;
        uint64_t senderId;

        bool
        operator<(CompactSessionKey const& o) const
        {
            if (txSetHash < o.txSetHash)
                return true;
            if (o.txSetHash < txSetHash)
                return false;
            if (nonce < o.nonce)
                return true;
            if (o.nonce < nonce)
                return false;
            return senderId < o.senderId;
        }
    };

    // State for a single compact reconstruction session.
    struct CompactSession
    {
        CompactTransactionSet compact;
        ResolvedShortIdMap resolved;
        // Total tx count across all phases for short-circuit computation
        size_t totalTxCount{0};
        // Timestamp of when we first received this compact message
        VirtualClock::time_point receivedAt;
        // Whether we have sent a refill request
        bool refillRequested{false};
    };

    std::map<CompactSessionKey, CompactSession> mCompactSessions;

    // Set of txSetHashes that have been fully reconstructed (or obtained
    // via full GET_TX_SET). Used to detect redundant compact arrivals.
    std::set<Hash> mReconstructedTxSetHashes;

    // --- End compact tx set state ---

    // Information about the most recent tracked SCP slot
    // Set regardless of whether the local instance if fully in sync with the
    // network or not (Herder::State is used to properly track the state of
    // Herder) On startup, this variable is set to LCL
    ConsensusData mTrackingSCP;

    uint32_t mMaxTxSize{0};

    UnorderedSet<LedgerKey>
    recomputeKeysToFilter(uint32_t protocolVersion) const;
};
}
