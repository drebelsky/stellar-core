// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/CompactTxSet.h"
#include "crypto/SHA.h"
#include "crypto/ShortHash.h"
#include "util/Logging.h"
#include "xdrpp/marshal.h"

#include <algorithm>
#include <cstring>

namespace stellar
{

namespace
{

// Compute the short ID for one TransactionEnvelope in the sender's
// compact-build path.  txFullHash = SHA-256(xdr_to_opaque(envelope)).
ShortTxId
shortIdForEnvelope(Hash const& txSetContentHash, uint64_t nonce,
                   TransactionEnvelope const& env)
{
    Hash txHash = xdrSha256(env);
    return shortHash::computeCompactTxSetShortId(txSetContentHash, nonce,
                                                 txHash);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Pack / unpack helpers
// ---------------------------------------------------------------------------

PackedShortTxIds
packShortIds(std::vector<ShortTxId> const& ids)
{
    PackedShortTxIds packed;
    packed.resize(ids.size() * 6);
    for (size_t i = 0; i < ids.size(); ++i)
    {
        std::memcpy(packed.data() + i * 6, ids[i].data(), 6);
    }
    return packed;
}

bool
unpackShortIds(PackedShortTxIds const& packed, std::vector<ShortTxId>& out)
{
    if (packed.size() % 6 != 0)
    {
        return false;
    }
    size_t count = packed.size() / 6;
    out.resize(count);
    for (size_t i = 0; i < count; ++i)
    {
        std::memcpy(out[i].data(), packed.data() + i * 6, 6);
    }
    return true;
}

bool
validatePackedShortIds(PackedShortTxIds const& packed)
{
    return packed.size() % 6 == 0;
}

// ---------------------------------------------------------------------------
// Builder (sender side)
// ---------------------------------------------------------------------------

bool
buildCompactTxSet(TxSetXDRFrame const& fullTxSet, uint64_t nonce,
                  CompactTransactionSet& out)
{
    if (!fullTxSet.isGeneralizedTxSet())
    {
        CLOG_WARNING(Herder,
                     "buildCompactTxSet: not a GeneralizedTransactionSet");
        return false;
    }

    GeneralizedTransactionSet genTxSet;
    fullTxSet.toXDR(genTxSet);

    // Only v == 1 is supported.
    if (genTxSet.v() != 1)
    {
        CLOG_WARNING(Herder,
                     "buildCompactTxSet: unsupported GeneralizedTransactionSet "
                     "version {}",
                     genTxSet.v());
        return false;
    }

    auto const& v1 = genTxSet.v1TxSet();
    if (v1.phases.size() != 2)
    {
        CLOG_WARNING(
            Herder,
            "buildCompactTxSet: expected exactly 2 phases, got {}",
            v1.phases.size());
        return false;
    }

    Hash const& contentHash = fullTxSet.getContentsHash();

    out.txSetHash = contentHash;
    out.nonce = nonce;

    for (size_t phaseIdx = 0; phaseIdx < 2; ++phaseIdx)
    {
        auto const& srcPhase = v1.phases[phaseIdx];
        auto& dstPhase = out.phases[phaseIdx];

        switch (srcPhase.v())
        {
        case 0:
        {
            // Sequential phase (Classic)
            dstPhase.v(0);
            auto& dstComponents = dstPhase.v0Components();
            auto const& srcComponents = srcPhase.v0Components();
            dstComponents.resize(srcComponents.size());

            for (size_t compIdx = 0; compIdx < srcComponents.size();
                 ++compIdx)
            {
                auto const& srcComp =
                    srcComponents[compIdx].txsMaybeDiscountedFee();
                auto& dstComp = dstComponents[compIdx];

                // Preserve baseFee presence
                if (srcComp.baseFee)
                {
                    dstComp.baseFee.activate() = *srcComp.baseFee;
                }

                // Compute short IDs for all envelopes
                std::vector<ShortTxId> ids;
                ids.reserve(srcComp.txs.size());
                for (auto const& env : srcComp.txs)
                {
                    ids.push_back(
                        shortIdForEnvelope(contentHash, nonce, env));
                }
                dstComp.shortTxIds = packShortIds(ids);
            }
            break;
        }
        case 1:
        {
            // Parallel phase (Soroban)
            dstPhase.v(1);
            auto& dstParallel = dstPhase.parallelTxsComponent();
            auto const& srcParallel = srcPhase.parallelTxsComponent();

            // Preserve baseFee presence
            if (srcParallel.baseFee)
            {
                dstParallel.baseFee.activate() = *srcParallel.baseFee;
            }

            auto const& srcStages = srcParallel.executionStages;
            dstParallel.executionStages.resize(srcStages.size());

            for (size_t stageIdx = 0; stageIdx < srcStages.size();
                 ++stageIdx)
            {
                auto const& srcStage = srcStages[stageIdx];
                auto& dstStage = dstParallel.executionStages[stageIdx];
                dstStage.resize(srcStage.size());

                for (size_t clusterIdx = 0; clusterIdx < srcStage.size();
                     ++clusterIdx)
                {
                    auto const& srcCluster = srcStage[clusterIdx];
                    std::vector<ShortTxId> ids;
                    ids.reserve(srcCluster.size());
                    for (auto const& env : srcCluster)
                    {
                        ids.push_back(
                            shortIdForEnvelope(contentHash, nonce, env));
                    }
                    dstStage[clusterIdx] = packShortIds(ids);
                }
            }
            break;
        }
        default:
            CLOG_WARNING(Herder,
                         "buildCompactTxSet: unknown phase discriminant {}",
                         srcPhase.v());
            return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Reconstructor (receiver side)
// ---------------------------------------------------------------------------

ReconstructResult
tryReconstruct(CompactTransactionSet const& compact,
               ResolvedShortIdMap const& resolved,
               Hash const& previousLedgerHash)
{
    ReconstructResult result;
    result.status = ReconstructResult::Status::COMPLETE;

    // Build a GeneralizedTransactionSet from the compact form + resolved map.
    GeneralizedTransactionSet genTxSet;
    genTxSet.v(1);
    auto& v1 = genTxSet.v1TxSet();
    v1.previousLedgerHash = previousLedgerHash;
    v1.phases.resize(2);

    // Walk the compact phases in positional order, consuming entries from
    // `resolved` sequentially.
    size_t resolvedIdx = 0;
    std::vector<ShortTxId> missing;

    for (size_t phaseIdx = 0; phaseIdx < 2; ++phaseIdx)
    {
        auto const& srcPhase = compact.phases[phaseIdx];
        auto& dstPhase = v1.phases[phaseIdx];

        switch (srcPhase.v())
        {
        case 0:
        {
            dstPhase.v(0);
            auto const& srcComponents = srcPhase.v0Components();
            auto& dstComponents = dstPhase.v0Components();
            dstComponents.resize(srcComponents.size());

            for (size_t compIdx = 0; compIdx < srcComponents.size();
                 ++compIdx)
            {
                auto const& srcComp = srcComponents[compIdx];
                auto& dstComp = dstComponents[compIdx];
                dstComp.type(TXSET_COMP_TXS_MAYBE_DISCOUNTED_FEE);

                if (srcComp.baseFee)
                {
                    dstComp.txsMaybeDiscountedFee().baseFee.activate() =
                        *srcComp.baseFee;
                }

                std::vector<ShortTxId> ids;
                if (!unpackShortIds(srcComp.shortTxIds, ids))
                {
                    CLOG_WARNING(
                        Herder,
                        "tryReconstruct: invalid PackedShortTxIds length");
                    result.status = ReconstructResult::Status::FAILED;
                    return result;
                }

                auto& dstTxs = dstComp.txsMaybeDiscountedFee().txs;
                dstTxs.resize(ids.size());

                for (size_t txIdx = 0; txIdx < ids.size(); ++txIdx)
                {
                    if (resolvedIdx >= resolved.size())
                    {
                        CLOG_WARNING(Herder,
                                     "tryReconstruct: resolved map too "
                                     "small");
                        result.status =
                            ReconstructResult::Status::FAILED;
                        return result;
                    }

                    auto const& entry = resolved[resolvedIdx++];
                    if (entry.status ==
                        ResolveResultEntry::Status::UNIQUE)
                    {
                        try
                        {
                            xdr::xdr_from_opaque(entry.envelopeBytes,
                                                 dstTxs[txIdx]);
                        }
                        catch (std::exception const& e)
                        {
                            CLOG_WARNING(
                                Herder,
                                "tryReconstruct: failed to parse "
                                "envelope at index {}: {}",
                                resolvedIdx - 1, e.what());
                            result.status =
                                ReconstructResult::Status::FAILED;
                            return result;
                        }
                    }
                    else
                    {
                        missing.push_back(ids[txIdx]);
                    }
                }
            }
            break;
        }
        case 1:
        {
            dstPhase.v(1);
            auto const& srcParallel = srcPhase.parallelTxsComponent();
            auto& dstParallel = dstPhase.parallelTxsComponent();

            if (srcParallel.baseFee)
            {
                dstParallel.baseFee.activate() = *srcParallel.baseFee;
            }

            auto const& srcStages = srcParallel.executionStages;
            dstParallel.executionStages.resize(srcStages.size());

            for (size_t stageIdx = 0; stageIdx < srcStages.size();
                 ++stageIdx)
            {
                auto const& srcStage = srcStages[stageIdx];
                auto& dstStage = dstParallel.executionStages[stageIdx];
                dstStage.resize(srcStage.size());

                for (size_t clusterIdx = 0; clusterIdx < srcStage.size();
                     ++clusterIdx)
                {
                    std::vector<ShortTxId> ids;
                    if (!unpackShortIds(srcStage[clusterIdx], ids))
                    {
                        CLOG_WARNING(Herder,
                                     "tryReconstruct: invalid "
                                     "PackedShortTxIds length in "
                                     "parallel phase");
                        result.status =
                            ReconstructResult::Status::FAILED;
                        return result;
                    }

                    auto& dstCluster = dstStage[clusterIdx];
                    dstCluster.resize(ids.size());

                    for (size_t txIdx = 0; txIdx < ids.size(); ++txIdx)
                    {
                        if (resolvedIdx >= resolved.size())
                        {
                            CLOG_WARNING(
                                Herder,
                                "tryReconstruct: resolved map too "
                                "small");
                            result.status =
                                ReconstructResult::Status::FAILED;
                            return result;
                        }

                        auto const& entry = resolved[resolvedIdx++];
                        if (entry.status ==
                            ResolveResultEntry::Status::UNIQUE)
                        {
                            try
                            {
                                xdr::xdr_from_opaque(entry.envelopeBytes,
                                                     dstCluster[txIdx]);
                            }
                            catch (std::exception const& e)
                            {
                                CLOG_WARNING(
                                    Herder,
                                    "tryReconstruct: failed to parse "
                                    "envelope at index {}: {}",
                                    resolvedIdx - 1, e.what());
                                result.status =
                                    ReconstructResult::Status::FAILED;
                                return result;
                            }
                        }
                        else
                        {
                            missing.push_back(ids[txIdx]);
                        }
                    }
                }
            }
            break;
        }
        default:
            CLOG_WARNING(Herder,
                         "tryReconstruct: unknown phase discriminant {}",
                         srcPhase.v());
            result.status = ReconstructResult::Status::FAILED;
            return result;
        }
    }

    if (!missing.empty())
    {
        result.status = ReconstructResult::Status::NEEDS_REFILL;
        result.missingShortIds = std::move(missing);
        return result;
    }

    // Verify the reconstructed tx set hashes to the expected value.
    Hash reconstructedHash = xdrSha256(genTxSet);
    if (reconstructedHash != compact.txSetHash)
    {
        CLOG_WARNING(Herder,
                     "tryReconstruct: hash mismatch after reconstruction");
        result.status = ReconstructResult::Status::FAILED;
        return result;
    }

    result.txSet = TxSetXDRFrame::makeFromWire(genTxSet);
    return result;
}

} // namespace stellar
