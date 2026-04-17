// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/ShortHash.h"
#include "herder/TxSetFrame.h"
#include "overlay/StellarXDR.h"

#include <array>
#include <cstdint>
#include <vector>

namespace stellar
{

// Per-short-ID resolution entry produced by the Rust overlay's mempool scan.
struct ResolveResultEntry
{
    enum class Status : uint8_t
    {
        UNIQUE = 0,
        MISSING = 1,
        AMBIGUOUS = 2
    };
    Status status;
    // Populated only when status == UNIQUE.
    xdr::opaque_vec<> envelopeBytes;
};

// Positional resolution results, one per short ID in the CompactTransactionSet.
using ResolvedShortIdMap = std::vector<ResolveResultEntry>;

struct ReconstructResult
{
    enum class Status
    {
        COMPLETE,
        NEEDS_REFILL,
        FAILED
    };
    Status status;
    // Populated when status == COMPLETE.
    TxSetXDRFrameConstPtr txSet;
    // Populated when status == NEEDS_REFILL: the non-UNIQUE short IDs.
    std::vector<ShortTxId> missingShortIds;
};

// Build a CompactTransactionSet from an already-materialized
// GeneralizedTransactionSet. The compact form replaces every
// TransactionEnvelope with its 6-byte SipHash-2-4 short ID, preserving
// the full phase/component/stage/cluster structure.
//
// Returns false (and leaves `out` unmodified) if the input tx set does not
// have exactly 2 phases or is not a GeneralizedTransactionSet (v == 1).
bool buildCompactTxSet(TxSetXDRFrame const& fullTxSet, uint64_t nonce,
                       CompactTransactionSet& out);

// Attempt to reconstruct a GeneralizedTransactionSet from a compact message
// and a positional resolution map (produced by Rust overlay mempool scan).
// previousLedgerHash must be supplied by the caller (typically the last closed
// ledger hash) because the compact message omits it but the content hash
// includes it.
ReconstructResult tryReconstruct(CompactTransactionSet const& compact,
                                 ResolvedShortIdMap const& resolved,
                                 Hash const& previousLedgerHash);

// Pack a vector of ShortTxIds into a PackedShortTxIds opaque blob.
PackedShortTxIds packShortIds(std::vector<ShortTxId> const& ids);

// Unpack a PackedShortTxIds opaque blob into a vector of ShortTxIds.
// Returns false if the blob length is not a multiple of 6.
bool unpackShortIds(PackedShortTxIds const& packed,
                    std::vector<ShortTxId>& out);

// Validate that a PackedShortTxIds blob length is a multiple of 6.
bool validatePackedShortIds(PackedShortTxIds const& packed);

} // namespace stellar
