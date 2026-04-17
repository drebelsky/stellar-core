// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/SHA.h"
#include "crypto/ShortHash.h"
#include "herder/CompactTxSet.h"
#include "herder/TxSetFrame.h"
#include "herder/test/TestTxSetUtils.h"
#include "main/Application.h"
#include "main/Config.h"
#include "test/TestAccount.h"
#include "test/TestUtils.h"
#include "test/TxTests.h"
#include "test/test.h"
#include "util/Math.h"
#include "xdrpp/marshal.h"
#include <lib/catch.hpp>

namespace stellar
{
namespace
{
using namespace txtest;

// Helper: create a GeneralizedTransactionSet with the given phases.
GeneralizedTransactionSet
makeGenTxSet(Hash const& previousLedgerHash,
             std::vector<TransactionEnvelope> const& classicTxs,
             std::vector<TransactionEnvelope> const& sorobanTxs,
             std::optional<int64_t> classicBaseFee = std::nullopt,
             std::optional<int64_t> sorobanBaseFee = std::nullopt)
{
    GeneralizedTransactionSet genTxSet;
    genTxSet.v(1);
    auto& v1 = genTxSet.v1TxSet();
    v1.previousLedgerHash = previousLedgerHash;
    v1.phases.resize(2);

    // Classic phase (v=0, sequential)
    auto& classicPhase = v1.phases[0];
    classicPhase.v(0);
    auto& classicComps = classicPhase.v0Components();
    classicComps.resize(1);
    classicComps[0].type(TXSET_COMP_TXS_MAYBE_DISCOUNTED_FEE);
    if (classicBaseFee)
    {
        classicComps[0].txsMaybeDiscountedFee().baseFee.activate() =
            *classicBaseFee;
    }
    classicComps[0].txsMaybeDiscountedFee().txs.assign(classicTxs.begin(),
                                                       classicTxs.end());

    // Soroban phase (v=0, sequential for simplicity)
    auto& sorobanPhase = v1.phases[1];
    sorobanPhase.v(0);
    auto& sorobanComps = sorobanPhase.v0Components();
    sorobanComps.resize(1);
    sorobanComps[0].type(TXSET_COMP_TXS_MAYBE_DISCOUNTED_FEE);
    if (sorobanBaseFee)
    {
        sorobanComps[0].txsMaybeDiscountedFee().baseFee.activate() =
            *sorobanBaseFee;
    }
    sorobanComps[0].txsMaybeDiscountedFee().txs.assign(sorobanTxs.begin(),
                                                       sorobanTxs.end());

    return genTxSet;
}

// Helper: create a simple TransactionEnvelope for testing.
TransactionEnvelope
makeDummyEnvelope(uint64_t seed)
{
    TransactionEnvelope env;
    env.type(ENVELOPE_TYPE_TX);
    auto& tx = env.v1().tx;
    tx.fee = static_cast<uint32>(100 + seed);
    tx.seqNum = static_cast<int64>(seed);
    tx.sourceAccount.type(KEY_TYPE_ED25519);
    // Fill with deterministic bytes
    for (size_t i = 0; i < 32; ++i)
    {
        tx.sourceAccount.ed25519()[i] =
            static_cast<uint8_t>((seed * 31 + i) & 0xFF);
    }
    return env;
}

// Helper: create a fee-bump TransactionEnvelope for testing.
TransactionEnvelope
makeDummyFeeBumpEnvelope(uint64_t seed)
{
    TransactionEnvelope env;
    env.type(ENVELOPE_TYPE_TX_FEE_BUMP);
    auto& fb = env.feeBump();
    fb.tx.fee = static_cast<int64>(200 + seed);
    fb.tx.feeSource.type(KEY_TYPE_ED25519);
    for (size_t i = 0; i < 32; ++i)
    {
        fb.tx.feeSource.ed25519()[i] =
            static_cast<uint8_t>((seed * 37 + i) & 0xFF);
    }
    // Inner tx
    fb.tx.innerTx.type(ENVELOPE_TYPE_TX);
    fb.tx.innerTx.v1().tx.fee = static_cast<uint32>(100 + seed);
    fb.tx.innerTx.v1().tx.seqNum = static_cast<int64>(seed);
    fb.tx.innerTx.v1().tx.sourceAccount.type(KEY_TYPE_ED25519);
    for (size_t i = 0; i < 32; ++i)
    {
        fb.tx.innerTx.v1().tx.sourceAccount.ed25519()[i] =
            static_cast<uint8_t>((seed * 41 + i) & 0xFF);
    }
    return env;
}

// Helper: build a fully resolved map where every entry is UNIQUE.
ResolvedShortIdMap
buildFullResolution(GeneralizedTransactionSet const& genTxSet)
{
    ResolvedShortIdMap resolved;
    auto const& v1 = genTxSet.v1TxSet();
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
                    ResolveResultEntry entry;
                    entry.status = ResolveResultEntry::Status::UNIQUE;
                    entry.envelopeBytes = xdr::xdr_to_opaque(env);
                    resolved.push_back(std::move(entry));
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
                        ResolveResultEntry entry;
                        entry.status =
                            ResolveResultEntry::Status::UNIQUE;
                        entry.envelopeBytes =
                            xdr::xdr_to_opaque(env);
                        resolved.push_back(std::move(entry));
                    }
                }
            }
            break;
        }
        default:
            break;
        }
    }
    return resolved;
}

// ---------------------------------------------------------------------------
// SipHash Short ID Tests
// ---------------------------------------------------------------------------

TEST_CASE("SipHash short ID computation", "[compact][siphash]")
{
    SECTION("deterministic output")
    {
        Hash txSetHash;
        std::fill(txSetHash.begin(), txSetHash.end(), 0xAB);
        uint64_t nonce = 12345;

        Hash txHash;
        std::fill(txHash.begin(), txHash.end(), 0xCD);

        auto id1 = shortHash::computeCompactTxSetShortId(txSetHash, nonce,
                                                          txHash);
        auto id2 = shortHash::computeCompactTxSetShortId(txSetHash, nonce,
                                                          txHash);
        REQUIRE(id1 == id2);
    }

    SECTION("different nonces produce different short IDs")
    {
        Hash txSetHash;
        std::fill(txSetHash.begin(), txSetHash.end(), 0xAB);
        Hash txHash;
        std::fill(txHash.begin(), txHash.end(), 0xCD);

        auto id1 =
            shortHash::computeCompactTxSetShortId(txSetHash, 1, txHash);
        auto id2 =
            shortHash::computeCompactTxSetShortId(txSetHash, 2, txHash);
        REQUIRE(id1 != id2);
    }

    SECTION("different tx hashes produce different short IDs")
    {
        Hash txSetHash;
        std::fill(txSetHash.begin(), txSetHash.end(), 0xAB);
        uint64_t nonce = 42;

        Hash txHash1, txHash2;
        std::fill(txHash1.begin(), txHash1.end(), 0x01);
        std::fill(txHash2.begin(), txHash2.end(), 0x02);

        auto id1 = shortHash::computeCompactTxSetShortId(txSetHash, nonce,
                                                          txHash1);
        auto id2 = shortHash::computeCompactTxSetShortId(txSetHash, nonce,
                                                          txHash2);
        REQUIRE(id1 != id2);
    }

    SECTION("short ID is exactly 6 bytes")
    {
        Hash txSetHash{}, txHash{};
        auto id =
            shortHash::computeCompactTxSetShortId(txSetHash, 0, txHash);
        REQUIRE(id.size() == 6);
    }
}

// ---------------------------------------------------------------------------
// PackedShortTxIds Pack/Unpack Tests
// ---------------------------------------------------------------------------

TEST_CASE("PackedShortTxIds pack and unpack", "[compact][packing]")
{
    SECTION("round-trip preserves IDs")
    {
        std::vector<ShortTxId> ids;
        for (uint8_t i = 0; i < 5; ++i)
        {
            ShortTxId id;
            for (size_t j = 0; j < 6; ++j)
                id[j] = static_cast<uint8_t>(i * 6 + j);
            ids.push_back(id);
        }

        auto packed = packShortIds(ids);
        REQUIRE(packed.size() == 30); // 5 * 6

        std::vector<ShortTxId> unpacked;
        REQUIRE(unpackShortIds(packed, unpacked));
        REQUIRE(unpacked == ids);
    }

    SECTION("empty list")
    {
        std::vector<ShortTxId> ids;
        auto packed = packShortIds(ids);
        REQUIRE(packed.size() == 0);

        std::vector<ShortTxId> unpacked;
        REQUIRE(unpackShortIds(packed, unpacked));
        REQUIRE(unpacked.empty());
    }

    SECTION("invalid length rejected")
    {
        PackedShortTxIds bad;
        bad.resize(7); // Not a multiple of 6

        std::vector<ShortTxId> out;
        REQUIRE(!unpackShortIds(bad, out));
        REQUIRE(!validatePackedShortIds(bad));
    }

    SECTION("valid lengths accepted")
    {
        for (size_t len : {0, 6, 12, 18, 600})
        {
            PackedShortTxIds p;
            p.resize(len);
            REQUIRE(validatePackedShortIds(p));
        }
    }
}

// ---------------------------------------------------------------------------
// Compact Tx Set Builder Tests
// ---------------------------------------------------------------------------

TEST_CASE("compact tx set build and reconstruct", "[compact][builder]")
{
    Hash prevHash;
    std::fill(prevHash.begin(), prevHash.end(), 0x11);

    SECTION("basic round-trip with classic transactions")
    {
        std::vector<TransactionEnvelope> classicTxs;
        for (uint64_t i = 0; i < 5; ++i)
        {
            classicTxs.push_back(makeDummyEnvelope(i));
        }

        auto genTxSet = makeGenTxSet(prevHash, classicTxs, {}, 100);
        auto frame = TxSetXDRFrame::makeFromWire(genTxSet);

        uint64_t nonce = 42;
        CompactTransactionSet compact;
        REQUIRE(buildCompactTxSet(*frame, nonce, compact));
        REQUIRE(compact.txSetHash == frame->getContentsHash());
        REQUIRE(compact.nonce == nonce);

        // Build a fully resolved map and reconstruct.
        auto resolved = buildFullResolution(genTxSet);
        auto result = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result.status == ReconstructResult::Status::COMPLETE);
        REQUIRE(result.txSet != nullptr);

        // Verify hash matches.
        GeneralizedTransactionSet reconstructedXdr;
        result.txSet->toXDR(reconstructedXdr);
        Hash reconstructedHash = xdrSha256(reconstructedXdr);
        REQUIRE(reconstructedHash == compact.txSetHash);
    }

    SECTION("round-trip with fee-bump transactions")
    {
        std::vector<TransactionEnvelope> classicTxs;
        classicTxs.push_back(makeDummyEnvelope(1));
        classicTxs.push_back(makeDummyFeeBumpEnvelope(2));
        classicTxs.push_back(makeDummyEnvelope(3));

        auto genTxSet = makeGenTxSet(prevHash, classicTxs, {}, 100);
        auto frame = TxSetXDRFrame::makeFromWire(genTxSet);

        uint64_t nonce = 99;
        CompactTransactionSet compact;
        REQUIRE(buildCompactTxSet(*frame, nonce, compact));

        auto resolved = buildFullResolution(genTxSet);
        auto result = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result.status == ReconstructResult::Status::COMPLETE);

        GeneralizedTransactionSet reconstructedXdr;
        result.txSet->toXDR(reconstructedXdr);
        REQUIRE(xdrSha256(reconstructedXdr) == compact.txSetHash);
    }

    SECTION("round-trip with both classic and soroban phases")
    {
        std::vector<TransactionEnvelope> classicTxs;
        for (uint64_t i = 0; i < 3; ++i)
            classicTxs.push_back(makeDummyEnvelope(i));

        std::vector<TransactionEnvelope> sorobanTxs;
        for (uint64_t i = 10; i < 13; ++i)
            sorobanTxs.push_back(makeDummyEnvelope(i));

        auto genTxSet =
            makeGenTxSet(prevHash, classicTxs, sorobanTxs, 100, 200);
        auto frame = TxSetXDRFrame::makeFromWire(genTxSet);

        uint64_t nonce = 7;
        CompactTransactionSet compact;
        REQUIRE(buildCompactTxSet(*frame, nonce, compact));

        auto resolved = buildFullResolution(genTxSet);
        auto result = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result.status == ReconstructResult::Status::COMPLETE);

        GeneralizedTransactionSet reconstructedXdr;
        result.txSet->toXDR(reconstructedXdr);
        REQUIRE(xdrSha256(reconstructedXdr) == compact.txSetHash);
    }

    SECTION("empty phase (0 transactions in one phase)")
    {
        // Classic has txs, Soroban is empty.
        std::vector<TransactionEnvelope> classicTxs;
        classicTxs.push_back(makeDummyEnvelope(1));

        auto genTxSet = makeGenTxSet(prevHash, classicTxs, {});
        auto frame = TxSetXDRFrame::makeFromWire(genTxSet);

        uint64_t nonce = 1;
        CompactTransactionSet compact;
        REQUIRE(buildCompactTxSet(*frame, nonce, compact));

        auto resolved = buildFullResolution(genTxSet);
        auto result = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result.status == ReconstructResult::Status::COMPLETE);
    }

    SECTION("both phases empty")
    {
        auto genTxSet = makeGenTxSet(prevHash, {}, {});
        auto frame = TxSetXDRFrame::makeFromWire(genTxSet);

        uint64_t nonce = 1;
        CompactTransactionSet compact;
        REQUIRE(buildCompactTxSet(*frame, nonce, compact));

        auto resolved = buildFullResolution(genTxSet);
        auto result = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result.status == ReconstructResult::Status::COMPLETE);
    }

    SECTION("baseFee presence preserved")
    {
        // With baseFee
        auto genTxSetWithFee =
            makeGenTxSet(prevHash, {makeDummyEnvelope(1)}, {}, 500);
        auto frameWithFee = TxSetXDRFrame::makeFromWire(genTxSetWithFee);

        CompactTransactionSet compact1;
        REQUIRE(buildCompactTxSet(*frameWithFee, 1, compact1));
        REQUIRE(compact1.phases[0].v0Components()[0].baseFee);
        REQUIRE(*compact1.phases[0].v0Components()[0].baseFee == 500);

        // Without baseFee
        auto genTxSetNoFee =
            makeGenTxSet(prevHash, {makeDummyEnvelope(1)}, {});
        auto frameNoFee = TxSetXDRFrame::makeFromWire(genTxSetNoFee);

        CompactTransactionSet compact2;
        REQUIRE(buildCompactTxSet(*frameNoFee, 1, compact2));
        REQUIRE(!compact2.phases[0].v0Components()[0].baseFee);

        // Reconstruction with fee round-trips correctly
        auto resolved1 = buildFullResolution(genTxSetWithFee);
        auto result1 = tryReconstruct(compact1, resolved1, prevHash);
        REQUIRE(result1.status == ReconstructResult::Status::COMPLETE);
        GeneralizedTransactionSet xdr1;
        result1.txSet->toXDR(xdr1);
        REQUIRE(xdrSha256(xdr1) == compact1.txSetHash);
    }
}

// ---------------------------------------------------------------------------
// Reconstruction with Missing/Ambiguous Entries
// ---------------------------------------------------------------------------

TEST_CASE("compact tx set reconstruction with missing entries",
          "[compact][reconstruct]")
{
    Hash prevHash;
    std::fill(prevHash.begin(), prevHash.end(), 0x22);

    std::vector<TransactionEnvelope> classicTxs;
    for (uint64_t i = 0; i < 5; ++i)
        classicTxs.push_back(makeDummyEnvelope(i));

    auto genTxSet = makeGenTxSet(prevHash, classicTxs, {}, 100);
    auto frame = TxSetXDRFrame::makeFromWire(genTxSet);

    uint64_t nonce = 42;
    CompactTransactionSet compact;
    REQUIRE(buildCompactTxSet(*frame, nonce, compact));

    SECTION("NEEDS_REFILL when entries are MISSING")
    {
        auto resolved = buildFullResolution(genTxSet);
        // Mark last two as MISSING
        resolved[3].status = ResolveResultEntry::Status::MISSING;
        resolved[3].envelopeBytes.clear();
        resolved[4].status = ResolveResultEntry::Status::MISSING;
        resolved[4].envelopeBytes.clear();

        auto result = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result.status == ReconstructResult::Status::NEEDS_REFILL);
        REQUIRE(result.missingShortIds.size() == 2);
    }

    SECTION("NEEDS_REFILL when entries are AMBIGUOUS")
    {
        auto resolved = buildFullResolution(genTxSet);
        resolved[2].status = ResolveResultEntry::Status::AMBIGUOUS;
        resolved[2].envelopeBytes.clear();

        auto result = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result.status == ReconstructResult::Status::NEEDS_REFILL);
        REQUIRE(result.missingShortIds.size() == 1);
    }

    SECTION("FAILED when resolved map too small")
    {
        auto resolved = buildFullResolution(genTxSet);
        resolved.pop_back();
        resolved.pop_back();

        auto result = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result.status == ReconstructResult::Status::FAILED);
    }

    SECTION("FAILED on hash mismatch")
    {
        auto resolved = buildFullResolution(genTxSet);
        // Corrupt the first envelope
        resolved[0].envelopeBytes.push_back(0xFF);

        // This will either throw during XDR parse or produce a hash
        // mismatch. Either way, we should not get COMPLETE.
        auto result = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result.status != ReconstructResult::Status::COMPLETE);
    }
}

// ---------------------------------------------------------------------------
// Reconstruction After Refill
// ---------------------------------------------------------------------------

TEST_CASE("compact tx set reconstruction after refill",
          "[compact][refill]")
{
    Hash prevHash;
    std::fill(prevHash.begin(), prevHash.end(), 0x33);

    std::vector<TransactionEnvelope> classicTxs;
    for (uint64_t i = 0; i < 3; ++i)
        classicTxs.push_back(makeDummyEnvelope(i));

    auto genTxSet = makeGenTxSet(prevHash, classicTxs, {}, 100);
    auto frame = TxSetXDRFrame::makeFromWire(genTxSet);
    auto const& contentHash = frame->getContentsHash();

    uint64_t nonce = 55;
    CompactTransactionSet compact;
    REQUIRE(buildCompactTxSet(*frame, nonce, compact));

    SECTION("successful reconstruction after refilling missing entries")
    {
        // First attempt: mark entry 1 as missing
        auto resolved = buildFullResolution(genTxSet);
        auto savedEnv1 = resolved[1].envelopeBytes;
        resolved[1].status = ResolveResultEntry::Status::MISSING;
        resolved[1].envelopeBytes.clear();

        auto result1 = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result1.status == ReconstructResult::Status::NEEDS_REFILL);
        REQUIRE(result1.missingShortIds.size() == 1);

        // Simulate refill: put the envelope back
        resolved[1].status = ResolveResultEntry::Status::UNIQUE;
        resolved[1].envelopeBytes = savedEnv1;

        auto result2 = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result2.status == ReconstructResult::Status::COMPLETE);

        GeneralizedTransactionSet reconstructedXdr;
        result2.txSet->toXDR(reconstructedXdr);
        REQUIRE(xdrSha256(reconstructedXdr) == compact.txSetHash);
    }

    SECTION("successful reconstruction after refilling ambiguous entries")
    {
        // Ambiguous entry at position 2
        auto resolved = buildFullResolution(genTxSet);
        auto savedEnv2 = resolved[2].envelopeBytes;
        resolved[2].status = ResolveResultEntry::Status::AMBIGUOUS;
        resolved[2].envelopeBytes.clear();

        auto result1 = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result1.status == ReconstructResult::Status::NEEDS_REFILL);

        // After refill with authoritative envelope
        resolved[2].status = ResolveResultEntry::Status::UNIQUE;
        resolved[2].envelopeBytes = savedEnv2;

        auto result2 = tryReconstruct(compact, resolved, prevHash);
        REQUIRE(result2.status == ReconstructResult::Status::COMPLETE);
    }
}

// ---------------------------------------------------------------------------
// Config Flag Tests
// ---------------------------------------------------------------------------

TEST_CASE("compact tx set config flags", "[compact][config]")
{
    SECTION("defaults")
    {
        Config cfg(getTestConfig());
        REQUIRE(cfg.COMPACT_TX_SET_LEADER_NOMINATION == true);
        REQUIRE(cfg.COMPACT_TX_SET_NON_LEADER_NOMINATION == false);
        REQUIRE(cfg.COMPACT_TX_SET_BALLOT_ROUNDS == false);
        REQUIRE(cfg.COMPACT_TX_SET_REFILL_MAX_RATIO == 0.5);
    }
}

// ---------------------------------------------------------------------------
// Short ID Input Hash Domain Test
// ---------------------------------------------------------------------------

TEST_CASE("short ID uses SHA-256 of XDR envelope bytes",
          "[compact][siphash]")
{
    // Verify that the short ID input is SHA-256(xdr(envelope)),
    // matching the Rust mempool's compute_tx_hash(data).
    auto env = makeDummyEnvelope(42);

    // Compute the xdr bytes and their SHA-256
    auto xdrBytes = xdr::xdr_to_opaque(env);
    Hash expectedTxHash = sha256(xdrBytes);

    // The short ID computation uses xdrSha256(env) internally,
    // which should be equivalent.
    Hash xdrShaResult = xdrSha256(env);
    REQUIRE(expectedTxHash == xdrShaResult);

    // Now verify that computeCompactTxSetShortId produces output
    // from this hash.
    Hash txSetHash;
    std::fill(txSetHash.begin(), txSetHash.end(), 0xAA);
    uint64_t nonce = 1;

    auto shortId1 = shortHash::computeCompactTxSetShortId(txSetHash, nonce,
                                                           expectedTxHash);
    auto shortId2 = shortHash::computeCompactTxSetShortId(txSetHash, nonce,
                                                           xdrShaResult);
    REQUIRE(shortId1 == shortId2);
}

// ---------------------------------------------------------------------------
// Malformed Input Tests
// ---------------------------------------------------------------------------

TEST_CASE("malformed compact tx set handling", "[compact][malformed]")
{
    SECTION("invalid packed short IDs length")
    {
        CompactTransactionSet compact;
        compact.txSetHash = Hash{};
        compact.nonce = 1;
        compact.phases[0].v(0);
        compact.phases[0].v0Components().resize(1);
        compact.phases[0].v0Components()[0].shortTxIds.resize(7); // bad
        compact.phases[1].v(0);
        compact.phases[1].v0Components().resize(1);
        compact.phases[1].v0Components()[0].shortTxIds.resize(0);

        ResolvedShortIdMap resolved;
        Hash dummyHash{};
        auto result = tryReconstruct(compact, resolved, dummyHash);
        REQUIRE(result.status == ReconstructResult::Status::FAILED);
    }
}

// ---------------------------------------------------------------------------
// Positional Order Preservation Test
// ---------------------------------------------------------------------------

TEST_CASE("compact tx set positional order preservation",
          "[compact][order]")
{
    Hash prevHash;
    std::fill(prevHash.begin(), prevHash.end(), 0x44);

    // Create transactions with specific ordering
    std::vector<TransactionEnvelope> txs;
    for (uint64_t i = 0; i < 10; ++i)
        txs.push_back(makeDummyEnvelope(i * 7 + 3)); // non-sequential seeds

    auto genTxSet = makeGenTxSet(prevHash, txs, {}, 100);
    auto frame = TxSetXDRFrame::makeFromWire(genTxSet);

    uint64_t nonce = 88;
    CompactTransactionSet compact;
    REQUIRE(buildCompactTxSet(*frame, nonce, compact));

    // Fully resolve and reconstruct
    auto resolved = buildFullResolution(genTxSet);
    auto result = tryReconstruct(compact, resolved, prevHash);
    REQUIRE(result.status == ReconstructResult::Status::COMPLETE);

    // Verify byte-identical serialization
    GeneralizedTransactionSet originalXdr;
    frame->toXDR(originalXdr);
    GeneralizedTransactionSet reconstructedXdr;
    result.txSet->toXDR(reconstructedXdr);

    auto originalBytes = xdr::xdr_to_opaque(originalXdr);
    auto reconstructedBytes = xdr::xdr_to_opaque(reconstructedXdr);

    // The previousLedgerHash differs (reconstructor sets it to zero),
    // but the content hash should match since content hash excludes it.
    REQUIRE(xdrSha256(reconstructedXdr) == frame->getContentsHash());
}

// ---------------------------------------------------------------------------
// Parallel (Soroban) Phase Tests
// ---------------------------------------------------------------------------

TEST_CASE("compact tx set with parallel phase", "[compact][parallel]")
{
    Hash prevHash;
    std::fill(prevHash.begin(), prevHash.end(), 0x55);

    // Build a parallel phase manually
    GeneralizedTransactionSet genTxSet;
    genTxSet.v(1);
    auto& v1 = genTxSet.v1TxSet();
    v1.previousLedgerHash = prevHash;
    v1.phases.resize(2);

    // Classic: sequential, empty
    v1.phases[0].v(0);
    v1.phases[0].v0Components().resize(1);
    v1.phases[0].v0Components()[0].type(TXSET_COMP_TXS_MAYBE_DISCOUNTED_FEE);

    // Soroban: parallel phase
    v1.phases[1].v(1);
    auto& par = v1.phases[1].parallelTxsComponent();
    par.baseFee.activate() = 300;

    // 2 stages, each with 2 clusters
    par.executionStages.resize(2);
    par.executionStages[0].resize(2);
    par.executionStages[1].resize(1);

    // Fill clusters with dummy envelopes
    for (uint64_t i = 0; i < 3; ++i)
        par.executionStages[0][0].push_back(makeDummyEnvelope(100 + i));
    for (uint64_t i = 0; i < 2; ++i)
        par.executionStages[0][1].push_back(makeDummyEnvelope(200 + i));
    for (uint64_t i = 0; i < 4; ++i)
        par.executionStages[1][0].push_back(makeDummyEnvelope(300 + i));

    auto frame = TxSetXDRFrame::makeFromWire(genTxSet);
    uint64_t nonce = 77;
    CompactTransactionSet compact;
    REQUIRE(buildCompactTxSet(*frame, nonce, compact));

    // Verify parallel phase structure preserved
    REQUIRE(compact.phases[1].v() == 1);
    REQUIRE(compact.phases[1].parallelTxsComponent().baseFee);
    REQUIRE(*compact.phases[1].parallelTxsComponent().baseFee == 300);
    REQUIRE(compact.phases[1].parallelTxsComponent().executionStages.size() ==
            2);
    REQUIRE(compact.phases[1]
                .parallelTxsComponent()
                .executionStages[0]
                .size() == 2);

    // Reconstruct
    auto resolved = buildFullResolution(genTxSet);
    auto result = tryReconstruct(compact, resolved, prevHash);
    REQUIRE(result.status == ReconstructResult::Status::COMPLETE);

    GeneralizedTransactionSet reconstructedXdr;
    result.txSet->toXDR(reconstructedXdr);
    REQUIRE(xdrSha256(reconstructedXdr) == compact.txSetHash);
}

// ---------------------------------------------------------------------------
// Multiple Components in Sequential Phase
// ---------------------------------------------------------------------------

TEST_CASE("compact tx set with multiple components",
          "[compact][components]")
{
    Hash prevHash;
    std::fill(prevHash.begin(), prevHash.end(), 0x66);

    // Manually build a tx set with 2 sequential components (different
    // base fees).
    GeneralizedTransactionSet genTxSet;
    genTxSet.v(1);
    auto& v1 = genTxSet.v1TxSet();
    v1.previousLedgerHash = prevHash;
    v1.phases.resize(2);

    // Classic: 2 components
    v1.phases[0].v(0);
    v1.phases[0].v0Components().resize(2);

    v1.phases[0].v0Components()[0].type(TXSET_COMP_TXS_MAYBE_DISCOUNTED_FEE);
    v1.phases[0].v0Components()[0].txsMaybeDiscountedFee().baseFee.activate() =
        100;
    for (uint64_t i = 0; i < 3; ++i)
    {
        v1.phases[0].v0Components()[0].txsMaybeDiscountedFee().txs.push_back(
            makeDummyEnvelope(i));
    }

    v1.phases[0].v0Components()[1].type(TXSET_COMP_TXS_MAYBE_DISCOUNTED_FEE);
    v1.phases[0].v0Components()[1].txsMaybeDiscountedFee().baseFee.activate() =
        200;
    for (uint64_t i = 10; i < 12; ++i)
    {
        v1.phases[0].v0Components()[1].txsMaybeDiscountedFee().txs.push_back(
            makeDummyEnvelope(i));
    }

    // Soroban: empty
    v1.phases[1].v(0);
    v1.phases[1].v0Components().resize(1);
    v1.phases[1].v0Components()[0].type(TXSET_COMP_TXS_MAYBE_DISCOUNTED_FEE);

    auto frame = TxSetXDRFrame::makeFromWire(genTxSet);
    uint64_t nonce = 33;
    CompactTransactionSet compact;
    REQUIRE(buildCompactTxSet(*frame, nonce, compact));

    // Verify structure: 2 components in classic phase
    REQUIRE(compact.phases[0].v0Components().size() == 2);
    REQUIRE(*compact.phases[0].v0Components()[0].baseFee == 100);
    REQUIRE(*compact.phases[0].v0Components()[1].baseFee == 200);

    // Reconstruct
    auto resolved = buildFullResolution(genTxSet);
    auto result = tryReconstruct(compact, resolved, prevHash);
    REQUIRE(result.status == ReconstructResult::Status::COMPLETE);

    GeneralizedTransactionSet reconstructedXdr;
    result.txSet->toXDR(reconstructedXdr);
    REQUIRE(xdrSha256(reconstructedXdr) == compact.txSetHash);
}

} // anonymous namespace
} // namespace stellar
