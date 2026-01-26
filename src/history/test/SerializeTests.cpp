// Copyright 2018 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "history/HistoryArchive.h"
#include "ledger/InMemorySorobanState.h"
#include "ledger/LedgerManager.h"
#include "ledger/LedgerTypeUtils.h"
#include "main/Application.h"
#include "test/Catch2.h"
#include "test/test.h"

#include <algorithm>
#include <fstream>
#include <string>
#include <vector>

using namespace stellar;

namespace
{
LedgerEntry
constructTTLEntry(LedgerEntry const& entry, TTLData const& ttlData)
{
    auto ttlKey = getTTLKey(entry);
    LedgerEntry ttlEntry;
    ttlEntry.data.type(TTL);
    ttlEntry.data.ttl().keyHash = ttlKey.ttl().keyHash;
    ttlEntry.data.ttl().liveUntilLedgerSeq = ttlData.liveUntilLedgerSeq;
    ttlEntry.lastModifiedLedgerSeq = ttlData.lastModifiedLedgerSeq;
    return ttlEntry;
}
} // namespace

TEST_CASE("Serialization round trip", "[history]")
{
    std::vector<std::string> testFiles = {
        "stellar-history.testnet.6714239.json",
        "stellar-history.livenet.15686975.json",
        "stellar-history.testnet.6714239.networkPassphrase.json",
        "stellar-history.testnet.6714239.networkPassphrase.v2.json"};
    for (size_t i = 0; i < testFiles.size(); i++)
    {
        auto testFilePath = getBuildTestDataPath(testFiles[i]);
        SECTION("Serialize " + testFilePath.string())
        {
            std::ifstream in(testFilePath);
            REQUIRE(in);
            in.exceptions(std::ios::badbit);
            std::string hasString((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());

            // Test fromString
            HistoryArchiveState has;
            has.fromString(hasString);
            REQUIRE(hasString == has.toString());

            // Test load
            HistoryArchiveState hasLoad;
            hasLoad.load(testFilePath.string());
            REQUIRE(hasString == hasLoad.toString());
        }
    }
}

TEST_CASE("tmp")
{
    REQUIRE(!chdir("/Users/daniel/sc-run/"));
    VirtualClock clock;
    Config cfg;
    cfg.load("pubnet.cfg");
    Application::pointer app = Application::create(clock, cfg, false);
    auto& lm = app->getLedgerManager();
    lm.loadLastKnownLedger();

    auto const& sorobanState = lm.getInMemorySorobanStateForTesting();

    // Helper to write sorted entry/TTL pairs to a binary file
    auto writeSortedPairs =
        [](std::string const& filename,
           std::vector<std::pair<xdr::opaque_vec<>, xdr::opaque_vec<>>>& pairs) {
            // Sort by serialized LedgerEntry bytes (lexicographic)
            std::sort(pairs.begin(), pairs.end(),
                      [](auto const& a, auto const& b) {
                          return a.first < b.first;
                      });

            std::ofstream out(filename, std::ios::binary);
            out.exceptions(std::ios::failbit | std::ios::badbit);
            for (auto const& [entryBytes, ttlBytes] : pairs)
            {
                out.write(reinterpret_cast<char const*>(entryBytes.data()),
                          entryBytes.size());
                out.write(reinterpret_cast<char const*>(ttlBytes.data()),
                          ttlBytes.size());
            }
        };

    // Write CONTRACT_DATA entries
    {
        std::vector<std::pair<xdr::opaque_vec<>, xdr::opaque_vec<>>> pairs;
        for (auto const& mapEntry : sorobanState.mContractDataEntries)
        {
            auto const& entry = mapEntry.get();
            auto const& le = *entry.ledgerEntry;
            auto ttlEntry = constructTTLEntry(le, entry.ttlData);

            pairs.emplace_back(xdr::xdr_to_opaque(le),
                               xdr::xdr_to_opaque(ttlEntry));
        }
        writeSortedPairs("contract_data.bin", pairs);
    }

    // Write CONTRACT_CODE entries
    {
        std::vector<std::pair<xdr::opaque_vec<>, xdr::opaque_vec<>>> pairs;
        for (auto const& [keyHash, entry] : sorobanState.mContractCodeEntries)
        {
            auto const& le = *entry.ledgerEntry;
            auto ttlEntry = constructTTLEntry(le, entry.ttlData);

            pairs.emplace_back(xdr::xdr_to_opaque(le),
                               xdr::xdr_to_opaque(ttlEntry));
        }
        writeSortedPairs("contract_code.bin", pairs);
    }
}
