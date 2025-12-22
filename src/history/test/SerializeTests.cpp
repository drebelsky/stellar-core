// Copyright 2018 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "history/HistoryArchive.h"
#include "ledger/LedgerManager.h"
#include "main/Application.h"
#include "test/Catch2.h"
#include "test/test.h"

#include <fstream>
#include <string>

using namespace stellar;

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
#if 0
    auto snapshot = app->getBucketManager()
                        .getBucketSnapshotManager()
                        .copySearchableLiveBucketListSnapshot();
    auto& snap = *snapshot;
    auto x = snap.getSnapshot();
    auto& levels = x.getLevels();
    auto& level = levels[10];
    auto& bucket = *level.curr.mBucket;
    auto& index = *bucket.mIndex;
    auto& memIndex = *index.mInMemoryIndex;
    auto& disIndex = *index.mDiskIndex;
    CLOG_FATAL(Ledger, "GREP {}", index.lookup);
#endif
}

TEST_CASE("tmp2")
{
    REQUIRE(!chdir("/Users/daniel/sc-run/buckets"));
    XDRInputFileStream fs;
    fs.open(std::string{"bucket-"
                        "d2eec36a3eb7bf2a517fe2593d7adbb747cce6722fa953b2ccaec7"
                        "ef78f30d0e.xdr"});
    BucketEntry be;
    size_t total = 0;
    while (fs.readOne(be))
        total++;
    CLOG_FATAL(Ledger, "GREP {}", total);
}
