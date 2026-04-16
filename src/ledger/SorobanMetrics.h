// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include <cstdint>

namespace stellar
{
class MetricsRegistry;

// Placeholder for what used to be a large medida-backed cache of
// soroban/network-config metrics. All fields have been removed; callers that
// previously read these metrics get a no-op API (accumulate calls are silently
// dropped, publishAndResetLedgerWideMetrics does nothing).
class SorobanMetrics
{
  public:
    SorobanMetrics(MetricsRegistry&)
    {
    }

    void
    accumulateModelledCpuInsns(uint64_t, uint64_t, uint64_t)
    {
    }
    void
    accumulateLedgerTxCount(uint64_t)
    {
    }
    void
    accumulateLedgerCpuInsn(uint64_t)
    {
    }
    void
    accumulateLedgerTxsSizeByte(uint64_t)
    {
    }
    void
    accumulateLedgerReadEntry(uint64_t)
    {
    }
    void
    accumulateLedgerReadByte(uint64_t)
    {
    }
    void
    accumulateLedgerWriteEntry(uint64_t)
    {
    }
    void
    accumulateLedgerWriteByte(uint64_t)
    {
    }

    void
    publishAndResetLedgerWideMetrics()
    {
    }
};
}
