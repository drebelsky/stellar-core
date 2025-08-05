#pragma once

// Copyright 2017 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "transactions/PadForTestingOpFrame.h"

#ifdef BUILD_TESTS
namespace stellar
{
ThresholdLevel
PadForTestingOpFrame::getThresholdLevel() const
{
    return ThresholdLevel::LOW;
}

bool
PadForTestingOpFrame::isOpSupported(LedgerHeader const& header) const
{
    return true;
}

PadForTestingOpFrame::PadForTestingOpFrame(Operation const& op,
                                           TransactionFrame const& parentTx)
    : OperationFrame(op, parentTx)
    , mPadForTestingOp(mOperation.body.padForTestingOp())
{
}

bool
PadForTestingOpFrame::doApply(
    AppConnector& app, AbstractLedgerTxn& ltx, Hash const& sorobanBasePrngSeed,
    OperationResult& res,
    std::optional<RefundableFeeTracker>& refundableFeeTracker,
    OperationMetaBuilder& opMeta) const
{
    return true;
}

bool
PadForTestingOpFrame::doCheckValid(uint32_t ledgerVersion,
                                   OperationResult& res) const
{
    return true;
}
}
#endif
