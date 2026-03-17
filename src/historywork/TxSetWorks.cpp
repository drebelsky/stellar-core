#include "src/historywork/TxSetWorks.h"
#include "history/HistoryArchiveManager.h"
#include "historywork/MakeRemoteDirWork.h"
#include "historywork/PutRemoteFileWork.h"
#include "util/GlobalChecks.h"
#include "work/WorkSequence.h"

namespace stellar
{

FetchTxSetWork::FetchTxSetWork(Application& app, Hash const& hash,
                               std::shared_ptr<HistoryArchive> const& archive,
                               std::function<void(TxSetXDRFrameConstPtr)> cb)
    : Work(app, "fetch-txset", BasicWork::RETRY_NEVER)
    , mTmpDir(app.getTmpDirManager().tmpDir("txset-fetch"))
    , mFileInfo(mTmpDir, FileType::HISTORY_FILE_TYPE_TXSET, binToHex(hash))
    , mGetAndUnzipWork(nullptr)
    , mCallback(cb)
    , mArchive(archive)

{
}

BasicWork::State
FetchTxSetWork::doWork()
{
    if (!mGetAndUnzipWork)
    {
        mGetAndUnzipWork =
            addWork<GetAndUnzipRemoteFileWork>(mFileInfo, mArchive);
        return State::WORK_RUNNING;
    }

    if (mGetAndUnzipWork->getState() != State::WORK_SUCCESS)
    {
        return mGetAndUnzipWork->getState();
    }

    XDRInputFileStream in;
    in.open(mFileInfo.localPath_nogz());
    StoredTransactionSet txSet;
    if (!in.readOne(txSet))
    {
        return State::WORK_FAILURE;
    }
    in.close();
    mTxSet = TxSetXDRFrame::makeFromStoredTxSet(txSet);
    // TODO: consider whether it's better to call the callback here or in
    // onSuccess
    return State::WORK_SUCCESS;
}

void
FetchTxSetWork::onSuccess()
{
    mCallback(mTxSet);
}

void
FetchTxSetWork::onFailureRaise()
{
    CLOG_ERROR(History, "Failed to fetch TxSet {} from archive {}",
               mFileInfo.baseName_nogz(), mArchive->getName());
    mCallback(nullptr);
}

void
FetchTxSetWork::onFailureRetry()
{
    CLOG_FATAL(History, "FetchTxSetWork should never retry");
    releaseAssert(false);
}

PutTxSetWork::PutTxSetWork(Application& app, Hash const& hash,
                           TxSetXDRFrameConstPtr txSet,
                           std::function<void(bool)> cb)
    : Work(app, "put-txset", BasicWork::RETRY_NEVER)
    , mTmpDir(app.getTmpDirManager().tmpDir("txset"))
    , mTxSet(txSet)
    , mCallback(cb)
    , mFileInfo(mTmpDir, FileType::HISTORY_FILE_TYPE_TXSET, binToHex(hash))
    , mGzipWork(nullptr)
{
    // We need to be able to disseminate non-generalized tx sets for the initial
    // upgrade releaseAssert(txSet->isGeneralizedTxSet());
}

BasicWork::State
PutTxSetWork::doWork()
{
    if (!mGzipWork)
    {
        XDROutputFileStream out(mApp.getClock().getIOContext(), true);
        out.open(mFileInfo.localPath_nogz());
        StoredTransactionSet xdrTxSet;
        mTxSet->storeXDR(xdrTxSet);
        out.writeOne(xdrTxSet);
        out.close();
        mGzipWork = addWork<GzipFileWork>(mFileInfo.localPath_nogz());
        return State::WORK_RUNNING;
    }

    if (mGzipWork->getState() != State::WORK_SUCCESS)
    {
        return mGzipWork->getState();
    }

    if (mUploadWorks.empty())
    {
        auto writableArchives =
            mApp.getHistoryArchiveManager().getWritableHistoryArchives();
        // TODO: will need to be thought about more for non-experimental version
        releaseAssert(!writableArchives.empty());
        for (auto const& archive : writableArchives)
        {
            auto mkdir = std::make_shared<MakeRemoteDirWork>(
                mApp, mFileInfo.remoteDir(), archive);
            auto putFile = std::make_shared<PutRemoteFileWork>(
                mApp, mFileInfo.localPath_gz(), mFileInfo.remoteName(),
                archive);
            mUploadWorks.emplace_back(addWork<WorkSequence>(
                "put-txset-upload-seq-" + archive->getName(),
                std::vector<std::shared_ptr<BasicWork>>{mkdir, putFile}));
        }
        return State::WORK_RUNNING;
    }

    return WorkUtils::getWorkStatus(mUploadWorks);
}

void
PutTxSetWork::onSuccess()
{
    mCallback(true);
}

void
PutTxSetWork::onFailureRaise()
{
    CLOG_ERROR(History, "Failed to put TxSet {}",
               binToHex(mTxSet->getContentsHash()), mFileInfo.remoteName());
    mCallback(false);
}

void
PutTxSetWork::onFailureRetry()
{
    CLOG_FATAL(History, "PutTxSetWork should never retry");
    releaseAssert(false);
}

} // stellar
