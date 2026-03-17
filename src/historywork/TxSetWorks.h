#include "herder/TxSetFrame.h"
#include "history/FileTransferInfo.h"
#include "historywork/GetAndUnzipRemoteFileWork.h"
#include "historywork/GzipFileWork.h"
#include "work/Work.h"

namespace stellar
{
class FetchTxSetWork : public Work
{
  public:
    // Unlike other Works that take an archive, archive is not optional here
    // because TxSets are only stored in specific archives
    // cb is called with nullptr if the fetch fails, and with the TxSet if it
    // succeeds
    FetchTxSetWork(Application& app, Hash const& hash,
                   std::shared_ptr<HistoryArchive> const& archive,
                   std::function<void(TxSetXDRFrameConstPtr)> cb);

  protected:
    BasicWork::State doWork() override;
    void onSuccess() final;
    void onFailureRaise() final;
    void onFailureRetry() final;

  private:
    // TODO: instead of inheriting, we hold GetAndUnzipRemoteFileWork as a child
    // work because we can't construct the file info adequately, otherwise
    TmpDir mTmpDir;
    FileTransferInfo mFileInfo;
    std::shared_ptr<GetAndUnzipRemoteFileWork> mGetAndUnzipWork;
    std::function<void(TxSetXDRFrameConstPtr)> mCallback;
    std::shared_ptr<HistoryArchive> mArchive;
    TxSetXDRFrameConstPtr mTxSet;
};

class PutTxSetWork : public Work
{
  public:
    // cb is called with `true` if the put succeeds, and with `false` if it
    // fails
    PutTxSetWork(Application& app, Hash const& hash,
                 TxSetXDRFrameConstPtr txSet, std::function<void(bool)> cb);

  protected:
    BasicWork::State doWork() override;
    void onSuccess() override final;
    void onFailureRaise() override;
    void onFailureRetry() override;

  private:
    TmpDir mTmpDir;
    TxSetXDRFrameConstPtr mTxSet;
    std::function<void(bool)> mCallback;
    FileTransferInfo mFileInfo;

    std::shared_ptr<GzipFileWork> mGzipWork;
    std::list<std::shared_ptr<BasicWork>> mUploadWorks;
};
} // namespace stellar
