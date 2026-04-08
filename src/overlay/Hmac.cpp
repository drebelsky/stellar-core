#include "overlay/Hmac.h"
#ifdef BUILD_TESTS
#include "crypto/Random.h"
#endif
#include "crypto/SHA.h"
#include "util/GlobalChecks.h"
#include "util/types.h"
#include <xdrpp/marshal.h>

bool
Hmac::setSendMackey(HmacSha256Key const& key)
{
    ZoneScoped;
    LOCK_GUARD(mMutex, guard);
    if (!isZero(mSendMacKey.key))
    {
        return false;
    }
    mSendMacKey = key;
    return true;
}

bool
Hmac::setRecvMackey(HmacSha256Key const& key)
{
    ZoneScoped;
    LOCK_GUARD(mMutex, guard);
    if (!isZero(mRecvMacKey.key))
    {
        return false;
    }
    mRecvMacKey = key;
    return true;
}

namespace
{
template <typename T>
concept IsAuthenticatedMessageVariant =
    std::same_as<T, AuthenticatedMessage::_v0_t> ||
    std::same_as<T, AuthenticatedMessage::_v1_t>;

template <IsAuthenticatedMessageVariant T>
bool
checkAuth(T const& msg, HmacSha256Key const& recvMacKey, uint64_t expectedSeq,
          std::string& errorMsg)
{
    if (msg.sequence != expectedSeq)
    {
        errorMsg = "unexpected auth sequence";
        return false;
    }
    if (isZero(recvMacKey.key))
    {
        errorMsg = "receive mac key is zero";
        return false;
    }
    if (!hmacSha256Verify(msg.mac, recvMacKey,
                          xdr::xdr_to_opaque(msg.sequence, msg.message)))
    {
        errorMsg = "unexpected MAC";
        return false;
    }
    return true;
}
} // namespace

bool
Hmac::checkAuthenticatedMessage(AuthenticatedMessage const& msg,
                                std::string& errorMsg)
{
    ZoneScoped;
    LOCK_GUARD(mMutex, guard);

    if (msg.v() == 0)
    {
        if (!checkAuth(msg.v0(), mRecvMacKey, mRecvMacSeq, errorMsg))
        {
            return false;
        }
    }
    else if (!checkAuth(msg.v1(), mRecvMacKey, mRecvMacSeq, errorMsg))
    {
        return false;
    }

    ++mRecvMacSeq;
    return true;
}

void
Hmac::setAuthenticatedMessageBody(AuthenticatedMessage& aMsg,
                                  StellarMessage const& msg)

{
    ZoneScoped;
    LOCK_GUARD(mMutex, guard);

    aMsg.v(0);
    aMsg.v0().message = msg;
    if (msg.type() != HELLO && msg.type() != ERROR_MSG)
    {
        aMsg.v0().sequence = mSendMacSeq;
        aMsg.v0().mac =
            hmacSha256(mSendMacKey, xdr::xdr_to_opaque(mSendMacSeq, msg));
        mSendMacSeq++;
    }
}

void
Hmac::setAuthenticatedMessageBody(AuthenticatedMessage& aMsg,
                                  xdr::opaque_vec<>&& msg)

{
    ZoneScoped;
    LOCK_GUARD(mMutex, guard);

    aMsg.v(1);
    aMsg.v1().mac =
        hmacSha256(mSendMacKey, xdr::xdr_to_opaque(mSendMacSeq, msg));
    aMsg.v1().message = std::move(msg);
    aMsg.v1().sequence = mSendMacSeq;
    mSendMacSeq++;
}

#ifdef BUILD_TESTS
void
Hmac::damageRecvMacKey()
{
    LOCK_GUARD(mMutex, guard);
    auto bytes = randomBytes(mRecvMacKey.key.size());
    std::copy(bytes.begin(), bytes.end(), mRecvMacKey.key.begin());
}
#endif
