// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "privatesend-util.h"

CKeyHolder::CKeyHolder(CWallet* pwallet) :
    reserveKey(pwallet)
{
    reserveKey.GetReservedDestination(OutputType::BECH32, dest, false); //OutputType::LEGACY TODO CHECK IF THIS IS OKAY OR IF DEFAULT ADDRESS TYPE SHOULD BE USED
}

void CKeyHolder::KeepDestination()
{
    reserveKey.KeepDestination();
}

void CKeyHolder::ReturnDestination()
{
    reserveKey.ReturnDestination();
}

CScript CKeyHolder::GetScriptForDestination() const
{
    return ::GetScriptForDestination(dest);
}


CScript CKeyHolderStorage::AddKey(CWallet* pwallet)
{
    auto keyHolder = std::unique_ptr<CKeyHolder>(new CKeyHolder(pwallet));
    auto script = keyHolder->GetScriptForDestination();

    LOCK(cs_storage);
    storage.emplace_back(std::move(keyHolder));
    LogPrintf("CKeyHolderStorage::%s -- storage size %lld\n", __func__, storage.size());
    return script;
}

void CKeyHolderStorage::KeepAll()
{
    std::vector<std::unique_ptr<CKeyHolder>> tmp;
    {
        // don't hold cs_storage while calling KeepDestination(), which might lock cs_wallet
        LOCK(cs_storage);
        std::swap(storage, tmp);
    }

    if (tmp.size() > 0) {
        for (auto &key : tmp) {
            key->KeepDestination();
        }
        LogPrintf("CKeyHolderStorage::%s -- %lld keys kept\n", __func__, tmp.size());
    }
}

void CKeyHolderStorage::ReturnAll()
{
    std::vector<std::unique_ptr<CKeyHolder>> tmp;
    {
        // don't hold cs_storage while calling ReturnDestination(), which might lock cs_wallet
        LOCK(cs_storage);
        std::swap(storage, tmp);
    }

    if (tmp.size() > 0) {
        for (auto &key : tmp) {
            key->ReturnDestination();
        }
        LogPrintf("CKeyHolderStorage::%s -- %lld keys returned\n", __func__, tmp.size());
    }
}
