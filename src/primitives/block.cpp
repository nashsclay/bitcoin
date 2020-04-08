// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2020 ComputerCraftr
// Copyright (c) 2018-2020 The Simplicity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <streams.h>
#include <tinyformat.h>
#include <crypto/common.h>
#include <crypto/scrypt.h>

uint256 CBlockHeader::GetHash() const
{
    if (nVersion > 1)
        return SerializeHash(*this);
    /*else if (nVersion == 0) {
        std::vector<unsigned char> vch(80); // block header size in bytes
        CVectorWriter ss(SER_NETWORK, PROTOCOL_VERSION, vch, 0);
        ss << *this;
        uint256 thash;
        scrypt_N_1_1_256((const char*)vch.data(), (char*)&thash, 1024);
        return thash;
    }*/ else {
        std::vector<unsigned char> vch(80); // block header size in bytes
        CVectorWriter ss(SER_NETWORK, PROTOCOL_VERSION, vch, 0);
        ss << *this;
        return HashQuark((const char*)vch.data(), (const char*)vch.data() + vch.size());
    }
}

uint256 CBlockHeader::GetPoWHash() const
{
    std::vector<unsigned char> vch(80); // block header size in bytes
    CVectorWriter ss(SER_NETWORK, PROTOCOL_VERSION, vch, 0);
    ss << *this;
    if (GetAlgo(nVersion) == ALGO_POW_SCRYPT_SQUARED) {
        uint256 thash;
        scrypt_N_1_1_256((const char*)vch.data(), (char*)&thash, 1048576);
        return thash;
    } else
        return HashQuark((const char*)vch.data(), (const char*)vch.data() + vch.size());
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, type=%i, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        GetAlgo(nVersion) == -1 ? IsProofOfWork() : GetAlgo(nVersion),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
