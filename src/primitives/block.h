// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2020 ComputerCraftr
// Copyright (c) 2018-2020 The Simplicity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    static const uint32_t CURRENT_VERSION = 9;
    uint32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    // peercoin: two types of block: proof-of-work or proof-of-stake
    bool IsProofOfStake() const
    {
        // nNonce == 0 for PoS blocks
        return (nVersion & VERSION_ALGO) == VERSION_POS || (nVersion < CBlockHeader::CURRENT_VERSION && nNonce == 0);
    }

    bool IsProofOfWork() const
    {
        return (nVersion & VERSION_POW) || (nVersion < CBlockHeader::CURRENT_VERSION && nNonce != 0);
    }

    enum BlockType {
        ALGO_POS = 0,
        ALGO_POW_QUARK = 1,
        ALGO_POW_SCRYPT_SQUARED = 2,
        ALGO_COUNT
    };

    enum AlgoFlags {
        VERSION_POS = 1<<29,
        VERSION_POW_QUARK = 2<<29,
        VERSION_POW_SCRYPT_SQUARED = 3<<29,
        VERSION_ALGO = 7<<29,
        VERSION_POW = 6<<29
    };

    static int GetAlgo(int version)
    {
        switch (version & VERSION_ALGO) {
            case VERSION_POS:
                return ALGO_POS;
            case VERSION_POW_QUARK:
                return ALGO_POW_QUARK;
            case VERSION_POW_SCRYPT_SQUARED:
                return ALGO_POW_SCRYPT_SQUARED;
            default:
                return -1;
        }
    }

    static uint32_t GetVer(int algo)
    {
        switch (algo) {
            case ALGO_POS:
                return VERSION_POS;
            case ALGO_POW_QUARK:
                return VERSION_POW_QUARK;
            case ALGO_POW_SCRYPT_SQUARED:
                return VERSION_POW_SCRYPT_SQUARED;
            default:
                return CBlockHeader::CURRENT_VERSION;
        }
    }

    uint256 GetHash() const;
    uint256 GetPoWHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // peercoin: block signature - signed by coin base txout[0]'s owner
    std::vector<unsigned char> vchBlockSig;

    // memory only
    //mutable CTxOut txoutMasternode; // masternode payment
    //mutable std::vector<CTxOut> voutSuperblock; // superblock payment
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITEAS(CBlockHeader, *this);
        READWRITE(vtx);
        if (vtx.size() > 1 && vtx[1]->IsCoinStake())
            READWRITE(vchBlockSig);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        //txoutMasternode = CTxOut();
        //voutSuperblock.clear();
        fChecked = false;
        vchBlockSig.clear();
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    // peercoin: two types of block: proof-of-work or proof-of-stake
    /*bool IsProofOfStake() const
    {
        return (vtx.size() > 1 && vtx[1]->IsCoinStake());
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }*/

    unsigned int GetStakeEntropyBit() const; // peercoin: entropy bit for stake modifier if chosen by modifier

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
