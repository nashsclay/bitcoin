// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2020 ComputerCraftr
// Copyright (c) 2018-2020 The Simplicity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

// peercoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

/*const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, int algo)
{
    while (pindex && pindex->pprev && (CBlockHeader::GetAlgo(pindex->nVersion) != algo))
        pindex = pindex->pprev;
    return pindex;
}*/

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit[1]).GetCompact();
    if (pindexLast == nullptr /*|| params.fPowNoRetargeting*/)
        return nProofOfWorkLimit; // genesis block

    if (params.fPowAllowMinDifficultyBlocks) {
        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 2* 10 minutes
        // then allow mining of a min-difficulty block.
        /*if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + (20*60))
            return nProofOfWorkLimit;
        if (pindexLast->pprev && pindexLast->nBits == nProofOfWorkLimit) { TODO
            // Return the block before the last non-special-min-difficulty-rules-block
            const CBlockIndex* pindex = pindexLast;
            while (pindex->pprev && pindex->nBits == nProofOfWorkLimit)
                pindex = pindex->pprev;
            if (pindex->pprev)
                pindex = pindex->pprev;
            return pindex->nBits;
        }*/
        return DarkGravityWave4(pindexLast, pblock, params);
    } else {
        return CalculateNextTargetRequired(pindexLast, pblock, params);
    }
}

unsigned int CalculateNextTargetRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    //const int algo = CBlockHeader::GetAlgo(pblock->nVersion);
    const bool fProofOfStake = /*algo == POS ||*/ pblock->nNonce == 0; // nNonce = 0 for PoS blocks
    const arith_uint256 bnPowLimit = UintToArith256(fProofOfStake ? params.powLimit[0] : params.powLimit[1]);
    if (pindexLast == nullptr)
        return bnPowLimit.GetCompact(); // genesis block

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == nullptr)
        return bnPowLimit.GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == nullptr)
        return bnPowLimit.GetCompact(); // second block

    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime(); // difficulty for PoW and PoS are calculated separately

    // peercoin: target change every block
    // peercoin: retarget with exponential moving toward target spacing
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int64_t nTargetSpacing = params.nPowTargetSpacing;
    int64_t nTargetTimespan = params.nPowTargetTimespan;
    int64_t nInterval = params.DifficultyAdjustmentInterval();

    // Previous blunders with difficulty calculations follow...
    int nHeight = pindexLast->nHeight + 1;
    if (nHeight < params.nMandatoryUpgradeBlock[0]) {
        nTargetSpacing = 80; // The effective block time in the original Crave fork wallet was actually 40 seconds...
        nTargetTimespan = 20 * 60;
        nInterval = nTargetTimespan / nTargetSpacing;

        // Limiting the solvetime and how much the difficulty can rise here allows attackers to drop the difficulty to zero using timestamps in the past
        if (nActualSpacing < 0)
            nActualSpacing = nTargetSpacing;
    } else if (nHeight < params.nMandatoryUpgradeBlock[1]) {
        nTargetSpacing = 80;
        nTargetTimespan = 20 * 60;
        nInterval = nTargetTimespan / nTargetSpacing;

        // Difficulty was reset to before the scrypt difficulty bug started when the patch was deployed, so we need to account for the first two blocks on the new difficulty here
        //if (nHeight == 1035619) return 0x1f099ab7;
        //if (nHeight == 1035629) return 0x1f0382e8;

        if (!fProofOfStake)
            nTargetSpacing *= 4; // 4 * nTargetSpacing was used to get a 320 second target on both PoW algos, but nInterval wasn't adjusted accordingly...
        else
            nTargetSpacing *= 2; // 2 * nTargetSpacing was used to get a 160 second target on PoS, but nInterval wasn't adjusted accordingly...

        // Limiting the solvetime and how much the difficulty can rise here allows attackers to drop the difficulty to zero using timestamps in the past
        if (nActualSpacing < 1)
            nActualSpacing = 1;

        // Should have just returned bnPowLimit for one block instead of this nonsense
        //if (nHeight < (params.nMandatoryUpgradeBlock[0]+10) && nHeight >= params.nMandatoryUpgradeBlock[0])
            //bnNew *= (int)pow(4.0, 10.0+params.nMandatoryUpgradeBlock[0]-nHeight);
    } else { // Now that we got that over with, we can do it the right way here
        nTargetSpacing *= 2; // 160 second block time for PoW + 160 second block time for PoS = 80 second effective block time

        if (!fProofOfStake)
            nTargetSpacing *= 2; // Multiply by the number of PoW algos

        nInterval = nTargetTimespan / nTargetSpacing; // Update nInterval with new nTargetSpacing
    }

    // If nActualSpacing is very, very negative (close to but greater than -nTargetTimespan/2), it would cause the difficulty calculation to result
    // in zero or a negative number, so we have no choice but to limit the solvetime to the lowest value this method can handle. Ideally, this if
    // statement would become impossible to trigger by requiring sequential timestamps or MTP enforcement and a large enough nTargetTimespan. There
    // may be a way to extend this calculation to appropriately handle even lower negative numbers, but the difficulty already increases significantly
    // for small negative solvetimes and the next solvetime would have to be many times larger than this negative value in order to simply return
    // to the same difficulty as before, which can be modeled by the following equation where x is previous solvetime and f(x) is the next solvetime:
    // f(x) = ((nInterval + 1) * nTargetSpacing / 2)^2 / ((nInterval - 1) * nTargetSpacing / 2 + x) - ((nInterval - 1) * nTargetSpacing / 2)
    if (nActualSpacing <= -((nInterval - 1) * nTargetSpacing / 2))
        nActualSpacing = -((nInterval - 1) * nTargetSpacing / 2) + 1;

    // This is a linear equation used to adjust the next difficulty target based on the previous solvetime only (no averaging is used). On SPL, it
    // simplifies to f(x) = (x + 43160) / 43240 where x is nActualSpacing and bnNew is directly multiplied by f(x) to calculate the next difficulty
    // target. The equation is equal to 1 when x is 80 and the y-intercept of 43160 / 43240 is the result that we would arrive at from a solvetime of
    // zero, but the x-intercept at -43160 poses several problems for the difficulty calculation, as the target cannot be zero or a negative number.
    // This forces us to impose a restriction on solvetime such that x > -43160 which is an asymmetric limit on how much the difficulty can rise, but
    // enforcing sequential timestamps and our strict future time limit effectively mitigates the risk of this being exploited against us. The issue
    // is much more pronounced when using faster responding difficulty calculations, as the x-intercept for this function when we were using the 20
    // minute nTargetTimespan was only -560, and a block 10 minutes in the past would have already bumped into the solvetime limit and could be used
    // to lower the difficulty. Increasing nTargetTimespan or decreasing nTargetSpacing lowers the x-intercept farther in order to handle out of order
    // timestamps better, but this also slows the response time of the difficulty adjustment algorithm and makes it more stable. The first derivative
    // of f(x) (or simply the slope of this linear equation) is what determines how quickly the difficulty adjustment responds to changes in solvetimes,
    // with smaller derivatives corresponding to slower responding difficulty calculations. The derivative of our current equation is 1 / 43240 while
    // the previous equation with the 20 minute nTargetTimespan had a derivative of 1 / 640.
    uint64_t numerator = (nInterval - 1) * nTargetSpacing + 2 * nActualSpacing;
    uint64_t denominator = (nInterval + 1) * nTargetSpacing;

    // Keep in mind the integer division here - this is why the *= operator cannot be used, as it would change the order of operations so that the division occurred first
    bnNew = bnNew * numerator / denominator;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

unsigned int DarkGravityWave4(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    //const int algo = CBlockHeader::GetAlgo(pblock->nVersion);
    const bool fProofOfStake = /*algo == POS ||*/ pblock->nNonce == 0; // nNonce = 0 for PoS blocks
    const arith_uint256 bnPowLimit = UintToArith256(fProofOfStake ? params.powLimit[0] : params.powLimit[1]);
    uint32_t nPastBlocks = 24;
    if (pindexLast == nullptr)
        return bnPowLimit.GetCompact(); // genesis block

    const CBlockIndex *pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == nullptr)
        return bnPowLimit.GetCompact(); // first block
    const CBlockIndex *pindex = pindexPrev;
    arith_uint256 bnPastTargetAvg;

    // This is a simple moving average of difficulty targets with double weight for the most recent target
    // (2 * T1 + T2 + T3 + T4 + ...) / (24 + 1)
    for (unsigned int i = 1; i <= nPastBlocks; i++) {
        arith_uint256 bnTarget = arith_uint256().SetCompact(pindex->nBits);
        if (i == 1)
            bnTarget *= 2;
        bnPastTargetAvg += bnTarget / (nPastBlocks + 1);

        const CBlockIndex* pprev = GetLastBlockIndex(pindex->pprev, fProofOfStake);
        if (pprev /*&& i != nPastBlocks*/) // Skipping the last index here causes one too few timestamps to be used when calculating nActualTimespan
            pindex = pprev;
        else
            break;
    }

    arith_uint256 bnNew(bnPastTargetAvg);

    // If pprev was nullptr, nActualTimespan will use one fewer than nPastBlocks timestamps, which causes difficulty to be slightly higher than expected
    int64_t nActualTimespan = pindexPrev->GetBlockTime() - pindex->GetBlockTime();
    uint64_t nTargetTimespan = nPastBlocks * params.nPowTargetSpacing;

    // We have no choice but to limit the timespan here in case the calculation resulted in zero or a negative number, but it shouldn't be possible to reach this while requiring sequential timestamps or MTP enforcement
    if (nActualTimespan < 1)
        nActualTimespan = 1;

    // Keep in mind the integer division here - this is why the *= operator cannot be used, as it would change the order of operations so that the division occurred first
    bnNew = bnNew * nActualTimespan / nTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit[1]))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
