// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2020 John "ComputerCraftr" Studnicka
// Copyright (c) 2018-2020 The Simplicity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

// peercoin: find last block index up to pindex
static inline const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, const bool fProofOfStake)
{
    while (pindex && pindex->pprev && pindex->IsProofOfStake() != fProofOfStake)
        pindex = pindex->pprev;
    return pindex;
}

static inline const CBlockIndex* GetLastBlockIndexForAlgo(const CBlockIndex* pindex, const int& algo)
{
    while (pindex && pindex->pprev && CBlockHeader::GetAlgo(pindex->nVersion) != algo)
        pindex = pindex->pprev;
    return pindex;
}

static inline const CBlockIndex* GetASERTReferenceBlockAndHeightForAlgo(const CBlockIndex* pindex, const uint32_t& nProofOfWorkLimit, const int& nASERTStartHeight, const int& algo, uint32_t& nBlocksPassed)
{
    nBlocksPassed = 0;
    while (pindex && pindex->pprev && pindex->nHeight >= nASERTStartHeight) {
        //if (pindex->nBits != (nProofOfWorkLimit - 1))
            nBlocksPassed++;
        const CBlockIndex* pprev = GetLastBlockIndexForAlgo(pindex->pprev, algo);
        if (pprev)
            pindex = pprev;
        else
            break;
    }
    return pindex;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const int algo = CBlockHeader::GetAlgo(pblock->nVersion);
    const uint32_t nProofOfWorkLimit = UintToArith256(params.powLimit[algo == -1 ? CBlockHeader::ALGO_POW_QUARK : algo]).GetCompact();
    if (pindexLast == nullptr || params.fPowNoRetargeting)
        return nProofOfWorkLimit;

    if (pindexLast->nHeight+1 >= params.nMandatoryUpgradeBlock[1] && params.fPowAllowMinDifficultyBlocks && algo != -1) {
        // Special difficulty rule:
        // If the new block's timestamp is more than 30 minutes (be careful to ensure this is at least twice the actual PoW target spacing to avoid interfering with retargeting)
        // then allow mining of a min-difficulty block.
        const CBlockIndex* pindexPrev = GetLastBlockIndexForAlgo(pindexLast, algo);
        if (pindexPrev->nHeight > 10 && pblock->GetBlockTime() > pindexPrev->GetBlockTime() + (30*60))
            return (nProofOfWorkLimit - 1);
        if (pindexPrev->pprev && pindexPrev->nBits == (nProofOfWorkLimit - 1)) {
            // Return the block before the last non-special-min-difficulty-rules-block
            const CBlockIndex* pindex = pindexPrev;
            while (pindex->pprev && (pindex->nBits == (nProofOfWorkLimit - 1) || CBlockHeader::GetAlgo(pindex->nVersion) != algo))
                pindex = pindex->pprev;
            const CBlockIndex* pprev = GetLastBlockIndexForAlgo(pindex->pprev, algo);
            if (pprev && pprev->nHeight > 10) {
                // Don't return pprev->nBits if it is another min-difficulty block; instead return pindex->nBits
                if (pprev->nBits != (nProofOfWorkLimit - 1))
                    return pprev->nBits;
                else
                    return pindex->nBits;
            }
        }
    }

    return SimpleTargetFrontier(pindexLast, pblock, params);
    /*if (pblock->IsProofOfStake() && (unsigned)(pindexLast->nHeight+1) >= (params.nMandatoryUpgradeBlock[1]+params.nMinerConfirmationWindow))
        return SimpleMovingAverageTarget(pindexLast, pblock, params);
    else
        return CalculateNextTargetRequired(pindexLast, pblock, params);*/
}

unsigned int CalculateNextTargetRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const int algo = CBlockHeader::GetAlgo(pblock->nVersion);
    const bool fProofOfStake = pblock->IsProofOfStake();
    const arith_uint256 bnPowLimit = algo == -1 ? UintToArith256(params.powLimit[fProofOfStake ? CBlockHeader::ALGO_POS : CBlockHeader::ALGO_POW_QUARK]) : UintToArith256(params.powLimit[algo]);
    const uint32_t nProofOfWorkLimit = bnPowLimit.GetCompact();
    if (pindexLast == nullptr)
        return nProofOfWorkLimit; // genesis block

    const CBlockIndex* pindexPrev = algo == -1 ? GetLastBlockIndex(pindexLast, fProofOfStake) : GetLastBlockIndexForAlgo(pindexLast, algo);
    if (pindexPrev->pprev == nullptr)
        return nProofOfWorkLimit; // first block

    const CBlockIndex* pindexPrevPrev = algo == -1 ? GetLastBlockIndex(pindexPrev->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindexPrev->pprev, algo);
    if (pindexPrevPrev->pprev == nullptr)
        return nProofOfWorkLimit; // second block

    int nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime(); // Difficulty for PoW and PoS are calculated separately

    // peercoin: target change every block
    // peercoin: retarget with exponential moving toward target spacing
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int nTargetSpacing = params.nPowTargetSpacing;
    uint32_t nTargetTimespan = params.nPowTargetTimespan;
    int nInterval = params.DifficultyAdjustmentInterval(); // alpha_reciprocal = (N(SMA) + 1) / 2 for same "center of mass" as SMA

    // Previous blunders with difficulty calculations follow...
    const int nHeight = pindexLast->nHeight + 1;
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
        if (nHeight == 1035619 && pblock->nTime == 1574157019 && algo == CBlockHeader::ALGO_POW_SCRYPT_SQUARED && pindexPrev->GetBlockHash() == uint256S("0x676df2e0427b68622343a0f1fb4e683dfc587ed6d49e5566dcca2dcbb179f5d2")) return 0x1f099ab7;
        if (nHeight == 1035629 && pblock->nTime == 1574158315 && algo == CBlockHeader::ALGO_POW_SCRYPT_SQUARED && pindexPrev->GetBlockHash() == uint256S("0x1787ac2c2d10543cdea74c15f1cbbdd95988eeea420cf55c5f50890c208f4f14")) return 0x1f0382e8;

        if (!fProofOfStake)
            nTargetSpacing *= 4; // 4 * nTargetSpacing was used to get a 320 second target on both PoW algos, but nInterval wasn't adjusted accordingly, so the effective interval was actually 4 * nInterval
        else
            nTargetSpacing *= 2; // 2 * nTargetSpacing was used to get a 160 second target on PoS, but nInterval wasn't adjusted accordingly, so the effective interval was actually 2 * nInterval

        // Limiting the solvetime and how much the difficulty can rise here allows attackers to drop the difficulty to zero using timestamps in the past
        if (nActualSpacing < 1)
            nActualSpacing = 1;

        // Should have just returned nProofOfWorkLimit for one block instead of this nonsense
        //if (nHeight < (params.nMandatoryUpgradeBlock[0]+10) && nHeight >= params.nMandatoryUpgradeBlock[0])
            //bnNew *= (int)pow(4.0, 10.0+params.nMandatoryUpgradeBlock[0]-nHeight);
    } else { // Now that we got that over with, we can do it the right way here
        nTargetSpacing *= 2; // 160 second block time for PoW + 160 second block time for PoS = 80 second effective block time

        if (!fProofOfStake)
            nTargetSpacing *= (CBlockHeader::ALGO_COUNT - 1); // Multiply by the number of PoW algos

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
    // simplifies to f(x) = (x + 3560) / 3640 where x is nActualSpacing and bnNew is directly multiplied by f(x) to calculate the next difficulty
    // target. The equation is equal to 1 when x is 80 and the y-intercept of 3560 / 3640 is the result that we would arrive at from a solvetime of
    // zero, but the x-intercept at -3560 poses several problems for the difficulty calculation, as the target cannot be zero or a negative number.
    // This forces us to impose a restriction on solvetime such that x > -3560 which is an asymmetric limit on how much the difficulty can rise, but
    // enforcing sequential timestamps and our strict future time limit effectively mitigates the risk of this being exploited against us. The issue
    // is much more pronounced when using faster responding difficulty calculations, as the x-intercept for this function when we were using the 20
    // minute nTargetTimespan was only -560, and a block 10 minutes in the past would have already bumped into the solvetime limit and could be used
    // to lower the difficulty. Increasing nTargetTimespan or decreasing nTargetSpacing lowers the x-intercept farther in order to handle out of order
    // timestamps better, but this also slows the response time of the difficulty adjustment algorithm and makes it more stable. The first derivative
    // of f(x) (or simply the slope of this linear equation) is what determines how quickly the difficulty adjustment responds to changes in solvetimes,
    // with smaller derivatives corresponding to slower responding difficulty calculations. The derivative of our current equation is 1 / 3640 while
    // the previous equation with the 20 minute nTargetTimespan had a derivative of 1 / 640.
    const uint32_t numerator = (nInterval - 1) * nTargetSpacing + 2 * nActualSpacing;
    const uint32_t denominator = (nInterval + 1) * nTargetSpacing;

    // Keep in mind the order of operations and integer division here - this is why the *= operator cannot be used, as it could cause overflow or integer division to occur
    arith_uint512 bnNew512 = arith_uint512(bnNew) * numerator / denominator; // For peercoin: next_target = prev_target * (nInterval - 1 + 2 * prev_solvetime/target_solvetime) / (nInterval + 1)

    // Some algorithms were affected by the arith_uint256 overflow bug while calculating difficulty, so we need to use the old formula here
    if (nHeight < params.nMandatoryUpgradeBlock[1] && (algo == CBlockHeader::ALGO_POW_QUARK || algo == CBlockHeader::ALGO_POW_SCRYPT_SQUARED))
        bnNew = bnNew * numerator / denominator;
    else
        bnNew = bnNew512.trim256();

    if (bnNew > bnPowLimit || bnNew512 > arith_uint512(bnPowLimit) || bnNew == arith_uint256())
        bnNew = bnPowLimit;

    return nHeight < params.nMandatoryUpgradeBlock[1] ? bnNew.GetCompact() : bnNew.GetCompactRounded();
}

unsigned int WeightedTargetExponentialMovingAverage(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const int algo = CBlockHeader::GetAlgo(pblock->nVersion);
    const bool fProofOfStake = pblock->IsProofOfStake();
    const arith_uint256 bnPowLimit = algo == -1 ? UintToArith256(params.powLimit[fProofOfStake ? CBlockHeader::ALGO_POS : CBlockHeader::ALGO_POW_QUARK]) : UintToArith256(params.powLimit[algo]);
    const uint32_t nProofOfWorkLimit = bnPowLimit.GetCompact();
    if (pindexLast == nullptr)
        return nProofOfWorkLimit; // genesis block

    const CBlockIndex* pindexPrev = algo == -1 ? GetLastBlockIndex(pindexLast, fProofOfStake) : GetLastBlockIndexForAlgo(pindexLast, algo);
    if (pindexPrev->pprev == nullptr)
        return nProofOfWorkLimit; // first block

    const CBlockIndex* pindexPrevPrev = algo == -1 ? GetLastBlockIndex(pindexPrev->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindexPrev->pprev, algo);
    if (pindexPrevPrev->pprev == nullptr)
        return nProofOfWorkLimit; // second block

    int nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime(); // Difficulty for PoW and PoS are calculated separately

    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int nTargetSpacing = params.nPowTargetSpacing;
    const uint32_t nTargetTimespan = params.nPowTargetTimespan;
    nTargetSpacing *= 2; // 160 second block time for PoW + 160 second block time for PoS = 80 second effective block time
    if (!fProofOfStake)
        nTargetSpacing *= (CBlockHeader::ALGO_COUNT - 1); // Multiply by the number of PoW algos
    const int nInterval = nTargetTimespan / (nTargetSpacing * 2); // alpha_reciprocal = (N(SMA) + 1) / 2 for same "center of mass" as SMA

    // nActualSpacing must be restricted as to not produce a negative number below
    if (nActualSpacing <= -((nInterval - 1) * nTargetSpacing))
        nActualSpacing = -((nInterval - 1) * nTargetSpacing) + 1;

    const uint32_t numerator = (nInterval - 1) * nTargetSpacing + nActualSpacing;
    const uint32_t denominator = nInterval * nTargetSpacing;

    // Keep in mind the order of operations and integer division here - this is why the *= operator cannot be used, as it could cause overflow or integer division to occur
    arith_uint512 bnNew512 = arith_uint512(bnNew) * numerator / denominator; // For WTEMA: next_target = prev_target * (nInterval - 1 + prev_solvetime/target_solvetime) / nInterval
    bnNew = bnNew512.trim256();

    if (bnNew512 > arith_uint512(bnPowLimit) || bnNew == arith_uint256())
        bnNew = bnPowLimit;

    return bnNew.GetCompactRounded();
}

unsigned int ASERT(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const int algo = CBlockHeader::GetAlgo(pblock->nVersion);
    const bool fProofOfStake = pblock->IsProofOfStake();
    const arith_uint256 bnPowLimit = algo == -1 ? UintToArith256(params.powLimit[fProofOfStake ? CBlockHeader::ALGO_POS : CBlockHeader::ALGO_POW_QUARK]) : UintToArith256(params.powLimit[algo]);
    const uint32_t nProofOfWorkLimit = bnPowLimit.GetCompact();
    uint32_t nTargetSpacing = params.nPowTargetSpacing;
    nTargetSpacing *= 2; // 160 second block time for PoW + 160 second block time for PoS = 80 second effective block time
    if (!fProofOfStake)
        nTargetSpacing *= (CBlockHeader::ALGO_COUNT - 1); // Multiply by the number of PoW algos

    if (pindexLast == nullptr)
        return nProofOfWorkLimit; // genesis block

    const CBlockIndex* pindexPrev = algo == -1 ? GetLastBlockIndex(pindexLast, fProofOfStake) : GetLastBlockIndexForAlgo(pindexLast, algo);
    if (pindexPrev->pprev == nullptr)
        return nProofOfWorkLimit; // first block

    const CBlockIndex* pindexPrevPrev = algo == -1 ? GetLastBlockIndex(pindexPrev->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindexPrev->pprev, algo);
    if (pindexPrevPrev->pprev == nullptr)
        return nProofOfWorkLimit; // second block

    const uint32_t nASERTStartHeight = 30;
    const uint32_t nASERTBlockTargetsToAverage = 10; //params.nASERTBlockTargetAveragingTimespan / nTargetSpacing;

    const uint32_t nHeight = pindexLast->nHeight + 1;
    if (nHeight < nASERTStartHeight)
        return WeightedTargetExponentialMovingAverage(pindexLast, pblock, params);

    uint32_t nBlocksPassed = 0;
    const CBlockIndex* pindexReferenceBlock = GetASERTReferenceBlockAndHeightForAlgo(pindexPrev, nProofOfWorkLimit, nASERTStartHeight, algo, nBlocksPassed);
    const int64_t nTimeDiff = pindexPrev->GetBlockTime() - pindexReferenceBlock->GetBlockTime();
    const uint32_t nHeightDiff = nBlocksPassed; //pindexPrev->nHeight - pindexReferenceBlock->nHeight;
    arith_uint256 refBlockTarget;

    if (nASERTBlockTargetsToAverage && nHeight >= nASERTStartHeight + nASERTBlockTargetsToAverage) {
        const uint32_t nBlocksToSkip = nHeightDiff % nASERTBlockTargetsToAverage; // todo: check that this isn't off by one
        const CBlockIndex* pindex = pindexPrev;

        for (unsigned int i = 0; i < nBlocksToSkip; i++) {
            pindex = algo == -1 ? GetLastBlockIndex(pindex->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindex->pprev, algo);
        }

        for (unsigned int i = 0; i < nASERTBlockTargetsToAverage; i++) {
            if (pindex->nBits != (nProofOfWorkLimit - 1) || !params.fPowAllowMinDifficultyBlocks) { // Don't add min difficulty targets to the average
                arith_uint256 bnTarget = arith_uint256().SetCompact(pindex->nBits);
                refBlockTarget += bnTarget / nASERTBlockTargetsToAverage;
            } else
                i--; // Average one more block to make up for the one we skipped
            pindex = algo == -1 ? GetLastBlockIndex(pindex->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindex->pprev, algo);
        }
    } else
        refBlockTarget = arith_uint256().SetCompact(pindexReferenceBlock->nBits);

    arith_uint256 bnNew(refBlockTarget);
    const int64_t dividend = nTimeDiff - nTargetSpacing * nHeightDiff;
    const uint32_t divisor = params.nPowTargetTimespan; // Must be positive
    const int exponent = dividend / divisor; // todo: apparently this rounds down positive and rounds up negative numbers
    const uint32_t remainder = dividend >= 0 ? dividend % divisor : -dividend % divisor; // Must be positive
    arith_uint256 numerator = 1; // We are using uint256 rather than uint64_t here because a nPowTargetTimespan of more than 7 days in the divisor would cause the following cubic approximation to overflow a uint64_t
    arith_uint256 denominator = 1;

    if (exponent >= 0) {
        for (int i = 0; i < exponent; i++)
            numerator *= 2;

        if (remainder != 0) { // Approximate 2^x with (4x^3+11x^2+35x+50)/50 for 0<x<1 (must be equal to 1 at x=0 and equal to 2 at x=1 to avoid discontinuities) - note: x+1 and (3x^2+7x+10)/10 are also decent and less complicated approximations
            //numerator *= divisor + remainder;
            //denominator *= divisor;
            const arith_uint256 bnDivisor(divisor);
            const arith_uint256 bnRemainder(remainder);
            numerator = numerator * ((4 * bnRemainder*bnRemainder*bnRemainder) + (11 * bnRemainder*bnRemainder * bnDivisor) + (35 * bnRemainder * bnDivisor*bnDivisor) + (50 * bnDivisor*bnDivisor*bnDivisor));
            denominator = denominator * (50 * bnDivisor*bnDivisor*bnDivisor);
        }
    } else {
        for (int i = 0; i > exponent; i--)
            denominator *= 2;

        if (remainder != 0) { // Approximate 2^x with (4x^3+11x^2+35x+50)/50 for 0<x<1 (must be equal to 1 at x=0 and equal to 2 at x=1 to avoid discontinuities) - note: x+1 and (3x^2+7x+10)/10 are also decent and less complicated approximations
            //numerator *= divisor;
            //denominator *= divisor + remainder;
            const arith_uint256 bnDivisor(divisor);
            const arith_uint256 bnRemainder(remainder);
            numerator = numerator * (50 * bnDivisor*bnDivisor*bnDivisor);
            denominator = denominator * ((4 * bnRemainder*bnRemainder*bnRemainder) + (11 * bnRemainder*bnRemainder * bnDivisor) + (35 * bnRemainder * bnDivisor*bnDivisor) + (50 * bnDivisor*bnDivisor*bnDivisor));
        }
    }

    // Keep in mind the order of operations and integer division here - this is why the *= operator cannot be used, as it could cause overflow or integer division to occur
    arith_uint512 bnNew512 = arith_uint512(bnNew) * arith_uint512(numerator) / arith_uint512(denominator);
    bnNew = bnNew512.trim256();

    //printf("numerator = %s\n", numerator.ToString().c_str());
    //printf("denominator = %s\n", denominator.ToString().c_str());
    //printf("10000 * 2^(%li/%u) = %s\n", dividend, divisor, arith_uint512((10000 * arith_uint512(numerator)) / arith_uint512(denominator)).trim256().ToString().c_str());
    if (bnNew512 > arith_uint512(bnPowLimit) || bnNew == arith_uint256())
        bnNew = bnPowLimit;

    return bnNew.GetCompactRounded();
}

unsigned int SimpleTargetFrontier(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const int algo = CBlockHeader::GetAlgo(pblock->nVersion);
    const bool fProofOfStake = pblock->IsProofOfStake();
    const arith_uint256 bnPowLimit = algo == -1 ? UintToArith256(params.powLimit[fProofOfStake ? CBlockHeader::ALGO_POS : CBlockHeader::ALGO_POW_QUARK]) : UintToArith256(params.powLimit[algo]);
    const uint32_t nProofOfWorkLimit = bnPowLimit.GetCompact();
    if (pindexLast == nullptr)
        return nProofOfWorkLimit; // genesis block

    const CBlockIndex* pindexPrev = algo == -1 ? GetLastBlockIndex(pindexLast, fProofOfStake) : GetLastBlockIndexForAlgo(pindexLast, algo);
    if (pindexPrev->pprev == nullptr)
        return nProofOfWorkLimit; // first block

    const CBlockIndex* pindexPrevPrev = algo == -1 ? GetLastBlockIndex(pindexPrev->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindexPrev->pprev, algo);
    if (pindexPrevPrev->pprev == nullptr)
        return nProofOfWorkLimit; // second block

    const uint32_t nStartHeight = 5;

    const uint32_t nHeight = pindexLast->nHeight + 1;
    if (nHeight < nStartHeight)
        //return WeightedTargetExponentialMovingAverage(pindexLast, pblock, params);
        return 0x1d2fffff;

    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime(); // Difficulty for PoW and PoS are calculated separately

    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int64_t nTargetSpacing = params.nPowTargetSpacing;
    uint32_t nTargetAdjustmentPercentage = 1; // Target will adjust up or down by 0.1% every block depending on whether the previous solvetime was slow or fast (2% = 17 block DigiShield = 68 block SMA, also 1.02^(35 blocks) = 2x target)
    //nTargetSpacing *= 2; // 160 second block time for PoW + 160 second block time for PoS = 80 second effective block time
    //if (!fProofOfStake)
        //nTargetSpacing *= (CBlockHeader::ALGO_COUNT - 1); // Multiply by the number of PoW algos

    // Long term solvetime correction adjusting nTargetSpacing
    uint32_t nBlocksPassed = 0;
    const CBlockIndex* pindexReferenceBlock = GetASERTReferenceBlockAndHeightForAlgo(pindexPrev, nProofOfWorkLimit, 2 /* nStartHeight */, algo, nBlocksPassed);
    const int64_t nTimeDiff = pindexPrev->GetBlockTime() - pindexReferenceBlock->GetBlockTime();
    const uint32_t nHeightDiff = nBlocksPassed; //pindexPrev->nHeight - pindexReferenceBlock->nHeight;
    const int64_t nScheduleDeviation = nTimeDiff - nTargetSpacing * nHeightDiff;

    // todo: multiply target spacing by ln(2) and round instead of truncating
    //printf("actual spacing = %li\n", nActualSpacing);
    nActualSpacing *= 100000000000ull; // Increase accuracy for the next calculation
    const int64_t LN2 = 69314718056ull; // Natural logarithm of 2 (rounded)

    //printf("(schedule deviation=%li) / (target spacing=%li) = %li blocks behind schedule at height=%u\n", nScheduleDeviation, nTargetSpacing, nScheduleDeviation / nTargetSpacing, nHeight);
    //printf("average spacing = %li seconds per block\n", nTimeDiff / nHeightDiff);

    // WARNING: The following code will cause oscillations in difficulty if the number of blocks of acceptable schedule deviation is set too small. This is due
    // to undershoot/overshoot in difficulty target while attempting to increase/decrease target spacing. Ample time must be provided for the difficulty target
    // to adjust back up/down to its ideal value so that the actual spacing will reflect the original target spacing or else the difficulty target will continually
    // oscillate by undershooting/overshooting the ideal value because the current target when schedule deviation has been eliminated will be lower/higher than ideal.
    if (nScheduleDeviation <= -100 * nTargetSpacing) { // If we are at least 100 blocks ahead of schedule, increase nTargetSpacing by 10% and adjust target 10x faster
        nTargetSpacing *= LN2;
        nTargetSpacing = (nTargetSpacing * 11) / 10;
        nTargetAdjustmentPercentage *= 10;
        //printf("height=%u ahead of schedule\n", nHeight);
    } else if (nScheduleDeviation >= 100 * nTargetSpacing) { // If we are at least 100 blocks behind schedule, decrease nTargetSpacing by 10% and adjust target 10x faster
        nTargetSpacing *= LN2;
        nTargetSpacing = (nTargetSpacing * 9) / 10;
        nTargetAdjustmentPercentage *= 10;
        //printf("height=%u behind schedule\n", nHeight);
    } else
        nTargetSpacing *= LN2;

    //printf("nActualSpacing = %li, nTargetSpacing = %li, nActualSpacing < nTargetSpacing = %i\n", nActualSpacing, nTargetSpacing, nActualSpacing < nTargetSpacing);
    const uint32_t numerator = nActualSpacing < nTargetSpacing ? (1000 - nTargetAdjustmentPercentage) : (1000 + nTargetAdjustmentPercentage);
    const uint32_t denominator = 1000;

    // Keep in mind the order of operations and integer division here - this is why the *= operator cannot be used, as it could cause overflow or integer division to occur
    arith_uint512 bnNew512 = arith_uint512(bnNew) * numerator / denominator;
    bnNew = bnNew512.trim256();

    if (bnNew512 > arith_uint512(bnPowLimit) || bnNew == arith_uint256())
        bnNew = bnPowLimit;

    return bnNew.GetCompactRounded();
}

unsigned int SimpleMovingAverageTarget(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const int algo = CBlockHeader::GetAlgo(pblock->nVersion);
    const bool fProofOfStake = pblock->IsProofOfStake();
    const arith_uint256 bnPowLimit = algo == -1 ? UintToArith256(params.powLimit[fProofOfStake ? CBlockHeader::ALGO_POS : CBlockHeader::ALGO_POW_QUARK]) : UintToArith256(params.powLimit[algo]);
    const uint32_t nProofOfWorkLimit = bnPowLimit.GetCompact();
    uint32_t nTargetSpacing = params.nPowTargetSpacing;
    nTargetSpacing *= 2; // 160 second block time for PoW + 160 second block time for PoS = 80 second effective block time
    if (!fProofOfStake)
        nTargetSpacing *= (CBlockHeader::ALGO_COUNT - 1); // Multiply by the number of PoW algos

    bool fUseTempering = true; // true = DigiShield, false = Dark Gravity Wave
    const uint32_t nTemperingFactor = 4;
    int nPastBlocks = params.nPowTargetTimespan / nTargetSpacing; // DGW default of 24 - needs to be more than 6 for MTP=11 enforcement to ensure that nActualTimespan will always be positive (or require sequential timestamps)
    if (fUseTempering)
        nPastBlocks /= nTemperingFactor; // DigiShield averages fewer blocks in order to respond faster but uses tempering to maintain similar stability

    // nFirstWeightMultiplier can be calculated using the formula (nPastBlocks * x) / (1 - x) + 1 where x = 1/3 (configurable) in order to give 33.3% of the overall weight to the most recent target
    const uint32_t nFirstWeightMultiplier = 1; // DGW default of 2 to put double weight on the most recent element in the average - set equal to 1 for normal SMA behavior
    if (pindexLast == nullptr)
        return nProofOfWorkLimit; // genesis block

    const CBlockIndex* pindexPrev = algo == -1 ? GetLastBlockIndex(pindexLast, fProofOfStake) : GetLastBlockIndexForAlgo(pindexLast, algo);
    if (pindexPrev->pprev == nullptr)
        return nProofOfWorkLimit; // first block

    const CBlockIndex* pindexPrevPrev = algo == -1 ? GetLastBlockIndex(pindexPrev->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindexPrev->pprev, algo);
    if (pindexPrevPrev->pprev == nullptr)
        return nProofOfWorkLimit; // second block

    //nPastBlocks = std::min(nPastBlocks, pindexLast->nHeight);
    if (pindexLast->nHeight < nPastBlocks + 2) // We are adding 2 here to skip the first two blocks at nProofOfWorkLimit, but it isn't necessary to do this for the average to work
        return WeightedTargetExponentialMovingAverage(pindexLast, pblock, params);

    const CBlockIndex* pindex = pindexPrev;
    arith_uint256 bnPastTargetAvg;

    // This is a simple moving average of difficulty targets with double weight for the most recent target by default (same as a harmonic SMA of difficulties)
    // (2 * T1 + T2 + T3 + T4 + ... + T24) / (24 + 1)
    for (int nCountBlocks = 1; nCountBlocks <= nPastBlocks; nCountBlocks++) {
        if (pindex->nBits != (nProofOfWorkLimit - 1) || !params.fPowAllowMinDifficultyBlocks) { // Don't add min difficulty targets to the average
            arith_uint256 bnTarget = arith_uint256().SetCompact(pindex->nBits);
            if (nCountBlocks == 1)
                bnTarget *= nFirstWeightMultiplier;
            bnPastTargetAvg += bnTarget / (nPastBlocks + nFirstWeightMultiplier - 1); // Number of elements added to average is nFirstWeightMultiplier - 1
        } else
            nCountBlocks--; // Average one more block to make up for the one we skipped

        const CBlockIndex* pprev = algo == -1 ? GetLastBlockIndex(pindex->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindex->pprev, algo);
        // If we skip the last index here, it causes nActualTimespan to be calculated with one less timestamp than it is supposed to use
        if (pprev && pprev->nHeight != 0) //&& nCountBlocks != nPastBlocks
            pindex = pprev;
        else
            break;
    }

    if (bnPastTargetAvg == arith_uint256())
        bnPastTargetAvg = bnPowLimit;
    arith_uint256 bnNew(bnPastTargetAvg);

    // If pprev was nullptr, nActualTimespan will use one less than nPastBlocks timestamps, which causes difficulty to be slightly higher than expected
    int nActualTimespan = pindexPrev->GetBlockTime() - pindex->GetBlockTime(); // Dark Gravity Wave
    int nTargetTimespan = nPastBlocks * nTargetSpacing;
    // Respond faster by avoiding tempering when the average solvetime is at least 15% too low or too high
    // WARNING: The following code will cause oscillations in difficulty if the max error percentage is set too low due to undershoot/overshoot in difficulty target
    const int nMaxSolvetimeErrorPercentage = 15;
    if (nActualTimespan <= (nTargetTimespan * (100 - nMaxSolvetimeErrorPercentage)) / 100 || nActualTimespan >= (nTargetTimespan * (100 + nMaxSolvetimeErrorPercentage)) / 100)
        fUseTempering = false;

    // Note we did not use MTP to calculate nActualTimespan here, which enables the time warp attack to drop the difficulty to zero using timestamps in the past due to the timespan limit below
    if (fUseTempering) { // DigiShield
        nActualTimespan += (nTemperingFactor - 1) * nTargetTimespan; // Temper nActualTimespan with the formula (3 * nTargetTimespan + nActualTimespan) / 4
        nTargetTimespan *= nTemperingFactor; // We multiply by 4 here in order to divide by 4 in the final calculation
    }

    // We have no choice but to limit the timespan here in case the calculation resulted in zero or a negative number, but it shouldn't be possible to reach this while requiring sequential timestamps or MTP enforcement
    if (nActualTimespan < 1)
        nActualTimespan = 1;

    // Keep in mind the order of operations and integer division here - this is why the *= operator cannot be used, as it could cause overflow or integer division to occur
    arith_uint512 bnNew512 = arith_uint512(bnNew) * nActualTimespan / nTargetTimespan; // next_target = avg(nPastBlocks prev_targets) * (nTemperingFactor - 1 + avg(nPastBlocks prev_solvetimes)/target_solvetime) / nTemperingFactor
    bnNew = bnNew512.trim256();

    if (bnNew512 > arith_uint512(bnPowLimit) || bnNew == arith_uint256())
        bnNew = bnPowLimit;

    return bnNew.GetCompactRounded();
}

unsigned int WeightedMovingAverageTarget(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const int algo = CBlockHeader::GetAlgo(pblock->nVersion);
    const bool fProofOfStake = pblock->IsProofOfStake();
    const arith_uint256 bnPowLimit = algo == -1 ? UintToArith256(params.powLimit[fProofOfStake ? CBlockHeader::ALGO_POS : CBlockHeader::ALGO_POW_QUARK]) : UintToArith256(params.powLimit[algo]);
    const uint32_t nProofOfWorkLimit = bnPowLimit.GetCompact();
    uint32_t nTargetSpacing = params.nPowTargetSpacing;
    nTargetSpacing *= 2; // 160 second block time for PoW + 160 second block time for PoS = 80 second effective block time
    if (!fProofOfStake)
        nTargetSpacing *= (CBlockHeader::ALGO_COUNT - 1); // Multiply by the number of PoW algos

    const uint32_t X_CUBED_MULTI = 0; // Cubically increasing weight for more recent solvetimes
    const uint32_t X_SQUARED_MULTI = 0; // Quadratically increasing weight for more recent solvetimes
    const uint32_t X_MULTI = 1; // Linearly increasing weight for more recent solvetimes
    int nPastBlocks = params.nPowTargetTimespan / nTargetSpacing;
    if (pindexLast == nullptr)
        return nProofOfWorkLimit; // genesis block

    const CBlockIndex* pindexPrev = algo == -1 ? GetLastBlockIndex(pindexLast, fProofOfStake) : GetLastBlockIndexForAlgo(pindexLast, algo);
    if (pindexPrev->pprev == nullptr)
        return nProofOfWorkLimit; // first block

    const CBlockIndex* pindexPrevPrev = algo == -1 ? GetLastBlockIndex(pindexPrev->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindexPrev->pprev, algo);
    if (pindexPrevPrev->pprev == nullptr)
        return nProofOfWorkLimit; // second block

    //nPastBlocks = std::min(nPastBlocks, pindexLast->nHeight);
    if (pindexLast->nHeight < nPastBlocks + 2) // We are adding 2 here to skip the first two blocks at nProofOfWorkLimit, but it isn't necessary to do this for the average to work
        return WeightedTargetExponentialMovingAverage(pindexLast, pblock, params);

    const CBlockIndex* pindex = pindexPrev;
    arith_uint256 bnPastTargetAvg;
    int64_t nSumSolvetimesWeighted = 0;
    uint32_t nElementsAveraged = 0;

    // This is a linearly weighted moving average of solvetimes
    // (1 * ST1 + 2 * ST2 + 3 * ST3 + 4 * ST4 + ... + 24 * ST24) / (1 + 2 + 3 + 4 + ... + 24)
    for (int nCountBlocks = nPastBlocks; nCountBlocks >= 1; nCountBlocks--) {
        const CBlockIndex* pprev = algo == -1 ? GetLastBlockIndex(pindex->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindex->pprev, algo);
        if (pindex->nBits != (nProofOfWorkLimit - 1) || !params.fPowAllowMinDifficultyBlocks) { // Don't add min difficulty targets to the average
            arith_uint256 bnTarget = arith_uint256().SetCompact(pindex->nBits);
            bnPastTargetAvg += bnTarget / nPastBlocks;

            if (pprev && pprev->nHeight != 0) {
                const uint32_t nWeightMultiplier = (X_CUBED_MULTI * nCountBlocks*nCountBlocks*nCountBlocks) + (X_SQUARED_MULTI * nCountBlocks*nCountBlocks) + (X_MULTI * nCountBlocks);
                nSumSolvetimesWeighted += (pindex->GetBlockTime() - pprev->GetBlockTime()) * nWeightMultiplier; // nWeightMultiplier == nCountBlocks
                nElementsAveraged += nWeightMultiplier;
            }
        } else
            nCountBlocks++; // Average one more block to make up for the one we skipped

        if (pprev && pprev->nHeight != 0)
            pindex = pprev;
        else
            break;
    }

    if (bnPastTargetAvg == arith_uint256())
        bnPastTargetAvg = bnPowLimit;
    arith_uint256 bnNew(bnPastTargetAvg);

    // We have no choice but to limit the timespan here in case the calculation resulted in zero or a negative number, but it shouldn't be possible to reach this while requiring sequential timestamps or MTP enforcement
    if (nSumSolvetimesWeighted < 1)
        nSumSolvetimesWeighted = 1;

    const uint32_t nActualTimespanWeighted = nSumSolvetimesWeighted;
    const uint32_t nTargetTimespan = nPastBlocks * nTargetSpacing * nElementsAveraged;

    // Keep in mind the order of operations and integer division here - this is why the *= operator cannot be used, as it could cause overflow or integer division to occur
    arith_uint512 bnNew512 = arith_uint512(bnNew) * nActualTimespanWeighted / nTargetTimespan; // next_target = avg(nPastBlocks prev_targets) * lwma(nPastBlocks prev_solvetimes) / target_solvetime
    bnNew = bnNew512.trim256();

    if (bnNew512 > arith_uint512(bnPowLimit) || bnNew == arith_uint256())
        bnNew = bnPowLimit;

    return bnNew.GetCompactRounded();
}

bool CheckProofOfWork(const uint256& hash, const unsigned int& nBits, const int& algo, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || algo < -1 || algo == CBlockHeader::ALGO_POS || algo >= CBlockHeader::ALGO_COUNT || bnTarget > UintToArith256(params.powLimit[algo == -1 ? CBlockHeader::ALGO_POW_QUARK : algo]))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
