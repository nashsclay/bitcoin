// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <arith_uint256.h>
#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static const int NEVER = std::numeric_limits<int>::max();

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.nTime = 1517690700;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    if (genesisReward == 0) {
        txNew.vin[0].scriptSig = CScript() << 4867816 << CScriptNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();
    } else {
        txNew.vin[0].scriptSig = CScript() << OP_0 << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = genesisReward;
        txNew.vout[0].scriptPubKey = genesisOutputScript;
    }

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

    arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
    /*while (true) {
        arith_uint256 hash = UintToArith256(genesis.GetPoWHash());
        if (hash <= hashTarget) {
            // Found a solution
            printf("genesis block found\n   hash: %s\n target: %s\n   bits: %08x\n  nonce: %u\n", hash.ToString().c_str(), hashTarget.ToString().c_str(), genesis.nBits, genesis.nNonce);
            break;
        }
        genesis.nNonce += 1;
        if ((genesis.nNonce & 0x1ffff) == 0)
            printf("testing nonce: %u\n", genesis.nNonce);
    }*/
    uint256 hash = genesis.GetPoWHash();
    assert(hash == uint256S("0xf4bbfc518aa3622dbeb8d2818a606b82c2b8b1ac2f28553ebdb6fc04d7abaccf") || UintToArith256(hash) <= hashTarget);

    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "http://www.bbc.co.uk/news/world-us-canada-42926976"; // Trump Russia: Democrats say firing special counsel could cause crisis
    const CScript genesisOutputScript = CScript() << ParseHex("03b95000b2b06e391c058ea14d47ac3c525753c68460864f254ada5a63e27a8134") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 100000;
        consensus.nInstantSendConfirmationsRequired = 6;
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 328008; // actual historical value
        consensus.nBudgetPaymentsCycleBlocks = 16616; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nSuperblockStartBlock = 614820; // The block at which 12.1 goes live (end of final 12.0 budget cycle)
        consensus.nSuperblockStartHash = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.nSuperblockCycle = 16616; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nMasternodeCollateral[0] = 100000 * COIN; // was 200000 * COIN
        consensus.nMasternodeCollateral[1] = 1000000 * COIN;
        consensus.nMasternodeCollateral[2] = 10000000 * COIN;
        consensus.nPoSStartBlock = 0;
        consensus.nLastPoWBlock = NEVER;
        consensus.nMandatoryUpgradeBlock[0] = 1030000;
        consensus.nMandatoryUpgradeBlock[1] = 1450000;
        consensus.nUpgradeBlockVersion[0] = 8; // Block headers must be at least this version after upgrade block
        consensus.nUpgradeBlockVersion[1] = 9;
        consensus.nBadScryptDiffStartTime = 1573746979;
        consensus.nBadScryptDiffEndTime = 1574121600;
        consensus.BIP16Exception = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x63740505e585d80da6d612d0ddbdaec3b3eebd86c1c7447ebeebe13841a7efdd");
        consensus.BIP65Height = 0; // f4bbfc518aa3622dbeb8d2818a606b82c2b8b1ac2f28553ebdb6fc04d7abaccf
        consensus.BIP66Height = 0; // f4bbfc518aa3622dbeb8d2818a606b82c2b8b1ac2f28553ebdb6fc04d7abaccf
        consensus.CSVHeight = 1; // 63740505e585d80da6d612d0ddbdaec3b3eebd86c1c7447ebeebe13841a7efdd
        consensus.SegwitHeight = 0; // f4bbfc518aa3622dbeb8d2818a606b82c2b8b1ac2f28553ebdb6fc04d7abaccf
        consensus.MinBIP9WarningHeight = 0; // segwit activation height + miner confirmation window
        consensus.powLimit[CBlockHeader::ALGO_POS] = uint256S("00000fffff000000000000000000000000000000000000000000000000000000"); // 0x1e0fffff
        consensus.powLimit[CBlockHeader::ALGO_POW_QUARK] = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000"); // 0x1f00ffff
        consensus.powLimit[CBlockHeader::ALGO_POW_SCRYPT_SQUARED] = uint256S("001fffff00000000000000000000000000000000000000000000000000000000"); // 0x1f1fffff
        consensus.powLimit[CBlockHeader::ALGO_POW_SHA1D] = uint256S("000000ffff000000000000000000000000000000000000000000000000000000");
        consensus.powLimit[CBlockHeader::ALGO_POW_ARGON2D] = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000"); // 0x1f00ffff
        consensus.nPowTargetTimespan = 2 * 60 * 60; // 2 hours
        consensus.nPowTargetSpacing = 80; // 80-second block spacing
        consensus.nStakeTimestampMask = 0xf; // 16 second time slots - normally, more than this wouldn't work with an 80 second block time because 80 isn't divisible by 32, but the effective PoS target spacing is 160 seconds due to hybrid PoW/PoS
        consensus.nStakeMinDepth[0] = 200;
        consensus.nStakeMinDepth[1] = 600;
        consensus.nStakeMinAge[0] = 2 * 60 * 60; // previous min age was 2 hours
        consensus.nStakeMinAge[1] = 12 * 60 * 60; // current minimum age for coin age is 12 hours
        consensus.nStakeMaxAge = 30 * 24 * 60 * 60;
        consensus.nModifierInterval = 1 * 60; // Modifier interval: time to elapse before new modifier is computed
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 0.95 * 7 * 24 * 60 * 60 / consensus.nPowTargetSpacing; // 95% of the blocks in the past week
        consensus.nMinerConfirmationWindow = 7 * 24 * 60 * 60 / consensus.nPowTargetSpacing; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"); // 1110000

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xb3;
        pchMessageStart[1] = 0x07;
        pchMessageStart[2] = 0x9a;
        pchMessageStart[3] = 0x1e;
        nDefaultPort = 11957;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 5;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1517690700, 561379, UintToArith256(consensus.powLimit[CBlockHeader::ALGO_POW_QUARK]).GetCompact(), 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //printf("Merkle hash mainnet: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //printf("Genesis hash mainnet: %s\n", consensus.hashGenesisBlock.ToString().c_str());
        assert(genesis.hashMerkleRoot == uint256S("0x40bdd3d5ae84b91a71190094a82948400eb3356e87c5376b64d79509cf552d84"));
        assert(consensus.hashGenesisBlock == uint256S("0xf4bbfc518aa3622dbeb8d2818a606b82c2b8b1ac2f28553ebdb6fc04d7abaccf"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("zentec.ddns.net");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,18);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,59);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,93);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        nExtCoinType = 448;

        bech32_hrp = "sp";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour

        checkpointData = {
            {
                {      0, uint256S("0xf4bbfc518aa3622dbeb8d2818a606b82c2b8b1ac2f28553ebdb6fc04d7abaccf")},
                {  50000, uint256S("0x525c080ed904eeaaf00ac0c088c6cd0ceabe3918bebbd80ec2ed494939077965")},
                { 100000, uint256S("0x9c8f67b0d656a451250b1f4e1fca9980e23ae5eb2d70e0798b76ea4c30e63bad")},
                { 150000, uint256S("0xb9d5e51f05e23034c6da1347ca28a704ad75d2249ca5ac16e97ed9c25b261e3a")},
                { 200000, uint256S("0x505d2588728736dce8985830f0cce34cc3ae766482fba2e46ae522c98423a560")},
                { 250000, uint256S("0xa66859b5e88ef9db8194eddde917a40adfca707958d56f97d727373090152250")},
                { 300000, uint256S("0x25a1eaa7edd3e06afecb7de062d0a713d09766ffa0685997ae01ca5950b4ff61")},
                { 350000, uint256S("0x0457c2096e529aab2855d7338e77f3a3a3da9a45bb272a0d74ca35f0d234ef16")},
                { 400000, uint256S("0x02709ff59f09b08684bdab6000b7ad134f1d54ac4079202c94173378fabc44e7")},
                { 450000, uint256S("0x54fbd621e99ed213de13a273935cf29ec8b086f8498351f1bc103c43f6f356d1")},
                { 500000, uint256S("0x8c9974c78873ca6f3636c096007b90a3d23ed6f79b645a6d3e83d875c90b79f5")},
                { 550000, uint256S("0xc5f0a3c19ecfd9ccdb2818a71663e063486cd75874fe68a84755092417e4ae85")},
                { 600000, uint256S("0x5698cbf27f591da46ababc40c9ed7718086493e3542c00c35a6de86de6b6add6")},
                { 650000, uint256S("0xcf6076eda981af1097e52f505c0c3dfefc60af9b93ba674fda8e22235ff50df3")},
                { 700000, uint256S("0x2f852dfbc9b767905400c0e706ff63eca8d5e4090d4d49f873f9be1a754cc243")},
                { 750000, uint256S("0xc723e552d2287dc1309d33ded2b722beb2fe08ec5eaa0a95c63de2ea12aee150")},
                { 800000, uint256S("0xa27bf851d7055180d0f94593862a8a68a176d40bc3218427c26cc7d4ac050bb7")},
                { 850000, uint256S("0x94efaa5b8397bb0fa5c63cf211551e94f9cb21bb18c3fb0e15f798614cd9d6a6")},
                { 900000, uint256S("0x8dd45153002324052253321454138627161a91982185a578940307ed45193635")},
                { 950000, uint256S("0x0cbb4dfac570e6cbf7aa10b3f8a138b3dda3e908ab78e301f12354731bbce560")},
                {1000000, uint256S("0xda2636057aa54f047fddb79a6d71617ac075c59c26c84761585735b4e5978f3c")},
                {1050000, uint256S("0x9ab97fa25881e95b4c22fb7515d90738054a43231231acf8d5fc3be581591192")},
                {1100000, uint256S("0x8aecf2e9d02460c3a97d83a178bf6f9f81684e2df1f95d8cd9dea1ae780b814e")},
                {1110000, uint256S("0x442f3ff725f9128bb432cac6e4c312c31548a646bacb933ff80fc214aea09eff")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000000000005f8920febd3925f8272a6a71237563d78c2edfdd09ddf
            /* nTime    */ 1582906496,
            /* nTxCount */ 1845905,
            /* dTxRate  */ 3.77848885073875,
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 4100;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 4200; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPaymentsStartBlock
        consensus.nSuperblockStartHash = uint256(); // do not check this on testnet
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on testnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMasternodeCollateral[0] = 10000 * COIN;
        consensus.nMasternodeCollateral[1] = 100000 * COIN;
        consensus.nMasternodeCollateral[2] = 1000000 * COIN;
        consensus.nPoSStartBlock = 0;
        consensus.nLastPoWBlock = NEVER;
        consensus.nMandatoryUpgradeBlock[0] = 0;
        consensus.nMandatoryUpgradeBlock[1] = 0;
        consensus.nUpgradeBlockVersion[0] = 0; // Block headers must be at least this version after upgrade block
        consensus.nUpgradeBlockVersion[1] = 0;
        consensus.nBadScryptDiffStartTime = 0;
        consensus.nBadScryptDiffEndTime = 0;
        consensus.BIP16Exception = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x16e0228f2712c94c10ec590a98a416a664bdf42ebd10a6ffe563d817ee19b6b9");
        consensus.BIP65Height = 0; // 16e0228f2712c94c10ec590a98a416a664bdf42ebd10a6ffe563d817ee19b6b9
        consensus.BIP66Height = 0; // 16e0228f2712c94c10ec590a98a416a664bdf42ebd10a6ffe563d817ee19b6b9
        consensus.CSVHeight = 1; // 000037a145d6812571b0c413d868a43146d7159056afe7a06b344e9ee0de39fc
        consensus.SegwitHeight = 0; // 16e0228f2712c94c10ec590a98a416a664bdf42ebd10a6ffe563d817ee19b6b9
        consensus.MinBIP9WarningHeight = 0; // segwit activation height + miner confirmation window
        consensus.powLimit[CBlockHeader::ALGO_POS] = uint256S("000000ffff000000000000000000000000000000000000000000000000000000");
        consensus.powLimit[CBlockHeader::ALGO_POW_QUARK] = uint256S("000000ffff000000000000000000000000000000000000000000000000000000");
        consensus.powLimit[CBlockHeader::ALGO_POW_SCRYPT_SQUARED] = uint256S("001fffff00000000000000000000000000000000000000000000000000000000");
        consensus.powLimit[CBlockHeader::ALGO_POW_SHA1D] = uint256S("000000ffff000000000000000000000000000000000000000000000000000000");
        consensus.powLimit[CBlockHeader::ALGO_POW_ARGON2D] = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 2 * 60 * 60; // 2 hours
        consensus.nPowTargetSpacing = 64; // 64-second block spacing
        consensus.nStakeTimestampMask = 0xf; // 16 second time slots
        consensus.nStakeMinDepth[0] = 100;
        consensus.nStakeMinDepth[1] = 100;
        consensus.nStakeMinAge[0] = 1 * 60 * 60;
        consensus.nStakeMinAge[1] = 1 * 60 * 60; // test net min age is 1 hour
        consensus.nStakeMaxAge = 30 * 24 * 60 * 60;
        consensus.nModifierInterval = 1 * 60; // Modifier interval: time to elapse before new modifier is computed
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 0.75 * 7 * 24 * 60 * 60 / consensus.nPowTargetSpacing; // 75% for testchains
        consensus.nMinerConfirmationWindow = 7 * 24 * 60 * 60 / consensus.nPowTargetSpacing; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"); // 1580000

        pchMessageStart[0] = 0xf1;
        pchMessageStart[1] = 0xe3;
        pchMessageStart[2] = 0xdc;
        pchMessageStart[3] = 0xc6;
        nDefaultPort = 21957;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 5;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1574924400, 2961, UintToArith256(consensus.powLimit[CBlockHeader::ALGO_POW_QUARK]).GetCompact(), CBlockHeader::VERSION_POW_QUARK, 10000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //printf("Merkle hash testnet: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //printf("Genesis hash testnet: %s\n", consensus.hashGenesisBlock.ToString().c_str());
        assert(genesis.hashMerkleRoot == uint256S("0x56d78c2879e2a685669fd14576a9b267dcc2adad9ffa6049d079e5acf3137b40"));
        assert(consensus.hashGenesisBlock == uint256S("0x16e0228f2712c94c10ec590a98a416a664bdf42ebd10a6ffe563d817ee19b6b9"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed.bitcoin.jonasschnelli.ch");
        vSeeds.emplace_back("seed.tbtc.petertodd.org");
        vSeeds.emplace_back("seed.testnet.bitcoin.sprovoost.nl");
        vSeeds.emplace_back("testnet-seed.bluematt.me"); // Just a static list of stable node(s), only supports x9

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,139);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Testnet BIP44 coin type is '1' (All coins' testnet default)
        nExtCoinType = 1;

        bech32_hrp = "ts";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        checkpointData = {
            {
                {0, uint256S("0x16e0228f2712c94c10ec590a98a416a664bdf42ebd10a6ffe563d817ee19b6b9")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000000b7ab6ce61eb6d571003fbe5fe892da4c9b740c49a07542462d
            /* nTime    */ 1574924400,
            /* nTxCount */ 1,
            /* dTxRate  */ 0.1517002392872353,
        };
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 1500;
        consensus.nSuperblockStartHash = uint256(); // do not check this on regtest
        consensus.nSuperblockCycle = 10;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 100;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMasternodeCollateral[0] = 100 * COIN;
        consensus.nMasternodeCollateral[1] = 1000 * COIN;
        consensus.nMasternodeCollateral[2] = 10000 * COIN;
        consensus.nPoSStartBlock = 0;
        consensus.nLastPoWBlock = NEVER;
        consensus.nMandatoryUpgradeBlock[0] = 0;
        consensus.nMandatoryUpgradeBlock[1] = 0;
        consensus.nUpgradeBlockVersion[0] = 0; // Block headers must be at least this version after upgrade block
        consensus.nUpgradeBlockVersion[1] = 0;
        consensus.nBadScryptDiffStartTime = 0;
        consensus.nBadScryptDiffEndTime = 0;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.CSVHeight = 432; // CSV activated on regtest (Used in rpc activation tests)
        consensus.SegwitHeight = 0; // SEGWIT is always activated on regtest unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit[CBlockHeader::ALGO_POS] = uint256S("7fffff0000000000000000000000000000000000000000000000000000000000");
        consensus.powLimit[CBlockHeader::ALGO_POW_QUARK] = uint256S("7fffff0000000000000000000000000000000000000000000000000000000000");
        consensus.powLimit[CBlockHeader::ALGO_POW_SCRYPT_SQUARED] = uint256S("7fffff0000000000000000000000000000000000000000000000000000000000");
        consensus.powLimit[CBlockHeader::ALGO_POW_SHA1D] = uint256S("7fffff0000000000000000000000000000000000000000000000000000000000");
        consensus.powLimit[CBlockHeader::ALGO_POW_ARGON2D] = uint256S("7fffff0000000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 2 * 60 * 60; // 2 hours
        consensus.nPowTargetSpacing = 32; // 32-second block spacing
        consensus.nStakeTimestampMask = 0x3; // 4 second time slots
        consensus.nStakeMinDepth[0] = 0;
        consensus.nStakeMinDepth[1] = 0;
        consensus.nStakeMinAge[0] = 1 * 60 * 60;
        consensus.nStakeMinAge[1] = 1 * 60 * 60; // test net min age is 1 hour
        consensus.nStakeMaxAge = 30 * 24 * 60 * 60;
        consensus.nModifierInterval = 1 * 60; // Modifier interval: time to elapse before new modifier is computed
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false; //true;
        consensus.nRuleChangeActivationThreshold = 0.75 * 24 * 60 * 60 / consensus.nPowTargetSpacing; // 75% for testchains
        consensus.nMinerConfirmationWindow = 24 * 60 * 60 / consensus.nPowTargetSpacing; // Faster than normal for regtest (one day instead of one week)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(1574924400, 47047, 0x1f00ffff, CBlockHeader::VERSION_POW_QUARK, 10000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //printf("Merkle hash regtest: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //printf("Genesis hash regtest: %s\n", consensus.hashGenesisBlock.ToString().c_str());
        assert(genesis.hashMerkleRoot == uint256S("0x56d78c2879e2a685669fd14576a9b267dcc2adad9ffa6049d079e5acf3137b40"));
        assert(consensus.hashGenesisBlock == uint256S("0xbccd4c5f87de046e4cd9e222982371c0cf0ad8b5fcfa6753be472f04544fb41f"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        checkpointData = {
            {
                {0, uint256S("0xbccd4c5f87de046e4cd9e222982371c0cf0ad8b5fcfa6753be472f04544fb41f")},
            }
        };

        chainTxData = ChainTxData{
            1574924400,
            1,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,139);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Testnet BIP44 coin type is '1' (All coins' testnet default)
        nExtCoinType = 1;

        bech32_hrp = "sprt";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (gArgs.IsArgSet("-segwitheight")) {
        int64_t height = gArgs.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

const CChainParams &Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
