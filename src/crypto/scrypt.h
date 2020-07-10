// Copyright (c) 2018-2020 John "ComputerCraftr" Studnicka
// Copyright (c) 2018-2020 The Simplicity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SCRYPT_H
#define BITCOIN_CRYPTO_SCRYPT_H

#include <compat/byteswap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static const unsigned int SCRYPT_SCRATCHPAD_SIZE = 1024 * 128 + 63; // N = 1024
static const unsigned int SCRYPT2_SCRATCHPAD_SIZE = 1048576 * 128 + 63; // N = 1024^2 = 1048576

void scrypt_N_1_1_256(const char *input, char *output, unsigned int N);
void scrypt_N_1_1_256_sp_generic(const char *input, char *output, char *scratchpad, unsigned int N);

#if defined(USE_SSE2)
#include <string>
#if defined(_M_X64) || defined(__x86_64__) || defined(_M_AMD64) || (defined(MAC_OSX) && defined(__i386__))
#define USE_SSE2_ALWAYS 1
#define scrypt_N_1_1_256_sp(input, output, scratchpad, N) scrypt_N_1_1_256_sp_sse2((input), (output), (scratchpad), (N))
#else
#define scrypt_N_1_1_256_sp(input, output, scratchpad, N) scrypt_N_1_1_256_sp_detected((input), (output), (scratchpad), (N))
#endif

std::string scrypt_detect_sse2();
void scrypt_N_1_1_256_sp_sse2(const char *input, char *output, char *scratchpad, unsigned int N);
extern void (*scrypt_N_1_1_256_sp_detected)(const char *input, char *output, char *scratchpad, unsigned int N);
#else
#define scrypt_N_1_1_256_sp(input, output, scratchpad, N) scrypt_N_1_1_256_sp_generic((input), (output), (scratchpad), (N))
#endif

#ifndef __FreeBSD__
static inline uint32_t le32dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;
    return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
        ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void le32enc(void *pp, uint32_t x)
{
    uint8_t *p = (uint8_t *)pp;
    p[0] = x & 0xff;
    p[1] = (x >> 8) & 0xff;
    p[2] = (x >> 16) & 0xff;
    p[3] = (x >> 24) & 0xff;
}

static inline uint32_t be32dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;
    return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
        ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static inline void be32enc(void *pp, uint32_t x)
{
    uint8_t *p = (uint8_t *)pp;
    p[3] = x & 0xff;
    p[2] = (x >> 8) & 0xff;
    p[1] = (x >> 16) & 0xff;
    p[0] = (x >> 24) & 0xff;
}
#endif

static const uint32_t sha256_h[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static inline void sha256_init(uint32_t *state)
{
    memcpy(state, sha256_h, 32);
}

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)     ((x & (y ^ z)) ^ z)
#define Maj(x, y, z)    ((x & (y | z)) | (y & z))
#define ROTR(x, n)      ((x >> n) | (x << (32 - n)))
#define S0(x)           (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)           (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)           (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define s1(x)           (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k) \
    do { \
        t0 = h + S1(e) + Ch(e, f, g) + k; \
        t1 = S0(a) + Maj(a, b, c); \
        d += t0; \
        h  = t0 + t1; \
    } while (0)

/* Adjusted round function for rotating state */
#define RNDr(S, W, i) \
    RND(S[(64 - i) % 8], S[(65 - i) % 8], \
        S[(66 - i) % 8], S[(67 - i) % 8], \
        S[(68 - i) % 8], S[(69 - i) % 8], \
        S[(70 - i) % 8], S[(71 - i) % 8], \
        W[i] + sha256_k[i])

/*
 * SHA256 block compression function.  The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
static inline void sha256_transform(uint32_t *state, const uint32_t *block, int swap)
{
    uint32_t W[64];
    uint32_t S[8];
    uint32_t t0, t1;
    int i;

    /* 1. Prepare message schedule W. */
    if (swap) {
        for (i = 0; i < 16; i++)
            W[i] = bswap_32(block[i]);
    } else
        memcpy(W, block, 64);
    for (i = 16; i < 64; i += 2) {
        W[i]   = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
        W[i+1] = s1(W[i - 1]) + W[i - 6] + s0(W[i - 14]) + W[i - 15];
    }

    /* 2. Initialize working variables. */
    memcpy(S, state, 32);

    /* 3. Mix. */
    RNDr(S, W,  0);
    RNDr(S, W,  1);
    RNDr(S, W,  2);
    RNDr(S, W,  3);
    RNDr(S, W,  4);
    RNDr(S, W,  5);
    RNDr(S, W,  6);
    RNDr(S, W,  7);
    RNDr(S, W,  8);
    RNDr(S, W,  9);
    RNDr(S, W, 10);
    RNDr(S, W, 11);
    RNDr(S, W, 12);
    RNDr(S, W, 13);
    RNDr(S, W, 14);
    RNDr(S, W, 15);
    RNDr(S, W, 16);
    RNDr(S, W, 17);
    RNDr(S, W, 18);
    RNDr(S, W, 19);
    RNDr(S, W, 20);
    RNDr(S, W, 21);
    RNDr(S, W, 22);
    RNDr(S, W, 23);
    RNDr(S, W, 24);
    RNDr(S, W, 25);
    RNDr(S, W, 26);
    RNDr(S, W, 27);
    RNDr(S, W, 28);
    RNDr(S, W, 29);
    RNDr(S, W, 30);
    RNDr(S, W, 31);
    RNDr(S, W, 32);
    RNDr(S, W, 33);
    RNDr(S, W, 34);
    RNDr(S, W, 35);
    RNDr(S, W, 36);
    RNDr(S, W, 37);
    RNDr(S, W, 38);
    RNDr(S, W, 39);
    RNDr(S, W, 40);
    RNDr(S, W, 41);
    RNDr(S, W, 42);
    RNDr(S, W, 43);
    RNDr(S, W, 44);
    RNDr(S, W, 45);
    RNDr(S, W, 46);
    RNDr(S, W, 47);
    RNDr(S, W, 48);
    RNDr(S, W, 49);
    RNDr(S, W, 50);
    RNDr(S, W, 51);
    RNDr(S, W, 52);
    RNDr(S, W, 53);
    RNDr(S, W, 54);
    RNDr(S, W, 55);
    RNDr(S, W, 56);
    RNDr(S, W, 57);
    RNDr(S, W, 58);
    RNDr(S, W, 59);
    RNDr(S, W, 60);
    RNDr(S, W, 61);
    RNDr(S, W, 62);
    RNDr(S, W, 63);

    /* 4. Mix local working variables into global state */
    for (i = 0; i < 8; i++)
        state[i] += S[i];
}

static const uint32_t keypad[12] = {
    0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000280
};
static const uint32_t innerpad[11] = {
    0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x000004a0
};
static const uint32_t outerpad[8] = {
    0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300
};
static const uint32_t finalblk[16] = {
    0x00000001, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000620
};

static inline void HMAC_SHA256_80_init(const uint32_t *key,
    uint32_t *tstate, uint32_t *ostate)
{
    uint32_t ihash[8];
    uint32_t pad[16];
    int i;

    /* tstate is assumed to contain the midstate of key */
    memcpy(pad, key + 16, 16);
    memcpy(pad + 4, keypad, 48);
    sha256_transform(tstate, pad, 0);
    memcpy(ihash, tstate, 32);

    sha256_init(ostate);
    for (i = 0; i < 8; i++)
        pad[i] = ihash[i] ^ 0x5c5c5c5c;
    for (; i < 16; i++)
        pad[i] = 0x5c5c5c5c;
    sha256_transform(ostate, pad, 0);

    sha256_init(tstate);
    for (i = 0; i < 8; i++)
        pad[i] = ihash[i] ^ 0x36363636;
    for (; i < 16; i++)
        pad[i] = 0x36363636;
    sha256_transform(tstate, pad, 0);
}

static inline void PBKDF2_SHA256_80_128(const uint32_t *tstate,
    const uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
    uint32_t istate[8], ostate2[8];
    uint32_t ibuf[16], obuf[16];
    int i, j;

    memcpy(istate, tstate, 32);
    sha256_transform(istate, salt, 0);

    memcpy(ibuf, salt + 16, 16);
    memcpy(ibuf + 5, innerpad, 44);
    memcpy(obuf + 8, outerpad, 32);

    for (i = 0; i < 4; i++) {
        memcpy(obuf, istate, 32);
        ibuf[4] = i + 1;
        sha256_transform(obuf, ibuf, 0);

        memcpy(ostate2, ostate, 32);
        sha256_transform(ostate2, obuf, 0);
        for (j = 0; j < 8; j++)
            output[8 * i + j] = bswap_32(ostate2[j]);
    }
}

static inline void PBKDF2_SHA256_128_32(uint32_t *tstate, uint32_t *ostate,
    const uint32_t *salt, uint32_t *output)
{
    uint32_t buf[16];
    int i;

    sha256_transform(tstate, salt, 1);
    sha256_transform(tstate, salt + 16, 1);
    sha256_transform(tstate, finalblk, 0);
    memcpy(buf, tstate, 32);
    memcpy(buf + 8, outerpad, 32);

    sha256_transform(ostate, buf, 0);
    for (i = 0; i < 8; i++)
        output[i] = bswap_32(ostate[i]);
}

#endif // BITCOIN_CRYPTO_SCRYPT_H
