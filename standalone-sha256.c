/*
 * SPDX-FileCopyrightText: 2011 Original C code: IETF Trust and the persons identified as the document authors. All rights reserved.
 * SPDX-FileCopyrightText: 2025 Refactoring and modifications: stfnw.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Refactored SHA256 implementation derived from
 * https://datatracker.ietf.org/doc/html/rfc6234.
 * Self-contained single-file implementation; with macros replaced with
 * functions. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#define CHECK_RES(func)                                                        \
    do {                                                                       \
        int ret = (func);                                                      \
        if (ret != shaSuccess) {                                               \
            fprintf(stderr, "Error code %d at %s:%d\n", ret, __FILE__,         \
                    __LINE__);                                                 \
            exit(EXIT_FAILURE);                                                \
        }                                                                      \
    } while (0)

/* All SHA functions return one of these values. */
enum {
    shaSuccess = 0,
    shaNull,         /* Null pointer parameter */
    shaInputTooLong, /* input data too u64 */
    shaStateError,   /* called Input after FinalBits or Result */
    shaBadParam      /* passed a bad parameter */
};

/* These constants hold size information for each of the SHA hashing ops */
enum {
    SHA1_Message_Block_Size = 64,
    SHA224_Message_Block_Size = 64,
    SHA256_Message_Block_Size = 64,
    SHA384_Message_Block_Size = 128,
    SHA512_Message_Block_Size = 128,
    USHA_Max_Message_Block_Size = SHA512_Message_Block_Size,

    SHA1HashSize = 20,
    SHA224HashSize = 28,
    SHA256HashSize = 32,
    SHA384HashSize = 48,
    SHA512HashSize = 64,
    USHAMaxHashSize = SHA512HashSize,

    SHA1HashSizeBits = 160,
    SHA224HashSizeBits = 224,
    SHA256HashSizeBits = 256,
    SHA384HashSizeBits = 384,
    SHA512HashSizeBits = 512,
    USHAMaxHashSizeBits = SHA512HashSizeBits
};

typedef struct SHA256Context {
    u32 Intermediate_Hash[SHA256HashSize / 4]; /* Message Digest */

    u64 Length; /* Message length in bits */

    i16 Message_Block_Index; /* Message_Block array index */
                             /* 512-bit message blocks */
    u8 Message_Block[SHA256_Message_Block_Size];

    i32 Computed;  /* Is the hash computed? */
    i32 Corrupted; /* Cumulative corruption code */
} SHA256Context;

u32 SHA256_SHR(u32 bits, u32 word) { return word >> bits; }
u32 SHA256_ROTL(u32 bits, u32 word) {
    return (word << bits) | (word >> (32 - bits));
}
u32 SHA256_ROTR(u32 bits, u32 word) {
    return (word >> bits) | (word << (32 - bits));
}

u32 SHA256_SIGMA0(u32 word) {
    return SHA256_ROTR(2, word) ^ SHA256_ROTR(13, word) ^ SHA256_ROTR(22, word);
}
u32 SHA256_SIGMA1(u32 word) {
    return SHA256_ROTR(6, word) ^ SHA256_ROTR(11, word) ^ SHA256_ROTR(25, word);
}
u32 SHA256_sigma0(u32 word) {
    return SHA256_ROTR(7, word) ^ SHA256_ROTR(18, word) ^ SHA256_SHR(3, word);
}
u32 SHA256_sigma1(u32 word) {
    return SHA256_ROTR(17, word) ^ SHA256_ROTR(19, word) ^ SHA256_SHR(10, word);
}

u32 SHA_Ch(u32 x, u32 y, u32 z) { return (x & y) ^ ((~x) & z); }
u32 SHA_Maj(u32 x, u32 y, u32 z) { return (x & y) ^ (x & z) ^ (y & z); }
u32 SHA_Parity(u32 x, u32 y, u32 z) { return x ^ y ^ z; }

static u32 SHA256_H0[SHA256HashSize / 4] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372,
                                            0xA54FF53A, 0x510E527F, 0x9B05688C,
                                            0x1F83D9AB, 0x5BE0CD19};

static i32 SHA256Reset(SHA256Context *context) {
    if (!context) {
        return shaNull;
    }

    context->Length = 0;
    context->Message_Block_Index = 0;

    context->Intermediate_Hash[0] = SHA256_H0[0];
    context->Intermediate_Hash[1] = SHA256_H0[1];
    context->Intermediate_Hash[2] = SHA256_H0[2];
    context->Intermediate_Hash[3] = SHA256_H0[3];
    context->Intermediate_Hash[4] = SHA256_H0[4];
    context->Intermediate_Hash[5] = SHA256_H0[5];
    context->Intermediate_Hash[6] = SHA256_H0[6];
    context->Intermediate_Hash[7] = SHA256_H0[7];

    context->Computed = 0;
    context->Corrupted = shaSuccess;

    return shaSuccess;
}

static void SHA256ProcessMessageBlock(SHA256Context *context) {
    /* Constants defined in FIPS 180-3, section 4.2.2 */
    static const u32 K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    u32 W[64]; /* Word sequence */

    /* Initialize the first 16 words in the array W */
    for (i32 t = 0, t4 = 0; t < 16; t++, t4 += 4) {
        W[t] = (((u32)context->Message_Block[t4]) << 24) |
               (((u32)context->Message_Block[t4 + 1]) << 16) |
               (((u32)context->Message_Block[t4 + 2]) << 8) |
               (((u32)context->Message_Block[t4 + 3]));
    }

    for (i32 t = 16; t < 64; t++) {
        W[t] = SHA256_sigma1(W[t - 2]) + W[t - 7] + SHA256_sigma0(W[t - 15]) +
               W[t - 16];
    }

    u32 A = context->Intermediate_Hash[0];
    u32 B = context->Intermediate_Hash[1];
    u32 C = context->Intermediate_Hash[2];
    u32 D = context->Intermediate_Hash[3];
    u32 E = context->Intermediate_Hash[4];
    u32 F = context->Intermediate_Hash[5];
    u32 G = context->Intermediate_Hash[6];
    u32 H = context->Intermediate_Hash[7];

    for (i32 t = 0; t < 64; t++) {
        u32 temp1 = H + SHA256_SIGMA1(E) + SHA_Ch(E, F, G) + K[t] + W[t];
        u32 temp2 = SHA256_SIGMA0(A) + SHA_Maj(A, B, C);
        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;
    context->Intermediate_Hash[5] += F;
    context->Intermediate_Hash[6] += G;
    context->Intermediate_Hash[7] += H;

    context->Message_Block_Index = 0;
}

i32 SHA256Input(SHA256Context *context, const u8 *message_array, u32 length) {
    if (!context)
        return shaNull;
    if (!length)
        return shaSuccess;
    if (!message_array)
        return shaNull;
    if (context->Computed)
        return context->Corrupted = shaStateError;
    if (context->Corrupted)
        return context->Corrupted;

    while (length--) {
        context->Message_Block[context->Message_Block_Index++] = *message_array;

        context->Length += 8;
        if (context->Message_Block_Index == SHA256_Message_Block_Size) {
            SHA256ProcessMessageBlock(context);
        }

        message_array++;
    }

    return context->Corrupted;
}

static void SHA256PadMessage(SHA256Context *context, u8 Pad_Byte) {
    /* Check to see if the current message block is too small to hold
     * the initial padding bits and length.  If so, we will pad the
     * block, process it, and then continue padding into a second
     * block. */
    if (context->Message_Block_Index >= (SHA256_Message_Block_Size - 8)) {
        context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
        while (context->Message_Block_Index < SHA256_Message_Block_Size)
            context->Message_Block[context->Message_Block_Index++] = 0;
        SHA256ProcessMessageBlock(context);
    } else {
        context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    }

    while (context->Message_Block_Index < (SHA256_Message_Block_Size - 8)) {
        context->Message_Block[context->Message_Block_Index++] = 0;
    }

    /* Store the message length as the last 8 octets */
    context->Message_Block[56] = (u8)(context->Length >> 56);
    context->Message_Block[57] = (u8)(context->Length >> 48);
    context->Message_Block[58] = (u8)(context->Length >> 40);
    context->Message_Block[59] = (u8)(context->Length >> 32);
    context->Message_Block[60] = (u8)(context->Length >> 24);
    context->Message_Block[61] = (u8)(context->Length >> 16);
    context->Message_Block[62] = (u8)(context->Length >> 8);
    context->Message_Block[63] = (u8)(context->Length >> 0);

    SHA256ProcessMessageBlock(context);
}

static void SHA256Finalize(SHA256Context *context, u8 Pad_Byte) {
    SHA256PadMessage(context, Pad_Byte);
    /* message may be sensitive, so clear it out */
    for (i32 i = 0; i < SHA256_Message_Block_Size; ++i) {
        context->Message_Block[i] = 0;
    }
    context->Length = 0; /* and clear length */
    context->Computed = 1;
}

static i32 SHA256Result(SHA256Context *context,
                        u8 Message_Digest[SHA256HashSize]) {
    if (!context)
        return shaNull;
    if (!Message_Digest)
        return shaNull;
    if (context->Corrupted)
        return context->Corrupted;

    if (!context->Computed) {
        SHA256Finalize(context, 0x80);
    }

    for (i32 i = 0; i < SHA256HashSize; ++i) {
        Message_Digest[i] =
            (u8)(context->Intermediate_Hash[i >> 2] >> 8 * (3 - (i & 0x03)));
    }

    return shaSuccess;
}

void printResult(u8 *Message_Digest) {
    for (u8 i = 0; i < SHA256HashSize; i++) {
        printf("%02x", Message_Digest[i]);
    }
    putchar('\n');
}

void hashfile(const char *hashfilename) {
    FILE *hashfp =
        (strcmp(hashfilename, "-") == 0) ? stdin : fopen(hashfilename, "r");
    if (!hashfp) {
        fprintf(stderr, "cannot open file '%s'\n", hashfilename);
        exit(EXIT_FAILURE);
    }

    SHA256Context sha;
    memset(&sha, '\343', sizeof(sha)); /* force bad data into struct */

    CHECK_RES(SHA256Reset(&sha));

    i32 nread;
    u8 buf[4096];
    while ((nread = fread(buf, 1, sizeof(buf), hashfp)) > 0) {
        CHECK_RES(SHA256Input(&sha, buf, nread));
    }

    u8 Message_Digest[SHA256HashSize];
    CHECK_RES(SHA256Result(&sha, Message_Digest));

    printResult(Message_Digest);

    if (hashfp != stdin) {
        fclose(hashfp);
    }
}

i32 main(i32 argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s infile\n", argv[0]);
        return 1;
    }

    hashfile(argv[1]);

    return 0;
}
