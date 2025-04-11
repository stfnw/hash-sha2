/*
 * SPDX-FileCopyrightText: 2011 Original C code: IETF Trust and the persons identified as the document authors. All rights reserved.
 * SPDX-FileCopyrightText: 2025 Refactoring and modifications: stfnw.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Refactored SHA1 implementation derived from
 * https://datatracker.ietf.org/doc/html/rfc6234.
 * Self-contained single-file
 * implementation; with macros replaced with functions. */

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

typedef struct SHA1Context {
    u32 Intermediate_Hash[SHA1HashSize / 4]; /* Message Digest */

    u64 Length; /* Message length in bits */

    i16 Message_Block_Index; /* Message_Block array index */
                             /* 512-bit message blocks */
    u8 Message_Block[SHA1_Message_Block_Size];

    i32 Computed;  /* Is the hash computed? */
    i32 Corrupted; /* Cumulative corruption code */
} SHA1Context;

u32 SHA1_ROTL(u8 bits, u32 word) {
    return (word << bits) | (word >> (32 - bits));
}

u32 SHA_Ch(u32 x, u32 y, u32 z) { return (x & y) ^ ((~x) & z); }
u32 SHA_Maj(u32 x, u32 y, u32 z) { return (x & y) ^ (x & z) ^ (y & z); }
u32 SHA_Parity(u32 x, u32 y, u32 z) { return x ^ y ^ z; }

i32 SHA1Reset(SHA1Context *context) {
    if (!context) {
        return shaNull;
    }

    context->Length = 0;
    context->Message_Block_Index = 0;

    /* Initial Hash Values: FIPS 180-3 section 5.3.1 */
    context->Intermediate_Hash[0] = 0x67452301;
    context->Intermediate_Hash[1] = 0xEFCDAB89;
    context->Intermediate_Hash[2] = 0x98BADCFE;
    context->Intermediate_Hash[3] = 0x10325476;
    context->Intermediate_Hash[4] = 0xC3D2E1F0;

    context->Computed = 0;
    context->Corrupted = shaSuccess;

    return shaSuccess;
}

static void SHA1ProcessMessageBlock(SHA1Context *context) {
    /* Constants defined in FIPS 180-3, section 4.2.1 */
    const u32 K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

    u32 W[80]; /* Word sequence */

    /* Initialize the first 16 words in the array W */
    for (i32 t = 0; t < 16; t++) {
        W[t] = ((u32)context->Message_Block[t * 4]) << 24;
        W[t] |= ((u32)context->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((u32)context->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((u32)context->Message_Block[t * 4 + 3]);
    }

    for (i32 t = 16; t < 80; t++)
        W[t] = SHA1_ROTL(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);

    u32 A = context->Intermediate_Hash[0];
    u32 B = context->Intermediate_Hash[1];
    u32 C = context->Intermediate_Hash[2];
    u32 D = context->Intermediate_Hash[3];
    u32 E = context->Intermediate_Hash[4];

    for (i32 t = 0; t < 20; t++) {
        u32 temp = SHA1_ROTL(5, A) + SHA_Ch(B, C, D) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1_ROTL(30, B);
        B = A;
        A = temp;
    }

    for (i32 t = 20; t < 40; t++) {
        u32 temp = SHA1_ROTL(5, A) + SHA_Parity(B, C, D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1_ROTL(30, B);
        B = A;
        A = temp;
    }

    for (i32 t = 40; t < 60; t++) {
        u32 temp = SHA1_ROTL(5, A) + SHA_Maj(B, C, D) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1_ROTL(30, B);
        B = A;
        A = temp;
    }

    for (i32 t = 60; t < 80; t++) {
        u32 temp = SHA1_ROTL(5, A) + SHA_Parity(B, C, D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1_ROTL(30, B);
        B = A;
        A = temp;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;
    context->Message_Block_Index = 0;
}

i32 SHA1Input(SHA1Context *context, const u8 *message_array, unsigned length) {
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
        if (context->Message_Block_Index == SHA1_Message_Block_Size) {
            SHA1ProcessMessageBlock(context);
        }

        message_array++;
    }

    return context->Corrupted;
}

static void SHA1PadMessage(SHA1Context *context, u8 Pad_Byte) {
    /* Check to see if the current message block is too small to hold
     * the initial padding bits and length.  If so, we will pad the
     * block, process it, and then continue padding into a second
     * block. */
    if (context->Message_Block_Index >= (SHA1_Message_Block_Size - 8)) {
        context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
        while (context->Message_Block_Index < SHA1_Message_Block_Size) {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(context);
    } else {
        context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    }

    while (context->Message_Block_Index < (SHA1_Message_Block_Size - 8)) {
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

    SHA1ProcessMessageBlock(context);
}

static void SHA1Finalize(SHA1Context *context, u8 Pad_Byte) {
    SHA1PadMessage(context, Pad_Byte);
    /* message may be sensitive, clear it out */
    for (i32 i = 0; i < SHA1_Message_Block_Size; ++i) {
        context->Message_Block[i] = 0;
    }
    context->Length = 0; /* and clear length */
    context->Computed = 1;
}

i32 SHA1Result(SHA1Context *context, u8 Message_Digest[SHA1HashSize]) {
    if (!context)
        return shaNull;
    if (!Message_Digest)
        return shaNull;
    if (context->Corrupted)
        return context->Corrupted;

    if (!context->Computed)
        SHA1Finalize(context, 0x80);

    for (i32 i = 0; i < SHA1HashSize; ++i) {
        Message_Digest[i] =
            (u8)(context->Intermediate_Hash[i >> 2] >> (8 * (3 - (i & 0x03))));
    }

    return shaSuccess;
}

void printResult(u8 *Message_Digest) {
    for (u8 i = 0; i < SHA1HashSize; i++) {
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

    SHA1Context sha;
    memset(&sha, '\343', sizeof(sha)); /* force bad data into struct */

    CHECK_RES(SHA1Reset(&sha));

    i32 nread;
    u8 buf[4096];
    while ((nread = fread(buf, 1, sizeof(buf), hashfp)) > 0) {
        CHECK_RES(SHA1Input(&sha, buf, nread));
    }

    u8 Message_Digest[SHA1HashSize];
    CHECK_RES(SHA1Result(&sha, Message_Digest));

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
