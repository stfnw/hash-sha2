/*
 * SPDX-FileCopyrightText: 2011 Original C code: IETF Trust and the persons identified as the document authors. All rights reserved.
 * SPDX-FileCopyrightText: 2025 Refactoring and modifications: stfnw.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Refactored SHA512 implementation derived from
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

typedef struct SHA512Context {
    u64 Intermediate_Hash[SHA512HashSize / 8]; /* Message Digest */
    u64 Length_High, Length_Low;               /* Message length in bits */

    i16 Message_Block_Index; /* Message_Block array index */
                             /* 1024-bit message blocks */
    u8 Message_Block[SHA512_Message_Block_Size];

    i32 Computed;  /* Is the hash computed?*/
    i32 Corrupted; /* Cumulative corruption code */
} SHA512Context;

u64 SHA_Ch(u64 x, u64 y, u64 z) { return (x & y) ^ ((~x) & z); }
u64 SHA_Maj(u64 x, u64 y, u64 z) { return (x & y) ^ (x & z) ^ (y & z); }
u64 SHA_Parity(u64 x, u64 y, u64 z) { return x ^ y ^ z; }

u64 SHA512_SHR(u8 bits, u64 word) { return word >> bits; }
u64 SHA512_ROTR(u8 bits, u64 word) {
    return (word >> bits) | (word << (64 - bits));
}

u64 SHA512_SIGMA0(u64 word) {
    return SHA512_ROTR(28, word) ^ SHA512_ROTR(34, word) ^
           SHA512_ROTR(39, word);
}
u64 SHA512_SIGMA1(u64 word) {
    return SHA512_ROTR(14, word) ^ SHA512_ROTR(18, word) ^
           SHA512_ROTR(41, word);
}
u64 SHA512_sigma0(u64 word) {
    return SHA512_ROTR(1, word) ^ SHA512_ROTR(8, word) ^ SHA512_SHR(7, word);
}
u64 SHA512_sigma1(u64 word) {
    return SHA512_ROTR(19, word) ^ SHA512_ROTR(61, word) ^ SHA512_SHR(6, word);
}

i32 SHA512AddLength(SHA512Context *context, u32 length) {
    u64 addTemp = context->Length_Low;
    context->Corrupted = ((context->Length_Low += length) < addTemp) &&
                                 (++context->Length_High == 0)
                             ? shaInputTooLong
                             : context->Corrupted;
    return context->Corrupted;
}

static u64 SHA512_H0[] = {0x6A09E667F3BCC908ll, 0xBB67AE8584CAA73Bll,
                          0x3C6EF372FE94F82Bll, 0xA54FF53A5F1D36F1ll,
                          0x510E527FADE682D1ll, 0x9B05688C2B3E6C1Fll,
                          0x1F83D9ABFB41BD6Bll, 0x5BE0CD19137E2179ll};

static i32 SHA512Reset(SHA512Context *context) {
    if (!context) {
        return shaNull;
    }
    context->Message_Block_Index = 0;

    context->Length_High = context->Length_Low = 0;

    for (i32 i = 0; i < SHA512HashSize / 8; i++) {
        context->Intermediate_Hash[i] = SHA512_H0[i];
    }

    context->Computed = 0;
    context->Corrupted = shaSuccess;

    return shaSuccess;
}

static void SHA512ProcessMessageBlock(SHA512Context *context) {
    /* Constants defined in FIPS 180-3, section 4.2.3 */
    static const u64 K[80] = {
        0x428A2F98D728AE22ll, 0x7137449123EF65CDll, 0xB5C0FBCFEC4D3B2Fll,
        0xE9B5DBA58189DBBCll, 0x3956C25BF348B538ll, 0x59F111F1B605D019ll,
        0x923F82A4AF194F9Bll, 0xAB1C5ED5DA6D8118ll, 0xD807AA98A3030242ll,
        0x12835B0145706FBEll, 0x243185BE4EE4B28Cll, 0x550C7DC3D5FFB4E2ll,
        0x72BE5D74F27B896Fll, 0x80DEB1FE3B1696B1ll, 0x9BDC06A725C71235ll,
        0xC19BF174CF692694ll, 0xE49B69C19EF14AD2ll, 0xEFBE4786384F25E3ll,
        0x0FC19DC68B8CD5B5ll, 0x240CA1CC77AC9C65ll, 0x2DE92C6F592B0275ll,
        0x4A7484AA6EA6E483ll, 0x5CB0A9DCBD41FBD4ll, 0x76F988DA831153B5ll,
        0x983E5152EE66DFABll, 0xA831C66D2DB43210ll, 0xB00327C898FB213Fll,
        0xBF597FC7BEEF0EE4ll, 0xC6E00BF33DA88FC2ll, 0xD5A79147930AA725ll,
        0x06CA6351E003826Fll, 0x142929670A0E6E70ll, 0x27B70A8546D22FFCll,
        0x2E1B21385C26C926ll, 0x4D2C6DFC5AC42AEDll, 0x53380D139D95B3DFll,
        0x650A73548BAF63DEll, 0x766A0ABB3C77B2A8ll, 0x81C2C92E47EDAEE6ll,
        0x92722C851482353Bll, 0xA2BFE8A14CF10364ll, 0xA81A664BBC423001ll,
        0xC24B8B70D0F89791ll, 0xC76C51A30654BE30ll, 0xD192E819D6EF5218ll,
        0xD69906245565A910ll, 0xF40E35855771202All, 0x106AA07032BBD1B8ll,
        0x19A4C116B8D2D0C8ll, 0x1E376C085141AB53ll, 0x2748774CDF8EEB99ll,
        0x34B0BCB5E19B48A8ll, 0x391C0CB3C5C95A63ll, 0x4ED8AA4AE3418ACBll,
        0x5B9CCA4F7763E373ll, 0x682E6FF3D6B2B8A3ll, 0x748F82EE5DEFB2FCll,
        0x78A5636F43172F60ll, 0x84C87814A1F0AB72ll, 0x8CC702081A6439ECll,
        0x90BEFFFA23631E28ll, 0xA4506CEBDE82BDE9ll, 0xBEF9A3F7B2C67915ll,
        0xC67178F2E372532Bll, 0xCA273ECEEA26619Cll, 0xD186B8C721C0C207ll,
        0xEADA7DD6CDE0EB1Ell, 0xF57D4F7FEE6ED178ll, 0x06F067AA72176FBAll,
        0x0A637DC5A2C898A6ll, 0x113F9804BEF90DAEll, 0x1B710B35131C471Bll,
        0x28DB77F523047D84ll, 0x32CAAB7B40C72493ll, 0x3C9EBE0A15C9BEBCll,
        0x431D67C49C100D4Cll, 0x4CC5D4BECB3E42B6ll, 0x597F299CFC657E2All,
        0x5FCB6FAB3AD6FAECll, 0x6C44198C4A475817ll};
    u64 W[80]; /* Word sequence */

    /* Initialize the first 16 words in the array W */
    for (i32 t = 0, t8 = 0; t < 16; t++, t8 += 8) {
        W[t] = ((u64)(context->Message_Block[t8]) << 56) |
               ((u64)(context->Message_Block[t8 + 1]) << 48) |
               ((u64)(context->Message_Block[t8 + 2]) << 40) |
               ((u64)(context->Message_Block[t8 + 3]) << 32) |
               ((u64)(context->Message_Block[t8 + 4]) << 24) |
               ((u64)(context->Message_Block[t8 + 5]) << 16) |
               ((u64)(context->Message_Block[t8 + 6]) << 8) |
               ((u64)(context->Message_Block[t8 + 7]));
    }

    for (i32 t = 16; t < 80; t++) {
        W[t] = SHA512_sigma1(W[t - 2]) + W[t - 7] + SHA512_sigma0(W[t - 15]) +
               W[t - 16];
    }
    u64 A = context->Intermediate_Hash[0];
    u64 B = context->Intermediate_Hash[1];
    u64 C = context->Intermediate_Hash[2];
    u64 D = context->Intermediate_Hash[3];
    u64 E = context->Intermediate_Hash[4];
    u64 F = context->Intermediate_Hash[5];
    u64 G = context->Intermediate_Hash[6];
    u64 H = context->Intermediate_Hash[7];

    for (i32 t = 0; t < 80; t++) {
        u64 temp1 = H + SHA512_SIGMA1(E) + SHA_Ch(E, F, G) + K[t] + W[t];
        u64 temp2 = SHA512_SIGMA0(A) + SHA_Maj(A, B, C);
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

i32 SHA512Input(SHA512Context *context, const u8 *message_array, u32 length) {
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

        if ((SHA512AddLength(context, 8) == shaSuccess) &&
            (context->Message_Block_Index == SHA512_Message_Block_Size)) {
            SHA512ProcessMessageBlock(context);
        }

        message_array++;
    }

    return context->Corrupted;
}

static void SHA512PadMessage(SHA512Context *context, u8 Pad_Byte) {
    /* Check to see if the current message block is too small to hold
     * the initial padding bits and length.  If so, we will pad the
     * block, process it, and then continue padding into a second
     * block. */
    if (context->Message_Block_Index >= (SHA512_Message_Block_Size - 16)) {
        context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
        while (context->Message_Block_Index < SHA512_Message_Block_Size)
            context->Message_Block[context->Message_Block_Index++] = 0;

        SHA512ProcessMessageBlock(context);
    } else {
        context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    }

    while (context->Message_Block_Index < (SHA512_Message_Block_Size - 16)) {
        context->Message_Block[context->Message_Block_Index++] = 0;
    }

    /* Store the message length as the last 16 octets */
    context->Message_Block[112] = (u8)(context->Length_High >> 56);
    context->Message_Block[113] = (u8)(context->Length_High >> 48);
    context->Message_Block[114] = (u8)(context->Length_High >> 40);
    context->Message_Block[115] = (u8)(context->Length_High >> 32);
    context->Message_Block[116] = (u8)(context->Length_High >> 24);
    context->Message_Block[117] = (u8)(context->Length_High >> 16);
    context->Message_Block[118] = (u8)(context->Length_High >> 8);
    context->Message_Block[119] = (u8)(context->Length_High >> 0);

    context->Message_Block[120] = (u8)(context->Length_Low >> 56);
    context->Message_Block[121] = (u8)(context->Length_Low >> 48);
    context->Message_Block[122] = (u8)(context->Length_Low >> 40);
    context->Message_Block[123] = (u8)(context->Length_Low >> 32);
    context->Message_Block[124] = (u8)(context->Length_Low >> 24);
    context->Message_Block[125] = (u8)(context->Length_Low >> 16);
    context->Message_Block[126] = (u8)(context->Length_Low >> 8);
    context->Message_Block[127] = (u8)(context->Length_Low >> 0);

    SHA512ProcessMessageBlock(context);
}

static void SHA512Finalize(SHA512Context *context, u8 Pad_Byte) {
    SHA512PadMessage(context, Pad_Byte);
    /* message may be sensitive, clear it out */
    for (i16 i = 0; i < SHA512_Message_Block_Size; ++i) {
        context->Message_Block[i] = 0;
    }
    context->Length_High = context->Length_Low = 0;
    context->Computed = 1;
}

static i32 SHA512Result(SHA512Context *context,
                        u8 Message_Digest[SHA512HashSize]) {
    if (!context)
        return shaNull;
    if (!Message_Digest)
        return shaNull;
    if (context->Corrupted)
        return context->Corrupted;

    if (!context->Computed)
        SHA512Finalize(context, 0x80);

    for (i32 i = 0; i < SHA512HashSize; ++i) {
        Message_Digest[i] =
            (u8)(context->Intermediate_Hash[i >> 3] >> 8 * (7 - (i % 8)));
    }

    return shaSuccess;
}

void printResult(u8 *Message_Digest) {
    for (u8 i = 0; i < SHA512HashSize; i++) {
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

    SHA512Context sha;
    memset(&sha, '\343', sizeof(sha)); /* force bad data into struct */

    CHECK_RES(SHA512Reset(&sha));

    i32 nread;
    u8 buf[4096];
    while ((nread = fread(buf, 1, sizeof(buf), hashfp)) > 0) {
        CHECK_RES(SHA512Input(&sha, buf, nread));
    }

    u8 Message_Digest[SHA512HashSize];
    CHECK_RES(SHA512Result(&sha, Message_Digest));

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
