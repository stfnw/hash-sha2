/**************************** sha.h ****************************/
/***************** See RFC 6234 for details. *******************/
/*
 * Copyright (c) 2011 IETF Trust and the persons identified as
 * authors of the code.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * - Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and
 *   the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 * - Neither the name of Internet Society, IETF or IETF Trust, nor
 *   the names of specific contributors, may be used to endorse or
 *   promote products derived from this software without specific
 *   prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */
#ifndef _SHA_H_
#define _SHA_H_

/*
 *  Description:
 *      This file implements the Secure Hash Algorithms
 *      as defined in the U.S. National Institute of Standards
 *      and Technology Federal Information Processing Standards
 *      Publication (FIPS PUB) 180-3 published in October 2008
 *      and formerly defined in its predecessors, FIPS PUB 180-1
 *      and FIP PUB 180-2.
 *
 *      A combined document showing all algorithms is available at
 *              http://csrc.nist.gov/publications/fips/
 *                     fips180-3/fips180-3_final.pdf
 *
 *      The five hashes are defined in these sizes:
 *              SHA-1           20 byte / 160 bit
 *              SHA-224         28 byte / 224 bit
 *              SHA-256         32 byte / 256 bit
 *              SHA-384         48 byte / 384 bit
 *              SHA-512         64 byte / 512 bit
 *
 *  Compilation Note:
 *    These files may be compiled with two options:
 *        USE_32BIT_ONLY - use 32-bit arithmetic only, for systems
 *                         without 64-bit integers
 *
 *        USE_MODIFIED_MACROS - use alternate form of the SHA_Ch()
 *                         and SHA_Maj() macros that are equivalent
 *                         and potentially faster on many systems
 *
 */

#include <stdint.h>
/*
 * If you do not have the ISO standard stdint.h header file, then you
 * must typedef the following:
 *    name              meaning
 *  u64         unsigned 64-bit integer
 *  u32         unsigned 32-bit integer
 *  u8          unsigned 8-bit integer (i.e., u8)
 *  i16    integer of >= 16 bits
 *
 * See stdint-example.h
 */

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#ifndef _SHA_enum_
#define _SHA_enum_
/*
 *  All SHA functions return one of these values.
 */
enum {
    shaSuccess = 0,
    shaNull,         /* Null pointer parameter */
    shaInputTooLong, /* input data too u64 */
    shaStateError,   /* called Input after FinalBits or Result */
    shaBadParam      /* passed a bad parameter */
};
#endif /* _SHA_enum_ */

/*
 *  These constants hold size information for each of the SHA
 *  hashing operations
 */
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

/*
 *  These constants are used in the USHA (Unified SHA) functions.
 */
typedef enum SHAversion { SHA1, SHA224, SHA256, SHA384, SHA512 } SHAversion;

/*
 *  This structure will hold context information for the SHA-1
 *  hashing operation.
 */
typedef struct SHA1Context {
    u32 Intermediate_Hash[SHA1HashSize / 4]; /* Message Digest */

    u32 Length_High; /* Message length in bits */
    u32 Length_Low;  /* Message length in bits */

    i16 Message_Block_Index; /* Message_Block array index */
                                       /* 512-bit message blocks */
    u8 Message_Block[SHA1_Message_Block_Size];

    i32 Computed;  /* Is the hash computed? */
    i32 Corrupted; /* Cumulative corruption code */
} SHA1Context;

/*
 *  This structure will hold context information for the SHA-256
 *  hashing operation.
 */
typedef struct SHA256Context {
    u32 Intermediate_Hash[SHA256HashSize / 4]; /* Message Digest */

    u32 Length_High; /* Message length in bits */
    u32 Length_Low;  /* Message length in bits */

    i16 Message_Block_Index; /* Message_Block array index */
                                       /* 512-bit message blocks */
    u8 Message_Block[SHA256_Message_Block_Size];

    i32 Computed;  /* Is the hash computed? */
    i32 Corrupted; /* Cumulative corruption code */
} SHA256Context;

/*
 *  This structure will hold context information for the SHA-512
 *  hashing operation.
 */
typedef struct SHA512Context {
#ifdef USE_32BIT_ONLY
    u32 Intermediate_Hash[SHA512HashSize / 4]; /* Message Digest  */
    u32 Length[4];                             /* Message length in bits */
#else                                          /* !USE_32BIT_ONLY */
    u64 Intermediate_Hash[SHA512HashSize / 8]; /* Message Digest */
    u64 Length_High, Length_Low;               /* Message length in bits */
#endif                                         /* USE_32BIT_ONLY */

    i16 Message_Block_Index; /* Message_Block array index */
                                       /* 1024-bit message blocks */
    u8 Message_Block[SHA512_Message_Block_Size];

    i32 Computed;  /* Is the hash computed?*/
    i32 Corrupted; /* Cumulative corruption code */
} SHA512Context;

/*
 *  This structure will hold context information for the SHA-224
 *  hashing operation.  It uses the SHA-256 structure for computation.
 */
typedef struct SHA256Context SHA224Context;

/*
 *  This structure will hold context information for the SHA-384
 *  hashing operation.  It uses the SHA-512 structure for computation.
 */
typedef struct SHA512Context SHA384Context;

/*
 *  This structure holds context information for all SHA
 *  hashing operations.
 */
typedef struct USHAContext {
    i32 whichSha; /* which SHA is being used */
    union {
        SHA1Context sha1Context;
        SHA224Context sha224Context;
        SHA256Context sha256Context;
        SHA384Context sha384Context;
        SHA512Context sha512Context;
    } ctx;

} USHAContext;

/*
 *  This structure will hold context information for the HMAC
 *  keyed-hashing operation.
 */
typedef struct HMACContext {
    i32 whichSha;           /* which SHA is being used */
    i32 hashSize;           /* hash size of SHA being used */
    i32 blockSize;          /* block size of SHA being used */
    USHAContext shaContext; /* SHA context */
    u8 k_opad[USHA_Max_Message_Block_Size];
    /* outer padding - key XORd with opad */
    i32 Computed;  /* Is the MAC computed? */
    i32 Corrupted; /* Cumulative corruption code */

} HMACContext;

/*
 *  This structure will hold context information for the HKDF
 *  extract-and-expand Key Derivation Functions.
 */
typedef struct HKDFContext {
    i32 whichSha; /* which SHA is being used */
    HMACContext hmacContext;
    i32 hashSize; /* hash size of SHA being used */
    u8 prk[USHAMaxHashSize];
    /* pseudo-random key - output of hkdfInput */
    i32 Computed;  /* Is the key material computed? */
    i32 Corrupted; /* Cumulative corruption code */
} HKDFContext;

/*
 *  Function Prototypes
 */

/* SHA-1 */
extern i32 SHA1Reset(SHA1Context *);
extern i32 SHA1Input(SHA1Context *, const u8 *bytes, u32 bytecount);
extern i32 SHA1FinalBits(SHA1Context *, u8 bits, u32 bit_count);
extern i32 SHA1Result(SHA1Context *, u8 Message_Digest[SHA1HashSize]);

/* SHA-224 */
extern i32 SHA224Reset(SHA224Context *);
extern i32 SHA224Input(SHA224Context *, const u8 *bytes, u32 bytecount);
extern i32 SHA224FinalBits(SHA224Context *, u8 bits, u32 bit_count);
extern i32 SHA224Result(SHA224Context *, u8 Message_Digest[SHA224HashSize]);

/* SHA-256 */
extern i32 SHA256Reset(SHA256Context *);
extern i32 SHA256Input(SHA256Context *, const u8 *bytes, u32 bytecount);
extern i32 SHA256FinalBits(SHA256Context *, u8 bits, u32 bit_count);
extern i32 SHA256Result(SHA256Context *, u8 Message_Digest[SHA256HashSize]);

/* SHA-384 */
extern i32 SHA384Reset(SHA384Context *);
extern i32 SHA384Input(SHA384Context *, const u8 *bytes, u32 bytecount);
extern i32 SHA384FinalBits(SHA384Context *, u8 bits, u32 bit_count);
extern i32 SHA384Result(SHA384Context *, u8 Message_Digest[SHA384HashSize]);

/* SHA-512 */
extern i32 SHA512Reset(SHA512Context *);
extern i32 SHA512Input(SHA512Context *, const u8 *bytes, u32 bytecount);
extern i32 SHA512FinalBits(SHA512Context *, u8 bits, u32 bit_count);
extern i32 SHA512Result(SHA512Context *, u8 Message_Digest[SHA512HashSize]);

/* Unified SHA functions, chosen by whichSha */
extern i32 USHAReset(USHAContext *context, SHAversion whichSha);
extern i32 USHAInput(USHAContext *context, const u8 *bytes, u32 bytecount);
extern i32 USHAFinalBits(USHAContext *context, u8 bits, u32 bit_count);
extern i32 USHAResult(USHAContext *context, u8 Message_Digest[USHAMaxHashSize]);
extern i32 USHABlockSize(enum SHAversion whichSha);
extern i32 USHAHashSize(enum SHAversion whichSha);
extern i32 USHAHashSizeBits(enum SHAversion whichSha);
extern const char *USHAHashName(enum SHAversion whichSha);

/*
 * HMAC Keyed-Hashing for Message Authentication, RFC 2104,
 * for all SHAs.
 * This interface allows a fixed-length text input to be used.
 */
extern i32 hmac(SHAversion whichSha,         /* which SHA algorithm to use */
                const u8 *text,              /* pointer to data stream */
                i32 text_len,                /* length of data stream */
                const u8 *key,               /* pointer to authentication key */
                i32 key_len,                 /* length of authentication key */
                u8 digest[USHAMaxHashSize]); /* caller digest to fill in */

/*
 * HMAC Keyed-Hashing for Message Authentication, RFC 2104,
 * for all SHAs.
 * This interface allows any length of text input to be used.
 */
extern i32 hmacReset(HMACContext *context, enum SHAversion whichSha,
                     const u8 *key, i32 key_len);
extern i32 hmacInput(HMACContext *context, const u8 *text, i32 text_len);
extern i32 hmacFinalBits(HMACContext *context, u8 bits, u32 bit_count);
extern i32 hmacResult(HMACContext *context, u8 digest[USHAMaxHashSize]);

/*
 * HKDF HMAC-based Extract-and-Expand Key Derivation Function,
 * RFC 5869, for all SHAs.
 */
extern i32 hkdf(SHAversion whichSha, const u8 *salt, i32 salt_len,
                const u8 *ikm, i32 ikm_len, const u8 *info, i32 info_len,
                u8 okm[], i32 okm_len);
extern i32 hkdfExtract(SHAversion whichSha, const u8 *salt, i32 salt_len,
                       const u8 *ikm, i32 ikm_len, u8 prk[USHAMaxHashSize]);
extern i32 hkdfExpand(SHAversion whichSha, const u8 prk[], i32 prk_len,
                      const u8 *info, i32 info_len, u8 okm[], i32 okm_len);

/*
 * HKDF HMAC-based Extract-and-Expand Key Derivation Function,
 * RFC 5869, for all SHAs.
 * This interface allows any length of text input to be used.
 */
extern i32 hkdfReset(HKDFContext *context, enum SHAversion whichSha,
                     const u8 *salt, i32 salt_len);

extern i32 hkdfInput(HKDFContext *context, const u8 *ikm, i32 ikm_len);
extern i32 hkdfFinalBits(HKDFContext *context, u8 ikm_bits, u32 ikm_bit_count);
extern i32 hkdfResult(HKDFContext *context, u8 prk[USHAMaxHashSize],
                      const u8 *info, i32 info_len, u8 okm[USHAMaxHashSize],
                      i32 okm_len);
#endif /* _SHA_H_ */
