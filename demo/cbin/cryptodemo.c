/*
 * Compiled artefact target — ECDAT demo target G (SPEC.md §14, collector §7.2).
 *
 * The point of a binary collector is that source scanning and binary scanning
 * answer different questions. Source says what someone wrote; a linked binary
 * says what is deployed and callable right now, including code nobody has the
 * source for any more. This file is here to become that binary.
 *
 * It is built with symbols intact and dynamically linked, so pyelftools can
 * read three separate kinds of evidence out of it:
 *
 *   DT_NEEDED   libcrypto.so.1.1  -> OpenSSL 1.1.x is what this is linked
 *                                    against. This is the input the advisor's
 *                                    `requires: openssl>=3.5` check fails on,
 *                                    which turns an ML-KEM recommendation into
 *                                    a `blocked` status with a prerequisite
 *                                    chain — the highest-value output we emit.
 *   .dynsym     MD5_Init, RSA_generate_key_ex, EVP_sha1, DES_ecb_encrypt
 *                                 -> proof of capability. confidence: high.
 *   .rodata     algorithm and cipher-suite names
 *                                 -> a hint, not proof. confidence: medium.
 *
 * Lines carrying an ECDAT-EXPECT marker are the ones a collector must report.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/opensslv.h>
#include <openssl/rsa.h>

/*
 * String constants land in .rodata. A name in .rodata proves only that the
 * string is present — it might be a log label, a lookup key, or dead data —
 * so §7.2 caps these at confidence: medium while symbols get high.
 */
/* ECDAT-EXPECT: rodata-algorithm-names */
static const char *const KNOWN_SUITES[] = {
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
    "sha1WithRSAEncryption",
    "AES-128-CBC",
    "AES-256-GCM",
};

/* MD5 over a record id. */
static void record_digest(const char *record, unsigned char out[MD5_DIGEST_LENGTH])
{
    MD5_CTX ctx;
    MD5_Init(&ctx);  /* ECDAT-EXPECT: symbol-md5 */
    MD5_Update(&ctx, record, strlen(record));
    MD5_Final(out, &ctx);
}

/* 1024-bit RSA keygen: below the SP 800-131A Rev.2 floor. */
static RSA *make_signing_key(void)
{
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, e, NULL);  /* ECDAT-EXPECT: symbol-rsa-keygen */
    BN_free(e);
    return rsa;
}

/* Pulls EVP_sha1 into .dynsym — the EVP-layer spelling of the same weakness. */
static const EVP_MD *legacy_digest(void)
{
    return EVP_sha1();  /* ECDAT-EXPECT: symbol-sha1 */
}

/* Single DES in ECB mode: a 56-bit key and a structure-leaking mode. */
static void encrypt_block(const unsigned char in[8], unsigned char out[8])
{
    DES_cblock key = {'8', 'b', 'y', 't', 'e', 'k', 'e', 'y'};
    DES_key_schedule schedule;

    DES_set_key_unchecked(&key, &schedule);
    DES_ecb_encrypt((const_DES_cblock *)in, (DES_cblock *)out, &schedule, DES_ENCRYPT);  /* ECDAT-EXPECT: symbol-des-ecb */
}

int main(void)
{
    unsigned char digest[MD5_DIGEST_LENGTH];
    unsigned char cipher_block[8];
    RSA *signing_key;
    size_t i;

    printf("ecdat demo cbin, built against %s\n", OPENSSL_VERSION_TEXT);

    record_digest("demo-settlement-0001", digest);
    printf("md5      : ");
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    signing_key = make_signing_key();
    printf("rsa      : %d bits\n", RSA_bits(signing_key));
    RSA_free(signing_key);

    printf("evp md   : %s\n", EVP_MD_name(legacy_digest()));

    encrypt_block((const unsigned char *)"12345678", cipher_block);
    printf("des-ecb  : %02x%02x...\n", cipher_block[0], cipher_block[1]);

    for (i = 0; i < sizeof(KNOWN_SUITES) / sizeof(KNOWN_SUITES[0]); i++) {
        printf("suite    : %s\n", KNOWN_SUITES[i]);
    }

    fflush(stdout);

    /* Stays resident so the container remains scannable while the demo runs. */
    for (;;) {
        sleep(3600);
    }

    return 0;
}
