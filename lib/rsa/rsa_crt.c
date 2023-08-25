#include "rsa_crt.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <assert.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"


struct __attribute__((unused)) bignum_st {
  BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
                                 * chunks. */
  int top;                    /* Index of last used d +1. */
  /* The next are internal book keeping for bn_expand. */
  int dmax;                   /* Size of the d array. */
  int neg;                    /* one if the number is negative */
  int flags;
};

int RSACRT_alloc(RSACRT_ctx_t **out) {
  *out = malloc(sizeof(RSACRT_ctx_t));
  if (*out == NULL) {
    return 1;
  }
  return 0;
}

int RSACRT_check_openssl_version(void) {
  // TODO check for FIPS?
  return OPENSSL_VERSION_MAJOR == 3
         && OPENSSL_VERSION_MINOR == 0
         && OPENSSL_VERSION_PATCH == 2;
}

int RSACRT_init(BN_ULONG *vuln_mem, RSACRT_ctx_t *out) {
  // Initialize the OpenSSL library
  OpenSSL_add_all_algorithms();

  RSA *rsa = RSA_new();
  BIGNUM *e = BN_new();
  BN_set_word(e, RSA_F4);
  RSA_generate_key_ex(rsa, 2048, e, NULL);

  // now get the params out
  const BIGNUM *dmp1;
  RSA_get0_crt_params(rsa, &dmp1, NULL, NULL);

  BIGNUM *dp = BN_new();
  BN_copy(dp, dmp1);

  assert(BN_cmp(dp, dmp1) == 0);
  // copy dmp1->d to vuln
  memcpy(vuln_mem, dp->d, dp->dmax * sizeof(BN_ULONG));
  dp->d = vuln_mem;

  assert(BN_cmp(dp, dmp1) == 0);

  assert((size_t)vuln_mem==(size_t)dp->d);

  int ret = RSA_set0_crt_params(rsa, dp, NULL, NULL);
  if (ret != 1) {
    return 1;
  }

  out->sk = rsa;
  out->pk = RSAPublicKey_dup(rsa);
  return 0;
}

int RSACRT_sign(const RSACRT_ctx_t *ctx, const unsigned char *msg, const size_t msg_len, unsigned char **sig, unsigned int *siglen) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(msg, msg_len, hash);


  *sig = malloc(RSA_size(ctx->sk));
  memset(*sig, 0, RSA_size(ctx->sk));

  // Calculate the RSA-CRT signature
  int res = RSA_sign(
      NID_sha256,
      hash,
      SHA256_DIGEST_LENGTH,
      *sig,
      siglen,
      ctx->sk);
  if (!res) {
    printf("%lu", ERR_get_error());
  }

  return res;
}

int RSACRT_verify(const RSACRT_ctx_t *ctx, const unsigned char *msg, const size_t msg_len, const unsigned char *sig, size_t siglen) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(msg, msg_len, hash);

  int res = RSA_verify(
      NID_sha256,
      hash,
      SHA256_DIGEST_LENGTH,
      sig,
      siglen,
      ctx->pk);

  return res;
}

void RSACRT_free_ctx(RSACRT_ctx_t *ctx) {
  RSA_free(ctx->pk);
}

#pragma clang diagnostic pop