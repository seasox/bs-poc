//
// Created by Jeremy Boy on 18.08.23.
//

#ifndef RSA_CRT_SIGNATURE_RSA_CRT_H
#define RSA_CRT_SIGNATURE_RSA_CRT_H

#include <stddef.h>
#include <openssl/rsa.h>

typedef struct RSACRT_ctx {
  RSA *sk;
  RSA *pk;
} RSACRT_ctx_t;

extern int RSACRT_check_openssl_version(void);

extern int RSACRT_alloc(RSACRT_ctx_t **out);

extern int RSACRT_init(BN_ULONG *vuln_mem, RSACRT_ctx_t *out);

extern int RSACRT_sign(const RSACRT_ctx_t *ctx, const unsigned char *msg, const size_t msg_len, unsigned char **sig, unsigned int *siglen);

extern int RSACRT_verify(const RSACRT_ctx_t *ctx, const unsigned char *msg, const size_t msg_len, const unsigned char *sig, size_t siglen);

extern void RSACRT_free_ctx(RSACRT_ctx_t *ctx);

#endif //RSA_CRT_SIGNATURE_RSA_CRT_H
