//
// Created by Jeremy Boy on 18.08.23.
//

#ifndef RSA_CRT_SIGNATURE_RSA_CRT_H
#define RSA_CRT_SIGNATURE_RSA_CRT_H

#include <stddef.h>

typedef struct bignum_st BIGNUM;
typedef struct RSACRT_ctx RSACRT_ctx_t;

extern int RSACRT_check_openssl_version(void);

extern int RSACRT_alloc(RSACRT_ctx_t **out);

extern int RSACRT_init(unsigned long *vuln_mem, RSACRT_ctx_t *out);

/**
 * Returns 1 on success and 0 for failure
*/
extern int RSACRT_sign(const RSACRT_ctx_t *ctx, const unsigned char *msg, const size_t msg_len, unsigned char **sig, unsigned int *siglen);

/**
 * Returns 1 on success and 0 for failure
*/
extern int RSACRT_verify(const RSACRT_ctx_t *ctx, const unsigned char *msg, const size_t msg_len, const unsigned char *sig, unsigned int siglen);

extern void RSACRT_get_dmp1(const RSACRT_ctx_t *ctx, BIGNUM **dp_out);

extern int RSACRT_check_dmp1(const RSACRT_ctx_t *ctx, const BIGNUM *exp);

extern void RSACRT_free_ctx(RSACRT_ctx_t *ctx);

#endif //RSA_CRT_SIGNATURE_RSA_CRT_H
