#ifndef MINIMASSL_SHA_H
#define MINIMASSL_SHA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_DIGEST_LENGTH 32

/*
 * Keep the public OpenSSL-compatible header self-contained.
 *
 * Do not include the private src/crypto.h here: consumers of the
 * .slib bundle should only need the public include/openssl headers.
 * src/sha.c converts this public context to the internal implementation
 * context because both layouts are intentionally identical.
 */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buffer[64];
    size_t   buffered;
} SHA256_CTX;

/* All return 1 on success, 0 on failure (OpenSSL convention). */
int SHA256_Init(SHA256_CTX* c);
int SHA256_Update(SHA256_CTX* c, const void* data, size_t len);

#endif