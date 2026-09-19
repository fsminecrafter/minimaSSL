#ifndef MINIMASSL_SHA_H
#define MINIMASSL_SHA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_DIGEST_LENGTH 32

struct SHA256state_st {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buffer[64];
    size_t   buffered;
};
typedef struct SHA256state_st SHA256_CTX;

int SHA256_Init(SHA256_CTX* c);
int SHA256_Update(SHA256_CTX* c, const void* data, size_t len);
/* Zeroizes *c afterwards, like OpenSSL. */
int SHA256_Final(unsigned char* md, SHA256_CTX* c);

/* If md is NULL a static buffer is used (NOT thread-safe - same as OpenSSL). */
unsigned char* SHA256(const unsigned char* d, size_t n, unsigned char* md);

#ifdef __cplusplus
}
#endif
#endif