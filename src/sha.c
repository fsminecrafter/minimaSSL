#include <openssl/sha.h>
#include "crypto.h"      /* dlr_sha256_ctx is now an alias of SHA256_CTX */
#include "mssl_core.h"

int SHA256_Init(SHA256_CTX* c) {
    if (!c) return 0;
    dlr_sha256_init(c);
    return 1;
}

int SHA256_Update(SHA256_CTX* c, const void* data, size_t len) {
    static const unsigned char empty = 0;
    if (!c) return 0;
    if (!data) {
        if (len) return 0;
        data = &empty;                 /* avoid memcpy(NULL, ..., 0) */
    }
    dlr_sha256_update(c, data, len);
    return 1;
}

int SHA256_Final(unsigned char* md, SHA256_CTX* c) {
    if (!md || !c) return 0;
    dlr_sha256_final(c, md);
    mssl_cleanse(c, sizeof *c);
    return 1;
}

unsigned char* SHA256(const unsigned char* d, size_t n, unsigned char* md) {
    static unsigned char static_md[SHA256_DIGEST_LENGTH];
    SHA256_CTX c;
    if (!md) md = static_md;
    if (!SHA256_Init(&c) || !SHA256_Update(&c, d, n) || !SHA256_Final(md, &c)) return NULL;
    return md;
}