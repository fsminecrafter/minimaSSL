#include <openssl/sha.h>
#include <stddef.h>
#include "crypto.h"

static void sha_cleanse(void* p, size_t n) {
    volatile unsigned char* v = (volatile unsigned char*)p;
    while (n--) *v++ = 0;
}

/*
 * SHA256_CTX and dlr_sha256_ctx intentionally have the same ABI/layout.
 * Keep the cast local so the public header stays independent of src/.
 */

int SHA256_Init(SHA256_CTX* c) {
    if (!c) return 0;
    dlr_sha256_init((dlr_sha256_ctx*)c);
    return 1;
}

int SHA256_Update(SHA256_CTX* c, const void* data, size_t len) {
    static const unsigned char empty = 0;
    if (!c) return 0;
    if (!data) {
        if (len) return 0;      /* non-zero length with NULL data is an error */
        data = &empty;          /* avoid memcpy(NULL, ..., 0) inside update */
    }
    dlr_sha256_update((dlr_sha256_ctx*)c, data, len);
    return 1;
}

int SHA256_Final(unsigned char* md, SHA256_CTX* c) {
    if (!md || !c) return 0;
    dlr_sha256_final((dlr_sha256_ctx*)c, md);
    sha_cleanse(c, sizeof *c);
    return 1;
}