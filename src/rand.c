#include <openssl/rand.h>
#include <stddef.h>

#ifdef MINIMASSL_HOST
#include <stdio.h>
static int fill(void* buf, size_t n) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    return got == n;
}
#else
#include <stdlib.h>      /* SDK stdlib.h: mos_random_bytes() over SYS_RANDOM */
static int fill(void* buf, size_t n) {
    return mos_random_bytes(buf, n) == (long)n;   /* short count == failure */
}
#endif

int RAND_bytes(unsigned char* buf, int num) {
    if (num < 0 || (!buf && num > 0)) return 0;
    if (num == 0) return 1;
    return fill(buf, (size_t)num);
}