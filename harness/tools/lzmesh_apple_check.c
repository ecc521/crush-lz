// Encodes inputs with Apple's LZMESH and decodes them with crushlzmesh.
// Usage: [SLICES=n] [REPS=n] lzmesh_apple_check FILE...
// Checks whole files plus random slices; REPS also times both decoders.
#include "../../crates/lzmesh/csrc/crushlzmesh.h"
#include <compression.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int reps = 0;
static double apple_secs = 0;

static int check(const uint8_t *src, size_t n, const char *what, double *dec_secs, size_t *dec_bytes) {
    size_t cap = n + n / 2 + 4096;
    uint8_t *enc = malloc(cap), *out = malloc(n + 64);
    size_t en = compression_encode_buffer(enc, cap, src, n, NULL, COMPRESSION_LZMESH);
    if (!en && n) {
        printf("%s: apple encode failed\n", what);
        return 1;
    }
    size_t dn = 0;
    struct timespec a, b;
    int rc = crushlzmesh_decode_buffer(out, n + 64, enc, en, &dn);
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int r = 0; r < reps; r++) crushlzmesh_decode_buffer(out, n + 64, enc, en, &dn);
    clock_gettime(CLOCK_MONOTONIC, &b);
    if (reps) *dec_secs += ((b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) * 1e-9) / reps;
    *dec_bytes += n;
    if (reps) {
        clock_gettime(CLOCK_MONOTONIC, &a);
        for (int r = 0; r < reps; r++) compression_decode_buffer(out, n + 64, enc, en, NULL, COMPRESSION_LZMESH);
        clock_gettime(CLOCK_MONOTONIC, &b);
        apple_secs += ((b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) * 1e-9) / reps;
    }
    int bad = rc != 0 || dn != n || memcmp(out, src, n) != 0;
    if (bad) {
        size_t i = 0;
        while (i < dn && i < n && out[i] == src[i]) i++;
        printf("%s: rc=%d size %zu/%zu first diff %zu\n", what, rc, dn, n, i);
    }
    free(enc);
    free(out);
    return bad;
}

int main(int argc, char **argv) {
    int fails = 0, total = 0;
    double secs = 0;
    size_t bytes = 0;
    srand(1);
    int slices = getenv("SLICES") ? atoi(getenv("SLICES")) : 40;
    reps = getenv("REPS") ? atoi(getenv("REPS")) : 0;
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        size_t n = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *buf = malloc(n);
        if (fread(buf, 1, n, f) != n) n = 0;
        fclose(f);
        fails += check(buf, n, argv[i], &secs, &bytes);
        total++;
        for (int k = 0; k < slices && n > 2; k++) {
            size_t len = 1 + rand() % (k < 30 ? 3000 : 200000);
            if (len > n) len = n;
            size_t off = rand() % (n - len + 1);
            char what[64];
            snprintf(what, sizeof what, "slice %zu+%zu", off, len);
            fails += check(buf + off, len, what, &secs, &bytes);
            total++;
        }
        free(buf);
    }
    printf("%d/%d failed", fails, total);
    if (reps) printf("; decode %.1f MB/s (apple %.1f MB/s)", bytes / secs / 1e6, bytes / apple_secs / 1e6);
    printf("\n");
    return fails != 0;
}
