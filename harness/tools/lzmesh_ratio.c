// Encodes files with crushlzmesh at a level, checks both decoders, and
// compares the size with Apple's encoder.
// Usage: LEVEL=n [REPS=r] lzmesh_ratio FILE...
// Times are thread CPU time, the minimum over REPS runs per file.
#include "../../crates/lzmesh/csrc/crushlzmesh.h"
#ifndef NO_APPLE
#include <compression.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

int main(int argc, char **argv) {
    int level = getenv("LEVEL") ? atoi(getenv("LEVEL")) : 10;
    crushlzmesh_params prm;
    crushlzmesh_params_for_level(level, &prm);
    // Optional overrides for tuning.
    if (getenv("DEPTH")) prm.search_depth = atoi(getenv("DEPTH"));
    if (getenv("MAXD")) prm.max_depth = atoi(getenv("MAXD"));
    if (getenv("NICE")) prm.lookahead = atoi(getenv("NICE"));
    if (getenv("ITERS")) prm.iterations = atoi(getenv("ITERS"));
    if (getenv("HBITS")) prm.hash_bits = atoi(getenv("HBITS"));
    int reps = getenv("REPS") ? atoi(getenv("REPS")) : 1;
    if (reps < 1) reps = 1;
    size_t tin = 0, tours = 0, tapple = 0;
    double tenc = 0, tapp = 0, tdo = 0, tda = 0;
    int fails = 0;
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        size_t n = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *src = malloc(n + 1);
        if (fread(src, 1, n, f) != n) n = 0;
        fclose(f);
        size_t cap = crushlzmesh_encode_bound(n);
        uint8_t *enc = malloc(cap), *aenc = malloc(n + n / 2 + 4096), *out = malloc(n + 64);
        size_t en = 0, an = 0;
        double best = 1e9, abest = 1e9;
        for (int r = 0; r < reps; r++) {
            double t0 = now();
            en = crushlzmesh_encode_buffer(enc, cap, src, n, NULL, &prm);
            double t1 = now();
#ifndef NO_APPLE
            an = compression_encode_buffer(aenc, n + n / 2 + 4096, src, n, NULL, COMPRESSION_LZMESH);
#else
            an = n;
#endif
            double t2 = now();
            if (t1 - t0 < best) best = t1 - t0;
            if (t2 - t1 < abest) abest = t2 - t1;
        }
        tenc += best;
        tapp += abest;
#ifndef NO_APPLE
        size_t dn = compression_decode_buffer(out, n + 64, enc, en, NULL, COMPRESSION_LZMESH);
#else
        size_t dn = n;
        memcpy(out, src, n);
#endif
        int bad = !en || dn != n || memcmp(out, src, n);
        size_t on = 0;
        int rc = crushlzmesh_decode_buffer(out, n + 64, enc, en, &on);
        bad |= rc != 0 || on != n || memcmp(out, src, n);
        if (bad) {
            printf("FAIL %s en=%zu apple_dec=%zu ours rc=%d %zu\n", argv[i], en, dn, rc, on);
            fails++;
        }
        if (getenv("DUMP")) {
            char fn[4096];
            const char *b = strrchr(argv[i], '/');
            snprintf(fn, sizeof fn, "%s/%s.mesh", getenv("DUMP"), b ? b + 1 : argv[i]);
            FILE *g = fopen(fn, "wb");
            if (g) {
                fwrite(enc, 1, en, g);
                fclose(g);
            }
        }
        if (getenv("VERBOSE")) printf("%-60.60s %8zu %8zu %+.2f%%\n", argv[i], en, an, 100.0 * ((double)en / an - 1));
#ifndef NO_APPLE
        if (getenv("DEC") && !bad) {
            // Apple's decoder on our stream vs on Apple's own stream.
            double b1 = 1e9, b2 = 1e9;
            for (int r = 0; r < reps; r++) {
                double t0 = now();
                compression_decode_buffer(out, n + 64, enc, en, NULL, COMPRESSION_LZMESH);
                double t1 = now();
                compression_decode_buffer(out, n + 64, aenc, an, NULL, COMPRESSION_LZMESH);
                double t2 = now();
                if (t1 - t0 < b1) b1 = t1 - t0;
                if (t2 - t1 < b2) b2 = t2 - t1;
            }
            tdo += b1;
            tda += b2;
        }
#endif
        tin += n;
        tours += en;
        tapple += an;
        free(src);
        free(enc);
        free(aenc);
        free(out);
    }
    printf("level %d: ours %zu (%.2f%%) apple %zu (%.2f%%) delta %+.2f%%  enc %.2f MB/s apple %.1f MB/s (%.3fx)  fails %d\n",
           level, tours, 100.0 * tours / tin, tapple, 100.0 * tapple / tin, 100.0 * ((double)tours / tapple - 1),
           tin / tenc / 1e6, tin / tapp / 1e6, tapp / tenc, fails);
    if (tdo > 0)
        printf("apple decode: our stream %.0f MB/s, apple stream %.0f MB/s (%.3fx)\n", tin / tdo / 1e6, tin / tda / 1e6,
               tda / tdo);
    return fails != 0;
}
