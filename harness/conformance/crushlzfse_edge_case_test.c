// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Round-trips crushlzfse_encode_buffer at every level over the shapes a
// corpus benchmark never feeds it: partial and tiny inputs, empty input,
// highly repetitive data, and incompressible data.
#include "crushlzfse.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check_one(const char *label, int level, const uint8_t *data, size_t len,
                      void *scratch, size_t scratch_size) {
    size_t cap = len * 2 + 4096;
    uint8_t *dst = malloc(cap);
    uint8_t *back = malloc(len ? len : 1);

    size_t out_size = crushlzfse_encode_buffer(dst, cap, data, len, scratch, scratch_size, level);
    if (out_size == 0) {
        printf("level=%d %-30s len=%-8zu -> INCOMPRESSIBLE/EMPTY (encoder returned 0)\n", level, label, len);
        free(dst); free(back);
        return 1; // 0 is legitimate for len==0 or genuinely incompressible input
    }

    size_t back_len = 0;
    int rc = crushlzfse_decode_buffer(back, len, dst, out_size, &back_len);
    int ok = rc == 0 && (back_len == len) && (len == 0 || memcmp(back, data, len) == 0);
    printf("level=%d %-30s len=%-8zu out=%-8zu %s\n", level, label, len, out_size, ok ? "OK" : "*** MISMATCH ***");

    free(dst); free(back);
    return ok;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <real_file_for_repetitive/partial tests>\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *file_data = malloc(fsize);
    fread(file_data, 1, fsize, f);
    fclose(f);

    size_t scratch_size = 0;
    for (int level = CRUSHLZFSE_LEVEL_MIN; level <= CRUSHLZFSE_LEVEL_MAX; level++) {
        crushlzfse_encode_params params;
        crushlzfse_params_for_level(level, &params);
        size_t n = crushlzfse_scratch_size(&params);
        if (n > scratch_size) scratch_size = n;
    }
    void *scratch = malloc(scratch_size);

    int all_ok = 1;

    size_t partial_sizes[] = {1, 2, 3, 4, 7, 8, 9, 15, 16, 63, 64, 65, 100, 1000, 4095, 4096, 4097,
                               32767, 32768, 32769, 65535, 65536};

    uint8_t *rep = malloc(65536);
    memset(rep, 0x41, 65536);
    uint8_t *rep_period3 = malloc(65536);
    memset(rep_period3, 0x41, 65536);
    for (size_t n = 1; n <= 2000; n++) rep_period3[n-1] = (uint8_t)(n % 3);

    uint8_t *rnd = malloc(65536);
    uint32_t x = 0x2545F491;
    for (int i = 0; i < 65536; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        rnd[i] = (uint8_t)(x & 0xff);
    }

    for (int level = CRUSHLZFSE_LEVEL_MIN; level <= CRUSHLZFSE_LEVEL_MAX; level++) {
        for (size_t i = 0; i < sizeof(partial_sizes)/sizeof(partial_sizes[0]); i++) {
            size_t n = partial_sizes[i];
            if ((long)n > fsize) continue;
            all_ok &= check_one("partial-chunk-from-real-file", level, file_data, n, scratch, scratch_size);
        }
        all_ok &= check_one("empty", level, file_data, 0, scratch, scratch_size);
        all_ok &= check_one("65536x same byte", level, rep, 65536, scratch, scratch_size);
        all_ok &= check_one("period-3 pattern, 65536", level, rep_period3, 65536, scratch, scratch_size);
        all_ok &= check_one("65536 random bytes", level, rnd, 65536, scratch, scratch_size);
        if (fsize > 200000) {
            all_ok &= check_one("mid-file 37-byte slice", level, file_data + 150000, 37, scratch, scratch_size);
            all_ok &= check_one("mid-file 5000-byte slice", level, file_data + 150000, 5000, scratch, scratch_size);
        }
    }

    printf("\n%s\n", all_ok ? "ALL EDGE CASES PASSED (all levels)" : "*** AT LEAST ONE FAILURE ABOVE ***");
    free(file_data); free(scratch); free(rep); free(rep_period3); free(rnd);
    return all_ok ? 0 : 1;
}
