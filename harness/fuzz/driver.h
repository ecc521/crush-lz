// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
#ifndef CRUSHLZ_FUZZ_DRIVER_H
#define CRUSHLZ_FUZZ_DRIVER_H

/*
 * The entry points every fuzz target shares. A target defines
 *
 *     static void run_one(const uint8_t *data, size_t size);
 *
 * and #includes this last. Under FUZZ_LIBFUZZER it gets LLVMFuzzerTestOneInput;
 * otherwise a standalone main() that replays files named as arguments, or
 * runs a PRNG campaign deterministic in `./target <iters> <seed>`.
 *
 * Define FUZZ_MAX_INPUT before including to enlarge the replay buffer.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef FUZZ_MAX_INPUT
#define FUZZ_MAX_INPUT (1 << 20)
#endif

#ifdef FUZZ_LIBFUZZER

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    run_one(data, size);
    return 0;
}

#else

int main(int argc, char **argv) {
    /* Replay mode when the first argument names a readable file. */
    if (argc > 1 && argv[1][0] != '-') {
        FILE *probe = fopen(argv[1], "rb");
        if (probe) {
            fclose(probe);
            for (int a = 1; a < argc; a++) {
                FILE *f = fopen(argv[a], "rb");
                if (!f) continue;
                static uint8_t buf[FUZZ_MAX_INPUT];
                size_t got = fread(buf, 1, sizeof(buf), f);
                fclose(f);
                printf("replaying %s (%zu bytes)\n", argv[a], got);
                run_one(buf, got);
            }
            printf("replay complete, no failures\n");
            return 0;
        }
    }

    unsigned long iters = (argc > 1) ? strtoul(argv[1], NULL, 10) : 200000;
    uint32_t seed = (argc > 2) ? (uint32_t)strtoul(argv[2], NULL, 10) : 1u;
    if (seed == 0) seed = 1;

    printf("standalone campaign: %lu iterations, seed %u\n", iters, seed);
    uint32_t x = seed;
    static uint8_t prog[512];
    for (unsigned long it = 0; it < iters; it++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        size_t plen = 8 + (x % (sizeof(prog) - 8));
        for (size_t k = 0; k < plen; k++) {
            x ^= x << 13; x ^= x >> 17; x ^= x << 5;
            prog[k] = (uint8_t)(x >> 16);
        }
        run_one(prog, plen);

        if ((it & 0x3FFF) == 0x3FFF) {
            printf("  %lu/%lu\n", it + 1, iters);
            fflush(stdout);
        }
    }
    printf("campaign complete, no failures\n");
    return 0;
}

#endif /* FUZZ_LIBFUZZER */
#endif /* CRUSHLZ_FUZZ_DRIVER_H */
