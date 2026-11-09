// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Concurrency test: real pthreads, each with its own scratch, independently
 * compressing a disjoint, round-robin-interleaved set of real-file chunks
 * through crushlzbitmap_encode_chunk() and round-trip checking every result.
 * Run at the default level and the fast level, which share almost no
 * encoder code. Build with -fsanitize=thread for the authoritative check.
 */
#include "crushlzbitmap.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK_SIZE 32768
#include "test_threads.h"

/* Set in main() before any thread starts; read-only thereafter. */
static int N_THREADS = 8;

typedef struct {
    const uint8_t *chunks;
    long n_chunks;
    int thread_id;
    const crushlzbitmap_params *params;
    long *failures;
} worker_arg;

static size_t zbm_ladder_max_scratch(void)
{
    size_t max = 0;
    for(int lv = CRUSHLZBITMAP_LEVEL_MIN; lv <= CRUSHLZBITMAP_LEVEL_MAX; ++lv) {
        crushlzbitmap_params p;
        size_t n;
        crushlzbitmap_params_for_level(lv, &p);
        n = crushlzbitmap_scratch_size(&p);
        if(n > max) max = n;
    }
    return max;
}

static void *worker(void *argp)
{
    worker_arg *arg = (worker_arg *)argp;
    /* Chunk 0 carries the data; chunk 1, past the end of the input, is the
     * terminator. Together they are a complete stream. */
    uint8_t *dst = malloc(CRUSHLZBITMAP_MAX_CHUNK_SIZE * 2);
    uint8_t *back = malloc(CHUNK_SIZE);
    size_t scratch_bytes = zbm_ladder_max_scratch();
    void *scratch = calloc(1, scratch_bytes);
    long local_failures = 0;
    long i;

    for(i = arg->thread_id; i < arg->n_chunks; i += N_THREADS) {
        const uint8_t *chunk = arg->chunks + (size_t)i * CHUNK_SIZE;
        size_t chunk_out, term_out = 0, decmp_len = 0;
        int err;

        chunk_out = crushlzbitmap_encode_chunk(dst, CRUSHLZBITMAP_MAX_CHUNK_SIZE, chunk, CHUNK_SIZE, 0,
                                               scratch, scratch_bytes, arg->params);
        if(chunk_out)
            term_out = crushlzbitmap_encode_chunk(dst + chunk_out, CRUSHLZBITMAP_MAX_CHUNK_SIZE, chunk,
                                                  CHUNK_SIZE, 1, scratch, scratch_bytes, arg->params);
        if(!chunk_out || !term_out) {
            fprintf(stderr, "thread %d: COMPRESS FAILED at chunk %ld\n", arg->thread_id, i);
            local_failures++;
            continue;
        }
        err = crushlzbitmap_decode_buffer(back, CHUNK_SIZE, dst, chunk_out + term_out, &decmp_len);
        if(err || decmp_len != CHUNK_SIZE || memcmp(back, chunk, CHUNK_SIZE) != 0) {
            fprintf(stderr, "thread %d: CORRUPTION at chunk %ld (chunk_out=%zu term_out=%zu decmp_len=%zu)\n",
                    arg->thread_id, i, chunk_out, term_out, decmp_len);
            local_failures++;
        }
    }
    free(dst);
    free(back);
    free(scratch);
    arg->failures[arg->thread_id] = local_failures;
    return NULL;
}

static long run_level(const char *label, int level, const uint8_t *all_chunks, long n_chunks)
{
    crushlzbitmap_params params;
    pthread_t threads[N_THREADS];
    worker_arg args[N_THREADS];
    long failures[N_THREADS];
    memset(failures, 0, sizeof failures);
    long total_failures = 0;
    int t;

    crushlzbitmap_params_for_level(level, &params);
    for(t = 0; t < N_THREADS; t++) {
        args[t] = (worker_arg){.chunks = all_chunks, .n_chunks = n_chunks, .thread_id = t,
                                .params = &params, .failures = failures};
        pthread_create(&threads[t], NULL, worker, &args[t]);
    }
    for(t = 0; t < N_THREADS; t++) {
        pthread_join(threads[t], NULL);
        total_failures += failures[t];
    }
    printf("%-6s n_chunks=%ld threads=%d failures=%ld\n", label, n_chunks, N_THREADS, total_failures);
    return total_failures;
}

int main(int argc, char **argv)
{
    N_THREADS = crushlz_test_threads();
    if(argc < 2) {
        fprintf(stderr, "usage: %s <manifest_file>\n", argv[0]);
        return 1;
    }
    FILE *manifest = fopen(argv[1], "rb");
    if(!manifest) { perror("fopen manifest"); return 1; }

    size_t cap = 32 * 1024 * 1024;
    uint8_t *all_chunks = malloc(cap);
    long n_chunks = 0;
    char path[4096];

    while(fgets(path, sizeof(path), manifest)) {
        size_t plen = strlen(path);
        while(plen > 0 && (path[plen - 1] == '\n' || path[plen - 1] == '\r')) path[--plen] = 0;
        if(plen == 0) continue;
        FILE *f = fopen(path, "rb");
        if(!f) continue;
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        if(fsize < CHUNK_SIZE) { fclose(f); continue; }
        uint8_t *buf = malloc(fsize);
        size_t got = fread(buf, 1, fsize, f);
        fclose(f);
        for(long off = 0; off + CHUNK_SIZE <= (long)got; off += CHUNK_SIZE) {
            if((size_t)(n_chunks + 1) * CHUNK_SIZE > cap) break;
            memcpy(all_chunks + (size_t)n_chunks * CHUNK_SIZE, buf + off, CHUNK_SIZE);
            n_chunks++;
        }
        free(buf);
        if((size_t)(n_chunks + 1) * CHUNK_SIZE > cap) break;
    }
    fclose(manifest);

    if(n_chunks < N_THREADS * 4) {
        fprintf(stderr, "not enough real chunks found (%ld) for a meaningful concurrency test\n", n_chunks);
        return 1;
    }

    long total = 0;
    total += run_level("deep", CRUSHLZBITMAP_LEVEL_DEFAULT, all_chunks, n_chunks);
    total += run_level("fast", CRUSHLZBITMAP_LEVEL_MIN, all_chunks, n_chunks);

    printf("%s\n", total == 0 ? "CONCURRENCY TEST PASSED" : "*** CONCURRENCY TEST FAILED ***");
    free(all_chunks);
    return total == 0 ? 0 : 1;
}
