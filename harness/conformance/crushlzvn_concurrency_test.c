// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Concurrency test for CrushLZVN's dispatch layer, mirroring
// crushlzfse_concurrency_test.c: each thread rotates through every level
// with its own reused scratch buffer, so the scratch carving inside
// crushlzvn_encode_buffer_advanced is hit concurrently at every depth.
// Build with -fsanitize=thread for the authoritative check.
#include "crushlzvn.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK_SIZE 65536
#include "test_threads.h"

/* Set in main() before any thread starts; read-only thereafter. */
static int N_THREADS = 8;

typedef struct {
  const uint8_t *chunks;
  long n_chunks;
  int thread_id;
  long *failures;
} worker_arg;

static void *worker(void *argp) {
  worker_arg *arg = (worker_arg *)argp;
  size_t scratch_size = 0;
  for (int l = CRUSHLZVN_LEVEL_MIN; l <= CRUSHLZVN_LEVEL_MAX; l++) {
    crushlzvn_encode_params p;
    crushlzvn_params_for_level(l, &p);
    size_t n = crushlzvn_scratch_size(&p);
    if (n > scratch_size) scratch_size = n;
  }
  void *scratch = malloc(scratch_size);
  uint8_t *dst = malloc(CHUNK_SIZE * 2);
  uint8_t *back = malloc(CHUNK_SIZE);
  long local_failures = 0;

  for (long i = arg->thread_id; i < arg->n_chunks; i += N_THREADS) {
    const uint8_t *chunk = arg->chunks + (size_t)i * CHUNK_SIZE;
    const int n_levels = CRUSHLZVN_LEVEL_MAX - CRUSHLZVN_LEVEL_MIN + 1;
    int level = CRUSHLZVN_LEVEL_MIN + (int)((i + arg->thread_id) % n_levels);
    size_t out_size = crushlzvn_encode_buffer(dst, CHUNK_SIZE * 2, chunk, CHUNK_SIZE, scratch, scratch_size, level);
    if (out_size == 0 || out_size >= CHUNK_SIZE) {
      continue; // legitimate "didn't shrink" outcome
    }
    size_t back_len = 0;
    int rc = crushlzvn_decode_buffer(back, CHUNK_SIZE, dst, out_size, &back_len);
    if (rc != 0 || back_len != CHUNK_SIZE || memcmp(back, chunk, CHUNK_SIZE) != 0) {
      fprintf(stderr, "thread %d: CORRUPTION at chunk %ld level %d (out_size=%zu back_len=%zu)\n",
              arg->thread_id, i, level, out_size, back_len);
      local_failures++;
    }
  }
  free(scratch); free(dst); free(back);
  arg->failures[arg->thread_id] = local_failures;
  return NULL;
}

int main(int argc, char **argv) {
    N_THREADS = crushlz_test_threads();
  if (argc < 2) { fprintf(stderr, "usage: %s <manifest_file>\n", argv[0]); return 1; }
  FILE *manifest = fopen(argv[1], "rb");
  if (!manifest) { perror("fopen manifest"); return 1; }

  size_t cap = 32 * 1024 * 1024;
  uint8_t *all_chunks = malloc(cap);
  long n_chunks = 0;
  char path[4096];
  while (fgets(path, sizeof(path), manifest)) {
    size_t plen = strlen(path);
    while (plen > 0 && (path[plen-1] == '\n' || path[plen-1] == '\r')) path[--plen] = 0;
    if (plen == 0) continue;
    FILE *f = fopen(path, "rb");
    if (!f) continue;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < CHUNK_SIZE) { fclose(f); continue; }
    uint8_t *buf = malloc(fsize);
    size_t got = fread(buf, 1, fsize, f);
    fclose(f);
    for (long off = 0; off + CHUNK_SIZE <= (long)got; off += CHUNK_SIZE) {
      if ((size_t)(n_chunks + 1) * CHUNK_SIZE > cap) break;
      memcpy(all_chunks + (size_t)n_chunks * CHUNK_SIZE, buf + off, CHUNK_SIZE);
      n_chunks++;
    }
    free(buf);
    if ((size_t)(n_chunks + 1) * CHUNK_SIZE > cap) break;
  }
  fclose(manifest);

  if (n_chunks < N_THREADS * 4) {
    fprintf(stderr, "not enough real chunks found (%ld) for a meaningful concurrency test\n", n_chunks);
    return 1;
  }

  pthread_t threads[N_THREADS];
  worker_arg args[N_THREADS];
  long failures[N_THREADS];
    memset(failures, 0, sizeof failures);

  for (int t = 0; t < N_THREADS; t++) {
    args[t] = (worker_arg){.chunks = all_chunks, .n_chunks = n_chunks, .thread_id = t, .failures = failures};
    pthread_create(&threads[t], NULL, worker, &args[t]);
  }
  long total_failures = 0;
  for (int t = 0; t < N_THREADS; t++) {
    pthread_join(threads[t], NULL);
    total_failures += failures[t];
  }

  printf("n_chunks=%ld threads=%d failures=%ld\n", n_chunks, N_THREADS, total_failures);
  printf("%s\n", total_failures == 0 ? "CRUSHLZVN CONCURRENCY TEST PASSED" : "*** CONCURRENCY TEST FAILED ***");
  free(all_chunks);
  return total_failures == 0 ? 0 : 1;
}
