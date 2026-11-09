// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crushlzbitmap.h"
#include "test_threads.h"

static const char *fixture_dir(void);

static void fatal_with_loc(const char *fn, int line, int test)
{
    fprintf(stderr, "Fatal error in test %.3u (function %s(), line %d)\n", test, fn, line);
    exit(1);
}
#define FATAL(test)  fatal_with_loc(__func__, __LINE__, test)

#define ORIGINAL    0
#define COMPRESSED  1

static int tests_run, tests_failed;

static void report_results(void)
{
    puts("");

    /* Zero tests is a failure, not a pass: a binary that found no work to
     * do has verified nothing. */
    if(tests_run == 0) {
        fprintf(stderr, "zbm_test: NO FIXTURES FOUND in '%s': ran 0 tests.\n",
                fixture_dir());
        fprintf(stderr, "Set ZBM_FIXTURE_DIR to the directory holding the\n"
                        "NNN-original / NNN-compressed pairs.\n");
        puts("");
        exit(1);
    }

    if(tests_failed == 0)
        printf("Ran %d tests with no failures\n", tests_run);
    else
        printf("Ran %d tests with %d failures\n", tests_run, tests_failed);
    puts("");

    exit(tests_failed != 0);
}

/* Where the NNN-original / NNN-compressed pairs live. The Makefile exports
 * ZBM_FIXTURE_DIR as an absolute path; the default keeps a bare ./zbm_test
 * working from the conformance directory. */
static const char *fixture_dir(void)
{
    const char *d = getenv("ZBM_FIXTURE_DIR");
    return (d && *d) ? d : "zbm_fixtures";
}

static char *read_file(int i, int which, size_t *len)
{
    char name[PATH_MAX];
    FILE *file = NULL;
    char *buf = NULL;
    size_t length;

    if(i > 999)
        FATAL(i);
    snprintf(name, sizeof name, "%s/%.3u-%s", fixture_dir(), i,
             which == ORIGINAL ? "original" : "compressed");
    file = fopen(name, "r");
    if(!file) {
        if(errno == ENOENT) /* No more tests */
            report_results();
        FATAL(i);
    }

    if(fseek(file, 0, SEEK_END))
        FATAL(i);
    length = ftell(file);
    if(fseek(file, 0, SEEK_SET))
        FATAL(i);

    buf = malloc(length);
    if(!buf)
        FATAL(i);

    if(fread(buf, 1, length, file) != length)
        FATAL(i);
    if(fclose(file))
        FATAL(i);
    file = NULL;

    *len = length;
    return buf;
}

static void run_decompress_test(int i)
{
    char *original = NULL;
    char *compressed = NULL;
    char *decompressed = NULL;
    size_t orig_len, compr_len, decmp_len;
    int err;

    original = read_file(i, ORIGINAL, &orig_len);
    compressed = read_file(i, COMPRESSED, &compr_len);

    printf("%.3u(decm)... ", i);
    fflush(stdout);

    /* A destination one byte short must be refused, not truncated. */
    if(orig_len > 0) {
        decompressed = malloc(orig_len);
        if(!decompressed)
            FATAL(i);
        err = crushlzbitmap_decode_buffer(decompressed, orig_len - 1, compressed, compr_len, &decmp_len);
        if(err != CRUSHLZBITMAP_OUTPUT_TOO_SMALL) {
            printf("FAILURE - short destination returned %d\n", err);
            ++tests_failed;
        }
        free(decompressed);
    }
    decompressed = malloc(orig_len ? orig_len : 1);
    if(!decompressed)
        FATAL(i);
    err = crushlzbitmap_decode_buffer(decompressed, orig_len, compressed, compr_len, &decmp_len);
    if(err) {
        printf("FAILURE - error code: %d\n", err);
        ++tests_failed;
    } else if(decmp_len == orig_len && memcmp(decompressed, original, orig_len) == 0) {
        printf("SUCCESS - ratio: %.2f\n", (double)orig_len / compr_len);
    } else {
        printf("FAILURE - output doesn't match\n");
        ++tests_failed;
    }
    ++tests_run;

    free(compressed);
    free(original);
    free(decompressed);
}

/* Dumps our own compressor's output for inspection. Nothing reads it back;
 * the assertion is the round trip after the call site. Output goes to
 * ZBM_OUTPUT_DIR, never next to the committed fixtures. */
static void save_compression(const char *buf, size_t size, int i)
{
    char name[PATH_MAX];
    const char *dir = getenv("ZBM_OUTPUT_DIR");
    FILE *file = NULL;

    if(i > 999)
        FATAL(i);
    snprintf(name, sizeof name, "%s/%.3u-recompressed",
             (dir && *dir) ? dir : ".", i);
    file = fopen(name, "w");
    if(!file)
        FATAL(i);

    if(fwrite(buf, 1, size, file) != size)
        FATAL(i);
    if(fclose(file))
        FATAL(i);
    file = NULL;
}

struct arguments {
    char        dest[CRUSHLZBITMAP_MAX_CHUNK_SIZE];
    const void  *src;
    size_t      src_size;
    off_t       index;
    size_t      out_len;
    int         err;
};

/* One chunk per call, the way decmpfs stores them; each thread lets the
 * encoder allocate its own scratch. */
static void *compress_chunk(void *arguments)
{
    struct arguments *args = arguments;

    args->out_len = crushlzbitmap_encode_chunk(args->dest, CRUSHLZBITMAP_MAX_CHUNK_SIZE, args->src,
                                               args->src_size, (size_t)args->index, NULL, 0, NULL);
    args->err = args->out_len == 0 ? CRUSHLZBITMAP_INVALID : 0;
    return NULL;
}

/* Array bound for the thread pool below; crushlz_test_threads() picks the
 * actual count at runtime and is clamped to this. */
#define MAX_THREADS 128

static int n_threads;

static int compress(void *dest, size_t dest_size, const void *src, size_t src_size, size_t *out_len, int testnum)
{
    static struct arguments args[MAX_THREADS] = {0};
    pthread_t threads[MAX_THREADS];
    off_t i, j, k;
    int last_error = 0;

    *out_len = 0;

    for(i = 0; i < n_threads; ++i) {
        args[i].src = src;
        args[i].src_size = src_size;
        args[i].index = i;
        if(pthread_create(&threads[i], NULL, compress_chunk, &args[i]))
            FATAL(testnum);
    }

    j = 0;
    for(j = 1; ; ++j) {
        for(i = 0; i < n_threads; ++i) {
            if(pthread_join(threads[i], NULL))
                FATAL(testnum);
            if(args[i].err)
                last_error = args[i].err;
            if(args[i].out_len > dest_size)
                last_error = CRUSHLZBITMAP_OUTPUT_TOO_SMALL;
            if(last_error)
                goto done;

            memcpy(dest, args[i].dest, args[i].out_len);
            dest += args[i].out_len;
            dest_size -= args[i].out_len;
            *out_len += args[i].out_len;
            if(args[i].out_len == CRUSHLZBITMAP_LAST_CHUNK_SIZE)
                goto done;

            args[i].index = n_threads * j + i;
            if(args[i].index < j)
                FATAL(testnum);
            if(pthread_create(&threads[i], NULL, compress_chunk, &args[i]))
                FATAL(testnum);
        }
    }

done:
    for(k = 0; k < n_threads; ++k) {
        if(k == i) /* This one thread has been joined already */
            continue;
        if(pthread_join(threads[k], NULL))
            FATAL(testnum);
    }
    return last_error;
}

static void run_compress_test(int i)
{
    char *original = NULL;
    char *compressed = NULL;
    char *decompressed = NULL;
    size_t orig_len, compr_len, max_compr_len, decmp_len;
    int err;

    original = read_file(i, ORIGINAL, &orig_len);

    printf("%.3u(comp)... ", i);
    fflush(stdout);

    max_compr_len = crushlzbitmap_encode_bound(orig_len);
    compressed = malloc(max_compr_len);
    if(!compressed)
        FATAL(i);

    err = compress(compressed, max_compr_len, original, orig_len, &compr_len, i);
    if(err) {
        printf("FAILURE - compression error code: %d\n", err);
        ++tests_failed;
    } else {
        save_compression(compressed, compr_len, i);
        decompressed = malloc(orig_len);
        if(!decompressed)
            FATAL(i);
        err = crushlzbitmap_decode_buffer(decompressed, orig_len, compressed, compr_len, &decmp_len);
        if(err) {
            printf("FAILURE - decompression error code: %d\n", err);
            ++tests_failed;
        } else if(decmp_len == orig_len && memcmp(decompressed, original, orig_len) == 0) {
            printf("SUCCESS - ratio: %.2f\n", (double)orig_len / compr_len);
        } else {
            printf("FAILURE - decompression doesn't match original\n");
            ++tests_failed;
        }
    }
    ++tests_run;

    free(compressed);
    free(original);
    free(decompressed);
}

static void run_test(int i)
{
    run_decompress_test(i);
    run_compress_test(i);
}

int main(int argc, char *argv[])
{
    int i;

    n_threads = crushlz_test_threads();
    if(n_threads > MAX_THREADS)
        n_threads = MAX_THREADS;

    if(argc == 2) {
        run_test(atoi(argv[1]));
    } else {
        for(i = 1;; ++i)
            run_test(i);
    }
}
