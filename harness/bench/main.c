// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * The benchmark harness: walk a manifest, chunk each file, run the selected
 * encoders, verify every encode through the oracle (core/oracle.h) before
 * its size is counted, and print ratio and throughput tables.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "engines.h"
#include "oracle.h"

/* Upper bound on engines in one run. It bounds only the per-engine arrays
 * below, which cost a few tens of KB at this size; the per-block `sizes`
 * matrix strides on the actual count, so an unused slot costs nothing. */
#define MAX_SEL 256

typedef struct {
    const engine *e;
    int    level;
    char   label[64];
    /* Decoders timed as "ours" and "Apple's" for this format; NULL when the
     * format has none, in which case the column reads "-". */
    const engine *ours_decoder;
    const engine *apple_decoder;
    size_t in_bytes, out_bytes;
    double enc_ns, dec_ns_ours, dec_ns_apple;
    long   verified;   /* encoded, and every decoder agreed */
    long   stored;     /* did not compress, a real outcome, not an error */
    long   refused;    /* encoder returned 0: it could not or would not
                          encode this block, which is not the same as
                          encoding it badly */
    long   failures;   /* oracle disagreement: these bytes are excluded from
                          the ratio, because a size from output that does not
                          decode correctly is not a measurement */
} selected;

typedef struct {
    char  *path;
    size_t first_block;   /* index into the per-block size matrix */
    size_t nblocks;
} source_file;

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

/* Throughput with an M/K suffix and four significant figures. */
static const char *fmt_rate(double mbs, char *buf, size_t n) {
    /* Every rate here is decimal (bytes / 1e6), so the suffixes are decimal
     * too and readme_table.py's mbps() scales them the same way. Past 9999
     * the unit steps up rather than staying in M: %.4g switches to an
     * exponent there, and a rate written "1.131e+04M" came back out of the
     * README as n/a because the parser's number regex rejected it. */
    if (mbs >= 10000.0)  snprintf(buf, n, "%.4gG", mbs / 1000.0);
    else if (mbs >= 1.0) snprintf(buf, n, "%.4gM", mbs);
    else if (mbs > 0.0)  snprintf(buf, n, "%.4gK", mbs * 1000.0);
    else                 snprintf(buf, n, "-");
    return buf;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s <manifest> [options]\n"
        "\n"
        "  --engines LIST     comma-separated, each name[:level]\n"
        "                     (default: every available engine at its default level)\n"
        "  --block N          block size in bytes (default 65536, the decmpfs chunk)\n"
        "  --decode-reps N    decode repetitions per block (default 3)\n"
        "  --jobs N           worker threads, partitioned by file (default 1)\n"
        "  --sequential       one full pass per engine instead of interleaving\n"
        "                     them per block; slower to drift but the only mode\n"
        "                     whose absolute rates mean anything (see below)\n"
        "  --list             print the engine registry and exit\n"
        "\n"
        "The manifest is one file path per line. Engines that carry state\n"
        "across blocks (crushlzfse-chain) are reset at each file and only run\n"
        "when named in --engines.\n"
        "\n"
        "Interleaved (the default) has every engine re-encode the block the\n"
        "previous ones just pulled into cache, so each later position in --engines\n"
        "runs warmer: one engine listed eight times reads 947 MB/s first and 1364\n"
        "last. The order is shuffled per block so that lands on all of them\n"
        "equally, which keeps engines in a run comparable to each other but leaves\n"
        "every rate above what the engine does on its own. Use --sequential for a\n"
        "number you intend to publish.\n", argv0);
}

static void list_engines(void) {
    size_t n;
    const engine *all = engines_all(&n);
    printf("%-16s %-9s %-10s %-11s %-8s %s\n",
           "ENGINE", "FORMAT", "ENCODER", "LEVELS", "DECMPFS", "STATUS");
    for (size_t i = 0; i < n; i++) {
        const engine *e = &all[i];
        char levels[16];
        if (e->level_min == e->level_max) snprintf(levels, sizeof levels, "-");
        else snprintf(levels, sizeof levels, "%d..%d", e->level_min, e->level_max);
        char dec[8];
        if (e->decmpfs_type) snprintf(dec, sizeof dec, "%d/%d", e->decmpfs_type, e->decmpfs_type + 1);
        else snprintf(dec, sizeof dec, "-");
        printf("%-16s %-9s %-10s %-11s %-8s %s\n", e->name, format_name(e->format),
               origin_name(e->origin), levels, dec,
               e->available ? "ok" : "unavailable");
    }
    printf("\nDecoders per format (1 means the only implementation is ours,\n"
           "so agreement proves nothing about the format itself):\n");
    for (int f = 0; f < FMT_COUNT; f++)
        printf("  %-9s %zu\n", format_name((format_id)f), oracle_decoder_count((format_id)f));
}

static int select_default(selected *sel) {
    size_t n, k = 0;
    const engine *all = engines_all(&n);
    for (size_t i = 0; i < n && k < MAX_SEL; i++) {
        if (!all[i].available || !all[i].encode || all[i].reset) continue;
        sel[k].e = &all[i];
        sel[k].level = all[i].level_default;
        snprintf(sel[k].label, sizeof sel[k].label, "%s", all[i].name);
        k++;
    }
    return (int)k;
}

static int select_from_spec(char *spec, selected *sel) {
    int k = 0;
    for (char *tok = strtok(spec, ","); tok && k < MAX_SEL; tok = strtok(NULL, ",")) {
        char *colon = strchr(tok, ':');
        int level;
        if (colon) *colon = '\0';
        const engine *e = engine_by_name(tok);
        if (!e) { fprintf(stderr, "unknown engine: %s\n", tok); return -1; }
        if (!e->available) { fprintf(stderr, "engine unavailable: %s\n", tok); return -1; }
        level = colon ? atoi(colon + 1) : e->level_default;
        if (level < e->level_min || level > e->level_max) {
            fprintf(stderr, "%s: level %d out of range %d..%d\n",
                    e->name, level, e->level_min, e->level_max);
            return -1;
        }
        sel[k].e = e;
        sel[k].level = level;
        if (e->level_min == e->level_max)
            snprintf(sel[k].label, sizeof sel[k].label, "%s", e->name);
        else
            snprintf(sel[k].label, sizeof sel[k].label, "%s:%d", e->name, level);
        k++;
    }
    return k;
}

/* Per-worker accumulators for one engine, merged after all workers join. */
typedef struct {
    size_t in_bytes, out_bytes;
    double enc_ns, dec_ns_ours, dec_ns_apple;
    long   verified, stored, refused, failures;
} counters;

/* Work is partitioned by whole file, so a file's blocks land contiguously in
 * the merged `sizes`/`block_raw` arrays for the per-file best-of-N sum. */
typedef struct {
    int worker_id, jobs;
    size_t block, cap;
    int decode_reps, nsel;
    int sequential;             /* one pass per engine, rather than interleaved */
    const selected *sel;        /* shared engine config: e, level, label */
    source_file *files;         /* shared; each worker writes only its own */
    size_t nfiles;

    /* filled in by worker_run */
    counters totals[MAX_SEL];
    size_t  *sizes;              /* nblocks * nsel, this worker's rows only */
    size_t  *block_raw;          /* nblocks, this worker's rows only */
    size_t   nblocks;
    long     oracle_failures;
} worker_ctx;

/* One lazily created decode state per engine, for decoders that are not
 * also the producing engine. */
static void *state_for_engine(const engine *e, const engine *all, void **cache) {
    size_t idx = (size_t)(e - all);
    /* Decode-only: decoders take no scratch, so the level is immaterial. */
    if (!cache[idx] && e->state_new) cache[idx] = e->state_new(e->level_default);
    return cache[idx];
}

static void *worker_run(void *argp) {
    worker_ctx *ctx = argp;
    const int nsel = ctx->nsel;
    const selected *sel = ctx->sel;

    uint8_t *raw = malloc(ctx->block);
    uint8_t *comp = malloc(ctx->cap);
    uint8_t *dec = malloc(ctx->block);
    oracle *orc = oracle_new(ctx->block);

    void *states[MAX_SEL];
    memset(states, 0, sizeof states);
    for (int s = 0; s < nsel; s++)
        if (sel[s].e->state_new) states[s] = sel[s].e->state_new(sel[s].level);

    size_t n_all_engines;
    const engine *all_engines = engines_all(&n_all_engines);
    void **decoder_states = calloc(n_all_engines, sizeof(void *));

    /* Per-block engine order; see the shuffle in the block loop. Seeded per
     * worker so the workers do not march in lockstep. */
    int order[MAX_SEL];
    for (int s = 0; s < nsel; s++) order[s] = s;
    uint64_t rng = 0x9E3779B97F4A7C15ULL ^ (uint64_t)ctx->worker_id;

    size_t blocks_cap = 4096, nblocks = 0;
    size_t *sizes = malloc(blocks_cap * (size_t)nsel * sizeof *sizes);
    size_t *block_raw = malloc(blocks_cap * sizeof *block_raw);

    /* Sequential mode gives each engine the corpus to itself: nsel passes of
     * one engine, rather than one pass with every engine interleaved. A pass
     * streams far more than L2, so by the time the next engine reaches a block
     * the previous engine's copy of it is long gone, which is what makes the
     * rate comparable to running that engine alone, and to a compressor walking
     * a file that is resident in RAM but not in cache. Verified order-
     * independent: reversing the engine list moves every rate by under 3%,
     * against 45% interleaved. Costs the same as interleaving: the same
     * encodes in a different order, plus re-reading the corpus per pass,
     * which is page-cached and outside the timed region. */
    const int npasses  = ctx->sequential ? nsel : 1;
    const int per_pass = ctx->sequential ? 1 : nsel;

    for (int pass = 0; pass < npasses; pass++) {
    nblocks = 0;
    for (size_t fi = (size_t)ctx->worker_id; fi < ctx->nfiles; fi += (size_t)ctx->jobs) {
        FILE *f = fopen(ctx->files[fi].path, "rb");
        if (!f) continue;
        ctx->files[fi].first_block = nblocks;   /* worker-local for now; the
                                                    caller shifts this once it
                                                    knows every worker's size;
                                                    every pass recomputes the
                                                    same value */
        for (int s = 0; s < nsel; s++)
            if (sel[s].e->reset && states[s]) sel[s].e->reset(states[s]);

        for (;;) {
            size_t got = fread(raw, 1, ctx->block, f);
            if (got == 0) break;

            if (nblocks == blocks_cap) {
                blocks_cap *= 2;
                sizes = realloc(sizes, blocks_cap * (size_t)nsel * sizeof *sizes);
                block_raw = realloc(block_raw, blocks_cap * sizeof *block_raw);
            }
            block_raw[nblocks] = got;

            /* Shuffle the order every block. Every engine here re-encodes the
             * block the previous ones just pulled into cache, so each later
             * position runs warmer than the one before it: the same engine
             * listed eight times read 947, 1036, 1100, 1229, 1240, 1332, 1352,
             * 1364 MB/s down the list, ratios byte-identical. It is cache
             * residency, not the decode work in between. --decode-reps 1 and
             * 3 give the same curve, and it tracks --block against L1: at
             * 16K the spread is 74%, at 256K it is 17%.
             *
             * A fixed order therefore hands whoever is listed last a warm cache
             * for free. Shuffling spreads that evenly, which makes engines in
             * one run comparable to each other. It does NOT make them
             * comparable to a solo run: position 0 is the honest figure (947
             * here against 974 for the engine run by itself), and every
             * interleaved rate sits above it. For a published number, give each
             * engine its own run.
             *
             * A plain rotation is not enough: it equalises the first slot but
             * keeps every engine behind the same predecessor. */
            for (int i = ctx->sequential ? 0 : nsel - 1; i > 0; i--) {
                rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
                int j = (int)((rng >> 33) % (uint64_t)(i + 1));
                int t = order[i]; order[i] = order[j]; order[j] = t;
            }
            for (int si = 0; si < per_pass; si++) {
                const int s = ctx->sequential ? pass : order[si];
                const engine *e = sel[s].e;

                double t0 = now_ns();
                size_t out = e->encode(states[s], comp, ctx->cap, raw, got, sel[s].level);
                double t1 = now_ns();

                sizes[nblocks * (size_t)nsel + s] = 0;
                if (out == 0 || out >= got) {
                    ctx->totals[s].in_bytes += got;
                    ctx->totals[s].out_bytes += got;
                    if (out == 0) ctx->totals[s].refused++; else ctx->totals[s].stored++;
                    sizes[nblocks * (size_t)nsel + s] = got;
                    continue;
                }

                oracle_result orr;
                if (oracle_verify(orc, e, raw, got, comp, out, &orr) != 0) {
                    fprintf(stderr,
                            "ORACLE FAILURE  %s  %s  block %zu of %s\n"
                            "  %d/%d decoders agreed; first disagreement: %s (returned %zu, wanted %zu)\n",
                            sel[s].label, format_name(e->format), nblocks, ctx->files[fi].path,
                            orr.agreed, orr.checked,
                            orr.first_failure ? orr.first_failure : "?",
                            orr.first_failure_len, got);
                    ctx->totals[s].failures++;
                    ctx->oracle_failures++;
                    sizes[nblocks * (size_t)nsel + s] = got;   /* treat as stored */
                    continue;
                }

                /* Time every decoder this format has, reusing states[s] when
                 * the producer is its own decoder. */
                if (sel[s].ours_decoder) {
                    const engine *d = sel[s].ours_decoder;
                    void *dst = (d == e) ? states[s] : state_for_engine(d, all_engines, decoder_states);
                    double d0 = now_ns();
                    for (int r = 0; r < ctx->decode_reps; r++)
                        d->decode(dst, dec, ctx->block, comp, out);
                    double d1 = now_ns();
                    ctx->totals[s].dec_ns_ours += (d1 - d0) / ctx->decode_reps;
                }
                if (sel[s].apple_decoder) {
                    const engine *d = sel[s].apple_decoder;
                    void *dst = (d == e) ? states[s] : state_for_engine(d, all_engines, decoder_states);
                    double d0 = now_ns();
                    for (int r = 0; r < ctx->decode_reps; r++)
                        d->decode(dst, dec, ctx->block, comp, out);
                    double d1 = now_ns();
                    ctx->totals[s].dec_ns_apple += (d1 - d0) / ctx->decode_reps;
                }

                ctx->totals[s].in_bytes += got;
                ctx->totals[s].out_bytes += out;
                ctx->totals[s].enc_ns += t1 - t0;
                ctx->totals[s].verified++;
                sizes[nblocks * (size_t)nsel + s] = out;
            }
            nblocks++;
        }
        ctx->files[fi].nblocks = nblocks - ctx->files[fi].first_block;
        fclose(f);
    }
    }

    for (int s = 0; s < nsel; s++)
        if (sel[s].e->state_free && states[s]) sel[s].e->state_free(states[s]);
    for (size_t i = 0; i < n_all_engines; i++)
        if (decoder_states[i] && all_engines[i].state_free) all_engines[i].state_free(decoder_states[i]);
    free(decoder_states);
    oracle_free(orc);
    free(raw);
    free(comp);
    free(dec);

    ctx->sizes = sizes;
    ctx->block_raw = block_raw;
    ctx->nblocks = nblocks;
    return NULL;
}

int main(int argc, char **argv) {
    size_t block = 65536;
    int decode_reps = 3;
    int jobs = 1;
    int sequential = 0;
    char *engine_spec = NULL;
    const char *manifest_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--list") == 0) { list_engines(); return 0; }
        else if (strcmp(argv[i], "--engines") == 0 && i + 1 < argc) engine_spec = argv[++i];
        else if (strcmp(argv[i], "--block") == 0 && i + 1 < argc) block = (size_t)atol(argv[++i]);
        else if (strcmp(argv[i], "--decode-reps") == 0 && i + 1 < argc) decode_reps = atoi(argv[++i]);
        else if (strcmp(argv[i], "--jobs") == 0 && i + 1 < argc) jobs = atoi(argv[++i]);
        else if (strcmp(argv[i], "--sequential") == 0) sequential = 1;
        else if (argv[i][0] != '-' && !manifest_path) manifest_path = argv[i];
        else { usage(argv[0]); return 1; }
    }
    if (!manifest_path) { usage(argv[0]); return 1; }
    if (block < 1024) { fprintf(stderr, "--block must be >= 1024\n"); return 1; }
    if (jobs < 1) { fprintf(stderr, "--jobs must be >= 1\n"); return 1; }
    if (decode_reps < 1) { fprintf(stderr, "--decode-reps must be >= 1\n"); return 1; }

    selected sel[MAX_SEL];
    memset(sel, 0, sizeof sel);
    int nsel = engine_spec ? select_from_spec(engine_spec, sel) : select_default(sel);
    if (nsel <= 0) return 1;

    /* Resolve which decoder is "ours" and which is "Apple's" per format. */
    for (int s = 0; s < nsel; s++) {
        const engine *decoders[8];
        size_t nd = engines_decoders_for_format(sel[s].e->format, decoders, 8);
        sel[s].ours_decoder = NULL;
        sel[s].apple_decoder = NULL;
        for (size_t i = 0; i < nd; i++) {
            if (decoders[i]->origin == ORIGIN_OURS) sel[s].ours_decoder = decoders[i];
            else if (decoders[i]->origin == ORIGIN_APPLE) sel[s].apple_decoder = decoders[i];
        }
    }

    /* ---- read the manifest ---- */
    FILE *mf = fopen(manifest_path, "rb");
    if (!mf) { perror(manifest_path); return 1; }
    size_t files_cap = 1024, nfiles = 0;
    source_file *files = malloc(files_cap * sizeof *files);
    char line[4096];
    while (fgets(line, sizeof line, mf)) {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        if (!len) continue;
        if (nfiles == files_cap) {
            files_cap *= 2;
            files = realloc(files, files_cap * sizeof *files);
        }
        files[nfiles].path = strdup(line);
        files[nfiles].first_block = 0;
        files[nfiles].nblocks = 0;
        nfiles++;
    }
    fclose(mf);
    if (!nfiles) { fprintf(stderr, "empty manifest\n"); return 1; }

    if (jobs > (int)nfiles) jobs = (int)nfiles;

    size_t cap = block * 2 + 4096;    /* room for incompressible output */

    /* ---- run the workers, partitioned by file (fi % jobs) ---- */
    worker_ctx *ctxs = calloc((size_t)jobs, sizeof *ctxs);
    pthread_t *tids = calloc((size_t)jobs, sizeof *tids);
    if (!ctxs || !tids) { fprintf(stderr, "out of memory\n"); return 1; }

    for (int w = 0; w < jobs; w++) {
        ctxs[w] = (worker_ctx){
            .worker_id = w, .jobs = jobs, .block = block, .cap = cap,
            .decode_reps = decode_reps, .nsel = nsel, .sequential = sequential,
            .sel = sel,
            .files = files, .nfiles = nfiles,
        };
        if (pthread_create(&tids[w], NULL, worker_run, &ctxs[w]) != 0) {
            fprintf(stderr, "pthread_create failed for worker %d\n", w);
            return 1;
        }
    }
    for (int w = 0; w < jobs; w++)
        pthread_join(tids[w], NULL);

    /* ---- merge ----
     *
     * Per-block compressed size for every engine, for best-of-N and
     * leave-one-out below; 0 means no usable result and falls back to
     * stored. `worker_offset` is where worker w's rows land. */
    size_t *worker_offset = malloc((size_t)jobs * sizeof *worker_offset);
    size_t nblocks = 0;
    for (int w = 0; w < jobs; w++) {
        worker_offset[w] = nblocks;
        nblocks += ctxs[w].nblocks;
    }
    if (!nblocks) { fprintf(stderr, "no data read from manifest\n"); return 1; }

    size_t *sizes = malloc(nblocks * (size_t)nsel * sizeof *sizes);
    size_t *block_raw = malloc(nblocks * sizeof *block_raw);
    long oracle_failures = 0;

    for (int w = 0; w < jobs; w++) {
        memcpy(sizes + worker_offset[w] * (size_t)nsel, ctxs[w].sizes,
               ctxs[w].nblocks * (size_t)nsel * sizeof *sizes);
        memcpy(block_raw + worker_offset[w], ctxs[w].block_raw,
               ctxs[w].nblocks * sizeof *block_raw);
        free(ctxs[w].sizes);
        free(ctxs[w].block_raw);

        oracle_failures += ctxs[w].oracle_failures;
        for (int s = 0; s < nsel; s++) {
            sel[s].in_bytes  += ctxs[w].totals[s].in_bytes;
            sel[s].out_bytes += ctxs[w].totals[s].out_bytes;
            sel[s].enc_ns    += ctxs[w].totals[s].enc_ns;
            sel[s].dec_ns_ours   += ctxs[w].totals[s].dec_ns_ours;
            sel[s].dec_ns_apple  += ctxs[w].totals[s].dec_ns_apple;
            sel[s].verified  += ctxs[w].totals[s].verified;
            sel[s].stored    += ctxs[w].totals[s].stored;
            sel[s].refused   += ctxs[w].totals[s].refused;
            sel[s].failures  += ctxs[w].totals[s].failures;
        }
    }

    /* Shift first_block from worker-local to merged numbering. */
    for (size_t fi = 0; fi < nfiles; fi++) {
        if (!files[fi].nblocks) continue;
        files[fi].first_block += worker_offset[(int)(fi % (size_t)jobs)];
    }

    free(ctxs);
    free(tids);
    free(worker_offset);

    /* ---- results ---- */
    printf("blocks: %zu   block size: %zu   files: %zu\n\n", nblocks, block, nfiles);
    printf("%-18s %-10s %8s %8s %10s %12s %12s %8s %7s\n",
           "ENGINE", "ENCODER", "RATIO", "SAVED%", "ENC B/s", "DEC B/s(ours)", "DEC B/s(apple)",
           "REFUSED", "FAILED");
    for (int s = 0; s < nsel; s++) {
        double ratio = sel[s].in_bytes ? (double)sel[s].in_bytes / (double)sel[s].out_bytes : 0;
        double saved = sel[s].in_bytes
            ? 100.0 * (1.0 - (double)sel[s].out_bytes / (double)sel[s].in_bytes) : 0;
        double enc = sel[s].enc_ns > 0 ? (double)sel[s].in_bytes * 1e9 / sel[s].enc_ns / 1e6 : 0;
        double dec_ours  = sel[s].dec_ns_ours  > 0 ? (double)sel[s].in_bytes * 1e9 / sel[s].dec_ns_ours  / 1e6 : 0;
        double dec_apple = sel[s].dec_ns_apple > 0 ? (double)sel[s].in_bytes * 1e9 / sel[s].dec_ns_apple / 1e6 : 0;
        char ebuf[24], dobuf[24], dabuf[24];
        printf("%-18s %-10s %8.4f %7.2f%% %10s %12s %12s %8ld %7ld%s\n",
               sel[s].label, origin_name(sel[s].e->origin), ratio, saved,
               fmt_rate(enc, ebuf, sizeof ebuf),
               fmt_rate(dec_ours, dobuf, sizeof dobuf), fmt_rate(dec_apple, dabuf, sizeof dabuf),
               sel[s].refused, sel[s].failures,
               sel[s].failures      ? "  <-- NOT TRUSTWORTHY"
               : sel[s].refused     ? "  <-- declined, not measured"
                                    : "");
    }

    /* Best-of-N pool: only engines decmpfs can decode, and only those with
     * no oracle failures, since their sizes are not deliverable. */
    int pool[MAX_SEL], npool = 0;
    for (int s = 0; s < nsel; s++)
        if (sel[s].e->decmpfs_type != 0 && sel[s].failures == 0)
            pool[npool++] = s;

    if (npool == 0) {
        fprintf(stderr, "\nno engine is both shippable and verified; "
                        "skipping best-of-N\n");
        return oracle_failures ? 2 : 0;
    }

    /* Per-block best-of-N is a ceiling; decmpfs stores one compression type
     * per file, so the per-file number is what is achievable. */
    size_t total_raw = 0, best_block = 0;
    for (size_t b = 0; b < nblocks; b++) {
        total_raw += block_raw[b];
        size_t best = block_raw[b];
        for (int i = 0; i < npool; i++) {
            size_t v = sizes[b * (size_t)nsel + pool[i]];
            if (v && v < best) best = v;
        }
        best_block += best;
    }

    size_t best_file = 0, files_counted = 0;
    for (size_t fi = 0; fi < nfiles; fi++) {
        if (!files[fi].nblocks) continue;
        size_t best = (size_t)-1;
        for (int i = 0; i < npool; i++) {
            size_t t = 0;
            for (size_t b = 0; b < files[fi].nblocks; b++) {
                size_t v = sizes[(files[fi].first_block + b) * (size_t)nsel + pool[i]];
                t += v ? v : block_raw[files[fi].first_block + b];
            }
            if (t < best) best = t;
        }
        best_file += best;
        files_counted++;
    }

    printf("\n%-18s %10s %10s   (pool: %d shippable, verified engine%s)\n",
           "BEST-OF-N", "RATIO", "SAVED%", npool, npool == 1 ? "" : "s");
    printf("%-18s %10.4f %9.2f%%\n", "per block",
           (double)total_raw / (double)best_block,
           100.0 * (1.0 - (double)best_block / (double)total_raw));
    if (files_counted)
        printf("%-18s %10.4f %9.2f%%   <- what decmpfs can reach (one type per file)\n",
               "per file", (double)total_raw / (double)best_file,
               100.0 * (1.0 - (double)best_file / (double)total_raw));

    /* Leave-one-out marginal value: bytes lost by dropping each engine.
     * Ties are credited to nobody, so the win column sums to at most 100%. */
    printf("\n%-18s %14s %10s %9s %8s\n",
           "MARGINAL VALUE", "BYTES LOST", "OF BEST", "WINS", "OF BLOCKS");
    for (int i = 0; i < npool; i++) {
        int s = pool[i];
        size_t without = 0;
        for (size_t b = 0; b < nblocks; b++) {
            size_t best = block_raw[b];
            for (int j = 0; j < npool; j++) {
                if (j == i) continue;
                size_t v = sizes[b * (size_t)nsel + pool[j]];
                if (v && v < best) best = v;
            }
            without += best;
        }
        long wins = 0;
        for (size_t b = 0; b < nblocks; b++) {
            size_t mine = sizes[b * (size_t)nsel + s];
            if (!mine) continue;
            int strictly_best = 1;
            for (int j = 0; j < npool; j++) {
                if (pool[j] == s) continue;
                size_t other = sizes[b * (size_t)nsel + pool[j]];
                if (other && other <= mine) { strictly_best = 0; break; }
            }
            if (strictly_best && mine < block_raw[b]) wins++;
        }
        printf("%-18s %14zu %9.3f%% %9ld %7.1f%%\n", sel[s].label,
               without - best_block,
               100.0 * (double)(without - best_block) / (double)best_block,
               wins, 100.0 * (double)wins / (double)nblocks);
    }
    for (int s = 0; s < nsel; s++) {
        int in_pool = 0;
        for (int i = 0; i < npool; i++) if (pool[i] == s) in_pool = 1;
        if (!in_pool)
            printf("%-18s %14s            (%s)\n", sel[s].label, "-",
                   sel[s].e->decmpfs_type == 0 ? "no decmpfs type; not selectable"
                                               : "oracle failures; excluded");
    }

    if (oracle_failures)
        fprintf(stderr, "\n%ld oracle failures; results above are not trustworthy\n",
                oracle_failures);

    return oracle_failures ? 2 : 0;
}
