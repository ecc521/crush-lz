/*
 * Hardware validation of the intrinsic models in harness/proofs/simd: each
 * modelled intrinsic against the real one, the scalar builtins against
 * table references, and the decoder's whole SIMD wrappers three ways (real
 * intrinsics, models, portable branch; see zbm_wrap.c). Loads and stores
 * run flush against PROT_NONE guard pages, so a wider real access faults.
 *
 *   harness/simd_validate/run.sh               fast
 *   SIMD_VALIDATE_EXHAUSTIVE=1 harness/simd_validate/run.sh
 */
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__aarch64__)
#include <arm_neon.h>
#include "neon_model.h"
#define HAVE_VEC 1
#elif defined(__x86_64__) && defined(__SSE4_1__)
#include <immintrin.h>
#include "sse_model.h"
#define HAVE_VEC 1
#elif defined(__x86_64__)
#define HAVE_VEC 0  /* baseline x86-64: crush_simd.h is portable, no SSSE3 */
#else
#error "arm64 or x86-64 only"
#endif

#define WRAP_DECL(p)                                                           \
    const char *p##branch(void);                                               \
    void p##blend8_row(uint8_t *, const uint8_t *, const uint8_t *,           \
                       const uint8_t *);                                      \
    void p##blend8_tab(uint8_t *, const uint8_t *, const uint8_t *, uint8_t); \
    void p##blend8_sel_inplace(uint8_t *, const uint8_t *, const uint8_t *);  \
    void p##cpy8(uint8_t *, const uint8_t *);                                 \
    void p##cpy16(uint8_t *, const uint8_t *);                                \
    void p##cpy32(uint8_t *, const uint8_t *);                                \
    void p##copy_fwd(uint8_t *, const uint8_t *, uint32_t);                   \
    const uint8_t *p##blend_table(void);
WRAP_DECL(R_)
WRAP_DECL(D_)
WRAP_DECL(P_)

static int exhaustive;
static unsigned long long checks, failures;
static const char *volatile current = "startup";

static void fail(const char *what, long a, long b)
{
    if (failures++ < 20)
        fprintf(stderr, "FAIL %s (%ld, %ld)\n", what, a, b);
}

#define CHECK(cond, what, a, b) \
    do { checks++; if (!(cond)) fail(what, (long)(a), (long)(b)); } while (0)

static void on_fault(int sig)
{
    char msg[256];
    int n = snprintf(msg, sizeof msg, "FAULT signal %d in %s\n", sig, current);
    (void)!write(2, msg, (size_t)n);
    _exit(2);
}

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void)
{
    rng ^= rng >> 12; rng ^= rng << 25; rng ^= rng >> 27;
    return rng * 0x2545f4914f6cdd1dull;
}
static void fill(uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) p[i] = (uint8_t)rnd(); }

/* A read-write region of `pages` pages between two PROT_NONE pages. */
static size_t page;
static uint8_t *guarded(size_t pages)
{
    uint8_t *m = mmap(NULL, (pages + 2) * page, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (m == MAP_FAILED) { perror("mmap"); exit(1); }
    if (mprotect(m, page, PROT_NONE) || mprotect(m + (pages + 1) * page, page, PROT_NONE)) {
        perror("mprotect"); exit(1);
    }
    return m + page;
}

/* ---- per-intrinsic suites ---------------------------------------------- */

#if HAVE_VEC

#if defined(__aarch64__)
static void real_ld8(uint8_t *out, const uint8_t *p) { vst1_u8(out, vld1_u8(p)); }
static void real_ld16(uint8_t *out, const uint8_t *p) { vst1q_u8(out, vld1q_u8(p)); }
static void real_st8(uint8_t *p, const uint8_t *v) { vst1_u8(p, vld1_u8(v)); }
static void real_st16(uint8_t *p, const uint8_t *v) { vst1q_u8(p, vld1q_u8(v)); }
static void model_ld(uint8_t *out, const uint8_t *p, int w)
{
    if (w == 8) { M_uint8x8_t v = M_vld1_u8(p); memcpy(out, v.b, 8); }
    else { M_uint8x16_t v = M_vld1q_u8(p); memcpy(out, v.b, 16); }
}
static void model_st(uint8_t *p, const uint8_t *src, int w)
{
    if (w == 8) { M_uint8x8_t v; memcpy(v.b, src, 8); M_vst1_u8(p, v); }
    else { M_uint8x16_t v; memcpy(v.b, src, 16); M_vst1q_u8(p, v); }
}
#define LD_WIDE 16
#else
static void real_ld8(uint8_t *out, const uint8_t *p)
{ _mm_storeu_si128((__m128i *)(void *)out, _mm_loadl_epi64((const __m128i *)(const void *)p)); }
static void real_ld16(uint8_t *out, const uint8_t *p)
{ _mm_storeu_si128((__m128i *)(void *)out, _mm_loadu_si128((const __m128i *)(const void *)p)); }
static void real_st8(uint8_t *p, const uint8_t *v)
{ _mm_storel_epi64((__m128i *)(void *)p, _mm_loadu_si128((const __m128i *)(const void *)v)); }
static void real_st16(uint8_t *p, const uint8_t *v)
{ _mm_storeu_si128((__m128i *)(void *)p, _mm_loadu_si128((const __m128i *)(const void *)v)); }
/* Loads report all 16 lanes: MOVQ must zero the upper eight. */
static void model_ld(uint8_t *out, const uint8_t *p, int w)
{
    M_m128i v = w == 8 ? M_mm_loadl_epi64(p) : M_mm_loadu_si128(p);
    memcpy(out, v.b, 16);
}
static void model_st(uint8_t *p, const uint8_t *src, int w)
{
    M_m128i v; memcpy(v.b, src, 16);
    if (w == 8) M_mm_storel_epi64(p, v); else M_mm_storeu_si128(p, v);
}
#define LD_WIDE 16
#endif

/* Loads flush against the guard after, and starting at the guard before,
 * at offsets 0..63; the result must equal the model's. */
static void test_loads(void)
{
    uint8_t *g = guarded(1);
    for (int w = 8; w <= 16; w += 8) {
        current = w == 8 ? "load 8 at guard" : "load 16 at guard";
        for (int off = 0; off < 64; off++)
            for (int at_end = 0; at_end < 2; at_end++) {
                fill(g, page);
                const uint8_t *p = at_end ? g + page - w - off : g + off;
                uint8_t real[LD_WIDE], model[LD_WIDE];
                memset(real, 0xA5, sizeof real);
                memset(model, 0x5A, sizeof model);
                if (w == 8) real_ld8(real, p); else real_ld16(real, p);
                model_ld(model, p, w);
#if defined(__aarch64__)
                int lanes = w;
#else
                int lanes = 16;
#endif
                CHECK(memcmp(real, model, (size_t)lanes) == 0, current, off, at_end);
                CHECK(memcmp(real, p, (size_t)w) == 0, "load equals memory", w, off);
            }
    }
}

/* Stores flush against the guard and inside canaries: only p[0, w) may
 * change, to the model's bytes. */
static void test_stores(void)
{
    uint8_t *g = guarded(1);
    uint8_t *shadow = malloc(page);
    for (int w = 8; w <= 16; w += 8) {
        current = w == 8 ? "store 8 at guard" : "store 16 at guard";
        for (int off = 0; off < 64; off++)
            for (int at_end = 0; at_end < 2; at_end++) {
                uint8_t v[16];
                fill(v, 16);
                fill(g, page);
                memcpy(shadow, g, page);
                size_t pos = at_end ? page - (size_t)w - (size_t)off : (size_t)off + 64;
                if (w == 8) real_st8(g + pos, v); else real_st16(g + pos, v);
                model_st(shadow + pos, v, w);
                CHECK(memcmp(g, shadow, page) == 0, current, off, at_end);
                CHECK(memcmp(g + pos, v, (size_t)w) == 0, "store equals value", w, off);
            }
    }
    free(shadow);
}

/* The table lookup: 16 distinct table bytes, every index value in every
 * lane, the other lanes random. */
static void test_table_lookup(void)
{
    int tables = exhaustive ? 256 : 4;
    current = "table lookup";
    for (int t = 0; t < tables; t++) {
        uint8_t tab[16];
        if (t == 0) for (int j = 0; j < 16; j++) tab[j] = (uint8_t)(0xF0 - 7 * j);
        else if (t == 1) for (int j = 0; j < 16; j++) tab[j] = (uint8_t)(j + 1);
        else fill(tab, 16);
#if defined(__aarch64__)
        const int lanes = 8;
#else
        const int lanes = 16;
#endif
        for (int lane = 0; lane < lanes; lane++)
            for (int v = 0; v < 256; v++) {
                uint8_t idx[16], real[16], model[16];
                fill(idx, 16);
                idx[lane] = (uint8_t)v;
#if defined(__aarch64__)
                vst1_u8(real, vqtbl1_u8(vld1q_u8(tab), vld1_u8(idx)));
                M_uint8x16_t mt; memcpy(mt.b, tab, 16);
                M_uint8x8_t mi; memcpy(mi.b, idx, 8);
                M_uint8x8_t mr = M_vqtbl1_u8(mt, mi);
                memcpy(model, mr.b, 8);
                CHECK(real[lane] == (v < 16 ? tab[v] : 0), "TBL lane semantics", lane, v);
#else
                _mm_storeu_si128((__m128i *)(void *)real,
                                 _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)tab),
                                                  _mm_loadu_si128((const __m128i *)(const void *)idx)));
                M_m128i mt, mi;
                memcpy(mt.b, tab, 16); memcpy(mi.b, idx, 16);
                M_m128i mr = M_mm_shuffle_epi8(mt, mi);
                memcpy(model, mr.b, 16);
                CHECK(real[lane] == ((v & 0x80) ? 0 : tab[v & 15]), "PSHUFB lane semantics", lane, v);
#endif
                CHECK(memcmp(real, model, (size_t)lanes) == 0, "table lookup == model", lane, v);
            }
    }
}

/* Lane moves: vcombine_u8 / _mm_unpacklo_epi64. */
static void test_combine(void)
{
    long n = exhaustive ? 10000000 : 200000;
    current = "combine";
    for (long i = 0; i < n; i++) {
        uint8_t a[16], b[16], real[16], model[16];
        fill(a, 16); fill(b, 16);
#if defined(__aarch64__)
        vst1q_u8(real, vcombine_u8(vld1_u8(a), vld1_u8(b)));
        M_uint8x8_t ma, mb; memcpy(ma.b, a, 8); memcpy(mb.b, b, 8);
        M_uint8x16_t mr = M_vcombine_u8(ma, mb);
#else
        _mm_storeu_si128((__m128i *)(void *)real,
                         _mm_unpacklo_epi64(_mm_loadu_si128((const __m128i *)(const void *)a),
                                            _mm_loadu_si128((const __m128i *)(const void *)b)));
        M_m128i ma, mb; memcpy(ma.b, a, 16); memcpy(mb.b, b, 16);
        M_m128i mr = M_mm_unpacklo_epi64(ma, mb);
#endif
        memcpy(model, mr.b, 16);
        CHECK(memcmp(real, model, 16) == 0, "combine == model", i, 0);
    }
}

#else
static void skipped(void) { printf("  (intrinsic suites skipped: no SSE4.1 in this build)\n"); }
#define test_loads skipped
#define test_stores skipped
#define test_table_lookup skipped
#define test_combine skipped
#endif

/* ---- scalar builtins against table references -------------------------- */

static uint8_t pop8[256], clz8[256], ctz8[256];
static void init_tables(void)
{
    for (int b = 0; b < 256; b++) {
        int p = 0, z = 8, t = 8;
        for (int i = 0; i < 8; i++) p += (b >> i) & 1;
        for (int i = 7; i >= 0; i--) if ((b >> i) & 1) { z = 7 - i; break; }
        for (int i = 0; i < 8; i++) if ((b >> i) & 1) { t = i; break; }
        pop8[b] = (uint8_t)p; clz8[b] = (uint8_t)z; ctz8[b] = (uint8_t)t;
    }
}
static int ref_pop32(uint32_t x) { return pop8[x & 255] + pop8[(x >> 8) & 255] + pop8[(x >> 16) & 255] + pop8[x >> 24]; }
static int ref_clz32(uint32_t x)
{
    if (x >> 24) return clz8[x >> 24];
    if (x >> 16) return 8 + clz8[x >> 16];
    if (x >> 8) return 16 + clz8[x >> 8];
    return 24 + clz8[x];
}
static int ref_ctz32(uint32_t x)
{
    if (x & 255) return ctz8[x & 255];
    if ((x >> 8) & 255) return 8 + ctz8[(x >> 8) & 255];
    if ((x >> 16) & 255) return 16 + ctz8[(x >> 16) & 255];
    return 24 + ctz8[x >> 24];
}
static int ref_pop64(uint64_t x) { return ref_pop32((uint32_t)x) + ref_pop32((uint32_t)(x >> 32)); }
static int ref_clz64(uint64_t x) { return (x >> 32) ? ref_clz32((uint32_t)(x >> 32)) : 32 + ref_clz32((uint32_t)x); }
static int ref_ctz64(uint64_t x) { return (uint32_t)x ? ref_ctz32((uint32_t)x) : 32 + ref_ctz32((uint32_t)(x >> 32)); }

struct span { uint64_t lo, hi, step; unsigned long long bad; };
static void *scan32(void *arg)
{
    struct span *s = arg;
    for (uint64_t v = s->lo; v < s->hi; v += s->step) {
        uint32_t x = (uint32_t)v;
        if (x == 0) continue;
        s->bad += (__builtin_popcount(x) != ref_pop32(x)) +
                  (__builtin_clz(x) != ref_clz32(x)) +
                  (__builtin_ctz(x) != ref_ctz32(x));
    }
    return NULL;
}

static void test_builtins(void)
{
    current = "scalar builtins";
    int nt = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (nt < 1) nt = 1;
    if (nt > 64) nt = 64;
    uint64_t step = exhaustive ? 1 : 251;   /* fast: every 251st input */
    pthread_t th[64];
    struct span sp[64];
    uint64_t total = (uint64_t)1 << 32, chunk = total / (uint64_t)nt;
    for (int i = 0; i < nt; i++) {
        sp[i].lo = (uint64_t)i * chunk;
        sp[i].hi = i == nt - 1 ? total : sp[i].lo + chunk;
        sp[i].step = step;
        sp[i].bad = 0;
        pthread_create(&th[i], NULL, scan32, &sp[i]);
    }
    unsigned long long bad = 0;
    for (int i = 0; i < nt; i++) { pthread_join(th[i], NULL); bad += sp[i].bad; }
    checks += 3 * (total / step);
    CHECK(bad == 0, "popcount/clz/ctz over 32-bit inputs", (long)bad, 0);
    /* Every single bit, every run of ones, then random. */
    for (int i = 0; i < 64; i++)
        for (int j = i; j < 64; j++) {
            uint64_t x = (j == 63 ? ~0ull : ((1ull << (j + 1)) - 1)) & ~((1ull << i) - 1);
            CHECK(__builtin_popcountll(x) == ref_pop64(x), "popcountll", i, j);
            CHECK(__builtin_clzll(x) == ref_clz64(x), "clzll", i, j);
            CHECK(__builtin_ctzll(x) == ref_ctz64(x), "ctzll", i, j);
        }
    long n = exhaustive ? 1L << 30 : 1L << 22;
    for (long i = 0; i < n; i++) {
        uint64_t x = rnd() >> (rnd() & 63);
        if (!x) continue;
        CHECK(__builtin_popcountll(x) == ref_pop64(x), "popcountll random", i, 0);
        CHECK(__builtin_clzll(x) == ref_clz64(x), "clzll random", i, 0);
        CHECK(__builtin_ctzll(x) == ref_ctz64(x), "ctzll random", i, 0);
    }
}

/* ---- whole wrappers, three ways ---------------------------------------- */

static void test_blends(void)
{
    long per = exhaustive ? 100000 : 2000;
    const uint8_t *tab = R_blend_table();
    CHECK(memcmp(tab, P_blend_table(), 256 * 16) == 0, "one blend table", 0, 0);
    current = "zbm_blend8 over all 256 rows";
    for (int bmp = 0; bmp < 256; bmp++)
        for (long i = 0; i < per; i++) {
            uint8_t base[8], lits[8], r[8], d[8], p[8];
            fill(base, 8); fill(lits, 8);
            R_blend8_tab(r, base, lits, (uint8_t)bmp);
            D_blend8_tab(d, base, lits, (uint8_t)bmp);
            P_blend8_tab(p, base, lits, (uint8_t)bmp);
            CHECK(memcmp(r, d, 8) == 0, "blend8 row: real == model", bmp, i);
            CHECK(memcmp(r, p, 8) == 0, "blend8 row: real == portable", bmp, i);
            for (int k = 0; k < 8; k++) {
                int set = (bmp >> k) & 1, below = 0;
                for (int j = 0; j < k; j++) below += (bmp >> j) & 1;
                CHECK(r[k] == (set ? lits[below] : base[k]), "blend8 meaning", bmp, k);
            }
        }
    current = "zbm_blend8_sel in place over all 256 rows";
    for (int bmp = 0; bmp < 256; bmp++)
        for (long i = 0; i < per; i++) {
            uint8_t d0[8], lits[8], r[8], d[8], p[8];
            fill(d0, 8); fill(lits, 8);
            memcpy(r, d0, 8); memcpy(d, d0, 8); memcpy(p, d0, 8);
            R_blend8_sel_inplace(r, lits, tab + 16 * bmp);
            D_blend8_sel_inplace(d, lits, tab + 16 * bmp);
            P_blend8_sel_inplace(p, lits, tab + 16 * bmp);
            CHECK(memcmp(r, d, 8) == 0, "in place: real == model", bmp, i);
            CHECK(memcmp(r, p, 8) == 0, "in place: real == portable", bmp, i);
        }
    /* Arbitrary selectors: the model must still match the hardware; the
     * portable branch is expected to differ once a selector is 16+. */
    current = "zbm_blend8_row arbitrary selectors";
    long n = exhaustive ? 50000000 : 1000000, differ = 0;
    for (long i = 0; i < n; i++) {
        uint8_t base[8], lits[8], row[8], r[8], d[8], p[8];
        fill(base, 8); fill(lits, 8); fill(row, 8);
        R_blend8_row(r, base, lits, row);
        D_blend8_row(d, base, lits, row);
        P_blend8_row(p, base, lits, row);
        CHECK(memcmp(r, d, 8) == 0, "arbitrary selector: real == model", i, 0);
        differ += memcmp(r, p, 8) != 0;
    }
    printf("  arbitrary selectors: portable differs from native in %ld of %ld\n", differ, n);
    if (strcmp(R_branch(), "portable") != 0)
        CHECK(differ > 0, "portable differs for some selector >= 16", differ, n);
}

typedef void (*cpy_fn)(uint8_t *, const uint8_t *);
static void test_fixed_copies(void)
{
    static const struct { const char *name; int w; cpy_fn f[3]; } c[] = {
        {"cpy8", 8, {R_cpy8, D_cpy8, P_cpy8}},
        {"cpy16", 16, {R_cpy16, D_cpy16, P_cpy16}},
        {"cpy32", 32, {R_cpy32, D_cpy32, P_cpy32}},
    };
    uint8_t *s = guarded(1), *d = guarded(1), *ref = malloc(page);
    for (int k = 0; k < 3; k++) {
        current = c[k].name;
        for (int impl = 0; impl < 3; impl++)
            for (int off = 0; off < 64; off++)
                for (int at_end = 0; at_end < 2; at_end++) {
                    size_t pos = at_end ? page - (size_t)c[k].w - (size_t)off : (size_t)off;
                    fill(s, page); fill(d, page);
                    memcpy(ref, d, page);
                    memcpy(ref + pos, s + pos, (size_t)c[k].w);
                    c[k].f[impl](d + pos, s + pos);
                    CHECK(memcmp(d, ref, page) == 0, c[k].name, impl, off);
                }
    }
    free(ref);
}

static void test_copy_fwd(void)
{
    typedef void (*fwd_fn)(uint8_t *, const uint8_t *, uint32_t);
    static const fwd_fn f[3] = {R_copy_fwd, D_copy_fwd, P_copy_fwd};
    static const int fast_offs[] = {0, 1, 3, 7, 8, 15, 16, 31, 32, 63};
    int noffs = exhaustive ? 64 : (int)(sizeof fast_offs / sizeof fast_offs[0]);
    const size_t span = 4096 + 256;
    size_t pages = (2 * span + page - 1) / page + 1;
    uint8_t *s = guarded(pages), *d = guarded(pages);
    uint8_t *ref = malloc(pages * page);
    size_t region = pages * page;
    current = "zbm_copy_fwd";
    for (uint32_t n = 0; n <= 4096; n++) {
        for (int a = 0; a < noffs; a++)
            for (int b = 0; b < noffs; b++) {
                size_t so = exhaustive ? (size_t)a : (size_t)fast_offs[a];
                size_t dof = exhaustive ? (size_t)b : (size_t)fast_offs[b];
                for (int impl = 0; impl < 3; impl++) {
                    /* Separate buffers, canaries all around d. */
                    fill(s + so, n);
                    memset(d, 0xCC, dof + n + 128);
                    memcpy(ref, d, dof + n + 128);
                    memcpy(ref + 64 + dof, s + so, n);
                    f[impl](d + 64 + dof, s + so, n);
                    CHECK(memcmp(d, ref, dof + n + 128) == 0, "copy_fwd separate", n, impl);
                }
            }
        for (int impl = 0; impl < 3; impl++) {
            /* Both flush against their guard pages. */
            uint8_t *se = s + region - n, *de = d + region - n;
            fill(se, n);
            f[impl](de, se, n);
            CHECK(memcmp(de, se, n) == 0, "copy_fwd at guards", n, impl);
            /* One buffer, source just before destination (gap 0, 1, 8). */
            for (int gap = 0; gap <= 8; gap += gap ? 7 : 1) {
                uint8_t *src = s + 17, *dst = s + 17 + n + gap;
                fill(src, n);
                memcpy(ref, src, n);
                dst[n] = 0xEE;
                f[impl](dst, src, n);
                CHECK(memcmp(dst, ref, n) == 0 && memcmp(src, ref, n) == 0 && dst[n] == 0xEE,
                      "copy_fwd same buffer", n, gap);
            }
        }
    }
    free(ref);
}

int main(void)
{
    const char *e = getenv("SIMD_VALIDATE_EXHAUSTIVE");
    exhaustive = e && *e && strcmp(e, "0") != 0;
    page = (size_t)sysconf(_SC_PAGESIZE);
    signal(SIGSEGV, on_fault);
    signal(SIGBUS, on_fault);
    init_tables();
    printf("simd_validate: %s, %s, branches %s / %s / %s\n",
#if defined(__aarch64__)
           "arm64",
#elif defined(__AVX2__)
           "x86-64-v3",
#else
           "x86-64",
#endif
           exhaustive ? "exhaustive" : "fast", R_branch(), D_branch(), P_branch());
#define RUN(t) do { unsigned long long c0 = checks, f0 = failures; t(); \
        printf("  %-20s %12llu checks %s\n", #t, checks - c0, failures == f0 ? "ok" : "FAILED"); \
        fflush(stdout); } while (0)
    RUN(test_loads);
    RUN(test_stores);
    RUN(test_table_lookup);
    RUN(test_combine);
    RUN(test_builtins);
    RUN(test_blends);
    RUN(test_fixed_copies);
    RUN(test_copy_fwd);
    printf("%s: %llu checks, %llu failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
