/*
 * Equivalence of the decoder's SIMD wrappers: the NEON (N_) and SSE (S_)
 * branches of crush_simd.h, run on the intrinsic models, write exactly the
 * bytes the portable branch (P_) writes, for arbitrary data. Every buffer is
 * an object of exactly the documented width, so CBMC's pointer checks also
 * prove each wrapper's footprint.
 *
 * The blends agree only when every selector is below 16 (TBL zeroes larger
 * indices, PSHUFB uses the low 4 bits unless bit 7 is set, and the portable
 * branch uses the low 4 bits). The lemma below proves that of every row of
 * the shipping zbm_blend_row table; with -DEQUIV_NEGATIVE the selectors are
 * unrestricted and run_equiv.sh requires CBMC to find a disagreement.
 */
#include <stdint.h>
#include <stdlib.h>
#include "zbm_blend_tables.h"

#define DECL(p)                                                                \
    void p##blend8_row(uint8_t *, const uint8_t *, const uint8_t *,           \
                       const uint8_t *);                                      \
    void p##blend8_sel(uint8_t *, const uint8_t *, const uint8_t *,           \
                       const uint8_t *);                                      \
    void p##blend8_sel_inplace(uint8_t *, const uint8_t *, const uint8_t *);  \
    void p##cpy8(uint8_t *, const uint8_t *);                                 \
    void p##cpy16(uint8_t *, const uint8_t *);                                \
    void p##cpy32(uint8_t *, const uint8_t *);
DECL(P_)
DECL(N_)
DECL(S_)

uint8_t nondet_u8(void);
int nondet_int(void);

/* A fresh object of exactly n arbitrary bytes. */
static uint8_t *object(size_t n)
{
    uint8_t *p = malloc(n);
    __CPROVER_assume(p != NULL);
    return p;
}

static uint8_t *copy_of(const uint8_t *s, size_t n)
{
    uint8_t *p = object(n);
    for (size_t i = 0; i < n; i++)
        p[i] = s[i];
    return p;
}

/* A macro, so each comparison is its own CBMC property. */
#define same(a, b, n, what)                                                    \
    do {                                                                       \
        for (size_t i_ = 0; i_ < (n); i_++)                                    \
            __CPROVER_assert((a)[i_] == (b)[i_], what);                        \
    } while (0)

static const uint8_t *selector_row(void)
{
    uint8_t *row = object(8);
#ifndef EQUIV_NEGATIVE
    for (int i = 0; i < 8; i++)
        __CPROVER_assume(row[i] < 16);
#endif
    return row;
}

static void blend_row(void)
{
    const uint8_t *base = object(8), *lits = object(8), *row = selector_row();
    uint8_t *p = object(8), *n = object(8), *s = object(8);
    P_blend8_row(p, base, lits, row);
    N_blend8_row(n, base, lits, row);
    S_blend8_row(s, base, lits, row);
    same(n, p, 8, "blend8_row: NEON == portable");
    same(s, p, 8, "blend8_row: SSE == portable");
    /* What the blend means: lane i is lits[sel] or base[sel - 8]. */
    for (int i = 0; i < 8; i++)
        __CPROVER_assert(p[i] == (row[i] < 8 ? lits[row[i] & 7] : base[row[i] & 7]),
                         "blend8_row: selector semantics");
}

static void blend_sel(void)
{
    const uint8_t *base = object(8), *lits = object(8), *row = selector_row();
    uint8_t *p = object(8), *n = object(8), *s = object(8);
    P_blend8_sel(p, base, lits, row);
    N_blend8_sel(n, base, lits, row);
    S_blend8_sel(s, base, lits, row);
    same(n, p, 8, "blend8_sel: NEON == portable");
    same(s, p, 8, "blend8_sel: SSE == portable");
}

static void blend_sel_inplace(void)
{
    const uint8_t *lits = object(8), *row = selector_row();
    const uint8_t *d0 = object(8);
    uint8_t *p = copy_of(d0, 8), *n = copy_of(d0, 8), *s = copy_of(d0, 8);
    P_blend8_sel_inplace(p, lits, row);
    N_blend8_sel_inplace(n, lits, row);
    S_blend8_sel_inplace(s, lits, row);
    same(n, p, 8, "blend8_sel in place: NEON == portable");
    same(s, p, 8, "blend8_sel in place: SSE == portable");
    for (int i = 0; i < 8; i++)
        __CPROVER_assert(p[i] == (row[i] < 8 ? lits[row[i] & 7] : d0[row[i] & 7]),
                         "blend8_sel in place: reads base before writing it");
}

static void copies(void)
{
    const uint8_t *s8 = object(8), *s16 = object(16), *s32 = object(32);
    uint8_t *p8 = object(8), *n8 = object(8), *x8 = object(8);
    uint8_t *p16 = object(16), *n16 = object(16), *x16 = object(16);
    uint8_t *p32 = object(32), *n32 = object(32), *x32 = object(32);
    P_cpy8(p8, s8); N_cpy8(n8, s8); S_cpy8(x8, s8);
    P_cpy16(p16, s16); N_cpy16(n16, s16); S_cpy16(x16, s16);
    P_cpy32(p32, s32); N_cpy32(n32, s32); S_cpy32(x32, s32);
    same(p8, s8, 8, "cpy8: portable copies");
    same(n8, s8, 8, "cpy8: NEON copies");
    same(x8, s8, 8, "cpy8: SSE copies");
    same(p16, s16, 16, "cpy16: portable copies");
    same(n16, s16, 16, "cpy16: NEON copies");
    same(x16, s16, 16, "cpy16: SSE copies");
    same(p32, s32, 32, "cpy32: portable copies");
    same(n32, s32, 32, "cpy32: NEON copies");
    same(x32, s32, 32, "cpy32: SSE copies");
}

/* Every selector the decoder can load is below 16: all rows of the
 * shipping table, as zbm_blend8 (zbm_blend_row[bmp]), ZBM_RESOLVE and the
 * per-block loop (rowbase + (bmp << 4)) and zbm_patch_literals index it. */
static void table_lemma(void)
{
    uint8_t bmp = nondet_u8();
    int i = nondet_int();
    __CPROVER_assume(i >= 0 && i < 8);
    const uint8_t *rowbase = zbm_blend_row[0];
    __CPROVER_assert(zbm_blend_row[bmp][i] < 16, "table: every selector below 16");
    /* The stride form addresses the same row. (CBMC 6.11 reads a byte
     * past row 0 through rowbase as an unconstrained value, so compare
     * addresses rather than loaded bytes.) */
    __CPROVER_assert(rowbase + ((size_t)bmp << 4) == &zbm_blend_row[bmp][0],
                     "table: row by stride is row bmp");
    /* And it means the blend described above: a set bit takes the next
     * literal, a clear bit takes the baseline's own lane. */
    unsigned below = 0;
    for (int j = 0; j < 8; j++)
        below += (j < i) & ((bmp >> j) & 1u);
    __CPROVER_assert(zbm_blend_row[bmp][i] ==
                         (((bmp >> i) & 1u) ? below : 8u + (unsigned)i),
                     "table: selector is popcount below or own lane");
}

void harness(void)
{
    blend_row();
    blend_sel();
    blend_sel_inplace();
#ifndef EQUIV_NEGATIVE
    copies();
    table_lemma();
#endif
}
