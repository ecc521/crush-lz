#include "proof.h"
#undef memcpy
#include "libzbitmap.c"

uint8_t nondet_u8(void);
uint32_t nondet_u32(void);
size_t nondet_size(void);

void harness(void)
{
    struct zbm_compress_state *st = malloc(sizeof(*st));
    __CPROVER_assume(st != NULL);
    size_t cap = nondet_size();
    __CPROVER_assume(cap <= ZBM_BITMAP_BYTECNT);
    uint8_t *dst = malloc(cap);
    __CPROVER_assume(dst != NULL);
    st->dest = dst;
    st->dest_end = dst + cap;
    uint32_t before = nondet_u32();
    __CPROVER_assume(before <= CRUSHLZBITMAP_MAX_CHUNK_SIZE - ZBM_BITMAP_BYTECNT);
    st->written = before;
    for(unsigned i = 0; i < ZBM_BITMAP_COUNT; ++i) {
        st->top_bitmaps[i].bitmap = nondet_u8();
        st->top_bitmaps[i].period_bytecnt = nondet_u8();
        __CPROVER_assume(st->top_bitmaps[i].period_bytecnt <= 2);
    }
    int rc = zbm_write_trailing_bitmaps(st);
    __CPROVER_assert(rc == (cap < ZBM_BITMAP_BYTECNT ? ZBM_CANT_COMPRESS : 0),
                      "trailing table checks exact destination capacity");
    if(rc == 0) {
        __CPROVER_assert(st->dest == dst + ZBM_BITMAP_BYTECNT &&
                          st->written == before + ZBM_BITMAP_BYTECNT, "table advances exact extent");
        for(unsigned b = 0; b < ZBM_BITMAP_BYTECNT * 8; ++b) {
            unsigned want = 0;
            if(b < ZBM_BITMAP_COUNT * 10) {
                unsigned i = b / 10, bit = b % 10;
                want = bit < 8 ? (st->top_bitmaps[i].bitmap >> bit) & 1 :
                                (st->top_bitmaps[i].period_bytecnt >> (bit - 8)) & 1;
            }
            __CPROVER_assert(((dst[b / 8] >> (b % 8)) & 1) == want,
                              "table serializes exact bitmap and period bits with zero padding");
        }
    } else {
        __CPROVER_assert(st->dest == dst && st->written == before, "short table leaves cursors unchanged");
    }
    PROOF_REACHABLE(cap == ZBM_BITMAP_BYTECNT && rc == 0, "exact table capacity");
    PROOF_REACHABLE(cap == ZBM_BITMAP_BYTECNT - 1 && rc != 0, "one byte short");
    PROOF_REACHABLE(cap == 0 && rc != 0, "no capacity");
}
