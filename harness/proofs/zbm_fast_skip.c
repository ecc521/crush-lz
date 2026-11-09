#include "proof.h"
#include "libzbitmap.c"

size_t nondet_size(void);
uint32_t nondet_u32(void);
int nondet_int(void);

/*
 * The fast loop keeps its skip marker as a byte offset from its first block:
 * a search at offset `at` lets the block at offset `later` search again once
 * later >= at + skip. The original pointer marker src + skip could be formed
 * beyond the input allocation. The offset sum cannot wrap, and it makes the
 * same decision for every block as the original pointer comparison.
 */
void harness(void)
{
    size_t at = nondet_size(), later = nondet_size();
    uint32_t failures = nondet_u32();
    int shift = nondet_int();
    __CPROVER_assume(at < CRUSHLZBITMAP_CHUNK_SIZE && later < CRUSHLZBITMAP_CHUNK_SIZE);
    __CPROVER_assume(failures <= ZBM_MAX_BITMAP_COUNT && shift >= 1 && shift <= 31);
    size_t skip = zbm_fast_skip_bytes(failures, shift);
    size_t requested = 8 * (1 + (size_t)(failures >> shift));
    __CPROVER_assert(skip == requested, "skip is the original search distance");
    __CPROVER_assert(skip >= 8, "the searching block never searches again");
    __CPROVER_assert(at + skip >= at && at + skip <= CRUSHLZBITMAP_CHUNK_SIZE + 8 + 4 * ZBM_MAX_BITMAP_COUNT,
                     "skip offset does not wrap");
    __CPROVER_assert((later >= at + skip) == (later >= at + requested),
                     "every block makes the original search decision");
    PROOF_REACHABLE(at + requested > CRUSHLZBITMAP_CHUNK_SIZE, "original marker past the chunk");
    PROOF_REACHABLE(later >= at + skip && later > at + 8, "search after a long skip");
    PROOF_REACHABLE(later < at + skip && later > at, "block skipped");
}
