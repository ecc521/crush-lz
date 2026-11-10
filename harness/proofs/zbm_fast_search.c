#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

uint64_t nondet_u64(void);

/*
 * The fast loop's helpers, each for any source position inside an
 * allocation of any size. PROOF_PACK8 selects the literal packer at every
 * bitmap, PROOF_FAST_HASH8 the bucket hash; otherwise the candidate scorer,
 * for every candidate count the loop uses and any distances its contract
 * admits.
 */
void harness(void)
{
    size_t n;
    uint8_t *buf = zbm_any_buffer(&n);
    const uint8_t *src = zbm_any_ptr(buf, n);
#if defined(PROOF_PACK8)
    uint8_t d[8];
    uint8_t bm = (uint8_t)nondet_u32();

    zbm_pack8(d, src, zbm_pack_row[bm]);
    PROOF_REACHABLE(bm == 0xff, "every lane a literal");
#elif defined(PROOF_FAST_HASH8)
    int sh = nondet_int();
    uint32_t h[8];

    zbm_fast_hash8(src, sh, h);
    PROOF_REACHABLE(sh == 16 && h[7] == 0xffffu, "largest bucket of a 16-bit table");
    PROOF_REACHABLE(sh == 23, "smallest table the fast tier uses");
#else
    uint32_t dd[12];
    int K = nondet_int();
    uint64_t needle = nondet_u64();
    uint32_t best = nondet_u32();
    int i;

    for(i = 0; i < 12; ++i)
        dd[i] = nondet_u32();
    uint32_t r = zbm_fast_score(src, needle, dd, K, best);
    PROOF_REACHABLE(K == 10 && (r & 0xffffu) == dd[9] && (best & 0xffffu) == 0, "last candidate of ten wins");
    PROOF_REACHABLE(K == 6 && (r & 0xffffu) == dd[0] && dd[0] == __CPROVER_POINTER_OFFSET(src),
                    "candidate at the start of the allocation wins");
    PROOF_REACHABLE(K == 4 && r == best, "the period in force keeps the block");
#endif
}
