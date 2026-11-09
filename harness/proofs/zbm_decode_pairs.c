#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    size_t sn, dn;
    uint8_t *srcbuf, *dstbuf;
    zbm_any_buffers(&srcbuf, &sn, &dstbuf, &dn);
    const uint8_t *src = zbm_any_ptr(srcbuf, sn), *end = zbm_any_ptr(srcbuf, sn);
    struct zbm_pair_state cur;
    cur.dest = zbm_any_ptr(dstbuf, dn);
    cur.data = zbm_any_ptr(srcbuf, sn); cur.m1 = zbm_any_ptr(srcbuf, sn);
    cur.m2 = zbm_any_ptr(srcbuf, sn); cur.m3.addr = zbm_any_ptr(srcbuf, sn);
    cur.m3.nibble = nondet_int(); cur.period = nondet_u32(); cur.avail = nondet_size();
    uint8_t bmp[16], pbc[16];
    uint32_t k = nondet_u32();
    size_t avail_end = nondet_size(), before = cur.avail;
    uint32_t unused = zbm_decode_pairs(&cur, src, end, avail_end, bmp, pbc, zbm_blend_row[0], k);
    PROOF_REACHABLE(unused == 0 && k == 1 && cur.avail == before + 16, "complete pair");
    PROOF_REACHABLE(unused == 0 && __CPROVER_same_object(srcbuf, dstbuf),
                    "pairs with source and output in one object");
    PROOF_REACHABLE(unused == 0 && k > 100 && cur.avail > before + 1600, "many unchecked pairs");
    PROOF_REACHABLE(unused == k && cur.m3.nibble == 0 && cur.avail == before, "bail before first block");
    PROOF_REACHABLE(unused == k && cur.m3.nibble == 1 && cur.avail == before + 8, "first committed, second retries slow path");
}
