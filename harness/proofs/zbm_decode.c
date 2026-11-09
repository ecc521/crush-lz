/* The public API proof composes the chunk contract. It is end-to-end only
 * once all of that contract's compressed-decoder dependencies are proved.
 *
 * Alias geometry: src and dst are each NULL or a range of an allocation;
 * the two ranges are in separate allocations or are disjoint ranges of one
 * (zbm_any_buffers). out_len is NULL, its own object, or a separate disjoint
 * range within the source or destination allocation. That matches the
 * documented contract: separate storage ranges, not separate objects. */
#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    size_t sn, dn;
    uint8_t *sbuf, *dbuf;
    zbm_any_buffers(&sbuf, &sn, &dbuf, &dn);
    const uint8_t *src = NULL;
    size_t src_size = nondet_size();
    if(nondet_bool()) {
        src = zbm_any_ptr(sbuf, sn);
        __CPROVER_assume(src_size <= sn - (size_t)(src - sbuf));
    }
    uint8_t *dst = NULL;
    size_t dst_size = nondet_size();
    if(nondet_bool()) {
        dst = zbm_any_ptr(dbuf, dn);
        __CPROVER_assume(dst_size <= dn - (size_t)(dst - dbuf));
    }
    size_t out = nondet_size();
    size_t *out_len = NULL;
    int out_choice = nondet_int();
    if(out_choice == 1) {
        out_len = &out;
    } else if(out_choice == 2 && sn >= sizeof(size_t)) {
        size_t off = nondet_size();
        __CPROVER_assume(off <= sn - sizeof(size_t));
        __CPROVER_assume(off % sizeof(size_t) == 0);
        size_t *p = (size_t *)(sbuf + off);
        __CPROVER_assume(src == NULL || src_size == 0 ||
                         ZBM_DISJOINT(p, sizeof(size_t), src, src_size));
        __CPROVER_assume(dst == NULL || dst_size == 0 ||
                         ZBM_DISJOINT(p, sizeof(size_t), dst, dst_size));
        out_len = p;
    } else if(out_choice == 3 && dn >= sizeof(size_t)) {
        size_t off = nondet_size();
        __CPROVER_assume(off <= dn - sizeof(size_t));
        __CPROVER_assume(off % sizeof(size_t) == 0);
        size_t *p = (size_t *)(dbuf + off);
        __CPROVER_assume(src == NULL || src_size == 0 ||
                         ZBM_DISJOINT(p, sizeof(size_t), src, src_size));
        __CPROVER_assume(dst == NULL || dst_size == 0 ||
                         ZBM_DISJOINT(p, sizeof(size_t), dst, dst_size));
        out_len = p;
    }

    int rc = crushlzbitmap_decode_buffer(dst, dst_size, src, src_size, out_len);
    __CPROVER_assert(rc == 0 || rc == CRUSHLZBITMAP_INVALID ||
                     rc == CRUSHLZBITMAP_OUTPUT_TOO_SMALL, "documented status");
    if(out_len) __CPROVER_assert(*out_len <= dst_size, "reported length within capacity");
    PROOF_REACHABLE(rc == 0 && dst != NULL && *out_len > 0, "decoded stream");
    PROOF_REACHABLE(rc == 0 && dst != NULL && *out_len > 0 && __CPROVER_same_object(src, dst),
                    "decoded stream, source and destination in one object");
    PROOF_REACHABLE(rc == 0 && dst != NULL && out_len != NULL && __CPROVER_same_object(dst, out_len) && *out_len > 0,
                    "decoded stream, destination and out_len in one object");
    PROOF_REACHABLE(rc == 0 && dst == NULL && dst_size == SIZE_MAX && *out_len > 0, "uncapped size probe");
    PROOF_REACHABLE(rc == CRUSHLZBITMAP_OUTPUT_TOO_SMALL && *out_len > 0, "capacity exhausted after a complete chunk");
    PROOF_REACHABLE(rc == CRUSHLZBITMAP_INVALID && src != NULL, "malformed stream");
    PROOF_REACHABLE(rc == 0 && *out_len > ((size_t)1 << 40), "large decoded size");
}
