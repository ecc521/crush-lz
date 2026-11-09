/*
 * Proof: zbm_cpy8, zbm_cpy16 or zbm_cpy32 (PROOF_CPY_WIDTH) in
 * crates/lzbitmap/csrc/crush_simd.h meets ZBM_CPY_CONTRACT: it reads only
 * s[0, N) and writes only d[0, N), for ranges in one buffer or two. Built on
 * the portable branch (memcpy contract) and on the native branches (the
 * intrinsic models), so composed native proofs can replace the copy by the
 * same contract.
 */
#include "proof.h"
#include "libzbitmap.c"

size_t nondet_size(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t n = nondet_size(), dpos = nondet_size(), spos = nondet_size();
    __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT && dpos <= n && spos <= n);
    uint8_t *buf = malloc(n);
    __CPROVER_assume(buf != NULL);
    uint8_t *d = buf + dpos;
    const uint8_t *s = buf + spos;
    if (nondet_bool()) {
        size_t m = nondet_size(), o = nondet_size();
        __CPROVER_assume(m > 0 && m <= PROOF_MAX_OBJECT && o <= m);
        uint8_t *other = malloc(m);
        __CPROVER_assume(other != NULL);
        s = other + o;
    }
#if PROOF_CPY_WIDTH == 8
    zbm_cpy8(d, s);
#elif PROOF_CPY_WIDTH == 16
    zbm_cpy16(d, s);
#elif PROOF_CPY_WIDTH == 32
    zbm_cpy32(d, s);
#else
#error "PROOF_CPY_WIDTH must be 8, 16 or 32"
#endif
    PROOF_REACHABLE(__CPROVER_same_object(d, s) && s + PROOF_CPY_WIDTH == d,
                    "source flush before destination");
    PROOF_REACHABLE(__CPROVER_same_object(d, s) && d + PROOF_CPY_WIDTH == s,
                    "destination flush before source");
    PROOF_REACHABLE(!__CPROVER_same_object(d, s), "two buffers");
}
