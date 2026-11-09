/*
 * Proof: the public LZFSE decoders in crates/crushlzfse/csrc/lzfse_decode.c
 * meet their contracts for nullable zero-length buffers and any sizes up to
 * PROOF_MAX_OBJECT, consuming the lzfse_decode contract. PROOF_WITH_SCRATCH
 * checks lzfse_decode_buffer_with_scratch (caller scratch at any aligned
 * offset); otherwise lzfse_decode_buffer, with internal allocation allowed
 * to fail, consuming the _with_scratch contract.
 */
#include "proof.h"
#include "lzfse_decode.c"

size_t nondet_size(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t sn = nondet_size(), dn = nondet_size();
    __CPROVER_assume(sn <= PROOF_MAX_OBJECT && dn <= PROOF_MAX_OBJECT);
    uint8_t *src = NULL, *dst = NULL;
    if (sn != 0 && dn != 0 && nondet_bool()) {
        // Both orientations, with an arbitrary gap, are legal restrict ranges.
        __CPROVER_assume(sn + dn <= PROOF_MAX_OBJECT);
        size_t gap = nondet_size();
        __CPROVER_assume(gap <= PROOF_MAX_OBJECT - sn - dn);
        uint8_t *shared = malloc(sn + gap + dn);
        __CPROVER_assume(shared != NULL);
        if (nondet_bool()) {
            src = shared;
            dst = shared + sn + gap;
        } else {
            dst = shared;
            src = shared + dn + gap;
        }
    } else {
        if (sn != 0 || nondet_bool()) {
            src = malloc(sn != 0 ? sn : 1);
            __CPROVER_assume(src != NULL);
        }
        if (dn != 0 || nondet_bool()) {
            dst = malloc(dn != 0 ? dn : 1);
            __CPROVER_assume(dst != NULL);
        }
    }
    void *scratch = NULL;
    size_t pad = 0;
    if (nondet_bool()) {
        lzfse_decoder_state *s = malloc(sizeof(*s));
        __CPROVER_assume(s != NULL);
        scratch = s;
    }
#ifdef PROOF_WITH_SCRATCH
    __CPROVER_assume(scratch != NULL);
    size_t written = lzfse_decode_buffer_with_scratch(dst, dn, src, sn, scratch);
#else
    size_t written = lzfse_decode_buffer(dst, dn, src, sn, scratch);
#endif

    PROOF_REACHABLE(src == NULL && sn == 0 && written == 0, "null empty source");
    PROOF_REACHABLE(dst == NULL && dn == 0 && sn != 0, "null empty destination");
    PROOF_REACHABLE(written > 0 && written < dn, "partial output");
    PROOF_REACHABLE(written > 0 && written == dn, "destination full or exact");
    PROOF_REACHABLE(written > 0 && __CPROVER_same_object(src, dst),
                    "shared allocation, disjoint source and destination");
#ifndef PROOF_WITH_SCRATCH
    PROOF_REACHABLE(scratch == NULL && written > 0, "internal scratch");
    PROOF_REACHABLE(scratch != NULL && written > 0, "caller scratch");
#else
    PROOF_REACHABLE(written > 0, "caller scratch");
#endif
}
