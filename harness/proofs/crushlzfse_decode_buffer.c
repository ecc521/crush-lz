/*
 * Proof: crushlzfse_decode_buffer in crates/crushlzfse/csrc/crushlzfse.c
 * meets its contract for nullable zero-length buffers and any sizes up to
 * PROOF_MAX_OBJECT, with internal allocation allowed to fail, consuming the
 * lzfse_decode contract.
 */
#include "proof.h"
#include "crushlzfse.c"

size_t nondet_size(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t sn = nondet_size(), dn = nondet_size();
    __CPROVER_assume(sn <= PROOF_MAX_OBJECT && dn <= PROOF_MAX_OBJECT);
    uint8_t *src = NULL, *dst = NULL;
    size_t *shared_out = NULL;
    if (sn != 0 && dn != 0 && nondet_bool()) {
        _Bool out_in_allocation = nondet_bool();
        size_t prefix = out_in_allocation ? sizeof(size_t) : 0;
        __CPROVER_assume(sn <= PROOF_MAX_OBJECT - prefix);
        __CPROVER_assume(dn <= PROOF_MAX_OBJECT - prefix - sn);
        size_t gap = nondet_size();
        __CPROVER_assume(gap <= PROOF_MAX_OBJECT - prefix - sn - dn);
        uint8_t *shared = malloc(prefix + sn + gap + dn);
        __CPROVER_assume(shared != NULL);
        if (out_in_allocation) shared_out = (size_t *)shared;
        uint8_t *first = shared + prefix;
        if (nondet_bool()) {
            src = first;
            dst = first + sn + gap;
        } else {
            dst = first;
            src = first + dn + gap;
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
    size_t output = nondet_size();
    size_t *out = nondet_bool() ?
        (shared_out != NULL && nondet_bool() ? shared_out : &output) : NULL;

    int res = crushlzfse_decode_buffer(dst, dn, src, sn, out);

    PROOF_REACHABLE(out == NULL && res == CRUSHLZFSE_INVALID, "null output length rejected");
    PROOF_REACHABLE(src == NULL && sn == 0 && out != NULL && res == CRUSHLZFSE_INVALID,
                    "null empty source rejected");
    PROOF_REACHABLE(dst == NULL && dn == 0 && out != NULL && res == 0 && output == 0,
                    "empty destination accepts an empty stream");
    PROOF_REACHABLE(out != NULL && res == CRUSHLZFSE_OUTPUT_TOO_SMALL && output > 0,
                    "destination exhausted after partial output");
    PROOF_REACHABLE(out != NULL && res == 0 && output > 0, "nonempty decode");
    PROOF_REACHABLE(out != NULL && res == 0 && output > 0 &&
                        __CPROVER_same_object(src, dst),
                    "shared allocation, disjoint source and destination");
    PROOF_REACHABLE(out == shared_out && out != NULL && res == 0 && *out > 0,
                    "output length shares allocation with disjoint buffers");
    PROOF_REACHABLE(sn != 0 && out != NULL && res == CRUSHLZFSE_INVALID,
                    "malformed stream or allocation failure");
}
