/*
 * Proof: lzvn_decode_buffer in crates/crushlzfse/csrc/lzvn_decode_base.c meets its contract.
 */
#include "proof.h"
#include "lzvn_decode_base.c"

size_t nondet_size(void);
_Bool nondet_bool(void);

void harness(void)
{
    const uint8_t *src = NULL;
    size_t src_size = nondet_size();
    uint8_t *dst = NULL;
    size_t dst_size = nondet_size();
    _Bool shared = nondet_bool();
    size_t gap = 0, lead = 0;

    if (shared) {
        size_t sn = nondet_size(), dn = nondet_size();
        __CPROVER_assume(sn <= PROOF_MAX_OBJECT && dn <= PROOF_MAX_OBJECT);
        __CPROVER_assume(sn <= PROOF_MAX_OBJECT - dn);
        gap = nondet_size();
        lead = nondet_size();
        __CPROVER_assume(gap <= PROOF_MAX_OBJECT - sn - dn);
        __CPROVER_assume(lead <= PROOF_MAX_OBJECT - sn - dn - gap);
        size_t total = lead + sn + gap + dn;
        uint8_t *buf = malloc(total != 0 ? total : 1);
        __CPROVER_assume(buf != NULL);
        uint8_t *first = buf + lead;
        if (nondet_bool()) {
            if (sn != 0 || nondet_bool()) {
                src = first;
                src_size = sn;
            }
            if (dn != 0 || nondet_bool()) {
                dst = first + sn + gap;
                dst_size = dn;
            }
        } else {
            if (dn != 0 || nondet_bool()) {
                dst = first;
                dst_size = dn;
            }
            if (sn != 0 || nondet_bool()) {
                src = first + dn + gap;
                src_size = sn;
            }
        }
    } else {
        if (nondet_bool()) {
            size_t n = nondet_size(), o = nondet_size();
            __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT && o <= n);
            uint8_t *buf = malloc(n);
            __CPROVER_assume(buf != NULL);
            __CPROVER_assume(src_size <= n - o);
            src = buf + o;
        }

        if (nondet_bool()) {
            size_t n = nondet_size(), o = nondet_size();
            __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT && o <= n);
            uint8_t *buf = malloc(n);
            __CPROVER_assume(buf != NULL);
            __CPROVER_assume(dst_size <= n - o);
            dst = buf + o;
        }
    }

    size_t out = lzvn_decode_buffer(dst, dst_size, src, src_size);

    __CPROVER_assert(out <= dst_size, "out <= dst_size");

    PROOF_REACHABLE(dst != NULL && src != NULL && out > 0, "stream decoded into dst");
    PROOF_REACHABLE(shared && dst != NULL && src != NULL && out > 0, "shared allocation stream decoded into dst");
    PROOF_REACHABLE(shared && gap > 0 && lead > 0 && out > 0,
                    "shared allocation decode with leading offset and gap");
    PROOF_REACHABLE(dst == NULL && out == 0, "null destination rejected");
    PROOF_REACHABLE(src == NULL && out == 0, "null source rejected");
}
