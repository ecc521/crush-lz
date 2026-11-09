/*
 * Proof: lzvn_copy_literal_short in crates/crushlzfse/csrc/lzvn_decode_base.c meets its contract.
 */
#include "proof.h"
#include "lzvn_decode_base.c"

size_t nondet_size(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t sn = nondet_size(), so = nondet_size();
    size_t dn = nondet_size(), dof = nondet_size();
    __CPROVER_assume(sn > 0 && sn <= PROOF_MAX_OBJECT && so <= sn);
    __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT && dof <= dn);
    uint8_t *sbuf = NULL, *dbuf = NULL;
    _Bool shared = nondet_bool();
    size_t gap = 0, lead = 0;
    if (shared) {
        __CPROVER_assume(sn <= PROOF_MAX_OBJECT - dn);
        gap = nondet_size();
        lead = nondet_size();
        __CPROVER_assume(gap <= PROOF_MAX_OBJECT - sn - dn);
        __CPROVER_assume(lead <= PROOF_MAX_OBJECT - sn - dn - gap);
        uint8_t *arena = malloc(lead + sn + gap + dn);
        __CPROVER_assume(arena != NULL);
        uint8_t *first = arena + lead;
        if (nondet_bool()) {
            sbuf = first;
            dbuf = first + sn + gap;
        } else {
            dbuf = first;
            sbuf = first + dn + gap;
        }
    } else {
        sbuf = malloc(sn);
        dbuf = malloc(dn);
        __CPROVER_assume(sbuf != NULL && dbuf != NULL);
    }

    size_t src_len = nondet_size();
    size_t dst_len = nondet_size();
    size_t L = nondet_size();
    __CPROVER_assume(L <= 3);
    size_t written = 0;

    int rc = lzvn_copy_literal_short(dbuf + dof, dst_len, sbuf + so, src_len, L, &written);

    PROOF_REACHABLE(rc == 0 && dst_len >= 4 && src_len >= 4, "four-byte copy");
    PROOF_REACHABLE(rc == 0 && L <= dst_len && (dst_len < 4 || src_len < 4), "byte copy fits");
    PROOF_REACHABLE(rc == 1 && L > dst_len, "destination truncated");
    PROOF_REACHABLE(shared && rc == 0 && L > 0, "shared allocation copy");
}
