/*
 * Proof: lzvn_copy64 in crates/crushlzfse/csrc/lzvn_encode_base.c meets its contract.
 */
#include "proof.h"
#include "lzvn_encode_base.c"

size_t nondet_size(void);

void harness(void)
{
    size_t sn = nondet_size(), so = nondet_size();
    __CPROVER_assume(sn > 0 && sn <= PROOF_MAX_OBJECT && so <= sn);
    uint8_t *sbuf = malloc(sn);
    __CPROVER_assume(sbuf != NULL);

    size_t dn = nondet_size(), dof = nondet_size();
    __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT && dof <= dn);
    uint8_t *dbuf = malloc(dn);
    __CPROVER_assume(dbuf != NULL);

    size_t nbytes = nondet_size();
    __CPROVER_assume(nbytes <= PROOF_MAX_OBJECT - 8);
    __CPROVER_assume(nbytes + 7 <= sn - so);
    __CPROVER_assume(nbytes + 7 <= dn - dof);

    unsigned char *ret = lzvn_copy64(dbuf + dof, sbuf + so, nbytes);
    __CPROVER_assert(ret == dbuf + dof + nbytes, "ret == dst + nbytes");

    PROOF_REACHABLE(nbytes == 0, "copy 0 bytes");
    PROOF_REACHABLE(nbytes > 0 && nbytes < 8, "copy < 8 bytes");
    PROOF_REACHABLE(nbytes == 8, "copy exact 8 bytes");
    PROOF_REACHABLE(nbytes > 8, "copy > 8 bytes");
}
