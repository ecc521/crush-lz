/*
 * Proof: decode_block in crates/crushlz4/csrc/crushlz4.c meets its contract,
 * for any bytes in src.
 *
 * As in lz4_copy_match.c, the harness only supplies pointers into buffers of
 * unconstrained size; CBMC assumes decode_block's requires clauses
 * (--enforce-contract), and lz4_decode.c checks them at the call site.
 * copy_match is replaced by its contract (proved in lz4_copy_match.c), so
 * every call to it must establish its requires clauses: off <= the bytes
 * before d, mlen <= room, room inside dst.
 *
 * The block's bytes are unconstrained: every stream of every length is
 * covered, malformed or not. The loop contracts in the source make the
 * proof unbounded in slen, dst_cap and the number of sequences.
 */
#include "proof.h"
#include "crushlz4.c"

size_t nondet_size(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t sn = nondet_size(), so = nondet_size();
    __CPROVER_assume(sn > 0 && sn <= PROOF_MAX_OBJECT && so <= sn);
    uint8_t *sbuf = malloc(sn);
    __CPROVER_assume(sbuf != NULL);

    uint8_t *dst = NULL;
    if (nondet_bool()) {
        size_t dn = nondet_size(), dof = nondet_size();
        __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT && dof <= dn);
        uint8_t *dbuf = malloc(dn);
        __CPROVER_assume(dbuf != NULL);
        dst = dbuf + dof;
    }

    size_t dst_cap = nondet_size(), slen = nondet_size();
    size_t *dst_pos;    /* allocated by the is_fresh requires clause */
    int rc = decode_block(dst, dst_cap, dst_pos, sbuf + so, slen);

    PROOF_REACHABLE(rc == 0 && dst != NULL && slen > 0, "block decoded into dst");
    PROOF_REACHABLE(rc == 0 && dst == NULL && slen > 0, "block validated, no dst");
    PROOF_REACHABLE(rc == CLZ4_INVAL, "malformed block");
    PROOF_REACHABLE(rc == CLZ4_RANGE, "dst too small");
    PROOF_REACHABLE(rc == 0 && slen > ((size_t)1 << 40), "block longer than 2^40");
}
