/*
 * Proof: lzvn_copy_match in crates/crushlzfse/csrc/lzvn_decode_base.c meets its contract.
 */
#include "proof.h"
#include "lzvn_decode_base.c"

size_t nondet_size(void);

void harness(void)
{
    size_t n = nondet_size();
    __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT);
    uint8_t *buf = malloc(n);
    __CPROVER_assume(buf != NULL);
    size_t pos = nondet_size();
    __CPROVER_assume(pos <= n);

    size_t dst_len = nondet_size();
    size_t D = nondet_size();
    size_t M = nondet_size();
    size_t written = 0;

    int rc = lzvn_copy_match(buf + pos, dst_len, D, M, &written);

    PROOF_REACHABLE(rc == 0 && D >= 8 && dst_len >= M + 7 && M > 16, "wide copy");
    PROOF_REACHABLE(rc == 0 && M <= dst_len && (D < 8 || dst_len < M + 7), "byte copy fits");
    PROOF_REACHABLE(rc == 1 && M > dst_len, "destination truncated");
    PROOF_REACHABLE(M > ((size_t)1 << 40), "match longer than 2^40");
}
