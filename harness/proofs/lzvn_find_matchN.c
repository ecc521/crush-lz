/*
 * Proof: lzvn_find_matchN in crates/crushlzfse/csrc/lzvn_encode_base.c meets its contract.
 */
#include "proof.h"
#include "lzvn_encode_base.c"

size_t nondet_size(void);
lzvn_offset nondet_offset(void);

void harness(void)
{
    size_t sn = nondet_size();
    __CPROVER_assume(sn > 0 && sn <= LZVN_ENCODE_MAX_SRC_SIZE);
    uint8_t *sbuf = malloc(sn);
    __CPROVER_assume(sbuf != NULL);

    lzvn_offset src_begin = nondet_offset();
    lzvn_offset l_begin = nondet_offset();
    lzvn_offset m0_begin = nondet_offset();
    lzvn_offset m_begin = nondet_offset();
    lzvn_offset n = nondet_offset();

    __CPROVER_assume(0 <= src_begin && src_begin <= l_begin && l_begin <= m_begin && m_begin <= (lzvn_offset)sn);
    __CPROVER_assume(src_begin <= m0_begin && m0_begin < m_begin);
    __CPROVER_assume(0 <= n && n <= 4 && m_begin + n <= (lzvn_offset)sn);

    lzvn_match_info match;
    memset(&match, 0, sizeof(match));

    int rc = lzvn_find_matchN(sbuf, src_begin, (lzvn_offset)sn, l_begin, m0_begin, m_begin, n, &match);

    PROOF_REACHABLE(n < 3 && rc == 0, "n < 3 rejected");
    PROOF_REACHABLE(n >= 3 && rc == 0, "distance out of range rejected");
    PROOF_REACHABLE(rc == 1 && n == 4 && match.M > 4, "extended match");
    PROOF_REACHABLE(rc == 1 && match.m_begin < m_begin, "backwards match expansion");
    PROOF_REACHABLE(rc == 1 && n == 3, "three-byte match");
}
