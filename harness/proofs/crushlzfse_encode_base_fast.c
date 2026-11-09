/*
 * Proof: crushlzfse_encode_base_fast in crates/crushlzfse/csrc/lzfse_encode_base.c meets its contract.
 */
#include "proof.h"
#include "lzfse_encode_base.c"

size_t nondet_size(void);
int nondet_int(void);

void harness(void)
{
    lzfse_encoder_state s;
    memset(&s, 0, sizeof(s));

    size_t sn = nondet_size();
    __CPROVER_assume(sn <= PROOF_MAX_OBJECT);
    uint8_t *src = malloc(sn);
    __CPROVER_assume(src != NULL);

    size_t dn = nondet_size();
    __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT);
    uint8_t *dst = malloc(dn);
    __CPROVER_assume(dst != NULL);
    __CPROVER_assume(!__CPROVER_same_object(src, dst));

    s.src = src;
    s.src_end = (lzfse_offset)sn;
    s.src_literal = 0;
    s.src_encode_i = 0;
    s.dst = dst;
    s.dst_begin = dst;
    s.dst_end = dst + dn;

    int hash_bits = nondet_int();
    __CPROVER_assume(hash_bits >= 10 && hash_bits <= 16);

    int long_table = nondet_int();
    __CPROVER_assume(long_table == 0 || long_table == 1);

    int lazy = nondet_int();
    __CPROVER_assume(lazy == 0 || lazy == 1);

    int min_match = nondet_int();
    __CPROVER_assume(min_match >= 4 && min_match <= (long_table || lazy ? 6 : 8));

    int skip_shift = nondet_int();
    __CPROVER_assume(skip_shift >= 1 && skip_shift <= 31);

    int max_step = nondet_int();
    __CPROVER_assume(max_step >= 1 && max_step <= 64);

    size_t entries = (size_t)1 << hash_bits;
    __CPROVER_assume(entries <= PROOF_MAX_OBJECT / sizeof(uint16_t));
    uint16_t *table = malloc(entries * sizeof(uint16_t));
    __CPROVER_assume(table != NULL);

    uint16_t *ltable = NULL;
    if (long_table) {
        ltable = malloc(entries * sizeof(uint16_t));
        __CPROVER_assume(ltable != NULL);
    }

    int res = crushlzfse_encode_base_fast(&s, hash_bits, min_match, skip_shift,
                                          max_step, long_table, lazy, table, ltable);
    __CPROVER_assert(LZFSE_ENCODE_STATUS(res), "status in range");
    __CPROVER_assert(s.dst_begin == dst && s.dst_end == dst + dn, "keeps buffers");
    __CPROVER_assert(s.dst >= dst && s.dst <= dst + dn, "dst in range");

    PROOF_REACHABLE(long_table == 0 && lazy == 0 && min_match == 4, "plain mode MM 4");
    PROOF_REACHABLE(long_table == 0 && lazy == 0 && min_match == 8, "plain mode MM 8");
    PROOF_REACHABLE(long_table == 1 && lazy == 0 && min_match == 5, "long table mode");
    PROOF_REACHABLE(long_table == 0 && lazy == 1 && min_match == 6, "lazy mode");
    PROOF_REACHABLE(long_table == 1 && lazy == 1 && min_match == 4, "long table and lazy mode");
}
