/*
 * Proof: crushlzfse_fast_index_match in crates/crushlzfse/csrc/fast_match.h.
 */
#include "proof.h"
#include "lzfse_internal.h"
#include "fast_match.h"

int nondet_int(void);
_Bool nondet_bool(void);

void harness(void)
{
    int hash_bits = nondet_int();
    __CPROVER_assume(hash_bits >= CRUSHLZFSE_FAST_MIN_HASH_BITS &&
                     hash_bits <= CRUSHLZFSE_FAST_MAX_HASH_BITS);

    int min_match = nondet_int();
    __CPROVER_assume(min_match >= CRUSHLZFSE_FAST_MIN_MIN_MATCH &&
                     min_match <= CRUSHLZFSE_FAST_MAX_MIN_MATCH);

    size_t table_entries = (size_t)1 << hash_bits;
    uint16_t *table = malloc(table_entries * sizeof(uint16_t));
    __CPROVER_assume(table != NULL);

    int long_table = nondet_bool() ? 1 : 0;
    uint16_t *ltable = NULL;
    if (long_table) {
        ltable = malloc(table_entries * sizeof(uint16_t));
        __CPROVER_assume(ltable != NULL);
        __CPROVER_assume(!__CPROVER_same_object(table, ltable));
    }

    /* Bounded source buffer */
    size_t src_size = 64;
    uint8_t *src = malloc(src_size);
    __CPROVER_assume(src != NULL);

    lzfse_offset mpos = nondet_int();
    lzfse_offset end = nondet_int();
    __CPROVER_assume(mpos >= 0 && end >= 4 && mpos + 4 <= end);
    __CPROVER_assume(end + 8 <= src_size);

    crushlzfse_fast_index_match(src, mpos, end, min_match, hash_bits,
                                CRUSHLZFSE_FAST_PRIME, table, ltable, long_table);

    PROOF_REACHABLE(long_table == 0, "reach short table only");
    PROOF_REACHABLE(long_table == 1, "reach long table");
}
