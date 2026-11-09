/*
 * Proof: crushlzfse_fast_best in crates/crushlzfse/csrc/fast_match.h.
 */
#include "proof.h"
#include "lzfse_internal.h"
#include "fast_match.h"

int nondet_int(void);
_Bool nondet_bool(void);
uint16_t nondet_uint16(void);

void harness(void)
{
    int hash_bits = CRUSHLZFSE_FAST_MIN_HASH_BITS;

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

    lzfse_offset pos = nondet_int();
    lzfse_offset src_end = nondet_int();
    __CPROVER_assume(pos >= 1);
    __CPROVER_assume(src_end >= pos + 16);
    __CPROVER_assume(src_end <= src_size);

    /* Historical match table entries are earlier positions: 0 <= entry < pos */
    uint16_t entry_short = nondet_uint16();
    __CPROVER_assume(entry_short < pos);

    uint64_t v = load8(src + pos);
    uint32_t h = crushlzfse_fast_hash(v, min_match, hash_bits, CRUSHLZFSE_FAST_PRIME);
    table[h] = entry_short;

    if (long_table) {
        uint16_t entry_long = nondet_uint16();
        __CPROVER_assume(entry_long < pos);
        uint32_t hl = crushlzfse_fast_hash(v, 8, hash_bits, CRUSHLZFSE_FAST_PRIME);
        ltable[hl] = entry_long;
    }

    lzfse_offset ref = 0;
    uint32_t best = crushlzfse_fast_best(src, pos, src_end, min_match, hash_bits,
                                         CRUSHLZFSE_FAST_PRIME, table, ltable,
                                         long_table, &ref);

    if (best > 0) {
        __CPROVER_assert(ref < pos, "ref < pos");
        __CPROVER_assert(best >= 4, "match length at least 4");
        __CPROVER_assert(best <= (uint32_t)(src_end - pos - 8), "match length within bounds");
    }

    PROOF_REACHABLE(best == 0, "reach no match");
    PROOF_REACHABLE(best > 0 && long_table, "reach match with long table");
    PROOF_REACHABLE(best > 0 && !long_table, "reach match with short table");
}
