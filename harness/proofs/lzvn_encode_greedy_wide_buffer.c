/*
 * Proof: lzvn_encode_greedy_wide_buffer in crates/crushlzfse/csrc/lzvn_encode_base.c meets its contract.
 */
#include "proof.h"
#include "lzvn_encode_base.c"

size_t nondet_size(void);
int32_t nondet_int32(void);

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

    size_t src_size = sn - so;
    size_t dst_size = dn - dof;

    int32_t hash_bits = nondet_int32();
    __CPROVER_assume(hash_bits >= 10 && hash_bits <= 16);

    int32_t hash_width = nondet_int32();
    __CPROVER_assume(hash_width >= 1 && hash_width <= 64);

    size_t n_hash = (size_t)1 << hash_bits;
    size_t table_entries = n_hash * (size_t)hash_width;

    __CPROVER_assume(table_entries <= PROOF_MAX_OBJECT / sizeof(int32_t));
    int32_t *hist_pos = malloc(table_entries * sizeof(int32_t));
    __CPROVER_assume(hist_pos != NULL);

    uint32_t *hist_value = malloc(table_entries * sizeof(uint32_t));
    __CPROVER_assume(hist_value != NULL);

    uint16_t *hist_cursor = malloc(n_hash * sizeof(uint16_t));
    __CPROVER_assume(hist_cursor != NULL);

    size_t out = lzvn_encode_greedy_wide_buffer(dbuf + dof, dst_size,
                                               sbuf + so, src_size,
                                               hash_bits, hash_width,
                                               hist_pos, hist_value, hist_cursor);

    __CPROVER_assert(out <= dst_size, "out <= dst_size");

    PROOF_REACHABLE(dst_size < LZVN_ENCODE_MIN_DST_SIZE && out == 0, "dst too small rejected");
    PROOF_REACHABLE(src_size >= LZVN_ENCODE_MIN_SRC_SIZE && dst_size >= 16 && out > 0, "successful encode");
    PROOF_REACHABLE(src_size < LZVN_ENCODE_MIN_SRC_SIZE && dst_size >= 16 && out > 0, "small source encode");
}
