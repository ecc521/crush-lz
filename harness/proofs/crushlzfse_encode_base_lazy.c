/*
 * Proof: crushlzfse_encode_base_lazy in crates/crushlzfse/csrc/lzfse_encode_base.c meets its contract.
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

    int hash_width = nondet_int();
    __CPROVER_assume(hash_width >= 1 && hash_width <= 32);

    int lookahead = nondet_int();
    __CPROVER_assume(lookahead >= 0 && lookahead <= 2);

    size_t nbuckets = (size_t)1 << hash_bits;
    size_t table_entries = nbuckets * (size_t)hash_width;
    __CPROVER_assume(table_entries <= PROOF_MAX_OBJECT / sizeof(int32_t));

    int32_t *hist_pos = malloc(table_entries * sizeof(int32_t));
    __CPROVER_assume(hist_pos != NULL);

    uint8_t *hist_tag = malloc(table_entries + ROW_HASH_TAG_PADDING);
    __CPROVER_assume(hist_tag != NULL);

    uint16_t *hist_cursor = malloc(nbuckets * sizeof(uint16_t));
    __CPROVER_assume(hist_cursor != NULL);

    int res = crushlzfse_encode_base_lazy(&s, hash_bits, hash_width, lookahead,
                                          hist_pos, hist_tag, hist_cursor);
    __CPROVER_assert(LZFSE_ENCODE_STATUS(res), "status in range");
    __CPROVER_assert(s.dst_begin == dst && s.dst_end == dst + dn, "keeps buffers");
    __CPROVER_assert(s.dst >= dst && s.dst <= dst + dn, "dst in range");

    PROOF_REACHABLE(hash_width == 4, "width 4 specialized");
    PROOF_REACHABLE(hash_width == 8, "width 8 specialized");
    PROOF_REACHABLE(hash_width == 16, "width 16 specialized");
    PROOF_REACHABLE(hash_width == 32, "width 32 specialized");
    PROOF_REACHABLE(hash_width != 4 && hash_width != 8 && hash_width != 16 && hash_width != 32, "generic width");
}
