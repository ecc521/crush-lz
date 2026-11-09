/*
 * Proof: lzfse_push_match in crates/crushlzfse/csrc/lzfse_encode_base.c meets its contract.
 */
#include "proof.h"
#include "lzfse_encode_base.c"

size_t nondet_size(void);
int nondet_int(void);
uint32_t nondet_u32(void);

void harness(void)
{
    lzfse_encoder_state s;
    memset(&s, 0, sizeof(s));

    size_t sn = nondet_size();
    __CPROVER_assume(sn <= PROOF_MAX_OBJECT);
    uint8_t *src = malloc(sn);
    __CPROVER_assume(src != NULL || sn == 0);

    size_t dn = nondet_size();
    __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT);
    uint8_t *dst = malloc(dn);
    __CPROVER_assume(dst != NULL);
    __CPROVER_assume(!__CPROVER_same_object(src, dst));

    s.src = src;
    s.src_end = (lzfse_offset)sn;
    s.src_literal = (lzfse_offset)(nondet_size());
    __CPROVER_assume(s.src_literal >= 0 && s.src_literal <= s.src_end);

    s.dst_begin = dst;
    s.dst_end = dst + dn;
    size_t dst_offset = nondet_size();
    __CPROVER_assume(dst_offset <= dn);
    s.dst = dst + dst_offset;

    lzfse_match match;
    uint32_t L = nondet_u32();
    __CPROVER_assume(L <= 3 * LZFSE_ENCODE_MAX_L_VALUE);
    __CPROVER_assume(s.src_literal + (lzfse_offset)L <= s.src_end);
    match.pos = s.src_literal + (lzfse_offset)L;

    uint32_t D = nondet_u32();
    __CPROVER_assume(D >= 1 && (lzfse_offset)D <= match.pos);
    match.ref = match.pos - (lzfse_offset)D;

    match.length = nondet_u32();
    __CPROVER_assume(match.length <= 3 * LZFSE_ENCODE_MAX_M_VALUE);

    int res = lzfse_push_match(&s, &match);
    __CPROVER_assert(LZFSE_ENCODE_STATUS(res), "status in range");
    __CPROVER_assert(s.dst_begin == dst && s.dst_end == dst + dn, "keeps buffers");
    __CPROVER_assert(s.dst == dst + dst_offset, "dst preserved");
    __CPROVER_assert(s.src_literal >= 0 && s.src_literal <= s.src_end, "literal in range");

    PROOF_REACHABLE(res == LZFSE_STATUS_OK, "push match ok");
    PROOF_REACHABLE(res == LZFSE_STATUS_DST_FULL, "push match full");
}
