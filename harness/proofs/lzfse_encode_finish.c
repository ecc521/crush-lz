/*
 * Proof: lzfse_encode_finish in crates/crushlzfse/csrc/lzfse_encode_base.c meets its contract.
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
    __CPROVER_assume(src != NULL);

    size_t dn = nondet_size();
    __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT);
    uint8_t *dst = malloc(dn);
    __CPROVER_assume(dst != NULL);
    __CPROVER_assume(!__CPROVER_same_object(src, dst));

    s.src = src;
    s.src_end = (lzfse_offset)sn;
    s.src_literal = (lzfse_offset)(nondet_size());
    __CPROVER_assume(s.src_literal <= s.src_end);

    s.dst_begin = dst;
    s.dst_end = dst + dn;
    size_t dst_offset = nondet_size();
    __CPROVER_assume(dst_offset <= dn);
    s.dst = dst + dst_offset;

    s.pending.length = nondet_u32();
    s.pending.pos = (lzfse_offset)nondet_size();
    s.pending.ref = (lzfse_offset)nondet_size();

    int res = lzfse_encode_finish(&s);
    __CPROVER_assert(LZFSE_ENCODE_STATUS(res), "status in range");
    __CPROVER_assert(s.dst_begin == dst && s.dst_end == dst + dn, "keeps buffers");
    __CPROVER_assert(s.dst >= dst && s.dst <= dst + dn, "dst in range");

    PROOF_REACHABLE(res == LZFSE_STATUS_OK, "status ok");
    PROOF_REACHABLE(res == LZFSE_STATUS_DST_FULL, "status dst full");
    PROOF_REACHABLE(s.pending.length > 0, "pending match branch");
    PROOF_REACHABLE(s.src_literal < s.src_end, "literals branch");
    PROOF_REACHABLE(s.src_literal == s.src_end && s.pending.length == 0, "pure eos branch");
}
