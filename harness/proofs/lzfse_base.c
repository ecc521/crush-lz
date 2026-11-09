/*
 * Proof: lzfse_encode_base in crates/crushlzfse/csrc/lzfse_encode_base.c meets its contract.
 */
#include "proof.h"
#include "lzfse_encode_base.c"

size_t nondet_size(void);
int nondet_int(void);
_Bool nondet_bool(void);

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
    s.src_literal = 0;
    s.src_encode_i = 0;
    s.dst = dst;
    s.dst_begin = dst;
    s.dst_end = dst + dn;

    lzfse_zopt_scratch z;
    memset(&z, 0, sizeof(z));

    _Bool null_zopt = nondet_bool();
    if (!null_zopt) {
        s.zopt = &z;
        /* Nondet configuration clamped by lzfse_encode_base */
        z.cand_capacity = nondet_int();
        z.search_depth = nondet_int();
        z.iterations = nondet_int();
        z.max_live_buckets = nondet_int();
        z.tuple_tax = nondet_int();
        z.dp_nslots = nondet_int();
        z.split_max_blocks = nondet_int();
        z.enable_reparse = nondet_int();
    } else {
        s.zopt = NULL;
    }

    int res = lzfse_encode_base(&s);
    __CPROVER_assert(LZFSE_ENCODE_STATUS(res), "status in range");
    __CPROVER_assert(s.dst_begin == dst && s.dst_end == dst + dn, "keeps buffers");
    __CPROVER_assert(s.dst >= dst && s.dst <= dst + dn, "dst in range");

    PROOF_REACHABLE(null_zopt, "null zopt rejected with error");
    PROOF_REACHABLE(!null_zopt && sn > (size_t)LZFSE_ZOPT_BLOCK_SIZE, "oversized block fallback to literals");
    PROOF_REACHABLE(!null_zopt && sn <= (size_t)LZFSE_ZOPT_BLOCK_SIZE && res == LZFSE_STATUS_OK, "encode ok");
    PROOF_REACHABLE(!null_zopt && sn <= (size_t)LZFSE_ZOPT_BLOCK_SIZE && res == LZFSE_STATUS_DST_FULL, "encode dst full");
}
