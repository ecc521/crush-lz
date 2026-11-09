/*
 * Proof: lzfse_decode (the frame dispatcher in lzfse_decode_base.c) meets its
 * contract at the shipping table sizes, for symbolic source and destination
 * objects up to PROOF_MAX_OBJECT and any resumable entry state, including a
 * block already in progress (pending LMD work, LZVN or stored bytes).
 * The loop runs unbounded under its invariant and decreases clause.
 */
#include "proof.h"
#include "lzfse_internal.h"
#include "lzfse_frame_interface.h"
#include "lzfse_decode_base.c"

size_t nondet_size(void);

void harness(void)
{
    lzfse_decoder_state *s = malloc(sizeof(*s));
    __CPROVER_assume(s != NULL);

    size_t scap = nondet_size(), dcap = nondet_size();
    __CPROVER_assume(scap >= 1 && scap <= PROOF_MAX_OBJECT);
    __CPROVER_assume(dcap >= 1 && dcap <= PROOF_MAX_OBJECT);
    uint8_t *sbuf, *dbuf;
    if (nondet_size() & 1) {
        __CPROVER_assume(scap + dcap <= PROOF_MAX_OBJECT);
        size_t gap = nondet_size();
        __CPROVER_assume(gap <= PROOF_MAX_OBJECT - scap - dcap);
        uint8_t *shared = malloc(scap + gap + dcap);
        __CPROVER_assume(shared != NULL);
        if (nondet_size() & 1) {
            sbuf = shared;
            dbuf = shared + scap + gap;
        } else {
            dbuf = shared;
            sbuf = shared + dcap + gap;
        }
    } else {
        sbuf = malloc(scap);
        dbuf = malloc(dcap);
        __CPROVER_assume(sbuf != NULL && dbuf != NULL);
    }
#ifdef PROOF_SHARED_ONLY
    __CPROVER_assume(__CPROVER_same_object(sbuf, dbuf));
#endif

    size_t sb = nondet_size(), sp = nondet_size(), se = nondet_size();
    __CPROVER_assume(sb <= sp && sp <= se && se <= scap);
    size_t db = nondet_size(), dp = nondet_size(), de = nondet_size();
    __CPROVER_assume(db <= dp && dp <= de && de <= dcap);
    s->src_begin = sbuf + sb;
    s->src = sbuf + sp;
    s->src_end = sbuf + se;
    s->dst_begin = dbuf + db;
    s->dst = dbuf + dp;
    s->dst_end = dbuf + de;
    const uint32_t magic = s->block_magic;
    const int32_t pending = s->compressed_lzfse_block_state.l_value |
                            s->compressed_lzfse_block_state.m_value;

    int res = lzfse_decode(s);

    PROOF_REACHABLE(res == LZFSE_STATUS_OK, "end of stream");
    PROOF_REACHABLE(res == LZFSE_STATUS_SRC_EMPTY, "source exhausted");
    PROOF_REACHABLE(res == LZFSE_STATUS_ERROR, "malformed stream");
    PROOF_REACHABLE(res == LZFSE_STATUS_DST_FULL &&
                        s->block_magic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC,
                    "LMD fills the destination");
    PROOF_REACHABLE(res == LZFSE_STATUS_DST_FULL &&
                        s->block_magic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC,
                    "LZVN block fills the destination");
    PROOF_REACHABLE(res == LZFSE_STATUS_SRC_EMPTY &&
                        s->block_magic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC &&
                        s->dst > s->dst_begin,
                    "stored block split across source calls");
    PROOF_REACHABLE(magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC && pending != 0 &&
                        res == LZFSE_STATUS_OK,
                    "resumed LMD block with pending work completes the stream");
    PROOF_REACHABLE(__CPROVER_same_object(s->src_begin, s->dst_begin) &&
                        res == LZFSE_STATUS_OK,
                    "shared allocation, disjoint source and destination");
}
