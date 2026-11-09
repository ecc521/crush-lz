/*
 * Re-entry of lzvn_decode across returns. Each iteration repeats the LZFSE
 * frame's LZVN-block step (lzfse_decode, LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC):
 * the window is narrowed to the remaining payload and raw counts, dst_begin
 * stays fixed and d_prev round-trips through the block's uint32_t field.
 * Between calls the caller may supply more source or destination room in the
 * same objects, which is how a DST_FULL or truncated return is resumed. The
 * loop has no iteration bound: the loop contract proves that every call's
 * precondition follows from the previous call's postcondition. The first
 * call already starts from an arbitrary resumed state (d_prev and positions
 * left by earlier calls), so CBMC's base-case copy of the loop body covers
 * re-entry as well.
 */
#include "proof.h"
#include "lzvn_decode_base.c"

size_t nondet_size(void);
uint32_t nondet_u32(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t sn = nondet_size(), dn = nondet_size();
    __CPROVER_assume(sn > 0 && sn <= PROOF_MAX_OBJECT);
    __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT);
    const unsigned char *sbuf;
    unsigned char *dbuf;
    _Bool shared = nondet_bool();
    size_t gap = 0, lead = 0;
    if (shared) {
        __CPROVER_assume(sn <= PROOF_MAX_OBJECT - dn);
        gap = nondet_size();
        lead = nondet_size();
        __CPROVER_assume(gap <= PROOF_MAX_OBJECT - sn - dn);
        __CPROVER_assume(lead <= PROOF_MAX_OBJECT - sn - dn - gap);
        unsigned char *arena = malloc(lead + sn + gap + dn);
        __CPROVER_assume(arena != NULL);
        unsigned char *first = arena + lead;
        if (nondet_bool()) {
            sbuf = first;
            dbuf = first + sn + gap;
        } else {
            dbuf = first;
            sbuf = first + dn + gap;
        }
    } else {
        sbuf = malloc(sn);
        dbuf = malloc(dn);
        __CPROVER_assume(sbuf != NULL && dbuf != NULL);
    }

    size_t so = nondet_size(), se = nondet_size();
    size_t db = nondet_size(), dof = nondet_size(), de = nondet_size();
    __CPROVER_assume(so <= se && se <= sn);
    __CPROVER_assume(db <= dof && dof <= de && de <= dn);
    const unsigned char *src = sbuf + so, *src_end = sbuf + se;
    unsigned char *const dst_begin = dbuf + db;
    unsigned char *dst = dbuf + dof, *dst_end = dbuf + de;

    uint32_t n_payload = nondet_u32(), n_raw = nondet_u32();
    uint32_t d_prev = nondet_u32();
    __CPROVER_assume(d_prev <= dof - db);
    int status = 0;

    for (;;)
        __CPROVER_assigns(src, src_end, dst, dst_end, n_payload, n_raw, d_prev,
                          status, __CPROVER_object_upto(dbuf, dn))
        __CPROVER_loop_invariant(__CPROVER_same_object(src, sbuf) &&
                                 __CPROVER_same_object(src_end, sbuf) &&
                                 __CPROVER_POINTER_OFFSET(sbuf) <= __CPROVER_POINTER_OFFSET(src) &&
                                 __CPROVER_POINTER_OFFSET(src) <= __CPROVER_POINTER_OFFSET(src_end) &&
                                 __CPROVER_POINTER_OFFSET(src_end) - __CPROVER_POINTER_OFFSET(sbuf) <= sn)
        __CPROVER_loop_invariant(__CPROVER_same_object(dst, dbuf) &&
                                 __CPROVER_same_object(dst_end, dbuf) &&
                                 __CPROVER_POINTER_OFFSET(dbuf) <= __CPROVER_POINTER_OFFSET(dst_begin) &&
                                 __CPROVER_POINTER_OFFSET(dst_begin) <= __CPROVER_POINTER_OFFSET(dst) &&
                                 __CPROVER_POINTER_OFFSET(dst) <= __CPROVER_POINTER_OFFSET(dst_end) &&
                                 __CPROVER_POINTER_OFFSET(dst_end) - __CPROVER_POINTER_OFFSET(dbuf) <= dn)
        __CPROVER_loop_invariant(LZVN_PROOF_RANGES_DISJOINT(sbuf, sn, dbuf, dn))
        __CPROVER_loop_invariant(d_prev <= (size_t)(dst - dst_begin))
        __CPROVER_loop_invariant(status == 0)
    {
        if (n_payload > 0 && src_end <= src)
            break; // LZFSE_STATUS_SRC_EMPTY

        lzvn_decoder_state dstate;
        memset(&dstate, 0x00, sizeof(dstate));
        dstate.src = src;
        dstate.src_end = src_end;
        if (dstate.src_end - src > n_payload)
            dstate.src_end = src + n_payload;
        dstate.dst_begin = dst_begin;
        dstate.dst = dst;
        dstate.dst_end = dst_end;
        if (dstate.dst_end - dst > n_raw)
            dstate.dst_end = dst + n_raw;
        dstate.d_prev = d_prev;
        dstate.end_of_stream = 0;
        uint32_t d_in = d_prev;

        lzvn_decode(&dstate);

        size_t src_used = dstate.src - src;
        size_t dst_used = dstate.dst - dst;
        if (src_used > n_payload || dst_used > n_raw)
            break; // LZFSE_STATUS_ERROR
        src = dstate.src;
        dst = dstate.dst;
        n_payload -= (uint32_t)src_used;
        n_raw -= (uint32_t)dst_used;
        d_prev = (uint32_t)dstate.d_prev;

        PROOF_REACHABLE(d_in > 0 && dst_used > 0, "re-entry with a carried distance");
        PROOF_REACHABLE(shared && d_in > 0 && dst_used > 0,
                        "shared allocation re-entry");
        PROOF_REACHABLE(shared && gap > 0 && lead > 0 && d_in > 0 && dst_used > 0,
                        "shared allocation re-entry with leading offset and gap");
        if (n_payload == 0 && n_raw == 0 && dstate.end_of_stream) {
            PROOF_REACHABLE(d_in > 0, "block completed after re-entry");
            break; // block done
        }
        if (n_payload == 0 || n_raw == 0 || dstate.end_of_stream)
            break; // LZFSE_STATUS_ERROR
        PROOF_REACHABLE(dstate.truncated_mid_op, "re-entry after a truncated op");

        // LZFSE_STATUS_DST_FULL. The caller may resume with more room.
        size_t more_src = nondet_size(), more_dst = nondet_size();
        __CPROVER_assume(more_src <= sn -
                         (__CPROVER_POINTER_OFFSET(src_end) - __CPROVER_POINTER_OFFSET(sbuf)));
        __CPROVER_assume(more_dst <= dn -
                         (__CPROVER_POINTER_OFFSET(dst_end) - __CPROVER_POINTER_OFFSET(dbuf)));
        src_end += more_src;
        dst_end += more_dst;
    }
}
