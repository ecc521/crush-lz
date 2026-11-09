/*
 * Shared by the LZBITMAP decoder harnesses. Builds a struct zbm_state whose
 * pointers all point into two buffers of unconstrained size, the chunk and
 * the output, at unconstrained offsets; every scalar field is unconstrained.
 * The function's requires clauses (ZBM_STATE_OK) then pick out the states
 * the proof covers, so the harness itself assumes nothing about them.
 */
#ifndef ZBM_STATE_H
#define ZBM_STATE_H

size_t nondet_size(void);
uint32_t nondet_u32(void);
uint16_t nondet_u16(void);
int nondet_int(void);
_Bool nondet_bool(void);

static uint8_t *zbm_any_buffer(size_t *size)
{
    size_t n = nondet_size();
    __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT);
    uint8_t *b = malloc(n);
    __CPROVER_assume(b != NULL);
    *size = n;
    return b;
}

static uint8_t *zbm_any_ptr(uint8_t *buf, size_t n)
{
    size_t o = nondet_size();
    __CPROVER_assume(o <= n);
    return buf + o;
}

/*
 * The chunk and the output buffers: two allocations, or two disjoint ranges
 * of one allocation in either order. The public API asks only that source
 * and destination be separate storage ranges, not separate objects.
 */
static void zbm_any_buffers(uint8_t **src, size_t *sn, uint8_t **dst, size_t *dn)
{
    if(nondet_bool()) {
        *src = zbm_any_buffer(sn);
        *dst = zbm_any_buffer(dn);
        return;
    }
    size_t n, k = nondet_size();
    uint8_t *b = zbm_any_buffer(&n);
    __CPROVER_assume(k > 0 && k < n);
    if(nondet_bool()) {
        *src = b; *sn = k; *dst = b + k; *dn = n - k;
    } else {
        *dst = b; *dn = k; *src = b + k; *sn = n - k;
    }
}

static struct zbm_state *zbm_any_state(void)
{
    struct zbm_state *st = malloc(sizeof(*st));
    __CPROVER_assume(st != NULL);
    size_t sn, dn;
    uint8_t *src, *dst;
    zbm_any_buffers(&src, &sn, &dst, &dn);

    st->dest = zbm_any_ptr(dst, dn);
    st->dest_left = nondet_size();
    st->written = nondet_u32();
    st->period = nondet_u16();
    st->src = zbm_any_ptr(src, sn);
    st->len = nondet_u32();
    st->src_end = zbm_any_ptr(src, sn);
    st->decmp_len = nondet_u32();
    st->src_left = nondet_size();
    st->prewritten = nondet_size();
    st->data = zbm_any_ptr(src, sn);
    st->meta_1 = zbm_any_ptr(src, sn);
    st->meta_2 = zbm_any_ptr(src, sn);
    st->meta_3.addr = zbm_any_ptr(src, sn);
    st->meta_3.nibble = nondet_int();
    /* bitmaps[] is left as malloc gave it: unconstrained. */
    return st;
}

#endif
