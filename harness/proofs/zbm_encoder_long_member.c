#include "proof.h"
#include "libzbitmap.c"
int nondet_int(void);
void harness(void)
{
    uint64_t boundary[ZBM_MAX_BITMAP_COUNT / 64 + 1];
    uint64_t marked[ZBM_MAX_BITMAP_COUNT / 64 + 1];
    int cnt = nondet_int(), start = nondet_int(), end = nondet_int(), q = nondet_int();
    __CPROVER_assume(cnt >= 4 && cnt <= ZBM_MAX_BITMAP_COUNT);
    __CPROVER_assume(start >= 0 && start < cnt && end >= start && end < cnt);
    __CPROVER_assume(end - start >= 3);
    __CPROVER_assume(q >= start && q <= end);
    /* Any member of a run of four or more has a four-block window in that
     * run covering it. Only the three equality edges of this window matter;
     * unrelated boundaries remain arbitrary. */
    int window = q - 3 > start ? q - 3 : start;
    __CPROVER_assert(window >= start && window + 3 <= end && window <= q && q <= window + 3,
        "chosen four-block window covers the queried member");
    __CPROVER_assume(((boundary[window >> 6] >> (window & 63)) & 1u) == 0);
    __CPROVER_assume(((boundary[(window + 1) >> 6] >> ((window + 1) & 63)) & 1u) == 0);
    __CPROVER_assume(((boundary[(window + 2) >> 6] >> ((window + 2) & 63)) & 1u) == 0);
    zbm_proof_long_index = (unsigned)q;
    zbm_build_long_runs_arrays(&boundary, &marked, cnt);
    __CPROVER_assert(((marked[q >> 6] >> (q & 63)) & 1u) == 1u,
        "every member of a four-or-longer run is marked");
#ifdef PROOF_MEMBER_WINDOW
    int i = nondet_int();
    __CPROVER_assume(i >= 0 && i < cnt);
    __CPROVER_assume(i + 16 <= cnt && q >= i && q < i + 16);
    uint16_t bits = zbm_long_run_window(marked[i >> 6], marked[(i >> 6) + 1], (unsigned)(i & 63));
    __CPROVER_assert(((bits >> (q - i)) & 1u) == 1u,
        "a vector window containing a long-run member cannot be zero");
#endif
    PROOF_REACHABLE(cnt == 16 && start == 0 && end == 3 && q == 0,
        "first long-run member");
    PROOF_REACHABLE(cnt == 16 && start == 0 && end == 15 && q == 15,
        "last long-run member");
    PROOF_REACHABLE(cnt == 80 && start == 62 && end == 65 && q == 64,
        "four-block run crossing a word boundary");
    PROOF_REACHABLE(cnt == ZBM_MAX_BITMAP_COUNT && start == cnt - 4 && end == cnt - 1 && q == cnt - 1,
        "final member in maximum chunk");
}
