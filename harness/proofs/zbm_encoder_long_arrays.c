#include "proof.h"
#include "libzbitmap.c"
int nondet_int(void);
unsigned nondet_u32(void);
void harness(void)
{
#ifdef PROOF_LONG_STATE
    struct zbm_compress_state storage;
    const uint64_t (*boundary)[ZBM_MAX_BITMAP_COUNT / 64 + 1] = &storage.run_bnd;
    uint64_t (*marked)[ZBM_MAX_BITMAP_COUNT / 64 + 1] = &storage.run_long;
#else
    uint64_t boundary_storage[ZBM_MAX_BITMAP_COUNT / 64 + 1];
    uint64_t marked_storage[ZBM_MAX_BITMAP_COUNT / 64 + 1];
    const uint64_t (*boundary)[ZBM_MAX_BITMAP_COUNT / 64 + 1] = &boundary_storage;
    uint64_t (*marked)[ZBM_MAX_BITMAP_COUNT / 64 + 1] = &marked_storage;
#endif
    int cnt = nondet_int();
#ifdef ZBM_PROOF_LONG_VALUES
    zbm_proof_long_index = nondet_u32();
#endif
#ifdef PROOF_LONG_STATE
    __CPROVER_assume(cnt >= 0 && cnt <= ZBM_MAX_BITMAP_COUNT);
    __CPROVER_assume(cnt == 0 || zbm_proof_long_index < (unsigned)cnt);
    storage.bmp_cnt = cnt;
    unsigned qword = cnt == 0 ? 0 : zbm_proof_long_index >> 6;
    uint64_t expected = cnt == 0 ? 0 : zbm_long_run_spread(
        zbm_long_run_starts(~(*boundary)[qword], qword + 1 < (unsigned)((cnt + 63) >> 6) ? ~(*boundary)[qword + 1] : 0),
        qword == 0 ? 0 : zbm_long_run_starts(~(*boundary)[qword - 1], ~(*boundary)[qword]));
    zbm_build_long_runs_arrays(&storage.run_bnd, &storage.run_long, storage.bmp_cnt);
    __CPROVER_assert((*marked)[(cnt + 63) >> 6] == 0, "state map has a zero lookahead word");
    __CPROVER_assert(cnt == 0 || (*marked)[qword] == expected,
        "state long-run word matches the verified three-word expression");
#else
    zbm_build_long_runs_arrays(boundary, marked, cnt);
#endif
    PROOF_REACHABLE(cnt == 0, "empty long-run map");
    PROOF_REACHABLE(cnt == 1, "single-word long-run map");
    PROOF_REACHABLE(cnt == 65, "partial second word");
    PROOF_REACHABLE(cnt == ZBM_MAX_BITMAP_COUNT, "maximum long-run map");
#ifdef ZBM_PROOF_LONG_VALUES
    PROOF_REACHABLE(cnt > 0 && zbm_proof_long_index == 0, "first queried long-run word");
    PROOF_REACHABLE(cnt == ZBM_MAX_BITMAP_COUNT && zbm_proof_long_index == ZBM_MAX_BITMAP_COUNT - 1,
        "last queried long-run word");
#endif
}
