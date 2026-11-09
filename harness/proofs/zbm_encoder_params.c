#include "proof.h"
#include "libzbitmap.c"

crushlzbitmap_params nondet_params(void);
int nondet_int(void);

/* Independent statement of the public ranges and cross-field limits. */
static int row_valid(crushlzbitmap_row_params r)
{
    int log_depth = r.depth == 1 ? 0 : r.depth == 2 ? 1 :
                    r.depth == 4 ? 2 : r.depth == 8 ? 3 : r.depth == 16 ? 4 : -1;
    return r.hash_bits >= CRUSHLZBITMAP_MIN_ROW_HASH_BITS &&
           r.hash_bits <= CRUSHLZBITMAP_MAX_ROW_HASH_BITS && log_depth >= 0 &&
           r.hash_bits <= 18 - log_depth && r.dist_cache_size >= 0 &&
           r.dist_cache_size <= 8 && r.accept_diff >= 0 && r.accept_diff <= 8 &&
           r.scan_window >= 0 && r.scan_window <= CRUSHLZBITMAP_MAX_ROW_SCAN &&
           r.scan_window % 16 == 0 && (r.lookahead == 0 || r.lookahead == 1) &&
           (r.lookahead == 1 || (r.scan_window <= 32 && r.dist_cache_size <= 4));
}

void harness(void)
{
    crushlzbitmap_params p = nondet_params();
    int valid = 0;
    switch(p.strategy) {
    case CRUSHLZBITMAP_STRATEGY_ROW: valid = row_valid(p.p.row); break;
    case CRUSHLZBITMAP_STRATEGY_DP:
        valid = row_valid(p.p.dp.row) && p.p.dp.row.lookahead == 1 &&
                p.p.dp.max_candidates >= 1 && p.p.dp.max_candidates <= CRUSHLZBITMAP_MAX_DP_CANDS &&
                p.p.dp.iterations >= 1 && p.p.dp.iterations <= CRUSHLZBITMAP_MAX_ITERATIONS;
        break;
    case CRUSHLZBITMAP_STRATEGY_BEAM:
        valid = row_valid(p.p.beam.row) && p.p.beam.row.lookahead == 1 &&
                p.p.beam.max_candidates >= 1 && p.p.beam.max_candidates <= CRUSHLZBITMAP_MAX_DP_CANDS &&
                (p.p.beam.beam_width == 1 || p.p.beam.beam_width == 2 ||
                 p.p.beam.beam_width == 4 || p.p.beam.beam_width == 8 ||
                 p.p.beam.beam_width == 16 || p.p.beam.beam_width == 32 ||
                 p.p.beam.beam_width == 64);
        break;
    case CRUSHLZBITMAP_STRATEGY_FAST: {
        crushlzbitmap_fast_params f = p.p.fast;
        valid = f.hash_bits >= CRUSHLZBITMAP_MIN_FAST_HASH_BITS && f.hash_bits <= CRUSHLZBITMAP_MAX_FAST_HASH_BITS &&
                (f.windows == 1 || f.windows == 2 || f.windows == 4 || f.windows == 8) &&
                f.dist_cache_size >= 0 && f.dist_cache_size <= CRUSHLZBITMAP_MAX_FAST_DIST_CACHE &&
                f.accept_diff >= 0 && f.accept_diff <= CRUSHLZBITMAP_MAX_FAST_ACCEPT_DIFF &&
                f.skip_shift >= 0 && f.skip_shift <= CRUSHLZBITMAP_MAX_FAST_SKIP_SHIFT;
        break;
    }
    }
    int rc = zbm_validate_params(&p);
    __CPROVER_assert(rc == (valid ? 0 : ZBM_INVAL), "validation matches public parameter domain");
    __CPROVER_assert(zbm_validate_params(NULL) == ZBM_INVAL, "null params rejected by validator");
    int level = nondet_int();
    crushlzbitmap_params preset;
    int used = crushlzbitmap_params_for_level(level, &preset);
    int clamped = level < CRUSHLZBITMAP_LEVEL_MIN ? CRUSHLZBITMAP_LEVEL_MIN :
                  level > CRUSHLZBITMAP_LEVEL_MAX ? CRUSHLZBITMAP_LEVEL_MAX : level;
    __CPROVER_assert(used == clamped && zbm_validate_params(&preset) == 0,
                      "every clamped level supplies valid params");
    PROOF_REACHABLE(valid && p.strategy == CRUSHLZBITMAP_STRATEGY_ROW, "valid row");
    PROOF_REACHABLE(valid && p.strategy == CRUSHLZBITMAP_STRATEGY_DP, "valid DP");
    PROOF_REACHABLE(valid && p.strategy == CRUSHLZBITMAP_STRATEGY_BEAM, "valid beam");
    PROOF_REACHABLE(valid && p.strategy == CRUSHLZBITMAP_STRATEGY_FAST, "valid fast");
    PROOF_REACHABLE(!valid, "invalid params");
    PROOF_REACHABLE(level == (-2147483647 - 1), "minimum integer level");
    PROOF_REACHABLE(level == 2147483647, "maximum integer level");
}
