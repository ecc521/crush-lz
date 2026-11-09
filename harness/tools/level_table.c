// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Dumps what every level of every codec resolves to, as TSV on stdout:
//
//     codec <TAB> level <TAB> strategy <TAB> field <TAB> value
//
// readme_table.py joins this against a bench run to build the README tables,
// so that the settings, the memory column, the default marker and the merged
// rows for aliased levels all come from the API rather than from memory.
//
// block_size is absent: it is no longer a level setting at all, LZFSE/LZVN's
// DP block is now a fixed 64 KiB for every level (and every strategy).
#include <stdio.h>
#include "crushlzfse.h"
#include "crushlzvn.h"
#include "crushlzbitmap.h"
#include "crushlz4.h"
#include "crushlzmesh.h"

static void row(const char *codec, int level, const char *strategy,
                const char *field, long long value) {
    printf("%s\t%d\t%s\t%s\t%lld\n", codec, level, strategy, field, value);
}

static void lzfse_level(int l) {
    crushlzfse_encode_params p;
    crushlzfse_params_for_level(l, &p);
    int lazy = p.strategy == CRUSHLZFSE_STRATEGY_LAZY;
    int fast = p.strategy == CRUSHLZFSE_STRATEGY_FAST;
    const char *s = fast ? "Fast" : lazy ? "Lazy" : "Optimal";
    if (fast) {
        row("crushlzfse", l, s, "hash_bits", p.p.fast.hash_bits);
        row("crushlzfse", l, s, "min_match", p.p.fast.min_match);
        row("crushlzfse", l, s, "skip_shift", p.p.fast.skip_shift);
        row("crushlzfse", l, s, "max_step", p.p.fast.max_step);
        row("crushlzfse", l, s, "long_table", p.p.fast.long_table);
        row("crushlzfse", l, s, "lazy", p.p.fast.lazy);
    } else if (lazy) {
        row("crushlzfse", l, s, "hash_bits", p.p.lazy.hash_bits);
        row("crushlzfse", l, s, "hash_width", p.p.lazy.hash_width);
        row("crushlzfse", l, s, "lookahead", p.p.lazy.lookahead);
    } else {
        row("crushlzfse", l, s, "search_depth", p.p.optimal.search_depth);
        row("crushlzfse", l, s, "iterations", p.p.optimal.iterations);
        row("crushlzfse", l, s, "reparse", p.p.optimal.enable_reparse);
        row("crushlzfse", l, s, "split_max_blocks", p.p.optimal.split_max_blocks);
        row("crushlzfse", l, s, "hash_bits", p.p.optimal.hash_bits);
        row("crushlzfse", l, s, "store_limit", p.p.optimal.store_limit);
        row("crushlzfse", l, s, "tuple_tax", p.p.optimal.tuple_tax);
        row("crushlzfse", l, s, "max_live_buckets", p.p.optimal.max_live_buckets);
        row("crushlzfse", l, s, "table_search", p.p.optimal.table_search);
    }
    row("crushlzfse", l, s, "_scratch", (long long)crushlzfse_scratch_size(&p));
}

static void lzvn_level(int l) {
    crushlzvn_encode_params p;
    crushlzvn_params_for_level(l, &p);
    int greedy = p.strategy == CRUSHLZVN_STRATEGY_GREEDY;
    int fast = p.strategy == CRUSHLZVN_STRATEGY_FAST;
    const char *s = fast ? "Fast" : greedy ? "Greedy" : "Optimal";
    if (fast) {
        row("crushlzvn", l, s, "hash_bits", p.p.fast.hash_bits);
        row("crushlzvn", l, s, "min_match", p.p.fast.min_match);
        row("crushlzvn", l, s, "skip_shift", p.p.fast.skip_shift);
        row("crushlzvn", l, s, "max_step", p.p.fast.max_step);
        row("crushlzvn", l, s, "long_table", p.p.fast.long_table);
        row("crushlzvn", l, s, "lazy", p.p.fast.lazy);
    } else if (greedy) {
        row("crushlzvn", l, s, "hash_bits", p.p.greedy.hash_bits);
        row("crushlzvn", l, s, "hash_width", p.p.greedy.hash_width);
    } else {
        row("crushlzvn", l, s, "search_depth", p.p.optimal.search_depth);
        row("crushlzvn", l, s, "store_limit", p.p.optimal.store_limit);
        row("crushlzvn", l, s, "hash_bits", p.p.optimal.hash_bits);
        row("crushlzvn", l, s, "pareto_k", p.p.optimal.pareto_k);
    }
    row("crushlzvn", l, s, "_scratch", (long long)crushlzvn_scratch_size(&p));
}

static void zbm_row_fields(int l, const char *s, const crushlzbitmap_row_params *r) {
    row("lzbitmap", l, s, "hash_bits", r->hash_bits);
    row("lzbitmap", l, s, "depth", r->depth);
    row("lzbitmap", l, s, "dist_cache_size", r->dist_cache_size);
    row("lzbitmap", l, s, "accept_diff", r->accept_diff);
    row("lzbitmap", l, s, "scan_window", r->scan_window);
    row("lzbitmap", l, s, "lookahead", r->lookahead);
}

static void zbm_level(int l) {
    crushlzbitmap_params p;
    const char *s;
    if (crushlzbitmap_params_for_level(l, &p) != l) return;
    if (p.strategy == CRUSHLZBITMAP_STRATEGY_FAST) {
        s = "Fast";
        row("lzbitmap", l, s, "hash_bits", p.p.fast.hash_bits);
        row("lzbitmap", l, s, "windows", p.p.fast.windows);
        row("lzbitmap", l, s, "dist_cache_size", p.p.fast.dist_cache_size);
        row("lzbitmap", l, s, "accept_diff", p.p.fast.accept_diff);
        row("lzbitmap", l, s, "skip_shift", p.p.fast.skip_shift);
    } else if (p.strategy == CRUSHLZBITMAP_STRATEGY_ROW) {
        s = "Row";
        zbm_row_fields(l, s, &p.p.row);
    } else if (p.strategy == CRUSHLZBITMAP_STRATEGY_BEAM) {
        s = "Beam";
        zbm_row_fields(l, s, &p.p.beam.row);
        row("lzbitmap", l, s, "max_candidates", p.p.beam.max_candidates);
        row("lzbitmap", l, s, "beam_width", p.p.beam.beam_width);
    } else {
        s = "Dp";
        zbm_row_fields(l, s, &p.p.dp.row);
        row("lzbitmap", l, s, "max_candidates", p.p.dp.max_candidates);
        row("lzbitmap", l, s, "iterations", p.p.dp.iterations);
    }
    row("lzbitmap", l, s, "_scratch", (long long)crushlzbitmap_scratch_size(&p));
}

/* Two sections rather than one, because the two modes are two upstream
 * encoders with a knob each: printing both knobs on every row would show a
 * column that does nothing for half the ladder. */
static void lz4_level(int l) {
    crushlz4_encode_params p;
    if (crushlz4_params_for_level(l, &p) != l) return;
    if (p.mode == CRUSHLZ4_MODE_FAST) {
        row("crushlz4", l, "Fast", "acceleration", p.acceleration);
        row("crushlz4", l, "Fast", "_scratch", (long long)crushlz4_scratch_size(&p));
    } else {
        row("crushlz4", l, "Hc", "hc_level", p.hc_level);
        row("crushlz4", l, "Hc", "_scratch", (long long)crushlz4_scratch_size(&p));
    }
}

/* No _scratch row: the LZMESH encoder allocates its working buffers itself,
 * so the scratch size would understate its memory. */
static void lzmesh_level(int l) {
    crushlzmesh_params p;
    crushlzmesh_params_for_level(l, &p);
    if (p.strategy == CRUSHLZMESH_STRAT_LAZY) {
        row("lzmesh", l, "Lazy", "hash_bits", p.hash_bits);
        row("lzmesh", l, "Lazy", "min_match", p.min_match);
        row("lzmesh", l, "Lazy", "max_depth", p.max_depth);
    } else {
        row("lzmesh", l, "Optimal", "hash_bits", p.hash_bits);
        row("lzmesh", l, "Optimal", "min_match", p.min_match);
        row("lzmesh", l, "Optimal", "search_depth", p.search_depth);
        row("lzmesh", l, "Optimal", "lookahead", p.lookahead);
        row("lzmesh", l, "Optimal", "iterations", p.iterations);
    }
}

int main(void) {
    printf("# codec\tlevel\tstrategy\tfield\tvalue\n");
    for (int l = CRUSHLZFSE_LEVEL_MIN; l <= CRUSHLZFSE_LEVEL_MAX; l++) lzfse_level(l);
    for (int l = CRUSHLZVN_LEVEL_MIN; l <= CRUSHLZVN_LEVEL_MAX; l++) lzvn_level(l);
    for (int l = CRUSHLZBITMAP_LEVEL_MIN; l <= CRUSHLZBITMAP_LEVEL_MAX; l++) zbm_level(l);
    for (int l = CRUSHLZ4_LEVEL_MIN; l <= CRUSHLZ4_LEVEL_MAX; l++) lz4_level(l);
    for (int l = CRUSHLZMESH_LEVEL_MIN; l <= CRUSHLZMESH_LEVEL_MAX; l++) lzmesh_level(l);
    return 0;
}
