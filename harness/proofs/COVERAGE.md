# Memory-safety coverage

This is the inventory of what the proofs establish, codec by codec, and what
each result trusts. [README.md](README.md) explains how the proofs work.

## Scope

In scope: our C decoders and encoders for LZ4, LZVN, LZFSE and LZBITMAP,
their framing, scratch ownership and public C APIs, including the chained and
chunk APIs. The property is memory safety: no out-of-bounds access, no
undefined behavior, loops that terminate, and the documented status codes.
Output bytes are proved only for the finite helpers named below.

Out of scope:

- **LZMESH**, both the C sources and the Rust crate. No proof target covers
  it.
- The vendored upstream LZ4 compressor. Its capacity, scratch and
  return-value contracts are trusted (`TRUSTED` in `inventory.py`).
- Rust safe wrappers, FFI, worker ownership and native dispatch. These are
  reviewed and tested, not proved. The C-source proofs say nothing about
  compiled binaries or Rust behavior.
- Whole-stream byte correctness of any decoder or encoder. That is covered
  by fuzzing and the conformance suite.

## What counts as evidence

A registered target, a passing run and a proof of the shipping
implementation are different claims. A result counts only when verification
completes, every reachability witness is found, and the applicable mutants
are rejected. A timeout, an incomplete log or an unwitnessed goal does not
count. Reduced sizes, changed constants, omitted operations or stubbed
project functions cannot stand in for the shipping code.

Some registered CBMC targets check a reduced configuration and are not
counted as shipping evidence (`LEGACY_TARGETS` in `inventory.py`). In each
case a Frama-C proof covers the shipping body:

| CBMC target | Configuration it checks | Shipping proof |
|---|---|---|
| `lzfse_decode_literals` | `LZFSE_PROOF`: 64-state tables, no bulk loop, copies replaced by assertions | `frama/lzfse_literals_native.py` |
| `lzfse_decode_lmd` | `LZFSE_PROOF`: reduced tables and block limits | `frama/lzfse_lmd_native.py` |
| `emit`, `emit_literal` | `LZVN_FAST_COPY`: runs capped, copies asserted without writes | `frama/lzvn_match.py`, `frama/lzvn_literal.py` |
| `lzvn_decode` | Portable switch, shipped only without labels-as-values (MSVC) | `frama/lzvn_decode_native.py` |

Three registered CBMC targets do not complete within 48 GiB and are not
counted: `emit_literal_exact`, `lzvn_encode_greedy_wide` and
`lzvn_encode_greedy_wide_native`. The Frama-C proofs in the table rows below
cover those bodies.

## Registry

```sh
python3 harness/proofs/inventory.py > coverage.json
```

prints the CBMC registry from `run.sh` (256 targets), each harness's
assumptions, which target enforces each contract, every replaced contract
without an enforcing target, and the Frama-C scripts (63). It counts a
contract as enforced only when a results file written by
`replay.py collect` matches the current proof tree hash. No results file is
checked in, so run a replay first:

```sh
python3 harness/proofs/replay.py run --budget 56
python3 harness/proofs/replay.py collect --out harness/proofs/results-DATE.json
```

Every contract that a CBMC target replaces is enforced by another registered
target, modelled in `TRUSTED`, or proved by a Frama-C script listed in
`EXTERNAL_PROOFS`. The dispatcher-only contracts list
(`UNENFORCED_DISPATCH`) is empty.

Goal and property counts below are from the most recent full replay. They
move when the source changes. Each Frama-C runner checks a minimum goal count
and requires every goal to be proved, so a count is a sanity check, not part
of the claim.

## Decoders

| Area | Proved | Trusted or not covered |
|---|---|---|
| LZ4 | `crushlz4_decode_buffer` is memory safe and terminates for every source and destination size up to the 2^48 object bound, including NULL `dst` with any `dst_size`. It never reports `*out_len > dst_size` and returns only documented status codes. Three composed CBMC targets: `lz4_copy_match`, `lz4_decode_block`, `lz4_decode`. All 16 decoder mutants are caught. | Source and destination are separate objects. `decode_block` requires non-aliasing and `crushlz4.h` documents it; in-place decoding is outside the API. |
| LZBITMAP | `zbm_decode`, `zbm_handle_chunk`, `zbm_handle_compressed_chunk` and `zbm_decode_pairs`, with their 19 dependencies down to the blend, selector-load and copy wrappers, on three configurations: portable, native NEON (`_neon`) and native SSE (`_sse`). Malformed streams included. Source and destination may be disjoint ranges of one allocation, in either order. `out_len` may be NULL, its own object, or a separate range of any allocation. `zbm_blend8_correct` and `zbm_table_correct` prove exact blend bytes and table extraction. NEON and SSE wrapper footprints are proved in Frama-C (`frama/zbm_neon_footprints.py`, `frama/zbm_sse_footprints.py`). | Native intrinsic semantics are C models validated against hardware ([simd/README.md](simd/README.md)). Compiler code generation for intrinsics. Whole-stream output bytes. |
| LZVN | `frama/lzvn_decode_native.py` proves the shipping computed-goto body (1,775 goals), including termination. The generator checks the 256-entry `opc_tbl`, the four dispatch sites and three backedges, and that no other label address or computed goto remains. The same run proves a wrapper whose contract is translated clause by clause from the CBMC `LZVN_DECODE_CONTRACT`, so callers' CBMC proofs consume a proved contract. `lzvn_decode_resume` proves unbounded re-entry. `lzvn_decode_buffer` and `crushlzvn_decode_buffer` enforce their contracts, including nullable empty buffers and exhausted output. Shared-allocation source and destination spans are covered. | The CBMC-to-ACSL primitive table and CBMC's object-size bound. The MSVC-only portable switch commits different state on two failure returns. A call truncated mid-op returns a position that is safe to re-enter but is not a semantic resume point, as the header documents. Compiled dispatch is outside both tools. |
| LZFSE frame | `lzfse_decode_frame` proves the unbounded shipping frame loop at full table sizes, with symbolic source and destination objects and a resumable entry state. Its rank is `2 * (src_end - src) + (block_magic != 0)`. `frama/lzfse_frame_step_bridge.py` proves that the frame's literal and LMD contracts follow from the shipping-step contracts for both 32- and 64-byte copy margins. Builder contracts include their real decoder-table write footprints. All frame mutants are caught. | The frame contract interface is `lzfse_frame_interface.h`; its premises are stated there. |
| LZFSE literals | `frama/lzfse_literals_native.py` proves the shipping 64-bit bulk and checked loops for every declared literal count (625 goals), with the ARM lookahead configuration as a second run. `frama/lzfse_literals_native32.py` proves the 32-bit checked path (192 goals). Both use exact FSE primitive contracts. | A valid literal decoder table and starting states are preconditions; the table rows below discharge them. |
| LZFSE L/M/D | `frama/lzfse_lmd_native.py` proves the shipping LMD loop (1,209 goals), including termination and resume, in the baseline and ARM lookahead configurations. A separate result check proves that `DST_FULL` fills the output and preserves the starting-state predicate for the next call. `lzfse_lmd_resume` proves the pending L/M branch with copy helpers replaced by their proved contracts. `lzfse_lmd_distance_check` proves the shipping one-compare distance check equal to the two-compare form WP verifies. | WP cannot reason through the sign-extended wrap in the shipping distance check, so the script substitutes the two-compare form; the CBMC target ties them together. |
| FSE tables and bitstream | 64- and 32-bit pull, initialization, checked refill, unchecked refill and ARM64 lookahead refill are exact CBMC targets; refills load only bytes inside the input. `lzfse_decoder_tables_zero` proves the initializer zeroes every table entry. `fse_literal_table_valid` and the `fse_{l,m,d}_table_coverage` and `_preserve` targets follow an arbitrary row through the shipping builders from zeroed storage or a previous valid table. `fse_value_symbol_bounds`, `fse_value_symbol_row` and `fse_value_unpack` prove symbol limits, row arithmetic and the eight-byte store layout. `lzfse_table_builder_bridge` and `lzfse_table_predicate_bridge` connect builder results to the frame's table-validity predicate. | The literal builder target imports the sum-loop prefix relation proved by `frama/fse_table_prefix.py`, a cross-tool step. The literal preservation targets need a 16 GiB memory cap. |
| LZFSE buffer APIs | `crushlzfse_decode_buffer`, `lzfse_decode_buffer_with_scratch` and `lzfse_decode_buffer` for any object size up to the model bound, with allocation failure enabled, NULL and zero-length buffers, shared-allocation source and destination spans, and an `out_len` in the same allocation. | |
| LZFSE declared length | `frama/lzfse_declared_len.py` proves the native framing loop with no block-count cap (187 goals). `lzfse_declared_len` and `lzfse_declared_len_alias` cover the CBMC side; header-size, unpack and short-input targets prove the header components. | Integer overflow of the declared total is outside the spatial guarantee. Rust sizing callers are reviewed, not proved. |

### LZBITMAP decoder alias geometry

The documented contract (`docs/lzbitmap-format.md`) keeps source,
destination and the length result in separate storage ranges.

- `crushlzbitmap_decode_buffer`: `src` is NULL or `src_size` readable bytes.
  `dst` is NULL (size probe, any `dst_size`) or `dst_size` writable bytes.
  They are separate allocations or disjoint ranges of one allocation, in
  either order (`zbm_any_buffers`, with a witness that decodes with both in
  one object). The decoder takes no scratch.
- Inside, `ZBM_DISJOINT` states the separation: the frame loop invariant,
  `zbm_handle_chunk`, `zbm_handle_compressed_chunk`, `ZBM_STATE_OK`,
  `zbm_decode_pairs` and `zbm_patch_literals` require the chunk (or literal
  span) and the remaining output to be disjoint. `zbm_copy_fwd` accepts a
  source before or after the destination.
- History reads (`dest - period`, `dest - prewritten`) stay inside the output
  written so far. The blend base is 8 or more bytes before `dst` (pair and
  block loops, `period >= 8`) or `dst` itself (`zbm_patch_literals`). The
  wrapper contract allows any overlap of base and `dst`; the in-place case
  has a reachability witness and an exact-value proof on every branch.

## Encoders

| Area | Proved | Trusted or not covered |
|---|---|---|
| LZ4 wrapper | Header, alignment, query and API targets; `lz4_encode_allocation` proves allocation, scratch alignment and the encode contract. `frama/lz4_frame.py` proves the shipping framing loop (738 goals). Short-scratch, header-overrun, bound-floor, no-capacity and no-progress mutants are rejected. | The upstream LZ4 compressor. |
| LZVN emitters and greedy | `frama/lzvn_literal.py` and `frama/lzvn_match.py` prove the native literal and generic match emitters over all supported lengths, with CBMC footprint targets for their loads, stores and wide copies. `frama/lzvn_greedy_loop.py` proves the shipping greedy loop and its seven native width wrappers (1,066 goals). `lzvn_encode_greedy_wide_buffer`, `lzvn_encode_literal_only_buffer` and the end-marker target pass CBMC. `crushlzvn_scratch` proves the greedy history arrays and the optimal parse's arrays are ordered, disjoint ranges of one scratch allocation. | Correspondence between the Frama-C greedy-loop contract and the CBMC contract it replaces is checked by review. |
| LZVN fast | `lzvn_encode_fast_buffer` (CBMC). `frama/lzvn_fast_loop.py` proves the shipping fast loop across all 14 modes. `crushlzfse_fast_find`, `lzvn_fast_skip_step`, `frama/lzvn_fast_back.py` and `frama/lzvn_fast_best.py` prove its search helpers. | |
| LZVN optimal | `lzvn_encode_optimal_buffer_pareto` (CBMC) composes `frama/lzvn_zopt_build_candidates.py`, `frama/lzvn_pareto_run_dp.py`, `frama/lzvn_pareto_total_cost.py` and `frama/lzvn_zopt_commit.py`, each a proof of the shipping body. `lzvn_pareto_insert` is proved in both tools. | |
| LZVN public API | `crushlzvn_encode_buffer` enforces `crushlzvn_encode_buffer_advanced` across the public and advanced APIs, composing every strategy above, with a mutant for caller scratch/table overlap. `crushlzvn_params` and `crushlzvn_encode_bound` cover parameters and bounds. | |
| LZFSE params, bounds and scratch | Parameter, scratch, encode-bound and raw-block targets link the real `crushlzvn.c`. `lzfse_encode_init` enforces its contract. The encode-buffer target covers source sizes 0 to 65,536 and output capacities 0 to 65,552. | |
| LZFSE fast, lazy and optimal | `crushlzfse_encode_base_fast` and `crushlzfse_encode_base_lazy` (CBMC) over all modes, lookaheads and hash widths, with `frama/lzfse_fast_loop.py` and `frama/lzfse_lazy_loop.py` proving the shipping loops. `lzfse_encode_base` composes `frama/lzfse_zopt_build_candidates.py`, `frama/lzfse_zopt_find_splits.py`, `frama/lzfse_zopt_commit.py` and `frama/lzfse_run_dp_range.py`. `lzfse_encode_finish`, `lzfse_backend_match`, `lzfse_backend_literals`, `lzfse_push_match`, `lzfse_encode_matches` and `frama/lzfse_push_lmd.py` prove the backend. `crushlzfse_encode_buffer` composes the whole buffer API. | |
| LZFSE chained | `crushlzfse_encode_buffer_chained` and `load_seed`: NULL stats, valid seeds, arbitrary corrupted stats, internal and caller scratch, and error paths. | |
| LZBITMAP framing and APIs | `frama/zbm_frame.py` proves the framing loop (147 goals). `crushlzbitmap_encode_chunk` and `crushlzbitmap_encode_buffer` (CBMC, with allocation failure) and `zbm_compress_single_chunk` prove the chunk and buffer APIs. `zbm_encoder_params`, `zbm_encoder_scratch`, `zbm_encoder_magic`, `zbm_encoder_stored` and `zbm_encode_bound` prove parameters, scratch layout, the stream header, stored fallback and the worst-case envelope. | `zbm_compress_single_chunk` is proved against a model chunk builder (`mock_build_chunk` in its harness) that succeeds, ties, falls back after a partial attempt, or fails. **The shipping row, fast, DP and beam builders are not proved to meet that model.** |
| LZBITMAP shared writers | Period, bitmap and fused metadata writers ([frama/README.md](frama/README.md)); the selector writer at every capacity (`frama/selector_tight.py`); the literal writer with supplied and recomputed totals (`frama/literal_writer.py`, `frama/literal_recompute.py`); the trailing table (`frama/trailing_table.py`); and the ordinary metadata caller that composes them (`frama/build_metadata.py`). About 50 CBMC `zbm_encoder_*` targets prove the leaf helpers these scripts import. | Each writer's preconditions (initialized active fields, period-count shape, zero reserved-key counts, written-count headroom, separated buffers) are not established from the strategy callers. |
| LZBITMAP strategy components | Fast tail producer and loop (`frama/fast_tail.py`, `frama/fast_compose.py`, `frama/tail_counts.py`), fast metadata-2 writer (`frama/fast_meta2.py`), count initialization and folding, block commit and bitmap append, top-table selection, snapshot save and restore, and the trial scorer (`frama/score_trial.py`, `frama/snapshot_values.py`). `zbm_fast_skip` proves the fast loop's skip marker. | The search loops of each strategy and their composition with the writers. Whole LZBITMAP encoder memory safety is therefore not proved. |

LZBITMAP encoder helpers with exact-value proofs: `zbm_diff_bitmap_correct`,
`zbm_pack8_correct`, `zbm_encoder_nibbles_correct`,
`zbm_encoder_vector_nibbles_correct`, `zbm_encoder_key` and the
`*_values` targets. These compare the shipping code with an independent
model for every input in a finite domain.

The LZBITMAP encoder strategies and the Rust encoder entry points have been
source reviewed and are fuzzed. Review and fuzzing do not close the proof
obligations above.
