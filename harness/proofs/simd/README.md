# Native SIMD in the decoder proofs

Most registered proofs build with `CRUSH_SIMD_PORTABLE`. The LZBITMAP decoder
targets are also registered on the shipping NEON (`_neon`) and SSE (`_sse`)
branches of `crush_simd.h` (`run.sh`, `ZBM_NEON_DEFS`/`ZBM_SSE_DEFS`): every
intrinsic a decoder calls is replaced by a C model, and each model is checked
against the hardware.

## Trust boundary

Proved or checked here: which intrinsics and builtins decoder code reaches
(`check_intrinsics.py`), what each one does (the models, validated against
hardware by `harness/simd_validate`), and that the native wrappers equal the
portable ones (`run_equiv.sh`).

Still trusted: the compiler's code generation for C and for each intrinsic
call, auto-vectorisation, `memcpy`/`memset` lowering, and CBMC's own C
semantics. The x86 models have been validated only under Rosetta, an
emulator, not on Intel hardware.

No SIMD-computed value in the decoders reaches a pointer, length, loop bound
or index. The only decoder intrinsics are LZBITMAP's blend and copy wrappers
in `crush_simd.h`.

## Files

| File | What |
|---|---|
| `check_intrinsics.py` | Per shipping configuration (arm64; x86-64-v3; x86-64 with `CRUSH_SIMD_PORTABLE`), lists every intrinsic, builtin, asm statement and vector operator in each decoder-reachable function, from clang's AST and a cross-unit call graph. Fails on anything not modelled. Encoder-only uses are counted, not checked. |
| `neon_model.h`, `sse_model.h` | Models with prefixed names (`M_vqtbl1_u8`, `M_mm_shuffle_epi8`, ...) over `struct { uint8_t b[N]; }`. Loads and stores touch one byte at a time, so CBMC checks the exact footprint, and are straight-line, so loop contracts never see them. |
| `include/` | Shadow `arm_neon.h`, `emmintrin.h`, `tmmintrin.h`, `smmintrin.h`, `nmmintrin.h`, `immintrin.h`, `cpuid.h`. Put first on the include path. Modelled intrinsics map to the models; every other intrinsic in the unit is declared without a body so encoder code type-checks, and a proof that reaches one fails. |
| `equiv/`, `run_equiv.sh` | CBMC: the NEON and SSE wrappers on the models equal the portable wrappers. |
| `native_wrap.c` | The source of every native `run.sh` target: includes the harness named by `NATIVE_TARGET` and fails to compile unless the native branch was taken through the shadow headers, LP64, little-endian, signed `char`. |
| `check_bmi2_clone.py` | The plain and `target("bmi2")` expansions of `lzfse_decode_hot.h` are token-identical. |

## Models

| NEON | SSE | Semantics |
|---|---|---|
| `vld1_u8`, `vld1q_u8` | `_mm_loadl_epi64`, `_mm_loadu_si128` | read `p[0, 8)` or `p[0, 16)`, no alignment; `MOVQ` zeroes lanes 8..15 |
| `vst1_u8`, `vst1q_u8` | `_mm_storel_epi64`, `_mm_storeu_si128` | write `p[0, 8)` or `p[0, 16)` |
| `vcombine_u8` | `_mm_unpacklo_epi64` | low 8 lanes of each |
| `vqtbl1_u8` | `_mm_shuffle_epi8` | TBL: index of 16 or more gives 0. PSHUFB: bit 7 gives 0, else `t[i & 15]` |
| | `__get_cpuid_count` (x86-64 portable only) | arbitrary answer; outputs untouched when it returns 0 |

The scalar builtins (`__builtin_popcount`, `clz`, `ctz`, `expect`, fortified
`memcpy`/`memset`, `__atomic_load_n`/`store_n`) use CBMC's built-in semantics;
`simd_validate` checks the bit counts against table references.

TBL, PSHUFB and the portable branch (`sel & 15`) disagree on selectors 16 and
up. `equiv/equiv.c` proves every selector in `zbm_blend_row` is below 16, and
that each is the literal index or the lane's own baseline lane. Every decoder
call loads its selector from that table: `zbm_blend8` and
`zbm_patch_literals` as `zbm_blend_row[bmp]`, `ZBM_RESOLVE` and the
per-block loop as `rowbase + (bmp << 4)` with a `uint8_t` `bmp`.

## Running

```sh
harness/proofs/simd/check_intrinsics.py        # host clang; -v lists encoder uses
harness/proofs/simd/check_bmi2_clone.py
docker run --rm -v "$PWD:/work" -w /work --entrypoint harness/proofs/simd/run_equiv.sh \
  crushlz-proofs:6.11.0
harness/proofs/run.sh zbm_decode_pairs_neon zbm_decode_pairs_sse   # in the proof image
harness/simd_validate/run.sh                   # SIMD_VALIDATE_EXHAUSTIVE=1 for the long run
```

`replay.py run --only checks` runs the first three as replay jobs.

`_neon` targets need an aarch64 image; `_sse` targets forge the x86-64-v3
predefined macros on any host. Every CBMC target passes `-fsigned-char`:
`char` is signed on Apple arm64 and x86-64 but unsigned under goto-cc's
default arm64 Linux configuration. For a native target `run.sh` first runs a
preflight (`gcc -E -H` include trace: every intrinsic header must resolve into
`include/`; `gcc -E -dM`: no `CRUSH_SIMD_PORTABLE`), recorded beside the log as
`.preflight.txt` and `.intrinsic-headers.txt`, and after linking it fails if
any function reachable from the harness lacks a body and is not replaced by a
contract, so an unmodelled intrinsic cannot silently return anything
(`.unmodelled.txt`, `.models.txt`).

## Contracts

The decoder's SIMD wrappers carry one set of CBMC contracts on all three
branches, written once as macros at the top of `crush_simd.h`:
`ZBM_BLEND8_CONTRACT` (`zbm_blend8_sel`), `ZBM_BLEND8_ROW_CONTRACT`,
`ZBM_SEL_LOAD_CONTRACT` and `ZBM_CPY_CONTRACT(8|16|32)`. Each is enforced per
branch (`zbm_blend8_sel`, `zbm_blend8_row`, `zbm_sel_load`, `zbm_cpy8/16/32`
and their `_neon`/`_sse` variants), the native ones against the models, so a
composed target replaces a wrapper by the same contract on every branch.
`zbm_copy_fwd_neon`/`_sse` replace the copies; the blend targets replace the
blends exactly as the portable compositions do. The NEON `zbm_sel_load` and
`zbm_blend8_sel` are `static inline` functions so that they can carry
contracts.

The selector lemma reaches values through `zbm_blend8_correct_neon`/`_sse`:
for every bitmap and input byte, the native `zbm_blend8`, `zbm_blend8_row`
and in-place `zbm_blend8_sel` on a selector loaded from the table produce the
literal/copy bytes, and the pair-loop row `zbm_blend_row[0] + (bmp << 4)` is
proved to be the pointer `zbm_blend_row[bmp]`. Raising one table selector to
137 (correct under `sel & 15`, zero under TBL and PSHUFB) is caught on both
native targets. The literal count the pair loop reads through `rowbase` is
used by value: `zbm_decode_pairs` (all branches) rejects a table count of 17.

## Results

From the most recent replay in the CBMC 6.11.0 aarch64 image:

* 70/70 LZBITMAP decoder targets pass with every reachability goal
  witnessed: 23 portable, 23 `_neon`, 23 `_sse` and `zbm_table_correct`.
  The compositions take about as long natively as portable once the
  wrappers are replaced by contract (`zbm_copy_fwd_neon` takes about 1
  minute; executing the byte models directly takes about 55).
* 69/69 mutants caught, including `zbm_table_selector_high_neon`/`_sse`
  (pass under portable semantics) and the native wrapper overread and
  overwrite mutants.
* `check_intrinsics.py`: all three configurations pass (80, 82 and 85
  decoder-reachable functions; arm64 gained `zbm_sel_load` and
  `zbm_blend8_sel` as functions).
* `run_equiv.sh`: 1961/1961 properties; the unrestricted-selector run fails
  exactly the NEON/SSE versus portable comparisons, as required.
* `check_bmi2_clone.py`: identical, 1191 tokens (1646 with `LZFSE_PROOF`).
* Frama-C footprints: NEON 119/119 (five mutants), SSE 101/101 (one mutant),
  every mutant rejected by a goal some prover reported unknown.
* `simd_validate`, exhaustive: arm64 (M5) 16,474,439,129 checks and
  x86-64-v3 under Rosetta 16,475,487,627 checks, no failures.

## Notes for proof authors

* Empty asm register pins (`__asm__("" : "+r"(x))` in `zbm_decode_pairs` and
  `zbm_handle_compressed_chunk`, aarch64 only): goto-cc keeps them as an
  `OTHER asm` instruction and CBMC executes it as a no-op. The operands are
  neither havocked nor written, which matches the hardware: an empty
  template runs no instruction.
* CBMC 6.11 reads the exact table count through
  `zbm_blend_row[0] + (bmp << 4)`. A minimal harness confirms it, and the
  count mutation above is caught, so the composed proofs use the table
  values. `zbm_blend8_correct` also proves the pointer identity and reads
  through the direct index.
