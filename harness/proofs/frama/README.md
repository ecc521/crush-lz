# Frama-C WP proofs

Each Python script here is one Frama-C WP target. It extracts the shipping
function from the codec source, adds ACSL annotations, runs WP, and checks
the result with `wp_common.py`: a clean exit, no unexpected warnings, at
least the expected number of goals, and every goal proved. `--mutants` also
runs the script's unsafe source variants, each of which must leave a goal
unproved. [../COVERAGE.md](../COVERAGE.md) lists what each script proves.

Build the image from this directory's Dockerfile and run from the repository
root. Its default entry point is `period_metadata.py`; pass
`--entrypoint python3` and a script path to run any other:

```sh
docker build -t crushlz-frama-period:bookworm harness/proofs/frama
docker run --rm -v "$PWD:/work" -w /work --entrypoint python3 \
  crushlz-frama-period:bookworm harness/proofs/frama/lzvn_decode_native.py --mutants
```

The image uses Debian bookworm's Frama-C 25.0-beta (Manganese), Why3 1.5, CVC4
1.8 and Z3 4.8.12. Logs and generated sources go to
`harness/build/proofs-frama-*`.

## Metadata writers

Three LZBITMAP encoder scripts prove the shipping metadata writers. They
cover arbitrary period-byte counts in `[0, 2]`,
every block count in `[0, 4096]`, and arbitrary selector-table bytes.

| Script | Coverage | WP obligations |
|---|---|---|
| `period_metadata.py` | Period metadata, including bulk stores and the exact-capacity fallback | 148 |
| `bitmap_metadata.py` | Bitmap metadata, including its real selector builder and exact-capacity fallback | 171 |
| `fused_metadata.py` | Fused period/bitmap stores, exact scalar period summation, overlapping relocation and header writes | 162 |

Every obligation must pass. The totals include shared bookkeeping and trial
initialization helpers; they are not counts of distinct functions. Each writer
keeps successful cursors in their original allocation and within capacity.
Failure or refusal leaves the destination cursor and written count unchanged.
The annotated loops terminate. With written-count headroom for the maximum
component extent (two, one or three bytes per block), the written-count
increment equals the destination advance. Every result also retains one
allocation and an ordered destination/end cursor pair. This does not establish byte correctness or
whole-encoder safety.

```sh
docker run --rm -v "$PWD:/work" crushlz-frama-period:bookworm --mutants
docker run --rm -v "$PWD:/work" --entrypoint python3 crushlz-frama-period:bookworm \
  harness/proofs/frama/bitmap_metadata.py --mutants
docker run --rm -v "$PWD:/work" --entrypoint python3 crushlz-frama-period:bookworm \
  harness/proofs/frama/fused_metadata.py --mutants
```

Logs and generated sources go to
`harness/build/proofs-frama-{period,bitmap,fused}`.

The bitmap and fused targets use consequences of the registered CBMC
`zbm_encoder_key` proof: the key's exact arithmetic form, its high/low bytes
and its bound for period counts at most two. Its harness explicitly checks
these consequences. Replay that prerequisite whenever the source changes:

```sh
docker run --rm -v "$PWD:/work" crushlz-proofs:6.11.0 \
  sh harness/proofs/run.sh zbm_encoder_key
```

The targets retain source slices containing the actual writer bodies, with
loop annotations and verified read-only prefix bookkeeping. For the fused
writer, the actual scalar summation body also receives the bookkeeping array
as an extra read-only proof parameter. Its computed total is proved equal to
the final prefix. No prefix-sum axioms or alternate writer algorithms are
assumed. Unrelated functions in the slices are not WP targets.

WP uses the default Typed memory model without unsafe cast options. Pointer
validity within the state allocation alone may permit a read into a neighboring
member, so the bitmap and fused targets additionally assert the actual table
and selector-array index expressions' member-array bounds.

The external footprint models are standard `memcpy` specialized to the
writer's two-byte copy from a local word, and standard `memmove` for the fused
writer's overlapping byte span. All required source/destination validity and
`memcpy` separation conditions are proved at calls. The models permit writes
only to destination bytes and do not promise byte values. The library,
compiler and proof toolchains remain trusted. As in the CBMC suite, native
SIMD helper semantics remain a review assumption: WP selects the portable
scalar period total; the existing CBMC target checks native vector read
footprints. Native SIMD arithmetic is not separately solver-proved here.

The state must be valid. The output span must be disjoint from the whole
state or contained within its metadata scratch array. It must also be disjoint
from the cursor/count fields and the bitmap, period, selector and selector-table arrays
these writers access. Output may occupy `state->meta_scratch`, as trial scoring
does. Each target also proves that the exact three shipping trial-initialization
statements establish output independence, cursor validity and the 16 KiB
capacity. The fused header must be valid and disjoint from state/output.
Both destination cursors belong to one live allocation; a zero-capacity cursor
may be one past its end. Capacity is at most `2^48`; the platform is LP64 with
eight-bit bytes and little-endian keys.

There are 13 deliberately unsafe WP variants: three period, five bitmap and
five fused. Each must leave unresolved proof obligations. They check inadequate
capacity, extra writes or advances, selector-array/table bounds, and an oversized
relocation source. These are negative deductive-proof checks, not reported SMT
counterexamples. Eight period and nine bitmap executions of the unmodified
full source additionally witness boundary contracts under ASan/UBSan. Fourteen
fused cases exercise external and internal scratch destinations, in both
portable and native builds. These finite executions do not replace proofs.

Sharper safe bulk conditions are also proved: `2 * bmp_cnt <= room` for periods
(147 obligations), and `bmp_cnt <= room` for bitmaps (170 obligations). The last
speculative store begins no later than `2 * (bmp_cnt - 1)` or `bmp_cnt - 1`,
respectively.

The selector, literal and trailing-table writers and the metadata caller
that composes them have their own scripts here. The LZBITMAP strategy
builders are not proved to establish these writers' preconditions; see
[../COVERAGE.md](../COVERAGE.md).
