# Benchmark and test harness

| directory | contents |
|---|---|
| `core/` | Engine registry and decoder verification |
| `bench/` | Benchmark executable |
| `conformance/` | Correctness, concurrency and parameter tests |
| `fuzz/` | Standalone and libFuzzer targets |
| `proofs/` | CBMC and Frama-C proofs of memory safety and termination |
| `tools/` | Parameter sweeps, probes and table generation |

```bash
make -C harness          # Benchmark and conformance binaries
make -C harness check    # Full conformance suite
make -C harness probe    # Parameter sweeps, level_table and macOS probes
make -C harness proofs   # CBMC proofs (Frama-C: see proofs/README.md)
make -C harness clean
```

`flags.mk` defines C compiler flags for harness and crate Makefile builds.
Cargo and CMake maintain their own build settings.

## Engine registry

`core/engines.c` registers encoders, supported levels, decmpfs types and
decoders. Inspect the available engines and decoder counts with:

```bash
harness/build/bench --list
```

Engines are grouped by output format. On macOS, the harness includes Apple's
`libcompression` encoders and decoders. `zstd` and `zopfli` are optional
reference engines; missing libraries are listed as unavailable.

## Decoder verification

The harness decodes each encoded block with every registered decoder for
that format and compares the results with the original input.
A decoder count of one checks round-trip consistency; independent decoders
also check format compatibility. Release checks require Apple's decoders.

## Benchmark

```text
harness/build/bench <manifest> [options]

  --engines LIST    Comma-separated name[:level] entries
                    Default: all available engines at their default levels
  --block N         Input block size in bytes (default 65536)
  --decode-reps N   Decode repetitions per block (default 3)
  --jobs N          Worker threads, partitioned by file (default 1)
  --sequential      One corpus pass per engine
  --list            Print the registry and decoder counts
```

The manifest contains one file path per line. Each file is split into input
blocks, including a final partial block. LZFSE and LZVN reject input blocks
larger than 64 KiB.

`crushlzfse-chain` is `crushlzfse` with each file's blocks chained through
`crushlzfse_encode_buffer_chained`, starting afresh at every file. It runs
only when named, e.g. `--engines crushlzfse:9,crushlzfse-chain:9`.

Use `--sequential` for published throughput measurements. The default
interleaves engines per block, allowing later encoders to reuse cached input.
Exit status 2 indicates a decoder verification failure.

```bash
harness/build/bench manifest.txt --sequential --engines crushlzfse:8,apple-lzfse,zstd:19
```

Example output:

```
blocks: 120   block size: 65536   files: 120

ENGINE             ENCODER       RATIO   SAVED%    ENC B/s DEC B/s(ours) DEC B/s(apple)  REFUSED  FAILED
crushlzfse:8       ours         2.3231   56.95%       2.5M        2104M        2710M        0       0
apple-lzfse        APPLE        2.1957   54.46%     233.4M        2104M        2710M        0       0
zstd:19            reference    2.3292   57.07%       8.1M        2452M            -        0       0

BEST-OF-N               RATIO     SAVED%   (pool: 2 shippable, verified engines)
per block              2.3527     57.50%
per file               2.3527     57.50%   <- what decmpfs can reach (one type per file)

MARGINAL VALUE         BYTES LOST    OF BEST      WINS OF BLOCKS
crushlzfse:8                12154     0.364%        90    75.0%
apple-lzfse                     0     0.000%         2     1.7%
zstd:19                         -            (no decmpfs type; not selectable)
```

| field | meaning |
|---|---|
| `RATIO` | Input size divided by stored size |
| `SAVED%` | Percentage reduction in size |
| `ENC B/s`, `DEC B/s` | Encode and decode throughput; K/M/G suffixes use decimal units |
| `REFUSED` | Blocks the encoder rejected (returned 0) |
| `FAILED` | Blocks that failed decoder verification; excluded from ratio calculations |
| `BEST-OF-N per block` | Smallest verified output selected independently for each block |
| `BEST-OF-N per file` | Smallest verified output using one compression type per file |
| `MARGINAL VALUE` | Additional bytes required if an engine is removed from the selection pool |

The selection pool includes only verified engines with a decmpfs type.
Marginal value assumes the compression type is selectable; for a fixed format,
compare encoders of that format directly. Failed rows should not be used for
performance comparisons. Selection-pool results apply only to engines measured
in the same run.

Generate a smaller corpus manifest with:

```bash
cargo run -p xtask -- corpus manifest --quick > manifest.txt
```

See [CONTRIBUTING.md](../CONTRIBUTING.md#regenerating-the-readme-tables) for
published table generation.

## Conformance

The suite covers empty, short and incompressible inputs, concurrent calls,
parameter validation, cost models and decoder fast paths.
`zbm_decoder_diff_test` compares the LZBITMAP decoder with its bulk fast paths
disabled.

| command | scope |
|---|---|
| `make -C harness check` | Full suite with generated fixtures |
| `make -C harness check-quick` | Smaller fixtures and differential sweep; used by CI |
| `make -C harness asan-check` | AddressSanitizer and UndefinedBehaviorSanitizer |
| `make -C harness tsan-check` | ThreadSanitizer |
| `make -C harness msan-check` | MemorySanitizer; Linux clang only |

Every target builds with one job per core and runs its tests on one worker
per core (TSan: one binary at a time), slowest first by the previous run's
times. The two LZBITMAP differential sweeps run one level per job.

`FIXTURE_BYTES` caps fixture size, subject to the concurrency tests' minimum
of `N_THREADS * 4` chunks. `ZBM_DIFF_LEVELS` selects a comma-separated list
of differential-test levels; empty selects all levels.

## Fuzzing

`fuzz/build.sh` builds standalone targets by default. These use generated
inputs and can replay saved crash files. Pass `libfuzzer` for coverage-guided
fuzzing with a clang that includes the runtime.
See [fuzzing instructions](../CONTRIBUTING.md#tests-and-fuzzing) and the
script's header for build options.

`codec_buffers` exercises caller-buffer contracts for LZBITMAP, LZFSE and LZVN.
It compares exact output from fresh, dirty and reused scratch, alternates levels
and input sizes, and checks undersized scratch and destination boundaries.
Fresh scratch is intentionally uninitialized so MSan checks initialization.
Retained inputs and replay commands are in [buffer regressions](fuzz/regressions/README.md).

Inputs and compressed streams in the LZBITMAP, LZFSE and LZVN targets are copied into exact-sized
heap allocations so ASan sees their actual bounds. Guarded destinations have
physical guards on both sides of their writable mapping and poison unused
writable space under ASan. Run a corpus twice, with `FUZZ_GUARD_FRONT=0` and
`FUZZ_GUARD_FRONT=1`. Back placement protects the exact end physically; front
placement protects the exact start. ASan's shadow granularity can leave up to
seven accessible leading bytes in back placement, covered by the front run.
Selecting a new view invalidates the previous view of that mapping. Scratch
placement must preserve its documented alignment.

Run `fuzz/verify.sh` with the same `CC` used for fuzzing to verify ASan/UBSan
and guard enforcement. `fuzz/verify.sh msan` checks uninitialized-value detection;
`fuzz/verify.sh mte` signs the probe and checks an intentional heap-tag mismatch.
All modes require valid accesses to succeed. ASan also checks one-byte reads
and writes at buffer boundaries, including zero length; the other modes check
physical page guards. An MTE tag mismatch tests heap enforcement, not stack
instrumentation or sub-granule bounds.

For MSan, use a Linux/BSD toolchain and add `msan` to `fuzz/build.sh`.
MSan tracks uninitialized values separately
from ASan's bounds checks. The codec-only targets do not need Apple's framework.

For hardware-tagged heap checks on an M5 Mac, use Apple Clang and add `mte`.
The build signs with [checked-allocation entitlements](fuzz/mte-entitlements.plist),
including the parent hardened-process entitlements and pure-data allocations;
soft mode is omitted. For libFuzzer, set `FUZZER_RUNTIME` to a compatible
`libclang_rt.fuzzer_osx.a`. This is a separate heap-MTE/UBSan build; it does not
instrument stack allocations. Verify enforcement with a known invalid access
rather than treating successful compilation as evidence.

Source coverage accepts `LLVM_PROFDATA` and `LLVM_COV` overrides so both tools
can match the compiler that produced the profile. Set `FUZZ_SANITIZER=msan` or
`mte` when replaying those coverage builds. Corpus and source paths are relative
to the invoking directory; profiles are separate for each sanitizer mode.

Fuzz builds use the shipping x86-64-v3 target, including AVX2/BMI2. Set
`ISA_CFLAGS=` for a portable x86 build. Sanitizer instrumentation covers both
the codec and the harness, including Apple-generated streams copied to exact
heap allocations before our decoders read them.

## Investigation tools

- `zbm_apple_probe` (macOS): compare LZBITMAP against Apple's decoder by level
  and stride, and test whole-file round trips in both directions. Exit status
  is the number of failing file/level pairs.
- `zbm_edge_cases`: hand-built LZBITMAP streams at the edges of the format,
  each decoded by our decoder and, on macOS, by Apple's, with `same` or
  `DIFFERENT` per case. `-v` prints each case's question and the bytes.
- `zbm_sweep`, `crushlzfse_sweep`, `crushlzvn_sweep`, `crushlz4_sweep`: measure
  custom parameter sets against a manifest. On macOS they also check Apple's
  decoder. `crushlz4_sweep --reps N` reports the fastest of N encodes per block.
- `level_table`: emit per-level settings and scratch sizes for README generation.
