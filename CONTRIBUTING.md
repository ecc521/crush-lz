# Contributing

## License of contributions

By submitting a contribution, you confirm that you have the right to license
it and permit its use under any of these licenses:

- [MPL-2.0](https://www.mozilla.org/MPL/2.0/)
- [MIT](https://opensource.org/license/mit)
- [BSD-3-Clause](https://opensource.org/license/bsd-3-clause)

If your contribution includes code whose license prevents this grant, identify
it in the pull request.

If you consulted disassembly or other non-public material, list exactly what
you consulted in the pull request so maintainers can review its licensing implications.

## Compatibility contract

CrushLZ is intended to:

1. Avoid leaking compressor or decompressor scratch contents; callers should
   not need to zero scratch before use.
2. Handle untrusted input and compression settings safely.
3. Decode valid streams produced by CrushLZ or Apple's encoders.
4. Produce streams readable by CrushLZ and Apple's decoders.
5. Sustain at least 25% of corpus throughput on crafted inputs.
6. Produce streams at every level that decode no more than 15% slower than
   level 0 output.

Violations are generally bugs. These requirements are not exhaustive.
The following are permitted:

- Different CPUs may produce different valid streams for the same input and settings.
- A decoder may reject malformed input that Apple's decoder accepts.
- A lower compression level may occasionally produce smaller output than a higher level.

## AI Policy & Scope

Usage of AI is acceptable for development, *provided such use is compliant with copyright laws*. If an AI decompiles code on your behalf, or consults other non-public material, the licensing of its output is potentially contaminated, and *must be reported*. Agents should not have access to decompiled / non-public material, or memories developed using such material, at any time. 

Feature requests (such as streaming encode / decode) will likely be ignored. Crush-LZ is designed primarily for decmpfs compression, and expanding the codebase to add additional features is not in-scope unless there is reason to believe those features will be widely used. 

## Tests and fuzzing

```bash
cargo test
make -C harness check
make -C harness sanitize
make -C harness proofs     # CBMC >= 6; see harness/proofs/README.md
```

A change to code covered by a proof must keep `make -C harness proofs` and
`make -C harness proofs-mutants` passing. If the safety argument changes,
update the function and loop contracts to match.

Fuzzing requires clang with the libFuzzer runtime, which Apple's clang does
not include. Example using Homebrew LLVM:

```bash
CC=/opt/homebrew/opt/llvm/bin/clang harness/fuzz/build.sh libfuzzer
N=$(sysctl -n hw.ncpu 2>/dev/null || nproc)
mkdir -p harness/fuzz/corpus/crushlzfse_encode
harness/fuzz/build/crushlzfse_encode_libfuzzer -max_total_time=300 -workers=$N -jobs=$N harness/fuzz/corpus/crushlzfse_encode
```

Targets: `codec_buffers`, `crushlzfse_encode`, `crushlzvn_encode`, `crushlzfse_decode`,
`lzbitmap_encode`, `lzbitmap_decode`, `lz4_encode`, `lz4_decode`, `lzmesh_encode`,
`lzmesh_decode`. On macOS,
all encoder targets check output from both CrushLZ and Apple under both
sets of decoders. Apple encoder failure is fatal except for empty input
and its raw LZVN encoder's eight-byte source minimum. CrushLZ output is
still checked under both decoders for those short inputs.
`crushlzfse_decode_diff_vs_apple`, `lzbitmap_decode_diff_vs_apple`,
`lz4_decode_diff_vs_apple` and `lzmesh_decode_diff_vs_apple` compare decoder results against `libcompression`:
acceptance may differ, but successful complete decodes must agree.

For coverage reports:

```bash
CC=/opt/homebrew/opt/llvm/bin/clang harness/fuzz/build.sh crushlzfse_encode libfuzzer coverage
harness/fuzz/coverage.sh crushlzfse_encode harness/fuzz/corpus/crushlzfse_encode
```

Verify instrumentation before starting a campaign:

```bash
CC=/opt/homebrew/opt/llvm/bin/clang harness/fuzz/verify.sh asan
# In a Linux VM/container, with a matching clang runtime:
CC=clang harness/fuzz/verify.sh msan
# On a hardware-tagging-capable Mac, with Apple Clang:
CC=clang harness/fuzz/verify.sh mte
```

Run guarded targets with both `FUZZ_GUARD_FRONT=0` and `FUZZ_GUARD_FRONT=1`.
See the [harness guide](harness/README.md) for sanitizer and coverage options.

## Release checks on macOS

Linux CI cannot check compatibility with Apple's `libcompression`.
Before release, run conformance tests and a corpus benchmark on macOS:

```bash
cargo run -p xtask -- corpus fetch
cargo run -p xtask -- corpus build
cargo run -p xtask -- corpus manifest > manifest.txt
make -C harness check
harness/build/bench --list
harness/build/bench manifest.txt --sequential \
  --engines crushlzfse:0,crushlzvn:0,lzbitmap:0,crushlz4:0,crushlzfse:10,crushlzvn:10,lzbitmap:10,crushlz4:10,lzmesh:0,lzmesh:10,apple-lzfse,apple-lzvn,apple-lzbitmap,apple-lz4,apple-lzmesh
```

Levels 0 and 10 exercise the default and optimal parsers for all five codecs.
Verify that `--list` reports at least two decoders for each format, including
Apple's. Exit status 2 or any non-zero `FAILED` count blocks release.

## Regenerating the README tables

Tables between `<!-- TABLE:name -->` markers are generated; do not edit them
by hand. Settings and scratch sizes come from the API:

```bash
make -C harness probe
harness/build/level_table > levels.tsv
```

Measure all 88 engine/level pairs on a quiet machine, using `--sequential`
for a separate corpus pass per engine. The pairs may be split across runs.
For example, generate the full engine list and run it with Python:

```bash
python3 - <<'PYBENCH'
import subprocess
engines = [f"{codec}:{level}"
           for codec in ("crushlzfse", "crushlzvn", "lzbitmap", "crushlz4", "lzmesh")
           for level in range(-5, 11)]
engines += ["crushlzfse:11", "lzbitmap:11", "lzbitmap:12"]
engines += ["apple-lzfse", "apple-lzvn", "apple-lzbitmap", "apple-lz4", "apple-lzmesh"]
with open("docs/bench-run.txt", "w") as output:
    subprocess.run(["harness/build/bench", "manifest.txt", "--sequential",
                    "--engines", ",".join(engines)], stdout=output, check=True)
PYBENCH
python3 harness/tools/readme_table.py levels.tsv docs/bench-run.txt
python3 harness/tools/readme_table.py levels.tsv docs/bench-run.txt --check
```

Record the machine and measurement conditions with the benchmark data, and
commit the data with regenerated tables. Re-run measurements after changing
encoder settings; regenerating tables alone does not update measured performance.
Without a benchmark argument, the
script updates settings and replaces results with placeholders.
`--check` reports stale tables without writing files.

## Publishing

Set the version in `[workspace.package]` and regenerate `Cargo.lock` in the
same commit. Preserve the crates' combined SPDX license expressions.

Dry-run packaging for the four codec crates:

```bash
cargo publish -p crushlzfse --dry-run
cargo publish -p lzbitmap --dry-run
cargo publish -p crushlz4 --dry-run
cargo publish -p lzmesh --dry-run
```

Publish dependencies before the combined crate:

```bash
cargo publish -p crushlzfse
cargo publish -p lzbitmap
cargo publish -p crushlz4
cargo publish -p lzmesh
cargo publish -p crushlz
```

`crushlz` resolves dependencies from crates.io during packaging, so its dry
run requires the codec versions to be published first.
