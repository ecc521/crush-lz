# Codec buffer regressions

Replay the retained inputs with the stateful caller-buffer target:

```sh
CC=/opt/homebrew/opt/llvm/bin/clang harness/fuzz/build.sh codec_buffers libfuzzer
harness/fuzz/build/codec_buffers_libfuzzer -runs=1 harness/fuzz/regressions/zbm-fresh-epoch harness/fuzz/regressions/zbm-simd-tail
```

Use a Linux toolchain and add `msan` when checking uninitialized reads.

- `zbm-fresh-epoch` exercises fresh LZBITMAP caller scratch. Resetting the epoch
  forces the active row table to be cleared before it can provide candidates.
- `zbm-simd-tail` exercises the final partially populated group of bitmap numbers.
  Comparing only SIMD groups containing live entries avoids consuming untouched
  scratch without expanding the initialized tail.

The conformance test `zbm_scratch_initialization_test` also checks the controlled
scratch-tag reproducer, exact stream equality across scratch states and levels,
and long multi-chunk inputs. `zbm_row_epoch_test` forces index rebuilds to
check the initial clear and repeated epoch wraps.
