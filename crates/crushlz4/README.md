# crushlz4

An encoder and decoder for Apple's `COMPRESSION_LZ4` (0x100), used by decmpfs
types 15 and 16. Apple's `bv4` framing wraps standard LZ4 block data.
The block encoder is vendored upstream LZ4; framing and decoding are implemented
by this crate.

```toml
[dependencies]
crushlz4 = "0.1"
```

```rust
use crushlz4::{Level, Params, compress, compress_with, decompress};

let input = b"example input";
let packed = compress(input, Level::DEFAULT)?;
assert_eq!(decompress(&packed)?, input);

let packed = compress(input, Level::MAX)?;
assert_eq!(decompress(&packed)?, input);

// Custom settings for the fast encoder.
let mut params = Params::for_level(Level::DEFAULT).0;
params.acceleration = 4;
let packed = compress_with(input, &params)?;
assert_eq!(decompress(&packed)?, input);
```

`compress_into` writes into a caller-supplied buffer sized with `compress_bound`
and accepts a reusable `Scratch`. `decompress_into` decodes into a supplied buffer.

## Levels

Levels range from -5 to 10; the default is 0. Out-of-range levels are clamped.
Levels -5 to 0 use `LZ4_compress_fast`; levels 1 to 10 use `LZ4_compress_HC`.

[500 MiB corpus](../../README.md#reproducing-the-corpus), one Apple M5 Max Super core.
`saved%` is the percentage reduction in size. Decode columns measure each row's
output with this crate's decoder (`ours`) and `libcompression` (`apple`).
Memory is encoder scratch from `crushlz4_scratch_size`.
[Benchmark data](../../docs/bench-run.txt).

<!-- TABLE:results:crushlz4 -->
| level | saved% | enc MB/s | dec MB/s (ours) | dec MB/s (apple) | memory |
|---|---|---|---|---|---|
| -5 | 22.53% | 4878 | 19150 | 24920 | 16 KiB |
| -4 | 31.57% | 3382 | 14170 | 18880 | 16 KiB |
| -3 | 40.39% | 2399 | 10860 | 14610 | 16 KiB |
| -2 | 47.12% | 1845 | 8678 | 11770 | 16 KiB |
| -1 | 54.28% | 1331 | 6903 | 8820 | 16 KiB |
| **0 (def)** | **58.53%** | **1144** | **6281** | **7382** | **16 KiB** |
| *Apple* | *57.81%* | *1257* | *6419* | *7621* |  |
| 1 | 61.70% | 474 | 6891 | 8140 | 256 KiB |
| 2 | 64.04% | 254 | 7411 | 8763 | 256 KiB |
| 3 | 64.41% | 226 | 7506 | 8843 | 256 KiB |
| 4 | 64.63% | 202 | 7675 | 9004 | 256 KiB |
| 5 | 64.76% | 178 | 7753 | 9080 | 256 KiB |
| 6 | 64.83% | 155 | 7768 | 9068 | 256 KiB |
| 7 | 64.89% | 115 | 7887 | 9122 | 256 KiB |
| 8 | 64.94% | 62.11 | 7702 | 8973 | 256 KiB |
| 9 | 65.05% | 33.81 | 7750 | 8999 | 256 KiB |
| 10 | 65.07% | 28.74 | 7646 | 8788 | 256 KiB |
<!-- /TABLE:results:crushlz4 -->

## Settings

### Fast (levels -5 to 0)

`LZ4_compress_fast`, at `acceleration`. Higher values skip more input between
match attempts.

<!-- TABLE:settings:crushlz4:Fast -->
| level | acceleration |
|---|---|
| -5 | 128 |
| -4 | 64 |
| -3 | 32 |
| -2 | 16 |
| -1 | 5 |
| **0 (def)** | 1 |
<!-- /TABLE:settings:crushlz4:Fast -->

### HC (levels 1 to 10)

`LZ4_compress_HC`, at compression level `hc_level`.

<!-- TABLE:settings:crushlz4:Hc -->
| level | hc_level |
|---|---|
| 1 | 2 |
| 2 | 3 |
| 3 | 4 |
| 4 | 5 |
| 5 | 6 |
| 6 | 7 |
| 7 | 9 |
| 8 | 10 |
| 9 | 11 |
| 10 | 12 |
<!-- /TABLE:settings:crushlz4:Hc -->

`Params::for_level` returns the settings and the clamped level.
`compress_with` validates custom settings; invalid values return
`Error::InvalidParams`. `capabilities()` reports the accepted ranges.

## Format compatibility

The decoder accepts Apple's extensions to LZ4 blocks:

- Matches may reference output from earlier blocks in the same stream.
- Blocks may end on a match, without standard LZ4's final-literal restrictions.

The encoder produces independent blocks that follow standard LZ4 block rules.
Their payloads can be decoded by a standard LZ4 block decoder; the complete
stream requires a decoder for Apple's `bv4` framing.
See [crushlz4.c](csrc/crushlz4.c) for format details.

## Memory

Encoder scratch is approximately 16 KiB in fast mode and 256 KiB in HC mode,
independent of input size. Scratch may be reused across calls without clearing.
Passing `NULL` to the C API allocates scratch internally; a supplied buffer
smaller than `crushlz4_scratch_size(params)` is rejected.
The decoder allocates no working memory.

## C API

See [crushlz4.h](csrc/crushlz4.h) for functions, status codes and parameter
constraints, and the [C build instructions](../../README.md#using-the-c-libraries).

## Validation

The harness checks output against this decoder, Apple's decoder on macOS,
and upstream LZ4's block decoder. Rust ABI tests check the FFI layouts and
constants against the C implementation.

## Licensing

`MPL-2.0 AND BSD-2-Clause`. Framing, decoding and Rust bindings are MPL-2.0;
the unmodified upstream LZ4 block encoder is BSD-2-Clause.
See [LICENSE](LICENSE), [THIRD-PARTY.md](../../THIRD-PARTY.md) and
[vendor provenance](csrc/vendor/lz4/PROVENANCE.md).
