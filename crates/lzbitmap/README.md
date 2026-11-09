# lzbitmap

An LZBITMAP encoder and decoder for Apple's `COMPRESSION_LZBITMAP`, used by
decmpfs types 13 and 14.

```toml
[dependencies]
lzbitmap = "0.1"
```

```rust
use lzbitmap::{Level, compress, compress_parallel, decompress};

let input = b"example input";
let packed = compress(input, Level::DEFAULT)?;
assert_eq!(decompress(&packed)?, input);

// Encode independent chunks in parallel.
let packed = compress_parallel(input, Level::DEFAULT, 0)?;
assert_eq!(decompress(&packed)?, input);
```

`compress_into` writes into a caller-supplied buffer sized with `compress_bound`
and accepts a reusable `Scratch`. `decompress_into` decodes into a supplied buffer.
The C API's input limit is `CRUSHLZBITMAP_MAX_SRC_SIZE` (just under 4 GiB).

## Levels

Levels range from -5 to 12; the default is 0. Out-of-range levels are clamped.

[500 MiB corpus](../../README.md#reproducing-the-corpus), one Apple M5 Max Super core.
`saved%` is the percentage reduction in size. Decode columns measure each row's
output with this crate's decoder (`ours`) and `libcompression` (`apple`).
Memory is encoder scratch. [Benchmark data](../../docs/bench-run.txt).

<!-- TABLE:results:lzbitmap -->
| level | saved% | enc MB/s | dec MB/s (ours) | dec MB/s (apple) | memory |
|---|---|---|---|---|---|
| -5 | 60.22% | 834 | 7505 | 5797 | 1.08 MiB |
| -4 | 63.83% | 808 | 8012 | 6263 | 1.08 MiB |
| -3 | 64.82% | 667 | 7889 | 6168 | 1.08 MiB |
| -2 | 65.56% | 614 | 8115 | 6397 | 1.08 MiB |
| -1 | 66.48% | 527 | 8067 | 6374 | 1.08 MiB |
| **0 (def)** | **66.63%** | **488** | **7896** | **6270** | **1.08 MiB** |
| *Apple* | *66.28%* | *516* | *8234* | *6485* |  |
| 1 | 66.84% | 410 | 7967 | 6328 | 1.08 MiB |
| 2 | 67.22% | 348 | 8168 | 6411 | 1.08 MiB |
| 3 | 67.56% | 268 | 7998 | 6340 | 1.08 MiB |
| 4 | 67.81% | 196 | 7827 | 6349 | 1.08 MiB |
| 5 | 67.92% | 155 | 7847 | 6349 | 1.08 MiB |
| 6 | 67.99% | 103 | 7852 | 6344 | 1.08 MiB |
| 7 | 68.65% | 19.93 | 8204 | 6465 | 1.42 MiB |
| 8 | 68.85% | 17.61 | 7727 | 6324 | 1.42 MiB |
| 9 | 69.00% | 13.56 | 7849 | 6409 | 1.49 MiB |
| 10 | 69.19% | 7.6 | 7791 | 6451 | 1.64 MiB |
| 11 | 69.26% | 4.735 | 7831 | 6498 | 1.95 MiB |
| 12 | 69.29% | 2.824 | 7774 | 6504 | 2.58 MiB |
<!-- /TABLE:results:lzbitmap -->

## Strategies and settings

Each level runs one of four strategies. A strategy's table lists only the
settings that change between its levels; the fixed ones are given above it.

### Fast (levels -5 to -3)

Searches only where the period in force stops fitting.

- Keeps the current period while it serves a block with at most `accept_diff`
  literals.
- Otherwise looks up `windows` hash entries and the recent periods.
- Indexes only the blocks it searched. After `n` searches in a row that keep
  the period, it skips the next `n >> skip_shift` blocks; `skip_shift` 0
  never skips.
- Fixed: `hash_bits` 16, `dist_cache_size` 2.

<!-- TABLE:settings:lzbitmap:Fast -->
| level | windows | accept_diff | skip_shift |
|---|---|---|---|
| -5 | 2 | 4 | 3 |
| -4 | 4 | 2 | 4 |
| -3 | 8 | 1 | 4 |
<!-- /TABLE:settings:lzbitmap:Fast -->

### Row (levels -2 to 6)

Searches hash buckets for matching periods.

- Probes all `depth` entries of a bucket of a `hash_bits` table, and retries
  the `dist_cache_size` most recently used periods.
- Keeps the period in force without searching at `accept_diff` literals or
  fewer.
- `scan_window` also checks that many of the nearest periods exhaustively.
- `lookahead` (levels 1 and up) also probes the block after each candidate,
  preferring periods that persist.

<!-- TABLE:settings:lzbitmap:Row -->
| level | hash_bits | depth | dist_cache_size | accept_diff | scan_window | lookahead |
|---|---|---|---|---|---|---|
| -2 | 14 | 1 | 4 | 2 | 0 | no |
| -1 | 16 | 2 | 4 | 1 | 0 | no |
| **0 (def)** | 16 | 2 | 4 | 1 | 16 | no |
| 1 | 16 | 1 | 4 | 0 | 48 | yes |
| 2 | 15 | 4 | 4 | 0 | 0 | yes |
| 3 | 16 | 4 | 4 | 0 | 64 | yes |
| 4 | 16 | 4 | 8 | 0 | 256 | yes |
| 5 | 15 | 8 | 4 | 0 | 256 | yes |
| 6 | 14 | 16 | 8 | 0 | 256 | yes |
<!-- /TABLE:settings:lzbitmap:Row -->

### DP (level 7)

Chooses the period sequence by shortest path over candidates from the row
search.

- Keeps up to `max_candidates` per block and runs `iterations` passes; later
  passes reuse the previous pass's top-bitmap table.
- Settings: `hash_bits` 15, `depth` 8, `dist_cache_size` 8, `scan_window` 256,
  `lookahead` on, 8 candidates and 2 passes.

### Beam (levels 8 to 12)

Carries competing periods across 8-byte blocks and prices bitmap runs.

- Keeps `beam_width` states, a power of two from 1 to 64, and records up to
  `max_candidates` (1 to 255) per block.
- One row pass seeds the candidates and the top-bitmap estimate; the smaller
  serialized result wins.
- Levels 11 and 12 trade speed for maximum ratio.
- Trace and deduplication storage is part of the caller's scratch; nothing is
  allocated per chunk.
- Fixed: `lookahead` on, `scan_window` 256, `accept_diff` 0.

<!-- TABLE:settings:lzbitmap:Beam -->
| level | hash_bits | depth | dist_cache_size | max_candidates | beam_width |
|---|---|---|---|---|---|
| 8 | 15 | 8 | 4 | 4 | 4 |
| 9 | 15 | 8 | 4 | 4 | 8 |
| 10 | 14 | 16 | 8 | 8 | 16 |
| 11 | 14 | 16 | 8 | 16 | 32 |
| 12 | 14 | 16 | 8 | 32 | 64 |
<!-- /TABLE:settings:lzbitmap:Beam -->

Use `Params` to override individual settings:

```rust
use lzbitmap::{Level, Params, compress_with, decompress};

let input = b"example input";
let mut params = Params::for_level(Level(1)).0;
if let Params::Row { scan_window, .. } = &mut params {
    *scan_window = 64;
}
let packed = compress_with(input, &params)?;
assert_eq!(decompress(&packed)?, input);
```

`capabilities()` reports accepted ranges. Invalid parameters return
`Error::InvalidParams`. Additional constraints apply: for example, `depth`
must be a power of two and `scan_window` a multiple of 16.
See [crushlzbitmap.h](csrc/crushlzbitmap.h) for the full constraints.

## Compatibility

Apple publishes no LZBITMAP specification; see the
[format notes](../../docs/lzbitmap-format.md). The harness checks compatibility against
Apple's `libcompression` on macOS. Malformed input may be rejected differently
by the two decoders. The `crushlz` CLI's `--verify` option checks output before
writing it.

## Memory

The decoder uses a stack state struct and allocates no heap memory.
Encoder scratch does not grow with input length.
See [memory requirements](../../docs/memory.md).

## C API

See [crushlzbitmap.h](csrc/crushlzbitmap.h) for functions and status codes,
and the [C example and build instructions](../../README.md#using-the-c-libraries).

## Licensing

`MPL-2.0 AND MIT`. Corellium-derived sources retain their copyright notices
and MIT terms. See [LICENSE](LICENSE), [LICENSE-MIT](LICENSE-MIT) and
[THIRD-PARTY.md](../../THIRD-PARTY.md).
