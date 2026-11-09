# crushlzfse

LZFSE and LZVN encoders and decoders compatible with Apple's compression
streams. The lowest LZFSE levels use single-probe hash matching, the levels
around the default lazy matching, and higher levels cost-based optimal
parsing.

```toml
[dependencies]
crushlzfse = "0.1"
```

```rust
use crushlzfse::{Level, compress, decompress};

let input = b"example input";
let compressed = compress(input, Level::DEFAULT)?;
let restored = decompress(&compressed)?;
assert_eq!(restored, input);
```

Encoding accepts up to 64 KiB per call at every level. Larger inputs return
`Error::InputTooLarge`. Decoding accepts larger valid streams.
Raw LZVN is available through `crushlzfse::lzvn`; its output has no format header.

`compress_into` writes into a caller-supplied buffer sized with `compress_bound`
and accepts a reusable `Scratch`. `decompress_into` decodes into a supplied buffer.

## Levels

LZFSE levels range from -5 to 11; LZVN levels range from -5 to 10. The default
is 0. Out-of-range levels are clamped.

[500 MiB corpus](../../README.md#reproducing-the-corpus), one Apple M5 Max Super core.
`saved%` is the percentage reduction in size. Decode columns measure each row's
output with this crate's decoder (`ours`) and `libcompression` (`apple`).
Memory is encoder scratch. [Benchmark data](../../docs/bench-run.txt).

### LZFSE

<!-- TABLE:results:crushlzfse -->
| level | saved% | enc MB/s | dec MB/s (ours) | dec MB/s (apple) | memory |
|---|---|---|---|---|---|
| -5 | 65.48% | 1075 | 2917 | 2391 | 172 KiB |
| -4 | 67.28% | 963 | 2949 | 2455 | 172 KiB |
| -3 | 68.55% | 858 | 2912 | 2469 | 188 KiB |
| -2 | 69.43% | 711 | 3036 | 2533 | 220 KiB |
| -1 | 70.21% | 506 | 2968 | 2524 | 220 KiB |
| **0 (def)** | **70.54%** | **335** | **2896** | **2501** | **508 KiB** |
| *Apple* | *70.58%* | *200* | *3068* | *2611* |  |
| 1 | 71.13% | 266 | 3018 | 2583 | 508 KiB |
| 2 | 71.41% | 230 | 3074 | 2619 | 2.78 MiB |
| 3 | 71.59% | 189 | 3142 | 2663 | 2.78 MiB |
| 4 | 71.72% | 153 | 3172 | 2682 | 5.28 MiB |
| 5 | 71.79% | 126 | 3134 | 2647 | 2.68 MiB |
| 6 | 72.35% | 28.53 | 2718 | 2412 | 6.22 MiB |
| 7 | 72.89% | 20.81 | 2878 | 2529 | 8.97 MiB |
| 8 | 73.22% | 13.54 | 2825 | 2470 | 8.97 MiB |
| 9 | 73.56% | 9.131 | 2804 | 2447 | 10.47 MiB |
| 10 | 73.69% | 6.791 | 2754 | 2406 | 10.50 MiB |
| 11 | 73.75% | 3.779 | 2733 | 2408 | 13.50 MiB |
<!-- /TABLE:results:crushlzfse -->

Each level runs one of three strategies. A strategy's table lists only the
settings that change between its levels.

#### Fast (levels -5 to -1)

- Keeps 16-bit positions in a hash table of `hash_bits` bits, keyed on
  `min_match` bytes, and also tries the last match distance, which LZFSE codes
  as a single symbol.
- Verifies candidates on 4 bytes, so `min_match` is the hashed length, not the
  shortest match.
- Over unmatched input, the stride grows by one byte per `2^skip_shift` bytes
  since the last match, up to `max_step`.
- `long_table` adds a second table keyed on 8 bytes and consulted first.
- `lazy` tries up to two following bytes for a match at least two bytes longer
  before taking one.
- With `long_table` or `lazy` set, `min_match` is at most 6.

<!-- TABLE:settings:crushlzfse:Fast -->
| level | hash_bits | min_match | skip_shift | max_step | long_table | lazy |
|---|---|---|---|---|---|---|
| -5 | 13 | 8 | 3 | 12 | no | no |
| -4 | 13 | 6 | 3 | 12 | no | no |
| -3 | 14 | 5 | 4 | 16 | no | no |
| -2 | 14 | 5 | 6 | 4 | yes | no |
| -1 | 14 | 4 | 6 | 4 | yes | yes |
<!-- /TABLE:settings:crushlzfse:Fast -->

#### Lazy (levels 0 to 5)

- Keeps `hash_width` candidates per bucket of a hash table of `hash_bits` bits,
  and takes the longest, or the last match distance one byte ahead.
- With `lookahead` 1 or 2, also tries that many following positions and moves
  to any match that scores higher. A match scores four points per byte, less
  the bits its distance costs, and a later start must win by a few more points
  to pay for the literal it adds.

<!-- TABLE:settings:crushlzfse:Lazy -->
| level | hash_bits | hash_width | lookahead |
|---|---|---|---|
| **0 (def)** | 14 | 4 | 0 |
| 1 | 14 | 4 | 1 |
| 2 | 16 | 8 | 1 |
| 3 | 16 | 8 | 2 |
| 4 | 16 | 16 | 2 |
| 5 | 14 | 32 | 2 |
<!-- /TABLE:settings:crushlzfse:Lazy -->

#### Optimal (levels 6 to 11)

Parses each block for its smallest coded size.

- `search_depth`: match-tree nodes visited per position.
- `iterations`: cost-model refinement passes over each block.
- `reparse`: re-runs the parse after the block is split, into at most
  `split_max_blocks` blocks.
- `tuple_tax`: a flat surcharge on every match, in 1/256-bit units; it speeds
  up decoding at a small cost in ratio.
- `max_live_buckets`: literal-run states per position allowed to take a
  literal step.
- `table_search`: passes over each block's frequency tables, scored by the
  block's exact coded size (levels 10 and 11).
- Level 11 is an archival preset.

<!-- TABLE:settings:crushlzfse:Optimal -->
| level | search_depth | iterations | reparse | split_max_blocks | tuple_tax | max_live_buckets | table_search |
|---|---|---|---|---|---|---|---|
| 6 | 4 | 1 | no | 1 | 512 | 1 | 0 |
| 7 | 8 | 1 | no | 1 | 512 | 2 | 0 |
| 8 | 16 | 1 | no | 8 | 512 | 2 | 0 |
| 9 | 32 | 2 | yes | 8 | 256 | 4 | 0 |
| 10 | 32 | 3 | yes | 8 | 0 | 4 | 1 |
| 11 | 32 | 6 | yes | 8 | 0 | 8 | 4 |
<!-- /TABLE:settings:crushlzfse:Optimal -->

### LZVN

<!-- TABLE:results:crushlzvn -->
| level | saved% | enc MB/s | dec MB/s (ours) | dec MB/s (apple) | memory |
|---|---|---|---|---|---|
| -5 | 58.66% | 1359 | 3482 | 3545 | 16 KiB |
| -4 | 62.14% | 995 | 2411 | 2411 | 32 KiB |
| -3 | 63.12% | 753 | 2501 | 2501 | 32 KiB |
| -2 | 64.23% | 237 | 2163 | 2171 | 640 KiB |
| -1 | 65.50% | 187 | 2212 | 2223 | 1.12 MiB |
| **0 (def)** | **66.31%** | **148** | **2234** | **2248** | **2.12 MiB** |
| *Apple* | *66.32%* | *138* | *2215* | *2244* |  |
| 1 | 66.78% | 110 | 2246 | 2248 | 1.03 MiB |
| 2 | 67.15% | 89.72 | 2280 | 2289 | 2.03 MiB |
| 3 | 67.37% | 74.04 | 2319 | 2324 | 4.03 MiB |
| 4 to 7 | 67.51% | 60.25 | 2302 | 2322 | 8.03 MiB |
| 8 | 68.22% | 14.06 | 2380 | 2410 | 10.19 MiB |
| 9 | 68.59% | 10.12 | 2383 | 2407 | 14.19 MiB |
| 10 | 68.71% | 7.607 | 2398 | 2428 | 18.19 MiB |
<!-- /TABLE:results:crushlzvn -->

Each level runs one of three strategies. A strategy's table lists only the
settings that change between its levels.

#### Fast (levels -5 to -3)

The same matching as LZFSE's fast levels, without `long_table`.

<!-- TABLE:settings:crushlzvn:Fast -->
| level | hash_bits | min_match | skip_shift | max_step | lazy |
|---|---|---|---|---|---|
| -5 | 13 | 6 | 3 | 12 | no |
| -4 | 14 | 4 | 5 | 8 | no |
| -3 | 14 | 4 | 6 | 4 | yes |
<!-- /TABLE:settings:crushlzvn:Fast -->

#### Greedy (levels -2 to 7)

- Keeps `hash_width` candidates per bucket of a hash table of `hash_bits` bits,
  and takes the longest match.
- Levels 4 to 7 have identical settings; their throughput measurements are
  averaged.

<!-- TABLE:settings:crushlzvn:Greedy -->
| level | hash_bits | hash_width |
|---|---|---|
| -2 | 16 | 1 |
| -1 | 16 | 2 |
| **0 (def)** | 16 | 4 |
| 1 | 14 | 8 |
| 2 | 14 | 16 |
| 3 | 14 | 32 |
| 4 to 7 | 14 | 64 |
<!-- /TABLE:settings:crushlzvn:Greedy -->

#### Optimal (levels 8 to 10)

- `search_depth`: match-tree nodes visited per position.
- `pareto_k`: parser states kept per position.

<!-- TABLE:settings:crushlzvn:Optimal -->
| level | search_depth | pareto_k |
|---|---|---|
| 8 | 16 | 2 |
| 9 | 16 | 4 |
| 10 | 32 | 6 |
<!-- /TABLE:settings:crushlzvn:Optimal -->

## Custom parameters

Use `Params` to override individual settings:

```rust
use crushlzfse::{Level, Params, compress_with, decompress};

let input = b"example input";
let mut params = Params::for_level(Level(8)).0;
if let Params::Optimal { search_depth, iterations, .. } = &mut params {
    *search_depth = 64;
    *iterations = 4;
}
let compressed = compress_with(input, &params)?;
assert_eq!(decompress(&compressed)?, input);
```

`capabilities()` reports accepted ranges. Invalid parameters return
`Error::InvalidParams`.

## Chaining chunks

A file compressed as a run of 64 KiB chunks can carry statistics from each
chunk to the next. `compress_into_chained` (C:
`crushlzfse_encode_buffer_chained`) takes a `Stats` that it reads as the seed
and then overwrites with this chunk's L, M and D symbol counts. The optimal
levels (6 to 11) start their parse from that seed instead of a greedy guess,
which saves more and, at the multi-pass levels, can end the refinement
sooner. Every level writes the statistics, so a chain may mix levels.

```rust
use crushlzfse::{Level, Params, Scratch, Stats, compress_bound, compress_into_chained};

let file = vec![b'x'; 200_000];
let params = Params::for_level(Level(9)).0;
let (mut scratch, mut stats) = (Scratch::new(), Stats::default());
let mut out = vec![0u8; compress_bound(65_536, &params)];
for chunk in file.chunks(65_536) {
    let n = compress_into_chained(&mut out, chunk, &params, &mut scratch, &mut stats)?;
    // out[..n] is a complete stream for this chunk alone.
}
```

- Pass the chunks in order. A default (zeroed) `Stats`, or a NULL one in C,
  gives exactly the unchained output; start each file, or anywhere chunks
  may be encoded separately, from a zeroed one.
- Each output is still an independent stream that this crate's decoder and
  Apple's read on its own. Only the bytes chosen depend on the chunks before
  it in the chain, so the same chunk can encode differently in two chains.
- The contents are opaque, and arbitrary contents are safe: a foreign seed
  can only cost ratio. A chunk stored as LZVN or raw, and any error, leave
  `Stats` zeroed, so the next chunk runs unseeded.

`compress_chunks(src, &params, threads, segment)` does this for a whole
buffer and returns one stream per 64 KiB chunk. With one thread it is a
single chain. With more, the chain restarts every `segment` bytes (512 KiB
by default) and segments run in parallel; the output depends on the segment
size, never on the thread count. Each restart forgoes about one and a half
chunks of the gain, so longer segments compress better and shorter ones
spread a file over more cores.

## Memory

`scratch_size(&Params::for_level(level).0)` reports encoder working memory.
Scratch size depends on parameters and is independent of input length.
See [memory requirements](../../docs/memory.md) for sizes and reuse.

## C API

See [crushlzfse.h](csrc/crushlzfse.h) and [crushlzvn.h](csrc/crushlzvn.h)
for functions, status codes and parameter constraints, and the
[C build instructions](../../README.md#using-the-c-libraries).

## Compatibility

Decoders derive from Apple's reference implementation. The harness checks
encoded streams against Apple's `libcompression` on macOS.
The `crushlz` CLI's `--verify` option checks output before writing it.

## Licensing

`MPL-2.0 AND BSD-3-Clause`. Apple-derived sources retain their copyright
notices and BSD terms. See [LICENSE](LICENSE),
[LICENSE-BSD-3-CLAUSE](LICENSE-BSD-3-CLAUSE) and
[THIRD-PARTY.md](../../THIRD-PARTY.md).
