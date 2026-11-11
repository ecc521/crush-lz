# lzmesh

Apple LZMESH (`COMPRESSION_LZMESH`, `0xE05`) encoder and decoder for `crush-lz`.
Streams decode with macOS `libcompression`, and the decoder reads Apple's own
streams. The format notes are in
[`docs/lzmesh-format-notes.md`](../../docs/lzmesh-format-notes.md).

## Levels

Levels range from -5 to 10; the default is 0. Out-of-range levels are clamped,
and levels -5 to -1 are the same as 0.

[500 MiB corpus](../../README.md#reproducing-the-corpus) in 64 KiB blocks, one
Apple M5 Max Super core. `saved%` is the percentage reduction in size. Decode
columns measure each row's output with this crate's decoder (`ours`) and
`libcompression` (`apple`). [Benchmark data](../../docs/bench-run.txt).

<!-- TABLE:results:lzmesh -->
| level | saved% | enc MB/s | dec MB/s (ours) | dec MB/s (apple) |
|---|---|---|---|---|
| **-5 to 0 (def)** | **73.02%** | **188** | **1393** | **3135** |
| *Apple* | *72.68%* | *383* | *1227* | *2745* |
| 1 | 73.24% | 171 | 1369 | 3175 |
| 2 | 73.39% | 159 | 1443 | 3205 |
| 3 | 73.50% | 139 | 1461 | 3219 |
| 4 | 73.61% | 103 | 1463 | 3247 |
| 5 | 73.67% | 79.22 | 1467 | 3241 |
| 6 | 74.11% | 19.67 | 1493 | 3243 |
| 7 | 74.22% | 17.27 | 1491 | 3291 |
| 8 | 74.39% | 11.7 | 1520 | 3289 |
| 9 | 74.44% | 8.814 | 1512 | 3259 |
| 10 | 74.45% | 8.2 | 1525 | 3308 |
<!-- /TABLE:results:lzmesh -->

## Strategies and settings

Each level runs one of two strategies. A strategy's table lists only the
settings that change between its levels.

### Lazy (levels -5 to 5)

- Lazy parse over a `hash_bits` table, following up to `max_depth`
  candidates per position.
- Searches a hash chain up to depth 8 and hash rows above it.
- Fixed: `min_match` 3.

<!-- TABLE:settings:lzmesh:Lazy -->
| level | hash_bits | max_depth |
|---|---|---|
| **-5 to 0 (def)** | 16 | 1 |
| 1 | 17 | 2 |
| 2 | 17 | 4 |
| 3 | 17 | 8 |
| 4 | 18 | 24 |
| 5 | 18 | 64 |
<!-- /TABLE:settings:lzmesh:Lazy -->

### Optimal (levels 6 to 10)

- Optimal parse over a binary tree, visiting up to `search_depth` nodes per
  position and accepting any match of `lookahead` bytes or longer at once.
- Parses in 64 KiB chunks. The first chunk is priced from a greedy parse of
  its matches, each later one from the chunk before.
- An input of one chunk runs `iterations` passes, each priced from the
  previous pass, and keeps the cheapest. Larger inputs take one pass per chunk.
- Fixed: `min_match` 3.

<!-- TABLE:settings:lzmesh:Optimal -->
| level | hash_bits | search_depth | lookahead | iterations |
|---|---|---|---|---|
| 6 | 17 | 8 | 64 | 1 |
| 7 | 17 | 16 | 96 | 1 |
| 8 | 18 | 16 | 128 | 2 |
| 9 | 18 | 32 | 128 | 3 |
| 10 | 18 | 128 | 192 | 3 |
<!-- /TABLE:settings:lzmesh:Optimal -->
