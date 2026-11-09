# Memory requirements

Encoder scratch sizes come from the libraries' sizing functions. Input and
output buffers require additional memory.

## Decoders

| decoder | working memory |
|---|---|
| LZFSE | 47,568 bytes on x86-64, 47,600 on ARM64, allocated per call |
| LZVN | 88 bytes, on the stack |
| LZBITMAP | A small state struct, on the stack |
| LZ4 | None |
| LZMESH | About 512 KiB, allocated per call |

Decoder working memory is independent of compression level and input length.

## Encoders

Scratch size depends on parameters, not input length. LZFSE and LZVN encode
up to 64 KiB per call. LZBITMAP and LZ4 split larger inputs into chunks.

### Scratch by level

| level | LZFSE | LZVN | LZBITMAP | LZ4 |
|------:|------:|-----:|---------:|----:|
| -5 | 172 KiB | 16 KiB | 1.08 MiB | 16 KiB |
| -4 | 172 KiB | 32 KiB | 1.08 MiB | 16 KiB |
| -3 | 188 KiB | 32 KiB | 1.08 MiB | 16 KiB |
| -2 | 220 KiB | 640 KiB | 1.08 MiB | 16 KiB |
| -1 | 220 KiB | 1.12 MiB | 1.08 MiB | 16 KiB |
| 0 | 508 KiB | 2.12 MiB | 1.08 MiB | 16 KiB |
| 1 | 508 KiB | 1.03 MiB | 1.08 MiB | 256 KiB |
| 2 | 2.78 MiB | 2.03 MiB | 1.08 MiB | 256 KiB |
| 3 | 2.78 MiB | 4.03 MiB | 1.08 MiB | 256 KiB |
| 4 | 5.28 MiB | 8.03 MiB | 1.08 MiB | 256 KiB |
| 5 | 2.68 MiB | 8.03 MiB | 1.08 MiB | 256 KiB |
| 6 | 6.22 MiB | 8.03 MiB | 1.08 MiB | 256 KiB |
| 7 | 8.97 MiB | 8.03 MiB | 1.42 MiB | 256 KiB |
| 8 | 8.97 MiB | 10.19 MiB | 1.42 MiB | 256 KiB |
| 9 | 10.47 MiB | 14.19 MiB | 1.49 MiB | 256 KiB |
| 10 | 10.50 MiB | 18.19 MiB | 1.64 MiB | 256 KiB |
| 11 | 13.50 MiB | n/a | 1.95 MiB | n/a |
| 12 | n/a | n/a | 2.58 MiB | n/a |

LZFSE's levels up to 0 are mostly encoder state; the small-input LZVN
fallback, which reuses the level's region, uses tables sized for inputs under
4 KiB. LZFSE and LZVN use larger match tables at higher
greedy levels and additional parse state at optimal levels. LZBITMAP's DP
level adds candidate tables and a second row index; beam levels also add
survivor traces and candidate-deduplication stamps to the row encoder's
scratch. LZ4 uses upstream encoder state: approximately 16 KiB for fast mode
and 256 KiB for HC mode, including alignment slack.

LZMESH takes no scratch. Its encoder allocates working memory on each call,
and that memory grows with input length: about 4 bytes per input byte at
levels up to 5, and a match tree of up to 8 bytes per input byte (capped at
a 16 MiB window) at levels 6 and up.

## Querying and reusing scratch

Use the sizing function for the parameters you will encode with:

| codec | C sizing function |
|---|---|
| LZFSE | `crushlzfse_scratch_size(&params)` |
| LZVN | `crushlzvn_scratch_size(&params)` |
| LZBITMAP | `crushlzbitmap_scratch_size(&params)` |
| LZ4 | `crushlz4_scratch_size(&params)` |

Passing `NULL` as scratch to an encoder allocates and frees working memory
internally. To reuse an allocation, pass a buffer and its length on each call.
An undersized buffer is rejected. Give each concurrent encode its own scratch.
Follow the alignment requirements in the codec's header; LZBITMAP requires
16-byte alignment.

When reusing a buffer across parameter sets, allocate the largest scratch size
reported for those sets. Rust's `Scratch` types grow on demand.

The CLI's `--max-memory` option limits estimated encoder scratch.
For LZBITMAP, `--threads` multiplies the per-worker scratch requirement.
