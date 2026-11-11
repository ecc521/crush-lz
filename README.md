# crush-lz

LZFSE, LZVN, LZBITMAP, LZ4 and LZMESH encoders and decoders for
Apple-compatible compression streams. Written in C, with Rust bindings and a CLI. Higher
compression levels target smaller output for APFS filesystem compression.

To compress files on APFS with these encoders, see
[apfscompress](https://github.com/ecc521/apfscompress).

| crate | contents | license | docs |
|---|---|---|---|
| [`crushlzfse`](crates/crushlzfse) | LZFSE and LZVN encoders and decoders | MPL-2.0 AND BSD-3-Clause | [crates.io](https://crates.io/crates/crushlzfse) · [docs.rs](https://docs.rs/crushlzfse) |
| [`lzbitmap`](crates/lzbitmap) | LZBITMAP encoder and decoder | MPL-2.0 AND MIT | [crates.io](https://crates.io/crates/lzbitmap) · [docs.rs](https://docs.rs/lzbitmap) |
| [`crushlz4`](crates/crushlz4) | LZ4 encoder and decoder | MPL-2.0 AND BSD-2-Clause | [crates.io](https://crates.io/crates/crushlz4) · [docs.rs](https://docs.rs/crushlz4) |
| [`lzmesh`](crates/lzmesh) | LZMESH encoder and decoder | MPL-2.0 | [crates.io](https://crates.io/crates/lzmesh) · [docs.rs](https://docs.rs/lzmesh) |
| [`crushlz`](crates/crushlz) | Combined Rust API and CLI | MPL-2.0 AND MIT AND BSD-2-Clause AND BSD-3-Clause | [crates.io](https://crates.io/crates/crushlz) · [docs.rs](https://docs.rs/crushlz) |

## Compatibility

CrushLZ must decode streams produced by Apple's encoders, and its output must
be readable by Apple's decoders. See the [compatibility contract](CONTRIBUTING.md#compatibility-contract)
for requirements and exceptions.

## Results

[500 MiB corpus](#reproducing-the-corpus) in 64 KiB blocks, one Apple M5 Max
Super core. Cells show `saved% / encode MB/s`; `saved%` is the percentage reduction in size.
Level 0 is the default. 

<!-- TABLE:results:all -->
| level | LZFSE | LZVN | LZBITMAP | LZ4 | LZMESH |
|---|---|---|---|---|---|
| -5 | 65.48% / 1075 | 58.66% / 1359 | 60.22% / 834 | 22.53% / 4878 | 73.02% / 187 |
| -4 | 67.28% / 963 | 62.14% / 995 | 63.83% / 808 | 31.57% / 3382 | 73.02% / 189 |
| -3 | 68.55% / 858 | 63.12% / 753 | 64.82% / 667 | 40.39% / 2399 | 73.02% / 189 |
| -2 | 69.43% / 711 | 64.23% / 237 | 65.56% / 614 | 47.12% / 1845 | 73.02% / 188 |
| -1 | 70.21% / 506 | 65.50% / 187 | 66.48% / 527 | 54.28% / 1331 | 73.02% / 188 |
| **0 (def)** | 70.54% / 335 | 66.31% / 148 | 66.63% / 488 | 58.53% / 1144 | 73.02% / 188 |
| *Apple* | *70.58% / 200* | *66.32% / 138* | *66.28% / 516* | *57.81% / 1257* | *72.68% / 383* |
| 1 | 71.13% / 266 | 66.78% / 110 | 66.84% / 410 | 61.70% / 474 | 73.24% / 171 |
| 2 | 71.41% / 230 | 67.15% / 89.72 | 67.22% / 348 | 64.04% / 254 | 73.39% / 159 |
| 3 | 71.59% / 189 | 67.37% / 74.04 | 67.56% / 268 | 64.41% / 226 | 73.50% / 139 |
| 4 | 71.72% / 153 | 67.51% / 60.13 | 67.81% / 196 | 64.63% / 202 | 73.61% / 103 |
| 5 | 71.79% / 126 | 67.51% / 60.24 | 67.92% / 155 | 64.76% / 178 | 73.67% / 79.22 |
| 6 | 72.35% / 28.53 | 67.51% / 60.02 | 67.99% / 103 | 64.83% / 155 | 74.11% / 19.67 |
| 7 | 72.89% / 20.81 | 67.51% / 60.59 | 68.65% / 19.93 | 64.89% / 115 | 74.22% / 17.27 |
| 8 | 73.22% / 13.54 | 68.22% / 14.06 | 68.85% / 17.61 | 64.94% / 62.11 | 74.39% / 11.7 |
| 9 | 73.56% / 9.131 | 68.59% / 10.12 | 69.00% / 13.56 | 65.05% / 33.81 | 74.44% / 8.814 |
| 10 | 73.69% / 6.791 | 68.71% / 7.607 | 69.19% / 7.6 | 65.07% / 28.74 | 74.45% / 8.2 |
| 11 | 73.75% / 3.779 | n/a | 69.26% / 4.735 | n/a | n/a |
| 12 | n/a | n/a | 69.29% / 2.824 | n/a | n/a |
<!-- /TABLE:results:all -->

Decompression, MB/s. Measured using the corpus compressed at crush-lz level 0. 

<!-- TABLE:decode:all -->
| decoder | LZFSE | LZVN | LZBITMAP | LZ4 | LZMESH |
|---|---|---|---|---|---|
| crush-lz | 2896 | 2234 | 7896 | 6281 | 1364 |
| *Apple* | *2501* | *2248* | *6270* | *7382* | *3141* |
<!-- /TABLE:decode:all -->

[Measurements](docs/bench-run.txt) · [Reproduction instructions](CONTRIBUTING.md#regenerating-the-readme-tables)

LZMESH is not optimized, since it is not a decmpfs algorithm. LZRAVEN is not currently supported (Apple's compressor is very high ratio, and faster compression can use LZMESH). 

## CLI

```bash
cargo install crushlz
crushlz encode input.bin output.lzfse --algo lzfse --level 9
crushlz decode output.lzfse recovered.bin
```

LZFSE and LZVN encoding accepts up to 64 KiB per call or input file.
LZBITMAP and LZ4 encode larger inputs as independent chunks; LZMESH takes
inputs of any size.
Output uses the codec's stream format without an additional container.
Decoding detects LZFSE, LZBITMAP and LZ4 automatically; raw LZVN and LZMESH
require `--algo lzvn` or `--algo lzmesh`.

| command | purpose |
|---|---|
| `crushlz encode` (`c`) | Compress with `--level`, `--algo`, `--verify`, `--threads` |
| `crushlz decode` (`d`) | Decompress |
| `crushlz test` (`t`) | Decode and discard; report format and size |
| `crushlz info` | Identify the format without decoding |
| `crushlz limits` | List algorithms and level ranges |

See the [CLI and Rust API guide](crates/crushlz/README.md) for options and examples.

## Using the Rust bindings

`crushlz` covers every format behind one function pair:

```toml
[dependencies]
crushlz = "0.1"
```

```rust
use crushlz::{Algo, decode, decode_as, encode};

let input = b"example input";

// LZFSE, LZBITMAP and LZ4 streams carry a magic, so `decode` finds the format.
let packed = encode(Algo::Lzbitmap, input, 0)?;
assert_eq!(decode(&packed)?, input);

// Raw LZVN and LZMESH have none; name the format to decode them.
let packed = encode(Algo::Lzmesh, input, 6)?;
assert_eq!(decode_as(Algo::Lzmesh, &packed)?, input);
```

Each codec is also its own crate, with per-codec settings, scratch reuse and
encoding into caller buffers:

```rust
let packed = lzbitmap::compress(input, lzbitmap::Level(7))?;
assert_eq!(lzbitmap::decompress(&packed)?, input);
```

See the READMEs of [crushlzfse](crates/crushlzfse), [lzbitmap](crates/lzbitmap),
[crushlz4](crates/crushlz4) and [lzmesh](crates/lzmesh).

## Using the C libraries

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix /usr/local
```

This installs `libcrushlzfse`, `liblzbitmap`, `libcrushlz4`, their headers and
`pkg-config` files. LZMESH is available from Rust and the CLI only. For
example, an LZBITMAP round trip:

```c
#include <crushlzbitmap.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char input[] = "example input";
    const size_t input_size = sizeof(input) - 1;
    const size_t capacity = crushlzbitmap_encode_bound(input_size);
    void *packed = malloc(capacity);
    if (packed == NULL) return 1;

    size_t packed_size = crushlzbitmap_encode_buffer(
        packed, capacity, input, input_size,
        NULL, 0, CRUSHLZBITMAP_LEVEL_DEFAULT);
    if (packed_size == 0) {
        free(packed);
        return 1;
    }

    char restored[sizeof(input) - 1];
    size_t restored_size = 0;
    int status = crushlzbitmap_decode_buffer(
        restored, sizeof(restored), packed, packed_size, &restored_size);
    free(packed);
    return status != 0 || restored_size != input_size ||
           memcmp(restored, input, input_size) != 0;
}
```

```bash
cc -o mytool mytool.c $(pkg-config --cflags --libs lzbitmap)
```

API declarations and parameter constraints:

- [LZFSE](crates/crushlzfse/csrc/crushlzfse.h) and [LZVN](crates/crushlzfse/csrc/crushlzvn.h)
- [LZBITMAP](crates/lzbitmap/csrc/crushlzbitmap.h)
- [LZ4](crates/crushlz4/csrc/crushlz4.h)

See [memory requirements](docs/memory.md) for scratch sizing and reuse.

## Benchmarking

```bash
make -C harness
harness/build/bench --list
harness/build/bench manifest.txt --sequential --engines crushlzfse:8,apple-lzfse,zstd:19
```

The [harness guide](harness/README.md) describes benchmark options, output,
conformance tests and fuzzing. Apple's codecs require macOS; `zstd` and
`zopfli` are optional benchmark baselines.

## Reproducing the corpus

```bash
cargo run -p xtask -- corpus fetch
cargo run -p xtask -- corpus build
cargo run -p xtask -- corpus manifest > manifest.txt
```

Source hashes are pinned in `corpus/oss.lock.toml`; sampling uses a fixed seed.

## Testing

```bash
cargo test
make -C harness check
make -C harness sanitize
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for fuzzing and release checks.

## License

Project code is licensed under MPL-2.0. Apple-derived code also carries
BSD-3-Clause terms, Corellium-derived code MIT terms, and vendored LZ4 code
BSD-2-Clause terms. See [THIRD-PARTY.md](THIRD-PARTY.md) for scope and notices.
