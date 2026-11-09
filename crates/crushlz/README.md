# crushlz

A combined Rust API and CLI for LZFSE, LZVN, LZBITMAP, LZ4 and LZMESH.

```bash
cargo install crushlz
```

## CLI

```bash
crushlz encode input.bin output.lzfse --algo lzfse --level 9
crushlz decode output.lzfse recovered.bin
```

Output uses the codec's stream format without an additional container.
Decoding detects LZFSE, LZBITMAP and LZ4 automatically.
Raw LZVN and LZMESH require an explicit algorithm:

```bash
crushlz encode payload.bin payload.lzvn --algo lzvn --level 6
crushlz decode payload.lzvn recovered.bin --algo lzvn
```

LZFSE and LZVN encoding accepts up to 64 KiB per input file or API call at
all levels. LZBITMAP and LZ4 split larger inputs into independent chunks;
LZBITMAP's input limit is just under 4 GiB. LZMESH takes inputs of any size.

| command | purpose |
|---|---|
| `encode` (`c`) | Compress with `--algo`, `--level`, `--threads`, `--verify` |
| `decode` (`d`) | Decompress |
| `test` (`t`) | Decode and discard; report format and size |
| `info` | Identify the format without decoding |
| `limits` | List algorithms and level ranges |

Encoding options:

- `--verify`: decode and compare with the input before writing output.
  On macOS this also checks Apple's decoder.
- `--threads N`: parallel LZBITMAP encoding; 0 uses one worker per core.
  Other algorithms use one thread. Output does not depend on the thread count.
- `--max-memory MiB`: reject encoding if estimated scratch exceeds the budget.
  Input and output buffers are excluded from the estimate.

LZFSE levels range from -5 to 11, LZBITMAP from -5 to 12, and LZVN, LZ4 and LZMESH from -5 to 10,
with default 0. This API and CLI reject
out-of-range levels.

## Library

```rust
use crushlz::{Algo, decode, decode_as, detect, encode};

let input = b"example input";
let packed = encode(Algo::Lzfse, input, 9)?;
assert_eq!(detect(&packed), Some(Algo::Lzfse));
assert_eq!(decode(&packed)?, input);

let packed = encode(Algo::Lzvn, input, 6)?;
assert_eq!(decode_as(Algo::Lzvn, &packed)?, input);
```

For codec-specific settings and buffer reuse, use the individual crates:
[crushlzfse](../crushlzfse), [lzbitmap](../lzbitmap), [crushlz4](../crushlz4), [lzmesh](../lzmesh).

## Formats

| algorithm | decmpfs types | stream |
|---|---|---|
| `lzfse` | 11/12 | LZFSE framing; may contain LZVN blocks |
| `lzvn` | 7/8 | Raw LZVN, without a format header |
| `lzbitmap` | 13/14 | LZBITMAP framing |
| `lz4` | 15/16 | Apple's `bv4` framing around LZ4 blocks |
| `lzmesh` | none | LZMESH blocks, without a format header |

## Licensing

`MPL-2.0 AND MIT AND BSD-2-Clause AND BSD-3-Clause`. This crate includes
Apple-derived, Corellium-derived and upstream LZ4 code through its dependencies.
See [THIRD-PARTY.md](../../THIRD-PARTY.md).
