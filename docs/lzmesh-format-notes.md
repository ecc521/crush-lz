# LZMESH (0xE05) format notes

Black-box findings, derived only from Apple's public `compression_encode_buffer`
and `compression_decode_buffer` on macOS 27.2.

`harness/tools/lzmesh_probe/meshdec.py` is a Python reference block decoder;
`check_corpus.py` in the same directory decodes Apple's encoding of corpus
files with it (run it from that directory). The C decoder in `crates/lzmesh`
decodes Apple's streams for all 500 `corpus/segments/main` files, and Apple's
decoder accepts our encoder's output for all of them.

The entropy coder is canonical Huffman (max code length 10) over 8
interleaved lanes.

## Framing

Blocks follow each other and the stream ends with a single `0xFF` byte.

- Raw block: `00`, `u32 LE usize`, then `usize` bytes.
- Compressed block: `01`, `u32 LE usize`, `u16 LE s1`, `u16 LE s2`, then `s2`
  payload bytes, then one byte holding bits 8..15 of the distance count
  (see the footer).

Apple's decoder treats `usize` as an output cap and silently truncates the last
match. Its encoder relies on this: the final op of a block is
`lits + rep0 len 2`, and the match part gets cut off.
It also rejects a block unless `s2 < usize`.

A block can also end with ops that stop short of `usize`; Apple's encoder
does both.

### Stream budget

Apple's decoder rejects a block unless

```
r32(lits) + r32(ops) + r32(extras) + r32(dists) + r32(4 * dists) <= 62944
```

where `r32` rounds up to a multiple of 32 and each term is a stream's element
count (extras in bytes). Every term was moved across a 32-byte step on its own
to confirm its weight. Apple's own blocks reach at most 62592. There is no
separate limit on the op count (30000 ops decode fine).

Apple's encoder splits input into blocks of varying size (e.g. 33796, then
81274, then 186130 bytes; up to at least 609469). Matches reach into earlier
blocks, and the rep distances carry over from block to block.

## Payload layout

```
[raw/RLE streams][lanes 0..7][lane-size trailer][footer]
                 ^ s1 - 9
```

### Footer (last 9 payload bytes)

`[modes u16 LE][ops u16 LE][extras u16 LE][lits u16 LE][dists u8]`

`modes` holds 3 bits per stream, in this order: literals (bits 0..2), ops
(3..5), extras (6..8), distances (9..11). Values:

| mode | meaning | bytes in the raw region |
|---|---|---|
| 0 | raw | `count` bytes |
| 1 | RLE: every element equals one stored byte | 1 byte |
| 2 | Huffman coded in the lanes | 0 bytes |

The high byte of `modes` is 0x04 when distances are coded. Apple's usual large block has `modes = 0x492`
(everything coded) and `s1 = 9`.

`dists` is the low 8 bits of the distance count; the byte after the payload
holds the high 8 bits. The count must equal the number of ops with
`mcode >= 32`.

### Raw region

Starting at payload offset 0, the streams whose mode is 0 or 1 are stored in
the order literals, ops, extras, distances. The lanes begin right after, at
`s1 - 9`. When no lane data is needed (nothing coded and no far distances) the
payload is just the raw region and the footer.

### Ops (one byte per op)

`op = lcode << 6 | mcode`

Literal count before the match:

- first op of the whole stream: `lcode + 1`, or `4 + extra` when `lcode == 3`
- every other op, including the first op of later blocks: `lcode`, or
  `3 + extra` when `lcode == 3`

Match:

| mcode | meaning |
|---|---|
| 0..31 | repeat distance `rep[mcode >> 3]`, length `(mcode & 7) + 2`; `&7 == 7` means `9 + extra` |
| 32..62 | new distance from the dist stream, length `mcode - 30` (2..32) |
| 63 | new distance, length `33 + extra` |

Rep distances start as `[1, 1, 1, 1]` at the start of the stream. Using
`rep[i]` moves it to the front. A new distance is pushed to the front and the
oldest one drops off.

### Extras

One value per escape, in op order: the literal extra first, then the match
extra. A byte below 0xFF is the value. `0xFF` is followed by a u32 LE value.
When extras are coded, the Huffman symbols are these bytes.

### Distances

One byte per new-distance match: `b = k << 3 | low3`.

- `k == 0`: `D = low3 + 1`
- `k > 0`: `a` is `(1 << k) | v`, where `v` is `k` bits read from the lanes,
  and `D = ((a - 1) << 3 | low3) + 1`.

`D` can exceed 32 bits. Apple's decoder keeps its low 32 bits, and that value
is what the match uses and what enters the rep slots. A `D` that becomes 0, or
points before the start of the output, is rejected when the match copies a
byte; a match cut to zero length by the block size is not checked.

## Lanes

Eight bitstreams. Bits are read LSB-first within each byte. Every non-empty
lane ends with a single `1` stop bit, then zero padding to a byte boundary, so
lanes 1..7 start on byte boundaries. Apple's decoder does not check the stop
bit or the padding (see "Decoder strictness").

Contents, in decode order:

1. For each coded stream, in the order literals, ops, extras, distances:
   a Huffman table (below), then its symbols. Symbol `j` of the stream is read
   from lane `j % 8`.
2. The far-distance bits: the `j`-th distance (counting every distance,
   including `k == 0` ones) reads its `k` bits from lane `j % 8`. The value is
   stored LSB-first.

A Huffman code is read MSB-first (first code bit at the lowest bit position).

### Huffman table

Read from lane 0 except where noted:

- 11 fields of 3 bits, LSB-first: the code length (0..7) of each code-length
  value 0..10. These define the code-length code; it is canonical (sorted by
  length, then value). A code-length value of 0 means "symbol absent".
- 16 fields of 2 bits, MSB-first, one per high nibble. Bit 1 (0b10) means
  symbols `h0..h7` take part, bit 0 (0b01) means `h8..hf` take part.
- For each participating symbol in increasing byte order, its code length as
  a code-length-code symbol. Participating symbol `j` is read from lane
  `j % 8`, so these are spread over all lanes.

The symbol code is canonical Huffman over the byte values: sorted by code
length, then by byte value. Code lengths are at most 10.

### Lane-size trailer

The trailer ends at `E - 1`, where `E = len(payload) - 9` is the first footer
byte.

- `w = payload[E - 1] >> 3` is the field width.
- The trailer is `max(4, ceil((7w + 5) / 8))` bytes long and ends at `E - 1`
  (inclusive).
- Starting at its first byte, 7 fields of `w` bits, LSB-first: the byte sizes
  of lanes 0..6. Lane 0 starts at `s1 - 9`; lane 7 runs to the trailer start.

Raw-literal blocks that only carry far-distance bits use the same lanes and
trailer.

## Decoder strictness

Found by differential fuzzing against Apple's decoder
(`harness/fuzz/lzmesh_decode_diff_vs_apple.c`):

- Lane sizes only place each lane's start. A lane that reads past its end
  continues into the following bytes up to the footer, then reads zeros.
  Stop bits and padding are not checked.
- A block's streams must be used up exactly: leftover ops, literals, extras or
  distances make Apple reject it.
- Only the literals actually written must exist, so the final literal run may
  claim more than the block has room for, up to a limit that depends on the
  index of the op being decoded:
  `lit_offset + run > r32(lits) + op_index` fails.
- Not matched yet: Apple rejects some streams in which lane 7 overruns into
  the lane-size trailer, and accepts others; no threshold on the overrun
  separates them. Our decoder accepts these (about 0.07% of damaged streams
  in the fuzzer) and never decodes a stream differently from Apple.

## Open questions

- Can a coded table hold a single symbol? Apple uses RLE mode instead, so an
  encoder can avoid the case.
- Whether lits/ops counts above 65535 can occur in one block (they did not in
  the corpus, even for a 609 KB block).
