# LZBITMAP stream format

This describes the format Crush supports and, separately, the observed
behavior of Apple's decoder.

For supported streams, sufficient destination space must produce exactly the
bytes specified here. For every input, including unsupported or malformed
streams, the decoder must stay memory safe, honor the destination capacity,
and terminate. Outside the supported format, success, rejection and output
bytes are unspecified by the format. This never permits C undefined behavior.

The compatibility goal is to support every stream Apple decodes with the
ordinary literal/copy semantics, except periods below eight. Current Crush
rejects periods below eight and references before produced output; those are
implementation choices, not prescribed error outcomes of this format.
Safety assumes the API is supplied readable source bytes, sufficient writable
destination storage for its declared capacity, and a writable `out_len`;
source, destination and the length result are separate storage ranges.

"Apple" below means observed behavior of libcompression on macOS 27.2 build
26B5101f, not documentation or a promise about other OS versions.

## Stream

```
stream  = "ZBM" 0x09, chunk*, end-chunk, [ignored bytes]
chunk   = len:u24le, decmp_len:u24le, body
```

* `end-chunk` is `len = 6, decmp_len = 0`. A stream without one is invalid.
  Bytes after it are ignored.
* `6 <= len <= bytes left in the stream`, `decmp_len <= 32768`.
* A data chunk of any positive `decmp_len` may come before the end chunk. It
  does not have to be 32768 bytes, a multiple of 8, or the last data chunk.
* Output is one buffer for the whole stream. Copies may reach into earlier
  chunks.

The chunk kind comes from the two lengths:

| condition              | kind       |
|------------------------|------------|
| `len == decmp_len + 6` | stored: the body is `decmp_len` raw bytes |
| `len != decmp_len + 6` | compressed, provided its body satisfies the rules below |

Compression need not save space. Crush supports compressed chunks larger than
their stored form and small chunks with coherent semantics. Apple rejects
the oversized compressed chunks tested here. Equal lengths always select the
stored interpretation, regardless of the body's apparent structure.

## Compressed chunk

```
offset 0   len, decmp_len           (6 bytes)
offset 6   off1, off2, off3: u24le  (9 bytes)
offset 15  literals                 [15, off1)
           meta1: period bytes      [off1, off2)
           meta2: explicit bitmaps  starting at off2
           meta3: selector nibbles  starting at off3
len - 17   bitmap table             (17 bytes)
```

Each offset must be `< len`, with `15 <= off1 <= off2 <= off3`.
The latter two cursors may consume bytes also used by later metadata or the
bitmap table. They must stay inside the chunk; the offsets identify starting
positions, not exclusive ownership of those bytes. Separate areas remain the
ordinary encoding layout.

**Bitmap table.** The first 15 bytes are a little-endian bit stream of 12
entries, 10 bits each: bits `[10i, 10i+8)` are the bitmap and
`[10i+8, 10i+10)` the period byte count `pbc`. `pbc = 3` makes the chunk
invalid even when nothing selects that entry. The last 2 bytes are ignored.

**Selectors.** meta3 is read a nibble at a time, low nibble first.

* `0, 1, 2`: an explicit block. Its bitmap is the next meta2 byte, and the
  nibble value is its `pbc`.
* `3..14`: table entry `n - 3`.
* `0xf`: a repeat marker (see Runs), or a standalone selector that reuses the
  last consumed non-`0xf` nibble. That history includes count digits and starts
  at zero in each chunk.

**Applying a block.**

1. If `pbc > 0`, read `pbc` bytes from meta1 as a little-endian period, and
   that becomes the current period.
2. The block covers `count = min(8, decmp_len - written)` bytes.
3. Bit `i` set means the next literal byte. Bit `i` clear means a copy:
   `out[p] = out[p - period]`.
4. Bits at or past `count` are ignored and consume no literals.

The period starts at 8 in every chunk; it does not carry over from the previous
chunk. The correctness guarantee covers periods `8..65535`. Periods `0..7`
are outside that guarantee: Apple's behavior varies and does not reliably
implement ordinary backward copying. Crush currently rejects them.

**Copy distance.** Every live copy at stream-output position `p` must have
`p >= period`. A literal prefix can make a later copy valid even when its block
started less than `period` bytes into output; Crush uses its scalar path there.
An actual copy from before the start of produced output is outside the
correctness guarantee. Crush currently returns an error; it does not reproduce
Apple's output for such streams, which varies with the chunk layout.

**Runs.** After a selector, if more than 8 bytes of the chunk remain and the
next nibble is `0xf`, a count follows. The selector applies
`4 + sum(nibbles)` times in total, where the count keeps reading nibbles while
they are `0xf` (`0xf 0xf 3` is `4 + 15 + 3 = 22`). With 8 or fewer bytes left,
no count is read. A standalone selector `0xf` uses `3 + sum(count nibbles)`
instead, without needing a second introducer. Thus `0xf, 1` repeats the
remembered selector four times. With at most eight bytes remaining it applies
that selector once and reads no count.

A run may name more blocks than the chunk has left. Once the
chunk is full, the extra blocks are dropped and consume nothing: no literals,
no meta1 period bytes, no meta2 bitmaps.
The count has no 16-bit validity limit. Crush consumes all its nibbles but
saturates the internal count at 4096, the most blocks any chunk can use.

**End of chunk.** After `decmp_len` bytes:

* Literals must end exactly at `off1`.
* meta1 must end exactly at `off2`.
* meta2 and meta3 may leave unused bytes or consume bytes belonging to later
  metadata and the table. Every actual read must be inside the chunk.

## Where Apple differs

Each case was tested against an accepted control stream. There is no
independent whole-stream reference model; the conformance regressions named
below carry independent bytewise expectations.

| Input | Apple | Crush |
|---|---|---|
| Compressed chunk with `len > decmp_len + 6` | rejects tested cases | accepts |
| Over-long run whose selector reads meta1 (`pbc > 0`) or meta2 (`0..2`) | drops extra blocks in isolated cases | drops extra blocks; `zbm_overlong_run_test.c` |
| `0xf` where a selector is expected | all 15 remembered values and 1..40-byte tails match ordinary runs and independent bytes in 1200 cases | supports via a slow-path history scan; `zbm_repeat_history_test.c` |
| Period 1..7 | accepts; output is wrong for some layouts | rejects |
| Period 0 | usually rejects; sometimes accepts with the output of the next row | rejects |
| Copy from before the start of output | small chunks: rejects. Large chunks: copies from `dst[0]` instead (wrong output, but memory-safe). The switch depends on chunk layout. | rejects |
| Literal prefix makes each actual copy valid despite an early block start | rejects seven isolated layouts | accepts ordinary copy semantics; `zbm_copy_after_literals_test.c` |
| meta2 read past `off3` | confirmed first meta3 byte with a control; a further sweep reuses selector bytes and 0..8 table bytes, then rejects 9..12 in that layout | accepts chunk-bounded reads; `zbm_metadata_overlap_test.c` |
| meta3 nibbles inside the table | confirmed both nibbles of table byte 0 with an accepted control | accepts chunk-bounded reads; same regression |

The period and early-copy rows are not exhaustive characterizations of
Apple's decoder.

## Not covered

* Selector-history layouts beyond every remembered value and trailing partial
  blocks.
* Metadata/table overlap beyond the specific cases above.
* Noncanonical zero-output terminators: Crush accepts some compressed ones,
  whereas the specified canonical terminator is six bytes. No correctness
  guarantee is made for the other forms.
* The NULL-destination size probe validates headers and lengths only, as the
  API documents. A successful probe does not certify a supported chunk body.

Both decoders agree on everything else tested:

* bytes after the end chunk are ignored;
* the table's last 2 bytes are ignored;
* `pbc = 3` in an unused table entry is invalid;
* unused bytes at the end of meta2 or meta3 are allowed;
* unused literal or meta1 bytes are invalid;
* a stored chunk over 32768 bytes is invalid;
* the period resets to 8 at each chunk;
* copies reach across chunks of any length;
* an explicit selector repeated in a run reads a new meta2 byte per block;
* a partial last block ignores the bitmap bits past its end.
