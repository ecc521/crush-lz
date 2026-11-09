# Proofs

Fuzzing tests one input at a time. These proofs check a property for *every*
input at once: no out-of-bounds access, no undefined behavior, and loops
that terminate. Two tools share the work:

- [CBMC](https://github.com/diffblue/cbmc) checks function contracts and
  their composition. The targets are the `.c` harnesses here, registered in
  `run.sh`.
- [Frama-C WP](https://frama-c.com/fc-plugins/wp.html) proves loops and
  bodies that are too large for CBMC, from source slices extracted from the
  shipping code. The targets are the Python scripts in `frama/`; see
  [frama/README.md](frama/README.md).

The memory-safety contracts do not specify output bytes. Finite helper
proofs check exact values for blend, table, packing and nibble helpers.
Whole-decoder output correctness is not proved.

[COVERAGE.md](COVERAGE.md) lists every codec's proved obligations and what
each one trusts.

## Running

```bash
make -C harness proofs           # every CBMC proof, plus its reachability goals
make -C harness proofs-mutants   # each CBMC proof must fail on known bugs
harness/proofs/run.sh lz4_decode_block   # one proof
```

Proofs and mutants run in parallel, one per CPU (`PROOF_JOBS` overrides).
Allow up to 4 GiB per active proof job; some targets need 16 to 48 GiB
(`CBMC_GIB` in `replay.py`). Main verification and reachability run serially
within each job. Set `PROOF_PARALLEL_REACH=1` only when memory permits both
at once. Every CBMC run is capped at `PROOF_TIMEOUT` minutes (default 60).

You need CBMC 6 or later. The Ubuntu 24.04 package (5.95) is too old: it
rejects loop contracts on `do`/`while` loops. CI pins CBMC 6.11.0.

The two Dockerfiles here pin both toolchains. Build them from the
repository root:

```bash
docker build -t crushlz-proofs:6.11.0 harness/proofs
docker build -t crushlz-frama-period:bookworm harness/proofs/frama
```

The CBMC image runs `make -C harness proofs` with the checkout mounted at
`/work`. It sets `PROOF_JOBS=16`; lower it to fit the container's memory:

```bash
docker run --rm --memory 8g -v "$PWD:/work" -e PROOF_JOBS=2 crushlz-proofs:6.11.0
docker run --rm -v "$PWD:/work" -w /work --entrypoint sh \
  crushlz-proofs:6.11.0 harness/proofs/run.sh lzfse_lmd_resume
```

Run any Frama-C script the same way. `--mutants` also checks that its unsafe
variants fail:

```bash
docker run --rm -v "$PWD:/work" -w /work --entrypoint python3 \
  crushlz-frama-period:bookworm harness/proofs/frama/lzfse_literals_native.py --mutants
```

Logs go to `harness/build/proofs` and `harness/build/proofs-frama-*`.

To replay everything (CBMC targets, CBMC mutants, Frama-C scripts and the
SIMD checks) in containers with a memory cap per job, and record the result:

```bash
python3 harness/proofs/replay.py run --budget 56
python3 harness/proofs/replay.py collect --out harness/proofs/results-DATE.json
```

`inventory.py` reads that file to report which contracts are enforced on the
current tree.

## What is proved

Memory safety and termination, under the assumptions in
[What the proofs trust](#what-the-proofs-trust). Details per target are in
[COVERAGE.md](COVERAGE.md).

| Codec | Decoder | Encoder |
|---|---|---|
| LZ4 | Our decoder: `crushlz4_decode_buffer` for every input, end to end | Our framing wrapper, allocation and queries. The upstream LZ4 compressor is trusted. |
| LZVN | The shipping computed-goto decoder body, re-entry, and the public buffer API | Greedy, fast and optimal strategies, emitters, scratch carving and the public API, composed end to end |
| LZFSE | Frame loop, literal and L/M/D loops, FSE bitstream and table builders, declared-length parser and buffer APIs, composed end to end | Fast, lazy and optimal strategies, backend, chained encoding, parameters, scratch and the public API, composed end to end |
| LZBITMAP | The full decoder on the portable, NEON and SSE branches | Framing, chunk and buffer APIs for a modelled chunk builder; shared metadata, selector and literal writers; many strategy components. **The strategy builders are not composed, so whole-encoder memory safety is not proved.** |
| LZMESH | Not covered | Not covered |

The table reflects the most recent full replay. No results file is checked
in; run `replay.py` to confirm it on your tree.

## How the proofs fit together

A function contract is a `requires` (what the caller must guarantee), an
`assigns` (what the function may write) and an `ensures` (what it
guarantees back). Each contract is used twice:

- **Enforced** in the function's own proof. CBMC assumes `requires`,
  runs the real body, and checks every access, the `assigns` frame and
  `ensures`.
- **Replaced** in each caller's proof. Every call becomes: assert
  `requires` at the call site, havoc only what `assigns` names, assume
  `ensures`.

The LZ4 decoder is the smallest example. Three proofs, one per function,
are joined by contracts:

| proof | proves | uses |
|---|---|---|
| `lz4_decode` | `crushlz4_decode_buffer` (and `decode`) is safe for any `src`, `dst`, sizes and bytes the API allows | `decode_block`'s contract |
| `lz4_decode_block` | `decode_block` meets its contract for any block bytes | `copy_match`'s contract |
| `lz4_copy_match` | `copy_match` meets its contract | none |

The runner removes contract-replaced implementations before instrumenting a
caller, keeping their contract symbols. Those implementations are checked in
their own proof targets. This avoids instrumenting unreachable loops.

This checks the composition within the pointer layouts each harness models.
If a contract is too weak, the caller's proof fails. If it is too strong,
the function's own proof fails. If a caller does not establish `requires`
(say it passes too large a `room`), the caller's proof fails. The mutants
`copy_match_room_too_big` and `decode_block_cap_too_big` check exactly
that.

Some contracts are proved by a Frama-C script instead of a CBMC target
(`EXTERNAL_PROOFS` in `inventory.py`). The script proves the shipping body
against an ACSL contract, and CBMC callers replace the body by the matching
CBMC contract. For the LZVN decoder and the LZFSE frame, a WP bridge proves
that one contract implies the other. Elsewhere the match is checked by
review.

Harness allocation sizes and pointer/alias construction are also trusted
assumptions. See [What the proofs trust](#what-the-proofs-trust).

Splitting the code this way is what keeps it tractable: each proof sees one
function body, with its callees reduced to a few constraints.

## Cost

Solver time cannot be predicted exactly, but it is bounded by design. A
proof's formula covers one function body, with each loop cut to a single
iteration and each callee cut to its contract. So cost tracks the largest
single function, not the size of the codec or of its inputs.

`run.sh` reports each proof's formula size and solver time. The formula
size is in the log within seconds of starting, before the solver runs. A
proof that hits the time cap fails like any other. The usual fix is to move
part of the function behind its own contract. A stronger loop invariant or a
different solver can also help.

| proof | formula | solver time |
|---|---|---|
| `lz4_copy_match` | 48k variables, 0.34M clauses | under 1 minute |
| `lz4_decode` | 93k variables, 1.5M clauses | about 2 minutes |
| `lz4_decode_block` | 667k variables, 5.8M clauses | about 22 minutes |

Times are from one core of a 4-core cloud VM with CaDiCaL. Mutants are
cheaper than proofs, because finding one counterexample is easier than
showing none exists.

## How a proof works

**Contracts in the codec source.** These are the `CLZ4_REQUIRES`,
`CLZ4_ASSIGNS`, `CLZ4_ENSURES` and `CLZ4_LOOP_*` annotations in
`crushlz4.c`, and the corresponding `ZBM_*`, LZFSE and LZVN annotations in
the other codecs. They expand to nothing outside a proof build. Helpers
with their own proof boundary are forced inline so the boundary adds no
runtime call.

```c
do
    CLZ4_LOOP_ASSIGNS(k, __CPROVER_object_upto(d, room))  /* what it may write */
    CLZ4_LOOP_INVARIANT(k == 0 || k < mlen)               /* true at every iteration */
    CLZ4_LOOP_DECREASES(mlen - k)                         /* drops every iteration */
{ ... } while (k < mlen);
```

CBMC never unrolls a loop with a contract. Instead it checks four things:

1. The invariant holds on entry.
2. *One* iteration, starting from *any* state where the invariant holds,
   keeps it true, writes only what `assigns` names, and makes `decreases`
   strictly smaller.
3. Every access inside that iteration is in bounds.
4. Whatever runs after the loop is safe, given only the invariant and the
   exit condition.

Steps 1 and 2 together cover every iteration count, so no length is
bounded. A residual instrumentation-loop unwind bound, where used, keeps the
codec loop contracts and requires every unwinding assertion to pass. Finite
helper proofs explicitly unroll their fixed-size loops instead. The
`decreases` check proves termination.

An invariant is all the proof knows about a loop once it is done. An inner
loop that only moves `sp` forward must therefore say
`sp >= CLZ4_LOOP_ENTRY(sp)`. Without it, CBMC finds a state where the inner
loop moved `sp` backwards, and the enclosing loop's `decreases` fails.

**A harness here.** It allocates buffers of unconstrained size and picks
unconstrained arguments, then calls the function. For an enforced
contract the harness assumes nothing beyond "these pointers point into
some buffer". CBMC assumes the `requires` clauses itself. Every value they
allow is checked at once, symbolically.

`proof.h` swaps `memcpy` for its contract: valid source, valid destination,
no overlap, and it writes only `d[0, n)`. Safety depends on where bytes go,
not which bytes they are. So a proof never needs `memcpy`'s data movement,
and the solver stays fast. Value proofs that need the bytes use the real
`memcpy` instead.

**A Frama-C script.** It extracts the shipping function from the codec
source, checks the extracted text against its expected shape (and often a
source hash), adds ACSL annotations, and runs WP. `wp_common.py` requires a
clean exit, no unexpected warnings, at least the expected number of goals,
and every goal proved. Frama-C's exit status alone does not confirm a
complete proof.

## What the proofs trust

A proof is only as good as these assumptions. Check them when reviewing.

- **The top harness's assumptions**, for example in `lz4_decode.c`. They
  are the API contract: `src` is NULL or readable for `src_size` bytes,
  `dst` is NULL or writable for `dst_size` bytes, and `out_len` is NULL or
  writable. The LZ4 harness allocates `src` and `dst` as separate objects,
  so its proofs do not cover overlapping buffers or disjoint slices of one
  allocation. Other codecs extend this to disjoint ranges of one allocation
  where COVERAGE.md says so. Objects are capped at `PROOF_MAX_OBJECT`
  (2^48 bytes); loop iteration counts are not bounded in the loop-contract
  proofs.
- **The `requires` clauses are not trusted.** Each is checked at every
  call site by the caller's proof. A harness for an enforced contract
  should assume only what it needs to build its pointers.
- **`PROOF_REACHABLE` goals guard against vacuity.** A contradictory
  `requires` or assumption would make every check pass. Each goal names a
  result the proof must be able to reach after the call. `run.sh` rebuilds
  with `PROOF_REACH`, which turns each goal into "this is impossible", and
  requires CBMC to refute every goal with a witness. All declared goals must
  appear in a completed result; a partial log or timeout is not a pass.
  Outcome witnesses do not prove that every internal branch is reachable or
  rule out every overconstraint in a harness.
- **The C source, not the binary.** CBMC checks C semantics on an LP64
  little-endian target. It trusts the compiler, and it ignores
  `CLZ4_NOVEC` and `__builtin_expect`, which affect only code generation.
  Unsigned wraparound is not flagged, because the decoders rely on it
  (`off - 1 >= dp`).
- **Plain `char` signedness.** The CBMC image is linux/arm64, where
  goto-cc treats plain `char` as unsigned. The shipping targets use signed
  `char`, so `run.sh` passes `-fsigned-char` to every target.
- **Reduced configurations are not evidence.** The CBMC targets
  `lzfse_decode_literals` and `lzfse_decode_lmd` check the reduced
  `LZFSE_PROOF` configuration, and `emit` and `emit_literal` check
  `LZVN_FAST_COPY`. They are not counted; Frama-C proofs cover the shipping
  bodies.
- **The `lzfse_decode` dispatcher target caps the frame loop at four
  iterations.** The capped path is pruned, so every status witness comes
  from a real return. `lzfse_decode_frame` proves the unbounded loop.
- **Dispatcher contracts.** The encoder contracts compiled under
  `CRUSHLZFSE_DISPATCH_PROOF` and `CRUSHLZVN_DISPATCH_PROOF` are enforced by
  their own targets. `UNENFORCED_DISPATCH` in `inventory.py` is empty.
- **Standard library models.** `proof.h` gives `memcpy`, `memmove` and
  `memset` the C standard's requirements and write frames, nothing more.
  The Frama-C scripts use the same footprints.
- **Native SIMD.** Intrinsics are replaced by C models that are validated
  against hardware, not proved. See [simd/README.md](simd/README.md).
- **Cross-tool contracts.** Where a Frama-C proof stands in for a CBMC
  contract without a WP bridge, the two contracts are matched by review.
- **Encoder callers.** Encoder proofs assume valid, separate source,
  destination, parameter and scratch objects, the documented scratch
  alignment and supported source sizes. The Rust safe APIs provide these.
  C callers must.
- **The tools.** CBMC and its contract instrumentation; Frama-C, WP, Why3
  and the SMT solvers it calls (Z3 and CVC4).

## When a proof fails

`run.sh` prints the failed checks and the log path. To get the
counterexample, rerun the last `cbmc` command from `run.sh` on
`harness/build/proofs/<proof>.goto` with `--trace` (add `--stop-on-fail`
for the first one quickly). The trace gives concrete sizes and arguments
that break the property. That input can become a regression test. A trace
through a loop with a contract starts from an arbitrary state that
satisfies the invariant, not from the function's entry. If that state
cannot really happen, the invariant is too weak: strengthen it.

A failed Frama-C goal has no trace. The log names the goal and its source
location. Read the generated source in `harness/build/proofs-frama-*`.

When you change annotated code, the result is one of three things:

1. **The contracts still hold.** This covers refactors and scheduling
   changes. The proofs pass with no edits.
2. **The change is unsafe.** A proof fails.
3. **The change alters the safety argument on purpose,** for example a
   different slack or a wider copy. Edit the invariant, `assigns` clause or
   contract to match. That diff is the part a reviewer needs to check.

A Frama-C script that extracts source fails when the shipping text no
longer matches its expected shape. Update the script's patterns and source
hash together with the proof.

## Mutants

`run.sh mutants` applies each edit in `MUTANTS` to a copy of the source and
checks that the proof then *fails*. They target bounds checks (safe-zone
margins, offsets, ranges and source lengths), capacity and progress checks,
history bounds, chunk source and destination limits, loops that stop making
progress, and callers that break a callee's `requires`. A proof that passes
a mutant is not checking what it claims. When you add a proof, add a mutant
for each property it guards.

Each Frama-C script's `--mutants` option runs its unsafe source variants.
A variant counts as rejected when at least one goal stays unproved. Often
that goal times out rather than being refuted, which shows the proof
depends on the mutated check but is weaker evidence than a counterexample.

## Adding a proof

1. Annotate each loop in the target function with `assigns`, an invariant
   and a `decreases` clause. Give the function a contract if anything
   calls it.
2. Write `harness/proofs/<name>.c`:
   - include `proof.h`, then the codec source;
   - build pointers into unconstrained buffers, and assume nothing else;
   - add a `PROOF_REACHABLE` goal for each outcome, after the call.
3. Register it in `run.sh`: the function whose contract it enforces, and
   the callees to replace by theirs. Every replaced contract must be
   enforced by some other proof in the list, or proved by a Frama-C script
   listed in `EXTERNAL_PROOFS`.
4. Add mutants.

For a body CBMC cannot handle, write a script in `frama/` on top of
`wp_common.py` instead. `replay.py` runs every script in that directory.
Give it a minimum goal count and unsafe variants for `--mutants`.
