#!/usr/bin/env python3
# Copyright (c) 2026 Tucker Willenborg
# SPDX-License-Identifier: MPL-2.0
"""Regenerates every results and settings table in the READMEs.

    harness/build/level_table > levels.tsv
    harness/build/bench manifest.txt --sequential --engines ... > docs/bench-run.txt
    python3 harness/tools/readme_table.py levels.tsv docs/bench-run.txt

Pass --sequential. Without it bench interleaves the engines per block, and each
one then re-encodes the block the previous ones just pulled into cache; engines
stay comparable to each other, but every rate sits above what that engine does on
its own, and two levels with identical settings can read 45% apart. --sequential
gives each engine its own pass and reproduces a solo run. Runs split across
several invocations are fine in that mode: reversing the engine order moves a
rate by under 3%.

Measurements come from the bench run; settings, the memory column, the
default marker and the merging of aliased levels come from the level table,
which reads them from the API. Tables are rewritten in place between

    <!-- TABLE:name -->  ...  <!-- /TABLE:name -->

markers. With --check nothing is written and a stale table exits non-zero,
which is what CI wants.
"""
import re
import sys

CODECS = [("LZFSE", "crushlzfse", "apple-lzfse"), ("LZVN", "crushlzvn", "apple-lzvn"),
          ("LZBITMAP", "lzbitmap", "apple-lzbitmap"), ("LZ4", "crushlz4", "apple-lz4"),
          ("LZMESH", "lzmesh", "apple-lzmesh")]
README = {"crushlzfse": "crates/crushlzfse/README.md", "crushlzvn": "crates/crushlzfse/README.md",
          "lzbitmap": "crates/lzbitmap/README.md", "crushlz4": "crates/crushlz4/README.md",
          "lzmesh": "crates/lzmesh/README.md"}
DEFAULT = 0
LEVELS = range(-5, 13)
# ENGINE ENCODER RATIO SAVED% ENC DEC(ours) DEC(apple) REFUSED FAILED
BENCH = re.compile(r"^(\S+)\s+(ours|APPLE)\s+[\d.]+\s+([\d.]+)%\s+"
                   r"(\S+)\s+(\S+)\s+(\S+)\s+\d+\s+\d+")


def mbps(text):
    # The exponent form is accepted because runs stored before bench's
    # formatter was fixed carry rates like "1.131e+04M".
    m = re.match(r"^([\d.]+(?:[eE][+-]?\d+)?)([KMG]?)$", text)
    if not m:
        return None
    return float(m.group(1)) * {"": 1e-6, "K": 1e-3, "M": 1.0, "G": 1e3}[m.group(2)]


def read_bench(paths):
    out = {}
    for path in paths:
        for line in open(path):
            m = BENCH.match(line)
            if m:
                out[m.group(1)] = (float(m.group(3)), mbps(m.group(4)),
                                   mbps(m.group(5)), mbps(m.group(6)))
    return out


def read_levels(path):
    """{codec: {level: (strategy, {field: value})}} in field order."""
    out = {}
    for line in open(path):
        if line.startswith("#") or not line.strip():
            continue
        codec, level, strategy, field, value = line.rstrip("\n").split("\t")
        codec_map = out.setdefault(codec, {})
        strat, fields = codec_map.setdefault(int(level), (strategy, {}))
        fields[field] = int(value)
    return out


def memory(n):
    """MiB reads as 0.06 below a megabyte, so switch units rather than digits.
    crushlz4's depth-1 levels are the first to need this."""
    if not n:
        return ""
    if n < 1048576:
        return f"{n / 1024:.0f} KiB"
    return f"{n / 1048576:.2f} MiB"


def rate(v):
    if v is None:
        return ""
    return f"{v:.4g}" if v < 100 else f"{v:.0f}"


def groups(levels, codec_levels):
    """Consecutive levels whose settings render identically, merged.

    Compares the rendered fields rather than the structs: the params carry a
    union, so the bytes behind the inactive arm are not ours to read.
    """
    out, run = [], []
    for lv in levels:
        if lv not in codec_levels:
            continue
        key = (codec_levels[lv][0], tuple(sorted(codec_levels[lv][1].items())))
        if run and run[-1][1] == key:
            run[-1][0].append(lv)
        else:
            run.append(([lv], key))
    for lvs, _ in run:
        out.append(lvs)
    return out


def label(lvs):
    # "to", not a hyphen: the ladder starts below zero, and "-1-0" does not read.
    text = str(lvs[0]) if len(lvs) == 1 else f"{lvs[0]} to {lvs[-1]}"
    if DEFAULT in lvs:
        return f"**{text} (def)**"
    return text


PLACEHOLDER = "(regenerated in the release pass)"


def results_table(codec, engine, apple, levels):
    if not BENCH_ROWS:
        return f"| level | saved% | enc MB/s | dec MB/s (ours) | dec MB/s (apple) |\n|---|---|---|---|---|\n| {PLACEHOLDER} | | | | |"
    scratch = {lv: f[1].get("_scratch") for lv, f in levels.items()}
    varies = len(set(scratch.values())) > 1
    head = ["level", "saved%", "enc MB/s", "dec MB/s (ours)", "dec MB/s (apple)"]
    if varies:
        head.append("memory")
    rows = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]

    def cells(names, lvs=None, italic=False):
        got = [BENCH_ROWS[n] for n in names if n in BENCH_ROWS]
        if not got:
            body = ["n/a"] * 4
        else:
            # Levels in a merged group are the same encoder, so their spread is
            # position within the run, not the level. Averaging cancels it.
            def col(i):
                vals = [g[i] for g in got if g[i] is not None]
                return sum(vals) / len(vals) if vals else None
            saved, enc, d_ours, d_apple = col(0), col(1), col(2), col(3)
            body = [f"{saved:.2f}%", rate(enc), rate(d_ours), rate(d_apple)]
        if varies:
            body.append(memory(scratch.get(lvs[0]) if lvs else None))
        if italic:
            body = [f"*{c}*" if c else c for c in body]
        return body

    for lvs in groups(LEVELS, levels):
        # A level the bench data has not measured yet is left out rather
        # than shown as n/a; it appears with the next run that covers it.
        if not any(f"{engine}:{lv}" in BENCH_ROWS for lv in lvs):
            continue
        text = label(lvs)
        bold = DEFAULT in lvs
        body = cells([f"{engine}:{lv}" for lv in lvs], lvs)
        if bold:
            body = [f"**{c}**" if c else c for c in body]
        rows.append("| " + " | ".join([text] + body) + " |")
        if DEFAULT in lvs:
            rows.append("| " + " | ".join(["*Apple*"] + cells([apple], None, True)) + " |")
    return "\n".join(rows)


def settings_table(codec, strategy, levels):
    picked = {lv: v for lv, v in levels.items() if v[0] == strategy}
    if not picked:
        return None
    order = list(next(iter(picked.values()))[1])
    order = [f for f in order if f != "_scratch"]
    # A field with one value across every level of this strategy says nothing
    # per level. Drop it; it reappears by itself the day it starts varying.
    order = [f for f in order if len({picked[lv][1][f] for lv in picked}) > 1]
    rows = ["| " + " | ".join(["level"] + order) + " |", "|" + "---|" * (len(order) + 1)]
    # A field that is only ever 0 or 1 is a flag, not a count.
    flags = {f for f in order if {picked[lv][1][f] for lv in picked} <= {0, 1}}

    def show(field, value):
        if field in flags:
            return "yes" if value else "no"
        return str(value)

    for lvs in groups(LEVELS, picked):
        vals = picked[lvs[0]][1]
        rows.append("| " + " | ".join([label(lvs)] + [show(f, vals[f]) for f in order]) + " |")
    return "\n".join(rows)


def splice(path, name, body, check):
    src = open(path, encoding="utf-8").read()
    pat = re.compile(rf"(<!-- TABLE:{re.escape(name)} -->\n).*?(\n<!-- /TABLE:{re.escape(name)} -->)",
                     re.S)
    if not pat.search(src):
        # A missing marker is a deliberate absence, not a stale table.
        print(f"skipped TABLE:{name}: no marker in {path}")
        return True
    new = pat.sub(lambda m: m.group(1) + body + m.group(2), src)
    if new == src:
        return True
    if check:
        print(f"stale: TABLE:{name} in {path}", file=sys.stderr)
        return False
    open(path, "w", encoding="utf-8").write(new)
    print(f"updated TABLE:{name} in {path}")
    return True


def main(argv):
    check = "--check" in argv
    args = [a for a in argv if a != "--check"]
    if not args:
        sys.exit(__doc__)
    global BENCH_ROWS
    levels = read_levels(args[0])
    BENCH_ROWS = read_bench(args[1:])

    ok = True
    top = ["| level | " + " | ".join(c[0] for c in CODECS) + " |", "|---|" + "---|" * len(CODECS)]
    if not BENCH_ROWS:
        top.append(f"| {PLACEHOLDER} |" + " |" * len(CODECS))
    for lv in LEVELS if BENCH_ROWS else []:
        text = f"**{lv} (def)**" if lv == DEFAULT else str(lv)
        cells = []
        for _, engine, _ in CODECS:
            got = BENCH_ROWS.get(f"{engine}:{lv}")
            cells.append(f"{got[0]:.2f}% / {rate(got[1])}" if got else "n/a")
        if all(c == "n/a" for c in cells):
            continue
        top.append(f"| {text} | " + " | ".join(cells) + " |")
        if lv == DEFAULT:
            apple = [f"*{BENCH_ROWS[c[2]][0]:.2f}% / {rate(BENCH_ROWS[c[2]][1])}*"
                     if c[2] in BENCH_ROWS else "*n/a*" for c in CODECS]
            top.append("| *Apple* | " + " | ".join(apple) + " |")
    ok &= splice("README.md", "results:all", "\n".join(top), check)

    dec = ["| decoder | " + " | ".join(c[0] for c in CODECS) + " |", "|---|" + "---|" * len(CODECS)]
    if BENCH_ROWS:
        got = [BENCH_ROWS.get(f"{engine}:{DEFAULT}") for _, engine, _ in CODECS]
        dec.append("| crush-lz | " + " | ".join(rate(g[2]) if g else "n/a" for g in got) + " |")
        dec.append("| *Apple* | " + " | ".join(f"*{rate(g[3])}*" if g else "*n/a*" for g in got) + " |")
    else:
        dec.append(f"| {PLACEHOLDER} |" + " |" * len(CODECS))
    ok &= splice("README.md", "decode:all", "\n".join(dec), check)

    for _, engine, apple in CODECS:
        if engine not in levels:
            continue
        ok &= splice(README[engine], f"results:{engine}",
                     results_table(engine, engine, apple, levels[engine]), check)
        for strategy in dict.fromkeys(v[0] for v in levels[engine].values()):
            body = settings_table(engine, strategy, levels[engine])
            ok &= splice(README[engine], f"settings:{engine}:{strategy}", body, check)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
