#!/usr/bin/env python3
# Copyright (c) 2026 Tucker Willenborg
# SPDX-License-Identifier: MPL-2.0
"""Sums the MetricTable of an xctrace CPU Counters export.

    cpu_counters.py metrics.xml [units]

Counts (cycles) are summed over every sample; ratios (the bottleneck
fractions) are averaged weighted by sample duration. With `units`, each
count is also printed divided by it. cpu_counters.sh produces the input.
"""
import collections
import re
import sys


def main(path, units):
    text = open(path).read()
    ids = {}
    sums = collections.Counter()
    weighted = collections.Counter()
    weight = collections.Counter()
    is_ratio = {}

    def value(tag, row):
        m = re.search(r'<' + tag + r' id="(\d+)"[^>]*>([^<]*)<', row)
        if m:
            ids[(tag, m.group(1))] = m.group(2)
            return m.group(2)
        m = re.search(r'<' + tag + r' ref="(\d+)"/>', row)
        return ids.get((tag, m.group(1))) if m else None

    for row in re.finditer(r'<row>(.*?)</row>', text, re.S):
        r = row.group(1)
        duration = value('duration', r)
        names = []
        for i, v, ref in re.findall(r'<string (?:id="(\d+)"[^>]*>([^<]*)<|ref="(\d+)"/>)', r):
            if i:
                ids[('string', i)] = v
                names.append(v)
            else:
                names.append(ids.get(('string', ref)))
        if len(names) < 2:
            continue
        name = names[1]
        v = value('fixed-decimal', r)
        ratio = value('boolean', r)
        if v is None:
            continue
        v = float(v)
        d = float(duration or 0)
        if ratio == '1':
            weighted[name] += v * d
            weight[name] += d
            is_ratio[name] = True
        else:
            sums[name] += v
            is_ratio[name] = False

    for name in sorted(is_ratio):
        if is_ratio[name]:
            print(f"{name:40s} {weighted[name] / max(weight[name], 1):.4f}")
        else:
            line = f"{name:40s} {sums[name]:16.0f}"
            if units:
                line += f"  per unit {sums[name] / units:8.1f}"
            print(line)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1], float(sys.argv[2]) if len(sys.argv) > 2 else None)
