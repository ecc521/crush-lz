#!/bin/zsh
# Copyright (c) 2026 Tucker Willenborg
# SPDX-License-Identifier: MPL-2.0
#
# Records a command under Instruments' CPU Counters template (CPU Bottlenecks
# mode) and prints the summed metrics: cycles, and the fraction of issue
# bandwidth that was useful, discarded (mispredicted paths), or lost to
# instruction delivery or processing stalls. macOS only; needs Xcode.
#
#   harness/tools/cpu_counters.sh NAME [UNITS] — command args...
#
# NAME names the trace (cpu_counters_NAME.trace in the current directory).
# UNITS, when given, is a work count the cycles are divided by, e.g. the
# number of 8-byte blocks the command encodes.
set -e
here=$(dirname "$0")
name=$1; shift
units=""
if [[ "$1" != "--" ]]; then units=$1; shift; fi
[[ "$1" == "--" ]] && shift
trace=cpu_counters_$name.trace
rm -rf "$trace"
xctrace record --template 'CPU Counters' --output "$trace" --launch — "$@" 2>&1 | grep -v "^Starting\|^Ctrl-C\|^Target app\|^Recording\|^Output file" || true
xctrace export --input "$trace" --xpath '//trace-toc/run[1]/data/table[@schema="MetricTable"]' 2>/dev/null > "cpu_counters_$name.xml"
python3 "$here/cpu_counters.py" "cpu_counters_$name.xml" $units
