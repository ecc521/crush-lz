#!/bin/bash
# Runs conformance binaries on a rolling pool of JOBS workers, slowest first
# by the previous run's times. The LZBITMAP differential sweeps run as one
# job per level so no single binary holds the pool.
#
#   run_tests.sh <logdir> <binary>...
#
# Environment: JOBS (default 1), MANIFEST and FIXDIR (fixture arguments),
# SAN=1 to report only sanitizer lines on failure, and whatever the tests
# read themselves (ZBM_*, CRUSHLZ_TEST_THREADS).
set -u

if [ "${1-}" = --one ]; then
  id=$2 bin=$3 lv=$4
  case $(basename "$bin") in
    *concurrency*) arg=$MANIFEST ;;
    *edge_case*)   arg=$FIXDIR/ragged.bin ;;
    *)             arg= ;;
  esac
  [ "$lv" != - ] && export ZBM_DIFF_LEVELS=$lv
  start=$SECONDS
  if out=$("$bin" $arg 2>&1); then st=ok; else st=FAIL; fi
  { echo "$st"; echo "$out"; } > "$LOGS/$id"
  echo "$id $((SECONDS - start))" >> "$LOGS/.times"
  exit 0
fi

logs=$1; shift
here=$(cd "$(dirname "$0")" && pwd)
hdr=$here/../../crates/lzbitmap/csrc/crushlzbitmap.h
level_of() { awk -v k="CRUSHLZBITMAP_LEVEL_$1" '$2 == k { gsub(/[()]/, "", $3); print $3 }' "$hdr"; }
times=$logs.times
rm -rf "$logs"; mkdir -p "$logs"
export LOGS=$logs MANIFEST=${MANIFEST:-} FIXDIR=${FIXDIR:-}

if [ -n "${ZBM_DIFF_LEVELS:-}" ]; then
  levels=$(echo "$ZBM_DIFF_LEVELS" | tr ',' ' ')
else
  levels=$(seq "$(level_of MIN)" "$(level_of MAX)")
fi

list_jobs() {
  for t in "$@"; do
    name=$(basename "$t")
    case $name in
      zbm_decoder_diff_test|zbm_simd_diff_test)
        for l in $levels; do echo "$name@$l $t $l"; done ;;
      *) echo "$name $t -" ;;
    esac
  done
}

# One "seconds id binary level" line per job; unknown jobs sort first.
jobs=$(list_jobs "$@" | while read -r id t l; do
  s=$( [ -f "$times" ] && awk -v id="$id" '$1 == id { print $2 }' "$times")
  echo "${s:-999999} $id $t $l"
done | sort -rn | cut -d' ' -f2-)

echo "$jobs" | xargs -P "${JOBS:-1}" -n 3 bash "$0" --one
[ -f "$logs/.times" ] && mv "$logs/.times" "$times"

fail=0
for t in "$@"; do
  name=$(basename "$t")
  printf '%-40s ' "$name"
  found=0
  bad=
  for f in "$logs/$name" "$logs/$name"@*; do
    [ -f "$f" ] || continue
    found=1
    [ "$(head -1 "$f")" = ok ] || bad="$bad $f"
  done
  if [ $found = 0 ]; then echo "NO RESULT"; fail=1
  elif [ -z "$bad" ]; then echo ok
  else
    echo FAIL; fail=1
    for f in $bad; do
      case $f in *@*) echo "  level ${f##*@}:" ;; esac
      if [ "${SAN:-0}" = 1 ]; then
        tail -n +2 "$f" | grep -E "runtime error|ERROR:|WARNING:|SUMMARY:" | head -6
      else
        tail -n +2 "$f" | tail -15
      fi
    done
  fi
done
exit $fail
