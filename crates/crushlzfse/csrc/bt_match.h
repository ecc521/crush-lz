// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Binary-tree match finder for the LZFSE and LZVN optimal parsers.
//
// Every position is inserted into a tree of the earlier positions that share
// its three-byte hash, ordered by the bytes that follow each one. Inserting a
// position walks from the root towards where it belongs, and the nodes on
// that path are exactly the candidates whose common prefix with it is
// longest, so one walk of at most `depth` nodes both inserts the position
// and returns its matches in strictly increasing length. A hash chain of the
// same depth sees only the most recent positions; the tree sees the best
// ones, which is what an optimal parse needs.
//
// The structure is the one LZMA's bt4 and zstd's btopt use. A call is one
// block of at most 64 KiB with no history, so positions index the block
// directly and need no window arithmetic.

#ifndef BT_MATCH_H
#define BT_MATCH_H

#include <stdint.h>
#include <string.h>

// Longest increasing run one walk can report. A walk adds a match only when
// it is longer than every earlier one, so this is reached only on degenerate
// input; past it the shortest are dropped.
#define BT_MAX_MATCHES 64

// No position: an empty root or the end of a branch.
#define BT_NONE (-1)

// Root bucket of the three bytes at p, for a table of 2^bits roots.
static inline uint32_t bt_hash3(const uint8_t *p, uint32_t bits) {
  uint32_t x = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
  return (x * 2654435761u) >> (32 - bits);
}

// Root bits for an input of len bytes: hash_bits, lowered while half as
// many roots would still outnumber the positions, so a short input clears a
// short table. Never below 10.
static inline uint32_t bt_root_bits(uint32_t hash_bits, size_t len) {
  uint32_t bits = hash_bits;
  while (bits > 10 && ((size_t)1 << (bits - 1)) >= len) bits--;
  return bits;
}

// Inserts pos under root *head and returns its matches, nearest and shortest
// first, in len/dist (room for BT_MAX_MATCHES). son holds two links per
// position. limit is how many bytes from pos may be compared; the tree stays
// correct as long as every position is inserted with the limit its own end
// allows. Reported lengths are capped at cap_len, and a match must be at
// least min_len long and at most max_dist away. *longest gets the uncapped
// length of the longest match, 0 if none, and *longest_dist its distance,
// which past cap_len need not be the last one reported.
static inline int bt_insert_find(const uint8_t *src, int32_t pos, uint32_t limit,
                                 int32_t depth, int32_t max_dist, uint32_t min_len,
                                 uint32_t cap_len, int32_t *son, int32_t *head,
                                 int32_t *len, int32_t *dist, uint32_t *longest,
                                 int32_t *longest_dist) {
  // Too close to the end to hold a match: leave pos out of the tree.
  if (limit < min_len) {
    *longest = 0;
    *longest_dist = 0;
    return 0;
  }
  const uint8_t *cur = src + pos;
  int32_t m = *head;
  *head = pos;
  int32_t *ptr0 = &son[2 * pos + 1];
  int32_t *ptr1 = &son[2 * pos];
  // Common prefix with the smallest node above and the largest node below
  // the insertion point: every node between them shares at least the
  // shorter of the two, so comparing can start there.
  uint32_t len0 = 0, len1 = 0;
  uint32_t best = min_len - 1;
  int32_t best_dist = 0;
  int n = 0;
  for (int32_t d = depth;; d--) {
    if (m == BT_NONE || d == 0 || pos - m > max_dist) {
      *ptr0 = *ptr1 = BT_NONE;
      break;
    }
    int32_t *pair = &son[2 * m];
    const uint8_t *mp = src + m;
    uint32_t l = len0 < len1 ? len0 : len1;
    if (mp[l] == cur[l]) {
      l = match_extend(mp, cur, l + 1, limit);
      if (l > best) {
        best = l;
        best_dist = pos - m;
        if (n == BT_MAX_MATCHES) {
          memmove(len, len + 1, (BT_MAX_MATCHES - 1) * sizeof(*len));
          memmove(dist, dist + 1, (BT_MAX_MATCHES - 1) * sizeof(*dist));
          n--;
        }
        uint32_t c = l < cap_len ? l : cap_len;
        // Past cap_len every longer match reports the same length; keep
        // the nearest.
        if (n == 0 || (uint32_t)len[n - 1] < c) {
          len[n] = (int32_t)c;
          dist[n] = pos - m;
          n++;
        }
        if (l >= limit) {
          // Equal to pos as far as the tree can see: pos takes its place
          // and its subtrees.
          *ptr1 = pair[0];
          *ptr0 = pair[1];
          break;
        }
      }
    }
    if (mp[l] < cur[l]) {
      *ptr1 = m;
      ptr1 = &pair[1];
      m = *ptr1;
      len1 = l;
    } else {
      *ptr0 = m;
      ptr0 = &pair[0];
      m = *ptr0;
      len0 = l;
    }
  }
  *longest = best >= min_len ? best : 0;
  *longest_dist = best_dist;
  return n;
}

#endif // BT_MATCH_H
