#!/usr/bin/env bash
# Copyright (c) 2026 Tucker Willenborg
# SPDX-License-Identifier: MPL-2.0
#
# Fallback for `corpus fetch` when a locked URL is unreachable (e.g. cloud
# VMs that only reach GitHub and package registries). Rebuilds the same
# extracted tree from a mirror pinned by sha256 or git commit; `corpus build`
# reproducing corpus/manifest.tsv exactly is the end-to-end check.
#
# Usage: corpus/fetch-mirrors.sh CACHE_DIR ID...   (called by `corpus fetch`)
set -euo pipefail

CACHE="$1"; shift
U="$CACHE/unpacked.noindex"
TMP="$CACHE/mirror-tmp"
mkdir -p "$U" "$TMP"

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

get() { # url dest sha256
    if [ -f "$2" ] && [ "$(sha "$2")" = "$3" ]; then return 0; fi
    curl -fsSL --retry 3 -o "$2" "$1" || return 1
    local got; got="$(sha "$2")"
    if [ "$got" != "$3" ]; then
        echo "hash mismatch for $1: got $got want $3" >&2
        rm -f "$2"; return 1
    fi
}

git_tree() { # repo commit dest [paths...]: export a pinned commit's tree
    local repo="$1" rev="$2" dest="$3"; shift 3
    local g="$TMP/$(basename "$repo").git"
    rm -rf "$g"
    git init -q --bare "$g"
    git -C "$g" fetch -q --depth 1 --filter=blob:none "$repo" "$rev"
    mkdir -p "$dest"
    git -C "$g" archive "$rev" "$@" | tar -x -C "$dest"
    rm -rf "$g"
}

done_mark() { touch "$U/$1/.mirror-complete"; echo "$1 ready"; }
ready() { [ -f "$U/$1/.mirror-complete" ]; }

fetch_exif() {
    local id=exif-samples; ready $id && return 0; rm -rf "$U/$id"
    # Upstream is GitHub's archive of master; the repository is archived, so
    # its last commit is the tree that was locked.
    git_tree https://github.com/ianare/exif-samples \
        5332a9cf0220e9c6c93f88a187daa90808051e10 "$U/$id/exif-samples-master"
    done_mark $id
}

fetch_gnome() {
    local id=gnome-backgrounds-47; ready $id && return 0; rm -rf "$U/$id"
    # gitlab.gnome.org archive of tag 47.0, rebuilt from the GitHub mirror.
    git_tree https://github.com/GNOME/gnome-backgrounds \
        f1c1f85d5b059f57554e1c8c6c810110b80b2ca3 "$U/$id/gnome-backgrounds-47.0"
    done_mark $id
}

fetch_go() {
    local id=go-1.26.5; ready $id && return 0; rm -rf "$U/$id"
    # go.dev's darwin-arm64 tarball, rebuilt from the module proxy's toolchain
    # zip (same binaries and src/) plus the api/ doc/ misc/ test/ directories
    # that distpack leaves out of the module zip, from the go1.26.5 tag.
    local z="$TMP/go-toolchain.zip"
    get https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go1.26.5.darwin-arm64.zip \
        "$z" e53418c1be1296acb941920fa767dd8d8978740e9712c60b7d05475b17b2459d
    rm -rf "$TMP/go"; mkdir -p "$TMP/go" "$U/$id"
    unzip -qq -o "$z" -d "$TMP/go"
    mv "$TMP/go/golang.org/toolchain@v0.0.1-go1.26.5.darwin-arm64" "$U/$id/go"
    rm -rf "$TMP/go" "$z"
    git_tree https://github.com/golang/go \
        c19862e5f8415b4f24b189d065ed739517c548ba "$U/$id/go" api doc misc test
    done_mark $id
}

fetch_silesia() {
    local id=silesia; ready $id && return 0; rm -rf "$U/$id"
    # A re-zip of the same twelve files; the archive differs from
    # sun.aei.polsl.pl's, the extracted files do not.
    local z="$TMP/silesia.zip"
    get https://raw.githubusercontent.com/DataCompression/corpus-collection/d59143a41cc7d65063a70e86063a3c39aeae6d9f/Silesia-Corpus/silesia.zip \
        "$z" 1b39576418fa3ebb09cf0ceab59bf1cb9fa262c19d9dc6d3cda1e4fae7910a09
    mkdir -p "$U/$id"; unzip -qq -o "$z" -d "$U/$id"; rm -f "$z"
    done_mark $id
}

for id in "$@"; do
    case "$id" in
        exif-samples) fetch_exif ;;
        gnome-backgrounds-47) fetch_gnome ;;
        go-1.26.5) fetch_go ;;
        silesia) fetch_silesia ;;
        *) echo "no mirror for $id" >&2; exit 1 ;;
    esac
done
rm -rf "$TMP"
