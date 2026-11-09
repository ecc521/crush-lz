# Third-party code and licensing

This project is offered under the Mozilla Public License 2.0 (see [LICENSE](LICENSE)).

Depending on which portion(s) of this project that you use, MIT, BSD-2-Clause and/or BSD-3-Clause terms may also apply.

## LZFSE and LZVN: `crates/crushlzfse`

Derived from Apple's LZFSE reference implementation.

    Copyright (c) 2015-2016, Apple Inc. All rights reserved.
    BSD-3-Clause. See crates/crushlzfse/LICENSE

## LZBITMAP: `crates/lzbitmap`

Derived from Corellium's LZBITMAP implementation.

    Copyright (c) 2022 Corellium LLC
    Author: Ernesto A. Fernández <ernesto@corellium.com>
    MIT. See crates/lzbitmap/LICENSE

## LZ4: `crates/crushlz4`

Project code and vendored LZ4 code have separate licenses.

Framing, decoding, compression-level settings and Rust bindings are MPL-2.0. See [LICENSE](crates/crushlz4/LICENSE).

    Copyright (c) 2026, Tucker Willenborg. All rights reserved.

The block encoder is upstream LZ4, vendored **unmodified** under
`crates/crushlz4/csrc/vendor/lz4`: `lz4.c`, `lz4.h`, `lz4hc.c`, `lz4hc.h`
from upstream's `lib/` directory, at commit `0774d055` (v1.10.0). Those four
files retain upstream BSD-2-Clause headers and are licensed under BSD-2-Clause.

    Copyright (c) 2011-2020, Yann Collet. All rights reserved.
    BSD-2-Clause. See crates/crushlz4/csrc/vendor/lz4/LICENSE

Only upstream's `lib/` is taken. The rest of the LZ4 repository is
GPL-2.0-or-later and is deliberately not vendored. See
[PROVENANCE.md](crates/crushlz4/csrc/vendor/lz4/PROVENANCE.md) for update instructions.

## `crates/crushlz`

The combined crate declares `MPL-2.0 AND MIT AND BSD-2-Clause AND BSD-3-Clause`.

## Benchmark corpora

`xtask corpus` rebuilds the open-source corpus from artifacts pinned by hash in `corpus/oss.lock.toml`.
