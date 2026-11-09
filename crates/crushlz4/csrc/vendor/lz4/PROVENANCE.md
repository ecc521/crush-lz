# Vendored LZ4

Upstream: https://github.com/lz4/lz4
Commit:   0774d05537f9762f838f7ab541b7765f1a729cb5
Version:  1.10.0
Files:    lz4.c, lz4.h, lz4hc.c, lz4hc.h  (from the upstream `lib/` directory)

**These four files are unmodified.** They carry their own BSD 2-Clause
headers and `LICENSE` is upstream's, reproduced verbatim. Only `lib/` is
taken: the rest of the LZ4 repository is GPL-2.0-or-later and is deliberately
not vendored here.

Do not edit these files. Anything crush-lz needs on top of them belongs in
`../../crushlz4.c`, which is MPL-2.0 and calls into this as a library. A
local change here would have to be re-applied on every upstream bump and
would put the BSD-2-only status of these files in question.

To refresh: clone upstream at the tag you want, copy those four files plus
`LICENSE` over this directory, and update the commit and version above.
