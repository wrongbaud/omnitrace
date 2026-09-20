# lzop (`.lzo`)

`src/discovery/validators/lzop.cpp` (validator `lzop`), signature `lzop` in
`signatures/core.toml` (format `lzop`, category `compressed`), and
`src/containers/lzop/LzopReader.cpp` (reader `lzop`). Both parse the format
through `omnitrace::lzop` ([core/Lzop.h](../../include/omnitrace/core/Lzop.h)).

This is the **lzop file format**, not the bare LZO1X blocks SquashFS and
JFFS2 compress with; those have no header and are handled by their own
readers ([squashfs.md](squashfs.md), [jffs2.md](jffs2.md)). Both use the same
in-tree LZO1X decoder, so neither needs a dependency.

## On-disk layout (big-endian)

A `.lzo` file is one or more **members** laid end to end. Each is a header
and then blocks:

| field | notes |
|---|---|
| `magic[9]` | `89 4c 5a 4f 00 0d 0a 1a 0a` |
| `version` u16 | the lzop that wrote it; `0x1040` is 1.04 |
| `lib_version` u16 | the LZO library version |
| `version_needed` u16 | only from version `0x0940` on |
| `method` u8 | 1 `lzo1x-1`, 2 `lzo1x-1-15`, 3 `lzo1x-999`, 128 zlib |
| `level` u8 | only from `0x0940` on |
| `flags` u32 | which checksums follow, and whether the extra field and filter are present; the top byte is the OS that wrote it |
| `filter` u32 | only when `F_H_FILTER` |
| `mode` u32, `mtime_low` u32, `mtime_high` u32 | the original file's; the high word only from `0x0940` on |
| `name_len` u8, `name[]` | the original name |
| `checksum` u32 | Adler-32, or CRC-32 when `F_H_CRC32`, over everything from `version` through `name` |

Then, until a zero length ends the member:

| field | notes |
|---|---|
| `uncompressed_len` u32 | **0 ends the member** |
| `compressed_len` u32 | equal to the above when the block was **stored** |
| checksum(s) of the uncompressed bytes | Adler-32 and/or CRC-32, per the flags |
| checksum(s) of the compressed bytes | only when there are fewer of them than of the originals |
| `compressed_len` bytes | |

**The block lengths are in the stream**, so a member's extent is a walk of
the block headers with the data skipped. That is why the validator can size
an lzop stream without decompressing it -- unlike gzip, xz or zstd, where
finding the end means decoding to it (`compressed_stream_length` in
`src/discovery/validators/common.h`). On a magic hit, which is what a
validator sees, that difference is the whole cost.

## Identification

| tier | when |
|---|---|
| rejected | no magic, or a header field outside what lzop writes |
| magic | the header does not match its own checksum (`lzop-header-checksum-mismatch`); not sized |
| structural | header verified, but the blocks do not reach a member's terminator; `extent: unknown`, so no reader is handed it |
| consistent | header verified and every member's blocks walk to their terminator; `size` is the last member's end |

The top tier is `consistent`, not `verified`: the header checksum covers the
header, and checking the blocks against their own checksums means decoding
them, which is the reader's job rather than something to do on every magic
hit. The reader does do it, and reports the result.

## The reader

Each member becomes one entry: `payload` when the file holds one, and
`payload0`, `payload1`, ... when it holds several. The name in the header is
metadata (`original_name`), never the path -- a name out of evidence must not
steer where the Sink writes.

Blocks are decoded one at a time and written straight through, so a gigabyte
payload costs one block buffer (lzop's default block is 256 KiB, its largest
64 MiB). A block whose compressed length equals its uncompressed length was
stored verbatim and is copied rather than decoded.

**It checks what it produced.** Every block carries a checksum of its
uncompressed bytes, so this is the one wrapper format in the tree that can
say whether the payload is what was compressed. The entry's `checksum` extra
is one of:

* `ok` -- every block matched.
* `mismatch` -- at least one did not (`lzop-checksum-mismatch`). The bytes are
  still emitted, because they are what is on the medium; what the entry says
  is that they are not what lzop was given.
* `none` -- `lzop -F` was used and there is no per-block checksum, so "ok"
  would be a claim nothing supports.

A member whose method this build cannot decode (lzop can be built against
zlib) is reported with `lzop-unsupported-method` and produces no entry rather
than a guess.

## Attributes

From the validator: `version`, `lib_version`, `method`, `level`, `flags`,
`original_name`, `mode`, `mtime`, `header_checksum`, `members`, `blocks`,
`stored_blocks`, `payload_bytes`, and `extent` when it is unknown. From the
reader: `version`, `method`, `level`, `members`, `blocks`, `payload_bytes`,
`original_name`, and `bad_checksums` when non-zero.
Meanings: `docs/reference/ATTRS.md`.

## Diagnostics

| code | severity | meaning |
|---|---|---|
| `lzop-header-checksum-mismatch` | warning | the header fails its own checksum; not sized |
| `lzop-block-walk-failed` | warning | the blocks do not reach a terminator; `extent: unknown` |
| `lzop-limit-blocks` | info | the walk stopped at its block or member cap |
| `lzop-unsupported-method` | warning | a method this build does not decode |
| `lzop-bad-block` | warning | a malformed, unreadable or undecodable block; the payload ends there |
| `lzop-checksum-mismatch` | warning | a block does not match the checksum lzop stored for it |

## Not yet supported

* **zlib-method members.** lzop can be built against zlib; such a file is
  recognised and reported, not decoded.
* **Filters** (`F_H_FILTER`). lzop's optional byte filters are recorded in
  the attrs but not applied, so a filtered payload decodes to the pre-filter
  bytes. lzop has not written one by default in any released version.
* Multipart streams (`F_MULTIPART`) are not distinguished from members laid
  end to end, which is how lzop actually writes several files.

## Verified on

* lzop 1.04 output, checked byte for byte against the originals: a stored
  single block, a five-block `lzo1x-1` stream, the same at `lzo1x-999`, an
  incompressible 900 KB file (four stored blocks), and two members
  concatenated, which come out as `payload0` and `payload1` in order.
* `-C` (CRC-32 block checksums) and `-F` (none) report `checksum` `ok` and
  `none` respectively.
* A flipped byte inside a stored block: the full 900000 bytes still come out
  and the entry reports `checksum: mismatch` -- the data is recovered and the
  doubt is recorded, which is the forensic order of priorities.
* `tree.tar.lzo` resolves on to its tar and that tar's files.
* `dongle-example` in the corpus turns out to hold a real one at `0x41fc1`:
  lzop 1.03, `lzo1x-999`, fifteen 256 KiB blocks, header checksum ok. The
  reader gets 7946904 bytes out of its 3.6 MiB -- an ARM image -- with the
  same sha256 `lzop -d` produces, and `lzop -t` agrees the stream is intact.
  The `xz`, `romfs` and `android-sparse` hits that used to be reported inside
  those 3.6 MiB were magics in its compressed data, and are now absorbed into
  it, which is why that image's finding count went from 15 to 13.

## References

* <https://www.lzop.org/> and <https://github.com/lzop/lzop> (`src/lzop.c`,
  `src/conf.h`), read for understanding; nothing copied
