# SquashFS v1–v4

Reader: `src/filesystems/squashfs/SquashfsReader.{h,cpp}` (`fs::FilesystemReader`,
format id `squashfs`). Validator: `src/discovery/validators/squashfs.cpp`.
Tests: `tests/unit/filesystems/squashfs_test.cpp`.

SquashFS is the read-only compressed filesystem found in the majority of Linux
router, camera, NAS and appliance firmware. Version 4 (2009, kernel 2.6.29) is
the only version in current use, but **v1–v3 images are still shipping on
devices in the field**, and this reader walks them too — see
[The legacy layout](#the-legacy-layout-v1v3).

## On-disk layout

Everything is in the byte order given by the magic: `hsqs` little-endian,
`sqsh` big-endian. Vendor images with a modified magic (`shsq`, `qshs`; DD-WRT
and some Broadcom SDKs) are accepted and the byte order is chosen by whichever
makes the major version read as one that exists (1 to 4).

```
offset  size
0       96      superblock
96      var     compressor options metadata block   (flag 0x0400)
        var     data blocks and fragment blocks     (in file order)
        var     inode table                         (metadata blocks)
        var     directory table                     (metadata blocks)
        var     fragment table                      (metadata blocks + u64 index)
        var     export table                        (optional; metadata blocks + u64 index)
        var     id table                            (metadata blocks + u64 index)
        var     xattr table                         (optional; header + id blocks + u64 index)
```

Superblock (96 bytes):

| off | size | field | off | size | field |
|---|---|---|---|---|---|
| 0 | 4 | magic | 32 | 8 | root_inode (reference) |
| 4 | 4 | inodes | 40 | 8 | bytes_used |
| 8 | 4 | mkfs_time | 48 | 8 | id_table_start |
| 12 | 4 | block_size | 56 | 8 | xattr_id_table_start (or all ones) |
| 16 | 4 | fragments | 64 | 8 | inode_table_start |
| 20 | 2 | compression (1 gzip, 2 lzma, 3 lzo, 4 xz, 5 lz4, 6 zstd) | 72 | 8 | directory_table_start |
| 22 | 2 | block_log | 80 | 8 | fragment_table_start |
| 24 | 2 | flags | 88 | 8 | export_table_start (or all ones) |
| 26 | 2 | no_ids | | | |
| 28 | 2 | s_major (4) | | | |
| 30 | 2 | s_minor | | | |

The reader requires `block_log` in 12..20 and `block_size == 1 << block_log`,
exactly as the kernel does; anything else is refused at `open()`.

**Metadata blocks.** Every table is a chain of blocks of at most 8 KiB of
decoded data, each preceded by a 2-byte header: bit 15 set means stored raw,
the low 15 bits are the on-disk size. A *metadata reference* is a 64-bit value
`(block_offset << 16) | offset_in_block` relative to the table start; structures
may straddle block boundaries. The reader keeps decoded blocks in a small LRU
keyed by absolute offset and reads through a cursor, so an inode is never
copied twice.

**Inodes.** 16-byte header (`type, permissions, uid_idx, gid_idx, mtime,
inode_number`) then a type-specific body. Types 1–7 are basic dir, file,
symlink, block dev, char dev, fifo, socket; 8–14 are the extended variants
that add `nlink`, `xattr_idx`, and for files a 64-bit size, a `sparse` byte
count, and for directories an index. `uid_idx`/`gid_idx` index the id table.
Permissions are the 12 low mode bits only; there are no type bits on disk.
`rdev` uses the Linux `new_encode_dev` layout (major bits 8..19, minor bits
0..7 and 20..31).

**Regular file data.** `start_block` is the absolute offset of the first data
block; a `u32` list follows the inode, one per block, whose low 24 bits are the
on-disk size and bit 24 means stored raw. Size 0 is a sparse block (all zeros,
nothing on disk). The number of list entries is `ceil(size / block_size)` when
the file has no fragment and `floor(size / block_size)` when its tail lives in
fragment `fragment` at `block_offset` inside the decoded fragment block. The
reader streams block by block to the `Sink`; at most one decoded block
(≤ `block_size`) plus one decoded fragment block is held at a time.

**Directories.** A directory inode's `file_size` is the listing length plus 3
(the kernel subtracts 3 and treats ≤ 3 as empty). The listing is a sequence of
headers (`count-1, start_block, inode_number`) each followed by up to 256
entries (`offset, inode_number delta, type, name_size-1, name`). Entries are
stored sorted by name, and the walk emits them in that order, pre-order, so
output is deterministic. The root directory itself has no entry and is not
emitted; its inode is `root_inode`.

**Tables.** The fragment, id and export tables are arrays of fixed-size
records packed into metadata blocks, addressed through a list of `u64` block
pointers at `*_table_start`. Fragment entries are 16 bytes (`start, size,
unused`, size encoded like a data block). Ids are `u32`. The xattr id table
starts with a 16-byte header (`xattr_table_start, xattr_ids, unused`) followed
by its pointer list; each id record is `(xattr ref, count, size)`.

## What the reader captures

`FileMeta`: `path`, `kind`, `mode` (permission bits), `uid`/`gid` (resolved
through the id table), `mtime`, `inode` (the inode number), `nlink`,
`link_target`, `rdev_major`/`rdev_minor`, `size` (file size; symlink target
length; 0 for directories and specials), `extra["sparse"]` (extended file
sparse byte count when non-zero) and `extra["xattrs"]` (number of extended
attributes on the inode, from the xattr id table; names and values are not
decoded). SquashFS has no ctime/atime and no history, so `WalkOptions::history`
is a no-op.

`FilesystemInfo`: `format`, `block_size`, `compression`, `endian`, `size`
(`bytes_used`), and `attrs` `version`, `magic`, `inodes`, `fragments`, `flags`
(hex), `compression_id`, `id_count`, `mkfs_time`, `root_inode`, `exportable`,
`xattr_ids`, plus the decoded compressor options when present (`gzip_level`,
`gzip_window`, `gzip_strategies`, `xz_dict_size`, `xz_filters`, `lz4_version`,
`lz4_flags`, `zstd_level`, `lzo_algorithm`, `lzo_level`).

Compression goes through `core/Compression.h`: gzip blocks are zlib streams
(`Codec::Zlib`), lzma is LZMA-alone, xz streams carry their own BCJ filter
chain, lz4 blocks are raw (`Codec::Lz4` without frame magic), zstd frames and
LZO1X via the in-tree decoder. Every decode is capped at the size the format
allows (8 KiB for metadata, `block_size` for data and fragments), so
`Limits::max_decompress_ratio` is not applied per block: a block of mostly
zeros legitimately exceeds any ratio, and the cap already bounds memory.

## Diagnostics

| code | severity | when |
|---|---|---|
| `squashfs-unsupported-compression` | Error | compression id not in 1..6; recorded at open, compressed blocks then fail to decode |
| `squashfs-metadata-corrupt` | Error/Warning | a metadata block header, size, payload or a structure inside it is unreadable; `walk` fails when this hits the root inode or root listing, otherwise the entry/subtree is skipped |
| `squashfs-block-corrupt` | Warning | a data or fragment block does not decode (or a raw block has the wrong size); the block is zero-filled and the entry marked `truncated`; a block claiming more than `block_size` on disk ends the file's data |
| `squashfs-data-truncated` | Warning | a data block lies past the end of the Span (truncated image); the file ends there and is marked `truncated` |
| `squashfs-bad-fragment` | Warning | fragment index outside the table or its entry unreadable; tail zero-filled |
| `squashfs-dir-loop` | Warning | a directory entry refers to one of its own ancestors; not descended |
| `squashfs-bad-inode-type` | Warning | inode type outside 1..14; entry skipped |
| `squashfs-bad-entry-name` | Warning | entry name empty, `.`, `..`, or containing `/` or NUL; entry skipped |
| `squashfs-bad-id` | Warning | uid/gid index outside the id table (reported once per walk; ids reported as 0) |
| `squashfs-bad-xattr` | Warning | xattr id outside the xattr table; `extra["xattrs"]` omitted |
| `squashfs-truncated-image` | Warning | `bytes_used` exceeds the Span |
| `squashfs-truncated` | Warning | validator: `bytes_used` exceeds the available bytes. The finding's size is clamped to the Span and it stays at `Structural`: every table sits at the end of the image, so on a cut image none of them is there to be checked. It still absorbs the gzip/xz/lz4/zstd hits inside its range (`docs/formats/signatures.md`) |
| `squashfs-minor-version` | Info | `s_minor != 0`; parsed as 4.0 |
| `squashfs-root-invalid` | Error | `root_inode` is not a directory; `walk` fails |
| `squashfs-limit-nodes` / `squashfs-limit-files` | Warning | `Limits::max_nodes_per_fs` / `max_files` reached; walk stops, `truncated` set. Also emitted when a single directory listing holds more than `max_nodes_per_fs` entries: the listing is cut there, `truncated` set |
| `squashfs-limit-file-bytes` | Warning | a symlink's `target_size` exceeds `Limits::max_file_bytes`; the entry is skipped (the target is never allocated up front) |
| `squashfs-sink-error` | Warning | the Sink refused an entry (unsafe path, its own limit); entry skipped, walk continues |

`open()` fails with `Status` (no diagnostics) for: fewer than 96 bytes, unknown
magic, major version ≠ 4, `block_log` outside 12..20, `block_size` not
matching, `bytes_used` < 96.

## History

None. SquashFS is write-once; there are no superseded versions or deletion
records to recover.

## Truncated images

A SquashFS stored as a file inside another filesystem is only as complete as
the extraction that produced it, and `Limits::max_file_bytes` (CLI
`--max-file-bytes`, default 1 GiB) is the usual reason it is not. The QNX6
`storage` partition of the corpus keeps its update images this way:
`osimage/os_a.img` is 1,107,136,512 bytes of which the default cap writes
1,073,741,824, and the result is a SquashFS whose superblock parses, whose
`bytes_used` is 1,105,987,639, and whose inode, directory, fragment, export and
id tables all lie past the cut. The validator reports it at `Structural` with
`squashfs-truncated`; the reader opens it and then fails the walk at the root
inode with `squashfs-metadata-corrupt`, and coverage becomes `partial`. Raise
`--max-file-bytes` past the entry size (the `<fmt>-limit-file-bytes` warning
gives it) and the same image reads as `Consistent` with all 60,530 entries.

## The legacy layout (v1–v3)

v1–v3 use a different superblock, different inodes and a different directory
format from v4. None of it is a minor variation, and it is worth stating why
the numbers below are not simply copied from a header file: **the published
structures are bitfields**, whose wire layout is the compiler's choice rather
than the format's, so every offset here was read off a corpus image and
checked against a byte-for-byte comparison with unsquashfs's output.

| | v1–v3 | v4 |
|---|---|---|
| superblock | packed, unaligned, 51 / 63 / 119 bytes for v1 / v2 / v3 | 96 bytes, aligned |
| `bytes_used` | 32-bit at offset 8; v3 adds a 64-bit twin at 63 | 64-bit at 40 |
| owner ids | two tables (`uid_start`, `guid_start`) of plain uncompressed `u32`, indexed separately, `0xFF` meaning "group is the owner" | one metadata table, one index |
| compressor | **not recorded** — see below | `compression` id at 20 |
| inode base | 12 bytes: one 32-bit word packing `type:4`, `mode:12`, `uid:8`, `guid:8`, then `mtime`, `inode_number` | 16 bytes, four 16-bit fields |
| directory inode | `nlink`, then `file_size:19` \| `offset:13` in one word, `start_block`, `parent` | `start_block`, `nlink`, `file_size`, `offset`, `parent` |
| regular inode | 64-bit `start_block`, then `fragment`, `offset`, `file_size` | 32-bit `start_block` first |
| directory header | **9 bytes**: `count` as one byte, then a 32-bit start block and a 32-bit base inode | 12 bytes, three 32-bit fields |
| directory entry | **5 bytes**: `offset:13` \| `type:3` in 16 bits, a one-byte name length, a 16-bit signed inode delta | 8 bytes, four 16-bit fields |

The directory header is the one to be careful about. The published struct is
`count:8; start_block:24; inode_number:32`, which reads as 8 bytes — and 8
produces a name that is one byte adrift on the second entry and garbage after
that. Nine is what the bytes say: parsing one corpus router's root directory
with 9 consumes exactly the 231 bytes the inode claims and yields 22 clean
names, where 8 consumes 46 and yields none.

### The compressor is not recorded

v1–v3 predate the `compression` field: the format assumed zlib, and vendors who
changed it changed the *magic* instead. So the reader finds the compressor by
decoding the first metadata block of the inode table with each candidate and
keeping whichever works (`squashfs-compression-probed` says which). That is a
decode rather than a guess — a wrong codec fails on a block whose length the
superblock already fixed — and it costs one block per image.

The candidate that matters is **DD-WRT/Broadcom LZMA**: LZMA1 with a five-byte
header (properties plus dictionary size), no uncompressed-size field and no end
marker. liblzma's `LZMA_FILTER_LZMA1EXT` decodes exactly that when told how
much output to produce, which SquashFS always knows — the block list gives the
size of every data block and metadata blocks are 8 KiB.

### A damaged block costs that block, not the file

One `.ko` on the router-wrt corpus image has a data block that no LZMA decoder will
take (unsquashfs and unblob both drop the whole 4.3 MB file). This reader
zero-fills the block, emits the rest, marks the entry truncated and says which
block and at what offset with `squashfs-block-corrupt`. Damaged evidence is
still evidence.

## Known gaps

* Extended attribute names and values are not decoded (only the count).
* The export table and the extended-directory index are not used (they only
  accelerate lookups by inode number / name).
* Directory mtime is captured in `FileMeta` but `DiskSink` does not apply it.
* Hard links are emitted as independent regular files with `nlink > 1`; the
  Sink has no hard-link primitive.
* Big-endian images are covered by the synthetic test only; there is no
  big-endian mksquashfs to produce a real fixture.
* The v1–v3 **extended regular inode** (type 9) is refused by name rather than
  parsed: no image in the corpus has one, and guessing a layout would emit a
  file made of the wrong bytes. `squashfs-bad-inode-type` names it.
* v1–v3 fixtures are synthetic (`SynthLegacy` in the reader test, uncompressed
  so the test is about the structures). Real v1–v3 coverage is the corpus,
  because `mksquashfs` 4.x cannot write them.

## References

* Linux `fs/squashfs/squashfs_fs.h`, `inode.c`, `dir.c`, `file.c`,
  `fragment.c`, `id.c`, `xattr_id.c` (read for understanding; no code copied)
* https://dr-emann.github.io/squashfs/ — the community format description
* squashfs-tools (`mksquashfs`, `unsquashfs`) — reference producer/consumer
* squashfs-tools 3.4 `squashfs_fs.h` — the v1–v3 structures, as bitfields;
  the wire offsets in this page were read off evidence, not off that header
  used by the tests
