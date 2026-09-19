# SquashFS v4

Reader: `src/filesystems/squashfs/SquashfsReader.{h,cpp}` (`fs::FilesystemReader`,
format id `squashfs`). Validator: `src/discovery/validators/squashfs.cpp`.
Tests: `tests/unit/filesystems/squashfs_test.cpp`.

SquashFS is the read-only compressed filesystem found in the majority of Linux
router, camera, NAS and appliance firmware. Version 4 (2009, kernel 2.6.29) is
the only version in current use; 1–3 are recognised by the validator and refused
by the reader (`squashfs-unsupported-version`).

## On-disk layout

Everything is in the byte order given by the magic: `hsqs` little-endian,
`sqsh` big-endian. Vendor images with a modified magic (`shsq`, `qshs`; DD-WRT
and some Broadcom SDKs) are accepted and the byte order is chosen by whichever
makes the major version read as 4.

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

## Known gaps

* Extended attribute names and values are not decoded (only the count).
* The export table and the extended-directory index are not used (they only
  accelerate lookups by inode number / name).
* Directory mtime is captured in `FileMeta` but `DiskSink` does not apply it.
* Hard links are emitted as independent regular files with `nlink > 1`; the
  Sink has no hard-link primitive.
* Big-endian images are covered by the synthetic test only; there is no
  big-endian mksquashfs to produce a real fixture.

## References

* Linux `fs/squashfs/squashfs_fs.h`, `inode.c`, `dir.c`, `file.c`,
  `fragment.c`, `id.c`, `xattr_id.c` (read for understanding; no code copied)
* https://dr-emann.github.io/squashfs/ — the community format description
* squashfs-tools (`mksquashfs`, `unsquashfs`) — reference producer/consumer
  used by the tests
