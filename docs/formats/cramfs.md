# cramfs

`src/discovery/validators/cramfs.cpp` (validator `cramfs`), signatures
`cramfs-le` / `cramfs-be` in `signatures/core.toml` (format `cramfs`,
category `filesystem`).

## On-disk layout (76-byte superblock, filesystem byte order)

| offset | field | constraint |
|---|---|---|
| 0 | `magic` u32 | `0x28cd3d45` |
| 4 | `size` u32 | image bytes (valid only with FSID_VERSION_2) |
| 8 | `flags` u32 | `0x1` FSID_VERSION_2, `0x2` SORTED_DIRS, `0x100` HOLES, `0x200` WRONG_SIGNATURE, `0x400` SHIFTED_ROOT_OFFSET, `0x800` EXT_BLOCK_POINTERS |
| 12 | `future` u32 | |
| 16 | `signature[16]` | `Compressed ROMFS` (required; otherwise the 4-byte magic is noise and the hit is rejected) |
| 32 | `fsid.crc` u32 | crc32 (zlib) of the whole image with this field zeroed |
| 36 | `fsid.edition` u32 | |
| 40 | `fsid.blocks` u32 | |
| 44 | `fsid.files` u32 | > 0 |
| 48 | `name[16]` | |
| 64 | root inode (12 bytes) | |

## Tiers

| tier | when |
|---|---|
| rejected | signature string absent |
| structural | v1 image (no size field; `size` 0), `size` < 76 or `files` 0, or the image runs past the data |
| consistent | image inside the data |
| verified | whole-image CRC matches |

## Attributes

`version` (1/2), `flags`, `name`, `edition`, `blocks`, `files`, `crc`,
`crc_check` (`ok` / `mismatch`).

## Diagnostics

`cramfs-unknown-flags` (info), `cramfs-v1-no-size` (info), `cramfs-bad-size`
(warning), `cramfs-truncated` (warning), `cramfs-crc-mismatch` (warning).

## Verified on

* `mkfs.cramfs` output (util-linux 2.40): verified, size and file count as
  built.

## The reader

`src/filesystems/cramfs/CramfsReader.cpp` walks the tree and inflates file
data. A directory's data is `size` bytes of back-to-back inodes, each 12 bytes
followed by its name NUL-padded to a multiple of four; a regular file's data
is a table of u32 block pointers followed by the zlib blocks, where pointer
`i` is the offset one past block `i`. Blocks are 4096 bytes uncompressed
(cramfs uses the page size and `mkfs.cramfs -b` accepts nothing else), so the
last block is short and every other one is full.

The trap is the inode, which is three u32 words of C bitfields:

```c
__u32 mode:16, uid:16;  __u32 size:24, gid:8;  __u32 namelen:6, offset:26;
```

GCC packs bitfields from the least significant end on a little-endian target
and from the most significant end on a big-endian one, so **a big-endian
image is not a byte swap of a little-endian one** — the fields sit at
different bit positions. Both layouts are spelled out in `read_inode`.
`namelen` counts 4-byte units and `offset` is in 4-byte units too, which is
what lets a 26-bit field address a 256 MiB image and what makes every
structure in the image 4-byte aligned.

Bounded by a visited set of directory data offsets (a directory can name an
ancestor), a nesting depth of 64, and `Limits::max_nodes_per_fs`.

### Not read

* `EXT_BLOCK_POINTERS` (flag `0x800`) gives a pointer's high bits extra
  meaning — uncompressed and direct blocks, added for cramfs on MTD. This
  build does not decode them and says so with `cramfs-unsupported-flags`
  rather than quietly producing wrong bytes.
* cramfs stores no timestamps, so every entry's times are absent rather than
  epoch; the entry carries `no_timestamps` to say the absence is the format's.
* `mkfs.cramfs` truncates gid to 8 bits (it warns while doing it), so a gid
  above 255 in the source tree is not recoverable from the image.
* Device nodes carry no rdev in cramfs, so a char or block device is listed
  with its mode and no numbers.

## Diagnostics (reader)

`cramfs-bad-inode`, `cramfs-bad-block`, `cramfs-decompress-failed`,
`cramfs-cycle`, `cramfs-limit-nodes`, `cramfs-limit-depth`,
`cramfs-sink-error`, `cramfs-unsupported-flags`.

## Verified on

* `mkfs.cramfs` (util-linux 2.41) output in both `-N little` and `-N big`:
  the extracted tree is identical to the source directory — every path, mode,
  symlink target and CRC-32, including a 200 KB multi-block file and a 9 KB
  incompressible one.
* Hostile images built in `tests/unit/filesystems/cramfs_test.cpp`: a
  directory pointing at an ancestor, a directory pointing outside the image, a
  block pointer outside the image, and a block that does not inflate. Each is
  reported and cut rather than followed.

## Known gaps

* No `--history`: cramfs is read-only and keeps no superseded versions.
