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

## Known gaps

* Inodes and block pointers are not walked; extraction belongs to a reader.
