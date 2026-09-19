# ext2 / ext3 / ext4 (discovery validator)

This page is for examiners who see an `ext2`, `ext3` or `ext4` node in
`INFO.yaml` and for contributors who will write the reader. After reading it
you know what the validator checks, why a hit lands at a given tier, which
attrs and diagnostics it emits, and what is not done yet.

`src/discovery/validators/ext.cpp` (validator `ext`), signature `ext` in
`signatures/core.toml` (magic `53 ef` at `magic_offset = 0x438`, format `ext`,
category `filesystem`). There is no reader: `analyze` reports the node,
carves it, lists it in `partitions/mount.sh` as type `ext4`
(`discovery::mount_type_for`, `src/discovery/Recurse.cpp:1035`) and adds the
coverage row `ext4 / unsupported / "no reader registered"`.

## On-disk layout

The superblock is 1024 bytes into the filesystem, little-endian regardless of
host. The validator reads these fields (offsets relative to the superblock):

| offset | field | use |
|---|---|---|
| 0x00 | `s_inodes_count` u32 | must be non-zero; consistency check |
| 0x04 | `s_blocks_count_lo` u32 | must be non-zero; size |
| 0x14 | `s_first_data_block` u32 | 1 for 1 KiB blocks, 0 otherwise |
| 0x18 | `s_log_block_size` u32 | block size `1024 << n`, `n <= 6` |
| 0x20 | `s_blocks_per_group` u32 | must be non-zero; block-group count |
| 0x28 | `s_inodes_per_group` u32 | must be non-zero; consistency check |
| 0x2C | `s_mtime` u32 | `last_mount_time` |
| 0x30 | `s_wtime` u32 | `last_write_time` |
| 0x34 | `s_mnt_count` u16 | `mount_count` |
| 0x38 | `s_magic` u16 | `0xEF53` (the signature) |
| 0x3A | `s_state` u16 | bit 0 clean, bit 1 errors |
| 0x4C | `s_rev_level` u32 | 0 (good old) or 1 (dynamic); anything else rejected |
| 0x58 | `s_inode_size` u16 | rev 1: 128..block size, power of two |
| 0x5C | `s_feature_compat` u32 | `has_journal` (0x4) marks ext3 |
| 0x60 | `s_feature_incompat` u32 | ext4 flags (extents, 64bit, flex_bg, ...) |
| 0x64 | `s_feature_ro_compat` u32 | ext4 flags (huge_file, gdt_csum, metadata_csum, ...) |
| 0x68 | `s_uuid[16]` | `uuid` (rev 1) |
| 0x78 | `s_volume_name[16]` | `volume_name` (rev 1) |
| 0x88 | `s_last_mounted[64]` | `last_mounted` (rev 1) |
| 0x150 | `s_blocks_count_hi` u32 | high half of the block count when `INCOMPAT_64BIT` (0x80) is set |
| 0x3FC | `s_checksum` u32 | crc32c over bytes 0..0x3FB when `RO_COMPAT_METADATA_CSUM` (0x400) is set |

## What the validator checks

The magic is two bytes, so a false hit inside a 16 MiB image is normal. Every
hard constraint therefore rejects the hit (`nullopt`) instead of downgrading it:
`s_log_block_size > 6`, `s_rev_level > 1`, a zero block, inode or per-group
count, a `s_first_data_block` that disagrees with the block size, or a rev 1
`s_inode_size` that is below 128, not a power of two or larger than a block.

| tier | assigned when |
|---|---|
| rejected | any hard constraint above fails, or the superblock is not inside the data |
| structural | the superblock parsed (`make_finding(..., Confidence::Structural)`, `ext.cpp:72`) |
| consistent | the claimed size fits in the data and `inodes_count == block_groups * inodes_per_group` |
| verified | consistent and the `metadata_csum` crc32c matches `s_checksum` (rev 1 with `RO_COMPAT_METADATA_CSUM` only; ext2/ext3 and older ext4 stop at consistent) |

The format id is chosen from the feature flags (`ext.cpp:73-79`): rev 1 with
any ext4 `incompat` or `ro_compat` flag is `ext4`; rev 1 with `has_journal`
is `ext3`; everything else is `ext2`. The TOML format id stays `ext`; the
finding overrides `format`, which is what `Node::format` and the coverage row
show.

**Size.** `blocks_count * block_size`, saturating, clamped to the data with
`ext-truncated`. A truncated filesystem cannot be consistent, so it stays at
structural.

**Backup superblocks.** Block groups 1, 3, 5, 7, 9, ... start with a copy of
the superblock. Each copy matches the same signature and is validated as a
nested finding that starts 1024 bytes before it. Its claimed size runs past
the end of the data, so it gets `ext-truncated`, stays at structural, and is
absorbed into the primary finding's `also_matched` by conflict resolution
whenever the primary reached consistent or verified (`docs/formats/signatures.md`).

## Attributes

`block_size`, `blocks_count`, `inode_count`, `blocks_per_group`,
`inodes_per_group`, `block_groups`, `rev_level`, `state` (`clean`,
`not-clean`, `errors`), `last_mount_time`, `last_write_time`, `mount_count`;
rev 1 adds `inode_size`, `feature_compat`, `feature_incompat`,
`feature_ro_compat` (hex), `uuid`, `volume_name`, `last_mounted`;
`superblock_checksum` (`ok` / `mismatch`) when `metadata_csum` is set. Meanings:
`docs/reference/ATTRS.md`.

`last_mount_time`, `last_write_time` and `last_mounted` are forensic leads on
their own: when the device last ran and where the filesystem was mounted.

## Diagnostics

| code | severity | meaning |
|---|---|---|
| `ext-truncated` | warning | `blocks_count * block_size` exceeds the data; size clamped, tier capped at structural |
| `ext-inode-count-mismatch` | warning | `inodes_count != block_groups * inodes_per_group`; tier capped at structural |
| `ext-superblock-csum-mismatch` | warning | `metadata_csum` crc32c differs from `s_checksum`; the superblock was modified after the checksum was written |

## Verified on

* `tests/fixtures/out/ext4.img` (mke2fs, 16 MiB, 4 KiB blocks, one block
  group): one finding at `0x0`, `verified`, `superblock_checksum=ok`,
  `volume_name=omnitrace`.
* An eMMC image from a local corpus: GPT partitions whose first byte is ext4
  are listed as `ext4` in `partitions/mount.sh` (`docs/CLI.md`).

## Not yet supported

* No reader. Nothing is extracted; the coverage row is `unsupported`. The
  plan (`DEVELOPMENT_PLAN.md` 5.3) is to read ext through libtsk, which also
  gives orphan-inode and unallocated-dirent recovery.
* The journal, group descriptors and inode tables are not read, so the
  validator cannot tell a damaged filesystem from a clean one beyond the
  superblock checksum.
* No `mount.sh` distinction between ext2/3/4: all three mount as `ext4`,
  which the kernel driver handles.

## References

* Linux `fs/ext4/ext4.h` (read for understanding; no code copied)
* https://www.kernel.org/doc/html/latest/filesystems/ext4/ (superblock layout,
  feature flags, `metadata_csum`)
* e2fsprogs (`mke2fs`, `dumpe2fs`, `e2fsck -n`) as the reference tools
