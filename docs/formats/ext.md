# ext2 / ext3 / ext4

This page is for examiners who see an `ext2`, `ext3` or `ext4` node in
`INFO.yaml` and for contributors touching the validator or the reader. After
reading it you know what the validator checks, why a hit lands at a given
tier, what the reader extracts, how deleted files are recovered, which attrs
and diagnostics each emits, and what is not done.

* Validator: `src/discovery/validators/ext.cpp` (validator `ext`), signature
  `ext` in `signatures/core.toml` (magic `53 ef` at `magic_offset = 0x438`,
  format `ext`, category `filesystem`).
* Reader: `src/filesystems/ext/ExtReader.{h,cpp}`, one class registered for
  the three ids the validator can emit (`ext2`, `ext3`, `ext4`). Native, no
  libtsk or libext2fs.
* Tests: `tests/unit/filesystems/ext_test.cpp`; fixture
  `tests/fixtures/out/ext4.img` (`tests/fixtures/generate.py`).

ext is the rootfs and data partition of most Linux-based embedded devices
(eMMC infotainment units, NAS boxes, set-top boxes), usually behind a GPT or
MBR table, and the format under Android's `userdata` before f2fs.

The first half of this page is the validator; the reader starts at
[Reader](#reader).

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

## Validator gaps

* The validator reads the superblock only; the group descriptors and inode
  tables are the reader's job, so a hit can be `verified` and still be a
  damaged filesystem (the reader's diagnostics say so).
* No `mount.sh` distinction between ext2/3/4: all three mount as `ext4`,
  which the kernel driver handles.

## Reader

`ExtReader` walks the live tree exactly as a mount would show it and, with
`--history`, adds what the on-disk structures still say about files that
are gone. Everything is read through `Span`; file data is streamed to the
`Sink` one run of blocks at a time (at most `kStreamChunkBlocks` blocks of
one extent, or one block when checking a freed file against the block
bitmap), so no file is ever held in memory.

### On-disk structures the reader uses

All little-endian. Offsets are relative to the structure.

| structure | where | fields used |
|---|---|---|
| superblock | byte 1024 | everything the validator reads plus `s_first_ino` (0x54), `s_journal_inum` (0xE0), `s_desc_size` (0xFE), `s_first_meta_bg` (0x104), `s_mkfs_time` (0x108), `s_free_blocks_count_hi` (0x158), `s_checksum_type` (0x175), `s_checksum_seed` (0x270), `s_encoding` (0x27C) |
| group descriptor | block `first_data_block + 1`, `desc_size` bytes each (32, or 64 with `64bit`); with `meta_bg` the descriptors of meta group *m* sit in the first block of group `m * (block_size / desc_size)` (after that group's superblock backup when it has one) | `bg_block_bitmap`, `bg_inode_bitmap`, `bg_inode_table` (lo and hi halves), `bg_flags` (`INODE_UNINIT`, `BLOCK_UNINIT`), `bg_itable_unused`, `bg_checksum` |
| inode | `inode_table * block_size + (ino - 1) % inodes_per_group * inode_size` | `i_mode`, `i_uid`/`i_gid` with the `l_i_uid_high`/`l_i_gid_high` halves, `i_size` (64-bit for regular files, and for directories with `largedir`), `i_atime`/`i_ctime`/`i_mtime`, `i_dtime`, `i_links_count`, `i_blocks` (with `l_i_blocks_high` and the `HUGE_FILE_FL` unit rule), `i_flags`, `i_block[15]`, `i_generation`, `i_file_acl` (with the hi half under `64bit`), `i_size_high`, `i_extra_isize`, and when `i_extra_isize` covers them `i_ctime_extra`/`i_mtime_extra`/`i_atime_extra` (2 epoch bits + 30 nsec bits) and `i_crtime`/`i_crtime_extra` |
| extent tree | root in `i_block` (12-byte header `eh_magic 0xF30A, eh_entries, eh_max, eh_depth`, then 12-byte entries), index nodes in their own blocks | leaf: `ee_block, ee_len (> 32768 = uninitialized), ee_start_hi/lo`; index: `ei_block, ei_leaf_lo/hi`. Depth is capped at 5 (`EXT4_MAX_EXTENT_DEPTH`); as in the kernel's `__ext4_ext_check`, a child block must carry `eh_depth` one below its parent, start at the logical block its parent's index entry names, and hold ascending entries, so an index block that points at itself is refused once instead of being re-entered at every level |
| block map | `i_block[0..11]` direct, `[12]` single, `[13]` double, `[14]` triple indirect (ext2/ext3 and ext4 inodes without `EXTENTS_FL`) | pointers are 32-bit block numbers; 0 is a hole |
| inline data | `INLINE_DATA_FL`: `i_block` (60 bytes) then the `system.data` xattr in the inode body | directories: `i_block[0..3]` is the parent inode, entries follow without "." and ".." |
| directory entry | 8-byte header `inode, rec_len, name_len, file_type` (`name_len` is 16-bit without the `filetype` feature) then the name; `rec_len` uses the 64 KiB-block encoding when `block_size >= 65536` | entries with `inode == 0` are skipped (htree `dx_root`/`dx_node` fake entries, the `metadata_csum` tail); every directory block is read linearly, the hash index is never consulted |
| extended attributes | in-inode after `128 + i_extra_isize` (magic `0xEA020000`, values relative to the first entry) and in the EA block `i_file_acl` (32-byte header, values relative to the block) | `e_name_index` prefix (`user.`, `trusted.`, `security.`, `system.`, ACL names), `e_name`, `e_value_size`, `e_value_inum` (values in EA inodes are reported by size only) |

Checksums: with `metadata_csum` the superblock crc32c (bytes 0..0x3FB), every
group descriptor (crc32c of seed, group number and the descriptor with
`bg_checksum` zeroed, low 16 bits) and every inode (crc32c of seed, inode
number, generation and the inode with `i_checksum_lo`/`hi` zeroed) are
verified; with `gdt_csum` the descriptors are verified with crc16 over the
uuid, group number and descriptor. The seed is `s_checksum_seed` with
`csum_seed`, else crc32c(~0, uuid). A mismatch is a diagnostic, never a
refusal. Directory-block, extent-block and bitmap checksums are not verified.

### What the reader captures

Every entry gets a `FileMeta` with: `kind` from `i_mode`; `mode` (permission
bits, 07777); `uid`/`gid` (32-bit); `size`; `inode`; `nlink`; `mtime`,
`ctime`, `atime` with their nanoseconds and `crtime` when the inode is larger
than 128 bytes and `i_extra_isize` covers the field; `link_target` for fast
symlinks (target in `i_block` when the inode owns no data blocks, the EA
block excluded), slow symlinks (target in data blocks) and inline symlinks;
`rdev_major`/`rdev_minor` from the old (`i_block[0]`, 8:8) or new
(`i_block[1]`, 12:20) device encoding. `extra` keys:

| key | value |
|---|---|
| `flags` | `i_flags` as hex, when non-zero |
| `immutable`, `append_only`, `inline`, `encrypted`, `verity`, `casefold`, `compressed` | `true` when the matching inode flag is set |
| `generation` | `i_generation` when non-zero |
| `dtime` | `i_dtime` when non-zero (freed inodes) |
| `checksum` | `mismatch` when `metadata_csum` is on and the inode checksum fails |
| `xattrs` | `name=size;name=size` for every attribute in the inode body then the EA block, on-disk order; `name=size@inode<n>` for values kept in an EA inode. ACLs are named, never decoded |
| `content` | history entries only: `recovered from unallocated blocks`, `recovered from unallocated blocks; N reused blocks zero-filled`, `unavailable: extents cleared`, `unavailable: block map cleared`, `unavailable: size 0`, `unavailable: inode cleared` |
| `other_names` | history entries only: further slack names that pointed at the same inode, `;`-joined |
| `orphan` | history entries only: `true` when the inode is still allocated but no live entry names it |

Encrypted files (`EXT4_ENCRYPT_FL`) are listed with their stored names and
size but no data is written (the entry is marked truncated). Compressed
(`EXT2_COMPR_FL`) and casefolded entries are extracted as stored.

**Walk order** (deterministic): the root's entries in on-disk order; when an
entry is a directory it is emitted and then its entries follow immediately
(depth-first), each directory's entries in the order its blocks hold them.
`.` and `..` are never entries. A directory inode met twice (an ancestor or
a directory hard-linked twice) is reported (`ext-dir-loop`) and not
descended again; hard-linked regular files are listed under every name with
the shared inode number. `lost+found` is an ordinary directory. Entries
naming a reserved inode (`< s_first_ino`, other than the root) are skipped
with `ext-dirent-corrupt`; the journal (inode 8) is never walked.

**Sparse files and holes** read as zeros, as do uninitialized extents. A
run that maps blocks outside the filesystem or outside the image stops the
file there (zero-filled to `i_size`, entry marked truncated) so the offsets
of everything recovered stay right.

**Limits** (all from `Limits`): `max_nodes_per_fs` bounds the entries held
per directory, the slack entries collected for history, the freed inodes
scanned, and the xattr entries reported per inode; `max_files` bounds the
entries emitted; `max_file_bytes` bounds one file's data, a symlink
target and the directory blocks read for one directory (a `largedir`
`i_size` is 64-bit, so a hostile directory could otherwise map 2^32 blocks).
A tripped limit is a `ext-limit-*` warning and `truncated`. A superblock
whose `blocks_count` reaches past the data (`ext-truncated-image`) has its
block-group count clamped to the groups that start inside the data, so no
per-group scan runs over groups that cannot exist.

### Attributes (`FilesystemInfo::attrs`)

`volume_name`, `uuid`, `block_size`, `blocks_count`, `inode_count`,
`free_blocks`, `free_inodes`, `block_groups`, `blocks_per_group`,
`inodes_per_group`, `inode_size`, `first_ino`, `rev_level`,
`feature_compat`/`feature_incompat`/`feature_ro_compat` (hex), `features`
(names, `compat|incompat|ro_compat`), `state`, `errors_behaviour`,
`last_mount_time`, `last_write_time`, `last_check_time`, `mkfs_time`,
`mount_count`, `max_mount_count`, `last_mounted`, `creator_os`,
`has_journal`, `journal_inode`, `needs_recovery`, `csum_type` (`crc32c`,
`crc16` or `none`), `desc_size`, `encoding` (casefold only). Meanings:
`docs/reference/ATTRS.md`. `FilesystemInfo::format` is `ext2`, `ext3` or
`ext4` by the same feature-flag rule the validator uses.

### History

ext keeps no versions, but three things survive an unlink until they are
overwritten, and `--history` turns them into entries:

1. **Freed inodes.** Every inode table is scanned (groups with
   `INODE_UNINIT` and the `bg_itable_unused` tail are skipped). An inode
   whose bit in the inode bitmap is clear and that looks like a file
   (`i_dtime` set, or a known type with a size or a time) is a deletion
   candidate; so is an allocated inode that no live entry reaches (an
   orphan, `extra.orphan=true`).
2. **Slack directory entries.** When the kernel unlinks an entry it merges
   the record into its predecessor's `rec_len`; the bytes stay. Every
   directory block's slack (from the end of each live record, `8 + name_len`
   rounded to 4, to its `rec_len`) is parsed with the same validation as a
   live entry (inode in range, `rec_len` and name inside the block, a legal
   file type, no `/` or NUL). The `..` entry of an htree root and htree
   index blocks are skipped: their slack is the hash index. Names pointing
   at an inode that is still reachable are renames and are dropped.
3. **Block references.** With debugfs, or on ext2/ext3 images where the
   pointers were not cleared, a freed inode still names its blocks. They are
   streamed only where the block bitmap shows them unallocated; a block that
   was reallocated is zero-filled and counted (`ext-deleted-blocks-reused`).
   A real kernel unlink on ext4 leaves an extent header with zero entries
   (and ext2/ext3 clear the map), which gives a metadata-only entry
   (`ext-deleted-no-blocks`) with the recorded size, owner and times.

The path of a history entry is the first slack name that points at the
inode (further names go to `extra.other_names`), or `lost+found/#<inode>`
when no name survives. When that path is live with a different inode the
entry is `superseded` (an older version of the current file), otherwise
`deleted`. `version` is an ordinal per path, 1 upwards in
(`dtime`, `ctime`, `mtime`, inode) order; `extra.dtime` holds the deletion
time. A slack name whose inode is empty on disk gives a metadata-only entry
(`extra.content=unavailable: inode cleared`). History entries are emitted
after the live tree, sorted by path then version; `DiskSink` puts them
under `.omnitrace-versions/<path>/v<version>`.

What this cannot do: name an inode whose entry was reused (the
`tests/fixtures/out/ext4.img` fixture's `config.txt` v1 is such a case and
surfaces as `lost+found/#26`), or recover data whose blocks were reused; it
does not read the journal, which on ext3/ext4 often holds older copies of
directory blocks and inodes.

### Diagnostics (reader)

| code | severity | when |
|---|---|---|
| `ext-superblock-bad` | status / warning | `open()` refuses a superblock that fails a hard constraint (magic, `s_log_block_size > 6`, `s_rev_level > 1`, inode size, zero counts, per-group counts larger than a bitmap block, `s_first_data_block` vs block size, `s_desc_size`); as a warning the `metadata_csum` crc32c of the superblock does not match and the walk continues |
| `ext-truncated-image` | warning | `blocks_count * block_size` exceeds the data; reads past the end fail per entry |
| `ext-unsupported-feature` | warning / info | unknown incompat bits, a non-crc32c checksum type (warning); journal needs recovery (not replayed), encrypted, casefold or compressed entries (info, once per feature) |
| `ext-gdt-csum-mismatch` | warning | N group descriptors fail crc16/crc32c; summarised once with the first group |
| `ext-inode-csum-mismatch` | warning | N inode checksums fail; summarised once at the end of the walk, each entry carries `extra.checksum=mismatch` |
| `ext-metadata-corrupt` | error / warning | root inode or root listing unreadable (error, walk fails); an inode, group descriptor, bitmap or directory block unreadable, a symlink target unreadable, an inode with no known type (warning, entry or subtree skipped) |
| `ext-root-invalid` | error | inode 2 is not a directory |
| `ext-extent-corrupt` | warning | bad extent magic, entries beyond `eh_max` or the node, depth over 5, a child whose depth or first block disagrees with its parent's index entry, overlapping or descending entries, blocks outside the filesystem; the file is cut there |
| `ext-blockmap-corrupt` | warning | a direct or indirect pointer outside the filesystem or an unreadable indirect block; the file is cut there |
| `ext-inline-data-corrupt` | warning | inline data shorter than `i_size` or an unreadable `system.data` |
| `ext-data-truncated` | warning | a data block lies outside the image; rest of the file zero-filled |
| `ext-dirent-corrupt` | warning | bad `rec_len`/`name_len` (rest of the block skipped), a name with `/` or NUL, a reserved or empty inode, a directory size not a multiple of the block size |
| `ext-dir-loop` | warning | a directory inode already listed; not descended |
| `ext-xattr-corrupt` | warning | bad EA magic, an entry past the end, a value outside the area |
| `ext-deleted-no-blocks` | info | a freed inode has no block references left; metadata-only entry |
| `ext-deleted-blocks-reused` | warning | N blocks of a freed inode are allocated elsewhere; zero-filled |
| `ext-limit-nodes`, `ext-limit-files`, `ext-limit-file-bytes` | warning | a `Limits` field tripped; `truncated` set (`ext-limit-file-bytes` also when a directory's `i_size` exceeds the cap: its later blocks are not read) |
| `ext-sink-error` | warning | the Sink refused the entry (unsafe path, sink limit) |

Meanings and examiner actions: `docs/reference/DIAGNOSTICS.md`.

### Verified on

* `tests/fixtures/out/ext4.img`: every `tree` entry (mode, owner, times,
  size, sha256, link target, hard-link count) and, with history,
  `history/deleted.txt` (inode 27, content and sha256 recovered),
  `lost+found/#26` (config.txt v1, no surviving name) and
  `history/.config.v2` (config.txt v2 under its temporary name), while
  `.config.v3` (a rename of the live inode) is correctly absent.
* mkfs images built in the test: ext4 (extents, flex_bg, metadata_csum,
  64bit, journal), ext4 without metadata_csum/64bit, ext2 with 1 KiB blocks
  (double-indirect maps), ext3, ext4 with inline_data; each with a 3 MiB
  multi-extent file, a sparse file, a 1000-entry htree directory, fast and
  slow symlinks, a hard link, char/block devices, a fifo, xattrs, immutable
  flag, nanosecond timestamps; listing compared to the staging tree,
  `DiskSink` output diffed against it, deletions made with `debugfs rm`
  recovered by name with content (ext2/ext3/ext4 with intact maps), as
  metadata-only when the map was cleared, and flagged when a block was
  reallocated.
* Corpus: a 512 MiB ext4 rootfs and a 50 MiB ext2 partition from local
  eMMC images, diffed against `debugfs rdump` (content, names, symlink
  targets, modes, mtimes; uid/gid/size against `debugfs stat` for a sample).
* Hostile: truncation at every offset, `s_log_block_size 20`, extent depth
  9, an index block that points at itself 84 times under a depth-2 root,
  extents past the image, `rec_len` 0 and larger than the block, `i_size`
  2^60 on a file and on a `largedir` directory, an indirect block pointing
  at itself, a directory loop, seeded byte flips; all under ASan/UBSan.

### Known gaps

* The journal is never replayed or read: a filesystem with
  `needs_recovery` is listed in its pre-replay state, and the older
  metadata copies the journal holds are not mined for history.
* Encrypted files: names and data are listed as stored; no decryption.
* Casefold: names are compared byte-wise; no folding.
* Directory-block, extent-block and bitmap checksums are not verified.
* `bigalloc` clusters are treated as blocks (the block bitmap check for
  freed files is per block, which under-reports reuse on such volumes).
* Files whose values live in EA inodes (`ea_inode`) report the xattr size
  only.
* Deleted directories are listed without their (former) children.

## References

* Linux `fs/ext4/ext4.h`, `ext4_extents.h`, `xattr.h`, `dir.c`, `inline.c`,
  `namei.c` (read for understanding; no code copied)
* https://www.kernel.org/doc/html/latest/filesystems/ext4/ (superblock
  layout, group descriptors, inode layout, extent tree, directory entries,
  htree, extended attributes, `metadata_csum`, inline data)
* e2fsprogs (`mke2fs`, `dumpe2fs`, `debugfs`, `e2fsck -n`) as the reference
  tools; `debugfs rdump` / `stat` / `blocks` / `ea_list` are what the tests
  compare against
* moria (MIT) for the shape of a range-checked ext walk; no code copied
