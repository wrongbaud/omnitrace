# QNX6 (fs-qnx6, Power-Safe)

Validator `src/discovery/validators/qnx6.cpp` (signatures `qnx6-le` /
`qnx6-be` in `signatures/core.toml`), reader
`src/filesystems/qnx6/Qnx6Reader.{h,cpp}` registered as `qnx6`, tests
`tests/unit/discovery/qnx6_validator_test.cpp` and
`tests/unit/filesystems/qnx6_test.cpp`. No fixture: there is no `mkqnx6fs`
outside the QNX SDP, so the tests build images byte by byte and compare the
corpus partitions against a qnxmount FUSE mount. QNX6 is the read-write
"Power-Safe" filesystem of QNX Neutrino 6.4+ and QNX SDP 7/8: the eMMC
partitions of automotive infotainment and cluster units (the corpus:
`dps_mfg`, `dps_os`, `storage`) and the nested update images stored as files
inside them. It is copy-on-write with two alternating superblocks, so the
previous committed snapshot is always intact and the reader recovers it as
history.

## On-disk layout

Byte order is per image: the magic reads `22 11 19 68` on little-endian
units and `68 19 11 22` on big-endian ones (some PowerPC automotive units).
All offsets below are relative to the partition start.

| range | what |
|---|---|
| `0x0000..0x1FFF` | boot block; on many images `EB 10 90 00`, then u32 `offset`, u32 `sblk0`, u32 `sblk1` (sector numbers of the two superblocks, **often garbage**, see below) |
| `0x2000..0x21FF` | primary superblock (512 bytes) |
| `data_start` | `round_up(0x3000, blocksize)`: `0x3000` for 512 B..4 KiB blocks, `0x4000` for 8 and 16 KiB, one block for larger |
| `data_start + num_blocks * blocksize` | second superblock, followed by `round_up(0x1000, blocksize)` bytes of superblock area; the filesystem ends there |

Superblock (`struct qnx6_super_block`, 512 bytes):

| offset | field | notes |
|---|---|---|
| 0 | `magic` u32 | `0x68191122` |
| 4 | `checksum` u32 | CRC-32 over bytes 8..511: polynomial `0x04C11DB7`, MSB first, seed 0, no final xor (the kernel's `crc32_be(0, ...)`, `crcmod.mkCrcFun(0x104C11DB7, initCrc=0, rev=False)` in qnxmount) |
| 8 | `serial` u64 | commit counter; the higher of the two superblocks is the current snapshot |
| 16 | `ctime`, `atime` u32 | |
| 24 | `flags` u32 | `0x302` / `0x300` on the corpus; not decoded |
| 28 | `version1`, `version2` u16 | `4.3` on every corpus image |
| 32 | `volumeid[16]` | |
| 48 | `blocksize` u32 | power of two, 512..65536; 4096 on every corpus image |
| 52 | `num_inodes`, `free_inodes` u32 | |
| 60 | `num_blocks`, `free_blocks` u32 | data blocks after `data_start` |
| 68 | `allocgroup` u32 | |
| 72 | `Inode` root node | the inode table, stored as a file |
| 152 | `Bitmap` root node | the block bitmap, stored as a file |
| 232 | `Longfile` root node | the long file name table, stored as a file |
| 312, 392 | `Iclaim`, `Iextra` root nodes | not decoded (`qnx6-unsupported-feature` Info when non-empty) |
| 472 | `migrateblocks`, `scrubblock` u32 | |
| 480 | spare | |

Root node (80 bytes): `size` u64, `ptr[16]` u32, `levels` u8, `mode` u8,
6 spare bytes. A root node and an inode describe a file the same way: 16
block pointers and `levels` (0..5, `QNX6_PTR_MAX_LEVELS`) of indirection.
Block pointers are data-block numbers relative to `data_start`;
`0xFFFFFFFF` is an unused pointer (a hole, read as zeros). With
`ptrbits = log2(blocksize / 4)` the direct pointer of file block `n` is
`ptr[n >> (ptrbits * levels)]` and each level then takes the next `ptrbits`
bits of `n` as the index into an indirect block of u32 pointers (the
kernel's `qnx6_block_map`).

Inode (`struct qnx6_inode_entry`, 128 bytes; inode `n` is record `n - 1` of
the inode table, inode 1 is the root directory):

| offset | field | notes |
|---|---|---|
| 0 | `size` u64 | |
| 8 | `uid`, `gid` u32 | |
| 16 | `ftime` u32 | creation time (`FileMeta::crtime`) |
| 20 | `mtime`, `atime`, `ctime` u32 | |
| 32 | `mode` u16 | POSIX type and permission bits |
| 34 | `ext_mode` u16 | reported in `extra["ext_mode"]` |
| 36 | `block_ptr[16]` u32 | |
| 100 | `filelevels` u8 | |
| 101 | `status` u8 | `0x01` for the root and system directories, `0x03` for ordinary entries, `0x02` deleted, `0x00` unused (corpus and `QNX6_FILE_*` in the kernel) |
| 102 | unknown u16, 24 zero bytes | |

Directory entry (32 bytes, `blocksize / 32` per block; entries are used in
on-disk order):

| offset | field | notes |
|---|---|---|
| 0 | `inode` u32 | 0 = free slot |
| 4 | `size` u8 | name length 1..27, or `0xFF` for a long name; anything else is corrupt |
| 5 | `name[27]` | short name, not NUL-terminated when 27 bytes long |
| 5 | (long name) 3 zero bytes, `long_inode` u32 at 8, `checksum` u32 at 12 | `long_inode` is an index in **blocks** into the longfile table |

Long file name record (at `index * blocksize` in the longfile file): `size`
u16 then up to 510 name bytes. The checksum in the directory entry is the
kernel's `qnx6_lfile_checksum`: `crc = ((crc >> 1) + c) ^ (crc & 1 ? 0x80000000 : 0)`
over the name bytes (as signed chars). `.` and `..` are real entries.

Bitmap: one bit per block of the **whole partition** in blocksize units,
LSB first, from byte 0 (so data block `b` is bit `data_start / blocksize + b`;
the last bits cover the second superblock area); 1 = allocated. The corpus
`dps_mfg` image (1020 data blocks, 1024 bits, 58 set, `free_blocks` 966)
confirms the numbering.

Symlink targets are the inode's file data. Device numbers are not decoded
(the encoding is unknown; `rdev_major/minor` stay 0). There is no link
count in the inode; `nlink` is reported as 1.

## Validator

### What the validator does

1. Rejects hits whose structure start is not 4 KiB aligned (the signature
   carries `alignment = 4096`) and parses the superblock at `+0x2000` in the
   signature's byte order.
2. **Structural** once `blocksize` is a power of two in 512..65536,
   `num_blocks` and `num_inodes` are non-zero, every root node has at most
   5 levels and the inode table can hold the root inode; otherwise a
   `magic` finding with `qnx6-bad-superblock` and no size.
3. Size = `data_start + num_blocks * blocksize + round_up(0x1000, blocksize)`,
   clamped to the span (`qnx6-truncated`), so the second superblock is
   inside the finding and its magic is skipped by the scanner's
   same-signature coverage rule. Nested QNX6 images stored as files inside
   another QNX6 (the `storage` partition holds several) are sized the same
   way and land inside the enclosing finding.
4. **Consistent** when the extent fits and every non-hole pointer of the
   inode, bitmap and longfile root nodes is below `num_blocks`
   (`qnx6-bad-root-pointer` otherwise).
5. The second superblock is read at its computed place, then, if absent,
   where the boot block's `sblk1` hint points (the hint is garbage on
   `dps_os`: it says sector 6143 while the superblock is at `0x17ff000`),
   else `qnx6-superblock-single`.
6. **Verified** when the CRC of the superblock the geometry came from
   verifies; a failing CRC on either superblock is `qnx6-superblock-bad-crc`.
7. The current superblock is the checksum-valid one, then the higher
   serial, then the primary (`qnx6-serial-tie` when equal); its fields fill
   the attrs.
8. A hit on a **second** superblock whose primary is corrupt or wiped (an
   intact primary's finding always covers the second one first) is
   recognised when a boot block or a superblock magic sits where that
   filesystem would begin; the finding is then placed at the filesystem
   start with the geometry taken from the second superblock and a
   `qnx6-bad-superblock` diagnostic naming the primary's problem. The
   magic-tier finding of the corrupt primary ends up in `also_matched`.

### Validator attributes

`blocksize`, `num_blocks`, `num_inodes`, `free_inodes`, `free_blocks`,
`serial`, `ctime`, `atime`, `flags`, `version`, `volume_id`, `endian`,
`data_start`, `second_superblock_offset` (or `none`), `second_serial`,
`current_superblock` (`primary` / `secondary`), `root_levels`,
`blocks_per_group`, `inode_table_size`, `longfile_size`.

### Validator diagnostics

| code | severity | meaning |
|---|---|---|
| `qnx6-bad-superblock` | warning | impossible block size, zero counts, more than 5 levels or a tiny inode table; that superblock is not used |
| `qnx6-truncated` | warning | the claimed extent runs past the span; size clamped, tier stays structural |
| `qnx6-bad-root-pointer` | warning | a root-node pointer lies beyond `num_blocks`; tier stays structural |
| `qnx6-superblock-bad-crc` | warning | a superblock's checksum does not verify |
| `qnx6-superblock-single` | info | no second superblock |
| `qnx6-serial-tie` | info | both superblocks carry the same serial |

### Validator verified on

* `qnx-example` corpus (`UserData.BIN`, GPT): `dps_mfg` at `0x800000`
  (4 MiB, 1020 blocks, serials 15/16, second superblock at `+0x3ff000`),
  `dps_os` at `0x1000000` (24 MiB, 6140 blocks, inode table with one level
  of indirection, second superblock at `+0x17ff000` although the boot block
  points elsewhere) and `storage` at `0x16800000` (3724795 blocks, 65536
  inodes, serials 996049/996050). Every finding is `verified` with a size
  that ends at the partition end; the hits on the second superblocks
  (`0xbfd000`, `0x27fd000`) no longer become findings of their own.

## Reader

`Qnx6Reader::open()` parses both superblocks and picks the current one;
`walk()` emits the live tree and, with `WalkOptions::history`, the
previous snapshot's differences and the deleted inode-table records.
Everything is read through `Span`; file data is streamed to the `Sink` one
block at a time through a 32-slot cache of metadata blocks (inode table,
directories, longfile, bitmap, indirect blocks).

### Open

* The primary superblock at `0x2000` is tried in both byte orders. When it
  is missing or structurally unusable (`qnx6-bad-superblock`), a superblock
  is looked for at the tail of the span (`size - 0x1000`, then one block of
  each supported size before the end): the finding produced from a second
  superblock ends there.
* The second superblock is read after the last data block, then at the boot
  block's hint. Both are CRC-checked (`qnx6-superblock-bad-crc`).
* Current = checksum-valid, then higher serial, then primary. With both
  checksums bad the higher serial is still used (a mount would refuse; an
  examiner wants the tree). One superblock only: `qnx6-superblock-single`,
  no snapshot history. Equal serials: `qnx6-serial-tie`, no snapshot
  history. Superblocks disagreeing on block size: the other is ignored.
* `num_blocks * blocksize` past the span: `qnx6-truncated`; blocks past
  the end read as out of range. Version other than 4.x:
  `qnx6-unsupported-feature` (Warning). Non-empty `iclaim` / `iextra`
  trees: `qnx6-unsupported-feature` (Info).
* `open()` fails with `qnx6-no-superblock` when no usable superblock exists.

### Live walk

* Root is inode 1. Directories are walked depth first, entries in on-disk
  order (fs-qnx6 has no other order); `.` and `..` and free slots are
  skipped. A name length of 0 or 28..254, a name containing `/` or NUL, an
  inode number past the table, or an entry naming an unused record is
  `qnx6-dirent-corrupt` (entry skipped). A long-name entry whose index is
  past the longfile table, in an unused block, or whose record has length 0
  or above 510 is `qnx6-longfile-corrupt` (entry skipped); a checksum
  mismatch keeps the name and counts `qnx6-longfile-checksum` (Info: the
  MMI variant uses another checksum).
* An inode record that cannot be read (past the table, unused table block,
  unreadable indirect block) is `qnx6-inode-tree-corrupt`; for the root it
  is an Error and the snapshot is not walked.
* A directory naming an ancestor, or a second name for a directory already
  walked, is `qnx6-dir-loop` (listed, not descended).
* Regular files stream block by block: holes as zeros; a block outside the
  data area, an indirect block that cannot be read or a tree deeper than
  the pointers allow is `qnx6-block-out-of-range` (range zero-filled, entry
  `truncated`). Symlink targets are read from the data blocks, cut at
  PATH_MAX (`qnx6-bad-symlink`).
* Walk-level caps: `max_nodes_per_fs` metadata records
  (`qnx6-limit-nodes`), `max_files` entries (`qnx6-limit-files`),
  `max_file_bytes` per entry (`qnx6-limit-file-bytes`); each sets
  `truncated`. The Sink's refusals are `qnx6-sink-error`.

### What the reader captures

`FileMeta`: `path`, `kind` (from `mode`), `mode` (permission bits), `uid`,
`gid`, `size` (0 for directories; target length for symlinks), `mtime`,
`atime`, `ctime`, `crtime` (= `ftime`), `inode`, `nlink` (always 1: the
format keeps none), `link_target`, `version` (the serial of the snapshot
the entry comes from), `deleted`, `superseded`, and `extra`: `status`
(hex), `ext_mode` (hex, when non-zero), `levels` (when indirect),
`record` = `inode-table`, `orphan` = `true`.

`FilesystemInfo`: `size` (the validator's extent), `block_size`, `endian`,
and the attrs of the validator plus `longfile_slots`, `longfile_count`,
`superblock_crc` (`ok` / `bad`) and `truncated`.

### History

fs-qnx6 commits by writing changed blocks to free space, then writing the
other superblock with the next serial; blocks referenced by the previous
snapshot are never reused until that snapshot itself is superseded. So the
lower-serial superblock describes a complete, consistent, intact earlier
state of the whole filesystem. With `WalkOptions::history` the reader
emits, after the live tree:

1. **The previous snapshot.** It is walked exactly like the live one. An
   entry whose path is live with the same inode number and a byte-identical
   inode record is the same file and is not repeated (its directory is
   still descended: a child may differ). Any other entry is emitted with
   `version` = the old serial: `superseded = true` when the path is still
   live (content or metadata changed, or the name now points at another
   inode), `deleted = true` when the path no longer exists (its content is
   intact and streamed in full). A snapshot with a corrupt root is
   `qnx6-inode-tree-corrupt` (Warning) and skipped.
2. **Deleted inode-table records.** Every record of the current inode table
   that no live entry references but that still carries a mode, a size or
   block pointers (fs-qnx6 marks unlinked records `status = 0x02` and
   frees their blocks; some units zero the record instead) is emitted with
   `deleted = true`, `version` = the current serial and
   `extra["record"] = "inode-table"`. Its path is the name the previous
   snapshot gave that inode, else `lost+found/#<inode>` with
   `extra["orphan"] = "true"` (counted in a `qnx6-dirent-corrupt` Info). A
   record already emitted from the previous snapshot with the same content
   pointers is not repeated. Its blocks were freed at deletion time and may
   have been reallocated since, so only blocks the **current bitmap shows
   free** are streamed; an allocated one is zero-filled, the entry marked
   `truncated`, and `qnx6-deleted-blocks-reused` reported per entry and
   once per walk. A deleted directory record is listed but its entries are
   not walked (each child has its own record).

`Limits::max_versions_per_entry` caps history entries per path
(`qnx6-limit-versions`; the live tree is complete, so the walk is not
`truncated`). `WalkResult.superseded` / `deleted` count the flags;
`DiskSink` places every historical entry under
`.omnitrace-versions/<path>/v<serial>`. The live part of a history walk is
byte-identical to a plain walk.

Example, `dps_mfg` (serial 15 -> 16): between the snapshots `DID/F124` was
created, which rewrote the `DID` directory and the root; the history walk
emits `DID` as superseded (version 15) and nothing as deleted (the root is
never emitted, and `F111`, `F113` are byte-identical records). On `dps_os`
(5185 -> 5186) it emits `de-blocks/dps_storage.bin` as superseded with its
former 2216-byte content.

### Limits

| Limits field | effect |
|---|---|
| `max_nodes_per_fs` | directory blocks, directory entries and inode records parsed (`qnx6-limit-nodes`), so a directory whose size claims 2^56 bytes of holes ends with the budget; also bounds the longfile scan at open |
| `max_files` | entries emitted (`qnx6-limit-files`) |
| `max_file_bytes` | bytes streamed per entry (`qnx6-limit-file-bytes`) |
| `max_versions_per_entry` | history entries per path (`qnx6-limit-versions`) |
| `max_bytes` | enforced by the Sink |

### Reader diagnostics

| code | severity | when |
|---|---|---|
| `qnx6-superblock-bad-crc` | warning | a superblock's checksum failed |
| `qnx6-superblock-single` | info | one superblock only; no snapshot history |
| `qnx6-serial-tie` | info | equal serials; no snapshot history |
| `qnx6-bad-superblock` | warning | a superblock is unusable (or the two disagree on block size); the other is used |
| `qnx6-truncated` | warning | extent past the span |
| `qnx6-unsupported-feature` | warning / info | version not 4.x / iclaim or iextra data not decoded |
| `qnx6-inode-tree-corrupt` | error / warning | root inode unreadable (snapshot skipped) / an inode record or directory block unreadable |
| `qnx6-dirent-corrupt` | warning / info | bad directory entry skipped / count of orphan records under lost+found |
| `qnx6-longfile-corrupt` | warning | long-name entry unresolvable; skipped |
| `qnx6-longfile-checksum` | info | long-name checksum mismatch; name used |
| `qnx6-dir-loop` | warning | ancestor or repeated directory; not descended |
| `qnx6-block-out-of-range` | warning | a data or indirect block unreadable; zero-filled, entry truncated |
| `qnx6-deleted-blocks-reused` | warning | a deleted record's block is allocated again; zero-filled |
| `qnx6-bad-symlink` | warning | symlink target above PATH_MAX; cut |
| `qnx6-limit-nodes` / `-files` / `-file-bytes` | warning | a `Limits` guard tripped; `truncated` set |
| `qnx6-limit-versions` | warning | history entries dropped; walk not truncated |
| `qnx6-sink-error` | warning | the Sink refused an entry; skipped |

`open()` fails with `qnx6-no-superblock` when no superblock is usable.

### Verified on

* `dps_mfg` and `dps_os` of the `qnx-example` corpus: names, kinds, modes,
  owners, sizes, mtimes, symlink targets and SHA-256 of every entry equal
  those of a qnxmount FUSE mount of the same bytes, `diff -r
  --no-dereference` of the extracted tree against the mount is empty, and
  the history walk's live part is identical (qnxmount needs a copy of
  `dps_os` with the boot block's superblock pointers corrected; the reader
  reads the untouched bytes). Long names (`key_sync_soa_tls_private.pem`,
  ...) resolve through the longfile table with matching checksums.
* `storage` (14.2 GiB, inode table and longfile with one level of
  indirection, 65536 inode records): the top two directory levels match
  qnxmount's listing entry by entry.
* Synthetic images in both byte orders with an inode table behind two
  levels of indirection, a file behind two levels, a three-block file with
  a hole, a 54-byte name, and a previous snapshot.

### Known gaps

* Device numbers are not decoded (`rdev_*` are 0); `nlink` is always 1.
* `iclaim` / `iextra` trees, `flags`, `ext_mode` and the boot block are
  reported, not interpreted.
* The layout for block sizes other than 4096 follows `round_up(0x3000,
  blocksize)` (qnxmount's rule, which agrees with the kernel for 4096 and
  below); no such image was available to verify.
* The MMI (infotainment) variant's long-name checksum is not implemented; its names
  are still used (`qnx6-longfile-checksum`).
* Only two snapshots exist on disk, so history is one step deep; blocks of
  files deleted before the previous snapshot are only reachable through
  inode-table records that a unit did not zero.
* Extended attributes, if the format stores any, are not read.
* ETFS (NAND) and EFS/FFS3 (NOR) are different formats and are not
  covered by this reader; QNX IFS is `docs/formats/qnx-ifs.md`.

## References

* QNX SDP documentation, *System Architecture*: "Power-Safe filesystem"
  (fs-qnx6), `mkqnx6fs`, `chkqnx6fs`.
* Linux `fs/qnx6/{qnx6.h,inode.c,dir.c,namei.c}` and
  `include/linux/qnx6_fs.h` (read for understanding; nothing copied).
* NFI qnxmount `qnxmount/qnx6/{parser.ksy,interface.py}` (Apache-2.0; read
  for understanding, and used as the reference implementation in the
  corpus tests).
* The `qnx-example` corpus superblocks, inode table, directories, longfile
  table and bitmap, dumped by hand to pin every field above.
